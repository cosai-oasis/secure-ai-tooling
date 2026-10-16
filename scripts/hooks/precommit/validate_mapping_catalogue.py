#!/usr/bin/env python3
"""
Tier 2 catalogue-membership validator for framework mapping values.

Implements ADR-027 D5 Tier 2 over the vendored catalogue input defined by ADR-038.
Tier 1 (validate_mapping_drift.py) confirms that a pinned value's version token is
registered; Tier 2 additionally confirms that the value's id exists in the edition the
token names.

Read contract (ADR-038 D3, D4). The registry and the schema are tracked sources outside
the record; they are loaded first, then each adjudicated framework goes through:
  1. Verify the record. For each adjudicated framework, read
     `<catalogue-dir>/<framework>/SHA256SUMS` and check every listed file against its
     digest. Nothing in the subdirectory is parsed before this stage passes.
  2. Check the framework is registered, then parse the manifest from its verified bytes.
  3. Require the registered editions. Every token in `version` ∪ `priorVersions` must
     resolve to one manifest entry, and that entry's catalogue must be listed in the
     record (and so already verified) before it is parsed.

Per-value verdicts use Tier 1's four states:
  - a value of a framework key outside ADJUDICATED_FRAMEWORKS is "skip";
  - an adjudicated value first receives Tier 1's verdict ("skip" for the delimiter-less
    legacy form, "invalid" for an unregistered token) and a Tier 1 "skip" or "invalid"
    stands, so Tier 2 never accepts a value Tier 1 rejects;
  - a value Tier 1 accepts is "invalid" when its id is absent from the techniques ∪
    mitigations of its own pinned edition, or when its token is unresolved; otherwise it
    keeps Tier 1's "current" / "valid-but-superseded".

CLI:
    validate_mapping_catalogue.py [content ...] [--force] [--block]
        [--frameworks PATH] [--schema PATH] [--catalogue-dir PATH]

    Positional content paths default to the four consumer YAMLs. Every default is
    anchored on this file, never on the process working directory (ADR-038 D3a).

Exit codes (ADR-038 D4a):
    0  Without --force: nothing examined. With --force: no invalid value, or invalid
       values without --block (warn tier).
    1  --force --block and at least one invalid value.
    2  Read error (any input missing, unreadable, unparsable, misshapen, a digest
       mismatch, an unresolved registered edition, a D5 table error), in both modes.
       An invalid pinned-subschema pattern makes the schema unparsable; a content file
       with no entity list is misshapen.

Output is identical with and without --block; only the exit code differs.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml

# Ensure scripts/hooks is on sys.path so `precommit.*` imports work both when
# this file is executed directly and when it is imported as a package module.
_HOOKS_DIR = Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

from precommit.framework_mapping import (  # noqa: E402
    DEFAULT_FRAMEWORKS_PATH,
    DEFAULT_SCHEMA_PATH,
    FrameworkMappingError,
    known_versions,
    load_pinned_patterns,
    load_registry,
    split_pinned_value,
)
from precommit.validate_mapping_drift import (  # noqa: E402
    _DEFAULT_CONTENT_FILES,
)
from precommit.validate_mapping_drift import (  # noqa: E402
    classify_value as _tier1_classify_value,
)

# This file lives at scripts/hooks/precommit/; scripts/ is two levels above its directory.
DEFAULT_CATALOGUE_DIR: Path = Path(__file__).resolve().parent.parent.parent / "framework_catalogues"

_SUMS_NAME = "SHA256SUMS"
_MANIFEST_NAME = "manifest.yaml"

# GNU coreutils text-mode line: 64 hex digits, two spaces, file name.
_SUMS_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})  (.+)$")

# The C loader is a safe loader too; it parses the ~1 MB catalogues several times faster.
_SAFE_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class CatalogueReadError(Exception):
    """An input could not be read, verified or parsed (exit 2, ADR-038 D4)."""


def _safe_load(data: bytes) -> Any:
    return yaml.load(data, Loader=_SAFE_LOADER)


# ---------------------------------------------------------------------------
# MITRE ATLAS resolver and parser
# ---------------------------------------------------------------------------


def _parse_atlas_manifest(data: bytes) -> list[dict]:
    """
    Parse upstream `dist/manifest.yaml` and check its shape.

    The manifest is a verbatim upstream copy, so every entry (registered or not) must
    carry a string `release` and a `versions` list of mappings with a string
    `format-version`. A non-string `release` is rejected rather than coerced: an
    unquoted `2025.10` loads as the float 2025.1 and could not be compared safely.
    """
    try:
        manifest = _safe_load(data)
    except yaml.YAMLError as exc:
        raise CatalogueReadError(f"{_MANIFEST_NAME} does not parse: {exc}") from exc
    if not isinstance(manifest, list):
        raise CatalogueReadError(f"{_MANIFEST_NAME} is not a list of release entries")
    for index, entry in enumerate(manifest):
        where = f"{_MANIFEST_NAME} entry {index}"
        if not isinstance(entry, dict):
            raise CatalogueReadError(f"{where} is not a mapping")
        if not isinstance(entry.get("release"), str):
            raise CatalogueReadError(f"{where} has no string `release`")
        versions = entry.get("versions")
        if not isinstance(versions, list):
            raise CatalogueReadError(f"{where} ({entry['release']}) has no `versions` list")
        for item in versions:
            if not isinstance(item, dict) or not isinstance(item.get("format-version"), str):
                raise CatalogueReadError(
                    f"{where} ({entry['release']}) has a `versions` item without a string `format-version`"
                )
    return manifest


def resolve_token(token: str, manifest: list[dict]) -> str | None:
    """
    Resolve a pin token to a manifest release (ADR-038 D3b).

    Lookup 1: the entry whose `release` equals the token. Otherwise lookup 2: the unique
    entry with a `versions[].format-version` equal to the token. No match, or more than
    one, returns None (unresolved). `path` strings are never consulted.
    """
    entries = [e for e in manifest if isinstance(e, dict)]
    by_release = [e for e in entries if e.get("release") == token]
    if by_release:
        return by_release[0]["release"] if len(by_release) == 1 else None
    by_format = [
        e
        for e in entries
        if any(isinstance(v, dict) and v.get("format-version") == token for v in e.get("versions") or [])
    ]
    if len(by_format) == 1:
        return by_format[0]["release"]
    return None


def _atlas_catalogue_file(release: str) -> str:
    """Local file name of a release's v6 catalogue (ADR-038 D2 layout)."""
    return f"ATLAS-{release}.yaml"


def _parse_atlas_ids(name: str, data: bytes) -> set[str]:
    """
    Return the pin-target ids of a v6 catalogue (ADR-038 D3d).

    Ids are the keys of the top-level `techniques:` and `mitigations:` maps. Either map
    absent, not a mapping or empty makes the catalogue unparsable. Tactics, case studies
    and prose are not pin targets.
    """
    try:
        doc = _safe_load(data)
    except yaml.YAMLError as exc:
        raise CatalogueReadError(f"{name} does not parse: {exc}") from exc
    if not isinstance(doc, dict):
        raise CatalogueReadError(f"{name} is not a mapping")
    ids: set[str] = set()
    for key in ("techniques", "mitigations"):
        block = doc.get(key)
        if not isinstance(block, dict) or not block:
            raise CatalogueReadError(f"{name}: top-level `{key}:` is absent, not a mapping, or empty")
        ids.update(str(k) for k in block)
    return ids


@dataclass(frozen=True)
class _CatalogueSource:
    """How Tier 2 reads one adjudicated framework's vendored catalogues."""

    subdirectory: str
    parse_manifest: Callable[[bytes], list[dict]]
    resolve: Callable[[str, list[dict]], str | None]
    catalogue_file: Callable[[str], str]
    parse_ids: Callable[[str, bytes], set[str]]


# The adjudicated set (ADR-038 D5). It is declared here, next to the code that reads each
# framework, rather than derived from the catalogue directories: deleting a directory must
# be a read error, never a silent switch of that framework's values to "skip". Only
# Of the registered frameworks, only mitre-atlas publishes machine-readable per-edition
# catalogues.
ADJUDICATED_FRAMEWORKS: dict[str, _CatalogueSource] = {
    "mitre-atlas": _CatalogueSource(
        subdirectory="mitre-atlas",
        parse_manifest=_parse_atlas_manifest,
        resolve=resolve_token,
        catalogue_file=_atlas_catalogue_file,
        parse_ids=_parse_atlas_ids,
    ),
}


# ---------------------------------------------------------------------------
# Per-value classification
# ---------------------------------------------------------------------------


def classify_value(
    fw_id: str,
    value: str,
    *,
    registry: dict[str, dict],
    pinned_patterns: dict[str, dict],
    catalogues: dict[str, dict],
) -> tuple[str, str | None]:
    """
    Classify one mapping value as "skip" | "current" | "valid-but-superseded" | "invalid".

    Args:
        fw_id:           Framework key from the `mappings` block.
        value:           The mapping value.
        registry:        Registry dict from load_registry().
        pinned_patterns: Pinned subschemas from load_pinned_patterns().
        catalogues:      Framework id -> {"manifest": <parsed manifest list>,
                         "editions": {<release>: set of ids}}.

    Returns:
        (state, detail). detail is non-None for "invalid" and "valid-but-superseded".
        An invalid detail names the value and either the registered tokens whose edition
        contains the id (`present at <token>`), `absent from every registered edition`,
        or `unresolved` for a token no manifest entry resolves.
    """
    source = ADJUDICATED_FRAMEWORKS.get(fw_id)
    if source is None:
        return ("skip", None)

    # Tier 1 first: its "skip"/"invalid" stands; Tier 2 may only downgrade an accepted value.
    state, detail = _tier1_classify_value(fw_id, value, registry=registry, pinned_patterns=pinned_patterns)
    if state not in ("current", "valid-but-superseded"):
        return (state, detail)

    try:
        base_ref, token = split_pinned_value(fw_id, value, registry=registry, pinned_patterns=pinned_patterns)
    except FrameworkMappingError as exc:  # unreachable after a Tier 1 pass; never fall through
        return ("invalid", f"{value!r}: {exc}")

    loaded = catalogues.get(fw_id)
    if loaded is None or token is None:
        return ("invalid", f"{value!r}: no catalogue loaded for {fw_id!r}")
    manifest = loaded["manifest"]
    editions = loaded["editions"]

    release = source.resolve(token, manifest)
    if release is None:
        # ADR-038 D3b: reachable only below main(), whose D3c check exits 2 first.
        return ("invalid", f"{value!r}: registered token {token!r} is unresolved in the manifest")
    ids = editions.get(release)
    if ids is None:
        return ("invalid", f"{value!r}: no catalogue loaded for edition {token!r} (release {release})")
    if base_ref in ids:
        return (state, detail)

    # Re-pin guidance names REGISTERED tokens (e.g. 5.0.1, not its release 2025.10).
    present_at = []
    for other in sorted(known_versions(fw_id, registry) - {token}):
        other_release = source.resolve(other, manifest)
        if other_release is not None and base_ref in editions.get(other_release, set()):
            present_at.append(f"present at {other}")
    where = "; ".join(present_at) if present_at else "absent from every registered edition"
    return ("invalid", f"{value!r}: {base_ref!r} is not in edition {token!r} (release {release}); {where}")


# ---------------------------------------------------------------------------
# Catalogue loading (ADR-038 D4 stages)
# ---------------------------------------------------------------------------


def _read_record(sums_path: Path) -> dict[str, str]:
    """
    Parse SHA256SUMS into {name: lowercase digest}.

    Stricter than coreutils on names: a name must be a bare file name in this
    subdirectory (no `/`, `\\`, `.` or `..`), because the record covers nothing outside
    it. A malformed or duplicated line, or an empty record, is a read error.
    """
    try:
        text = sums_path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CatalogueReadError(f"cannot read {sums_path}: {exc}") from exc

    record: dict[str, str] = {}
    problems: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = _SUMS_LINE_RE.match(line)
        if match is None:
            problems.append(f"line {number} is not `<64-hex-digest>  <name>`")
            continue
        digest, name = match.group(1).lower(), match.group(2)
        if "/" in name or "\\" in name or name in (".", ".."):
            problems.append(f"line {number} names {name!r}, which is not a bare file name in this directory")
        elif name in record:
            problems.append(f"line {number} lists {name!r} a second time")
        else:
            record[name] = digest
    if not record and not problems:
        problems.append("lists no files")
    if problems:
        raise CatalogueReadError(f"{sums_path}: " + "; ".join(problems))
    return record


def _verify_record(fw_dir: Path) -> dict[str, bytes]:
    """
    Stage 1: verify every file SHA256SUMS lists; return {name: verified bytes}.

    Later stages parse these bytes, not a fresh read, so what is parsed is exactly what
    was verified.
    """
    record = _read_record(fw_dir / _SUMS_NAME)
    if _MANIFEST_NAME not in record:
        raise CatalogueReadError(f"{fw_dir / _SUMS_NAME}: {_MANIFEST_NAME} is not listed")

    verified: dict[str, bytes] = {}
    problems: list[str] = []
    for name, recorded in record.items():
        path = fw_dir / name
        if not path.is_file():
            problems.append(f"{name} is listed in {_SUMS_NAME} but missing at {path}")
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            problems.append(f"cannot read {path}: {exc}")
            continue
        actual = hashlib.sha256(data).hexdigest()
        if actual != recorded:
            problems.append(f"digest mismatch: {path}: recorded {recorded}, actual {actual}")
            continue
        verified[name] = data
    if problems:
        raise CatalogueReadError("; ".join(problems))
    return verified


def _load_catalogues(catalogue_dir: Path, registry: dict[str, dict]) -> dict[str, dict]:
    """
    Run the three D4 stages for every adjudicated framework.

    Returns the loaded state classify_value takes. Raises CatalogueReadError on any read
    failure. The registry is a tracked source outside the record and is loaded by the
    caller; its table-key check runs here, before the manifest is parsed.
    """
    # Stage 1 for every framework before any parse.
    verified_by_fw: dict[str, dict[str, bytes]] = {}
    for fw_id, source in ADJUDICATED_FRAMEWORKS.items():
        fw_dir = catalogue_dir / source.subdirectory
        if not fw_dir.is_dir():
            raise CatalogueReadError(f"{fw_id}: no catalogue directory at {fw_dir}")
        verified_by_fw[fw_id] = _verify_record(fw_dir)

    catalogues: dict[str, dict] = {}
    for fw_id, source in ADJUDICATED_FRAMEWORKS.items():
        verified = verified_by_fw[fw_id]
        fw_dir = catalogue_dir / source.subdirectory
        if fw_id not in registry:
            raise CatalogueReadError(f"{fw_id}: adjudicated framework is absent from the registry")
        if registry[fw_id].get("version") is None:
            raise CatalogueReadError(f"{fw_id}: adjudicated framework has no registered version in the registry")

        # Stage 2: the manifest, parsed only from its verified bytes.
        manifest = source.parse_manifest(verified[_MANIFEST_NAME])

        # Stage 3: the eager required set (ADR-038 D3c). An unresolved registered edition
        # is a registry/manifest inconsistency in the gate's own input, so it is a read
        # error whether or not any value pins it; a per-value rule would see nothing right
        # after a bump and exit 0.
        editions: dict[str, set[str]] = {}
        problems: list[str] = []
        for token in sorted(known_versions(fw_id, registry)):
            release = source.resolve(token, manifest)
            if release is None:
                problems.append(
                    f"{fw_id}: registered edition {token!r} is unresolved in {fw_dir / _MANIFEST_NAME} "
                    "(no unique manifest entry)"
                )
                continue
            name = source.catalogue_file(release)
            if name not in verified:
                on_disk = "file present" if (fw_dir / name).exists() else "file absent"
                problems.append(
                    f"{fw_id}: catalogue {name} for registered edition {token!r} is not listed in "
                    f"{fw_dir / _SUMS_NAME} ({on_disk})"
                )
                continue
            if release not in editions:
                editions[release] = source.parse_ids(name, verified[name])
        if problems:
            raise CatalogueReadError("; ".join(problems))
        catalogues[fw_id] = {"manifest": manifest, "editions": editions}
    return catalogues


# ---------------------------------------------------------------------------
# Content scanning
# ---------------------------------------------------------------------------


def _iter_mapping_values(path: Path) -> Iterator[tuple[Any, str, str]]:
    """
    Yield (entity_id, fw_id, value) for every string mapping value in a content YAML.

    Same traversal as validate_mapping_drift._scan_file: every top-level list-valued key
    is scanned, because `description:` and `categories:` precede the entity key in the
    live files. A missing or unparsable file is a read error, and so is a file with no
    entity list: empty, not a mapping, or a mapping without a top-level non-empty list
    whose items are all mappings. Such a file would add nothing to the summary, so the
    gate would report clean having read nothing from it.
    """
    try:
        data: Any = _safe_load(path.read_bytes())
    except (OSError, yaml.YAMLError) as exc:
        raise CatalogueReadError(f"cannot read content file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CatalogueReadError(f"content file {path} is empty or not a mapping")
    if not any(
        isinstance(block, list) and block and all(isinstance(item, dict) for item in block)
        for block in data.values()
    ):
        raise CatalogueReadError(f"content file {path} has no top-level list of entity mappings")
    for block in data.values():
        if not isinstance(block, list):
            continue
        for entity in block:
            if not isinstance(entity, dict):
                continue
            mappings = entity.get("mappings")
            if not isinstance(mappings, dict):
                continue
            entity_id = entity.get("id", "<unknown>")
            for fw_id, values in mappings.items():
                if not isinstance(values, list):
                    continue
                for value in values:
                    if isinstance(value, str):
                        yield entity_id, fw_id, value


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_tracked_inputs(frameworks: Path, schema: Path) -> tuple[dict[str, dict], dict[str, dict]]:
    """
    Load the registry and the pinned patterns; any failure is a read error naming the file.

    A pinned subschema that is not a valid JSON Schema (e.g. a `pattern` that does not
    compile) makes the schema unparsable, so it is checked here, before any value is read.
    """
    try:
        registry = load_registry(frameworks)
    except Exception as exc:  # noqa: BLE001 - every failure to read the registry is exit 2
        raise CatalogueReadError(f"cannot read registry {frameworks}: {exc}") from exc
    try:
        pinned_patterns = load_pinned_patterns(schema)
    except Exception as exc:  # noqa: BLE001 - every failure to read the schema is exit 2
        raise CatalogueReadError(f"cannot read pinned patterns from {schema}: {exc!r}") from exc
    if not isinstance(pinned_patterns, dict):
        raise CatalogueReadError(f"{schema}: framework-mapping-patterns-pinned has no properties mapping")
    # Check every pinned subschema now, with the same validator class jsonschema.validate
    # selects, so an invalid `pattern` regex is a read error here rather than a SchemaError
    # raised mid-classification (exit 1 with a traceback in both modes).
    for fw_id, sub_schema in pinned_patterns.items():
        try:
            jsonschema.validators.validator_for(sub_schema).check_schema(sub_schema)
        except jsonschema.SchemaError as exc:
            raise CatalogueReadError(
                f"{schema}: pinned subschema for {fw_id!r} is invalid: {exc.message}"
            ) from exc
    return registry, pinned_patterns


def main(argv: list[str]) -> int:
    """Run the Tier 2 validator; return 0, 1 or 2 per ADR-038 D4a."""
    parser = argparse.ArgumentParser(
        description="Check pinned framework mapping values against vendored per-edition catalogues "
        "(ADR-027 D5 Tier 2, ADR-038)."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Content YAML files to scan (defaults to the four consumer YAMLs).",
    )
    parser.add_argument("--force", action="store_true", help="Enable the scan; without it nothing is read.")
    parser.add_argument("--block", action="store_true", help="Exit 1 when any value is invalid.")
    parser.add_argument("--frameworks", type=Path, default=DEFAULT_FRAMEWORKS_PATH, help="frameworks.yaml path.")
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH, help="frameworks.schema.json path.")
    parser.add_argument(
        "--catalogue-dir", type=Path, default=DEFAULT_CATALOGUE_DIR, help="Vendored catalogue root."
    )
    args = parser.parse_args(argv)

    # --force is the enabling argument (ADR-038 D4a): without it no input is read,
    # so there is no read error to report and no summary to print.
    if not args.force:
        print("skipping validation: --force not given (nothing examined)")
        return 0

    content_paths = [Path(p) for p in args.paths] if args.paths else _DEFAULT_CONTENT_FILES
    counts = {"skip": 0, "current": 0, "valid-but-superseded": 0, "invalid": 0}
    invalid_lines: list[str] = []
    try:
        registry, pinned_patterns = _load_tracked_inputs(args.frameworks, args.schema)
        catalogues = _load_catalogues(args.catalogue_dir, registry)
        for path in content_paths:
            for entity_id, fw_id, value in _iter_mapping_values(path):
                state, detail = classify_value(
                    fw_id,
                    value,
                    registry=registry,
                    pinned_patterns=pinned_patterns,
                    catalogues=catalogues,
                )
                counts[state] += 1
                if state == "invalid":
                    invalid_lines.append(
                        f"invalid: {path.name}: entity={entity_id!r} framework={fw_id!r} value={value!r}: {detail}"
                    )
    except CatalogueReadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("catalogue check not performed: read error (exit 2)", file=sys.stderr)
        return 2

    # Identical output in both modes; only the exit code depends on --block (D4a).
    for line in invalid_lines:
        print(line)
    print("summary: " + " ".join(f"{name}={count}" for name, count in counts.items()))
    return 1 if args.block and counts["invalid"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
