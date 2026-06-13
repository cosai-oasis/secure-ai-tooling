#!/usr/bin/env python3
"""
Pre-commit hook: assert mapping-value purity for content YAML files.

Implements ADR-027 D4c — the purity side of the generator-plus-purity pair
for framework mapping values. Paired with framework-mapping-maintainer.py.

For each mapping value under a `mappings.<framework>: [values]` block in
risks/controls/components/personas.yaml, the validator classifies the value
as "ok", "skip", or "fail" according to the D4c / D3a algorithm:

  1. Unknown framework key → FAIL (fail-loud).
  2. Versioned framework + value has no `@` or `:` → FAIL (unpinned value; a
     version token is mandatory now that #343 has migrated the corpus and the
     strict schema enforces pinning — ADR-027 D7/M1 "block" phase. The prior
     "skip" was the pre-migration "warn" tolerance and is retired).
  3. Otherwise, attempt split_pinned_value + compose_pinned_value round-trip:
     - FrameworkMappingError raised AND versioned → FAIL (delimiter present
       but won't round-trip = tampered pinned value).
     - FrameworkMappingError raised AND unversioned (STRIDE) → SKIP (legacy
       spelling not in closed enum; no delimiter signal = not tampered).
     - round-trip mismatch → FAIL.
     - round-trip match → OK.

CLI:
    validate_mapping_purity.py [file ...]
        Positional file args are paths to content YAML files to validate.
        Defaults to the four standard content files when none are given.

Exit codes:
    0  All values are ok or skip.
    1  Any value classified as fail. Failures printed to stderr.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

# Ensure scripts/hooks is on sys.path so `precommit.*` imports work both when
# this file is executed directly (e.g. by the pre-commit framework) and when
# it is imported as a package module (e.g. by pytest with pythonpath configured).
_HOOKS_DIR = Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

from precommit.framework_mapping import (  # noqa: E402
    DEFAULT_FRAMEWORKS_PATH,
    DEFAULT_SCHEMA_PATH,
    FrameworkMappingError,
    compose_pinned_value,
    load_pinned_patterns,
    load_registry,
    split_pinned_value,
)

# Repo root resolved from this file's location (same pattern as framework_mapping.py).
# This file lives at scripts/hooks/precommit/validate_mapping_purity.py.
_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parent.parent.parent.parent

# Default content files scanned when no positional args are supplied.
_DEFAULT_CONTENT_FILES: list[Path] = [
    _REPO_ROOT / "risk-map" / "yaml" / "risks.yaml",
    _REPO_ROOT / "risk-map" / "yaml" / "controls.yaml",
    _REPO_ROOT / "risk-map" / "yaml" / "components.yaml",
    _REPO_ROOT / "risk-map" / "yaml" / "personas.yaml",
]


def classify_value(
    fw_id: str,
    value: str,
    *,
    registry: dict[str, dict],
    pinned_patterns: dict[str, dict],
) -> tuple[str, str | None]:
    """
    Classify a single mapping value as "ok", "skip", or "fail" (D4c).

    Args:
        fw_id:           Framework key from the `mappings` block.
        value:           The mapping value string to classify.
        registry:        Registry dict from load_registry().
        pinned_patterns: Pinned subschemas from load_pinned_patterns().

    Returns:
        Tuple (status, detail) where status is one of "ok", "skip", "fail".
        detail is a human-readable string describing the failure, or None.

    Post-#343 note: a versioned framework value lacking a version token now FAILs
    (step 2) — pinning is mandatory. "skip" survives only for the unversioned
    STRIDE framework (step 3, FrameworkMappingError + unversioned).
    """
    # Step 1: unknown framework key is always a failure (D4c fail-loud).
    if fw_id not in registry:
        return ("fail", f"unknown framework key {fw_id!r} (not in registry)")

    is_versioned = registry[fw_id].get("version") is not None

    # Step 2: versioned framework with no delimiter → unpinned value → FAIL.
    # D3a / H3: `@` and `:` never appear in any legacy base ref or concept id, so
    # their absence is an unambiguous "this value carries no version token". Post
    # -#343 the corpus is migrated and the strict schema makes pinning mandatory,
    # so an unpinned value on a versioned framework is invalid (the ADR-027 D7/M1
    # "block" phase; the pre-migration "skip" tolerance is retired). check-jsonschema
    # rejects the same value — the purity validator must agree.
    # Do NOT build a per-framework delimiter table — delimiter selection belongs
    # inside split_pinned_value / compose_pinned_value; we only test for presence
    # of either reserved character.
    if is_versioned and ("@" not in value and ":" not in value):
        return (
            "fail",
            f"{value!r}: unpinned value for versioned framework {fw_id!r}; "
            f"a version token is required (ADR-027 D7/M1)",
        )

    # Step 3: attempt split + compose round-trip.
    try:
        base_ref, version = split_pinned_value(fw_id, value, registry=registry, pinned_patterns=pinned_patterns)
        recomposed = compose_pinned_value(
            fw_id, version, base_ref, registry=registry, pinned_patterns=pinned_patterns
        )
    except FrameworkMappingError as exc:
        if is_versioned:
            # Delimiter was present but round-trip fails → tampered pinned value.
            return ("fail", f"{value!r} failed round-trip: {exc}")
        # Unversioned (STRIDE): FrameworkMappingError from compose means the bare
        # ref is not in the closed PascalCase enum — a legacy spelling, not a tamper
        # (no delimiter to signal pinned intent for an unversioned framework).
        return ("skip", None)

    # Step 3 (cont.): mismatch after round-trip → tampered value.
    if recomposed != value:
        return ("fail", f"{value!r} round-trip mismatch: recomposed as {recomposed!r}")

    return ("ok", None)


def _scan_file(
    path: Path,
    registry: dict[str, dict],
    pinned_patterns: dict[str, dict],
) -> list[str]:
    """
    Parse a content YAML file and return a list of failure messages.

    Iterates over every top-level list-valued key (risks, controls, personas,
    description, categories, etc.) and, within each, over every dict item that
    has a `mappings` key. Scanning all list keys (not just the first) guards
    against the silent-skip bug where description/categories precede the entity
    key and would otherwise absorb the single-key scan. Items without a
    `mappings` key are skipped silently.

    Args:
        path:            Path to the content YAML file.
        registry:        Registry dict from load_registry().
        pinned_patterns: Pinned subschemas from load_pinned_patterns().

    Returns:
        List of failure message strings (empty on success).
    """
    with open(path, encoding="utf-8") as fh:
        data: Any = yaml.safe_load(fh)

    if not isinstance(data, dict):
        return []

    # Scan ALL top-level list-valued keys, not just the first.
    # Real content files have `description:` (and sometimes `categories:`) as
    # lists BEFORE the entity key (risks/controls/personas); taking only the
    # first list-valued key would silently skip all entity mappings (silent-skip
    # bug). Items from non-entity lists (prose strings, category dicts) have no
    # `mappings` key and are skipped harmlessly inside the loop below.
    failures: list[str] = []
    for v in data.values():
        if not isinstance(v, list):
            continue
        for entity in v:
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
                    if not isinstance(value, str):
                        continue
                    status, detail = classify_value(
                        fw_id, value, registry=registry, pinned_patterns=pinned_patterns
                    )
                    if status == "fail":
                        failures.append(
                            f"  {path.name}: entity={entity_id!r} framework={fw_id!r} value={value!r}: {detail}"
                        )

    return failures


def main(argv: list[str]) -> int:
    """
    Run the mapping-value purity validator. Returns 0 on success, 1 on any failure.

    Args:
        argv: Command-line arguments (positional file paths, or empty for defaults).

    Returns:
        0 if all values are ok or skip; 1 if any purity failure is found.
    """
    parser = argparse.ArgumentParser(
        description="Validate framework mapping-value purity in content YAML files (ADR-027 D4c)."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Content YAML file paths to validate (defaults to the four standard content files).",
    )
    args = parser.parse_args(argv)

    target_paths = [Path(p) for p in args.paths] if args.paths else _DEFAULT_CONTENT_FILES

    # Load registry and pinned patterns once; pass into every classify_value call.
    try:
        registry = load_registry(DEFAULT_FRAMEWORKS_PATH)
        pinned_patterns = load_pinned_patterns(DEFAULT_SCHEMA_PATH)
    except Exception as exc:  # noqa: BLE001
        print(f"error: failed to load framework registry or schema: {exc}", file=sys.stderr)
        return 1

    all_failures: list[str] = []

    for path in target_paths:
        if not path.is_file():
            print(f"error: content file not found: {path}", file=sys.stderr)
            return 1
        try:
            failures = _scan_file(path, registry, pinned_patterns)
        except Exception as exc:  # noqa: BLE001
            print(f"error: failed to scan {path}: {exc}", file=sys.stderr)
            return 1
        all_failures.extend(failures)

    if all_failures:
        print("mapping-value purity check failed:", file=sys.stderr)
        for msg in all_failures:
            print(msg, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
