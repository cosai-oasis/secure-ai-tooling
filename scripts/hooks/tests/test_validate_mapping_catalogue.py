#!/usr/bin/env python3
"""
Contract-pinning tests for the ADR-038 Tier 2 catalogue-membership validator.

Tooling under test:
  scripts/hooks/precommit/validate_mapping_catalogue.py

Authoritative spec: docs/adr/038-tier-2-catalogue-data-input.md
  D2   — catalogue layout: <catalogue-dir>/<framework>/{manifest.yaml, ATLAS-<release>.yaml,
         SHA256SUMS, SOURCE, LICENSE}; SOURCE and LICENSE are never read.
  D3a  — every input is a CLI option with a `__file__`-anchored default; positional
         content paths default to the four consumer YAMLs.
  D3b  — token resolution: by `release`, else by the UNIQUE `versions[].format-version`;
         none or more than one → unresolved.
  D3c  — eager required set: every token in `version` ∪ `priorVersions` (stripped via
         `known_versions`) must resolve and have a listed, verified catalogue — read error.
  D3d  — ids are the keys of the top-level `techniques:` and `mitigations:` maps; either
         map absent, non-mapping or empty → read error.
  D4   — SHA256SUMS (coreutils format) verified BEFORE any parse; then parse; then the
         registered-edition completeness check. Every read failure exits 2.
  D4a  — per-flag contract: `--force` is the enabling argument; warn tier exits 0 on
         invalid; `--block` exits 1 on invalid; read error exits 2 in both; output is
         identical in both modes.
  D5   — adjudicated set is a table in the validator; today {mitre-atlas}; a table key
         missing from the registry or without a catalogue subdirectory is a read error.
Per-value semantics: Tier 1's verdict comes first and a Tier 1 `skip` or `invalid` stands,
so Tier 2 never accepts a value Tier 1 rejects; it can turn an accepted value into `invalid`.

Python surface pinned by this file (ADR-038 names the CLI and the D5 table but no Python
API; these names are this file's decisions, stated here so the implementer can see them):

  ADJUDICATED_FRAMEWORKS
      Mapping whose keys are the framework ids Tier 2 adjudicates (D5 table). Only the
      key set is pinned.
  DEFAULT_CATALOGUE_DIR
      Path; `<repo>/scripts/framework_catalogues`, anchored on the validator's __file__.
  resolve_token(token: str, manifest: list[dict]) -> str | None
      D3b. `manifest` is the parsed `manifest.yaml` (a top-level list of release entries,
      the upstream shape). Returns the resolved entry's `release` string, or None when the
      token is unresolved.
  classify_value(fw_id, value, *, registry, pinned_patterns, catalogues) -> (state, detail)
      Per-value verdict, Tier 1's four states. `catalogues` is a dict keyed by framework
      id → {"manifest": <parsed manifest list>, "editions": {<release>: set[str] of ids}}.
      `detail` is non-None for "invalid" and "valid-but-superseded".
  main(argv: list[str]) -> int
      0 / 1 / 2 per D4a.

Output conventions pinned by this file (ADR-038 D4a names a "summary line with its
per-verdict counts" and "detail lines" but fixes no text; these are this file's decisions):

  summary line   exactly one line, starting with `summary`, carrying the four tokens
                 `skip=N`, `current=N`, `valid-but-superseded=N`, `invalid=N` (any order).
  skip line      without `--force`: a line containing `skipping validation: --force not given`
                 (the wording documented in hook-validations.md §19) and NO summary line.
  invalid detail names the value verbatim and, for a value absent at its pinned edition:
                 `present at <registered-token>` when the id exists at another registered
                 edition (the REGISTERED token, e.g. `5.0.1` not `2025.10`, because the line
                 is re-pin guidance), or `absent from every registered edition` otherwise;
                 for an unresolved registered token the word `unresolved`.
  read errors    exit 2; the message names the offending file's basename (or the token /
                 framework key). A digest mismatch says `digest mismatch` and names both hex
                 digests (D4); that phrase is also how the stage-order tests assert that the
                 digest stage did NOT fire. A D5 table-key error says `registry` (key absent
                 from frameworks.yaml) or `no catalogue directory` (no subdirectory) beside the
                 key, because the bare key and the word "catalogue" both appear in paths.
  SHA256SUMS     a line whose digest is not 64 hex characters, or that has no separator, and an
                 empty record are read errors naming `SHA256SUMS` (the empty record may instead
                 surface as "manifest.yaml not listed"). A listed name carrying a path separator
                 or a `..` component is a read error naming `SHA256SUMS`, even when every
                 required line is present and the extra line's digest is valid for the file it
                 reaches. The name rule is STRICTER than coreutils, which accepts `/` and `..`;
                 D4's "covers nothing outside the subdirectory" is the reason. A name listed
                 twice with a wrong digest on either line is a read error (coreutils agrees).
                 Coreutils also accepts a single-space separator; that case is deliberately
                 left unpinned.
  manifest shape a manifest that parses to anything but a list, or whose entries lack
                 `release` or `versions` (ANY entry, registered or not: it is a verbatim
                 upstream copy and every upstream entry carries both), is unparsable (D4).
  stdout/stderr  not pinned individually; assertions search the combined output, except
                 the D4a identity check, which compares each stream between modes.

Green controls (tests that pass on a clean tree) and the red partner each one bounds:

  test_non_empty_maps_with_unrelated_extra_keys_are_fine
      ↔ test_unparsable_catalogue_is_a_read_error_naming_the_file
  test_extra_vendored_edition_listed_and_present_is_tolerated
      ↔ test_listed_file_for_unregistered_edition_must_still_exist
  test_source_and_license_are_never_read
      ↔ test_record_integrity_failures_exit_2_naming_the_file[manifest-missing]
  test_record_is_reproducible_by_sha256sum_check (fixture control)
      ↔ test_digest_mismatch_exits_2_naming_file_and_both_digests
  test_unregistered_manifest_entry_needs_no_catalogue
      ↔ test_registered_edition_catalogue_missing_exits_2_without_a_pinning_value
  test_prior_versions_are_stripped_from_versionids
      ↔ test_registered_prior_edition_unresolved_exits_2
  test_non_adjudicated_framework_needs_no_catalogue_directory
      ↔ test_table_key_without_catalogue_subdirectory_exits_2
  test_clean_corpus_exits_0_with_and_without_block, test_superseded_is_informational_under_block
      ↔ test_force_block_exits_1_with_identical_output
  test_mappings_free_corpus_prints_zero_summary, test_values_in_every_content_file_are_counted
      ↔ test_without_force_prints_skip_line_no_summary_exits_0, test_summary_partition_sums_to_value_count
  test_ids_are_keys_of_techniques_and_mitigations_maps
      ↔ test_id_mentioned_in_prose_or_case_study_is_not_a_member, test_tactic_id_is_not_a_pin_target
  test_positional_content_paths_override_the_defaults
      ↔ test_missing_content_positional_is_a_read_error
  TestClassifyValue skip/current cases ↔ its invalid cases; TestTokenResolution resolves ↔ unresolved.

Import strategy: module-level import so a ModuleNotFoundError at collection time signals
that the production module is absent (same convention as test_validate_mapping_drift.py).

Fixtures: every test builds a synthetic catalogue tree under tmp_path in the repository
layout (risk-map/yaml, risk-map/schemas, scripts/framework_catalogues/mitre-atlas). No real
ATLAS file is vendored here; that is the edition-flip commit's job. The synthetic registry
and schema are derived from the live ones with the mitre-atlas entry overridden, so they
stay schema-complete and are stable across the edition flip. The synthetic schema is written
alone (its sibling `$ref` targets such as riskmap.schema.json are not materialised), so the
validator reads only the `framework-mapping-patterns-pinned` block from it, as Tier 1 does
through `load_pinned_patterns`; it must not run full jsonschema validation of the registry.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml
from precommit.framework_mapping import load_pinned_patterns, load_registry
from precommit.validate_mapping_catalogue import (
    ADJUDICATED_FRAMEWORKS,
    DEFAULT_CATALOGUE_DIR,
    classify_value,
    main,
    resolve_token,
)
from precommit.validate_mapping_drift import classify_value as tier1_classify_value

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
VALIDATOR_SCRIPT = REPO_ROOT / "scripts" / "hooks" / "precommit" / "validate_mapping_catalogue.py"
LIVE_FRAMEWORKS_YAML = REPO_ROOT / "risk-map" / "yaml" / "frameworks.yaml"
LIVE_FRAMEWORKS_SCHEMA = REPO_ROOT / "risk-map" / "schemas" / "frameworks.schema.json"
LIVE_CATALOGUE_DIR = REPO_ROOT / "scripts" / "framework_catalogues"
LIVE_CONTENT_FILES = [
    REPO_ROOT / "risk-map" / "yaml" / name
    for name in ("risks.yaml", "controls.yaml", "components.yaml", "personas.yaml")
]

# ---------------------------------------------------------------------------
# Synthetic edition model
#
# Two registered editions and two unregistered manifest entries:
#   CURRENT        '2026.08'  a release token; vendored.
#   PRIOR          '5.0.1'    a format-version token carried only by release 2025.10; vendored.
#   UNREGISTERED   '2026.09'  in the manifest, not in the registry, never vendored (D7a/D8).
#   '2025.09'                 carries a second legacy format-version (4.9.0) so the uniqueness
#                             lookup for 5.0.1 is exercised against a sibling, not a vacuum.
# ---------------------------------------------------------------------------

CURRENT = "2026.08"
PRIOR = "5.0.1"
PRIOR_RELEASE = "2025.10"
UNREGISTERED = "2026.09"
FRAMEWORK = "mitre-atlas"

MANIFEST: list[dict] = [
    {
        "release": UNREGISTERED,
        "release-date": "2026-09-15",
        "versions": [{"format-version": "6.0.0", "path": f"v6/ATLAS-{UNREGISTERED}.yaml"}],
    },
    {
        "release": CURRENT,
        "release-date": "2026-08-31",
        "versions": [{"format-version": "6.0.0", "path": f"v6/ATLAS-{CURRENT}.yaml"}],
    },
    {
        "release": PRIOR_RELEASE,
        "release-date": "2025-10-15",
        "versions": [
            {"format-version": "6.0.0", "path": f"v6/ATLAS-{PRIOR_RELEASE}.yaml"},
            {"format-version": PRIOR, "path": f"legacy/ATLAS-{PRIOR}.yaml"},
        ],
    },
    {
        "release": "2025.09",
        "release-date": "2025-09-30",
        "versions": [
            {"format-version": "6.0.0", "path": "v6/ATLAS-2025.09.yaml"},
            {"format-version": "4.9.0", "path": "legacy/ATLAS-4.9.0.yaml"},
        ],
    },
]

# Pin-target namespaces per vendored edition. AML.T0019 and the sub-technique AML.T0001.001
# exist only at the prior edition (the parent AML.T0001 exists at both, so a parent fallback
# is detectable); AML.M0028 and AML.T0115 only at the current one; AML.T0001, AML.T0001.000
# and AML.M0001 exist at both.
PRIOR_TECHNIQUES = {"AML.T0001", "AML.T0001.000", "AML.T0001.001", "AML.T0019"}
PRIOR_MITIGATIONS = {"AML.M0001"}
CURRENT_TECHNIQUES = {"AML.T0001", "AML.T0001.000", "AML.T0115"}
CURRENT_MITIGATIONS = {"AML.M0001", "AML.M0028"}
PRIOR_IDS = PRIOR_TECHNIQUES | PRIOR_MITIGATIONS
CURRENT_IDS = CURRENT_TECHNIQUES | CURRENT_MITIGATIONS

# The pinned pattern admitting both registered tokens (what the edition-flip schema looks like).
PINNED_PATTERN = r"^AML\.(T|M)\d{4}(\.\d{3})?@(5\.0\.1|2026\.08)$"


def _pattern_for(tokens: list[str]) -> str:
    """Build the mitre-atlas pinned pattern for an explicit token alternation."""
    alternation = "|".join(re.escape(t) for t in tokens)
    return rf"^AML\.(T|M)\d{{4}}(\.\d{{3}})?@({alternation})$"


def _catalogue_doc(release: str, techniques: set[str], mitigations: set[str]) -> dict:
    """
    A tiny v6-shaped catalogue (D3d / Context "v6 shape").

    Carries the eight top-level keys. The non-namespace blocks deliberately mention
    technique-shaped ids (a case-study reference and a description cross-reference to
    AML.T0019) so a parser that scans file text instead of the two maps' keys is caught.
    """
    techniques_map = {tid: {"name": f"Technique {tid}", "description": "Synthetic."} for tid in sorted(techniques)}
    if "AML.T0001" in techniques_map:
        techniques_map["AML.T0001"]["description"] = "Synthetic. Supersedes AML.T0019 in later editions."
    return {
        "format-version": "6.0.0",
        "collection": {"name": "ATLAS", "version": release, "id": "AML.C0000"},
        "matrix": {"name": "ATLAS Matrix", "id": "AML.MX0000"},
        "tactics": {"AML.TA0001": {"name": "Reconnaissance"}},
        "techniques": techniques_map,
        "mitigations": {mid: {"name": f"Mitigation {mid}"} for mid in sorted(mitigations)},
        "case-studies": {"AML.CS0001": {"name": "Case", "techniques": ["AML.T0019", "AML.T0001"]}},
        "relationships": {},
    }


# ---------------------------------------------------------------------------
# Tree builder
# ---------------------------------------------------------------------------


@dataclass
class Tree:
    """A synthetic repository layout holding registry, schema, catalogues and content."""

    root: Path
    frameworks: Path
    schema: Path
    catalogue_dir: Path
    fw_dir: Path
    content: dict[str, Path] = field(default_factory=dict)

    @property
    def content_paths(self) -> list[str]:
        return [str(self.content[k]) for k in ("risks", "controls", "components", "personas")]

    @property
    def options(self) -> list[str]:
        return [
            "--frameworks",
            str(self.frameworks),
            "--schema",
            str(self.schema),
            "--catalogue-dir",
            str(self.catalogue_dir),
        ]

    def catalogue_path(self, release: str) -> Path:
        return self.fw_dir / f"ATLAS-{release}.yaml"

    def write_catalogue(self, release: str, techniques: set[str], mitigations: set[str]) -> Path:
        path = self.catalogue_path(release)
        path.write_text(yaml.safe_dump(_catalogue_doc(release, techniques, mitigations)), encoding="utf-8")
        return path

    def write_catalogue_data(self, release: str, data: object) -> Path:
        """Write an arbitrary YAML document as a catalogue (for D3d shape mutations)."""
        path = self.catalogue_path(release)
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        return path

    def write_manifest(self, manifest: object) -> None:
        """Write any YAML document as the manifest (a list normally; other shapes for D4 mutations)."""
        (self.fw_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    def write_sums_lines(self, lines: list[str]) -> None:
        """Write SHA256SUMS verbatim from the given lines (for record-format mutations)."""
        (self.fw_dir / "SHA256SUMS").write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")

    def record_sums(self, names: list[str] | None = None) -> None:
        """
        Regenerate SHA256SUMS in GNU coreutils format (D4).

        Defaults to manifest.yaml plus every ATLAS-*.yaml present. Never lists SOURCE,
        LICENSE or itself.
        """
        if names is None:
            names = ["manifest.yaml"] + sorted(p.name for p in self.fw_dir.glob("ATLAS-*.yaml"))
        lines = []
        for name in names:
            digest = hashlib.sha256((self.fw_dir / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}\n")
        (self.fw_dir / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")

    def recorded_digest(self, name: str) -> str:
        for line in (self.fw_dir / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            digest, _, listed = line.partition("  ")
            if listed == name:
                return digest
        raise KeyError(name)

    def write_registry(
        self, *, version: str | None, prior_tokens: list[str], include_framework: bool = True
    ) -> None:
        """
        Derive frameworks.yaml from the live registry with the mitre-atlas entry overridden.

        priorVersions are written as versionIds (`mitre-atlas@<token>`), the ADR-027 D2c
        shape that `known_versions` strips.
        """
        data = yaml.safe_load(LIVE_FRAMEWORKS_YAML.read_text(encoding="utf-8"))
        entries = []
        for entry in data["frameworks"]:
            if entry.get("id") != FRAMEWORK:
                entries.append(entry)
                continue
            if not include_framework:
                continue
            entry = dict(entry)
            entry["version"] = version
            entry["versionId"] = f"{FRAMEWORK}@{version}"
            entry["priorVersions"] = [f"{FRAMEWORK}@{t}" for t in prior_tokens]
            if prior_tokens:
                entry["supersedes"] = f"{FRAMEWORK}@{prior_tokens[-1]}"
            entries.append(entry)
        data["frameworks"] = entries
        self.frameworks.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    def write_schema(self, pattern: str) -> None:
        """Derive frameworks.schema.json from the live schema with the mitre-atlas pinned pattern replaced."""
        schema = json.loads(LIVE_FRAMEWORKS_SCHEMA.read_text(encoding="utf-8"))
        schema = copy.deepcopy(schema)
        schema["definitions"]["framework-mapping-patterns-pinned"]["properties"][FRAMEWORK] = {
            "type": "string",
            "pattern": pattern,
        }
        self.schema.write_text(json.dumps(schema, indent=2), encoding="utf-8")

    def write_content(
        self, kind: str, mappings: dict[str, list[str]] | None, entity_id: str | None = None
    ) -> None:
        """
        Write one consumer YAML with a single entity carrying `mappings` (or none), in the
        LIVE file shape: list-valued keys precede the entity key.

        Measured on the live tree: risks = title, description (list), risks; controls = title,
        description (list), categories (list), controls; components = id, title, description
        (list), categories (list), components; personas = id, title, description (list),
        personas. A validator that scans only the first list-valued key therefore reads
        `description:` and never reaches the entities (the silent-skip bug
        validate_mapping_drift.py::_scan_file guards against).
        """
        entity: dict = {"id": entity_id or f"{kind[:-1]}Probe", "title": "Probe"}
        if mappings is not None:
            entity["mappings"] = mappings
        doc: dict = {}
        if kind in ("components", "personas"):
            doc["id"] = kind
        doc["title"] = kind.capitalize()
        doc["description"] = ["Synthetic prose paragraph one.", "Synthetic prose paragraph two."]
        if kind in ("controls", "components"):
            doc["categories"] = [{"id": "categoryProbe", "title": "Probe category"}]
        doc[kind] = [entity]
        self.content[kind].write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def build_tree(
    base: Path,
    *,
    risks: dict[str, list[str]] | None = None,
    controls: dict[str, list[str]] | None = None,
    version: str = CURRENT,
    prior_tokens: list[str] | None = None,
    pattern: str = PINNED_PATTERN,
    manifest: list[dict] | None = None,
) -> Tree:
    """
    Build a complete, clean synthetic tree under `base` in the repository layout.

    The default corpus carries one retained value (`AML.T0001@5.0.1`) in risks.yaml and no
    mappings elsewhere; pass `risks` / `controls` to override.
    """
    yaml_dir = base / "risk-map" / "yaml"
    schema_dir = base / "risk-map" / "schemas"
    catalogue_dir = base / "scripts" / "framework_catalogues"
    fw_dir = catalogue_dir / FRAMEWORK
    for d in (yaml_dir, schema_dir, fw_dir):
        d.mkdir(parents=True, exist_ok=True)

    tree = Tree(
        root=base,
        frameworks=yaml_dir / "frameworks.yaml",
        schema=schema_dir / "frameworks.schema.json",
        catalogue_dir=catalogue_dir,
        fw_dir=fw_dir,
        content={k: yaml_dir / f"{k}.yaml" for k in ("risks", "controls", "components", "personas")},
    )
    tree.write_registry(version=version, prior_tokens=[PRIOR] if prior_tokens is None else prior_tokens)
    tree.write_schema(pattern)

    tree.write_manifest(MANIFEST if manifest is None else manifest)
    tree.write_catalogue(PRIOR_RELEASE, PRIOR_TECHNIQUES, PRIOR_MITIGATIONS)
    tree.write_catalogue(CURRENT, CURRENT_TECHNIQUES, CURRENT_MITIGATIONS)
    tree.record_sums()
    (fw_dir / "SOURCE").write_text(
        "upstream: https://github.com/mitre-atlas/atlas-data\ncommit: 0000000\nlicense: Apache-2.0\n",
        encoding="utf-8",
    )
    (fw_dir / "LICENSE").write_text("Apache License 2.0 (synthetic placeholder)\n", encoding="utf-8")

    tree.write_content("risks", {FRAMEWORK: [f"AML.T0001@{PRIOR}"]} if risks is None else risks)
    tree.write_content("controls", controls)
    tree.write_content("components", None)
    tree.write_content("personas", None)
    return tree


def _catalogues_for(tree: Tree) -> dict:
    """The loaded-state shape classify_value takes, built from the fixture constants."""
    return {
        FRAMEWORK: {
            "manifest": yaml.safe_load((tree.fw_dir / "manifest.yaml").read_text(encoding="utf-8")),
            "editions": {PRIOR_RELEASE: set(PRIOR_IDS), CURRENT: set(CURRENT_IDS)},
        }
    }


# ---------------------------------------------------------------------------
# Invocation and output helpers
# ---------------------------------------------------------------------------


def _argv(tree: Tree, *, force: bool = True, block: bool = False, paths: list[str] | None = None) -> list[str]:
    """Positionals first, then flags, then options — the BLOCK_PROBES ordering."""
    argv = list(tree.content_paths if paths is None else paths)
    if force:
        argv.append("--force")
    if block:
        argv.append("--block")
    return argv + tree.options


def _invoke(argv: list[str], capsys) -> tuple[int, str, str]:
    """Run main() in-process; a SystemExit is reported through its code."""
    try:
        rc = main(argv)
    except SystemExit as exc:  # argparse paths
        rc = exc.code if isinstance(exc.code, int) else 2
    out, err = capsys.readouterr()
    return rc, out, err


_SUMMARY_LINE_RE = re.compile(r"^\s*summary\b.*$", re.MULTILINE)
_COUNT_RE = re.compile(r"\b(skip|current|valid-but-superseded|invalid)=(\d+)\b")
CLASSES = ("skip", "current", "valid-but-superseded", "invalid")
DIGEST_MISMATCH = "digest mismatch"


def _names_any(text: str, expected: str | tuple[str, ...]) -> bool:
    """True when the output carries the expected name, or any one of an accepted set of names."""
    alternatives = (expected,) if isinstance(expected, str) else expected
    return any(e in text for e in alternatives)


def _summary_lines(text: str) -> list[str]:
    return _SUMMARY_LINE_RE.findall(text)


def _summary_counts(text: str) -> dict[str, int]:
    """Parse the single summary line into its four counts; fail loudly on zero or many."""
    lines = _summary_lines(text)
    assert len(lines) == 1, f"expected exactly one summary line, found {len(lines)}:\n{text}"
    counts = {k: int(v) for k, v in _COUNT_RE.findall(lines[0])}
    missing = [c for c in CLASSES if c not in counts]
    assert not missing, f"summary line lacks {missing}: {lines[0]!r}"
    return counts


def _run_block_and_warn(tree: Tree, capsys) -> tuple[tuple[int, str, str], tuple[int, str, str]]:
    warn = _invoke(_argv(tree, block=False), capsys)
    block = _invoke(_argv(tree, block=True), capsys)
    return warn, block


# ---------------------------------------------------------------------------
# Read-error mutations (D4 / D3c / D3d / D5), each with the substring its message must carry.
# Applied to a freshly built clean tree.
# ---------------------------------------------------------------------------


def _mut_digest_mismatch(t: Tree) -> None:
    with open(t.catalogue_path(CURRENT), "ab") as fh:
        fh.write(b"\n# local tamper\n")


def _mut_listed_catalogue_absent(t: Tree) -> None:
    t.catalogue_path(PRIOR_RELEASE).unlink()


def _mut_required_catalogue_unlisted(t: Tree) -> None:
    t.record_sums(["manifest.yaml", f"ATLAS-{PRIOR_RELEASE}.yaml"])  # drops ATLAS-2026.08.yaml


def _mut_manifest_unlisted(t: Tree) -> None:
    t.record_sums([f"ATLAS-{PRIOR_RELEASE}.yaml", f"ATLAS-{CURRENT}.yaml"])


def _mut_sums_missing(t: Tree) -> None:
    (t.fw_dir / "SHA256SUMS").unlink()


def _mut_manifest_missing(t: Tree) -> None:
    (t.fw_dir / "manifest.yaml").unlink()


def _mut_unparsable_catalogue(t: Tree) -> None:
    t.catalogue_path(CURRENT).write_bytes(b"techniques: {AML.T0001: [unterminated\n")
    t.record_sums()


def _mut_empty_techniques(t: Tree) -> None:
    t.write_catalogue_data(CURRENT, _catalogue_doc(CURRENT, set(), CURRENT_MITIGATIONS))
    t.record_sums()


def _mut_missing_mitigations_key(t: Tree) -> None:
    doc = _catalogue_doc(CURRENT, CURRENT_TECHNIQUES, CURRENT_MITIGATIONS)
    del doc["mitigations"]
    t.write_catalogue_data(CURRENT, doc)
    t.record_sums()


def _mut_techniques_not_a_mapping(t: Tree) -> None:
    doc = _catalogue_doc(CURRENT, CURRENT_TECHNIQUES, CURRENT_MITIGATIONS)
    doc["techniques"] = sorted(CURRENT_TECHNIQUES)
    t.write_catalogue_data(CURRENT, doc)
    t.record_sums()


def _mut_catalogue_top_level_not_a_mapping(t: Tree) -> None:
    t.write_catalogue_data(CURRENT, ["not", "a", "catalogue"])
    t.record_sums()


def _mut_registered_current_unresolved(t: Tree) -> None:
    # Registry bumped to a token the vendored manifest does not carry; no value pins it.
    t.write_registry(version="2026.10", prior_tokens=[PRIOR, CURRENT])
    t.write_schema(_pattern_for([PRIOR, CURRENT, "2026.10"]))


def _mut_registered_prior_unresolved(t: Tree) -> None:
    t.write_registry(version=CURRENT, prior_tokens=[PRIOR, "7.7.7"])
    t.write_schema(_pattern_for([PRIOR, CURRENT, "7.7.7"]))


def _mut_registered_edition_ambiguous(t: Tree) -> None:
    # `6.0.0` is a format-version carried by every manifest entry: more than one match → unresolved.
    t.write_registry(version="6.0.0", prior_tokens=[PRIOR, CURRENT])
    t.write_schema(_pattern_for([PRIOR, CURRENT, "6.0.0"]))


def _mut_registered_catalogue_absent_and_unlisted(t: Tree) -> None:
    t.catalogue_path(CURRENT).unlink()
    t.record_sums()


def _mut_table_key_absent_from_registry(t: Tree) -> None:
    t.write_registry(version=CURRENT, prior_tokens=[PRIOR], include_framework=False)


def _mut_table_key_without_subdirectory(t: Tree) -> None:
    shutil.rmtree(t.fw_dir)


# manifest.yaml parse and shape errors (D4 "unparsable manifest"); record regenerated so stage 1 passes.
def _mut_manifest_unparsable(t: Tree) -> None:
    (t.fw_dir / "manifest.yaml").write_bytes(b"- release: {unterminated\n")
    t.record_sums()


def _mut_manifest_not_a_list(t: Tree) -> None:
    t.write_manifest({"releases": MANIFEST})
    t.record_sums()


def _mut_manifest_entry_without_release(t: Tree) -> None:
    manifest = copy.deepcopy(MANIFEST)
    del manifest[3][
        "release"
    ]  # the unregistered 2025.09 entry: shape errors are not scoped to registered editions
    t.write_manifest(manifest)
    t.record_sums()


def _mut_manifest_entry_without_versions(t: Tree) -> None:
    manifest = copy.deepcopy(MANIFEST)
    del manifest[3]["versions"]
    t.write_manifest(manifest)
    t.record_sums()


# Registry and schema inputs (D3a): unreadable tracked sources are read errors too.
def _mut_registry_unparsable(t: Tree) -> None:
    t.frameworks.write_bytes(b"frameworks: [unterminated\n")


def _mut_registry_without_frameworks_array(t: Tree) -> None:
    t.frameworks.write_text("title: Frameworks\n", encoding="utf-8")


def _mut_schema_without_pinned_block(t: Tree) -> None:
    schema = json.loads(t.schema.read_text(encoding="utf-8"))
    del schema["definitions"]["framework-mapping-patterns-pinned"]
    t.schema.write_text(json.dumps(schema, indent=2), encoding="utf-8")


# A pinned pattern that is not a valid regex (unbalanced group): the schema parses as JSON but
# cannot be used, so it is unparsable under D4.
INVALID_PINNED_PATTERN = r"^AML\.(T|M)\d{4}(@(5\.0\.1)$"


def _mut_schema_invalid_pinned_pattern(t: Tree) -> None:
    t.write_schema(INVALID_PINNED_PATTERN)


# SHA256SUMS format and scope (D4): malformed lines, an empty record, names outside the subdirectory.
def _sums_line(t: Tree, name: str) -> str:
    return f"{hashlib.sha256((t.fw_dir / name).read_bytes()).hexdigest()}  {name}"


def _catalogue_sums_lines(t: Tree) -> list[str]:
    return [_sums_line(t, f"ATLAS-{PRIOR_RELEASE}.yaml"), _sums_line(t, f"ATLAS-{CURRENT}.yaml")]


def _mut_sums_short_digest(t: Tree) -> None:
    t.write_sums_lines([_sums_line(t, "manifest.yaml")[1:], *_catalogue_sums_lines(t)])


def _mut_sums_non_hex_digest(t: Tree) -> None:
    t.write_sums_lines([f"{'g' * 64}  manifest.yaml", *_catalogue_sums_lines(t)])


def _mut_sums_no_separator(t: Tree) -> None:
    t.write_sums_lines([_sums_line(t, "manifest.yaml").replace("  ", ""), *_catalogue_sums_lines(t)])


def _mut_sums_empty(t: Tree) -> None:
    t.write_sums_lines([])


def _required_sums_lines(t: Tree) -> list[str]:
    return [_sums_line(t, "manifest.yaml"), *_catalogue_sums_lines(t)]


def _mut_sums_name_dotdot(t: Tree) -> None:
    # All required lines intact PLUS a digest-valid line reaching an existing file outside the
    # subdirectory through `..`. `sha256sum -c --strict` accepts this record (rc 0).
    outside = t.fw_dir / ".." / ".." / ".." / "risk-map" / "yaml" / "frameworks.yaml"
    assert outside.resolve() == t.frameworks.resolve()
    digest = hashlib.sha256(outside.read_bytes()).hexdigest()
    t.write_sums_lines([*_required_sums_lines(t), f"{digest}  ../../../risk-map/yaml/frameworks.yaml"])


def _mut_sums_name_with_slash(t: Tree) -> None:
    # The `/` variant without `..`: an absolute path to an existing file outside the
    # subdirectory, digest-valid. Coreutils accepts it; the validator must not.
    digest = hashlib.sha256(t.frameworks.read_bytes()).hexdigest()
    t.write_sums_lines([*_required_sums_lines(t), f"{digest}  {t.frameworks.resolve()}"])


def _mut_sums_duplicate_name_last_correct(t: Tree) -> None:
    # The same name twice: a wrong digest first, the right one second. `sha256sum -c --strict`
    # returns 1 (the first line fails); a last-wins validator would exit 0.
    good = _sums_line(t, "manifest.yaml")
    bad = f"{'0' * 64}  manifest.yaml"
    t.write_sums_lines([bad, good, *_catalogue_sums_lines(t)])


READ_ERROR_MUTATIONS: list[tuple[str, Callable[[Tree], None], str | tuple[str, ...]]] = [
    ("digest-mismatch", _mut_digest_mismatch, f"ATLAS-{CURRENT}.yaml"),
    ("listed-catalogue-absent", _mut_listed_catalogue_absent, f"ATLAS-{PRIOR_RELEASE}.yaml"),
    ("required-catalogue-unlisted", _mut_required_catalogue_unlisted, f"ATLAS-{CURRENT}.yaml"),
    ("manifest-unlisted", _mut_manifest_unlisted, "manifest.yaml"),
    ("sha256sums-missing", _mut_sums_missing, "SHA256SUMS"),
    ("manifest-missing", _mut_manifest_missing, "manifest.yaml"),
    ("unparsable-catalogue", _mut_unparsable_catalogue, f"ATLAS-{CURRENT}.yaml"),
    ("empty-techniques-map", _mut_empty_techniques, f"ATLAS-{CURRENT}.yaml"),
    ("missing-mitigations-key", _mut_missing_mitigations_key, f"ATLAS-{CURRENT}.yaml"),
    ("techniques-not-a-mapping", _mut_techniques_not_a_mapping, f"ATLAS-{CURRENT}.yaml"),
    ("catalogue-not-a-mapping", _mut_catalogue_top_level_not_a_mapping, f"ATLAS-{CURRENT}.yaml"),
    ("registered-current-unresolved", _mut_registered_current_unresolved, "2026.10"),
    ("registered-prior-unresolved", _mut_registered_prior_unresolved, "7.7.7"),
    ("registered-edition-ambiguous", _mut_registered_edition_ambiguous, "6.0.0"),
    (
        "registered-catalogue-absent-unlisted",
        _mut_registered_catalogue_absent_and_unlisted,
        f"ATLAS-{CURRENT}.yaml",
    ),
    ("table-key-absent-from-registry", _mut_table_key_absent_from_registry, FRAMEWORK),
    ("table-key-without-subdirectory", _mut_table_key_without_subdirectory, FRAMEWORK),
    ("manifest-unparsable", _mut_manifest_unparsable, "manifest.yaml"),
    ("manifest-not-a-list", _mut_manifest_not_a_list, "manifest.yaml"),
    ("manifest-entry-without-release", _mut_manifest_entry_without_release, "manifest.yaml"),
    ("manifest-entry-without-versions", _mut_manifest_entry_without_versions, "manifest.yaml"),
    ("registry-unparsable", _mut_registry_unparsable, "frameworks.yaml"),
    ("registry-without-frameworks-array", _mut_registry_without_frameworks_array, "frameworks.yaml"),
    ("schema-without-pinned-block", _mut_schema_without_pinned_block, "frameworks.schema.json"),
    ("sums-short-digest", _mut_sums_short_digest, "SHA256SUMS"),
    ("sums-non-hex-digest", _mut_sums_non_hex_digest, "SHA256SUMS"),
    ("sums-no-separator", _mut_sums_no_separator, "SHA256SUMS"),
    ("sums-empty", _mut_sums_empty, ("SHA256SUMS", "manifest.yaml")),
    ("sums-name-with-slash", _mut_sums_name_with_slash, "SHA256SUMS"),
    ("sums-name-dotdot", _mut_sums_name_dotdot, "SHA256SUMS"),
    ("sums-duplicate-name-last-correct", _mut_sums_duplicate_name_last_correct, ("SHA256SUMS", "manifest.yaml")),
]
READ_ERROR_IDS = [m[0] for m in READ_ERROR_MUTATIONS]


def _mutation(mutation_id: str) -> tuple[Callable[[Tree], None], str | tuple[str, ...]]:
    _, mutate, expected = next(m for m in READ_ERROR_MUTATIONS if m[0] == mutation_id)
    return mutate, expected


# ===========================================================================
# 1. Token resolution (ADR-038 D3b)
# ===========================================================================


class TestTokenResolution:
    """
    D3b: a token resolves by `release`, else by the unique `format-version`; none or more
    than one match is unresolved. Pinned on resolve_token over the parsed manifest list.
    """

    def test_release_token_resolves_to_its_release(self):
        """A token equal to an entry's `release` resolves to that release (lookup 1)."""
        assert resolve_token(CURRENT, MANIFEST) == CURRENT

    def test_unique_format_version_token_resolves_to_carrying_release(self):
        """`5.0.1` is a format-version carried by exactly one entry; it resolves to release 2025.10 (lookup 2)."""
        assert resolve_token(PRIOR, MANIFEST) == PRIOR_RELEASE

    def test_other_unique_format_version_resolves_to_its_own_release(self):
        """Green control for lookup 2: the sibling legacy format-version resolves to ITS release, not 2025.10."""
        assert resolve_token("4.9.0", MANIFEST) == "2025.09"

    def test_format_version_carried_by_every_entry_is_unresolved(self):
        """`6.0.0` matches every entry's format-version: more than one match → unresolved (None)."""
        assert resolve_token("6.0.0", MANIFEST) is None

    def test_format_version_shared_by_two_entries_is_unresolved(self):
        """
        Two matches are already too many: "exactly one" is the rule, not "fewer than all".

        Pins the boundary between "unique" and "ambiguous" at 2, so an implementation that
        special-cases 6.0.0 by name instead of counting matches is caught.
        """
        manifest = copy.deepcopy(MANIFEST)
        manifest[0]["versions"].append({"format-version": "4.9.0", "path": "legacy/dup.yaml"})
        assert resolve_token("4.9.0", manifest) is None

    def test_unknown_token_is_unresolved(self):
        """A token matching no `release` and no `format-version` is unresolved."""
        assert resolve_token("9.9.9", MANIFEST) is None

    def test_release_lookup_precedes_format_version_lookup(self):
        """
        D3b orders the lookups: by release first, "otherwise" by format-version.

        A token that is one entry's `release` and another entry's `format-version` resolves
        to the release entry. Synthetic shape; pins the order, not a real collision.
        """
        manifest = copy.deepcopy(MANIFEST)
        manifest[3]["versions"].append({"format-version": CURRENT, "path": "legacy/odd.yaml"})
        assert resolve_token(CURRENT, manifest) == CURRENT

    def test_manifest_without_matching_release_does_not_resolve_by_path(self):
        """
        Green boundary: a token appearing only inside a `path` string resolves nothing.

        Resolution reads `release` and `format-version`, never the path text.
        """
        assert resolve_token("ATLAS-2026.08", MANIFEST) is None


# ===========================================================================
# 2. Per-value classes (ADR-038 D3b, D5)
# ===========================================================================


class TestClassifyValue:
    """
    Per-value verdicts via classify_value over the loaded-state dict.

    Each adjudicated value is first checked against the registry's version set exactly as
    Tier 1 does (a Tier 1 `skip` or `invalid` stands; Tier 2 never accepts what Tier 1 rejects), then its id
    is checked for membership in techniques ∪ mitigations of the edition its token names.
    """

    @pytest.fixture
    def loaded(self, tmp_path):
        tree = build_tree(tmp_path)
        return load_registry(tree.frameworks), load_pinned_patterns(tree.schema), _catalogues_for(tree)

    def _classify(self, loaded, fw_id, value):
        registry, patterns, catalogues = loaded
        return classify_value(fw_id, value, registry=registry, pinned_patterns=patterns, catalogues=catalogues)

    def _tier1(self, loaded, fw_id, value):
        registry, patterns, _ = loaded
        return tier1_classify_value(fw_id, value, registry=registry, pinned_patterns=patterns)

    def test_present_at_current_edition_is_current(self, loaded):
        """Id present in the catalogue of the registry's current edition → current."""
        state, _ = self._classify(loaded, FRAMEWORK, f"AML.T0001@{CURRENT}")
        assert state == "current"

    def test_sub_technique_present_at_current_edition_is_current(self, loaded):
        """A sub-technique id (`AML.T0001.000`) is a key of `techniques:` like any other → current."""
        state, _ = self._classify(loaded, FRAMEWORK, f"AML.T0001.000@{CURRENT}")
        assert state == "current"

    def test_sub_technique_absent_at_edition_is_invalid_without_parent_fallback(self, loaded):
        """
        `AML.T0001.001` is absent at 2026.08 while its parent `AML.T0001` is present there:
        the sub-technique is its own pin target, so the value is invalid (present at 5.0.1), and
        the parent's presence is no fallback. 13 of the 53 live ATLAS pins are sub-techniques.
        """
        state, detail = self._classify(loaded, FRAMEWORK, f"AML.T0001.001@{CURRENT}")
        assert state == "invalid"
        assert detail is not None
        assert f"present at {PRIOR}" in detail

    def test_sub_technique_present_at_its_own_edition_is_valid_but_superseded(self, loaded):
        """Green partner: the same sub-technique pinned to the edition that carries it passes."""
        state, _ = self._classify(loaded, FRAMEWORK, f"AML.T0001.001@{PRIOR}")
        assert state == "valid-but-superseded"

    def test_mitigation_present_at_current_edition_is_current(self, loaded):
        """Mitigations are the second half of the namespace: `AML.M0028@2026.08` → current."""
        state, _ = self._classify(loaded, FRAMEWORK, f"AML.M0028@{CURRENT}")
        assert state == "current"

    def test_present_at_prior_edition_is_valid_but_superseded(self, loaded):
        """
        Id present at the edition its token names, which is a priorVersions member → valid-but-superseded.

        The value is checked against ITS OWN edition (2025.10 via 5.0.1), never the current one.
        """
        state, detail = self._classify(loaded, FRAMEWORK, f"AML.T0001@{PRIOR}")
        assert state == "valid-but-superseded"
        assert detail is not None

    def test_present_only_at_prior_edition_is_still_valid_but_superseded(self, loaded):
        """
        AML.T0019 was dropped at 2026.08 but the value pins 5.0.1, where it exists → valid-but-superseded.

        Tier 2 never claims currency (D1a): a retained pin to a dropped id passes.
        """
        state, _ = self._classify(loaded, FRAMEWORK, f"AML.T0019@{PRIOR}")
        assert state == "valid-but-superseded"

    def test_absent_at_pinned_edition_present_at_current_is_invalid_naming_it(self, loaded):
        """
        AML.M0028@5.0.1: absent at 2025.10, present at 2026.08 → invalid; the detail names
        the value and `present at 2026.08` (the registered token, as re-pin guidance).
        """
        state, detail = self._classify(loaded, FRAMEWORK, f"AML.M0028@{PRIOR}")
        assert state == "invalid"
        assert detail is not None
        assert f"AML.M0028@{PRIOR}" in detail
        assert f"present at {CURRENT}" in detail

    def test_absent_at_current_present_at_prior_names_registered_token(self, loaded):
        """
        AML.T0019@2026.08: absent at 2026.08, present at 2025.10 → invalid; the detail names
        the edition by its REGISTERED token `5.0.1`, not the release `2025.10`, because the
        contributor re-pins with the registered token.

        Decision (ADR silent on which spelling): registered token.
        """
        state, detail = self._classify(loaded, FRAMEWORK, f"AML.T0019@{CURRENT}")
        assert state == "invalid"
        assert detail is not None
        assert f"present at {PRIOR}" in detail

    def test_absent_everywhere_is_invalid(self, loaded):
        """
        An id in no registered edition → invalid; the detail says `absent from every registered edition`.

        The detail wording is a test-level choice; the ADR does not fix it.
        """
        state, detail = self._classify(loaded, FRAMEWORK, f"AML.T9999@{PRIOR}")
        assert state == "invalid"
        assert detail is not None
        assert f"AML.T9999@{PRIOR}" in detail
        assert "absent from every registered edition" in detail
        assert "present at" not in detail

    def test_unregistered_token_is_invalid_agreeing_with_tier1(self, loaded):
        """
        `AML.T0001@2025.10`: the release exists in the manifest and the id exists there, but
        `2025.10` is not in version ∪ priorVersions → invalid, exactly as Tier 1 says.

        Pins that a Tier 1 `invalid` stands by computing Tier 1's verdict live.
        """
        value = f"AML.T0001@{PRIOR_RELEASE}"
        state, detail = self._classify(loaded, FRAMEWORK, value)
        assert state == "invalid"
        assert detail is not None and value in detail
        tier1_state, _ = self._tier1(loaded, FRAMEWORK, value)
        assert tier1_state == "invalid"

    def test_registered_but_unresolved_token_is_invalid_per_value(self, tmp_path):
        """
        D3b last paragraph: a value whose registered token resolves to no manifest entry is
        reported invalid with that reason, so no value falls through without a verdict.

        Unreachable through main() (D3c exits 2 first), so pinned at the unit level: the
        registry carries `7.7.7`, the manifest does not. The detail carries `unresolved`.
        """
        tree = build_tree(tmp_path, prior_tokens=[PRIOR, "7.7.7"], pattern=_pattern_for([PRIOR, CURRENT, "7.7.7"]))
        registry = load_registry(tree.frameworks)
        patterns = load_pinned_patterns(tree.schema)
        state, detail = classify_value(
            FRAMEWORK,
            "AML.T0001@7.7.7",
            registry=registry,
            pinned_patterns=patterns,
            catalogues=_catalogues_for(tree),
        )
        assert state == "invalid"
        assert detail is not None
        assert "unresolved" in detail

    def test_delimiter_less_legacy_value_is_skip_agreeing_with_tier1(self, loaded):
        """A versioned-framework value with neither `@` nor `:` is the legacy form → skip in both tiers."""
        state, detail = self._classify(loaded, FRAMEWORK, "AML.T0001")
        assert state == "skip"
        assert detail is None
        assert self._tier1(loaded, FRAMEWORK, "AML.T0001")[0] == "skip"

    def test_legacy_value_of_an_id_absent_everywhere_is_still_skip(self, loaded):
        """
        Boundary: skip is decided by form, not by membership. A delimiter-less value naming an
        id no edition contains is still skip — Tier 2 adjudicates pinned values only.
        """
        state, _ = self._classify(loaded, FRAMEWORK, "AML.T9999")
        assert state == "skip"

    @pytest.mark.parametrize(
        ("fw_id", "value"),
        [
            ("stride", "Tampering"),
            ("stride", "tampering"),
            ("nist-ai-rmf", "GOVERN-1.1@1.0"),
            ("owasp-top10-llm", "LLM01:2025"),
            ("iso-22989", "AI Producer@2022"),
            ("eu-ai-act", "Article 9@2024"),
        ],
    )
    def test_non_adjudicated_framework_values_are_skip(self, loaded, fw_id, value):
        """D5 / I-a: a value of a framework key not in the adjudicated table is skip, whatever its form."""
        state, detail = self._classify(loaded, fw_id, value)
        assert state == "skip"
        assert detail is None

    def test_non_adjudicated_value_invalid_under_tier1_is_still_skip(self, loaded):
        """
        Boundary: Tier 2 does not re-run Tier 1 on non-adjudicated frameworks. `GOVERN-1.1@9.9`
        is invalid under Tier 1, and skip here — Tier 1 owns that verdict.
        """
        assert self._tier1(loaded, "nist-ai-rmf", "GOVERN-1.1@9.9")[0] == "invalid"
        state, _ = self._classify(loaded, "nist-ai-rmf", "GOVERN-1.1@9.9")
        assert state == "skip"

    def test_unknown_framework_key_is_skip(self, loaded):
        """A framework key in neither the registry nor the table is skip (purity owns unknown keys)."""
        state, _ = self._classify(loaded, "not-a-framework", "X@1.0")
        assert state == "skip"


# ===========================================================================
# 3. Catalogue parsing (ADR-038 D3d) — through main(), the only path that reads files
# ===========================================================================


class TestCatalogueParsing:
    """D3d: ids are the keys of `techniques:` ∪ `mitigations:`; nothing else in the file counts."""

    def test_ids_are_keys_of_techniques_and_mitigations_maps(self, tmp_path, capsys):
        """A technique key, a sub-technique key and a mitigation key are all members → current, exit 0."""
        tree = build_tree(
            tmp_path,
            risks={FRAMEWORK: [f"AML.T0001@{CURRENT}", f"AML.T0001.000@{CURRENT}", f"AML.M0028@{CURRENT}"]},
        )
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 0, out + err
        counts = _summary_counts(out + err)
        assert counts["current"] == 3
        assert counts["invalid"] == 0

    def test_id_mentioned_in_prose_or_case_study_is_not_a_member(self, tmp_path, capsys):
        """
        AML.T0019 is referenced at 2026.08 by a description and a case-study list but is not a
        key of either map → `AML.T0019@2026.08` is invalid. Catches text-scanning parsers.
        """
        tree = build_tree(tmp_path, risks={FRAMEWORK: [f"AML.T0019@{CURRENT}"]})
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 1, out + err
        assert _summary_counts(out + err)["invalid"] == 1
        assert f"AML.T0019@{CURRENT}" in out + err

    def test_sub_technique_membership_is_read_from_the_file(self, tmp_path, capsys):
        """
        Through main(): `AML.T0001.001@2026.08` is invalid because the 2026.08 catalogue's
        `techniques:` map lacks that key, although it has `AML.T0001`. Pins the file-level
        half of the no-parent-fallback rule.
        """
        tree = build_tree(tmp_path, risks={FRAMEWORK: [f"AML.T0001.001@{CURRENT}", f"AML.T0001@{CURRENT}"]})
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        combined = out + err
        assert rc == 1, combined
        counts = _summary_counts(combined)
        assert counts["invalid"] == 1
        assert counts["current"] == 1
        assert f"AML.T0001.001@{CURRENT}" in combined

    def test_tactic_id_is_not_a_pin_target(self, tmp_path, capsys):
        """
        Boundary: a key of `tactics:` is not a member. `AML.TA0001` cannot be expressed in the
        pinned pattern, so the probe is a technique-shaped id planted as a tactic key.
        """
        tree = build_tree(tmp_path, risks={FRAMEWORK: [f"AML.T0777@{CURRENT}"]})
        doc = _catalogue_doc(CURRENT, CURRENT_TECHNIQUES, CURRENT_MITIGATIONS)
        doc["tactics"]["AML.T0777"] = {"name": "Mis-filed"}
        tree.write_catalogue_data(CURRENT, doc)
        tree.record_sums()
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 1, out + err
        assert f"AML.T0777@{CURRENT}" in out + err

    @pytest.mark.parametrize(
        "mutation_id",
        [
            "unparsable-catalogue",
            "empty-techniques-map",
            "missing-mitigations-key",
            "techniques-not-a-mapping",
            "catalogue-not-a-mapping",
        ],
    )
    def test_unparsable_catalogue_is_a_read_error_naming_the_file(self, tmp_path, capsys, mutation_id):
        """
        A catalogue that does not parse, or whose `techniques:`/`mitigations:` map is absent,
        not a mapping or empty, is a read error: exit 2, message names the file. Digests are
        regenerated by the mutation so this is the parse stage, not the digest stage, and the
        digest-mismatch message must not appear.
        """
        mutate, expected = _mutation(mutation_id)
        tree = build_tree(tmp_path)
        mutate(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        combined = out + err
        assert rc == 2, combined
        assert _names_any(combined, expected)
        assert DIGEST_MISMATCH not in combined

    def test_non_empty_maps_with_unrelated_extra_keys_are_fine(self, tmp_path, capsys):
        """Green control: extra top-level keys and a non-empty namespace parse cleanly, exit 0."""
        tree = build_tree(tmp_path)
        doc = _catalogue_doc(CURRENT, CURRENT_TECHNIQUES, CURRENT_MITIGATIONS)
        doc["future-block"] = {"anything": True}
        tree.write_catalogue_data(CURRENT, doc)
        tree.record_sums()
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 0, out + err


# ===========================================================================
# 4. Provenance guard (ADR-038 D4)
# ===========================================================================


class TestProvenanceGuard:
    """D4 stage 1: SHA256SUMS is verified before anything in the subdirectory is parsed."""

    def test_digest_mismatch_exits_2_naming_file_and_both_digests(self, tmp_path, capsys):
        """A tampered catalogue exits 2; the message names the file, the recorded digest and the actual digest."""
        tree = build_tree(tmp_path)
        recorded = tree.recorded_digest(f"ATLAS-{CURRENT}.yaml")
        _mut_digest_mismatch(tree)
        actual = hashlib.sha256(tree.catalogue_path(CURRENT).read_bytes()).hexdigest()
        assert recorded != actual
        rc, out, err = _invoke(_argv(tree), capsys)
        combined = out + err
        assert rc == 2, combined
        assert f"ATLAS-{CURRENT}.yaml" in combined
        assert DIGEST_MISMATCH in combined
        assert recorded in combined
        assert actual in combined

    def test_manifest_digest_mismatch_exits_2(self, tmp_path, capsys):
        """The manifest is in the record too: a tampered manifest exits 2 as a digest mismatch naming it."""
        tree = build_tree(tmp_path)
        with open(tree.fw_dir / "manifest.yaml", "ab") as fh:
            fh.write(b"\n# tamper\n")
        rc, out, err = _invoke(_argv(tree), capsys)
        assert rc == 2, out + err
        assert "manifest.yaml" in out + err
        assert DIGEST_MISMATCH in out + err

    @pytest.mark.parametrize(
        "mutation_id",
        ["listed-catalogue-absent", "manifest-missing", "manifest-unlisted", "sha256sums-missing"],
    )
    def test_record_integrity_failures_exit_2_naming_the_file(self, tmp_path, capsys, mutation_id):
        """A listed file absent, the manifest absent or unlisted, or the record itself absent: exit 2, named."""
        mutate, expected = _mutation(mutation_id)
        tree = build_tree(tmp_path)
        mutate(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        assert rc == 2, out + err
        assert _names_any(out + err, expected)

    @pytest.mark.parametrize(
        "mutation_id",
        [
            "sums-short-digest",
            "sums-non-hex-digest",
            "sums-no-separator",
            "sums-empty",
            "sums-name-with-slash",
            "sums-name-dotdot",
            "sums-duplicate-name-last-correct",
        ],
    )
    def test_malformed_or_out_of_scope_record_is_a_read_error(self, tmp_path, capsys, mutation_id):
        """
        D4 record format and scope. A digest that is not 64 hex characters, a line with no
        separator, and an empty record are malformed. For the two traversal cases every required
        line is intact and one ADDED line, digest-valid, names an existing file outside the
        subdirectory (`../../../risk-map/yaml/frameworks.yaml`, and an absolute `/` path); the
        error must name `SHA256SUMS`, so a lenient validator cannot pass via "manifest.yaml not
        listed". Decision: stricter than coreutils, which accepts both records (rc 0), because
        the record "covers nothing outside the subdirectory". A name listed twice, wrong digest
        first and right digest second, is also a read error, matching `sha256sum -c --strict`
        (rc 1); a last-wins reader is wrong. Exit 2 under `--force`.
        """
        mutate, expected = _mutation(mutation_id)
        tree = build_tree(tmp_path)
        mutate(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        assert rc == 2, out + err
        assert _names_any(out + err, expected)

    def test_required_catalogue_present_but_unlisted_exits_2(self, tmp_path, capsys):
        """D3c/D4 stage 3: a registered edition's catalogue on disk but absent from the record is a read error."""
        tree = build_tree(tmp_path)
        _mut_required_catalogue_unlisted(tree)
        assert tree.catalogue_path(CURRENT).is_file()
        rc, out, err = _invoke(_argv(tree), capsys)
        assert rc == 2, out + err
        assert f"ATLAS-{CURRENT}.yaml" in out + err

    def test_listed_file_for_unregistered_edition_must_still_exist(self, tmp_path, capsys):
        """
        "Every listed file must be present": a record line for a file that is not on disk is an
        error even when no registered edition needs that file.
        """
        tree = build_tree(tmp_path)
        tree.record_sums()
        sums = tree.fw_dir / "SHA256SUMS"
        sums.write_text(
            sums.read_text(encoding="utf-8") + f"{'0' * 64}  ATLAS-{UNREGISTERED}.yaml\n", encoding="utf-8"
        )
        rc, out, err = _invoke(_argv(tree), capsys)
        assert rc == 2, out + err
        assert f"ATLAS-{UNREGISTERED}.yaml" in out + err

    def test_extra_vendored_edition_listed_and_present_is_tolerated(self, tmp_path, capsys):
        """Green control: a correctly recorded catalogue for an unregistered edition changes nothing; exit 0."""
        tree = build_tree(tmp_path)
        tree.write_catalogue(UNREGISTERED, CURRENT_TECHNIQUES, CURRENT_MITIGATIONS)
        tree.record_sums()
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 0, out + err

    def test_source_and_license_are_never_read(self, tmp_path, capsys):
        """
        D2: SOURCE and LICENSE are provenance for reviewers, not validator inputs. With both
        files deleted the run exits 0 and produces the same output, verdict for verdict, as the
        run with them present. The corpus carries one invalid value so the compared verdicts are
        not all-zero. Red partner: a file the validator DOES read (manifest.yaml) exits 2 when
        deleted.
        """
        tree = build_tree(tmp_path, risks={FRAMEWORK: [f"AML.T0001@{PRIOR}", f"AML.M0028@{PRIOR}"]})
        with_files = _invoke(_argv(tree), capsys)
        (tree.fw_dir / "SOURCE").unlink()
        (tree.fw_dir / "LICENSE").unlink()
        without_files = _invoke(_argv(tree), capsys)
        assert with_files[0] == 0, with_files[1] + with_files[2]
        assert without_files == with_files
        assert _summary_counts(without_files[1] + without_files[2])["invalid"] == 1

    def test_record_is_reproducible_by_sha256sum_check(self, tmp_path):
        """
        Fixture control (green once the module exists): the record the fixture writes is what
        `sha256sum -c --strict SHA256SUMS` accepts, so stage 1 "by hand" (D4) matches the test's
        notion of the format. Guards the fixture, not the validator.
        """
        tree = build_tree(tmp_path)
        result = subprocess.run(
            ["sha256sum", "-c", "--strict", "SHA256SUMS"], cwd=tree.fw_dir, capture_output=True, text=True
        )
        assert result.returncode == 0, result.stdout + result.stderr


class TestManifestParsing:
    """
    D4 stage 2: manifest.yaml is parsed after its digest verifies, and D4 lists an unparsable
    manifest as a read error. Shape: a top-level list of entries, each carrying `release` and
    `versions` (the upstream `dist/manifest.yaml` shape). The record is regenerated by every
    mutation here, so these are parse-stage failures and must not read as digest mismatches.

    Deliberate stricter reading of ADR-038 D4: "unparsable" here covers a shape error on ANY
    entry, registered or not. D4 names only the unparsable manifest; the entry-level rule is
    this file's decision, taken because the manifest is a verbatim upstream copy whose every
    entry carried both keys when checked (37 entries, 2026-10-01). If an upstream entry ever
    lacks one, the gate goes red at the bump that vendors it, which is where it is cheapest.
    """

    @pytest.mark.parametrize(
        "mutation_id",
        [
            "manifest-unparsable",
            "manifest-not-a-list",
            "manifest-entry-without-release",
            "manifest-entry-without-versions",
        ],
    )
    def test_unparsable_or_misshapen_manifest_is_a_read_error(self, tmp_path, capsys, mutation_id):
        """
        Garbage YAML, a mapping instead of a list, or an entry lacking `release` / `versions`:
        exit 2 naming manifest.yaml, no digest-mismatch message. The misshapen entry is the
        UNREGISTERED 2025.09 one (decision: shape errors are not scoped to registered editions).
        """
        mutate, expected = _mutation(mutation_id)
        tree = build_tree(tmp_path)
        mutate(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        combined = out + err
        assert rc == 2, combined
        assert _names_any(combined, expected)
        assert DIGEST_MISMATCH not in combined

    def test_manifest_with_extra_entry_keys_is_fine(self, tmp_path, capsys):
        """Green control: an entry carrying keys beyond `release`/`release-date`/`versions` parses; exit 0."""
        tree = build_tree(tmp_path)
        manifest = copy.deepcopy(MANIFEST)
        manifest[1]["notes"] = "synthetic"
        tree.write_manifest(manifest)
        tree.record_sums()
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 0, out + err


# ===========================================================================
# 5. Required set (ADR-038 D3c) — eager, over every registered edition
# ===========================================================================


class TestRequiredSet:
    """
    D3c: every token in version ∪ priorVersions must resolve and have a verified catalogue,
    whether or not any value pins it. The fixture corpus pins only `5.0.1`, so every case
    here is detected without a pinning value.
    """

    def test_registered_current_edition_unresolved_in_manifest_exits_2(self, tmp_path, capsys):
        """
        A registry bump to `2026.10` without a manifest refresh. No value pins it;
        the run still exits 2 and names the token. Never downgraded to per-value invalid.
        """
        tree = build_tree(tmp_path)
        _mut_registered_current_unresolved(tree)
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 2, out + err
        assert "2026.10" in out + err
        assert not _summary_lines(out + err), "a read error aborts before any verdict summary"

    def test_registered_prior_edition_unresolved_exits_2(self, tmp_path, capsys):
        """A priorVersions versionId whose stripped token resolves nowhere is the same read error."""
        tree = build_tree(tmp_path)
        _mut_registered_prior_unresolved(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        assert rc == 2, out + err
        assert "7.7.7" in out + err

    def test_registered_edition_matching_every_entry_exits_2(self, tmp_path, capsys):
        """`6.0.0` as a registered token is ambiguous (every entry carries it) → unresolved → exit 2."""
        tree = build_tree(tmp_path)
        _mut_registered_edition_ambiguous(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        assert rc == 2, out + err
        assert "6.0.0" in out + err

    def test_registered_edition_catalogue_missing_exits_2_without_a_pinning_value(self, tmp_path, capsys):
        """The manifest resolves 2026.08 but its catalogue is absent and unlisted; nothing pins it → exit 2."""
        tree = build_tree(tmp_path)
        _mut_registered_catalogue_absent_and_unlisted(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        assert rc == 2, out + err
        assert f"ATLAS-{CURRENT}.yaml" in out + err

    def test_unregistered_manifest_entry_needs_no_catalogue(self, tmp_path, capsys):
        """Green control (D7a/D8): `2026.09` is in the manifest, unregistered and unvendored; exit 0."""
        tree = build_tree(tmp_path)
        assert not tree.catalogue_path(UNREGISTERED).exists()
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 0, out + err

    def test_prior_versions_are_stripped_from_versionids(self, tmp_path, capsys):
        """
        Green control for the `known_versions` stripping: priorVersions holds `mitre-atlas@5.0.1`,
        and the token `5.0.1` resolves. A check that tried to resolve the versionId literally
        would exit 2 here.
        """
        tree = build_tree(tmp_path)
        registry = load_registry(tree.frameworks)
        assert registry[FRAMEWORK]["priorVersions"] == [f"{FRAMEWORK}@{PRIOR}"]
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 0, out + err


# ===========================================================================
# 6. Two-stage order (ADR-038 D4)
# ===========================================================================


class TestTwoStageOrder:
    """D4: verify the record, then parse, then require the registered editions."""

    def test_digest_is_verified_before_parsing(self, tmp_path, capsys):
        """
        A catalogue that is both tampered (record stale) and unparsable fails as a digest mismatch:
        both digests are reported, which only the digest stage emits.
        """
        tree = build_tree(tmp_path)
        recorded = tree.recorded_digest(f"ATLAS-{CURRENT}.yaml")
        tree.catalogue_path(CURRENT).write_bytes(b"techniques: {AML.T0001: [unterminated\n")
        actual = hashlib.sha256(tree.catalogue_path(CURRENT).read_bytes()).hexdigest()
        rc, out, err = _invoke(_argv(tree), capsys)
        combined = out + err
        assert rc == 2, combined
        assert DIGEST_MISMATCH in combined
        assert recorded in combined
        assert actual in combined

    def test_manifest_digest_is_verified_before_parsing(self, tmp_path, capsys):
        """
        The same order for manifest.yaml: tampered (record stale) AND unparsable reports the
        digest mismatch with both digests, not a parse error. D4: "the manifest is parsed only
        after its digest is verified".
        """
        tree = build_tree(tmp_path)
        recorded = tree.recorded_digest("manifest.yaml")
        manifest = tree.fw_dir / "manifest.yaml"
        manifest.write_bytes(b"- release: {unterminated\n")
        actual = hashlib.sha256(manifest.read_bytes()).hexdigest()
        rc, out, err = _invoke(_argv(tree), capsys)
        combined = out + err
        assert rc == 2, combined
        assert "manifest.yaml" in combined
        assert DIGEST_MISMATCH in combined
        assert recorded in combined
        assert actual in combined

    def test_digest_is_verified_before_registry_completeness(self, tmp_path, capsys):
        """
        With a stale record AND an unresolvable registered token, the run stops at stage 1:
        the mismatch is reported and the token is not, because the manifest was never parsed.
        """
        tree = build_tree(tmp_path)
        _mut_registered_current_unresolved(tree)
        recorded = tree.recorded_digest(f"ATLAS-{PRIOR_RELEASE}.yaml")
        with open(tree.catalogue_path(PRIOR_RELEASE), "ab") as fh:
            fh.write(b"\n# tamper\n")
        rc, out, err = _invoke(_argv(tree), capsys)
        combined = out + err
        assert rc == 2, combined
        assert DIGEST_MISMATCH in combined
        assert recorded in combined
        assert "2026.10" not in combined

    def test_completeness_is_checked_after_a_clean_parse(self, tmp_path, capsys):
        """
        Record clean, manifest parses, a registered token still unresolved → the completeness
        error names the token, and the digest-mismatch message is absent (stage 1 passed).
        """
        tree = build_tree(tmp_path)
        _mut_registered_current_unresolved(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        combined = out + err
        assert rc == 2, combined
        assert "2026.10" in combined
        assert DIGEST_MISMATCH not in combined


# ===========================================================================
# 7. Adjudicated set (ADR-038 D5)
# ===========================================================================


class TestAdjudicatedSet:
    """D5: a module-level table; today exactly {mitre-atlas}; its two read-error classes."""

    def test_table_holds_exactly_mitre_atlas(self):
        """Today the adjudicated set is {mitre-atlas}; only the key set is pinned."""
        assert set(ADJUDICATED_FRAMEWORKS) == {FRAMEWORK}

    def test_table_key_absent_from_registry_exits_2(self, tmp_path, capsys):
        """
        A table key the registry does not carry is a read error naming the key beside the word
        `registry`. The bare key is not discriminating on its own: it is also a path segment.
        """
        tree = build_tree(tmp_path)
        _mut_table_key_absent_from_registry(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        combined = out + err
        assert rc == 2, combined
        assert FRAMEWORK in combined
        assert "registry" in combined

    def test_table_key_without_catalogue_subdirectory_exits_2(self, tmp_path, capsys):
        """
        A table key with no `<catalogue-dir>/<key>/` is a read error naming the key beside the
        phrase `no catalogue directory` (the bare word "catalogue" is in every path).

        This is the fail-closed half of the rejected "derive the set from the directories"
        alternative: deleting the directory must not turn the framework's values into skip.
        """
        tree = build_tree(tmp_path)
        _mut_table_key_without_subdirectory(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        combined = out + err
        assert rc == 2, combined
        assert FRAMEWORK in combined
        assert "no catalogue directory" in combined
        assert not _summary_lines(combined)

    def test_catalogue_root_missing_exits_2(self, tmp_path, capsys):
        """`--catalogue-dir` pointing nowhere is the same read error, not a silent skip."""
        tree = build_tree(tmp_path)
        shutil.rmtree(tree.catalogue_dir)
        rc, out, err = _invoke(_argv(tree), capsys)
        assert rc == 2, out + err

    def test_non_adjudicated_framework_needs_no_catalogue_directory(self, tmp_path, capsys):
        """Green control: nist-ai-rmf is registered with no subdirectory, and its values are skip; exit 0."""
        tree = build_tree(tmp_path, risks={"nist-ai-rmf": ["GOVERN-1.1@1.0"]})
        assert not (tree.catalogue_dir / "nist-ai-rmf").exists()
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 0, out + err
        assert _summary_counts(out + err)["skip"] == 1


# ===========================================================================
# 8. Per-flag contract (ADR-038 D4a)
# ===========================================================================


class TestPerFlagContract:
    """`--force` enables; `--block` escalates invalid to exit 1; read errors exit 2 regardless."""

    def test_without_force_prints_skip_line_no_summary_exits_0(self, tmp_path, capsys):
        """
        N-b: without `--force` the validator says it examined nothing, prints no summary line and
        exits 0 — even over a corpus carrying an invalid value.
        """
        tree = build_tree(tmp_path, risks={FRAMEWORK: [f"AML.T9999@{PRIOR}"]})
        rc, out, err = _invoke(_argv(tree, force=False), capsys)
        combined = out + err
        assert rc == 0, combined
        assert "skipping validation: --force not given" in combined
        assert not _summary_lines(combined)
        assert "AML.T9999" not in combined

    def test_without_force_reads_nothing(self, tmp_path, capsys):
        """
        Every input path points nowhere; a read would be a read error (exit 2). Exit 0 with the
        skip line proves nothing was opened (D4a: "no input was read").
        """
        missing = tmp_path / "missing"
        argv = [
            str(missing / "risks.yaml"),
            "--frameworks",
            str(missing / "frameworks.yaml"),
            "--schema",
            str(missing / "schema.json"),
            "--catalogue-dir",
            str(missing / "catalogues"),
        ]
        rc, out, err = _invoke(argv, capsys)
        assert rc == 0, out + err
        assert "skipping validation: --force not given" in out + err

    def test_without_force_block_still_exits_0(self, tmp_path, capsys):
        """
        `--block` alone does not enable: the skip path depends only on `--force`.

        Decision: D4a states the no-`--force` behaviour unconditionally, so `--block` without
        `--force` is the same skip (exit 0, skip line, no summary).
        """
        tree = build_tree(tmp_path, risks={FRAMEWORK: [f"AML.T9999@{PRIOR}"]})
        rc, out, err = _invoke(_argv(tree, force=False, block=True), capsys)
        assert rc == 0, out + err
        assert "skipping validation: --force not given" in out + err
        assert not _summary_lines(out + err)

    def test_force_warn_prints_invalid_detail_and_summary_exits_0(self, tmp_path, capsys):
        """Warn tier: the invalid value's detail line and the summary print; exit 0."""
        tree = build_tree(tmp_path, risks={FRAMEWORK: [f"AML.M0028@{PRIOR}"]})
        rc, out, err = _invoke(_argv(tree, block=False), capsys)
        combined = out + err
        assert rc == 0, combined
        assert f"AML.M0028@{PRIOR}" in combined
        assert f"present at {CURRENT}" in combined
        assert _summary_counts(combined)["invalid"] == 1

    def test_force_block_exits_1_with_identical_output(self, tmp_path, capsys):
        """
        D4a: output is identical in both modes, stream by stream; only the exit code differs
        (0 → 1). This is the CI-tier marker contract: the detail line prints under `--block` too.
        """
        tree = build_tree(tmp_path, risks={FRAMEWORK: [f"AML.M0028@{PRIOR}", f"AML.T0001@{CURRENT}"]})
        (warn_rc, warn_out, warn_err), (block_rc, block_out, block_err) = _run_block_and_warn(tree, capsys)
        assert warn_rc == 0
        assert block_rc == 1
        assert block_out == warn_out
        assert block_err == warn_err
        assert f"AML.M0028@{PRIOR}" in block_out + block_err

    def test_clean_corpus_exits_0_with_and_without_block(self, tmp_path, capsys):
        """The default fixture corpus (one retained `@5.0.1` value) exits 0 in both modes with invalid=0."""
        tree = build_tree(tmp_path)
        (warn_rc, warn_out, warn_err), (block_rc, block_out, block_err) = _run_block_and_warn(tree, capsys)
        assert warn_rc == 0, warn_out + warn_err
        assert block_rc == 0, block_out + block_err
        assert _summary_counts(block_out + block_err)["invalid"] == 0

    def test_superseded_is_informational_under_block(self, tmp_path, capsys):
        """valid-but-superseded never blocks: a corpus of retained prior-edition pins exits 0 under `--block`."""
        tree = build_tree(tmp_path, risks={FRAMEWORK: [f"AML.T0001@{PRIOR}", f"AML.T0019@{PRIOR}"]})
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 0, out + err
        counts = _summary_counts(out + err)
        assert counts["valid-but-superseded"] == 2
        assert counts["invalid"] == 0

    @pytest.mark.parametrize("block", [False, True], ids=["warn", "block"])
    @pytest.mark.parametrize(("mutation_id", "mutate", "expected"), READ_ERROR_MUTATIONS, ids=READ_ERROR_IDS)
    def test_read_error_exits_2_in_both_modes(self, tmp_path, capsys, block, mutation_id, mutate, expected):
        """
        Every D4 read-error class exits 2 identically with and without `--block`, never 0 under
        `--force`, and the message carries the file, token or key it concerns.
        """
        tree = build_tree(tmp_path)
        mutate(tree)
        rc, out, err = _invoke(_argv(tree, block=block), capsys)
        assert rc == 2, f"{mutation_id} ({'block' if block else 'warn'}): rc={rc}\n{out}{err}"
        assert _names_any(out + err, expected)

    # (file, framework, value, expected class) — the class is re-derived per value from the
    # edition model above: CURRENT_IDS / PRIOR_IDS membership, the registered token set
    # {5.0.1, 2026.08}, the delimiter rule, and the adjudicated set {mitre-atlas}.
    PARTITION_CORPUS: list[tuple[str, str, str, str]] = [
        ("risks", FRAMEWORK, f"AML.T0001@{CURRENT}", "current"),  # in CURRENT_IDS
        ("risks", FRAMEWORK, f"AML.M0028@{CURRENT}", "current"),  # in CURRENT_IDS
        ("risks", FRAMEWORK, f"AML.T0001@{PRIOR}", "valid-but-superseded"),  # in PRIOR_IDS, prior token
        ("risks", FRAMEWORK, f"AML.M0028@{PRIOR}", "invalid"),  # not in PRIOR_IDS (present at 2026.08)
        ("risks", FRAMEWORK, "AML.T0001", "skip"),  # delimiter-less legacy form
        ("risks", "stride", "Tampering", "skip"),  # non-adjudicated
        ("risks", "stride", "tampering", "skip"),  # non-adjudicated
        ("risks", "owasp-top10-llm", "LLM01:2025", "skip"),  # non-adjudicated
        ("controls", FRAMEWORK, f"AML.T9999@{PRIOR}", "invalid"),  # in no edition
        ("controls", "nist-ai-rmf", "GOVERN-1.1@1.0", "skip"),  # non-adjudicated
        ("controls", "iso-22989", "AI Producer@2022", "skip"),  # non-adjudicated
    ]

    def test_summary_partition_sums_to_value_count(self, tmp_path, capsys):
        """
        The four classes partition the input. The expected counts are derived from
        PARTITION_CORPUS (per-value classes), never written as literals, and every class is
        represented so no count is trivially zero.
        """
        corpus: dict[str, dict[str, list[str]]] = {"risks": {}, "controls": {}}
        for kind, fw_id, value, _ in self.PARTITION_CORPUS:
            corpus[kind].setdefault(fw_id, []).append(value)
        expected = Counter(cls for _, _, _, cls in self.PARTITION_CORPUS)
        assert set(expected) == set(CLASSES), "fixture must exercise every class"
        invalid_values = [v for _, _, v, cls in self.PARTITION_CORPUS if cls == "invalid"]

        tree = build_tree(tmp_path, risks=corpus["risks"], controls=corpus["controls"])
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        combined = out + err
        assert rc == 1, combined
        counts = _summary_counts(combined)
        assert counts == dict(expected)
        assert sum(counts.values()) == len(self.PARTITION_CORPUS)
        for value in invalid_values:
            assert value in combined

    @pytest.mark.parametrize("kind", ["risks", "controls", "components", "personas"])
    def test_values_in_every_content_file_are_counted(self, tmp_path, capsys, kind):
        """All four positionals are scanned: a value in any one of the four files reaches the summary."""
        tree = build_tree(tmp_path, risks={})
        tree.write_content(kind, {"iso-22989": ["AI Producer@2022"], FRAMEWORK: [f"AML.T0001@{CURRENT}"]})
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 0, out + err
        counts = _summary_counts(out + err)
        assert counts["skip"] == 1
        assert counts["current"] == 1
        assert sum(counts.values()) == 2

    @pytest.mark.parametrize("kind", ["risks", "controls", "components", "personas"])
    def test_entity_key_after_list_valued_preamble_is_scanned(self, tmp_path, capsys, kind):
        """
        The live files put list-valued keys (`description:`, and `categories:` for controls and
        components) BEFORE the entity key. A validator that scans only the first list-valued
        key reads prose, finds no mappings, prints all-zero counts and exits 0 on the live
        tree (ADR-037's vacuity class). This test verifies the fixture has that shape, then
        requires the invalid value under the entity key to reach the summary and block.
        Compare validate_mapping_drift.py::_scan_file, which iterates every list-valued key.
        """
        tree = build_tree(tmp_path, risks={})
        tree.write_content(kind, {FRAMEWORK: [f"AML.M0028@{PRIOR}"]})
        doc = yaml.safe_load(tree.content[kind].read_text(encoding="utf-8"))
        list_keys = [k for k, v in doc.items() if isinstance(v, list)]
        assert list_keys[0] == "description", list_keys
        assert list_keys[-1] == kind
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        combined = out + err
        assert rc == 1, combined
        counts = _summary_counts(combined)
        assert counts["invalid"] == 1
        assert sum(counts.values()) == 1
        assert f"AML.M0028@{PRIOR}" in combined

    def test_mappings_free_corpus_prints_zero_summary(self, tmp_path, capsys):
        """A corpus without any mappings is examined (summary printed, all zeros), not skipped."""
        tree = build_tree(tmp_path, risks={})
        rc, out, err = _invoke(_argv(tree, block=True), capsys)
        assert rc == 0, out + err
        assert sum(_summary_counts(out + err).values()) == 0


# ===========================================================================
# 9. CLI inputs (ADR-038 D3a)
# ===========================================================================


class TestCliInputs:
    """Every input is a CLI option with a `__file__`-anchored default; positionals override the four YAMLs."""

    @pytest.mark.parametrize("option", ["--frameworks", "--schema", "--catalogue-dir"])
    def test_each_override_is_honoured(self, tmp_path, capsys, option):
        """
        Pointing one override at a path that does not exist turns a clean run into exit 2, so the
        option is read rather than ignored in favour of the default.
        """
        tree = build_tree(tmp_path)
        argv = _argv(tree)
        idx = argv.index(option) + 1
        argv[idx] = str(tmp_path / "nowhere" / Path(argv[idx]).name)
        rc, out, err = _invoke(argv, capsys)
        assert rc == 2, out + err

    def test_overrides_point_the_run_at_the_given_tree(self, tmp_path, capsys):
        """
        Two trees differ only in the catalogue: the verdict follows `--catalogue-dir`. Pins that
        the override selects the data, not merely that the path is opened.
        """
        tree = build_tree(tmp_path / "a", risks={FRAMEWORK: [f"AML.T0115@{PRIOR}"]})
        other = build_tree(tmp_path / "b")
        other.write_catalogue(PRIOR_RELEASE, PRIOR_TECHNIQUES | {"AML.T0115"}, PRIOR_MITIGATIONS)
        other.record_sums()
        rc_a, out_a, err_a = _invoke(_argv(tree, block=True), capsys)
        argv_b = _argv(tree, block=True)
        argv_b[argv_b.index("--catalogue-dir") + 1] = str(other.catalogue_dir)
        rc_b, out_b, err_b = _invoke(argv_b, capsys)
        assert rc_a == 1, out_a + err_a
        assert rc_b == 0, out_b + err_b

    def test_positional_content_paths_override_the_defaults(self, tmp_path, capsys):
        """One positional file is the whole scan: the summary counts only its values."""
        tree = build_tree(tmp_path, risks={FRAMEWORK: [f"AML.T0001@{CURRENT}", f"AML.T0001@{PRIOR}", "AML.T0001"]})
        rc, out, err = _invoke(_argv(tree, block=True, paths=[str(tree.content["risks"])]), capsys)
        assert rc == 0, out + err
        assert sum(_summary_counts(out + err).values()) == 3

    def test_missing_content_positional_is_a_read_error(self, tmp_path, capsys):
        """
        A positional content path that does not exist exits 2 (decision: a content file the gate
        cannot read is a read failure under D4's "every read failure is a read error"; Tier 1
        returns 1 here, and Tier 2 refuses with the read-error code instead).
        """
        tree = build_tree(tmp_path)
        rc, out, err = _invoke(_argv(tree, paths=[str(tmp_path / "absent.yaml")]), capsys)
        assert rc == 2, out + err

    @pytest.mark.parametrize(
        "mutation_id",
        ["registry-unparsable", "registry-without-frameworks-array", "schema-without-pinned-block"],
    )
    def test_unreadable_registry_or_schema_is_a_read_error(self, tmp_path, capsys, mutation_id):
        """
        `--frameworks` that does not parse or has no `frameworks:` array, and `--schema` without
        the `framework-mapping-patterns-pinned` block, are read errors: exit 2 naming the file.
        The override tests above cover only a missing path; this covers an unreadable one.
        """
        mutate, expected = _mutation(mutation_id)
        tree = build_tree(tmp_path)
        mutate(tree)
        rc, out, err = _invoke(_argv(tree), capsys)
        assert rc == 2, out + err
        assert _names_any(out + err, expected)

    @pytest.mark.parametrize("block", [False, True], ids=["warn", "block"])
    def test_invalid_pinned_pattern_is_a_read_error(self, tmp_path, block):
        """
        D4/D4a: a `--schema` whose mitre-atlas pinned pattern is not a valid regex is an
        unparsable schema: exit 2 in both modes, naming the schema file, with no traceback.
        Run as a subprocess because an uncaught exception is what this pins against: in-process
        it would surface as a raised error rather than the exit 1 and traceback a hook sees.
        The default tree carries an adjudicated value, so classification is reached.
        """
        tree = build_tree(tmp_path)
        _mut_schema_invalid_pinned_pattern(tree)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_SCRIPT), *_argv(tree, block=block)],
            capture_output=True,
            text=True,
        )
        combined = result.stdout + result.stderr
        assert result.returncode == 2, combined
        assert "frameworks.schema.json" in combined
        assert "Traceback" not in combined

    # Content files that parse but hold no entity list. Each would otherwise contribute nothing
    # to the summary and let the gate report clean having read nothing from that file.
    ENTITY_LESS_CONTENT: list[tuple[str, str]] = [
        ("empty-file", ""),
        ("top-level-list", "- id: personaProbe\n  title: Probe\n"),
        ("mapping-of-scalars", "id: personas\ntitle: Personas\n"),
    ]

    @pytest.mark.parametrize("block", [False, True], ids=["warn", "block"])
    @pytest.mark.parametrize(
        ("shape", "text"), ENTITY_LESS_CONTENT, ids=[shape for shape, _ in ENTITY_LESS_CONTENT]
    )
    def test_entity_less_content_file_is_a_read_error(self, tmp_path, capsys, block, shape, text):
        """
        D4: a content file that is empty, is not a mapping, or is a mapping without a top-level
        list of entity mappings is a read error: exit 2 in both modes, naming the file. The
        other three files stay valid, so the run would otherwise print a non-empty summary.
        """
        tree = build_tree(tmp_path)
        tree.content["personas"].write_text(text, encoding="utf-8")
        rc, out, err = _invoke(_argv(tree, block=block), capsys)
        assert rc == 2, f"{shape} ({'block' if block else 'warn'}): rc={rc}\n{out}{err}"
        assert "personas.yaml" in out + err

    def test_default_catalogue_dir_is_file_anchored(self, tmp_path):
        """
        D2/D3a: DEFAULT_CATALOGUE_DIR is `<repo>/scripts/framework_catalogues`, absolute, when
        the module is imported from a cwd OUTSIDE the repository. Run in a subprocess with
        cwd=tmp_path, because from the repository root a cwd-relative `.resolve()` would give the
        same answer and the assertion would be vacuous. The behavioural partner is
        test_defaults_do_not_follow_the_process_cwd; this test pins the location itself.
        """
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from precommit.validate_mapping_catalogue import DEFAULT_CATALOGUE_DIR as d; print(d)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(REPO_ROOT / "scripts" / "hooks")],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        reported = Path(result.stdout.strip())
        assert reported.is_absolute()
        assert reported == LIVE_CATALOGUE_DIR
        assert DEFAULT_CATALOGUE_DIR is not None

    def test_defaults_do_not_follow_the_process_cwd(self, tmp_path):
        """
        L constraint 3: run twice with no options — once from a cwd that carries a complete,
        clean decoy tree in the repository layout, once from the repository root — and require
        identical exit code and output. A cwd-anchored validator would read the decoy from the
        first cwd and diverge. The assertion is lifecycle-stable: before the real catalogues
        exist both runs exit 2 the same way; after, both report the live corpus.
        """
        assert VALIDATOR_SCRIPT.is_file(), f"validator script missing: {VALIDATOR_SCRIPT}"
        build_tree(tmp_path)  # decoy at tmp_path/risk-map/..., tmp_path/scripts/framework_catalogues/...
        command = [sys.executable, str(VALIDATOR_SCRIPT), "--force"]
        from_decoy = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
        from_root = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True)
        assert from_decoy.returncode == from_root.returncode
        assert from_decoy.stdout == from_root.stdout
        assert from_decoy.stderr == from_root.stderr
        # The decoy itself is clean, so a cwd-anchored run from tmp_path would have exited 0 with
        # a one-value summary; pin that this is not what both runs produced.
        decoy_counts = _COUNT_RE.findall(from_decoy.stdout + from_decoy.stderr)
        assert dict(decoy_counts) != {"skip": "0", "current": "0", "valid-but-superseded": "1", "invalid": "0"}


# ===========================================================================
# 10. Live corpus (skipped until the edition flip vendors the real catalogues)
# ===========================================================================


def _live_value_count() -> int:
    """Count mapping values in the four live consumer YAMLs the way the validators iterate them."""
    count = 0
    for path in LIVE_CONTENT_FILES:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        for block in data.values():
            if not isinstance(block, list):
                continue
            for entity in block:
                mappings = entity.get("mappings") if isinstance(entity, dict) else None
                if not isinstance(mappings, dict):
                    continue
                for values in mappings.values():
                    if isinstance(values, list):
                        count += sum(1 for v in values if isinstance(v, str))
    return count


@pytest.mark.live_corpus
@pytest.mark.skipif(
    not (LIVE_CATALOGUE_DIR / FRAMEWORK).is_dir(),
    reason="vendored catalogues are absent from the tree; D5 exits 2 without them",
)
class TestLiveCorpus:
    """Smoke test over the real tree: defaults, `--force --block`, exit 0, counts partition the corpus."""

    def test_live_corpus_partition_and_exit_0(self, capsys):
        """The four summary counts sum to the live value count (derived, not pinned) and the run exits 0."""
        rc, out, err = _invoke(["--force", "--block"], capsys)
        assert rc == 0, out + err
        counts = _summary_counts(out + err)
        assert sum(counts.values()) == _live_value_count()
