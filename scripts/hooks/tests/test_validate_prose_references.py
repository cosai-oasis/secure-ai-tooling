#!/usr/bin/env python3
r"""
Tests for scripts/hooks/precommit/validate_prose_references.py

This module tests the pre-commit lint that enforces ADR-016 D6 semantic
reference rules against prose fields in risk-map/yaml/{risks,controls,
components,personas}.yaml.

Pattern lineage: mirrors validate_identification_questions.py / its test suite
(commit 627f236, sub-PR A5) and the sibling subset linter test suite.
Direct-import style for unit tests; subprocess for end-to-end CLI behavior.
Same warn/block toggle, same stderr-format convention, same sys.path injection.

API shape committed to by this test suite
==========================================
Module: precommit.validate_prose_references

Importable names:
    ProseField   — NamedTuple(file_path: Path, entry_id: str, field_name: str,
                               index: int | None, raw_text: str,
                               tokens: list[Token])
                   (same shape as the subset linter's ProseField — both import
                   from the tokenizer and share the same NamedTuple definition,
                   or one module re-exports the other's definition)
    Diagnostic   — NamedTuple(hook_id: str, file_path: Path, entry_id: str,
                               field_name: str, index: int | None, reason: str)
    IdIndex      — NamedTuple(
                       risks: frozenset[str],
                       controls: frozenset[str],
                       components: frozenset[str],
                       personas: frozenset[str],
                       ext_refs: dict[str, frozenset[str]],
                                # entry_id → frozenset of externalReferences ids
                   )
    find_prose_fields(yaml_path: Path, schema_dir: Path) -> Iterator[ProseField]
    build_id_index(yaml_paths: list[Path]) -> IdIndex
    check_references(field: ProseField, id_index: IdIndex) -> list[Diagnostic]
    main(argv: list[str] | None = None) -> NoReturn

Diagnostic format (committed):
    validate-prose-references: <file>:<entry-id>:<field>[<index>]: <reason>

    Regex: r'^validate-prose-references: [^:]+:[^:]+:[^\[]+\[\d+\]: .+$'

Warn-only mode (default):
    - Always exits 0; diagnostics printed to stderr.
Block mode (--block flag):
    - Exits 1 if any diagnostics; exits 0 if clean.
Usage error / unreadable file: exits 2.

Fixture corpus:
    scripts/hooks/tests/fixtures/wrapper_linters/
    — valid/                   : clean YAML passing both linters
    — reference_violations/    : YAML triggering reference violations only
    — schemas/                 : minimal mock schemas for introspection tests

The tokenizer (_prose_tokens.py, locked at 25e3d22) is NOT modified.
The prose_subset/ fixture directory is NOT modified.

Test Coverage
=============
Total tests: 73 across 11 test classes

TestSchemaProseFieldDiscovery      —  5 tests
TestBuildIdIndex                   —  7 tests
TestIntraDocSentinelResolution     —  9 tests
TestCrossEntitySentinelResolution  —  6 tests
TestExternalRefSentinelResolution  —  7 tests
TestBareCamelCaseRejection         —  6 tests
TestInlineUrlRejection             —  5 tests
TestRawHtmlTagRejection            —  4 tests
TestMultiClassViolations           —  4 tests
TestCLIExitCodes                   —  9 tests
TestEdgeCases                      — 11 tests

Coverage areas:
    find_prose_fields:   same schema-driven introspection as subset linter
    build_id_index:      union of all entity IDs + per-entry externalReferences
    check_references:    SENTINEL_INTRA resolution, SENTINEL_REF resolution,
                         INVALID_CAMELCASE_ID, INVALID_URL, INVALID_HTML,
                         multi-class, per-entry ext-ref scope
    main():              warn/block toggle, exit codes, multi-file walk
    Diagnostic format:   prefix, colon-separated fields, index bracket
    Edge cases:          unclosed {{, dotted ref ID, no ext refs, empty corpus
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# sys.path injection — mirrors A5 pattern
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent / "precommit"))

# Deferred import: wrapping in try/except lets pytest collect tests even when
# the module under test cannot be imported.  The _IMPORT_ERROR variable is
# checked by a module-scoped autouse fixture that re-raises the error at test
# execution time, producing ImportError failures rather than collection errors.
# When the import succeeds, _IMPORT_ERROR is None.
try:
    from validate_prose_references import (  # noqa: E402
        IdIndex,
        ProseField,
        build_id_index,
        check_references,
        find_prose_fields,
        main,
    )

    _IMPORT_ERROR: Exception | None = None
except ImportError as _e:
    _IMPORT_ERROR = _e
    # Stub names so module-level references do not raise NameError at load time.
    IdIndex = None  # type: ignore[assignment,misc]
    ProseField = None  # type: ignore[assignment,misc]
    build_id_index = None  # type: ignore[assignment]
    check_references = None  # type: ignore[assignment]
    find_prose_fields = None  # type: ignore[assignment]
    main = None  # type: ignore[assignment]


@pytest.fixture(autouse=True)
def _require_module_under_test():
    """Fail every test with ImportError when the implementation module is absent."""
    if _IMPORT_ERROR is not None:
        raise _IMPORT_ERROR


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "wrapper_linters"
_SCHEMA_DIR = _FIXTURE_ROOT / "schemas"
_VALID_DIR = _FIXTURE_ROOT / "valid"
_REF_VIOL_DIR = _FIXTURE_ROOT / "reference_violations"
_HOOK_MODULE = Path(__file__).parent.parent / "precommit" / "validate_prose_references.py"
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# ---------------------------------------------------------------------------
# Committed diagnostic format regex
#
# Field segment allows dotted paths (e.g. "tourContent.introduced").
# The references linter embeds the token value directly in reason strings
# (e.g. "... at 'riskBaz'"); the regex matches any non-empty reason.
# ---------------------------------------------------------------------------
_DIAG_PATTERN = re.compile(r"^validate-prose-references: [^:]+:[^:]+:[^:\[]+(?:\.[^:\[]+)*\[\d+\]: .+$")

# ---------------------------------------------------------------------------
# Helpers for building synthetic YAML and schema fixtures
# ---------------------------------------------------------------------------


def _prose_ref() -> dict:
    r"""Return the $ref dict for a prose field."""
    return {"$ref": "riskmap.schema.json#/definitions/utils/text"}


def _write_mock_schema(tmp_path: Path, entity: str, ids: list[str], extra_props: dict | None = None) -> Path:
    r"""Write a minimal schema JSON with the given entity's ID enum and prose fields.

    Args:
        tmp_path:    Directory to write the schema file into.
        entity:      Singular entity name ('risk', 'control', etc.).
        ids:         IDs to enumerate in the schema enum.
        extra_props: Additional property definitions merged into entity properties.
    """
    props: dict = {
        "id": {"type": "string", "enum": ids},
        "title": {"type": "string"},
        "description": _prose_ref(),
    }
    if extra_props:
        props.update(extra_props)
    schema = {
        "$id": f"mock_{entity}s.schema.json",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {f"{entity}s": {"type": "array", "items": {"$ref": f"#/definitions/{entity}"}}},
        "definitions": {entity: {"type": "object", "properties": props}},
    }
    path = tmp_path / f"{entity}s.schema.json"
    path.write_text(json.dumps(schema))
    return path


def _write_yaml(tmp_path: Path, name: str, content: dict) -> Path:
    r"""Write a YAML file from a dict and return the path."""
    p = tmp_path / name
    p.write_text(yaml.dump(content))
    return p


def _make_risk(risk_id: str, description: list[str] | None = None, ext_refs: list[dict] | None = None) -> dict:
    r"""Build a minimal risk entry dict, optionally with a description and externalReferences."""
    entry: dict = {"id": risk_id, "title": f"Title {risk_id}"}
    if description is not None:
        entry["description"] = description
    if ext_refs is not None:
        entry["externalReferences"] = ext_refs
    return entry


def _make_control(control_id: str, description: list[str] | None = None) -> dict:
    r"""Build a minimal control entry dict."""
    entry: dict = {"id": control_id, "title": f"Title {control_id}"}
    if description is not None:
        entry["description"] = description
    return entry


def _make_index(
    risks: list[str] | None = None,
    controls: list[str] | None = None,
    components: list[str] | None = None,
    personas: list[str] | None = None,
    ext_refs: dict[str, list[str]] | None = None,
) -> "IdIndex":
    r"""Build an IdIndex directly from lists.

    Args:
        risks:      Risk ID strings.
        controls:   Control ID strings.
        components: Component ID strings.
        personas:   Persona ID strings.
        ext_refs:   Mapping entry_id → list of externalReferences ids.
    """
    return IdIndex(
        risks=frozenset(risks or []),
        controls=frozenset(controls or []),
        components=frozenset(components or []),
        personas=frozenset(personas or []),
        ext_refs={k: frozenset(v) for k, v in (ext_refs or {}).items()},
    )


def _make_field(
    raw_text: str,
    entry_id: str = "riskAlpha",
    field_name: str = "description",
    index: int = 0,
    file_path: Path | None = None,
) -> "ProseField":
    r"""Build a ProseField with tokens populated from the tokenizer."""
    from precommit._prose_tokens import tokenize  # noqa: PLC0415

    return ProseField(
        file_path=file_path or Path("risks.yaml"),
        entry_id=entry_id,
        field_name=field_name,
        index=index,
        raw_text=raw_text,
        tokens=tokenize(raw_text),
    )


# ===========================================================================
# TestSchemaProseFieldDiscovery
# ===========================================================================


class TestSchemaProseFieldDiscovery:
    r"""find_prose_fields() discovers prose fields via schema $ref introspection.

    Uses the same introspection idiom as the subset linter's find_prose_fields.
    Both linters may share the same implementation or duplicate it; the test
    contract is identical.
    """

    def test_finds_description_in_controls_schema(self, tmp_path):
        r"""
        find_prose_fields discovers description as a prose field via $ref.

        Given: A controls YAML and schema marking description as utils/text
        When: find_prose_fields is called
        Then: ProseFields are yielded for the description field
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        _write_mock_schema(schema_dir, "control", ["controlAlpha"])
        yaml_path = _write_yaml(
            tmp_path,
            "controls.yaml",
            {"controls": [_make_control("controlAlpha", description=["Prose."])]},
        )
        fields = list(find_prose_fields(yaml_path, schema_dir))
        assert any(f.field_name == "description" for f in fields)

    def test_entry_id_is_propagated_to_prose_field(self, tmp_path):
        r"""
        ProseField.entry_id matches the YAML entry's id value.

        Given: A risk entry with id 'riskBeta' and a description
        When: find_prose_fields is called
        Then: The yielded ProseField has entry_id == 'riskBeta'
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        _write_mock_schema(schema_dir, "risk", ["riskBeta"])
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {"risks": [_make_risk("riskBeta", description=["Prose."])]},
        )
        fields = list(find_prose_fields(yaml_path, schema_dir))
        assert any(f.entry_id == "riskBeta" for f in fields)

    def test_multi_entry_yaml_all_entries_visited(self, tmp_path):
        r"""
        find_prose_fields enumerates all entries in a multi-entry YAML.

        Given: A YAML with 3 risk entries each with a description
        When: find_prose_fields is called
        Then: ProseFields are yielded for all 3 entry IDs
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        _write_mock_schema(schema_dir, "risk", ["riskAlpha", "riskBeta", "riskGamma"])
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {
                "risks": [
                    _make_risk("riskAlpha", description=["Prose A."]),
                    _make_risk("riskBeta", description=["Prose B."]),
                    _make_risk("riskGamma", description=["Prose C."]),
                ]
            },
        )
        fields = list(find_prose_fields(yaml_path, schema_dir))
        ids = {f.entry_id for f in fields}
        assert {"riskAlpha", "riskBeta", "riskGamma"} <= ids

    def test_fixture_valid_dir_does_not_crash(self):
        r"""
        find_prose_fields does not crash on the valid/ fixture YAML files.

        Given: valid/single_clean_risk.yaml and the fixture schema dir
        When: find_prose_fields is called
        Then: No exception; returns a list
        """
        yaml_path = _VALID_DIR / "single_clean_risk.yaml"
        fields = list(find_prose_fields(yaml_path, _SCHEMA_DIR))
        assert isinstance(fields, list)

    def test_paragraph_index_matches_array_position(self, tmp_path):
        r"""
        ProseField.index matches the paragraph's position in the prose array.

        Given: A description with 2 paragraphs
        When: find_prose_fields is called
        Then: ProseFields are yielded with indices 0 and 1
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"])
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {"risks": [_make_risk("riskAlpha", description=["Para 0.", "Para 1."])]},
        )
        fields = [f for f in find_prose_fields(yaml_path, schema_dir) if f.field_name == "description"]
        assert {0, 1} <= {f.index for f in fields}

    def test_nested_object_prose_fields_discovered(self, tmp_path):
        r"""
        Nested prose fields in object properties (e.g. tourContent.introduced) are
        discovered by find_prose_fields via schema introspection.

        Given: A schema with tourContent.introduced/exposed/mitigated prose sub-fields
        When: find_prose_fields is called on a YAML with tourContent data
        Then: ProseFields are yielded with dotted field names like 'tourContent.introduced'
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = _prose_ref()
        tour_content_prop = {
            "type": "object",
            "properties": {
                "introduced": prose_ref,
                "exposed": prose_ref,
            },
        }
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"], extra_props={"tourContent": tour_content_prop})
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {
                "risks": [
                    {
                        "id": "riskAlpha",
                        "title": "Alpha",
                        "tourContent": {
                            "introduced": ["Intro text."],
                            "exposed": ["Exposed text."],
                        },
                    }
                ]
            },
        )
        fields = list(find_prose_fields(yaml_path, schema_dir))
        field_names = {f.field_name for f in fields}
        assert "tourContent.introduced" in field_names
        assert "tourContent.exposed" in field_names


# ===========================================================================
# TestBuildIdIndex
# ===========================================================================


class TestBuildIdIndex:
    r"""build_id_index() constructs the union of IDs and per-entry ext refs.

    The function accepts a list of YAML paths (any of risks/controls/components/
    personas) and returns an IdIndex containing all entity IDs in the union
    plus per-entry externalReferences id sets.
    """

    def test_risks_ids_collected(self, tmp_path):
        r"""
        build_id_index extracts risk IDs from a risks YAML file.

        Given: A risks YAML with ids 'riskAlpha' and 'riskBeta'
        When: build_id_index is called with that file
        Then: IdIndex.risks contains 'riskAlpha' and 'riskBeta'
        """
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {"risks": [_make_risk("riskAlpha"), _make_risk("riskBeta")]},
        )
        idx = build_id_index([yaml_path])
        assert "riskAlpha" in idx.risks
        assert "riskBeta" in idx.risks

    def test_controls_ids_collected(self, tmp_path):
        r"""
        build_id_index extracts control IDs from a controls YAML file.

        Given: A controls YAML with id 'controlAlpha'
        When: build_id_index is called with that file
        Then: IdIndex.controls contains 'controlAlpha'
        """
        yaml_path = _write_yaml(tmp_path, "controls.yaml", {"controls": [_make_control("controlAlpha")]})
        idx = build_id_index([yaml_path])
        assert "controlAlpha" in idx.controls

    def test_ext_refs_collected_per_entry(self, tmp_path):
        r"""
        build_id_index populates ext_refs with per-entry externalReferences IDs.

        Given: A risk entry with externalReferences containing id 'cwe-89'
        When: build_id_index is called
        Then: IdIndex.ext_refs['riskAlpha'] contains 'cwe-89'
        """
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {
                "risks": [
                    _make_risk(
                        "riskAlpha",
                        ext_refs=[
                            {"type": "cwe", "id": "cwe-89", "title": "CWE-89", "url": "https://example.com"}
                        ],
                    )
                ]
            },
        )
        idx = build_id_index([yaml_path])
        assert "cwe-89" in idx.ext_refs.get("riskAlpha", frozenset())

    def test_multi_file_index_union(self, tmp_path):
        r"""
        build_id_index takes the union of IDs from multiple YAML files.

        Given: A risks YAML with 'riskAlpha' and a controls YAML with 'controlAlpha'
        When: build_id_index is called with both files
        Then: IdIndex contains both risk and control IDs
        """
        risks_yaml = _write_yaml(tmp_path, "risks.yaml", {"risks": [_make_risk("riskAlpha")]})
        controls_yaml = _write_yaml(tmp_path, "controls.yaml", {"controls": [_make_control("controlAlpha")]})
        idx = build_id_index([risks_yaml, controls_yaml])
        assert "riskAlpha" in idx.risks
        assert "controlAlpha" in idx.controls

    def test_ext_refs_scope_is_per_entry_not_global(self, tmp_path):
        r"""
        ext_refs in IdIndex are scoped per-entry, not cross-entry.

        Given: Two risk entries each with different externalReferences
        When: build_id_index is called
        Then: 'cwe-89' is in riskAlpha's ext_refs but NOT in riskBeta's ext_refs
        """
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {
                "risks": [
                    _make_risk(
                        "riskAlpha",
                        ext_refs=[{"type": "cwe", "id": "cwe-89", "title": "T", "url": "https://example.com"}],
                    ),
                    _make_risk(
                        "riskBeta",
                        ext_refs=[
                            {"type": "paper", "id": "smith-2023", "title": "T2", "url": "https://example.com/2"}
                        ],
                    ),
                ]
            },
        )
        idx = build_id_index([yaml_path])
        assert "cwe-89" in idx.ext_refs.get("riskAlpha", frozenset())
        assert "cwe-89" not in idx.ext_refs.get("riskBeta", frozenset())
        assert "smith-2023" in idx.ext_refs.get("riskBeta", frozenset())

    def test_entry_without_ext_refs_has_empty_set(self, tmp_path):
        r"""
        An entry with no externalReferences has an empty set in IdIndex.ext_refs.

        Given: A risk entry with no externalReferences field
        When: build_id_index is called
        Then: ext_refs.get('riskAlpha', frozenset()) is an empty frozenset
        """
        yaml_path = _write_yaml(tmp_path, "risks.yaml", {"risks": [_make_risk("riskAlpha")]})
        idx = build_id_index([yaml_path])
        ext = idx.ext_refs.get("riskAlpha", frozenset())
        assert len(ext) == 0

    def test_dotted_ref_id_is_preserved(self, tmp_path):
        r"""
        Dotted identifiers like 'nist-ai-rmf-1.0' in externalReferences are preserved.

        Given: A risk entry with externalReferences id 'nist-ai-rmf-1.0'
        When: build_id_index is called
        Then: IdIndex.ext_refs['riskAlpha'] contains 'nist-ai-rmf-1.0'
        """
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {
                "risks": [
                    _make_risk(
                        "riskAlpha",
                        ext_refs=[
                            {
                                "type": "spec",
                                "id": "nist-ai-rmf-1.0",
                                "title": "NIST AI RMF",
                                "url": "https://example.com",
                            }
                        ],
                    )
                ]
            },
        )
        idx = build_id_index([yaml_path])
        assert "nist-ai-rmf-1.0" in idx.ext_refs.get("riskAlpha", frozenset())

    def test_non_entity_yaml_shape_contributes_zero_ids(self):
        r"""
        build_id_index gracefully skips YAML files with non-entity top-level shapes.

        Given: The non_entity_shape.yaml fixture (dict-of-configs, no list-of-entries)
        When: build_id_index is called with that file
        Then: No error; returned IdIndex has zero IDs from that file
        """
        yaml_path = _FIXTURE_ROOT / "non_entity_shape.yaml"
        idx = build_id_index([yaml_path])
        assert len(idx.risks) == 0
        assert len(idx.controls) == 0
        assert len(idx.components) == 0
        assert len(idx.personas) == 0

    def test_non_entity_yaml_does_not_raise_on_non_list_value(self, tmp_path):
        r"""
        build_id_index does not raise when a known key (e.g. 'risks') maps to a dict
        rather than a list (as in mermaid-styles.yaml).

        Given: A YAML where risks: is a dict (not a list)
        When: build_id_index is called
        Then: No TypeError/AttributeError; returned index has zero risks
        """
        yaml_path = _write_yaml(
            tmp_path,
            "mermaid_styles.yaml",
            {"risks": {"defaultColor": "#ff0000", "highlightColor": "#ff6600"}},
        )
        idx = build_id_index([yaml_path])
        assert len(idx.risks) == 0


# ===========================================================================
# TestIntraDocSentinelResolution
# ===========================================================================


class TestIntraDocSentinelResolution:
    r"""{{riskFoo}}, {{controlFoo}}, etc. are resolved against the IdIndex.

    ADR-016 D6: for each SENTINEL_INTRA token, assert the inner ID exists in
    the corresponding entity set (risk IDs for risk-prefix, etc.).
    """

    def test_resolved_risk_sentinel_produces_no_diagnostic(self):
        r"""
        {{riskAlpha}} resolves against IdIndex.risks that contains 'riskAlpha'.

        Given: Prose '{{riskAlpha}} is related.' and IdIndex.risks={'riskAlpha'}
        When: check_references is called
        Then: Returns no diagnostics
        """
        idx = _make_index(risks=["riskAlpha"])
        field = _make_field("{{riskAlpha}} is related.")
        assert check_references(field, idx) == []

    def test_unresolved_risk_sentinel_produces_diagnostic(self):
        r"""
        {{riskDoesNotExist}} with an empty risk ID set produces one diagnostic.

        Given: Prose '{{riskDoesNotExist}} is mentioned.' and IdIndex.risks={}
        When: check_references is called
        Then: Exactly one Diagnostic is returned with reason referencing the ID
        """
        idx = _make_index(risks=[])
        field = _make_field("{{riskDoesNotExist}} is mentioned.")
        diags = check_references(field, idx)
        assert len(diags) == 1
        assert "riskDoesNotExist" in diags[0].reason

    def test_resolved_control_sentinel_produces_no_diagnostic(self):
        r"""
        {{controlAlpha}} resolves against IdIndex.controls containing 'controlAlpha'.

        Given: Prose '{{controlAlpha}} mitigates this.' and IdIndex.controls={'controlAlpha'}
        When: check_references is called
        Then: Returns no diagnostics
        """
        idx = _make_index(controls=["controlAlpha"])
        field = _make_field("{{controlAlpha}} mitigates this.")
        assert check_references(field, idx) == []

    def test_unresolved_control_sentinel_produces_diagnostic(self):
        r"""
        {{controlUnknown}} not in IdIndex.controls produces one diagnostic.

        Given: Prose '{{controlUnknown}}.' and IdIndex.controls={}
        When: check_references is called
        Then: One Diagnostic with reason naming the unresolved ID
        """
        idx = _make_index(controls=[])
        field = _make_field("{{controlUnknown}}.")
        diags = check_references(field, idx)
        assert len(diags) == 1
        assert "controlUnknown" in diags[0].reason

    def test_resolved_component_sentinel_produces_no_diagnostic(self):
        r"""
        {{componentAlpha}} resolves against IdIndex.components containing 'componentAlpha'.

        Given: Prose '{{componentAlpha}} processes input.' and IdIndex.components={'componentAlpha'}
        When: check_references is called
        Then: Returns no diagnostics
        """
        idx = _make_index(components=["componentAlpha"])
        field = _make_field("{{componentAlpha}} processes input.")
        assert check_references(field, idx) == []

    def test_resolved_persona_sentinel_produces_no_diagnostic(self):
        r"""
        {{personaAlpha}} resolves against IdIndex.personas containing 'personaAlpha'.

        Given: Prose '{{personaAlpha}} is responsible.' and IdIndex.personas={'personaAlpha'}
        When: check_references is called
        Then: Returns no diagnostics
        """
        idx = _make_index(personas=["personaAlpha"])
        field = _make_field("{{personaAlpha}} is responsible.")
        assert check_references(field, idx) == []

    def test_two_sentinels_one_unresolved_produces_one_diagnostic(self):
        r"""
        When two sentinels are present and one is unresolved, exactly one diagnostic.

        Given: Prose '{{riskAlpha}} and {{riskMissing}}.' with only riskAlpha in the index
        When: check_references is called
        Then: Exactly one Diagnostic for riskMissing only
        """
        idx = _make_index(risks=["riskAlpha"])
        field = _make_field("{{riskAlpha}} and {{riskMissing}}.")
        diags = check_references(field, idx)
        assert len(diags) == 1
        assert "riskMissing" in diags[0].reason

    def test_fixture_intra_doc_sentinels_valid_resolves_cleanly(self, tmp_path):
        r"""
        The valid/intra_doc_sentinels.yaml fixture resolves without diagnostics.

        Given: valid/intra_doc_sentinels.yaml with {{riskBeta}}, {{controlAlpha}},
               {{riskGamma}} and an IdIndex containing all those IDs
        When: find_prose_fields + check_references are called
        Then: No diagnostics are returned
        """
        yaml_path = _VALID_DIR / "intra_doc_sentinels.yaml"
        idx = _make_index(
            risks=["riskAlpha", "riskBeta", "riskGamma", "riskDelta"],
            controls=["controlAlpha", "controlBeta", "controlGamma"],
        )
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_references(field, idx))
        assert all_diags == []

    def test_fixture_unresolved_intra_doc_produces_diagnostic(self):
        r"""
        The reference_violations/unresolved_intra_doc.yaml fixture produces diagnostics.

        Given: A risk with {{riskDoesNotExist}} and an empty risk ID index
        When: find_prose_fields + check_references are called
        Then: At least one Diagnostic is returned
        """
        yaml_path = _REF_VIOL_DIR / "unresolved_intra_doc.yaml"
        idx = _make_index(risks=[])
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_references(field, idx))
        assert len(all_diags) >= 1


# ===========================================================================
# TestCrossEntitySentinelResolution
# ===========================================================================


class TestCrossEntitySentinelResolution:
    r"""Sentinel prefix must match the entity being looked up.

    {{riskFoo}} resolves against risks only; {{controlFoo}} resolves against
    controls only.  Mismatched prefix (e.g. risk ID in control sentinel) fails.
    """

    def test_risk_prefix_resolves_against_risk_set_only(self):
        r"""
        {{riskAlpha}} resolves against risks, not controls.

        Given: IdIndex.risks={'riskAlpha'} and IdIndex.controls={}
        When: check_references is called on 'See {{riskAlpha}}.'
        Then: No diagnostic (riskAlpha is in risks)
        """
        idx = _make_index(risks=["riskAlpha"], controls=[])
        field = _make_field("See {{riskAlpha}}.")
        assert check_references(field, idx) == []

    def test_control_prefix_resolves_against_control_set_only(self):
        r"""
        {{controlAlpha}} resolves against controls, not risks.

        Given: IdIndex.controls={'controlAlpha'} and IdIndex.risks={}
        When: check_references is called on 'See {{controlAlpha}}.'
        Then: No diagnostic (controlAlpha is in controls)
        """
        idx = _make_index(controls=["controlAlpha"], risks=[])
        field = _make_field("See {{controlAlpha}}.")
        assert check_references(field, idx) == []

    def test_risk_id_in_control_prefix_fails_resolution(self):
        r"""
        A risk ID referenced via {{controlXxx}} syntax is not resolved.

        Given: IdIndex.risks={'riskAlpha'} only; no 'controlAlpha' in controls
        When: check_references is called on '{{controlAlpha}}.'
        Then: One Diagnostic (controlAlpha is not in controls even though riskAlpha is in risks)
        """
        idx = _make_index(risks=["riskAlpha"], controls=[])
        field = _make_field("{{controlAlpha}}.")
        diags = check_references(field, idx)
        assert len(diags) == 1

    def test_persona_prefix_resolves_against_personas(self):
        r"""
        {{personaAlpha}} resolves against personas, not risks or controls.

        Given: IdIndex.personas={'personaAlpha'}
        When: check_references is called
        Then: No diagnostic
        """
        idx = _make_index(personas=["personaAlpha"])
        field = _make_field("{{personaAlpha}} is responsible.")
        assert check_references(field, idx) == []

    def test_component_prefix_resolves_against_components(self):
        r"""
        {{componentAlpha}} resolves against components.

        Given: IdIndex.components={'componentAlpha'}
        When: check_references is called
        Then: No diagnostic
        """
        idx = _make_index(components=["componentAlpha"])
        field = _make_field("{{componentAlpha}} is involved.")
        assert check_references(field, idx) == []

    def test_unresolved_cross_entity_produces_correct_reason(self):
        r"""
        Unresolved sentinel produces a reason that names the expected entity set.

        Given: {{componentMissing}} and IdIndex.components={}
        When: check_references is called
        Then: Diagnostic reason mentions 'componentMissing' or 'component'
        """
        idx = _make_index(components=[])
        field = _make_field("See {{componentMissing}}.")
        diags = check_references(field, idx)
        assert len(diags) >= 1
        assert "componentMissing" in diags[0].reason or "component" in diags[0].reason.lower()


# ===========================================================================
# TestExternalRefSentinelResolution
# ===========================================================================


class TestExternalRefSentinelResolution:
    r"""{{ref:identifier}} is resolved per-entry against IdIndex.ext_refs.

    ADR-016 D2: the ref: prefix keeps resolution local to the entry.
    """

    def test_resolved_ref_sentinel_produces_no_diagnostic(self):
        r"""
        {{ref:cwe-89}} resolves when 'cwe-89' is in the entry's ext_refs.

        Given: Prose 'See {{ref:cwe-89}}.' and IdIndex.ext_refs={'riskAlpha': {'cwe-89'}}
        When: check_references is called on a ProseField for entry 'riskAlpha'
        Then: No diagnostic
        """
        idx = _make_index(ext_refs={"riskAlpha": ["cwe-89"]})
        field = _make_field("See {{ref:cwe-89}}.", entry_id="riskAlpha")
        assert check_references(field, idx) == []

    def test_unresolved_ref_sentinel_produces_diagnostic(self):
        r"""
        {{ref:nonexistent}} not in the entry's ext_refs produces one diagnostic.

        Given: Prose 'See {{ref:nonexistent}}.' and entry has no externalReferences
        When: check_references is called
        Then: One Diagnostic naming 'nonexistent'
        """
        idx = _make_index(ext_refs={})
        field = _make_field("See {{ref:nonexistent}}.", entry_id="riskAlpha")
        diags = check_references(field, idx)
        assert len(diags) == 1
        assert "nonexistent" in diags[0].reason

    def test_ref_resolved_for_owning_entry_not_another(self):
        r"""
        {{ref:foo}} resolves against the entry's own ext_refs only.

        Given: IdIndex.ext_refs={'riskBeta': {'foo'}} and field is for 'riskAlpha'
        When: check_references is called on a field for entry 'riskAlpha'
        Then: One Diagnostic — 'foo' is in riskBeta's refs, not riskAlpha's

        Per ADR-016 D2: resolution scope is per-entry, not global.
        """
        idx = _make_index(ext_refs={"riskBeta": ["foo"], "riskAlpha": []})
        field = _make_field("See {{ref:foo}}.", entry_id="riskAlpha")
        diags = check_references(field, idx)
        assert len(diags) == 1

    def test_dotted_ref_identifier_resolves_correctly(self):
        r"""
        {{ref:nist-ai-rmf-1.0}} resolves when 'nist-ai-rmf-1.0' is in ext_refs.

        Given: Prose 'Per {{ref:nist-ai-rmf-1.0}} section 3.' with dotted ID in ext_refs
        When: check_references is called
        Then: No diagnostic (dots in IDs are valid per tokenizer's regex)
        """
        idx = _make_index(ext_refs={"riskAlpha": ["nist-ai-rmf-1.0"]})
        field = _make_field("Per {{ref:nist-ai-rmf-1.0}} section 3.", entry_id="riskAlpha")
        assert check_references(field, idx) == []

    def test_fixture_ref_sentinels_valid_resolves_cleanly(self, tmp_path):
        r"""
        The valid/ref_sentinels.yaml fixture resolves without diagnostics.

        Given: valid/ref_sentinels.yaml with {{ref:smith-2023}} and {{ref:cwe-89}}
               and an IdIndex built from that same YAML
        When: check_references is called
        Then: No diagnostics
        """
        yaml_path = _VALID_DIR / "ref_sentinels.yaml"
        idx = build_id_index([yaml_path])
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_references(field, idx))
        assert all_diags == []

    def test_fixture_unresolved_external_ref_produces_diagnostic(self):
        r"""
        The reference_violations/unresolved_external_ref.yaml fixture produces diagnostics.

        Given: A risk with {{ref:nonexistent-ref}} where that ID is absent
        When: find_prose_fields + check_references with correct index are called
        Then: At least one Diagnostic is returned
        """
        yaml_path = _REF_VIOL_DIR / "unresolved_external_ref.yaml"
        idx = build_id_index([yaml_path])
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_references(field, idx))
        assert len(all_diags) >= 1

    def test_multiple_ref_sentinels_one_unresolved_produces_one_diagnostic(self):
        r"""
        Two {{ref:...}} sentinels, one resolved and one not, produce one diagnostic.

        Given: Prose 'See {{ref:real}} and {{ref:missing}}.' with only 'real' in ext_refs
        When: check_references is called
        Then: Exactly one Diagnostic for 'missing'
        """
        idx = _make_index(ext_refs={"riskAlpha": ["real"]})
        field = _make_field("See {{ref:real}} and {{ref:missing}}.", entry_id="riskAlpha")
        diags = check_references(field, idx)
        assert len(diags) == 1
        assert "missing" in diags[0].reason


# ===========================================================================
# TestBareCamelCaseRejection
# ===========================================================================


class TestBareCamelCaseRejection:
    r"""Bare camelCase entity-prefix identifiers outside sentinels are rejected.

    ADR-016 D6 rule 6: any (risk|control|component|persona)[A-Z]... in prose
    not wrapped in {{ }} must produce a diagnostic.
    """

    def test_bare_risk_id_in_prose_produces_diagnostic(self):
        r"""
        'riskAlpha' mentioned in prose without sentinel braces produces a diagnostic.

        Given: Prose 'The riskAlpha attack pattern is related.' and full IdIndex
        When: check_references is called
        Then: One Diagnostic naming 'riskAlpha' and noting it must be sentinel-wrapped
        """
        idx = _make_index(risks=["riskAlpha"])
        field = _make_field("The riskAlpha attack pattern is related.")
        diags = check_references(field, idx)
        assert len(diags) >= 1
        assert "riskAlpha" in diags[0].reason

    def test_sentinel_wrapped_id_does_not_produce_bare_camelcase_diagnostic(self):
        r"""
        {{riskAlpha}} (sentinel-wrapped) does NOT produce a bare-camelCase diagnostic.

        Given: Prose '{{riskAlpha}} is mentioned.' and IdIndex.risks={'riskAlpha'}
        When: check_references is called
        Then: No bare-camelCase diagnostic (the tokenizer's R4 context-awareness handles this)
        """
        idx = _make_index(risks=["riskAlpha"])
        field = _make_field("{{riskAlpha}} is mentioned.")
        diags = check_references(field, idx)
        # No bare-camelCase diagnostic; there may be a resolution diagnostic
        # if the ID is not in the index, but since it IS in the index, no diags at all
        camel_diags = [
            d
            for d in diags
            if "camel" in d.reason.lower() or "bare" in d.reason.lower() or "wrapped" in d.reason.lower()
        ]
        assert camel_diags == []

    def test_bare_control_id_produces_diagnostic(self):
        r"""
        'controlAlpha' in prose without sentinel produces a diagnostic.

        Given: Prose 'Use controlAlpha to mitigate.' and IdIndex.controls={'controlAlpha'}
        When: check_references is called
        Then: At least one Diagnostic with reason mentioning 'controlAlpha'
        """
        idx = _make_index(controls=["controlAlpha"])
        field = _make_field("Use controlAlpha to mitigate.")
        diags = check_references(field, idx)
        assert len(diags) >= 1
        assert "controlAlpha" in diags[0].reason

    def test_bare_camelcase_diagnostic_reason_mentions_sentinel(self):
        r"""
        The bare-camelCase diagnostic reason mentions sentinel wrapping.

        Given: Prose 'The riskBeta pattern...'
        When: check_references is called
        Then: Diagnostic reason mentions sentinel syntax (e.g. '{{...}}' or 'sentinel')
        """
        idx = _make_index(risks=["riskBeta"])
        field = _make_field("The riskBeta pattern is concerning.")
        diags = check_references(field, idx)
        assert len(diags) >= 1
        reason = diags[0].reason
        # The reason should mention how to fix it (sentinel wrapping or {{ }})
        assert "{{" in reason or "sentinel" in reason.lower() or "wrap" in reason.lower()

    def test_fixture_bare_camelcase_produces_diagnostic(self):
        r"""
        The reference_violations/bare_camelcase_in_prose.yaml fixture produces diagnostics.

        Given: A risk with 'riskBeta' mentioned in bare prose
        When: find_prose_fields + check_references with IdIndex containing riskBeta
        Then: At least one Diagnostic is returned
        """
        yaml_path = _REF_VIOL_DIR / "bare_camelcase_in_prose.yaml"
        idx = _make_index(risks=["riskAlpha", "riskBeta", "riskGamma", "riskDelta"])
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_references(field, idx))
        assert len(all_diags) >= 1

    def test_plain_word_without_entity_prefix_not_flagged(self):
        r"""
        Prose words that do not match (risk|control|component|persona)[A-Z]... are not flagged.

        Given: Prose 'The algorithm processes input from multiple sources.'
        When: check_references is called
        Then: No diagnostic (no entity-prefix camelCase present)
        """
        idx = _make_index(risks=["riskAlpha"])
        field = _make_field("The algorithm processes input from multiple sources.")
        diags = check_references(field, idx)
        camel_diags = [d for d in diags if "camel" in d.reason.lower() or "bare" in d.reason.lower()]
        assert camel_diags == []


# ===========================================================================
# TestInlineUrlRejection
# ===========================================================================


class TestInlineUrlRejection:
    r"""Inline URLs in prose produce diagnostics from the references linter.

    ADR-016 D6 rule 4: any inline URL (raw https://, markdown link, <a href>)
    must be rejected.  The references linter overlaps with the subset linter
    here; the more specific message (from the references linter) wins per ADR-017 D5.
    """

    def test_raw_https_url_produces_diagnostic(self):
        r"""
        A raw https:// URL in prose produces at least one diagnostic.

        Given: Prose 'See https://example.com here.'
        When: check_references is called
        Then: At least one Diagnostic with reason referencing URL / externalReferences
        """
        idx = _make_index()
        field = _make_field("See https://example.com here.")
        diags = check_references(field, idx)
        assert len(diags) >= 1

    def test_markdown_link_produces_diagnostic(self):
        r"""
        A [text](url) markdown link in prose produces at least one diagnostic.

        Given: Prose 'See [the paper](https://example.com/paper) here.'
        When: check_references is called
        Then: At least one Diagnostic
        """
        idx = _make_index()
        field = _make_field("See [the paper](https://example.com/paper) here.")
        diags = check_references(field, idx)
        assert len(diags) >= 1

    def test_inline_url_diagnostic_mentions_external_references(self):
        r"""
        The inline URL diagnostic reason mentions externalReferences or sentinel.

        Given: Prose with a raw URL
        When: check_references is called
        Then: Diagnostic reason guides the author toward externalReferences + sentinel

        ADR-016 D4: the reason should indicate the correct fix (use externalReferences).
        """
        idx = _make_index()
        field = _make_field("See https://example.com here.")
        diags = check_references(field, idx)
        assert len(diags) >= 1
        reason_lower = diags[0].reason.lower()
        assert any(word in reason_lower for word in ("externalreferences", "url", "link", "sentinel", "ref:"))

    def test_fixture_raw_url_produces_diagnostic(self):
        r"""
        The reference_violations/raw_url_in_description.yaml fixture produces diagnostics.

        Given: A risk with a raw https:// URL in prose
        When: find_prose_fields + check_references are called
        Then: At least one Diagnostic
        """
        yaml_path = _REF_VIOL_DIR / "raw_url_in_description.yaml"
        idx = _make_index()
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_references(field, idx))
        assert len(all_diags) >= 1

    def test_clean_sentinel_ref_without_inline_url_passes(self):
        r"""
        Clean {{ref:foo}} sentinel produces no inline-URL diagnostic.

        Given: Prose 'See {{ref:cwe-89}} for context.' and 'cwe-89' in ext_refs
        When: check_references is called
        Then: No diagnostic
        """
        idx = _make_index(ext_refs={"riskAlpha": ["cwe-89"]})
        field = _make_field("See {{ref:cwe-89}} for context.", entry_id="riskAlpha")
        assert check_references(field, idx) == []


# ===========================================================================
# TestRawHtmlTagRejection
# ===========================================================================


class TestRawHtmlTagRejection:
    r"""Raw HTML tags in prose produce diagnostics from the references linter.

    ADR-016 D6 rule 5: any <tag> in prose must be rejected.
    Overlap with the subset linter is expected; the references linter's message
    is the more specific one.
    """

    def test_anchor_tag_produces_diagnostic(self):
        r"""
        A raw <a href="..."> HTML anchor produces at least one diagnostic.

        Given: Prose 'See <a href="https://example.com">link</a>.'
        When: check_references is called
        Then: At least one Diagnostic for the HTML tag
        """
        idx = _make_index()
        field = _make_field('See <a href="https://example.com">link</a>.')
        diags = check_references(field, idx)
        assert len(diags) >= 1

    def test_two_html_tags_produce_two_diagnostics(self):
        r"""
        Two distinct HTML tags each produce their own diagnostic.

        Given: Prose with '<strong>x</strong> and <em>y</em>'
        When: check_references is called
        Then: At least 2 Diagnostics (per-tag granularity, one per tag)
        """
        idx = _make_index()
        field = _make_field("The <strong>critical</strong> and <em>important</em> case.")
        diags = check_references(field, idx)
        assert len(diags) >= 2

    def test_html_diagnostic_mentions_tag_or_html(self):
        r"""
        HTML tag diagnostic reason mentions 'html' or 'tag'.

        Given: Prose with '<br/>'
        When: check_references is called
        Then: Diagnostic reason mentions 'html' or 'tag'
        """
        idx = _make_index()
        field = _make_field("Line break: <br/>")
        diags = check_references(field, idx)
        assert len(diags) >= 1
        assert any("html" in d.reason.lower() or "tag" in d.reason.lower() for d in diags)

    def test_clean_prose_with_bold_italic_no_html_diagnostic(self):
        r"""
        Bold **text** and italic *text* produce no HTML diagnostic.

        Given: Prose '**Bold** and *italic* prose.'
        When: check_references is called
        Then: No diagnostics
        """
        idx = _make_index()
        field = _make_field("**Bold** and *italic* prose.")
        assert check_references(field, idx) == []


# ===========================================================================
# TestMultiClassViolations
# ===========================================================================


class TestMultiClassViolations:
    r"""Entries with multiple violation classes produce multiple diagnostics."""

    def test_bare_camelcase_plus_inline_url_produces_two_diagnostic_classes(self):
        r"""
        Prose with bare-camelCase AND inline URL produces diagnostics for both.

        Given: Prose 'The riskAlpha covers https://example.com attacks.'
        When: check_references is called
        Then: At least 2 diagnostics (one for URL, one for bare camelCase)
        """
        idx = _make_index(risks=["riskAlpha"])
        field = _make_field("The riskAlpha covers https://example.com attacks.")
        diags = check_references(field, idx)
        assert len(diags) >= 2

    def test_unresolved_sentinel_plus_bare_camelcase_produces_two_diagnostics(self):
        r"""
        Unresolved {{riskMissing}} plus bare 'controlAlpha' produces 2 diagnostics.

        Given: Prose '{{riskMissing}} and controlAlpha are involved.'
        When: check_references is called with empty risks and controls
        Then: At least 2 diagnostics
        """
        idx = _make_index(risks=[], controls=[])
        field = _make_field("{{riskMissing}} and controlAlpha are involved.")
        diags = check_references(field, idx)
        assert len(diags) >= 2

    def test_fixture_multi_violation_entry_produces_multiple_diagnostics(self):
        r"""
        The reference_violations/multi_violation_entry.yaml fixture produces 2+ diagnostics.

        Given: A risk with bare camelCase + raw URL + unresolved sentinel in one field
        When: find_prose_fields + check_references are called
        Then: At least 2 diagnostics
        """
        yaml_path = _REF_VIOL_DIR / "multi_violation_entry.yaml"
        idx = _make_index(risks=[])  # empty — {{riskUnknown}} will be unresolved
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_references(field, idx))
        assert len(all_diags) >= 2

    def test_no_early_return_all_violations_reported(self):
        r"""
        check_references does not stop at the first diagnostic (no early return).

        Given: Prose with 3 distinct violation classes in one field
        When: check_references is called
        Then: At least 3 Diagnostics are returned
        """
        idx = _make_index(risks=[])
        # bare camelCase + URL + unresolved sentinel
        text = "The riskBeta issue, see https://example.com and {{riskUnknown}}."
        field = _make_field(text)
        diags = check_references(field, idx)
        assert len(diags) >= 3


# ===========================================================================
# TestCLIExitCodes
# ===========================================================================


class TestCLIExitCodes:
    r"""CLI exit-code contract for validate_prose_references.py.

    Mirrors the subset linter's CLI contract:
    - Warn-only (no --block): always exits 0.
    - Block mode (--block): exits 1 on any violation, 0 if clean.
    - Usage / IO error: exits 2.
    """

    def _write_files(self, tmp_path: Path, description: list[str]) -> tuple[Path, Path]:
        r"""Write a minimal schema dir and risks YAML for CLI tests."""
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"])
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {"risks": [_make_risk("riskAlpha", description=description)]},
        )
        return yaml_path, schema_dir

    def test_warn_mode_violation_exits_0(self, tmp_path, capsys):
        r"""
        Warn-only mode exits 0 even when violations are found.

        Given: A YAML with a bare camelCase violation and no --block flag
        When: main() is called
        Then: sys.exit(0)
        """
        yaml_path, schema_dir = self._write_files(tmp_path, ["The riskBeta is mentioned here."])
        idx_yaml = _write_yaml(tmp_path, "idx.yaml", {"risks": []})
        with pytest.raises(SystemExit) as exc_info:
            main([str(yaml_path), "--schema-dir", str(schema_dir), "--id-sources", str(idx_yaml)])
        assert exc_info.value.code == 0

    def test_warn_mode_clean_input_exits_0_no_stderr(self, tmp_path, capsys):
        r"""
        Warn-only mode with clean input exits 0 and produces no stderr.

        Given: Clean prose and no --block flag
        When: main() is called
        Then: sys.exit(0); stderr is empty
        """
        yaml_path, schema_dir = self._write_files(tmp_path, ["Clean prose here."])
        # Provide an id-source that makes the index empty (no sentinels to resolve)
        idx_yaml = _write_yaml(tmp_path, "idx.yaml", {"risks": []})
        with pytest.raises(SystemExit) as exc_info:
            main([str(yaml_path), "--schema-dir", str(schema_dir), "--id-sources", str(idx_yaml)])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_block_mode_violation_exits_nonzero(self, tmp_path, capsys):
        r"""
        Block mode exits non-zero when any violation is found.

        Given: A YAML with a raw URL violation and --block flag
        When: main() is called
        Then: sys.exit(1) or non-zero
        """
        yaml_path, schema_dir = self._write_files(tmp_path, ["See https://example.com here."])
        idx_yaml = _write_yaml(tmp_path, "idx.yaml", {"risks": []})
        with pytest.raises(SystemExit) as exc_info:
            main([str(yaml_path), "--schema-dir", str(schema_dir), "--id-sources", str(idx_yaml), "--block"])
        assert exc_info.value.code == 1

    def test_block_mode_clean_input_exits_0(self, tmp_path, capsys):
        r"""
        Block mode with clean prose exits 0.

        Given: Clean prose and --block flag
        When: main() is called
        Then: sys.exit(0)
        """
        yaml_path, schema_dir = self._write_files(tmp_path, ["Clean prose here."])
        idx_yaml = _write_yaml(tmp_path, "idx.yaml", {"risks": []})
        with pytest.raises(SystemExit) as exc_info:
            main([str(yaml_path), "--schema-dir", str(schema_dir), "--id-sources", str(idx_yaml), "--block"])
        assert exc_info.value.code == 0

    def test_violations_emitted_to_stderr(self, tmp_path, capsys):
        r"""
        Diagnostic lines are emitted to stderr.

        Given: A YAML with a raw URL violation
        When: main() is called in warn-only mode
        Then: stderr contains 'validate-prose-references'
        """
        yaml_path, schema_dir = self._write_files(tmp_path, ["See https://example.com here."])
        idx_yaml = _write_yaml(tmp_path, "idx.yaml", {"risks": []})
        with pytest.raises(SystemExit):
            main([str(yaml_path), "--schema-dir", str(schema_dir), "--id-sources", str(idx_yaml)])
        captured = capsys.readouterr()
        assert "validate-prose-references" in captured.err

    def test_stderr_lines_match_format_regex(self, tmp_path, capsys):
        r"""
        Every non-empty stderr line in warn mode matches the diagnostic format regex.

        Given: A YAML with a URL violation
        When: main() is called without --block
        Then: All stderr lines match _DIAG_PATTERN
        """
        yaml_path, schema_dir = self._write_files(tmp_path, ["See https://example.com here."])
        idx_yaml = _write_yaml(tmp_path, "idx.yaml", {"risks": []})
        with pytest.raises(SystemExit):
            main([str(yaml_path), "--schema-dir", str(schema_dir), "--id-sources", str(idx_yaml)])
        captured = capsys.readouterr()
        lines = [ln for ln in captured.err.splitlines() if ln.strip()]
        assert len(lines) >= 1
        for line in lines:
            assert _DIAG_PATTERN.match(line), f"Line does not match diagnostic pattern: {line!r}"

    def test_multiple_files_in_one_invocation(self, tmp_path, capsys):
        r"""
        main() accepts multiple file paths and reports diagnostics per file.

        Given: Two YAML files — one clean, one with a violation
        When: main() is called with both
        Then: Diagnostics appear only for the violating file; exits 0 (warn mode)
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        _write_mock_schema(schema_dir, "risk", ["riskAlpha", "riskBeta"])
        clean_path = _write_yaml(
            tmp_path, "clean.yaml", {"risks": [_make_risk("riskAlpha", description=["Clean prose."])]}
        )
        viol_path = _write_yaml(
            tmp_path, "viol.yaml", {"risks": [_make_risk("riskBeta", description=["See https://example.com."])]}
        )
        idx_yaml = _write_yaml(tmp_path, "idx.yaml", {"risks": []})

        with pytest.raises(SystemExit) as exc_info:
            main([str(clean_path), str(viol_path), "--schema-dir", str(schema_dir), "--id-sources", str(idx_yaml)])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "viol.yaml" in captured.err
        assert "clean.yaml" not in captured.err

    def test_no_args_exits_gracefully(self, capsys):
        r"""
        main() with no file args exits without crashing.

        Given: No file arguments
        When: main() is called with empty argv
        Then: Exits 0 (no files to check)
        """
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 0

    def test_subprocess_invocation_warn_mode_returns_0(self, tmp_path):
        r"""
        End-to-end subprocess invocation in warn mode returns exit code 0.

        Given: A YAML with a URL violation
        When: python3 validate_prose_references.py <file> --schema-dir <dir> --id-sources <file>
        Then: Return code is 0
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"])
        yaml_path = _write_yaml(
            tmp_path, "risks.yaml", {"risks": [_make_risk("riskAlpha", description=["See https://example.com."])]}
        )
        idx_yaml = _write_yaml(tmp_path, "idx.yaml", {"risks": []})
        result = subprocess.run(
            [
                sys.executable,
                str(_HOOK_MODULE),
                str(yaml_path),
                "--schema-dir",
                str(schema_dir),
                "--id-sources",
                str(idx_yaml),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0


# ===========================================================================
# TestEdgeCases
# ===========================================================================


class TestEdgeCases:
    r"""Edge cases, graceful degradation, and integration checks."""

    def test_unclosed_sentinel_does_not_crash_linter(self):
        r"""
        Prose with '{{riskFoo is unclosed' does not crash check_references.

        Given: A ProseField with an unclosed {{ sentinel
        When: check_references is called
        Then: No exception; returns a list

        The tokenizer emits a TEXT token for unclosed sentinels.
        The references linter must not crash when no SENTINEL token is present.
        """
        idx = _make_index(risks=[])
        field = _make_field("{{riskFoo is unclosed")
        result = check_references(field, idx)
        assert isinstance(result, list)

    def test_empty_prose_produces_no_diagnostic(self):
        r"""
        An empty prose field produces no diagnostics.

        Given: A ProseField with raw_text == ''
        When: check_references is called
        Then: Returns no diagnostics
        """
        idx = _make_index()
        field = _make_field("")
        assert check_references(field, idx) == []

    def test_plain_clean_prose_produces_no_diagnostic(self):
        r"""
        Plain prose with no special tokens produces no diagnostics.

        Given: 'This control enforces access policies.'
        When: check_references is called
        Then: No diagnostics
        """
        idx = _make_index()
        field = _make_field("This control enforces access policies.")
        assert check_references(field, idx) == []

    def test_diagnostic_hook_id_is_correct(self):
        r"""
        Diagnostics from check_references have hook_id 'validate-prose-references'.

        Given: Any violation (e.g. raw URL)
        When: check_references is called
        Then: Diagnostic.hook_id == 'validate-prose-references'
        """
        idx = _make_index()
        field = _make_field("See https://example.com here.")
        diags = check_references(field, idx)
        assert len(diags) >= 1
        assert diags[0].hook_id == "validate-prose-references"

    def test_diagnostic_entry_id_matches_field(self):
        r"""
        Diagnostic.entry_id matches the ProseField.entry_id.

        Given: A ProseField with entry_id='controlBeta' and a URL violation
        When: check_references is called
        Then: Diagnostic.entry_id == 'controlBeta'
        """
        idx = _make_index()
        field = _make_field("See https://example.com.", entry_id="controlBeta")
        diags = check_references(field, idx)
        assert len(diags) >= 1
        assert diags[0].entry_id == "controlBeta"

    def test_build_id_index_with_empty_list(self):
        r"""
        build_id_index with an empty file list returns an empty IdIndex.

        Given: An empty list of YAML paths
        When: build_id_index is called
        Then: All IdIndex sets are empty
        """
        idx = build_id_index([])
        assert len(idx.risks) == 0
        assert len(idx.controls) == 0
        assert len(idx.components) == 0
        assert len(idx.personas) == 0
        assert len(idx.ext_refs) == 0

    def test_real_corpus_does_not_crash(self):
        r"""
        Running on the real risks.yaml in warn-only mode does not crash.

        Given: The actual risk-map/yaml/risks.yaml and schemas/
        When: find_prose_fields + check_references are called with a real index
        Then: No exception is raised; a list is returned

        The live corpus has warn-only violations; this test verifies graceful handling.
        """
        yaml_dir = _REPO_ROOT / "risk-map" / "yaml"
        schema_dir = _REPO_ROOT / "risk-map" / "schemas"
        yaml_path = yaml_dir / "risks.yaml"
        assert yaml_path.exists(), f"Real risks.yaml not found at {yaml_path}"

        # Build index from all four YAML files
        yaml_paths = [yaml_dir / f for f in ["risks.yaml", "controls.yaml", "components.yaml", "personas.yaml"]]
        idx = build_id_index([p for p in yaml_paths if p.exists()])

        all_diags = []
        for field in find_prose_fields(yaml_path, schema_dir):
            all_diags.extend(check_references(field, idx))
        assert isinstance(all_diags, list)

    def test_id_index_is_namedtuple_or_dataclass(self):
        r"""
        IdIndex can be constructed and accessed by field name.

        Given: A manually constructed IdIndex
        When: Accessing .risks, .controls, .components, .personas, .ext_refs
        Then: All fields are accessible without exception
        """
        idx = _make_index(risks=["riskAlpha"], controls=["controlAlpha"])
        assert "riskAlpha" in idx.risks
        assert "controlAlpha" in idx.controls
        assert isinstance(idx.ext_refs, dict)

    def test_missing_file_exits_with_error_code(self):
        r"""
        A non-existent file path causes an appropriate non-zero exit.

        Given: A file path that does not exist
        When: main() is called
        Then: Exits with a non-zero code
        """
        with pytest.raises(SystemExit) as exc_info:
            main(["/nonexistent/path/does_not_exist.yaml"])
        assert exc_info.value.code == 2

    def test_valid_clean_control_fixture_no_diagnostics(self, tmp_path):
        r"""
        The valid/single_clean_control.yaml fixture produces no diagnostics.

        Given: valid/single_clean_control.yaml and an empty IdIndex
        When: find_prose_fields + check_references are called
        Then: No diagnostics
        """
        yaml_path = _VALID_DIR / "single_clean_control.yaml"
        idx = _make_index()
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_references(field, idx))
        assert all_diags == []

    def test_invalid_sentinel_structure_does_not_crash(self):
        r"""
        An INVALID_SENTINEL token from the tokenizer does not crash check_references.

        Given: Prose with '{{xyz_invalid}}' — INVALID_SENTINEL from the tokenizer
        When: check_references is called
        Then: No exception; returns a list (may or may not produce a diagnostic)
        """
        idx = _make_index()
        field = _make_field("See {{xyz_invalid}} for context.")
        result = check_references(field, idx)
        assert isinstance(result, list)

    def test_url_diagnostic_reason_contains_snippet(self):
        r"""
        ADR-017 D4: INVALID_URL diagnostic reason contains 'at <token-snippet>'.

        Given: Prose 'See https://example.com here.'
        When: check_references is called
        Then: Diagnostic reason contains "at '" and the URL text
        """
        idx = _make_index()
        field = _make_field("See https://example.com here.")
        diags = check_references(field, idx)
        url_diags = [d for d in diags if "url" in d.reason.lower() or "external" in d.reason.lower()]
        assert len(url_diags) >= 1
        assert "at '" in url_diags[0].reason

    def test_html_diagnostic_reason_contains_snippet(self):
        r"""
        ADR-017 D4: INVALID_HTML diagnostic reason contains 'at <token-snippet>'.

        Given: Prose 'See <br/> in prose.'
        When: check_references is called
        Then: Diagnostic reason contains "at '" and the tag text
        """
        idx = _make_index()
        field = _make_field("See <br/> in prose.")
        diags = check_references(field, idx)
        html_diags = [d for d in diags if "html" in d.reason.lower() or "tag" in d.reason.lower()]
        assert len(html_diags) >= 1
        assert "at '" in html_diags[0].reason

    def test_camelcase_diagnostic_reason_contains_snippet(self):
        r"""
        INVALID_CAMELCASE_ID diagnostic reason contains the bare identifier as a snippet.

        Given: Prose 'The riskAlpha is mentioned.'
        When: check_references is called
        Then: Diagnostic reason contains 'riskAlpha' and "at '"
        """
        idx = _make_index(risks=["riskAlpha"])
        field = _make_field("The riskAlpha is mentioned.")
        diags = check_references(field, idx)
        camel_diags = [
            d
            for d in diags
            if "sentinel" in d.reason.lower() or "bare" in d.reason.lower() or "wrap" in d.reason.lower()
        ]
        assert len(camel_diags) >= 1
        assert "at '" in camel_diags[0].reason
        assert "riskAlpha" in camel_diags[0].reason
