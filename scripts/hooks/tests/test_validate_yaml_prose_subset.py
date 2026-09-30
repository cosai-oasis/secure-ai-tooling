#!/usr/bin/env python3
r"""
Tests for scripts/hooks/precommit/validate_yaml_prose_subset.py

This module tests the pre-commit lint that enforces the ADR-017 D4 grammar
rules against prose fields in risk-map/yaml/{risks,controls,components,
personas}.yaml.

Pattern lineage: mirrors validate_identification_questions.py / its test suite
(commit 627f236, sub-PR A5).  Direct-import style for unit tests; subprocess
for end-to-end CLI exit-code assertions.  Same warn/block toggle, same
stderr-format convention, same sys.path injection idiom.

API shape committed to by this test suite
==========================================
Module: precommit.validate_yaml_prose_subset

Importable names:
    ProseField   — NamedTuple(file_path: Path, entry_id: str, field_name: str,
                               index: int | None, raw_text: str,
                               tokens: list[Token])
    Diagnostic   — NamedTuple(hook_id: str, file_path: Path, entry_id: str,
                               field_name: str, index: int | None, reason: str)
    find_prose_fields(yaml_path: Path, schema_dir: Path) -> Iterator[ProseField]
    check_prose_field(field: ProseField) -> list[Diagnostic]
    main(argv: list[str] | None = None) -> NoReturn

Diagnostic format (committed):
    validate-yaml-prose-subset: <file>:<entry-id>:<field>[<index>]: <reason>

    Regex: r'^validate-yaml-prose-subset: [^:]+:[^:]+:[^\[]+\[\d+\]: .+$'

Warn-only mode (default):
    - Always exits 0; diagnostics printed to stderr.
Block mode (--block flag):
    - Exits 1 if any diagnostics; exits 0 if clean.
Usage error / unreadable file: exits 2.

Fixture corpus:
    scripts/hooks/tests/fixtures/wrapper_linters/
    — valid/          : clean YAML passing both linters
    — subset_violations/ : YAML triggering grammar violations only
    — reference_violations/ : (used by the references linter only)
    — schemas/        : minimal mock schemas for introspection tests

The tokenizer (_prose_tokens.py) is extended on this branch per ADR-028 D1/D3
(the Token.shape field, _classify_emphasis_shape, and the tightened
_RE_ITALIC_UNDERSCORE).  The prose_subset/ fixture directory gains the
accepting/emphasis_shapes/ pairs (ADR-028 D-Open-18, Path 3b).

Test Coverage
=============
Total tests: 69 across 10 test classes

TestSchemaProseFieldDiscovery    — 8 tests
TestSingleViolationDetection     — 13 tests
TestMultiViolationEntry          — 3 tests
TestCleanFieldPassesSilently     — 7 tests
TestFoldedBulletDrift            — 4 tests
TestDiagnosticFormat             — 8 tests
TestCLIExitCodes                 — 8 tests
TestEdgeCases                    — 7 tests
TestTokenizerConsistency         — 5 tests
TestFoldedBulletVsListAtColumn0  — 6 tests

Coverage areas:
    find_prose_fields:  schema-driven enumeration, $ref detection, multi-entry
    check_prose_field:  all INVALID_* token kinds, clean pass, no early return
    main():             warn-only exits 0, block exits 1 on violation, block
                        exits 0 on clean, exit 2 on bad file, multi-file walk
    Diagnostic format:  prefix, colon-separated fields, index bracket notation
    Tokenizer parity:   subset linter delegates to tokenizer, no divergence
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
    from validate_yaml_prose_subset import (  # noqa: E402
        Diagnostic,
        ProseField,
        _delim_for_token,
        check_prose_field,
        find_prose_fields,
        main,
    )

    _IMPORT_ERROR: Exception | None = None
except ImportError as _e:
    _IMPORT_ERROR = _e
    # Stub names so module-level references do not raise NameError at load time.
    Diagnostic = None  # type: ignore[assignment,misc]
    ProseField = None  # type: ignore[assignment,misc]
    _delim_for_token = None  # type: ignore[assignment]
    check_prose_field = None  # type: ignore[assignment]
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
_SUBSET_VIOL_DIR = _FIXTURE_ROOT / "subset_violations"
_HOOK_MODULE = Path(__file__).parent.parent / "precommit" / "validate_yaml_prose_subset.py"
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# ---------------------------------------------------------------------------
# Helpers for building synthetic YAML and schema fixtures
# ---------------------------------------------------------------------------


def _write_mock_schema(tmp_path: Path, entity: str, ids: list[str], extra_props: dict | None = None) -> Path:
    r"""Write a minimal schema JSON declaring one prose field for the given entity.

    The schema marks ``description`` (and optionally ``shortDescription``) as
    ``$ref: riskmap.schema.json#/definitions/utils/text`` so ``find_prose_fields``
    can detect them via introspection.

    Args:
        tmp_path:    Where to write the schema file.
        entity:      Singular entity name (``"risk"``, ``"control"``, etc.).
        ids:         IDs to enumerate in the schema enum.
        extra_props: Additional property definitions merged into the entity's
                     ``properties`` block.
    """
    prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
    props: dict = {
        "id": {"type": "string", "enum": ids},
        "title": {"type": "string"},
        "description": prose_ref,
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
    """Write a YAML file from a dict and return the path."""
    p = tmp_path / name
    p.write_text(yaml.dump(content))
    return p


def _make_risk(risk_id: str, short: list[str] | None = None, long: list[str] | None = None) -> dict:
    """Build a minimal risk entry dict."""
    entry: dict = {"id": risk_id, "title": f"Title for {risk_id}"}
    if short is not None:
        entry["shortDescription"] = short
    if long is not None:
        entry["longDescription"] = long
    return entry


def _make_control(control_id: str, description: list[str] | None = None) -> dict:
    """Build a minimal control entry dict."""
    entry: dict = {"id": control_id, "title": f"Title for {control_id}"}
    if description is not None:
        entry["description"] = description
    return entry


# ---------------------------------------------------------------------------
# Diagnostic format regex (committed contract for the linter)
#
# Field segment allows dotted paths (e.g. "tourContent.introduced") — dots are
# permitted but no additional colons.  The reason segment now requires the
# ADR-017 D4 "at '<snippet>'" suffix.
#
# The optional second bracket group ``(?:\[\d+\])?`` accommodates the
# nested-index extension (issue #285): when a violating token lives inside an
# inner-list string the location becomes ``<field>[<outer>][<inner>]: <reason>``.
# Flat-array diagnostics still emit the bare ``<field>[<outer>]:`` form.
# ---------------------------------------------------------------------------
_DIAG_PATTERN = re.compile(
    r"^validate-yaml-prose-subset: [^:]+:[^:]+:[^:\[.]+(?:\.[^:\[.]+)*\[\d+\](?:\[\d+\])?: .+ at '.*'$"
)


# ===========================================================================
# TestSchemaProseFieldDiscovery
# ===========================================================================


class TestSchemaProseFieldDiscovery:
    r"""Tests for find_prose_fields() — schema-driven field enumeration.

    The linter must walk prose fields identified by
    ``$ref: riskmap.schema.json#/definitions/utils/text`` in the schema, NOT
    a hardcoded list.  Adding a new prose field to the schema must make the
    linter walk it automatically.
    """

    def test_finds_description_field_in_controls_schema(self, tmp_path):
        r"""
        find_prose_fields detects description as a prose field via schema $ref.

        Given: A controls YAML with one entry having a description field,
               and a schema that marks description as a utils/text prose field
        When: find_prose_fields is called with the YAML path and schema dir
        Then: Exactly one ProseField is yielded covering the description array
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        _write_mock_schema(schema_dir, "control", ["controlAlpha"])
        yaml_path = _write_yaml(
            tmp_path,
            "controls.yaml",
            {"controls": [_make_control("controlAlpha", description=["Clean prose."])]},
        )
        fields = list(find_prose_fields(yaml_path, schema_dir))
        # At least one field for the description
        assert any(f.field_name == "description" for f in fields)

    def test_finds_short_and_long_description_in_risks_schema(self, tmp_path):
        r"""
        find_prose_fields enumerates both shortDescription and longDescription.

        Given: A risks YAML with one entry carrying both prose fields,
               and a schema marking both as utils/text
        When: find_prose_fields is called
        Then: ProseFields are yielded for both shortDescription and longDescription
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        _write_mock_schema(
            schema_dir,
            "risk",
            ["riskAlpha"],
            extra_props={"shortDescription": prose_ref, "longDescription": prose_ref},
        )
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {
                "risks": [
                    _make_risk(
                        "riskAlpha",
                        short=["Short prose."],
                        long=["Long prose."],
                    )
                ]
            },
        )
        fields = list(find_prose_fields(yaml_path, schema_dir))
        field_names = {f.field_name for f in fields}
        assert "shortDescription" in field_names
        assert "longDescription" in field_names

    def test_multi_entry_yaml_enumerates_all_entries(self, tmp_path):
        r"""
        find_prose_fields yields prose fields for every entry in the YAML.

        Given: A YAML with 3 risk entries each having a shortDescription
        When: find_prose_fields is called
        Then: At least 3 ProseFields are yielded (one per entry)
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        _write_mock_schema(
            schema_dir,
            "risk",
            ["riskAlpha", "riskBeta", "riskGamma"],
            extra_props={"shortDescription": prose_ref},
        )
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {
                "risks": [
                    _make_risk("riskAlpha", short=["Prose alpha."]),
                    _make_risk("riskBeta", short=["Prose beta."]),
                    _make_risk("riskGamma", short=["Prose gamma."]),
                ]
            },
        )
        fields = list(find_prose_fields(yaml_path, schema_dir))
        entry_ids = {f.entry_id for f in fields}
        assert {"riskAlpha", "riskBeta", "riskGamma"} <= entry_ids

    def test_non_prose_fields_are_not_enumerated(self, tmp_path):
        r"""
        find_prose_fields does not yield ProseFields for non-prose schema fields.

        Given: A schema where title and id are plain string fields (no utils/text $ref)
        When: find_prose_fields is called on a YAML with such fields
        Then: No ProseField is yielded for title or id
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
        field_names = {f.field_name for f in fields}
        assert "id" not in field_names
        assert "title" not in field_names

    def test_prose_field_carries_correct_entry_id(self, tmp_path):
        r"""
        Each ProseField.entry_id matches the YAML entry's id value.

        Given: A risk entry with id 'riskAlpha' and a shortDescription
        When: find_prose_fields is called
        Then: The yielded ProseField has entry_id == 'riskAlpha'
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"], extra_props={"shortDescription": prose_ref})
        yaml_path = _write_yaml(tmp_path, "risks.yaml", {"risks": [_make_risk("riskAlpha", short=["Prose."])]})
        fields = list(find_prose_fields(yaml_path, schema_dir))
        assert any(f.entry_id == "riskAlpha" for f in fields)

    def test_prose_field_index_reflects_paragraph_position(self, tmp_path):
        r"""
        ProseField.index correctly identifies the paragraph index within the array.

        Given: A risk shortDescription with 3 paragraphs
        When: find_prose_fields is called
        Then: ProseFields are yielded with indices 0, 1, 2 for each paragraph
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"], extra_props={"shortDescription": prose_ref})
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {"risks": [_make_risk("riskAlpha", short=["Para zero.", "Para one.", "Para two."])]},
        )
        fields = [f for f in find_prose_fields(yaml_path, schema_dir) if f.field_name == "shortDescription"]
        indices = {f.index for f in fields}
        assert {0, 1, 2} <= indices

    def test_new_prose_field_in_schema_automatically_discovered(self, tmp_path):
        r"""
        A new prose field added to the schema is discovered without code changes.

        Given: A schema with a novel field 'summary' marked as utils/text
        When: find_prose_fields is called on a YAML that has summary entries
        Then: ProseFields are yielded for the summary field
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"], extra_props={"summary": prose_ref})
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {"risks": [{"id": "riskAlpha", "title": "Alpha", "summary": ["A summary."]}]},
        )
        fields = list(find_prose_fields(yaml_path, schema_dir))
        assert any(f.field_name == "summary" for f in fields)

    def test_uses_fixture_schema_dir(self):
        r"""
        find_prose_fields works with the shared fixture schema directory.

        Given: The valid/single_clean_risk.yaml fixture and the fixture schemas/ dir
        When: find_prose_fields is called
        Then: ProseFields are yielded without exception
        """
        yaml_path = _VALID_DIR / "single_clean_risk.yaml"
        fields = list(find_prose_fields(yaml_path, _SCHEMA_DIR))
        # Should return at least one field; no crash
        assert isinstance(fields, list)

    def test_nested_object_prose_fields_discovered(self, tmp_path):
        r"""
        Nested prose fields inside an object property (e.g. tourContent.introduced)
        are discovered via schema introspection.

        Given: A schema with tourContent as an object containing introduced/exposed/mitigated
               prose sub-fields
        When: find_prose_fields is called on a YAML with tourContent data
        Then: ProseFields are yielded with dotted field names like 'tourContent.introduced'
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        tour_content_prop = {
            "type": "object",
            "properties": {
                "introduced": prose_ref,
                "exposed": prose_ref,
                "mitigated": prose_ref,
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
                            "introduced": ["Intro prose."],
                            "exposed": ["Exposed prose."],
                            "mitigated": ["Mitigated prose."],
                        },
                    }
                ]
            },
        )
        fields = list(find_prose_fields(yaml_path, schema_dir))
        field_names = {f.field_name for f in fields}
        assert "tourContent.introduced" in field_names
        assert "tourContent.exposed" in field_names
        assert "tourContent.mitigated" in field_names

    def test_fixture_mock_schema_discovers_tour_content_fields(self):
        r"""
        The updated mock_risks.schema.json fixture declares tourContent nested fields.

        Given: The fixture schemas/ dir (with tourContent in mock_risks.schema.json)
               and the subset_violations/tour_content_nested.yaml fixture
        When: find_prose_fields is called
        Then: At least one ProseField with field_name containing 'tourContent' is yielded
        """
        yaml_path = _SUBSET_VIOL_DIR / "tour_content_nested.yaml"
        fields = list(find_prose_fields(yaml_path, _SCHEMA_DIR))
        tour_fields = [f for f in fields if "tourContent" in f.field_name]
        assert len(tour_fields) >= 1

    def test_tour_content_violation_detected_with_dotted_field_name(self):
        r"""
        A prose violation in tourContent.introduced emits a diagnostic with dotted field name.

        Given: The subset_violations/tour_content_nested.yaml fixture (contains <a> tag)
        When: find_prose_fields + check_prose_field are called
        Then: At least one Diagnostic with field_name 'tourContent.introduced'
        """
        yaml_path = _SUBSET_VIOL_DIR / "tour_content_nested.yaml"
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_prose_field(field))
        tour_diags = [d for d in all_diags if "tourContent.introduced" in d.field_name]
        assert len(tour_diags) >= 1


# ===========================================================================
# TestSingleViolationDetection
# ===========================================================================


class TestSingleViolationDetection:
    r"""Each major rejection token class produces exactly one diagnostic.

    Tests use synthetic ProseField objects to isolate check_prose_field()
    from YAML loading, letting them focus on grammar rule coverage.
    """

    def _make_field(
        self, raw_text: str, entry_id: str = "riskAlpha", field_name: str = "shortDescription"
    ) -> "ProseField":
        r"""Build a ProseField with tokens populated from the tokenizer."""
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        tokens = tokenize(raw_text)
        return ProseField(
            file_path=Path("test.yaml"),
            entry_id=entry_id,
            field_name=field_name,
            index=0,
            raw_text=raw_text,
            tokens=tokens,
        )

    def test_raw_https_url_produces_one_diagnostic(self):
        r"""
        Prose containing a raw https:// URL produces exactly one diagnostic.

        Given: A ProseField with text 'See https://example.com for details.'
        When: check_prose_field is called
        Then: Exactly one Diagnostic is returned with reason referencing URL
        """
        field = self._make_field("See https://example.com for details.")
        diags = check_prose_field(field)
        assert len(diags) == 1
        reason = diags[0].reason.lower()
        assert any(word in reason for word in ("url", "http", "link", "inline"))

    def test_raw_http_url_produces_one_diagnostic(self):
        r"""
        Prose containing a raw http:// URL (non-TLS) produces exactly one diagnostic.

        Given: A ProseField with 'See http://example.com/legacy for background.'
        When: check_prose_field is called
        Then: Exactly one Diagnostic is returned
        """
        field = self._make_field("See http://example.com/legacy for background.")
        diags = check_prose_field(field)
        assert len(diags) == 1

    def test_markdown_link_produces_one_diagnostic(self):
        r"""
        Prose containing [text](url) markdown link syntax produces one diagnostic.

        Given: A ProseField with '[paper](https://example.com/paper)'
        When: check_prose_field is called
        Then: Exactly one Diagnostic is returned
        """
        field = self._make_field("See [the paper](https://example.com/paper) for context.")
        diags = check_prose_field(field)
        assert len(diags) == 1

    def test_raw_html_anchor_produces_diagnostic(self):
        r"""
        Prose containing a raw <a> HTML tag produces at least one diagnostic.

        Given: A ProseField with '<a href=\"https://example.com\">link</a>'
        When: check_prose_field is called
        Then: At least one Diagnostic is returned for the HTML tag
        """
        field = self._make_field('See <a href="https://example.com">link</a>.')
        diags = check_prose_field(field)
        assert len(diags) >= 1
        assert any("html" in d.reason.lower() or "tag" in d.reason.lower() for d in diags)

    def test_raw_html_strong_tag_produces_diagnostic(self):
        r"""
        Prose containing a <strong> HTML tag produces at least one diagnostic.

        Given: A ProseField with 'The <strong>critical</strong> path...'
        When: check_prose_field is called
        Then: At least one Diagnostic is returned (HTML not permitted; use **bold**)
        """
        field = self._make_field("The <strong>critical</strong> path involves this.")
        diags = check_prose_field(field)
        assert len(diags) >= 1

    def test_markdown_heading_produces_diagnostic(self):
        r"""
        Prose beginning with ## heading syntax produces exactly one diagnostic.

        Given: A ProseField with '## Background\nDetails follow.'
        When: check_prose_field is called
        Then: Exactly one Diagnostic is returned for the heading token
        """
        field = self._make_field("## Background\nDetails follow.")
        diags = check_prose_field(field)
        assert len(diags) == 1
        assert "heading" in diags[0].reason.lower() or "markdown" in diags[0].reason.lower()

    def test_list_at_column_zero_produces_diagnostic(self):
        r"""
        Prose beginning with '- item' at column 0 produces exactly one diagnostic.

        Given: A ProseField with '- item one\n- item two'
        When: check_prose_field is called
        Then: Diagnostics are returned for the column-0 list markers
        """
        field = self._make_field("- item one\n- item two")
        diags = check_prose_field(field)
        assert len(diags) >= 1

    def test_code_fence_produces_diagnostic(self):
        r"""
        Prose containing ```code``` fenced block produces at least one diagnostic.

        Given: A ProseField with 'Example: ```payload here```'
        When: check_prose_field is called
        Then: At least one Diagnostic is returned for the code fence
        """
        field = self._make_field("Example: ```payload here```")
        diags = check_prose_field(field)
        assert len(diags) >= 1

    def test_inline_code_produces_diagnostic(self):
        r"""
        Prose containing `inline code` backtick syntax produces at least one diagnostic.

        Given: A ProseField with 'Use `SELECT *` to query.'
        When: check_prose_field is called
        Then: At least one Diagnostic is returned
        """
        field = self._make_field("Use `SELECT *` to query.")
        diags = check_prose_field(field)
        assert len(diags) >= 1

    def test_image_syntax_produces_diagnostic(self):
        r"""
        Prose containing ![alt](url) image syntax produces at least one diagnostic.

        Given: A ProseField with '![diagram](https://example.com/img.png)'
        When: check_prose_field is called
        Then: At least one Diagnostic is returned
        """
        field = self._make_field("![diagram](https://example.com/img.png)")
        diags = check_prose_field(field)
        assert len(diags) >= 1

    def test_blockquote_produces_diagnostic(self):
        r"""
        Prose beginning with '>' blockquote syntax produces at least one diagnostic.

        Given: A ProseField with '> This is a blockquote.'
        When: check_prose_field is called
        Then: At least one Diagnostic is returned
        """
        field = self._make_field("> This is a blockquote.")
        diags = check_prose_field(field)
        assert len(diags) >= 1

    def test_pipe_table_produces_diagnostic(self):
        r"""
        Prose containing a markdown pipe table produces at least one diagnostic.

        Given: A ProseField with '| col A | col B |\n| val1 | val2 |'
        When: check_prose_field is called
        Then: At least one Diagnostic is returned
        """
        field = self._make_field("| col A | col B |\n| val1 | val2 |")
        diags = check_prose_field(field)
        assert len(diags) >= 1

    def test_invalid_sentinel_produces_diagnostic(self):
        r"""
        A malformed sentinel {{xyz}} (wrong prefix) produces at least one diagnostic.

        Given: A ProseField with '{{xyzUnknown}}' — not a valid entity prefix
        When: check_prose_field is called
        Then: At least one Diagnostic is returned (INVALID_SENTINEL from tokenizer)
        """
        field = self._make_field("See {{xyzUnknown}} for context.")
        diags = check_prose_field(field)
        assert len(diags) >= 1


# ===========================================================================
# TestMultiViolationEntry
# ===========================================================================


class TestMultiViolationEntry:
    r"""Multiple violations in one ProseField produce multiple Diagnostics.

    No early return allowed: every INVALID_* token must produce a diagnostic.
    """

    def _make_field(self, raw_text: str) -> "ProseField":
        r"""Build a ProseField from raw text, populating tokens via tokenizer."""
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        return ProseField(
            file_path=Path("test.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text=raw_text,
            tokens=tokenize(raw_text),
        )

    def test_three_distinct_violations_produce_three_diagnostics(self):
        r"""
        One ProseField with 3 distinct violation classes yields 3+ diagnostics.

        Given: Text with a raw URL, an HTML tag, and a markdown heading
        When: check_prose_field is called
        Then: At least 3 Diagnostics are returned (no de-dup, no early return)
        """
        # heading (line-anchored), html tag, and raw url — all three classes
        text = "## Heading\nSee <br/> and https://example.com here."
        field = self._make_field(text)
        diags = check_prose_field(field)
        assert len(diags) >= 3

    def test_two_html_tags_produce_two_diagnostics(self):
        r"""
        Two separate HTML tags in one ProseField each produce their own diagnostic.

        Given: Text with '<strong>x</strong> and <em>y</em>'
        When: check_prose_field is called
        Then: At least 2 Diagnostics are returned (one per tag, per tokenizer)
        """
        text = "The <strong>critical</strong> and <em>urgent</em> case."
        field = self._make_field(text)
        diags = check_prose_field(field)
        assert len(diags) >= 2

    def test_fixture_multi_violation_entry(self):
        r"""
        The multi_violation_entry fixture yields 3+ diagnostics when checked.

        Given: The subset_violations/multi_violation_entry.yaml fixture
        When: find_prose_fields + check_prose_field are called
        Then: Total diagnostic count across all fields is >= 3
        """
        yaml_path = _SUBSET_VIOL_DIR / "multi_violation_entry.yaml"
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_prose_field(field))
        assert len(all_diags) >= 3


# ===========================================================================
# TestCleanFieldPassesSilently
# ===========================================================================


class TestCleanFieldPassesSilently:
    r"""Clean prose — bold, italic, sentinels — produces zero diagnostics.

    The subset linter does NOT validate sentinel ID resolution; that is the
    references linter's job.  So {{riskFoo}} in prose is accepted here even
    if riskFoo is not a known ID.
    """

    def _check(self, text: str) -> list:
        r"""Helper: tokenize text and run check_prose_field."""
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        field = ProseField(
            file_path=Path("x.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text=text,
            tokens=tokenize(text),
        )
        return check_prose_field(field)

    def test_bold_text_passes(self):
        r"""
        Bold **text** produces no diagnostics.

        Given: A ProseField with '**Bold** text is acceptable.'
        When: check_prose_field is called
        Then: Returns no diagnostics
        """
        assert self._check("**Bold** text is acceptable.") == []

    def test_italic_asterisk_passes(self):
        r"""
        Italic *text* produces no diagnostics.

        Given: A ProseField with '*italic* text is acceptable.'
        When: check_prose_field is called
        Then: Returns no diagnostics
        """
        assert self._check("*italic* text is acceptable.") == []

    def test_italic_underscore_passes(self):
        r"""
        Italic _text_ produces no diagnostics.

        Given: A ProseField with '_italic_ underscore is acceptable.'
        When: check_prose_field is called
        Then: Returns no diagnostics
        """
        assert self._check("_italic_ underscore is acceptable.") == []

    def test_sentinel_intra_not_rejected_by_subset_linter(self):
        r"""
        {{riskFoo}} sentinel (any well-formed intra-doc ID) passes subset lint.

        Given: A ProseField with 'See {{riskFoo}} for context.'
        When: check_prose_field is called
        Then: Returns no diagnostics (subset linter does not resolve IDs)
        """
        assert self._check("See {{riskFoo}} for context.") == []

    def test_sentinel_ref_not_rejected_by_subset_linter(self):
        r"""
        {{ref:any-id}} sentinel passes subset lint regardless of resolution.

        Given: A ProseField with 'See {{ref:cwe-89}} for the pattern.'
        When: check_prose_field is called
        Then: Returns no diagnostics (ID resolution is the references linter's job)
        """
        assert self._check("See {{ref:cwe-89}} for the pattern.") == []

    def test_bare_camelcase_id_not_flagged_by_subset_linter(self):
        r"""
        Bare camelCase entity-prefix identifiers are NOT flagged by the subset linter.

        Given: A ProseField with 'The riskAlpha pattern is a concern.'
        When: check_prose_field is called
        Then: Returns no diagnostics — INVALID_CAMELCASE_ID is delegated to the
              references linter per ADR-017 D4 rule 5.
        """
        from precommit._prose_tokens import TokenKind, tokenize  # noqa: PLC0415

        text = "The riskAlpha pattern is a concern."
        tokens = tokenize(text)
        # Confirm the tokenizer does produce INVALID_CAMELCASE_ID for this text.
        assert any(t.kind == TokenKind.INVALID_CAMELCASE_ID for t in tokens)
        # The subset linter must NOT emit a diagnostic for it.
        assert self._check(text) == []

    def test_fixture_single_clean_risk_passes(self):
        r"""
        The valid/single_clean_risk.yaml fixture produces no diagnostics.

        Given: The clean risk fixture and the shared fixture schema dir
        When: find_prose_fields + check_prose_field are called
        Then: Total diagnostic count is 0
        """
        yaml_path = _VALID_DIR / "single_clean_risk.yaml"
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_prose_field(field))
        assert all_diags == []


# ===========================================================================
# TestFoldedBulletDrift
# ===========================================================================


class TestFoldedBulletDrift:
    r"""ADR-020 D4 / issue #225 folded-bullet drift detection.

    The tokenizer emits INVALID_FOLDED_BULLET for whitespace-prefixed '- '
    lines; the subset linter must surface these as Diagnostics.
    """

    def _make_field(self, raw_text: str) -> "ProseField":
        r"""Build a ProseField with tokens from the tokenizer."""
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        return ProseField(
            file_path=Path("controls.yaml"),
            entry_id="controlAlpha",
            field_name="description",
            index=1,
            raw_text=raw_text,
            tokens=tokenize(raw_text),
        )

    def test_indented_dash_line_produces_folded_bullet_diagnostic(self):
        r"""
        A line with leading whitespace and '- item' triggers INVALID_FOLDED_BULLET.

        Given: A prose string with '  - technique one\n  - technique two'
        When: check_prose_field is called
        Then: At least one Diagnostic is returned for folded-bullet drift
        """
        text = "Techniques include:\n  - technique one\n  - technique two"
        field = self._make_field(text)
        diags = check_prose_field(field)
        assert len(diags) >= 1

    def test_fixture_folded_bullet_drift_produces_diagnostics(self):
        r"""
        The folded_bullet_drift.yaml fixture yields diagnostics for drift lines.

        Given: The subset_violations/folded_bullet_drift.yaml fixture
        When: find_prose_fields + check_prose_field are called
        Then: At least one Diagnostic is returned
        """
        yaml_path = _SUBSET_VIOL_DIR / "folded_bullet_drift.yaml"
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_prose_field(field))
        assert len(all_diags) >= 1

    def test_folded_bullet_diagnostic_reason_distinguishes_from_list(self):
        r"""
        The diagnostic reason text distinguishes folded-bullet from column-0 list.

        Given: Both '  - indented item' (folded-bullet) and '- col0 item' (list)
        When: check_prose_field is called on each
        Then: The reasons or the token kinds differ — the linter reflects the distinction
        """
        from precommit._prose_tokens import TokenKind, tokenize  # noqa: PLC0415

        folded_text = "  - indented bullet"
        list_text = "- column zero list"

        folded_tokens = tokenize(folded_text)
        list_tokens = tokenize(list_text)

        folded_kinds = {t.kind for t in folded_tokens}
        list_kinds = {t.kind for t in list_tokens}

        # The tokenizer must distinguish them (contract with the tokenizer)
        assert TokenKind.INVALID_FOLDED_BULLET in folded_kinds
        assert TokenKind.INVALID_LIST in list_kinds
        assert TokenKind.INVALID_FOLDED_BULLET not in list_kinds
        assert TokenKind.INVALID_LIST not in folded_kinds

    def test_pure_prose_with_no_drift_passes_folded_bullet_check(self):
        r"""
        Clean prose with no folded bullets produces no INVALID_FOLDED_BULLET diagnostic.

        Given: A ProseField with 'This control covers authentication mechanisms.'
        When: check_prose_field is called
        Then: No folded-bullet diagnostic is produced
        """
        from precommit._prose_tokens import TokenKind, tokenize  # noqa: PLC0415

        text = "This control covers authentication mechanisms."
        tokens = tokenize(text)
        # Confirm tokenizer produces no folded bullet
        assert not any(t.kind == TokenKind.INVALID_FOLDED_BULLET for t in tokens)

        field = ProseField(
            file_path=Path("controls.yaml"),
            entry_id="controlAlpha",
            field_name="description",
            index=0,
            raw_text=text,
            tokens=tokens,
        )
        diags = check_prose_field(field)
        assert diags == []


# ===========================================================================
# TestDiagnosticFormat
# ===========================================================================


class TestDiagnosticFormat:
    r"""Diagnostic format contract.

    Every diagnostic emitted by the subset linter must match:
        ^validate-yaml-prose-subset: <file>:<entry-id>:<field>[<index>]: <reason>$

    The regex _DIAG_PATTERN above locks this contract for the linter.
    """

    def _get_diags(
        self,
        text: str,
        entry_id: str = "riskAlpha",
        field_name: str = "shortDescription",
        index: int = 0,
    ) -> list["Diagnostic"]:
        r"""Tokenize text and run check_prose_field."""
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id=entry_id,
            field_name=field_name,
            index=index,
            raw_text=text,
            tokens=tokenize(text),
        )
        return check_prose_field(field)

    def _diag_to_line(self, diag: "Diagnostic") -> str:
        r"""Convert a Diagnostic to its string representation.

        Matches the ``_emit_diagnostic`` format:
        ``<hook_id>: <file>:<entry_id>:<field>[<index>][<nested_index>]: <reason>``

        The optional ``[<nested_index>]`` segment is appended only when
        ``diag.nested_index is not None`` (issue #285 extension).
        """
        idx_str = f"[{diag.index}]" if diag.index is not None else "[0]"
        nested_str = f"[{diag.nested_index}]" if getattr(diag, "nested_index", None) is not None else ""
        return (
            f"{diag.hook_id}: {diag.file_path}:{diag.entry_id}:"
            f"{diag.field_name}{idx_str}{nested_str}: {diag.reason}"
        )

    def test_diagnostic_hook_id_is_correct(self):
        r"""
        Diagnostic.hook_id is 'validate-yaml-prose-subset'.

        Given: Any prose violation
        When: check_prose_field returns a Diagnostic
        Then: Diagnostic.hook_id == 'validate-yaml-prose-subset'
        """
        diags = self._get_diags("See https://example.com here.")
        assert len(diags) >= 1
        assert diags[0].hook_id == "validate-yaml-prose-subset"

    def test_diagnostic_file_path_matches_input(self):
        r"""
        Diagnostic.file_path matches the ProseField.file_path.

        Given: A ProseField with file_path=Path('risks.yaml')
        When: check_prose_field returns a Diagnostic
        Then: Diagnostic.file_path == Path('risks.yaml')
        """
        diags = self._get_diags("See https://example.com here.")
        assert len(diags) >= 1
        assert diags[0].file_path == Path("risks.yaml")

    def test_diagnostic_entry_id_matches_input(self):
        r"""
        Diagnostic.entry_id matches the ProseField.entry_id.

        Given: A ProseField with entry_id='riskBeta'
        When: check_prose_field returns a Diagnostic
        Then: Diagnostic.entry_id == 'riskBeta'
        """
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskBeta",
            field_name="shortDescription",
            index=0,
            raw_text="See https://example.com here.",
            tokens=tokenize("See https://example.com here."),
        )
        diags = check_prose_field(field)
        assert len(diags) >= 1
        assert diags[0].entry_id == "riskBeta"

    def test_diagnostic_field_and_index_match_input(self):
        r"""
        Diagnostic.field_name and .index match the ProseField values.

        Given: A ProseField with field_name='longDescription' and index=2
        When: check_prose_field returns a Diagnostic
        Then: Diagnostic.field_name == 'longDescription' and .index == 2
        """
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="longDescription",
            index=2,
            raw_text="See https://example.com here.",
            tokens=tokenize("See https://example.com here."),
        )
        diags = check_prose_field(field)
        assert len(diags) >= 1
        assert diags[0].field_name == "longDescription"
        assert diags[0].index == 2

    def test_diagnostic_format_string_matches_regex(self):
        r"""
        The formatted diagnostic string matches the committed regex contract.

        Given: A URL violation producing a Diagnostic
        When: The Diagnostic is formatted as its string representation
        Then: The string matches _DIAG_PATTERN
        """
        diags = self._get_diags("See https://example.com here.")
        assert len(diags) >= 1
        diag = diags[0]
        line = self._diag_to_line(diag)
        assert _DIAG_PATTERN.match(line), f"Diagnostic line does not match pattern: {line!r}"

    def test_stderr_output_from_main_matches_format(self, tmp_path, capsys):
        r"""
        main() stderr output matches the diagnostic format regex for every line.

        Given: A YAML file with a URL violation
        When: main() is called without --block
        Then: Every non-empty stderr line matches _DIAG_PATTERN
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"], extra_props={"shortDescription": prose_ref})
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {"risks": [_make_risk("riskAlpha", short=["See https://example.com here."])]},
        )

        with pytest.raises(SystemExit):
            main([str(yaml_path), "--schema-dir", str(schema_dir)])
        captured = capsys.readouterr()
        lines = [ln for ln in captured.err.splitlines() if ln.strip()]
        assert len(lines) >= 1
        for line in lines:
            assert _DIAG_PATTERN.match(line), f"Line does not match diagnostic pattern: {line!r}"

    def test_diagnostic_reason_is_nonempty(self):
        r"""
        Every Diagnostic produced by check_prose_field has a non-empty reason.

        Given: Any prose violation
        When: check_prose_field returns Diagnostics
        Then: All Diagnostic.reason fields are non-empty strings
        """
        diags = self._get_diags("See https://example.com and <br/> in prose.")
        assert all(d.reason for d in diags)

    def test_multiple_violations_use_same_format(self):
        r"""
        When multiple violations exist, all Diagnostics use consistent format.

        Given: Prose with a URL and an HTML tag (two violation classes)
        When: check_prose_field returns multiple Diagnostics
        Then: All use hook_id 'validate-yaml-prose-subset' and have non-empty reason
        """
        diags = self._get_diags("See https://example.com and <br/> in prose.")
        assert len(diags) >= 2
        for d in diags:
            assert d.hook_id == "validate-yaml-prose-subset"
            assert d.reason

    def test_diagnostic_reason_contains_snippet_suffix(self):
        r"""
        ADR-017 D4: each Diagnostic reason ends with "at '<token-value>'".

        Given: Prose with '<a href=\"#riskBar\">' (HTML tag violation)
        When: check_prose_field returns a Diagnostic
        Then: Diagnostic.reason contains the token value as "at '<a href=\"#riskBar\">'"
        """
        diags = self._get_diags('See <a href="#riskBar">link</a>.')
        assert len(diags) >= 1
        # Find the diagnostic for the opening <a> tag
        open_tag_diags = [d for d in diags if "<a href=" in d.reason]
        assert len(open_tag_diags) >= 1, f"Expected snippet in reason; got: {[d.reason for d in diags]}"
        # Snippet format: at '<a href="#riskBar">'
        assert "at '" in open_tag_diags[0].reason

    def test_diagnostic_reason_snippet_for_closing_tag(self):
        r"""
        The closing tag gets its own diagnostic with its own snippet.

        Given: Prose with '<a href=\"#riskBar\">link</a>'
        When: check_prose_field returns Diagnostics
        Then: At least one Diagnostic has '</a>' in the reason (as the closing-tag snippet)
        """
        diags = self._get_diags('See <a href="#riskBar">link</a>.')
        assert len(diags) >= 2
        closing_tag_diags = [d for d in diags if "</a>" in d.reason]
        assert len(closing_tag_diags) >= 1

    def test_dotted_field_name_in_diagnostic_format(self, tmp_path):
        r"""
        Diagnostics for nested prose fields use dotted field names in the format string.

        Given: A YAML with a tourContent.introduced HTML violation
        When: find_prose_fields + check_prose_field are called
        Then: The formatted diagnostic line contains 'tourContent.introduced' in the field segment
        """
        yaml_path = _SUBSET_VIOL_DIR / "tour_content_nested.yaml"
        all_diags = []
        for field in find_prose_fields(yaml_path, _SCHEMA_DIR):
            all_diags.extend(check_prose_field(field))
        tour_diags = [d for d in all_diags if "tourContent.introduced" in d.field_name]
        assert len(tour_diags) >= 1
        # Format the diagnostic line and confirm it matches the committed regex
        diag = tour_diags[0]
        line = self._diag_to_line(diag)
        assert _DIAG_PATTERN.match(line), f"Diagnostic line does not match pattern: {line!r}"

    @pytest.mark.timeout(2)
    def test_diagnostic_pattern_resists_redos(self):
        r"""
        CodeQL #20 regression guard: _DIAG_PATTERN must match in bounded time on a
        many-dotted-segments adversarial input.

        Given: An input shaped like 'validate-yaml-prose-subset: 9:9:9' + '.9' * N + ':NO_BRACKET'
        When: _DIAG_PATTERN.match(input) runs against N=50 dotted segments
        Then: The match completes in well under 1 second AND returns None (input is malformed)

        Pre-fix, the ambiguous quantifier [^:\[]+(?:\.[^:\[]+)* admitted exponential
        backtracking when the [<digit>] suffix failed: ~53s on N=30 segments.  The fix
        adds the dot to the inner negated character class — [^:\[.]+(?:\.[^:\[.]+)* —
        making the dot exclusively the segment separator and eliminating the ambiguity.
        Linear-time guaranteed.
        """
        import time as _time  # local import keeps top-level imports minimal

        redos_seed = "validate-yaml-prose-subset: 9:9:9" + ".9" * 50 + ":NO_BRACKET"
        t0 = _time.monotonic()
        result = _DIAG_PATTERN.match(redos_seed)
        elapsed = _time.monotonic() - t0
        assert result is None, "malformed redos seed must not match the diagnostic format"
        assert elapsed < 1.0, (
            f"diagnostic regex took {elapsed:.3f}s on redos seed; "
            f"should be linear-time (sub-millisecond).  CodeQL #20 may have regressed."
        )


# ===========================================================================
# TestCLIExitCodes
# ===========================================================================


class TestCLIExitCodes:
    r"""CLI exit-code contract.

    Warn-only mode (no --block): always exits 0.
    Block mode (--block):        exits 1 on any violation, 0 if clean.
    Usage error / bad file:      exits 2.
    """

    def _write_test_files(self, tmp_path: Path, prose: list[str], clean: bool = False) -> tuple[Path, Path]:
        r"""Write a schema dir and a risks YAML to tmp_path for CLI tests."""
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"], extra_props={"shortDescription": prose_ref})
        yaml_path = _write_yaml(tmp_path, "risks.yaml", {"risks": [_make_risk("riskAlpha", short=prose)]})
        return yaml_path, schema_dir

    def test_warn_mode_with_violation_exits_0(self, tmp_path, capsys):
        r"""
        Warn-only mode (no --block) always exits 0 even with violations.

        Given: A YAML with a URL violation and no --block flag
        When: main() is called
        Then: sys.exit(0)
        """
        yaml_path, schema_dir = self._write_test_files(tmp_path, ["See https://example.com here."])
        with pytest.raises(SystemExit) as exc_info:
            main([str(yaml_path), "--schema-dir", str(schema_dir)])
        assert exc_info.value.code == 0

    def test_warn_mode_clean_input_exits_0(self, tmp_path, capsys):
        r"""
        Warn-only mode with clean input exits 0 and produces no stderr.

        Given: A YAML with clean prose and no --block flag
        When: main() is called
        Then: sys.exit(0); no stderr output
        """
        yaml_path, schema_dir = self._write_test_files(tmp_path, ["Clean prose with **bold** and *italic*."])
        with pytest.raises(SystemExit) as exc_info:
            main([str(yaml_path), "--schema-dir", str(schema_dir)])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_block_mode_with_violation_exits_1(self, tmp_path, capsys):
        r"""
        Block mode with any violation exits 1.

        Given: A YAML with a URL violation and --block flag
        When: main() is called
        Then: sys.exit(1) (or any non-zero code indicating failure)
        """
        yaml_path, schema_dir = self._write_test_files(tmp_path, ["See https://example.com here."])
        with pytest.raises(SystemExit) as exc_info:
            main([str(yaml_path), "--schema-dir", str(schema_dir), "--block"])
        assert exc_info.value.code == 1

    def test_block_mode_clean_input_exits_0(self, tmp_path, capsys):
        r"""
        Block mode with clean input exits 0.

        Given: A YAML with clean prose and --block flag
        When: main() is called
        Then: sys.exit(0)
        """
        yaml_path, schema_dir = self._write_test_files(tmp_path, ["Clean prose with **bold**."])
        with pytest.raises(SystemExit) as exc_info:
            main([str(yaml_path), "--schema-dir", str(schema_dir), "--block"])
        assert exc_info.value.code == 0

    def test_warn_mode_violations_appear_on_stderr(self, tmp_path, capsys):
        r"""
        In warn-only mode, violations are emitted to stderr.

        Given: A YAML with a URL violation
        When: main() is called without --block
        Then: stderr contains the hook name prefix
        """
        yaml_path, schema_dir = self._write_test_files(tmp_path, ["See https://example.com here."])
        with pytest.raises(SystemExit):
            main([str(yaml_path), "--schema-dir", str(schema_dir)])
        captured = capsys.readouterr()
        assert "validate-yaml-prose-subset" in captured.err

    def test_multiple_files_in_one_invocation(self, tmp_path, capsys):
        r"""
        main() accepts multiple file paths in one invocation.

        Given: Two YAML files (one clean, one with a violation) and a shared schema dir
        When: main() is called with both file paths
        Then: Diagnostics appear only for the violating file; exits 0 (warn mode)
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        _write_mock_schema(
            schema_dir,
            "risk",
            ["riskAlpha", "riskBeta"],
            extra_props={"shortDescription": prose_ref},
        )
        clean_path = _write_yaml(
            tmp_path, "clean.yaml", {"risks": [_make_risk("riskAlpha", short=["Clean prose."])]}
        )
        viol_path = _write_yaml(
            tmp_path,
            "viol.yaml",
            {"risks": [_make_risk("riskBeta", short=["See https://example.com."])]},
        )

        with pytest.raises(SystemExit) as exc_info:
            main([str(clean_path), str(viol_path), "--schema-dir", str(schema_dir)])
        assert exc_info.value.code == 0  # warn mode
        captured = capsys.readouterr()
        assert "viol.yaml" in captured.err
        assert "clean.yaml" not in captured.err

    def test_no_args_exits_gracefully(self, capsys):
        r"""
        main() with no file arguments exits without crashing.

        Given: No file arguments (pre-commit may pass zero files when no files match)
        When: main() is called with an empty argv
        Then: Exits 0 (no files to check, nothing to report)
        """
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 0

    def test_subprocess_invocation_warn_mode_returns_0(self, tmp_path):
        r"""
        End-to-end subprocess invocation in warn mode returns exit code 0.

        Given: A YAML with a URL violation; subprocess calls the module directly
        When: python3 validate_yaml_prose_subset.py <file> --schema-dir <dir>
        Then: Return code is 0 (warn-only mode)
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"], extra_props={"shortDescription": prose_ref})
        yaml_path = _write_yaml(
            tmp_path, "risks.yaml", {"risks": [_make_risk("riskAlpha", short=["See https://example.com."])]}
        )
        result = subprocess.run(
            [sys.executable, str(_HOOK_MODULE), str(yaml_path), "--schema-dir", str(schema_dir)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0


# ===========================================================================
# TestEdgeCases
# ===========================================================================


class TestEdgeCases:
    r"""Edge cases and error handling."""

    def test_empty_prose_string_produces_no_diagnostic(self):
        r"""
        An empty string in a prose field produces no diagnostics.

        Given: A ProseField with raw_text == ''
        When: check_prose_field is called
        Then: Returns no diagnostics (tokenizer returns [] for empty input)
        """
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text="",
            tokens=tokenize(""),
        )
        assert check_prose_field(field) == []

    def test_unclosed_sentinel_does_not_crash(self):
        r"""
        Prose with an unclosed '{{riskFoo' does not crash the linter.

        Given: A ProseField with '{{riskFoo is unclosed' (no closing }})
        When: check_prose_field is called
        Then: No exception is raised; linter returns a list (possibly empty)

        The tokenizer emits a TEXT token for unclosed {{ per its spec.
        The subset linter must not crash when no SENTINEL token is present.
        """
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        text = "{{riskFoo is unclosed"
        tokens = tokenize(text)
        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text=text,
            tokens=tokens,
        )
        result = check_prose_field(field)
        assert isinstance(result, list)

    def test_plain_text_only_passes(self):
        r"""
        Prose containing only plain text produces no diagnostics.

        Given: 'This is a plain sentence with no special tokens.'
        When: check_prose_field is called
        Then: Returns no diagnostics
        """
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        text = "This is a plain sentence with no special tokens."
        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text=text,
            tokens=tokenize(text),
        )
        assert check_prose_field(field) == []

    def test_bold_and_italic_combined_passes(self):
        r"""
        Combined bold + italic (composable per ADR-017 D1) produces no diagnostics.

        Given: 'The **emphatically *not* allowed** path is **critical**.'
        When: check_prose_field is called
        Then: Returns no diagnostics
        """
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        text = "The **emphatically *not* allowed** path is **critical**."
        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text=text,
            tokens=tokenize(text),
        )
        assert check_prose_field(field) == []

    def test_dotted_ref_identifier_passes(self):
        r"""
        {{ref:nist-ai-rmf-1.0}} with a dot in the identifier passes the subset lint.

        Given: 'Per {{ref:nist-ai-rmf-1.0}} section 3.'
        When: check_prose_field is called
        Then: Returns no diagnostics (the dot is valid per the tokenizer's regex)
        """
        from precommit._prose_tokens import TokenKind, tokenize  # noqa: PLC0415

        text = "Per {{ref:nist-ai-rmf-1.0}} section 3."
        tokens = tokenize(text)
        # Confirm tokenizer accepts the dotted ref
        assert any(t.kind == TokenKind.SENTINEL_REF for t in tokens)

        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text=text,
            tokens=tokens,
        )
        assert check_prose_field(field) == []

    def test_real_corpus_does_not_crash_in_warn_mode(self):
        r"""
        Running against the real risks.yaml in warn-only mode does not crash.

        Given: The actual risk-map/yaml/risks.yaml and schemas/ directory
        When: find_prose_fields + check_prose_field are called
        Then: No exception is raised; a list of Diagnostics is returned

        The live corpus has warn-only violations; this test verifies graceful handling.
        """
        yaml_path = _REPO_ROOT / "risk-map" / "yaml" / "risks.yaml"
        schema_dir = _REPO_ROOT / "risk-map" / "schemas"
        assert yaml_path.exists(), f"Real risks.yaml not found at {yaml_path}"
        all_diags = []
        for field in find_prose_fields(yaml_path, schema_dir):
            all_diags.extend(check_prose_field(field))
        assert isinstance(all_diags, list)

    def test_missing_file_exits_with_error_code(self, capsys):
        r"""
        A non-existent file path causes an appropriate exit.

        Given: A file path that does not exist
        When: main() is called with that path
        Then: Exits with a non-zero code (2 for usage/IO error)
        """
        with pytest.raises(SystemExit) as exc_info:
            main(["/nonexistent/path/does_not_exist.yaml"])
        assert exc_info.value.code == 2


# ===========================================================================
# TestTokenizerConsistency
# ===========================================================================


class TestTokenizerConsistency:
    r"""The subset linter must not diverge from the tokenizer's grammar.

    These tests confirm the linter delegates to tokenize() rather than adding
    its own detection logic that could differ from the tokenizer.
    """

    def _check(self, text: str) -> list:
        r"""Tokenize and run check_prose_field."""
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text=text,
            tokens=tokenize(text),
        )
        return check_prose_field(field)

    def test_url_diagnostic_uses_tokenizer_invalid_url_token(self):
        r"""
        The subset linter's URL diagnostic originates from INVALID_URL tokens.

        Given: Prose with a raw URL
        When: check_prose_field is called
        Then: The tokenizer produces an INVALID_URL token for the URL

        This guards against the linter adding a separate URL regex that could
        diverge from the tokenizer's classification.
        """
        from precommit._prose_tokens import TokenKind, tokenize  # noqa: PLC0415

        text = "See https://example.com for details."
        tokens = tokenize(text)
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens), "Tokenizer must produce INVALID_URL"
        # And the linter must produce a diagnostic
        diags = self._check(text)
        assert len(diags) >= 1

    def test_html_diagnostic_uses_tokenizer_invalid_html_token(self):
        r"""
        The subset linter's HTML diagnostic originates from INVALID_HTML tokens.

        Given: Prose with a raw HTML tag
        When: check_prose_field is called
        Then: The tokenizer produces an INVALID_HTML token
        """
        from precommit._prose_tokens import TokenKind, tokenize  # noqa: PLC0415

        text = "The <strong>critical</strong> element."
        tokens = tokenize(text)
        assert any(t.kind == TokenKind.INVALID_HTML for t in tokens), "Tokenizer must produce INVALID_HTML"
        diags = self._check(text)
        assert len(diags) >= 1

    def test_folded_bullet_diagnostic_uses_invalid_folded_bullet_token(self):
        r"""
        The folded-bullet diagnostic originates from INVALID_FOLDED_BULLET tokens.

        Given: Prose with whitespace-prefixed '- item'
        When: check_prose_field is called
        Then: The tokenizer produces INVALID_FOLDED_BULLET and the linter surfaces it
        """
        from precommit._prose_tokens import TokenKind, tokenize  # noqa: PLC0415

        text = "Items:\n  - technique one\n  - technique two"
        tokens = tokenize(text)
        assert any(t.kind == TokenKind.INVALID_FOLDED_BULLET for t in tokens)
        diags = self._check(text)
        assert len(diags) >= 1

    def test_invalid_sentinel_produces_diagnostic_from_tokenizer_token(self):
        r"""
        INVALID_SENTINEL tokens from the tokenizer are surfaced as Diagnostics.

        Given: Prose with a structurally valid but semantically invalid sentinel {{xyz}}
        When: check_prose_field is called
        Then: The tokenizer produces INVALID_SENTINEL and the linter reports it
        """
        from precommit._prose_tokens import TokenKind, tokenize  # noqa: PLC0415

        text = "See {{xyzUnknown}} for context."
        tokens = tokenize(text)
        assert any(t.kind == TokenKind.INVALID_SENTINEL for t in tokens)
        diags = self._check(text)
        assert len(diags) >= 1

    def test_clean_prose_has_no_invalid_tokens(self):
        r"""
        Clean prose contains no INVALID_* tokens, confirming no false positives.

        Given: 'A **bold** and *italic* sentence with plain text.'
        When: tokenize() is called
        Then: No INVALID_* kind tokens are present — the linter should produce no diagnostics
        """
        from precommit._prose_tokens import TokenKind, tokenize  # noqa: PLC0415

        text = "A **bold** and *italic* sentence with plain text."
        tokens = tokenize(text)
        invalid_kinds = {k for k in TokenKind if k.value.startswith("INVALID")}
        assert not any(t.kind in invalid_kinds for t in tokens)
        assert self._check(text) == []


# ===========================================================================
# TestFoldedBulletVsListAtColumn0
# ===========================================================================


class TestFoldedBulletVsListAtColumn0:
    r"""Tokenizer commitment: folded-bullet drift and column-0 list are distinct.

    Both are rejected; both must produce distinct reasons reflecting the
    different token kinds (INVALID_FOLDED_BULLET vs INVALID_LIST).
    """

    def _check_kinds(self, text: str) -> set:
        r"""Return the set of TokenKind values produced by the tokenizer."""
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        return {t.kind for t in tokenize(text)}

    def test_column_zero_dash_is_invalid_list_not_folded_bullet(self):
        r"""
        '- item' at column 0 produces INVALID_LIST, not INVALID_FOLDED_BULLET.

        Given: '- item one' at column 0
        When: tokenize() is called
        Then: Produces INVALID_LIST; does NOT produce INVALID_FOLDED_BULLET
        """
        from precommit._prose_tokens import TokenKind  # noqa: PLC0415

        kinds = self._check_kinds("- item one")
        assert TokenKind.INVALID_LIST in kinds
        assert TokenKind.INVALID_FOLDED_BULLET not in kinds

    def test_indented_dash_is_folded_bullet_not_invalid_list(self):
        r"""
        '  - item' (with leading whitespace) produces INVALID_FOLDED_BULLET.

        Given: '  - item one' at start of string
        When: tokenize() is called
        Then: Produces INVALID_FOLDED_BULLET; does NOT produce INVALID_LIST
        """
        from precommit._prose_tokens import TokenKind  # noqa: PLC0415

        kinds = self._check_kinds("  - item one")
        assert TokenKind.INVALID_FOLDED_BULLET in kinds
        assert TokenKind.INVALID_LIST not in kinds

    def test_subset_linter_rejects_column_zero_list(self):
        r"""
        The subset linter produces a diagnostic for column-0 list markers.

        Given: A ProseField with '- item one\n- item two'
        When: check_prose_field is called
        Then: At least one Diagnostic is returned
        """
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        text = "- item one\n- item two"
        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text=text,
            tokens=tokenize(text),
        )
        assert len(check_prose_field(field)) >= 1

    def test_subset_linter_rejects_folded_bullet(self):
        r"""
        The subset linter produces a diagnostic for folded-bullet drift lines.

        Given: A ProseField with '  - indented item' (leading whitespace + dash)
        When: check_prose_field is called
        Then: At least one Diagnostic is returned
        """
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        text = "  - indented item"
        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text=text,
            tokens=tokenize(text),
        )
        assert len(check_prose_field(field)) >= 1

    def test_reasons_differ_between_list_and_folded_bullet(self):
        r"""
        Diagnostics for list-at-column-0 and folded-bullet have distinct reasons.

        Given: Two ProseFields — one with column-0 list, one with folded-bullet
        When: check_prose_field is called on each
        Then: The diagnostic reasons are not identical strings (or token kinds differ)

        This confirms the linter surfaces the tokenizer's distinction rather than
        homogenising both into a single generic 'list' reason.
        """
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        list_field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text="- column zero item",
            tokens=tokenize("- column zero item"),
        )
        folded_field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text="  - folded bullet item",
            tokens=tokenize("  - folded bullet item"),
        )
        list_diags = check_prose_field(list_field)
        folded_diags = check_prose_field(folded_field)

        assert len(list_diags) >= 1
        assert len(folded_diags) >= 1

        # The reasons must not be identical — the distinction must be surfaced
        list_reason = list_diags[0].reason.lower()
        folded_reason = folded_diags[0].reason.lower()
        # At minimum the reasons should differ OR both mention distinct concepts
        # (We assert they are different; if the implementation uses the same
        # reason for both, this test fails, prompting a fix.)
        assert (
            list_reason != folded_reason
            or ("list" in list_reason and "folded" in folded_reason)
            or ("list" in list_reason and "bullet" in folded_reason)
        ), (
            f"Expected different reasons for list vs folded-bullet; "
            f"got list={list_reason!r}, folded={folded_reason!r}"
        )

    def test_asterisk_list_marker_at_column_zero_produces_diagnostic(self):
        r"""
        '* item' at column 0 is also an INVALID_LIST token and produces a diagnostic.

        Given: A ProseField with '* item one'
        When: check_prose_field is called
        Then: At least one Diagnostic is returned
        """
        from precommit._prose_tokens import TokenKind, tokenize  # noqa: PLC0415

        text = "* item one"
        tokens = tokenize(text)
        assert any(t.kind == TokenKind.INVALID_LIST for t in tokens)

        field = ProseField(
            file_path=Path("risks.yaml"),
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
            raw_text=text,
            tokens=tokens,
        )
        assert len(check_prose_field(field)) >= 1


# ===========================================================================
# TestNestedIndexDiagnostic
# ===========================================================================


class TestNestedIndexDiagnostic:
    r"""Diagnostics on inner-list strings carry nested_index and emit [outer][inner].

    Issue #285: when a prose-field value uses the nested-array shape
    (``items: oneOf [string, array<string>]``), the linter must surface both
    the outer index and the inner index so the exact string can be located.

    Three behavioural contracts are verified here:

    1. ``Diagnostic.nested_index`` is populated from ``ProseField.nested_index``
       when the violating string came from an inner list.
    2. The emitted stderr location string uses the ``[outer][inner]:`` form for
       inner-list violations (not the ambiguous bare ``[outer]:`` form).
    3. For flat-array violations (``nested_index is None``), the emitted line
       is unchanged — the bare ``[outer]:`` form without a second bracket pair.
    """

    def _make_nested_field(
        self,
        raw_text: str,
        index: int,
        nested_index: int | None,
        field_name: str = "shortDescription",
        entry_id: str = "riskAlpha",
    ) -> "ProseField":
        r"""Build a ProseField that simulates an inner-list source string.

        The ``nested_index`` argument is forwarded to ``ProseField`` so callers
        can exercise both the nested (``nested_index=<int>``) and flat-array
        (``nested_index=None``) paths without going through the full YAML
        discovery pipeline.
        """
        from precommit._prose_tokens import tokenize  # noqa: PLC0415

        return ProseField(
            file_path=Path("risks.yaml"),
            entry_id=entry_id,
            field_name=field_name,
            index=index,
            raw_text=raw_text,
            tokens=tokenize(raw_text),
            nested_index=nested_index,
        )

    # ------------------------------------------------------------------
    # 1. Diagnostic carries nested_index from ProseField
    # ------------------------------------------------------------------

    def test_diagnostic_nested_index_populated_from_prose_field(self):
        r"""
        Diagnostic.nested_index reflects the inner-list position from ProseField.

        Given: A ProseField with index=3 and nested_index=1, containing an HTML
               tag violation
        When: check_prose_field is called
        Then: Every returned Diagnostic has .index == 3 and .nested_index == 1
        """
        field = self._make_nested_field(
            raw_text="See <br/> in an inner-list string.",
            index=3,
            nested_index=1,
        )
        diags = check_prose_field(field)
        assert len(diags) >= 1, "Expected at least one diagnostic for the HTML tag"
        for diag in diags:
            assert diag.index == 3, f"Expected index=3, got {diag.index}"
            assert diag.nested_index == 1, (
                f"Expected nested_index=1 on Diagnostic; got {diag.nested_index!r}. "
                "Diagnostic.nested_index must mirror ProseField.nested_index (issue #285)."
            )

    def test_diagnostic_nested_index_is_none_for_flat_array_field(self):
        r"""
        Diagnostic.nested_index is None when the source ProseField is a flat-array item.

        Given: A ProseField with nested_index=None (flat-array shape), containing
               an HTML tag violation
        When: check_prose_field is called
        Then: Every returned Diagnostic has .nested_index is None
        """
        field = self._make_nested_field(
            raw_text="See <br/> in a flat-array string.",
            index=2,
            nested_index=None,
        )
        diags = check_prose_field(field)
        assert len(diags) >= 1, "Expected at least one diagnostic for the HTML tag"
        for diag in diags:
            assert diag.nested_index is None, (
                f"Expected nested_index=None for flat-array ProseField; got {diag.nested_index!r}."
            )

    def test_diagnostic_nested_index_preserved_across_multiple_violations(self):
        r"""
        All Diagnostics from one inner-list ProseField share the same nested_index.

        Given: A ProseField with nested_index=0 containing two HTML tags
               (<strong>...</strong>)
        When: check_prose_field is called
        Then: At least two Diagnostics are returned and all have nested_index == 0
        """
        field = self._make_nested_field(
            raw_text="The <strong>critical</strong> path.",
            index=1,
            nested_index=0,
        )
        diags = check_prose_field(field)
        assert len(diags) >= 2, "Expected diagnostics for both <strong> and </strong> tags"
        for diag in diags:
            assert diag.nested_index == 0, (
                f"All Diagnostics from one inner-list field must share nested_index=0; got {diag.nested_index!r}."
            )

    # ------------------------------------------------------------------
    # 2. Emitted location string uses [outer][inner] for nested violations
    # ------------------------------------------------------------------

    def test_emitted_stderr_contains_double_bracket_for_nested_violation(self, tmp_path, capsys):
        r"""
        main() emits ``<field>[<outer>][<inner>]:`` for inner-list violations.

        Given: The subset_violations/nested_list_html_violation.yaml fixture —
               riskAlpha.shortDescription is a mixed array where outer index 1 is
               a nested list; inner index 1 contains ``<strong>forbidden HTML</strong>``
        When: main() is called with the fixture file
        Then: At least one stderr line contains 'shortDescription[1][1]:' exactly
              (confirming both the outer and inner index are surfaced)
        """
        schema_dir = _SCHEMA_DIR
        yaml_path = _SUBSET_VIOL_DIR / "nested_list_html_violation.yaml"
        with pytest.raises(SystemExit):
            main([str(yaml_path), "--schema-dir", str(schema_dir)])
        captured = capsys.readouterr()
        lines = [ln for ln in captured.err.splitlines() if ln.strip()]
        assert len(lines) >= 1, "Expected at least one diagnostic line"
        double_bracket_lines = [ln for ln in lines if "shortDescription[1][1]:" in ln]
        assert len(double_bracket_lines) >= 1, (
            "Expected a line containing 'shortDescription[1][1]:' for the inner-index "
            "diagnostic (issue #285). Got stderr lines:\n" + "\n".join(f"  {ln}" for ln in lines)
        )

    def test_emitted_location_uses_outer_inner_bracket_not_bare_outer(self, tmp_path, capsys):
        r"""
        The inner-list violation line does NOT collapse to the bare [outer]: form.

        Given: The subset_violations/nested_list_html_violation.yaml fixture
        When: main() is called
        Then: No stderr line for the inner-list violation contains
              'shortDescription[1]:' without the second bracket pair
              (i.e., the bare [outer]: form is NOT emitted for inner-list strings)
        """
        schema_dir = _SCHEMA_DIR
        yaml_path = _SUBSET_VIOL_DIR / "nested_list_html_violation.yaml"
        with pytest.raises(SystemExit):
            main([str(yaml_path), "--schema-dir", str(schema_dir)])
        captured = capsys.readouterr()
        lines = [ln for ln in captured.err.splitlines() if ln.strip()]
        # A bare [1]: would look like "shortDescription[1]: " (no second bracket).
        # We verify no diagnostic line matches the ambiguous-collapse form.
        bare_outer_lines = [
            ln for ln in lines if "shortDescription[1]:" in ln and "shortDescription[1][" not in ln
        ]
        assert len(bare_outer_lines) == 0, (
            f"Expected NO bare 'shortDescription[1]:' lines for an inner-list violation; "
            f"found {len(bare_outer_lines)} line(s):\n"
            + "\n".join(f"  {ln}" for ln in bare_outer_lines)
            + "\nAll lines:\n"
            + "\n".join(f"  {ln}" for ln in lines)
        )

    def test_all_nested_diagnostic_lines_match_extended_format_regex(self, tmp_path, capsys):
        r"""
        Every stderr line from the nested-violation fixture matches _DIAG_PATTERN.

        Given: The subset_violations/nested_list_html_violation.yaml fixture
        When: main() is called
        Then: All non-empty stderr lines match the updated _DIAG_PATTERN, which
              accepts the optional second bracket pair ``(?:\[\d+\])?``
        """
        schema_dir = _SCHEMA_DIR
        yaml_path = _SUBSET_VIOL_DIR / "nested_list_html_violation.yaml"
        with pytest.raises(SystemExit):
            main([str(yaml_path), "--schema-dir", str(schema_dir)])
        captured = capsys.readouterr()
        lines = [ln for ln in captured.err.splitlines() if ln.strip()]
        assert len(lines) >= 1
        for line in lines:
            assert _DIAG_PATTERN.match(line), f"Diagnostic line does not match extended _DIAG_PATTERN: {line!r}"

    # ------------------------------------------------------------------
    # 3. Flat-array format is unchanged (nested_index is None path)
    # ------------------------------------------------------------------

    def test_flat_array_diagnostic_emits_single_bracket_only(self, tmp_path, capsys):
        r"""
        A flat-array violation still emits only [outer]: with no second bracket pair.

        Given: A YAML with a flat-array shortDescription containing one HTML violation
               at outer index 0 (nested_index=None)
        When: main() is called
        Then: The stderr line contains '[0]:' and does NOT contain '[0][':
              confirming the flat-array format is byte-for-byte unchanged
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
        _write_mock_schema(schema_dir, "risk", ["riskAlpha"], extra_props={"shortDescription": prose_ref})
        yaml_path = _write_yaml(
            tmp_path,
            "risks.yaml",
            {"risks": [_make_risk("riskAlpha", short=["Clean.", "See <br/> in flat array."])]},
        )
        with pytest.raises(SystemExit):
            main([str(yaml_path), "--schema-dir", str(schema_dir)])
        captured = capsys.readouterr()
        lines = [ln for ln in captured.err.splitlines() if ln.strip()]
        assert len(lines) >= 1, "Expected at least one diagnostic for the HTML tag"
        # All lines for shortDescription must have single-bracket only.
        desc_lines = [ln for ln in lines if "shortDescription" in ln]
        assert len(desc_lines) >= 1
        for line in desc_lines:
            # Must contain single-bracket form.
            assert re.search(r"shortDescription\[\d+\]:", line), f"Expected single-bracket form in: {line!r}"
            # Must NOT contain double-bracket form.
            assert not re.search(r"shortDescription\[\d+\]\[\d+\]:", line), (
                f"Flat-array line must not contain double brackets: {line!r}"
            )


# ===========================================================================
# TestLiveCorpusBaseline  (Spike S2)
# ===========================================================================


@pytest.mark.live_corpus
class TestLiveCorpusBaseline:
    r"""
    Spike S2: live-corpus regression baseline for the prose-subset linter.

    Guards that the linter produces ZERO diagnostics across the four content
    YAMLs in --block mode (confirmed by the Spike S3 probe before ADR-028
    was flipped to Accepted).

    ADR-028 §9.3 Spike S2 — gates Phase 5 regression check.
    """

    _REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
    _YAML_DIR = _REPO_ROOT / "risk-map" / "yaml"
    _CONTENT_YAMLS = ["risks.yaml", "controls.yaml", "components.yaml", "personas.yaml"]

    def _run_block(self, yaml_file: str) -> "subprocess.CompletedProcess[str]":
        """Run the linter in --block mode on a single content YAML."""
        import subprocess as _sp

        script = Path(__file__).parent.parent / "precommit" / "validate_yaml_prose_subset.py"
        return _sp.run(
            [sys.executable, str(script), "--block", str(self._YAML_DIR / yaml_file)],
            capture_output=True,
            text=True,
        )

    def test_risks_yaml_produces_zero_diagnostics(self):
        """
        Given: risk-map/yaml/risks.yaml (current corpus)
        When: validate_yaml_prose_subset --block is run
        Then: exits 0 (zero diagnostics)

        Baseline captured 2026-05-28.
        """
        result = self._run_block("risks.yaml")
        assert result.returncode == 0, f"risks.yaml produced diagnostics:\n{result.stderr}"
        assert result.stderr.strip() == "", f"risks.yaml produced unexpected stderr:\n{result.stderr}"

    def test_controls_yaml_produces_zero_diagnostics(self):
        """
        Given: risk-map/yaml/controls.yaml (current corpus)
        When: validate_yaml_prose_subset --block is run
        Then: exits 0 (zero diagnostics)
        """
        result = self._run_block("controls.yaml")
        assert result.returncode == 0, f"controls.yaml produced diagnostics:\n{result.stderr}"
        assert result.stderr.strip() == "", f"controls.yaml produced unexpected stderr:\n{result.stderr}"

    def test_components_yaml_produces_zero_diagnostics(self):
        """
        Given: risk-map/yaml/components.yaml (current corpus)
        When: validate_yaml_prose_subset --block is run
        Then: exits 0 (zero diagnostics)
        """
        result = self._run_block("components.yaml")
        assert result.returncode == 0, f"components.yaml produced diagnostics:\n{result.stderr}"
        assert result.stderr.strip() == "", f"components.yaml produced unexpected stderr:\n{result.stderr}"

    def test_personas_yaml_produces_zero_diagnostics(self):
        """
        Given: risk-map/yaml/personas.yaml (current corpus)
        When: validate_yaml_prose_subset --block is run
        Then: exits 0 (zero diagnostics)
        """
        result = self._run_block("personas.yaml")
        assert result.returncode == 0, f"personas.yaml produced diagnostics:\n{result.stderr}"
        assert result.stderr.strip() == "", f"personas.yaml produced unexpected stderr:\n{result.stderr}"


# ===========================================================================
# TestNestedEmphasisRejection — ADR-028 D5 depth-counter linter
# ===========================================================================
# These tests assert the ADR-028 D5 depth-counter walk in check_prose_field().
# ===========================================================================


class TestNestedEmphasisRejection:
    r"""
    Tests for ADR-028 D5: depth-counter emphasis-rejection walk in check_prose_field.

    Uses the same _make_field() idiom as TestSingleViolationDetection to build
    synthetic ProseField objects and call check_prose_field() directly.

    Tests that assert zero diagnostics guard against false positives.
    """

    def _make_field(
        self,
        raw_text: str,
        entry_id: str = "riskAlpha",
        field_name: str = "shortDescription",
        index: int = 0,
    ) -> "ProseField":
        """Build a ProseField with tokens populated from the tokenizer."""
        import sys as _sys
        from pathlib import Path as _Path

        _sys.path.insert(0, str(_Path(__file__).parent.parent / "precommit"))
        from precommit._prose_tokens import tokenize as _tok  # noqa: PLC0415

        tokens = _tok(raw_text)
        return ProseField(
            file_path=_Path("test.yaml"),
            entry_id=entry_id,
            field_name=field_name,
            index=index,
            raw_text=raw_text,
            tokens=tokens,
        )

    # --- Tests that MUST produce a diagnostic ---

    def test_nested_bold_produces_one_nested_emphasis_diagnostic(self):
        """
        Given: '**foo **nested** bar**' -> [BOLD(open), TEXT, BOLD(close)]
        When: check_prose_field is called
        Then: exactly ONE diagnostic with reason containing 'nested emphasis'
              and snippet "at '** bar**'" (the close token)

        ADR-028 D5: BOLD('**foo **') has shape='open' -> depth 0->1.
        BOLD('** bar**') has shape='close' and arrives at depth==1 -> nested emphasis.

        Close-branch emit: ADR-028 D5 (as amended 2026-05-29) requires the
        close-branch emit when depth > 0, checked before the decrement; this
        test verifies it.  BOLD('** bar**') is the only token in the stream
        [open, text, close] that arrives at depth > 0 (depth==1 before the
        decrement), so the single diagnostic's snippet is the close token's
        value: "at '** bar**'".
        """
        field = self._make_field("**foo **nested** bar**")
        diags = check_prose_field(field)
        assert len(diags) == 1, f"Expected 1 'nested emphasis' diagnostic, got {len(diags)}: {diags!r}."
        assert "nested emphasis" in diags[0].reason, (
            f"Expected reason containing 'nested emphasis', got {diags[0].reason!r}"
        )
        assert "at '** bar**'" in diags[0].reason, (
            f"Expected close-token snippet \"at '** bar**'\" in reason, got {diags[0].reason!r}"
        )

    def test_nested_italic_produces_one_nested_emphasis_diagnostic(self):
        """
        Given: '*foo *nested* bar*' -> [ITALIC(open), TEXT, ITALIC(close)]
        When: check_prose_field is called
        Then: ONE diagnostic with reason containing 'nested emphasis'

        Same depth-counter logic for italic-asterisk delimiter as for bold.
        """
        field = self._make_field("*foo *nested* bar*")
        diags = check_prose_field(field)
        assert len(diags) == 1, f"Expected 1 diagnostic for nested italic, got {len(diags)}: {diags!r}."
        assert "nested emphasis" in diags[0].reason

    def test_nested_underscore_produces_one_nested_emphasis_diagnostic(self):
        """
        Given: '_foo _nested_ bar_' -> [ITALIC(open), TEXT, ITALIC(close)]
        When: check_prose_field is called
        Then: exactly ONE diagnostic with reason containing 'nested emphasis'

        ADR-028 D-Open-21.2(b) + D5: under CommonMark-style not-intraword
        underscore flanking, '_foo _nested_ bar_' splits into
        [ITALIC('_foo _', open), TEXT('nested'), ITALIC('_ bar_', close)].
        The close token arrives at depth==1 -> depth-counter emits 'nested emphasis',
        parallel to the asterisk case (test_nested_italic_... above).
        """
        field = self._make_field("_foo _nested_ bar_")
        diags = check_prose_field(field)
        assert len(diags) == 1, (
            f"Expected 1 'nested emphasis' diagnostic for underscore italic, got {len(diags)}: {diags!r}."
        )
        assert "nested emphasis" in diags[0].reason, (
            f"Expected reason containing 'nested emphasis', got {diags[0].reason!r}"
        )

    def test_snake_case_underscore_produces_zero_diagnostics(self):
        """
        Given: 'home_bar and foo_baz'
        When: check_prose_field is called
        Then: ZERO diagnostics

        Intraword underscores must NOT be treated as emphasis delimiters under
        either the old or the new flanking rule (ADR-028 D3 invariant 3).
        Guard against false positives from the D-Open-21.2(b) fix.
        """
        field = self._make_field("home_bar and foo_baz")
        diags = check_prose_field(field)
        assert len(diags) == 0, (
            f"snake_case prose must produce 0 diagnostics (false-positive guard). Got: {diags!r}"
        )

    def test_italic_after_open_bold_produces_nested_emphasis_diagnostic(self):
        """
        Given: '**A ** *B* C**' -> [BOLD(open='**A **'), TEXT(' '), ITALIC(complete='*B*'), TEXT(' C**')]
        When: check_prose_field is called
        Then: exactly ONE diagnostic with reason containing 'nested emphasis'

        This test covers the 'complete at depth > 0' branch of ADR-028 D5.

        Empirically verified token stream (2026-05-29):
            tokenize('**A ** *B* C**') ->
              BOLD('**A **')   shape='open'     -> depth 0->1
              TEXT(' ')        shape='neutral'
              ITALIC('*B*')    shape='complete'  -> depth==1 -> emit_diagnostic
              TEXT(' C**')     shape='neutral'

        The reviewer's suggested string '**A ** *B* C**' was verified to yield
        this exact stream.  BOLD('**A **') has trailing interior whitespace
        ('A ') -> shape='open'; ITALIC('*B*') is a complete-shape token that
        arrives at depth==1 after the open bold.  The diagnostic fires on the
        ITALIC token because it is a complete-emphasis token inside an open span.
        """
        field = self._make_field("**A ** *B* C**")
        diags = check_prose_field(field)
        assert len(diags) == 1, (
            f"Expected 1 'nested emphasis' diagnostic for complete italic at depth>0, got {len(diags)}: {diags!r}."
        )
        assert "nested emphasis" in diags[0].reason, (
            f"Expected reason containing 'nested emphasis', got {diags[0].reason!r}"
        )

    def test_emphasis_wrapped_sentinel_intra_produces_diagnostic(self):
        """
        Given: '**{{riskPromptInjection}}**'
        When: check_prose_field is called
        Then: ONE diagnostic with reason containing 'emphasis-wrapped sentinel'

        ADR-028 D5: emphasis-wrapped-sentinel predicate fires when emphasis
        token interior (stripped) fullmatches the sentinel inner regex.
        """
        field = self._make_field("**{{riskPromptInjection}}**")
        diags = check_prose_field(field)
        assert len(diags) == 1, f"Expected 1 'emphasis-wrapped sentinel' diagnostic, got {len(diags)}: {diags!r}."
        assert "emphasis-wrapped sentinel" in diags[0].reason, (
            f"Expected 'emphasis-wrapped sentinel' in reason, got {diags[0].reason!r}"
        )

    def test_emphasis_wrapped_ref_sentinel_produces_diagnostic(self):
        """
        Given: '**{{ref:x}}**'
        When: check_prose_field is called
        Then: ONE diagnostic with reason containing 'emphasis-wrapped sentinel'

        The wrapped-sentinel predicate applies to both SENTINEL_INTRA and
        SENTINEL_REF inner forms — the test strips the delimiter pair and
        fullmatches the tokenizer's two internal regexes,
        _RE_SENTINEL_INTRA_INNER and _RE_SENTINEL_REF_INNER.
        """
        field = self._make_field("**{{ref:x}}**")
        diags = check_prose_field(field)
        assert len(diags) == 1, f"Expected 1 diagnostic for '**{{ref:x}}**', got {len(diags)}: {diags!r}."
        assert "emphasis-wrapped sentinel" in diags[0].reason

    def test_emphasis_wrapped_sentinel_with_newlines_produces_diagnostic(self):
        """
        Given: '**\\n{{ref:x}}\\n**'
        When: check_prose_field is called
        Then: ONE diagnostic with reason containing 'emphasis-wrapped sentinel'

        ADR-028 D3: '**\\n**' has both-edges whitespace -> shape='open'.
        The emphasis-wrapped-sentinel predicate uses .strip() on the interior,
        so leading/trailing newlines do not prevent detection.
        """
        field = self._make_field("**\n{{ref:x}}\n**")
        diags = check_prose_field(field)
        assert len(diags) == 1, f"Expected 1 diagnostic for newline-wrapped sentinel, got {len(diags)}: {diags!r}."
        assert "emphasis-wrapped sentinel" in diags[0].reason

    # --- Tests that MUST produce ZERO diagnostics (ADR-028 D5 faux-depth guard) ---

    def test_sibling_complete_bold_spans_produce_zero_diagnostics(self):
        """
        Given: '**hello** world **goodbye**'
        When: check_prose_field is called
        Then: ZERO diagnostics

        ADR-028 D5 faux-depth guard: the two BOLD tokens have shape='complete'
        -> depth stays at 0 throughout -> no nested-emphasis diagnostic.
        """
        field = self._make_field("**hello** world **goodbye**")
        diags = check_prose_field(field)
        assert len(diags) == 0, (
            f"Sibling complete bold spans must produce 0 diagnostics (faux-depth guard). Got: {diags!r}"
        )

    def test_sentinel_at_depth_zero_produces_zero_diagnostics(self):
        """
        Given: '**hello** world {{ref:x}}'
        When: check_prose_field is called
        Then: ZERO diagnostics

        The sentinel is at depth==0 (outside any open emphasis).
        ADR-028 D5: the emphasis-wrapped-sentinel predicate checks the emphasis
        token's interior, not any subsequent sentinel at depth 0.
        """
        field = self._make_field("**hello** world {{ref:x}}")
        diags = check_prose_field(field)
        assert len(diags) == 0, f"Sentinel at depth 0 must produce 0 diagnostics. Got: {diags!r}"

    def test_clean_bold_produces_zero_diagnostics(self):
        """
        Given: '**bold**'
        When: check_prose_field is called
        Then: ZERO diagnostics

        Simple complete-shape bold — no nesting, no sentinel inside.
        """
        field = self._make_field("**bold**")
        diags = check_prose_field(field)
        assert len(diags) == 0, f"Clean bold must produce 0 diagnostics. Got: {diags!r}"

    def test_clean_italic_asterisk_produces_zero_diagnostics(self):
        """
        Given: '*italic*'
        When: check_prose_field is called
        Then: ZERO diagnostics
        """
        field = self._make_field("*italic*")
        diags = check_prose_field(field)
        assert len(diags) == 0, f"Clean italic must produce 0 diagnostics. Got: {diags!r}"

    def test_clean_italic_underscore_produces_zero_diagnostics(self):
        """
        Given: '_italic_' at string boundary
        When: check_prose_field is called
        Then: ZERO diagnostics
        """
        field = self._make_field("_italic_")
        diags = check_prose_field(field)
        assert len(diags) == 0, f"Clean underscore italic must produce 0 diagnostics. Got: {diags!r}"

    def test_bold_containing_italic_produces_zero_diagnostics(self):
        """
        Given: '**bold *italic* inside**'
        When: check_prose_field is called
        Then: ZERO diagnostics

        ADR-017 D1: italic inside bold is one permitted nesting level.
        The tokenizer emits a single BOLD token for this span (italic-in-bold
        is absorbed atomically).  No depth-counter violation.
        """
        field = self._make_field("**bold *italic* inside**")
        diags = check_prose_field(field)
        assert len(diags) == 0, f"Bold-with-italic-inside must produce 0 diagnostics. Got: {diags!r}"

    def test_nested_bold_wrapping_sentinel_emits_both_diagnostics(self):
        """
        Given: '**x **y**{{ref:x}}**' -> [BOLD(open), TEXT, BOLD(complete '**{{ref:x}}**')]
        When: check_prose_field is called
        Then: the trailing BOLD token emits BOTH a 'nested emphasis' AND an
              'emphasis-wrapped sentinel' diagnostic (two diagnostics total).

        ADR-028 D5 (Addendum 2026-05-29, third erratum): the nested-emphasis and
        wrapped-sentinel predicates are independent and may both fire on a single
        emphasis token.  The complete token '**{{ref:x}}**' arrives at depth > 0
        (nested, via the preceding open '**x **') and its stripped interior is a
        sentinel (wrapped).  This pins the intended double-emit so a future change
        cannot silently collapse it to one diagnostic.
        """
        field = self._make_field("**x **y**{{ref:x}}**")
        diags = check_prose_field(field)
        reasons = [d.reason for d in diags]
        assert len(diags) == 2, f"Expected exactly 2 diagnostics (nested + wrapped). Got: {diags!r}"
        assert "nested emphasis at '**{{ref:x}}**'" in reasons, reasons
        assert "emphasis-wrapped sentinel at '**{{ref:x}}**'" in reasons, reasons


# ===========================================================================
# TestEmphasisDiagnosticFormat — ADR-028 D6 diagnostic format locks
# ===========================================================================
# Locks the exact diagnostic format strings for the two reason constants:
# ADR-028 D6: 'nested emphasis' and 'emphasis-wrapped sentinel', plus the
# token-snippet convention ('at <token.value!r>').
# ===========================================================================


class TestEmphasisDiagnosticFormat:
    r"""
    Tests for ADR-028 D6: diagnostic format for emphasis violations.

    The ADR-017 D4 format is preserved byte-for-byte:
        validate-yaml-prose-subset: <file>:<entry-id>:<field>[<index>]: <reason>

    The <reason> for emphasis violations follows the existing 'at '<snippet>''
    pattern: the reason string ends with "at '<token.value>'" where token.value
    is the offending emphasis token's full value (including delimiters).
    """

    def _make_field(
        self,
        raw_text: str,
        entry_id: str = "riskAlpha",
        field_name: str = "shortDescription",
        index: int = 0,
    ) -> "ProseField":
        """Build a ProseField with tokens from the tokenizer."""
        import sys as _sys
        from pathlib import Path as _Path

        _sys.path.insert(0, str(_Path(__file__).parent.parent / "precommit"))
        from precommit._prose_tokens import tokenize as _tok  # noqa: PLC0415

        tokens = _tok(raw_text)
        return ProseField(
            file_path=_Path("test.yaml"),
            entry_id=entry_id,
            field_name=field_name,
            index=index,
            raw_text=raw_text,
            tokens=tokens,
        )

    def test_nested_emphasis_diagnostic_reason_string(self):
        """
        Given: '**foo **nested** bar**' triggers nested emphasis
        When: check_prose_field produces a Diagnostic
        Then: reason starts with 'nested emphasis' and ends with "at '** bar**'"

        ADR-028 D6: reason string is 'nested emphasis' (unchanged); the snippet
        convention follows the existing INVALID_* pattern: "at '<token.value>'".
        The offending token is the BOLD('** bar**') (the 'close'-shape token at
        depth > 0).
        """
        field = self._make_field("**foo **nested** bar**")
        diags = check_prose_field(field)
        assert len(diags) == 1, f"Expected 1 diagnostic, got {diags!r}."
        reason = diags[0].reason
        assert reason.startswith("nested emphasis"), f"Reason must start with 'nested emphasis', got {reason!r}"
        assert "at '** bar**'" in reason, f"Reason must contain \"at '** bar**'\", got {reason!r}"

    def test_nested_emphasis_format_diagnostic_line(self):
        """
        Given: a Diagnostic for nested emphasis
        When: format_diagnostic_line is called
        Then: output matches ADR-017 D4 format with 'nested emphasis' reason

        Asserts the full committed format string including hook_id prefix.
        """
        from precommit._linter_types import format_diagnostic_line  # noqa: PLC0415

        field = self._make_field(
            "**foo **nested** bar**",
            entry_id="riskAlpha",
            field_name="shortDescription",
            index=0,
        )
        diags = check_prose_field(field)
        assert len(diags) == 1, f"Expected 1 diagnostic, got {diags!r}."
        line = format_diagnostic_line(diags[0])
        # Format: validate-yaml-prose-subset: test.yaml:riskAlpha:shortDescription[0]: nested emphasis at '...'
        assert line.startswith("validate-yaml-prose-subset: "), f"Expected hook_id prefix, got {line!r}"
        assert "riskAlpha" in line
        assert "shortDescription[0]" in line
        assert "nested emphasis" in line
        assert _DIAG_PATTERN.match(line), f"Diagnostic line does not match committed pattern: {line!r}"

    def test_emphasis_wrapped_sentinel_diagnostic_reason_string(self):
        """
        Given: '**{{riskPromptInjection}}**' triggers emphasis-wrapped sentinel
        When: check_prose_field produces a Diagnostic
        Then: reason starts with 'emphasis-wrapped sentinel' and contains the token value

        ADR-028 D6: reason string is 'emphasis-wrapped sentinel'; snippet is
        the full BOLD token value '**{{riskPromptInjection}}**'.
        """
        field = self._make_field("**{{riskPromptInjection}}**")
        diags = check_prose_field(field)
        assert len(diags) == 1, f"Expected 1 diagnostic, got {diags!r}."
        reason = diags[0].reason
        assert reason.startswith("emphasis-wrapped sentinel"), (
            f"Reason must start with 'emphasis-wrapped sentinel', got {reason!r}"
        )
        assert "at '**{{riskPromptInjection}}**'" in reason, f"Reason must contain token snippet, got {reason!r}"

    def test_emphasis_wrapped_sentinel_format_diagnostic_line_matches_pattern(self):
        """
        Given: a Diagnostic for emphasis-wrapped sentinel
        When: format_diagnostic_line is called
        Then: output matches the committed _DIAG_PATTERN regex

        Verifies the emphasis violation slots into the existing format contract
        without modifying the pattern.
        """
        from precommit._linter_types import format_diagnostic_line  # noqa: PLC0415

        field = self._make_field(
            "**{{riskPromptInjection}}**",
            entry_id="riskBeta",
            field_name="shortDescription",
            index=1,
        )
        diags = check_prose_field(field)
        assert len(diags) == 1, f"Expected 1 diagnostic, got {diags!r}."
        line = format_diagnostic_line(diags[0])
        assert _DIAG_PATTERN.match(line), (
            f"Emphasis-wrapped-sentinel diagnostic does not match committed pattern: {line!r}"
        )


# ===========================================================================
# TestDelimForTokenGuard — _delim_for_token fail-loud contract
# ===========================================================================
# _delim_for_token is called only on BOLD/ITALIC tokens, so its input always
# starts with '**', '*', or '_'.  It must fail loud on any other value rather
# than silently returning a wrong delimiter (which would make
# _is_emphasis_wrapped_sentinel slice the wrong interior).
# ===========================================================================


class TestDelimForTokenGuard:
    """Tests for the _delim_for_token delimiter-dispatch helper (ADR-028 D5)."""

    def test_bold_delimiter(self):
        """'**...**' values return the two-character bold delimiter."""
        assert _delim_for_token("**foo**") == "**"

    def test_italic_asterisk_delimiter(self):
        """'*...*' values return the single asterisk delimiter."""
        assert _delim_for_token("*foo*") == "*"

    def test_italic_underscore_delimiter(self):
        """'_..._' values return the underscore delimiter."""
        assert _delim_for_token("_foo_") == "_"

    def test_unrecognized_value_raises(self):
        """
        A value that is not a BOLD/ITALIC token (no '**', '*', or '_' prefix)
        must raise rather than silently returning a delimiter. Guards against a
        future emphasis kind reaching the helper with an unhandled delimiter.
        """
        with pytest.raises(ValueError):
            _delim_for_token("plain text")

    def test_empty_value_raises(self):
        """An empty string is not a valid emphasis token value and must raise."""
        with pytest.raises(ValueError):
            _delim_for_token("")


# ===========================================================================
# TestGuidanceFieldLinted — per-control guidance is a lint-visible prose field
# ===========================================================================
# The optional ``guidance`` property (ADR-020 D9 amendment; design record
# control-description-and-guidance.md) shares the description prose shape.
# The linter discovers prose fields from the schema, so these tests run the
# CLI against the REAL risk-map/schemas/ dir with a synthetic controls.yaml.
# The basename is pinned to controls.yaml so schema inference resolves
# controls.schema.json by stem rather than falling back to array-key matching.
# ===========================================================================


class TestGuidanceFieldLinted:
    r"""Grammar violations inside ``guidance`` are reported with field name ``guidance``."""

    _REAL_SCHEMA_DIR = _REPO_ROOT / "risk-map" / "schemas"

    def _write_controls_yaml(self, tmp_path: Path, guidance: list) -> Path:
        r"""Write ``<tmp_path>/controls.yaml`` with one clean-description control carrying guidance."""
        entry = _make_control("controlAlpha", description=["A clean description."])
        entry["guidance"] = guidance
        return _write_yaml(tmp_path, "controls.yaml", {"controls": [entry]})

    def _run_block(self, yaml_path: Path, capsys) -> tuple[int, list[str]]:
        r"""Run main() in --block mode; return (exit_code, non-empty stderr lines)."""
        with pytest.raises(SystemExit) as exc_info:
            main([str(yaml_path), "--schema-dir", str(self._REAL_SCHEMA_DIR), "--block"])
        err = capsys.readouterr().err
        return exc_info.value.code, [ln for ln in err.splitlines() if ln.strip()]

    def test_raw_url_in_guidance_reported_with_field_guidance(self, tmp_path, capsys):
        r"""
        A raw URL inside guidance produces one diagnostic naming the guidance field.

        Given: controls.yaml with guidance ["See https://example.com for details."]
               and the real schema dir
        When: main() is called with --block
        Then: exit code 1 and exactly one stderr line of the form
              ``...:controlAlpha:guidance[0]: ...`` matching the diagnostic regex
        """
        yaml_path = self._write_controls_yaml(tmp_path, ["See https://example.com for details."])
        code, lines = self._run_block(yaml_path, capsys)
        assert code == 1, f"expected --block exit 1 for a URL in guidance; stderr={lines!r}"
        assert len(lines) == 1, f"expected exactly one diagnostic; got {lines!r}"
        assert re.search(r":controlAlpha:guidance\[0\]: ", lines[0]), lines[0]
        assert _DIAG_PATTERN.match(lines[0]), f"diagnostic does not match committed format: {lines[0]!r}"

    def test_violation_in_nested_guidance_item_reported_with_nested_index(self, tmp_path, capsys):
        r"""
        A violation inside an inner-list guidance item carries the nested index.

        Given: guidance ["Lead.", ["Fine.", "See https://example.com for details."]]
               (a raw URL is a single-diagnostic violation; raw HTML would emit
               one diagnostic per tag)
        When: main() is called with --block
        Then: exit code 1 and the single diagnostic is located at ``guidance[1][1]``
        """
        yaml_path = self._write_controls_yaml(tmp_path, ["Lead.", ["Fine.", "See https://example.com now."]])
        code, lines = self._run_block(yaml_path, capsys)
        assert code == 1, f"expected --block exit 1 for a URL in nested guidance; stderr={lines!r}"
        assert len(lines) == 1, f"expected exactly one diagnostic; got {lines!r}"
        assert re.search(r":controlAlpha:guidance\[1\]\[1\]: ", lines[0]), lines[0]

    def test_clean_guidance_produces_no_diagnostic(self, tmp_path, capsys):
        r"""
        Clean guidance prose passes silently (no false positives on the new field).

        Given: guidance ["Use **strong** wording and a {{ref:spec-1}} citation."]
        When: main() is called with --block
        Then: exit code 0 and no stderr output
        """
        yaml_path = self._write_controls_yaml(tmp_path, ["Use **strong** wording and a {{ref:spec-1}} citation."])
        code, lines = self._run_block(yaml_path, capsys)
        assert code == 0
        assert lines == []
