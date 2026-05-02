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

The tokenizer (_prose_tokens.py, locked at 25e3d22) is NOT modified.
The prose_subset/ fixture directory is NOT modified.

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
# ---------------------------------------------------------------------------
_DIAG_PATTERN = re.compile(r"^validate-yaml-prose-subset: [^:]+:[^:]+:[^:\[]+(?:\.[^:\[]+)*\[\d+\]: .+ at '.*'$")


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
        r"""Convert a Diagnostic to its string representation."""
        idx_str = f"[{diag.index}]" if diag.index is not None else ""
        return f"{diag.hook_id}: {diag.file_path}:{diag.entry_id}:{diag.field_name}{idx_str}: {diag.reason}"

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
