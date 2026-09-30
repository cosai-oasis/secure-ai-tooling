#!/usr/bin/env python3
"""
Tests for Decision 4 (C1-schema-tightenings): description-field $refs in the
four content schemas point at `riskmap.schema.json#/definitions/utils/prose-strict`
(not `utils/text`), per ADRs 018-021 D4.

Scope: 16 $ref sites in 4 content schemas (risks, controls, components, personas).
The 16th site is the optional per-control ``guidance`` property (ADR-020 D9 amendment,
design record control-description-and-guidance.md), which shares the ``description``
prose shape.
Supporting schemas (frameworks, actor-access, impact-type, lifecycle-stage) are
out of scope for this PR — they remain on utils/text.

Coexistence: definitions/utils/text is retained in riskmap.schema.json.
Supporting schemas + self-assessment.schema.json (C3 sibling PR) still
reference it. Removal is a follow-up once all consumers migrate.

Coverage:
- Each of the 16 $ref sites references utils/prose-strict.
- Zero residual utils/text $refs in each of the 4 content schemas
  (JSON-walk regex assertion, robust against reformatting).
- riskmap.schema.json#/definitions/utils/text still exists (coexistence guard).
- Live-corpus audit per schema: each content YAML corpus validates clean
  against its parent schema's prose-strict shape. Surfaces content drift
  (empty arrays / empty strings) if it ever appears.

Sites under test (16 total):
  risks.schema.json (7):
    /properties/description
    /definitions/risk/properties/shortDescription
    /definitions/risk/properties/longDescription
    /definitions/risk/properties/tourContent/properties/introduced
    /definitions/risk/properties/tourContent/properties/exposed
    /definitions/risk/properties/tourContent/properties/mitigated
    /definitions/risk/properties/examples

  controls.schema.json (3):
    /properties/description
    /definitions/control/properties/description
    /definitions/control/properties/guidance

  components.schema.json (4):
    /properties/description
    /definitions/category/properties/description
    /definitions/subcategory/properties/description
    /definitions/component/properties/description

  personas.schema.json (2):
    /properties/description
    /definitions/persona/properties/description
"""

import json
import re
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft7Validator

sys.path.insert(0, str(Path(__file__).parent.parent))

from conftest import _load_schema, _make_registry

# ============================================================================
# Module-level constants
# ============================================================================

PROSE_STRICT_REF = "riskmap.schema.json#/definitions/utils/prose-strict"
UTILS_TEXT_REF_PATTERN = re.compile(r"riskmap\.schema\.json#/definitions/utils/text")

# Each site is (schema_filename, json_pointer_path_to_the_property).
# The path is expressed as a list of keys for dict traversal.
# These map to the 15 confirmed utils/text $ref sites found by JSON walk, plus
# the per-control guidance site added with the guidance property (16 total).
MIGRATION_SITES: list[tuple[str, list[str]]] = [
    # risks.schema.json — 7 sites
    ("risks.schema.json", ["properties", "description"]),
    ("risks.schema.json", ["definitions", "risk", "properties", "shortDescription"]),
    ("risks.schema.json", ["definitions", "risk", "properties", "longDescription"]),
    ("risks.schema.json", ["definitions", "risk", "properties", "tourContent", "properties", "introduced"]),
    ("risks.schema.json", ["definitions", "risk", "properties", "tourContent", "properties", "exposed"]),
    ("risks.schema.json", ["definitions", "risk", "properties", "tourContent", "properties", "mitigated"]),
    ("risks.schema.json", ["definitions", "risk", "properties", "examples"]),
    # controls.schema.json — 3 sites
    ("controls.schema.json", ["properties", "description"]),
    ("controls.schema.json", ["definitions", "control", "properties", "description"]),
    # Optional per-control guidance: same prose shape as description.
    ("controls.schema.json", ["definitions", "control", "properties", "guidance"]),
    # components.schema.json — 4 sites
    ("components.schema.json", ["properties", "description"]),
    ("components.schema.json", ["definitions", "category", "properties", "description"]),
    ("components.schema.json", ["definitions", "subcategory", "properties", "description"]),
    ("components.schema.json", ["definitions", "component", "properties", "description"]),
    # personas.schema.json — 2 sites
    ("personas.schema.json", ["properties", "description"]),
    ("personas.schema.json", ["definitions", "persona", "properties", "description"]),
]

# Content schemas where every utils/text $ref must be migrated to prose-strict.
CONTENT_SCHEMAS: list[str] = [
    "risks.schema.json",
    "controls.schema.json",
    "components.schema.json",
    "personas.schema.json",
]

# Maps each content schema to the YAML corpus file for live-corpus audit probes.
CORPUS_YAML_FILES: dict[str, str] = {
    "risks.schema.json": "risks.yaml",
    "controls.schema.json": "controls.yaml",
    "components.schema.json": "components.yaml",
    "personas.schema.json": "personas.yaml",
}


# ============================================================================
# Helpers
# ============================================================================


def _resolve_path(schema: dict, key_path: list[str]) -> dict | None:
    """
    Traverse a nested dict following key_path and return the final node.
    Returns None if any key is missing.
    """
    node = schema
    for key in key_path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _site_id(schema_file: str, path: list[str]) -> str:
    """Human-readable pytest ID for a migration site."""
    return f"{schema_file}:/{'/'.join(path)}"


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def schemas_dir(risk_map_schemas_dir: Path) -> Path:
    """Alias for concise test signatures."""
    return risk_map_schemas_dir


# ============================================================================
# Decision 4 — each site $refs prose-strict
# ============================================================================


class TestProseMigrationRefValue:
    """
    Each of the 16 $ref sites references utils/prose-strict per ADRs 018-021 D4
    (15 migrated sites plus the per-control guidance property).
    """

    @pytest.mark.parametrize(
        "schema_file,key_path",
        MIGRATION_SITES,
        ids=[_site_id(s, p) for s, p in MIGRATION_SITES],
    )
    def test_description_ref_points_to_prose_strict(
        self,
        schemas_dir: Path,
        schema_file: str,
        key_path: list[str],
    ):
        """
        Test that the $ref at this site points at utils/prose-strict.

        Given: A content schema and a JSON path to a text-field property
        When: The $ref value at that path is inspected
        Then: It equals 'riskmap.schema.json#/definitions/utils/prose-strict'
              (per ADRs 018-021 D4)
        """
        schema = _load_schema(schemas_dir, schema_file)
        node = _resolve_path(schema, key_path)
        assert node is not None, (
            f"Path /{'/'.join(key_path)} not found in {schema_file}; "
            "either the schema changed shape or the site list needs updating"
        )
        actual_ref = node.get("$ref")
        assert actual_ref == PROSE_STRICT_REF, (
            f"{schema_file} /{'/'.join(key_path)} must $ref '{PROSE_STRICT_REF}'; "
            f"got: {actual_ref!r} (per ADRs 018-021 D4 utils/text → utils/prose-strict migration)"
        )


# ============================================================================
# Decision 4 — zero residual utils/text $refs in each content schema
# ============================================================================


class TestZeroResidualUtilsTextRefs:
    """
    No utils/text $ref remains in any of the 4 content schemas.

    Uses a JSON-serialisation regex walk rather than line-number counting, so it
    remains robust against reformatting or line shifts.
    """

    @pytest.mark.parametrize(
        "schema_file",
        CONTENT_SCHEMAS,
        ids=CONTENT_SCHEMAS,
    )
    def test_no_utils_text_ref_in_content_schema(
        self,
        schemas_dir: Path,
        schema_file: str,
    ):
        """
        Test that no utils/text $ref remains in the content schema.

        Given: A content schema file
        When: Its full JSON serialisation is scanned for utils/text refs
        Then: No matches are found

        Supporting schemas (frameworks, actor-access, impact-type,
        lifecycle-stage) are explicitly out of scope for this PR; they retain
        utils/text. This test only asserts the 4 content schemas.
        """
        schema = _load_schema(schemas_dir, schema_file)
        serialised = json.dumps(schema)
        matches = UTILS_TEXT_REF_PATTERN.findall(serialised)
        assert not matches, (
            f"{schema_file} contains {len(matches)} residual utils/text $ref(s). "
            "Every content-schema description site must reference utils/prose-strict. "
            "(Supporting schemas — frameworks, actor-access, impact-type, "
            "lifecycle-stage — are explicitly out of scope and may retain utils/text.)"
        )


# ============================================================================
# Coexistence guard — utils/text still exists in riskmap.schema.json
# ============================================================================


class TestUtilsTextCoexistenceGuard:
    """
    riskmap.schema.json#/definitions/utils/text is retained alongside
    utils/prose-strict. Supporting schemas (frameworks, actor-access,
    impact-type, lifecycle-stage) and self-assessment.schema.json (archived
    by C3 sibling PR) still reference it; removal is a follow-up once all
    consumers migrate.
    """

    def test_utils_text_still_exists_in_riskmap_schema(self, schemas_dir: Path):
        """
        Test that definitions/utils/text is present in riskmap.schema.json.

        Given: riskmap.schema.json
        When: definitions/utils/text is looked up
        Then: It is present (C1 does not remove utils/text from riskmap)

        Removal is deferred until all consumers (supporting schemas +
        self-assessment.schema.json) have migrated — follow-up PR concern.
        """
        schema = _load_schema(schemas_dir, "riskmap.schema.json")
        utils = schema.get("definitions", {}).get("utils", {})
        assert "text" in utils, (
            "riskmap.schema.json#/definitions/utils/text must still exist. "
            "Removal is deferred — supporting schemas still reference utils/text."
        )

    def test_utils_prose_strict_exists_in_riskmap_schema(self, schemas_dir: Path):
        """
        Test that definitions/utils/prose-strict exists in riskmap.schema.json.

        Given: riskmap.schema.json
        When: definitions/utils/prose-strict is looked up
        Then: It is present (landed in Phase A via A2 task 2.2.9a)
        """
        schema = _load_schema(schemas_dir, "riskmap.schema.json")
        utils = schema.get("definitions", {}).get("utils", {})
        assert "prose-strict" in utils, (
            "riskmap.schema.json#/definitions/utils/prose-strict must exist "
            "(prerequisite for Decision 4 migration)."
        )

    def test_supporting_schemas_still_use_utils_text(self, schemas_dir: Path):
        """
        Test that at least one supporting schema still uses utils/text.

        Given: The 4 supporting schemas that are out of scope for this PR
        When: Their JSON is scanned for utils/text $refs
        Then: At least one schema has a utils/text $ref

        Confirms that removing utils/text from riskmap.schema.json would break a
        live consumer, validating why coexistence must be preserved.
        """
        supporting_schemas = [
            "frameworks.schema.json",
            "actor-access.schema.json",
            "impact-type.schema.json",
            "lifecycle-stage.schema.json",
        ]
        total_text_refs = 0
        for schema_file in supporting_schemas:
            schema = _load_schema(schemas_dir, schema_file)
            serialised = json.dumps(schema)
            total_text_refs += len(UTILS_TEXT_REF_PATTERN.findall(serialised))

        assert total_text_refs > 0, (
            "Expected at least one utils/text $ref in supporting schemas "
            "(frameworks, actor-access, impact-type, lifecycle-stage). "
            "If all are zero, utils/text removal eligibility may have changed — "
            "verify before deferring removal to a follow-up PR."
        )


# ============================================================================
# Live-corpus audit — YAML corpus validates clean against prose-strict shape
# ============================================================================


class TestCorpusProseStrictCompatibility:
    """
    Forward guard: each YAML corpus file validates clean against its full parent
    schema (which uses prose-strict for all description fields).

    prose-strict requires: minItems:1 on outer array, minLength:1 on string items
    at both depths, minItems:1 on inner array. A failure here surfaces content
    drift (an empty array or empty string finding its way into a description
    field) — route back to the maintainer to fix before the next tightening pass.

    Validates against the *full parent schema* (not just definitions/<entity>)
    so the file-level description and complete cross-file $ref wiring are
    exercised.
    """

    @pytest.mark.parametrize(
        "schema_file,yaml_file",
        [(s, CORPUS_YAML_FILES[s]) for s in CONTENT_SCHEMAS],
        ids=CONTENT_SCHEMAS,
    )
    def test_yaml_corpus_validates_clean_against_parent_schema(
        self,
        schemas_dir: Path,
        risk_map_yaml_dir: Path,
        schema_file: str,
        yaml_file: str,
    ):
        """
        Test that the full YAML corpus validates clean against the parent schema.

        Given: A content schema (description fields use prose-strict) and its
               corresponding YAML corpus file
        When: The YAML data is validated against the full parent schema
        Then: No errors are raised

        On failure: schema_file + per-error JSON-path identify which YAML
        fields carry empty arrays or empty strings, so the maintainer can fix
        the offending content.
        """
        yaml_path = risk_map_yaml_dir / yaml_file
        if not yaml_path.is_file():
            pytest.fail(f"{yaml_file} not found at {yaml_path}")
        with open(yaml_path) as fh:
            data = yaml.safe_load(fh)

        schema = _load_schema(schemas_dir, schema_file)
        registry = _make_registry(schemas_dir)
        validator = Draft7Validator(schema, registry=registry)

        errors = list(validator.iter_errors(data))
        if errors:
            # Collect a concise error summary for the maintainer.
            error_summary = "\n".join(f"  [{e.json_path}] {e.message}" for e in errors[:20])
            excess = max(0, len(errors) - 20)
            if excess:
                error_summary += f"\n  ... and {excess} more errors"
            pytest.fail(
                f"CONTENT DRIFT: {yaml_file} has validation errors against {schema_file}:\n{error_summary}"
            )


# ============================================================================
# Test summary
# ============================================================================
"""
Test Summary
============
Total test methods: 16 + 4 + 3 + 4 = 27
Test classes: 4

- TestProseMigrationRefValue (16 parametrized) — each site references
  utils/prose-strict.
- TestZeroResidualUtilsTextRefs (4 parametrized — one per content schema)
  — no utils/text $ref remains.
- TestUtilsTextCoexistenceGuard (3) — utils/text retained, prose-strict
  present, supporting schemas still consume utils/text.
- TestCorpusProseStrictCompatibility (4 parametrized — one per YAML file)
  — live YAML validates clean against its parent schema.

Coverage areas:
- Per-site $ref value assertion: all 16 sites point at prose-strict
- Zero-residual regex walk: no utils/text remains in content schemas
- Coexistence: utils/text retained in riskmap.schema.json (supporting schemas need it)
- Corpus audit: YAML content is prose-strict compatible
"""
