#!/usr/bin/env python3
"""
Tests for the optional mappings field on components.schema.json.

Phase 2 of issue #343 flips components.schema.json from the hybrid
(selective-strict + loose catch-all) shape to a fully-strict shape per
ADR-027 D3a and D7:

- ALL six frameworks declared in mappings.properties, each items-$ref pointing at
  frameworks.schema.json#/definitions/framework-mapping-patterns-pinned/properties/<fw>.
- additionalProperties: false (the loose catch-all is removed).
- propertyNames $ref to the framework id enum is KEPT.
- Field remains optional (NOT in required).

components.yaml currently has 0 mappings entries, so the live-corpus guard
trivially passes once the schema flip lands.

Coverage:
- mappings property declared in definitions/component/properties.
- propertyNames $ref to frameworks.schema.json is present.
- All six framework keys declared in mappings.properties.
- additionalProperties is exactly false (catch-all removed).
- Field is NOT in required.
- Pinned mitre-atlas value AML.T0020@5.0.1 accepted; legacy AML.T0020 rejected.
- Pinned stride PascalCase accepted; lowercase-kebab rejected.
- Pinned nist-ai-rmf @1.0 accepted; short-prefix form rejected.
- Pinned owasp :2025 accepted; bare LLMnn rejected.
- Pinned iso @2022 enum accepted; bare string / off-enum rejected.
- Pinned eu-ai-act @2024 accepted; bare Article N rejected.
- Unknown framework key is rejected via propertyNames + additionalProperties:false.
- Current components.yaml (no mappings) passes unchanged.

These tests are RED until the Phase-2 schema flip lands (#343 ADR-027 D3a/D7).
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# Module-level constants
# ============================================================================

SCHEMA_FILE = "components.schema.json"
ENTITY_KEY = "component"

# All six frameworks must be wired with per-property strict-pinned patterns
# after Phase 2 (#343 ADR-027 D3a).
ALL_SIX_FRAMEWORKS = {"mitre-atlas", "iso-22989", "eu-ai-act", "stride", "nist-ai-rmf", "owasp-top10-llm"}

# Pinned forms that must be ACCEPTED after the strict flip.
PINNED_VALID_EXAMPLES: dict[str, list[str]] = {
    "mitre-atlas": ["AML.T0020@5.0.1", "AML.M0011@5.0.1", "AML.T0010.002@5.0.1"],
    "nist-ai-rmf": ["GOVERN-6.2@1.0", "MEASURE-2.11@1.0"],
    "stride": ["Tampering", "Spoofing", "InformationDisclosure"],
    "owasp-top10-llm": ["LLM06:2025", "LLM01:2025"],
    "iso-22989": ["AI Producer@2022", "AI Customer (application builder)@2022"],
    "eu-ai-act": ["Article 5@2024", "Article 5(1)@2024"],
}

# Legacy/unpinned forms that must be REJECTED after the strict flip.
LEGACY_INVALID_EXAMPLES: dict[str, list[str]] = {
    "mitre-atlas": ["AML.T0020", "AML.M0011"],  # missing @5.0.1
    "nist-ai-rmf": ["GV-6.2", "MS-2.11", "GOVERN-6.2"],  # short prefix / missing @1.0
    "stride": ["tampering", "spoofing", "information-disclosure"],  # lowercase / kebab
    "owasp-top10-llm": ["LLM01", "LLM09"],  # missing :2025
    "iso-22989": ["AI Producer", "Data supplier"],  # missing @2022 / off-enum
    "eu-ai-act": ["Article 5", "Article 5(1)"],  # missing @2024
}

# Malformed mitre-atlas examples that must always be rejected.
INVALID_MITRE_ATLAS: list[str] = [
    "aml-t0020",  # lowercase-kebab
    "AML.T20",  # short ID
    "AML.X0020",  # non-T/M letter
]


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def components_schema(risk_map_schemas_dir: Path) -> dict:
    """Parsed components.schema.json."""
    path = risk_map_schemas_dir / SCHEMA_FILE
    if not path.is_file():
        pytest.fail(f"Schema not found: {path}")
    with open(path) as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def component_properties(components_schema: dict) -> dict:
    """definitions/component/properties block."""
    props = components_schema.get("definitions", {}).get(ENTITY_KEY, {}).get("properties", {})
    assert props, f"definitions/{ENTITY_KEY}/properties must exist in {SCHEMA_FILE}"
    return props


@pytest.fixture(scope="module")
def mappings_schema(component_properties: dict) -> dict:
    """The mappings sub-schema from definitions/component/properties."""
    if "mappings" not in component_properties:
        pytest.fail(
            f"definitions/{ENTITY_KEY}/properties/mappings not found in {SCHEMA_FILE}. "
            "The mappings field has not been declared yet."
        )
    return component_properties["mappings"]


@pytest.fixture(scope="module")
def registry(risk_map_schemas_dir: Path) -> Registry:
    """
    referencing.Registry that resolves bare-filename $refs against the
    schemas directory. Replaces the deprecated jsonschema.RefResolver.
    """

    def retrieve(uri: str):
        # The validator hands us the URI portion of a $ref; for our refs the
        # URI is a bare schema filename relative to risk_map_schemas_dir.
        name = uri.rsplit("/", 1)[-1]
        path = risk_map_schemas_dir / name
        with open(path) as fh:
            return Resource.from_contents(json.load(fh), default_specification=DRAFT7)

    return Registry(retrieve=retrieve)


# ============================================================================
# Schema meta-validity
# ============================================================================


class TestSchemaMetaValidity:
    """components.schema.json must be valid Draft-07."""

    def test_schema_passes_draft07_metaschema(self, components_schema: dict):
        """
        Test that components.schema.json is a valid Draft-07 schema.

        Given: components.schema.json loaded
        When: Draft7Validator.check_schema() is called
        Then: No SchemaError is raised
        """
        try:
            Draft7Validator.check_schema(components_schema)
        except SchemaError as exc:
            pytest.fail(f"{SCHEMA_FILE} is not valid Draft-07: {exc.message}")


# ============================================================================
# mappings field presence and structure
# ============================================================================


class TestMappingsFieldPresence:
    """The mappings field must be declared under definitions/component/properties."""

    def test_mappings_property_exists(self, component_properties: dict):
        """
        Test that the mappings property is declared.

        Given: definitions/component/properties in components.schema.json
        When: The keys are inspected
        Then: 'mappings' is present
        """
        assert "mappings" in component_properties, f"definitions/{ENTITY_KEY}/properties must declare 'mappings'"

    def test_mappings_is_object_type(self, mappings_schema: dict):
        """
        Test that the mappings schema declares type: object.

        Given: definitions/component/properties/mappings
        When: Its 'type' is examined
        Then: It is 'object'
        """
        assert mappings_schema.get("type") == "object", "mappings must be type: object"

    def test_mappings_has_property_names_ref(self, mappings_schema: dict):
        """
        Test that propertyNames is wired to the framework id enum.

        Given: The mappings sub-schema
        When: Its propertyNames is examined
        Then: It uses $ref to frameworks.schema.json#/definitions/framework/properties/id
        """
        property_names = mappings_schema.get("propertyNames", {})
        expected_ref = "frameworks.schema.json#/definitions/framework/properties/id"
        assert property_names.get("$ref") == expected_ref, (
            f"mappings.propertyNames must $ref {expected_ref!r}; got: {property_names!r}"
        )

    def test_mappings_additional_properties_is_false(self, mappings_schema: dict):
        """
        Test that mappings.additionalProperties is exactly false (catch-all removed).

        Given: The mappings sub-schema (post Phase-2 flip, #343)
        When: additionalProperties is examined
        Then: It is the boolean false — NOT a schema-object catch-all

        ADR-027 D3a: the loose catch-all for stride/nist-ai-rmf/owasp-top10-llm
        must be removed. This is RED until the Phase-2 schema flip lands (#343).
        """
        ap = mappings_schema.get("additionalProperties", "<MISSING>")
        assert ap is False, (
            f"mappings must have additionalProperties: false (strict Phase-2 flip, "
            f"#343 ADR-027 D3a); got: {ap!r}. The loose catch-all must be removed."
        )

    @pytest.mark.parametrize("framework_key", sorted(ALL_SIX_FRAMEWORKS))
    def test_all_six_frameworks_declared_in_properties(self, mappings_schema: dict, framework_key: str):
        """
        Test that all six framework keys are declared in mappings.properties.

        Given: The mappings sub-schema properties block
        When: A framework key is looked up
        Then: It is present (all six, not just the previous three)

        ADR-027 D3a: all six frameworks must be explicitly wired with per-property
        entries after the Phase-2 flip. This is RED until stride, nist-ai-rmf,
        and owasp-top10-llm are added to properties (#343).
        """
        props = mappings_schema.get("properties", {})
        assert framework_key in props, (
            f"mappings.properties must declare '{framework_key}' "
            "(all six frameworks strictly wired per ADR-027 D3a, #343 Phase 2)"
        )

    @pytest.mark.parametrize("framework_key", sorted(ALL_SIX_FRAMEWORKS))
    def test_framework_items_ref_points_at_pinned_block(self, mappings_schema: dict, framework_key: str):
        """
        Test that each framework's items $ref resolves to framework-mapping-patterns-pinned.

        Given: mappings.properties.<framework_key>.items
        When: Its $ref is inspected
        Then: It ends in 'framework-mapping-patterns-pinned/properties/<framework_key>'

        ADR-027 D7: consumer $refs must repoint from the base block to the pinned block.
        RED until Phase-2 schema flip lands (#343).
        """
        fw_schema = mappings_schema.get("properties", {}).get(framework_key, {})
        items = fw_schema.get("items", {})
        ref = items.get("$ref", "")
        expected_suffix = f"framework-mapping-patterns-pinned/properties/{framework_key}"
        assert ref.endswith(expected_suffix), (
            f"mappings.properties.{framework_key}.items.$ref must end with "
            f"'{expected_suffix}' (pinned block, ADR-027 D7, #343 Phase 2); got: {ref!r}"
        )


# ============================================================================
# Optional — not in required
# ============================================================================


class TestMappingsIsOptional:
    """mappings must be optional in the component object schema."""

    def test_mappings_not_in_required(self, components_schema: dict):
        """
        Test that mappings is not in the required array.

        Given: definitions/component in components.schema.json
        When: Its required array is inspected
        Then: 'mappings' is absent
        """
        entity_schema = components_schema["definitions"][ENTITY_KEY]
        required = entity_schema.get("required", [])
        assert "mappings" not in required, (
            "mappings must NOT be in definitions/component/required (optional field)"
        )


# ============================================================================
# Behavioral validation — pinned values accepted after strict flip
# ============================================================================


class TestPinnedValuesAccepted:
    """
    Pinned-form values for all six frameworks must be accepted after the Phase-2
    strict flip (#343 ADR-027 D3a/D7).

    These will FAIL against the current schema because:
    - nist-ai-rmf/stride/owasp-top10-llm are not yet in properties (catch-all only).
    - mitre-atlas/iso-22989/eu-ai-act $refs still point at base patterns (no @token).
    """

    @pytest.mark.parametrize(
        ("framework_key", "value"),
        [(fw, v) for fw, vals in PINNED_VALID_EXAMPLES.items() for v in vals],
    )
    def test_pinned_value_accepted(
        self, mappings_schema: dict, registry: Registry, framework_key: str, value: str
    ):
        """
        Test that pinned-form values for all six frameworks are accepted.

        Given: A mappings object with <framework_key>: [<pinned-value>]
        When: It is validated against the mappings schema (post Phase-2 flip)
        Then: No errors — each framework's pinned pattern accepts the versioned form

        RED until Phase-2 schema flip lands (#343 ADR-027 D3a/D7).
        """
        validator = Draft7Validator(mappings_schema, registry=registry)
        instance = {framework_key: [value]}
        errors = list(validator.iter_errors(instance))
        assert not errors, (
            f"Pinned value {framework_key!r}: {value!r} must be accepted after Phase-2 flip "
            f"(#343 ADR-027 D3a); got: {[e.message for e in errors]}"
        )


# ============================================================================
# Behavioral validation — legacy forms rejected after strict flip
# ============================================================================


class TestLegacyFormsRejected:
    """
    Legacy (unpinned / non-canonical) forms must be REJECTED after the Phase-2
    strict flip (#343 ADR-027 D3a).

    Currently stride/nist-ai-rmf/owasp-top10-llm pass via the loose catch-all
    and mitre-atlas/iso-22989 accept bare strings via the base pattern. All of
    these must be rejected after the flip.
    """

    @pytest.mark.parametrize(
        ("framework_key", "legacy_value"),
        [(fw, v) for fw, vals in LEGACY_INVALID_EXAMPLES.items() for v in vals],
    )
    def test_legacy_value_rejected(
        self, mappings_schema: dict, registry: Registry, framework_key: str, legacy_value: str
    ):
        """
        Test that legacy/unpinned values are rejected after the strict flip.

        Given: A mappings object with <framework_key>: [<legacy-value>]
        When: It is validated against the mappings schema (post Phase-2 flip)
        Then: ValidationError — legacy forms do not satisfy the pinned patterns

        RED until Phase-2 schema flip lands (#343). Currently passes via catch-all
        or base patterns.
        """
        validator = Draft7Validator(mappings_schema, registry=registry)
        instance = {framework_key: [legacy_value]}
        errors = list(validator.iter_errors(instance))
        assert errors, (
            f"Legacy value {framework_key!r}: {legacy_value!r} must be REJECTED after "
            f"Phase-2 strict flip (#343 ADR-027 D3a); was incorrectly accepted"
        )


# ============================================================================
# Behavioral validation — structurally malformed values rejected (regression guard)
# ============================================================================


class TestMalformedValuesRejected:
    """
    Structurally malformed values must be rejected both before and after the flip.
    This is a regression guard.
    """

    @pytest.mark.parametrize("invalid_id", INVALID_MITRE_ATLAS)
    def test_mitre_atlas_malformed_value_rejected(
        self, mappings_schema: dict, registry: Registry, invalid_id: str
    ):
        """
        Test that structurally malformed mitre-atlas IDs are rejected.

        Given: A mappings object with mitre-atlas: [<malformed-id>]
        When: It is validated
        Then: ValidationError is raised (malformed forms fail both base and pinned patterns)
        """
        validator = Draft7Validator(mappings_schema, registry=registry)
        instance = {"mitre-atlas": [invalid_id]}
        errors = list(validator.iter_errors(instance))
        assert errors, f"mitre-atlas malformed value {invalid_id!r} must be rejected by the strict pattern"


# ============================================================================
# Behavioral validation — unknown framework key rejected
# ============================================================================


class TestUnknownFrameworkRejected:
    """Unknown framework keys must be rejected via propertyNames + additionalProperties:false."""

    def test_unknown_framework_key_rejected(self, mappings_schema: dict, registry: Registry):
        """
        Test that an unregistered framework key is rejected.

        Given: A mappings object with made-up-framework: ["some-value"]
        When: It is validated
        Then: ValidationError (propertyNames + additionalProperties:false after Phase-2 flip)
        """
        validator = Draft7Validator(mappings_schema, registry=registry)
        instance = {"made-up-framework": ["some-value"]}
        errors = list(validator.iter_errors(instance))
        assert errors, (
            "Unknown framework key 'made-up-framework' must be rejected via "
            "propertyNames + additionalProperties:false (#343 Phase 2)"
        )


# ============================================================================
# Regression — current components.yaml still validates
# ============================================================================


class TestCurrentYamlStillValid:
    """
    The current components.yaml must continue to pass check-jsonschema
    (additive only, no existing content is invalidated).
    """

    def test_components_yaml_passes_check_jsonschema(self, risk_map_schemas_dir: Path, risk_map_yaml_dir: Path):
        """
        Test that current components.yaml validates against components.schema.json.

        Given: The current components.yaml on disk (no mappings fields today)
        When: check-jsonschema is run with --schemafile components.schema.json
        Then: Exit code is 0 (schema addition is backward-compatible)
        """
        schema_path = risk_map_schemas_dir / SCHEMA_FILE
        yaml_path = risk_map_yaml_dir / "components.yaml"
        base_uri = f"file://{risk_map_schemas_dir}/"
        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(schema_path),
                str(yaml_path),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"components.yaml must remain valid:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ============================================================================
# ADR-026 Amendment 2026-05-21: D10 — schema conditional pairing constraint
#
# D10 adds an allOf of if/then clauses to definitions/component in
# components.schema.json so an invalid (category, subcategory) pair is
# REJECTED by check-jsonschema on every edit path, not only at the form.
#
# Contract (from D10):
#  (a) Every valid (category, subcategory) pair must be ACCEPTED.
#  (b) A synthetic invalid pair must be REJECTED.
#  (c) A component with category but no subcategory must be ACCEPTED
#      (subcategory is optional per component `required` array).
#
# The tests in this class use Draft7Validator against the component sub-schema
# via the registry fixture, matching the existing behavioral test pattern in
# this module.
#
# These tests enforce the ADR-026 D10 contract: the component schema must
# contain JSON Schema if/then pairing constraints so that invalid
# (category, subcategory) pairs are rejected at validation time. They will
# fail until D10 is implemented; that is intentional — they are the
# specification.
# ============================================================================

# Valid tuples per ADR-026 Amendment D8 taxonomy table.
_D10_VALID_PAIRS: list[tuple[str, str]] = [
    ("componentsInfrastructure", "componentsData"),
    ("componentsInfrastructure", "componentsModelDeployment"),
    ("componentsModel", "componentsModelTraining"),
    ("componentsModel", "componentsModelCore"),
    ("componentsModel", "componentsOrchestration"),
    ("componentsApplication", "componentsAgent"),
    ("componentsApplication", "componentsApplicationCore"),
]

# An example of an invalid pair (category from Application, subcategory from
# Infrastructure — a cross-category crossing the taxonomy nesting forbids).
# componentsModelDeployment is under componentsInfrastructure, NOT componentsModel.
_D10_INVALID_PAIR = ("componentsApplication", "componentsData")

# A minimal valid component object with no subcategory (subcategory is optional).
# description must be a list (prose-strict enforced by riskmap.schema.json).
_MINIMAL_COMPONENT_NO_SUBCATEGORY: dict = {
    "id": "componentDataSources",
    "title": "Data Sources",
    "description": ["Test."],
    "category": "componentsInfrastructure",
    "edges": {"to": ["componentDataSources"]},
}


class TestSchemaContainsPairingConstraint:
    """
    Asserts that definitions/component in components.schema.json declares an
    allOf pairing constraint per ADR-026 D10.

    These are structural schema-inspection tests; they do not invoke
    check-jsonschema. The behavioral enforcement tests in
    TestPairingConstraintBehavior use check-jsonschema via subprocess to
    validate against the full schema with $ref resolution (same path as the
    pre-commit hook).
    """

    def test_component_definition_has_allof(self, components_schema: dict) -> None:
        """
        Test that definitions/component declares an allOf clause.

        Given: definitions/component in components.schema.json
        When: Its keys are inspected
        Then: 'allOf' is present

        ADR-026 D10 adds an allOf of if/then clauses, one per category, to
        enforce (category, subcategory) pairing at schema-validation time.
        Absence means no pairing enforcement at all.
        """
        component_def = components_schema.get("definitions", {}).get("component", {})
        assert "allOf" in component_def, (
            "definitions/component must declare 'allOf' for the pairing constraint "
            "(ADR-026 D10). The schema has not been updated yet."
        )

    def test_allof_contains_one_clause_per_category(self, components_schema: dict) -> None:
        """
        Test that definitions/component.allOf contains exactly three clauses
        (one per category: Infrastructure, Model, Application).

        Given: definitions/component.allOf
        When: Its length is checked
        Then: It contains exactly 3 if/then clauses

        ADR-026 D10 shape: one if/then per category (3 categories = 3 clauses).
        """
        component_def = components_schema.get("definitions", {}).get("component", {})
        all_of = component_def.get("allOf", [])
        assert len(all_of) == 3, (
            f"definitions/component.allOf must contain exactly 3 if/then clauses "
            f"(one per category per ADR-026 D10); got {len(all_of)}."
        )

    def test_each_allof_clause_has_if_then(self, components_schema: dict) -> None:
        """
        Test that every clause in allOf has both 'if' and 'then' keys.

        Given: definitions/component.allOf
        When: Each clause is inspected
        Then: All clauses contain 'if' and 'then'

        ADR-026 D10 uses JSON Schema if/then for conditional pairing constraints.
        A clause without 'then' would be a no-op; without 'if' it would apply
        unconditionally.
        """
        component_def = components_schema.get("definitions", {}).get("component", {})
        all_of = component_def.get("allOf", [])

        # Guard: pre-impl allOf is absent/empty, so the loop never runs (vacuous pass).
        # This forces a failure until the D10 if/then pairing constraint is added to
        # the schema (ADR-026 D10).
        assert all_of, (
            "definitions/component.allOf must be non-empty before checking clause shape "
            "(ADR-026 D10 requires if/then pairing constraints)."
        )

        for i, clause in enumerate(all_of):
            assert "if" in clause, f"allOf[{i}] is missing 'if' key (ADR-026 D10 if/then shape). Clause: {clause}"
            assert "then" in clause, (
                f"allOf[{i}] is missing 'then' key (ADR-026 D10 if/then shape). Clause: {clause}"
            )


def _write_minimal_components_yaml(
    out_dir: Path,
    extra_components: list[dict],
    risk_map_yaml_dir: Path,
) -> Path:
    """
    Write a minimal components.yaml for schema validation testing.

    Copies the real taxonomy (categories[]) from the live components.yaml and
    replaces the components[] list with extra_components. The real taxonomy is
    required so that the D10 allOf if/then clauses (which reference category
    and subcategory values from the taxonomy) have something to match against.

    Creates out_dir if it does not exist.
    Returns the path to the written YAML file.
    """
    import yaml as pyyaml

    out_dir.mkdir(parents=True, exist_ok=True)

    with open(risk_map_yaml_dir / "components.yaml") as fh:
        real = pyyaml.safe_load(fh)

    synthetic = {
        "id": "components",
        "title": real["title"],
        "description": real["description"],
        "categories": real["categories"],
        "components": extra_components,
    }

    out_path = out_dir / "components_test.yaml"
    with open(out_path, "w") as fh:
        pyyaml.dump(synthetic, fh, allow_unicode=True)
    return out_path


def _run_check_jsonschema_for_components(schema_path: Path, yaml_path: Path) -> subprocess.CompletedProcess:
    """
    Invoke check-jsonschema for a (components schema, yaml) pair.

    Uses the same invocation pattern as TestCurrentYamlStillValid and the
    pre-commit hook (list form, captures output, base-uri for $ref resolution).
    """
    base_uri = f"file://{schema_path.parent}/"
    return subprocess.run(
        [
            "check-jsonschema",
            "--base-uri",
            base_uri,
            "--schemafile",
            str(schema_path),
            str(yaml_path),
        ],
        capture_output=True,
        text=True,
    )


class TestPairingConstraintBehavior:
    """
    Behavioral tests for the D10 pairing constraint using check-jsonschema.

    Uses check-jsonschema via subprocess (the exact tool the pre-commit hook
    uses) against synthetic YAML files so $ref resolution across schema files
    works correctly. This mirrors the validation path TestCurrentYamlStillValid
    uses for the live corpus.
    """

    @pytest.mark.parametrize("category_id,subcategory_id", _D10_VALID_PAIRS)
    def test_valid_pair_is_accepted(
        self,
        risk_map_schemas_dir: Path,
        risk_map_yaml_dir: Path,
        tmp_path: Path,
        category_id: str,
        subcategory_id: str,
    ) -> None:
        """
        Test that every valid (category, subcategory) pair is accepted.

        Given: A synthetic components.yaml with one component using a valid
               (category, subcategory) pair per the ADR-026 D8 taxonomy table
        When: check-jsonschema validates it against components.schema.json
        Then: Exit code is 0 (no validation errors)

        ADR-026 D10(a): every valid tuple must ACCEPT.
        Uses check-jsonschema (same as pre-commit hook) for end-to-end $ref
        resolution; validates the full document, not just a sub-schema.
        """
        component_instance = {
            "id": "componentDataSources",
            "title": "Test Component",
            "description": ["Test."],
            "category": category_id,
            "subcategory": subcategory_id,
            "edges": {"to": ["componentDataSources"]},
        }
        yaml_path = _write_minimal_components_yaml(
            tmp_path / f"valid_{category_id}_{subcategory_id}",
            [component_instance],
            risk_map_yaml_dir,
        )

        schema_path = risk_map_schemas_dir / SCHEMA_FILE
        result = _run_check_jsonschema_for_components(schema_path, yaml_path)

        assert result.returncode == 0, (
            f"Valid pair ({category_id!r}, {subcategory_id!r}) must be ACCEPTED "
            f"by the D10 pairing constraint (ADR-026 D10a). "
            f"check-jsonschema failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_invalid_pair_is_rejected(
        self,
        risk_map_schemas_dir: Path,
        risk_map_yaml_dir: Path,
        tmp_path: Path,
    ) -> None:
        """
        Test that an invalid (category, subcategory) pair is rejected.

        Given: A synthetic components.yaml with one component having
               category=componentsApplication and subcategory=componentsData
               (a cross-category violation: componentsData belongs to
               componentsInfrastructure, not componentsApplication)
        When: check-jsonschema validates it
        Then: Exit code is non-zero (validation fails)

        ADR-026 D10(b): invalid pairs must be REJECTED.
        The pairing constraint is the load-bearing enforcement — without it
        a hand-edit or generated diff could introduce an invalid pair under
        a green CI even if the form selector prevents it at submission time.
        """
        invalid_category, invalid_subcategory = _D10_INVALID_PAIR
        component_instance = {
            "id": "componentDataSources",
            "title": "Test Component",
            "description": ["Test."],
            "category": invalid_category,
            "subcategory": invalid_subcategory,
            "edges": {"to": ["componentDataSources"]},
        }
        yaml_path = _write_minimal_components_yaml(
            tmp_path / "invalid_pair",
            [component_instance],
            risk_map_yaml_dir,
        )

        schema_path = risk_map_schemas_dir / SCHEMA_FILE
        result = _run_check_jsonschema_for_components(schema_path, yaml_path)

        assert result.returncode != 0, (
            f"Invalid pair ({invalid_category!r}, {invalid_subcategory!r}) must be "
            f"REJECTED by the D10 pairing constraint (ADR-026 D10b). "
            f"componentsData belongs to componentsInfrastructure, not componentsApplication. "
            f"check-jsonschema returned exit 0 (no errors), meaning the constraint "
            f"has not been added to the schema yet."
        )

    def test_component_without_subcategory_is_accepted(
        self,
        risk_map_schemas_dir: Path,
        risk_map_yaml_dir: Path,
        tmp_path: Path,
    ) -> None:
        """
        Test that a component with category but no subcategory is accepted.

        Given: A synthetic components.yaml with one component that has a
               valid category but omits the subcategory field entirely
        When: check-jsonschema validates it
        Then: Exit code is 0 (subcategory is optional)

        ADR-026 D10(c): subcategory is not required. The allOf if/then
        clauses must only restrict the subcategory value WHEN the field is
        present; omitting subcategory entirely must stay valid per the
        component required array: ["id", "title", "category", "edges"].
        """
        yaml_path = _write_minimal_components_yaml(
            tmp_path / "no_subcategory",
            [_MINIMAL_COMPONENT_NO_SUBCATEGORY],
            risk_map_yaml_dir,
        )

        schema_path = risk_map_schemas_dir / SCHEMA_FILE
        result = _run_check_jsonschema_for_components(schema_path, yaml_path)

        assert result.returncode == 0, (
            f"Component with category but no subcategory must be ACCEPTED "
            f"(ADR-026 D10c: subcategory is optional). "
            f"check-jsonschema failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_real_components_yaml_still_passes_after_d10(
        self,
        risk_map_schemas_dir: Path,
        risk_map_yaml_dir: Path,
    ) -> None:
        """
        Test that the live components.yaml still passes check-jsonschema
        after the D10 pairing constraint is added (regression guard).

        Given: risk-map/yaml/components.yaml (the live corpus)
        When: check-jsonschema validates it against the D10-amended schema
        Then: Exit code is 0 (no existing component violates the constraint)

        ADR-026 D10 must be backward-compatible: every component in the live
        corpus uses a valid (category, subcategory) pair per the taxonomy.
        If any existing component fails, the constraint is either wrong or
        the data has a pre-existing error that the constraint correctly surfaces.
        """
        schema_path = risk_map_schemas_dir / SCHEMA_FILE
        yaml_path = risk_map_yaml_dir / "components.yaml"
        result = _run_check_jsonschema_for_components(schema_path, yaml_path)

        assert result.returncode == 0, (
            f"Live components.yaml must pass the D10 pairing constraint "
            f"(backward-compatibility regression guard, ADR-026 D10). "
            f"check-jsonschema failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ============================================================================
# Test summary (Phase 2 strict wiring — #343 ADR-027 D3a/D7)
# ============================================================================
"""
Test Summary
============
Test classes: 10

- TestSchemaMetaValidity (1)             — schema valid Draft-07
- TestMappingsFieldPresence              — property exists, type=object,
                                           propertyNames $ref,
                                           additionalProperties:false,
                                           all-six in properties,
                                           items $ref → pinned block
                                           (parametrized × 6 for last two = 14 total)
- TestMappingsIsOptional (1)             — not in required
- TestPinnedValuesAccepted               — parametrized: all six fw × pinned values
                                           (≈ 14 cases)
- TestLegacyFormsRejected                — parametrized: all six fw × legacy values
                                           (≈ 14 cases)
- TestMalformedValuesRejected (3)        — structurally bad mitre-atlas rejected
- TestUnknownFrameworkRejected (1)       — propertyNames + additionalProperties:false
- TestCurrentYamlStillValid (1)          — components.yaml still passes (trivially,
                                           no mappings entries today)
- TestSchemaContainsPairingConstraint    — D10 allOf structure (pre-existing)
- TestPairingConstraintBehavior          — D10 valid/invalid pairs via check-jsonschema
                                           (pre-existing)

RED items (fail until Phase-2 schema flip lands, #343):
- TestMappingsFieldPresence.test_mappings_additional_properties_is_false
- TestMappingsFieldPresence.test_all_six_frameworks_declared_in_properties
  (stride, nist-ai-rmf, owasp-top10-llm not yet in properties)
- TestMappingsFieldPresence.test_framework_items_ref_points_at_pinned_block
- TestPinnedValuesAccepted (all pinned forms require @-token or :year)
- TestLegacyFormsRejected (all legacy forms currently accepted)

Coverage areas:
- mappings field: presence, strict structure, optional status
- Strict-pinned wiring: all six frameworks, valid/invalid examples
- Structural: additionalProperties:false, items $ref pinned block
- Regression: components.yaml validates (no mappings content today)
- D10 pairing constraint (pre-existing, unaffected by Phase 2)
"""
