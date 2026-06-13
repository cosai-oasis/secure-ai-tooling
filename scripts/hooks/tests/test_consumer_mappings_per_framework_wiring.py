#!/usr/bin/env python3
"""
Tests for strict per-framework wiring in the risks + controls mappings block.

Phase 2 of issue #343 flips risks.schema.json and controls.schema.json from the
hybrid (selective-strict + loose catch-all) shape to a fully-strict shape per
ADR-027 D3a and D7:

- ALL six frameworks declared in mappings.properties, each items-$ref pointing at
  frameworks.schema.json#/definitions/framework-mapping-patterns-pinned/properties/<fw>.
- additionalProperties: false (the loose catch-all is removed).
- propertyNames $ref to the framework id enum is KEPT (already present).

The base `framework-mapping-patterns` block stays byte-for-byte in
frameworks.schema.json; this test file only tests the consumer $ref repoint.

After the flip:
- Pinned forms ACCEPTED: AML.T0020@5.0.1, GOVERN-6.2@1.0, MEASURE-2.11@1.0,
  Tampering, InformationDisclosure, LLM06:2025, AI Producer@2022, Article 5@2024.
- Legacy forms REJECTED: AML.T0020, GV-6.2, MS-2.11, tampering, spoofing,
  information-disclosure, LLM06, AI Producer, Article 5.
- Malformed STILL REJECTED: aml-t0020, AML.X0020, off-enum iso values.
- Unknown framework key REJECTED via propertyNames + additionalProperties:false.

These tests assert the strict ADR-027 pinned wiring that the schema now enforces (#343).
"""

import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from conftest import _load_schema, _make_registry  # noqa: E402, I001  conftest needs sys.path manipulation


# ============================================================================
# Module-level constants
# ============================================================================

# Consumer schemas being flipped. Both get identical strict treatment.
CONSUMER_SCHEMAS = [
    ("risks.schema.json", "risk"),
    ("controls.schema.json", "control"),
]

ALL_SIX_FRAMEWORKS = {
    "mitre-atlas",
    "nist-ai-rmf",
    "stride",
    "owasp-top10-llm",
    "iso-22989",
    "eu-ai-act",
}

# Pinned forms that must be ACCEPTED after the strict flip.
# Each value includes the version token required by framework-mapping-patterns-pinned.
MITRE_ATLAS_PINNED_VALID: list[str] = [
    "AML.T0020@5.0.1",
    "AML.M0011@5.0.1",
    "AML.T0010.002@5.0.1",
]

NIST_PINNED_VALID: list[str] = [
    "GOVERN-6.2@1.0",
    "MEASURE-2.11@1.0",
    "MEASURE-2.3@1.0",
]

STRIDE_PINNED_VALID: list[str] = [
    # STRIDE has no version token (version is null); PascalCase form is the pinned shape.
    "Tampering",
    "Spoofing",
    "InformationDisclosure",
    "DenialOfService",
    "Repudiation",
]

OWASP_PINNED_VALID: list[str] = [
    "LLM06:2025",
    "LLM01:2025",
    "LLM09:2025",
]

ISO_PINNED_VALID: list[str] = [
    "AI Producer@2022",
    "AI Customer (application builder)@2022",
    "AI Partner (data supplier)@2022",
]

EU_AI_ACT_PINNED_VALID: list[str] = [
    "Article 5@2024",
    "Article 5(1)@2024",
    "Article 50@2024",
]

# Legacy forms that must be REJECTED after the strict flip (no version token).
MITRE_ATLAS_LEGACY_INVALID: list[str] = [
    "AML.T0020",  # missing @5.0.1
    "AML.M0011",  # missing @5.0.1
]

NIST_LEGACY_INVALID: list[str] = [
    "GV-6.2",  # old short-prefix form (not GOVERN/MAP/MEASURE/MANAGE prefix)
    "MS-2.11",  # old short-prefix form
    "GOVERN-6.2",  # base pattern form, missing @1.0 version
]

STRIDE_LEGACY_INVALID: list[str] = [
    "tampering",  # lowercase; stride pinned still requires PascalCase
    "spoofing",
    "information-disclosure",  # kebab-case
]

OWASP_LEGACY_INVALID: list[str] = [
    "LLM06",  # missing :2025 version
    "LLM01",
    "LLM09",
]

ISO_LEGACY_INVALID: list[str] = [
    "AI Producer",  # missing @2022
    "Data supplier",  # off-enum AND missing @2022
]

EU_AI_ACT_LEGACY_INVALID: list[str] = [
    "Article 5",  # missing @2024
    "Article 5(1)",  # missing @2024
]

# Malformed values that must be REJECTED regardless of version token.
MITRE_ATLAS_MALFORMED: list[str] = [
    "aml-t0020",  # lowercase-kebab
    "AML.X0020",  # non-T/M letter
    "AML.T20",  # short ID
]

ISO_OFF_ENUM: list[str] = [
    "AI Part (Data supplier)@2022",  # wrong label (not in the 2022 enum)
]


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def risks_schema(risk_map_schemas_dir: Path) -> dict:
    return _load_schema(risk_map_schemas_dir, "risks.schema.json")


@pytest.fixture(scope="module")
def controls_schema(risk_map_schemas_dir: Path) -> dict:
    return _load_schema(risk_map_schemas_dir, "controls.schema.json")


@pytest.fixture(scope="module")
def schemas_registry(risk_map_schemas_dir: Path) -> Registry:
    """Shared registry for risks + controls cross-file $ref resolution."""
    return _make_registry(risk_map_schemas_dir)


def _get_mappings_schema(schema: dict, entity_key: str) -> dict:
    """Extract definitions/<entity>/properties/mappings from a schema."""
    mappings = schema.get("definitions", {}).get(entity_key, {}).get("properties", {}).get("mappings")
    if mappings is None:
        pytest.fail(f"definitions/{entity_key}/properties/mappings not found")
    return mappings


# ============================================================================
# Schema meta-validity
# ============================================================================


class TestSchemaMetaValidity:
    """risks.schema.json and controls.schema.json must each be valid Draft-07."""

    @pytest.mark.parametrize("schema_file,entity_key", CONSUMER_SCHEMAS, ids=["risks", "controls"])
    def test_schema_passes_draft07_metaschema(self, risk_map_schemas_dir: Path, schema_file: str, entity_key: str):
        """
        Test that each consumer schema is valid Draft-07.

        Given: A consumer schema file
        When: Draft7Validator.check_schema() is called
        Then: No SchemaError is raised
        """
        schema = _load_schema(risk_map_schemas_dir, schema_file)
        try:
            Draft7Validator.check_schema(schema)
        except SchemaError as exc:
            pytest.fail(f"{schema_file} is not valid Draft-07: {exc.message}")


# ============================================================================
# Strict wiring shape — Phase 2 ADR-027 D3a/D7 contract
# ============================================================================


class TestMappingsStrictWiringShape:
    """
    The mappings block in risks/controls declares:
    - additionalProperties: false (catch-all removed).
    - all six frameworks in properties, each items-$ref pointing at
      framework-mapping-patterns-pinned.

    These tests assert the strict ADR-027 D3a/D7 shape now enforced by the schema (#343).
    """

    @pytest.mark.parametrize("schema_file,entity_key", CONSUMER_SCHEMAS, ids=["risks", "controls"])
    def test_mappings_additional_properties_is_false(
        self, risk_map_schemas_dir: Path, schema_file: str, entity_key: str
    ):
        """
        Test that mappings.additionalProperties is exactly false (catch-all removed).

        Given: The mappings sub-schema in a consumer schema (strict #343 schema)
        When: additionalProperties is inspected
        Then: It is the boolean false — NOT a schema object catch-all

        ADR-027 D3a: the consumer mappings block is fully strict; the loose
        catch-all that allowed legacy forms has been removed (#343).
        """
        schema = _load_schema(risk_map_schemas_dir, schema_file)
        mappings = _get_mappings_schema(schema, entity_key)
        ap = mappings.get("additionalProperties", "<MISSING>")
        assert ap is False, (
            f"{schema_file} definitions/{entity_key}/properties/mappings must have "
            f"additionalProperties: false (strict schema, #343 ADR-027 D3a); "
            f"got: {ap!r}. The loose catch-all must be removed."
        )

    @pytest.mark.parametrize("schema_file,entity_key", CONSUMER_SCHEMAS, ids=["risks", "controls"])
    @pytest.mark.parametrize("framework_key", sorted(ALL_SIX_FRAMEWORKS))
    def test_all_six_frameworks_declared_in_properties(
        self, risk_map_schemas_dir: Path, schema_file: str, entity_key: str, framework_key: str
    ):
        """
        Test that all six framework keys are declared in mappings.properties.

        Given: The mappings sub-schema properties block in a consumer schema
        When: A framework key is looked up
        Then: It is present (all six, not just the previous three)

        ADR-027 D3a: all six frameworks are explicitly wired with per-property
        entries pointing at framework-mapping-patterns-pinned (#343).
        """
        schema = _load_schema(risk_map_schemas_dir, schema_file)
        mappings = _get_mappings_schema(schema, entity_key)
        props = mappings.get("properties", {})
        assert framework_key in props, (
            f"{schema_file} mappings.properties must declare '{framework_key}' "
            "(all six frameworks strictly wired per ADR-027 D3a, #343 Phase 2)"
        )

    @pytest.mark.parametrize("schema_file,entity_key", CONSUMER_SCHEMAS, ids=["risks", "controls"])
    @pytest.mark.parametrize("framework_key", sorted(ALL_SIX_FRAMEWORKS))
    def test_framework_items_ref_points_at_pinned_block(
        self, risk_map_schemas_dir: Path, schema_file: str, entity_key: str, framework_key: str
    ):
        """
        Test that each framework's items $ref resolves to framework-mapping-patterns-pinned.

        Given: The mappings.properties.<framework_key>.items sub-schema
        When: Its $ref is inspected
        Then: It ends in 'framework-mapping-patterns-pinned/properties/<framework_key>'

        ADR-027 D7: the consumer $refs point from framework-mapping-patterns
        (base block) to framework-mapping-patterns-pinned (strict block) (#343).
        """
        schema = _load_schema(risk_map_schemas_dir, schema_file)
        mappings = _get_mappings_schema(schema, entity_key)
        fw_schema = mappings.get("properties", {}).get(framework_key, {})
        items = fw_schema.get("items", {})
        ref = items.get("$ref", "")
        expected_suffix = f"framework-mapping-patterns-pinned/properties/{framework_key}"
        assert ref.endswith(expected_suffix), (
            f"{schema_file} mappings.properties.{framework_key}.items.$ref must end with "
            f"'{expected_suffix}' (pinned block, ADR-027 D7, #343 Phase 2); got: {ref!r}"
        )


# ============================================================================
# Pinned values ACCEPTED
# ============================================================================


class TestPinnedValuesAccepted:
    """
    Per-framework pinned-form values are accepted by the strict schema (#343).

    The pinned patterns require the version token (@5.0.1 etc.); the schemas
    now point at framework-mapping-patterns-pinned (not the base block).
    """

    @pytest.mark.parametrize("valid_id", MITRE_ATLAS_PINNED_VALID)
    def test_mitre_atlas_pinned_accepted_in_risks(
        self, risks_schema: dict, schemas_registry: Registry, valid_id: str
    ):
        """
        Test that pinned mitre-atlas IDs (with @5.0.1) pass in risks mappings.

        Given: risks mappings schema with mitre-atlas strict-pinned wiring
        When: {"mitre-atlas": [<valid_id>]} is validated
        Then: No errors — the @5.0.1 token satisfies the pinned pattern

        The $ref now points at framework-mapping-patterns-pinned per ADR-027 D7 (#343).
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"mitre-atlas": [valid_id]}))
        assert not errors, (
            f"risks mitre-atlas pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", MITRE_ATLAS_PINNED_VALID)
    def test_mitre_atlas_pinned_accepted_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, valid_id: str
    ):
        """
        Test that pinned mitre-atlas IDs (with @5.0.1) pass in controls mappings.

        Given: controls mappings schema with mitre-atlas strict-pinned wiring
        When: {"mitre-atlas": [<valid_id>]} is validated
        Then: No errors
        """
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"mitre-atlas": [valid_id]}))
        assert not errors, (
            f"controls mitre-atlas pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", NIST_PINNED_VALID)
    def test_nist_ai_rmf_pinned_accepted_in_risks(
        self, risks_schema: dict, schemas_registry: Registry, valid_id: str
    ):
        """
        Test that pinned nist-ai-rmf IDs (GOVERN/MEASURE/MAP/MANAGE-N.N@1.0) pass.

        Given: risks mappings schema with nist-ai-rmf strict-pinned wiring
        When: {"nist-ai-rmf": [<valid_id>]} is validated
        Then: No errors

        nist-ai-rmf is wired in properties and points at the pinned block
        per ADR-027 D3a (#343).
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"nist-ai-rmf": [valid_id]}))
        assert not errors, (
            f"risks nist-ai-rmf pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", NIST_PINNED_VALID)
    def test_nist_ai_rmf_pinned_accepted_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, valid_id: str
    ):
        """Test that pinned nist-ai-rmf IDs pass in controls mappings."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"nist-ai-rmf": [valid_id]}))
        assert not errors, (
            f"controls nist-ai-rmf pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", STRIDE_PINNED_VALID)
    def test_stride_pinned_accepted_in_risks(self, risks_schema: dict, schemas_registry: Registry, valid_id: str):
        """
        Test that STRIDE PascalCase values pass in risks mappings after the flip.

        Given: risks mappings schema with stride strict-pinned wiring
        When: {"stride": [<PascalCase-value>]} is validated
        Then: No errors — stride pinned pattern uses same PascalCase as the base
              but the value must come from stride's explicitly-wired properties entry

        stride is now declared in properties per ADR-027 D3a (#343); the former
        loose catch-all that stride fell through to has been removed.
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"stride": [valid_id]}))
        assert not errors, (
            f"risks stride pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", STRIDE_PINNED_VALID)
    def test_stride_pinned_accepted_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, valid_id: str
    ):
        """Test that STRIDE PascalCase values pass in controls mappings."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"stride": [valid_id]}))
        assert not errors, (
            f"controls stride pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", OWASP_PINNED_VALID)
    def test_owasp_pinned_accepted_in_risks(self, risks_schema: dict, schemas_registry: Registry, valid_id: str):
        """
        Test that OWASP LLMnn:2025 values pass in risks mappings after the flip.

        Given: risks mappings schema with owasp-top10-llm strict-pinned wiring
        When: {"owasp-top10-llm": [<LLMnn:2025>]} is validated
        Then: No errors

        owasp-top10-llm is wired in properties and points at the pinned block
        (pattern ^LLM\\d{2}:2025$) per ADR-027 D3a (#343).
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"owasp-top10-llm": [valid_id]}))
        assert not errors, (
            f"risks owasp-top10-llm pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", OWASP_PINNED_VALID)
    def test_owasp_pinned_accepted_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, valid_id: str
    ):
        """Test that OWASP LLMnn:2025 values pass in controls mappings."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"owasp-top10-llm": [valid_id]}))
        assert not errors, (
            f"controls owasp-top10-llm pinned value {valid_id!r} must be accepted; "
            f"got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", ISO_PINNED_VALID)
    def test_iso_22989_pinned_accepted_in_risks(
        self, risks_schema: dict, schemas_registry: Registry, valid_id: str
    ):
        """
        Test that iso-22989 enum-pinned values (with @2022) pass in risks mappings.

        Given: risks mappings schema with iso-22989 strict-pinned wiring
        When: {"iso-22989": [<role@2022>]} is validated
        Then: No errors — the @2022 token satisfies the pinned oneOf enum

        iso-22989 is now repointed to the pinned block (which uses a oneOf enum,
        not a bare string) per ADR-027 D7/D8 (#343).
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"iso-22989": [valid_id]}))
        assert not errors, (
            f"risks iso-22989 pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", ISO_PINNED_VALID)
    def test_iso_22989_pinned_accepted_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, valid_id: str
    ):
        """Test that iso-22989 enum-pinned values (with @2022) pass in controls mappings."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"iso-22989": [valid_id]}))
        assert not errors, (
            f"controls iso-22989 pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", EU_AI_ACT_PINNED_VALID)
    def test_eu_ai_act_pinned_accepted_in_risks(
        self, risks_schema: dict, schemas_registry: Registry, valid_id: str
    ):
        """
        Test that eu-ai-act Article N@2024 values pass in risks mappings.

        Given: risks mappings schema with eu-ai-act strict-pinned wiring
        When: {"eu-ai-act": [<Article N@2024>]} is validated
        Then: No errors — the @2024 token satisfies the pinned pattern
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"eu-ai-act": [valid_id]}))
        assert not errors, (
            f"risks eu-ai-act pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("valid_id", EU_AI_ACT_PINNED_VALID)
    def test_eu_ai_act_pinned_accepted_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, valid_id: str
    ):
        """Test that eu-ai-act Article N@2024 values pass in controls mappings."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"eu-ai-act": [valid_id]}))
        assert not errors, (
            f"controls eu-ai-act pinned value {valid_id!r} must be accepted; got: {[e.message for e in errors]}"
        )


# ============================================================================
# Legacy forms REJECTED
# ============================================================================


class TestLegacyFormsRejected:
    """
    Legacy (unpinned) forms are REJECTED by the strict schema (#343).

    These formerly passed via the loose catch-all or via the base
    framework-mapping-patterns (which had no version token requirement).
    The strict pinned patterns now reject them.
    """

    @pytest.mark.parametrize("legacy_id", MITRE_ATLAS_LEGACY_INVALID)
    def test_mitre_atlas_legacy_rejected_in_risks(
        self, risks_schema: dict, schemas_registry: Registry, legacy_id: str
    ):
        """
        Test that mitre-atlas IDs without @5.0.1 are rejected in risks mappings.

        Given: risks mappings schema with strict-pinned mitre-atlas wiring
        When: {"mitre-atlas": [<id-without-version>]} is validated
        Then: ValidationError — pinned pattern ^AML\\.(T|M)\\d{4}(\\.\\d{3})?@(5\\.0\\.1)$ rejects it

        The base pattern formerly accepted bare AML.Tnnnn; the pinned pattern now rejects it.
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"mitre-atlas": [legacy_id]}))
        assert errors, (
            f"risks mitre-atlas legacy value {legacy_id!r} must be REJECTED "
            f"(missing @5.0.1, ADR-027 D3a strict flip, #343); "
            f"was incorrectly accepted (currently on loose/base schema)"
        )

    @pytest.mark.parametrize("legacy_id", MITRE_ATLAS_LEGACY_INVALID)
    def test_mitre_atlas_legacy_rejected_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, legacy_id: str
    ):
        """Test that mitre-atlas IDs without @5.0.1 are rejected in controls mappings."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"mitre-atlas": [legacy_id]}))
        assert errors, (
            f"controls mitre-atlas legacy value {legacy_id!r} must be REJECTED "
            f"(missing @5.0.1, ADR-027 D3a strict flip, #343)"
        )

    @pytest.mark.parametrize("legacy_id", NIST_LEGACY_INVALID)
    def test_nist_ai_rmf_legacy_rejected_in_risks(
        self, risks_schema: dict, schemas_registry: Registry, legacy_id: str
    ):
        """
        Test that nist-ai-rmf legacy forms (GV-N.N, MS-N.N, or GOVERN-N.N without @1.0)
        are rejected in risks mappings.

        Given: risks mappings schema with strict-pinned nist-ai-rmf wiring
        When: {"nist-ai-rmf": [<legacy>]} is validated
        Then: ValidationError — pinned pattern requires @1.0 suffix and full prefix

        The loose catch-all formerly allowed these through; the strict pinned pattern rejects them (#343).
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"nist-ai-rmf": [legacy_id]}))
        assert errors, (
            f"risks nist-ai-rmf legacy value {legacy_id!r} must be REJECTED (ADR-027 D3a strict flip, #343)"
        )

    @pytest.mark.parametrize("legacy_id", NIST_LEGACY_INVALID)
    def test_nist_ai_rmf_legacy_rejected_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, legacy_id: str
    ):
        """Test that nist-ai-rmf legacy forms are rejected in controls mappings."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"nist-ai-rmf": [legacy_id]}))
        assert errors, (
            f"controls nist-ai-rmf legacy value {legacy_id!r} must be REJECTED (ADR-027 D3a strict flip, #343)"
        )

    @pytest.mark.parametrize("legacy_id", STRIDE_LEGACY_INVALID)
    def test_stride_legacy_rejected_in_risks(self, risks_schema: dict, schemas_registry: Registry, legacy_id: str):
        """
        Test that lowercase/kebab stride values are rejected in risks mappings.

        Given: risks mappings schema with strict-pinned stride wiring
        When: {"stride": [<lowercase-form>]} is validated
        Then: ValidationError — pinned pattern (same as base) requires PascalCase

        The loose catch-all formerly allowed these through; stride is now explicitly
        wired to the pinned PascalCase pattern, so they are rejected (#343 ADR-027 D3a).
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"stride": [legacy_id]}))
        assert errors, (
            f"risks stride legacy value {legacy_id!r} must be REJECTED "
            f"(ADR-027 D3a strict flip — stride wired to pinned PascalCase, #343)"
        )

    @pytest.mark.parametrize("legacy_id", STRIDE_LEGACY_INVALID)
    def test_stride_legacy_rejected_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, legacy_id: str
    ):
        """Test that lowercase/kebab stride values are rejected in controls mappings."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"stride": [legacy_id]}))
        assert errors, (
            f"controls stride legacy value {legacy_id!r} must be REJECTED (ADR-027 D3a strict flip, #343)"
        )

    @pytest.mark.parametrize("legacy_id", OWASP_LEGACY_INVALID)
    def test_owasp_legacy_rejected_in_risks(self, risks_schema: dict, schemas_registry: Registry, legacy_id: str):
        """
        Test that owasp-top10-llm values without :2025 year are rejected in risks.

        Given: risks mappings schema with strict-pinned owasp-top10-llm wiring
        When: {"owasp-top10-llm": [<LLMnn-without-year>]} is validated
        Then: ValidationError — pinned pattern ^LLM\\d{2}:2025$ rejects bare LLMnn

        The loose catch-all formerly allowed these through; the strict pinned pattern
        ^LLM\\d{2}:2025$ now rejects bare LLMnn values (#343).
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"owasp-top10-llm": [legacy_id]}))
        assert errors, (
            f"risks owasp-top10-llm legacy value {legacy_id!r} must be REJECTED (ADR-027 D3a strict flip, #343)"
        )

    @pytest.mark.parametrize("legacy_id", OWASP_LEGACY_INVALID)
    def test_owasp_legacy_rejected_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, legacy_id: str
    ):
        """Test that owasp-top10-llm values without :2025 are rejected in controls."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"owasp-top10-llm": [legacy_id]}))
        assert errors, (
            f"controls owasp-top10-llm legacy value {legacy_id!r} must be REJECTED (ADR-027 D3a strict flip, #343)"
        )

    @pytest.mark.parametrize("legacy_id", ISO_LEGACY_INVALID)
    def test_iso_22989_legacy_rejected_in_risks(
        self, risks_schema: dict, schemas_registry: Registry, legacy_id: str
    ):
        """
        Test that iso-22989 bare-string values (without @2022) are rejected in risks.

        Given: risks mappings schema with strict-pinned iso-22989 wiring
        When: {"iso-22989": [<role-without-version>]} is validated
        Then: ValidationError — pinned block uses a oneOf enum requiring @2022 suffix

        The base iso-22989 was a bare string with no pattern; the pinned block
        (now active) uses a oneOf enum that rejects bare strings (#343 ADR-027 D7).
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"iso-22989": [legacy_id]}))
        assert errors, (
            f"risks iso-22989 legacy value {legacy_id!r} must be REJECTED "
            f"(ADR-027 D7 pinned oneOf enum requires @2022 suffix, #343)"
        )

    @pytest.mark.parametrize("legacy_id", ISO_LEGACY_INVALID)
    def test_iso_22989_legacy_rejected_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, legacy_id: str
    ):
        """Test that iso-22989 bare-string values (without @2022) are rejected in controls."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"iso-22989": [legacy_id]}))
        assert errors, (
            f"controls iso-22989 legacy value {legacy_id!r} must be REJECTED "
            f"(ADR-027 D7 pinned oneOf enum requires @2022 suffix, #343)"
        )

    @pytest.mark.parametrize("legacy_id", EU_AI_ACT_LEGACY_INVALID)
    def test_eu_ai_act_legacy_rejected_in_risks(
        self, risks_schema: dict, schemas_registry: Registry, legacy_id: str
    ):
        """
        Test that eu-ai-act Article N values (without @2024) are rejected in risks.

        Given: risks mappings schema with strict-pinned eu-ai-act wiring
        When: {"eu-ai-act": [<Article N without @2024>]} is validated
        Then: ValidationError — pinned pattern requires @2024 suffix

        The base eu-ai-act pattern ^Article\\s\\d+(\\(\\d+\\))?$ had no version token;
        eu-ai-act is now repointed to the pinned pattern requiring @2024 (#343).
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"eu-ai-act": [legacy_id]}))
        assert errors, (
            f"risks eu-ai-act legacy value {legacy_id!r} must be REJECTED "
            f"(pinned pattern requires @2024, ADR-027 D3a, #343)"
        )

    @pytest.mark.parametrize("legacy_id", EU_AI_ACT_LEGACY_INVALID)
    def test_eu_ai_act_legacy_rejected_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, legacy_id: str
    ):
        """Test that eu-ai-act Article N values (without @2024) are rejected in controls."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"eu-ai-act": [legacy_id]}))
        assert errors, (
            f"controls eu-ai-act legacy value {legacy_id!r} must be REJECTED "
            f"(pinned pattern requires @2024, ADR-027 D3a, #343)"
        )


# ============================================================================
# Malformed values REJECTED (these should already fail; confirm regression)
# ============================================================================


class TestMalformedValuesRejected:
    """
    Malformed values that are structurally wrong must be rejected both before and
    after the strict flip. This is a regression guard — if any of these start
    passing, a schema regression has been introduced.
    """

    @pytest.mark.parametrize("invalid_id", MITRE_ATLAS_MALFORMED)
    def test_mitre_atlas_malformed_rejected_in_risks(
        self, risks_schema: dict, schemas_registry: Registry, invalid_id: str
    ):
        """
        Test that structurally malformed mitre-atlas IDs are rejected in risks.

        Given: risks mappings schema
        When: {"mitre-atlas": [<malformed-id>]} is validated
        Then: ValidationError — malformed forms fail both base and pinned patterns
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"mitre-atlas": [invalid_id]}))
        assert errors, f"risks mitre-atlas malformed {invalid_id!r} must be rejected"

    @pytest.mark.parametrize("invalid_id", MITRE_ATLAS_MALFORMED)
    def test_mitre_atlas_malformed_rejected_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, invalid_id: str
    ):
        """Test that structurally malformed mitre-atlas IDs are rejected in controls."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"mitre-atlas": [invalid_id]}))
        assert errors, f"controls mitre-atlas malformed {invalid_id!r} must be rejected"

    @pytest.mark.parametrize("off_enum_id", ISO_OFF_ENUM)
    def test_iso_22989_off_enum_rejected_in_risks(
        self, risks_schema: dict, schemas_registry: Registry, off_enum_id: str
    ):
        """
        Test that iso-22989 values not in the @2022 enum are rejected (pinned).

        Given: risks mappings schema with strict-pinned iso-22989 wiring
        When: {"iso-22989": [<value-not-in-2022-enum>]} is validated
        Then: ValidationError — oneOf enum does not contain the value

        The base iso-22989 was a bare string (accepted anything); the pinned block
        now active restricts to the closed 2022 oneOf enum (#343).
        """
        mappings = _get_mappings_schema(risks_schema, "risk")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"iso-22989": [off_enum_id]}))
        assert errors, (
            f"risks iso-22989 off-enum value {off_enum_id!r} must be REJECTED "
            f"(pinned 2022 oneOf enum, ADR-027 D7/D8, #343)"
        )

    @pytest.mark.parametrize("off_enum_id", ISO_OFF_ENUM)
    def test_iso_22989_off_enum_rejected_in_controls(
        self, controls_schema: dict, schemas_registry: Registry, off_enum_id: str
    ):
        """Test that iso-22989 off-enum values are rejected in controls (pinned oneOf)."""
        mappings = _get_mappings_schema(controls_schema, "control")
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"iso-22989": [off_enum_id]}))
        assert errors, (
            f"controls iso-22989 off-enum value {off_enum_id!r} must be REJECTED "
            f"(pinned 2022 oneOf enum, ADR-027 D7/D8, #343)"
        )


# ============================================================================
# Unknown framework key rejected via propertyNames + additionalProperties:false
# ============================================================================


class TestUnknownFrameworkRejected:
    """Unknown framework keys must be rejected; additionalProperties:false closes the door."""

    @pytest.mark.parametrize("schema_file,entity_key", CONSUMER_SCHEMAS, ids=["risks", "controls"])
    def test_unknown_framework_key_rejected(
        self,
        risk_map_schemas_dir: Path,
        schemas_registry: Registry,
        schema_file: str,
        entity_key: str,
    ):
        """
        Test that an unregistered framework key is rejected.

        Given: A mappings object with made-up-framework: ["some-value"]
        When: It is validated against the mappings schema
        Then: ValidationError (propertyNames constraint + additionalProperties:false)

        This already passes via propertyNames; additionalProperties:false provides
        defense-in-depth after the flip.
        """
        schema = _load_schema(risk_map_schemas_dir, schema_file)
        mappings = _get_mappings_schema(schema, entity_key)
        validator = Draft7Validator(mappings, registry=schemas_registry)
        errors = list(validator.iter_errors({"made-up-framework": ["some-value"]}))
        assert errors, (
            f"{schema_file}: unknown framework key 'made-up-framework' must be rejected "
            f"via propertyNames + additionalProperties:false"
        )


# ============================================================================
# Regression — current YAML files still validate (live corpus guard)
# ============================================================================


@pytest.mark.live_corpus
class TestCurrentYamlStillValid:
    """
    Current risks.yaml and controls.yaml must still pass check-jsonschema after
    the Phase-2 strict flip + Phase-2 content migration.

    This class is marked @pytest.mark.live_corpus. Both the schema flip and
    content migration to pinned forms are complete (#343).
    """

    def test_risks_yaml_passes_check_jsonschema(self, risk_map_schemas_dir: Path, risk_map_yaml_dir: Path):
        """
        Test that risks.yaml continues to validate against the strict risks.schema.json.

        Given: The current risks.yaml on disk
        When: check-jsonschema is run with risks.schema.json
        Then: Exit code is 0 (content migrated to pinned forms, strict schema active)
        """
        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                f"file://{risk_map_schemas_dir}/",
                "--schemafile",
                str(risk_map_schemas_dir / "risks.schema.json"),
                str(risk_map_yaml_dir / "risks.yaml"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"risks.yaml must remain valid against strict risks.schema.json "
            f"(#343 Phase 2 complete — content migrated to pinned forms):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_controls_yaml_passes_check_jsonschema(self, risk_map_schemas_dir: Path, risk_map_yaml_dir: Path):
        """
        Test that controls.yaml continues to validate against the strict controls.schema.json.

        Given: The current controls.yaml on disk
        When: check-jsonschema is run with controls.schema.json
        Then: Exit code is 0 (content migrated to pinned forms, strict schema active)
        """
        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                f"file://{risk_map_schemas_dir}/",
                "--schemafile",
                str(risk_map_schemas_dir / "controls.schema.json"),
                str(risk_map_yaml_dir / "controls.yaml"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"controls.yaml must remain valid against strict controls.schema.json "
            f"(#343 Phase 2 complete — content migrated to pinned forms):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ============================================================================
# Test summary
# ============================================================================
"""
Test Summary (Phase 2 strict wiring — #343 ADR-027 D3a/D7)
===========================================================
Test classes: 7

- TestSchemaMetaValidity (2)            — risks + controls valid Draft-07
- TestMappingsStrictWiringShape         — additionalProperties:false + all-six in
                                          properties + items $ref → pinned block
                                          (parametrized × 2 schemas × 6 frameworks = 26)
- TestPinnedValuesAccepted              — per-framework pinned forms accepted
                                          (6 fw × 2 schemas × multiple values ≈ 48)
- TestLegacyFormsRejected               — legacy/unversioned forms rejected after flip
                                          (6 fw × 2 schemas × multiple values ≈ 44)
- TestMalformedValuesRejected           — structurally bad forms still rejected (10)
- TestUnknownFrameworkRejected (2)      — propertyNames + additionalProperties:false
- TestCurrentYamlStillValid (2)         — live corpus regression guard (live_corpus mark)

All tests are GREEN: the strict schema is active and content has been migrated (#343).

Coverage areas:
- Strict structural shape: additionalProperties:false, all-six properties, pinned $refs
- Behavioral: pinned accepted / legacy rejected / malformed rejected (per fw × per schema)
- Regression: live corpus validates clean after both schema flip + content migration
"""
