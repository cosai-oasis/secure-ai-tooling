#!/usr/bin/env python3
"""
Tests for personas.schema.json schema updates.

This module tests the expanded persona schema supporting 8 CoSAI personas with:
- New persona ID enum values (8 new + 2 legacy personas)
- Optional fields: deprecated, mappings, responsibilities, identificationQuestions
- Backward compatibility with existing personas.yaml

Phase 2 of issue #343 flips the persona mappings block to strict-pinned wiring
per ADR-027 D3a/D7:
- mappings.additionalProperties changes from a loose array catch-all to the
  boolean false.
- All six frameworks are explicitly wired with per-property entries pointing at
  framework-mapping-patterns-pinned.
- Bare/legacy iso-22989 values ("AI Producer", "Data supplier") are REJECTED;
  pinned values with @2022 suffix ("AI Producer@2022") are required.

Tests cover:
- Schema validation for new persona IDs
- Optional field validation and structure (Phase-2: strict mappings shape)
- Backward compatibility with existing personas.yaml
- Valid and invalid persona configurations
- Edge cases and error conditions
- Phase-2 strict flip: pinned iso accepted, legacy iso rejected
"""

import json
import subprocess
import sys
from pathlib import Path

# Add parent directory to path for test utilities
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# Schema Structure Tests - New Persona ID Enum Values
# ============================================================================


class TestPersonaIdEnumUpdates:
    """Test that persona schema accepts all 9 persona IDs (7 new + 2 legacy)."""

    def test_persona_id_enum_exists_in_schema(self, personas_schema_path):
        """
        Test that persona ID enum is defined in schema.

        Given: personas.schema.json file
        When: Schema is loaded and parsed
        Then: Persona definition includes id property with enum constraint
        """
        assert personas_schema_path.exists(), "personas.schema.json must exist"

        with open(personas_schema_path) as f:
            schema = json.load(f)

        persona_def = schema["definitions"]["persona"]
        assert "id" in persona_def["properties"], "id field must be defined"
        assert "enum" in persona_def["properties"]["id"], "id must have enum constraint"

    def test_persona_id_enum_contains_new_persona_ids(self, personas_schema_path):
        """
        Test that persona ID enum includes all 7 new CoSAI persona IDs.

        Given: personas.schema.json persona definition
        When: ID enum values are examined
        Then: Contains all new persona IDs:
              - personaModelProvider
              - personaDataProvider
              - personaPlatformProvider
              - personaAgenticProvider
              - personaApplicationDeveloper
              - personaGovernance
              - personaEndUser
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        id_enum = schema["definitions"]["persona"]["properties"]["id"]["enum"]
        new_personas = {
            "personaModelProvider",
            "personaDataProvider",
            "personaPlatformProvider",
            "personaAgenticProvider",
            "personaApplicationDeveloper",
            "personaGovernance",
            "personaEndUser",
        }

        for persona_id in new_personas:
            assert persona_id in id_enum, f"{persona_id} must be in persona ID enum"

    def test_persona_id_enum_contains_legacy_persona_ids(self, personas_schema_path):
        """
        Test that persona ID enum retains existing legacy persona IDs.

        Given: personas.schema.json persona definition
        When: ID enum values are examined
        Then: Contains legacy persona IDs:
              - personaModelCreator
              - personaModelConsumer
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        id_enum = schema["definitions"]["persona"]["properties"]["id"]["enum"]
        legacy_personas = {"personaModelCreator", "personaModelConsumer"}

        for persona_id in legacy_personas:
            assert persona_id in id_enum, f"Legacy {persona_id} must remain in enum"

    def test_persona_id_enum_has_minimum_required_values(self, personas_schema_path):
        """
        Test that persona ID enum has at least 9 values (7 new + 2 legacy).

        Given: personas.schema.json persona definition
        When: ID enum values are counted
        Then: Enum contains at least 9 persona IDs
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        id_enum = schema["definitions"]["persona"]["properties"]["id"]["enum"]

        # Uses minimum check to avoid breaking when new personas are added
        assert len(id_enum) >= 9, f"Expected at least 9 persona IDs, found {len(id_enum)}"


# ============================================================================
# Schema Structure Tests - New Optional Fields
# ============================================================================


class TestPersonaOptionalFields:
    """Test new optional fields in persona schema."""

    def test_deprecated_field_exists_in_schema(self, personas_schema_path):
        """
        Test that deprecated field is defined in persona schema.

        Given: personas.schema.json persona definition
        When: Properties are examined
        Then: deprecated field is defined as boolean type
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        persona_props = schema["definitions"]["persona"]["properties"]

        assert "deprecated" in persona_props, "deprecated field must be defined"
        assert persona_props["deprecated"]["type"] == "boolean", "deprecated must be boolean type"

    def test_deprecated_field_is_optional(self, personas_schema_path):
        """
        Test that deprecated field is not in required fields.

        Given: personas.schema.json persona definition
        When: Required fields are examined
        Then: deprecated is not in required array
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        persona_def = schema["definitions"]["persona"]
        required_fields = persona_def.get("required", [])

        assert "deprecated" not in required_fields, "deprecated must be optional"

    def test_mappings_field_exists_in_schema(self, personas_schema_path):
        """
        Test that mappings field is defined in persona schema.

        Given: personas.schema.json persona definition
        When: Properties are examined
        Then: mappings field is defined as object with array values
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        persona_props = schema["definitions"]["persona"]["properties"]

        assert "mappings" in persona_props, "mappings field must be defined"
        assert persona_props["mappings"]["type"] == "object", "mappings must be object type"

    def test_mappings_additional_properties_is_false(self, personas_schema_path):
        """
        Test that mappings.additionalProperties is the boolean false (Phase-2 strict flip).

        Given: personas.schema.json mappings definition (strict #343 schema)
        When: additionalProperties is examined
        Then: It is exactly the boolean false — the loose catch-all has been removed

        ADR-027 D3a: all six frameworks are explicitly wired with per-property
        entries; the loose array catch-all was replaced by false (#343).
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        mappings_def = schema["definitions"]["persona"]["properties"]["mappings"]
        ap = mappings_def.get("additionalProperties", "<MISSING>")
        assert ap is False, (
            f"personas.schema.json definitions/persona/properties/mappings/additionalProperties "
            f"must be the boolean false (strict schema, #343 ADR-027 D3a); "
            f"got: {ap!r}. The loose array catch-all must be replaced with false."
        )

    def test_mappings_field_is_optional(self, personas_schema_path):
        """
        Test that mappings field is not in required fields.

        Given: personas.schema.json persona definition
        When: Required fields are examined
        Then: mappings is not in required array
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        persona_def = schema["definitions"]["persona"]
        required_fields = persona_def.get("required", [])

        assert "mappings" not in required_fields, "mappings must be optional"

    def test_responsibilities_field_exists_in_schema(self, personas_schema_path):
        """
        Test that responsibilities field is defined in persona schema.

        Given: personas.schema.json persona definition
        When: Properties are examined
        Then: responsibilities field is defined as array of strings
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        persona_props = schema["definitions"]["persona"]["properties"]

        assert "responsibilities" in persona_props, "responsibilities field must be defined"
        assert persona_props["responsibilities"]["type"] == "array", "responsibilities must be array type"
        assert persona_props["responsibilities"]["items"]["type"] == "string", (
            "responsibilities items must be strings"
        )

    def test_responsibilities_field_is_optional(self, personas_schema_path):
        """
        Test that responsibilities field is not in required fields.

        Given: personas.schema.json persona definition
        When: Required fields are examined
        Then: responsibilities is not in required array
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        persona_def = schema["definitions"]["persona"]
        required_fields = persona_def.get("required", [])

        assert "responsibilities" not in required_fields, "responsibilities must be optional"

    def test_identification_questions_field_exists_in_schema(self, personas_schema_path):
        """
        Test that identificationQuestions field is defined in persona schema.

        Given: personas.schema.json persona definition
        When: Properties are examined
        Then: identificationQuestions field is defined as array of strings
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        persona_props = schema["definitions"]["persona"]["properties"]

        assert "identificationQuestions" in persona_props, "identificationQuestions field must be defined"
        assert persona_props["identificationQuestions"]["type"] == "array", (
            "identificationQuestions must be array type"
        )
        assert persona_props["identificationQuestions"]["items"]["type"] == "string", (
            "identificationQuestions items must be strings"
        )

    def test_identification_questions_field_is_optional(self, personas_schema_path):
        """
        Test that identificationQuestions field is not in required fields.

        Given: personas.schema.json persona definition
        When: Required fields are examined
        Then: identificationQuestions is not in required array
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        persona_def = schema["definitions"]["persona"]
        required_fields = persona_def.get("required", [])

        assert "identificationQuestions" not in required_fields, "identificationQuestions must be optional"


# ============================================================================
# Backward Compatibility Tests
# ============================================================================


class TestPersonaBackwardCompatibility:
    """Test backward compatibility with existing personas.yaml structure."""

    def test_existing_personas_yaml_still_validates(self, personas_yaml_path, personas_schema_path, base_uri):
        """
        Test that current personas.yaml validates against updated schema.

        Given: Existing personas.yaml with only id, title, description fields
        When: Schema validation is performed against updated schema
        Then: Validation passes (backward compatible)
        """
        yaml_path = personas_yaml_path
        schema_path = personas_schema_path
        base_uri_str = base_uri

        assert yaml_path.exists(), "personas.yaml must exist"
        assert schema_path.exists(), "personas.schema.json must exist"

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_path)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Existing personas.yaml should validate with updated schema.\nError output:\n{result.stderr}"
        )

    def test_deprecated_persona_without_optional_fields_passes_validation(
        self, tmp_path, personas_schema_path, base_uri
    ):
        """
        Test that a deprecated persona with only core fields validates.

        Given: A deprecated persona with id, title, description, and deprecated: true
               but no identificationQuestions or other optional fields
        When: Schema validation is performed
        Then: Validation passes — the ADR-021 D8 conditional constraint exempts
              deprecated personas, so the minimal valid persona without
              identificationQuestions is one marked deprecated: true
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaModelCreator
    title: Model Creator
    description:
      - Organizations that train and tune models
    deprecated: true
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = personas_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Deprecated persona without identificationQuestions should validate. Error: {result.stderr}"
        )


# ============================================================================
# Valid Configuration Tests
# ============================================================================


class TestValidPersonaConfigurations:
    """Test that valid persona configurations pass schema validation."""

    def test_new_persona_id_passes_validation(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that new persona IDs validate successfully.

        Given: A persona with one of the new CoSAI persona IDs
        When: Schema validation is performed
        Then: Validation passes
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaModelProvider
    title: Model Provider
    description:
      - Organizations that provide AI models
    identificationQuestions:
      - "Do you supply or license AI models to other organizations?"
      - "Are you responsible for the training and release of AI model artifacts?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"New persona ID should validate. Error: {result.stderr}"

    def test_persona_with_deprecated_field_passes_validation(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that persona with deprecated field validates.

        Given: A persona with deprecated: true
        When: Schema validation is performed
        Then: Validation passes
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaModelCreator
    title: Model Creator
    description:
      - Legacy persona
    deprecated: true
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Persona with deprecated field should validate. Error: {result.stderr}"

    def test_persona_with_mappings_passes_validation(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that persona with framework mappings (pinned forms) validates.

        Given: A persona with mappings to external frameworks using pinned iso-22989 values
        When: Schema validation is performed
        Then: Validation passes

        Uses pinned iso-22989 values (with @2022 suffix) per ADR-027 D7/D8.
        Bare/legacy values ("Data supplier", "AI Producer") are REJECTED by the
        strict schema (#343); the pinned value "AI Partner (data supplier)@2022"
        is accepted because iso-22989 is now wired to framework-mapping-patterns-pinned.
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaDataProvider
    title: Data Provider
    description:
      - Organizations that provide data
    mappings:
      iso-22989:
        - "AI Partner (data supplier)@2022"
    identificationQuestions:
      - "Do you collect, curate, or license datasets used to train AI systems?"
      - "Are you responsible for the quality and provenance of data supplied to AI pipelines?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Persona with mappings should validate. Error: {result.stderr}"

    def test_persona_with_responsibilities_passes_validation(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that persona with responsibilities validates.

        Given: A persona with responsibilities array
        When: Schema validation is performed
        Then: Validation passes
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaGovernance
    title: Governance
    description:
      - Organizations responsible for governance
    responsibilities:
      - "Establish AI governance policies"
      - "Monitor compliance with regulations"
      - "Define risk management frameworks"
    identificationQuestions:
      - "Do you set or enforce AI governance policies within your organization?"
      - "Are you responsible for AI risk management or compliance oversight?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Persona with responsibilities should validate. Error: {result.stderr}"

    def test_persona_with_identification_questions_passes_validation(
        self, tmp_path, personas_schema_path, base_uri
    ):
        """
        Test that persona with identificationQuestions validates.

        Given: A persona with identificationQuestions array
        When: Schema validation is performed
        Then: Validation passes
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaEndUser
    title: End User
    description:
      - End users of AI systems
    identificationQuestions:
      - "Do you directly interact with AI-powered applications?"
      - "Are you a consumer of AI-enabled services?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Persona with identificationQuestions should validate. Error: {result.stderr}"
        )

    def test_persona_with_all_optional_fields_passes_validation(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that persona with all optional fields (pinned mappings) validates.

        Given: A persona with deprecated, mappings, responsibilities, identificationQuestions
               using a pinned iso-22989 value (with @2022 suffix)
        When: Schema validation is performed
        Then: Validation passes

        Uses pinned iso-22989 per ADR-027 D7/D8; the strict pinned oneOf enum
        rejects bare values such as "AI system developer" (#343).
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaApplicationDeveloper
    title: Application Developer
    description:
      - Developers building AI applications
    deprecated: false
    mappings:
      iso-22989:
        - "AI Customer (application builder)@2022"
    responsibilities:
      - "Integrate AI models into applications"
      - "Implement security controls"
    identificationQuestions:
      - "Do you develop applications that use AI models?"
      - "Are you responsible for AI integration?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Persona with all optional fields should validate. Error: {result.stderr}"


# ============================================================================
# Invalid Configuration Tests
# ============================================================================


class TestInvalidPersonaConfigurations:
    """Test that invalid persona configurations fail schema validation."""

    def test_persona_with_invalid_id_fails_validation(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that persona with invalid ID fails validation.

        Given: A persona with ID not in the enum
        When: Schema validation is performed
        Then: Validation fails with enum error
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaInvalidRole
    title: Invalid Role
    description:
      - This ID is not in the enum
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Invalid persona ID should fail validation"
        output = result.stdout + result.stderr
        assert "personaInvalidRole" in output or "enum" in output.lower(), (
            f"Error should mention invalid ID or enum violation. Output: {output}"
        )

    def test_persona_with_wrong_deprecated_type_fails_validation(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that persona with non-boolean deprecated fails validation.

        Given: A persona with deprecated: "yes" (string instead of boolean)
        When: Schema validation is performed
        Then: Validation fails with type error
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaModelCreator
    title: Model Creator
    description:
      - Test persona
    deprecated: "yes"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Non-boolean deprecated should fail validation"
        output = result.stdout + result.stderr
        assert "boolean" in output.lower() or "type" in output.lower(), (
            f"Error should mention type mismatch. Output: {output}"
        )

    def test_persona_with_wrong_mappings_type_fails_validation(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that persona with non-object mappings fails validation.

        Given: A persona with mappings as array instead of object
        When: Schema validation is performed
        Then: Validation fails with type error
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaDataProvider
    title: Data Provider
    description:
      - Test persona
    mappings:
      - "invalid"
      - "should be object"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Non-object mappings should fail validation"
        output = result.stdout + result.stderr
        assert "object" in output.lower() or "type" in output.lower(), (
            f"Error should mention type mismatch. Output: {output}"
        )

    def test_persona_with_non_string_array_responsibilities_fails_validation(
        self, tmp_path, personas_schema_path, base_uri
    ):
        """
        Test that persona with non-string responsibilities fails validation.

        Given: A persona with responsibilities containing non-string values
        When: Schema validation is performed
        Then: Validation fails with type error
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaGovernance
    title: Governance
    description:
      - Test persona
    responsibilities:
      - 123
      - 456
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Non-string responsibilities should fail validation"
        output = result.stdout + result.stderr
        assert "string" in output.lower() or "type" in output.lower(), (
            f"Error should mention expected string type. Output: {output}"
        )


# ============================================================================
# Phase-2 strict-flip tests — iso-22989 pinned vs legacy
# ============================================================================


class TestPersonaMappingsStrictFlip:
    """
    Tests for the strict persona mappings block (#343 ADR-027 D3a/D7).

    iso-22989 values in persona mappings must use the pinned @2022 oneOf enum.
    Bare values ("AI Producer", "Data supplier") are rejected by the strict schema.
    """

    def test_persona_bare_iso_value_rejected(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that a bare iso-22989 value (without @2022) is rejected.

        Given: A persona with iso-22989: ["AI Producer"] (no version token)
        When: Schema validation is performed
        Then: Validation fails (non-zero exit)

        The pinned iso-22989 oneOf enum requires the @2022 suffix per ADR-027 D7/D8.
        The loose catch-all that formerly allowed this value has been removed (#343).
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaModelProvider
    title: Model Provider
    description:
      - Organizations that provide AI models
    mappings:
      iso-22989:
        - "AI Producer"
    identificationQuestions:
      - "Do you supply or license AI models to other organizations?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, (
            "Bare iso-22989 value 'AI Producer' (without @2022) must be REJECTED "
            "by the strict persona schema (ADR-027 D7/D8, #343). "
            "The loose catch-all that formerly accepted this value has been removed."
        )

    def test_persona_pinned_iso_value_accepted(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that a pinned iso-22989 value (with @2022 suffix) is accepted.

        Given: A persona with iso-22989: ["AI Producer@2022"]
        When: Schema validation is performed
        Then: Validation passes

        The pinned oneOf enum for iso-22989 accepts the six @2022 members per
        ADR-027 D7/D8. iso-22989 is now wired to framework-mapping-patterns-pinned
        as a consumer $ref target (#343).
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaModelProvider
    title: Model Provider
    description:
      - Organizations that provide AI models
    mappings:
      iso-22989:
        - "AI Producer@2022"
    identificationQuestions:
      - "Do you supply or license AI models to other organizations?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Pinned iso-22989 value 'AI Producer@2022' must be ACCEPTED "
            f"by the strict Phase-2 persona schema (ADR-027 D7/D8, #343). "
            f"Error: {result.stderr}"
        )

    def test_persona_unknown_framework_key_rejected(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that an unknown framework key in persona mappings is rejected.

        Given: A persona with mappings containing made-up-framework key
        When: Schema validation is performed
        Then: Validation fails (propertyNames + additionalProperties:false)

        propertyNames rejects the unknown key; additionalProperties:false provides
        defense-in-depth (#343).
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaModelProvider
    title: Model Provider
    description:
      - Organizations that provide AI models
    mappings:
      made-up-framework:
        - "some-value"
    identificationQuestions:
      - "Do you supply or license AI models to other organizations?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, (
            "Unknown framework key 'made-up-framework' in persona mappings must be REJECTED "
            "(propertyNames constraint)"
        )


# ============================================================================
# Edge Case Tests
# ============================================================================


class TestPersonaEdgeCases:
    """Test edge cases for persona schema validation."""

    def test_persona_with_empty_mappings_object_passes_validation(self, tmp_path, personas_schema_path, base_uri):
        """
        Test that persona with empty mappings object validates.

        Given: A persona with mappings: {}
        When: Schema validation is performed
        Then: Validation passes
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaPlatformProvider
    title: Platform Provider
    description:
      - Test persona
    mappings: {}
    identificationQuestions:
      - "Do you operate the compute or serving infrastructure on which AI models run?"
      - "Are you responsible for platform-level security controls for AI workloads?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Empty mappings object should validate. Error: {result.stderr}"

    def test_persona_with_empty_responsibilities_array_passes_validation(
        self, tmp_path, personas_schema_path, base_uri
    ):
        """
        Test that persona with empty responsibilities array validates.

        Given: A persona with responsibilities: []
        When: Schema validation is performed
        Then: Validation passes
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaAgenticProvider
    title: Agentic Provider
    description:
      - Test persona
    responsibilities: []
    identificationQuestions:
      - "Do you build or operate autonomous AI agents that act on behalf of users?"
      - "Are you responsible for orchestrating multi-step AI workflows or pipelines?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Empty responsibilities array should validate. Error: {result.stderr}"

    def test_multiple_personas_with_mixed_optional_fields(self, tmp_path, personas_schema_path, base_uri):
        """
        Test multiple personas with different combinations of optional fields.

        Given: Multiple personas with varied optional field combinations; the persona
               that includes mappings uses a pinned iso-22989 value (with @2022)
        When: Schema validation is performed
        Then: All personas validate successfully

        Uses pinned iso-22989 per ADR-027 D7/D8; the strict pinned oneOf enum
        rejects bare "AI Producer" and requires the @2022 suffix (#343).
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaModelProvider
    title: Model Provider
    description:
      - Provider with mappings only
    mappings:
      iso-22989:
        - "AI Producer@2022"
    identificationQuestions:
      - "Do you supply or license AI models to other organizations?"

  - id: personaDataProvider
    title: Data Provider
    description:
      - Provider with responsibilities only
    responsibilities:
      - "Provide data"
    identificationQuestions:
      - "Do you collect or curate datasets used to train AI systems?"

  - id: personaPlatformProvider
    title: Platform Provider
    description:
      - Provider with questions only
    identificationQuestions:
      - "Do you operate the infrastructure on which AI models are served?"

  - id: personaModelCreator
    title: Model Creator (Legacy)
    description:
      - Legacy persona marked as deprecated
    deprecated: true
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Multiple personas with mixed fields should validate. Error: {result.stderr}"
        )


# ============================================================================
# Conditional identificationQuestions requirement (ADR-021 D8)
# ============================================================================


class TestIdentificationQuestionsConditionalRequirement:
    """
    Schema constraint tests for the if/then conditional requirement on
    identificationQuestions (ADR-021 D8).

    Non-deprecated personas must supply identificationQuestions.  Deprecated
    personas (personaModelCreator / personaModelConsumer) are exempt so that
    their existing minimal entries remain valid.

    The constraint must be expressed as JSON Schema if/then at the
    definitions.persona level — NOT as a flat addition to required[] — because
    a flat required addition would wrongly reject the two legitimately-deprecated
    empty personas.
    """

    def test_non_deprecated_persona_without_identification_questions_is_rejected(
        self, tmp_path, personas_schema_path, base_uri
    ):
        """
        Test that a non-deprecated persona missing identificationQuestions fails validation.

        Given: A persona with id/title/description but no deprecated flag and
               no identificationQuestions field
        When:  Schema validation is run with check-jsonschema
        Then:  Validation fails (non-zero exit)

        This is the primary constraint introduced by ADR-021 D8: active personas
        must declare identification questions so framework consumers can determine
        which persona applies to their context.
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaEndUser
    title: End User
    description:
      - End users of AI-powered systems
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, (
            "Non-deprecated persona without identificationQuestions must fail validation "
            "(ADR-021 D8 requires the if/then conditional constraint); "
            "schema currently lacks this constraint."
        )

    def test_deprecated_persona_without_identification_questions_is_accepted(
        self, tmp_path, personas_schema_path, base_uri
    ):
        """
        Test that a deprecated persona without identificationQuestions passes validation.

        Given: A persona with deprecated: true and no identificationQuestions field
        When:  Schema validation is run with check-jsonschema
        Then:  Validation passes (zero exit)

        The if/then constraint must be conditional on the absence of deprecated: true
        so that personaModelCreator and personaModelConsumer (which carry
        deprecated: true and no identification questions) remain valid.
        A flat required[] addition would break these entries.
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaModelCreator
    title: Model Creator
    description:
      - Legacy persona superseded by personaModelProvider
    deprecated: true
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            "Deprecated persona without identificationQuestions must pass validation; "
            "the constraint must be conditional (if/then), not a flat required[]. "
            f"Error output:\n{result.stderr}"
        )

    def test_non_deprecated_persona_with_identification_questions_is_accepted(
        self, tmp_path, personas_schema_path, base_uri
    ):
        """
        Test that a non-deprecated persona with identificationQuestions passes validation.

        Given: A persona with id/title/description and a valid identificationQuestions array
        When:  Schema validation is run with check-jsonschema
        Then:  Validation passes (zero exit)

        Confirms the happy path: once the if/then constraint is present, a well-formed
        active persona that includes identificationQuestions must still validate cleanly.
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaEndUser
    title: End User
    description:
      - End users of AI-powered systems
    identificationQuestions:
      - "Do you directly interact with AI-powered applications as a consumer?"
      - "Are you a primary recipient of AI-generated outputs rather than a developer or operator?"
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            "Non-deprecated persona with identificationQuestions must pass validation. "
            f"Error output:\n{result.stderr}"
        )

    def test_non_deprecated_persona_model_provider_without_identification_questions_is_rejected(
        self, tmp_path, personas_schema_path, base_uri
    ):
        """
        Test that the D8 constraint applies to personaModelProvider, not only personaEndUser.

        Given: A personaModelProvider with id/title/description but no deprecated flag
               and no identificationQuestions field
        When:  Schema validation is run with check-jsonschema
        Then:  Validation fails (non-zero exit)

        This guards against a regression where the if/then constraint is narrowed
        to a specific persona id rather than applying generally to all non-deprecated
        personas (ADR-021 D8).
        """
        yaml_content = """
title: Test Personas
description:
  - Test personas for validation
personas:
  - id: personaModelProvider
    title: Model Provider
    description:
      - Organizations that supply AI models to consumers
"""
        yaml_file = tmp_path / "personas.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(personas_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, (
            "Non-deprecated personaModelProvider without identificationQuestions must fail validation "
            "(ADR-021 D8 constraint must be general, not limited to personaEndUser)."
        )


# ============================================================================
# Test Summary
# ============================================================================

"""
Test Summary
============
Total Tests: 27

Schema Structure Tests - Persona ID Enum (4):
- Persona ID enum exists in schema
- Enum contains all 7 new persona IDs
- Enum contains 2 legacy persona IDs
- Enum has at least 9 values (minimum check)

Schema Structure Tests - Optional Fields (8):
- deprecated field exists and is boolean type
- deprecated field is optional
- mappings field exists and is object type
- mappings field has array values (string arrays)
- mappings field is optional
- responsibilities field exists and is array of strings
- responsibilities field is optional
- identificationQuestions field exists and is array of strings
- identificationQuestions field is optional

Backward Compatibility Tests (2):
- Existing personas.yaml still validates
- Legacy persona without optional fields validates

Valid Configuration Tests (6):
- New persona ID validates
- Persona with deprecated field validates
- Persona with mappings validates
- Persona with responsibilities validates
- Persona with identificationQuestions validates
- Persona with all optional fields validates

Invalid Configuration Tests (4):
- Persona with invalid ID fails
- Persona with wrong deprecated type fails
- Persona with wrong mappings type fails
- Persona with non-string responsibilities fails

Edge Case Tests (3):
- Persona with empty mappings object validates
- Persona with empty responsibilities array validates
- Multiple personas with mixed optional fields validate

Coverage Areas:
- New persona ID enum values (7 new + 2 legacy)
- Optional field definitions and types
- Backward compatibility with existing data
- Valid persona configurations
- Invalid persona configurations
- Edge cases and empty values
"""
