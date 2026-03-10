#!/usr/bin/env python3
"""
Tests for personas.schema.json schema updates

This module tests the expanded persona schema supporting 8 CoSAI personas with:
- New persona ID enum values (8 new + 2 legacy personas)
- Optional fields: deprecated, mappings, responsibilities, identificationQuestions
- Backward compatibility with existing personas.yaml

Tests cover:
- Schema validation for new persona IDs
- Optional field validation and structure
- Backward compatibility with legacy persona entries
- Valid and invalid persona configurations
- Edge cases and error conditions
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

    def test_mappings_field_has_array_values(self, personas_schema_path):
        """
        Test that mappings object contains arrays of strings.

        Given: personas.schema.json mappings definition
        When: additionalProperties are examined
        Then: Values are defined as arrays of strings
        """
        with open(personas_schema_path) as f:
            schema = json.load(f)

        mappings_def = schema["definitions"]["persona"]["properties"]["mappings"]

        assert "additionalProperties" in mappings_def, "mappings must define additionalProperties"
        additional_props = mappings_def["additionalProperties"]
        assert additional_props["type"] == "array", "mapping values must be arrays"
        assert additional_props["items"]["type"] == "string", "mapping array items must be strings"

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

    def test_legacy_persona_without_optional_fields_passes_validation(
        self, tmp_path, personas_schema_path, base_uri
    ):
        """
        Test that persona with only required fields validates.

        Given: A persona with only id, title, description (no optional fields)
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
      - Organizations that train and tune models
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

        assert result.returncode == 0, f"Legacy persona should validate. Error: {result.stderr}"


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
        Test that persona with framework mappings validates.

        Given: A persona with mappings to external frameworks
        When: Schema validation is performed
        Then: Validation passes
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
        - "Data supplier"
        - "Data provider"
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
        Test that persona with all optional fields validates.

        Given: A persona with deprecated, mappings, responsibilities, identificationQuestions
        When: Schema validation is performed
        Then: Validation passes
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
        - "AI system developer"
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

        Given: Multiple personas with varied optional field combinations
        When: Schema validation is performed
        Then: All personas validate successfully
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
        - "Model provider"

  - id: personaDataProvider
    title: Data Provider
    description:
      - Provider with responsibilities only
    responsibilities:
      - "Provide data"

  - id: personaPlatformProvider
    title: Platform Provider
    description:
      - Provider with no optional fields

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
