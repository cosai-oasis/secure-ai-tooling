#!/usr/bin/env python3
"""
Tests for frameworks.schema.json applicableTo field validation.

This module tests the applicableTo field that enables dynamic framework filtering
in templates. The applicableTo field specifies which entity types a framework can
be applied to (controls, risks, components, personas).

Tests cover:
- Schema structure validation for applicableTo field
- Required field validation
- Array type and minItems constraints
- Enum validation for entity types
- Valid and invalid applicableTo configurations
- Edge cases (all types, single type, duplicates)
- Integration with actual frameworks.yaml data
"""

import json
import subprocess
import sys
from pathlib import Path

# Add parent directory to path for test utilities
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# Schema Structure Tests
# ============================================================================


class TestFrameworkIdEnumUpdates:
    """Test that framework ID enum includes iso-22989 for persona mappings."""

    def test_framework_id_enum_includes_iso_22989(self, frameworks_schema_path):
        """
        Test that framework ID enum includes iso-22989.

        Given: frameworks.schema.json framework definition
        When: ID enum values are examined
        Then: iso-22989 is included in the enum
        """
        with open(frameworks_schema_path) as f:
            schema = json.load(f)

        id_enum = schema["definitions"]["framework"]["properties"]["id"]["enum"]

        assert "iso-22989" in id_enum, "iso-22989 must be in framework ID enum for persona mappings"

    def test_iso_22989_framework_validates(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test that iso-22989 framework definition validates.

        Given: A framework with id: iso-22989
        When: Schema validation is performed
        Then: Validation passes
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: iso-22989
    name: ISO/IEC 22989
    fullName: ISO/IEC 22989 Artificial Intelligence Concepts and Terminology
    description: International standard for AI concepts and terminology
    baseUri: https://www.iso.org/standard/74296.html
    applicableTo:
      - personas
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(frameworks_schema_path),
                str(yaml_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"iso-22989 framework should validate. Error: {result.stderr}"


class TestApplicableToSchemaStructure:
    """Test that applicableTo field exists and has correct schema structure."""

    def test_applicable_to_field_exists_in_schema(self, frameworks_schema_path):
        """
        Test that applicableTo field is defined in framework schema.

        Given: frameworks.schema.json file
        When: Schema is loaded and parsed
        Then: Framework definition includes applicableTo property
        """
        assert frameworks_schema_path.exists(), "frameworks.schema.json must exist"

        with open(frameworks_schema_path) as f:
            schema = json.load(f)

        framework_def = schema["definitions"]["framework"]
        properties = framework_def["properties"]

        assert "applicableTo" in properties, "applicableTo field must be defined in framework schema"

    def test_applicable_to_is_array_type(self, frameworks_schema_path):
        """
        Test that applicableTo is defined as array type.

        Given: frameworks.schema.json framework definition
        When: applicableTo property is examined
        Then: Property type is "array"
        """
        with open(frameworks_schema_path) as f:
            schema = json.load(f)

        applicable_to_def = schema["definitions"]["framework"]["properties"]["applicableTo"]

        assert applicable_to_def["type"] == "array", "applicableTo must be array type"

    def test_applicable_to_items_are_strings(self, frameworks_schema_path):
        """
        Test that applicableTo array items are strings.

        Given: frameworks.schema.json applicableTo definition
        When: items schema is examined
        Then: Items are defined as string type
        """
        with open(frameworks_schema_path) as f:
            schema = json.load(f)

        applicable_to_def = schema["definitions"]["framework"]["properties"]["applicableTo"]
        items_def = applicable_to_def["items"]

        assert items_def["type"] == "string", "applicableTo items must be strings"

    def test_applicable_to_has_enum_constraint(self, frameworks_schema_path):
        """
        Test that applicableTo items have enum constraint.

        Given: frameworks.schema.json applicableTo items definition
        When: items schema is examined
        Then: Enum constraint is defined with valid entity types
        """
        with open(frameworks_schema_path) as f:
            schema = json.load(f)

        items_def = schema["definitions"]["framework"]["properties"]["applicableTo"]["items"]

        assert "enum" in items_def, "applicableTo items must have enum constraint"

    def test_applicable_to_enum_contains_expected_values(self, frameworks_schema_path):
        """
        Test that applicableTo enum includes all expected entity types.

        Given: frameworks.schema.json applicableTo enum definition
        When: Enum values are examined
        Then: Contains ["controls", "risks", "components", "personas"]
        """
        with open(frameworks_schema_path) as f:
            schema = json.load(f)

        items_def = schema["definitions"]["framework"]["properties"]["applicableTo"]["items"]
        enum_values = items_def["enum"]

        expected_values = {"controls", "risks", "components", "personas"}
        actual_values = set(enum_values)

        assert actual_values == expected_values, (
            f"applicableTo enum must contain exactly {expected_values}, got {actual_values}"
        )

    def test_applicable_to_has_min_items_constraint(self, frameworks_schema_path):
        """
        Test that applicableTo has minItems constraint.

        Given: frameworks.schema.json applicableTo definition
        When: Schema constraints are examined
        Then: minItems is set to 1
        """
        with open(frameworks_schema_path) as f:
            schema = json.load(f)

        applicable_to_def = schema["definitions"]["framework"]["properties"]["applicableTo"]

        assert "minItems" in applicable_to_def, "applicableTo must have minItems constraint"
        assert applicable_to_def["minItems"] == 1, "applicableTo minItems must be 1"

    def test_applicable_to_is_required_field(self, frameworks_schema_path):
        """
        Test that applicableTo is a required field.

        Given: frameworks.schema.json framework definition
        When: Required fields are examined
        Then: applicableTo is in the required array
        """
        with open(frameworks_schema_path) as f:
            schema = json.load(f)

        framework_def = schema["definitions"]["framework"]
        required_fields = framework_def.get("required", [])

        assert "applicableTo" in required_fields, "applicableTo must be a required field"


# ============================================================================
# Schema Validation Tests - Valid Cases
# ============================================================================


class TestApplicableToValidCases:
    """Test that valid applicableTo configurations pass schema validation."""

    def test_framework_with_controls_and_risks_passes_validation(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test framework with applicableTo containing controls and risks.

        Given: A framework with applicableTo: ["controls", "risks"]
        When: Schema validation is performed
        Then: Validation passes without errors
        """
        # This matches mitre-atlas expected configuration
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: mitre-atlas
    name: MITRE ATLAS
    fullName: Test Framework
    description: Test framework description
    baseUri: https://example.com
    applicableTo:
      - controls
      - risks
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        # Use check-jsonschema for validation with base URI for $ref resolution
        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Validation should pass. Error: {result.stderr}"

    def test_framework_with_controls_only_passes_validation(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test framework with applicableTo containing only controls.

        Given: A framework with applicableTo: ["controls"]
        When: Schema validation is performed
        Then: Validation passes without errors
        """
        # This matches nist-ai-rmf expected configuration
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: nist-ai-rmf
    name: NIST AI RMF
    fullName: Test Framework
    description: Test framework description
    baseUri: https://example.com
    applicableTo:
      - controls
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Validation should pass. Error: {result.stderr}"

    def test_framework_with_risks_only_passes_validation(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test framework with applicableTo containing only risks.

        Given: A framework with applicableTo: ["risks"]
        When: Schema validation is performed
        Then: Validation passes without errors
        """
        # This matches stride and owasp-top10-llm expected configuration
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: stride
    name: STRIDE
    fullName: Test Framework
    description: Test framework description
    baseUri: https://example.com
    applicableTo:
      - risks
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Validation should pass. Error: {result.stderr}"

    def test_framework_with_all_entity_types_passes_validation(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test framework with all possible entity types.

        Given: A framework with applicableTo: ["controls", "risks", "components", "personas"]
        When: Schema validation is performed
        Then: Validation passes without errors
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: mitre-atlas
    name: Test Framework
    fullName: Test Framework
    description: Framework applicable to all entity types
    baseUri: https://example.com
    applicableTo:
      - controls
      - risks
      - components
      - personas
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Validation should pass. Error: {result.stderr}"

    def test_framework_with_components_passes_validation(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test framework with applicableTo containing components.

        Given: A framework with applicableTo: ["components"]
        When: Schema validation is performed
        Then: Validation passes without errors
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: nist-ai-rmf
    name: Test Framework
    fullName: Test Framework
    description: Framework applicable to components
    baseUri: https://example.com
    applicableTo:
      - components
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Validation should pass. Error: {result.stderr}"

    def test_framework_with_personas_passes_validation(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test framework with applicableTo containing personas.

        Given: A framework with applicableTo: ["personas"]
        When: Schema validation is performed
        Then: Validation passes without errors
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: stride
    name: Test Framework
    fullName: Test Framework
    description: Framework applicable to personas
    baseUri: https://example.com
    applicableTo:
      - personas
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Validation should pass. Error: {result.stderr}"


# ============================================================================
# Schema Validation Tests - Invalid Cases
# ============================================================================


class TestApplicableToInvalidCases:
    """Test that invalid applicableTo configurations fail schema validation."""

    def test_framework_without_applicable_to_fails_validation(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test that framework without applicableTo fails validation.

        Given: A framework definition without applicableTo field
        When: Schema validation is performed
        Then: Validation fails with required field error
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: mitre-atlas
    name: Test Framework
    fullName: Test Framework
    description: Framework missing applicableTo
    baseUri: https://example.com
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Validation should fail when applicableTo is missing"
        output = result.stdout + result.stderr
        assert "applicableTo" in output or "required" in output.lower(), (
            f"Error should mention missing required field applicableTo. Output: {output}"
        )

    def test_framework_with_empty_applicable_to_fails_validation(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test that framework with empty applicableTo array fails validation.

        Given: A framework with applicableTo: []
        When: Schema validation is performed
        Then: Validation fails with minItems constraint violation
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: mitre-atlas
    name: Test Framework
    fullName: Test Framework
    description: Framework with empty applicableTo
    baseUri: https://example.com
    applicableTo: []
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Validation should fail when applicableTo is empty"
        output = result.stdout + result.stderr
        assert "non-empty" in output.lower() or "minItems" in output or "too short" in output.lower(), (
            f"Error should mention minItems constraint violation. Output: {output}"
        )

    def test_framework_with_invalid_entity_type_fails_validation(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test that framework with invalid entity type fails validation.

        Given: A framework with applicableTo: ["invalid-type"]
        When: Schema validation is performed
        Then: Validation fails with enum constraint violation
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: mitre-atlas
    name: Test Framework
    fullName: Test Framework
    description: Framework with invalid entity type
    baseUri: https://example.com
    applicableTo:
      - invalid-type
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Validation should fail with invalid entity type"
        output = result.stdout + result.stderr
        assert "enum" in output.lower() or "invalid-type" in output, (
            f"Error should mention enum constraint violation or invalid value. Output: {output}"
        )

    def test_framework_with_multiple_invalid_types_fails_validation(
        self, tmp_path, frameworks_schema_path, base_uri
    ):
        """
        Test that framework with multiple invalid types fails validation.

        Given: A framework with applicableTo: ["valid-control", "bad-type"]
        When: Schema validation is performed
        Then: Validation fails with enum constraint violation
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: mitre-atlas
    name: Test Framework
    fullName: Test Framework
    description: Framework with mixed valid and invalid types
    baseUri: https://example.com
    applicableTo:
      - controls
      - bad-type
      - risks
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Validation should fail with any invalid entity type"
        output = result.stdout + result.stderr
        assert "bad-type" in output or "enum" in output.lower(), (
            f"Error should mention the invalid value. Output: {output}"
        )

    def test_framework_with_non_array_applicable_to_fails_validation(
        self, tmp_path, frameworks_schema_path, base_uri
    ):
        """
        Test that framework with non-array applicableTo fails validation.

        Given: A framework with applicableTo as a string instead of array
        When: Schema validation is performed
        Then: Validation fails with type error
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: mitre-atlas
    name: Test Framework
    fullName: Test Framework
    description: Framework with string applicableTo
    baseUri: https://example.com
    applicableTo: controls
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Validation should fail when applicableTo is not an array"
        output = result.stdout + result.stderr
        assert "array" in output.lower() or "type" in output.lower(), (
            f"Error should mention type mismatch. Output: {output}"
        )

    def test_framework_with_numeric_applicable_to_fails_validation(
        self, tmp_path, frameworks_schema_path, base_uri
    ):
        """
        Test that framework with numeric items in applicableTo fails validation.

        Given: A framework with applicableTo: [1, 2, 3]
        When: Schema validation is performed
        Then: Validation fails with type error
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: mitre-atlas
    name: Test Framework
    fullName: Test Framework
    description: Framework with numeric applicableTo
    baseUri: https://example.com
    applicableTo:
      - 1
      - 2
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Validation should fail with numeric values"
        output = result.stdout + result.stderr
        assert "string" in output.lower() or "type" in output.lower(), (
            f"Error should mention expected string type. Output: {output}"
        )


# ============================================================================
# Edge Case Tests
# ============================================================================


class TestApplicableToEdgeCases:
    """Test edge cases for applicableTo field validation."""

    def test_framework_with_duplicate_entity_types(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test framework with duplicate entity types in applicableTo.

        Given: A framework with applicableTo: ["controls", "controls"]
        When: Schema validation is performed
        Then: Validation behavior is documented (may pass or fail based on uniqueItems)

        Note: This test documents current behavior. If uniqueItems constraint is added
        to schema later, this test should be updated to expect failure.
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: owasp-top10-llm
    name: Test Framework
    fullName: Test Framework
    description: Framework with duplicate types
    baseUri: https://example.com
    applicableTo:
      - controls
      - controls
      - risks
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        # Document current behavior - duplicates may be allowed without uniqueItems constraint
        # This test will need updating if uniqueItems is added to schema
        if result.returncode == 0:
            # Currently allowed - duplicates are valid without uniqueItems constraint
            assert True, "Duplicates are currently allowed (no uniqueItems constraint)"
        else:
            # If uniqueItems constraint exists, verify error message
            assert "unique" in result.stderr.lower(), "Error should mention uniqueness violation"

    def test_framework_with_case_sensitive_entity_types_fails(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test that entity types are case-sensitive.

        Given: A framework with applicableTo: ["Controls", "Risks"] (capitalized)
        When: Schema validation is performed
        Then: Validation fails as enum values are case-sensitive
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: mitre-atlas
    name: Test Framework
    fullName: Test Framework
    description: Framework with capitalized types
    baseUri: https://example.com
    applicableTo:
      - Controls
      - Risks
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, "Validation should fail with capitalized entity types"
        output = result.stdout + result.stderr
        assert "Controls" in output or "Risks" in output or "enum" in output.lower(), (
            f"Error should mention invalid capitalized values. Output: {output}"
        )

    def test_multiple_frameworks_with_different_applicable_to(self, tmp_path, frameworks_schema_path, base_uri):
        """
        Test multiple frameworks with different applicableTo configurations.

        Given: Multiple frameworks with varied applicableTo arrays
        When: Schema validation is performed
        Then: All valid configurations pass validation
        """
        yaml_content = """
title: Test Frameworks
description:
  - Test frameworks for validation
frameworks:
  - id: mitre-atlas
    name: Framework 1
    fullName: Framework 1
    description: Controls and risks
    baseUri: https://example1.com
    applicableTo:
      - controls
      - risks

  - id: nist-ai-rmf
    name: Framework 2
    fullName: Framework 2
    description: Risks only
    baseUri: https://example2.com
    applicableTo:
      - risks

  - id: stride
    name: Framework 3
    fullName: Framework 3
    description: All types
    baseUri: https://example3.com
    applicableTo:
      - controls
      - risks
      - components
      - personas
"""
        yaml_file = tmp_path / "frameworks.yaml"
        yaml_file.write_text(yaml_content)

        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Multiple valid frameworks should pass. Error: {result.stderr}"


# ============================================================================
# Integration Tests with Actual Data
# ============================================================================


class TestApplicableToIntegration:
    """Integration tests validating actual frameworks.yaml with applicableTo field."""

    def test_actual_frameworks_yaml_structure_is_loadable(self, frameworks_yaml_path):
        """
        Test that actual frameworks.yaml can be loaded.

        Given: The actual frameworks.yaml file
        When: File is loaded
        Then: File loads successfully without parse errors
        """
        import yaml

        yaml_path = frameworks_yaml_path
        assert yaml_path.exists(), "frameworks.yaml must exist"

        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        assert data is not None, "frameworks.yaml should contain valid YAML"
        assert "frameworks" in data, "frameworks.yaml should have frameworks array"

    def test_mitre_atlas_expected_applicable_to_configuration(self, frameworks_yaml_path):
        """
        Test mitre-atlas should have applicableTo: ["controls", "risks"].

        Given: The actual frameworks.yaml file with applicableTo added
        When: mitre-atlas framework is examined
        Then: applicableTo contains ["controls", "risks"]

        Note: This test will fail initially (RED) until applicableTo is added to frameworks.yaml
        """
        import yaml

        yaml_path = frameworks_yaml_path

        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        mitre_atlas = next((fw for fw in data["frameworks"] if fw["id"] == "mitre-atlas"), None)
        assert mitre_atlas is not None, "mitre-atlas framework must exist"

        assert "applicableTo" in mitre_atlas, "mitre-atlas must have applicableTo field"
        assert set(mitre_atlas["applicableTo"]) == {"controls", "risks"}, (
            "mitre-atlas should be applicable to controls and risks"
        )

    def test_nist_ai_rmf_expected_applicable_to_configuration(self, frameworks_yaml_path):
        """
        Test nist-ai-rmf should have applicableTo: ["controls"].

        Given: The actual frameworks.yaml file with applicableTo added
        When: nist-ai-rmf framework is examined
        Then: applicableTo contains ["controls"]

        Note: This test will fail initially (RED) until applicableTo is added to frameworks.yaml
        """
        import yaml

        yaml_path = frameworks_yaml_path

        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        nist_rmf = next((fw for fw in data["frameworks"] if fw["id"] == "nist-ai-rmf"), None)
        assert nist_rmf is not None, "nist-ai-rmf framework must exist"

        assert "applicableTo" in nist_rmf, "nist-ai-rmf must have applicableTo field"
        assert nist_rmf["applicableTo"] == ["controls"], "nist-ai-rmf should be applicable to controls only"

    def test_stride_expected_applicable_to_configuration(self, frameworks_yaml_path):
        """
        Test stride should have applicableTo: ["risks"].

        Given: The actual frameworks.yaml file with applicableTo added
        When: stride framework is examined
        Then: applicableTo contains ["risks"]

        Note: This test will fail initially (RED) until applicableTo is added to frameworks.yaml
        """
        import yaml

        yaml_path = frameworks_yaml_path

        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        stride = next((fw for fw in data["frameworks"] if fw["id"] == "stride"), None)
        assert stride is not None, "stride framework must exist"

        assert "applicableTo" in stride, "stride must have applicableTo field"
        assert stride["applicableTo"] == ["risks"], "stride should be applicable to risks only"

    def test_owasp_top10_llm_expected_applicable_to_configuration(self, frameworks_yaml_path):
        """
        Test owasp-top10-llm should have applicableTo: ["controls", "risks"].

        Given: The actual frameworks.yaml file with applicableTo added
        When: owasp-top10-llm framework is examined
        Then: applicableTo contains ["controls", "risks"]

        Note: Updated during Phase 2C - owasp-top10-llm applies to both controls and risks
        because 4 controls reference it (controlInputValidationAndSanitization,
        controlOutputValidationAndSanitization, controlApplicationAccessManagement,
        controlAgentPluginPermissions)
        """
        import yaml

        yaml_path = frameworks_yaml_path

        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        owasp = next((fw for fw in data["frameworks"] if fw["id"] == "owasp-top10-llm"), None)
        assert owasp is not None, "owasp-top10-llm framework must exist"

        assert "applicableTo" in owasp, "owasp-top10-llm must have applicableTo field"
        assert set(owasp["applicableTo"]) == {"controls", "risks"}, (
            "owasp-top10-llm should be applicable to controls and risks"
        )

    def test_actual_frameworks_yaml_passes_schema_validation_with_applicable_to(
        self, frameworks_yaml_path, frameworks_schema_path, base_uri
    ):
        """
        Test that actual frameworks.yaml passes schema validation after adding applicableTo.

        Given: The actual frameworks.yaml with applicableTo field added to all frameworks
        When: Schema validation is performed using check-jsonschema
        Then: Validation passes without errors

        Note: This test will fail initially (RED) until applicableTo is added to all frameworks
        """
        yaml_path = frameworks_yaml_path
        schema_path = frameworks_schema_path
        base_uri_str = base_uri

        result = subprocess.run(
            ["check-jsonschema", "--base-uri", base_uri_str, "--schemafile", str(schema_path), str(yaml_path)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Actual frameworks.yaml should pass validation after adding applicableTo.\n"
            f"Error output:\n{result.stderr}"
        )


# ============================================================================
# Test Summary
# ============================================================================

"""
Test Summary
============
Total Tests: 33

Framework ID Enum Tests (2):
- framework ID enum includes iso-22989
- iso-22989 framework definition validates

Schema Structure Tests (7):
- applicableTo field exists in schema
- applicableTo is array type
- applicableTo items are strings
- applicableTo has enum constraint
- applicableTo enum contains expected values
- applicableTo has minItems constraint
- applicableTo is required field

Valid Cases Tests (6):
- Framework with controls and risks
- Framework with controls only
- Framework with risks only
- Framework with all entity types
- Framework with components
- Framework with personas

Invalid Cases Tests (7):
- Framework without applicableTo fails
- Framework with empty applicableTo fails
- Framework with invalid entity type fails
- Framework with multiple invalid types fails
- Framework with non-array applicableTo fails
- Framework with numeric applicableTo fails

Edge Cases Tests (3):
- Framework with duplicate entity types
- Framework with case-sensitive types fails
- Multiple frameworks with different applicableTo

Integration Tests (6):
- Actual frameworks.yaml is loadable
- mitre-atlas expected configuration
- nist-ai-rmf expected configuration
- stride expected configuration
- owasp-top10-llm expected configuration
- Actual frameworks.yaml passes schema validation

Coverage Areas:
- Schema definition completeness
- Required field validation
- Type constraints (array, string)
- Value constraints (enum, minItems)
- Valid applicableTo configurations for all entity types
- Invalid configurations (missing, empty, wrong type, invalid values)
- Edge cases (duplicates, case sensitivity, multiple frameworks)
- Integration with actual frameworks.yaml data
- Real-world framework configurations (mitre-atlas, nist-ai-rmf, stride, owasp-top10-llm)
"""
