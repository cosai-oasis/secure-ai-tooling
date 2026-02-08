"""
Tests for TemplateRenderer class.

This module tests the TemplateRenderer functionality for rendering GitHub issue
templates with placeholder expansion and framework filtering based on applicability.

Test Coverage:
- Template initialization
- Placeholder expansion (categories, personas, controls, risks, etc.)
- Framework filtering by entity type
- YAML formatting preservation
- Integration with production templates
- Error handling and edge cases
"""

from pathlib import Path
from typing import Any

import pytest

# TemplateRenderer import - PYTHONPATH is set to ./scripts/hooks in GitHub Actions
from issue_template_generator.schema_parser import SchemaParser
from issue_template_generator.template_renderer import TemplateRenderer

# ============================================================================
# Pytest Fixtures
# ============================================================================


@pytest.fixture
def sample_frameworks_data() -> dict[str, Any]:
    """
    Provide sample frameworks data for testing.

    Mimics structure from frameworks.yaml with applicableTo fields.
    """
    return {
        "frameworks": [
            {
                "id": "mitre-atlas",
                "name": "MITRE ATLAS",
                "fullName": "Adversarial Threat Landscape for Artificial-Intelligence Systems",
                "baseUri": "https://atlas.mitre.org",
                "applicableTo": ["controls", "risks"],
            },
            {
                "id": "nist-ai-rmf",
                "name": "NIST AI RMF",
                "fullName": "NIST Artificial Intelligence Risk Management Framework",
                "baseUri": "https://www.nist.gov/itl/ai-risk-management-framework",
                "applicableTo": ["controls"],
            },
            {
                "id": "stride",
                "name": "STRIDE",
                "fullName": "STRIDE Threat Model",
                "baseUri": "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats",
                "applicableTo": ["risks"],
            },
            {
                "id": "owasp-top10-llm",
                "name": "OWASP Top 10 for LLM",
                "fullName": "OWASP Top 10 for Large Language Model Applications",
                "baseUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications",
                "applicableTo": ["controls", "risks"],
            },
        ]
    }


@pytest.fixture
def sample_schema_parser(tmp_path: Path) -> SchemaParser:
    """
    Create a SchemaParser with sample schema data for testing.

    Creates temporary schema files with enum values that can be
    used for placeholder expansion.
    """
    import json

    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()

    # Create controls schema
    controls_schema = {
        "$id": "controls.schema.json",
        "definitions": {
            "category": {
                "properties": {"id": {"enum": ["controlsData", "controlsInfrastructure", "controlsModel"]}}
            },
            "control": {"properties": {"id": {"enum": ["control1", "control2", "control3"]}}},
        },
    }

    # Create risks schema
    risks_schema = {
        "$id": "risks.schema.json",
        "definitions": {
            "category": {
                "properties": {
                    "id": {"enum": ["risksSupplyChainAndDevelopment", "risksDeploymentAndInfrastructure"]}
                }
            },
            "risk": {"properties": {"id": {"enum": ["DP", "MST", "PIJ"]}}},
        },
    }

    # Create personas schema
    personas_schema = {
        "$id": "personas.schema.json",
        "definitions": {
            "persona": {"properties": {"id": {"enum": ["personaModelCreator", "personaModelConsumer"]}}}
        },
    }

    # Create components schema
    components_schema = {
        "$id": "components.schema.json",
        "definitions": {
            "component": {
                "properties": {
                    "id": {"enum": ["componentDataSources", "componentTrainingData", "componentModelServing"]}
                }
            }
        },
    }

    # Write schema files
    (schema_dir / "controls.schema.json").write_text(json.dumps(controls_schema))
    (schema_dir / "risks.schema.json").write_text(json.dumps(risks_schema))
    (schema_dir / "personas.schema.json").write_text(json.dumps(personas_schema))
    (schema_dir / "components.schema.json").write_text(json.dumps(components_schema))

    return SchemaParser(schema_dir)


@pytest.fixture
def simple_template_content() -> str:
    """Provide simple template content for basic testing."""
    return """name: Test Template
description: Test description
body:
  - type: dropdown
    id: category
    attributes:
      label: Category
      options:
        {{CONTROL_CATEGORIES}}
"""


@pytest.fixture
def template_with_multiple_placeholders() -> str:
    """Provide template with multiple placeholder types."""
    return """name: Test Template
description: Test
body:
  - type: dropdown
    id: category
    attributes:
      label: Category
      options:
        {{CONTROL_CATEGORIES}}

  - type: checkboxes
    id: personas
    attributes:
      label: Personas
      options:
        {{PERSONAS}}
"""


# ============================================================================
# Test Classes
# ============================================================================


class TestTemplateRendererInit:
    """Test TemplateRenderer initialization."""

    def test_init_with_valid_inputs(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test TemplateRenderer initialization with valid inputs.

        Given: Valid SchemaParser and frameworks data
        When: TemplateRenderer is initialized
        Then: Instance is created successfully
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)

        assert renderer.schema_parser == sample_schema_parser
        assert renderer.frameworks_data == sample_frameworks_data

    def test_init_with_none_schema_parser(self, sample_frameworks_data: dict[str, Any]) -> None:
        """
        Test initialization with None schema_parser.

        Given: None as schema_parser
        When: TemplateRenderer is initialized
        Then: Raises TypeError
        """
        with pytest.raises(TypeError, match="schema_parser.*required|cannot be None"):
            TemplateRenderer(None, sample_frameworks_data)

    def test_init_with_none_frameworks_data(self, sample_schema_parser: SchemaParser) -> None:
        """
        Test initialization with None frameworks_data.

        Given: None as frameworks_data
        When: TemplateRenderer is initialized
        Then: Raises TypeError
        """
        with pytest.raises(TypeError, match="frameworks_data.*required|cannot be None"):
            TemplateRenderer(sample_schema_parser, None)

    def test_init_with_invalid_frameworks_data_structure(self, sample_schema_parser: SchemaParser) -> None:
        """
        Test initialization with invalid frameworks data structure.

        Given: frameworks_data without 'frameworks' key
        When: TemplateRenderer is initialized
        Then: Raises ValueError or KeyError
        """
        invalid_data = {"some_key": "some_value"}

        with pytest.raises((ValueError, KeyError), match="frameworks|invalid structure"):
            TemplateRenderer(sample_schema_parser, invalid_data)


class TestExpandPlaceholders:
    """Test expand_placeholders() method."""

    def test_expand_control_categories_placeholder(
        self,
        sample_schema_parser: SchemaParser,
        sample_frameworks_data: dict[str, Any],
        simple_template_content: str,
    ) -> None:
        """
        Test expanding CONTROL_CATEGORIES placeholder.

        Given: Template with {{CONTROL_CATEGORIES}} placeholder
        When: expand_placeholders() is called with entity_type="controls"
        Then: Placeholder is replaced with plain string enum values (dropdown format)
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(simple_template_content, "controls")

        assert "{{CONTROL_CATEGORIES}}" not in result
        # Dropdown format: plain strings, no label/value objects
        assert "- controlsData" in result
        assert "- controlsInfrastructure" in result
        assert "- controlsModel" in result
        # Should NOT have label/value format in options (check that options are plain strings)
        # Note: template itself contains "label: Category" which is the field label, not option format
        assert "- label: controlsData" not in result  # Options should be plain strings, not objects
        assert "value: controlsData" not in result  # Options should not have value field

    def test_expand_risk_categories_placeholder(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expanding RISK_CATEGORIES placeholder.

        Given: Template with {{RISK_CATEGORIES}} placeholder
        When: expand_placeholders() is called with entity_type="risks"
        Then: Placeholder is replaced with plain string enum values (dropdown format)
        """
        template = """options:
        {{RISK_CATEGORIES}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "risks")

        assert "{{RISK_CATEGORIES}}" not in result
        # Dropdown format: plain strings, no label/value objects
        assert "- risksSupplyChainAndDevelopment" in result
        assert "- risksDeploymentAndInfrastructure" in result
        # Should NOT have label/value format
        assert "label:" not in result
        assert "value:" not in result

    def test_expand_personas_placeholder(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expanding PERSONAS placeholder.

        Given: Template with {{PERSONAS}} placeholder
        When: expand_placeholders() is called
        Then: Placeholder is replaced with label-only objects (checkbox format)
        """
        template = """options:
        {{PERSONAS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        assert "{{PERSONAS}}" not in result
        # Checkbox format: label only, no value field
        assert "- label: personaModelCreator" in result
        assert "- label: personaModelConsumer" in result
        # Should NOT have value field
        assert "value:" not in result

    def test_expand_components_placeholder(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expanding COMPONENTS placeholder.

        Given: Template with {{COMPONENTS}} placeholder
        When: expand_placeholders() is called
        Then: Placeholder is replaced with component IDs
        """
        template = """Common components: {{COMPONENTS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        assert "{{COMPONENTS}}" not in result
        assert "componentDataSources" in result
        assert "componentTrainingData" in result

    def test_expand_multiple_placeholders(
        self,
        sample_schema_parser: SchemaParser,
        sample_frameworks_data: dict[str, Any],
        template_with_multiple_placeholders: str,
    ) -> None:
        """
        Test expanding multiple placeholders in same template.

        Given: Template with multiple different placeholders (dropdown + checkbox)
        When: expand_placeholders() is called
        Then: All placeholders are replaced with correct field-type-aware formats
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template_with_multiple_placeholders, "controls")

        assert "{{CONTROL_CATEGORIES}}" not in result
        assert "{{PERSONAS}}" not in result

        # CONTROL_CATEGORIES should be dropdown format (plain strings)
        assert "- controlsData" in result
        # PERSONAS should be checkbox format (label only)
        assert "- label: personaModelCreator" in result

        # Verify mixed formats coexist correctly
        lines = result.split("\n")
        dropdown_lines = [line for line in lines if line.strip().startswith("- controls")]
        checkbox_lines = [line for line in lines if "- label: persona" in line]

        assert len(dropdown_lines) > 0, "Should have dropdown format lines"
        assert len(checkbox_lines) > 0, "Should have checkbox format lines"

    def test_expand_placeholder_preserves_indentation(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that placeholder expansion preserves YAML indentation.

        Given: Template with indented placeholder
        When: expand_placeholders() is called
        Then: Expanded values maintain proper indentation
        """
        template = """    options:
        {{CONTROL_CATEGORIES}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Check that expanded values are properly indented
        lines = result.split("\n")
        # At least one expanded line should have proper indentation
        assert any(line.startswith("        -") for line in lines)

    def test_expand_placeholder_case_insensitive(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test placeholder expansion with different cases.

        Given: Template with lowercase placeholder
        When: expand_placeholders() is called
        Then: Placeholder is still recognized and replaced
        """
        template = """options:
        {{control_categories}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Should handle case-insensitive placeholders
        assert "{{control_categories}}" not in result or "controlsData" in result

    def test_expand_placeholder_with_no_matching_placeholder(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test template with no placeholders.

        Given: Template without any placeholders
        When: expand_placeholders() is called
        Then: Template is returned unchanged
        """
        template = """name: Simple Template
description: No placeholders here"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        assert result == template

    def test_expand_placeholder_with_unknown_placeholder(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test template with unknown placeholder.

        Given: Template with {{UNKNOWN_PLACEHOLDER}}
        When: expand_placeholders() is called
        Then: Unknown placeholder is left as-is or raises warning
        """
        template = """options:
        {{UNKNOWN_PLACEHOLDER}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Unknown placeholders should either remain or be handled gracefully
        assert "{{UNKNOWN_PLACEHOLDER}}" in result or result == template

    def test_expand_placeholder_with_empty_enum(
        self, tmp_path: Path, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test placeholder expansion when enum is empty.

        Given: Schema with empty enum array
        When: expand_placeholders() is called
        Then: Handles empty enum gracefully
        """
        import json

        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()

        schema = {"$id": "test.schema.json", "definitions": {"category": {"properties": {"id": {"enum": []}}}}}

        (schema_dir / "controls.schema.json").write_text(json.dumps(schema))
        parser = SchemaParser(schema_dir)

        template = """options:
        {{CONTROL_CATEGORIES}}"""

        renderer = TemplateRenderer(parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Should handle empty enum without crashing
        assert isinstance(result, str)

    def test_expand_placeholder_with_special_characters_in_values(
        self, tmp_path: Path, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test placeholder expansion with special characters in enum values.

        Given: Enum values containing hyphens, underscores
        When: expand_placeholders() is called
        Then: Special characters are preserved
        """
        import json

        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()

        schema = {
            "$id": "test.schema.json",
            "definitions": {
                "category": {"properties": {"id": {"enum": ["category-one", "category_two", "category.three"]}}}
            },
        }

        (schema_dir / "controls.schema.json").write_text(json.dumps(schema))
        parser = SchemaParser(schema_dir)

        template = """options:
        {{CONTROL_CATEGORIES}}"""

        renderer = TemplateRenderer(parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        assert "category-one" in result
        assert "category_two" in result
        assert "category.three" in result

    def test_expand_placeholder_invalid_entity_type(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test placeholder expansion with invalid entity type.

        Given: Invalid entity_type parameter
        When: expand_placeholders() is called
        Then: Raises ValueError
        """
        template = """options:
        {{CONTROL_CATEGORIES}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)

        with pytest.raises(ValueError, match="Invalid entity type|entity_type"):
            renderer.expand_placeholders(template, "invalid_type")

    def test_expand_placeholder_empty_template(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test placeholder expansion with empty template.

        Given: Empty string as template
        When: expand_placeholders() is called
        Then: Returns empty string
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders("", "controls")

        assert result == ""

    @pytest.mark.parametrize(
        "placeholder,entity_type,expected_values,field_type",
        [
            ("LIFECYCLE_STAGE", "controls", ["planning", "data-preparation", "model-training"], "checkbox"),
            ("IMPACT_TYPE", "controls", ["confidentiality", "integrity", "availability"], "checkbox"),
            ("ACTOR_ACCESS", "controls", ["external", "api", "user"], "checkbox"),
            (
                "COMPONENT_CATEGORIES",
                "components",
                ["componentsInfrastructure", "componentsModel", "componentsApplication"],
                "dropdown",
            ),
        ],
    )
    def test_expand_new_placeholder_types(
        self,
        placeholder: str,
        entity_type: str,
        expected_values: list[str],
        field_type: str,
        risk_map_schemas_dir: Path,
    ) -> None:
        """
        Test expansion of new placeholder types with field-type awareness.

        Given: Template with new placeholder types
        When: expand_placeholders() is called
        Then: Placeholder is replaced with enum values in correct format based on field type
        """
        from issue_template_generator.schema_parser import SchemaParser

        schema_parser = SchemaParser(risk_map_schemas_dir)
        frameworks_data = {"frameworks": []}

        template = f"""options:
        {{{{{placeholder}}}}}"""

        renderer = TemplateRenderer(schema_parser, frameworks_data)
        result = renderer.expand_placeholders(template, entity_type)

        # Placeholder should be removed
        assert f"{{{{{placeholder}}}}}" not in result

        # Expected values should be present
        for expected in expected_values:
            assert expected in result

        # Verify correct format based on field type
        if field_type == "dropdown":
            # Dropdown format: plain strings only
            assert "label:" not in result
            assert "value:" not in result
            for expected in expected_values:
                assert f"- {expected}" in result
        elif field_type == "checkbox":
            # Checkbox format: label only, no value
            assert "label:" in result
            assert "value:" not in result
            for expected in expected_values:
                assert f"- label: {expected}" in result


class TestFieldTypeAwareExpansion:
    """
    Test field-type-aware placeholder expansion.

    These tests verify that placeholders are expanded with the correct format
    based on their field type (dropdown vs checkbox) to match GitHub schema requirements.
    """

    def test_expand_dropdown_placeholder_format(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that dropdown placeholders generate plain string lists.

        Given: Template with CONTROL_CATEGORIES (dropdown type)
        When: expand_placeholders() is called
        Then: Output is plain string list format without label/value objects
        """
        template = """options:
        {{CONTROL_CATEGORIES}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Dropdown format requirements
        expected = """options:
        - controlsData
        - controlsInfrastructure
        - controlsModel"""

        assert result == expected

    def test_expand_checkbox_placeholder_format(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that checkbox placeholders generate label-only objects.

        Given: Template with PERSONAS (checkbox type)
        When: expand_placeholders() is called
        Then: Output is label-only object format without value field
        """
        template = """options:
        {{PERSONAS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Checkbox format requirements
        expected = """options:
        - label: personaModelCreator
        - label: personaModelConsumer"""

        assert result == expected

    def test_expand_dropdown_preserves_indentation(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that dropdown expansion preserves YAML indentation.

        Given: Template with indented CONTROL_CATEGORIES placeholder
        When: expand_placeholders() is called
        Then: Expanded plain strings maintain proper indentation
        """
        template = """body:
  - type: dropdown
    attributes:
      options:
        {{CONTROL_CATEGORIES}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Verify indentation is preserved
        lines = result.split("\n")
        options_lines = [line for line in lines if "- controls" in line]

        for line in options_lines:
            # All dropdown items should have 8 spaces indentation
            assert line.startswith("        - controls"), f"Bad indentation: '{line}'"

    def test_expand_checkbox_preserves_indentation(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that checkbox expansion preserves YAML indentation.

        Given: Template with indented PERSONAS placeholder
        When: expand_placeholders() is called
        Then: Expanded label objects maintain proper indentation
        """
        template = """body:
  - type: checkboxes
    attributes:
      options:
        {{PERSONAS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Verify indentation is preserved
        lines = result.split("\n")
        persona_lines = [line for line in lines if "- label: persona" in line]

        for line in persona_lines:
            # All checkbox items should have 8 spaces indentation
            assert line.startswith("        - label: persona"), f"Bad indentation: '{line}'"

    def test_expand_dropdown_no_quotes(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that dropdown values have no quotes.

        Given: Template with CONTROL_CATEGORIES placeholder
        When: expand_placeholders() is called
        Then: Values are plain strings without quotes
        """
        template = """options:
        {{CONTROL_CATEGORIES}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Should NOT have quotes around values
        assert '"controlsData"' not in result
        assert '"controlsModel"' not in result
        assert '"controlsInfrastructure"' not in result

        # Should have plain values
        assert "- controlsData" in result
        assert "- controlsModel" in result

    def test_expand_checkbox_no_value_field(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that checkbox objects have no value field.

        Given: Template with PERSONAS placeholder
        When: expand_placeholders() is called
        Then: Objects have label field only, no value field
        """
        template = """options:
        {{PERSONAS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Should have label field
        assert "label:" in result
        assert "- label: personaModelCreator" in result

        # Should NOT have value field
        assert "value:" not in result

    def test_expand_mixed_field_types_in_same_template(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test multiple placeholders with different field types in same template.

        Given: Template with both dropdown and checkbox placeholders
        When: expand_placeholders() is called
        Then: Each placeholder expands to correct format based on field type
        """
        template = """body:
  - type: dropdown
    id: category
    attributes:
      options:
        {{CONTROL_CATEGORIES}}

  - type: checkboxes
    id: personas
    attributes:
      options:
        {{PERSONAS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Verify dropdown format (plain strings)
        assert "- controlsData" in result
        assert "- controlsModel" in result

        # Verify checkbox format (label only)
        assert "- label: personaModelCreator" in result
        assert "- label: personaModelConsumer" in result

        # Verify no value fields anywhere
        assert "value:" not in result

    def test_expand_dropdown_with_empty_enum(self, tmp_path: Path, sample_frameworks_data: dict[str, Any]) -> None:
        """
        Test dropdown placeholder expansion when enum is empty.

        Given: Schema with empty enum array
        When: expand_placeholders() is called with dropdown placeholder
        Then: Returns empty string (no list items)
        """
        import json

        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()

        schema = {"$id": "test.schema.json", "definitions": {"category": {"properties": {"id": {"enum": []}}}}}

        (schema_dir / "controls.schema.json").write_text(json.dumps(schema))
        parser = SchemaParser(schema_dir)

        template = """options:
        {{CONTROL_CATEGORIES}}"""

        renderer = TemplateRenderer(parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Empty enum should result in empty string
        expected = "options:\n        "
        assert result == expected

    def test_expand_checkbox_with_single_value(
        self, tmp_path: Path, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test checkbox placeholder expansion with single enum value.

        Given: Schema with single enum value
        When: expand_placeholders() is called with checkbox placeholder
        Then: Generates single label-only object
        """
        import json

        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()

        schema = {
            "$id": "test.schema.json",
            "definitions": {"persona": {"properties": {"id": {"enum": ["personaModelCreator"]}}}},
        }

        (schema_dir / "personas.schema.json").write_text(json.dumps(schema))
        parser = SchemaParser(schema_dir)

        template = """options:
        {{PERSONAS}}"""

        renderer = TemplateRenderer(parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Single value should still be formatted as checkbox
        expected = """options:
        - label: personaModelCreator"""
        assert result == expected

    def test_expand_dropdown_with_special_characters(
        self, tmp_path: Path, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test dropdown placeholder expansion with special characters in values.

        Given: Enum values containing hyphens, underscores
        When: expand_placeholders() is called with dropdown placeholder
        Then: Special characters are preserved without quotes
        """
        import json

        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()

        schema = {
            "$id": "test.schema.json",
            "definitions": {
                "category": {"properties": {"id": {"enum": ["category-one", "category_two", "category.three"]}}}
            },
        }

        (schema_dir / "controls.schema.json").write_text(json.dumps(schema))
        parser = SchemaParser(schema_dir)

        template = """options:
        {{CONTROL_CATEGORIES}}"""

        renderer = TemplateRenderer(parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Special characters should be preserved without quotes
        assert "- category-one" in result
        assert "- category_two" in result
        assert "- category.three" in result

        # Should NOT have quotes
        assert '"category-one"' not in result
        assert '"category_two"' not in result


class TestFilterFrameworksByApplicability:
    """Test filter_frameworks_by_applicability() method."""

    def test_filter_frameworks_for_controls(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test filtering frameworks applicable to controls.

        Given: Frameworks with different applicableTo values
        When: filter_frameworks_by_applicability() is called with "controls"
        Then: Returns only frameworks applicable to controls
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.filter_frameworks_by_applicability("controls")

        assert "mitre-atlas" in result
        assert "nist-ai-rmf" in result
        assert "owasp-top10-llm" in result  # Applicable to both controls and risks
        assert "stride" not in result  # Not applicable to controls

    def test_filter_frameworks_for_risks(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test filtering frameworks applicable to risks.

        Given: Frameworks with different applicableTo values
        When: filter_frameworks_by_applicability() is called with "risks"
        Then: Returns only frameworks applicable to risks
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.filter_frameworks_by_applicability("risks")

        assert "mitre-atlas" in result
        assert "stride" in result
        assert "owasp-top10-llm" in result
        assert "nist-ai-rmf" not in result  # Not applicable to risks

    def test_filter_frameworks_for_components(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test filtering frameworks applicable to components.

        Given: Frameworks without components in applicableTo
        When: filter_frameworks_by_applicability() is called with "components"
        Then: Returns empty list
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.filter_frameworks_by_applicability("components")

        assert result == []

    def test_filter_frameworks_for_personas(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test filtering frameworks applicable to personas.

        Given: Frameworks without personas in applicableTo
        When: filter_frameworks_by_applicability() is called with "personas"
        Then: Returns empty list
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.filter_frameworks_by_applicability("personas")

        assert result == []

    def test_filter_frameworks_invalid_entity_type(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test framework filtering with invalid entity type.

        Given: Invalid entity_type
        When: filter_frameworks_by_applicability() is called
        Then: Raises ValueError
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)

        with pytest.raises(ValueError, match="Invalid entity type|entity_type"):
            renderer.filter_frameworks_by_applicability("invalid_type")

    def test_filter_frameworks_empty_frameworks_data(self, sample_schema_parser: SchemaParser) -> None:
        """
        Test framework filtering with empty frameworks data.

        Given: Empty frameworks list
        When: filter_frameworks_by_applicability() is called
        Then: Returns empty list
        """
        empty_frameworks = {"frameworks": []}
        renderer = TemplateRenderer(sample_schema_parser, empty_frameworks)
        result = renderer.filter_frameworks_by_applicability("controls")

        assert result == []

    def test_filter_frameworks_preserves_order(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that framework filtering preserves original order.

        Given: Frameworks in specific order
        When: filter_frameworks_by_applicability() is called
        Then: Returned frameworks maintain original order
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.filter_frameworks_by_applicability("risks")

        # Should be in order: mitre-atlas, stride, owasp-top10-llm
        assert result.index("mitre-atlas") < result.index("stride")
        assert result.index("stride") < result.index("owasp-top10-llm")


# ============================================================================
# Phase 2 Tests: Framework List Generation and Mappings Expansion
# ============================================================================


class TestGetFrameworksList:
    """
    Test get_frameworks_list() method for comma-separated framework lists.

    This method generates comma-separated lists of framework IDs for use in
    "update" templates (e.g., {{CONTROL_FRAMEWORKS_LIST}}).
    """

    def test_get_frameworks_list_for_controls(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test get_frameworks_list() returns correct frameworks for controls.

        Given: Frameworks with various applicableTo values
        When: get_frameworks_list() is called with entity_type="controls"
        Then: Returns comma-separated string "mitre-atlas, nist-ai-rmf, owasp-top10-llm"
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.get_frameworks_list("controls")

        assert result == "mitre-atlas, nist-ai-rmf, owasp-top10-llm"

    def test_get_frameworks_list_for_risks(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test get_frameworks_list() returns correct frameworks for risks.

        Given: Frameworks with various applicableTo values
        When: get_frameworks_list() is called with entity_type="risks"
        Then: Returns comma-separated string "mitre-atlas, stride, owasp-top10-llm"
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.get_frameworks_list("risks")

        assert result == "mitre-atlas, stride, owasp-top10-llm"

    def test_get_frameworks_list_for_components(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test get_frameworks_list() returns empty string for components.

        Given: No frameworks applicable to components
        When: get_frameworks_list() is called with entity_type="components"
        Then: Returns empty string ""
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.get_frameworks_list("components")

        assert result == ""

    def test_get_frameworks_list_preserves_order(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that get_frameworks_list() preserves framework order from YAML.

        Given: Frameworks in specific order in frameworks.yaml
        When: get_frameworks_list() is called
        Then: Returned string maintains original order
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.get_frameworks_list("controls")

        # mitre-atlas should come before nist-ai-rmf, which comes before owasp-top10-llm
        parts = result.split(", ")
        assert parts.index("mitre-atlas") < parts.index("nist-ai-rmf")
        assert parts.index("nist-ai-rmf") < parts.index("owasp-top10-llm")

    def test_get_frameworks_list_with_single_framework(self, sample_schema_parser: SchemaParser) -> None:
        """
        Test get_frameworks_list() with single applicable framework.

        Given: Only one framework applicable to entity type
        When: get_frameworks_list() is called
        Then: Returns single framework ID without comma
        """
        single_framework_data = {
            "frameworks": [{"id": "nist-ai-rmf", "name": "NIST AI RMF", "applicableTo": ["controls"]}]
        }

        renderer = TemplateRenderer(sample_schema_parser, single_framework_data)
        result = renderer.get_frameworks_list("controls")

        assert result == "nist-ai-rmf"

    def test_get_frameworks_list_empty_frameworks(self, sample_schema_parser: SchemaParser) -> None:
        """
        Test get_frameworks_list() with empty frameworks data.

        Given: Empty frameworks list
        When: get_frameworks_list() is called
        Then: Returns empty string
        """
        empty_frameworks = {"frameworks": []}
        renderer = TemplateRenderer(sample_schema_parser, empty_frameworks)
        result = renderer.get_frameworks_list("controls")

        assert result == ""

    def test_get_frameworks_list_invalid_entity_type(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test get_frameworks_list() with invalid entity type.

        Given: Invalid entity_type parameter
        When: get_frameworks_list() is called
        Then: Raises ValueError
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)

        with pytest.raises(ValueError, match="Invalid entity type"):
            renderer.get_frameworks_list("invalid_type")


class TestExpandFrameworkMappings:
    """
    Test expand_framework_mappings() method for generating framework mapping sections.

    This method generates full YAML textarea sections for frameworks applicable
    to the entity type, used in "new" templates (e.g., {{FRAMEWORK_MAPPINGS}}).
    """

    def test_expand_framework_mappings_for_controls(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expand_framework_mappings() generates sections for controls.

        Given: Frameworks with controls in applicableTo
        When: expand_framework_mappings() is called with entity_type="controls"
        Then: Generates textarea sections for 3 frameworks (mitre-atlas, nist-ai-rmf, owasp-top10-llm)
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_framework_mappings("controls")

        # Should be a list of framework mapping sections
        assert isinstance(result, list)
        assert len(result) == 3

        # Check framework IDs are present
        framework_ids = [section["id"] for section in result]
        assert "mapping-mitre-atlas" in framework_ids
        assert "mapping-nist-ai-rmf" in framework_ids
        assert "mapping-owasp-top10-llm" in framework_ids

    def test_expand_framework_mappings_for_risks(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expand_framework_mappings() generates sections for risks.

        Given: Frameworks with risks in applicableTo
        When: expand_framework_mappings() is called with entity_type="risks"
        Then: Generates textarea sections for 3 frameworks (mitre-atlas, stride, owasp-top10-llm)
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_framework_mappings("risks")

        # Should be a list of framework mapping sections
        assert isinstance(result, list)
        assert len(result) == 3

        # Check framework IDs are present
        framework_ids = [section["id"] for section in result]
        assert "mapping-mitre-atlas" in framework_ids
        assert "mapping-stride" in framework_ids
        assert "mapping-owasp-top10-llm" in framework_ids

    def test_expand_framework_mappings_structure(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expand_framework_mappings() generates correct YAML structure.

        Given: Frameworks applicable to entity type
        When: expand_framework_mappings() is called
        Then: Each section has type=textarea, id=mapping-*, label, description, placeholder
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_framework_mappings("controls")

        for section in result:
            # Check required fields
            assert "type" in section
            assert section["type"] == "textarea"

            assert "id" in section
            assert section["id"].startswith("mapping-")

            assert "attributes" in section
            attributes = section["attributes"]

            assert "label" in attributes
            assert "description" in attributes
            assert "placeholder" in attributes

            # Validations should be present
            assert "validations" in section
            assert "required" in section["validations"]
            assert section["validations"]["required"] is False

    def test_expand_framework_mappings_excludes_inapplicable(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expand_framework_mappings() excludes inapplicable frameworks.

        Given: stride is applicable to risks but NOT controls
        When: expand_framework_mappings() is called with entity_type="controls"
        Then: stride should NOT be included in results
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_framework_mappings("controls")

        # Check stride is NOT included
        framework_ids = [section["id"] for section in result]
        assert "mapping-stride" not in framework_ids

        # But should include nist-ai-rmf
        assert "mapping-nist-ai-rmf" in framework_ids

    def test_expand_framework_mappings_includes_framework_details(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expand_framework_mappings() includes framework name and baseUri in description.

        Given: Frameworks with name and baseUri fields
        When: expand_framework_mappings() is called
        Then: Description includes framework name and baseUri
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_framework_mappings("controls")

        # Find mitre-atlas section
        mitre_section = next(s for s in result if s["id"] == "mapping-mitre-atlas")

        # Check description includes framework details
        description = mitre_section["attributes"]["description"]
        assert "MITRE ATLAS" in description or "mitre-atlas" in description.lower()
        assert "atlas.mitre.org" in description or "https://atlas.mitre.org" in description

    def test_expand_framework_mappings_empty_frameworks(self, sample_schema_parser: SchemaParser) -> None:
        """
        Test expand_framework_mappings() with empty frameworks data.

        Given: Empty frameworks list
        When: expand_framework_mappings() is called
        Then: Returns empty list
        """
        empty_frameworks = {"frameworks": []}
        renderer = TemplateRenderer(sample_schema_parser, empty_frameworks)
        result = renderer.expand_framework_mappings("controls")

        assert result == []

    def test_expand_framework_mappings_preserves_order(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expand_framework_mappings() preserves framework order.

        Given: Frameworks in specific order in YAML
        When: expand_framework_mappings() is called
        Then: Returned sections maintain original order
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_framework_mappings("controls")

        framework_ids = [section["id"] for section in result]

        # Should be in order: mitre-atlas, nist-ai-rmf, owasp-top10-llm
        assert framework_ids.index("mapping-mitre-atlas") < framework_ids.index("mapping-nist-ai-rmf")
        assert framework_ids.index("mapping-nist-ai-rmf") < framework_ids.index("mapping-owasp-top10-llm")

    def test_expand_framework_mappings_invalid_entity_type(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expand_framework_mappings() with invalid entity type.

        Given: Invalid entity_type parameter
        When: expand_framework_mappings() is called
        Then: Raises ValueError
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)

        with pytest.raises(ValueError, match="Invalid entity type"):
            renderer.expand_framework_mappings("invalid_type")


class TestFrameworkPlaceholderExpansion:
    """
    Test placeholder expansion for framework-related placeholders.

    Tests the integration of framework filtering with placeholder expansion
    for {{FRAMEWORK_MAPPINGS}}, {{CONTROL_FRAMEWORKS_LIST}}, {{RISK_FRAMEWORKS_LIST}}.
    """

    def test_expand_framework_mappings_placeholder(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test {{FRAMEWORK_MAPPINGS}} placeholder expansion.

        Given: Template with {{FRAMEWORK_MAPPINGS}} placeholder
        When: expand_placeholders() is called
        Then: Placeholder is replaced with framework mapping sections in YAML format
        """
        template = """body:
  - type: markdown
    attributes:
      value: "## Framework Mappings"

  {{FRAMEWORK_MAPPINGS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Placeholder should be removed
        assert "{{FRAMEWORK_MAPPINGS}}" not in result

        # Should contain framework sections
        assert "mapping-mitre-atlas" in result
        assert "mapping-nist-ai-rmf" in result
        assert "mapping-owasp-top10-llm" in result

        # Should NOT contain stride (not applicable to controls)
        assert "mapping-stride" not in result

    def test_expand_control_frameworks_list_placeholder(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test {{CONTROL_FRAMEWORKS_LIST}} placeholder expansion.

        Given: Template with {{CONTROL_FRAMEWORKS_LIST}} placeholder
        When: expand_placeholders() is called with entity_type="controls"
        Then: Placeholder is replaced with comma-separated framework IDs
        """
        template = """  - type: textarea
    id: mappings
    attributes:
      description: |
        Update mappings to external frameworks: {{CONTROL_FRAMEWORKS_LIST}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Placeholder should be removed
        assert "{{CONTROL_FRAMEWORKS_LIST}}" not in result

        # Should contain comma-separated list
        assert "mitre-atlas, nist-ai-rmf, owasp-top10-llm" in result

    def test_expand_risk_frameworks_list_placeholder(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test {{RISK_FRAMEWORKS_LIST}} placeholder expansion.

        Given: Template with {{RISK_FRAMEWORKS_LIST}} placeholder
        When: expand_placeholders() is called with entity_type="risks"
        Then: Placeholder is replaced with comma-separated framework IDs for risks
        """
        template = """  - type: textarea
    id: mappings
    attributes:
      description: |
        Update mappings to external frameworks: {{RISK_FRAMEWORKS_LIST}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "risks")

        # Placeholder should be removed
        assert "{{RISK_FRAMEWORKS_LIST}}" not in result

        # Should contain comma-separated list for risks
        assert "mitre-atlas, stride, owasp-top10-llm" in result

    def test_framework_mappings_preserves_indentation(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test {{FRAMEWORK_MAPPINGS}} preserves YAML indentation.

        Given: Template with indented {{FRAMEWORK_MAPPINGS}} placeholder
        When: expand_placeholders() is called
        Then: Expanded sections maintain proper YAML indentation
        """
        template = """body:
  - type: markdown
    attributes:
      value: "## Mappings"

  {{FRAMEWORK_MAPPINGS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Check that framework sections are indented at same level as placeholder
        lines = result.split("\n")

        # Find lines with "- type: textarea" (framework sections)
        textarea_lines = [line for line in lines if "- type: textarea" in line]

        # All should start with 2-space indentation (body level)
        for line in textarea_lines:
            assert line.startswith("  - type: textarea"), f"Bad indentation: '{line}'"


class TestFrameworkMappingsIntegration:
    """
    Integration tests for framework mappings in generated templates.

    Tests the complete flow from template rendering to final output
    with framework-specific placeholders.
    """

    def test_generated_new_control_has_dynamic_frameworks(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test generated "new control" template has correct framework sections.

        Given: New control template with {{FRAMEWORK_MAPPINGS}}
        When: Template is rendered
        Then: Generated template has framework sections for mitre-atlas, nist-ai-rmf, owasp-top10-llm
        """
        template = """name: New Control
description: Submit a new control
body:
  - type: input
    id: title
    attributes:
      label: Title

  - type: markdown
    attributes:
      value: "## Framework Mappings"

  {{FRAMEWORK_MAPPINGS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "controls")

        import yaml

        parsed = yaml.safe_load(result)

        # Find framework mapping sections in body
        framework_sections = [
            item
            for item in parsed["body"]
            if item.get("type") == "textarea" and item.get("id", "").startswith("mapping-")
        ]

        # Should have 3 framework sections
        assert len(framework_sections) == 3

        framework_ids = [section["id"] for section in framework_sections]
        assert "mapping-mitre-atlas" in framework_ids
        assert "mapping-nist-ai-rmf" in framework_ids
        assert "mapping-owasp-top10-llm" in framework_ids

    def test_generated_new_risk_has_dynamic_frameworks(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test generated "new risk" template has correct framework sections.

        Given: New risk template with {{FRAMEWORK_MAPPINGS}}
        When: Template is rendered
        Then: Generated template has framework sections for mitre-atlas, stride, owasp-top10-llm
        """
        template = """name: New Risk
description: Submit a new risk
body:
  - type: input
    id: title
    attributes:
      label: Title

  - type: markdown
    attributes:
      value: "## Framework Mappings"

  {{FRAMEWORK_MAPPINGS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "risks")

        import yaml

        parsed = yaml.safe_load(result)

        # Find framework mapping sections in body
        framework_sections = [
            item
            for item in parsed["body"]
            if item.get("type") == "textarea" and item.get("id", "").startswith("mapping-")
        ]

        # Should have 3 framework sections
        assert len(framework_sections) == 3

        framework_ids = [section["id"] for section in framework_sections]
        assert "mapping-mitre-atlas" in framework_ids
        assert "mapping-stride" in framework_ids
        assert "mapping-owasp-top10-llm" in framework_ids

        # Should NOT have nist-ai-rmf (not applicable to risks)
        assert "mapping-nist-ai-rmf" not in framework_ids

    def test_generated_update_control_has_framework_list(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test generated "update control" template has framework list in description.

        Given: Update control template with {{CONTROL_FRAMEWORKS_LIST}}
        When: Template is rendered
        Then: Description contains comma-separated list "mitre-atlas, nist-ai-rmf, owasp-top10-llm"
        """
        template = """name: Update Control
description: Update an existing control
body:
  - type: textarea
    id: mappings
    attributes:
      label: Framework Mappings
      description: |
        Update mappings to: {{CONTROL_FRAMEWORKS_LIST}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "controls")

        import yaml

        parsed = yaml.safe_load(result)

        # Find mappings textarea
        mappings_section = next(item for item in parsed["body"] if item["id"] == "mappings")

        description = mappings_section["attributes"]["description"]
        assert "mitre-atlas, nist-ai-rmf, owasp-top10-llm" in description

    def test_generated_update_risk_has_framework_list(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test generated "update risk" template has framework list in description.

        Given: Update risk template with {{RISK_FRAMEWORKS_LIST}}
        When: Template is rendered
        Then: Description contains comma-separated list "mitre-atlas, stride, owasp-top10-llm"
        """
        template = """name: Update Risk
description: Update an existing risk
body:
  - type: textarea
    id: mappings
    attributes:
      label: Framework Mappings
      description: |
        Update mappings to: {{RISK_FRAMEWORKS_LIST}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "risks")

        import yaml

        parsed = yaml.safe_load(result)

        # Find mappings textarea
        mappings_section = next(item for item in parsed["body"] if item["id"] == "mappings")

        description = mappings_section["attributes"]["description"]
        assert "mitre-atlas, stride, owasp-top10-llm" in description


class TestFrameworkMappingsEdgeCases:
    """
    Test edge cases for framework mappings functionality.

    Tests error handling, missing data, and boundary conditions.
    """

    def test_framework_mappings_handles_empty_applicable_to(self, sample_schema_parser: SchemaParser) -> None:
        """
        Test expand_framework_mappings() handles frameworks with empty applicableTo.

        Given: Framework with empty applicableTo array
        When: expand_framework_mappings() is called
        Then: Framework is excluded from results
        """
        frameworks_with_empty = {
            "frameworks": [
                {"id": "empty-framework", "name": "Empty Framework", "applicableTo": []},
                {"id": "nist-ai-rmf", "name": "NIST AI RMF", "applicableTo": ["controls"]},
            ]
        }

        renderer = TemplateRenderer(sample_schema_parser, frameworks_with_empty)
        result = renderer.expand_framework_mappings("controls")

        # Should only have nist-ai-rmf
        assert len(result) == 1
        assert result[0]["id"] == "mapping-nist-ai-rmf"

    def test_framework_mappings_handles_missing_framework_data(self, sample_schema_parser: SchemaParser) -> None:
        """
        Test expand_framework_mappings() handles missing framework fields gracefully.

        Given: Framework with missing optional fields (baseUri, fullName)
        When: expand_framework_mappings() is called
        Then: Handles gracefully without crashing
        """
        minimal_framework_data = {
            "frameworks": [
                {
                    "id": "minimal-framework",
                    "name": "Minimal Framework",
                    "applicableTo": ["controls"],
                    # Missing baseUri, fullName
                }
            ]
        }

        renderer = TemplateRenderer(sample_schema_parser, minimal_framework_data)
        result = renderer.expand_framework_mappings("controls")

        # Should still generate section
        assert len(result) == 1
        assert result[0]["id"] == "mapping-minimal-framework"
        assert "attributes" in result[0]

    def test_framework_list_handles_missing_applicable_to(self, sample_schema_parser: SchemaParser) -> None:
        """
        Test get_frameworks_list() handles frameworks missing applicableTo field.

        Given: Framework without applicableTo field
        When: get_frameworks_list() is called
        Then: Treats framework as not applicable to any entity type
        """
        frameworks_no_applicable = {
            "frameworks": [
                {
                    "id": "no-applicable",
                    "name": "No Applicable",
                    # Missing applicableTo field
                },
                {"id": "nist-ai-rmf", "name": "NIST AI RMF", "applicableTo": ["controls"]},
            ]
        }

        renderer = TemplateRenderer(sample_schema_parser, frameworks_no_applicable)
        result = renderer.get_frameworks_list("controls")

        # Should only include nist-ai-rmf
        assert result == "nist-ai-rmf"

    def test_framework_mappings_handles_none_entity_type(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test expand_framework_mappings() with None entity_type.

        Given: None as entity_type parameter
        When: expand_framework_mappings() is called
        Then: Raises TypeError or ValueError
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)

        with pytest.raises((TypeError, ValueError)):
            renderer.expand_framework_mappings(None)


class TestRenderTemplate:
    """Test render_template() main method."""

    def test_render_template_expands_placeholders(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test full template rendering with placeholder expansion.

        Given: Template with placeholders
        When: render_template() is called
        Then: Placeholders are expanded
        """
        template = """name: Test Template
body:
  - type: dropdown
    id: category
    attributes:
      options:
        {{CONTROL_CATEGORIES}}

  - type: textarea
    id: risks
    attributes:
      label: Risks
      description: |
        List risks here"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "controls")

        # Check placeholder expansion
        assert "{{CONTROL_CATEGORIES}}" not in result
        assert "controlsData" in result

    def test_render_template_preserves_yaml_structure(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that full rendering preserves YAML structure.

        Given: Valid YAML template
        When: render_template() is called
        Then: Output is still valid YAML with correct structure
        """
        template = """name: Test Template
description: Test
body:
  - type: input
    id: title
    attributes:
      label: Title*
    validations:
      required: true"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "controls")

        # Should parse as valid YAML
        import yaml

        parsed = yaml.safe_load(result)
        assert parsed["name"] == "Test Template"
        assert "body" in parsed

    def test_render_template_handles_complex_template(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test rendering complex template with multiple features.

        Given: Complex template with multiple sections and placeholders
        When: render_template() is called
        Then: All features are rendered correctly
        """
        template = """name: Complex Template
description: Test complex rendering
body:
  - type: dropdown
    id: category
    attributes:
      options:
        {{CONTROL_CATEGORIES}}

  - type: checkboxes
    id: personas
    attributes:
      options:
        {{PERSONAS}}

  - type: textarea
    id: risks
    attributes:
      description: List risks

  - type: markdown
    attributes:
      value: |
        ## Framework Mappings"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "controls")

        assert "{{CONTROL_CATEGORIES}}" not in result
        assert "{{PERSONAS}}" not in result
        assert "controlsData" in result
        assert "personaModelCreator" in result

    def test_render_template_empty_template(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test rendering empty template.

        Given: Empty string template
        When: render_template() is called
        Then: Returns empty string
        """
        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template("", "controls")

        assert result == ""

    def test_render_template_no_changes_needed(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test rendering template that needs no changes.

        Given: Template without placeholders
        When: render_template() is called
        Then: Returns template unchanged
        """
        template = """name: Simple Template
description: No changes needed
body:
  - type: input
    id: title"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "controls")

        assert result == template


class TestTemplateRendererIntegration:
    """Integration tests with production data."""

    def test_render_production_control_template(
        self, risk_map_schemas_dir: Path, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test rendering actual control template with production schemas.

        Given: Production schema directory and control template structure
        When: render_template() is called
        Then: Template is rendered correctly with actual enum values
        """
        parser = SchemaParser(risk_map_schemas_dir)
        renderer = TemplateRenderer(parser, sample_frameworks_data)

        template = """name: New Control
body:
  - type: dropdown
    id: category
    attributes:
      options:
        {{CONTROL_CATEGORIES}}

  - type: textarea
    id: risks
    attributes:
      description: List risks"""

        result = renderer.render_template(template, "controls")

        # Should contain actual production categories
        assert "controlsData" in result
        assert "controlsInfrastructure" in result
        assert "controlsModel" in result
        assert "controlsApplication" in result

    def test_render_production_risk_template(
        self, risk_map_schemas_dir: Path, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test rendering actual risk template with production schemas.

        Given: Production schema directory and risk template structure
        When: render_template() is called
        Then: Template is rendered with actual risk categories
        """
        parser = SchemaParser(risk_map_schemas_dir)
        renderer = TemplateRenderer(parser, sample_frameworks_data)

        template = """name: New Risk
body:
  - type: dropdown
    id: category
    attributes:
      options:
        {{RISK_CATEGORIES}}

  - type: textarea
    id: controls
    attributes:
      description: List controls"""

        result = renderer.render_template(template, "risks")

        # Should contain actual production risk categories
        assert "risksSupplyChainAndDevelopment" in result or "risksDeployment" in result

    def test_integration_with_production_frameworks_yaml(
        self, risk_map_schemas_dir: Path, repo_root: Path
    ) -> None:
        """
        Test integration with actual frameworks.yaml file.

        Given: Actual frameworks.yaml from repository
        When: TemplateRenderer is initialized
        Then: Framework filtering works with real data
        """
        import yaml

        frameworks_path = repo_root / "risk-map" / "yaml" / "frameworks.yaml"
        with open(frameworks_path, "r", encoding="utf-8") as f:
            frameworks_data = yaml.safe_load(f)

        parser = SchemaParser(risk_map_schemas_dir)
        renderer = TemplateRenderer(parser, frameworks_data)

        # Test framework filtering with real data
        control_frameworks = renderer.filter_frameworks_by_applicability("controls")
        risk_frameworks = renderer.filter_frameworks_by_applicability("risks")

        # Should have different frameworks for different entity types
        assert len(control_frameworks) > 0
        assert len(risk_frameworks) > 0


class TestTemplateRendererErrorHandling:
    """Test error handling in TemplateRenderer."""

    def test_render_with_missing_schema_file(self, tmp_path: Path, sample_frameworks_data: dict[str, Any]) -> None:
        """
        Test rendering when schema file is missing.

        Given: SchemaParser with missing schema files
        When: render_template() tries to access missing schema
        Then: Raises FileNotFoundError with clear message
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()

        parser = SchemaParser(schema_dir)
        renderer = TemplateRenderer(parser, sample_frameworks_data)

        template = """options:
        {{CONTROL_CATEGORIES}}"""

        with pytest.raises(FileNotFoundError):
            renderer.render_template(template, "controls")

    def test_render_with_malformed_yaml_template(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test rendering malformed YAML template.

        Given: Template with invalid YAML syntax
        When: render_template() is called
        Then: Handles gracefully or raises appropriate error
        """
        template = """name: Test
body:
  - type: input
      invalid_indentation: true"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)

        # Should either handle gracefully or raise clear error
        # Implementation can decide behavior
        result = renderer.render_template(template, "controls")
        assert isinstance(result, str)

    def test_render_with_circular_placeholder_reference(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test handling of circular placeholder references.

        Given: Template with self-referencing placeholders
        When: render_template() is called
        Then: Detects and prevents infinite loop
        """
        template = """options:
        {{PLACEHOLDER_A}}
        {{PLACEHOLDER_A}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)

        # Should not hang or crash
        result = renderer.render_template(template, "controls")
        assert isinstance(result, str)


class TestYAMLFormattingPreservation:
    """Test YAML formatting and structure preservation."""

    def test_preserve_multiline_strings(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test preservation of multiline strings.

        Given: Template with multiline string (|)
        When: render_template() is called
        Then: Multiline format is preserved
        """
        template = """  - type: textarea
    attributes:
      description: |
        Line 1
        Line 2
        Line 3"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "controls")

        assert "description: |" in result
        assert "Line 1" in result
        assert "Line 2" in result

    def test_preserve_markdown_sections(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test preservation of markdown sections.

        Given: Template with markdown type sections
        When: render_template() is called
        Then: Markdown sections are preserved intact
        """
        template = """  - type: markdown
    attributes:
      value: |
        ## Framework Mappings

        **Note**: These are optional."""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "controls")

        assert "## Framework Mappings" in result
        assert "**Note**:" in result

    def test_preserve_reference_links(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test preservation of reference links.

        Given: Template with markdown links
        When: render_template() is called
        Then: Links are preserved
        """
        template = """description: |
        [View controls](../../risk-map/tables/controls-summary.md)"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "controls")

        assert "[View controls]" in result
        assert "../../risk-map/tables/controls-summary.md" in result

    def test_preserve_comment_sections(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test preservation of YAML comments.

        Given: Template with YAML comments
        When: render_template() is called
        Then: Comments are preserved
        """
        template = """# This is a comment
name: Test Template
# Another comment
body:
  - type: input"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.render_template(template, "controls")

        # Comments should be preserved
        assert "# This is a comment" in result
        assert "# Another comment" in result


class TestGitHubSchemaValidation:
    """
    Test generated templates match GitHub schema requirements.

    These integration tests verify that placeholder expansion produces
    output that would pass GitHub's check-jsonschema validation.
    """

    def test_dropdown_output_is_valid_yaml_string_list(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that dropdown output structure is valid YAML string list.

        Given: Template with dropdown placeholder
        When: expand_placeholders() is called
        Then: Output is a valid YAML list of strings that parses correctly
        """
        import yaml

        template = """body:
  - type: dropdown
    id: category
    attributes:
      label: Category
      options:
        {{CONTROL_CATEGORIES}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Parse result as YAML
        parsed = yaml.safe_load(result)

        # Verify structure
        assert "body" in parsed
        assert len(parsed["body"]) == 1
        assert parsed["body"][0]["type"] == "dropdown"

        # Verify options are a list of strings (not objects)
        options = parsed["body"][0]["attributes"]["options"]
        assert isinstance(options, list)
        assert all(isinstance(opt, str) for opt in options)

        # Verify expected values
        assert "controlsData" in options
        assert "controlsModel" in options

    def test_checkbox_output_is_valid_yaml_object_list(
        self, sample_schema_parser: SchemaParser, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that checkbox output structure is valid YAML object list.

        Given: Template with checkbox placeholder
        When: expand_placeholders() is called
        Then: Output is valid YAML list of objects with label field only
        """
        import yaml

        template = """body:
  - type: checkboxes
    id: personas
    attributes:
      label: Personas
      options:
        {{PERSONAS}}"""

        renderer = TemplateRenderer(sample_schema_parser, sample_frameworks_data)
        result = renderer.expand_placeholders(template, "controls")

        # Parse result as YAML
        parsed = yaml.safe_load(result)

        # Verify structure
        assert "body" in parsed
        assert len(parsed["body"]) == 1
        assert parsed["body"][0]["type"] == "checkboxes"

        # Verify options are a list of objects
        options = parsed["body"][0]["attributes"]["options"]
        assert isinstance(options, list)
        assert all(isinstance(opt, dict) for opt in options)

        # Verify each object has label only (no value field)
        for opt in options:
            assert "label" in opt
            assert "value" not in opt
            assert isinstance(opt["label"], str)

        # Verify expected values
        labels = [opt["label"] for opt in options]
        assert "personaModelCreator" in labels
        assert "personaModelConsumer" in labels

    def test_generated_templates_match_github_schema_structure(
        self, risk_map_schemas_dir: Path, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test that generated templates have structure matching GitHub schema.

        Given: Production schemas and realistic template
        When: render_template() is called
        Then: Output structure matches GitHub issue form schema requirements
        """
        import yaml

        parser = SchemaParser(risk_map_schemas_dir)
        renderer = TemplateRenderer(parser, sample_frameworks_data)

        # Realistic template with both dropdown and checkbox
        template = """name: Test Template
description: Test
body:
  - type: dropdown
    id: category
    attributes:
      label: Category
      options:
        {{CONTROL_CATEGORIES}}

  - type: checkboxes
    id: personas
    attributes:
      label: Personas
      options:
        {{PERSONAS}}

  - type: input
    id: title
    attributes:
      label: Title
    validations:
      required: true"""

        result = renderer.render_template(template, "controls")

        # Parse and verify structure
        parsed = yaml.safe_load(result)

        assert parsed["name"] == "Test Template"
        assert "body" in parsed
        assert len(parsed["body"]) == 3

        # Verify dropdown (first element)
        dropdown = parsed["body"][0]
        assert dropdown["type"] == "dropdown"
        assert "options" in dropdown["attributes"]
        dropdown_options = dropdown["attributes"]["options"]
        assert isinstance(dropdown_options, list)
        assert all(isinstance(opt, str) for opt in dropdown_options)

        # Verify checkboxes (second element)
        checkboxes = parsed["body"][1]
        assert checkboxes["type"] == "checkboxes"
        assert "options" in checkboxes["attributes"]
        checkbox_options = checkboxes["attributes"]["options"]
        assert isinstance(checkbox_options, list)
        assert all(isinstance(opt, dict) for opt in checkbox_options)
        assert all("label" in opt and "value" not in opt for opt in checkbox_options)

        # Verify input (third element)
        input_field = parsed["body"][2]
        assert input_field["type"] == "input"
        assert input_field["validations"]["required"] is True

    def test_production_control_template_structure(
        self, risk_map_schemas_dir: Path, sample_frameworks_data: dict[str, Any]
    ) -> None:
        """
        Test production control template has valid GitHub schema structure.

        Given: Production schemas and control template
        When: Template is rendered
        Then: All dropdown and checkbox fields have correct formats
        """
        import yaml

        parser = SchemaParser(risk_map_schemas_dir)
        renderer = TemplateRenderer(parser, sample_frameworks_data)

        # Production-like control template
        template = """name: New Control
description: Submit a new security control
body:
  - type: dropdown
    id: category
    attributes:
      label: Category
      options:
        {{CONTROL_CATEGORIES}}

  - type: checkboxes
    id: personas
    attributes:
      label: Applicable Personas
      options:
        {{PERSONAS}}

  - type: checkboxes
    id: lifecycle
    attributes:
      label: Lifecycle Stage
      options:
        {{LIFECYCLE_STAGE}}"""

        result = renderer.render_template(template, "controls")
        parsed = yaml.safe_load(result)

        # Verify all fields are correctly formatted
        for item in parsed["body"]:
            if item["type"] == "dropdown":
                # Dropdowns must have string lists
                options = item["attributes"]["options"]
                assert all(isinstance(opt, str) for opt in options), (
                    f"Dropdown {item['id']} has non-string options"
                )

            elif item["type"] == "checkboxes":
                # Checkboxes must have object lists with label only
                options = item["attributes"]["options"]
                assert all(isinstance(opt, dict) for opt in options), (
                    f"Checkboxes {item['id']} has non-dict options"
                )
                assert all("label" in opt and "value" not in opt for opt in options), (
                    f"Checkboxes {item['id']} has invalid object structure"
                )
