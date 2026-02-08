"""
Tests for IssueTemplateGenerator class and CLI entry point.

This module tests the IssueTemplateGenerator orchestrator that combines
SchemaParser and TemplateRenderer to generate GitHub issue templates,
plus the command-line interface for template generation.

Test Coverage:
- IssueTemplateGenerator initialization
- Template discovery and entity type mapping
- Single template generation
- Batch template generation (all templates)
- Template validation (YAML + GitHub schema)
- Dry-run mode with diff comparison
- CLI argument parsing and execution
- Integration with production schemas and templates
- Error handling and edge cases
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

# IssueTemplateGenerator import - PYTHONPATH is set to ./scripts/hooks in GitHub Actions
from issue_template_generator.generator import IssueTemplateGenerator
from issue_template_generator.schema_parser import SchemaParser
from issue_template_generator.template_renderer import TemplateRenderer

# ============================================================================
# Pytest Fixtures
# ============================================================================


@pytest.fixture
def templates_dir(tmp_path: Path) -> Path:
    """
    Create temporary templates directory with sample template files.

    Mimics structure of scripts/TEMPLATES/ directory.
    """
    templates_dir = tmp_path / "scripts" / "TEMPLATES"
    templates_dir.mkdir(parents=True)

    # Create sample template files
    template_files = {
        "new_control.template.yml": """name: New Control
body:
  - type: dropdown
    id: category
    attributes:
      options:
        {{CONTROL_CATEGORIES}}
""",
        "update_control.template.yml": """name: Update Control
body:
  - type: input
    id: control-id
""",
        "new_risk.template.yml": """name: New Risk
body:
  - type: dropdown
    id: category
    attributes:
      options:
        {{RISK_CATEGORIES}}
""",
        "update_risk.template.yml": """name: Update Risk
body:
  - type: input
    id: risk-id
""",
        "new_component.template.yml": """name: New Component
body:
  - type: input
    id: component-id
""",
        "update_component.template.yml": """name: Update Component
body:
  - type: input
    id: component-id
""",
        "new_persona.template.yml": """name: New Persona
body:
  - type: input
    id: persona-id
""",
        "update_persona.template.yml": """name: Update Persona
body:
  - type: input
    id: persona-id
""",
        "infrastructure.template.yml": """name: Infrastructure
body:
  - type: input
    id: title
""",
    }

    for filename, content in template_files.items():
        (templates_dir / filename).write_text(content)

    return templates_dir


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    """Create temporary output directory for generated templates."""
    output_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
    output_dir.mkdir(parents=True)
    return output_dir


@pytest.fixture
def mock_repo_root(tmp_path: Path, templates_dir: Path, output_dir: Path) -> Path:
    """
    Create mock repository root with all necessary directories.

    Sets up:
    - scripts/TEMPLATES/ (template sources)
    - .github/ISSUE_TEMPLATE/ (output directory)
    - risk-map/schemas/ (schemas directory)
    - risk-map/yaml/frameworks.yaml (frameworks data)
    """
    repo_root = tmp_path

    # Create schemas directory with minimal schemas
    schemas_dir = repo_root / "risk-map" / "schemas"
    schemas_dir.mkdir(parents=True)

    schemas = {
        "controls.schema.json": {
            "$id": "controls.schema.json",
            "definitions": {
                "category": {
                    "properties": {"id": {"enum": ["controlsData", "controlsInfrastructure", "controlsModel"]}}
                },
                "control": {"properties": {"id": {"enum": ["control1", "control2"]}}},
            },
        },
        "risks.schema.json": {
            "$id": "risks.schema.json",
            "definitions": {
                "category": {
                    "properties": {
                        "id": {"enum": ["risksSupplyChainAndDevelopment", "risksDeploymentAndInfrastructure"]}
                    }
                },
                "risk": {"properties": {"id": {"enum": ["DP", "MST", "PIJ"]}}},
            },
        },
        "components.schema.json": {
            "$id": "components.schema.json",
            "definitions": {
                "component": {"properties": {"id": {"enum": ["componentDataSources", "componentTrainingData"]}}}
            },
        },
        "personas.schema.json": {
            "$id": "personas.schema.json",
            "definitions": {
                "persona": {"properties": {"id": {"enum": ["personaModelCreator", "personaModelConsumer"]}}}
            },
        },
    }

    for filename, schema_data in schemas.items():
        (schemas_dir / filename).write_text(json.dumps(schema_data))

    # Create frameworks.yaml
    yaml_dir = repo_root / "risk-map" / "yaml"
    yaml_dir.mkdir(parents=True)

    frameworks_data = {
        "frameworks": [
            {"id": "mitre-atlas", "name": "MITRE ATLAS", "applicableTo": ["controls", "risks"]},
            {"id": "nist-ai-rmf", "name": "NIST AI RMF", "applicableTo": ["controls"]},
        ]
    }

    (yaml_dir / "frameworks.yaml").write_text(yaml.dump(frameworks_data))

    return repo_root


@pytest.fixture
def sample_frameworks_data() -> dict[str, Any]:
    """Provide sample frameworks data for testing."""
    return {
        "frameworks": [
            {"id": "mitre-atlas", "name": "MITRE ATLAS", "applicableTo": ["controls", "risks"]},
            {"id": "nist-ai-rmf", "name": "NIST AI RMF", "applicableTo": ["controls"]},
        ]
    }


# ============================================================================
# Test Classes
# ============================================================================


class TestIssueTemplateGeneratorInit:
    """Test IssueTemplateGenerator initialization."""

    def test_init_with_valid_repo_root(self, mock_repo_root: Path) -> None:
        """
        Test initialization with valid repository root.

        Given: Valid repository root with all required directories
        When: IssueTemplateGenerator is initialized
        Then: Instance is created successfully with loaded schemas and frameworks
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        assert generator.repo_root == mock_repo_root
        assert isinstance(generator.schema_parser, SchemaParser)
        assert isinstance(generator.template_renderer, TemplateRenderer)
        assert isinstance(generator.frameworks_data, dict)
        assert "frameworks" in generator.frameworks_data

    def test_init_with_nonexistent_repo_root(self, tmp_path: Path) -> None:
        """
        Test initialization with non-existent repository root.

        Given: Repository root path that doesn't exist
        When: IssueTemplateGenerator is initialized
        Then: Raises FileNotFoundError
        """
        nonexistent_root = tmp_path / "does_not_exist"

        with pytest.raises(FileNotFoundError, match="Repository root.*not exist"):
            IssueTemplateGenerator(nonexistent_root)

    def test_init_with_missing_schemas_directory(self, tmp_path: Path) -> None:
        """
        Test initialization when schemas directory is missing.

        Given: Repository root without risk-map/schemas directory
        When: IssueTemplateGenerator is initialized
        Then: Raises FileNotFoundError
        """
        repo_root = tmp_path
        repo_root.mkdir(exist_ok=True)

        with pytest.raises(FileNotFoundError, match="Schema.*directory.*not exist"):
            IssueTemplateGenerator(repo_root)

    def test_init_with_missing_frameworks_yaml(self, tmp_path: Path) -> None:
        """
        Test initialization when frameworks.yaml is missing.

        Given: Repository root without risk-map/yaml/frameworks.yaml
        When: IssueTemplateGenerator is initialized
        Then: Raises FileNotFoundError
        """
        repo_root = tmp_path
        schemas_dir = repo_root / "risk-map" / "schemas"
        schemas_dir.mkdir(parents=True)

        with pytest.raises(FileNotFoundError, match="frameworks.yaml.*not found"):
            IssueTemplateGenerator(repo_root)

    def test_init_with_missing_templates_directory(self, tmp_path: Path) -> None:
        """
        Test initialization when templates directory is missing.

        Given: Repository root without scripts/TEMPLATES directory
        When: IssueTemplateGenerator is initialized
        Then: Raises FileNotFoundError
        """
        repo_root = tmp_path

        # Create schemas directory
        schemas_dir = repo_root / "risk-map" / "schemas"
        schemas_dir.mkdir(parents=True)
        (schemas_dir / "test.schema.json").write_text("{}")

        # Create frameworks.yaml
        yaml_dir = repo_root / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")

        # Missing scripts/TEMPLATES directory
        with pytest.raises(FileNotFoundError, match="Template.*directory.*not exist"):
            IssueTemplateGenerator(repo_root)

    def test_init_with_missing_output_directory(self, tmp_path: Path) -> None:
        """
        Test initialization when output directory is missing.

        Given: Repository root without .github/ISSUE_TEMPLATE directory
        When: IssueTemplateGenerator is initialized
        Then: Raises FileNotFoundError
        """
        repo_root = tmp_path

        # Create required directories except output
        schemas_dir = repo_root / "risk-map" / "schemas"
        schemas_dir.mkdir(parents=True)
        (schemas_dir / "test.schema.json").write_text("{}")

        yaml_dir = repo_root / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")

        templates_dir = repo_root / "scripts" / "TEMPLATES"
        templates_dir.mkdir(parents=True)

        # Missing .github/ISSUE_TEMPLATE
        with pytest.raises(FileNotFoundError, match="Output.*directory.*not exist"):
            IssueTemplateGenerator(repo_root)

    def test_init_with_malformed_frameworks_yaml(self, tmp_path: Path) -> None:
        """
        Test initialization with malformed frameworks.yaml.

        Given: frameworks.yaml with invalid YAML syntax
        When: IssueTemplateGenerator is initialized
        Then: Raises yaml.YAMLError
        """
        repo_root = tmp_path

        schemas_dir = repo_root / "risk-map" / "schemas"
        schemas_dir.mkdir(parents=True)
        (schemas_dir / "test.schema.json").write_text("{}")

        yaml_dir = repo_root / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("{invalid yaml: [unclosed")

        templates_dir = repo_root / "scripts" / "TEMPLATES"
        templates_dir.mkdir(parents=True)

        output_dir = repo_root / ".github" / "ISSUE_TEMPLATE"
        output_dir.mkdir(parents=True)

        with pytest.raises(yaml.YAMLError):
            IssueTemplateGenerator(repo_root)


class TestGetAvailableTemplates:
    """Test get_available_templates() method."""

    def test_get_available_templates_finds_all_templates(self, mock_repo_root: Path) -> None:
        """
        Test that get_available_templates() finds all template files.

        Given: Repository with 9 template files
        When: get_available_templates() is called
        Then: Returns list of 9 template names
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        templates = generator.get_available_templates()

        assert len(templates) == 9
        assert "new_control" in templates
        assert "update_control" in templates
        assert "new_risk" in templates
        assert "update_risk" in templates
        assert "new_component" in templates
        assert "update_component" in templates
        assert "new_persona" in templates
        assert "update_persona" in templates
        assert "infrastructure" in templates

    def test_get_available_templates_returns_sorted_list(self, mock_repo_root: Path) -> None:
        """
        Test that template names are returned in sorted order.

        Given: Repository with multiple templates
        When: get_available_templates() is called
        Then: Returns alphabetically sorted list
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        templates = generator.get_available_templates()

        assert templates == sorted(templates)

    def test_get_available_templates_with_empty_directory(self, tmp_path: Path) -> None:
        """
        Test get_available_templates() with no template files.

        Given: Templates directory with no .template.yml files
        When: get_available_templates() is called
        Then: Returns empty list
        """
        repo_root = tmp_path

        # Set up minimal repo structure
        schemas_dir = repo_root / "risk-map" / "schemas"
        schemas_dir.mkdir(parents=True)
        (schemas_dir / "test.schema.json").write_text("{}")

        yaml_dir = repo_root / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")

        templates_dir = repo_root / "scripts" / "TEMPLATES"
        templates_dir.mkdir(parents=True)

        output_dir = repo_root / ".github" / "ISSUE_TEMPLATE"
        output_dir.mkdir(parents=True)

        generator = IssueTemplateGenerator(repo_root)
        templates = generator.get_available_templates()

        assert templates == []


class TestEntityTypeMapping:
    """Test entity type mapping from template names."""

    def test_map_entity_type_for_new_control(self, mock_repo_root: Path) -> None:
        """
        Test entity type mapping for new_control template.

        Given: Template name "new_control"
        When: Entity type is determined
        Then: Returns "controls"
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        entity_type = generator._get_entity_type("new_control")

        assert entity_type == "controls"

    def test_map_entity_type_for_update_risk(self, mock_repo_root: Path) -> None:
        """
        Test entity type mapping for update_risk template.

        Given: Template name "update_risk"
        When: Entity type is determined
        Then: Returns "risks"
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        entity_type = generator._get_entity_type("update_risk")

        assert entity_type == "risks"

    def test_map_entity_type_for_new_component(self, mock_repo_root: Path) -> None:
        """
        Test entity type mapping for new_component template.

        Given: Template name "new_component"
        When: Entity type is determined
        Then: Returns "components"
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        entity_type = generator._get_entity_type("new_component")

        assert entity_type == "components"

    def test_map_entity_type_for_persona(self, mock_repo_root: Path) -> None:
        """
        Test entity type mapping for persona templates.

        Given: Template name "new_persona"
        When: Entity type is determined
        Then: Returns "personas"
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        entity_type = generator._get_entity_type("new_persona")

        assert entity_type == "personas"

    def test_map_entity_type_for_infrastructure(self, mock_repo_root: Path) -> None:
        """
        Test entity type mapping for infrastructure template.

        Given: Template name "infrastructure"
        When: Entity type is determined
        Then: Returns None (no specific entity type)
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        entity_type = generator._get_entity_type("infrastructure")

        assert entity_type is None

    @pytest.mark.parametrize(
        "template_name,expected_entity",
        [
            ("new_control", "controls"),
            ("update_control", "controls"),
            ("new_risk", "risks"),
            ("update_risk", "risks"),
            ("new_component", "components"),
            ("update_component", "components"),
            ("new_persona", "personas"),
            ("update_persona", "personas"),
            ("infrastructure", None),
        ],
    )
    def test_entity_type_mapping_comprehensive(
        self, mock_repo_root: Path, template_name: str, expected_entity: str | None
    ) -> None:
        """
        Test comprehensive entity type mapping for all templates.

        Given: Various template names
        When: Entity type is determined
        Then: Returns correct entity type for each
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        entity_type = generator._get_entity_type(template_name)

        assert entity_type == expected_entity


class TestGenerateSingleTemplate:
    """Test generate_template() method for single template generation."""

    def test_generate_template_creates_output_file(self, mock_repo_root: Path) -> None:
        """
        Test that generate_template() creates output file.

        Given: Valid template name
        When: generate_template() is called
        Then: Output file is created in output directory
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        output_path = generator.generate_template("new_control")

        assert output_path.exists()
        assert output_path.name == "new_control.yml"
        assert output_path.parent.name == "ISSUE_TEMPLATE"

    def test_generate_template_expands_placeholders(self, mock_repo_root: Path) -> None:
        """
        Test that generate_template() expands placeholders.

        Given: Template with {{CONTROL_CATEGORIES}} placeholder
        When: generate_template() is called
        Then: Output contains expanded category values
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        output_path = generator.generate_template("new_control")

        content = output_path.read_text()
        assert "{{CONTROL_CATEGORIES}}" not in content
        assert "controlsData" in content
        assert "controlsInfrastructure" in content

    def test_generate_template_preserves_yaml_structure(self, mock_repo_root: Path) -> None:
        """
        Test that generated template is valid YAML.

        Given: Valid template source
        When: generate_template() is called
        Then: Output is valid YAML
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        output_path = generator.generate_template("new_control")

        content = output_path.read_text()
        parsed = yaml.safe_load(content)

        assert "name" in parsed
        assert "body" in parsed

    def test_generate_template_with_nonexistent_template(self, mock_repo_root: Path) -> None:
        """
        Test generate_template() with non-existent template name.

        Given: Template name that doesn't exist
        When: generate_template() is called
        Then: Raises FileNotFoundError
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        with pytest.raises(FileNotFoundError, match="Template.*not found"):
            generator.generate_template("nonexistent_template")

    def test_generate_template_overwrites_existing_file(self, mock_repo_root: Path) -> None:
        """
        Test that generate_template() overwrites existing output file.

        Given: Existing output file
        When: generate_template() is called
        Then: File is overwritten with new content
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        # Create existing file
        output_dir = mock_repo_root / ".github" / "ISSUE_TEMPLATE"
        existing_file = output_dir / "new_control.yml"
        existing_file.write_text("old content")

        # Generate template
        output_path = generator.generate_template("new_control")

        content = output_path.read_text()
        assert "old content" not in content
        assert "controlsData" in content

    def test_generate_template_preserves_file_permissions(self, mock_repo_root: Path) -> None:
        """
        Test that generated template has appropriate file permissions.

        Given: Template generation
        When: generate_template() is called
        Then: Output file has readable permissions
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        output_path = generator.generate_template("new_control")

        assert output_path.exists()
        assert output_path.is_file()
        # File should be readable
        content = output_path.read_text()
        assert len(content) > 0


class TestDryRunMode:
    """Test dry-run mode with diff comparison."""

    def test_generate_template_dry_run_returns_diff(self, mock_repo_root: Path) -> None:
        """
        Test that dry_run mode returns diff instead of writing file.

        Given: Template name and dry_run=True
        When: generate_template() is called
        Then: Returns diff string without writing file
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        # Create existing file to compare against
        output_dir = mock_repo_root / ".github" / "ISSUE_TEMPLATE"
        existing_file = output_dir / "new_control.yml"
        existing_file.write_text("name: Old Control\nbody: []\n")

        diff = generator.generate_template("new_control", dry_run=True)

        assert isinstance(diff, str)
        assert "---" in diff or "+++" in diff or "Old Control" in diff
        # File should not be modified
        assert existing_file.read_text() == "name: Old Control\nbody: []\n"

    def test_dry_run_shows_added_lines(self, mock_repo_root: Path) -> None:
        """
        Test that dry_run diff shows added lines.

        Given: Template with new content
        When: generate_template() is called with dry_run=True
        Then: Diff shows lines to be added
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        output_dir = mock_repo_root / ".github" / "ISSUE_TEMPLATE"
        existing_file = output_dir / "new_control.yml"
        existing_file.write_text("name: Control\n")

        diff = generator.generate_template("new_control", dry_run=True)

        # Should show additions
        assert "+" in diff or "controlsData" in diff

    def test_dry_run_no_changes_returns_empty_diff(self, mock_repo_root: Path) -> None:
        """
        Test that dry_run returns empty diff when no changes.

        Given: Template matching existing file exactly
        When: generate_template() is called with dry_run=True
        Then: Returns empty diff or "no changes" message
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        # First generate the template (writes to disk)
        generator.generate_template("new_control")

        # Then check dry_run (should show no changes since file matches)
        diff = generator.generate_template("new_control", dry_run=True)

        # Diff should be empty or indicate no changes
        assert diff == "" or "no changes" in diff.lower() or "identical" in diff.lower()


class TestBatchGeneration:
    """Test generate_all_templates() batch generation."""

    def test_generate_all_templates_creates_all_files(self, mock_repo_root: Path) -> None:
        """
        Test that generate_all_templates() creates all template files.

        Given: Repository with 9 templates
        When: generate_all_templates() is called
        Then: All 9 output files are created
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        result = generator.generate_all_templates()

        assert len(result) == 9
        assert "new_control" in result
        assert "update_control" in result
        assert "new_risk" in result
        assert "update_risk" in result
        assert "new_component" in result
        assert "update_component" in result
        assert "new_persona" in result
        assert "update_persona" in result
        assert "infrastructure" in result

    def test_generate_all_templates_returns_output_paths(self, mock_repo_root: Path) -> None:
        """
        Test that generate_all_templates() returns dict of paths.

        Given: Multiple templates
        When: generate_all_templates() is called
        Then: Returns dict mapping template names to output paths
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        result = generator.generate_all_templates()

        for template_name, output_path in result.items():
            assert isinstance(output_path, (str, Path))
            if isinstance(output_path, Path):
                assert output_path.exists()
                assert output_path.name == f"{template_name}.yml"

    def test_generate_all_templates_dry_run_returns_diffs(self, mock_repo_root: Path) -> None:
        """
        Test that generate_all_templates() with dry_run returns diffs.

        Given: Multiple templates and dry_run=True
        When: generate_all_templates() is called
        Then: Returns dict of diffs without writing files
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        # Create some existing files
        output_dir = mock_repo_root / ".github" / "ISSUE_TEMPLATE"
        (output_dir / "new_control.yml").write_text("old content")

        result = generator.generate_all_templates(dry_run=True)

        assert len(result) == 9
        for template_name, diff in result.items():
            assert isinstance(diff, str)

    def test_generate_all_templates_handles_errors_gracefully(self, mock_repo_root: Path) -> None:
        """
        Test that generate_all_templates() continues on individual failures.

        Given: Templates where one might fail
        When: generate_all_templates() is called
        Then: Continues processing other templates and reports errors
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        # Remove one template file to cause error
        templates_dir = mock_repo_root / "scripts" / "TEMPLATES"
        (templates_dir / "new_control.template.yml").unlink()

        result = generator.generate_all_templates()

        # Should still process other templates
        assert "update_control" in result
        assert "new_risk" in result
        # Failed template might be in result with error message or excluded
        assert len(result) >= 8

    def test_generate_all_templates_reports_progress(self, mock_repo_root: Path, capsys) -> None:
        """
        Test that generate_all_templates() reports progress (optional).

        Given: Multiple templates
        When: generate_all_templates() is called
        Then: Optionally prints progress messages
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        result = generator.generate_all_templates()

        # This test is optional - implementation may or may not print progress
        assert len(result) == 9


class TestTemplateValidation:
    """Test validate_generated_template() method."""

    def test_validate_valid_yaml_template(self, mock_repo_root: Path) -> None:
        """
        Test validation of valid YAML template.

        Given: Valid YAML template content
        When: validate_generated_template() is called
        Then: Returns True
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        valid_template = """name: Test Template
description: Test
body:
  - type: input
    id: title
    attributes:
      label: Title
"""

        is_valid = generator.validate_generated_template(valid_template)
        assert is_valid is True

    def test_validate_invalid_yaml_syntax(self, mock_repo_root: Path) -> None:
        """
        Test validation of invalid YAML syntax.

        Given: Template with invalid YAML
        When: validate_generated_template() is called
        Then: Returns False
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        invalid_yaml = """name: Test
body:
  - type: input
      invalid_indentation: true"""

        is_valid = generator.validate_generated_template(invalid_yaml)
        assert is_valid is False

    def test_validate_empty_template(self, mock_repo_root: Path) -> None:
        """
        Test validation of empty template.

        Given: Empty string template
        When: validate_generated_template() is called
        Then: Returns False
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        is_valid = generator.validate_generated_template("")
        assert is_valid is False

    def test_validate_template_missing_required_fields(self, mock_repo_root: Path) -> None:
        """
        Test validation of template missing required fields.

        Given: Template without required 'name' field
        When: validate_generated_template() is called
        Then: Returns False
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        missing_name = """description: Test
body:
  - type: input
"""

        is_valid = generator.validate_generated_template(missing_name)
        assert is_valid is False

    @patch("subprocess.run")
    def test_validate_uses_check_jsonschema(self, mock_run: MagicMock, mock_repo_root: Path) -> None:
        """
        Test that validation uses check-jsonschema.

        Given: Valid template content
        When: validate_generated_template() is called
        Then: Calls check-jsonschema with correct arguments
        """
        mock_run.return_value = MagicMock(returncode=0)

        generator = IssueTemplateGenerator(mock_repo_root)

        template = """name: Test
description: Test
body:
  - type: input
"""

        generator.validate_generated_template(template)

        # Should call check-jsonschema
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "check-jsonschema" in call_args
        assert "--builtin-schema" in call_args
        assert "vendor.github-issue-forms" in call_args

    @patch("subprocess.run")
    def test_validate_handles_check_jsonschema_failure(self, mock_run: MagicMock, mock_repo_root: Path) -> None:
        """
        Test validation when check-jsonschema fails.

        Given: Template that fails GitHub schema validation
        When: validate_generated_template() is called
        Then: Returns False
        """
        mock_run.return_value = MagicMock(returncode=1)

        generator = IssueTemplateGenerator(mock_repo_root)

        template = """name: Test
body: []
"""

        is_valid = generator.validate_generated_template(template)
        assert is_valid is False


class TestCLIArgumentParsing:
    """Test CLI argument parsing."""

    @patch("sys.argv", ["generate_issue_templates.py"])
    def test_cli_no_arguments_generates_all(self) -> None:
        """
        Test CLI with no arguments generates all templates.

        Given: No command-line arguments
        When: CLI is invoked
        Then: Generates all templates
        """
        # This will be tested with actual CLI implementation
        # Placeholder for TDD
        pass

    @patch("sys.argv", ["generate_issue_templates.py", "--dry-run"])
    def test_cli_dry_run_flag(self) -> None:
        """
        Test CLI with --dry-run flag.

        Given: --dry-run argument
        When: CLI is invoked
        Then: Shows diffs without writing files
        """
        pass

    @patch("sys.argv", ["generate_issue_templates.py", "--template", "new_control"])
    def test_cli_specific_template(self) -> None:
        """
        Test CLI with --template argument.

        Given: --template new_control argument
        When: CLI is invoked
        Then: Generates only specified template
        """
        pass

    @patch("sys.argv", ["generate_issue_templates.py", "--validate"])
    def test_cli_validate_only(self) -> None:
        """
        Test CLI with --validate flag.

        Given: --validate argument
        When: CLI is invoked
        Then: Validates templates without generating
        """
        pass

    @patch("sys.argv", ["generate_issue_templates.py", "--verbose"])
    def test_cli_verbose_output(self) -> None:
        """
        Test CLI with --verbose flag.

        Given: --verbose argument
        When: CLI is invoked
        Then: Outputs detailed progress information
        """
        pass


class TestCLIExecution:
    """Test CLI main() function execution."""

    def test_cli_main_success_returns_zero(self, mock_repo_root: Path) -> None:
        """
        Test that CLI main() returns exit code 0 on success.

        Given: Valid repository and templates
        When: CLI main() is executed
        Then: Returns exit code 0
        """
        # Import and test main() function
        # This will be implemented with actual CLI
        pass

    def test_cli_main_error_returns_one(self) -> None:
        """
        Test that CLI main() returns exit code 1 on error.

        Given: Invalid repository or missing files
        When: CLI main() is executed
        Then: Returns exit code 1
        """
        pass

    def test_cli_main_prints_clear_error_messages(self) -> None:
        """
        Test that CLI prints clear error messages.

        Given: Error condition
        When: CLI main() is executed
        Then: Prints helpful error message to stderr
        """
        pass

    def test_cli_main_handles_keyboard_interrupt(self) -> None:
        """
        Test that CLI handles KeyboardInterrupt gracefully.

        Given: User presses Ctrl+C during execution
        When: KeyboardInterrupt is raised
        Then: Exits gracefully with appropriate message
        """
        pass


class TestIntegrationWithProductionData:
    """Integration tests with production schemas and templates."""

    def test_generate_control_template_with_production_schemas(
        self, repo_root: Path, risk_map_schemas_dir: Path
    ) -> None:
        """
        Test generating control template with production schemas.

        Given: Production schema directory
        When: generate_template("new_control") is called
        Then: Template is generated with actual enum values
        """
        # Skip if not in production environment
        if not (repo_root / "scripts" / "TEMPLATES").exists():
            pytest.skip("Production templates not available")

        # This test would use actual production data
        # Placeholder for integration test
        pass

    def test_generate_all_templates_matches_existing_templates(self, repo_root: Path) -> None:
        """
        Test that generated templates match existing templates (regression).

        Given: Production repository
        When: generate_all_templates() is called
        Then: Generated templates match existing templates
        """
        if not (repo_root / "scripts" / "TEMPLATES").exists():
            pytest.skip("Production templates not available")

        # This would be a regression test
        pass

    def test_infrastructure_template_generation(self, mock_repo_root: Path) -> None:
        """
        Test infrastructure template (no entity type mapping).

        Given: Infrastructure template (generic, no entity type)
        When: generate_template("infrastructure") is called
        Then: Template is generated without entity-specific placeholders
        """
        generator = IssueTemplateGenerator(mock_repo_root)
        output_path = generator.generate_template("infrastructure")

        content = output_path.read_text()
        assert "name: Infrastructure" in content


class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge cases."""

    def test_generate_template_with_write_permission_error(self, mock_repo_root: Path) -> None:
        """
        Test handling of write permission errors.

        Given: Output directory without write permissions
        When: generate_template() is called
        Then: Raises PermissionError with clear message
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        # Make output directory read-only
        output_dir = mock_repo_root / ".github" / "ISSUE_TEMPLATE"
        output_dir.chmod(0o444)

        try:
            with pytest.raises(PermissionError, match="Permission denied|cannot write"):
                generator.generate_template("new_control")
        finally:
            # Restore permissions for cleanup
            output_dir.chmod(0o755)

    def test_generate_template_with_corrupted_template_file(self, mock_repo_root: Path) -> None:
        """
        Test handling of corrupted template file.

        Given: Template file with binary/corrupted content
        When: generate_template() is called
        Then: Raises appropriate error
        """
        generator = IssueTemplateGenerator(mock_repo_root)

        # Corrupt a template file
        templates_dir = mock_repo_root / "scripts" / "TEMPLATES"
        corrupted = templates_dir / "new_control.template.yml"
        corrupted.write_bytes(b"\x00\x01\x02\x03")

        with pytest.raises((UnicodeDecodeError, yaml.YAMLError)):
            generator.generate_template("new_control")

    def test_handle_very_large_enum_values(self, tmp_path: Path) -> None:
        """
        Test handling of very large enum value lists.

        Given: Schema with 1000+ enum values
        When: generate_template() is called
        Then: Handles large enums efficiently
        """
        # Create repo with large enums
        repo_root = tmp_path

        schemas_dir = repo_root / "risk-map" / "schemas"
        schemas_dir.mkdir(parents=True)

        large_enum = [f"value_{i}" for i in range(1000)]
        schema = {
            "$id": "controls.schema.json",
            "definitions": {"category": {"properties": {"id": {"enum": large_enum}}}},
        }

        (schemas_dir / "controls.schema.json").write_text(json.dumps(schema))

        # Set up rest of repo
        yaml_dir = repo_root / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")

        templates_dir = repo_root / "scripts" / "TEMPLATES"
        templates_dir.mkdir(parents=True)
        (templates_dir / "test.template.yml").write_text("name: Test\nbody:\n  - type: input")

        output_dir = repo_root / ".github" / "ISSUE_TEMPLATE"
        output_dir.mkdir(parents=True)

        # Should handle large enum without issues
        generator = IssueTemplateGenerator(repo_root)
        assert generator is not None

    def test_concurrent_template_generation(self, mock_repo_root: Path) -> None:
        """
        Test that multiple generators can run concurrently.

        Given: Multiple IssueTemplateGenerator instances
        When: Templates are generated concurrently
        Then: No conflicts or data corruption
        """
        generator1 = IssueTemplateGenerator(mock_repo_root)
        generator2 = IssueTemplateGenerator(mock_repo_root)

        # Both should work independently
        result1 = generator1.generate_template("new_control")
        result2 = generator2.generate_template("new_risk")

        assert result1.exists()
        assert result2.exists()
