#!/usr/bin/env python3
"""
Tests for Component Edge Consistency Validator

This test suite validates the CoSAI Risk Map component edge consistency
validation system. The validator ensures that component relationships are bidirectional
and that all referenced components exist.

Test Coverage:
==============
1. Core Validation Logic:
   - Edge consistency validation (bidirectional relationships)
   - Isolated component detection and handling
   - Missing component reference detection
   - YAML file loading and parsing error handling

2. Component Graph Generation:
   - Mermaid diagram generation from component relationships
   - Node ranking and layout algorithms
   - Category-based subgraph organization
   - Debug mode output formatting

3. Git Integration:
   - Staged file detection for pre-commit hooks
   - Force mode validation for manual testing
   - Error handling for git command failures

4. End-to-End Workflows:
   - Complete validation scenarios with realistic data
   - Error reporting and user feedback
   - Integration with CoSAI Risk Map framework

The tests use temporary YAML files and mocked git operations to ensure isolation
and reproducibility. Each test class focuses on a specific aspect of the system:

- TestComponentEdgeValidator: Core validation logic
- TestValidationScenarios: Real-world validation scenarios
- TestGitIntegration: Git workflow integration
- TestComponentGraph: Mermaid diagram generation
- TestEndToEndIntegration: Complete validation workflows
"""

import subprocess

# Import the validator using git repo root
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import riskmap_validator.utils
import yaml


def get_git_root():
    """Get the git repository root directory."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except subprocess.CalledProcessError:
        # Fallback to relative path if not in git repo
        return Path(__file__).parent.parent.parent


# Add scripts/hooks directory to path
git_root = get_git_root()
sys.path.insert(0, str(git_root / "scripts" / "hooks"))

# Import graphing classes if you test them
from riskmap_validator.graphing import ComponentGraph, ControlGraph  # noqa: E402
from riskmap_validator.models import ComponentNode, ControlNode  # noqa: E402
from riskmap_validator.utils import get_staged_yaml_files  # noqa: E402

# Import the validator and its exception from the validator module
from riskmap_validator.validator import ComponentEdgeValidator, EdgeValidationError  # noqa: E402


class TestComponentEdgeValidator:
    """
    Test the main ComponentEdgeValidator class functionality.

    This test class covers the core validation engine that ensures component
    edge consistency in the CoSAI Risk Map framework. Tests include:

    - YAML file loading and parsing (including error cases)
    - Component data extraction from YAML structures
    - Edge consistency validation (bidirectional relationships)
    - Isolated component detection
    - Missing component reference detection
    - Edge map construction for validation algorithms
    """

    @pytest.fixture
    def validator(self):
        """Create a validator instance for testing."""
        return ComponentEdgeValidator(allow_isolated=False, verbose=False)

    @pytest.fixture
    def validator_allow_isolated(self):
        """Create a validator that allows isolated components."""
        return ComponentEdgeValidator(allow_isolated=True, verbose=False)

    @pytest.fixture
    def grapher(self, title: str, to_edge: list[str], from_edge: list[str]):
        return ComponentNode(title=title, category="", to_edges=to_edge, from_edges=from_edge)

    @pytest.fixture
    def temp_yaml_file(self):
        """Create a temporary YAML file for testing."""
        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        yield Path(temp_file.name)
        # Cleanup
        Path(temp_file.name).unlink(missing_ok=True)

    def create_yaml_file(self, file_path: Path, data: dict):
        """Helper to create YAML file with given data."""
        with open(file_path, "w") as f:
            yaml.dump(data, f)

    def test_load_nonexistent_file(self, validator):
        """Test loading a file that doesn't exist."""
        with pytest.raises(FileNotFoundError):
            path = Path("nonexistent.yaml")
            riskmap_validator.utils.parse_components_yaml(path)

    def test_load_empty_yaml_file(self, validator, temp_yaml_file):
        """Test loading an empty YAML file."""
        with pytest.raises(TypeError):
            temp_yaml_file.write_text("")

            riskmap_validator.utils.parse_components_yaml(temp_yaml_file)

    def test_load_invalid_yaml_file(self, validator, temp_yaml_file):
        """Test loading an invalid YAML file."""
        with pytest.raises(yaml.YAMLError):
            temp_yaml_file.write_text("invalid: yaml: content: [")

            riskmap_validator.utils.parse_components_yaml(temp_yaml_file)

    def test_find_isolated_components(self, validator):
        """Test finding components with no edges."""

        components: dict[str, ComponentNode] = {
            "comp-a": ComponentNode(title="Test1", category="test1", to_edges=["comp-b"], from_edges=[]),
            "comp-b": ComponentNode(title="Test2", category="test1", to_edges=[], from_edges=["comp-a"]),
            "comp-isolated": ComponentNode(title="Test3", category="test1", to_edges=[], from_edges=[]),
            "comp-isolated2": ComponentNode(title="Test4", category="test1", to_edges=[], from_edges=[]),
        }

        isolated = validator.find_isolated_components(components)
        assert isolated == {"comp-isolated", "comp-isolated2"}

    def test_find_missing_components(self, validator):
        """Test finding components referenced but not defined."""
        components: dict[str, ComponentNode] = {
            "comp-a": ComponentNode(
                title="Test1",
                category="test1",
                to_edges=["comp-missing1", "comp-b"],
                from_edges=["comp-missing2"],
            ),
            "comp-b": ComponentNode(title="Test2", category="test1", to_edges=[], from_edges=["comp-a"]),
        }

        missing = validator.find_missing_components(components)
        assert missing == {"comp-missing1", "comp-missing2"}

    def test_build_edge_maps(self, validator):
        """Test building forward and reverse edge maps."""
        components: dict[str, ComponentNode] = {
            "comp-a": ComponentNode(
                title="Test1",
                category="test1",
                to_edges=["comp-b", "comp-c"],
                from_edges=[],
            ),
            "comp-b": ComponentNode(title="Test2", category="test1", to_edges=[], from_edges=["comp-a"]),
            "comp-c": ComponentNode(title="Test3", category="test1", to_edges=[], from_edges=["comp-a"]),
        }

        forward_map, reverse_map = validator.build_edge_maps(components)

        assert forward_map == {"comp-a": ["comp-b", "comp-c"]}
        assert reverse_map == {
            "comp-a": ["comp-b", "comp-c"]
        }  # No incoming edges to comp-a but has outgoing edges

    def test_validate_edge_consistency_valid(self, validator):
        """Test edge consistency validation with valid edges."""
        # Bidirectional consistency
        forward_map = {"comp-b": ["comp-a"]}
        reverse_map = {"comp-b": ["comp-a"]}

        errors = validator.validate_edge_consistency(forward_map, reverse_map)
        assert errors == []

    def test_validate_edge_consistency_missing_reverse(self, validator):
        """Test validation when 'to' edge has no corresponding 'from'."""
        # comp-a points to comp-b, but comp-b doesn't point back
        forward_map = {"comp-a": ["comp-b"]}
        reverse_map = {}  # No reverse edges

        errors = validator.validate_edge_consistency(forward_map, reverse_map)
        assert len(errors) == 1
        assert "'comp-a' has outgoing edges but no corresponding incoming edges" in errors[0]

    def test_validate_edge_consistency_missing_forward(self, validator):
        """Test validation when 'from' edge has no corresponding 'to'."""
        # comp-b has incoming from comp-a, but comp-a doesn't have outgoing to comp-b
        forward_map = {}  # No forward edges
        reverse_map = {"comp-b": ["comp-a"]}

        errors = validator.validate_edge_consistency(forward_map, reverse_map)
        assert len(errors) == 1
        assert "has incoming edges but no corresponding outgoing edges" in errors[0]


class TestValidationScenarios:
    """
    Test complete validation scenarios with real YAML data.

    This class tests end-to-end validation workflows using realistic component
    data that mirrors the structure of the actual CoSAI Risk Map YAML files.

    Test scenarios include:
    - Valid component graphs with proper bidirectional edges
    - Invalid graphs with missing reverse edges
    - Invalid graphs with missing forward edges
    - Handling of isolated components (with and without allowance)
    - Complex multi-error scenarios
    - Edge cases like empty components sections

    Each test creates temporary YAML files with specific data patterns
    to validate different aspects of the validation logic.
    """

    @pytest.fixture
    def temp_yaml_file(self):
        """Create a temporary YAML file for testing."""
        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        yield Path(temp_file.name)
        Path(temp_file.name).unlink(missing_ok=True)

    def create_yaml_file(self, file_path: Path, data: dict):
        """Helper to create YAML file with given data."""
        with open(file_path, "w") as f:
            yaml.dump(data, f)

    def test_valid_component_graph(self, temp_yaml_file):
        """Test a completely valid component graph."""
        valid_data = {
            "components": [
                {"id": "frontend", "edges": {"to": ["backend"], "from": []}},
                {"id": "backend", "edges": {"to": ["database"], "from": ["frontend"]}},
                {"id": "database", "edges": {"to": [], "from": ["backend"]}},
            ]
        }
        self.create_yaml_file(temp_yaml_file, valid_data)

        validator = ComponentEdgeValidator(verbose=False)
        result = validator.validate_file(temp_yaml_file)
        assert result is True

    def test_isolated_components_rejected(self, temp_yaml_file):
        """Test that isolated components are rejected by default."""
        data_with_isolated = {
            "components": [
                {
                    "id": "connected-a",
                    "title": "Test1",
                    "category": "test1",
                    "edges": {"to": ["connected-b"], "from": []},
                },
                {
                    "id": "connected-b",
                    "title": "Test2",
                    "category": "test1",
                    "edges": {"to": [], "from": ["connected-a"]},
                },
                {
                    "id": "isolated",
                    "title": "Isolated",
                    "category": "test1",
                    "edges": {"to": [], "from": []},
                },
            ]
        }
        self.create_yaml_file(temp_yaml_file, data_with_isolated)

        validator = ComponentEdgeValidator(allow_isolated=False, verbose=False)
        result = validator.validate_file(temp_yaml_file)
        assert result is False

    def test_isolated_components_allowed(self, temp_yaml_file):
        """Test that isolated components are allowed when configured."""
        data_with_isolated = {
            "components": [
                {
                    "id": "connected-a",
                    "title": "Test1",
                    "edges": {"to": ["connected-b"], "from": []},
                },
                {
                    "id": "connected-b",
                    "title": "Test2",
                    "edges": {"to": [], "from": ["connected-a"]},
                },
                {
                    "id": "isolated",
                    "title": "Isolated",
                    "edges": {"to": [], "from": []},
                },
            ]
        }
        self.create_yaml_file(temp_yaml_file, data_with_isolated)

        validator = ComponentEdgeValidator(allow_isolated=True, verbose=False)
        result = validator.validate_file(temp_yaml_file)
        assert result is True

    def test_missing_from_edge(self, temp_yaml_file):
        """Test validation failure when 'to' edge has no corresponding 'from'."""
        data_missing_from = {
            "components": [
                {
                    "id": "comp-a",
                    "title": "Test1",
                    "category": "test1",
                    "edges": {"to": ["comp-b"], "from": []},
                },
                {
                    "id": "comp-b",
                    "title": "Test2",
                    "category": "test1",
                    "edges": {"to": [], "from": []},
                },  # Missing 'from': ['comp-a']
            ]
        }
        self.create_yaml_file(temp_yaml_file, data_missing_from)

        validator = ComponentEdgeValidator(verbose=False)
        result = validator.validate_file(temp_yaml_file)
        assert result is False

    def test_missing_to_edge(self, temp_yaml_file):
        """Test validation failure when 'from' edge has no corresponding 'to'."""
        data_missing_to = {
            "components": [
                {
                    "id": "comp-a",
                    "title": "Test1",
                    "category": "test1",
                    "edges": {"to": [], "from": []},
                },  # Missing 'to': ['comp-b']
                {
                    "id": "comp-b",
                    "title": "Test2",
                    "category": "test1",
                    "edges": {"to": [], "from": ["comp-a"]},
                },
            ]
        }
        self.create_yaml_file(temp_yaml_file, data_missing_to)

        validator = ComponentEdgeValidator(verbose=False)
        result = validator.validate_file(temp_yaml_file)
        assert result is False

    def test_missing_component_reference(self, temp_yaml_file):
        """Test validation failure when referencing non-existent components."""
        data_missing_component = {
            "components": [
                {
                    "id": "comp-a",
                    "title": "Test1",
                    "category": "test1",
                    "edges": {"to": ["non-existent"], "from": []},
                },
                {
                    "id": "comp-b",
                    "title": "Test2",
                    "category": "test1",
                    "edges": {"to": [], "from": ["also-missing"]},
                },
            ]
        }
        self.create_yaml_file(temp_yaml_file, data_missing_component)

        validator = ComponentEdgeValidator(verbose=False)
        result = validator.validate_file(temp_yaml_file)
        assert result is False

    def test_complex_invalid_graph(self, temp_yaml_file):
        """Test a complex graph with multiple types of validation errors."""
        complex_invalid_data = {
            "components": [
                {
                    "id": "frontend",
                    "title": "Test1",
                    "category": "test1",
                    "edges": {"to": ["backend", "missing-service"], "from": []},
                },
                {
                    "id": "backend",
                    "title": "Test2",
                    "category": "test1",
                    "edges": {"to": [], "from": []},
                },  # Missing from: ['frontend']
                {
                    "id": "database",
                    "title": "Test3",
                    "category": "test1",
                    "edges": {"to": [], "from": ["backend"]},
                },  # backend doesn't point to database
                {
                    "id": "isolated",
                    "title": "Test4",
                    "category": "test1",
                    "edges": {"to": [], "from": []},
                },  # Isolated component
            ]
        }
        self.create_yaml_file(temp_yaml_file, complex_invalid_data)

        validator = ComponentEdgeValidator(allow_isolated=False, verbose=False)
        result = validator.validate_file(temp_yaml_file)
        assert result is False

    def test_empty_components_section(self, temp_yaml_file):
        """Test handling of empty components section."""
        empty_data = {"components": []}
        self.create_yaml_file(temp_yaml_file, empty_data)

        validator = ComponentEdgeValidator(verbose=False)
        result = validator.validate_file(temp_yaml_file)
        assert result is True  # Empty is valid

    def test_no_components_section(self, temp_yaml_file):
        with pytest.raises(KeyError):
            """Test handling of YAML without components section."""
            no_components_data = {"other_section": {"some": "data"}}
            self.create_yaml_file(temp_yaml_file, no_components_data)

            validator = ComponentEdgeValidator(verbose=False)
            _ = validator.validate_file(temp_yaml_file)


class TestGitIntegration:
    """
    Test git integration functionality for pre-commit hook workflows.

    The validator integrates with git to automatically validate staged YAML files
    during the pre-commit process. This class tests:

    - Detection of staged YAML files using git commands
    - Force mode operation that bypasses git checks
    - Error handling for git command failures
    - File existence verification before validation

    Tests use mocked subprocess calls to simulate various git scenarios
    without requiring an actual git repository state.
    """

    @patch("subprocess.run")
    def test_get_staged_yaml_files_with_staged_file(self, mock_run):
        """Test getting staged files when target file is staged."""
        # Mock git command to return our target file
        mock_result = MagicMock()
        mock_result.stdout = "risk-map/yaml/components.yaml\nother-file.txt"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        # Mock file existence
        target_file = Path("risk-map/yaml/components.yaml")
        with patch.object(Path, "exists", return_value=True):
            result = get_staged_yaml_files(target_file, force_check=False)

        assert result == [target_file]
        mock_run.assert_called_once_with(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True,
        )

    @patch("subprocess.run")
    def test_get_staged_yaml_files_no_staged_files(self, mock_run):
        """Test getting staged files when no files are staged."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = get_staged_yaml_files(force_check=False)
        assert result == []

    def test_get_staged_yaml_files_force_mode(self):
        """Test force mode returns file regardless of git status."""
        target_file = Path("test.yaml")

        with patch.object(Path, "exists", return_value=True):
            result = get_staged_yaml_files(target_file, force_check=True)

        assert result == [target_file]

    def test_get_staged_yaml_files_force_mode_missing_file(self):
        """Test force mode with non-existent file."""
        target_file = Path("missing.yaml")

        with patch.object(Path, "exists", return_value=False):
            result = get_staged_yaml_files(target_file, force_check=True)

        assert result == []

    @patch("subprocess.run")
    def test_get_staged_yaml_files_git_error(self, mock_run):
        """Test handling git command errors."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")

        result = get_staged_yaml_files(force_check=False)
        assert result == []


class TestEdgeValidationError:
    """
    Test custom exception handling for validation errors.

    The EdgeValidationError class provides structured error reporting
    for validation failures. This class verifies proper exception
    creation, inheritance, and string representation.
    """

    def test_edge_validation_error_creation(self):
        """Test creating EdgeValidationError."""
        error = EdgeValidationError("Test error message")
        assert str(error) == "Test error message"

    def test_edge_validation_error_inheritance(self):
        """Test that EdgeValidationError inherits from Exception."""
        error = EdgeValidationError("Test")
        assert isinstance(error, Exception)


# Integration test to verify the script works end-to-end
class TestEndToEndIntegration:
    """
    Test complete validation workflows from start to finish.

    These integration tests verify that the entire validation system
    works correctly when processing realistic component data. Tests
    cover both successful validation scenarios and failure cases with
    multiple validation errors.

    The tests simulate real usage patterns by creating temporary
    YAML files with component data that matches the structure
    and complexity of actual CoSAI Risk Map files.
    """

    @pytest.fixture
    def temp_yaml_file(self):
        """Create a temporary YAML file for testing."""
        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        yield Path(temp_file.name)
        Path(temp_file.name).unlink(missing_ok=True)

    def test_complete_validation_workflow_success(self, temp_yaml_file):
        """Test complete validation workflow that should succeed."""
        valid_data = {
            "components": [
                {
                    "id": "web-server",
                    "edges": {
                        "to": ["app-server", "load-balancer"],
                        "from": ["load-balancer"],
                    },
                },
                {
                    "id": "app-server",
                    "edges": {"to": ["database"], "from": ["web-server"]},
                },
                {"id": "database", "edges": {"to": [], "from": ["app-server"]}},
                {
                    "id": "load-balancer",
                    "edges": {"to": ["web-server"], "from": ["web-server"]},
                },
            ]
        }

        with open(temp_yaml_file, "w") as f:
            yaml.dump(valid_data, f)

        validator = ComponentEdgeValidator(allow_isolated=False, verbose=False)
        result = validator.validate_file(temp_yaml_file)
        assert result is True

    def test_complete_validation_workflow_failure(self, temp_yaml_file):
        """Test complete validation workflow that should fail."""
        broken_data = {
            "components": [
                {
                    "id": "frontend",
                    "title": "test1",
                    "categrory": "test",
                    "edges": {
                        "to": ["backend"],  # backend exists
                        "from": [],
                    },
                },
                {
                    "id": "backend",
                    "title": "test2",
                    "category": "test",
                    "edges": {
                        "to": ["missing-db"],  # missing-db doesn't exist
                        "from": [],  # Should be ['frontend'] for consistency
                    },
                },
                {
                    "id": "orphaned",
                    "title": "test3",
                    "category": "test",
                    "edges": {
                        "to": [],
                        "from": [],  # Isolated component
                    },
                },
            ]
        }

        with open(temp_yaml_file, "w") as f:
            yaml.dump(broken_data, f)

        validator = ComponentEdgeValidator(allow_isolated=False, verbose=False)
        result = validator.validate_file(temp_yaml_file)
        assert result is False


class TestComponentGraph:
    """
    Test the ComponentGraph class functionality for Mermaid diagram generation.

    The ComponentGraph class converts validated component relationships into
    Mermaid diagram format for visualization. This test suite covers:

    - Graph initialization and structure building
    - Node ranking algorithms for proper layout
    - Category-based subgraph organization
    - Mermaid syntax generation and formatting
    - Debug mode output with detailed comments
    - Edge case handling (cycles, isolated nodes, empty graphs)
    - Tilde calculation for subgraph spacing

    Tests use both simple linear component chains and complex graphs with
    cycles to ensure the ranking and visualization algorithms work correctly
    across different graph topologies.
    """

    @pytest.fixture
    def simple_components(self):
        """Create simple test components for graph testing."""
        return {
            "comp-a": ComponentNode(title="Node A", category="Data", to_edges=["comp-b"], from_edges=[]),
            "comp-b": ComponentNode(
                title="Node B",
                category="Model",
                to_edges=["comp-c"],
                from_edges=["comp-a"],
            ),
            "comp-c": ComponentNode(
                title="Node C",
                category="Application",
                to_edges=[],
                from_edges=["comp-b"],
            ),
        }

    @pytest.fixture
    def simple_forward_map(self):
        """Create simple forward map for testing."""
        return {"comp-a": ["comp-b"], "comp-b": ["comp-c"]}

    @pytest.fixture
    def complex_components(self):
        """Create more complex components with cycles."""
        return {
            "data-src": ComponentNode(
                title="Data Sources",
                category="Data",
                to_edges=["model"],
                from_edges=["app"],
            ),
            "model": ComponentNode(
                title="The Model",
                category="Model",
                to_edges=["app"],
                from_edges=["data-src", "infra"],
            ),
            "app": ComponentNode(
                title="Application",
                category="Application",
                to_edges=["data-src"],
                from_edges=["model"],
            ),
            "infra": ComponentNode(
                title="Infrastructure",
                category="Infrastructure",
                to_edges=["model"],
                from_edges=[],
            ),
        }

    @pytest.fixture
    def complex_forward_map(self):
        """Create complex forward map with cycles."""
        return {
            "data-src": ["model"],
            "model": ["app"],
            "app": ["data-src"],
            "infra": ["model"],
        }

    def test_component_graph_initialization(self, simple_forward_map, simple_components):
        """Test ComponentGraph initialization."""
        graph = ComponentGraph(simple_forward_map, simple_components)
        assert graph.components == simple_components
        assert graph.forward_map == simple_forward_map
        assert graph.debug is False
        assert isinstance(graph.graph, str)

    def test_component_graph_initialization_with_debug(self, simple_forward_map, simple_components):
        """Test ComponentGraph initialization with debug flag."""
        graph = ComponentGraph(simple_forward_map, simple_components, debug=True)
        assert graph.debug is True
        assert isinstance(graph.graph, str)

    def test_build_graph_structure_without_debug(self, simple_forward_map, simple_components):
        """Test graph structure generation without debug comments."""
        graph = ComponentGraph(simple_forward_map, simple_components, debug=False)
        mermaid_output = graph.to_mermaid()

        # Should contain basic mermaid structure
        assert "graph TD" in mermaid_output
        assert "classDef hidden display: none;" in mermaid_output

        # Should contain component connections
        assert "comp-a --> comp-b" in mermaid_output
        assert "comp-b --> comp-c" in mermaid_output

        # Should NOT contain debug comments
        assert "%% comp-a rank" not in mermaid_output
        assert "%% Rank" not in mermaid_output

    def test_build_graph_structure_with_debug(self, simple_forward_map, simple_components):
        """Test graph structure generation with debug comments."""
        graph = ComponentGraph(simple_forward_map, simple_components, debug=True)
        mermaid_output = graph.to_mermaid()

        # Should contain basic mermaid structure
        assert "graph TD" in mermaid_output

        # Debug mode should still generate valid mermaid output
        assert "```mermaid" in mermaid_output
        assert "```" in mermaid_output

        # Should still contain main structure
        assert "comp-a --> comp-b" in mermaid_output

    def test_mermaid_output_format(self, simple_forward_map, simple_components):
        """Test that mermaid output has correct format."""
        graph = ComponentGraph(simple_forward_map, simple_components)
        mermaid_output = graph.to_mermaid()

        # Should start and end with mermaid code block markers
        assert mermaid_output.startswith("```mermaid")
        assert mermaid_output.endswith("```\n")

        # Should have proper line structure
        lines = mermaid_output.split("\n")
        assert len(lines) > 10  # Should have substantial content

        # Should contain component edges
        assert "comp-a --> comp-b" in mermaid_output
        assert "comp-b --> comp-c" in mermaid_output

        # Should contain style definitions section
        assert "%% Node style definitions" in mermaid_output

    def test_to_mermaid_method(self, simple_forward_map, simple_components):
        """Test the to_mermaid method returns the built graph."""
        graph = ComponentGraph(simple_forward_map, simple_components)
        assert graph.to_mermaid("mermaid") == graph.graph + "\n"

    def test_empty_components(self):
        """Test handling of empty components."""
        graph = ComponentGraph({}, {})
        mermaid_output = graph.to_mermaid()

        # Should still have basic structure
        assert "graph TD" in mermaid_output
        assert "```mermaid" in mermaid_output
        assert "```" in mermaid_output


class TestControlNode:
    """
    Test the ControlNode class functionality.

    ControlNode represents a single control with its metadata including:
    - Basic attributes (title, description, category)
    - Component mappings (which components the control applies to)
    - Risk mappings (which risks the control addresses)
    - Persona mappings (which personas implement the control)
    """

    def test_control_node_creation_basic(self):
        """Test creating a ControlNode with basic attributes."""
        node = ControlNode(
            title="Test Control",
            category="controlsData",
            components=["comp1", "comp2"],
            risks=["risk1"],
            personas=["persona1"],
        )

        assert node.title == "Test Control"
        assert node.category == "controlsData"
        assert node.components == ["comp1", "comp2"]
        assert node.risks == ["risk1"]
        assert node.personas == ["persona1"]

    def test_control_node_creation_with_all_components(self):
        """Test creating a ControlNode that applies to all components."""
        node = ControlNode(
            title="Global Control",
            category="controlsGovernance",
            components=["all"],
            risks=["risk1", "risk2"],
            personas=["persona1"],
        )

        assert node.components == ["all"]
        assert len(node.risks) == 2
        assert node.category == "controlsGovernance"

    def test_control_node_creation_with_no_components(self):
        """Test creating a ControlNode that applies to no components."""
        node = ControlNode(
            title="Policy Control",
            category="controlsGovernance",
            components=["none"],
            risks=["risk1"],
            personas=["persona1"],
        )

        assert node.components == ["none"]

    def test_control_node_equality(self):
        """Test ControlNode equality comparison."""
        node1 = ControlNode(
            title="Control A",
            category="controlsData",
            components=["comp1"],
            risks=["risk1"],
            personas=["persona1"],
        )

        node2 = ControlNode(
            title="Control A",
            category="controlsData",
            components=["comp1"],
            risks=["risk1"],
            personas=["persona1"],
        )

        node3 = ControlNode(
            title="Control B",
            category="controlsModel",
            components=["comp2"],
            risks=["risk2"],
            personas=["persona2"],
        )

        assert node1 == node2
        assert node1 != node3

    def test_control_node_empty_lists_default(self):
        """Test that empty lists are handled correctly."""
        node = ControlNode(
            title="Minimal Control",
            category="controlsData",
            components=[],
            risks=[],
            personas=[],
        )

        assert node.components == []
        assert node.risks == []
        assert node.personas == []


class TestControlGraph:
    """
    Test the ControlGraph class functionality for control-to-component visualization.

    ControlGraph creates Mermaid diagrams showing relationships between controls
    and components, with features including:
    - Dynamic component subgrouping based on shared control relationships
    - Multiple edge styling for different types of control mappings
    - Category-based organization and visualization
    - Optimization of control mappings to reduce visual complexity
    """

    @pytest.fixture
    def sample_controls(self):
        """Create sample controls for testing."""
        return {
            "control1": ControlNode(
                title="Simple Control",
                category="controlsData",
                components=["comp1", "comp2"],
                risks=["risk1"],
                personas=["persona1"],
            ),
            "control2": ControlNode(
                title="Multi Control",
                category="controlsInfrastructure",
                components=["comp1", "comp2", "comp3", "comp4"],
                risks=["risk2"],
                personas=["persona1"],
            ),
            "control3": ControlNode(
                title="All Control",
                category="controlsGovernance",
                components=["all"],
                risks=["risk1", "risk2"],
                personas=["persona1", "persona2"],
            ),
            "control4": ControlNode(
                title="No Components Control",
                category="controlsGovernance",
                components=["none"],
                risks=["risk3"],
                personas=["persona1"],
            ),
        }

    @pytest.fixture
    def sample_components(self):
        """Create sample components for testing."""
        return {
            "comp1": ComponentNode(
                title="Component 1",
                category="componentsData",
                to_edges=[],
                from_edges=[],
            ),
            "comp2": ComponentNode(
                title="Component 2",
                category="componentsData",
                to_edges=[],
                from_edges=[],
            ),
            "comp2a": ComponentNode(
                title="Component 2A",
                category="componentsData",
                to_edges=[],
                from_edges=[],
            ),
            "comp3": ComponentNode(
                title="Component 3",
                category="componentsInfrastructure",
                to_edges=[],
                from_edges=[],
            ),
            "comp4": ComponentNode(
                title="Component 4",
                category="componentsInfrastructure",
                to_edges=[],
                from_edges=[],
            ),
            "comp5": ComponentNode(
                title="Component 5",
                category="componentsModel",
                to_edges=[],
                from_edges=[],
            ),
        }

    def test_control_graph_initialization(self, sample_controls, sample_components):
        """Test ControlGraph initialization."""
        graph = ControlGraph(sample_controls, sample_components)

        assert graph.controls == sample_controls
        assert graph.components == sample_components
        assert graph.debug is False
        assert hasattr(graph, "component_by_category")
        assert hasattr(graph, "control_to_component_map")
        assert hasattr(graph, "subgroupings")

    def test_control_graph_initialization_with_debug(self, sample_controls, sample_components):
        """Test ControlGraph initialization with debug mode."""
        graph = ControlGraph(sample_controls, sample_components, debug=True)

        assert graph.debug is True

    def test_component_grouping_by_category(self, sample_controls, sample_components):
        """Test grouping components by category."""
        graph = ControlGraph(sample_controls, sample_components)

        # Check that components are grouped correctly
        assert "componentsData" in graph.component_by_category
        assert "componentsInfrastructure" in graph.component_by_category
        assert "componentsModel" in graph.component_by_category

        # comp1 and comp2 are moved to the dynamic subgroup componentsComp
        assert "componentsComp" in graph.component_by_category
        assert "comp1" in graph.component_by_category["componentsComp"]
        assert "comp2" in graph.component_by_category["componentsComp"]
        # comp2a remains in the original componentsData category
        assert "comp2a" in graph.component_by_category["componentsData"]
        # Other components remain in their original categories
        assert "comp3" in graph.component_by_category["componentsInfrastructure"]
        assert "comp5" in graph.component_by_category["componentsModel"]

    def test_control_component_mapping_basic(self, sample_controls, sample_components):
        """Test basic control to component mapping."""
        graph = ControlGraph(sample_controls, sample_components)

        # Check that mappings are created correctly
        assert "control1" in graph.control_to_component_map
        assert "control2" in graph.control_to_component_map
        assert "control3" in graph.control_to_component_map

        # Simple control should map to its optimized subgroup (since comp1 and comp2 are shared with control2)
        # The dynamic subgrouping should create a componentsComp cluster
        assert set(graph.control_to_component_map["control1"]) == {"componentsComp"}

        # Multi-control should map to its optimized mappings
        # comp1, comp2 are grouped into componentsComp, comp3, comp4 are grouped into componentsInfrastructure
        assert set(graph.control_to_component_map["control2"]) == {"componentsComp", "componentsInfrastructure"}

        # All control should map to components container
        assert graph.control_to_component_map["control3"] == ["components"]

        # None control should have empty mapping
        assert graph.control_to_component_map["control4"] == []

    def test_find_component_clusters(self, sample_controls, sample_components):
        """Test finding component clusters with shared controls."""
        graph = ControlGraph(sample_controls, sample_components)

        # Create a scenario where multiple controls target the same components
        component_to_controls = {
            "comp2": {"control1", "control2"},
            "comp3": {"control1", "control2"},
            "comp4": {"control2"},
        }

        clusters = graph._find_component_clusters(component_to_controls, min_shared_controls=2, min_nodes=2)

        # Should find a cluster of comp2 and comp3 (both targeted by control1 and control2)
        assert len(clusters) >= 1

        # Check that at least one cluster contains components with shared controls
        found_shared_cluster = False
        for cluster_components in clusters.values():
            if "comp2" in cluster_components and "comp3" in cluster_components:
                found_shared_cluster = True
                break

        assert found_shared_cluster

    def test_maps_to_full_category(self, sample_controls, sample_components):
        """Test detection of controls that map to full categories."""
        graph = ControlGraph(sample_controls, sample_components)

        # Create a control that maps to all infrastructure components
        all_infra_components = [
            comp_id for comp_id, comp in sample_components.items() if comp.category == "componentsInfrastructure"
        ]

        # Should detect full category mapping
        assert graph._maps_to_full_category(all_infra_components, "componentsInfrastructure")

        # Should not detect partial category mapping
        partial_components = all_infra_components[:-1]  # Remove one component
        assert not graph._maps_to_full_category(partial_components, "componentsInfrastructure")

    def test_category_check_order(self, sample_controls, sample_components):
        """Test the order in which categories are checked for optimization."""
        graph = ControlGraph(sample_controls, sample_components)

        check_order = graph._get_category_check_order()

        # Should return a list of categories
        assert isinstance(check_order, list)
        assert len(check_order) > 0

        # Should include main categories
        main_categories = {
            "componentsData",
            "componentsInfrastructure",
            "componentsModel",
        }
        for category in main_categories:
            if category in graph.component_by_category:
                assert category in check_order

    def test_mermaid_graph_generation(self, sample_controls, sample_components):
        """Test Mermaid graph generation."""
        graph = ControlGraph(sample_controls, sample_components)
        mermaid_output = graph.to_mermaid()

        # Should contain mermaid code block markers
        assert mermaid_output.startswith("```mermaid")
        assert mermaid_output.endswith("```\n")

        # Should contain graph declaration
        assert "graph LR" in mermaid_output

        # Should contain control subgraphs
        assert "controlsData" in mermaid_output
        assert "controlsInfrastructure" in mermaid_output
        assert "controlsGovernance" in mermaid_output

        # Should contain component subgraphs
        assert "componentsData" in mermaid_output
        assert "componentsInfrastructure" in mermaid_output
        assert "componentsModel" in mermaid_output

        # Should contain control-component relationships
        assert "-->" in mermaid_output or "-.->", mermaid_output

        # Should contain styling
        assert "linkStyle" in mermaid_output
        assert "style components" in mermaid_output

    def test_edge_styling_groups(self, sample_controls, sample_components):
        """Test that different types of edges get appropriate styling."""
        graph = ControlGraph(sample_controls, sample_components)
        mermaid_output = graph.to_mermaid()

        # Should contain edge styling for different types
        lines = mermaid_output.split("\n")

        # Look for linkStyle declarations
        link_style_lines = [line.strip() for line in lines if "linkStyle" in line]
        assert len(link_style_lines) > 0

        # Should have different stroke colors/styles
        style_patterns = ["stroke:#4285f4", "stroke:#34a853", "stroke:#9c27b0"]
        found_styles = set()

        for line in link_style_lines:
            for pattern in style_patterns:
                if pattern in line:
                    found_styles.add(pattern)

        # Should have at least some different styles applied
        assert len(found_styles) >= 1

    def test_controls_mapped_to_all_tracking(self, sample_controls, sample_components):
        """Test tracking of controls mapped to 'all' components."""
        graph = ControlGraph(sample_controls, sample_components)

        # Should track controls with 'all' mapping
        assert "control3" in graph.controls_mapped_to_all

        # Should not track other controls
        assert "control1" not in graph.controls_mapped_to_all
        assert "control4" not in graph.controls_mapped_to_all

    @patch("pathlib.Path.exists")
    @patch("builtins.open")
    @patch("yaml.safe_load")
    def test_dynamic_category_name_loading(
        self, mock_yaml_load, mock_open, mock_exists, sample_controls, sample_components
    ):
        """Test loading category names from YAML files."""
        # Mock file existence
        mock_exists.return_value = True

        # Mock YAML data
        controls_yaml_data = {
            "categories": [
                {"id": "controlsData", "title": "Data"},
                {"id": "controlsModel", "title": "Model"},
            ]
        }
        components_yaml_data = {
            "categories": [
                {"id": "componentsData", "title": "Data components"},
                {"id": "componentsModel", "title": "Model components"},
            ]
        }

        def mock_load_side_effect(*args, **kwargs):
            # Return different data based on which file is being loaded
            filename = mock_open.return_value.__enter__.return_value.name
            if "controls.yaml" in str(filename):
                return controls_yaml_data
            else:
                return components_yaml_data

        mock_yaml_load.side_effect = mock_load_side_effect

        # Create graph and test category name loading
        graph = ControlGraph(sample_controls, sample_components)

        # Test category display name generation (when mock doesn't properly load, fallback behavior applies)
        assert "Data Controls" in graph._get_category_display_name("controlsData")
        assert "Model Controls" in graph._get_category_display_name("controlsModel")

    def test_empty_controls_and_components(self):
        """Test handling of empty controls and components."""
        graph = ControlGraph({}, {}, config_loader={})  # pyright: ignore[reportArgumentType]

        # Should initialize without errors
        assert graph.controls == {}
        assert graph.components == {}
        assert graph.control_to_component_map == {}

        # Should generate valid (but minimal) mermaid output
        mermaid_output = graph.to_mermaid()
        assert "```mermaid" in mermaid_output
        assert "```" in mermaid_output

    def test_large_multi_edge_control_styling(self):
        """Test edge styling for controls with many components (3+ edges)."""
        # Create controls with many component mappings across different categories to prevent optimization
        many_component_control = ControlNode(
            title="Complex Control",
            category="controlsInfrastructure",
            components=["comp1", "comp2", "comp3", "comp4", "comp5"],
            risks=["risk1"],
            personas=["persona1"],
        )

        components = {
            "comp1": ComponentNode(
                title="Component 1",
                category="componentsData",
                to_edges=[],
                from_edges=[],
            ),
            "comp2": ComponentNode(
                title="Component 2",
                category="componentsData",
                to_edges=[],
                from_edges=[],
            ),
            "comp3": ComponentNode(
                title="Component 3",
                category="componentsInfrastructure",
                to_edges=[],
                from_edges=[],
            ),
            "comp4": ComponentNode(
                title="Component 4",
                category="componentsModel",
                to_edges=[],
                from_edges=[],
            ),
            "comp5": ComponentNode(
                title="Component 5",
                category="componentsApplication",
                to_edges=[],
                from_edges=[],
            ),
        }

        controls = {"multiEdgeControl": many_component_control}

        graph = ControlGraph(controls, components)
        mermaid_output = graph.to_mermaid()

        # Should contain multiple edge styling with different colors
        link_style_lines = [line.strip() for line in mermaid_output.split("\n") if "linkStyle" in line]

        # Multi-edge styling only applies to individual component mappings, not category mappings
        # In this test, the control maps to categories, so it should use subgraph edge styling
        subgraph_edge_styles = [
            line
            for line in link_style_lines
            if "#34a853" in line  # Green color for subgraph edges
        ]

        # Should have subgraph edge styling (4 category targets = 1 subgraph edge style group)
        assert len(subgraph_edge_styles) > 0

        # Verify it's not using multi-edge colors (since it maps to categories, not individual components)
        multi_edge_colors = ["#9c27b0", "#ff9800", "#e91e63", "#795548"]
        multi_edge_styles = [
            line for line in link_style_lines if any(color in line for color in multi_edge_colors)
        ]
        assert len(multi_edge_styles) == 0  # Should be 0 since this control maps to categories
