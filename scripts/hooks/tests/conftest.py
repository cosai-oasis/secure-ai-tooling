"""
Shared test fixtures and configuration for the CoSAI Risk Map test suite.

This module provides common fixtures, mock objects, and test data used across
multiple test modules in the validation system test suite.
"""

# Import test modules for type hints and fixtures
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from riskmap_validator.models import ComponentNode, ControlNode, RiskNode
from riskmap_validator.validator import ComponentEdgeValidator

# ============================================================================
# Repository Path Fixtures - Dynamic Path Resolution
# ============================================================================


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """
    Dynamically find the repository root directory.

    This fixture works in any environment:
    - devcontainer (/workspaces/secure-ai-tooling)
    - GitHub Actions ($GITHUB_WORKSPACE)
    - local development (any path)

    Returns:
        Path: Absolute path to repository root

    Implementation:
        1. First tries git command (most reliable)
        2. Falls back to navigating up from this file's location
    """
    try:
        # Try git method first (most reliable across environments)
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback: navigate up from this file's location
        # conftest.py is at scripts/hooks/tests/conftest.py
        # Go up 4 levels: tests -> hooks -> scripts -> repo_root
        return Path(__file__).resolve().parent.parent.parent.parent


@pytest.fixture(scope="session")
def risk_map_yaml_dir(repo_root: Path) -> Path:
    """
    Path to risk-map/yaml directory.

    Args:
        repo_root: Repository root path fixture

    Returns:
        Path: Absolute path to risk-map/yaml directory
    """
    return repo_root / "risk-map" / "yaml"


@pytest.fixture(scope="session")
def risk_map_schemas_dir(repo_root: Path) -> Path:
    """
    Path to risk-map/schemas directory.

    Args:
        repo_root: Repository root path fixture

    Returns:
        Path: Absolute path to risk-map/schemas directory
    """
    return repo_root / "risk-map" / "schemas"


@pytest.fixture(scope="session")
def frameworks_yaml_path(risk_map_yaml_dir: Path) -> Path:
    """
    Path to frameworks.yaml file.

    Args:
        risk_map_yaml_dir: YAML directory path fixture

    Returns:
        Path: Absolute path to frameworks.yaml
    """
    return risk_map_yaml_dir / "frameworks.yaml"


@pytest.fixture(scope="session")
def controls_yaml_path(risk_map_yaml_dir: Path) -> Path:
    """
    Path to controls.yaml file.

    Args:
        risk_map_yaml_dir: YAML directory path fixture

    Returns:
        Path: Absolute path to controls.yaml
    """
    return risk_map_yaml_dir / "controls.yaml"


@pytest.fixture(scope="session")
def risks_yaml_path(risk_map_yaml_dir: Path) -> Path:
    """
    Path to risks.yaml file.

    Args:
        risk_map_yaml_dir: YAML directory path fixture

    Returns:
        Path: Absolute path to risks.yaml
    """
    return risk_map_yaml_dir / "risks.yaml"


@pytest.fixture(scope="session")
def frameworks_schema_path(risk_map_schemas_dir: Path) -> Path:
    """
    Path to frameworks.schema.json file.

    Args:
        risk_map_schemas_dir: Schemas directory path fixture

    Returns:
        Path: Absolute path to frameworks.schema.json
    """
    return risk_map_schemas_dir / "frameworks.schema.json"


@pytest.fixture(scope="session")
def personas_yaml_path(risk_map_yaml_dir: Path) -> Path:
    """
    Path to personas.yaml file.

    Args:
        risk_map_yaml_dir: YAML directory path fixture

    Returns:
        Path: Absolute path to personas.yaml
    """
    return risk_map_yaml_dir / "personas.yaml"


@pytest.fixture(scope="session")
def personas_schema_path(risk_map_schemas_dir: Path) -> Path:
    """
    Path to personas.schema.json file.

    Args:
        risk_map_schemas_dir: Schemas directory path fixture

    Returns:
        Path: Absolute path to personas.schema.json
    """
    return risk_map_schemas_dir / "personas.schema.json"


@pytest.fixture(scope="session")
def base_uri(risk_map_schemas_dir: Path) -> str:
    """
    Base URI for schema validation with check-jsonschema.

    Args:
        risk_map_schemas_dir: Schemas directory path fixture

    Returns:
        str: file:// URI for schema base directory
    """
    return f"file://{risk_map_schemas_dir}/"


# ============================================================================
# Component and Control Fixtures
# ============================================================================


@pytest.fixture
def sample_components():
    """Sample component data for testing."""
    return {
        "componentDataSources": ComponentNode(
            title="Data Sources", category="componentsData", to_edges=["componentDataValidation"], from_edges=[]
        ),
        "componentDataValidation": ComponentNode(
            title="Data Validation",
            category="componentsData",
            to_edges=["componentModelTraining"],
            from_edges=["componentDataSources"],
        ),
        "componentModelTraining": ComponentNode(
            title="Model Training",
            category="componentsModel",
            to_edges=["componentModelDeployment"],
            from_edges=["componentDataValidation"],
        ),
        "componentModelDeployment": ComponentNode(
            title="Model Deployment",
            category="componentsInfrastructure",
            to_edges=[],
            from_edges=["componentModelTraining"],
        ),
    }


@pytest.fixture
def sample_controls():
    """Sample control data for testing."""
    return {
        "controlInputValidation": ControlNode(
            title="Input Validation",
            category="controlsData",
            components=["componentDataSources", "componentDataValidation"],
            risks=["DP", "PIJ"],
            personas=["personaModelCreator"],
        ),
        "controlModelIntegrity": ControlNode(
            title="Model Integrity Management",
            category="controlsModel",
            components=["componentModelTraining", "componentModelDeployment"],
            risks=["MST", "MDT"],
            personas=["personaModelCreator", "personaModelConsumer"],
        ),
        "controlUniversalSecurity": ControlNode(
            title="Universal Security Controls",
            category="controlsGovernance",
            components=["all"],
            risks=["all"],
            personas=["personaModelCreator", "personaModelConsumer"],
        ),
    }


@pytest.fixture
def sample_risks():
    """Sample risk data for testing."""
    return {
        "DP": RiskNode(title="Data Poisoning", category="risks"),
        "PIJ": RiskNode(title="Prompt Injection", category="risks"),
        "MST": RiskNode(title="Model Source Tampering", category="risks"),
        "MDT": RiskNode(title="Model Deployment Tampering", category="risks"),
        "OrphanRisk": RiskNode(title="Orphaned Risk", category="risks"),
    }


@pytest.fixture
def sample_personas():
    """Sample persona data for testing yaml_to_markdown persona generators."""
    return {
        "personas": [
            {
                "id": "personaTest1",
                "title": "Test Persona Active",
                "description": ["An active test persona"],
                "responsibilities": ["Responsibility 1", "Responsibility 2"],
                "identificationQuestions": ["Question 1?", "Question 2?"],
                "mappings": {"iso-22989": ["AI Producer"]},
            },
            {
                "id": "personaTest2",
                "title": "Test Persona Deprecated",
                "description": ["A deprecated test persona"],
                "deprecated": True,
            },
        ]
    }


@pytest.fixture
def sample_personas_minimal():
    """Minimal persona data for testing xref generators."""
    return {
        "personas": [
            {"id": "personaTest1", "title": "Test Persona 1"},
            {"id": "personaTest2", "title": "Test Persona 2"},
        ]
    }


@pytest.fixture
def sample_component_yaml():
    """Sample YAML content for component testing."""
    return """
title: Test Components
description: Test component data for validation
components:
  - id: componentDataSources
    title: Data Sources
    category: componentsData
    outgoing_edges:
      - componentDataValidation

  - id: componentDataValidation
    title: Data Validation
    category: componentsData
    incoming_edges:
      - componentDataSources
    outgoing_edges:
      - componentModelTraining

  - id: componentModelTraining
    title: Model Training
    category: componentsModel
    incoming_edges:
      - componentDataValidation
    outgoing_edges:
      - componentModelDeployment

  - id: componentModelDeployment
    title: Model Deployment
    category: componentsInfrastructure
    incoming_edges:
      - componentModelTraining
"""


@pytest.fixture
def sample_controls_yaml():
    """Sample YAML content for controls testing."""
    return """
title: Test Controls
description: Test control data for validation
controls:
  - id: controlInputValidation
    title: Input Validation
    category: controlsData
    components:
      - componentDataSources
      - componentDataValidation
    risks:
      - DP
      - PIJ
    personas:
      - personaModelCreator

  - id: controlModelIntegrity
    title: Model Integrity Management
    category: controlsModel
    components:
      - componentModelTraining
      - componentModelDeployment
    risks:
      - MST
      - MDT
    personas:
      - personaModelCreator
      - personaModelConsumer
"""


@pytest.fixture
def sample_risks_yaml():
    """Sample YAML content for risks testing."""
    return """
title: Test Risks
description: Test risk data for validation
risks:
  - id: DP
    title: Data Poisoning
    personas:
      - personaModelCreator
    controls:
      - controlInputValidation

  - id: PIJ
    title: Prompt Injection
    personas:
      - personaModelCreator
    controls:
      - controlInputValidation

  - id: MST
    title: Model Source Tampering
    personas:
      - personaModelCreator
    controls:
      - controlModelIntegrity

  - id: MDT
    title: Model Deployment Tampering
    personas:
      - personaModelCreator
      - personaModelConsumer
    controls:
      - controlModelIntegrity
"""


@pytest.fixture
def invalid_component_yaml():
    """Invalid YAML content for error testing."""
    return """
title: Invalid Components
components:
  - id: componentA
    title: Component A
    outgoing_edges:
      - componentB
      # Missing componentB definition - will cause validation error
"""


@pytest.fixture
def temp_yaml_file():
    """Create a temporary YAML file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yield Path(f.name)
    # Cleanup handled by tempfile


@pytest.fixture
def temp_directory():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def mock_git_repo():
    """Mock git repository for testing git integration."""
    with patch("subprocess.run") as mock_run:
        # Configure mock to simulate successful git operations
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "risk-map/yaml/components.yaml\n"
        mock_run.return_value.stderr = ""
        yield mock_run


@pytest.fixture
def validator_instance():
    """Create a ComponentEdgeValidator instance for testing."""
    return ComponentEdgeValidator()


@pytest.fixture
def isolated_component_yaml():
    """YAML with isolated component for testing isolation detection."""
    return """
title: Components with Isolation
components:
  - id: componentConnected
    title: Connected Component
    outgoing_edges:
      - componentAlsoConnected

  - id: componentAlsoConnected
    title: Also Connected Component
    incoming_edges:
      - componentConnected

  - id: componentIsolated
    title: Isolated Component
    # No edges - this component is isolated
"""


@pytest.fixture
def bidirectional_error_yaml():
    """YAML with bidirectional edge errors for testing edge validation."""
    return """
title: Components with Edge Errors
components:
  - id: componentA
    title: Component A
    outgoing_edges:
      - componentB
      # componentB should have incoming edge from componentA but doesn't

  - id: componentB
    title: Component B
    outgoing_edges:
      - componentC

  - id: componentC
    title: Component C
    # Missing incoming edge from componentB
"""


@pytest.fixture
def complex_component_graph():
    """Complex component graph for advanced testing scenarios."""
    return {
        "componentDataIngestion": ComponentNode(
            title="Data Ingestion",
            category="componentsData",
            to_edges=["componentDataPreprocessing", "componentDataValidation"],
            from_edges=[],
        ),
        "componentDataPreprocessing": ComponentNode(
            title="Data Preprocessing",
            category="componentsData",
            to_edges=["componentFeatureEngineering"],
            from_edges=["componentDataIngestion"],
        ),
        "componentDataValidation": ComponentNode(
            title="Data Validation",
            category="componentsData",
            to_edges=["componentFeatureEngineering"],
            from_edges=["componentDataIngestion"],
        ),
        "componentFeatureEngineering": ComponentNode(
            title="Feature Engineering",
            category="componentsData",
            to_edges=["componentModelTraining"],
            from_edges=["componentDataPreprocessing", "componentDataValidation"],
        ),
        "componentModelTraining": ComponentNode(
            title="Model Training",
            category="componentsModel",
            to_edges=["componentModelValidation", "componentModelTesting"],
            from_edges=["componentFeatureEngineering"],
        ),
        "componentModelValidation": ComponentNode(
            title="Model Validation",
            category="componentsModel",
            to_edges=["componentModelDeployment"],
            from_edges=["componentModelTraining"],
        ),
        "componentModelTesting": ComponentNode(
            title="Model Testing",
            category="componentsModel",
            to_edges=["componentModelDeployment"],
            from_edges=["componentModelTraining"],
        ),
        "componentModelDeployment": ComponentNode(
            title="Model Deployment",
            category="componentsInfrastructure",
            to_edges=["componentModelMonitoring"],
            from_edges=["componentModelValidation", "componentModelTesting"],
        ),
        "componentModelMonitoring": ComponentNode(
            title="Model Monitoring",
            category="componentsInfrastructure",
            to_edges=[],
            from_edges=["componentModelDeployment"],
        ),
    }


# Shared test utilities
def create_temp_yaml_file(content: str, suffix: str = ".yaml") -> Path:
    """Helper function to create temporary YAML files with content."""
    temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    temp_file.write(content)
    temp_file.close()
    return Path(temp_file.name)


def assert_mermaid_structure(mermaid_content: str, expected_elements: list[str]):
    """Helper function to assert Mermaid diagram contains expected elements."""
    for element in expected_elements:
        assert element in mermaid_content, f"Expected '{element}' in Mermaid content"


def count_mermaid_edges(mermaid_content: str) -> int:
    """Helper function to count edges in Mermaid diagram."""
    import re

    # Count arrow patterns: -->, -.->
    edge_pattern = r"[\w\[\]]+\s*[-\.]*>\s*[\w\[\]]+"
    return len(re.findall(edge_pattern, mermaid_content))
