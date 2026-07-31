"""
Shared test fixtures and configuration for the CoSAI Risk Map test suite.

This module provides common fixtures, mock objects, and test data used across
multiple test modules in the validation system test suite.
"""

# Import test modules for type hints and fixtures
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7
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
def lifecycle_stage_yaml_path(risk_map_yaml_dir: Path) -> Path:
    """
    Path to lifecycle-stage.yaml file.

    Args:
        risk_map_yaml_dir: YAML directory path fixture

    Returns:
        Path: Absolute path to lifecycle-stage.yaml
    """
    return risk_map_yaml_dir / "lifecycle-stage.yaml"


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
            risks=["riskDataPoisoning", "riskPromptInjection"],
            personas=["personaModelCreator"],
        ),
        "controlModelIntegrity": ControlNode(
            title="Model Integrity Management",
            category="controlsModel",
            components=["componentModelTraining", "componentModelDeployment"],
            risks=["riskModelSourceTampering", "riskModelDeploymentTampering"],
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
        "riskDataPoisoning": RiskNode(title="Data Poisoning", category="risks"),
        "riskPromptInjection": RiskNode(title="Prompt Injection", category="risks"),
        "riskModelSourceTampering": RiskNode(title="Model Source Tampering", category="risks"),
        "riskModelDeploymentTampering": RiskNode(title="Model Deployment Tampering", category="risks"),
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


# ============================================================================
# Schema registry helpers (shared across C1 tightening tests)
# ============================================================================
# Phase A follow-up: _make_registry was duplicated in test_consumer_external_references_refs.py
# and test_consumer_mappings_per_framework_wiring.py. Lifted here so C1 test modules can
# import it without re-duplicating. Existing per-file copies still work; only new callers
# need to use this fixture.


def _load_schema(schemas_dir: Path, filename: str) -> dict:
    """Load and return a parsed JSON schema, failing with a clear message if absent."""
    path = schemas_dir / filename
    if not path.is_file():
        pytest.fail(f"Schema not found: {path}")
    with open(path) as fh:
        return json.load(fh)


def _make_registry(schemas_dir: Path) -> Registry:
    """
    Build a referencing.Registry that resolves bare-filename $refs against schemas
    in the given directory. Replaces the deprecated jsonschema.RefResolver pattern
    (deprecated since jsonschema 4.18; scheduled for removal).

    The retrieve callback strips path prefixes so only the basename is used.
    This works because all consumer-schema $refs in this repo are bare filenames
    (e.g., 'riskmap.schema.json', 'frameworks.schema.json') — not path-prefixed URIs.
    """

    def retrieve(uri: str):
        # URI-stripping breadcrumb: the validator hands us the URI portion of a $ref.
        # For bare-filename $refs (all cases in this repo), the URI is just the filename.
        # Path-prefixed refs (e.g., '../foo.json') would silently drop the prefix; acceptable
        # because no such refs exist in the current schema set.
        name = uri.rsplit("/", 1)[-1]
        path = schemas_dir / name
        with open(path) as fh:
            return Resource.from_contents(json.load(fh), default_specification=DRAFT7)

    return Registry(retrieve=retrieve)


@pytest.fixture(scope="module")
def schema_registry(risk_map_schemas_dir: Path) -> Registry:
    """
    Module-scoped referencing.Registry for cross-file $ref resolution in C1 tests.

    Resolves bare-filename $refs (e.g., 'riskmap.schema.json#/definitions/...') against
    the risk-map/schemas/ directory. Used by C1 tightening tests that validate
    synthetic entries against consumer schemas with cross-file $refs.
    """
    return _make_registry(risk_map_schemas_dir)


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


# ============================================================================
# Shared helpers for validate_riskmap.py warn-only check tests
# ============================================================================
#
# These fixtures support the controls↔components mirror check (ADR-020 D7) and
# the category/subcategory nesting check (ADR-018 D6) tests, which both build
# minimal synthesised corpora and invoke validate_riskmap.py via subprocess.
# Lifecycle-uniqueness tests retain their own corpus helpers because their
# signatures differ (4-file corpus, no extra-args support).


@pytest.fixture
def make_component():
    """Return a callable that builds minimal ComponentNode instances for tests.

    The callable signature is (title, category, subcategory=None) -> ComponentNode.
    Edges default to empty lists since the warn-only checks do not exercise
    bidirectional edge validation.
    """

    def _make(title: str, category: str, subcategory: str | None = None) -> ComponentNode:
        return ComponentNode(
            title=title,
            category=category,
            subcategory=subcategory,
            to_edges=[],
            from_edges=[],
        )

    return _make


# The four component categories mermaid-styles.schema.json requires an entry
# for (sharedElements.componentCategories.required). Kept here so synthetic
# corpora get a styles file that is valid against the real schema rather than
# an ad-hoc stub.
_REAL_COMPONENT_CATEGORIES: tuple[str, ...] = (
    "componentsInfrastructure",
    "componentsApplication",
    "componentsModel",
    "componentsExternalTools",
)


# Sentinel distinguishing "caller said nothing" (write the default styles
# file) from "caller passed None" (deliberately omit the file). A plain None
# default cannot express both.
_UNSET: Any = object()


def build_mermaid_styles(styled_categories: tuple[str, ...] | list[str] | None = None) -> dict[str, Any]:
    """Build a mermaid-styles.yaml body that validates against its schema.

    Synthetic corpora need a *real* styles file, not the loader's emergency
    defaults: validate_riskmap.py's category style guard (ADR-030 D1) treats
    fallback-to-defaults as a failure, because the hardcoded defaults style
    every real category and would mask a missing or corrupt styles file.

    Args:
        styled_categories: Category ids to emit under
            sharedElements.componentCategories. Defaults to all four real
            categories, which is what mermaid-styles.schema.json requires.
            Pass a subset to build a deliberately unstyled-category fixture;
            the result is then intentionally schema-invalid.

    Returns:
        A dict ready to be written with yaml.dump().
    """
    categories = tuple(styled_categories) if styled_categories is not None else _REAL_COMPONENT_CATEGORIES
    flowchart_config = {"nodeSpacing": 25, "rankSpacing": 30, "padding": 5, "wrappingWidth": 250}
    components_container = {
        "fill": "#f0f0f0",
        "stroke": "#666666",
        "strokeWidth": "3px",
        "strokeDasharray": "10 5",
    }
    controls_container = {"fill": "#f0f0f0", "stroke": "#666666", "strokeWidth": "3px"}
    multi_edge_styles = [
        {"stroke": "#9c27b0", "strokeWidth": "2px"},
        {"stroke": "#ff9800", "strokeWidth": "2px", "strokeDasharray": "5 5"},
        {"stroke": "#e91e63", "strokeWidth": "2px", "strokeDasharray": "10 2"},
        {"stroke": "#c95792", "strokeWidth": "2px", "strokeDasharray": "10 5"},
    ]
    all_control_edges = {"stroke": "#4285f4", "strokeWidth": "3px", "strokeDasharray": "8 4"}
    subgraph_edges = {"stroke": "#34a853", "strokeWidth": "2px"}

    return {
        "version": "1.0.0",
        "foundation": {
            "colors": {
                "primary": "#4285f4",
                "success": "#34a853",
                "accent": "#9c27b0",
                "warning": "#ff9800",
                "error": "#e91e63",
                "neutral": "#333333",
                "lightGray": "#f0f0f0",
                "darkGray": "#666666",
            },
            "strokeWidths": {"thin": "1px", "medium": "2px", "thick": "3px"},
            "strokePatterns": {
                "solid": "",
                "dashed": "5 5",
                "dotted": "8 4",
                "longDash": "10 2",
                "longDashSpaced": "10 5",
            },
        },
        "sharedElements": {
            "cssClasses": {
                "hidden": "display: none;",
                "allControl": "stroke:#4285f4,stroke-width:2px,stroke-dasharray: 5 5",
            },
            "componentCategories": {
                category: {
                    "fill": "#e6f3e6",
                    "stroke": "#333333",
                    "strokeWidth": "2px",
                    "subgroupFill": "#d4e6d4",
                }
                for category in categories
            },
        },
        "graphTypes": {
            "component": {
                "direction": "TD",
                "flowchartConfig": flowchart_config,
                "specialStyling": {},
            },
            "control": {
                "direction": "LR",
                "flowchartConfig": flowchart_config,
                "specialStyling": {
                    "componentsContainer": components_container,
                    "controlsContainer": controls_container,
                    "edgeStyles": {
                        "allControlEdges": all_control_edges,
                        "subgraphEdges": subgraph_edges,
                        "multiEdgeStyles": multi_edge_styles,
                    },
                },
            },
            "risk": {
                "direction": "TD",
                "flowchartConfig": flowchart_config,
                "specialStyling": {
                    "riskCategories": {
                        "risks": {
                            "fill": "#ffeef0",
                            "stroke": "#e91e63",
                            "strokeWidth": "2px",
                            "subgroupFill": "#ffe0e6",
                        }
                    },
                    "componentsContainer": components_container,
                    "controlsContainer": controls_container,
                    "risksContainer": {"fill": "#f0f0f0", "stroke": "#666666", "strokeWidth": "3px"},
                    "edgeStyles": {
                        "riskControlEdges": [
                            {"stroke": "#e91e63", "strokeWidth": "2px", "strokeDasharray": "5 3"},
                            {"stroke": "#d81b60", "strokeWidth": "2px", "strokeDasharray": "8 4"},
                            {"stroke": "#c2185b", "strokeWidth": "2px", "strokeDasharray": "10 2"},
                            {"stroke": "#ad1457", "strokeWidth": "2px", "strokeDasharray": "12 5"},
                        ],
                        "allControlEdges": all_control_edges,
                        "subgraphEdges": subgraph_edges,
                        "multiEdgeStyles": multi_edge_styles,
                    },
                },
            },
        },
    }


def write_mermaid_styles(yaml_dir: Path, mermaid_styles: Any = _UNSET) -> None:
    """Write a mermaid-styles.yaml under yaml_dir, or deliberately omit it.

    Args:
        yaml_dir: The corpus's risk-map/yaml/ directory.
        mermaid_styles: Omit for the default schema-complete body; None to
            write no file at all; a str to write it verbatim (corrupt-file
            cases); a dict to write a custom body.
    """
    if mermaid_styles is _UNSET:
        mermaid_styles = build_mermaid_styles()
    if mermaid_styles is None:
        return
    body = mermaid_styles if isinstance(mermaid_styles, str) else yaml.dump(mermaid_styles)
    (yaml_dir / "mermaid-styles.yaml").write_text(body, encoding="utf-8")


@pytest.fixture
def write_riskmap_corpus():
    """Return a callable that writes a minimal synthetic corpus and returns the base.

    The callable writes components.yaml, controls.yaml, a risks.yaml stub and
    a mermaid-styles.yaml under base/risk-map/yaml/ — the minimum for
    validate_riskmap.py --force to load without ENOENT on a missing risks file
    and without the styles loader degrading to emergency defaults — plus a
    components.schema.json stub under base/risk-map/schemas/.

    The schema stub carries only the one field the validator reads from it:
    definitions.category.properties.id.enum, derived by default from the
    components fixture's own `categories:` block. validate_riskmap.py resolves
    the schema cwd-relatively like every other input, so without this the
    category style check has no categories to check. Deriving the
    enum from the corpus keeps synthetic corpora self-describing: a fixture
    declares the categories it means to exercise and nothing else, instead of
    having to enumerate whatever the real repo schema happens to contain.

    Pass schema_categories to decouple the two — that is the case the guard
    exists for, a category present in the schema but absent from the corpus.
    Pass write_schema=False to exercise the schema-unavailable path.

    The styles file defaults to build_mermaid_styles(), which styles all four
    real categories. Pass mermaid_styles=None to omit the file (the
    fallback-to-emergency-defaults path the guard rejects), a str to write it
    verbatim (corrupt-file cases), or a dict to write a custom body.
    """

    def _write(
        base: Path,
        components: dict[str, Any],
        controls: dict[str, Any],
        schema_categories: list[str] | None = None,
        write_schema: bool = True,
        mermaid_styles: dict[str, Any] | str | None = _UNSET,
    ) -> Path:
        yaml_dir = base / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "components.yaml").write_text(yaml.dump(components), encoding="utf-8")
        (yaml_dir / "controls.yaml").write_text(yaml.dump(controls), encoding="utf-8")
        (yaml_dir / "risks.yaml").write_text(yaml.dump({"risks": []}), encoding="utf-8")
        write_mermaid_styles(yaml_dir, mermaid_styles)

        if write_schema:
            if schema_categories is None:
                schema_categories = [entry["id"] for entry in components.get("categories", [])]
            schemas_dir = base / "risk-map" / "schemas"
            schemas_dir.mkdir(parents=True, exist_ok=True)
            (schemas_dir / "components.schema.json").write_text(
                json.dumps(
                    {
                        "$schema": "http://json-schema.org/draft-07/schema#",
                        "definitions": {"category": {"properties": {"id": {"enum": sorted(schema_categories)}}}},
                    }
                ),
                encoding="utf-8",
            )
        return base

    return _write


@pytest.fixture
def run_validate_riskmap():
    """Return a callable that runs validate_riskmap.py via subprocess.

    Always passes --force (bypass git-staged check) and --allow-isolated
    (skip orphan check so minimal synthesised corpora pass).  Extra args
    (e.g. "--block") are forwarded after these defaults.
    """
    script = Path(__file__).parent.parent / "validate_riskmap.py"

    def _run(cwd: Path, *extra_args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(script), "--force", "--allow-isolated", *extra_args],
            capture_output=True,
            text=True,
            cwd=str(cwd),
        )

    return _run
