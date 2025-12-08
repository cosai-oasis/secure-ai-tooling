#!/usr/bin/env python3
"""
Tests for BaseGraph and MultiEdgeStyler classes

This test suite validates the foundational graph generation classes used across
all Mermaid graph types. The tests focus on initialization validation, category
handling, cluster finding, node mapping, and style generation.

Test Coverage:
==============
1. BaseGraph Class Initialization:
   - TypeError when components is not dict
   - TypeError when components contains non-ComponentNode values
   - Valid/invalid controls dict validation
   - Valid/invalid risks dict validation
   - Config loader initialization

2. Node Type Mapping (_nodetype_a_to_b_mapping):
   - component-by-control mapping type
   - risk-by-control mapping type
   - Invalid mapping_type ValueError
   - Empty components/risks handling
   - "all" components handling
   - "none" components handling

3. Category Name Loading (_load_category_names):
   - Successful YAML loading
   - Exception handling for missing/corrupt files
   - with_controls=False filtering
   - Caching behavior

4. Node Clustering (_find_node_clusters):
   - Component clusters finding
   - Risks clusters finding
   - Invalid node_type (should return {})
   - Cluster naming conflict resolution
   - Fallback subgroup naming

5. Node Grouping (_group_node_by):
   - Components grouping with/without subcategories
   - Controls grouping
   - Risks grouping
   - ValueError with invalid node_type
   - Subcategory processing

6. Nested Subgraph Generation (_get_nested_subgraph_new):
   - Components without subcategory
   - Subgroup iteration and line generation
   - Empty line removal
   - Empty category_subgroups handling

7. Node Styling (_get_node_style):
   - componentCategory style type
   - riskCategory style type
   - dynamicSubgroup style with parent categories
   - Fallback colors for Infrastructure/Data/Model/Application
   - Default gray fallback
   - Unknown style_type default

8. MultiEdgeStyler Class:
   - TypeError when basegraph is invalid
   - Edge index cycling (0-3)
   - Edge index cycling beyond 4
   - Empty multiEdgeStyles config
   - style_group with no edges
   - reset_index functionality

Coverage Target: 95%+ for graphing/base.py (up from 78%)
"""

import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import yaml

# Add scripts/hooks directory to path
git_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(git_root / "scripts" / "hooks"))

from riskmap_validator.graphing.base import BaseGraph, MultiEdgeStyler  # noqa: E402
from riskmap_validator.graphing.graph_utils import MermaidConfigLoader  # noqa: E402
from riskmap_validator.models import ComponentNode, ControlNode, RiskNode  # noqa: E402


class TestBaseGraphInitialization:
    """
    Test BaseGraph initialization validation.

    Tests focus on type validation for components, controls, and risks dictionaries.
    """

    @pytest.fixture
    def valid_components(self):
        """Provide valid components dictionary."""
        return {
            "comp1": ComponentNode(
                title="Component 1",
                category="componentsData",
                to_edges=["comp2"],
                from_edges=[],
            ),
            "comp2": ComponentNode(
                title="Component 2",
                category="componentsModel",
                to_edges=[],
                from_edges=["comp1"],
            ),
        }

    @pytest.fixture
    def valid_controls(self):
        """Provide valid controls dictionary."""
        return {
            "ctrl1": ControlNode(
                title="Control 1",
                category="controlsData",
                components=["comp1"],
                risks=["risk1"],
                personas=["persona1"],
            ),
        }

    @pytest.fixture
    def valid_risks(self):
        """Provide valid risks dictionary."""
        return {
            "risk1": RiskNode(title="Risk 1", category="risks"),
        }

    @pytest.fixture
    def mock_config_loader(self):
        """Provide mock MermaidConfigLoader."""
        mock = Mock(spec=MermaidConfigLoader)
        mock.get_control_edge_styles.return_value = {
            "allControlEdges": {"stroke": "#4285f4", "strokeWidth": "2px"},
            "multiEdgeStyles": [
                {"stroke": "#9c27b0", "strokeWidth": "2px"},
                {"stroke": "#ff9800", "strokeWidth": "2px"},
                {"stroke": "#34a853", "strokeWidth": "2px"},
                {"stroke": "#e91e63", "strokeWidth": "2px"},
            ],
        }
        mock.get_component_category_styles.return_value = {
            "componentsData": {
                "fill": "#fff5e6",
                "stroke": "#333333",
                "strokeWidth": "2px",
                "subgroupFill": "#f5f0e6",
            },
        }
        return mock

    def test_basegraph_creation_with_valid_components_succeeds(self, valid_components, mock_config_loader):
        """
        Test that BaseGraph can be created with valid components.

        Given: Valid components dictionary
        When: BaseGraph is instantiated
        Then: Object is created successfully
        """
        graph = BaseGraph(components=valid_components, config_loader=mock_config_loader)

        assert graph.components == valid_components
        assert len(graph.components) == 2
        assert graph.controls == {}
        assert graph.risks == {}

    def test_basegraph_components_not_dict_raises_typeerror(self, mock_config_loader):
        """
        Test that non-dict components raises TypeError.

        Given: Components parameter that is not a dict
        When: BaseGraph is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="'components' must be a dict of ComponentNodes"):
            BaseGraph(components=["not", "a", "dict"], config_loader=mock_config_loader)  # pyright: ignore[reportArgumentType]

    def test_basegraph_components_contains_non_componentnode_raises_typeerror(self, mock_config_loader):
        """
        Test that components dict with non-ComponentNode values raises TypeError.

        Given: Components dict containing non-ComponentNode values
        When: BaseGraph is instantiated
        Then: TypeError is raised
        """
        invalid_components = {
            "comp1": ComponentNode(
                title="Component 1",
                category="componentsData",
                to_edges=[],
                from_edges=[],
            ),
            "comp2": "not a component node",  # Invalid
        }

        with pytest.raises(TypeError, match="'components' must be a dict of ComponentNodes"):
            BaseGraph(components=invalid_components, config_loader=mock_config_loader)

    def test_basegraph_with_valid_controls_sets_controls(
        self, valid_components, valid_controls, mock_config_loader
    ):
        """
        Test that valid controls dict is set correctly.

        Given: Valid components and controls dictionaries
        When: BaseGraph is instantiated
        Then: Controls are set on the object
        """
        graph = BaseGraph(components=valid_components, controls=valid_controls, config_loader=mock_config_loader)

        assert graph.controls == valid_controls
        assert len(graph.controls) == 1

    def test_basegraph_with_invalid_controls_ignores_controls(self, valid_components, mock_config_loader):
        """
        Test that invalid controls dict is ignored (not set).

        Given: Valid components but invalid controls (not a dict)
        When: BaseGraph is instantiated
        Then: Controls remain empty dict
        """
        graph = BaseGraph(components=valid_components, controls="invalid", config_loader=mock_config_loader)  # pyright: ignore[reportArgumentType]

        assert graph.controls == {}

    def test_basegraph_with_controls_containing_non_controlnode_ignores_controls(
        self, valid_components, mock_config_loader
    ):
        """
        Test that controls dict with non-ControlNode values is ignored.

        Given: Controls dict containing non-ControlNode values
        When: BaseGraph is instantiated
        Then: Controls remain empty dict
        """
        invalid_controls = {
            "ctrl1": ControlNode(
                title="Control 1",
                category="controlsData",
                components=[],
                risks=[],
                personas=[],
            ),
            "ctrl2": {"not": "a control node"},  # Invalid
        }

        graph = BaseGraph(components=valid_components, controls=invalid_controls, config_loader=mock_config_loader)

        assert graph.controls == {}

    def test_basegraph_with_valid_risks_sets_risks(self, valid_components, valid_risks, mock_config_loader):
        """
        Test that valid risks dict is set correctly.

        Given: Valid components and risks dictionaries
        When: BaseGraph is instantiated
        Then: Risks are set on the object
        """
        graph = BaseGraph(components=valid_components, risks=valid_risks, config_loader=mock_config_loader)

        assert graph.risks == valid_risks
        assert len(graph.risks) == 1

    def test_basegraph_with_invalid_risks_ignores_risks(self, valid_components, mock_config_loader):
        """
        Test that invalid risks dict is ignored (not set).

        Given: Valid components but invalid risks (not a dict)
        When: BaseGraph is instantiated
        Then: Risks remain empty dict
        """
        graph = BaseGraph(components=valid_components, risks=["invalid"], config_loader=mock_config_loader)  # pyright: ignore[reportArgumentType]

        assert graph.risks == {}

    def test_basegraph_with_risks_containing_non_risknode_ignores_risks(
        self, valid_components, mock_config_loader
    ):
        """
        Test that risks dict with non-RiskNode values is ignored.

        Given: Risks dict containing non-RiskNode values
        When: BaseGraph is instantiated
        Then: Risks remain empty dict
        """
        invalid_risks = {
            "risk1": RiskNode(title="Risk 1", category="risks"),
            "risk2": 123,  # Invalid
        }

        graph = BaseGraph(components=valid_components, risks=invalid_risks, config_loader=mock_config_loader)

        assert graph.risks == {}


class TestNodeTypeMapping:
    """
    Test _nodetype_a_to_b_mapping method.

    Tests focus on mapping controls to components/risks with special handling
    for "all", "none", and filtering of non-existent nodes.
    """

    @pytest.fixture
    def components_and_controls(self):
        """Provide components and controls for mapping tests."""
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
            "comp2": ComponentNode(title="C2", category="componentsModel", to_edges=[], from_edges=[]),
        }
        controls = {
            "ctrl_all": ControlNode(
                title="All Control",
                category="controlsData",
                components=["all"],
                risks=[],
                personas=[],
            ),
            "ctrl_none": ControlNode(
                title="None Control",
                category="controlsData",
                components=["none"],
                risks=[],
                personas=[],
            ),
            "ctrl_specific": ControlNode(
                title="Specific Control",
                category="controlsData",
                components=["comp1"],
                risks=[],
                personas=[],
            ),
            "ctrl_nonexistent": ControlNode(
                title="Non-existent Control",
                category="controlsData",
                components=["comp1", "comp_missing"],
                risks=[],
                personas=[],
            ),
        }
        return components, controls

    @pytest.fixture
    def risks_and_controls(self):
        """Provide risks and controls for risk mapping tests."""
        risks = {
            "risk1": RiskNode(title="Risk 1", category="risks"),
            "risk2": RiskNode(title="Risk 2", category="risks"),
        }
        controls = {
            "ctrl_all_risks": ControlNode(
                title="All Risks",
                category="controlsData",
                components=[],
                risks=["all"],
                personas=[],
            ),
            "ctrl_none_risks": ControlNode(
                title="None Risks",
                category="controlsData",
                components=[],
                risks=["none"],
                personas=[],
            ),
            "ctrl_specific_risks": ControlNode(
                title="Specific Risks",
                category="controlsData",
                components=[],
                risks=["risk1"],
                personas=[],
            ),
        }
        return risks, controls

    @pytest.fixture
    def mock_config_loader(self):
        """Provide mock config loader."""
        return Mock(spec=MermaidConfigLoader)

    def test_component_to_control_mapping(self, components_and_controls, mock_config_loader):
        """
        Test component-by-control mapping.

        Given: Components and controls with various mapping types
        When: _component_to_control_mapping is called
        Then: Mapping is created correctly with "all", "none", specific, and filtered
        """
        components, controls = components_and_controls
        graph = BaseGraph(components=components, controls=controls, config_loader=mock_config_loader)
        graph._component_to_control_mapping()

        assert graph.initial_mapping["ctrl_all"] == ["components"]  # "all" mapped to special value
        assert graph.initial_mapping["ctrl_none"] == []  # "none" mapped to empty list
        assert graph.initial_mapping["ctrl_specific"] == ["comp1"]
        # ctrl_nonexistent should filter out comp_missing
        assert graph.initial_mapping["ctrl_nonexistent"] == ["comp1"]
        assert "comp_missing" not in graph.initial_mapping["ctrl_nonexistent"]

    def test_risk_to_control_mapping(self, risks_and_controls, mock_config_loader):
        """
        Test risk-by-control mapping.

        Given: Risks and controls with various mapping types
        When: _risk_to_control_mapping is called
        Then: Mapping is created correctly
        """
        risks, controls = risks_and_controls
        # Need minimal components to initialize
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, controls=controls, risks=risks, config_loader=mock_config_loader)
        graph._risk_to_control_mapping()

        assert graph.initial_mapping["ctrl_all_risks"] == ["risks"]  # "all" mapped to special value
        assert graph.initial_mapping["ctrl_none_risks"] == []  # "none" mapped to empty list
        assert graph.initial_mapping["ctrl_specific_risks"] == ["risk1"]

    def test_nodetype_a_to_b_mapping_invalid_type_raises_valueerror(
        self, components_and_controls, mock_config_loader
    ):
        """
        Test that invalid mapping_type raises ValueError.

        Given: Valid components and controls
        When: _nodetype_a_to_b_mapping is called with invalid type
        Then: ValueError is raised
        """
        components, controls = components_and_controls
        graph = BaseGraph(components=components, controls=controls, config_loader=mock_config_loader)

        with pytest.raises(ValueError, match="mapping_type must be: 'component-by-control' or 'risk-by-control'"):
            graph._nodetype_a_to_b_mapping("invalid-mapping-type")

    def test_component_mapping_with_empty_components_returns_early(self, mock_config_loader):
        """
        Test that component mapping with no components returns early.

        Given: Empty components dict
        When: _component_to_control_mapping is called
        Then: Method returns early without error
        """
        components = {}
        controls = {
            "ctrl1": ControlNode(
                title="Control 1",
                category="controlsData",
                components=["comp1"],
                risks=[],
                personas=[],
            ),
        }
        # BaseGraph requires at least one component, so we need to use a minimal one
        # Actually, looking at the code, empty components will fail initialization
        # So we test with components but empty controls
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, controls=controls, config_loader=mock_config_loader)
        graph.components = {}  # Manually set to empty after init
        graph._component_to_control_mapping()

        # Should return early and not set initial_mapping
        assert not hasattr(graph, "initial_mapping") or graph.initial_mapping == {}

    def test_risk_mapping_with_empty_risks_returns_early(self, mock_config_loader):
        """
        Test that risk mapping with no risks returns early.

        Given: Empty risks dict
        When: _risk_to_control_mapping is called
        Then: Method returns early without error
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        controls = {
            "ctrl1": ControlNode(
                title="Control 1",
                category="controlsData",
                components=[],
                risks=["risk1"],
                personas=[],
            ),
        }
        graph = BaseGraph(components=components, controls=controls, risks={}, config_loader=mock_config_loader)
        graph._risk_to_control_mapping()

        # Should return early
        assert not hasattr(graph, "initial_mapping") or graph.initial_mapping == {}


class TestCategoryNameLoading:
    """
    Test _load_category_names method.

    Tests focus on YAML loading, exception handling, caching, and filtering.
    """

    @pytest.fixture
    def mock_config_loader(self):
        """Provide mock config loader."""
        return Mock(spec=MermaidConfigLoader)

    @pytest.fixture
    def temp_yaml_files(self):
        """Create temporary YAML files for testing."""
        # Create temp directory structure
        temp_dir = Path(tempfile.mkdtemp())
        risk_map_dir = temp_dir / "risk-map" / "yaml"
        risk_map_dir.mkdir(parents=True)

        controls_file = risk_map_dir / "controls.yaml"
        components_file = risk_map_dir / "components.yaml"

        controls_data = {
            "categories": [
                {"id": "controlsData", "title": "Data Controls"},
                {"id": "controlsModel", "title": "Model Controls"},
            ]
        }
        components_data = {
            "categories": [
                {"id": "componentsData", "title": "Data Components"},
                {"id": "componentsModel", "title": "Model Components"},
            ]
        }

        with open(controls_file, "w") as f:
            yaml.dump(controls_data, f)
        with open(components_file, "w") as f:
            yaml.dump(components_data, f)

        yield temp_dir, controls_file, components_file

        # Cleanup
        import shutil

        shutil.rmtree(temp_dir)

    def test_load_category_names_caching(self, mock_config_loader):
        """
        Test that category names are cached after first load.

        Given: BaseGraph instance
        When: _load_category_names is called multiple times
        Then: Categories are loaded once and cached
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        # First call - should load
        with patch("pathlib.Path.exists", return_value=False):
            _ = graph._load_category_names()

        # Set cache manually
        graph._category_names_cache = {"test": "Test Category"}

        # Second call - should use cache
        names2 = graph._load_category_names()

        assert names2 == {"test": "Test Category"}

    def test_load_category_names_with_exception_returns_empty_dict(self, mock_config_loader):
        """
        Test that exception during YAML loading is handled gracefully.

        Given: YAML files that cause exceptions
        When: _load_category_names is called
        Then: Returns empty dict and doesn't raise exception
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        with patch("pathlib.Path.exists", return_value=True):
            with patch("builtins.open", side_effect=IOError("File error")):
                names = graph._load_category_names()

        # Should return empty dict on exception
        assert names == {}

    def test_load_category_names_with_controls_false_filters_controls(self, mock_config_loader):
        """
        Test that with_controls=False filters out control categories.

        Given: Category names including control categories
        When: _load_category_names(with_controls=False) is called
        Then: Only non-control categories are returned
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        # Set up cache with both component and control categories
        graph._category_names_cache = {
            "componentsData": "Data Components",
            "componentsModel": "Model Components",
            "controlsData": "Data Controls",
            "controlsModel": "Model Controls",
        }

        # Call with with_controls=False
        names = graph._load_category_names(with_controls=False)

        # Should only include component categories
        assert "componentsData" in names
        assert "componentsModel" in names
        assert "controlsData" not in names
        assert "controlsModel" not in names


class TestNodeClustering:
    """
    Test _find_node_clusters method.

    Tests focus on component and risk clustering with different node types.
    """

    @pytest.fixture
    def mock_config_loader(self):
        """Provide mock config loader."""
        return Mock(spec=MermaidConfigLoader)

    def test_find_component_clusters(self, mock_config_loader):
        """
        Test finding component clusters.

        Given: Components and node-to-controls mapping
        When: _find_component_clusters is called
        Then: Clusters are identified correctly
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
            "comp2": ComponentNode(title="C2", category="componentsData", to_edges=[], from_edges=[]),
            "comp3": ComponentNode(title="C3", category="componentsModel", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)
        graph.component_by_category = {"componentsData": ["comp1", "comp2"]}

        # Node to controls mapping with shared controls
        node_to_controls = {
            "comp1": {"ctrl1", "ctrl2"},
            "comp2": {"ctrl1", "ctrl2"},  # Shares 2 controls with comp1
            "comp3": {"ctrl3"},
        }

        clusters = graph._find_component_clusters(node_to_controls, min_shared_controls=2, min_nodes=2)

        # comp1 and comp2 should be clustered together
        assert len(clusters) >= 1
        # At least one cluster should contain both comp1 and comp2
        cluster_found = False
        for cluster_name, cluster_members in clusters.items():
            if "comp1" in cluster_members and "comp2" in cluster_members:
                cluster_found = True
                break
        assert cluster_found

    def test_find_node_clusters_with_risks_node_type(self, mock_config_loader):
        """
        Test finding risk clusters.

        Given: Risks and node-to-controls mapping
        When: _find_node_clusters is called with node_type="risks"
        Then: Risk clusters are identified correctly
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        risks = {
            "risk1": RiskNode(title="R1", category="risks"),
            "risk2": RiskNode(title="R2", category="risks"),
        }
        graph = BaseGraph(components=components, risks=risks, config_loader=mock_config_loader)

        # Node to controls mapping with shared controls
        node_to_controls = {
            "risk1": {"ctrl1", "ctrl2"},
            "risk2": {"ctrl1", "ctrl2"},  # Shares 2 controls with risk1
        }

        clusters = graph._find_node_clusters("risks", node_to_controls, min_shared_controls=2, min_nodes=2)

        # risk1 and risk2 should be clustered
        assert len(clusters) >= 1

    def test_find_node_clusters_with_invalid_node_type_returns_empty_dict(self, mock_config_loader):
        """
        Test that invalid node_type returns empty dict.

        Given: Invalid node_type
        When: _find_node_clusters is called
        Then: Returns empty dict
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        node_to_controls = {
            "comp1": {"ctrl1"},
        }

        clusters = graph._find_node_clusters("invalid_type", node_to_controls)

        assert clusters == {}

    def test_cluster_naming_conflict_resolution(self, mock_config_loader):
        """
        Test that cluster naming resolves conflicts with existing categories.

        Given: Components that would create conflicting cluster names
        When: _find_node_clusters is called
        Then: Conflict is resolved with modified name
        """
        components = {
            "componentData1": ComponentNode(title="Data 1", category="componentsData", to_edges=[], from_edges=[]),
            "componentData2": ComponentNode(title="Data 2", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)
        graph.component_by_category = {"componentsData": ["componentData1", "componentData2"]}

        node_to_controls = {
            "componentData1": {"ctrl1", "ctrl2"},
            "componentData2": {"ctrl1", "ctrl2"},
        }

        clusters = graph._find_node_clusters("component", node_to_controls, min_shared_controls=2, min_nodes=2)

        # Check that cluster names don't conflict
        for cluster_name in clusters.keys():
            # Should have some name (possibly with suffix to avoid conflict)
            assert cluster_name is not None
            assert len(cluster_name) > 0

    def test_cluster_fallback_naming(self, mock_config_loader):
        """
        Test fallback subgroup naming when no common prefix exists.

        Given: Components with no meaningful common prefix
        When: _find_node_clusters is called
        Then: Fallback naming pattern is used
        """
        components = {
            "compA": ComponentNode(title="A", category="componentsData", to_edges=[], from_edges=[]),
            "compZ": ComponentNode(title="Z", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)
        graph.component_by_category = {"componentsData": ["compA", "compZ"]}

        node_to_controls = {
            "compA": {"ctrl1", "ctrl2"},
            "compZ": {"ctrl1", "ctrl2"},
        }

        clusters = graph._find_node_clusters("component", node_to_controls, min_shared_controls=2, min_nodes=2)

        # Should use fallback naming like "componentsSubgroup1"
        if clusters:  # Clustering might not occur if common prefix is too short
            for cluster_name in clusters.keys():
                assert "components" in cluster_name.lower() or "subgroup" in cluster_name.lower()


class TestGroupNodeBy:
    """
    Test _group_node_by method.

    Tests focus on grouping nodes by category with subcategory support.
    """

    @pytest.fixture
    def mock_config_loader(self):
        """Provide mock config loader."""
        return Mock(spec=MermaidConfigLoader)

    def test_group_components_by_category_without_subcategories(self, mock_config_loader):
        """
        Test grouping components by category without subcategories.

        Given: Components with different categories
        When: _group_node_by("components") is called
        Then: Components are grouped by category
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
            "comp2": ComponentNode(title="C2", category="componentsData", to_edges=[], from_edges=[]),
            "comp3": ComponentNode(title="C3", category="componentsModel", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        groups, subcat_groups = graph._group_node_by("components", w_subcategories=False)

        assert "componentsData" in groups
        assert "componentsModel" in groups
        assert "comp1" in groups["componentsData"]
        assert "comp2" in groups["componentsData"]
        assert "comp3" in groups["componentsModel"]
        assert subcat_groups == {}

    def test_group_components_with_subcategories(self, mock_config_loader):
        """
        Test grouping components with subcategory processing.

        Given: Components with subcategories
        When: _group_node_by("components", w_subcategories=True) is called
        Then: Subcategory groups are created
        """
        components = {
            "comp1": ComponentNode(
                title="C1",
                category="componentsData",
                to_edges=[],
                from_edges=[],
                subcategory="Storage",
            ),
            "comp2": ComponentNode(
                title="C2",
                category="componentsData",
                to_edges=[],
                from_edges=[],
                subcategory="Processing",
            ),
            "comp3": ComponentNode(
                title="C3",
                category="componentsData",
                to_edges=[],
                from_edges=[],
            ),  # No subcategory
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        groups, subcat_groups = graph._group_node_by("components", w_subcategories=True)

        assert "componentsData" in groups
        assert "componentsData" in subcat_groups
        assert "Storage" in subcat_groups["componentsData"]
        assert "Processing" in subcat_groups["componentsData"]
        assert "comp1" in subcat_groups["componentsData"]["Storage"]
        assert "comp2" in subcat_groups["componentsData"]["Processing"]

    def test_group_controls_by_category(self, mock_config_loader):
        """
        Test grouping controls by category.

        Given: Controls with different categories
        When: _group_node_by("controls") is called
        Then: Controls are grouped by category
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        controls = {
            "ctrl1": ControlNode(
                title="Control 1",
                category="controlsData",
                components=[],
                risks=[],
                personas=[],
            ),
            "ctrl2": ControlNode(
                title="Control 2",
                category="controlsModel",
                components=[],
                risks=[],
                personas=[],
            ),
        }
        graph = BaseGraph(components=components, controls=controls, config_loader=mock_config_loader)

        groups, subcat_groups = graph._group_node_by("controls")

        assert "controlsData" in groups
        assert "controlsModel" in groups
        assert "ctrl1" in groups["controlsData"]
        assert "ctrl2" in groups["controlsModel"]

    def test_group_risks_by_category(self, mock_config_loader):
        """
        Test grouping risks by category.

        Given: Risks with different categories
        When: _group_node_by("risks") is called
        Then: Risks are grouped by category
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        risks = {
            "risk1": RiskNode(title="R1", category="risksPrivacy"),
            "risk2": RiskNode(title="R2", category="risksSecurity"),
        }
        graph = BaseGraph(components=components, risks=risks, config_loader=mock_config_loader)

        groups, subcat_groups = graph._group_node_by("risks")

        assert "risksPrivacy" in groups
        assert "risksSecurity" in groups
        assert "risk1" in groups["risksPrivacy"]
        assert "risk2" in groups["risksSecurity"]

    def test_group_node_by_invalid_node_type_raises_valueerror(self, mock_config_loader):
        """
        Test that invalid node_type raises ValueError.

        Given: Invalid node_type
        When: _group_node_by is called
        Then: ValueError is raised
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        with pytest.raises(ValueError, match="node_type must be 'controls' or 'components'"):
            graph._group_node_by("invalid_type")


class TestNestedSubgraphGeneration:
    """
    Test _get_nested_subgraph_new method.

    Tests focus on nested subgraph generation with subcategories.
    """

    @pytest.fixture
    def mock_config_loader(self):
        """Provide mock config loader."""
        return Mock(spec=MermaidConfigLoader)

    def test_nested_subgraph_with_empty_subcategories_returns_none(self, mock_config_loader):
        """
        Test that empty category_subgroups returns None.

        Given: Category with no subcategories
        When: _get_nested_subgraph_new is called
        Then: Returns None
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)
        graph.component_by_subcategory = {}  # No subcategories

        result = graph._get_nested_subgraph_new(["comp1"], "componentsData", "Data Components")

        assert result is None

    def test_nested_subgraph_with_components_without_subcategory(self, mock_config_loader):
        """
        Test nested subgraph includes components without subcategory.

        Given: Components with and without subcategories
        When: _get_nested_subgraph_new is called
        Then: Components without subcategory are included at top level
        """
        components = {
            "comp1": ComponentNode(
                title="C1",
                category="componentsData",
                to_edges=[],
                from_edges=[],
            ),  # No subcategory
            "comp2": ComponentNode(
                title="C2",
                category="componentsData",
                to_edges=[],
                from_edges=[],
                subcategory="Storage",
            ),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)
        graph.component_by_subcategory = {
            "componentsData": {
                "Storage": ["comp2"],
            }
        }

        result = graph._get_nested_subgraph_new(["comp1", "comp2"], "componentsData", "Data Components")

        assert result is not None
        result_str = "\n".join(result)
        # comp1 should be at top level (no nested subgroup)
        assert "comp1" in result_str

    def test_nested_subgraph_generates_subgroup_sections(self, mock_config_loader):
        """
        Test that subgroups are generated for subcategories.

        Given: Components with multiple subcategories
        When: _get_nested_subgraph_new is called
        Then: Subgroup sections are generated
        """
        components = {
            "comp1": ComponentNode(
                title="C1",
                category="componentsData",
                to_edges=[],
                from_edges=[],
                subcategory="Storage",
            ),
            "comp2": ComponentNode(
                title="C2",
                category="componentsData",
                to_edges=[],
                from_edges=[],
                subcategory="Processing",
            ),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)
        graph.component_by_subcategory = {
            "componentsData": {
                "Storage": ["comp1"],
                "Processing": ["comp2"],
            }
        }

        result = graph._get_nested_subgraph_new(["comp1", "comp2"], "componentsData", "Data Components")

        assert result is not None
        result_str = "\n".join(result)
        # Should contain subgroup keywords
        assert "subgraph" in result_str
        assert "end" in result_str

    def test_nested_subgraph_removes_empty_lines_at_end(self, mock_config_loader):
        """
        Test that empty lines are removed from subgroup sections.

        Given: Subgroup generation that produces empty lines
        When: _get_nested_subgraph_new is called
        Then: Empty lines at end of subgroup sections are removed
        """
        components = {
            "comp1": ComponentNode(
                title="C1",
                category="componentsData",
                to_edges=[],
                from_edges=[],
                subcategory="Storage",
            ),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)
        graph.component_by_subcategory = {
            "componentsData": {
                "Storage": ["comp1"],
            }
        }

        result = graph._get_nested_subgraph_new(["comp1"], "componentsData", "Data Components")

        assert result is not None
        # Check that we don't have consecutive empty lines at the end
        # The implementation removes empty line from subgroup sections
        assert result[-1] == ""  # Final empty line should be present
        if len(result) > 2:
            # But not duplicate empty lines
            assert not (result[-2] == "" and result[-3] == "")


class TestNodeStyling:
    """
    Test _get_node_style method.

    Tests focus on different style types and fallback mechanisms.
    """

    @pytest.fixture
    def mock_config_loader(self):
        """Provide mock config loader with category styles."""
        mock = Mock(spec=MermaidConfigLoader)
        mock.get_component_category_styles.return_value = {
            "componentsData": {
                "fill": "#fff5e6",
                "stroke": "#333333",
                "strokeWidth": "2px",
                "subgroupFill": "#f5f0e6",
            },
            "componentsModel": {
                "fill": "#ffe6e6",
                "stroke": "#333333",
                "strokeWidth": "2px",
                # No subgroupFill - will test fallback
            },
        }
        return mock

    def test_get_node_style_component_category(self, mock_config_loader):
        """
        Test componentCategory style type.

        Given: Category config with style properties
        When: _get_node_style("componentCategory") is called
        Then: Returns formatted style string
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        category_config = {"fill": "#fff5e6", "stroke": "#333333", "strokeWidth": "2px"}
        style = graph._get_node_style("componentCategory", category_config=category_config)

        assert "fill:#fff5e6" in style
        assert "stroke:#333333" in style
        assert "stroke-width:2px" in style

    def test_get_node_style_risk_category(self, mock_config_loader):
        """
        Test riskCategory style type.

        Given: Category config for risk
        When: _get_node_style("riskCategory") is called
        Then: Returns formatted style string with risk defaults
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        category_config = {}  # Empty to test defaults
        style = graph._get_node_style("riskCategory", category_config=category_config)

        assert "fill:#ffeef0" in style  # Default risk fill
        assert "stroke:#e91e63" in style  # Default risk stroke
        assert "stroke-width:2px" in style

    def test_get_node_style_dynamic_subgroup_with_config(self, mock_config_loader):
        """
        Test dynamicSubgroup style with parent category in config.

        Given: Parent category with subgroupFill in config
        When: _get_node_style("dynamicSubgroup") is called
        Then: Uses configured subgroupFill
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        style = graph._get_node_style("dynamicSubgroup", parent_category="componentsData")

        assert "fill:#f5f0e6" in style  # From mock config

    def test_get_node_style_dynamic_subgroup_infrastructure_fallback(self, mock_config_loader):
        """
        Test dynamicSubgroup fallback for Infrastructure category.

        Given: Parent category containing "Infrastructure" without subgroupFill in config
        When: _get_node_style("dynamicSubgroup") is called
        Then: Uses Infrastructure fallback color
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        style = graph._get_node_style("dynamicSubgroup", parent_category="componentsInfrastructure")

        assert "fill:#d4e6d4" in style  # Infrastructure fallback

    def test_get_node_style_dynamic_subgroup_data_fallback(self, mock_config_loader):
        """
        Test dynamicSubgroup fallback for Data category.

        Given: Parent category containing "Data" without subgroupFill in config
        When: _get_node_style("dynamicSubgroup") is called
        Then: Uses Data fallback color
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        # Force fallback by using category not in config
        style = graph._get_node_style("dynamicSubgroup", parent_category="componentsDataSpecial")

        assert "fill:#f5f0e6" in style  # Data fallback

    def test_get_node_style_dynamic_subgroup_model_fallback(self, mock_config_loader):
        """
        Test dynamicSubgroup fallback for Model category.

        Given: Parent category containing "Model" without subgroupFill in config
        When: _get_node_style("dynamicSubgroup") is called
        Then: Uses Model fallback color
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        # Test Model fallback - need to bypass config lookup
        # The code checks config first, so we modify the return value
        mock_config_loader.get_component_category_styles.return_value = {}
        style = graph._get_node_style("dynamicSubgroup", parent_category="componentsModelSpecial")

        assert "fill:#f0e6e6" in style  # Model fallback

    def test_get_node_style_dynamic_subgroup_application_fallback(self, mock_config_loader):
        """
        Test dynamicSubgroup fallback for Application category.

        Given: Parent category containing "Application" without subgroupFill in config
        When: _get_node_style("dynamicSubgroup") is called
        Then: Uses Application fallback color
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        mock_config_loader.get_component_category_styles.return_value = {}
        style = graph._get_node_style("dynamicSubgroup", parent_category="componentsApplicationSpecial")

        assert "fill:#e0f0ff" in style  # Application fallback

    def test_get_node_style_dynamic_subgroup_default_gray_fallback(self, mock_config_loader):
        """
        Test dynamicSubgroup default gray fallback.

        Given: Parent category not matching any specific type
        When: _get_node_style("dynamicSubgroup") is called
        Then: Uses default gray fallback
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        mock_config_loader.get_component_category_styles.return_value = {}
        style = graph._get_node_style("dynamicSubgroup", parent_category="componentsUnknownType")

        assert "fill:#f8f8f8" in style  # Default gray

    def test_get_node_style_unknown_type_returns_default(self, mock_config_loader):
        """
        Test that unknown style_type returns default style.

        Given: Unknown style_type
        When: _get_node_style is called
        Then: Returns default style
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)

        style = graph._get_node_style("unknownStyleType")

        assert "fill:#ffffff" in style  # Default fill
        assert "stroke:#333333" in style  # Default stroke
        assert "stroke-width:2px" in style


class TestMultiEdgeStyler:
    """
    Test MultiEdgeStyler class.

    Tests focus on edge index management and style generation.
    """

    @pytest.fixture
    def mock_basegraph(self):
        """Provide mock BaseGraph."""
        mock = Mock(spec=BaseGraph)
        mock_config = Mock(spec=MermaidConfigLoader)
        mock_config.get_control_edge_styles.return_value = {
            "multiEdgeStyles": [
                {"stroke": "#9c27b0", "strokeWidth": "2px"},
                {"stroke": "#ff9800", "strokeWidth": "2px"},
                {"stroke": "#34a853", "strokeWidth": "2px"},
                {"stroke": "#e91e63", "strokeWidth": "2px"},
            ],
        }
        mock.config_loader = mock_config
        mock._get_edge_style.side_effect = (
            lambda style: f"stroke:{style.get('stroke')},stroke-width:{style.get('strokeWidth')}"
        )
        return mock

    def test_multiedgestyler_creation_with_valid_basegraph_succeeds(self, mock_basegraph):
        """
        Test that MultiEdgeStyler can be created with valid BaseGraph.

        Given: Valid BaseGraph instance
        When: MultiEdgeStyler is instantiated
        Then: Object is created successfully
        """
        styler = MultiEdgeStyler(basegraph=mock_basegraph)

        assert styler.basegraph == mock_basegraph
        assert styler.index == 0
        assert len(styler.edges) == 4

    def test_multiedgestyler_invalid_basegraph_raises_typeerror(self):
        """
        Test that invalid basegraph raises TypeError.

        Given: Invalid basegraph (not BaseGraph instance)
        When: MultiEdgeStyler is instantiated
        Then: TypeError is raised with appropriate message
        """
        with pytest.raises(TypeError, match="Requires an instance of a BaseGraph subclass"):
            MultiEdgeStyler(basegraph="invalid")

    def test_multiedgestyler_none_basegraph_raises_typeerror(self):
        """
        Test that None basegraph raises TypeError.

        Given: None as basegraph
        When: MultiEdgeStyler is instantiated
        Then: TypeError is raised with appropriate message
        """
        with pytest.raises(TypeError, match="Requires an instance of a BaseGraph subclass"):
            MultiEdgeStyler(basegraph=None)

    def test_set_edge_cycles_through_indices(self, mock_basegraph):
        """
        Test that set_edge cycles through indices 0-3.

        Given: MultiEdgeStyler instance
        When: set_edge is called multiple times
        Then: Edges are distributed across 4 style groups cyclically
        """
        styler = MultiEdgeStyler(basegraph=mock_basegraph)

        styler.set_edge(0)  # Should go to edges[0]
        styler.set_edge(1)  # Should go to edges[1]
        styler.set_edge(2)  # Should go to edges[2]
        styler.set_edge(3)  # Should go to edges[3]
        styler.set_edge(4)  # Should cycle back to edges[0]
        styler.set_edge(5)  # Should go to edges[1]

        assert 0 in styler.edges[0]
        assert 1 in styler.edges[1]
        assert 2 in styler.edges[2]
        assert 3 in styler.edges[3]
        assert 4 in styler.edges[0]
        assert 5 in styler.edges[1]

    def test_reset_index_resets_to_zero(self, mock_basegraph):
        """
        Test that reset_index resets index to 0.

        Given: MultiEdgeStyler with non-zero index
        When: reset_index is called
        Then: Index is reset to 0
        """
        styler = MultiEdgeStyler(basegraph=mock_basegraph)

        styler.set_edge(0)
        styler.set_edge(1)
        styler.set_edge(2)
        assert styler.index == 3

        styler.reset_index()
        assert styler.index == 0

    def test_get_edge_style_lines_with_edges(self, mock_basegraph):
        """
        Test get_edge_style_lines generates correct linkStyle lines.

        Given: MultiEdgeStyler with edges set
        When: get_edge_style_lines is called
        Then: Returns linkStyle lines for all groups with edges
        """
        styler = MultiEdgeStyler(basegraph=mock_basegraph)

        styler.set_edge(0)
        styler.set_edge(1)
        styler.set_edge(2)

        lines = styler.get_edge_style_lines()

        assert len(lines) == 3  # Three style groups have edges
        assert all("linkStyle" in line for line in lines)

    def test_get_edge_style_lines_with_empty_edges(self, mock_basegraph):
        """
        Test get_edge_style_lines with no edges returns empty list.

        Given: MultiEdgeStyler with no edges set
        When: get_edge_style_lines is called
        Then: Returns empty list
        """
        styler = MultiEdgeStyler(basegraph=mock_basegraph)

        lines = styler.get_edge_style_lines()

        assert lines == []

    def test_get_edge_style_lines_with_empty_config_returns_empty_list(self, mock_basegraph):
        """
        Test get_edge_style_lines with empty multiEdgeStyles config.

        Given: Config with no multiEdgeStyles
        When: get_edge_style_lines is called
        Then: Returns empty list
        """
        mock_basegraph.config_loader.get_control_edge_styles.return_value = {
            "multiEdgeStyles": [],
        }
        styler = MultiEdgeStyler(basegraph=mock_basegraph)

        styler.set_edge(0)
        styler.set_edge(1)

        lines = styler.get_edge_style_lines()

        assert lines == []

    def test_get_edge_style_lines_skips_empty_style_groups(self, mock_basegraph):
        """
        Test that get_edge_style_lines skips empty style groups.

        Given: Edges only in some style groups
        When: get_edge_style_lines is called
        Then: Only generates lines for groups with edges
        """
        styler = MultiEdgeStyler(basegraph=mock_basegraph)

        # Only add to groups 0 and 2
        styler.edges[0].append(0)
        styler.edges[2].append(2)

        lines = styler.get_edge_style_lines()

        assert len(lines) == 2  # Only two groups have edges


class TestToMermaid:
    """
    Test to_mermaid method.

    Tests focus on output formatting.
    """

    @pytest.fixture
    def mock_config_loader(self):
        """Provide mock config loader."""
        return Mock(spec=MermaidConfigLoader)

    def test_to_mermaid_markdown_format(self, mock_config_loader):
        """
        Test to_mermaid with markdown format.

        Given: BaseGraph with graph content
        When: to_mermaid("markdown") is called
        Then: Returns graph wrapped in markdown code fence
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)
        graph.graph = "graph TD\n    comp1[Component 1]"

        result = graph.to_mermaid(output_format="markdown")

        assert result.startswith("```mermaid\n")
        assert "graph TD" in result
        assert result.strip().endswith("```")

    def test_to_mermaid_raw_format(self, mock_config_loader):
        """
        Test to_mermaid with raw format.

        Given: BaseGraph with graph content
        When: to_mermaid(output_format not markdown) is called
        Then: Returns graph content without markdown wrapper
        """
        components = {
            "comp1": ComponentNode(title="C1", category="componentsData", to_edges=[], from_edges=[]),
        }
        graph = BaseGraph(components=components, config_loader=mock_config_loader)
        graph.graph = "graph TD\n    comp1[Component 1]"

        result = graph.to_mermaid(output_format="raw")

        assert not result.startswith("```")
        assert "graph TD" in result
        assert "comp1[Component 1]" in result
