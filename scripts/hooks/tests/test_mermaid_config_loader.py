#!/usr/bin/env python3
"""
Tests for MermaidConfigLoader

This test suite ensures the configuration loading system works correctly
before and after refactoring. Critical for ensuring BaseGraph refactoring
doesn't break existing functionality.
"""

import sys
import tempfile
from pathlib import Path

import pytest
import yaml

# Add scripts/hooks directory to path
git_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(git_root / "scripts" / "hooks"))

from riskmap_validator.graphing import MermaidConfigLoader  # noqa: E402
from riskmap_validator.graphing.graph_utils import UnionFind  # noqa: E402


class TestMermaidConfigLoader:
    """Test MermaidConfigLoader functionality before refactoring."""

    @pytest.fixture
    def temp_config_file(self):
        """Create a temporary config file for testing."""
        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        yield Path(temp_file.name)
        Path(temp_file.name).unlink(missing_ok=True)

    @pytest.fixture
    def valid_config_data(self):
        """Create valid configuration data."""
        return {
            "version": "1.0.0",
            "foundation": {
                "colors": {
                    "primary": "#4285f4",
                    "success": "#34a853",
                }
            },
            "sharedElements": {
                "cssClasses": {
                    "hidden": "display: none;",
                    "allControl": "stroke:#4285f4,stroke-width:2px,stroke-dasharray: 5 5",
                },
                "componentCategories": {
                    "componentsData": {
                        "fill": "#fff5e6",
                        "stroke": "#333333",
                        "strokeWidth": "2px",
                    }
                },
            },
            "graphTypes": {
                "component": {
                    "direction": "TD",
                    "flowchartConfig": {"nodeSpacing": 25, "rankSpacing": 30},
                },
                "control": {
                    "direction": "LR",
                    "flowchartConfig": {"nodeSpacing": 25, "rankSpacing": 30},
                    "specialStyling": {
                        "componentsContainer": {
                            "fill": "#f0f0f0",
                            "stroke": "#666666",
                        },
                        "edgeStyles": {
                            "allControlEdges": {"stroke": "#4285f4"},
                            "multiEdgeStyles": [{"stroke": "#9c27b0"}],
                        },
                    },
                },
            },
        }

    def create_config_file(self, file_path: Path, data: dict):
        """Helper to create config file with given data."""
        with open(file_path, "w") as f:
            yaml.dump(data, f)

    def test_singleton_pattern(self, temp_config_file, valid_config_data):
        """Test that singleton pattern works correctly."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader1 = MermaidConfigLoader.get_instance(temp_config_file)
        loader2 = MermaidConfigLoader.get_instance(temp_config_file)
        loader3 = MermaidConfigLoader.get_instance()  # Default config

        # Same file should return same instance
        assert loader1 is loader2
        # Different file should return different instance
        assert loader1 is not loader3

    def test_load_valid_config(self, temp_config_file, valid_config_data):
        """Test loading valid configuration."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader = MermaidConfigLoader(temp_config_file)
        success, error = loader.get_load_status()

        assert success is True
        assert error is None

    def test_load_missing_config_file(self):
        """Test loading non-existent configuration file."""
        missing_file = Path("nonexistent_config.yaml")
        loader = MermaidConfigLoader(missing_file)
        success, error = loader.get_load_status()

        assert success is False
        assert "Configuration file not found" in error

    def test_load_invalid_yaml(self, temp_config_file):
        """Test loading invalid YAML configuration."""
        temp_config_file.write_text("invalid: yaml: [content")

        loader = MermaidConfigLoader(temp_config_file)
        success, error = loader.get_load_status()

        assert success is False
        assert "YAML parsing error" in error

    def test_load_invalid_structure(self, temp_config_file):
        """Test loading YAML with invalid structure."""
        invalid_data = {"invalid": "structure"}
        self.create_config_file(temp_config_file, invalid_data)

        loader = MermaidConfigLoader(temp_config_file)
        success, error = loader.get_load_status()

        assert success is False
        assert "missing required keys" in error

    def test_emergency_defaults_fallback(self):
        """Test that emergency defaults are used when config fails."""
        missing_file = Path("nonexistent.yaml")
        loader = MermaidConfigLoader(missing_file)

        # Should fall back to emergency defaults
        css_classes = loader.get_css_classes()
        assert "hidden" in css_classes
        assert "allControl" in css_classes

        categories = loader.get_component_category_styles()
        assert "componentsData" in categories
        assert "componentsInfrastructure" in categories

    def test_get_safe_value_with_valid_config(self, temp_config_file, valid_config_data):
        """Test _get_safe_value with valid configuration."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader = MermaidConfigLoader(temp_config_file)

        # Test nested value retrieval
        hidden_class = loader._get_safe_value("sharedElements", "cssClasses", "hidden")
        assert hidden_class == "display: none;"

        # Test missing value with default
        missing_value = loader._get_safe_value("nonexistent", "path", default="default_value")
        assert missing_value == "default_value"

    def test_get_graph_config(self, temp_config_file, valid_config_data):
        """Test graph configuration retrieval."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader = MermaidConfigLoader(temp_config_file)

        # Test component graph config
        config, preamble = loader.get_graph_config("component")
        assert config["direction"] == "TD"
        assert isinstance(preamble, list)
        assert len(preamble) > 0

        # Test control graph config
        config, preamble = loader.get_graph_config("control")
        assert config["direction"] == "LR"
        assert "specialStyling" in config

    def test_create_flowchart_preamble(self, temp_config_file, valid_config_data):
        """Test flowchart preamble generation."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader = MermaidConfigLoader(temp_config_file)
        graph_config = {"direction": "TD", "flowchartConfig": {"nodeSpacing": 25}}

        preamble = loader._create_flowchart_preamble(graph_config)

        assert isinstance(preamble, list)
        assert "graph TD" in preamble
        assert any("classDef hidden" in line for line in preamble)
        assert any("classDef allControl" in line for line in preamble)

    def test_get_css_classes(self, temp_config_file, valid_config_data):
        """Test CSS classes retrieval."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader = MermaidConfigLoader(temp_config_file)
        css_classes = loader.get_css_classes()

        assert isinstance(css_classes, dict)
        assert "hidden" in css_classes
        assert "allControl" in css_classes
        assert css_classes["hidden"] == "display: none;"

    def test_get_component_category_styles(self, temp_config_file, valid_config_data):
        """Test component category styles retrieval."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader = MermaidConfigLoader(temp_config_file)
        categories = loader.get_component_category_styles()

        assert isinstance(categories, dict)
        assert "componentsData" in categories
        assert categories["componentsData"]["fill"] == "#fff5e6"

    def test_get_control_edge_styles(self, temp_config_file, valid_config_data):
        """Test control edge styles retrieval."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader = MermaidConfigLoader(temp_config_file)
        edge_styles = loader.get_control_edge_styles()

        assert isinstance(edge_styles, dict)
        assert "allControlEdges" in edge_styles
        assert "multiEdgeStyles" in edge_styles

    def test_get_components_container_style(self, temp_config_file, valid_config_data):
        """Test components container style retrieval."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader = MermaidConfigLoader(temp_config_file)
        container_style = loader.get_components_container_style()

        assert isinstance(container_style, dict)
        assert "fill" in container_style
        assert container_style["fill"] == "#f0f0f0"

    def test_cache_clearing(self, temp_config_file, valid_config_data):
        """Test cache clearing functionality."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader = MermaidConfigLoader(temp_config_file)

        # Load config first
        success1, _ = loader.get_load_status()
        assert success1 is True

        # Clear cache
        loader.clear_cache()

        # Should reload on next access
        success2, _ = loader.get_load_status()
        assert success2 is True

    def test_invalid_graph_config_fallback(self, temp_config_file, valid_config_data):
        """Test fallback behavior for invalid graph configuration."""
        self.create_config_file(temp_config_file, valid_config_data)

        loader = MermaidConfigLoader(temp_config_file)

        # Test with non-existent graph type
        config, preamble = loader.get_graph_config("nonexistent")
        assert config == {}
        assert preamble == []

    def test_emergency_defaults_structure(self):
        """Test that emergency defaults have required structure."""
        loader = MermaidConfigLoader(Path("nonexistent.yaml"))
        emergency_defaults = loader._get_emergency_defaults()

        # Check required top-level keys
        required_keys = ["version", "foundation", "sharedElements", "graphTypes"]
        for key in required_keys:
            assert key in emergency_defaults

        # Check foundation structure
        assert "colors" in emergency_defaults["foundation"]

        # Check shared elements structure
        assert "cssClasses" in emergency_defaults["sharedElements"]
        assert "componentCategories" in emergency_defaults["sharedElements"]

        # Check graph types structure
        assert "component" in emergency_defaults["graphTypes"]
        assert "control" in emergency_defaults["graphTypes"]


class TestMermaidConfigLoaderEdgeCases:
    """Test edge cases and coverage gaps for MermaidConfigLoader."""

    @pytest.fixture
    def temp_config_file(self):
        """Create a temporary config file for testing."""
        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        yield Path(temp_file.name)
        Path(temp_file.name).unlink(missing_ok=True)

    def test_load_config_non_dict_yaml_structure(self, temp_config_file):
        """
        Test _load_config() with YAML that parses to non-dict (e.g., list or string).

        Coverage: Lines 62-65
        """
        # Create YAML that parses to a list instead of dict
        temp_config_file.write_text("- item1\n- item2\n- item3")

        loader = MermaidConfigLoader(temp_config_file)
        success, error = loader.get_load_status()

        assert success is False
        assert "invalid YAML structure" in error
        assert loader._config is None

    def test_load_config_missing_required_keys(self, temp_config_file):
        """
        Test _load_config() with dict missing required keys.

        Coverage: Lines 70-73
        """
        # Create valid dict but missing required keys
        incomplete_config = {"version": "1.0.0", "foundation": {}}
        with open(temp_config_file, "w") as f:
            yaml.dump(incomplete_config, f)

        loader = MermaidConfigLoader(temp_config_file)
        success, error = loader.get_load_status()

        assert success is False
        assert "missing required keys" in error
        assert "sharedElements" in error or "graphTypes" in error

    def test_load_config_unexpected_exception(self, temp_config_file):
        """
        Test _load_config() handling of unexpected exceptions during load.

        Coverage: Lines 81-84
        """
        # Use a directory instead of a file to trigger an unexpected exception
        import os

        temp_dir = tempfile.mkdtemp()
        try:
            loader = MermaidConfigLoader(Path(temp_dir))
            success, error = loader.get_load_status()

            assert success is False
            assert "Unexpected error loading" in error
        finally:
            os.rmdir(temp_dir)

    def test_get_safe_value_emergency_defaults_invalid(self):
        """
        Test _get_safe_value() when emergency defaults are invalid.

        Coverage: Lines 233-234
        This tests the theoretical case where _get_emergency_defaults()
        returns non-dict (emergency safeguard).
        """
        loader = MermaidConfigLoader(Path("nonexistent.yaml"))

        # Mock emergency defaults to return invalid type
        original_get_emergency = loader._get_emergency_defaults

        def mock_emergency_defaults():
            return "not_a_dict"  # Invalid type

        loader._get_emergency_defaults = mock_emergency_defaults

        # Should fall back to default parameter
        result = loader._get_safe_value("sharedElements", "cssClasses", default={"fallback": "value"})
        assert result == {"fallback": "value"}

        # Restore original method
        loader._get_emergency_defaults = original_get_emergency

    def test_get_safe_value_primary_config_invalid_handling(self, temp_config_file):
        """
        Test _get_safe_value() when primary config is loaded but becomes invalid.

        Coverage: Lines 237-239
        """
        # Create valid YAML file first
        valid_config = {
            "version": "1.0.0",
            "foundation": {"colors": {}},
            "sharedElements": {"cssClasses": {}},
            "graphTypes": {},
        }
        with open(temp_config_file, "w") as f:
            yaml.dump(valid_config, f)

        loader = MermaidConfigLoader(temp_config_file)

        # Force load the config
        loader._load_config()

        # Corrupt the loaded config to non-dict
        loader._config = "not_a_dict"

        # Should fall back to emergency defaults
        css_classes = loader._get_safe_value("sharedElements", "cssClasses")
        assert isinstance(css_classes, dict)
        assert "hidden" in css_classes  # From emergency defaults

    def test_get_safe_value_both_defaults_fail_shortcircuit(self, temp_config_file):
        """
        Test _get_safe_value() short-circuit when both defaults fail.

        Coverage: Lines 244-245
        This tests the case where:
        1. Emergency defaults are invalid (use_defaults = True)
        2. Primary config loads successfully but is invalid (use_emergency_defaults = True)
        Both flags True triggers the short-circuit at line 245.
        """
        # Create a valid YAML file that loads successfully
        valid_config = {
            "version": "1.0.0",
            "foundation": {"colors": {}},
            "sharedElements": {"cssClasses": {}},
            "graphTypes": {},
        }
        with open(temp_config_file, "w") as f:
            yaml.dump(valid_config, f)

        loader = MermaidConfigLoader(temp_config_file)

        # Force the config to load first
        loader._load_config()

        # Now corrupt both the loaded config and emergency defaults
        loader._config = "not_a_dict"  # Primary config invalid -> use_emergency_defaults = True

        def mock_emergency_invalid():
            return "not_a_dict"  # Emergency defaults invalid -> use_defaults = True

        loader._get_emergency_defaults = mock_emergency_invalid

        # Should immediately return default without traversing (line 245)
        result = loader._get_safe_value("any", "path", default="final_fallback")
        assert result == "final_fallback"

    def test_get_safe_value_keyerror_in_emergency_defaults(self):
        """
        Test _get_safe_value() KeyError path in emergency defaults.

        Coverage: Line 256, 263-265
        """
        loader = MermaidConfigLoader(Path("nonexistent.yaml"))

        # Request a path that doesn't exist in emergency defaults
        result = loader._get_safe_value("nonexistent", "deeply", "nested", "path", default="not_found")
        assert result == "not_found"

    def test_get_graph_config_none_result_handling(self):
        """
        Test get_graph_config() handling when _get_safe_value returns None.

        Coverage: Line 372-373
        """
        loader = MermaidConfigLoader(Path("nonexistent.yaml"))

        # Mock _get_safe_value to return None explicitly
        original_get_safe = loader._get_safe_value

        def mock_get_safe(*args, **kwargs):
            return None

        loader._get_safe_value = mock_get_safe

        # Should handle None and convert to empty dict
        config, preamble = loader.get_graph_config("component")
        assert config == {}
        assert preamble == []

        # Restore
        loader._get_safe_value = original_get_safe

    def test_get_group_container_style_invalid_container_type(self):
        """
        Test _get_group_container_style() with invalid container_type.

        Coverage: Line 417-418
        """
        loader = MermaidConfigLoader()

        # Test with invalid container type
        result = loader._get_group_container_style("invalidContainer", "control")
        assert result == {}

    def test_get_group_container_style_invalid_graph_type(self):
        """
        Test _get_group_container_style() with invalid graph_type.

        Coverage: Line 420-421
        """
        loader = MermaidConfigLoader()

        # Test with invalid graph type
        result = loader._get_group_container_style("componentsContainer", "invalid_graph")
        assert result == {}

    def test_get_risk_control_edge_style_array_length_1(self):
        """
        Test get_risk_control_edge_style() with array of length 1 (modulo logic).

        Coverage: Lines 472-473
        """
        loader = MermaidConfigLoader()

        # Mock edge styles with single-element array
        original_get_risk = loader.get_risk_edge_styles

        def mock_risk_edges():
            return {"riskControlEdges": [{"stroke": "#single", "strokeWidth": "1px"}]}

        loader.get_risk_edge_styles = mock_risk_edges

        # Test that modulo works for indices beyond array length
        style0 = loader.get_risk_control_edge_style(0)
        style1 = loader.get_risk_control_edge_style(1)
        style5 = loader.get_risk_control_edge_style(5)

        assert style0["stroke"] == "#single"
        assert style1["stroke"] == "#single"  # index % 1 == 0
        assert style5["stroke"] == "#single"  # index % 1 == 0

        loader.get_risk_edge_styles = original_get_risk

    def test_get_risk_control_edge_style_array_length_2_3(self):
        """
        Test get_risk_control_edge_style() with arrays of length 2 and 3.

        Coverage: Lines 472-473
        """
        loader = MermaidConfigLoader()

        # Test with 2-element array
        def mock_risk_edges_2():
            return {
                "riskControlEdges": [
                    {"stroke": "#first"},
                    {"stroke": "#second"},
                ]
            }

        loader.get_risk_edge_styles = mock_risk_edges_2

        assert loader.get_risk_control_edge_style(0)["stroke"] == "#first"
        assert loader.get_risk_control_edge_style(1)["stroke"] == "#second"
        assert loader.get_risk_control_edge_style(2)["stroke"] == "#first"  # 2 % 2 == 0

        # Test with 3-element array
        def mock_risk_edges_3():
            return {
                "riskControlEdges": [
                    {"stroke": "#uno"},
                    {"stroke": "#dos"},
                    {"stroke": "#tres"},
                ]
            }

        loader.get_risk_edge_styles = mock_risk_edges_3

        assert loader.get_risk_control_edge_style(0)["stroke"] == "#uno"
        assert loader.get_risk_control_edge_style(1)["stroke"] == "#dos"
        assert loader.get_risk_control_edge_style(2)["stroke"] == "#tres"
        assert loader.get_risk_control_edge_style(3)["stroke"] == "#uno"  # 3 % 3 == 0

    def test_get_risk_control_edge_style_empty_array(self):
        """
        Test get_risk_control_edge_style() with empty array fallback.

        Coverage: Lines 474-476
        """
        loader = MermaidConfigLoader()

        # Mock with empty array
        def mock_empty_array():
            return {"riskControlEdges": []}

        loader.get_risk_edge_styles = mock_empty_array

        # Should fallback to emergency default
        style = loader.get_risk_control_edge_style(0)
        assert style["stroke"] == "#e91e63"
        assert style["strokeWidth"] == "2px"
        assert style["strokeDasharray"] == "5 3"

    def test_get_risk_control_edge_style_single_object(self):
        """
        Test get_risk_control_edge_style() with single object (backward compatibility).

        Coverage: Lines 478-480
        """
        loader = MermaidConfigLoader()

        # Mock with single dict object (old format)
        def mock_single_object():
            return {
                "riskControlEdges": {
                    "stroke": "#legacy",
                    "strokeWidth": "3px",
                    "strokeDasharray": "10 5",
                }
            }

        loader.get_risk_edge_styles = mock_single_object

        # Should return the single object regardless of index
        style = loader.get_risk_control_edge_style(0)
        assert style["stroke"] == "#legacy"
        style5 = loader.get_risk_control_edge_style(5)
        assert style5["stroke"] == "#legacy"

    def test_get_risk_control_edge_style_no_config(self):
        """
        Test get_risk_control_edge_style() with no configuration.

        Coverage: Lines 482-483
        When riskControlEdges is neither list nor dict (e.g., None or missing),
        the emergency default should be used.
        """
        loader = MermaidConfigLoader()

        # Mock with riskControlEdges as None (neither list nor dict)
        def mock_no_config():
            return {"riskControlEdges": None}

        loader.get_risk_edge_styles = mock_no_config

        # Should use emergency default
        style = loader.get_risk_control_edge_style(0)
        assert style["stroke"] == "#e91e63"
        assert style["strokeWidth"] == "2px"
        assert style["strokeDasharray"] == "5 3"

    def test_get_risk_control_edge_style_array_length_4_plus(self):
        """
        Test get_risk_control_edge_style() with array of length >= 4.

        Coverage: Line 471
        """
        loader = MermaidConfigLoader()

        # Mock with 4+ element array
        def mock_risk_edges_4():
            return {
                "riskControlEdges": [
                    {"stroke": "#color1"},
                    {"stroke": "#color2"},
                    {"stroke": "#color3"},
                    {"stroke": "#color4"},
                    {"stroke": "#color5"},
                ]
            }

        loader.get_risk_edge_styles = mock_risk_edges_4

        # Should use modulo 4 for indices
        assert loader.get_risk_control_edge_style(0)["stroke"] == "#color1"
        assert loader.get_risk_control_edge_style(1)["stroke"] == "#color2"
        assert loader.get_risk_control_edge_style(2)["stroke"] == "#color3"
        assert loader.get_risk_control_edge_style(3)["stroke"] == "#color4"
        assert loader.get_risk_control_edge_style(4)["stroke"] == "#color1"  # 4 % 4 == 0
        assert loader.get_risk_control_edge_style(7)["stroke"] == "#color4"  # 7 % 4 == 3

    def test_get_risks_container_style(self):
        """
        Test get_risks_container_style() method.

        Coverage: Line 396
        """
        loader = MermaidConfigLoader()

        # Should call _get_group_container_style with correct params
        result = loader.get_risks_container_style()
        assert isinstance(result, dict)

        # Test with custom graph_type
        result2 = loader.get_risks_container_style(graph_type="control")
        assert isinstance(result2, dict)

    def test_get_controls_container_style(self):
        """
        Test get_controls_container_style() method.

        Coverage: Line 401
        """
        loader = MermaidConfigLoader()

        result = loader.get_controls_container_style()
        assert isinstance(result, dict)

        result2 = loader.get_controls_container_style(graph_type="risk")
        assert isinstance(result2, dict)

    def test_get_risk_category_styles(self):
        """
        Test get_risk_category_styles() method.

        Coverage: Lines 436-437
        """
        loader = MermaidConfigLoader()

        result = loader.get_risk_category_styles()
        assert isinstance(result, dict)

        # With emergency defaults, should have risk categories
        assert "risks" in result

    def test_get_risk_edge_styles(self):
        """
        Test get_risk_edge_styles() method.

        Coverage: Lines 449-450
        """
        loader = MermaidConfigLoader()

        result = loader.get_risk_edge_styles()
        assert isinstance(result, dict)

        # With emergency defaults, should have edge styles
        assert "riskControlEdges" in result


class TestUnionFind:
    """Test UnionFind data structure edge cases."""

    def test_union_equal_rank_increment(self):
        """
        Test union() with equal rank trees increments rank.

        Coverage: Lines 544-547
        """
        elements = ["a", "b", "c", "d"]
        uf = UnionFind(elements)

        # Initially all elements have rank 0
        assert uf.rank["a"] == 0
        assert uf.rank["b"] == 0

        # Union two elements with equal rank
        uf.union("a", "b")

        # One root should have incremented rank
        root_a = uf.find("a")
        root_b = uf.find("b")
        assert root_a == root_b  # Same root

        # The chosen root should have rank 1
        assert uf.rank[root_a] == 1

    def test_union_different_ranks(self):
        """
        Test union() with different rank trees (no increment).

        Coverage: Lines 538-543
        """
        elements = ["x", "y", "z"]
        uf = UnionFind(elements)

        # Create different rank trees
        uf.union("x", "y")  # x and y merge, one gets rank 1
        initial_rank_xy = uf.rank[uf.find("x")]

        # Union z (rank 0) with x-y tree (rank 1)
        uf.union("z", "x")

        # The higher rank tree root should not increment
        final_root = uf.find("x")
        assert uf.rank[final_root] == initial_rank_xy

    def test_get_clusters_single_element(self):
        """
        Test get_clusters() with single-element clusters.

        Coverage: Line 560-564
        """
        elements = ["lone1", "lone2", "lone3"]
        uf = UnionFind(elements)

        # Don't perform any unions - each element is its own cluster
        clusters = uf.get_clusters()

        assert len(clusters) == 3
        for cluster in clusters:
            assert len(cluster) == 1

    def test_find_path_compression(self):
        """
        Test find() path compression optimization.

        Coverage: Lines 524-526
        """
        elements = ["a", "b", "c", "d"]
        uf = UnionFind(elements)

        # Create a chain: d -> c -> b -> a
        uf.union("a", "b")
        uf.union("b", "c")
        uf.union("c", "d")

        root = uf.find("d")

        # After path compression, d should point directly to root
        assert uf.parent["d"] == root

        # Subsequent finds should be O(1)
        assert uf.find("d") == root


class TestMermaidConfigLoaderIntegration:
    """Test integration between MermaidConfigLoader and graph classes."""

    def test_component_graph_uses_config_loader(self):
        """Test that ComponentGraph properly uses MermaidConfigLoader."""
        from riskmap_validator.graphing import ComponentGraph
        from riskmap_validator.models import ComponentNode

        components = {"comp1": ComponentNode("Test", "componentsData", [], [])}
        forward_map = {}

        # Should work with default config loader
        graph = ComponentGraph(forward_map, components)
        assert hasattr(graph, "config_loader")
        assert isinstance(graph.config_loader, MermaidConfigLoader)

        # Should work with custom config loader
        custom_loader = MermaidConfigLoader()
        graph_custom = ComponentGraph(forward_map, components, config_loader=custom_loader)
        assert graph_custom.config_loader is custom_loader

    def test_control_graph_uses_config_loader(self):
        """Test that ControlGraph properly uses MermaidConfigLoader."""
        from riskmap_validator.graphing import ControlGraph
        from riskmap_validator.models import ComponentNode, ControlNode

        controls = {"ctrl1": ControlNode("Test", "controlsData", ["comp1"], [], [])}
        components = {"comp1": ComponentNode("Test", "componentsData", [], [])}

        # Should work with default config loader
        graph = ControlGraph(controls, components)
        assert hasattr(graph, "config_loader")
        assert isinstance(graph.config_loader, MermaidConfigLoader)

        # Should work with custom config loader
        custom_loader = MermaidConfigLoader()
        graph_custom = ControlGraph(controls, components, config_loader=custom_loader)
        assert graph_custom.config_loader is custom_loader
