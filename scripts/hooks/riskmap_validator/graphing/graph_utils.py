from pathlib import Path
from typing import Any

import yaml

from ..config import DEFAULT_MERMAID_CONFIG_FILE


class MermaidConfigLoader:
    """
    Loads Mermaid styling configuration from YAML files with caching and fallbacks.

    Uses singleton pattern per file path. Provides emergency defaults if config fails to load.
    Thread-safe for read operations after initial loading.

    Fallback hierarchy: YAML config → emergency defaults → minimal defaults
    """

    _instances = {}  # Class-level cache for singleton pattern

    def __init__(self, config_file: Path = None) -> None:
        """
        Initialize with optional custom configuration file.

        Implements singleton pattern per file path to prevent duplicate loading.
        """
        self.config_file = config_file or DEFAULT_MERMAID_CONFIG_FILE
        self._config = None
        self._loaded = False
        self._load_error = None

    @classmethod
    def get_instance(cls, config_file: Path = None) -> "MermaidConfigLoader":
        """
        Get singleton instance for specified config file.
        """
        file_key = str(config_file or DEFAULT_MERMAID_CONFIG_FILE)
        if file_key not in cls._instances:
            cls._instances[file_key] = cls(config_file)
        return cls._instances[file_key]

    def _load_config(self) -> bool:
        """
        Load configuration from YAML file with error handling.

        Returns:
            True if loaded successfully, False otherwise
        """
        if self._loaded:
            return self._config is not None

        self._loaded = True

        try:
            if not self.config_file.exists():
                self._load_error = f"Configuration file not found: {self.config_file}"
                return False

            with open(self.config_file, "r", encoding="utf-8") as f:
                self._config = yaml.safe_load(f)

            if not isinstance(self._config, dict):
                self._load_error = f"Configuration file contains invalid YAML structure: {self.config_file}"
                self._config = None
                return False

            # Validate required top-level keys
            required_keys: list[str] = ["version", "foundation", "sharedElements", "graphTypes"]
            missing_keys: list[str] = [key for key in required_keys if key not in self._config]
            if missing_keys:
                self._load_error = f"Configuration missing required keys: {missing_keys}"
                self._config = None
                return False

            return True

        except yaml.YAMLError as e:
            self._load_error = f"YAML parsing error in {self.config_file}: {e}"
            self._config = None
            return False
        except Exception as e:
            self._load_error = f"Unexpected error loading {self.config_file}: {e}"
            self._config = None
            return False

    def _get_emergency_defaults(self) -> dict:
        """
        Get hardcoded emergency defaults for graph generation.

        Ensures graphs work even if config file is missing or corrupt.
        """
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
                }
            },
            "sharedElements": {
                "cssClasses": {
                    "hidden": "display: none;",
                    "allControl": "stroke:#4285f4,stroke-width:2px,stroke-dasharray: 5 5",
                },
                "componentCategories": {
                    "componentsInfrastructure": {
                        "fill": "#e6f3e6",
                        "stroke": "#333333",
                        "strokeWidth": "2px",
                        "subgroupFill": "#d4e6d4",
                    },
                    "componentsData": {
                        "fill": "#fff5e6",
                        "stroke": "#333333",
                        "strokeWidth": "2px",
                        "subgroupFill": "#f5f0e6",
                    },
                    "componentsApplication": {
                        "fill": "#e6f0ff",
                        "stroke": "#333333",
                        "strokeWidth": "2px",
                        "subgroupFill": "#e0f0ff",
                    },
                    "componentsModel": {
                        "fill": "#ffe6e6",
                        "stroke": "#333333",
                        "strokeWidth": "2px",
                        "subgroupFill": "#f0e6e6",
                    },
                },
            },
            "graphTypes": {
                "component": {
                    "direction": "TD",
                    "flowchartConfig": {"nodeSpacing": 25, "rankSpacing": 30, "padding": 5, "wrappingWidth": 250},
                },
                "control": {
                    "direction": "LR",
                    "flowchartConfig": {"nodeSpacing": 25, "rankSpacing": 30, "padding": 5, "wrappingWidth": 250},
                    "specialStyling": {
                        "componentsContainer": {
                            "fill": "#f0f0f0",
                            "stroke": "#666666",
                            "strokeWidth": "3px",
                            "strokeDasharray": "10 5",
                        },
                        "edgeStyles": {
                            "allControlEdges": {
                                "stroke": "#4285f4",
                                "strokeWidth": "3px",
                                "strokeDasharray": "8 4",
                            },
                            "subgraphEdges": {"stroke": "#34a853", "strokeWidth": "2px"},
                            "multiEdgeStyles": [
                                {"stroke": "#9c27b0", "strokeWidth": "2px"},
                                {"stroke": "#ff9800", "strokeWidth": "2px", "strokeDasharray": "5 5"},
                                {"stroke": "#e91e63", "strokeWidth": "2px", "strokeDasharray": "10 2"},
                                {"stroke": "#C95792", "strokeWidth": "2px", "strokeDasharray": "10 5"},
                            ],
                        },
                    },
                },
                "risk": {
                    "direction": "TD",
                    "flowchartConfig": {"nodeSpacing": 30, "rankSpacing": 40, "padding": 5, "wrappingWidth": 250},
                    "specialStyling": {
                        "componentsContainer": {
                            "fill": "#f0f0f0",
                            "stroke": "#666666",
                            "strokeWidth": "3px",
                            "strokeDasharray": "10 5",
                        },
                        "riskCategories": {
                            "risks": {
                                "fill": "#ffeef0",
                                "stroke": "#e91e63",
                                "strokeWidth": "2px",
                                "subgroupFill": "#ffe0e6",
                            }
                        },
                        "edgeStyles": {
                            "riskControlEdges": [
                                {"stroke": "#e91e63", "strokeWidth": "2px", "strokeDasharray": "5 3"},
                                {"stroke": "#d81b60", "strokeWidth": "2px", "strokeDasharray": "8 4"},
                                {"stroke": "#c2185b", "strokeWidth": "2px", "strokeDasharray": "10 2"},
                                {"stroke": "#ad1457", "strokeWidth": "2px", "strokeDasharray": "12 5"},
                            ],
                            "allControlEdges": {
                                "stroke": "#4285f4",
                                "strokeWidth": "3px",
                                "strokeDasharray": "8 4",
                            },
                            "subgraphEdges": {"stroke": "#34a853", "strokeWidth": "2px"},
                            "multiEdgeStyles": [
                                {"stroke": "#9c27b0", "strokeWidth": "2px"},
                                {"stroke": "#ff9800", "strokeWidth": "2px", "strokeDasharray": "5 5"},
                                {"stroke": "#e91e63", "strokeWidth": "2px", "strokeDasharray": "10 2"},
                                {"stroke": "#C95792", "strokeWidth": "2px", "strokeDasharray": "10 5"},
                            ],
                        },
                    },
                },
            },
        }

    def _get_safe_value(self, *path, default=None):
        """
        Get nested value from config with fallback to emergency defaults.

        Traverses config using key path. Falls back to emergency defaults, then final default.

        Args:
            *path: Sequence of keys to traverse (e.g., 'sharedElements', 'cssClasses')
            default: Final fallback value if not found

        Returns:
            Value at path, or default if not found
        """
        use_defaults = False
        use_emergency_defaults = False

        # Get emergency defaults once to avoid multiple calls
        emergency_defaults: dict[Any, Any] = self._get_emergency_defaults()

        # Load config if not already loaded
        if not self._load_config():
            if not isinstance(emergency_defaults, dict):
                use_defaults = True  # Emergency defaults invalid - use final default
            config: dict[Any, Any] = emergency_defaults
        else:
            if not isinstance(self._config, dict):
                config = {}
                use_emergency_defaults = True  # Primary config invalid - use emergency defaults
            else:
                config = self._config

        # Short-circuit if only final default is available
        if use_emergency_defaults and use_defaults:
            return default

        # Navigate config path using EAFP (try/except)
        try:
            current: dict[Any, Any] = config
            for key in path:
                current = current[key]
            return current
        except (KeyError, TypeError):
            # Path not found in primary config - try emergency defaults
            if use_defaults:
                return default  # Skip emergency defaults if already determined invalid
            else:
                try:
                    emergency_current: dict[Any, Any] = emergency_defaults
                    for emergency_key in path:
                        emergency_current = emergency_current[emergency_key]
                    return emergency_current
                except (KeyError, TypeError):
                    # Path not in emergency defaults either - use final default
                    return default

    def _create_flowchart_preamble(self, graph_config: dict) -> list[str] | None:
        """
        Generate Mermaid flowchart preamble from configuration.

        Creates graph declaration, initialization config, and CSS class definitions.

        Args:
            graph_config: Config dict with direction and flowchartConfig

        Returns:
            List of Mermaid syntax lines, or None if config invalid
        """
        if not isinstance(graph_config, dict) or not graph_config:
            return None

        css_classes: dict[Any, Any] = self.get_css_classes()

        graph_direction = graph_config.get("direction", "LR")
        flowchart_config = graph_config.get("flowchartConfig", {})
        node_spacing = flowchart_config.get("nodeSpacing", 25)
        rank_spacing = flowchart_config.get("rankSpacing", 30)
        node_padding = flowchart_config.get("padding", 5)
        wrapping_width = flowchart_config.get("wrappingWidth", 250)

        flowchart_params = f"'nodeSpacing': {node_spacing}, 'rankSpacing': {rank_spacing}"
        flowchart_params += f", 'padding': {node_padding}, 'wrappingWidth': {wrapping_width}"
        flowchart_init = flowchart_params
        mermaid_config = f"%%{{init: {{'flowchart': {{{flowchart_init}}}}}}}%%"

        # Get CSS class definitions with fallbacks
        hidden_class_def = css_classes.get("hidden", "display: none;")
        all_control_default = "stroke:#4285f4,stroke-width:2px,stroke-dasharray: 5 5"
        all_control_class_def = css_classes.get("allControl", all_control_default)

        lines: list[str] = []

        if frontmatter_config := graph_config.get("metadata"):  # Optional frontmatter config
            layout = frontmatter_config.get("layout")
            merge_edges = frontmatter_config.get("mergeEdges")
            node_strategy = frontmatter_config.get("nodePlacementStrategy")
            lines.extend(
                [
                    "---",
                    "config:",
                    f"  layout: {layout}",
                    "  elk:",
                    f"    mergeEdges: {merge_edges}",
                    f"    nodePlacementStrategy: {node_strategy}",
                    "---",
                    "",
                ]
            )

        lines.extend(
            [
                f"graph {graph_direction}",
                f"   {mermaid_config}",
                f"    classDef hidden {hidden_class_def}",
                f"    classDef allControl {all_control_class_def}",
                "",
            ]
        )

        return lines

    def get_component_category_styles(self) -> dict:
        """
        Get component category styling configuration.

        Returns styling for each category: fill, stroke, strokeWidth, subgroupFill.
        Used by ComponentGraph and ControlGraph for visual differentiation.

        Returns:
            Dict mapping category IDs to style properties, empty if not found
        """
        result = self._get_safe_value("sharedElements", "componentCategories", default={})
        return result if isinstance(result, dict) else {}

    def get_css_classes(self) -> dict:
        """
        Get CSS class definitions for graph styling.

        Returns predefined CSS classes: 'hidden' (display: none) and 'allControl' (blue dashed).
        Used in graph preambles and special element styling.

        Returns:
            Dict mapping class names to Mermaid style strings
        """
        result = self._get_safe_value("sharedElements", "cssClasses", default={})
        return result if isinstance(result, dict) else {}

    def get_graph_config(self, graph_type: str) -> tuple[dict, list]:
        """
        Get graph configuration and generated preamble for specified graph type.

        Combines config retrieval with preamble generation. Handles fallbacks for missing configs.

        Args:
            graph_type: Type of graph ('component', 'control', etc.)

        Returns:
            Tuple of (config dict, preamble lines list). Always returns valid containers.
        """
        # Get graph config with fallback to empty dict
        result = self._get_safe_value("graphTypes", graph_type, default={})
        if result is None:
            result = {}  # Ensure we always have a valid dictionary

        # Generate preamble from config
        preamble = self._create_flowchart_preamble(result)
        if preamble is None:
            preamble = []  # Ensure we always have a valid list

        return result, preamble

    def get_control_edge_styles(self) -> dict:
        """
        Get edge styling for control graphs.

        Returns styling for allControlEdges, subgraphEdges, and multiEdgeStyles (4 cycling colors).
        Used by ControlGraph for visual differentiation of relationship types.

        Returns:
            Dict with edge styling definitions, empty if not found
        """
        result = self._get_safe_value("graphTypes", "control", "specialStyling", "edgeStyles", default={})
        return result if isinstance(result, dict) else {}

    def get_risks_container_style(self, graph_type: str = "risk") -> dict:
        return self._get_group_container_style("risksContainer", graph_type)

    def get_components_container_style(self, graph_type: str = "risk") -> dict:
        return self._get_group_container_style("componentsContainer", graph_type)

    def get_controls_container_style(self, graph_type: str = "risk") -> dict:
        return self._get_group_container_style("controlsContainer", graph_type)

    def _get_group_container_style(self, container_type: str, graph_type: str) -> dict:
        """
        Get styling for containers of subgraphs - used in in control and risk graphs.

        Returns styling for top-level components, risks, controls subgraph:
        fill, stroke, strokeWidth, strokeDasharray
        Provides visual hierarchy in ControlGraph and RiskGraph visualizations.

        Returns:
            Dict with container styling properties, empty if not found
        """
        container_types: list[str] = ["componentsContainer", "controlsContainer", "risksContainer"]
        graph_types: list[str] = ["control", "risk"]
        if container_type not in container_types:
            return dict()

        if graph_type not in graph_types:
            return dict()

        result = self._get_safe_value("graphTypes", graph_type, "specialStyling", container_type, default={})
        return result if isinstance(result, dict) else {}

    def get_risk_category_styles(self) -> dict:
        """
        Get risk category styling configuration.

        Returns styling for risk categories: fill, stroke, strokeWidth, subgroupFill.
        Used by RiskGraph for visual differentiation.

        Returns:
            Dict mapping risk category IDs to style properties
        """
        result = self._get_safe_value("graphTypes", "risk", "specialStyling", "riskCategories", default={})
        return result if isinstance(result, dict) else {}

    def get_risk_edge_styles(self) -> dict:
        """
        Get edge styling for risk graphs.

        Returns styling for riskControlEdges, allControlEdges, subgraphEdges, and multiEdgeStyles.
        Used by RiskGraph for risk-to-control and control-to-component relationships.

        Returns:
            Dict with edge styling definitions
        """
        result = self._get_safe_value("graphTypes", "risk", "specialStyling", "edgeStyles", default={})
        return result if isinstance(result, dict) else {}

    def get_risk_control_edge_style(self, index: int = 0) -> dict:
        """
        Get risk-to-control edge style for specified index.

        Supports both single style object and array of 4 styles.
        When array is configured, cycles through styles using index % 4.

        Args:
            index: Edge index for array-based cycling (default: 0)

        Returns:
            Dict with stroke, strokeWidth, and strokeDasharray properties
        """
        edge_styles = self.get_risk_edge_styles()
        risk_control_edges = edge_styles.get("riskControlEdges", {})

        # Handle array format (new)
        if isinstance(risk_control_edges, list):
            if len(risk_control_edges) >= 4:
                return risk_control_edges[index % 4]
            elif len(risk_control_edges) > 0:
                return risk_control_edges[index % len(risk_control_edges)]
            else:
                # Empty array - fallback to emergency default
                return {"stroke": "#e91e63", "strokeWidth": "2px", "strokeDasharray": "5 3"}

        # Handle single object format (backward compatibility)
        elif isinstance(risk_control_edges, dict):
            return risk_control_edges

        # No configuration found - use emergency default
        return {"stroke": "#e91e63", "strokeWidth": "2px", "strokeDasharray": "5 3"}

    def clear_cache(self):
        """
        Clear cached config to force reload on next access.

        Resets _config, _loaded, and _load_error. Next access will reload from file.
        Useful during development when config files are modified.
        """
        self._config = None
        self._loaded = False
        self._load_error = None

    def get_load_status(self) -> tuple:
        """
        Get configuration loading status for debugging.

        Triggers loading if not already attempted. Safe to call multiple times.

        Returns:
            Tuple of (success bool, error message or None)
        """
        if not self._loaded:
            self._load_config()
        return (self._config is not None, self._load_error)


class UnionFind:
    def __init__(self, elements):
        """
        Initialize Union-Find data structure.

        Creates parent and rank mappings. Each element starts as its own parent.
        """
        self.parent = {elem: elem for elem in elements}  # Each element starts as its own parent
        self.rank = {elem: 0 for elem in elements}  # All trees start with rank 0

    def find(self, x):
        """
        Find root representative with path compression.
        """
        if self.parent[x] != x:
            # Path compression: make x point directly to the root
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x, y):
        """
        Merge sets containing x and y using union by rank.
        """
        root_x = self.find(x)  # Find root of x's set
        root_y = self.find(y)  # Find root of y's set

        if root_x != root_y:  # Only union if in different sets
            # Union by rank: attach smaller tree under larger tree
            if self.rank[root_x] < self.rank[root_y]:
                # y's tree is taller, make y's root the new root
                self.parent[root_x] = root_y
            elif self.rank[root_x] > self.rank[root_y]:
                # x's tree is taller, make x's root the new root
                self.parent[root_y] = root_x
            else:
                # Same rank: arbitrarily choose x's root and increment rank
                self.parent[root_y] = root_x
                self.rank[root_x] += 1

    def get_clusters(self):
        """
        Extract all disjoint sets as clusters.

        Groups elements by their root representative.
        Applies path compression for true roots.

        Returns:
            List of sets, each set is a cluster of related elements
        """
        clusters = {}
        for elem in self.parent:
            root = self.find(elem)  # Get root with path compression
            if root not in clusters:
                clusters[root] = set()
            clusters[root].add(elem)
        return list(clusters.values())
