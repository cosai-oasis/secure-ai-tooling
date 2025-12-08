"""
Core foundation classes for Mermaid graph generation in the CoSAI Risk Map framework.

This module provides the foundational components used across all graph types:
- BaseGraph: Common functionality for category handling, display names, and configuration
- MermaidConfigLoader: Configuration management with caching and fallback mechanisms
- MultiEdgeStyler: Specialized edge styling for controls with multiple component mappings

The classes in this module enable consistent behavior across ComponentGraph, ControlGraph,
and RiskGraph implementations while providing shared utilities for Mermaid visualization.

Key Features:
    - Dynamic category discovery from YAML configuration files
    - Singleton configuration management with emergency fallbacks
    - Consistent edge styling across all graph types
    - Category display name mapping and normalization

Dependencies:
    - ..config: Configuration constants and default paths
    - pathlib: File system path handling
    - yaml: YAML configuration file parsing
"""

from os.path import commonprefix
from pathlib import Path

import yaml

from riskmap_validator.models import ComponentNode, ControlNode, RiskNode

from .graph_utils import MermaidConfigLoader, UnionFind


class BaseGraph:
    """
    Base class for Mermaid graph generation with shared utilities.

    This class provides common functionality for both ComponentGraph and ControlGraph,
    including category handling, display name generation, and configuration management.

    Key Features:
    - Dynamic category discovery from component/control data
    - Category display name generation with YAML config loading
    - Shared configuration patterns
    - Consistent category handling across graph types
    """

    def __init__(
        self,
        components: dict[str, ComponentNode],
        controls: dict[str, ControlNode] | None = None,
        risks: dict[str, RiskNode] | None = None,
        config_loader: "MermaidConfigLoader|None" = None,
    ):
        """
        Initialize BaseGraph with optional configuration loader.

        Args:
            config_loader (MermaidConfigLoader, optional): Configuration loader for
                styling and layout options. Defaults to None, which creates a singleton
                instance using default configuration paths.
        """
        self.config_loader = config_loader or MermaidConfigLoader.get_instance()
        self._category_names_cache = None
        self.controls: dict[str, ControlNode] = {}
        self.risks: dict[str, RiskNode] = {}

        self.component_by_category: dict[str, list[str]] = dict()
        self.component_by_subcategory: dict[str, dict[str, list[str]]] = dict()
        self.control_by_category: dict[str, list[str]] = dict()
        self.risks_by_category: dict[str, list[str]] = dict()

        self.components_by_control: dict[str, list[str]] = dict()
        self.graph: str = ""

        if not isinstance(components, dict) or not all(
            isinstance(node, ComponentNode) for node in components.values()
        ):
            raise TypeError("'components' must be a dict of ComponentNodes")
        self.components = components

        if isinstance(controls, dict) and all(isinstance(node, ControlNode) for node in controls.values()):
            self.controls = controls

        if isinstance(risks, dict) and all(isinstance(node, RiskNode) for node in risks.values()):
            self.risks = risks

    def to_mermaid(self, output_format: str = "markdown"):
        lines = self.graph
        if output_format == "markdown":
            lines = "```mermaid\n" + lines + "\n```"

        return lines + "\n"

    def _component_to_control_mapping(self):
        self._nodetype_a_to_b_mapping("component-by-control")

    def _risk_to_control_mapping(self):
        self._nodetype_a_to_b_mapping("risk-by-control")

    def _nodetype_a_to_b_mapping(self, mapping_type: str):
        # Build initial node_type a to mapping_type map (without optimization)
        initial_mapping = {}
        if mapping_type == "component-by-control":
            target_property = "components"
            if not self.components:
                return
            node_inventory = self.components
        elif mapping_type == "risk-by-control":
            target_property = "risks"
            if not self.risks:
                return
            node_inventory = self.risks

        else:
            raise ValueError("mapping_type must be: 'component-by-control' or 'risk-by-control'")

        for control_id, control in self.controls.items():
            mapped = getattr(control, target_property)
            if mapped == ["all"]:
                initial_mapping[control_id] = [target_property]
                continue  # Skip 'all' controls for subgrouping analysis
            elif mapped == ["none"] or not mapped:
                initial_mapping[control_id] = []
                continue  # Skip 'none' controls
            else:
                # Filter to only include components that actually exist
                valid_target_node = [node_id for node_id in mapped if node_id in node_inventory]
                initial_mapping[control_id] = valid_target_node

        self.initial_mapping = initial_mapping

    def _load_category_names(self, with_controls: bool = True) -> dict[str, str]:
        """
        Load category names from YAML files.

        Loads category display names from both controls.yaml and components.yaml
        configuration files, providing human-readable names for category IDs.

        Returns:
            dict[str, str]: Dictionary mapping category IDs to display names.
                           Returns empty dict if loading fails.
        """
        category_names: dict[str, str] = {}

        if not hasattr(self, "_category_names_cache") or self._category_names_cache is None:
            yaml_paths = [Path("risk-map/yaml/controls.yaml"), Path("risk-map/yaml/components.yaml")]

            # Load control categories & component categories
            for yaml_path in yaml_paths:
                try:
                    if yaml_path.exists():
                        with open(yaml_path, "r", encoding="utf-8") as f:
                            controls_data = yaml.safe_load(f)

                        for category in controls_data.get("categories", []):
                            if "id" in category and "title" in category:
                                # Append "Controls" to control category titles
                                category_names[category["id"]] = category["title"].title()
                except Exception:
                    pass  # Fallback to generated names if loading fails
            self._category_names_cache = category_names
        else:
            category_names = self._category_names_cache

        if not with_controls:
            category_names = {
                category_id: category_title
                for category_id, category_title in self._load_category_names().items()
                if not category_id.startswith("controls")
            }

        return category_names

    def _find_component_clusters(
        self, node_to_controls: dict[str, set], min_shared_controls: int = 2, min_nodes: int = 2
    ) -> dict[str, list[str]]:
        """
        Find clusters of components that share significant control overlap using graph clustering using
        Union Find class
        """
        return self._find_node_clusters("component", node_to_controls, min_shared_controls, min_nodes)

    def _find_node_clusters(
        self, node_type: str, node_to_controls: dict[str, set], min_shared_controls: int = 2, min_nodes: int = 2
    ) -> dict[str, list[str]]:
        """
        Find clusters of nodes that share significant control overlap using graph clustering using
        Union Find class
        """
        if node_type == "component":
            node_prefix = "component"
            node_category_prefix = "components"
        elif node_type == "risks":
            node_prefix = "risk"
            node_category_prefix = "risks"
        else:
            return {}

        nodes = list(node_to_controls.keys())

        uf = UnionFind(nodes)

        # Step 3: Union nodes with significant control overlap
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                comp1, comp2 = nodes[i], nodes[j]

                # Calculate shared controls using set intersection
                shared_controls = node_to_controls[comp1] & node_to_controls[comp2]

                # If significant overlap, these nodes should be clustered
                if len(shared_controls) >= min_shared_controls:
                    uf.union(comp1, comp2)

        # Step 4: Extract final clusters
        merged_clusters = uf.get_clusters()

        # Convert to named subgroups and filter by size
        result = {}
        for i, cluster in enumerate(merged_clusters):
            if len(cluster) >= min_nodes:
                # Generate a meaningful subgroup name
                cluster_list = sorted(list(cluster))

                # Try to find a common prefix for naming, avoiding conflicts
                common_prefix = commonprefix([comp.replace(node_prefix, "") for comp in cluster_list])
                if common_prefix and len(common_prefix) > 2:
                    # Check if this would conflict with existing categories
                    subgroup_name = f"{node_category_prefix}{common_prefix.title()}"
                    if subgroup_name in self.component_by_category:
                        # Avoid conflict by adding parent category context
                        parent_title = self.components[cluster_list[0]].category.replace(node_category_prefix, "")

                        if common_prefix.title() == parent_title:
                            subgroup_name += "Subgroup"
                        else:
                            subgroup_name += parent_title
                else:
                    subgroup_name = f"{node_category_prefix}Subgroup{i + 1}"

                result[subgroup_name] = cluster_list

        return result

    def _get_category_display_name(self, category: str) -> str:
        """
        Convert category ID to display name.

        Generates human-readable display names for category IDs, with fallback
        to auto-generated names when YAML configuration is not available.

        Args:
            category (str): Category ID to convert (e.g., "componentsData", "controlsInfrastructure")

        Returns:
            str: Human-readable display name (e.g., "Data Components", "Infrastructure Controls")
        """
        # Load category names if not already cached
        if not hasattr(self, "_category_names_cache") or self._category_names_cache is None:
            self._category_names_cache = self._load_category_names()

        category_names = self._category_names_cache
        title_suffix: str = ""

        # Handle dynamically generated category names
        if category not in category_names:
            # Remove "components" or "controls" prefix and capitalize
            if category.startswith("components"):
                display_name = category.replace("components", "").strip()
            elif category.startswith("controls"):
                display_name = category.replace("controls", "").strip()
                title_suffix = " Controls"
            elif category.startswith("risks"):
                display_name = category.replace("risks", "").strip()
                title_suffix = " Risks"
            # This isn't an expected dynamic category
            else:
                return category.title()

            if display_name:
                # Add spacing before capital letters for better readability
                import re

                spaced_name = re.sub(r"([a-z])([A-Z])", r"\1 \2", display_name)
                return f"{spaced_name.title()}{title_suffix}"

        return category_names.get(category, category.title())

    def _group_controls_by_category(self) -> dict[str, list[str]]:
        """Group control IDs by their category."""
        self.control_by_category, _ = self._group_node_by("controls")

        return self.control_by_category

    def _group_risks_by_category(self) -> dict[str, list[str]]:
        """Group control IDs by their category."""
        self.risks_by_category, _ = self._group_node_by("risks")

        return self.risks_by_category

    def _group_components_by_category(self, w_subcategories: bool = False):
        """Group component IDs by their category (simple mapping without subgroups)."""
        self.component_by_category, self.component_by_subcategory = self._group_node_by("components", True)

    def _group_node_by(
        self, node_type: str, w_subcategories: bool = False
    ) -> tuple[dict[str, list[str]], dict[str, dict[str, list[str]]]]:
        if node_type == "controls":
            items = self.controls
        elif node_type == "components":
            items = self.components
        elif node_type == "risks":
            items = self.risks
        else:
            raise ValueError("node_type must be 'controls' or 'components'")

        """Group node IDs by their category (simple mapping without subgroups)."""
        groups: dict[str, list[str]] = {}
        subcat_groups: dict[str, dict[str, list[str]]] = dict()

        # Initialize main categories only - subgrouping handled dynamically in optimization
        for node_id, node in items.items():
            category = node.category

            process_subcategories = False
            subcat: str = ""

            if isinstance(node, ComponentNode) and node.subcategory and w_subcategories:
                process_subcategories = True
                subcat = node.subcategory

            if category not in groups:
                groups[category] = [node_id]
            else:
                groups[category].append(node_id)

            if process_subcategories:
                if category not in subcat_groups:
                    subcat_groups[category] = dict()
                if subcat not in subcat_groups[category]:
                    subcat_groups[category][subcat] = []

                subcat_groups[category][subcat].append(node_id)

        return (groups, subcat_groups)

    def _get_edge_style(self, style: str | dict) -> str:
        """
        Get formatted edge style string for a given style configuration.

        This method is shared across all graph types for consistent edge styling.
        It delegates to the utility function for the actual formatting.

        Args:
            style: Style key (e.g., 'allControlEdges', 'subgraphEdges') or direct style config dict

        Returns:
            Formatted style string for use in linkStyle commands

        Example:
            >>> graph = BaseGraph()
            >>> style_str = graph._get_edge_style("allControlEdges")
            >>> print(style_str)  # "stroke:#4285f4,stroke-width:2px,stroke-dasharray: 8 4"
            >>>
            >>> custom_style = {"stroke": "#ff0000", "strokeWidth": "3px"}
            >>> style_str = graph._get_edge_style(custom_style)
            >>> print(style_str)  # "stroke:#ff0000,stroke-width:3px"
        """
        if isinstance(style, str):
            edge_styles = self.config_loader.get_control_edge_styles()
            style_config = edge_styles.get(style, {})
        else:
            style_config = style

        stroke = style_config.get("stroke", "#666")
        stroke_width = style_config.get("strokeWidth", "2px")
        stroke_dasharray = style_config.get("strokeDasharray", "")

        style_str = f"stroke:{stroke},stroke-width:{stroke_width}"
        style_str += f",stroke-dasharray: {stroke_dasharray}" if stroke_dasharray else ""

        return style_str

    def _create_subgraph_section(
        self, category: str, category_name: str, item_ids: list[str], items: dict, indent: str = "    "
    ) -> list[str]:
        """
        Create a subgraph section with items.

        This is a shared utility method for creating Mermaid subgraph sections
        that can be used by all graph types (components, controls, risks).

        Args:
            category: Category ID for the subgraph
            category_name: Display name for the subgraph
            item_ids: List of item IDs to include in the subgraph
            items: Dictionary mapping item IDs to objects with .title attributes
            indent: Indentation string for nested subgraphs

        Returns:
            List of Mermaid syntax lines for the subgraph section
        """
        lines = []
        lines.append(f'{indent}subgraph {category} ["{category_name}"]')

        # Special case for governance controls (can be extended for other categories)
        if category == "controlsGovernance":
            lines.append(f"{indent}    direction LR")

        for item_id in sorted(item_ids):
            item = items[item_id]
            lines.append(f"{indent}    {item_id}[{item.title}]")

        lines.append(f"{indent}end")
        lines.append("")
        return lines

    def _get_nested_subgraph_new(
        self, component_ids: list[str], category: str, category_name: str
    ) -> list[str] | None:
        if not (category_subgroups := self.component_by_subcategory.get(category, {})):
            return None

        nested_subgraph = []
        nested_subgraph.append(f'    subgraph {category} ["{category_name}"]')

        for component_id in sorted(component_ids):
            if not self.components[component_id].subcategory:
                component = self.components[component_id]
                nested_subgraph.append(f"        {component_id}[{component.title}]")

        # Add nested subgroups using the helper method
        for subgroup_name, subgroup_components in category_subgroups.items():
            subgroup_display_name = self._get_category_display_name(subgroup_name)
            subgroup_lines = self._create_subgraph_section(
                subgroup_name, subgroup_display_name, subgroup_components, self.components, "        "
            )
            # Remove the empty line at the end for nested subgroups
            if subgroup_lines and subgroup_lines[-1] == "":
                subgroup_lines.pop()
            nested_subgraph.extend(subgroup_lines)
        #            self._processed_subgroups.add(subgroup_name)

        nested_subgraph.append("    end")
        nested_subgraph.append("")

        return nested_subgraph

    def _get_node_style(self, style_type: str, **kwargs) -> str:
        """
        Get formatted node style string for different node types.

        This is a shared utility method for creating Mermaid node styling
        that can be used by all graph types (components, controls, risks).

        Args:
            style_type: Type of node styling ('componentsContainer', 'componentCategory',
                                              'dynamicSubgroup', 'riskCategory')
            **kwargs: Additional parameters specific to style type
                     - For 'componentCategory': category_config dict
                     - For 'dynamicSubgroup': parent_category string
                     - For 'riskCategory': category_config dict

        Returns:
            Formatted style string for use in style commands
        """
        if style_type == "componentCategory":
            category_config = kwargs.get("category_config", {})
            fill = category_config.get("fill", "#ffffff")
            stroke = category_config.get("stroke", "#333333")
            stroke_width = category_config.get("strokeWidth", "2px")
            return f"fill:{fill},stroke:{stroke},stroke-width:{stroke_width}"

        elif style_type == "riskCategory":
            category_config = kwargs.get("category_config", {})
            fill = category_config.get("fill", "#ffeef0")
            stroke = category_config.get("stroke", "#e91e63")
            stroke_width = category_config.get("strokeWidth", "2px")
            return f"fill:{fill},stroke:{stroke},stroke-width:{stroke_width}"

        elif style_type == "dynamicSubgroup":
            parent_category = kwargs.get("parent_category", "")
            component_categories = self.config_loader.get_component_category_styles()
            parent_config = component_categories.get(parent_category, {})
            subgroup_fill = parent_config.get("subgroupFill")

            # Fallback logic for subgroup colors if not in config
            if not subgroup_fill:
                if "Infrastructure" in parent_category:
                    subgroup_fill = "#d4e6d4"
                elif "Data" in parent_category:
                    subgroup_fill = "#f5f0e6"
                elif "Model" in parent_category:
                    subgroup_fill = "#f0e6e6"
                elif "Application" in parent_category:
                    subgroup_fill = "#e0f0ff"
                else:
                    subgroup_fill = "#f8f8f8"  # Default light gray

            return f"fill:{subgroup_fill},stroke:#333,stroke-width:1px"

        else:
            # Default fallback
            return "fill:#ffffff,stroke:#333333,stroke-width:2px"

    def _style_node_from_dict(self, style: dict) -> str:
        fill = style.get("fill", "#f0f0f0")
        stroke = style.get("stroke", "#666666")
        stroke_width = style.get("strokeWidth", "3px")
        stroke_dasharray = style.get("strokeDasharray", "10 5")
        container_style = f"fill:{fill},stroke:{stroke},stroke-width:{stroke_width}"
        return f"{container_style},stroke-dasharray: {stroke_dasharray}"


class MultiEdgeStyler:
    """
    Manages styling for controls with multiple component mappings.

    Handles the cycling color assignment for controls that map to 3+ individual
    components, applying distinct visual styles using 4 cycling colors.
    """

    def __init__(self, basegraph=None):
        self.edges: list[list[int]] = [[], [], [], []]
        self.index: int = 0
        if not basegraph or not isinstance(basegraph, BaseGraph):
            raise TypeError("Requires an instance of a BaseGraph subclass")

        self.basegraph = basegraph

    def set_edge(self, edge_index: int) -> None:
        """Add an edge index to the current style group and advance to next style."""
        style_index = self.index % 4
        self.edges[style_index].append(edge_index)
        self.index += 1

    def reset_index(self) -> None:
        """Reset the style index to start cycling from the first color again."""
        self.index = 0

    def get_edge_style_lines(self) -> list[str]:
        """Generate linkStyle lines for all collected multi-edges."""
        edge_styles = self.basegraph.config_loader.get_control_edge_styles()
        style_config = edge_styles.get("multiEdgeStyles", [])
        if not style_config:
            return []

        lines: list[str] = []

        for i, style_group in enumerate(self.edges):
            if style_group and i < len(style_config):
                style = style_config[i]
                style_string = self.basegraph._get_edge_style(style)
                edge_list = ",".join(map(str, style_group))
                lines.append(f"    linkStyle {edge_list} {style_string}")
        return lines
