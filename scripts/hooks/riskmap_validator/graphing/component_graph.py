"""
Mermaid graph generator for AI system component relationships.

Generates directed graphs showing component dependencies with category-based
organization and topological ranking. Uses configuration-driven styling
for visual consistency across the CoSAI Risk Map framework.
"""

from ..models import ComponentNode
from .base import BaseGraph
from .graph_utils import MermaidConfigLoader


class ComponentGraph(BaseGraph):
    """
    Generates Mermaid graphs for component relationships with category-based organization.

    Creates directed graphs showing component dependencies grouped by category
    (Data, Infrastructure, Model, Application). Organizes components into subgraphs
    and applies styling based on configuration files.

    Attributes:
        forward_map (dict[str, list[str]]): Maps component IDs to their dependencies
        debug (bool): Includes debug comments when True
        graph (str): Generated Mermaid graph content
    """

    def __init__(
        self,
        forward_map: dict[str, list[str]],
        components: dict[str, ComponentNode],
        debug: bool = False,
        config_loader: MermaidConfigLoader = None,
    ):
        """
        Initialize ComponentGraph with component relationships.

        Args:
            forward_map (dict[str, list[str]]): Maps component IDs to dependency lists
            components (dict[str, ComponentNode]): Maps component IDs to ComponentNode objects
            debug (bool): Include debug comments in output
            config_loader (MermaidConfigLoader): Configuration for styling (creates default if None)
        """
        super().__init__(components=components, config_loader=config_loader)
        self.forward_map = forward_map
        self.debug = debug
        self.graph = self.build_graph(debug=debug)

    def build_graph(self, layout="horizontal", debug=False) -> str:
        """
        Build Mermaid graph with category subgraphs and component relationships.

        Args:
            layout (str): Graph layout orientation (unused, kept for compatibility)
            debug (bool): Include debug comments in output

        Returns:
            str: Complete Mermaid graph as string
        """

        # Load graph configuration and category styles
        _, graph_preamble = self.config_loader.get_graph_config("component")
        component_categories = self.config_loader.get_component_category_styles()

        # Group components by category for subgraph organization
        self._group_components_by_category(True)

        # Start with configuration-driven preamble
        graph_content = graph_preamble

        # Build category subgraphs
        for category in self.component_by_category:
            subgraph_lines = self._build_subgraph_structure(category, self.component_by_category[category], debug)
            graph_content.extend(subgraph_lines)

        # Add dependency edges outside subgraphs for cleaner layout
        graph_content.append("")
        for src, targets in self.forward_map.items():
            for tgt in targets:
                graph_content.append(f"    {src} --> {tgt}")

        # Apply category styling
        graph_content.extend(["", "%% Node style definitions"])
        for category_key, category_config in component_categories.items():
            style_str = self._get_node_style("componentCategory", category_config=category_config)
            graph_content.append(f"    style {category_key} {style_str}")

        return "\n".join(graph_content)

    def _build_subgraph_structure(
        self,
        category: str,
        components: list[str],
        debug: bool = False,
    ) -> list:
        """
        Build formatted subgraph for a component category.

        Args:
            category (str): Component category key
            components (list[str]): Component IDs in this category
            debug (bool): Include debug comments (unused here)

        Returns:
            list: Mermaid subgraph lines
        """
        category_display = self._get_category_display_name(category)

        if category in self.component_by_subcategory:
            subgraph_lines = self._get_nested_subgraph_new(
                category=category, category_name=category_display, component_ids=sorted(components)
            )
        else:
            subgraph_lines = self._create_subgraph_section(
                category=category,
                category_name=category_display,
                item_ids=sorted(components),
                items=self.components,
            )

        return subgraph_lines or []
