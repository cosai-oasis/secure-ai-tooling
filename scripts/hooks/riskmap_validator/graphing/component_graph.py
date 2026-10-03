"""
Mermaid graph generator for AI system component relationships.

Generates directed graphs showing component dependencies with category-based
organization and topological ranking. Uses configuration-driven styling
for visual consistency across the CoSAI Risk Map framework.

Two emission modes, selected by `graphTypes.component.emission.mode`
(ADR-036, `EmissionConfig`):

- `flat` (default/rollback): every `components.yaml` edge drawn as a plain
  `{src} --> {tgt}` line under category subgraphs. Unchanged by this module.
- `decoupled`: `build_decoupled_plan()` (`graphing/decouple.py`) classifies edges
  into intra-cluster edges, cross-cluster channels routed through ports, and
  lifted aspects; `_emit_decoupled()` serializes that IR into Mermaid text.
"""

import logging
import re

from ..models import ComponentNode
from .base import BaseGraph
from .decouple import DecoupledPlan, PepWrapper, apply_display_acronyms, build_decoupled_plan, verify_plan
from .graph_utils import MermaidConfigLoader

logger = logging.getLogger(__name__)

# Matches a single, unambiguous `<source> --> <egress_port_id>` line (used by
# S10): the `$` anchor rules out the PEP port-chain grammar (`in --> pep -->
# out`, which has a second ` --> ` after the first token) so only genuine
# source->egress lines match.
_SOURCE_EGRESS_EDGE_PATTERN = re.compile(r"^\s*(\S+) --> (p_out_\S+)\s*$", re.MULTILINE)

# S6 raise-site signatures keyed by the `portStyles` key whose line is missing
# from the built text. S6 raises the same message whether the key is
# unconfigured (a config gap) or configured but not emitted (an emitter
# defect), so a signature only identifies WHICH key; `validate_riskmap.py`
# then reads the resolved config to decide between the two. The
# missing-category-style-line raise site has no entry: it is never a
# portStyles gap.
S6_MISSING_PORT_STYLE_SIGNATURES = {
    "port": "missing 'classDef port'",
    "pepport": "missing 'classDef pepport'",
    "pepWrapOutline": "missing pepWrapOutline style line",
}


def _anchored_edge_pattern(src: str, tgt: str) -> re.Pattern:
    """
    Build a regex matching an exact `<src> --> <tgt>` edge line (S9/S10 text-fidelity
    checks), anchored at both line-start and line-end (`re.MULTILINE`).

    Plain substring matching (`expected in text`) is unsafe here: this corpus's real
    component/port ids have genuine prefix relationships (e.g. `componentApplication`
    is a strict prefix of `componentApplicationInputHandling`), so a cross-wired edge
    to the wrong node can still satisfy `expected in text` via a prefix match against
    the wrong line. Anchoring both ends rules that out.
    """
    return re.compile(rf"^\s*{re.escape(src)} --> {re.escape(tgt)}\s*$", re.MULTILINE)


def _escape_quoted_label(label: str) -> str:
    """
    Escape a concern/arm label for use inside a Mermaid quoted node label.

    Only applies to the `["..."]`-delimited port-label grammar, where an
    embedded `"` would prematurely close the string and garble the rest of the
    line. Uses Mermaid's own `#quot;` HTML-entity escape (not a bespoke scheme).
    `%%` header comments are not string-delimited, so labels there are never
    escaped -- see `_decoupled_header_comments`.
    """
    return label.replace('"', "#quot;")


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

        Dispatches on `config_loader.get_emission_config().mode` (ADR-036 D3): a
        missing/corrupt config or `mode == "flat"` takes the legacy flat path below,
        unchanged; `mode == "decoupled"` builds the transform IR and serializes it via
        `_emit_decoupled()`.

        Args:
            layout (str): Graph layout orientation (unused, kept for compatibility)
            debug (bool): Include debug comments in output

        Returns:
            str: Complete Mermaid graph as string
        """
        # Start each render pass with a clean subgraph-id collision set (see
        # BaseGraph._reset_declared_subgraph_ids). Category ids are fixed and
        # reappear on every call; without this, a second call to build_graph()
        # on the same instance would see its own first-pass ids as already
        # taken and rename them for no reason. Only the flat path below calls
        # _create_subgraph_section/_get_nested_subgraph_new -- _emit_decoupled()
        # writes its subgraph lines directly -- but the reset sits before the
        # mode dispatch so every build starts clean regardless of mode.
        self._reset_declared_subgraph_ids()

        emission_cfg = self.config_loader.get_emission_config()
        if emission_cfg.mode == "decoupled":
            plan = build_decoupled_plan(self.forward_map, self.components, emission_cfg)
            return self._emit_decoupled(plan)

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

    # ========================================================================
    # Decoupled emission pass (ADR-036 D2)
    # ========================================================================

    def _emit_decoupled(self, plan: DecoupledPlan) -> str:
        """
        Serialize a `DecoupledPlan` into Mermaid text.

        Fixed 8-step order: (1) frontmatter + `graph LR` preamble, (2) header
        comments (guard warnings, lifted-aspect inventory, undrawn hop lists,
        reachability diagnostics), (3) `classDef port`/`classDef pepport`, (4)
        cluster/band/block/PEP-wrap subgraphs and node declarations, (5) drawn
        intra edges + PEP port chains, (6) source->egress and ingress->landing
        edges (a PEP-wrapped source resolves through its wrapper's `_out` port,
        mirroring `Arm.landing_id`'s identical target-side pattern), (7)
        invisible band-ordering links, (8) style lines.

        Runs the D7 emission self-check before returning: delegates to
        `verify_plan()` for S1/S4/S5/S7 (IR-level), adds S2 (broadcast arm-count
        consistency -- text-derived, see `_check_s2_arm_counts`), S3 (ingress
        out-degree), and S6 (style/classDef completeness) as text-level checks.
        S9/S10 (`_check_arm_landing_edges`, `_check_source_egress_edges`) close
        the cross-wired-edge gap S1-S8 cannot see: an IR field can be correct
        while the built text draws the edge to the wrong node. S8
        (`plan.diagnostics`) and `plan.warnings` (D7 guard output, G-A1..G-O1)
        are surfaced as header comments and logged; neither ever raises.

        Args:
            plan: The transform IR built by `build_decoupled_plan()`.

        Returns:
            str: Complete Mermaid graph text.

        Raises:
            AssertionError: On any D7 acceptance-rubric violation (S1-S7) or
                either of the S9/S10 text-fidelity checks.
        """
        emission_cfg = self.config_loader.get_emission_config()
        port_styles = emission_cfg.port_styles or {}

        lines: list[str] = []
        lines.extend(self._decoupled_preamble())
        lines.extend(self._decoupled_header_comments(plan))
        lines.extend(self._decoupled_classdefs(port_styles))
        lines.append("")
        lines.extend(self._decoupled_cluster_subgraphs(plan, port_styles))
        lines.append("")
        lines.extend(self._decoupled_edges(plan))
        lines.append("")
        lines.extend(self._decoupled_band_links(plan))
        lines.append("")
        lines.extend(self._decoupled_styles(plan, port_styles))

        text = "\n".join(lines)

        verify_plan(plan, self.components)
        self._check_s2_arm_counts(plan, text)
        self._check_arm_landing_edges(plan, text)
        self._check_source_egress_edges(plan, text)
        self._check_s3_ingress_out_degree(plan, text)
        self._check_s6_style_classdef_presence(plan, port_styles, text)
        for warning in plan.warnings:
            logger.warning(warning)
        for message in plan.diagnostics:
            logger.debug(message)

        return text

    def _decoupled_preamble(self) -> list[str]:
        """
        Step 1: frontmatter + `graph LR` preamble.

        Reuses the existing `get_graph_config("component")` machinery (ELK
        metadata, flowchart init, `classDef hidden`/`allControl`) but forces the
        graph direction to `LR` regardless of the config's own `direction` key
        (ADR-036 D3: `mermaid-styles.yaml`'s `direction` key stays `TD`, the
        layout `mode: flat` rolls back to, so the decoupled path hardcodes
        `LR` rather than reading it from config).
        """
        _, preamble = self.config_loader.get_graph_config("component")
        lines = list(preamble)
        for i, line in enumerate(lines):
            if line.startswith("graph "):
                lines[i] = "graph LR"
                break
        return lines

    def _decoupled_header_comments(self, plan: DecoupledPlan) -> list[str]:
        """
        Step 2: header comments -- lifted-aspect inventory, then the undrawn
        `p_out ⇢ p_in` hop list per broadcast (ADR-036 D6's normative comment
        convention), then any D7 guard warnings (`plan.warnings`), then any
        advisory reachability diagnostics (S8). Each section is omitted
        entirely (no placeholder) when it has nothing to report.

        Guard warnings get one line per warning with no umbrella label line --
        deliberately, so a diff that adds/removes warnings only ever adds/
        removes lines that literally contain the warning text (see
        `TestPlanWarningsSurfaced.test_warnings_never_raise_and_do_not_alter_
        drawn_output_structure` in test_decouple_emitter.py, which asserts every
        extra line in a warnings-present run contains one of the warnings).
        """
        lines: list[str] = []

        for lifted in plan.lifted_aspects:
            by_cluster: dict[str, list[str]] = {}
            for src, _tgt in lifted.edges:
                by_cluster.setdefault(self.components[src].category, []).append(src)
            lines.append(
                f"%% {lifted.aspect_id} is a lifted aspect (D4) -- {len(lifted.edges)} cross "
                "in-edge(s) removed from the drawn graph, by source cluster:"
            )
            for cluster in sorted(by_cluster):
                sources = sorted(by_cluster[cluster])
                lines.append(f"%%   {cluster} ({len(sources)}): {', '.join(sources)}")
            lines.append("")

        for broadcast in plan.broadcasts:
            lines.append(
                f"%% {broadcast.label} ⇢ {broadcast.arm_count} "
                "— the port-to-port hops are documented here, never drawn:"
            )
            for channel in broadcast.channels:
                for arm in channel.arms:
                    lines.append(f"%%   {broadcast.egress_port_id} ⇢ {arm.port_id}")
            lines.append("")

        if plan.warnings:
            for warning in plan.warnings:
                lines.append(f"%% WARNING: {warning}")
            lines.append("")

        if plan.diagnostics:
            lines.append("%% Reachability diagnostics (advisory only, D2/S8 -- never blocks emission):")
            for message in plan.diagnostics:
                lines.append(f"%%   {message}")
            lines.append("")

        return lines

    def _decoupled_classdefs(self, port_styles: dict[str, str]) -> list[str]:
        """
        Step 3: `classDef port`/`classDef pepport`/`classDef aspectStyle`,
        config-driven and position-fixed -- emitted whenever the config supplies
        the corresponding style, independent of whether this particular plan
        uses any port/pepport/aspect node (mirrors the flat emitter's always-
        emit-the-full-style-block convention). A missing key here is caught by
        S6 if the plan actually needs it (port/pepport only -- S6 deliberately
        does not gain an aspectStyle clause, see `TestAspectVisualMarker`'s
        docstring).
        """
        lines: list[str] = []
        if port := port_styles.get("port"):
            lines.append(f"    classDef port {port}")
        if pepport := port_styles.get("pepport"):
            lines.append(f"    classDef pepport {pepport}")
        if aspect_style := port_styles.get("aspectStyle"):
            lines.append(f"    classDef aspectStyle {aspect_style}")
        return lines

    def _decoupled_cluster_subgraphs(self, plan: DecoupledPlan, port_styles: dict[str, str]) -> list[str]:
        """
        Step 4: cluster subgraphs, containing (in order) the egress band, the
        ingress band, nested blocks, and direct members -- PEP-wrapped members
        (cluster-level or block-level) render as their own wrap subgraph instead
        of a plain node line. Containment: cluster ⊃ block ⊃ PEP-wrap, and
        cluster ⊃ egress/ingress band.
        """
        egress_roots = {broadcast.src_root for broadcast in plan.broadcasts}
        ingress_roots = {channel.tgt_root for broadcast in plan.broadcasts for channel in broadcast.channels}

        lines: list[str] = []
        for root in sorted(plan.clusters):
            cluster = plan.clusters[root]
            display = self._get_category_display_name(root)
            lines.append(f'subgraph {root} ["{display}"]')

            if root in egress_roots:
                lines.append(f'    subgraph {root}_egress ["Egress"]')
                for broadcast in plan.broadcasts:
                    if broadcast.src_root != root:
                        continue
                    label = _escape_quoted_label(broadcast.label)
                    port_line = f'{broadcast.egress_port_id}["▸ {label}  ⇢ {broadcast.arm_count}"]:::port'
                    lines.append(f"        {port_line}")
                lines.append("    end")

            if root in ingress_roots:
                lines.append(f'    subgraph {root}_ingress ["Ingress"]')
                for broadcast in plan.broadcasts:
                    for channel in broadcast.channels:
                        if channel.tgt_root != root:
                            continue
                        for arm in channel.arms:
                            label = _escape_quoted_label(arm.label)
                            lines.append(f'        {arm.port_id}["{label} ▸"]:::port')
                lines.append("    end")

            for block_id in sorted(cluster.blocks):
                block = cluster.blocks[block_id]
                block_display = self._get_category_display_name(block.id)
                lines.append(f'    subgraph {block.id} ["{block_display}"]')
                for member_id in sorted(block.members):
                    lines.extend(self._decoupled_member_lines(member_id, plan, port_styles, indent="        "))
                lines.append("    end")

            for member_id in cluster.members:
                lines.extend(self._decoupled_member_lines(member_id, plan, port_styles, indent="    "))

            lines.append("end")
            lines.append("")

        return lines

    def _decoupled_member_lines(
        self, member_id: str, plan: DecoupledPlan, port_styles: dict[str, str], indent: str
    ) -> list[str]:
        """
        A cluster/block member: a PEP wrap subgraph, or a plain `id[title]` node line.

        A lifted aspect (D3/D4) gets a visual marker -- a second label line
        stating its live lifted in-edge count and the `:::aspectStyle` class --
        but only when `aspectStyle` is configured. Without it, the node falls
        back to the plain declaration: this class's presence/absence is the sole
        gate, so a config that omits it never leaves an orphaned `:::aspectStyle`
        usage with no backing `classDef` (mirrors the `port`/`pepport` graceful-
        degradation convention).
        """
        if member_id in plan.pep_wrappers:
            return self._decoupled_pep_wrap_lines(plan.pep_wrappers[member_id], indent)
        # ADR-036 D8: display-only substitution; component title data is untouched.
        title = apply_display_acronyms(self.components[member_id].title)
        aspect_style = port_styles.get("aspectStyle")
        if aspect_style:
            for lifted in plan.lifted_aspects:
                if lifted.aspect_id == member_id:
                    count = len(lifted.edges)
                    return [f"{indent}{member_id}[{title}<br/>{count} writes lifted]:::aspectStyle"]
        return [f"{indent}{member_id}[{title}]"]

    def _decoupled_pep_wrap_lines(self, wrapper: PepWrapper, indent: str) -> list[str]:
        """
        The PEP wrap subgraph (ADR-036 D3): the enforcement point drawn inside
        its own outlined enclosure, with dedicated `in`/`out` ports carrying the
        `pepport` class and the PEP node itself declared inside.
        """
        # ADR-036 D8: display-only substitution; component title data is untouched.
        title = apply_display_acronyms(self.components[wrapper.pep_id].title)
        inner = indent + "    "
        return [
            f'{indent}subgraph {wrapper.wrap_id} ["{title}"]',
            f'{inner}{wrapper.in_id}["in"]:::pepport',
            f'{inner}{wrapper.out_id}["out"]:::pepport',
            f"{inner}{wrapper.pep_id}[{title}]",
            f"{indent}end",
        ]

    def _decoupled_edges(self, plan: DecoupledPlan) -> list[str]:
        """
        Steps 5-6: drawn intra edges (wrap -> retarget -> collapse, already
        resolved by the transform), PEP port-chain edges, then source->egress
        and ingress->landing edges.

        A PEP-wrapped broadcast source resolves through its wrapper's `_out`
        port rather than its raw component id -- the source-side mirror of
        `Arm.landing_id`'s identical `_in`-port resolution in
        `decouple.py::_build_arms` (ADR-036 D3: traffic must visibly enter and
        leave through the enforcement point).
        """
        lines: list[str] = []
        for src, tgt in plan.drawn_intra_edges:
            lines.append(f"    {src} --> {tgt}")
        for a, b in plan.collapsed_pairs:
            lines.append(f"    {a} <--> {b}")
        for pep_id in sorted(plan.pep_wrappers):
            wrapper = plan.pep_wrappers[pep_id]
            lines.append(f"    {wrapper.in_id} --> {wrapper.pep_id} --> {wrapper.out_id}")

        lines.append("")
        for broadcast in plan.broadcasts:
            sources = sorted({src for channel in broadcast.channels for src, _tgt in channel.edges})
            for src in sources:
                resolved_src = plan.pep_wrappers[src].out_id if src in plan.pep_wrappers else src
                lines.append(f"    {resolved_src} --> {broadcast.egress_port_id}")
            for channel in broadcast.channels:
                for arm in channel.arms:
                    lines.append(f"    {arm.port_id} --> {arm.landing_id}")

        return lines

    def _decoupled_band_links(self, plan: DecoupledPlan) -> list[str]:
        """Step 7: invisible `~~~` ordering links, consumed directly from `plan.band_links`."""
        return [f"    {a} ~~~ {b}" for a, b in plan.band_links]

    def _decoupled_styles(self, plan: DecoupledPlan, port_styles: dict[str, str]) -> list[str]:
        """Step 8: category styles verbatim, band containers, then `pepWrapOutline` per wrapper."""
        lines: list[str] = ["%% Node style definitions"]

        component_categories = self.config_loader.get_component_category_styles()
        for category_key, category_config in component_categories.items():
            style_str = self._get_node_style("componentCategory", category_config=category_config)
            lines.append(f"    style {category_key} {style_str}")

        egress_roots = {broadcast.src_root for broadcast in plan.broadcasts}
        ingress_roots = {channel.tgt_root for broadcast in plan.broadcasts for channel in broadcast.channels}
        for root in sorted(egress_roots):
            lines.append(f"    style {root}_egress fill:none,stroke:none")
        for root in sorted(ingress_roots):
            lines.append(f"    style {root}_ingress fill:none,stroke:none")

        if pep_wrap_outline := port_styles.get("pepWrapOutline"):
            for pep_id in sorted(plan.pep_wrappers):
                wrapper = plan.pep_wrappers[pep_id]
                lines.append(f"    style {wrapper.wrap_id} {pep_wrap_outline}")

        return lines

    # ========================================================================
    # Emission self-check (D7): S2/S3/S6, plus S9/S10 (S1/S4/S5/S7
    # delegate to verify_plan)
    # ========================================================================

    def _check_s2_arm_counts(self, plan: DecoupledPlan, text: str) -> None:
        """
        S2: every broadcast's declared `arm_count` matches the number of arms
        actually rendered.

        Text-derived: counts each arm's ingress port node DECLARATION
        (`{port_id}["`) as it literally appears in the built text, rather than
        recomputing `sum(len(channel.arms) ...)` from the same IR the plan was
        built from -- that recompute is tautological (it can never disagree with
        itself) and is blind to a real emitter defect that drops a declaration
        while leaving the IR internally consistent.

        Falls back to the IR arm count when `plan.clusters` is empty: the
        isolated self-check unit fixtures in `test_decouple_emitter.py`
        construct a bare `Broadcast`/`Channel`/`Arm` set with no corresponding
        cluster structure at all (by design, to isolate one check at a time), so
        no ingress declaration is ever rendered for them -- text-derived counting
        is inapplicable there, not evidence of a defect.
        """
        for broadcast in plan.broadcasts:
            arms = [arm for channel in broadcast.channels for arm in channel.arms]
            if plan.clusters:
                actual = sum(1 for arm in arms if f'{arm.port_id}["' in text)
            else:
                actual = len(arms)
            if actual != broadcast.arm_count:
                raise AssertionError(
                    f"S2 violated: broadcast '{broadcast.egress_port_id}' declares "
                    f"arm_count={broadcast.arm_count} but {actual} arm(s) are actually present"
                )

    def _check_arm_landing_edges(self, plan: DecoupledPlan, text: str) -> None:
        """
        S9 (closes the cross-wired-landing gap): every arm's
        `<port_id> --> <landing_id>` edge must appear, anchored, in the built
        text. An arm's `landing_id` can be correct in the IR while
        `_decoupled_edges` draws the edge to a different node -- no existing
        check (S1-S8) inspects a specific arm's edge destination.

        Uses `_anchored_edge_pattern` rather than `expected in text`: this
        corpus's ids have real prefix relationships (e.g. `componentApplication`
        is a prefix of `componentApplicationInputHandling`), so an unanchored
        substring check would miss a cross-wired edge to a prefix-related sibling.
        """
        for broadcast in plan.broadcasts:
            for channel in broadcast.channels:
                for arm in channel.arms:
                    if not _anchored_edge_pattern(arm.port_id, arm.landing_id).search(text):
                        raise AssertionError(
                            f"S9 violated: expected ingress->landing edge "
                            f"{arm.port_id!r} --> {arm.landing_id!r} not found (anchored) "
                            f"in the built text"
                        )

    def _check_source_egress_edges(self, plan: DecoupledPlan, text: str) -> None:
        """
        S10: every broadcast source resolves -- through
        `plan.pep_wrappers`, exactly as `_decoupled_edges` resolves it -- to a
        `<source> --> <egress_port_id>` edge that appears, anchored, in the built
        text, and every emitted source->egress-shaped edge (`<id> --> p_out_...`)
        matches one of those expected pairs. Catches a wrongly-resolved PEP
        source and a source wired to the wrong (or a nonexistent) broadcast port.

        The first loop uses `_anchored_edge_pattern` for the same reason as S9
        (prefix-related ids defeat unanchored substring matching). The second
        loop flags ANY matched pair absent from `expected_pairs` -- including a
        port id that belongs to no broadcast at all -- rather than filtering to
        known egress ports first; a typo'd/stale/nonexistent port must not be
        silently skipped.
        """
        expected_pairs: set[tuple[str, str]] = set()
        for broadcast in plan.broadcasts:
            sources = {src for channel in broadcast.channels for src, _tgt in channel.edges}
            for src in sources:
                resolved = plan.pep_wrappers[src].out_id if src in plan.pep_wrappers else src
                expected_pairs.add((resolved, broadcast.egress_port_id))

        for src, port in sorted(expected_pairs):
            if not _anchored_edge_pattern(src, port).search(text):
                raise AssertionError(
                    f"S10 violated: expected source->egress edge {src!r} --> {port!r} "
                    f"not found (anchored) in the built text"
                )

        for src, port in _SOURCE_EGRESS_EDGE_PATTERN.findall(text):
            if (src, port) not in expected_pairs:
                raise AssertionError(
                    f"S10 violated: emitted source->egress edge ({src} --> {port}) does "
                    f"not match the expected source/egress-port mapping for this broadcast"
                )

    def _check_s3_ingress_out_degree(self, plan: DecoupledPlan, text: str) -> None:
        """
        S3: every ingress port has emitted out-degree exactly 1.

        Scans the built text for ` --> ` chains (handles the plain-edge and the
        PEP port-chain grammar alike) and counts each token's occurrences as an
        edge source.
        """
        out_degree: dict[str, int] = {}
        for line in text.splitlines():
            if " --> " not in line:
                continue
            tokens = [token.strip() for token in line.split(" --> ")]
            for src in tokens[:-1]:
                out_degree[src] = out_degree.get(src, 0) + 1

        for broadcast in plan.broadcasts:
            for channel in broadcast.channels:
                for arm in channel.arms:
                    degree = out_degree.get(arm.port_id, 0)
                    if degree != 1:
                        raise AssertionError(
                            f"S3 violated: ingress port '{arm.port_id}' has out-degree "
                            f"{degree}, expected exactly 1"
                        )

    def _check_s6_style_classdef_presence(
        self, plan: DecoupledPlan, port_styles: dict[str, str], text: str
    ) -> None:
        """
        S6: every expected `style`/`classDef` line is present, verbatim, in the
        built text -- category styles unconditionally, `classDef port`/
        `pepport` and per-wrapper `pepWrapOutline` only when the plan actually
        draws ports/PEP wrappers (a config that omits a style the plan needs is
        a real gap, not a cosmetic one).
        """
        component_categories = self.config_loader.get_component_category_styles()
        for category_key, category_config in component_categories.items():
            style_str = self._get_node_style("componentCategory", category_config=category_config)
            expected = f"style {category_key} {style_str}"
            if expected not in text:
                raise AssertionError(f"S6 violated: missing category style line {expected!r}")

        if plan.broadcasts:
            port_style = port_styles.get("port")
            if not (port_style or "").strip() or f"classDef port {port_style}" not in text:
                raise AssertionError(
                    f"S6 violated: {S6_MISSING_PORT_STYLE_SIGNATURES['port']}, required by drawn ports"
                )

        if plan.pep_wrappers:
            pepport_style = port_styles.get("pepport")
            if not (pepport_style or "").strip() or f"classDef pepport {pepport_style}" not in text:
                raise AssertionError(
                    f"S6 violated: {S6_MISSING_PORT_STYLE_SIGNATURES['pepport']}, required by PEP wrappers"
                )

            pep_wrap_outline = port_styles.get("pepWrapOutline")
            for wrapper in plan.pep_wrappers.values():
                expected = f"style {wrapper.wrap_id} {pep_wrap_outline}" if pep_wrap_outline else None
                if not (pep_wrap_outline or "").strip() or expected not in text:
                    raise AssertionError(
                        f"S6 violated: {S6_MISSING_PORT_STYLE_SIGNATURES['pepWrapOutline']} "
                        f"for wrapper '{wrapper.wrap_id}'"
                    )
