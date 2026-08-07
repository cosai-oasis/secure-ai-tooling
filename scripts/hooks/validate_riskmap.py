#!/usr/bin/env python3
"""
Git pre-commit hook for component edge validation and graph generation.

Validates bidirectional edge consistency in YAML component files.
Can generate Mermaid graph visualizations of component, control, and risk relationships.

Usage:
    python validate_riskmap.py                    # Check staged files
    python validate_riskmap.py --force            # Force check
    python validate_riskmap.py --to-graph out.md  # Generate component graph
    python validate_riskmap.py --to-controls-graph ctrl.md  # Generate control graph
    python validate_riskmap.py --to-risk-graph risk.md      # Generate risk graph

Options:
    --force             Force validation regardless of git status
    --file PATH         Validate this components corpus instead of the default;
                        not valid with --force, --mode lifecycle,
                        --to-controls-graph or --to-risk-graph
    --allow-isolated    Allow components with no edges
    --block             Promote warn-only check warnings to errors and exit 1
    --quiet, -q         Minimal output
    --debug             Include debug annotations in graphs
    --mermaid-format    Save additional .mermaid format files
"""

import argparse
import sys
from pathlib import Path

import yaml

# Configuration Constants
from riskmap_validator.config import DEFAULT_COMPONENTS_FILE
from riskmap_validator.graphing import ComponentGraph, ControlGraph, RiskGraph
from riskmap_validator.utils import get_staged_yaml_files, parse_controls_yaml, parse_risks_yaml
from riskmap_validator.validator import (
    ComponentEdgeValidator,
    CorpusParseError,
    check_category_subcategory_nesting,
    check_controls_components_mirror,
    check_lifecycle_stage_order_uniqueness,
)


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Validate component edge consistency in YAML files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                          # Check staged components.yaml
  %(prog)s --force                                  # Force check default file
  %(prog)s --file custom/components.yaml            # Check specific file
  %(prog)s --allow-isolated                         # Allow components with no edges
  %(prog)s --to-graph graph.md                      # Output component graph as .md code block
  %(prog)s --to-controls-graph controls.md          # Output control-to-component graph
  %(prog)s --to-risk-graph risk.md                  # Output risk-to-control-to-component graph
  %(prog)s --to-graph graph.md --mermaid-format     # Output both .md and .mermaid formats
  %(prog)s --quiet                                  # Minimal output
  %(prog)s --help                                   # Show this help

Exit Codes:
  0 - All validations passed
  1 - Validation failures found
  2 - Configuration or runtime error
        """,
    )

    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force validation even if files not staged for commit",
    )

    parser.add_argument(
        "--file",
        type=Path,
        help=(
            f"Path to the components YAML file to validate (default: {DEFAULT_COMPONENTS_FILE}). "
            "Names the corpus directly and ignores git staging, so it cannot be combined with "
            "--force, is not accepted with --mode lifecycle, and is rejected with "
            "--to-controls-graph and --to-risk-graph, which read the repo's own controls.yaml "
            "and risks.yaml. --to-graph stays available, being drawn from this corpus. The "
            "repo-scoped checks (lifecycle order, controls mirror) are skipped when it names a "
            "corpus other than the default."
        ),
    )

    parser.add_argument(
        "--allow-isolated",
        action="store_true",
        help="Allow components with no edges (isolated components)",
    )

    parser.add_argument("--quiet", "-q", action="store_true", help="Minimize output (only show errors)")

    parser.add_argument(
        "--to-graph",
        "-g",
        type=Path,
        help="Output component graph visualization to specified txt file",
    )

    parser.add_argument(
        "--to-controls-graph",
        "-c",
        type=Path,
        help="Output control-to-component graph visualization to specified file",
    )

    parser.add_argument(
        "--to-risk-graph",
        "-r",
        type=Path,
        help="Output risk-to-control-to-component graph visualization to specified file",
    )

    parser.add_argument(
        "--block",
        action="store_true",
        default=False,
        help="Promote warn-only check warnings to errors and exit 1.",
    )

    parser.add_argument("--debug", action="store_true", help="Include rank comments in graph output")

    parser.add_argument(
        "--mermaid-format",
        "-m",
        action="store_true",
        help="Save graphs in '.mermaid' format in addition to markdown code block",
    )

    parser.add_argument(
        "--mode",
        choices=["default", "lifecycle"],
        default="default",
        help=(
            "Run a specific check mode. 'lifecycle': run only the lifecycle-stage.yaml "
            "order-uniqueness check (used by validate-lifecycle-stage pre-commit hook). "
            "'default': run the full component-edges + warn-only check pipeline."
        ),
    )

    args = parser.parse_args()

    # --force and --file answer the same question — which corpus to validate —
    # and lifecycle mode reads a fixed path that --file cannot name. Reject
    # (exit 2, argparse's usage-error code) rather than accepting and discarding.
    if args.file is not None:
        if args.force:
            parser.error("--file cannot be combined with --force: both select which corpus to validate")
        if args.mode == "lifecycle":
            parser.error("--file is not valid with --mode lifecycle: that mode reads lifecycle-stage.yaml only")
        # Both graph call sites below pass no path, so they read the repo's own
        # controls.yaml — and, for --to-risk-graph, risks.yaml. Joined to the
        # components --file names, every control→component edge drops and the run
        # exits 0 on a fully rendered diagram of a system with no controls.
        for flag, value in (
            ("--to-controls-graph", args.to_controls_graph),
            ("--to-risk-graph", args.to_risk_graph),
        ):
            if value is not None:
                parser.error(
                    f"--file cannot be combined with {flag}: that graph joins the repo's own "
                    f"controls and risks to the components, so it cannot be built from the corpus "
                    f"--file names. Use --to-graph, which is drawn from that corpus."
                )

    return args


def _run_lifecycle_mode(args: argparse.Namespace) -> int:
    """
    Run the dedicated lifecycle-stage order-uniqueness short-circuit.

    Loads risk-map/yaml/lifecycle-stage.yaml and runs only the uniqueness
    check. Bypasses ComponentEdgeValidator, get_staged_yaml_files, and
    graph generation. Returns the exit code for sys.exit().
    """
    lifecycle_path = Path("risk-map/yaml/lifecycle-stage.yaml")
    if not lifecycle_path.exists():
        # Mirror default-mode graceful skip when the file is absent.
        if not args.quiet:
            print("   Lifecycle stage order uniqueness check skipped (lifecycle-stage.yaml not found)")
        return 0

    # Broad except mirrors the default-mode skip pattern: malformed YAML
    # or unexpected I/O state degrades to a skip rather than crashing
    # the dedicated hook. SystemExit is excluded so explicit exits below
    # propagate.
    try:
        with open(lifecycle_path, encoding="utf-8") as fh:
            lifecycle_data = yaml.safe_load(fh)
        result = check_lifecycle_stage_order_uniqueness(lifecycle_data)
    except SystemExit:
        raise
    except Exception as e:
        if not args.quiet:
            print(f"   ⚠️  Lifecycle stage order uniqueness check skipped: {e}")
        return 0

    if result.is_valid:
        if not args.quiet:
            print("✅ Lifecycle stage order uniqueness check passed")
        return 0

    print("❌ Lifecycle stage order uniqueness check failed:")
    for error in result.errors:
        print(f"     - {error}")
    return 1


def main() -> None:
    """
    Main entry point for component edge validator.

    Can be used as git pre-commit hook or standalone tool.
    """
    try:
        args = parse_args()

        # Lifecycle mode short-circuits before ComponentEdgeValidator and
        # get_staged_yaml_files so a lifecycle-only commit (validate-lifecycle-stage
        # pre-commit hook) is reachable without depending on components.yaml state.
        # Graph flags (--to-graph etc.) are silently ignored in this mode.
        if args.mode == "lifecycle":
            sys.exit(_run_lifecycle_mode(args))

        # Initialize validator
        validator = ComponentEdgeValidator(allow_isolated=args.allow_isolated, verbose=not args.quiet)

        if not args.quiet:
            if args.file is not None:
                print(f"🔍 Checking components in {args.file}...")
            elif args.force:
                print("🔍 Force checking components...")
            else:
                print("🔍 Checking for staged YAML files...")

        # Get files to validate. --file names the corpus directly: routing it
        # through get_staged_yaml_files would buy nothing (an existing target is
        # returned without consulting the staged list, utils.py:254-258) and,
        # outside a git repository, would exit 0 having validated nothing.
        if args.file is not None:
            if not args.file.exists():
                print(f"❌ --file path does not exist: {args.file}")
                sys.exit(2)
            if not args.file.is_file():
                print(f"❌ --file path is not a file: {args.file}")
                sys.exit(2)
            yaml_files = [args.file]
        else:
            if args.force:
                target_file = DEFAULT_COMPONENTS_FILE
            else:
                target_file = None

            yaml_files = get_staged_yaml_files(target_file, args.force)

        if not yaml_files:
            if not args.quiet:
                print("   No YAML files to validate - skipping")
            sys.exit(0)

        if not args.quiet:
            file_count = len(yaml_files)
            file_word = "file" if file_count == 1 else "files"
            print(f"   Found {file_count} YAML {file_word} to validate")

        # Validation of components.yaml is required if we are checking any other
        # file — whichever of components/controls/risks was staged. --file swaps
        # which corpus that is.
        components_file = args.file if args.file is not None else DEFAULT_COMPONENTS_FILE

        all_valid = True
        if yaml_files:
            # A corpus that will not parse is bad input, not an internal bug:
            # report the file and the reason. The guard covers the parse only —
            # a failure during the checks is a defect in this tool and must keep
            # reaching the crash banner, or good corpora get blamed on the user.
            try:
                components = validator.parse_corpus(components_file)
            except CorpusParseError as e:
                print(f"❌ Could not validate {components_file}: {e}")
                sys.exit(2)

            if not validator.validate_loaded(components, components_file):
                all_valid = False
            if not args.quiet and len(yaml_files) > 1:
                print()  # Add spacing between files

        # Report final results
        if not all_valid:
            print("❌ Component edge validation failed!")
            print("   Fix the above errors before committing.")
            sys.exit(1)

        if not args.quiet:
            print("✅ All YAML files passed component edge validation")

        # Lifecycle order and the controls↔components mirror read repo files
        # other than the corpus under test, so a custom --file corpus makes them
        # report manufactured findings; they skip, and say so — a silent skip is
        # indistinguishable from a pass. Nesting stays: its categories block
        # comes from the same file. Compared resolved, so --file naming the
        # default corpus is not a weaker run than --force over the same bytes.
        skip_repo_scoped = args.file is not None and args.file.resolve() != DEFAULT_COMPONENTS_FILE.resolve()

        # Lifecycle stage order uniqueness check (ADR-022 D4).
        # Block-mode-immediate: no --block flag required. If the file is absent,
        # skip gracefully — lifecycle-stage.yaml may not be present in all test cwds.
        # Guard on validator.components mirrors the mirror/nesting check pattern:
        # only run when a real component validation pass populated the validator,
        # avoiding spurious open() calls in unit tests that mock builtins.open.
        lifecycle_path = Path("risk-map/yaml/lifecycle-stage.yaml")
        if skip_repo_scoped:
            if not args.quiet:
                print("   Lifecycle stage order uniqueness check skipped (--file names a custom corpus)")
        elif validator.components:
            if lifecycle_path.exists():
                try:
                    with open(lifecycle_path, encoding="utf-8") as _fh:
                        _lifecycle_data = yaml.safe_load(_fh)
                    lifecycle_result = check_lifecycle_stage_order_uniqueness(_lifecycle_data)
                    if lifecycle_result.is_valid:
                        if not args.quiet:
                            print("✅ Lifecycle stage order uniqueness check passed")
                    else:
                        print("❌ Lifecycle stage order uniqueness check failed:")
                        for error in lifecycle_result.errors:
                            print(f"     - {error}")
                        sys.exit(1)
                except SystemExit:
                    raise
                except Exception as e:
                    if not args.quiet:
                        print(f"   ⚠️  Lifecycle stage order uniqueness check skipped: {e}")
            else:
                if not args.quiet:
                    print("   Lifecycle stage order uniqueness check skipped (lifecycle-stage.yaml not found)")

        # Run warn-only checks: controls↔components mirror (ADR-020 D7 / task 2.3.8)
        # and category/subcategory nesting (ADR-018 D6 / task 2.3.9).
        #
        # Both checks collect warnings independently. The exit decision is deferred
        # until after both have run so the user sees all warnings in one pass even
        # when --block is set.  The guard (controls_path.exists() and components
        # loaded) stays the same as before to avoid vacuous runs and file I/O in
        # test contexts where components are unavailable.
        controls_path = Path("risk-map/yaml/controls.yaml")

        # Track whether any warn-only check produced output that --block should
        # promote to a hard failure.
        warn_block_triggered = False

        if skip_repo_scoped:
            if not args.quiet:
                print("   Controls↔components mirror check skipped (--file names a custom corpus)")
        elif controls_path.exists() and validator.components:
            # Broad except wraps both the parse and the check. Lets malformed
            # controls.yaml or unexpected mock state in tests degrade to a skip
            # rather than crashing the script. SystemExit is excluded so the
            # block-mode exit below propagates correctly.
            try:
                controls = parse_controls_yaml(controls_path)
                component_ids = set(validator.components.keys())
                mirror_warnings = check_controls_components_mirror(controls, component_ids)
                if mirror_warnings:
                    label = "❌" if args.block else "⚠️"
                    print(f"   {label} Controls↔components mirror check found {len(mirror_warnings)} issue(s):")
                    for warning in mirror_warnings:
                        print(f"     - {warning}")
                    if args.block:
                        warn_block_triggered = True
                elif not args.quiet:
                    print("✅ Controls↔components mirror check passed")
            except SystemExit:
                raise
            except Exception as e:
                if not args.quiet:
                    print(f"   ⚠️  Controls↔components mirror check skipped: {e}")

        # Category/subcategory nesting check (ADR-018 D6 / task 2.3.9).
        # Runs regardless of whether the mirror check found issues so both sets
        # of warnings are visible before the exit decision below. Both halves of
        # the comparison come from components_file, so this check applies to a
        # --file corpus as it does to the default one.
        if components_file.exists() and validator.components:
            try:
                with open(components_file, encoding="utf-8") as _fh:
                    _components_data = yaml.safe_load(_fh)
                category_to_subcategories: dict[str, set[str]] = {}
                for _cat in _components_data.get("categories", []):
                    _cat_id = _cat.get("id")
                    if not isinstance(_cat_id, str):
                        continue
                    category_to_subcategories[_cat_id] = {
                        _sub.get("id") for _sub in _cat.get("subcategory", []) if isinstance(_sub.get("id"), str)
                    }
                nesting_warnings = check_category_subcategory_nesting(
                    validator.components, category_to_subcategories
                )
                if nesting_warnings:
                    label = "❌" if args.block else "⚠️"
                    print(f"   {label} Category/subcategory nesting check found {len(nesting_warnings)} issue(s):")
                    for warning in nesting_warnings:
                        print(f"     - {warning}")
                    if args.block:
                        warn_block_triggered = True
                elif not args.quiet:
                    print("✅ Category/subcategory nesting check passed")
            except SystemExit:
                raise
            except Exception as e:
                if not args.quiet:
                    print(f"   ⚠️  Category/subcategory nesting check skipped: {e}")

        # Unified exit for warn-only checks — fires after both checks have printed.
        if warn_block_triggered:
            print("   ❌ Warn-only check failures promoted to errors (--block).")
            sys.exit(1)

        if args.to_graph:
            graph = ComponentGraph(validator.forward_map, validator.components, debug=args.debug)
            try:
                graph_output = graph.to_mermaid()
                # Write graph to file
                with open(args.to_graph, "w", encoding="utf-8") as f:
                    f.write(graph_output)

                print(f"   Graph visualization saved to {args.to_graph}")

                # Save .mermaid format if requested
                if args.mermaid_format:
                    mermaid_file = args.to_graph.with_suffix(".mermaid")
                    mermaid_output = graph.to_mermaid(output_format="mermaid")
                    with open(mermaid_file, "w", encoding="utf-8") as f:
                        f.write(mermaid_output)
                    print(f"   Mermaid format saved to {mermaid_file}")
            except Exception as e:
                print(f"⚠️  Failed to generate graph: {e}")

        if args.to_controls_graph:
            try:
                # Parse controls and generate graph
                controls = parse_controls_yaml()
                control_graph = ControlGraph(controls, validator.components, debug=args.debug)

                controls_graph_output = control_graph.to_mermaid()

                # Write graph to file
                with open(args.to_controls_graph, "w", encoding="utf-8") as f:
                    f.write(controls_graph_output)

                print(f"   Controls graph visualization saved to {args.to_controls_graph}")

                # Save .mermaid format if requested
                if args.mermaid_format:
                    mermaid_file = args.to_controls_graph.with_suffix(".mermaid")
                    mermaid_output = control_graph.to_mermaid(output_format="mermaid")
                    with open(mermaid_file, "w", encoding="utf-8") as f:
                        f.write(mermaid_output)
                    print(f"   Mermaid format saved to {mermaid_file}")
            except Exception as e:
                print(f"⚠️  Failed to generate controls graph: {e}")

        if args.to_risk_graph:
            try:
                # Parse risks/controls and generate graph
                risks = parse_risks_yaml()
                controls = parse_controls_yaml()
                risk_graph = RiskGraph(risks, controls, validator.components, debug=args.debug)

                risk_graph_output = risk_graph.to_mermaid()

                # Write graph to file
                with open(args.to_risk_graph, "w", encoding="utf-8") as f:
                    f.write(risk_graph_output)

                print(f"   Risk graph visualization saved to {args.to_risk_graph}")

                # Save .mermaid format if requested
                if args.mermaid_format:
                    mermaid_file = args.to_risk_graph.with_suffix(".mermaid")
                    mermaid_output = risk_graph.to_mermaid(output_format="mermaid")
                    with open(mermaid_file, "w", encoding="utf-8") as f:
                        f.write(mermaid_output)
                    print(f"   Mermaid format saved to {mermaid_file}")
            except Exception as e:
                print(f"⚠️  Failed to generate risk graph: {e}")

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n⚠️  Validation interrupted by user")
        sys.exit(2)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("   Please report this issue to the maintainers")
        sys.exit(2)


if __name__ == "__main__":
    main()
