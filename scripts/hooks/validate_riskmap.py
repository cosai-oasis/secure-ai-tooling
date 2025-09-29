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
    --file PATH         Custom YAML file path
    --allow-isolated    Allow components with no edges
    --quiet, -q         Minimal output
    --debug             Include debug annotations in graphs
    --mermaid-format    Save additional .mermaid format files
"""

import argparse
import sys
from pathlib import Path

# Configuration Constants
from riskmap_validator.config import DEFAULT_COMPONENTS_FILE
from riskmap_validator.graphing import ComponentGraph, ControlGraph, RiskGraph
from riskmap_validator.utils import get_staged_yaml_files, parse_controls_yaml, parse_risks_yaml
from riskmap_validator.validator import ComponentEdgeValidator


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
        help=f"Path to YAML file to validate (default: {DEFAULT_COMPONENTS_FILE})",
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

    parser.add_argument("--debug", action="store_true", help="Include rank comments in graph output")

    parser.add_argument(
        "--mermaid-format",
        "-m",
        action="store_true",
        help="Save graphs in '.mermaid' format in addition to markdown code block",
    )

    return parser.parse_args()


def main() -> None:
    """
    Main entry point for component edge validator.

    Can be used as git pre-commit hook or standalone tool.
    """
    try:
        args = parse_args()

        # Initialize validator
        validator = ComponentEdgeValidator(allow_isolated=args.allow_isolated, verbose=not args.quiet)

        if not args.quiet:
            if args.force:
                print("🔍 Force checking components...")
            else:
                print("🔍 Checking for staged YAML files...")

        # Get files to validate
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

        # Validation of components.yaml is required if we are checking any other file
        all_valid = True
        if yaml_files:
            if not validator.validate_file(DEFAULT_COMPONENTS_FILE):
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
                    mermaid_file = args.to_graph.with_suffix('.mermaid')
                    mermaid_output = graph.to_mermaid(output_format='mermaid')
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
                    mermaid_file = args.to_controls_graph.with_suffix('.mermaid')
                    mermaid_output = control_graph.to_mermaid(output_format='mermaid')
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
                    mermaid_file = args.to_risk_graph.with_suffix('.mermaid')
                    mermaid_output = risk_graph.to_mermaid(output_format='mermaid')
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
