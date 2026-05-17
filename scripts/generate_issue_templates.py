#!/usr/bin/env python3
"""
Command-line interface for GitHub issue template generation.

This script provides a CLI for generating GitHub issue templates from
template sources with dynamic content from JSON schemas and frameworks.yaml.

Usage:
    # Generate all templates
    uv run --locked --no-sync python scripts/generate_issue_templates.py

    # Dry-run (show diffs without writing)
    uv run --locked --no-sync python scripts/generate_issue_templates.py --dry-run

    # Generate specific template
    uv run --locked --no-sync python scripts/generate_issue_templates.py --template new_control

    # Validate only (no generation)
    uv run --locked --no-sync python scripts/generate_issue_templates.py --validate

    # Verbose output
    uv run --locked --no-sync python scripts/generate_issue_templates.py --verbose
"""

import argparse
import subprocess
import sys
from pathlib import Path

# Add scripts/hooks to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent / "hooks"))

from issue_template_generator.generator import IssueTemplateGenerator


def find_repo_root() -> Path:
    """
    Find repository root directory.

    Uses git to find the repository root, with fallback to parent directory
    navigation if git is not available.

    Returns:
        Path to repository root

    Raises:
        RuntimeError: If repository root cannot be found
    """
    try:
        # Try git method first (most reliable)
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
        )
        return Path(result.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback: assume script is in scripts/ directory
        # Navigate up one level from scripts/ to repo root
        script_dir = Path(__file__).resolve().parent
        repo_root = script_dir.parent

        # Validate this looks like the repo root (has .git directory)
        if (repo_root / ".git").exists():
            return repo_root

        raise RuntimeError(
            "Could not find repository root. "
            "Please run from within a git repository or ensure .git directory exists."
        )


def main() -> int:
    """
    Main entry point for CLI.

    Returns:
        Exit code (0 = success, 1 = error, 130 = interrupted)
    """
    parser = argparse.ArgumentParser(
        description="Generate GitHub issue templates from template sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate all templates
  uv run --locked --no-sync python scripts/generate_issue_templates.py

  # Show what would change (dry-run)
  uv run --locked --no-sync python scripts/generate_issue_templates.py --dry-run

  # Generate single template
  uv run --locked --no-sync python scripts/generate_issue_templates.py --template new_control

  # Validate templates only
  uv run --locked --no-sync python scripts/generate_issue_templates.py --validate

  # Verbose output
  uv run --locked --no-sync python scripts/generate_issue_templates.py --verbose
        """,
    )

    parser.add_argument("--dry-run", action="store_true", help="Show diffs without writing files")

    parser.add_argument(
        "--template",
        type=str,
        metavar="TEMPLATE_NAME",
        help="Generate specific template only (e.g., new_control, update_risk)",
    )

    parser.add_argument("--validate", action="store_true", help="Validate templates only, don't generate")

    parser.add_argument("--verbose", action="store_true", help="Show detailed output")

    args = parser.parse_args()

    try:
        # Find repository root
        if args.verbose:
            print("Finding repository root...")

        repo_root = find_repo_root()

        if args.verbose:
            print(f"Repository root: {repo_root}")

        # Create IssueTemplateGenerator
        if args.verbose:
            print("Initializing IssueTemplateGenerator...")

        generator = IssueTemplateGenerator(repo_root)

        # Validate mode
        if args.validate:
            if args.verbose:
                print("Validating templates...")

            templates = generator.get_available_templates()
            all_valid = True

            for template_name in templates:
                try:
                    # Get the rendered content for validation
                    template_file = generator.templates_dir / f"{template_name}.template.yml"
                    template_content = template_file.read_text(encoding="utf-8")

                    entity_type = generator._get_entity_type(template_name)
                    if entity_type is not None:
                        rendered_content = generator.template_renderer.render_template(
                            template_content, entity_type
                        )
                    else:
                        rendered_content = template_content

                    is_valid = generator.validate_generated_template(rendered_content)

                    if is_valid:
                        print(f"✓ {template_name}: Valid")
                    else:
                        print(f"✗ {template_name}: Invalid")
                        all_valid = False

                except Exception as e:
                    print(f"✗ {template_name}: Error - {e}")
                    all_valid = False

            if all_valid:
                print("\nAll templates valid!")
                return 0
            else:
                print("\nSome templates are invalid.")
                return 1

        # Single template mode
        if args.template:
            if args.verbose:
                print(f"Generating template: {args.template}")

            try:
                result = generator.generate_template(args.template, dry_run=args.dry_run)

                if args.dry_run:
                    # Show diff
                    if isinstance(result, str):
                        if result:
                            print(f"\nDiff for {args.template}:")
                            print(result)
                        else:
                            print(f"\nNo changes for {args.template} (up to date)")
                else:
                    # Show generated file path
                    print(f"Generated: {result}")

                return 0

            except Exception as e:
                print(f"Error generating template '{args.template}': {e}", file=sys.stderr)
                return 1

        # Generate all templates mode (default)
        if args.verbose:
            print("Generating all templates...")

        results = generator.generate_all_templates(dry_run=args.dry_run)

        # Report results
        success_count = 0
        error_count = 0

        for template_name, result in results.items():
            if isinstance(result, str) and result.startswith("Error:"):
                # Error occurred
                print(f"✗ {template_name}: {result}", file=sys.stderr)
                error_count += 1
            elif args.dry_run:
                # Dry-run mode - show diffs
                if isinstance(result, str):
                    if result:
                        print(f"\nDiff for {template_name}:")
                        print(result)
                    else:
                        if args.verbose:
                            print(f"✓ {template_name}: No changes")
                success_count += 1
            else:
                # Write mode - show paths
                if args.verbose:
                    print(f"✓ {template_name}: {result}")
                success_count += 1

        # Summary
        print(f"\n{'=' * 60}")
        if args.dry_run:
            print("Dry-run complete (no files written)")
        else:
            print("Template generation complete")

        print(f"Success: {success_count}/{len(results)}")

        if error_count > 0:
            print(f"Errors: {error_count}")
            return 1

        return 0

    except KeyboardInterrupt:
        print("\n\nInterrupted by user (Ctrl+C)", file=sys.stderr)
        return 130

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
