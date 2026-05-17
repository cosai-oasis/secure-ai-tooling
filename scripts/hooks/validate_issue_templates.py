#!/usr/bin/env python3
"""
Validate GitHub config files using check-jsonschema.

This script validates GitHub YAML config files against official schemas
to ensure they conform to the expected structure.

Validates:
- Issue form templates against vendor.github-issue-forms schema
- config.yml against vendor.github-issue-config schema
- dependabot.yml against vendor.dependabot schema

Can run in two modes:
- Normal mode: Validates only staged files (for git hooks)
- Force mode: Validates all config files

Usage:
    python validate_issue_templates.py           # Check staged files only
    python validate_issue_templates.py --force   # Check all config files
    python validate_issue_templates.py --quiet   # Suppress informational output
"""

import argparse
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace with parsed arguments:
        - force: bool - Validate all config files regardless of git staging
        - quiet: bool - Suppress informational output
    """
    parser = argparse.ArgumentParser(
        description="Validate GitHub config files using check-jsonschema",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                # Validate staged templates only (pre-commit mode)
  %(prog)s --force        # Validate all config files (.github/ISSUE_TEMPLATE + dependabot.yml)
  %(prog)s --quiet        # Suppress informational output
  %(prog)s -f -q          # Force mode with quiet output

Exit Codes:
  0 - All validations passed or no files to validate
  1 - Validation failures or check-jsonschema not found
  2 - Unexpected errors
        """,
    )

    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Validate all config files (not just staged files)",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress informational output (only show errors)",
    )

    return parser.parse_args()


def get_staged_files() -> list[Path]:
    """
    Get list of staged files from git.

    Uses git diff --cached to detect files staged for commit.
    Filters to only include added, copied, or modified files (not deletions).

    Returns:
        List of Path objects for staged files.
        Returns empty list if not in git repository or no files staged.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,  # 10s timeout sufficient for git operations
        )

        # Parse output into Path objects, filtering empty lines
        staged_files = [Path(f) for f in result.stdout.strip().split("\n") if f]
        return staged_files

    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        # Not in git repo, git not available, or timeout - return empty list
        return []


def get_template_files(
    template_dir: Path, staged_only: bool = False, staged: list[Path] | None = None
) -> tuple[list[Path], Path | None]:
    """
    Get list of template files to validate.

    Args:
        template_dir: Path to .github/ISSUE_TEMPLATE directory
        staged_only: If True, only return files that are staged in git
        staged: Pre-computed list of staged files. If None and staged_only is True,
            calls get_staged_files() internally.

    Returns:
        Tuple of (issue_template_files, config_file_or_None):
        - issue_template_files: List of .yml files excluding config.yml
        - config_file_or_None: config.yml path if it exists and should be validated, else None
    """
    if not template_dir.exists():
        return ([], None)

    if staged_only:
        if staged is None:
            staged = get_staged_files()

        # Filter to .yml files in ISSUE_TEMPLATE directory (not nested)
        issue_forms = [
            f
            for f in staged
            if f.parent.name == "ISSUE_TEMPLATE" and f.suffix == ".yml" and f.name != "config.yml" and f.exists()
        ]

        # Check if config.yml is staged
        config_file = template_dir / "config.yml"
        config_staged = config_file in staged and config_file.exists()

        return (issue_forms, config_file if config_staged else None)
    else:
        # Get all .yml files in template directory (not nested)
        all_yml_files = [f for f in template_dir.glob("*.yml") if f.is_file()]

        # Separate config.yml from issue forms
        issue_forms = [f for f in all_yml_files if f.name != "config.yml"]

        config_file = template_dir / "config.yml"
        config_exists = config_file.exists() and config_file.is_file()

        return (issue_forms, config_file if config_exists else None)


def validate_with_schema(file_path: Path, schema: str, quiet: bool = False) -> bool:
    """
    Validate a file against a GitHub schema using check-jsonschema.

    Args:
        file_path: Path to file to validate
        schema: Schema name ('vendor.github-issue-forms', 'vendor.github-issue-config',
            or 'vendor.dependabot')
        quiet: If True, suppress output

    Returns:
        True if validation passed, False otherwise
    """
    try:
        # Run check-jsonschema subprocess
        result = subprocess.run(
            ["check-jsonschema", "--builtin-schema", schema, str(file_path)],
            capture_output=True,
            text=True,
            timeout=30,  # 30s timeout allows for schema download and validation
        )

        if result.returncode == 0:
            if not quiet:
                print(f"   ✅ {file_path.name} passed validation")
            return True
        else:
            # Validation failed - show error details
            print(f"   ❌ {file_path.name} failed validation")
            if result.stderr:
                # Indent error output for readability
                for line in result.stderr.strip().split("\n"):
                    print(f"      {line}")
            return False

    except FileNotFoundError:
        # check-jsonschema not installed
        print("   ❌ check-jsonschema not found")
        print("      Install with: uv sync --locked")
        return False

    except subprocess.TimeoutExpired:
        # Validation took too long
        print(f"   ❌ {file_path.name} validation timeout")
        return False

    except Exception as e:
        # Unexpected error during validation
        print(f"   ❌ {file_path.name} validation error: {e}")
        return False


def main() -> int:
    """
    Main validator entry point.

    Orchestrates the validation workflow:
    1. Parse command-line arguments
    2. Detect template files to validate
    3. Validate each file against appropriate schema
    4. Report results

    Returns:
        0: Success or no files to validate
        1: Validation failures
        2: Unexpected errors
    """
    try:
        args = parse_args()

        template_dir = Path(".github/ISSUE_TEMPLATE")
        dependabot_file = Path(".github/dependabot.yml")

        # Collect staged files once for non-force mode to avoid duplicate git calls
        staged = [] if args.force else get_staged_files()

        # Get issue template files to validate
        if template_dir.exists():
            if args.force:
                issue_forms, config_file = get_template_files(template_dir, staged_only=False)
            else:
                issue_forms, config_file = get_template_files(template_dir, staged_only=True, staged=staged)
        else:
            issue_forms, config_file = [], None

        # Determine if dependabot.yml needs validation
        if args.force:
            validate_dependabot = dependabot_file.exists()
        else:
            validate_dependabot = dependabot_file in staged and dependabot_file.exists()

        # Check if there are any files to validate
        if not issue_forms and not config_file and not validate_dependabot:
            if not args.quiet:
                print("   No GitHub config files to validate - skipping")
            return 0

        # Print validation start message
        if not args.quiet:
            print("🔍 Validating GitHub config files...")

        # Track validation results
        all_passed = True
        fail_count = 0

        # Validate issue form templates
        for form in issue_forms:
            if not args.quiet:
                print(f"   Validating {form.name} against vendor.github-issue-forms...")
            if not validate_with_schema(form, "vendor.github-issue-forms", args.quiet):
                all_passed = False
                fail_count += 1

        # Validate config.yml if present
        if config_file:
            if not args.quiet:
                print(f"   Validating {config_file.name} against vendor.github-issue-config...")
            if not validate_with_schema(config_file, "vendor.github-issue-config", args.quiet):
                all_passed = False
                fail_count += 1

        # Validate dependabot.yml if applicable
        if validate_dependabot:
            if not args.quiet:
                print(f"   Validating {dependabot_file.name} against vendor.dependabot...")
            if not validate_with_schema(dependabot_file, "vendor.dependabot", args.quiet):
                all_passed = False
                fail_count += 1

        # Report final results
        if all_passed:
            if not args.quiet:
                print("✅ All GitHub config files passed validation")
            return 0
        else:
            error_word = "failure" if fail_count == 1 else "failures"
            print(f"❌ Validation failed ({fail_count} {error_word})")
            return 1

    except KeyboardInterrupt:
        print("\n⚠️  Validation interrupted by user")
        return 2

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
