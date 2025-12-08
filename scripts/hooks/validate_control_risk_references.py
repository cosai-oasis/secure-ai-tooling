#!/usr/bin/env python3
"""
Git pre-commit hook to validate control-to-risk reference consistency in YAML files.

This script validates that:
- Each control in `controls.yaml` that lists specific risks is referenced by those risks in `risks.yaml`.
- Each risk in `risks.yaml` that lists specific controls is referenced by those controls in `controls.yaml`.
- Controls or risks that list "all" or "none" are exempt from validation.
- Identifies any controls or risks that have no cross-references.

Only runs when YAML files are modified in the commit.
Provides -f/--force option to run validation regardless of git status.
"""

import argparse
import subprocess
import sys
from pathlib import Path

import yaml


def get_staged_yaml_files(force_check: bool = False) -> list[Path]:
    """Get controls.yaml and risks.yaml if either is staged or if forced."""
    target_files: list[Path] = [
        Path("risk-map/yaml/controls.yaml"),
        Path("risk-map/yaml/risks.yaml"),
    ]

    # If force flag is set, return the target files if they exist
    if force_check:
        if all(path.exists() for path in target_files):
            return target_files
        else:
            print(f"  ⚠️  At least one target file {target_files} does not exist")
            return []

    try:
        # Get all staged files
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True,
        )

        staged_files = result.stdout.strip().split("\n") if result.stdout.strip() else []

        # Check if ANY of our target files is in the staged files
        staged_target_files = [path for path in target_files if str(path) in staged_files and path.exists()]

        # Return target files if at least one is staged and both exist
        if staged_target_files and all(path.exists() for path in target_files):
            return target_files
        else:
            return []

    except subprocess.CalledProcessError as e:
        print(f"Error getting staged files: {e}")
        return []


def load_yaml_file(file_path: Path) -> dict | None:
    """
    Load and parse YAML file with error handling.

    Returns:
        Parsed YAML data as dict, or None if loading fails
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file {file_path}: {e}")
        return None
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None


def extract_controls_data(yaml_data: dict) -> dict[str, str | list[str]]:
    """
    Extract control IDs and risk references from controls.yaml.

    Returns:
        Dict mapping control_id -> str | list of risk_ids
        (str for "all"/"none" keywords, list for specific risk IDs)
    """
    controls = {}

    if not yaml_data or "controls" not in yaml_data:
        return controls

    for control in yaml_data["controls"]:
        control_id = control.get("id")
        if not control_id:
            continue

        risks = control.get("risks", [])
        # Keep "all" and "none" as strings (Option 1 approach)
        # Type will be: str | list[str]
        controls[control_id] = risks

    return controls


def is_universal_control(risks_value: str | list[str]) -> bool:
    """
    Check if control applies to all risks.

    Args:
        risks_value: Value from controls.yaml risks field

    Returns:
        True if control has risks="all" (universal control)
    """
    return risks_value == "all"


def should_skip_validation(risks_value: str | list[str]) -> bool:
    """
    Check if control should skip bidirectional validation.

    Args:
        risks_value: Value from controls.yaml risks field

    Returns:
        True if value is "all", "none", or empty list
    """
    return risks_value in ("all", "none") or risks_value == []


def extract_risks_data(yaml_data: dict) -> dict[str, list[str]]:
    """
    Extract control references from risks.yaml and build reverse mapping.

    Returns:
        Dict mapping control_id -> list of risk_ids that reference that control
    """
    risks_by_control = {}

    if not yaml_data or "risks" not in yaml_data:
        return risks_by_control

    for risk in yaml_data["risks"]:
        risk_id = risk.get("id")
        if not risk_id:
            continue

        controls: list[str] = risk.get("controls", [])
        for control_id in controls:
            if risks_by_control.get(control_id) is None:
                risks_by_control[control_id] = [risk_id]
            else:
                risks_by_control[control_id].append(risk_id)

    return risks_by_control


def find_isolated_entries(
    controls: dict[str, str | list[str]], _risks: dict[str, list[str]]
) -> tuple[set[str], set[str]]:
    """
    Find entries with no cross-references.

    Args:
        controls: Dictionary mapping control_id -> list of risk_ids (from controls.yaml)
        _risks: Dictionary mapping control_id -> list of risk_ids (from risks.yaml) - currently unused

    Returns:
        tuple of (isolated_controls, isolated_risks)
        isolated_controls: Controls with empty risk lists
        isolated_risks: Currently not implemented - returns empty set
    """
    # Find controls that don't reference any risks
    isolated_controls = {control_id for control_id, risk_list in controls.items() if not risk_list}

    # TODO: Finding isolated risks requires parsing risks.yaml directly
    # Currently this function only finds isolated controls
    isolated_risks = set()

    return isolated_controls, isolated_risks


def compare_control_maps(controls: dict[str, str | list[str]], risks: dict[str, list[str]]) -> list[str]:
    """
    Compare control-to-risk mappings for consistency.

    Args:
        controls: Dict mapping control_id -> list of risk_ids (from controls.yaml)
        risks: Dict mapping control_id -> list of risk_ids (derived from risks.yaml)

    Logic:
        - controls.yaml explicitly lists which risks each control addresses
        - risks.yaml lists which controls address each risk (reverse mapping)
        - These two perspectives must be consistent
    """
    errors = []

    # Get all control IDs mentioned in either file
    all_control_ids = set(controls.keys()) | set(risks.keys())

    # Identify universal controls (those with risks="all")
    universal_controls = {
        control_id
        for control_id, risks_value in controls.items()
        if is_universal_control(risks_value)
    }

    # Check if any risks explicitly list universal controls
    if universal_controls:
        for control_id in universal_controls:
            if control_id in risks:
                # risks[control_id] = list of risk IDs that reference this control
                violating_risks = risks[control_id]
                for risk_id in violating_risks:
                    errors.append(
                        f"[ISSUE: risks.yaml] "
                        f"Risk '{risk_id}' explicitly lists universal control '{control_id}' "
                        f"in its 'controls' field.\n\tUniversal controls (those with 'risks: all' "
                        f"in controls.yaml) apply implicitly to all risks and should NOT be "
                        f"explicitly listed.\n\tACTION: Please remove '{control_id}' from the 'controls' "
                        f"list for risk '{risk_id}'."
                    )

    for control_id in all_control_ids:
        # Get risk lists from both perspectives
        risks_per_control_yaml = controls.get(control_id, [])  # What controls.yaml says
        risks_per_risks_yaml = risks.get(control_id, [])  # What we derive from risks.yaml

        # Skip only when both perspectives agree there are no risks to validate
        if risks_per_risks_yaml == [] and should_skip_validation(risks_per_control_yaml):
            continue

        # Case 1: Control in controls.yaml but not referenced in risks.yaml
        if control_id in controls and control_id not in risks:
            errors.append(
                f"[ISSUE: risks.yaml] "
                f"Control '{control_id}' lists risks '{risks_per_control_yaml}' in controls.yaml, "
                f"but none of these risks reference the control(s) in risks.yaml"
            )
            continue

        # Case 2: Control referenced in risks.yaml but missing from controls.yaml
        if control_id not in controls and control_id in risks:
            errors.append(
                f"[ISSUE: controls.yaml] "
                f"Control '{control_id}' is referenced by risks '{risks_per_risks_yaml}' in risks.yaml, "
                f"but the control(s) do not exist in controls.yaml"
            )
            continue

        # Case 3: Control exists in both but risk lists don't match
        # Skip if control has special keyword (already handled above)
        if isinstance(risks_per_control_yaml, str):
            # Special keywords "all"/"none" handled by skip logic or universal check
            continue

        # Safe to compare - both are lists
        if sorted(risks_per_control_yaml) != sorted(risks_per_risks_yaml):
            missing_from_risks_yaml = set(risks_per_control_yaml) - set(risks_per_risks_yaml)
            extra_in_risks_yaml = set(risks_per_risks_yaml) - set(risks_per_control_yaml)

            if missing_from_risks_yaml:
                errors.append(
                    f"[ISSUE: risks.yaml] "
                    f"Control '{control_id}' claims to address risks '{sorted(missing_from_risks_yaml)}' "
                    f"in controls.yaml, but the risk(s) don't list this control in their 'controls' "
                    f"section in risks.yaml"
                )

            if extra_in_risks_yaml:
                errors.append(
                    f"[ISSUE: controls.yaml] "
                    f"Risks {sorted(extra_in_risks_yaml)} reference control '{control_id}' in risks.yaml, "
                    f"but this control doesn't list these risks in its 'risks' section in controls.yaml"
                )

    return errors


def validate_control_to_risk(file_paths: list[Path]) -> bool:
    """Validate control-to-risk reference consistency."""
    print(f"   Validating control-to-risk references in: {', '.join(map(str, file_paths))}")

    # Load YAML files
    controls_yaml_data = load_yaml_file(file_paths[0])  # controls.yaml
    risks_yaml_data = load_yaml_file(file_paths[1])  # risks.yaml

    if not controls_yaml_data or not risks_yaml_data:
        print("  ❌   Failing - could not load YAML data")
        return False

    # Extract mappings
    # controls: control_id → risks it addresses (from controls.yaml)
    controls = extract_controls_data(controls_yaml_data)

    # risks: control_id → risks that reference it (derived from risks.yaml)
    risks = extract_risks_data(risks_yaml_data)

    if not controls:
        print(f"  ℹ️  No controls found in {file_paths[0]} - skipping validation")
        return True
    elif not risks:
        print(f"  ℹ️  No risks found in {file_paths[1]} - skipping validation")
        return True

    # Find isolated entries with no cross-references
    isolated_controls, isolated_risks = find_isolated_entries(controls, risks)

    # Validate cross-reference consistency
    errors = compare_control_maps(controls, risks)

    # Report results
    success = True

    if isolated_controls:
        print(f"   ❌ Found {len(isolated_controls)} isolated controls (no risk references):")
        for control in sorted(isolated_controls):
            print(f"     - Control '{control}' in controls.yaml has empty 'risks' list")
        success = False

    if isolated_risks:
        print(f"   ❌ Found {len(isolated_risks)} isolated risks (no control references):")
        for risk in sorted(isolated_risks):
            print(f"     - Risk '{risk}' in risks.yaml has empty 'controls' list")
        success = False

    if errors:
        print(f"   ❌ Found {len(errors)} cross-reference consistency errors:")
        for error in errors:
            print(f"     - {error}")
        success = False

    if success:
        print("  ✅ Control-to-risk references are consistent")

    return success


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate control-to-risk reference consistency in YAML files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python %(prog)s              # Check only if at least one of controls.yaml or risks.yaml is staged
  python %(prog)s --force      # Force check control-to-risk mapping regardless of git status
        """,
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force validation of controls-to-risk references even if not staged",
    )
    return parser.parse_args()


def main():
    """Main function for git pre-commit hook."""
    args = parse_args()

    if args.force:
        print("🔍 Force checking control-to-risk references...")
    else:
        print("🔍 Checking for YAML file changes...")

    # Get staged YAML files or force check
    yaml_files = get_staged_yaml_files(args.force)

    if not yaml_files:
        print("   No YAML files modified - skipping control-to-risk reference validation")
        sys.exit(0)

    print("   Found staged controls.yaml and/or risks.yaml file")

    # Validate control to risk references
    if not validate_control_to_risk(yaml_files):
        print("   ❌ Control-to-risk reference validation failed!")
        print("   Fix the above errors before committing.")
        sys.exit(1)
    else:
        print("✅ Control-to-risk reference validation passed for all files.")
        sys.exit(0)


if __name__ == "__main__":
    main()
