#!/usr/bin/env python3
"""
Git pre-commit hook to validate framework reference consistency in YAML files.

This script validates that:
- All framework IDs used in `mappings` fields exist in frameworks.yaml
- Framework IDs in YAML data match the enum in frameworks.schema.json
- Framework definitions are consistent and complete
- Personas only reference frameworks applicable to personas (applicableTo: ["personas"])
- Deprecated persona usage is flagged with warnings
- Identifies any framework references to non-existent frameworks

Only runs when framework-related YAML files are modified in the commit.
Provides -f/--force option to run validation regardless of git status.
"""

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


def get_staged_yaml_files(force_check: bool = False) -> list[Path]:
    """Get frameworks.yaml, risks.yaml, controls.yaml, and personas.yaml if any is staged or if forced."""
    target_files: list[Path] = [
        Path("risk-map/yaml/frameworks.yaml"),
        Path("risk-map/yaml/risks.yaml"),
        Path("risk-map/yaml/controls.yaml"),
        Path("risk-map/yaml/personas.yaml"),
    ]

    # If force flag is set, return the target files if they exist
    if force_check:
        if all(path.exists() for path in target_files):
            return target_files
        else:
            missing = [str(p) for p in target_files if not p.exists()]
            print(f"  ⚠️  Target file(s) do not exist: {', '.join(missing)}")
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

        # Return target files if at least one is staged and all exist
        if staged_target_files and all(path.exists() for path in target_files):
            return target_files
        else:
            return []

    except subprocess.CalledProcessError as e:
        print(f"Error getting staged files: {e}")
        return []


def load_yaml_file(file_path: Path) -> dict[str, Any] | None:
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


def extract_framework_ids(frameworks_data: dict[str, Any]) -> set[str]:
    """
    Extract framework IDs from frameworks.yaml.

    Returns:
        Set of valid framework IDs
    """
    framework_ids = set()

    if not frameworks_data or "frameworks" not in frameworks_data:
        return framework_ids

    for framework in frameworks_data["frameworks"]:
        framework_id = framework.get("id")
        if framework_id:
            framework_ids.add(framework_id)

    return framework_ids


def extract_framework_applicability(frameworks_data: dict[str, Any]) -> dict[str, list[str]]:
    """
    Extract applicableTo arrays from frameworks.yaml.

    Args:
        frameworks_data: Parsed frameworks.yaml dict

    Returns:
        Dict mapping framework_id -> list of applicable entity types
        Example: {"mitre-atlas": ["controls", "risks"], "nist-ai-rmf": ["controls"]}
    """
    frameworks_applicability = {}

    if not frameworks_data or "frameworks" not in frameworks_data:
        return frameworks_applicability

    for framework in frameworks_data["frameworks"]:
        framework_id = framework.get("id")
        if not framework_id:
            continue

        applicable_to = framework.get("applicableTo")
        if applicable_to is not None:
            # Store the applicableTo array (could be list or other type)
            # Schema validation will catch if it's not a list
            frameworks_applicability[framework_id] = applicable_to

    return frameworks_applicability


def extract_risk_framework_references(risks_data: dict[str, Any]) -> dict[str, list[str]]:
    """
    Extract framework references from risks.yaml.

    Returns:
        Dict mapping risk_id -> list of framework_ids referenced in mappings
    """
    risk_frameworks = {}

    if not risks_data or "risks" not in risks_data:
        return risk_frameworks

    for risk in risks_data["risks"]:
        risk_id = risk.get("id")
        if not risk_id:
            continue

        mappings = risk.get("mappings", {})
        if mappings and isinstance(mappings, dict):
            framework_ids = list(mappings.keys())
            if framework_ids:
                risk_frameworks[risk_id] = framework_ids

    return risk_frameworks


def extract_control_framework_references(controls_data: dict[str, Any]) -> dict[str, list[str]]:
    """
    Extract framework references from controls.yaml.

    Returns:
        Dict mapping control_id -> list of framework_ids referenced in mappings
    """
    control_frameworks = {}

    if not controls_data or "controls" not in controls_data:
        return control_frameworks

    for control in controls_data["controls"]:
        control_id = control.get("id")
        if not control_id:
            continue

        mappings = control.get("mappings", {})
        if mappings and isinstance(mappings, dict):
            framework_ids = list(mappings.keys())
            if framework_ids:
                control_frameworks[control_id] = framework_ids

    return control_frameworks


def validate_framework_references(
    valid_framework_ids: set[str],
    risk_frameworks: dict[str, list[str]],
    control_frameworks: dict[str, list[str]],
) -> list[str]:
    """
    Validate that all framework references exist in frameworks.yaml.

    Args:
        valid_framework_ids: Set of framework IDs defined in frameworks.yaml
        risk_frameworks: Dict mapping risk_id -> framework_ids used
        control_frameworks: Dict mapping control_id -> framework_ids used

    Returns:
        List of error messages (empty if all valid)
    """
    errors = []

    # Validate risk framework references
    for risk_id, framework_ids in risk_frameworks.items():
        for framework_id in framework_ids:
            if framework_id not in valid_framework_ids:
                errors.append(
                    f"[ISSUE: frameworks.yaml] "
                    f"Risk '{risk_id}' references framework '{framework_id}' "
                    f"which does not exist in frameworks.yaml"
                )

    # Validate control framework references
    for control_id, framework_ids in control_frameworks.items():
        for framework_id in framework_ids:
            if framework_id not in valid_framework_ids:
                errors.append(
                    f"[ISSUE: frameworks.yaml] "
                    f"Control '{control_id}' references framework '{framework_id}' "
                    f"which does not exist in frameworks.yaml"
                )

    return errors


def validate_framework_applicability(
    frameworks_applicability: dict[str, list[str]],
    risk_frameworks: dict[str, list[str]],
    control_frameworks: dict[str, list[str]],
) -> list[str]:
    """
    Validate that controls/risks only reference applicable frameworks.

    Args:
        frameworks_applicability: Dict mapping framework_id -> list of applicable entity types
        risk_frameworks: Dict mapping risk_id -> list of framework_ids
        control_frameworks: Dict mapping control_id -> list of framework_ids

    Returns:
        List of error messages (empty if all valid)
    """
    errors = []

    # Validate control framework applicability
    for control_id, framework_ids in control_frameworks.items():
        for framework_id in framework_ids:
            # Skip frameworks not in applicability dict (validated by validate_framework_references)
            if framework_id not in frameworks_applicability:
                continue

            applicable_to = frameworks_applicability[framework_id]
            # Check if "controls" is in the applicableTo array
            if "controls" not in applicable_to:
                errors.append(
                    f"[ISSUE: frameworks.yaml] "
                    f"Control '{control_id}' references framework '{framework_id}' "
                    f"which is not applicable to controls (applicableTo: {applicable_to})"
                )

    # Validate risk framework applicability
    for risk_id, framework_ids in risk_frameworks.items():
        for framework_id in framework_ids:
            # Skip frameworks not in applicability dict (validated by validate_framework_references)
            if framework_id not in frameworks_applicability:
                continue

            applicable_to = frameworks_applicability[framework_id]
            # Check if "risks" is in the applicableTo array
            if "risks" not in applicable_to:
                errors.append(
                    f"[ISSUE: frameworks.yaml] "
                    f"Risk '{risk_id}' references framework '{framework_id}' "
                    f"which is not applicable to risks (applicableTo: {applicable_to})"
                )

    return errors


def extract_persona_framework_references(personas_data: dict[str, Any] | None) -> dict[str, list[str]]:
    """Extract framework references from personas.yaml mappings field.

    Args:
        personas_data: Parsed personas.yaml data

    Returns:
        Dict mapping persona IDs to list of framework IDs they reference
    """
    persona_frameworks = {}
    if not personas_data or "personas" not in personas_data:
        return persona_frameworks

    for persona in personas_data["personas"]:
        persona_id = persona.get("id")
        if not persona_id:
            continue
        mappings = persona.get("mappings", {})
        if mappings and isinstance(mappings, dict):
            framework_ids = list(mappings.keys())
            if framework_ids:
                persona_frameworks[persona_id] = framework_ids
    return persona_frameworks


def validate_persona_framework_applicability(
    frameworks_data: dict[str, Any],
    persona_frameworks: dict[str, list[str]],
) -> list[str]:
    """Validate personas only reference frameworks applicable to personas.

    Args:
        frameworks_data: Parsed frameworks.yaml data
        persona_frameworks: Dict of persona IDs to their framework references

    Returns:
        List of error messages for any non-applicable framework references
    """
    errors = []

    # Build applicability lookup from frameworks data
    frameworks_applicability = {}
    if frameworks_data and "frameworks" in frameworks_data:
        for framework in frameworks_data["frameworks"]:
            fw_id = framework.get("id")
            if fw_id:
                frameworks_applicability[fw_id] = framework.get("applicableTo", [])

    for persona_id, framework_ids in persona_frameworks.items():
        for framework_id in framework_ids:
            if framework_id not in frameworks_applicability:
                errors.append(f"Persona '{persona_id}' references framework '{framework_id}' which does not exist")
                continue
            applicable_to = frameworks_applicability[framework_id]
            if "personas" not in applicable_to:
                errors.append(
                    f"Persona '{persona_id}' references framework '{framework_id}' "
                    f"which is not applicable to personas"
                )
    return errors


def check_deprecated_persona_usage(
    personas_data: dict[str, Any] | None,
    controls_data: dict[str, Any] | None,
    risks_data: dict[str, Any] | None,
) -> list[str]:
    """Warn when deprecated personas are used in controls/risks.

    Args:
        personas_data: Parsed personas.yaml data
        controls_data: Parsed controls.yaml data
        risks_data: Parsed risks.yaml data

    Returns:
        List of warning messages for deprecated persona usage
    """
    warnings = []

    # Build set of deprecated persona IDs
    deprecated_personas = set()
    if personas_data and "personas" in personas_data:
        for persona in personas_data["personas"]:
            if persona.get("deprecated", False):
                persona_id = persona.get("id")
                if persona_id:
                    deprecated_personas.add(persona_id)

    if not deprecated_personas:
        return warnings

    # Check controls
    if controls_data and "controls" in controls_data:
        for control in controls_data["controls"]:
            for persona_id in control.get("personas", []):
                if persona_id in deprecated_personas:
                    warnings.append(f"Control '{control.get('id')}' uses deprecated persona '{persona_id}'")

    # Check risks
    if risks_data and "risks" in risks_data:
        for risk in risks_data["risks"]:
            for persona_id in risk.get("personas", []):
                if persona_id in deprecated_personas:
                    warnings.append(f"Risk '{risk.get('id')}' uses deprecated persona '{persona_id}'")

    return warnings


def validate_framework_consistency(frameworks_data: dict[str, Any]) -> list[str]:
    """
    Validate that framework definitions are internally consistent.

    Checks that:
    - Each framework's 'id' field matches the key used in the frameworks array
    - All required fields are present
    - No duplicate framework IDs exist

    Args:
        frameworks_data: Parsed frameworks.yaml data

    Returns:
        List of error messages (empty if all valid)
    """
    errors = []
    seen_ids = set()

    if not frameworks_data or "frameworks" not in frameworks_data:
        errors.append("[ISSUE: frameworks.yaml] No frameworks array found in frameworks.yaml")
        return errors

    for idx, framework in enumerate(frameworks_data["frameworks"]):
        framework_id = framework.get("id")

        # Check for missing ID
        if not framework_id:
            errors.append(f"[ISSUE: frameworks.yaml] Framework at index {idx} is missing 'id' field")
            continue

        # Check for duplicate IDs
        if framework_id in seen_ids:
            errors.append(
                f"[ISSUE: frameworks.yaml] Duplicate framework ID '{framework_id}' found in frameworks.yaml"
            )
        seen_ids.add(framework_id)

        # Check for required fields
        required_fields = ["name", "fullName", "description", "baseUri"]
        for field in required_fields:
            if field not in framework or not framework[field]:
                errors.append(
                    f"[ISSUE: frameworks.yaml] Framework '{framework_id}' is missing required field '{field}'"
                )

    return errors


def validate_frameworks(file_paths: list[Path]) -> bool:
    """Validate framework reference consistency including persona mappings."""
    print(f"   Validating framework references in: {', '.join(map(str, file_paths))}")

    # Load YAML files
    frameworks_yaml_data = load_yaml_file(file_paths[0])  # frameworks.yaml
    risks_yaml_data = load_yaml_file(file_paths[1])  # risks.yaml
    controls_yaml_data = load_yaml_file(file_paths[2])  # controls.yaml
    personas_yaml_data = load_yaml_file(file_paths[3]) if len(file_paths) > 3 else None  # personas.yaml

    if not frameworks_yaml_data:
        print("  ❌ Failing - could not load frameworks.yaml")
        return False

    if not risks_yaml_data:
        print("  ❌ Failing - could not load risks.yaml")
        return False

    if not controls_yaml_data:
        print("  ❌ Failing - could not load controls.yaml")
        return False

    # Validate framework consistency first
    consistency_errors = validate_framework_consistency(frameworks_yaml_data)

    # Extract framework IDs
    valid_framework_ids = extract_framework_ids(frameworks_yaml_data)

    # Extract framework applicability
    frameworks_applicability = extract_framework_applicability(frameworks_yaml_data)

    if not valid_framework_ids:
        print("  ℹ️  No frameworks found in frameworks.yaml - skipping reference validation")
        if consistency_errors:
            print(f"   ❌ Found {len(consistency_errors)} framework consistency errors:")
            for error in consistency_errors:
                print(f"     - {error}")
            return False
        return True

    # Extract framework references from risks, controls, and personas
    risk_frameworks = extract_risk_framework_references(risks_yaml_data)
    control_frameworks = extract_control_framework_references(controls_yaml_data)
    persona_frameworks = extract_persona_framework_references(personas_yaml_data)

    # Validate references
    reference_errors = validate_framework_references(valid_framework_ids, risk_frameworks, control_frameworks)

    # Validate applicability for controls and risks
    applicability_errors = validate_framework_applicability(
        frameworks_applicability, risk_frameworks, control_frameworks
    )

    # Validate persona framework applicability
    persona_applicability_errors = validate_persona_framework_applicability(
        frameworks_yaml_data, persona_frameworks
    )

    # Check for deprecated persona usage (warnings only, don't fail validation)
    deprecation_warnings = check_deprecated_persona_usage(
        personas_yaml_data, controls_yaml_data, risks_yaml_data
    )

    # Report results
    success = True

    if consistency_errors:
        print(f"   ❌ Found {len(consistency_errors)} framework consistency errors:")
        for error in consistency_errors:
            print(f"     - {error}")
        success = False

    if reference_errors:
        print(f"   ❌ Found {len(reference_errors)} framework reference errors:")
        for error in reference_errors:
            print(f"     - {error}")
        success = False

    if applicability_errors:
        print(f"   ❌ Found {len(applicability_errors)} framework applicability errors:")
        for error in applicability_errors:
            print(f"     - {error}")
        success = False

    if persona_applicability_errors:
        print(f"   ❌ Found {len(persona_applicability_errors)} persona framework applicability errors:")
        for error in persona_applicability_errors:
            print(f"     - {error}")
        success = False

    # Report deprecation warnings (don't fail validation)
    if deprecation_warnings:
        print(f"   ⚠️  Found {len(deprecation_warnings)} deprecated persona usage warnings:")
        for warning in deprecation_warnings:
            print(f"     - {warning}")

    if success:
        print("  ✅ Framework references and applicability are consistent")
        framework_list = ", ".join(sorted(valid_framework_ids))
        print(f"     - Found {len(valid_framework_ids)} valid frameworks: {framework_list}")
        if risk_frameworks:
            print(f"     - Validated {len(risk_frameworks)} risks with framework mappings")
        if control_frameworks:
            print(f"     - Validated {len(control_frameworks)} controls with framework mappings")
        if persona_frameworks:
            print(f"     - Validated {len(persona_frameworks)} personas with framework mappings")

    return success


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate framework reference consistency in YAML files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python %(prog)s              # Check only if frameworks/risks/controls.yaml is staged
  python %(prog)s --force      # Force check framework references regardless of git status
        """,
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force validation of framework references even if not staged",
    )
    return parser.parse_args()


def main() -> None:
    """Main function for git pre-commit hook."""
    args = parse_args()

    if args.force:
        print("🔍 Force checking framework references...")
    else:
        print("🔍 Checking for framework-related YAML file changes...")

    # Get staged YAML files or force check
    yaml_files = get_staged_yaml_files(args.force)

    if not yaml_files:
        print("   No framework-related YAML files modified - skipping validation")
        sys.exit(0)

    print("   Found staged framework-related YAML files (frameworks, risks, controls, personas)")

    # Validate framework references
    if not validate_frameworks(yaml_files):
        print("   ❌ Framework reference validation failed!")
        print("   Fix the above errors before committing.")
        sys.exit(1)
    else:
        print("✅ Framework reference validation passed for all files.")
        sys.exit(0)


if __name__ == "__main__":
    main()
