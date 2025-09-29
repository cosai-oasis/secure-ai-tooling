"""
Utility functions for risk map validation system.

Provides file parsing, git integration, and helper functions for
YAML processing and staged file detection.

Dependencies:
    - PyYAML: For YAML file parsing
    - subprocess: For git command execution
"""

import subprocess
from pathlib import Path

import yaml

from .models import ComponentNode, ControlNode, RiskNode


def parse_components_yaml(file_path: Path = None) -> dict[str, ComponentNode]:
    if file_path is None:
        file_path = Path("risk-map/yaml/components.yaml")

    if not file_path.exists():
        raise FileNotFoundError(f"Controls file not found: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        components = {}

        for i, component in enumerate(data["components"]):
            component_id: str | None = component.get("id")
            if not component_id:
                continue

            if not isinstance(component_id, str):
                continue

            # Get component title
            component_title: str | None = component.get("title")
            if not component_title:
                continue

            if not isinstance(component_title, str):
                continue

            # Get component category
            category: str | None = component.get("category")
            if not category:
                continue

            if not isinstance(category, str):
                continue

            subcategory: str | None = component.get("subcategory")

            # Get edges with default empty lists
            edges = component.get("edges", {})
            if not isinstance(edges, dict):
                edges = {}

            # Ensure edges are lists
            to_edges = edges.get("to", [])
            from_edges = edges.get("from", [])

            if not isinstance(to_edges, list):
                to_edges = []

            if not isinstance(from_edges, list):
                from_edges = []

            # Create ComponentNode with validation
            components[component_id] = ComponentNode(
                    title=component_title,
                    category=category,
                    subcategory=subcategory,
                    to_edges=[str(edge) for edge in to_edges if edge],
                    from_edges=[str(edge) for edge in from_edges if edge],
                )

        return components

    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Error parsing components YAML: {e}")
    except KeyError as e:
        raise KeyError(f"Missing required field in components.yaml: {e}")


def parse_controls_yaml(file_path: Path = None) -> dict[str, ControlNode]:
    """
    Parse controls.yaml file and return dictionary of ControlNode objects.

    Args:
        file_path: Path to controls.yaml file. Defaults to risk-map/yaml/controls.yaml

    Returns:
        Dictionary mapping control IDs to ControlNode objects

    Raises:
        FileNotFoundError: If controls.yaml file doesn't exist
        yaml.YAMLError: If YAML parsing fails
        KeyError: If required fields are missing
    """
    if file_path is None:
        file_path = Path("risk-map/yaml/controls.yaml")

    if not file_path.exists():
        raise FileNotFoundError(f"Controls file not found: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        controls = {}

        for control_data in data.get("controls", []):
            control_id = control_data["id"]
            title = control_data["title"]
            category = control_data["category"]

            # Handle components: list, "all", or "none"
            components_raw = control_data.get("components", [])
            if isinstance(components_raw, str):
                components = [components_raw]  # Convert "all" or "none" to list
            elif isinstance(components_raw, list):
                components = components_raw
            else:
                components = []

            # Handle risks and personas
            risks = control_data.get("risks", [])
            personas = control_data.get("personas", [])

            # Ensure fields are string lists
            if not isinstance(risks, list):
                risks = []
            if not isinstance(personas, list):
                personas = []

            controls[control_id] = ControlNode(
                title=title, category=category, components=components, risks=risks, personas=personas
            )

        return controls

    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Error parsing controls YAML: {e}")
    except KeyError as e:
        raise KeyError(f"Missing required field in controls.yaml: {e}")


def parse_risks_yaml(file_path: Path = None) -> dict[str, RiskNode]:
    """
    Parse risks.yaml file and return dictionary of RiskNode objects.

    Args:
        file_path: Path to risks.yaml file. Defaults to risk-map/yaml/risks.yaml

    Returns:
        Dictionary mapping risk IDs to RiskNode objects

    Raises:
        FileNotFoundError: If risks.yaml file doesn't exist
        yaml.YAMLError: If YAML parsing fails
        KeyError: If required fields are missing
    """
    if file_path is None:
        file_path = Path("risk-map/yaml/risks.yaml")

    if not file_path.exists():
        raise FileNotFoundError(f"Risks file not found: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        risks = {}

        for risk_data in data.get("risks", []):
            risk_id = risk_data["id"]
            title = risk_data["title"]

            # Risks don't have explicit categories yet - use default
            category = risk_data.get("category", "risks")

            # Handle controls that mitigate this risk
            controls = risk_data.get("controls", [])

            # Handle personas
            personas = risk_data.get("personas", [])

            # Ensure fields are string lists
            if not isinstance(controls, list):
                controls = []
            if not isinstance(personas, list):
                personas = []

            risks[risk_id] = RiskNode(
                title=title,
                category=category
            )

        return risks

    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Error parsing risks YAML: {e}")
    except KeyError as e:
        raise KeyError(f"Missing required field in risks.yaml: {e}")


def get_staged_yaml_files(target_file: Path | None = None, force_check: bool = False) -> list[Path]:
    """
    Get YAML files that are staged for commit or force check specific file.

    Args:
        target_file: Specific file to check (defaults to DEFAULT_COMPONENTS_FILE)
        force_check: If True, return target file regardless of git status

    Returns:
        List of Path objects for files to validate
    """
    target_files = [
        Path("risk-map/yaml/components.yaml"),
        Path("risk-map/yaml/controls.yaml"),
        Path("risk-map/yaml/risks.yaml"),
                    ]

    # Force check mode - return target file if exists
    if force_check and isinstance(target_file, Path):
        if target_file.exists():
            return [target_file]
        else:
            print(f"  ⚠️  Target file {target_file} does not exist")
            return []

    try:
        # Get staged files from git
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True,
        )

        staged_files = result.stdout.strip().split("\n") if result.stdout.strip() else []

        if target_file is None:
            files: list[Path]= []
            for target in target_files:
                # Check if target file is staged
                if str(target) in staged_files and target.exists():
                    files.append(target)
            return files

        else:
            if isinstance(target_file, Path) and target_file.exists():
                return[target_file]
            else:
                return []

    except subprocess.CalledProcessError as e:
        print(f"⚠️  Error getting staged files: {e}")
        print("   Make sure you're in a git repository")
        return []
    except FileNotFoundError:
        print("⚠️  Git command not found - make sure git is installed")
        return []
