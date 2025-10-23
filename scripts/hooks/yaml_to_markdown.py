#!/usr/bin/env python3
"""
YAML to Markdown table generator for CoSAI Risk Map files.

Converts structured YAML data (components, controls, risks) into formatted
Markdown tables with intelligent column-specific formatting.

Supports multiple table formats:
- full: Complete detail tables with all columns
- summary: Condensed tables with ID, title, description, category
- xref-risks: Control to risk cross-reference tables
- xref-components: Control to component cross-reference tables

Usage:
    python yaml_to_markdown.py components                    # Convert components (full format)
    python yaml_to_markdown.py controls --format summary     # Summary table
    python yaml_to_markdown.py controls --format xref-risks  # Cross-reference table
    python yaml_to_markdown.py --all --format full           # All types, full format
"""

import argparse
import sys
from abc import ABC, abstractmethod
from itertools import chain
from pathlib import Path

import pandas as pd
import yaml

# Configuration: easily modifiable paths
DEFAULT_INPUT_DIR = Path("risk-map/yaml")
DEFAULT_OUTPUT_DIR = Path("risk-map/tables")
INPUT_FILE_PATTERN = "{type}.yaml"  # e.g., "components.yaml"
OUTPUT_FILE_PATTERN = "{type}-{format}.md"  # e.g., "controls-summary.md"


def format_edges(edges: dict | None) -> str:
    """Format edges dictionary into readable markdown."""
    if not edges or not isinstance(edges, dict):
        return ""

    parts = []
    if edges.get("to"):
        parts.append(f"**To:**<br> {'<br> '.join(edges['to'])}")
    if edges.get("from"):
        parts.append(f"**From:**<br> {'<br> '.join(edges['from'])}")

    return "<br>".join(parts) if parts else ""


def format_list(entry) -> str:
    """Format list entries with HTML line breaks."""
    if not entry or not isinstance(entry, list):
        return str(entry) if entry else ""

    return "<br> ".join(entry)


def format_dict(entry) -> str:
    """Format dictionary entries with HTML formatting."""
    if not entry or not isinstance(entry, dict):
        return str(entry) if entry else ""

    result: str = ""
    for k, v in entry.items():
        desc = v

        if isinstance(v, list):
            desc = "<br> ".join(v)

        result += f"**{k}**:<br> {desc}<br>"

    return result.replace("- >", "").replace("\n", "<br>")


def collapse_column(entry) -> str:
    """Collapse multi-line or nested list content into HTML-formatted string."""
    if isinstance(entry, str):
        return entry.replace("- >", "").replace("\n", "<br>")
    elif isinstance(entry, list) and len(entry) == 1:
        return entry[0].replace("- >", "").replace("\n", "<br>")
    elif not isinstance(entry, list):
        return str(entry) if entry else ""

    flattened_list = list(chain.from_iterable(item if isinstance(item, list) else [item] for item in entry))
    full_desc = "<br> ".join(flattened_list).replace("- >", "").replace("\n", "<br>")

    return full_desc


# ============================================================================
# Table Generator Classes
# ============================================================================

class TableGenerator(ABC):
    """
    Base class for table generation strategies.

    Each subclass implements a specific table format (full, summary, xref, etc.)
    and defines how to transform YAML data into markdown tables.
    """

    def __init__(self, input_dir: Path = DEFAULT_INPUT_DIR):
        """
        Initialize table generator.

        Args:
            input_dir: Directory containing YAML source files
        """
        self.input_dir = input_dir
        self._yaml_cache = {}  # Cache for loaded YAML files

    @abstractmethod
    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate markdown table from YAML data.

        Args:
            yaml_data: Parsed YAML data dictionary
            ytype: Type of data (components, controls, risks)

        Returns:
            Formatted markdown table string
        """
        pass

    def _load_yaml(self, filename: str) -> dict:
        """
        Load and cache YAML file.

        Args:
            filename: Name of YAML file to load (e.g., "risks.yaml")

        Returns:
            Parsed YAML data dictionary
        """
        if filename not in self._yaml_cache:
            file_path = self.input_dir / filename
            with open(file_path, "r") as f:
                self._yaml_cache[filename] = yaml.safe_load(f)
        return self._yaml_cache[filename]

    def _create_id_to_title_lookup(self, yaml_data: dict, data_key: str) -> dict[str, str]:
        """
        Create lookup dictionary mapping IDs to titles.

        Args:
            yaml_data: Parsed YAML data
            data_key: Key to extract items from (e.g., "risks", "components")

        Returns:
            Dictionary mapping id -> title
        """
        items = yaml_data.get(data_key, [])
        return {item["id"]: item["title"] for item in items if "id" in item and "title" in item}


class FullDetailTableGenerator(TableGenerator):
    """
    Generates full detail tables with all columns.

    This is the original/legacy table format that includes all fields
    from the YAML with column-specific formatting.
    """

    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate full detail markdown table.

        Args:
            yaml_data: Parsed YAML data dictionary
            ytype: Type of data (components, controls, risks)

        Returns:
            Formatted markdown table string
        """
        collapsable = ["description", "shortDescription", "longDescription", "examples"]

        # Convert to DataFrame
        df = pd.DataFrame(yaml_data.get(ytype))

        # Apply column-specific formatting
        for col in df.columns:
            if col in collapsable:
                df[col] = df[col].apply(collapse_column)
            elif col == "edges":
                df[col] = df[col].apply(format_edges)
            elif col == "tourContent":
                df[col] = df[col].apply(format_dict)
            else:
                df[col] = df[col].apply(format_list)

        df_filled = df.fillna("").sort_values("id")

        # Convert to markdown
        return df_filled.to_markdown(index=False)


class SummaryTableGenerator(TableGenerator):
    """
    Generates summary tables with condensed information.

    Includes: ID, Title, Description/ShortDescription, Category
    """

    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate summary markdown table.

        Args:
            yaml_data: Parsed YAML data dictionary
            ytype: Type of data (components, controls, risks)

        Returns:
            Formatted markdown table string
        """
        items = yaml_data.get(ytype, [])

        rows = []
        for item in items:
            # Prefer shortDescription over description
            desc = item.get("shortDescription") or item.get("description", "")

            row = {
                "ID": item.get("id", ""),
                "Title": item.get("title", ""),
                "Description": collapse_column(desc) if desc else "",
                "Category": item.get("category", "")
            }
            rows.append(row)

        df = pd.DataFrame(rows).sort_values("ID")
        return df.to_markdown(index=False)


class RiskXRefTableGenerator(TableGenerator):
    """
    Generates control-to-risk cross-reference tables.

    Shows which risks are associated with each control.
    Only applicable to controls.yaml.
    """

    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate control-to-risk cross-reference table.

        Args:
            yaml_data: Parsed YAML data dictionary (must be controls)
            ytype: Type of data (must be "controls")

        Returns:
            Formatted markdown table string

        Raises:
            ValueError: If ytype is not "controls"
        """
        if ytype != "controls":
            raise ValueError(f"RiskXRefTableGenerator only works with 'controls', got '{ytype}'")

        # Load risks.yaml for title lookup
        risks_data = self._load_yaml("risks.yaml")
        risks_lookup = self._create_id_to_title_lookup(risks_data, "risks")

        controls = yaml_data.get("controls", [])
        rows = []

        for control in controls:
            control_id = control.get("id", "")
            control_title = control.get("title", "")
            risk_ids = control.get("risks", [])

            # Handle special case: risks: "all" or risks: all
            is_all = risk_ids == "all" or (
                isinstance(risk_ids, list)
                and len(risk_ids) == 1
                and risk_ids[0] == "all"
            )
            if is_all:
                risk_ids_display = "all"
                risk_titles_display = "All Risks"
            elif isinstance(risk_ids, list):
                # Resolve risk titles
                risk_titles = [risks_lookup.get(rid, f"Unknown ({rid})") for rid in risk_ids]
                risk_ids_display = format_list(risk_ids)
                risk_titles_display = format_list(risk_titles)
            else:
                # Handle unexpected format
                risk_ids_display = str(risk_ids) if risk_ids else ""
                risk_titles_display = ""

            row = {
                "Control ID": control_id,
                "Control Title": control_title,
                "Risk IDs": risk_ids_display,
                "Risk Titles": risk_titles_display
            }
            rows.append(row)

        df = pd.DataFrame(rows).sort_values("Control ID")
        return df.to_markdown(index=False)


class ComponentXRefTableGenerator(TableGenerator):
    """
    Generates control-to-component cross-reference tables.

    Shows which components are associated with each control.
    Only applicable to controls.yaml.
    """

    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate control-to-component cross-reference table.

        Args:
            yaml_data: Parsed YAML data dictionary (must be controls)
            ytype: Type of data (must be "controls")

        Returns:
            Formatted markdown table string

        Raises:
            ValueError: If ytype is not "controls"
        """
        if ytype != "controls":
            raise ValueError(f"ComponentXRefTableGenerator only works with 'controls', got '{ytype}'")

        # Load components.yaml for title lookup
        components_data = self._load_yaml("components.yaml")
        components_lookup = self._create_id_to_title_lookup(components_data, "components")

        controls = yaml_data.get("controls", [])
        rows = []

        for control in controls:
            control_id = control.get("id", "")
            control_title = control.get("title", "")
            component_ids = control.get("components", [])

            # Handle special case: components: "all" or components: all
            is_all = component_ids == "all" or (
                isinstance(component_ids, list)
                and len(component_ids) == 1
                and component_ids[0] == "all"
            )
            if is_all:
                component_ids_display = "all"
                component_titles_display = "All Components"
            elif isinstance(component_ids, list):
                # Resolve component titles
                component_titles = [components_lookup.get(cid, f"Unknown ({cid})") for cid in component_ids]
                component_ids_display = format_list(component_ids)
                component_titles_display = format_list(component_titles)
            else:
                # Handle unexpected format
                component_ids_display = str(component_ids) if component_ids else ""
                component_titles_display = ""

            row = {
                "Control ID": control_id,
                "Control Title": control_title,
                "Component IDs": component_ids_display,
                "Component Titles": component_titles_display
            }
            rows.append(row)

        df = pd.DataFrame(rows).sort_values("Control ID")
        return df.to_markdown(index=False)


# Table generator registry
TABLE_GENERATORS = {
    "full": FullDetailTableGenerator,
    "summary": SummaryTableGenerator,
    "xref-risks": RiskXRefTableGenerator,
    "xref-components": ComponentXRefTableGenerator,
}


def yaml_to_markdown_table(yaml_file, ytype, table_format: str = "full"):
    """
    Convert YAML data to formatted Markdown table using specified format.

    Args:
        yaml_file: Path to YAML input file
        ytype: Type of data to extract (components, controls, risks)
        table_format: Format type (full, summary, xref-risks, xref-components)

    Returns:
        Formatted markdown table string

    Raises:
        ValueError: If table_format is not recognized or incompatible with ytype
    """
    # Validate format
    if table_format not in TABLE_GENERATORS:
        valid_formats = ", ".join(TABLE_GENERATORS.keys())
        raise ValueError(f"Invalid table format '{table_format}'. Valid formats: {valid_formats}")

    # Load YAML data
    with open(yaml_file, "r") as f:
        data = yaml.safe_load(f)

    # Validate ytype exists in YAML data
    if ytype not in data:
        raise ValueError(f"YAML file does not contain '{ytype}' key. Available keys: {', '.join(data.keys())}")

    # Get input directory for cross-reference lookups
    input_dir = Path(yaml_file).parent

    # Create generator instance and generate table
    generator_class = TABLE_GENERATORS[table_format]
    generator = generator_class(input_dir=input_dir)

    return generator.generate(data, ytype)


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Convert CoSAI Risk Map YAML files to Markdown tables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s components                                    # Convert components (full format)
  %(prog)s controls --format summary                     # Generate summary table
  %(prog)s controls --format xref-risks                  # Control-to-risk cross-reference
  %(prog)s controls --format xref-components             # Control-to-component cross-reference
  %(prog)s --all --format full                           # All types, full detail
  %(prog)s components --all-formats                      # All formats for components
  %(prog)s controls --all-formats                        # All formats for controls (4 tables)
  %(prog)s --all --all-formats                           # All types, all formats
  %(prog)s components -o custom/output.md                # Custom output file
  %(prog)s --all --all-formats --output-dir /tmp/tables  # Generate to custom directory
  %(prog)s controls --file custom/controls.yaml          # Custom input file
  %(prog)s components --quiet                            # Minimal output

Available Types:
  components    - AI system building blocks
  controls      - Security controls and mitigations
  risks         - Security threats and vulnerabilities

Available Formats:
  full              - Complete detail tables with all columns (default)
  summary           - Condensed tables (ID, Title, Description, Category)
  xref-risks        - Control-to-risk cross-reference (controls only)
  xref-components   - Control-to-component cross-reference (controls only)

Exit Codes:
  0 - Conversion completed successfully
  1 - Invalid arguments or missing files
  2 - Processing error
        """,
    )

    parser.add_argument(
        "types",
        nargs="*",
        help="Type(s) of YAML data to convert: components, controls, risks",
    )

    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Convert all types (components, controls, risks)",
    )

    parser.add_argument(
        "--format",
        "-f",
        type=str,
        default="full",
        choices=list(TABLE_GENERATORS.keys()),
        help="Table format to generate (default: full)",
    )

    parser.add_argument(
        "--all-formats",
        action="store_true",
        help="Generate all applicable formats for each type (overrides --format)",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file path (only valid when converting single type with single format)",
    )

    parser.add_argument(
        "--file",
        type=Path,
        help="Custom input YAML file path (overrides default location)",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Minimize output (only show errors)",
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Custom output directory for generated tables (overrides default location)",
    )

    return parser.parse_args()


def get_default_paths(ytype: str, table_format: str = "full", output_dir: Path = None) -> tuple[Path, Path]:
    """
    Get default input and output file paths for a given type and format.

    Uses configuration constants for easy modification:
    - DEFAULT_INPUT_DIR: Base directory for YAML files
    - DEFAULT_OUTPUT_DIR: Base directory for generated tables
    - INPUT_FILE_PATTERN: Naming pattern for input files
    - OUTPUT_FILE_PATTERN: Naming pattern for output files

    Args:
        ytype: Data type (components, controls, risks)
        table_format: Table format (full, summary, xref-risks, xref-components)
        output_dir: Optional custom output directory (overrides DEFAULT_OUTPUT_DIR)

    Returns:
        Tuple of (input_path, output_path)
    """
    input_filename = INPUT_FILE_PATTERN.format(type=ytype)
    output_filename = OUTPUT_FILE_PATTERN.format(type=ytype, format=table_format)

    input_path = DEFAULT_INPUT_DIR / input_filename
    output_base_dir = output_dir if output_dir is not None else DEFAULT_OUTPUT_DIR
    output_path = output_base_dir / output_filename

    return input_path, output_path


def get_applicable_formats(ytype: str) -> list[str]:
    """
    Get all applicable table formats for a given type.

    Args:
        ytype: Data type (components, controls, risks)

    Returns:
        List of applicable format names
    """
    # Base formats work for all types
    base_formats = ["full", "summary"]

    # Cross-reference formats only work with controls
    if ytype == "controls":
        return base_formats + ["xref-risks", "xref-components"]

    return base_formats


def convert_all_formats(ytype: str, input_file: Path = None, output_dir: Path = None, quiet: bool = False) -> bool:
    """
    Convert a single YAML type to all applicable markdown table formats.

    Args:
        ytype: Data type to convert
        input_file: Optional custom input file
        output_dir: Optional custom output directory
        quiet: Whether to suppress output messages

    Returns:
        True if all conversions successful, False if any failed
    """
    applicable_formats = get_applicable_formats(ytype)

    if not quiet:
        format_list = ", ".join(applicable_formats)
        print(f"📐 Generating {len(applicable_formats)} format(s) for {ytype}: {format_list}")

    all_successful = True
    for table_format in applicable_formats:
        if not convert_type(ytype, table_format, input_file, None, output_dir, quiet):
            all_successful = False

    return all_successful


def convert_type(
    ytype: str,
    table_format: str = "full",
    input_file: Path = None,
    output_file: Path = None,
    output_dir: Path = None,
    quiet: bool = False,
) -> bool:
    """
    Convert a single YAML type to markdown table.

    Args:
        ytype: Data type to convert
        table_format: Table format (full, summary, xref-risks, xref-components)
        input_file: Optional custom input file
        output_file: Optional custom output file (takes precedence over output_dir)
        output_dir: Optional custom output directory
        quiet: Whether to suppress output messages

    Returns:
        True if successful, False otherwise
    """
    try:
        # Validate format compatibility with type
        if table_format in ["xref-risks", "xref-components"] and ytype != "controls":
            print(f"❌ Error: Format '{table_format}' only works with 'controls', not '{ytype}'")
            return False

        # Determine paths
        default_input, default_output = get_default_paths(ytype, table_format, output_dir)
        in_file = input_file or default_input
        out_file = output_file or default_output

        if not in_file.exists():
            print(f"❌ Input file not found: {in_file}")
            return False

        if not quiet:
            print(f"🔄 Converting {ytype} ({table_format} format): {in_file} → {out_file}")

        # Convert and write
        result = yaml_to_markdown_table(yaml_file=in_file, ytype=ytype, table_format=table_format)

        # Create output directory if needed
        out_file.parent.mkdir(parents=True, exist_ok=True)

        with open(out_file, mode="w") as of:
            of.write(result)

        if not quiet:
            print(f"✅ Successfully wrote {out_file}")

        return True

    except Exception as e:
        print(f"❌ Error converting {ytype}: {e}")
        return False


def main() -> None:
    """
    Main entry point for YAML to Markdown converter.
    """
    try:
        args = parse_args()

        # Validate arguments
        if not args.all and not args.types:
            print("❌ Error: Must specify at least one type or use --all")
            print("   Run with --help for usage information")
            sys.exit(1)

        # Validate type names
        valid_types = {"components", "controls", "risks"}
        if args.types:
            invalid_types = set(args.types) - valid_types
            if invalid_types:
                print(f"❌ Error: Invalid type(s): {', '.join(invalid_types)}")
                print(f"   Valid types: {', '.join(sorted(valid_types))}")
                sys.exit(1)

        if args.output and args.output_dir:
            print("❌ Error: Cannot use both --output and --output-dir")
            print("   --output: Specify exact output file (single conversion only)")
            print("   --output-dir: Specify output directory (for multiple files)")
            sys.exit(1)

        if args.output and (args.all or len(args.types) > 1 or args.all_formats):
            print("❌ Error: --output can only be used when converting a single type with a single format")
            sys.exit(1)

        # Validate format compatibility (only if not using --all-formats)
        if not args.all_formats and args.format in ["xref-risks", "xref-components"]:
            types_to_convert = ["components", "controls", "risks"] if args.all else args.types
            non_control_types = [t for t in types_to_convert if t != "controls"]
            if non_control_types:
                print(f"❌ Error: Format '{args.format}' only works with 'controls'")
                print(f"   Cannot use with: {', '.join(non_control_types)}")
                sys.exit(1)

        # Determine which types to convert
        types_to_convert = ["components", "controls", "risks"] if args.all else args.types

        if not args.quiet:
            type_list = ", ".join(types_to_convert)
            print(f"📋 Converting {len(types_to_convert)} type(s): {type_list}")
            if args.all_formats:
                print("📐 Mode: All applicable formats\n")
            else:
                print(f"📐 Format: {args.format}\n")

        # Convert each type
        all_successful = True
        for ytype in types_to_convert:
            if args.all_formats:
                # Generate all applicable formats for this type
                if not convert_all_formats(ytype, args.file, args.output_dir, args.quiet):
                    all_successful = False
            else:
                # Use custom output only if converting single type with single format
                output = args.output if len(types_to_convert) == 1 else None

                if not convert_type(ytype, args.format, args.file, output, args.output_dir, args.quiet):
                    all_successful = False

            if not args.quiet and ytype != types_to_convert[-1]:
                print()  # Add spacing between conversions

        # Report final status
        if not all_successful:
            print("\n⚠️  Some conversions failed")
            sys.exit(2)

        if not args.quiet:
            print("\n✅ All conversions completed successfully")

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n⚠️  Conversion interrupted by user")
        sys.exit(2)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
