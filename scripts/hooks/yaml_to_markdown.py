#!/usr/bin/env python3
"""
YAML to Markdown table generator for CoSAI Risk Map files.

Converts structured YAML data (components, controls, risks, personas) into formatted
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

# Ensure repo root is on sys.path so scripts.hooks._sentinel_expansion resolves
# when this file is invoked directly as a script (not only as a module).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.hooks._sentinel_expansion import expand_sentinels_to_text  # noqa: E402

# Configuration: easily modifiable paths
DEFAULT_INPUT_DIR = Path("risk-map/yaml")
DEFAULT_OUTPUT_DIR = Path("risk-map/tables")
INPUT_FILE_PATTERN = "{type}.yaml"  # e.g., "components.yaml"
OUTPUT_FILE_PATTERN = "{type}-{format}.md"  # e.g., "controls-summary.md"


def format_edges(edges: dict | None) -> str:
    """Format edges dictionary into readable markdown."""
    # Handle pandas NaN values - check type first to avoid array ambiguity
    if not isinstance(edges, dict) and pd.isna(edges):
        return ""

    if not edges or not isinstance(edges, dict):
        return ""

    parts = []
    if edges.get("to"):
        # Strip trailing newlines that PyYAML may add from folded block scalars
        parts.append(f"**To:**<br> {'<br> '.join(v.strip() for v in edges['to'])}")
    if edges.get("from"):
        # Strip trailing newlines that PyYAML may add from folded block scalars
        parts.append(f"**From:**<br> {'<br> '.join(v.strip() for v in edges['from'])}")

    return "<br>".join(parts) if parts else ""


def format_list(entry, prefix: str = "") -> str:
    """
    Format list entries with HTML line breaks.

    Args:
        entry: List of strings to format, or a single value
        prefix: Optional prefix for each item (e.g., "- " for bulleted lists)

    Returns:
        HTML-formatted string with items separated by <br>
    """
    # Handle pandas NaN values - check type first to avoid array ambiguity
    if not isinstance(entry, list) and pd.isna(entry):
        return ""

    if not entry or not isinstance(entry, list):
        return str(entry) if entry else ""

    if prefix:
        # Strip trailing newlines that PyYAML may add from folded block scalars
        return "<br>".join(f"{prefix}{item.strip()}" for item in entry)
    # Strip trailing newlines that PyYAML may add from folded block scalars
    return "<br> ".join(item.strip() for item in entry)


def format_dict(entry) -> str:
    """Format dictionary entries with HTML formatting."""
    # Handle pandas NaN values - check type first to avoid array ambiguity
    if not isinstance(entry, dict) and pd.isna(entry):
        return ""

    if not entry or not isinstance(entry, dict):
        return str(entry) if entry else ""

    result: str = ""
    for k, v in entry.items():
        desc = v

        if isinstance(v, list):
            desc = "<br> ".join(v)

        result += f"**{k}**:<br> {desc}<br>"

    return result.replace("- >", "").replace("\n", "<br>")


def format_mappings(entry) -> str:
    """Format mappings dictionary for metadata fields."""
    # Handle pandas NaN values - check type first to avoid array ambiguity
    if not isinstance(entry, dict) and pd.isna(entry):
        return ""

    if not entry or not isinstance(entry, dict):
        return ""

    parts = []
    for framework, values in entry.items():
        if isinstance(values, list):
            values_str = ", ".join(values)
            parts.append(f"**{framework}**: {values_str}")
        else:
            parts.append(f"**{framework}**: {values}")

    return "<br>".join(parts)


def format_external_references(refs: list[dict] | None) -> str:
    """Format an externalReferences array as a markdown section with bullet list.

    Returns a "## References" section with one bullet per entry, or "" when
    refs is empty or None.

    Per ADR-016 D3, externalReferences entries carry schema-validated
    title/url/type fields. Brackets and parens in titles are not escaped —
    markdown injection is a known limitation under the trusted-author posture.

    Args:
        refs: list of dicts with keys title, url, type; or None

    Returns:
        Markdown section string starting with "## References\\n", or ""
    """
    if not refs:
        return ""
    bullets = "\n".join(f"- [{r['title']}]({r['url']}) ({r['type']})" for r in refs)
    return f"## References\n{bullets}\n"


_REFS_HEADER = "## References\n"


def _references_bullets_only(refs: list[dict] | None) -> str:
    """Return format_external_references(refs) with the leading "## References" header stripped.

    Per-entry sub-sections in the table generators emit their own
    "## References for {id}" header, so the helper's generic header would
    stack visually if concatenated raw. This trims it cleanly.
    """
    rendered = format_external_references(refs)
    if rendered.startswith(_REFS_HEADER):
        return rendered[len(_REFS_HEADER) :]
    return rendered


def _build_ref_lookup(entry: dict) -> dict[str, dict]:
    """Build a ref-id -> {"title", "url"} map from a single entity's externalReferences.

    Per ADR-016 D6 rule 3, ref-id resolution scope is per-entry: a ref id
    declared on one entry must not resolve from a sibling entry's
    externalReferences. Mirrors scripts/build_persona_site_data.py's helper.
    """
    return {ref["id"]: {"title": ref["title"], "url": ref["url"]} for ref in entry.get("externalReferences", [])}


def collapse_column(
    entry,
    *,
    intra_lookup: dict[str, str] | None = None,
    ref_lookup: dict[str, dict] | None = None,
    field_path: str = "",
) -> str:
    """Collapse multi-line or nested list content into HTML-formatted string.

    When both intra_lookup and ref_lookup are supplied (not None), sentinel
    spans are expanded via expand_sentinels_to_text before newline conversion.
    When either is None (the default), sentinels pass through unchanged so
    pre-A7 call sites keep working.

    An unresolved sentinel raises UnresolvedSentinelError and is never swallowed.

    Args:
        entry: string, list of strings, or other value to format
        intra_lookup: entity-id -> title map; None means no expansion
        ref_lookup: ref-id -> {title, url} map; None means no expansion
        field_path: location string for error messages (e.g. "risks[0].longDescription[0]")
    """
    # Handle pandas NaN values - check type first to avoid array ambiguity
    if not isinstance(entry, (str, list)) and pd.isna(entry):
        return ""

    # Assemble raw text before any HTML conversion, then optionally expand sentinels.
    if isinstance(entry, str):
        raw = entry.replace("- >", "")
    elif isinstance(entry, list) and len(entry) == 1:
        raw = entry[0].replace("- >", "")
    elif not isinstance(entry, list):
        return str(entry) if entry else ""
    else:
        flattened_list = list(chain.from_iterable(item if isinstance(item, list) else [item] for item in entry))
        raw = "<br> ".join(flattened_list).replace("- >", "")

    # Expand sentinels before newline→<br> conversion so markdown links survive intact.
    # Only expand when both lookups are supplied; None means the caller has not opted in.
    if intra_lookup is not None and ref_lookup is not None:
        raw = expand_sentinels_to_text(
            raw, intra_lookup=intra_lookup, ref_lookup=ref_lookup, field_path=field_path
        )

    full_desc = raw.replace("\n", "<br>")

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

    def __init__(
        self,
        input_dir: Path = DEFAULT_INPUT_DIR,
        *,
        intra_lookup: dict[str, str] | None = None,
        ref_lookup: dict[str, dict] | None = None,
    ):
        """
        Initialize table generator.

        Args:
            input_dir: Directory containing YAML source files
            intra_lookup: entity-id -> title map for sentinel expansion; None disables expansion
            ref_lookup: ref-id -> {title, url} map for sentinel expansion; None disables expansion
        """
        self.input_dir = input_dir
        self.intra_lookup = intra_lookup
        self.ref_lookup = ref_lookup
        self._yaml_cache = {}  # Cache for loaded YAML files

    def _ref_lookup_for_entry(self, entry: dict) -> dict[str, dict]:
        """Return per-entry ref lookup; fall back to constructor lookup for legacy/test paths.

        Public path (yaml_to_markdown_table) passes ref_lookup={} so cross-entry
        refs hard-fail per ADR-016 D6 rule 3. The fallback supports tests that
        inject a flat ref_lookup directly into the constructor.
        """
        local = _build_ref_lookup(entry)
        if local:
            return local
        return self.ref_lookup or {}

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

        When intra_lookup and ref_lookup are set on the instance, sentinel spans
        in collapsable fields are expanded per-row before the table is rendered.
        Entries with a non-empty externalReferences array get a "## References for {id}"
        sub-section appended after the main table.

        Args:
            yaml_data: Parsed YAML data dictionary
            ytype: Type of data (components, controls, risks)

        Returns:
            Formatted markdown table string, followed by any References sub-sections
        """
        collapsable = ["description", "guidance", "shortDescription", "longDescription", "examples"]

        entries = yaml_data.get(ytype) or []
        sorted_entries = sorted(entries, key=lambda e: e.get("id", ""))

        # Convert to DataFrame; drop externalReferences — it's rendered as sub-sections below.
        df = pd.DataFrame(entries)
        if "externalReferences" in df.columns:
            df = df.drop(columns=["externalReferences"])

        # pandas orders columns by first appearance across entries, so guidance would
        # land wherever the first entry carrying it puts the key. Pin it directly
        # after description.
        if "guidance" in df.columns and "description" in df.columns:
            cols = [c for c in df.columns if c != "guidance"]
            cols.insert(cols.index("description") + 1, "guidance")
            df = df[cols]

        # Apply column-specific formatting; use per-row sentinel expansion for prose fields.
        for col in df.columns:
            if col in collapsable:
                if self.intra_lookup is not None and self.ref_lookup is not None:
                    # Per-row expansion: thread row index into field_path for error messages.
                    # entries[row_idx] aligns with df.at[row_idx, col] because df is built
                    # from `entries` (insertion order, line above) and sort_values on
                    # df_filled runs only after this loop completes.
                    df = df.reset_index(drop=True)
                    for row_idx in range(len(df)):
                        df.at[row_idx, col] = collapse_column(
                            df.at[row_idx, col],
                            intra_lookup=self.intra_lookup,
                            ref_lookup=self._ref_lookup_for_entry(entries[row_idx]),
                            field_path=f"{ytype}[{row_idx}].{col}",
                        )
                else:
                    df[col] = df[col].apply(collapse_column)
            elif col == "edges":
                df[col] = df[col].apply(format_edges)
            elif col == "tourContent":
                df[col] = df[col].apply(format_dict)
            elif col == "mappings":
                df[col] = df[col].apply(format_mappings)
            else:
                df[col] = df[col].apply(format_list)

        df_filled = df.fillna("").sort_values("id")
        table = df_filled.to_markdown(index=False)

        # Append per-entry References sub-sections for entries with externalReferences.
        sections = [table]
        for entry in sorted_entries:
            refs = entry.get("externalReferences")
            if refs:
                sections.append(f"\n## References for {entry['id']}\n{_references_bullets_only(refs)}")

        return "\n".join(sections)


class SummaryTableGenerator(TableGenerator):
    """
    Generates summary tables with condensed information.

    Includes: ID, Title, Description/ShortDescription, Category
    """

    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate summary markdown table.

        When intra_lookup and ref_lookup are set on the instance, sentinel spans
        in the description field are expanded before the table is rendered.
        Entries with a non-empty externalReferences array get a "## References for {id}"
        sub-section appended after the main table.

        Args:
            yaml_data: Parsed YAML data dictionary
            ytype: Type of data (components, controls, risks)

        Returns:
            Formatted markdown table string, followed by any References sub-sections
        """
        items = yaml_data.get(ytype, []) or []
        sorted_items = sorted(items, key=lambda e: e.get("id", ""))

        rows = []
        for row_idx, item in enumerate(items):
            # Prefer shortDescription over description
            desc = item.get("shortDescription") or item.get("description", "")

            if desc and self.intra_lookup is not None and self.ref_lookup is not None:
                # Expand sentinels; field_path points at the source field and row.
                field_name = "shortDescription" if item.get("shortDescription") else "description"
                collapsed = collapse_column(
                    desc,
                    intra_lookup=self.intra_lookup,
                    ref_lookup=self._ref_lookup_for_entry(item),
                    field_path=f"{ytype}[{row_idx}].{field_name}",
                )
            else:
                collapsed = collapse_column(desc) if desc else ""

            row = {
                "ID": item.get("id", ""),
                "Title": item.get("title", ""),
                "Description": collapsed,
                "Category": item.get("category", ""),
            }
            rows.append(row)

        df = pd.DataFrame(rows).sort_values("ID")
        table = df.to_markdown(index=False)

        # Append per-entry References sub-sections for entries with externalReferences.
        sections = [table]
        for entry in sorted_items:
            refs = entry.get("externalReferences")
            if refs:
                sections.append(f"\n## References for {entry['id']}\n{_references_bullets_only(refs)}")

        return "\n".join(sections)


class PersonaSummaryTableGenerator(TableGenerator):
    """Generates summary tables for personas (no Category column)."""

    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate persona summary markdown table.

        Args:
            yaml_data: Parsed YAML data dictionary
            ytype: Type of data (must be "personas")

        Returns:
            Formatted markdown table string

        Raises:
            ValueError: If ytype is not "personas"
        """
        if ytype != "personas":
            raise ValueError(f"PersonaSummaryTableGenerator only works with 'personas', got '{ytype}'")

        items = yaml_data.get("personas", [])
        rows = []
        for idx, item in enumerate(items):
            desc = item.get("description", "")
            if desc and self.intra_lookup is not None and self.ref_lookup is not None:
                # Expand sentinels in description; field_path uses insertion-order index.
                collapsed = collapse_column(
                    desc,
                    intra_lookup=self.intra_lookup,
                    ref_lookup=self._ref_lookup_for_entry(item),
                    field_path=f"personas[{idx}].description",
                )
            else:
                collapsed = collapse_column(desc) if desc else ""
            row = {
                "ID": item.get("id", ""),
                "Title": item.get("title", ""),
                "Description": collapsed,
                "Status": "Deprecated" if item.get("deprecated", False) else "",
            }
            rows.append(row)

        # Handle empty list case
        if not rows:
            df = pd.DataFrame(columns=["ID", "Title", "Description", "Status"])
        else:
            df = pd.DataFrame(rows).sort_values("ID")
        table = df.to_markdown(index=False)

        # Append per-persona References sub-sections in id-sorted order so they
        # follow the table's row order (the DataFrame is sort_values("ID") above).
        sorted_items = sorted(items, key=lambda e: e.get("id", ""))
        sections = [table]
        for entry in sorted_items:
            refs = entry.get("externalReferences")
            if refs:
                sections.append(f"\n## References for {entry['id']}\n{_references_bullets_only(refs)}")

        return "\n".join(sections)


class PersonaFullDetailTableGenerator(TableGenerator):
    """Generates full detail tables for personas with all fields."""

    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate persona full detail markdown table.

        Args:
            yaml_data: Parsed YAML data dictionary
            ytype: Type of data (must be "personas")

        Returns:
            Formatted markdown table string

        Raises:
            ValueError: If ytype is not "personas"
        """
        if ytype != "personas":
            raise ValueError(f"PersonaFullDetailTableGenerator only works with 'personas', got '{ytype}'")

        items = yaml_data.get("personas", [])
        rows = []
        for idx, item in enumerate(items):
            desc = item.get("description", "")
            if self.intra_lookup is not None and self.ref_lookup is not None:
                # Build per-entry lookup once and reuse across all three expansion sites.
                row_ref_lookup = self._ref_lookup_for_entry(item)
                # Expand sentinels in description; field_path uses insertion-order index.
                collapsed_desc = collapse_column(
                    desc,
                    intra_lookup=self.intra_lookup,
                    ref_lookup=row_ref_lookup,
                    field_path=f"personas[{idx}].description",
                )
                # Expand sentinels in each responsibilities item before passing to format_list.
                expanded_resp = [
                    expand_sentinels_to_text(
                        r,
                        intra_lookup=self.intra_lookup,
                        ref_lookup=row_ref_lookup,
                        field_path=f"personas[{idx}].responsibilities[{i}]",
                    )
                    for i, r in enumerate(item.get("responsibilities", []))
                ]
                # Expand sentinels in each identificationQuestions item.
                expanded_idq = [
                    expand_sentinels_to_text(
                        q,
                        intra_lookup=self.intra_lookup,
                        ref_lookup=row_ref_lookup,
                        field_path=f"personas[{idx}].identificationQuestions[{i}]",
                    )
                    for i, q in enumerate(item.get("identificationQuestions", []))
                ]
            else:
                # No lookups: pass through unchanged (pre-A7 backward compat).
                collapsed_desc = collapse_column(desc)
                expanded_resp = item.get("responsibilities", [])
                expanded_idq = item.get("identificationQuestions", [])

            row = {
                "ID": item.get("id", ""),
                "Title": item.get("title", ""),
                "Description": collapsed_desc,
                "Status": "Deprecated" if item.get("deprecated", False) else "",
                "Responsibilities": format_list(expanded_resp, prefix="- "),
                "Identification Questions": format_list(expanded_idq, prefix="- "),
                "Mappings": format_mappings(item.get("mappings", {})),
            }
            rows.append(row)

        # Handle empty list case
        if not rows:
            df = pd.DataFrame(
                columns=[
                    "ID",
                    "Title",
                    "Description",
                    "Status",
                    "Responsibilities",
                    "Identification Questions",
                    "Mappings",
                ]
            )
        else:
            df = pd.DataFrame(rows).sort_values("ID")
        table = df.to_markdown(index=False)

        # Append per-persona References sub-sections in id-sorted order so they
        # follow the table's row order (the DataFrame is sort_values("ID") above).
        sorted_items = sorted(items, key=lambda e: e.get("id", ""))
        sections = [table]
        for entry in sorted_items:
            refs = entry.get("externalReferences")
            if refs:
                sections.append(f"\n## References for {entry['id']}\n{_references_bullets_only(refs)}")

        return "\n".join(sections)


class PersonaXRefTableGenerator(TableGenerator):
    """
    Base class for persona cross-reference table generators.

    Inverts persona references from another YAML file (controls or risks)
    to create persona-centric views showing what each persona is associated with.
    """

    # Subclasses must define these class attributes
    yaml_file: str = ""  # e.g., "controls.yaml"
    data_key: str = ""  # e.g., "controls"
    id_column: str = ""  # e.g., "Control IDs"
    title_column: str = ""  # e.g., "Control Titles"

    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate persona cross-reference table.

        Args:
            yaml_data: Parsed YAML data dictionary (must be personas)
            ytype: Type of data (must be "personas")

        Returns:
            Formatted markdown table string

        Raises:
            ValueError: If ytype is not "personas"
        """
        if ytype != "personas":
            raise ValueError(f"{self.__class__.__name__} only works with 'personas', got '{ytype}'")

        # Load cross-reference YAML and invert persona references
        xref_data = self._load_yaml(self.yaml_file)
        persona_items = {}  # persona_id -> [(item_id, item_title), ...]

        for item in xref_data.get(self.data_key, []):
            for persona_id in item.get("personas", []):
                if persona_id not in persona_items:
                    persona_items[persona_id] = []
                persona_items[persona_id].append((item.get("id", ""), item.get("title", "")))

        # Build rows from personas
        rows = []
        for persona in yaml_data.get("personas", []):
            pid = persona.get("id", "")
            # Sort items alphabetically by ID to ensure consistent output
            items_list = sorted(persona_items.get(pid, []), key=lambda x: x[0])
            rows.append(
                {
                    "Persona ID": pid,
                    "Persona Title": persona.get("title", ""),
                    self.id_column: format_list([i[0] for i in items_list]),
                    self.title_column: format_list([i[1] for i in items_list]),
                }
            )

        # Handle empty list case
        if not rows:
            df = pd.DataFrame(columns=["Persona ID", "Persona Title", self.id_column, self.title_column])
        else:
            df = pd.DataFrame(rows).sort_values("Persona ID")
        return df.to_markdown(index=False)


class PersonaControlXRefTableGenerator(PersonaXRefTableGenerator):
    """Shows which controls each persona is responsible for."""

    yaml_file = "controls.yaml"
    data_key = "controls"
    id_column = "Control IDs"
    title_column = "Control Titles"


class PersonaRiskXRefTableGenerator(PersonaXRefTableGenerator):
    """Shows which risks affect each persona."""

    yaml_file = "risks.yaml"
    data_key = "risks"
    id_column = "Risk IDs"
    title_column = "Risk Titles"


class FlatPersonaXRefTableGenerator(PersonaXRefTableGenerator):
    """
    Base class for flat persona cross-reference generators.

    Overrides PersonaXRefTableGenerator.generate() to emit one row per
    persona-item mapping instead of grouping multiple items per persona.
    Subclasses configure via class attributes (yaml_file, data_key,
    id_column, title_column) inherited from PersonaXRefTableGenerator.
    """

    # Subclasses must define these (singular, not plural)
    id_column: str = ""  # e.g., "Control ID"
    title_column: str = ""  # e.g., "Control Title"

    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate flat persona cross-reference table with one row per mapping.

        Args:
            yaml_data: Parsed YAML data dictionary (must be personas)
            ytype: Type of data (must be "personas")

        Returns:
            Formatted markdown table with one row per persona-item mapping

        Raises:
            ValueError: If ytype is not "personas"
        """
        if ytype != "personas":
            raise ValueError(f"{self.__class__.__name__} only works with 'personas', got '{ytype}'")

        # Load cross-reference YAML and invert persona references
        xref_data = self._load_yaml(self.yaml_file)
        persona_items = {}  # persona_id -> [(item_id, item_title), ...]

        for item in xref_data.get(self.data_key, []):
            for persona_id in item.get("personas", []):
                if persona_id not in persona_items:
                    persona_items[persona_id] = []
                persona_items[persona_id].append((item.get("id", ""), item.get("title", "")))

        # Build flat rows: one row per persona-item mapping
        rows = []
        for persona in yaml_data.get("personas", []):
            pid = persona.get("id", "")
            ptitle = persona.get("title", "")
            items_list = sorted(persona_items.get(pid, []), key=lambda x: x[0])

            for item_id, item_title in items_list:
                rows.append(
                    {
                        "Persona ID": pid,
                        "Persona Title": ptitle,
                        self.id_column: item_id,
                        self.title_column: item_title,
                    }
                )

        if rows:
            df = pd.DataFrame(rows).sort_values(["Persona ID", self.id_column])
        else:
            df = pd.DataFrame(columns=["Persona ID", "Persona Title", self.id_column, self.title_column])

        return df.to_markdown(index=False)


class FlatPersonaControlXRefTableGenerator(FlatPersonaXRefTableGenerator):
    """Flat persona-to-control xref: one row per persona-control mapping."""

    yaml_file = "controls.yaml"
    data_key = "controls"
    id_column = "Control ID"
    title_column = "Control Title"


class FlatPersonaRiskXRefTableGenerator(FlatPersonaXRefTableGenerator):
    """Flat persona-to-risk xref: one row per persona-risk mapping."""

    yaml_file = "risks.yaml"
    data_key = "risks"
    id_column = "Risk ID"
    title_column = "Risk Title"


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
                isinstance(risk_ids, list) and len(risk_ids) == 1 and risk_ids[0] == "all"
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
                "Risk Titles": risk_titles_display,
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
                isinstance(component_ids, list) and len(component_ids) == 1 and component_ids[0] == "all"
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
                "Component Titles": component_titles_display,
            }
            rows.append(row)

        df = pd.DataFrame(rows).sort_values("Control ID")
        return df.to_markdown(index=False)


class FlatControlXRefTableGenerator(TableGenerator):
    """
    Base class for flat control cross-reference generators.

    Creates one table row per control-item mapping instead of packing
    multiple IDs into single cells with <br> separators. Subclasses
    configure via class attributes for the specific xref type.
    """

    # Subclasses must define these
    xref_yaml_file: str = ""  # e.g., "risks.yaml"
    xref_data_key: str = ""  # e.g., "risks"
    control_field: str = ""  # field name in control dict, e.g., "risks"
    id_column: str = ""  # e.g., "Risk ID"
    title_column: str = ""  # e.g., "Risk Title"
    all_title: str = ""  # e.g., "All Risks"

    def generate(self, yaml_data: dict, ytype: str) -> str:
        """
        Generate flat control cross-reference table with one row per mapping.

        Args:
            yaml_data: Parsed YAML data dictionary (must be controls)
            ytype: Type of data (must be "controls")

        Returns:
            Formatted markdown table with one row per control-item mapping

        Raises:
            ValueError: If ytype is not "controls"
        """
        if ytype != "controls":
            raise ValueError(f"{self.__class__.__name__} only works with 'controls', got '{ytype}'")

        # Load xref YAML for title lookup
        xref_data = self._load_yaml(self.xref_yaml_file)
        lookup = self._create_id_to_title_lookup(xref_data, self.xref_data_key)

        controls = yaml_data.get("controls", [])
        rows = []

        for control in controls:
            control_id = control.get("id", "")
            control_title = control.get("title", "")
            item_ids = control.get(self.control_field, [])

            # Handle special case: "all" or ["all"]
            is_all = item_ids == "all" or (
                isinstance(item_ids, list) and len(item_ids) == 1 and item_ids[0] == "all"
            )
            if is_all:
                rows.append(
                    {
                        "Control ID": control_id,
                        "Control Title": control_title,
                        self.id_column: "all",
                        self.title_column: self.all_title,
                    }
                )
            elif isinstance(item_ids, list):
                for item_id in sorted(item_ids):
                    item_title = lookup.get(item_id, f"Unknown ({item_id})")
                    rows.append(
                        {
                            "Control ID": control_id,
                            "Control Title": control_title,
                            self.id_column: item_id,
                            self.title_column: item_title,
                        }
                    )

        if rows:
            df = pd.DataFrame(rows).sort_values(["Control ID", self.id_column])
        else:
            df = pd.DataFrame(columns=["Control ID", "Control Title", self.id_column, self.title_column])

        return df.to_markdown(index=False)


class FlatRiskXRefTableGenerator(FlatControlXRefTableGenerator):
    """Flat control-to-risk xref: one row per control-risk mapping."""

    xref_yaml_file = "risks.yaml"
    xref_data_key = "risks"
    control_field = "risks"
    id_column = "Risk ID"
    title_column = "Risk Title"
    all_title = "All Risks"


class FlatComponentXRefTableGenerator(FlatControlXRefTableGenerator):
    """Flat control-to-component xref: one row per control-component mapping."""

    xref_yaml_file = "components.yaml"
    xref_data_key = "components"
    control_field = "components"
    id_column = "Component ID"
    title_column = "Component Title"
    all_title = "All Components"


# Table generator registry
TABLE_GENERATORS = {
    "full": FullDetailTableGenerator,
    "summary": SummaryTableGenerator,
    "xref-risks": RiskXRefTableGenerator,
    "xref-components": ComponentXRefTableGenerator,
}


def yaml_to_markdown_table(yaml_file, ytype, table_format: str = "full", flat: bool = True):
    """
    Convert YAML data to formatted Markdown table using specified format.

    Args:
        yaml_file: Path to YAML input file
        ytype: Type of data to extract (components, controls, risks)
        table_format: Format type (full, summary, xref-risks, xref-components)
        flat: Use flat xref tables with one row per mapping (default True; xref formats only)

    Returns:
        Formatted markdown table string

    Raises:
        ValueError: If table_format is not recognized or incompatible with ytype
    """
    # Persona-specific formats handled separately below
    persona_formats = {"full", "summary", "xref-controls", "xref-risks"}

    # Validate format (defer persona-specific validation until we check ytype)
    if table_format not in TABLE_GENERATORS and table_format not in persona_formats:
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

    # Build intra_lookup from all four corpus files; tolerate missing siblings.
    # XRef generators don't expand prose, but passing lookups here is harmless.
    intra_lookup: dict[str, str] = {}
    for fname, key in (
        ("risks.yaml", "risks"),
        ("controls.yaml", "controls"),
        ("components.yaml", "components"),
        ("personas.yaml", "personas"),
    ):
        fpath = input_dir / fname
        if not fpath.exists():
            continue
        with open(fpath) as fh:
            sibling = yaml.safe_load(fh) or {}
        for item in sibling.get(key, []) or []:
            if isinstance(item, dict) and "id" in item and "title" in item:
                intra_lookup[item["id"]] = item["title"]

    # ref_lookup is built per-entry by the generator via _ref_lookup_for_entry;
    # this matches build_persona_site_data.py's _build_ref_lookup pattern
    # (ADR-016 D6 rule 3, per-entry resolution scope). The empty dict here makes
    # any sentinel that escapes per-entry lookup hard-fail.
    ref_lookup: dict[str, dict] = {}

    # Create generator instance and generate table
    # Handle persona-specific generators
    if ytype == "personas":
        persona_generators = {
            "full": PersonaFullDetailTableGenerator,
            "summary": PersonaSummaryTableGenerator,
            "xref-controls": PersonaControlXRefTableGenerator,
            "xref-risks": PersonaRiskXRefTableGenerator,
        }
        # Use flat generators if flat=True and format is xref
        if flat:
            persona_generators["xref-controls"] = FlatPersonaControlXRefTableGenerator
            persona_generators["xref-risks"] = FlatPersonaRiskXRefTableGenerator

        if table_format not in persona_generators:
            valid = ", ".join(persona_generators.keys())
            raise ValueError(f"Invalid table format '{table_format}' for personas. Valid: {valid}")
        generator_class = persona_generators[table_format]
    else:
        # Handle flat control xref generators
        if flat and table_format == "xref-risks":
            generator_class = FlatRiskXRefTableGenerator
        elif flat and table_format == "xref-components":
            generator_class = FlatComponentXRefTableGenerator
        else:
            generator_class = TABLE_GENERATORS[table_format]

    generator = generator_class(input_dir=input_dir, intra_lookup=intra_lookup, ref_lookup=ref_lookup)

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
  personas      - User roles and responsibilities

Available Formats:
  full              - Complete detail tables with all columns (default)
  summary           - Condensed tables (ID, Title, Description, Category/Status)
  xref-risks        - Cross-reference to risks (controls, personas)
  xref-components   - Control-to-component cross-reference (controls only)
  xref-controls     - Persona-to-control cross-reference (personas only)

Exit Codes:
  0 - Conversion completed successfully
  1 - Invalid arguments or missing files
  2 - Processing error
        """,
    )

    parser.add_argument(
        "types",
        nargs="*",
        help="Type(s) of YAML data to convert: components, controls, risks, personas",
    )

    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Convert all types (components, controls, risks, personas)",
    )

    # All valid formats including persona-specific ones
    all_formats = list(TABLE_GENERATORS.keys()) + ["xref-controls"]
    parser.add_argument(
        "--format",
        "-f",
        type=str,
        default="full",
        choices=all_formats,
        help="Table format to generate (default: full)",
    )

    parser.add_argument(
        "--all-formats",
        action="store_true",
        help="Generate all applicable formats for each type (overrides --format)",
    )

    parser.add_argument(
        "--no-flat",
        dest="flat",
        action="store_false",
        help="Use grouped xref tables instead of the default flat (one-row-per-mapping) format",
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
        ytype: Data type (components, controls, risks, personas)

    Returns:
        List of applicable format names
    """
    # Base formats work for all types
    base_formats = ["full", "summary"]

    if ytype == "personas":
        return base_formats + ["xref-controls", "xref-risks"]
    # Cross-reference formats only work with controls
    if ytype == "controls":
        return base_formats + ["xref-risks", "xref-components"]

    return base_formats


def convert_all_formats(
    ytype: str, input_file: Path = None, output_dir: Path = None, quiet: bool = False, flat: bool = True
) -> bool:
    """
    Convert a single YAML type to all applicable markdown table formats.

    Args:
        ytype: Data type to convert
        input_file: Optional custom input file
        output_dir: Optional custom output directory
        quiet: Whether to suppress output messages
        flat: Use flat xref tables with one row per mapping (default True)

    Returns:
        True if all conversions successful, False if any failed
    """
    applicable_formats = get_applicable_formats(ytype)

    if not quiet:
        format_list = ", ".join(applicable_formats)
        print(f"📐 Generating {len(applicable_formats)} format(s) for {ytype}: {format_list}")

    all_successful = True
    for table_format in applicable_formats:
        if not convert_type(ytype, table_format, input_file, None, output_dir, quiet, flat):
            all_successful = False

    return all_successful


def convert_type(
    ytype: str,
    table_format: str = "full",
    input_file: Path = None,
    output_file: Path = None,
    output_dir: Path = None,
    quiet: bool = False,
    flat: bool = True,
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
        flat: Use flat xref tables with one row per mapping (default True)

    Returns:
        True if successful, False otherwise
    """
    try:
        # Validate format compatibility with type
        # xref-components only works with controls
        if table_format == "xref-components" and ytype != "controls":
            print(f"❌ Error: Format '{table_format}' only works with 'controls', not '{ytype}'")
            return False

        # xref-risks works with both controls and personas
        if table_format == "xref-risks" and ytype not in ["controls", "personas"]:
            print(f"❌ Error: Format '{table_format}' only works with 'controls' or 'personas', not '{ytype}'")
            return False

        # xref-controls only works with personas
        if table_format == "xref-controls" and ytype != "personas":
            print(f"❌ Error: Format '{table_format}' only works with 'personas', not '{ytype}'")
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
        result = yaml_to_markdown_table(yaml_file=in_file, ytype=ytype, table_format=table_format, flat=flat)

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
        valid_types = {"components", "controls", "risks", "personas"}
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
        # xref-components only works with controls
        if not args.all_formats and args.format == "xref-components":
            types_to_convert = ["components", "controls", "risks", "personas"] if args.all else args.types
            non_control_types = [t for t in types_to_convert if t != "controls"]
            if non_control_types:
                print(f"❌ Error: Format '{args.format}' only works with 'controls'")
                print(f"   Cannot use with: {', '.join(non_control_types)}")
                sys.exit(1)

        # xref-risks works with both controls and personas
        if not args.all_formats and args.format == "xref-risks":
            types_to_convert = ["components", "controls", "risks", "personas"] if args.all else args.types
            invalid_types = [t for t in types_to_convert if t not in ["controls", "personas"]]
            if invalid_types:
                print(f"❌ Error: Format '{args.format}' only works with 'controls' or 'personas'")
                print(f"   Cannot use with: {', '.join(invalid_types)}")
                sys.exit(1)

        # xref-controls only works with personas
        if not args.all_formats and args.format == "xref-controls":
            types_to_convert = ["components", "controls", "risks", "personas"] if args.all else args.types
            non_persona_types = [t for t in types_to_convert if t != "personas"]
            if non_persona_types:
                print(f"❌ Error: Format '{args.format}' only works with 'personas'")
                print(f"   Cannot use with: {', '.join(non_persona_types)}")
                sys.exit(1)

        # Determine which types to convert
        types_to_convert = ["components", "controls", "risks", "personas"] if args.all else args.types

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
                if not convert_all_formats(ytype, args.file, args.output_dir, args.quiet, args.flat):
                    all_successful = False
            else:
                # Use custom output only if converting single type with single format
                output = args.output if len(types_to_convert) == 1 else None

                if not convert_type(ytype, args.format, args.file, output, args.output_dir, args.quiet, args.flat):
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
