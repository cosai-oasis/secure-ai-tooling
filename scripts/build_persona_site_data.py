#!/usr/bin/env python3
"""
Generate frontend data for the CoSAI-RM persona Pages experience.

This script keeps the website data model derived directly from the framework
YAML files instead of introducing a second website-only mapping.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import jsonschema
import referencing
import referencing.jsonschema
import yaml
from jsonschema import Draft7Validator

REPO_ROOT = Path(__file__).resolve().parent.parent

# Ensure REPO_ROOT is on sys.path so that "scripts.hooks._sentinel_expansion"
# resolves when this file is invoked directly as a script (not just as a module).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.hooks._sentinel_expansion import (  # noqa: E402
    expand_sentinels_to_items,
    expand_sentinels_to_text,
)

DEFAULT_PERSONAS_PATH = REPO_ROOT / "risk-map" / "yaml" / "personas.yaml"
DEFAULT_RISKS_PATH = REPO_ROOT / "risk-map" / "yaml" / "risks.yaml"
DEFAULT_CONTROLS_PATH = REPO_ROOT / "risk-map" / "yaml" / "controls.yaml"
DEFAULT_COMPONENTS_PATH = REPO_ROOT / "risk-map" / "yaml" / "components.yaml"
DEFAULT_SITE_DIR = REPO_ROOT / "site"
DEFAULT_OUTPUT_NAME = "persona-site-data.json"
GUIDED_QUESTION_THRESHOLD = 5

SCHEMAS_DIR = REPO_ROOT / "risk-map" / "schemas"
PERSONA_SITE_DATA_SCHEMA_PATH = SCHEMAS_DIR / "persona-site-data.schema.json"


def _make_schema_registry(schemas_dir: Path) -> referencing.Registry:
    """Build a referencing.Registry that resolves bare-filename $refs against schemas_dir.

    The persona-site-data schema $refs external-references.schema.json by
    relative URI; this registry retrieves and registers it on demand.
    """

    def retrieve(uri: str) -> referencing.Resource:
        # Extract the bare filename from the URI — all $refs in this repo are
        # bare filenames (e.g. "external-references.schema.json"), not full paths.
        name = uri.rsplit("/", 1)[-1]
        with (schemas_dir / name).open("r", encoding="utf-8") as fh:
            contents = json.load(fh)
        return referencing.Resource.from_contents(contents, default_specification=referencing.jsonschema.DRAFT7)

    return referencing.Registry(retrieve=retrieve)


def _load_output_schema() -> tuple[dict, referencing.Registry]:
    """Load the persona site data output schema and its $ref registry."""
    with PERSONA_SITE_DATA_SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    registry = _make_schema_registry(SCHEMAS_DIR)
    return schema, registry


_OUTPUT_SCHEMA, _OUTPUT_SCHEMA_REGISTRY = _load_output_schema()


def load_yaml(path: Path) -> dict:
    """Load a YAML file into a Python dictionary."""
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if data is None:
        raise ValueError(f"{path} is empty or all-null")
    return data


def normalize_text_entries(value, *, intra_lookup=None, ref_lookup=None, field_path=None) -> list:
    """Normalize YAML text scalars/lists into a shape-preserving list.

    When intra_lookup, ref_lookup, and field_path are all provided, string items
    are expanded via expand_sentinels_to_items. Otherwise (legacy / no-sentinel
    mode) the pre-A7 behavior is preserved: strip each string, drop empty strings.

    Top-level list items (nested-group shape) have their inner strings expanded
    via expand_sentinels_to_items when sentinel_mode is active (field_path uses
    [item_idx][inner_idx] notation for diagnostics). In legacy mode the pre-A7
    behaviour is preserved: strip each inner string, drop empty.

    NIT-08: Empty / whitespace-only list entries are silently dropped — do
    not use ``- ""`` as a spacing hack. Nested sub-lists that are empty after
    stripping are likewise dropped from the output.

    Args:
        value: A string, list, or None from a YAML field.
        intra_lookup: maps entity-id -> title (sentinel expansion mode).
        ref_lookup: maps ref-id -> {"title": str, "url": str}.
        field_path: caller-supplied location prefix for error messages.

    Returns:
        List of processed items (strings, nested lists, or mixed sentinel items).

    Raises:
        TypeError: for non-string, non-list leaf values.
        UnresolvedSentinelError: when sentinel expansion mode is active and a
            sentinel id cannot be resolved.
    """
    sentinel_mode = intra_lookup is not None and ref_lookup is not None and field_path is not None

    if value is None:
        return []

    if isinstance(value, list):
        items = value
    else:
        items = [value]

    result: list = []
    for item_idx, item in enumerate(items):
        if isinstance(item, list):
            # Nested group: mirrors the str-leaf branch — sentinel_mode expands
            # each inner string; legacy mode strips and drops empties only.
            sub: list[str | dict] = []
            for inner_idx, s in enumerate(item):
                if not isinstance(s, str):
                    raise TypeError(f"Nested prose items must be strings, got {type(s).__name__}: {s!r}")
                if sentinel_mode:
                    inner_field_path = f"{field_path}[{item_idx}][{inner_idx}]"
                    expanded = expand_sentinels_to_items(
                        s.strip(),
                        intra_lookup=intra_lookup,
                        ref_lookup=ref_lookup,
                        field_path=inner_field_path,
                    )
                    if len(expanded) == 0:
                        # Empty result — drop this inner item (NIT-08 parity).
                        pass
                    elif len(expanded) == 1 and isinstance(expanded[0], str):
                        # Single plain string — append as-is (no sentinels present).
                        sub.append(expanded[0])
                    else:
                        # Mixed or structured items — extend so the inner list
                        # carries text + ref/link + text per ADR-016 D5.
                        sub.extend(expanded)
                else:
                    stripped = s.strip()
                    if stripped:
                        sub.append(stripped)
            if sub:
                result.append(sub)

        elif isinstance(item, str):
            if sentinel_mode:
                # Build a per-item field_path for error diagnostics.
                item_field_path = f"{field_path}[{item_idx}]"
                expanded = expand_sentinels_to_items(
                    item.strip(),
                    intra_lookup=intra_lookup,
                    ref_lookup=ref_lookup,
                    field_path=item_field_path,
                )
                if len(expanded) == 0:
                    # Empty result — drop this item (NIT-08 parity).
                    pass
                elif len(expanded) == 1 and isinstance(expanded[0], str):
                    # Single plain string — emit as-is (preserves pre-A7 shape).
                    result.append(expanded[0])
                else:
                    # Mixed or structured items — wrap as nested array so the outer
                    # prose array keeps a clean type: the inner array branch of the
                    # schema already accepts ref/link items per ADR-016 D5.
                    result.append(expanded)
            else:
                # Legacy mode: strip and drop empty.
                stripped = item.strip()
                if stripped:
                    result.append(stripped)

        else:
            raise TypeError(f"Prose items must be string or list-of-strings, got {type(item).__name__}: {item!r}")

    return result


def humanize_identifier(identifier: str, prefix: str = "") -> str:
    """Convert schema-like identifiers into simple display labels."""
    trimmed = identifier[len(prefix) :] if prefix and identifier.startswith(prefix) else identifier
    return re.sub(r"(?<!^)(?=[A-Z])", " ", trimmed.replace("-", " ")).strip()


def normalize_control_risk_ids(raw_risks, all_risk_ids: list[str]) -> list[str]:
    """Expand control risk links into explicit IDs for easier client-side filtering."""
    if raw_risks == "all":
        return list(all_risk_ids)

    if raw_risks in (None, "none"):
        return []

    return [risk_id for risk_id in raw_risks if risk_id in all_risk_ids]


def _build_intra_lookup(
    personas_data: dict,
    risks_data: dict,
    controls_data: dict,
    components_data: dict,
) -> dict[str, str]:
    """Build a unified id->title map across all four entity types.

    Used for resolving intra-document sentinels like {{riskFoo}} or {{controlBar}}.

    Args:
        personas_data: parsed personas YAML dict.
        risks_data: parsed risks YAML dict.
        controls_data: parsed controls YAML dict.
        components_data: parsed components YAML dict.

    Returns:
        Dict mapping every entity id to its title.
    """
    lookup: dict[str, str] = {}
    for persona in personas_data.get("personas", []):
        lookup[persona["id"]] = persona["title"]
    for risk in risks_data.get("risks", []):
        lookup[risk["id"]] = risk["title"]
    for control in controls_data.get("controls", []):
        lookup[control["id"]] = control["title"]
    # components.yaml has a flat top-level "components" list alongside "categories".
    for component in components_data.get("components", []):
        lookup[component["id"]] = component["title"]
    return lookup


def _build_ref_lookup(entry: dict) -> dict[str, dict]:
    """Build a ref-id->entry map from a single entity's externalReferences.

    Per-entry scoping ensures {{ref:foo}} only resolves against the entry that
    declares "foo" in its own externalReferences — not a corpus-wide pool.

    Args:
        entry: a single risk, control, or persona dict from YAML.

    Returns:
        Dict mapping ref-id -> {"title": str, "url": str}.
    """
    return {ref["id"]: {"title": ref["title"], "url": ref["url"]} for ref in entry.get("externalReferences", [])}


def build_site_data(
    personas_data: dict,
    risks_data: dict,
    controls_data: dict,
    components_data: dict | None = None,
) -> dict:
    """Build the JSON structure consumed by the static persona site.

    Args:
        personas_data: parsed personas YAML dict.
        risks_data: parsed risks YAML dict.
        controls_data: parsed controls YAML dict.
        components_data: parsed components YAML dict, or None to load from
            DEFAULT_COMPONENTS_PATH. Providing it explicitly lets callers
            supply synthetic data in tests without touching disk.

    Returns:
        Dict conforming to persona-site-data.schema.json.
    """
    if components_data is None:
        components_data = load_yaml(DEFAULT_COMPONENTS_PATH)

    # Build once; used for all intra-sentinel resolutions across every entity.
    intra_lookup = _build_intra_lookup(personas_data, risks_data, controls_data, components_data)

    active_personas = [persona for persona in personas_data["personas"] if not persona.get("deprecated")]
    active_persona_ids = {persona["id"] for persona in active_personas}

    risk_categories = []
    seen_risk_categories = set()
    normalized_risks = []

    for idx, raw_risk in enumerate(risks_data["risks"]):
        category_id = raw_risk["category"]
        if category_id not in seen_risk_categories:
            risk_categories.append({"id": category_id, "title": humanize_identifier(category_id, "risks")})
            seen_risk_categories.add(category_id)

        ref_lookup = _build_ref_lookup(raw_risk)
        risk_field = f"risks[{idx}]"

        risk_record: dict = {
            "id": raw_risk["id"],
            "title": raw_risk["title"],
            "category": category_id,
            "shortDescription": normalize_text_entries(
                raw_risk.get("shortDescription"),
                intra_lookup=intra_lookup,
                ref_lookup=ref_lookup,
                field_path=f"{risk_field}.shortDescription",
            ),
            "longDescription": normalize_text_entries(
                raw_risk.get("longDescription"),
                intra_lookup=intra_lookup,
                ref_lookup=ref_lookup,
                field_path=f"{risk_field}.longDescription",
            ),
            "examples": normalize_text_entries(
                raw_risk.get("examples"),
                intra_lookup=intra_lookup,
                ref_lookup=ref_lookup,
                field_path=f"{risk_field}.examples",
            ),
            "controlIds": list(raw_risk.get("controls", [])),
            "personaIds": [
                persona_id for persona_id in raw_risk.get("personas", []) if persona_id in active_persona_ids
            ],
        }
        if "externalReferences" in raw_risk:
            risk_record["externalReferences"] = raw_risk["externalReferences"]

        normalized_risks.append(risk_record)

    all_risk_ids = [risk["id"] for risk in normalized_risks]
    normalized_controls = []

    for idx, raw_control in enumerate(controls_data["controls"]):
        ref_lookup = _build_ref_lookup(raw_control)
        control_field = f"controls[{idx}]"

        control_record: dict = {
            "id": raw_control["id"],
            "title": raw_control["title"],
            "category": raw_control["category"],
            "description": normalize_text_entries(
                raw_control.get("description"),
                intra_lookup=intra_lookup,
                ref_lookup=ref_lookup,
                field_path=f"{control_field}.description",
            ),
            "personaIds": [
                persona_id for persona_id in raw_control.get("personas", []) if persona_id in active_persona_ids
            ],
            "riskIds": normalize_control_risk_ids(raw_control.get("risks"), all_risk_ids),
        }
        # guidance is optional; emit it only when present so the output contract
        # stays unchanged for controls that do not carry it.
        if "guidance" in raw_control:
            control_record["guidance"] = normalize_text_entries(
                raw_control["guidance"],
                intra_lookup=intra_lookup,
                ref_lookup=ref_lookup,
                field_path=f"{control_field}.guidance",
            )
        if "externalReferences" in raw_control:
            control_record["externalReferences"] = raw_control["externalReferences"]

        normalized_controls.append(control_record)

    risk_ids_by_persona = {persona["id"]: [] for persona in active_personas}
    control_ids_by_persona = {persona["id"]: [] for persona in active_personas}

    for risk in normalized_risks:
        for persona_id in risk["personaIds"]:
            risk_ids_by_persona[persona_id].append(risk["id"])

    for control in normalized_controls:
        for persona_id in control["personaIds"]:
            control_ids_by_persona[persona_id].append(control["id"])

    question_records = []
    persona_records = []
    manual_fallback_persona_ids = []

    for idx, persona in enumerate(active_personas):
        # identificationQuestions schema is string[] (matchmaker prompts), so sentinels
        # expand to plain text rather than structured ref/link items. Mirrors the
        # markdown side (PersonaFullDetailTableGenerator); ADR-016 D5 hard-fail applies.
        persona_ref_lookup = _build_ref_lookup(persona)
        raw_questions = persona.get("identificationQuestions") or []
        # Strip each question first to drop trailing newlines from PyYAML block
        # scalars; the legacy normalize_text_entries path stripped at the same
        # point, and the markdown side strips downstream in format_list.
        question_prompts = [
            expand_sentinels_to_text(
                q.strip(),
                intra_lookup=intra_lookup,
                ref_lookup=persona_ref_lookup,
                field_path=f"personas[{idx}].identificationQuestions[{q_idx}]",
            )
            for q_idx, q in enumerate(raw_questions)
            if q.strip()
        ]
        match_mode = "guided" if len(question_prompts) >= GUIDED_QUESTION_THRESHOLD else "manual"

        question_ids = []
        for index, prompt in enumerate(question_prompts, start=1):
            question_id = f"{persona['id']}-q{index}"
            question_ids.append(question_id)
            question_records.append(
                {
                    "id": question_id,
                    "personaId": persona["id"],
                    "personaTitle": persona["title"],
                    "prompt": prompt,
                }
            )

        if match_mode == "manual":
            manual_fallback_persona_ids.append(persona["id"])

        ref_lookup = _build_ref_lookup(persona)
        persona_field = f"personas[{idx}]"

        persona_record: dict = {
            "id": persona["id"],
            "title": persona["title"],
            "description": normalize_text_entries(
                persona.get("description"),
                intra_lookup=intra_lookup,
                ref_lookup=ref_lookup,
                field_path=f"{persona_field}.description",
            ),
            "responsibilities": normalize_text_entries(
                persona.get("responsibilities"),
                intra_lookup=intra_lookup,
                ref_lookup=ref_lookup,
                field_path=f"{persona_field}.responsibilities",
            ),
            "identificationQuestions": question_prompts,
            "questionIds": question_ids,
            "questionCount": len(question_ids),
            "matchMode": match_mode,
            "riskIds": risk_ids_by_persona[persona["id"]],
            "controlIds": control_ids_by_persona[persona["id"]],
            "riskCount": len(risk_ids_by_persona[persona["id"]]),
            "controlCount": len(control_ids_by_persona[persona["id"]]),
        }
        if "externalReferences" in persona:
            persona_record["externalReferences"] = persona["externalReferences"]

        persona_records.append(persona_record)

    return {
        "personas": persona_records,
        "questions": question_records,
        "manualFallbackPersonaIds": manual_fallback_persona_ids,
        "riskCategories": risk_categories,
        "controlCategories": list(controls_data["categories"]),
        "risks": normalized_risks,
        "controls": normalized_controls,
    }


def resolve_output_path(site_dir: Path, output_path: Path | None) -> Path:
    """Resolve the final JSON output path for the site data."""
    if output_path is not None:
        return output_path

    return site_dir / "generated" / DEFAULT_OUTPUT_NAME


def write_site_data(data: dict, output_path: Path) -> None:
    """Write site data JSON with stable formatting, validating against the output schema first."""
    try:
        # Use Draft7Validator with the registry so cross-schema $refs (e.g.
        # external-references.schema.json) resolve from disk on demand.
        Draft7Validator(_OUTPUT_SCHEMA, registry=_OUTPUT_SCHEMA_REGISTRY).validate(data)
    except jsonschema.ValidationError as exc:
        raise jsonschema.ValidationError(
            f"Persona site data failed schema validation at {list(exc.absolute_path)!r}: {exc.message}",
        ) from exc
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        # Insertion-order deterministic; do not rely on alphabetical key sort.
        json.dump(data, handle, indent=2)
        handle.write("\n")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Generate CoSAI-RM persona site data JSON.")
    parser.add_argument(
        "--personas-path",
        type=Path,
        default=DEFAULT_PERSONAS_PATH,
        help=f"Path to personas YAML (default: {DEFAULT_PERSONAS_PATH.relative_to(REPO_ROOT)})",
    )
    parser.add_argument(
        "--risks-path",
        type=Path,
        default=DEFAULT_RISKS_PATH,
        help=f"Path to risks YAML (default: {DEFAULT_RISKS_PATH.relative_to(REPO_ROOT)})",
    )
    parser.add_argument(
        "--controls-path",
        type=Path,
        default=DEFAULT_CONTROLS_PATH,
        help=f"Path to controls YAML (default: {DEFAULT_CONTROLS_PATH.relative_to(REPO_ROOT)})",
    )
    parser.add_argument(
        "--site-dir",
        type=Path,
        default=DEFAULT_SITE_DIR,
        help=(
            f"Site asset directory (default: {DEFAULT_SITE_DIR.relative_to(REPO_ROOT)}); "
            "generated JSON lands under <site-dir>/generated/"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Exact output-JSON path (overrides the --site-dir/generated/ default)",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""
    args = parse_args()
    output_path = resolve_output_path(args.site_dir, args.output)
    site_data = build_site_data(
        load_yaml(args.personas_path),
        load_yaml(args.risks_path),
        load_yaml(args.controls_path),
    )
    write_site_data(site_data, output_path)
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
