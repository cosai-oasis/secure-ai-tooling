"""
Shared prose-field discovery for the ADR-017/ADR-016 prose linters.

Both ``validate_yaml_prose_subset`` and ``validate_prose_references`` import
``find_prose_fields`` from here so the iteration shape is identical.  The
schema's ``utils/text`` definition admits one level of nesting::

    {type: array, items: {oneOf: [
        {type: string},
        {type: array, items: {type: string}, minItems: 1}
    ]}}

This module yields one ``ProseField`` per inner string for both the flat-array
shape and the nested-array shape, with ``nested_index`` populated only for
inner-list strings (Phase-2 contract).

Two discovery paths are supported:

- **Entity-array schemas** — the prose ``$ref`` lives under
  ``definitions[*].properties[*]``; entries come from the top-level array
  whose key matches a schema array property (e.g. ``risks: [...]``).
- **File-level wrapper schemas** — the prose ``$ref`` lives directly under
  ``properties[*]`` at the schema root, sibling to (or instead of) any entity
  array.  The wrapper field is keyed at the YAML document root and its
  synthetic ``entry_id`` is ``yaml_path.stem``.
"""

import json
from collections.abc import Iterator
from pathlib import Path

import yaml

from precommit._linter_types import ProseField
from precommit._prose_tokens import tokenize

# $ref value that marks a field as a prose field in schema definitions.
_PROSE_REF = "riskmap.schema.json#/definitions/utils/text"


def _is_prose_ref(ref: str) -> bool:
    """Return True if the $ref value marks a prose field."""
    return ref == _PROSE_REF


def _walk_property(path: str, prop_schema: dict, names: list[str]) -> None:
    """Recursively collect prose-marked field paths.

    Handles three cases:
    - Leaf prose ref (e.g. shortDescription -> $ref: .../utils/text)
    - Array of objects (e.g. entries[].description) -- walks items.properties
    - Nested object (e.g. tourContent.introduced) -- walks its properties

    Args:
        path:        Dotted field path accumulated so far.
        prop_schema: The JSON schema fragment for this property.
        names:       Accumulator list; prose field paths are appended here.
    """
    ref = prop_schema.get("$ref")
    if ref and _is_prose_ref(ref):
        names.append(path)
        return
    # Array of objects: descend into items.properties (e.g. entries[].text)
    if prop_schema.get("type") == "array":
        items = prop_schema.get("items", {})
        for sub_name, sub_schema in items.get("properties", {}).items():
            _walk_property(f"{path}.{sub_name}", sub_schema, names)
        return
    # Nested object: descend into its properties (e.g. tourContent.introduced)
    if prop_schema.get("type") == "object":
        for sub_name, sub_schema in prop_schema.get("properties", {}).items():
            _walk_property(f"{path}.{sub_name}", sub_schema, names)


def _find_prose_field_names_in_schema(schema: dict) -> list[str]:
    """Return path-qualified prose field names found in the schema's definitions.

    Walks definitions[*]/properties for the prose $ref marker, recursing
    into object-typed properties so nested prose fields like
    tourContent.introduced are discovered. Returns dotted-path field names
    (e.g. 'longDescription', 'tourContent.introduced').

    Args:
        schema: Parsed JSON schema dict.

    Returns:
        List of dotted-path field names marked as prose fields.
    """
    names: list[str] = []
    for _defname, defdata in schema.get("definitions", {}).items():
        if not isinstance(defdata, dict):
            continue
        for prop_name, prop_schema in defdata.get("properties", {}).items():
            if isinstance(prop_schema, dict):
                _walk_property(prop_name, prop_schema, names)
    return names


def _find_wrapper_prose_field_names_in_schema(schema: dict) -> list[str]:
    """Return prose field names declared directly at the schema root.

    Wrapper case: a top-level property whose ``$ref`` resolves to ``utils/text``
    -- the prose field is keyed at the YAML document root, sibling to any
    entity arrays.  Only direct ``$ref`` matches are returned; array-typed
    top-level properties (entity arrays) are intentionally ignored here -- the
    entity-array path is handled by ``_find_prose_field_names_in_schema``.

    Args:
        schema: Parsed JSON schema dict.

    Returns:
        List of top-level prose field names.
    """
    names: list[str] = []
    for prop_name, prop_schema in schema.get("properties", {}).items():
        if not isinstance(prop_schema, dict):
            continue
        ref = prop_schema.get("$ref")
        if ref and _is_prose_ref(ref):
            names.append(prop_name)
    return names


def _infer_schema_name(yaml_path: Path, schema_dir: Path) -> Path | None:
    """Locate a schema file for the given YAML by stem-name or array-key matching.

    Looks for ``<stem>.schema.json`` in schema_dir (e.g. risks.yaml -> risks.schema.json).
    Falls back to iterating all ``*.schema.json`` files and finding one whose
    top-level array property name matches the YAML's top-level key.

    Args:
        yaml_path:  Path to the YAML file being linted.
        schema_dir: Directory containing JSON schema files.

    Returns:
        Path to the matched schema, or None if no schema is found.
    """
    # Primary: stem-based match (risks.yaml -> risks.schema.json)
    candidate = schema_dir / f"{yaml_path.stem}.schema.json"
    if candidate.is_file():
        return candidate

    # Secondary: iterate schemas and match by overlapping top-level array keys.
    # Used for non-canonical paths or test fixtures whose stem differs from
    # any schema filename.
    # Parse failures return None / continue rather than raising: check-jsonschema
    # runs as an upstream pre-commit hook and surfaces YAML/JSON errors there;
    # this linter only reports prose-grammar diagnostics on parseable inputs.
    try:
        with open(yaml_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return None
        yaml_top_keys = set(data.keys())
    except Exception:
        return None

    for schema_file in sorted(schema_dir.glob("*.schema.json")):
        try:
            with open(schema_file, "r", encoding="utf-8") as fh:
                schema = json.load(fh)
        except Exception:
            continue
        schema_props = set(schema.get("properties", {}).keys())
        if yaml_top_keys & schema_props:
            return schema_file

    return None


def _collect_entries(data: dict, schema: dict) -> Iterator[tuple[str, dict]]:
    """Yield (array_key, entry) pairs for every entity entry in the YAML.

    Looks for top-level keys in the YAML that correspond to array-typed
    properties in the schema, then yields each element of those arrays together
    with the array key name.

    Args:
        data:   Parsed YAML dict.
        schema: Parsed JSON schema dict.

    Yields:
        (array_key, entry_dict) pairs.
    """
    schema_array_keys = {
        k for k, v in schema.get("properties", {}).items() if isinstance(v, dict) and v.get("type") == "array"
    }
    for key in schema_array_keys:
        entries = data.get(key)
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    yield key, entry


def _iter_prose_strings(field_value: object) -> Iterator[tuple[int, int | None, str]]:
    """Yield ``(index, nested_index, raw_text)`` tuples for every prose string.

    Handles four shape cases admitted by the ``utils/text`` schema:

    - **Bare string** -- yields ``(0, None, value)``.
    - **Flat array of strings** -- yields ``(idx, None, value)`` per element.
    - **Pure nested array** -- every outer item is a list of strings; yields
      ``(outer_idx, inner_idx, value)`` per inner string.
    - **Mixed** -- outer strings yield ``(idx, None, value)`` and inner-list
      strings yield ``(outer_idx, inner_idx, value)`` interleaved by source order.

    Schema-illegal items (non-string outer scalars, non-string inner items)
    are silently skipped; doubly-nested lists yield their depth-1 strings and
    drop the deeper levels rather than discarding the whole field. The linter
    is not the place to enforce schema shape since check-jsonschema already
    runs upstream.

    Args:
        field_value: The decoded YAML value of a prose field.

    Yields:
        ``(index, nested_index, raw_text)`` tuples ready for ProseField construction.
    """
    if isinstance(field_value, str):
        # Bare string: a permissive fallback for callers that may receive
        # non-array prose values (real schemas use array form, but keep this
        # path so test-only or legacy data does not trigger an empty yield).
        yield 0, None, field_value
        return
    if not isinstance(field_value, list):
        return
    for outer_idx, item in enumerate(field_value):
        if isinstance(item, str):
            yield outer_idx, None, item
        elif isinstance(item, list):
            # Nested level -- schema permits exactly one nesting level, so we
            # only iterate inner strings here and do not recurse further.
            for inner_idx, inner in enumerate(item):
                if isinstance(inner, str):
                    yield outer_idx, inner_idx, inner


def find_prose_fields(yaml_path: Path, schema_dir: Path) -> Iterator[ProseField]:
    """Yield ProseField objects for every prose string in a YAML file.

    Schema introspection drives field discovery: only properties marked with
    ``$ref: riskmap.schema.json#/definitions/utils/text`` are treated as prose
    fields. The YAML file is matched to a schema by stem name first, then by
    top-level array-key overlap.

    Two iteration paths are walked in sequence:

    - **Entity-array entries** -- prose fields declared under the schema's
      ``definitions[*].properties`` are read from each entity entry; the
      entry's ``id`` field becomes ``ProseField.entry_id``.
    - **File-level wrapper fields** -- prose fields declared directly under
      the schema's top-level ``properties`` are read from the YAML root; the
      synthetic ``entry_id`` is the YAML file stem.

    Each prose field value may be a flat array of strings, a one-level nested
    array, a mixed sequence of strings and inner lists, or a bare string.
    Inner-list strings carry ``nested_index = inner_idx`` while outer strings
    keep ``nested_index = None``.

    Args:
        yaml_path:  Path to the YAML file to lint.
        schema_dir: Directory containing JSON schema files.

    Yields:
        ProseField for each prose string found.
    """
    schema_path = _infer_schema_name(yaml_path, schema_dir)
    if schema_path is None:
        return

    try:
        with open(schema_path, "r", encoding="utf-8") as fh:
            schema = json.load(fh)
    except Exception:
        return

    entity_field_names = _find_prose_field_names_in_schema(schema)
    wrapper_field_names = _find_wrapper_prose_field_names_in_schema(schema)
    if not entity_field_names and not wrapper_field_names:
        return

    try:
        with open(yaml_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception:
        return

    if not isinstance(data, dict):
        return

    # Entity-array path: walk every (array_key, entry) and emit ProseFields
    # for each declared entity-scope prose field.
    for _array_key, entry in _collect_entries(data, schema):
        entry_id = entry.get("id", "<unknown>")
        for field_name in entity_field_names:
            field_value = _resolve_dotted(entry, field_name)
            if field_value is None:
                continue
            for idx, nested_idx, raw in _iter_prose_strings(field_value):
                yield ProseField(
                    file_path=yaml_path,
                    entry_id=entry_id,
                    field_name=field_name,
                    index=idx,
                    raw_text=raw,
                    tokens=tokenize(raw),
                    nested_index=nested_idx,
                )

    # File-level wrapper path: prose fields declared at the schema root with
    # a direct ``$ref`` to ``utils/text``.  The synthetic entry_id is the
    # YAML file stem so wrapper diagnostics carry a stable, file-scoped id.
    if wrapper_field_names:
        wrapper_entry_id = yaml_path.stem
        for field_name in wrapper_field_names:
            field_value = data.get(field_name)
            if field_value is None:
                continue
            for idx, nested_idx, raw in _iter_prose_strings(field_value):
                yield ProseField(
                    file_path=yaml_path,
                    entry_id=wrapper_entry_id,
                    field_name=field_name,
                    index=idx,
                    raw_text=raw,
                    tokens=tokenize(raw),
                    nested_index=nested_idx,
                )


def _resolve_dotted(entry: dict, field_name: str) -> object:
    """Resolve a dotted field path against an entry dict.

    Walks dot-separated segments (e.g. ``"tourContent.introduced"``) returning
    None as soon as a non-dict is encountered or a key is missing.

    Args:
        entry:      The entry dict to walk.
        field_name: Dotted-path field name from schema introspection.

    Returns:
        The resolved value (which may itself be None), or None when any
        intermediate segment is missing.
    """
    field_value: object = entry
    for segment in field_name.split("."):
        if not isinstance(field_value, dict):
            return None
        field_value = field_value.get(segment)
    return field_value
