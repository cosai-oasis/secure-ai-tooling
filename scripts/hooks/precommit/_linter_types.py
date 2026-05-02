"""
Shared types for the ADR-017/ADR-016 prose wrapper linters.

Both validate_yaml_prose_subset and validate_prose_references import from here
to ensure the NamedTuple shapes are identical across the two linters.
"""

import sys
from pathlib import Path
from typing import NamedTuple

# Ensure the scripts/hooks directory is on sys.path so ``precommit.*`` imports
# work when this file is executed or imported directly without the package on path.
_HOOKS_DIR = Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

from precommit._prose_tokens import Token  # noqa: E402


class ProseField(NamedTuple):
    """A single prose field value extracted from a YAML entry.

    Attributes:
        file_path:    Path to the source YAML file.
        entry_id:     Value of the entry's 'id' field.
        field_name:   Schema property name (e.g. 'shortDescription').
        index:        Position of this string within its containing array (0-based),
                      or None if the field value is a bare scalar (not currently used
                      by the real schemas, but kept for forward-compatibility).
        raw_text:     The decoded string value as returned by PyYAML.
        tokens:       Token stream produced by tokenize(raw_text).
        nested_index: When the prose field shape uses one level of nesting
                      (``items: oneOf [string, array<string>]``) and this record
                      came from an inner-list string, this is the inner index
                      within that list; ``index`` then holds the outer index.
                      ``None`` for flat-array entries and bare-scalar entries.
    """

    file_path: Path
    entry_id: str
    field_name: str
    index: int | None
    raw_text: str
    tokens: list[Token]
    nested_index: int | None = None


class Diagnostic(NamedTuple):
    """A single lint finding from a prose wrapper linter.

    Attributes:
        hook_id:    Pre-commit hook identifier (e.g. 'validate-yaml-prose-subset').
        file_path:  Path to the YAML file that contains the violation.
        entry_id:   ID of the YAML entry where the violation was found.
        field_name: Schema property name of the violating prose field.
        index:      Paragraph index within the array (0-based); None only if
                    field is a bare scalar.
        reason:     Human-readable description of the violation.
    """

    hook_id: str
    file_path: Path
    entry_id: str
    field_name: str
    index: int | None
    reason: str


class IdIndex(NamedTuple):
    """Index of all known entity IDs and per-entry externalReferences IDs.

    Built by validate_prose_references.build_id_index() from the YAML corpus.
    All entity sets are frozensets (immutable after construction). The ext_refs
    dict maps each entry's ID to the frozenset of its externalReferences[].id
    values (per-entry scope per ADR-016 D2).

    Attributes:
        risks:       All known risk IDs.
        controls:    All known control IDs.
        components:  All known component IDs.
        personas:    All known persona IDs.
        ext_refs:    entry_id → frozenset of externalReferences[].id values.
    """

    risks: frozenset[str]
    controls: frozenset[str]
    components: frozenset[str]
    personas: frozenset[str]
    # `ext_refs` is a mutable dict by type but treated as read-only after `build_id_index()` returns.
    # Not wrapped in MappingProxyType to keep the type signature simple; if this becomes a bug
    # source, wrap at the build_id_index return boundary.
    ext_refs: dict[str, frozenset[str]]
