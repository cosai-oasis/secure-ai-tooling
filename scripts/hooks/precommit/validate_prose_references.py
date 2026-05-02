#!/usr/bin/env python3
"""
Pre-commit lint: ADR-016 D6 reference-resolution rules for risk-map YAML prose.

Resolves every sentinel and bare-camelCase identifier found in prose fields
against a corpus-wide ID index, and rejects inline URLs and raw HTML that
belong to the references-linter's domain per the ADR-017 D4 delegation table.

Ships warn-only (exit 0 with stderr output).  Pass --block to fail on violations.

Exit codes:
    0 — warn-only mode (always), or block mode with no violations
    1 — block mode with at least one violation
    2 — usage error or unreadable file
"""

import argparse
import glob
import sys
from pathlib import Path
from typing import NoReturn

import yaml

# Ensure the scripts/hooks directory is on sys.path so ``precommit.*`` imports
# work both when this file is executed directly and when imported as a package.
_HOOKS_DIR = Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

from precommit._linter_types import Diagnostic, IdIndex, ProseField  # noqa: E402
from precommit._prose_fields import find_prose_fields  # noqa: E402
from precommit._prose_tokens import TokenKind  # noqa: E402

# Re-export so callers can import ProseField, Diagnostic, IdIndex from this module.
__all__ = [
    "ProseField",
    "Diagnostic",
    "IdIndex",
    "find_prose_fields",
    "build_id_index",
    "check_references",
    "main",
]

# Hook identifier used as the prefix in every diagnostic line.
_HOOK_ID = "validate-prose-references"

# Default schema directory relative to the repository root.
_DEFAULT_SCHEMA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "risk-map" / "schemas"

# Default glob for id-sources (all YAML files in the risk-map/yaml/ directory).
_DEFAULT_ID_SOURCES_GLOB = str(
    Path(__file__).resolve().parent.parent.parent.parent / "risk-map" / "yaml" / "*.yaml"
)

# Maps entity-id prefix to the corresponding IdIndex field name.
_PREFIX_TO_FIELD: dict[str, str] = {
    "risk": "risks",
    "control": "controls",
    "component": "components",
    "persona": "personas",
}


def build_id_index(yaml_paths: list[Path]) -> IdIndex:
    """Build an IdIndex from a list of YAML files.

    Walks each YAML file, collects every ``id`` value from top-level array
    entries into the appropriate entity set (risks/controls/components/personas),
    and records each entry's ``externalReferences[].id`` values in ext_refs
    keyed by that entry's own ID.

    The entity-set membership is determined by the first camelCase prefix of
    the ID value (``risk*`` → risks, ``control*`` → controls, etc.). Entries
    whose ID does not match any known prefix are silently skipped for the
    entity sets but still processed for ext_refs.

    Args:
        yaml_paths: List of YAML file paths to index.

    Returns:
        IdIndex with frozenset entity sets and per-entry ext_refs mapping.
    """
    risks: set[str] = set()
    controls: set[str] = set()
    components: set[str] = set()
    personas: set[str] = set()
    ext_refs: dict[str, frozenset[str]] = {}

    for yaml_path in yaml_paths:
        try:
            with open(yaml_path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except Exception:
            continue

        if not isinstance(data, dict):
            continue

        # Walk every top-level list value looking for entry dicts with an 'id'.
        for key, value in data.items():
            if not isinstance(value, list):
                continue
            for entry in value:
                if not isinstance(entry, dict):
                    continue
                entry_id = entry.get("id")
                if not isinstance(entry_id, str) or not entry_id:
                    continue

                # Classify by ID prefix into the appropriate entity set.
                if entry_id.startswith("risk"):
                    risks.add(entry_id)
                elif entry_id.startswith("control"):
                    controls.add(entry_id)
                elif entry_id.startswith("component"):
                    components.add(entry_id)
                elif entry_id.startswith("persona"):
                    personas.add(entry_id)

                # Collect externalReferences IDs for this entry.
                raw_ext = entry.get("externalReferences")
                if isinstance(raw_ext, list):
                    ref_ids: set[str] = set()
                    for ref in raw_ext:
                        if isinstance(ref, dict):
                            ref_id = ref.get("id")
                            if isinstance(ref_id, str) and ref_id:
                                ref_ids.add(ref_id)
                    ext_refs[entry_id] = frozenset(ref_ids)

    return IdIndex(
        risks=frozenset(risks),
        controls=frozenset(controls),
        components=frozenset(components),
        personas=frozenset(personas),
        ext_refs=ext_refs,
    )


def _resolve_intra_sentinel(inner: str, id_index: IdIndex) -> tuple[str, frozenset[str]] | None:
    """Return (entity_label, id_set) for an intra-doc sentinel inner value.

    Parses the prefix from the inner content (e.g. ``riskFoo`` → prefix ``risk``).

    Args:
        inner:    Inner content of the sentinel (without braces).
        id_index: The ID index to look up.

    Returns:
        (entity_label, id_set) tuple, or None if the prefix is unrecognised.
    """
    for prefix, field_name in _PREFIX_TO_FIELD.items():
        if inner.startswith(prefix):
            return field_name, getattr(id_index, field_name)
    return None


def check_references(field: ProseField, id_index: IdIndex) -> list[Diagnostic]:
    """Check one ProseField against the ADR-016 D6 reference-resolution rules.

    For each token in the field's token stream:
    - SENTINEL_INTRA: resolve the inner ID against the matching entity set;
      emit diagnostic if not found.
    - SENTINEL_REF: resolve the inner identifier against the entry's own
      externalReferences IDs (per-entry scope per ADR-016 D2); emit if absent.
    - INVALID_CAMELCASE_ID: always emit (bare entity-prefix camelCase must be
      wrapped in a sentinel per ADR-016 D6 rule 5 / ADR-017 D4 rule 5 delegation).
    - INVALID_URL: emit with a message guiding toward externalReferences.
    - INVALID_HTML: emit with an HTML-tag rejection message.

    All other token kinds are silently ignored.

    Args:
        field:    A ProseField with tokens already populated.
        id_index: The corpus-wide ID index.

    Returns:
        List of Diagnostic objects (empty if the field is clean).
    """
    diagnostics: list[Diagnostic] = []

    def _diag(reason: str) -> Diagnostic:
        return Diagnostic(
            hook_id=_HOOK_ID,
            file_path=field.file_path,
            entry_id=field.entry_id,
            field_name=field.field_name,
            index=field.index,
            reason=reason,
        )

    for token in field.tokens:
        if token.kind == TokenKind.SENTINEL_INTRA:
            # Strip the {{ and }} to get the inner identifier.
            inner = token.value[2:-2]
            result = _resolve_intra_sentinel(inner, id_index)
            if result is None:
                # Unrecognised prefix — the tokenizer accepted it as SENTINEL_INTRA
                # only when the prefix matched; this branch should be unreachable,
                # but guard defensively.
                diagnostics.append(_diag(f"intra-doc sentinel '{inner}' has unrecognised entity prefix"))
            else:
                entity_label, id_set = result
                if inner not in id_set:
                    diagnostics.append(
                        _diag(
                            f"intra-doc identifier '{inner}' does not resolve to an existing {entity_label[:-1]}"
                        )
                    )

        elif token.kind == TokenKind.SENTINEL_REF:
            # Inner is "ref:<identifier>"; extract just the identifier part.
            inner = token.value[2:-2]  # strip {{ and }}
            ref_id = inner[len("ref:") :]  # strip the "ref:" prefix
            entry_ext_refs = id_index.ext_refs.get(field.entry_id, frozenset())
            if ref_id not in entry_ext_refs:
                diagnostics.append(
                    _diag(f"external-reference identifier '{ref_id}' not in this entry's externalReferences")
                )

        elif token.kind == TokenKind.INVALID_CAMELCASE_ID:
            # Value already named in the reason; no separate snippet suffix needed.
            diagnostics.append(
                _diag(f"bare camelCase identifier must be wrapped in {{{{...}}}} sentinel at {token.value!r}")
            )

        elif token.kind == TokenKind.INVALID_URL:
            # ADR-017 D4: append the offending token value as a snippet.
            base = "inline URL not permitted; use externalReferences + {{ref:...}} sentinel"
            reason = f"{base} at {token.value!r}" if token.value else base
            diagnostics.append(_diag(reason))

        elif token.kind == TokenKind.INVALID_HTML:
            # ADR-017 D4: append the offending token value as a snippet.
            base = "raw HTML tag not permitted in prose"
            reason = f"{base} at {token.value!r}" if token.value else base
            diagnostics.append(_diag(reason))

    return diagnostics


def _emit_diagnostic(diag: Diagnostic) -> None:
    """Print a single Diagnostic to stderr in the committed format.

    Format: ``<hook_id>: <file>:<entry_id>:<field>[<index>]: <reason>``

    Args:
        diag: The Diagnostic to emit.
    """
    idx_str = f"[{diag.index}]" if diag.index is not None else "[0]"
    line = f"{diag.hook_id}: {diag.file_path}:{diag.entry_id}:{diag.field_name}{idx_str}: {diag.reason}"
    print(line, file=sys.stderr)


def main(argv: list[str] | None = None) -> NoReturn:
    """CLI entry point for validate_prose_references.

    Accepts zero or more YAML file paths as positional arguments. Builds an ID
    index from --id-sources (defaulting to all risk-map/yaml/*.yaml files), then
    checks every prose field in each supplied YAML file.

    With no files, exits 0 immediately. With --block, exits 1 on any violation
    and 2 on IO/usage errors; without --block, always exits 0.

    Args:
        argv: Argument list. Defaults to sys.argv[1:] when None.
    """
    parser = argparse.ArgumentParser(
        description="Lint ADR-016 D6 reference-resolution rules in risk-map YAML prose.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s risk-map/yaml/risks.yaml\n"
            "  %(prog)s risk-map/yaml/risks.yaml --schema-dir risk-map/schemas\n"
            "  %(prog)s risk-map/yaml/risks.yaml --id-sources risk-map/yaml/risks.yaml"
            " risk-map/yaml/controls.yaml\n"
            "  %(prog)s risk-map/yaml/risks.yaml --block\n"
        ),
    )
    parser.add_argument("files", nargs="*", help="YAML file(s) to lint (pre-commit passes these).")
    parser.add_argument(
        "--schema-dir",
        default=str(_DEFAULT_SCHEMA_DIR),
        help="Directory containing JSON schema files (default: risk-map/schemas/ from repo root).",
    )
    parser.add_argument(
        "--id-sources",
        nargs="+",
        default=None,
        help=(
            "YAML file(s) to build the ID index from. "
            "Defaults to all risk-map/yaml/*.yaml files relative to repo root."
        ),
    )
    parser.add_argument(
        "--block",
        action="store_true",
        default=False,
        help="Exit 1 on any violation instead of warn-only (exit 0).",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if not args.files:
        sys.exit(0)

    schema_dir = Path(args.schema_dir)

    # Resolve id-sources: use supplied list or expand default glob.
    if args.id_sources is not None:
        id_source_paths = [Path(p) for p in args.id_sources]
    else:
        id_source_paths = [Path(p) for p in sorted(glob.glob(_DEFAULT_ID_SOURCES_GLOB))]

    id_index = build_id_index(id_source_paths)

    all_diagnostics: list[Diagnostic] = []

    for file_arg in args.files:
        yaml_path = Path(file_arg)
        if not yaml_path.is_file():
            print(
                f"{_HOOK_ID}: error: file not found or not readable: {file_arg}",
                file=sys.stderr,
            )
            # A missing file is always an IO/usage error regardless of --block mode.
            sys.exit(2)

        for field in find_prose_fields(yaml_path, schema_dir):
            all_diagnostics.extend(check_references(field, id_index))

    for diag in all_diagnostics:
        _emit_diagnostic(diag)

    if args.block and all_diagnostics:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1:])
