#!/usr/bin/env python3
"""
CLI for authoring, updating, and removing framework mapping values.

Implements ADR-027 D4 / D4a: generate-not-author for pinned mapping values.
Contributors supply a structured selection; tooling emits the pinned value and
writes the YAML.

Subcommands:
    add     Compose and append a pinned mapping value to an entity.
    remove  Remove a mapping value addressed by its derivable mappingId (D4b).
    update  Re-pin an existing mapping to a new version (re-pin interpretation).
    migrate Migrate all legacy mapping values in content files to pinned form (#343).

Usage:
    framework_mapping_maintainer.py [add|update|remove]
        --cosai-id <entity-id>
        --framework <framework-id>
        --version <version-string>
        --framework-specific-ref <ref>
        [--content-file <path>]
        [--frameworks-file <path>]
        [--schema-file <path>]

Exit codes: 0 on success, non-zero on any validation or entity-lookup failure.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# sys.path bootstrap — mirror build_persona_site_data.py pattern.
# Allows this script to be invoked directly as well as via module.
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from io import StringIO  # noqa: E402

from ruamel.yaml import YAML, CommentedMap, CommentedSeq  # noqa: E402
from ruamel.yaml.error import CommentMark  # noqa: E402
from ruamel.yaml.tokens import CommentToken  # noqa: E402

from scripts.hooks.precommit.framework_mapping import (  # noqa: E402
    DEFAULT_FRAMEWORKS_PATH,
    DEFAULT_SCHEMA_PATH,
    FrameworkMappingError,
    compose_pinned_value,
    derive_mapping_id,
    load_pinned_patterns,
    load_registry,
    migrate_legacy_value,
    split_pinned_value,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Map from cosai-id prefix to the YAML wrapper key and file name.
_PREFIX_TO_WRAPPER: dict[str, tuple[str, str]] = {
    "risk": ("risks", "risks.yaml"),
    "control": ("controls", "controls.yaml"),
    "component": ("components", "components.yaml"),
    "persona": ("personas", "personas.yaml"),
}

_CONTENT_DIR = REPO_ROOT / "risk-map" / "yaml"


# ---------------------------------------------------------------------------
# YAML utilities
# ---------------------------------------------------------------------------


def _make_yaml() -> YAML:
    """Return a ruamel YAML instance configured for round-trip fidelity."""
    y = YAML()
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def _dump_to_str(y: YAML, data: Any) -> str:
    """Serialize data to a YAML string using the given ruamel instance."""
    buf = StringIO()
    y.dump(data, buf)
    return buf.getvalue()


def _last_value_is_block(value: Any) -> bool:
    """
    Recursively check if the deepest last value in a nested structure is
    a block-style CommentedSeq or CommentedMap.

    ruamel emits blank lines between sequence items via lc data (not ca items)
    when the preceding item's last nested value is a block-style structure.
    This function identifies that case so we don't double-inject a blank line.
    """
    if isinstance(value, CommentedMap) and value:
        last_nested = value[list(value.keys())[-1]]
        return _last_value_is_block(last_nested)
    if isinstance(value, CommentedSeq):
        try:
            if value.fa.flow_style() is False:
                return True  # block-style sequence
        except AttributeError:
            pass
    return False


def _item_ends_with_block(item: Any) -> bool:
    """Return True if item's last value chain ends with a block structure."""
    if not isinstance(item, CommentedMap) or not item:
        return False
    return _last_value_is_block(item[list(item.keys())[-1]])


def _restore_blank_lines(seq: Any, source_text: str) -> None:
    """
    After mutations, inject missing blank-line CommentTokens into seq.ca.items.

    ruamel fails to re-capture blank lines between sequence items when the
    preceding item ends with a nested block sequence (it uses lc data instead).
    After deletion of such a nested structure, the lc data no longer reflects
    the blank, so the blank would be lost on dump.

    We inject a CommentToken for each blank line that:
      1. Exists in source_text just before an item (detected via item.lc.line)
      2. Is not already in seq.ca.items
      3. The preceding item (post-mutation) does NOT end with a block structure
         (which would mean ruamel still handles it via lc — and injecting
         would produce a double blank line)

    Scope / known limitations (the live corpus is LF-only, single-blank-separated,
    so these are out of scope for #347; #343 runs this tool against that corpus):
      - LF only. source_text is read as UTF-8 text; a CRLF file would have its
        line endings normalized on rewrite. The live consumer YAML is LF-only.
      - One blank line per gap. At most one CommentToken is injected per
        inter-item gap, matching the single-blank-line convention in
        risks.yaml / controls.yaml. A double-blank separator would collapse to one.
    """
    lines = source_text.splitlines()
    for idx in range(1, len(seq)):
        item = seq[idx]
        if not hasattr(item, "lc"):
            continue
        item_line = item.lc.line  # 0-indexed line where this item starts
        has_blank = item_line > 0 and lines[item_line - 1].strip() == ""
        if not has_blank:
            continue
        if idx in seq.ca.items:
            continue  # already captured; don't double-inject
        prev_item = seq[idx - 1]
        if _item_ends_with_block(prev_item):
            # ruamel will emit this blank via lc data — leave it alone
            continue
        ct = CommentToken("\n", CommentMark(0), None)
        seq.ca.items[idx] = [None, [ct], None, None]


# ---------------------------------------------------------------------------
# Content file resolution
# ---------------------------------------------------------------------------


def _resolve_content_file(cosai_id: str, explicit: Path | None) -> Path:
    """
    Return the content file path for a cosai-id.

    If explicit is given, return it directly. Otherwise infer from the
    cosai-id prefix (risk* → risks.yaml, control* → controls.yaml, etc.).

    Raises:
        SystemExit: If the prefix is not recognized.
    """
    if explicit is not None:
        return explicit

    lower_id = cosai_id.lower()
    for prefix, (_, filename) in _PREFIX_TO_WRAPPER.items():
        if lower_id.startswith(prefix):
            return _CONTENT_DIR / filename

    _die(
        f"Cannot infer content file from cosai-id {cosai_id!r}. "
        f"Use --content-file to specify the file explicitly. "
        f"Recognized prefixes: {sorted(_PREFIX_TO_WRAPPER.keys())}"
    )


def _resolve_wrapper_key(cosai_id: str, data: Any) -> str:
    """
    Infer the top-level wrapper key (e.g. 'controls', 'risks') from cosai-id.

    Falls back to checking which key's list contains the entity if inference
    fails or is ambiguous.

    Raises:
        SystemExit: If no wrapper key is found.
    """
    lower_id = cosai_id.lower()
    for prefix, (wrapper_key, _) in _PREFIX_TO_WRAPPER.items():
        if lower_id.startswith(prefix) and wrapper_key in data:
            return wrapper_key

    # Fallback: scan all known wrapper keys
    for wrapper_key in ("risks", "controls", "components", "personas"):
        if wrapper_key in data:
            return wrapper_key

    _die(f"Cannot determine wrapper key for cosai-id {cosai_id!r} in the content file.")


# ---------------------------------------------------------------------------
# Entity lookup
# ---------------------------------------------------------------------------


def _find_entity(wrapper_list: list, cosai_id: str) -> Any:
    """
    Return the entity dict whose 'id' field matches cosai_id.

    Returns None if not found.
    """
    for entity in wrapper_list:
        if isinstance(entity, dict) and entity.get("id") == cosai_id:
            return entity
    return None


# ---------------------------------------------------------------------------
# Error helper
# ---------------------------------------------------------------------------


def _die(message: str) -> None:
    """Print message to stderr and exit non-zero."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# subcommand: add
# ---------------------------------------------------------------------------


def _cmd_add(args: argparse.Namespace) -> None:
    """
    Compose a pinned value and append it to the entity's mappings block.

    - Creates the `mappings` key if absent.
    - Creates the framework list if absent.
    - If the value is already present → idempotent no-op (file not rewritten).

    ADR-027 D4 / D4a.
    """
    registry = load_registry(args.frameworks_file)
    pinned_patterns = load_pinned_patterns(args.schema_file)

    try:
        pinned = compose_pinned_value(
            args.framework,
            args.version,
            args.framework_specific_ref,
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
    except FrameworkMappingError as exc:
        _die(str(exc))

    content_file = _resolve_content_file(args.cosai_id, args.content_file)
    raw_text = content_file.read_text(encoding="utf-8")
    y = _make_yaml()
    data = y.load(raw_text)

    wrapper_key = _resolve_wrapper_key(args.cosai_id, data)
    wrapper_list = data[wrapper_key]
    entity = _find_entity(wrapper_list, args.cosai_id)
    if entity is None:
        _die(f"Entity {args.cosai_id!r} not found in {wrapper_key!r} list in {content_file}.")

    # Check idempotency BEFORE any mutation.
    existing_vals = (entity.get("mappings") or {}).get(args.framework, [])
    if pinned in existing_vals:
        # Byte-level no-op: value already present, no rewrite (D4a idempotency).
        return

    # Create mappings block if absent.
    if "mappings" not in entity:
        entity["mappings"] = CommentedMap()

    # Create framework list if absent.
    if args.framework not in entity["mappings"]:
        entity["mappings"][args.framework] = CommentedSeq()

    entity["mappings"][args.framework].append(pinned)

    _restore_blank_lines(wrapper_list, raw_text)
    content_file.write_text(_dump_to_str(y, data), encoding="utf-8")


# ---------------------------------------------------------------------------
# subcommand: remove
# ---------------------------------------------------------------------------


def _cmd_remove(args: argparse.Namespace) -> None:
    """
    Remove a mapping entry addressed by its derived mappingId (D4b).

    Computes the target pinned value and its mappingId, then scans the
    framework list to find and remove the matching entry. Cleans up empty
    framework lists and empty mappings blocks afterwards.

    ADR-027 D4 / D4a / D4b.
    """
    registry = load_registry(args.frameworks_file)
    pinned_patterns = load_pinned_patterns(args.schema_file)

    try:
        target_pinned = compose_pinned_value(
            args.framework,
            args.version,
            args.framework_specific_ref,
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
    except FrameworkMappingError as exc:
        _die(str(exc))

    target_id = derive_mapping_id(args.cosai_id, args.framework, target_pinned)

    content_file = _resolve_content_file(args.cosai_id, args.content_file)
    raw_text = content_file.read_text(encoding="utf-8")
    y = _make_yaml()
    data = y.load(raw_text)

    wrapper_key = _resolve_wrapper_key(args.cosai_id, data)
    wrapper_list = data[wrapper_key]
    entity = _find_entity(wrapper_list, args.cosai_id)
    if entity is None:
        _die(f"Entity {args.cosai_id!r} not found in {wrapper_key!r} list in {content_file}.")

    fw_list = (entity.get("mappings") or {}).get(args.framework)
    if not fw_list:
        _die(f"No {args.framework!r} mappings found for entity {args.cosai_id!r}. Nothing to remove.")

    # Find the entry whose mappingId matches (D4b positional addressing).
    match_idx = None
    for i, val in enumerate(fw_list):
        if derive_mapping_id(args.cosai_id, args.framework, val) == target_id:
            match_idx = i
            break

    if match_idx is None:
        _die(
            f"Mapping {target_pinned!r} not found for entity {args.cosai_id!r} "
            f"under framework {args.framework!r}. Nothing to remove."
        )

    fw_list.pop(match_idx)

    # Cleanup: empty list → remove framework key; empty mappings → remove mappings key.
    if len(fw_list) == 0:
        del entity["mappings"][args.framework]
    if "mappings" in entity and len(entity["mappings"]) == 0:
        del entity["mappings"]

    _restore_blank_lines(wrapper_list, raw_text)
    content_file.write_text(_dump_to_str(y, data), encoding="utf-8")


# ---------------------------------------------------------------------------
# subcommand: update
# ---------------------------------------------------------------------------


def _cmd_update(args: argparse.Namespace) -> None:
    """
    Re-pin a mapping in place: find by base-ref, replace with new version token.

    Interpretation: locate the existing entry whose base-ref (via split_pinned_value)
    matches --framework-specific-ref and replace it with a new pinned value composed
    from --version.

    Error paths:
      - Zero matches → non-zero + "nothing to update" diagnostic.
      - Multiple matches (same base-ref, different version tokens) → "ambiguous".

    ADR-027 D4 / D4a (re-pin interpretation; see test notes for spec ambiguity).
    """
    registry = load_registry(args.frameworks_file)
    pinned_patterns = load_pinned_patterns(args.schema_file)

    # Compose the new pinned value first to validate inputs early.
    try:
        new_pinned = compose_pinned_value(
            args.framework,
            args.version,
            args.framework_specific_ref,
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
    except FrameworkMappingError as exc:
        _die(str(exc))

    content_file = _resolve_content_file(args.cosai_id, args.content_file)
    raw_text = content_file.read_text(encoding="utf-8")
    y = _make_yaml()
    data = y.load(raw_text)

    wrapper_key = _resolve_wrapper_key(args.cosai_id, data)
    wrapper_list = data[wrapper_key]
    entity = _find_entity(wrapper_list, args.cosai_id)
    if entity is None:
        _die(f"Entity {args.cosai_id!r} not found in {wrapper_key!r} list in {content_file}.")

    fw_list = (entity.get("mappings") or {}).get(args.framework, [])

    # Find all entries whose base-ref matches --framework-specific-ref.
    matches: list[int] = []
    for i, val in enumerate(fw_list):
        try:
            base_ref, _ = split_pinned_value(
                args.framework,
                val,
                registry=registry,
                pinned_patterns=pinned_patterns,
            )
        except FrameworkMappingError:
            # A value that does not parse as a pinned mapping for this framework
            # (e.g. a still-legacy un-pinned value) simply cannot match the
            # requested base-ref. Skip it. Unexpected (non-FrameworkMappingError)
            # exceptions are programming errors and must propagate, not be hidden
            # as a spurious "nothing to update".
            continue
        if base_ref == args.framework_specific_ref:
            matches.append(i)

    if not matches:
        _die(
            f"No existing {args.framework!r} mapping with base-ref "
            f"{args.framework_specific_ref!r} found for entity "
            f"{args.cosai_id!r}. Nothing to update."
        )

    if len(matches) > 1:
        conflicting = [fw_list[i] for i in matches]
        _die(
            f"Ambiguous update: multiple {args.framework!r} entries share "
            f"base-ref {args.framework_specific_ref!r} for entity "
            f"{args.cosai_id!r}: {conflicting!r}. "
            "Use remove + add to disambiguate."
        )

    # Replace in place (same list position).
    fw_list[matches[0]] = new_pinned

    _restore_blank_lines(wrapper_list, raw_text)
    content_file.write_text(_dump_to_str(y, data), encoding="utf-8")


# ---------------------------------------------------------------------------
# subcommand: migrate
# ---------------------------------------------------------------------------

# Known wrapper keys in the consumer YAML files, in the order we check.
_WRAPPER_KEYS = ("risks", "controls", "components", "personas")

# Default content files for migrate when --content-file is not specified.
_DEFAULT_CONTENT_FILES = [
    _CONTENT_DIR / "risks.yaml",
    _CONTENT_DIR / "controls.yaml",
    _CONTENT_DIR / "components.yaml",
    _CONTENT_DIR / "personas.yaml",
]


def _collect_wrapper_list(data: Any) -> list:
    """
    Return the first recognized entity list found in data, or an empty list.

    Tries each wrapper key in order; the first match wins.
    """
    for wk in _WRAPPER_KEYS:
        if wk in data and isinstance(data[wk], list):
            return data[wk]
    return []


def _cmd_migrate(args: argparse.Namespace) -> None:
    """
    Migrate all legacy mapping values in content files to their pinned form.

    Two modes:
      --report-legacy: read-only audit; prints per-framework inventory and
                       total block/value counts; exits 0 without writing.
      default / --dry-run: two-pass to guarantee no partial writes on error.
        Pass 1 (compute): walk all files, call migrate_legacy_value for each
                          value. On any FrameworkMappingError, _die() immediately
                          with a diagnostic — before writing any file.
        Pass 2 (write):   only reached if pass 1 succeeds. --dry-run prints a
                          per-file summary without writing; otherwise writes
                          changed files and skips byte-identical ones.

    ADR-027 D4 / #343 Decision 2.
    """
    content_files: list[Path] = args.content_file if args.content_file else _DEFAULT_CONTENT_FILES
    registry = load_registry(args.frameworks_file)
    pinned_patterns = load_pinned_patterns(args.schema_file)

    # --report-legacy: read-only audit mode.
    if args.report_legacy:
        _run_report_legacy(content_files, registry, pinned_patterns)
        return

    # Two-pass migrate: pass 1 computes all mutations, pass 2 writes.
    _run_migrate(content_files, registry, pinned_patterns, dry_run=args.dry_run)


def _run_report_legacy(
    content_files: list[Path],
    registry: dict,
    pinned_patterns: dict,
) -> None:
    """
    Print a per-file, per-framework inventory of legacy vs pinned values.

    Counts framework-sub-blocks (one per entity×framework list present) and
    total values across all files. Unmappable legacy values are tallied under
    'legacy' without raising — report mode is a read-only audit.

    The output always includes a final 'TOTAL: <N> blocks / <M> values' line
    so tests can assert the aggregate numbers.
    """
    total_blocks = 0
    total_values = 0

    for fpath in content_files:
        raw_text = fpath.read_text(encoding="utf-8")
        y = _make_yaml()
        data = y.load(raw_text)
        wrapper_list = _collect_wrapper_list(data)

        # Per-file accumulators.
        file_blocks = 0
        file_values = 0
        # Per-framework counters: {fw_id: {"legacy": N, "pinned": N}}.
        fw_counts: dict[str, dict[str, int]] = {}

        for entity in wrapper_list:
            if not isinstance(entity, dict):
                continue
            mappings = entity.get("mappings") or {}
            for fw_id, fw_vals in mappings.items():
                if not isinstance(fw_vals, list) or not fw_vals:
                    continue
                file_blocks += 1
                total_blocks += 1
                if fw_id not in fw_counts:
                    fw_counts[fw_id] = {"legacy": 0, "pinned": 0}
                for val in fw_vals:
                    file_values += 1
                    total_values += 1
                    # Classify: try migrate_legacy_value in report mode —
                    # on error just count as legacy (report is read-only).
                    try:
                        _, changed = migrate_legacy_value(
                            fw_id,
                            val,
                            registry=registry,
                            pinned_patterns=pinned_patterns,
                        )
                        if changed:
                            fw_counts[fw_id]["legacy"] += 1
                        else:
                            fw_counts[fw_id]["pinned"] += 1
                    except FrameworkMappingError:
                        fw_counts[fw_id]["legacy"] += 1

        print(f"\n{fpath.name}: {file_blocks} blocks / {file_values} values")
        for fw_id, counts in sorted(fw_counts.items()):
            print(f"  {fw_id}: legacy={counts['legacy']} pinned={counts['pinned']}")

    print(f"\nTOTAL: {total_blocks} blocks / {total_values} values")


def _run_migrate(
    content_files: list[Path],
    registry: dict,
    pinned_patterns: dict,
    dry_run: bool,
) -> None:
    """
    Two-pass migrate: compute all edits (pass 1), then apply them (pass 2).

    The write path is LINE-ANCHORED, not a whole-file YAML re-emit. ruamel cannot
    losslessly round-trip the live corpus (re-emitting re-folds folded-scalar prose
    regardless of the configured width), so a full dump would inflate the diff with
    spurious prose re-wraps. Instead we use each value's (line, col) from ruamel's
    lc data to replace ONLY the value token on its own source line, copying every
    other byte verbatim — a value-only diff.

    Pass 1 loads every file read-only and records (line, col, old, new) edits per
    changed value. If any migrate_legacy_value call raises FrameworkMappingError,
    _die() is called immediately with a diagnostic — no file is written. A changed
    value with no resolvable source line (e.g. a flow-style sequence) also _die()s
    rather than being silently skipped.

    Pass 2 is only reached after a clean pass 1. In dry-run mode it prints per-file
    summaries without writing. Otherwise it rewrites files that have edits (a file
    with zero edits is left byte-identical, giving idempotency).
    """
    # Pass 1: load all files read-only, compute (line, col, old, new) edits.
    file_results: list[tuple[Path, str, list[tuple[int, int, str, str]]]] = []

    for fpath in content_files:
        raw_text = fpath.read_text(encoding="utf-8")
        y = _make_yaml()
        data = y.load(raw_text)
        wrapper_list = _collect_wrapper_list(data)
        edits: list[tuple[int, int, str, str]] = []

        for entity in wrapper_list:
            if not isinstance(entity, dict):
                continue
            entity_id = entity.get("id", "<unknown>")
            mappings = entity.get("mappings") or {}
            for fw_id, fw_vals in mappings.items():
                if not isinstance(fw_vals, list):
                    continue
                for i, val in enumerate(fw_vals):
                    try:
                        new_val, changed = migrate_legacy_value(
                            fw_id,
                            val,
                            registry=registry,
                            pinned_patterns=pinned_patterns,
                        )
                    except FrameworkMappingError as exc:
                        _die(f"{fpath.name}: entity {entity_id!r}, framework {fw_id!r}, value {val!r}: {exc}")
                    if not changed:
                        continue
                    # Resolve the value's source line via ruamel lc data. A changed
                    # value with no location is a fail-loud error, never a silent skip.
                    lc = getattr(fw_vals, "lc", None)
                    item_lc = lc.data.get(i) if lc is not None and lc.data else None
                    if item_lc is None:
                        _die(
                            f"{fpath.name}: entity {entity_id!r}, framework {fw_id!r}, value {val!r}: "
                            "cannot locate source line (flow-style sequences are not supported by migrate)"
                        )
                    edits.append((item_lc[0], item_lc[1], val, new_val))

        file_results.append((fpath, raw_text, edits))

    # Pass 2: apply edits or report.
    for fpath, raw_text, edits in file_results:
        if dry_run:
            print(f"{fpath.name}: {len(edits)} value(s) would be changed")
            continue
        if not edits:
            # Idempotent: no changed values -> leave the file byte-identical.
            continue
        # keepends preserves each line's terminator (and the final-newline state)
        # so only the value token on each edited line changes.
        lines = raw_text.splitlines(keepends=True)
        for line_idx, col, old, new in edits:
            line = lines[line_idx]
            head, tail = line[:col], line[col:]
            if old not in tail:
                _die(
                    f"{fpath.name}: line {line_idx + 1}: expected value {old!r} at column {col} "
                    f"but found {tail!r} — refusing to write a mislocated edit"
                )
            lines[line_idx] = head + tail.replace(old, new, 1)
        fpath.write_text("".join(lines), encoding="utf-8")

    if dry_run:
        total_would_change = sum(len(e) for _, _, e in file_results)
        print(f"dry-run: {total_would_change} total value(s) would be changed across {len(file_results)} file(s)")
    else:
        total_changed = sum(len(e) for _, _, e in file_results)
        changed_files = sum(1 for _, _, e in file_results if e)
        print(f"migrate: {total_changed} value(s) updated in {changed_files} file(s)")


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser with subcommands add / update / remove / migrate."""
    parser = argparse.ArgumentParser(
        prog="framework_mapping_maintainer.py",
        description=(
            "Author, update, and remove pinned framework mapping values "
            "in CoSAI Risk Map content files. ADR-027 D4 / D4a."
        ),
    )

    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--cosai-id",
        required=True,
        metavar="ID",
        help="CoSAI entity id (e.g. controlFoo, riskBar).",
    )
    parent.add_argument(
        "--framework",
        required=True,
        metavar="FW",
        help="Framework id from frameworks.yaml (e.g. mitre-atlas).",
    )
    parent.add_argument(
        "--version",
        default=None,
        metavar="VER",
        help="Framework version string (e.g. 5.0.1). Omit for unversioned frameworks.",
    )
    parent.add_argument(
        "--framework-specific-ref",
        required=True,
        metavar="REF",
        help="Spec-native canonical reference (e.g. AML.T0043, GOVERN-6.2).",
    )
    parent.add_argument(
        "--content-file",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "Path to the content YAML file. If omitted, inferred from "
            "--cosai-id prefix (risk*→risks.yaml, control*→controls.yaml, etc.)."
        ),
    )
    parent.add_argument(
        "--frameworks-file",
        type=Path,
        default=DEFAULT_FRAMEWORKS_PATH,
        metavar="FILE",
        help=f"Path to frameworks.yaml (default: {DEFAULT_FRAMEWORKS_PATH}).",
    )
    parent.add_argument(
        "--schema-file",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        metavar="FILE",
        help=f"Path to frameworks.schema.json (default: {DEFAULT_SCHEMA_PATH}).",
    )

    subs = parser.add_subparsers(dest="subcommand", required=True)

    subs.add_parser(
        "add",
        parents=[parent],
        help="Compose and append a pinned mapping value.",
    )
    subs.add_parser(
        "remove",
        parents=[parent],
        help="Remove a pinned mapping value (mappingId-addressed, D4b).",
    )
    subs.add_parser(
        "update",
        parents=[parent],
        help="Re-pin a mapping to a new version (re-pin interpretation).",
    )

    # migrate does not share the parent parser (no --cosai-id / --framework / etc.).
    migrate_p = subs.add_parser(
        "migrate",
        help="Migrate all legacy mapping values in content files to pinned form (#343).",
    )
    migrate_p.add_argument(
        "--content-file",
        type=Path,
        action="append",
        default=None,
        metavar="FILE",
        help=(
            "Content YAML file to migrate. May be repeated. Defaults to all 4 consumer YAMLs under risk-map/yaml/."
        ),
    )
    migrate_p.add_argument(
        "--frameworks-file",
        type=Path,
        default=DEFAULT_FRAMEWORKS_PATH,
        metavar="FILE",
        help=f"Path to frameworks.yaml (default: {DEFAULT_FRAMEWORKS_PATH}).",
    )
    migrate_p.add_argument(
        "--schema-file",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        metavar="FILE",
        help=f"Path to frameworks.schema.json (default: {DEFAULT_SCHEMA_PATH}).",
    )
    migrate_p.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print a per-file summary of what would change without writing.",
    )
    migrate_p.add_argument(
        "--report-legacy",
        action="store_true",
        default=False,
        help="Print a read-only inventory of legacy vs pinned values and exit 0.",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """
    Parse arguments and dispatch to the appropriate subcommand.

    Returns:
        0 on success; sys.exit is called on failure (non-zero).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Normalize attribute name: argparse converts hyphens in dest
    # but the flag is --framework-specific-ref, dest is framework_specific_ref.
    # (argparse already handles this via default dest naming.)

    dispatch = {
        "add": _cmd_add,
        "remove": _cmd_remove,
        "update": _cmd_update,
        "migrate": _cmd_migrate,
    }
    dispatch[args.subcommand](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
