#!/usr/bin/env python3
"""
Pre-commit lint: enforce ADR-033 D2a/D5/D8 vendor-neutrality for shipped surfaces.

`scripts/agents/**`, `scripts/skills/**`, and `scripts/agents-evals/**` are
the three authoring surfaces that ship in this repository. Prose in those
trees must not name a specific
AI harness product, company, CLI entry point, or model identifier; must not
embed harness-invocation stage directions (`<invoke ... tool>`,
`subagent_type`, "auto-loads"/"auto-triggers"); and must not reference
harness-specific config paths (`.claude/`, `.cursor/`, etc.). Framework-
authority references (MITRE, NIST, OWASP, ISO, EU AI Act, STRIDE) are
legitimate content and are allowlisted by span, so a denylist hit is only
suppressed where it actually overlaps an allowlist match on the same line —
not for the whole line.

A separate structural rule governs YAML frontmatter: the canonical skill-root
`SKILL.md` (`scripts/skills/<name>/SKILL.md`) may declare only
`name`/`description`; a top-level agent `.md` (directly under
`scripts/agents/`) must not declare a runtime-binding key (`tools`, `model`,
`color`, `allowed-tools`/`allowed_tools`) if it happens to carry a frontmatter
block at all. Frontmatter that cannot be verified (malformed YAML, an
unterminated fence) is a violation on those two structural targets, fail
closed rather than silently skipped; a same-named or bundled file that is not
one of those two structural targets (e.g. `references/SKILL.md`,
`references/*.md`) is exempt from this structural rule and only gets the
denylist scan.

`scripts/hooks/precommit/_neutrality_data.py` holds the denylist/allowlist
patterns; this module only implements the scan and CLI.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

# Ensure scripts/hooks is on sys.path so ``precommit.*`` imports work both
# when this file is executed directly (pre-commit's `entry:` and manual CLI
# use) and when it is imported as part of the precommit package (e.g.
# ``python3 -m precommit.validate_neutrality``). Mirrors the idiom in
# validate_yaml_prose_subset.py / validate_prose_references.py.
_HOOKS_DIR = Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

import precommit._neutrality_data as data  # noqa: E402

HOOK_NAME = "validate-neutrality"

# Denylist categories scanned per line: (compiled pattern, human-readable
# description used to build the violation message).
_DENYLIST_CATEGORIES: tuple[tuple[re.Pattern[str], str], ...] = (
    (data.VENDOR_PRODUCT_RE, "names a specific AI harness vendor, product, or company"),
    (data.MODEL_IDENTIFIER_RE, "names a specific model identifier"),
    (data.CLI_ENTRYPOINT_RE, "names a specific harness CLI entry point"),
    (data.INVOKE_TOOL_RE, "embeds a harness-invocation stage direction"),
    (data.SUBAGENT_TYPE_RE, "embeds a harness-specific subagent_type token"),
    (data.AUTO_LOAD_TRIGGER_RE, "embeds harness-specific auto-load/auto-trigger phrasing"),
    (data.HARNESS_CONFIG_PATH_RE, "references a harness-specific config path"),
)

# Frontmatter structural rules (ADR-033 category 3).
SKILL_FRONTMATTER_ALLOWED_KEYS = frozenset({"name", "description"})
_AGENT_FRONTMATTER_FORBIDDEN_KEYS_NORMALIZED = frozenset({"tools", "model", "color", "allowed-tools"})

# Text-file extensions eligible for discovery AND treated as "known text" by
# validate_file's binary/text policy. One shared set for both entry paths
# (PR #428 review Finding 3): restricting discovery to known text extensions
# (rather than a bare `rglob("*")` plus a try/except around the decode) keeps
# a binary file staged under scripts/agents/** or scripts/skills/** (e.g. a
# skill package's bundled icon or sample data) from ever reaching
# `path.read_text()` and crashing the hook with `UnicodeDecodeError`. Mirrors
# how `discover_workflow_files` in validate_workflow_uses_pinning.py restricts
# to `*.yml`.
_TEXT_EXTENSIONS = frozenset({".md", ".py", ".yaml", ".yml", ".json", ".txt", ".sh", ".js", ".ts", ".toml"})


def _looks_binary(raw: bytes) -> bool:
    """
    Heuristically detect binary content from raw bytes.

    Mirrors the Git/grep NUL-byte heuristic: a NUL in the first 8KB is a
    strong binary signal that is never legitimate in the text extensions this
    hook cares about. Only consulted for files whose extension is NOT a known
    text extension (see `validate_file`) — a known-text file with a NUL byte
    still fails closed as invalid UTF-8 rather than being silently skipped
    (LB1: a naive "NUL anywhere -> binary -> skip" rule would wrongly skip
    that case too).
    """
    return b"\x00" in raw[:8192]


@dataclass(frozen=True)
class Violation:
    """A single vendor-neutrality or frontmatter-structure violation."""

    path: Path
    line: int
    token: str
    message: str


def _allowlist_spans(line: str) -> list[tuple[int, int]]:
    """Return every framework-authority allowlist match span found in `line`."""
    spans: list[tuple[int, int]] = []
    for pattern in data.FRAMEWORK_ALLOWLIST_PATTERNS:
        spans.extend((match.start(), match.end()) for match in pattern.finditer(line))
    return spans


def _overlaps(span: tuple[int, int], others: list[tuple[int, int]]) -> bool:
    """True if `span` intersects any span in `others`."""
    start, end = span
    return any(start < other_end and other_start < end for other_start, other_end in others)


def _scan_line(path: Path, line_number: int, line: str) -> list[Violation]:
    """
    Scan one source line for denylist hits, suppressing allowlist overlaps.

    Suppression is per-match: an allowlisted span (e.g. "MITRE ATLAS") only
    suppresses a denylist hit whose span it actually overlaps, so a
    denylisted term sharing a line with legitimate framework content (but not
    overlapping it) is still flagged.
    """
    allow_spans = _allowlist_spans(line)
    violations: list[Violation] = []

    for pattern, description in _DENYLIST_CATEGORIES:
        for match in pattern.finditer(line):
            if _overlaps((match.start(), match.end()), allow_spans):
                continue
            # Strip enclosing backticks (CLI-entrypoint matches) for a clean token.
            token = match.group(0).strip("`")
            violations.append(
                Violation(
                    path=path,
                    line=line_number,
                    token=token,
                    message=f"{description}: {token!r}",
                )
            )

    return violations


def _find_key_line(lines: list[str], start: int, end: int, key: str) -> int:
    """
    Return the 1-based source line number of `key:` within lines[start:end].

    Falls back to the first line of the frontmatter block if the exact key
    line cannot be located (should not happen for well-formed YAML).
    """
    for index in range(start, end):
        if lines[index].strip().startswith(f"{key}:"):
            return index + 1
    return start + 1


def _normalize_frontmatter_key(key: object) -> str:
    """
    Normalize a frontmatter key for the allowlist/forbidden-key comparisons.

    Lowercases and maps underscores to hyphens so `Model`, `Allowed_Tools`, and
    `allowed-tools` all collapse to their canonical denylist form. Non-string
    keys (YAML permits them) are stringified first so the comparison never
    raises. LB3: without the lowercasing, capitalized keys evaded both checks.
    """
    return str(key).lower().replace("_", "-")


def _frontmatter_is_structurally_expected(path: Path) -> bool:
    """
    True when a file is one where a YAML frontmatter block is structurally expected.

    LB2 scoping: the malformed-frontmatter fail-closed rule applies ONLY to
    files that are supposed to carry frontmatter —

      * the canonical skill-root ``SKILL.md``: ``scripts/skills/<name>/SKILL.md``
        (parent dir is the skill's own directory, grandparent dir is ``skills``), and
      * a top-level agent definition: a ``.md`` file directly under
        ``scripts/agents/`` (parent dir ``agents``, grandparent ``scripts``).

    Bundled reference material (``references/*.md``, or any non-root ``.md`` —
    including a file that happens to also be named ``SKILL.md`` but sits deeper
    than the skill root, e.g. ``references/SKILL.md``) is deliberately excluded:
    it may legitimately open with a ``---`` markdown thematic break, so flagging
    it for "malformed frontmatter" would be a false positive. Reference files
    still get the denylist scan; they are only exempt from this structural rule.
    """
    parent = path.parent
    if path.name == "SKILL.md":
        return parent.parent.name == "skills"
    # Top-level agent definition: <...>/scripts/agents/<file>.md, nothing between
    # `agents` and the file. A deeper file (e.g. scripts/agents/foo/refs.md) is
    # bundled material, not a top-level agent def, and is excluded.
    return path.suffix == ".md" and parent.name == "agents" and parent.parent.name == "scripts"


def _find_reopened_forbidden_key(lines: list[str], body_start: int) -> tuple[str, int] | None:
    """
    Find a forbidden runtime-binding key smuggled into a re-opened `---` block.

    After the first frontmatter block closes, an author (or an adversary) can
    re-open a second `---`-delimited block deeper in the file and place a
    forbidden key inside it — content the first-block parser never sees. Scan
    the body for a `---` fence that opens such a block and return the first
    forbidden key found, as (key, 1-based line number). Returns None if none.

    This is a targeted structural check, not a full re-parse: it only looks for
    the specific evasion of a forbidden key inside a re-opened fence.
    """
    in_block = False
    for index in range(body_start, len(lines)):
        if lines[index].strip() == "---":
            in_block = not in_block
            continue
        if not in_block:
            continue
        # `key: value` shape inside a re-opened block. Split on the first colon
        # and normalize; a match on the forbidden set is the evasion we flag.
        stripped = lines[index].strip()
        if ":" in stripped:
            candidate = _normalize_frontmatter_key(stripped.split(":", 1)[0])
            if candidate in _AGENT_FRONTMATTER_FORBIDDEN_KEYS_NORMALIZED:
                return candidate, index + 1
    return None


def _frontmatter_violations(path: Path, lines: list[str]) -> list[Violation]:
    """
    Check a YAML frontmatter block (if present) against structural rules.

    SKILL.md files may declare only `name`/`description`. Top-level agent `.md`
    files must not declare a runtime-binding key. A file with no frontmatter
    block is trivially compliant.

    LB2 (fail closed): on files where frontmatter is structurally expected
    (`_frontmatter_is_structurally_expected`), frontmatter that will not parse,
    is not a mapping, or opens a `---` fence it never closes is *unverifiable*
    and is flagged — not silently skipped. A forbidden key hidden in a
    re-opened second `---` block is likewise flagged. Files where frontmatter is
    NOT structurally expected (bundled reference material) are exempt from this
    rule so a leading `---` thematic break does not false-positive.

    Note: a UTF-8-BOM-prefixed file has a non-"-" first character on
    `lines[0]`, so it is treated as having no frontmatter block. BOM
    stripping is not implemented; this is a documented gap, not a fix target.
    """
    if not lines or lines[0].strip() != "---":
        return []

    structurally_expected = _frontmatter_is_structurally_expected(path)

    closing_index = None
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            closing_index = index
            break

    if closing_index is None:
        # An opened-but-never-closed fence. Fail closed only where frontmatter
        # is structurally expected; reference material may legitimately open
        # with a `---` thematic break and never "close" it.
        if structurally_expected:
            return [
                Violation(
                    path=path,
                    line=1,
                    token="---",
                    message="unverifiable frontmatter: opening '---' fence has no closing '---'",
                )
            ]
        return []

    block_lines = lines[1:closing_index]
    try:
        # Split parse from default: only a truly empty/whitespace-only block
        # (parses to None) becomes {}. A falsy-but-non-mapping parse (False,
        # 0, []) must fall through to the isinstance(dict) guard below rather
        # than being coerced to {} and treated as compliant (PR #428 review
        # Finding 1 — `or {}` was a fail-open hole on structurally-expected
        # files).
        parsed = yaml.safe_load("\n".join(block_lines))
        frontmatter = {} if parsed is None else parsed
    except yaml.YAMLError as error:
        if structurally_expected:
            reason = str(error).splitlines()[0] if str(error) else "block is not valid YAML"
            return [
                Violation(
                    path=path,
                    line=1,
                    token="---",
                    message=f"unverifiable frontmatter: {reason}",
                )
            ]
        return []

    if not isinstance(frontmatter, dict):
        if structurally_expected:
            kind = type(frontmatter).__name__
            return [
                Violation(
                    path=path,
                    line=1,
                    token="---",
                    message=f"unverifiable frontmatter: block is not a key/value mapping (got {kind})",
                )
            ]
        return []

    # A file with well-formed frontmatter but no structural expectation (e.g.
    # references/SKILL.md, a bundled reference file that happens to share the
    # "SKILL.md" name but isn't the canonical skill root) is exempt from the
    # allowlist/forbidden-key ceiling entirely, same as it is from the
    # malformed-frontmatter checks above — it still gets the denylist scan
    # (_scan_line), just not this structural rule.
    if not structurally_expected:
        return []

    # Exact-case match on the fixed "SKILL.md" convention, gated on
    # `structurally_expected` above so only the canonical skill-root SKILL.md
    # (not a same-named file bundled deeper) is checked against the skill rule.
    is_skill = path.name == "SKILL.md"
    if is_skill:
        # LB3: normalize keys before the allowlist comparison so a capitalized
        # binding key (e.g. `Tools:`) does not evade the name/description ceiling.
        offending_keys = [
            key for key in frontmatter if _normalize_frontmatter_key(key) not in SKILL_FRONTMATTER_ALLOWED_KEYS
        ]
        rule = "SKILL.md frontmatter may declare only 'name' and 'description'"
    else:
        # LB3: lowercase-normalize so `Model:`/`Tools:`/`Allowed-Tools:` are caught.
        offending_keys = [
            key
            for key in frontmatter
            if _normalize_frontmatter_key(key) in _AGENT_FRONTMATTER_FORBIDDEN_KEYS_NORMALIZED
        ]
        rule = "agent frontmatter must not declare a runtime-binding key"

    violations = []
    for key in offending_keys:
        line_number = _find_key_line(lines, 1, closing_index, str(key))
        violations.append(
            Violation(path=path, line=line_number, token=str(key), message=f"{rule}: found {str(key)!r}")
        )

    # LB2: a forbidden key smuggled into a re-opened second `---` block after the
    # first block closes. Not checked for skill files: SKILL.md's own allowlist
    # check above already covers any key, reopened block or not.
    if not is_skill:
        reopened = _find_reopened_forbidden_key(lines, closing_index + 1)
        if reopened is not None:
            key, line_number = reopened
            violations.append(
                Violation(
                    path=path,
                    line=line_number,
                    token=key,
                    message=f"unverifiable frontmatter: runtime-binding key {key!r} in a re-opened '---' block",
                )
            )

    return violations


def validate_file(path: Path) -> list[Violation]:
    """
    Validate one file against the ADR-033 denylist/allowlist and frontmatter rules.

    Fails closed on unreadable input: a known-text-extension file carrying
    invalid UTF-8, or a broken (dangling) symlink, cannot be checked for
    neutrality, so it is flagged rather than silently passed or allowed to
    crash the gate. A file whose extension is not known text (e.g. a bundled
    binary asset) is silently skipped rather than flagged, whether it is
    handed to this function via discovery or as an explicit CLI argument.

    Args:
        path: File to validate.

    Returns:
        List of violations, empty if the file is clean or skipped.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        # Broken symlink or other unreadable path. Fail closed rather than raise.
        return [
            Violation(
                path=path,
                line=1,
                token=path.name,
                message="file could not be read; cannot verify neutrality",
            )
        ]

    is_known_text = path.suffix in _TEXT_EXTENSIONS
    if not is_known_text and _looks_binary(raw):
        # Not a known text extension and content looks binary (NUL in the
        # first 8KB): skip silently. A known-text file is never skipped here
        # even if its bytes also contain a NUL — see the UnicodeDecodeError
        # branch below (LB1).
        return []

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        if not is_known_text:
            # Undecodable and not a known text extension: treat as an
            # unrecognized binary asset and skip, same as the NUL-heuristic
            # branch above.
            return []
        # LB1: invalid UTF-8 in a known-text-extension file. Fail closed — an
        # undecodable file's neutrality cannot be verified, and an unguarded
        # decode would crash the whole hook (including main([]) self-discovery).
        return [
            Violation(
                path=path,
                line=1,
                token=path.name,
                message="file is not valid UTF-8; cannot verify neutrality",
            )
        ]

    lines = text.splitlines()

    violations: list[Violation] = []
    for line_number, line in enumerate(lines, start=1):
        violations.extend(_scan_line(path, line_number, line))
    violations.extend(_frontmatter_violations(path, lines))

    return violations


def discover_neutral_surface_files(root: Path) -> list[Path]:
    """
    Return files under `root/scripts/agents/**`, `root/scripts/skills/**`, and
    `root/scripts/agents-evals/**`.

    Deliberately targets only these three subtrees directly rather than walking
    a common `scripts/` ancestor and filtering — that would risk reaching
    `scripts/hooks/`, this checker's own home and the one place denylist
    tokens legitimately appear as detection data.

    Args:
        root: Repository root to scan.

    Only files with a known text extension (`_TEXT_EXTENSIONS`, the same set
    `validate_file` uses for its binary/text policy) are returned; a non-text
    file (e.g. a bundled icon or sample data asset) is silently excluded
    rather than crashing `validate_file` on decode.

    A dangling symlink (broken target) is included rather than filtered out.
    `path.is_file()` follows symlinks and returns False for one whose target is
    missing, so an `is_file()`-only filter would silently drop a broken link
    before `validate_file`'s `except OSError` guard ever runs — fail-open by
    omission. `path.is_symlink()` is checked independently of `is_file()` so a
    dangling link is discovered too; a symlink that resolves to a directory is
    still excluded (`is_dir()` on it is True, so it fails both checks), since
    feeding a directory to `validate_file` would not make sense.

    Returns:
        Discovered files in subtree-append order: agents, skills, then
        agents-evals, each subtree sorted internally. Any subtree may be
        empty (or absent) without error.
    """
    discovered: list[Path] = []
    for subdir in ("scripts/agents", "scripts/skills", "scripts/agents-evals"):
        base = root / subdir
        if not base.is_dir():
            continue
        discovered.extend(
            sorted(
                path
                for path in base.rglob("*")
                if not path.is_dir() and (path.is_file() or path.is_symlink()) and path.suffix in _TEXT_EXTENSIONS
            )
        )
    return discovered


def format_violation(violation: Violation) -> str:
    """Format one violation for stderr with actionable file:line context."""
    return f"{HOOK_NAME}: {violation.path}:{violation.line}: {violation.message}"


def main(argv: list[str]) -> int:
    """
    CLI entry point for pre-commit and manual validation.

    Pre-commit passes matched filenames explicitly; those are validated as-is
    with no re-filtering by scope, since pre-commit's own `files:` regex
    already restricts which files reach this hook. With no file arguments,
    the command self-discovers via `discover_neutral_surface_files` from the
    current working directory.

    Returns:
        1 if any violations are found, else 0.
    """
    parser = argparse.ArgumentParser(description="Validate ADR-033 vendor-neutrality for shipped surfaces.")
    parser.add_argument("files", nargs="*", help="Files to validate.")
    args = parser.parse_args(argv)

    files = [Path(file) for file in args.files] if args.files else discover_neutral_surface_files(Path.cwd())

    all_violations: list[Violation] = []
    for path in files:
        # path.exists() follows symlinks and is False for a dangling one, so a
        # bare `if not path.exists(): continue` would silently drop a broken
        # symlink before validate_file's OSError guard ever runs. Only skip a
        # path that neither exists nor is a symlink at all (i.e. genuinely
        # absent, not staged); let a dangling symlink through so it gets flagged.
        if not path.exists() and not path.is_symlink():
            continue
        all_violations.extend(validate_file(path))

    for violation in all_violations:
        print(format_violation(violation), file=sys.stderr)

    return 1 if all_violations else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
