"""
Shared tokenizer for the CoSAI Risk Map prose authoring subset.

This module is the single source of truth for the prose grammar defined in
ADR-017 D1/D2 (allowed and rejected token forms), ADR-016 D2 (sentinel
grammar), and ADR-020 D4 (folded-bullet drift heuristic). Both downstream
wrapper linters import it:
  - scripts/hooks/precommit/validate_yaml_prose_subset.py  (ADR-017 D4)
  - scripts/hooks/precommit/validate_prose_references.py   (ADR-016 D6)

Rule-precedence model (highest to lowest):
  1.  Fenced code block  (``` ... ```)
  2.  Inline code        (`...`)
  3.  Image              (![alt](url))
  4.  Markdown link / raw URL   ([text](url), https?://...)
  5.  HTML tag           (<tag> or </tag>)
  6.  Heading            (# at line start)
  7.  List marker        (- , * , N. at column 0)
  8.  Blockquote         (> at line start)
  9.  Pipe-table row     (| ... at line start)
  10. Folded-bullet drift (leading whitespace + "- " — ADR-020 D4)
  11. Sentinel           ({{ ... }})
  12. Bold               (**...**)
  13. Italic asterisk    (*...*)
  14. Italic underscore  (_..._)  — single underscore only; __ is not matched
  15. Bare camelCase ID  ((risk|control|component|persona)[A-Z]\\w*)
  16. Text               (catch-all, one character at a time to flush pending TEXT)

Line-anchored rules (headings, list markers, blockquotes, pipe tables,
folded-bullet drift) are applied only when the current position is at the
start of the string (i == 0) or immediately follows a newline character.

The partition-of-input invariant holds for every input: concatenating all
token values reconstructs the original string byte-for-byte.

Test fixtures live at scripts/hooks/tests/fixtures/prose_subset/.
"""

import re
from enum import Enum
from typing import NamedTuple


class TokenKind(Enum):
    """Token kinds for the ADR-017 prose authoring subset.

    Accepting kinds (permitted by ADR-017 D1 and ADR-016 D2):
        BOLD            **...**  (asterisk delimiters only; one nesting level)
        ITALIC          *...*  or  _..._
        SENTINEL_INTRA  {{(risk|control|component|persona)[A-Z]\\w*}}
        SENTINEL_REF    {{ref:[A-Za-z0-9_-]+}}
        TEXT            everything else (catch-all)

    Rejecting kinds (blocked by ADR-017 D2 and ADR-020 D4):
        INVALID_HTML          any HTML tag
        INVALID_URL           raw http/https URL or markdown link
        INVALID_HEADING       # at line start
        INVALID_LIST          - , * , or N. at column 0
        INVALID_CODE          fenced ``` block or inline ` code `
        INVALID_IMAGE         ![alt](url)
        INVALID_BLOCKQUOTE    > at line start
        INVALID_TABLE         markdown pipe-table row
        INVALID_FOLDED_BULLET whitespace-prefixed "- " line (ADR-020 D4)
        INVALID_CAMELCASE_ID  bare entity-prefix camelCase outside a sentinel
        INVALID_SENTINEL      malformed {{ }} (wrong prefix, empty ref, etc.)
    """

    BOLD = "BOLD"
    ITALIC = "ITALIC"
    SENTINEL_INTRA = "SENTINEL_INTRA"
    SENTINEL_REF = "SENTINEL_REF"
    TEXT = "TEXT"
    INVALID_HTML = "INVALID_HTML"
    INVALID_URL = "INVALID_URL"
    INVALID_HEADING = "INVALID_HEADING"
    INVALID_LIST = "INVALID_LIST"
    INVALID_CODE = "INVALID_CODE"
    INVALID_IMAGE = "INVALID_IMAGE"
    INVALID_BLOCKQUOTE = "INVALID_BLOCKQUOTE"
    INVALID_TABLE = "INVALID_TABLE"
    INVALID_FOLDED_BULLET = "INVALID_FOLDED_BULLET"
    INVALID_CAMELCASE_ID = "INVALID_CAMELCASE_ID"
    INVALID_SENTINEL = "INVALID_SENTINEL"


class Token(NamedTuple):
    """A single token produced by tokenize().

    Attributes:
        kind:  The token's classification (accepting or rejecting).
        value: The exact substring from the input that this token covers.
    """

    kind: TokenKind
    value: str


# ---------------------------------------------------------------------------
# Compiled patterns — ordered by precedence within their category
# ---------------------------------------------------------------------------

# Fenced code block: ``` ... ``` spanning multiple lines (single INVALID_CODE token)
_RE_FENCED_CODE = re.compile(r"```.*?```", re.DOTALL)

# Inline code: `...`
_RE_INLINE_CODE = re.compile(r"`[^`]+`")

# Image: ![alt](url) — must be checked before markdown link because both contain ]()
_RE_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")

# Markdown link: [text](url) — the ] immediately followed by ( pattern ADR-017 D2 cites
_RE_MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\([^)]*\)")

# Primary URL — scheme-with-authority (ADR-017 D4 rule 2 tier 1).
# Matches \b[a-z][a-z0-9+.\-]*://  followed by non-whitespace-non-brace chars.
# The [^\s{]+ stop-at-brace variant prevents \S+ from absorbing a following
# {{sentinel}} span — sentinels get their own token (Rule 11, higher precedence
# at the character level once the URL is consumed up to the { boundary).
# re.IGNORECASE covers authors who paste HTTP://, Ftp://, etc. from browser bars.
_RE_PRIMARY_URL = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s{]+", re.IGNORECASE)

# Opaque-data named list (ADR-017 D4 rule 2 tier 2).
# Colon-only schemes that lack // and escape the primary regex.
# Exactly four schemes per the ADR: mailto, javascript, data, tel.
# Requires at least one non-whitespace-non-brace char after the colon to avoid
# matching "mailto: " (scheme word alone in prose) as a false positive.
# re.IGNORECASE covers MAILTO:, DATA:, etc.
_RE_OPAQUE_URL = re.compile(r"\b(?:mailto|javascript|data|tel):[^\s{]+", re.IGNORECASE)

# HTML tag: opening (<tag ...>), closing (</tag>), or self-closing (<br/>)
# Matches '<' followed by alpha or '/' and continues through the closing '>'
_RE_HTML_TAG = re.compile(r"<[A-Za-z/][^>]*>")

# Heading: # characters at line start, followed by a space and title text
# Captures the entire rest of the line (no trailing \n)
_RE_HEADING = re.compile(r"#+[^\n]*")

# List marker at column 0: "- ", "* ", or "N. " followed by the rest of the line
_RE_LIST_DASH = re.compile(r"-\s[^\n]*")
_RE_LIST_ASTERISK = re.compile(r"\*\s[^\n]*")
_RE_LIST_NUMERIC = re.compile(r"\d+\.\s[^\n]*")

# Blockquote: > at line start, captures to end of line
_RE_BLOCKQUOTE = re.compile(r">[^\n]*")

# Pipe-table row: line starts with | and ends at (and including) the next \n or end
# The value includes the trailing \n when present (multiline table partition invariant)
_RE_PIPE_TABLE_ROW = re.compile(r"\|[^\n]*(?:\n|$)")

# Folded-bullet drift (ADR-020 D4): at least one leading whitespace char, then "- ",
# then the rest of the line up to (and including) the trailing \n or end of string.
# Leading whitespace distinguishes this from column-0 list markers (INVALID_LIST).
_RE_FOLDED_BULLET = re.compile(r"\s+\-\s[^\n]*(?:\n|$)")

# Sentinel ref identifier: letters, digits, hyphens, underscores, and dots.
# The dot is included to support identifiers like "nist-ai-rmf-1.0".
_RE_SENTINEL_INTRA_INNER = re.compile(r"(risk|control|component|persona)[A-Z]\w*$")
_RE_SENTINEL_REF_INNER = re.compile(r"ref:[A-Za-z0-9_.\-]+$")

# Bold: **...** non-greedy close at first ** so nested bold splits correctly.
# e.g. **foo **nested** bar** → BOLD("**foo **") + TEXT("nested") + BOLD("** bar**")
_RE_BOLD = re.compile(r"\*\*(.+?)\*\*", re.DOTALL)

# Italic asterisk: *...* — matched AFTER bold so ** is consumed first
_RE_ITALIC_ASTERISK = re.compile(r"\*(.+?)\*", re.DOTALL)

# Italic underscore: _..._ — single underscore only; __ is NOT italic (ADR-017 D1).
# Lookahead/lookbehind prevent matching when adjacent to another underscore.
_RE_ITALIC_UNDERSCORE = re.compile(r"(?<![_])_(?![_])(.+?)(?<![_])_(?![_])")

# Bare camelCase entity-prefix identifier: (risk|control|component|persona) immediately
# followed by a capital letter, then the rest of the identifier word.
# This fires only on plain prose; the sentinel branch consumes it first when inside {{}}.
_RE_BARE_CAMELCASE = re.compile(r"(risk|control|component|persona)([A-Z]\w*)")


# ---------------------------------------------------------------------------
# Sentinel helper
# ---------------------------------------------------------------------------


def _match_sentinel(text: str, i: int) -> Token | None:
    """Try to match a sentinel starting at position i (which must be '{{').

    Uses a brace-depth scan to find the matching '}}', so that nested-brace
    inputs like {{id{{ref:x}}}} are consumed as a single INVALID_SENTINEL
    token rather than splitting at the first '}}'. The depth counter increments
    on each '{{' and decrements on each '}}'; the sentinel span closes when
    depth reaches zero.

    If no matching '}}' exists (unclosed '{{'), returns None so the caller
    emits the '{{' as TEXT per ADR-016 D2 decision 1.

    Args:
        text: The full input string.
        i:    The index of the opening '{' (text[i:i+2] == '{{').

    Returns:
        A SENTINEL_INTRA, SENTINEL_REF, or INVALID_SENTINEL Token, or
        None if the braces are unclosed.
    """
    depth = 0
    j = i
    while j < len(text):
        if text[j : j + 2] == "{{":
            depth += 1
            j += 2
        elif text[j : j + 2] == "}}":
            depth -= 1
            j += 2
            if depth == 0:
                break
        else:
            j += 1
    else:
        # Reached end of string without closing — unclosed {{
        return None

    if depth != 0:
        # Should not happen given the loop logic, but guard defensively
        return None

    span = text[i:j]
    inner = span[2:-2]  # strip outer {{ and }}

    # Classify the inner content.
    if _RE_SENTINEL_INTRA_INNER.fullmatch(inner):
        return Token(TokenKind.SENTINEL_INTRA, span)
    if _RE_SENTINEL_REF_INNER.fullmatch(inner):
        return Token(TokenKind.SENTINEL_REF, span)
    # Structurally well-formed (has {{ and }}) but inner content is invalid.
    return Token(TokenKind.INVALID_SENTINEL, span)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def tokenize(text: str) -> list[Token]:
    """Tokenize a prose string according to the ADR-017 authoring subset grammar.

    Returns a list of Token objects in source order. The token stream is a
    partition of the input: every character in `text` appears in exactly one
    token's value, and ''.join(t.value for t in tokenize(text)) == text.

    Accepting kinds are produced for valid ADR-017 D1 constructs (BOLD, ITALIC,
    SENTINEL_INTRA, SENTINEL_REF, TEXT). Rejecting kinds (INVALID_*) are
    produced for any construct disallowed by ADR-017 D2 or ADR-020 D4.

    The `text` argument is expected to be a single prose field value as
    decoded by PyYAML — not raw YAML, not a file path.

    Test fixtures for all 42 grammar cases live at:
        scripts/hooks/tests/fixtures/prose_subset/

    Args:
        text: A prose string from a YAML field value.

    Returns:
        List of Token objects covering every character in text.
    """
    if not text:
        return []

    tokens: list[Token] = []
    i = 0
    pending_text_start = -1  # start index of an in-progress TEXT run

    def flush_text(end: int) -> None:
        """Emit a TEXT token for text[pending_text_start:end] if non-empty."""
        nonlocal pending_text_start
        if pending_text_start != -1 and end > pending_text_start:
            tokens.append(Token(TokenKind.TEXT, text[pending_text_start:end]))
        pending_text_start = -1

    def emit(kind: TokenKind, value: str) -> None:
        """Flush any pending TEXT, then emit the given token."""
        nonlocal i
        flush_text(i)
        tokens.append(Token(kind, value))
        i += len(value)

    def at_line_start() -> bool:
        """Return True if position i is at the start of a line."""
        return i == 0 or text[i - 1] == "\n"

    while i < len(text):
        ch = text[i]

        # --- Rule 1: Fenced code block (highest priority — must precede inline `) ---
        if ch == "`" and text[i : i + 3] == "```":
            m = _RE_FENCED_CODE.match(text, i)
            if m:
                emit(TokenKind.INVALID_CODE, m.group())
                continue

        # --- Rule 2: Inline code ---
        if ch == "`":
            m = _RE_INLINE_CODE.match(text, i)
            if m:
                emit(TokenKind.INVALID_CODE, m.group())
                continue

        # --- Rule 3: Image (! before [) — before markdown link ---
        if ch == "!" and i + 1 < len(text) and text[i + 1] == "[":
            m = _RE_IMAGE.match(text, i)
            if m:
                emit(TokenKind.INVALID_IMAGE, m.group())
                continue

        # --- Rule 4a: Markdown link [text](url) ---
        if ch == "[":
            m = _RE_MARKDOWN_LINK.match(text, i)
            if m:
                emit(TokenKind.INVALID_URL, m.group())
                continue

        # --- Rule 4b: Categorical URL rejection (ADR-017 D4 rule 2) ---
        # Fast-path gate: scheme names start with an ASCII letter. Both regexes
        # anchor on \b, so re.match() only succeeds at word-boundary positions.
        # The regex engine handles the "embedded mid-word" case naturally — at
        # positions inside a word (between two word chars) \b does not fire and
        # match() returns None. At i=0 \b always fires (start-of-string is a
        # boundary), which is intentional per ADR-017 D4 rule 2: any scheme
        # name — known or unknown — is rejected when it begins at a token
        # boundary. Primary catches authority-bearing schemes (http://, ftp://,
        # gs://, ...); opaque catches mailto:/javascript:/data:/tel:. Both
        # case-insensitive (re.IGNORECASE) for HTTP://, MAILTO:, etc.
        if ch.isalpha():
            m = _RE_PRIMARY_URL.match(text, i)
            if m:
                emit(TokenKind.INVALID_URL, m.group())
                continue
            m = _RE_OPAQUE_URL.match(text, i)
            if m:
                emit(TokenKind.INVALID_URL, m.group())
                continue

        # --- Rule 5: HTML tag ---
        if ch == "<" and i + 1 < len(text) and (text[i + 1].isalpha() or text[i + 1] == "/"):
            m = _RE_HTML_TAG.match(text, i)
            if m:
                emit(TokenKind.INVALID_HTML, m.group())
                continue

        # --- Line-anchored rules (only at line start) ---
        if at_line_start():
            # Rule 6: Heading (# at line start)
            if ch == "#":
                m = _RE_HEADING.match(text, i)
                if m:
                    emit(TokenKind.INVALID_HEADING, m.group())
                    continue

            # Rule 7: List marker at column 0
            if ch == "-" and i + 1 < len(text) and text[i + 1] == " ":
                m = _RE_LIST_DASH.match(text, i)
                if m:
                    emit(TokenKind.INVALID_LIST, m.group())
                    continue
            if ch == "*" and i + 1 < len(text) and text[i + 1] == " ":
                m = _RE_LIST_ASTERISK.match(text, i)
                if m:
                    emit(TokenKind.INVALID_LIST, m.group())
                    continue
            if ch.isdigit():
                m = _RE_LIST_NUMERIC.match(text, i)
                if m:
                    emit(TokenKind.INVALID_LIST, m.group())
                    continue

            # Rule 8: Blockquote (> at line start)
            if ch == ">":
                m = _RE_BLOCKQUOTE.match(text, i)
                if m:
                    emit(TokenKind.INVALID_BLOCKQUOTE, m.group())
                    continue

            # Rule 9: Pipe-table row (| at line start)
            if ch == "|":
                m = _RE_PIPE_TABLE_ROW.match(text, i)
                if m:
                    emit(TokenKind.INVALID_TABLE, m.group())
                    continue

            # Rule 10: Folded-bullet drift — leading whitespace then "- "
            # Only when at line start AND the first char is whitespace.
            # This distinguishes folded-bullet drift from column-0 list markers.
            if ch in (" ", "\t"):
                m = _RE_FOLDED_BULLET.match(text, i)
                if m:
                    emit(TokenKind.INVALID_FOLDED_BULLET, m.group())
                    continue

        # --- Rule 11: Sentinel {{ ... }} ---
        if ch == "{" and i + 1 < len(text) and text[i + 1] == "{":
            tok = _match_sentinel(text, i)
            if tok is not None:
                emit(tok.kind, tok.value)
                continue
            # Unclosed {{ — the entire remainder of the input is TEXT.
            # No camelCase or other rule fires inside an unclosed sentinel span.
            if pending_text_start == -1:
                pending_text_start = i
            i = len(text)  # advance past end; the flush_text call below emits all
            break

        # --- Rule 12: Bold **...** (non-greedy close at first **) ---
        if ch == "*" and i + 1 < len(text) and text[i + 1] == "*":
            m = _RE_BOLD.match(text, i)
            if m:
                emit(TokenKind.BOLD, m.group())
                continue

        # --- Rule 13: Italic asterisk *...* ---
        if ch == "*":
            m = _RE_ITALIC_ASTERISK.match(text, i)
            if m:
                emit(TokenKind.ITALIC, m.group())
                continue

        # --- Rule 14: Italic underscore _..._ (single underscore only) ---
        if ch == "_":
            m = _RE_ITALIC_UNDERSCORE.match(text, i)
            if m:
                emit(TokenKind.ITALIC, m.group())
                continue

        # --- Rule 15: Bare camelCase entity-prefix identifier ---
        # Only fires when not inside a sentinel (sentinels are consumed in Rule 11
        # before we reach here, so any remaining camelCase is genuinely bare).
        if ch.islower():
            m = _RE_BARE_CAMELCASE.match(text, i)
            if m:
                emit(TokenKind.INVALID_CAMELCASE_ID, m.group())
                continue

        # --- Rule 16: Text (catch-all) ---
        # Accumulate characters into a pending TEXT run.
        if pending_text_start == -1:
            pending_text_start = i
        i += 1

    # Flush any remaining TEXT
    flush_text(len(text))

    return tokens
