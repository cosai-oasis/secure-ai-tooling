#!/usr/bin/env python3
r"""
Tests for scripts/hooks/precommit/_prose_tokens.py

Tests for the shared YAML-prose tokenizer (ADR-017 D5). Decoupled import: if
`precommit._prose_tokens` cannot be imported, `_IMPORT_ERROR` is set and each
test fails via `_require_module()` with a clear message, while
`pytest --collect-only` still succeeds.

Grammar contract (sources: ADR-017 D1/D2, ADR-016 D2, ADR-020 D4):
  Accepting tokens:
    BOLD           - **...** (asterisk delimiters; one nesting level; italic inside OK)
    ITALIC         - *...* or _..._
    SENTINEL_INTRA - {{riskXxx}}, {{controlXxx}}, {{componentXxx}}, {{personaXxx}}
                     (bare entity-prefix form: lowercase prefix immediately followed by
                     a capital letter then the rest of the identifier)
                     Regex: \{\{(risk|control|component|persona)[A-Z]\w*\}\}
    SENTINEL_REF   - {{ref:identifier}} where identifier matches [A-Za-z0-9_-]+
    TEXT           - plain text run (catch-all for everything else)

  Rejecting tokens:
    INVALID_HTML          - any < followed by alpha or /
    INVALID_URL           - raw http:// or https://, [text](url) markdown link,
                            or ] immediately followed by (
    INVALID_HEADING       - # at line start
    INVALID_LIST          - "- ", "* ", or "N. " at line start
    INVALID_CODE          - fenced ``` block, inline `code`, or 4-space-indented block
    INVALID_IMAGE         - ![alt](url)
    INVALID_BLOCKQUOTE    - > at line start
    INVALID_TABLE         - markdown pipe-table row (| ... |)
    INVALID_FOLDED_BULLET - whitespace-dash-space pattern on its own line (ADR-020 D4 heuristic)
    INVALID_CAMELCASE_ID  - bare (risk|control|component|persona)[A-Z]... outside a sentinel
    INVALID_SENTINEL      - malformed {{ }} (wrong prefix, empty ref, unbalanced braces)

Representation decisions (locked; the implementation must match):

1. Token type: `Token` is a NamedTuple (not dataclass). Rationale: NamedTuple gives
   positional unpacking in assertions (`kind, value = token`) and equality semantics
   that are identical to dataclass(frozen=True), but with less boilerplate for a
   two-field value type. Tests use attribute access on Token instances.

2. Bold nesting: `**foo *bar* baz**` produces a SINGLE BOLD token whose `value` is
   the entire span `**foo *bar* baz**`. The inner italic is not extracted as a
   separate token at the top level — the BOLD token is treated as atomic at the
   outer level. Consumers that need to examine bold contents call `tokenize()` on
   the inner text (stripping the `**` delimiters) recursively if needed. This keeps
   the outer token stream flat and predictable.

   Rationale: the wrapper linters care about "is there a BOLD token here?" and "is
   the token kind valid?", not about the internal structure of the bold span. A
   flat outer stream matches ADR-017's description of "one nesting level" without
   requiring a tree output type.

3. Nested bold: `**foo **nested** bar**` — the outer `**` is consumed as the start
   of a BOLD span. The inner `**nested**` causes the BOLD span to close early at the
   inner `**`, producing BOLD(`**foo **`) followed by TEXT(`nested`) followed by
   BOLD(`** bar**`). This is the "rejected" representation: authors see a lint error
   because the inner `**nested**` is not valid one-nesting-level content. The exact
   token boundaries are tested in TestNestingRules.

   Alternative: emit a single INVALID_* token for the whole span. That choice was
   rejected because the tokenizer's job is to identify spans, not adjudicate whether
   nesting is valid — that's the wrapper linter's job using the token stream. The
   tokenizer emits what it sees; the linter decides whether the stream is conformant.

4. INVALID_FOLDED_BULLET: the heuristic fires on any line that has at least one
   leading whitespace character followed immediately by "- " (dash-space). Distinction:
   INVALID_LIST fires when "- " appears at column 0; INVALID_FOLDED_BULLET fires when
   "- " has any leading whitespace, indicating it is inside a folded-scalar continuation
   block per ADR-020 D4. Note: the ADR-020 D4 heuristic is `^\s*-\s+`, which technically
   matches zero-or-more leading spaces; our refinement reserves column-0 dash for
   INVALID_LIST and requires at least one leading whitespace for INVALID_FOLDED_BULLET.

5. TokenKind additions beyond the required set: none. The thirteen kinds listed in
   the ADR spec are sufficient for all fixture cases.

6. INVALID_SENTINEL scope: a `{{ }}` construct that matches the double-brace pattern
   but fails validation (inner identifier does not start with a recognized entity
   prefix risk|control|component|persona, empty ref identifier, or nested braces)
   produces INVALID_SENTINEL. An unclosed `{{` that never finds `}}` is treated as
   TEXT (the double-brace never closes, so no sentinel was intended by the grammar;
   the tokenizer does not look ahead past end of string for closure).

7. Source order: `tokenize()` returns tokens in the order their `value` substrings
   appear in the input. No reordering, no elision. Every character in the input
   appears in exactly one token's `value`.

Test Summary
============
Total fixture-parametrized pairs: 55
- accepting/: 7 fixture pairs (inc. double_underscore_not_bold)
- sentinels/: 7 fixture pairs
- rejecting/: 16 fixture pairs (existing) + 14 new URL fixture pairs (commit 5)
- folded_bullets/: 2 fixture pairs
- bare_camelcase/: 6 fixture pairs (inc. 3 non-flagging cases)
- malformed_sentinels/: 4 fixture pairs

Additional non-fixture tests:
- TestTokenAPI: 8 tests (import, Token shape, TokenKind members, callable)
- TestNestingRules: 6 tests (inc. __bold__ rejection and sentinel-inside-bold)
- TestMixedRuns: 3 tests
- TestEmptyAndWhitespace: 4 tests
- TestCategoricalUrlRejection: 66 tests total (commit 5 — ADR-017 D4 rule 2)
  - Primary-regex scheme-with-authority: 9 fixture pairs × 2 parametrized = 18 + 8 inline = 26
  - Named-list opaque-data: 5 fixture pairs × 2 parametrized = 10 + 5 inline = 15
  - Boundary / edge cases: 10 tests
  - Negative cases (must not reject): 6 tests
  - Regression: 3 tests
  - Gap closures (commit 5 review): 6 tests
    - Gap 1: test_git_plus_https_full_token_value (full-prefix value lock)
    - Gap 2: url_ftp_trailing_period fixture pair (2) + test_url_at_end_of_sentence_absorbs_trailing_period (1)
    - Gap 3: test_url_followed_immediately_by_sentinel_does_not_absorb_sentinel (1)
  Note: includes 21 permissive boundary tests (accepting either of two
  implementation choices for URL detection inside bold/italic spans,
  regression guards, and a strict full-token-value lock for git+https://...).

Coverage target: 90%+ of _prose_tokens.py on green.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Path setup — mirror the pattern used in test_validate_component_edges.py
# ---------------------------------------------------------------------------


def get_git_root() -> Path:
    """Return the repository root, falling back to path-based navigation."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except subprocess.CalledProcessError:
        # conftest.py is at scripts/hooks/tests/; go up three levels
        return Path(__file__).resolve().parent.parent.parent.parent


_GIT_ROOT = get_git_root()
sys.path.insert(0, str(_GIT_ROOT / "scripts" / "hooks"))

# Import the module under test. If the import fails, _IMPORT_ERROR is set and
# each test calls _require_module() to fail with a clear error message.
# Decoupling import from collection lets pytest --collect-only still succeed
# (signatures parse) even when the module is missing.
_IMPORT_ERROR: ImportError | None = None
try:
    from precommit._prose_tokens import Token, TokenKind, tokenize  # noqa: E402
except ImportError as _e:
    _IMPORT_ERROR = _e
    # Provide placeholder names so type-checkers and collection don't crash.
    # Tests will fail at runtime via _require_module() before they use these.
    Token = None  # type: ignore[assignment, misc]
    TokenKind = None  # type: ignore[assignment, misc]
    tokenize = None  # type: ignore[assignment]


def _require_module() -> None:
    """Fail immediately if the module under test could not be imported."""
    if _IMPORT_ERROR is not None:
        pytest.fail(f"Module 'precommit._prose_tokens' could not be imported.\nOriginal error: {_IMPORT_ERROR}")


# ---------------------------------------------------------------------------
# Fixture directory helper
# ---------------------------------------------------------------------------

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "prose_subset"


def _load_fixture_pair(rel_path: str) -> tuple[str, list[dict[str, str]]]:
    """
    Load a (.txt, .tokens.json) fixture pair.

    Args:
        rel_path: Path relative to FIXTURE_DIR, without extension.
                  e.g. "accepting/bold_simple"

    Returns:
        (input_text, expected_tokens) where expected_tokens is a list of
        {"kind": str, "value": str} dicts.
    """
    _require_module()
    txt_path = FIXTURE_DIR / (rel_path + ".txt")
    json_path = FIXTURE_DIR / (rel_path + ".tokens.json")
    input_text = txt_path.read_text(encoding="utf-8")
    expected = json.loads(json_path.read_text(encoding="utf-8"))
    return input_text, expected


def _tokens_to_dicts(tokens: list[Any]) -> list[dict[str, str]]:
    """Convert a list of Token objects to comparable dicts."""
    _require_module()
    return [{"kind": t.kind.name, "value": t.value} for t in tokens]


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestTokenAPI:
    """
    Verify the public surface of _prose_tokens matches the contract.

    Given: the module is importable
    When: Token, TokenKind, and tokenize are accessed
    Then: they have the exact shape the ADRs specify
    """

    def test_tokenize_is_callable(self):
        """
        tokenize must be a callable that accepts a str.

        Given: the module is imported
        When: tokenize is inspected
        Then: it is callable
        """
        _require_module()
        assert callable(tokenize)

    def test_token_has_kind_field(self):
        """
        Token instances must expose a .kind attribute.

        Given: a Token is constructed
        When: .kind is accessed
        Then: it returns a TokenKind member
        """
        _require_module()
        token = Token(kind=TokenKind.TEXT, value="hello")
        assert isinstance(token.kind, TokenKind)

    def test_token_has_value_field(self):
        """
        Token instances must expose a .value attribute.

        Given: a Token is constructed
        When: .value is accessed
        Then: it returns the raw string passed at construction
        """
        _require_module()
        token = Token(kind=TokenKind.TEXT, value="hello")
        assert token.value == "hello"

    def test_token_equality(self):
        """
        Two Tokens with the same kind and value must compare equal.

        Given: two Token instances with identical fields
        When: they are compared with ==
        Then: they are equal
        """
        _require_module()
        t1 = Token(kind=TokenKind.TEXT, value="x")
        t2 = Token(kind=TokenKind.TEXT, value="x")
        assert t1 == t2

    def test_token_inequality_on_kind(self):
        """
        Tokens with different kinds must not compare equal.

        Given: two Token instances with different kinds but the same value
        When: they are compared with ==
        Then: they are not equal
        """
        _require_module()
        t1 = Token(kind=TokenKind.TEXT, value="**foo**")
        t2 = Token(kind=TokenKind.BOLD, value="**foo**")
        assert t1 != t2

    def test_tokenkind_accepting_members_present(self):
        """
        All accepting TokenKind members required by ADR-017 D1 and ADR-016 D2 must exist.

        Given: TokenKind is imported
        When: member names are checked
        Then: BOLD, ITALIC, SENTINEL_INTRA, SENTINEL_REF, TEXT are all present
        """
        _require_module()
        required_accepting = {"BOLD", "ITALIC", "SENTINEL_INTRA", "SENTINEL_REF", "TEXT"}
        actual_names = {m.name for m in TokenKind}
        missing = required_accepting - actual_names
        assert not missing, f"Missing accepting TokenKind members: {missing}"

    def test_tokenkind_rejecting_members_present(self):
        """
        All rejecting TokenKind members required by ADR-017 D2 and ADR-020 D4 must exist.

        Given: TokenKind is imported
        When: member names are checked
        Then: all INVALID_* kinds are present
        """
        _require_module()
        required_rejecting = {
            "INVALID_HTML",
            "INVALID_URL",
            "INVALID_HEADING",
            "INVALID_LIST",
            "INVALID_CODE",
            "INVALID_IMAGE",
            "INVALID_BLOCKQUOTE",
            "INVALID_TABLE",
            "INVALID_FOLDED_BULLET",
            "INVALID_CAMELCASE_ID",
            "INVALID_SENTINEL",
        }
        actual_names = {m.name for m in TokenKind}
        missing = required_rejecting - actual_names
        assert not missing, f"Missing rejecting TokenKind members: {missing}"

    def test_tokenize_returns_list(self):
        """
        tokenize() must return a list.

        Given: a non-empty input string
        When: tokenize() is called
        Then: the return value is a list
        """
        _require_module()
        result = tokenize("hello world")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Fixture-parametrized tests
# ---------------------------------------------------------------------------

_ACCEPTING_FIXTURES = [
    "accepting/bold_simple",
    "accepting/bold_with_italic_inside",
    "accepting/italic_asterisk",
    "accepting/italic_underscore",
    "accepting/plain_text",
    "accepting/mixed_accepting_run",
    "accepting/double_underscore_not_bold",
]

_SENTINEL_FIXTURES = [
    "sentinels/intra_risk",
    "sentinels/intra_control",
    "sentinels/intra_component",
    "sentinels/intra_persona",
    "sentinels/ref_simple",
    "sentinels/ref_with_underscore",
    "sentinels/multiple_in_one_string",
]

_REJECTING_FIXTURES = [
    "rejecting/url_raw_http",
    "rejecting/url_raw_https",
    "rejecting/url_markdown_link",
    "rejecting/html_anchor",
    "rejecting/html_self_closing",
    "rejecting/html_closing",
    "rejecting/heading_h1",
    "rejecting/heading_h2",
    "rejecting/list_dash",
    "rejecting/list_asterisk",
    "rejecting/list_numeric",
    "rejecting/code_fenced",
    "rejecting/code_inline",
    "rejecting/image",
    "rejecting/blockquote",
    "rejecting/pipe_table",
]

# ---------------------------------------------------------------------------
# Commit 5 — ADR-017 D4 rule 2: categorical URL rejection fixtures
# ---------------------------------------------------------------------------

# Primary: scheme-with-authority regex  \b[a-z][a-z0-9+.\-]*://\S+
# These extend http/https coverage to every authority-bearing scheme.
_URL_PRIMARY_SCHEME_FIXTURES = [
    "rejecting/url_ftp",  # ftp://example.com/file — dead-scheme drift signal
    "rejecting/url_file",  # file:///etc/passwd — local-path exposure
    "rejecting/url_gs",  # gs://bucket/key — cloud ref (belongs in externalReferences per ADR-016)
    "rejecting/url_s3",  # s3://bucket/key.tar.gz — cloud ref
    "rejecting/url_ssh",  # ssh://user@host:22/path — SSH URL
    "rejecting/url_scheme_plus",  # git+https://github.com/user/repo — + in scheme char class
    "rejecting/url_scheme_dash",  # myscheme-v2://something — - in scheme char class
    "rejecting/url_scheme_dot",  # myscheme.2://something — . in scheme char class
    "rejecting/url_ftp_trailing_period",  # ftp://example.com. — trailing period absorbed by \S+ greediness
]

# Secondary: opaque-data named list (colon-only; no // authority component).
# These would escape the primary regex, hence the separate named-list rule.
_URL_OPAQUE_DATA_FIXTURES = [
    "rejecting/url_opaque_mailto",  # mailto:user@example.com — contact-exposure vector
    "rejecting/url_opaque_mailto_query",  # mailto:user@example.com?subject=Hello — with query
    "rejecting/url_opaque_javascript",  # javascript:alert(1) — XSS vector
    "rejecting/url_opaque_data",  # data:image/png;base64,... — XSS via data URI
    "rejecting/url_opaque_tel",  # tel:+1-555-0100 — contact-exposure vector
]

_FOLDED_BULLET_FIXTURES = [
    "folded_bullets/controls_yaml_known_case",
    "folded_bullets/risks_yaml_known_case",
]

_BARE_CAMELCASE_FIXTURES = [
    "bare_camelcase/in_prose_risk",
    "bare_camelcase/in_prose_control",
    "bare_camelcase/in_prose_component",
    "bare_camelcase/in_prose_persona",
    "bare_camelcase/inside_sentinel_ok",
    "bare_camelcase/lookalike_not_entity_prefix",
]

_MALFORMED_SENTINEL_FIXTURES = [
    "malformed_sentinels/no_entity_prefix",
    "malformed_sentinels/empty_ref",
    "malformed_sentinels/unclosed",
    "malformed_sentinels/nested",
]


class TestAcceptingTokens:
    """
    Verify that accepting token forms produce the expected token kinds.

    Given: a prose string containing only allowed ADR-017 D1 constructs
    When: tokenize() is called
    Then: all tokens have accepting kinds; stream matches the fixture's .tokens.json
    """

    @pytest.mark.parametrize("fixture_path", _ACCEPTING_FIXTURES)
    def test_fixture_token_stream(self, fixture_path: str):
        """
        Given: input from accepting/<name>.txt
        When: tokenize() is called
        Then: output matches accepting/<name>.tokens.json exactly (kind + value)
        """
        input_text, expected = _load_fixture_pair(fixture_path)
        result = _tokens_to_dicts(tokenize(input_text))
        assert result == expected, f"Fixture {fixture_path!r}: expected {expected!r}, got {result!r}"

    @pytest.mark.parametrize("fixture_path", _ACCEPTING_FIXTURES)
    def test_no_invalid_tokens(self, fixture_path: str):
        """
        Given: an accepting fixture input
        When: tokenize() is called
        Then: no token has an INVALID_* kind
        """
        input_text, _ = _load_fixture_pair(fixture_path)
        invalid_kinds = {k for k in TokenKind if k.name.startswith("INVALID")}
        for token in tokenize(input_text):
            assert token.kind not in invalid_kinds, f"Fixture {fixture_path!r}: unexpected INVALID token {token!r}"


class TestSentinels:
    """
    Verify sentinel tokenisation for both intra-document ({{riskXxx}}, {{controlXxx}},
    {{componentXxx}}, {{personaXxx}}) and external-reference ({{ref:identifier}}) forms.

    Given: a prose string containing a valid sentinel
    When: tokenize() is called
    Then: the sentinel is a single SENTINEL_INTRA or SENTINEL_REF token;
          surrounding text produces TEXT tokens
    """

    @pytest.mark.parametrize("fixture_path", _SENTINEL_FIXTURES)
    def test_fixture_token_stream(self, fixture_path: str):
        """
        Given: input from sentinels/<name>.txt
        When: tokenize() is called
        Then: output matches sentinels/<name>.tokens.json exactly
        """
        input_text, expected = _load_fixture_pair(fixture_path)
        result = _tokens_to_dicts(tokenize(input_text))
        assert result == expected, f"Fixture {fixture_path!r}: expected {expected!r}, got {result!r}"

    def test_intra_sentinel_produces_sentinel_intra_kind(self):
        """
        Given: {{riskPromptInjection}} in prose (bare-entity-prefix form)
        When: tokenize() is called
        Then: exactly one SENTINEL_INTRA token is produced with the full sentinel value
        """
        _require_module()
        tokens = tokenize("{{riskPromptInjection}}")
        assert len(tokens) == 1
        assert tokens[0].kind == TokenKind.SENTINEL_INTRA
        assert tokens[0].value == "{{riskPromptInjection}}"

    def test_ref_sentinel_produces_sentinel_ref_kind(self):
        """
        Given: {{ref:some-id}} in prose
        When: tokenize() is called
        Then: exactly one SENTINEL_REF token is produced with the full sentinel value
        """
        _require_module()
        tokens = tokenize("{{ref:some-id}}")
        assert len(tokens) == 1
        assert tokens[0].kind == TokenKind.SENTINEL_REF
        assert tokens[0].value == "{{ref:some-id}}"

    def test_all_four_entity_prefixes_accepted(self):
        """
        Given: one sentinel for each of the four entity prefixes (bare-entity-prefix form)
        When: tokenize() is called on each
        Then: each produces SENTINEL_INTRA, not INVALID_SENTINEL
        """
        _require_module()
        cases = [
            "{{riskPromptInjection}}",
            "{{controlInputValidationAndSanitization}}",
            "{{componentModelServing}}",
            "{{personaModelCreator}}",
        ]
        for sentinel in cases:
            tokens = tokenize(sentinel)
            assert len(tokens) == 1, f"Expected 1 token for {sentinel!r}, got {len(tokens)}"
            assert tokens[0].kind == TokenKind.SENTINEL_INTRA, (
                f"Expected SENTINEL_INTRA for {sentinel!r}, got {tokens[0].kind!r}"
            )


class TestRejectingTokens:
    """
    Verify that disallowed constructs (ADR-017 D2) produce INVALID_* tokens.

    Given: a prose string containing a disallowed form
    When: tokenize() is called
    Then: at least one token has an INVALID_* kind; stream matches fixture
    """

    @pytest.mark.parametrize("fixture_path", _REJECTING_FIXTURES)
    def test_fixture_token_stream(self, fixture_path: str):
        """
        Given: input from rejecting/<name>.txt
        When: tokenize() is called
        Then: output matches rejecting/<name>.tokens.json exactly
        """
        input_text, expected = _load_fixture_pair(fixture_path)
        result = _tokens_to_dicts(tokenize(input_text))
        assert result == expected, f"Fixture {fixture_path!r}: expected {expected!r}, got {result!r}"

    @pytest.mark.parametrize("fixture_path", _REJECTING_FIXTURES)
    def test_at_least_one_invalid_token(self, fixture_path: str):
        """
        Given: a rejecting fixture input
        When: tokenize() is called
        Then: at least one token has an INVALID_* kind
        """
        input_text, _ = _load_fixture_pair(fixture_path)
        invalid_kinds = {k for k in TokenKind if k.name.startswith("INVALID")}
        kinds_in_result = {t.kind for t in tokenize(input_text)}
        assert kinds_in_result & invalid_kinds, f"Fixture {fixture_path!r}: expected at least one INVALID token"

    def test_raw_http_produces_invalid_url(self):
        """
        Given: a raw http:// URL in prose
        When: tokenize() is called
        Then: the URL span produces INVALID_URL
        """
        _require_module()
        tokens = tokenize("http://example.com")
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens)

    def test_raw_https_produces_invalid_url(self):
        """
        Given: a raw https:// URL in prose
        When: tokenize() is called
        Then: the URL span produces INVALID_URL
        """
        _require_module()
        tokens = tokenize("https://example.com")
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens)

    def test_markdown_link_produces_invalid_url(self):
        """
        Given: [text](url) markdown link syntax
        When: tokenize() is called
        Then: the link span produces INVALID_URL
        """
        _require_module()
        tokens = tokenize("[click here](https://example.com)")
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens)

    def test_html_tag_opening_produces_invalid_html(self):
        """
        Given: an opening HTML tag in prose
        When: tokenize() is called
        Then: the tag span produces INVALID_HTML
        """
        _require_module()
        tokens = tokenize("<strong>text</strong>")
        assert any(t.kind == TokenKind.INVALID_HTML for t in tokens)

    def test_html_closing_tag_produces_invalid_html(self):
        """
        Given: a closing HTML tag </p> in prose
        When: tokenize() is called
        Then: the tag span produces INVALID_HTML
        """
        _require_module()
        tokens = tokenize("</p>")
        assert any(t.kind == TokenKind.INVALID_HTML for t in tokens)


class TestFoldedBulletDrift:
    """
    Verify the ADR-020 D4 folded-bullet drift heuristic.

    These fixtures mirror the two known cases from issue #225:
    - controls.yaml:257-262 (controlModelAndDataExecutionIntegrity)
    - risks.yaml riskSensitiveDataDisclosure longDescription[3][0]

    Given: a prose string that has been YAML-decoded from a folded scalar
           containing embedded "- item" lines (i.e., the author wrote a list
           inside a > folded scalar instead of using YAML array items)
    When: tokenize() is called
    Then: each embedded "- item" line produces INVALID_FOLDED_BULLET
    """

    @pytest.mark.parametrize("fixture_path", _FOLDED_BULLET_FIXTURES)
    def test_fixture_token_stream(self, fixture_path: str):
        """
        Given: input from folded_bullets/<name>.txt
        When: tokenize() is called
        Then: output matches folded_bullets/<name>.tokens.json exactly
        """
        input_text, expected = _load_fixture_pair(fixture_path)
        result = _tokens_to_dicts(tokenize(input_text))
        assert result == expected, f"Fixture {fixture_path!r}: expected {expected!r}, got {result!r}"

    def test_leading_dash_at_column_zero_is_list_not_folded(self):
        """
        Given: a line that starts "- item" at column 0 (no leading whitespace)
        When: tokenize() is called
        Then: it produces INVALID_LIST, not INVALID_FOLDED_BULLET

        This distinguishes a normal markdown list item from a folded-scalar
        continuation; the heuristic only fires when leading whitespace precedes
        the dash, indicating an embedded list inside a folded YAML scalar.
        """
        _require_module()
        tokens = tokenize("- plain list item")
        kinds = [t.kind for t in tokens]
        assert TokenKind.INVALID_LIST in kinds
        assert TokenKind.INVALID_FOLDED_BULLET not in kinds

    def test_indented_dash_inside_prose_is_folded_bullet(self):
        """
        Given: a string with leading whitespace before "- item"
        When: tokenize() is called
        Then: it produces INVALID_FOLDED_BULLET

        The leading whitespace signals folded-scalar embedding, not a top-level
        list marker.
        """
        _require_module()
        # Two spaces then dash-space: characteristic of folded-scalar indented content
        tokens = tokenize("  - embedded item")
        kinds = [t.kind for t in tokens]
        assert TokenKind.INVALID_FOLDED_BULLET in kinds

    def test_controls_yaml_known_drift_case(self):
        """
        Given: the exact folded-bullet text from controls.yaml:257-262
               (controlModelAndDataExecutionIntegrity.description[1])
        When: tokenize() is called
        Then: each embedded "- " line produces INVALID_FOLDED_BULLET

        This case is tracked as issue #225 and is the canonical known instance
        that motivated the heuristic. The input has already been YAML-decoded;
        the tokenizer receives a plain Python string.
        """
        _require_module()
        text = (
            "Examples include ...\n"
            "        - validating expected code and model signatures / hashes at inference-time\n"
            "        - limit and immutably record all modifications "
            "to runtime AI system components via oversight processes\n"
            "        - etc"
        )
        tokens = tokenize(text)
        folded_bullet_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_FOLDED_BULLET]
        assert len(folded_bullet_tokens) == 3, (
            f"Expected 3 INVALID_FOLDED_BULLET tokens, got {len(folded_bullet_tokens)}"
        )


class TestBareCamelCaseContext:
    """
    Verify the R4 bare-camelCase context-awareness cases.

    The tokenizer is called on prose strings only (YAML field-value context
    is the wrapper linter's responsibility). Within a prose string it must
    distinguish:

    1. riskFoo in prose                   → INVALID_CAMELCASE_ID
    2. {{riskPromptInjection}} in prose   → SENTINEL_INTRA only; no INVALID_CAMELCASE_ID
       (the inner identifier riskPromptInjection IS a bare-entity-prefix camelCase ID;
       it is suppressed because it is consumed by the sentinel match — this is the
       load-bearing test for R4 context-awareness)
    3. applesAreRed in prose              → TEXT, no flag (not an entity prefix)
    4. risk alone (lowercase)             → TEXT (no following capital)
    5. Risk at sentence start             → TEXT (capital prefix does not match)

    These five cases are the explicit acceptance criteria for R4 from the
    A3 issue draft.
    """

    @pytest.mark.parametrize("fixture_path", _BARE_CAMELCASE_FIXTURES)
    def test_fixture_token_stream(self, fixture_path: str):
        """
        Given: input from bare_camelcase/<name>.txt
        When: tokenize() is called
        Then: output matches bare_camelcase/<name>.tokens.json exactly
        """
        input_text, expected = _load_fixture_pair(fixture_path)
        result = _tokens_to_dicts(tokenize(input_text))
        assert result == expected, f"Fixture {fixture_path!r}: expected {expected!r}, got {result!r}"

    def test_r4_case1_bare_risk_id_in_prose_rejected(self):
        """
        R4 case 1: bare riskFoo in prose → INVALID_CAMELCASE_ID.

        Given: "see riskFoo for details"
        When: tokenize() is called
        Then: riskFoo produces INVALID_CAMELCASE_ID
        """
        _require_module()
        tokens = tokenize("see riskFoo for details")
        kinds = [t.kind for t in tokens]
        assert TokenKind.INVALID_CAMELCASE_ID in kinds
        camelcase_token = next(t for t in tokens if t.kind == TokenKind.INVALID_CAMELCASE_ID)
        assert camelcase_token.value == "riskFoo"

    def test_r4_case2_id_inside_sentinel_no_camelcase_flag(self):
        """
        R4 case 2: {{riskPromptInjection}} → SENTINEL_INTRA only; the inner
        identifier riskPromptInjection must NOT also produce INVALID_CAMELCASE_ID.

        This is the load-bearing R4 context-awareness test. The string
        "riskPromptInjection" IS a bare-entity-prefix camelCase identifier; in
        plain prose it would produce INVALID_CAMELCASE_ID. Inside the sentinel
        braces the lexer must consume it without flagging it, because the
        {{...}} context takes precedence.

        Given: "see {{riskPromptInjection}} for details"
        When: tokenize() is called
        Then: the stream contains SENTINEL_INTRA, not INVALID_CAMELCASE_ID
        """
        _require_module()
        tokens = tokenize("see {{riskPromptInjection}} for details")
        kinds = [t.kind for t in tokens]
        assert TokenKind.SENTINEL_INTRA in kinds
        assert TokenKind.INVALID_CAMELCASE_ID not in kinds

    def test_r4_case3_non_entity_camelcase_is_plain_text(self):
        """
        R4 case 3: applesAreRed (camelCase but not an entity prefix) → TEXT, no flag.

        Given: "applesAreRed is not a framework entity"
        When: tokenize() is called
        Then: no INVALID_CAMELCASE_ID token is produced
        """
        _require_module()
        tokens = tokenize("applesAreRed is not a framework entity")
        kinds = [t.kind for t in tokens]
        assert TokenKind.INVALID_CAMELCASE_ID not in kinds

    def test_r4_case4_lowercase_prefix_alone_is_text(self):
        """
        R4 case 4: "risk" alone with no following capital → TEXT.

        Given: "this is a risk to the system"
        When: tokenize() is called
        Then: no INVALID_CAMELCASE_ID token is produced for "risk"
        """
        _require_module()
        tokens = tokenize("this is a risk to the system")
        kinds = [t.kind for t in tokens]
        assert TokenKind.INVALID_CAMELCASE_ID not in kinds

    def test_r4_case5_capitalized_entity_word_at_sentence_start_is_text(self):
        """
        R4 case 5: "Risk" capitalized at sentence start → TEXT.

        The entity-prefix check matches lowercase-then-capital (riskXxx).
        "Risk" capitalized is not a valid entity-ID start.

        Given: "Risk is a concern here"
        When: tokenize() is called
        Then: no INVALID_CAMELCASE_ID token is produced
        """
        _require_module()
        tokens = tokenize("Risk is a concern here")
        kinds = [t.kind for t in tokens]
        assert TokenKind.INVALID_CAMELCASE_ID not in kinds

    def test_all_four_entity_prefixes_flagged_when_bare(self):
        """
        All four entity prefixes trigger INVALID_CAMELCASE_ID when bare in prose.

        Given: one bare camelCase ID for each entity prefix
        When: tokenize() is called on each
        Then: each produces INVALID_CAMELCASE_ID
        """
        _require_module()
        cases = [
            ("riskPromptInjection", "risk"),
            ("controlInputValidation", "control"),
            ("componentModelServing", "component"),
            ("personaModelCreator", "persona"),
        ]
        for bare_id, prefix in cases:
            tokens = tokenize(f"see {bare_id} here")
            kinds = [t.kind for t in tokens]
            assert TokenKind.INVALID_CAMELCASE_ID in kinds, (
                f"Expected INVALID_CAMELCASE_ID for bare {prefix} ID: {bare_id!r}"
            )


class TestMalformedSentinels:
    """
    Verify that malformed {{ }} constructs produce INVALID_SENTINEL.

    Given: a double-brace construct that fails the sentinel grammar
    When: tokenize() is called
    Then: the offending span produces INVALID_SENTINEL

    Malformed cases covered:
    - {{badFoo}} — structurally well-formed {{ }} but inner identifier does NOT start
      with a recognized entity prefix (risk|control|component|persona)
    - {{ref:}} — ref form with empty identifier
    - {{riskFoo (unclosed) — treated as TEXT (no closing }}; never a sentinel)
    - {{id{{ref:x}}}} — nested braces (outer construct is INVALID_SENTINEL)
    """

    @pytest.mark.parametrize("fixture_path", _MALFORMED_SENTINEL_FIXTURES)
    def test_fixture_token_stream(self, fixture_path: str):
        """
        Given: input from malformed_sentinels/<name>.txt
        When: tokenize() is called
        Then: output matches malformed_sentinels/<name>.tokens.json exactly
        """
        input_text, expected = _load_fixture_pair(fixture_path)
        result = _tokens_to_dicts(tokenize(input_text))
        assert result == expected, f"Fixture {fixture_path!r}: expected {expected!r}, got {result!r}"

    def test_no_entity_prefix_produces_invalid_sentinel(self):
        """
        Given: {{badFoo}} — structurally well-formed {{ }} but inner identifier does
        NOT start with a recognized entity prefix (risk|control|component|persona)
        When: tokenize() is called
        Then: INVALID_SENTINEL is produced, not SENTINEL_INTRA
        """
        _require_module()
        tokens = tokenize("{{badFoo}}")
        assert len(tokens) == 1
        assert tokens[0].kind == TokenKind.INVALID_SENTINEL

    def test_empty_ref_produces_invalid_sentinel(self):
        """
        Given: {{ref:}} with empty identifier
        When: tokenize() is called
        Then: INVALID_SENTINEL is produced, not SENTINEL_REF
        """
        _require_module()
        tokens = tokenize("{{ref:}}")
        assert len(tokens) == 1
        assert tokens[0].kind == TokenKind.INVALID_SENTINEL

    def test_unclosed_brace_is_plain_text(self):
        """
        Given: {{riskFoo with no closing }}
        When: tokenize() is called
        Then: the fragment is TEXT (no sentinel grammar match, no INVALID_SENTINEL)

        An unclosed {{ never forms a sentinel; the tokenizer does not project
        past the end of string to find a closing. This avoids treating every
        accidentally-placed double-brace as a lint violation.
        """
        _require_module()
        tokens = tokenize("{{riskFoo is unclosed")
        # All tokens should be TEXT; none should be INVALID_SENTINEL
        for token in tokens:
            assert token.kind == TokenKind.TEXT, f"Expected TEXT for unclosed brace, got {token!r}"


class TestNestingRules:
    """
    Verify bold nesting behaviour (ADR-017 D1: one nesting level).

    Representation decision (from module docstring):
    - **foo** → [BOLD("**foo**")]
    - **foo *bar* baz** → [BOLD("**foo *bar* baz**")]  (italic inside is OK; BOLD is atomic at outer level)
    - **foo **nested** bar** → tokenizer closes first BOLD at inner **, producing
      BOLD("**foo **") + TEXT("nested") + BOLD("** bar**")
      The wrapper linter sees a broken stream and rejects; but the tokenizer does not
      produce a single INVALID token for the whole span.
    """

    def test_simple_bold_single_token(self):
        """
        Given: **foo** (simple bold, no nesting)
        When: tokenize() is called
        Then: exactly one BOLD token with value "**foo**"
        """
        _require_module()
        tokens = tokenize("**foo**")
        assert len(tokens) == 1
        assert tokens[0].kind == TokenKind.BOLD
        assert tokens[0].value == "**foo**"

    def test_bold_with_italic_inside_is_single_bold_token(self):
        """
        Given: **foo *bar* baz** (italic nested inside bold — one level, allowed)
        When: tokenize() is called
        Then: exactly one BOLD token whose value is the entire span

        The BOLD is treated as atomic at the outer level. The italic-inside is
        permitted by ADR-017 D1 ("may contain plain text and italic") but the
        tokenizer does not sub-tokenize the bold interior.
        """
        _require_module()
        tokens = tokenize("**foo *bar* baz**")
        assert len(tokens) == 1
        assert tokens[0].kind == TokenKind.BOLD
        assert tokens[0].value == "**foo *bar* baz**"

    def test_nested_bold_produces_multiple_tokens(self):
        """
        Given: **foo **nested** bar** (bold nested inside bold — rejected)
        When: tokenize() is called
        Then: exactly 3 tokens: BOLD("**foo **"), TEXT("nested"), BOLD("** bar**")

        Representation decision (committed here for SWE): the tokenizer greedily
        consumes the first ** as bold-open. On encountering the second ** it closes
        the bold span, producing BOLD("**foo **"). The text between the second and
        third ** is TEXT("nested"). The third ** opens a new BOLD that closes at
        the fourth **, producing BOLD("** bar**").

        The exact token values:
          Token 0: BOLD,  value "**foo **"   (opens at first **, closes at second **)
          Token 1: TEXT,  value "nested"      (content between second and third **)
          Token 2: BOLD,  value "** bar**"   (opens at third **, closes at fourth **)

        The wrapper linter sees a stream where a BOLD token's value starts with "** "
        (BOLD[2] starts with "** "), signalling that something before it closed early;
        that is the detection signal for nested-bold rejection.

        Note: BOLD("**foo **") ends with a trailing space before the closing **.
        This matches greedy close-at-first-** semantics; the implementation
        must emit exactly this boundary. Any other segmentation is a spec deviation.
        """
        _require_module()
        tokens = tokenize("**foo **nested** bar**")
        assert len(tokens) == 3, f"Expected exactly 3 tokens for nested bold, got {len(tokens)}: {tokens!r}"
        assert tokens[0].kind == TokenKind.BOLD, f"Token 0: expected BOLD, got {tokens[0].kind!r}"
        assert tokens[0].value == "**foo **", f"Token 0: expected '**foo **', got {tokens[0].value!r}"
        assert tokens[1].kind == TokenKind.TEXT, f"Token 1: expected TEXT, got {tokens[1].kind!r}"
        assert tokens[1].value == "nested", f"Token 1: expected 'nested', got {tokens[1].value!r}"
        assert tokens[2].kind == TokenKind.BOLD, f"Token 2: expected BOLD, got {tokens[2].kind!r}"
        assert tokens[2].value == "** bar**", f"Token 2: expected '** bar**', got {tokens[2].value!r}"

    def test_simple_italic_single_token(self):
        """
        Given: *foo* (simple italic, asterisk delimiter)
        When: tokenize() is called
        Then: exactly one ITALIC token with value "*foo*"
        """
        _require_module()
        tokens = tokenize("*foo*")
        assert len(tokens) == 1
        assert tokens[0].kind == TokenKind.ITALIC
        assert tokens[0].value == "*foo*"

    def test_double_underscore_is_not_bold(self):
        """
        Given: __not bold__ (double-underscore form)
        When: tokenize() is called
        Then: no BOLD token is produced (ADR-017 D1 explicitly excludes __bold__)

        ADR-017 D1: "Asterisk delimiter only; __bold__ is NOT recognized."
        The double-underscore form must produce a TEXT token (or other non-BOLD
        token) regardless of how many underscores surround the content. The
        exact non-BOLD shape is not constrained; the implementation may produce
        TEXT("__not bold__") or TEXT("__") + TEXT("not bold") + TEXT("__") etc.
        """
        _require_module()
        tokens = tokenize("__not bold__")
        assert all(t.kind != TokenKind.BOLD for t in tokens), (
            f"__bold__ form must not produce BOLD per ADR-017 D1; got {tokens!r}"
        )

    def test_sentinel_inside_bold_representation(self):
        """
        Given: **{{riskPromptInjection}}** (sentinel wrapped in bold asterisks)
        When: tokenize() is called
        Then: the whole span tokenizes as a single BOLD token

        Representation decision (Minor M3):
        ADR-017 D1 says "Sentinels are atomic identifier tokens; they do not
        nest into bold or italic." The ADR says authors *should not* write this
        form, but does not mandate a specific tokenizer error. The atomic-bold
        rule is committed here: the BOLD match wins and the sentinel is
        swallowed inside the BOLD token's value. This is the easier path to
        implement (the bold regex fires first) and easier to detect downstream
        (a BOLD whose inner content is a sentinel is an authoring style
        violation, not a grammar error — the wrapper linter may warn on it
        separately).

        Expected stream: [BOLD("**{{riskPromptInjection}}**")]

        If sentinel-punches-through semantics (i.e.,
        BOLD("**") + SENTINEL_INTRA("{{riskPromptInjection}}") + BOLD("**"))
        prove significantly easier to implement and equally detectable
        downstream, the test and docstring should be updated to match the
        chosen shape. The assertion below encodes the atomic-bold choice.
        """
        _require_module()
        tokens = tokenize("**{{riskPromptInjection}}**")
        assert len(tokens) == 1, f"Expected 1 token (atomic-bold wins), got {len(tokens)}: {tokens!r}"
        assert tokens[0].kind == TokenKind.BOLD, f"Expected BOLD for **{{sentinel}}**, got {tokens[0].kind!r}"
        assert tokens[0].value == "**{{riskPromptInjection}}**", (
            f"Expected full span as value, got {tokens[0].value!r}"
        )


class TestMixedRuns:
    """
    Verify that mixed accepting and rejecting tokens come out in source order
    with no elision.

    The token stream is a partition of the input: every character in the input
    string appears in exactly one token's value, and concatenating all token
    values reconstructs the original input.
    """

    def test_tokens_cover_full_input(self):
        """
        Given: a set of representative inputs including plain text, bold, bare
               camelCase IDs, raw URLs, and sentinels
        When: tokenize() is called on each
        Then: concatenation of all token values equals the original input
              (partition-of-input invariant)

        Inputs exercised:
          - "plain text **bold** more text"  — TEXT and BOLD tokens
          - "see riskFoo and https://example.com here"  — INVALID_CAMELCASE_ID,
            INVALID_URL, and TEXT tokens
          - "{{riskPromptInjection}} mitigated by **strong** control"  — SENTINEL_INTRA,
            BOLD, and TEXT tokens
        """
        _require_module()
        inputs = [
            "plain text **bold** more text",
            "see riskFoo and https://example.com here",
            "{{riskPromptInjection}} mitigated by **strong** control",
        ]
        for text in inputs:
            tokens = tokenize(text)
            reconstructed = "".join(t.value for t in tokens)
            assert reconstructed == text, (
                f"Token values do not reconstruct input.\n"
                f"  Input:         {text!r}\n"
                f"  Reconstructed: {reconstructed!r}\n"
                f"  Tokens:        {tokens!r}"
            )

    def test_accepting_and_rejecting_tokens_in_source_order(self):
        """
        Given: a string with both accepting and rejecting tokens
        When: tokenize() is called
        Then: tokens appear in the order their values appear in the source string

        The source string has: TEXT, BOLD, TEXT, INVALID_URL, TEXT.
        """
        _require_module()
        text = "some **bold** and https://example.com here"
        tokens = tokenize(text)
        # Find positions of each token value in the original string
        pos = 0
        for token in tokens:
            idx = text.find(token.value, pos)
            assert idx != -1, f"Token value {token.value!r} not found at or after pos {pos}"
            assert idx >= pos, f"Token {token!r} appears before position {pos} — out of source order"
            pos = idx + len(token.value)

    def test_mixed_run_fixture(self):
        """
        Given: accepting/mixed_accepting_run fixture (plain + bold + italic)
        When: tokenize() is called
        Then: stream matches fixture exactly and values reconstruct the input
        """
        input_text, expected = _load_fixture_pair("accepting/mixed_accepting_run")
        tokens = tokenize(input_text)
        result = _tokens_to_dicts(tokens)
        assert result == expected
        reconstructed = "".join(t.value for t in tokens)
        assert reconstructed == input_text


class TestCategoricalUrlRejection:
    """
    Verify ADR-017 D4 rule 2: categorical inline-URL rejection.

    The rule has two components:
      1. Primary — scheme-with-authority regex: \\b[a-z][a-z0-9+.\\-]*://\\S+
         Catches every RFC-3986 authority-bearing scheme: ftp://, file://, gs://,
         s3://, ssh://, git+https://, and any future scheme matching the character
         class. The existing http:// / https:// coverage is a strict subset.
      2. Secondary — opaque-data named list for colon-only schemes that have no
         // authority component and would escape the primary regex: mailto:,
         javascript:, data:, tel:. The named list is non-exhaustive by design;
         adding to it is a tokenizer change with a one-line ADR amendment.

    Case-sensitivity: case-insensitive matching applies. Real authors write
    HTTP://, MAILTO:, Ftp:// etc. (typically copy-pasted from vendor docs or
    browser address bars). A purely lowercase-anchored regex would silently
    pass HTTP:// as TEXT, defeating the categorical intent. Tests for uppercase
    and mixed-case forms assert INVALID_URL, which requires case folding
    (re.IGNORECASE, str.lower() pre-check, or an alternation) before both the
    primary-regex and named-list checks.

    Token emitted on rejection: INVALID_URL (existing kind, line 56 of
    _prose_tokens.py). No new TokenKind is introduced — the URL rejection
    category is INVALID_URL regardless of which scheme triggered the rule.

    Existing http:// / https:// regression tests are in TestRejectingTokens;
    this class adds the new-scheme coverage without duplicating those.
    """

    # ------------------------------------------------------------------
    # Primary-regex fixtures (scheme-with-authority)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("fixture_path", _URL_PRIMARY_SCHEME_FIXTURES)
    def test_primary_scheme_fixture_token_stream(self, fixture_path: str):
        """
        Given: input from rejecting/<name>.txt containing a non-http/https scheme URL
        When: tokenize() is called
        Then: output matches rejecting/<name>.tokens.json exactly (INVALID_URL for the URL span)
        """
        input_text, expected = _load_fixture_pair(fixture_path)
        result = _tokens_to_dicts(tokenize(input_text))
        assert result == expected, f"Fixture {fixture_path!r}: expected {expected!r}, got {result!r}"

    @pytest.mark.parametrize("fixture_path", _URL_PRIMARY_SCHEME_FIXTURES)
    def test_primary_scheme_fixture_has_invalid_url_token(self, fixture_path: str):
        """
        Given: a primary-scheme fixture input
        When: tokenize() is called
        Then: at least one token has kind INVALID_URL
        """
        input_text, _ = _load_fixture_pair(fixture_path)
        assert any(t.kind == TokenKind.INVALID_URL for t in tokenize(input_text)), (
            f"Fixture {fixture_path!r}: expected INVALID_URL token, got none"
        )

    def test_ftp_url_in_prose_emits_invalid_url_token(self):
        """
        Given: "ftp://example.com/file" in prose (dead-scheme drift signal)
        When: tokenize() is called
        Then: INVALID_URL token with value "ftp://example.com/file"

        ftp:// is a dead-scheme in modern browsers; its presence in YAML prose
        indicates a URL that belongs in externalReferences per ADR-016.
        """
        _require_module()
        tokens = tokenize("see ftp://example.com/file here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "ftp:// URL must produce INVALID_URL"
        assert url_tokens[0].value == "ftp://example.com/file"

    def test_file_url_in_prose_emits_invalid_url_token(self):
        """
        Given: "file:///etc/passwd" in prose
        When: tokenize() is called
        Then: INVALID_URL token with value "file:///etc/passwd"

        file:// URLs have no valid use in YAML prose; they are local-path
        references that are useless in a browser context and a local-path
        exposure vector.
        """
        _require_module()
        tokens = tokenize("see file:///etc/passwd here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "file:// URL must produce INVALID_URL"
        assert url_tokens[0].value == "file:///etc/passwd"

    def test_gs_url_in_prose_emits_invalid_url_token(self):
        """
        Given: "gs://bucket/key" in prose (Google Cloud Storage)
        When: tokenize() is called
        Then: INVALID_URL token with value "gs://bucket/key"

        Cloud storage references belong in the structured externalReferences
        field per ADR-014 P3 / ADR-016 D4. The gs:// scheme is specifically
        called out in ADR-016 D4 as a legitimate cloud reference that still
        belongs in the structured field.
        """
        _require_module()
        tokens = tokenize("see gs://bucket/key here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "gs:// URL must produce INVALID_URL"
        assert url_tokens[0].value == "gs://bucket/key"

    def test_s3_url_in_prose_emits_invalid_url_token(self):
        """
        Given: "s3://bucket/key.tar.gz" in prose (AWS S3)
        When: tokenize() is called
        Then: INVALID_URL token with value "s3://bucket/key.tar.gz"
        """
        _require_module()
        tokens = tokenize("see s3://bucket/key.tar.gz here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "s3:// URL must produce INVALID_URL"
        assert url_tokens[0].value == "s3://bucket/key.tar.gz"

    def test_ssh_url_in_prose_emits_invalid_url_token(self):
        """
        Given: "ssh://user@host:22/path" in prose
        When: tokenize() is called
        Then: INVALID_URL token with value "ssh://user@host:22/path"
        """
        _require_module()
        tokens = tokenize("see ssh://user@host:22/path here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "ssh:// URL must produce INVALID_URL"
        assert url_tokens[0].value == "ssh://user@host:22/path"

    def test_git_plus_https_url_emits_invalid_url_token(self):
        """
        Given: "git+https://github.com/user/repo" in prose
        When: tokenize() is called
        Then: INVALID_URL token containing the full URL

        The '+' character in the scheme proves the [a-z0-9+.\\-]* character
        class in the primary regex; the scheme character class must not be
        restricted to [a-z0-9] only.
        """
        _require_module()
        tokens = tokenize("see git+https://github.com/user/repo here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "git+https:// URL must produce INVALID_URL"
        assert url_tokens[0].value == "git+https://github.com/user/repo"

    def test_scheme_with_dash_emits_invalid_url_token(self):
        """
        Given: "myscheme-v2://something" in prose
        When: tokenize() is called
        Then: INVALID_URL token with value "myscheme-v2://something"

        The '-' character in the scheme proves the [a-z0-9+.\\-]* character
        class (dash). Future schemes like 'coap+tcp://' also rely on this.
        """
        _require_module()
        tokens = tokenize("see myscheme-v2://something here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "myscheme-v2:// must produce INVALID_URL"
        assert url_tokens[0].value == "myscheme-v2://something"

    def test_scheme_with_dot_emits_invalid_url_token(self):
        """
        Given: "myscheme.2://something" in prose
        When: tokenize() is called
        Then: INVALID_URL token with value "myscheme.2://something"

        The '.' character in the scheme proves the [a-z0-9+.\\-]* character
        class (dot). RFC-3986 allows dots in scheme names.
        """
        _require_module()
        tokens = tokenize("see myscheme.2://something here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "myscheme.2:// must produce INVALID_URL"
        assert url_tokens[0].value == "myscheme.2://something"

    # ------------------------------------------------------------------
    # Named-list fixtures (opaque-data, no // authority)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("fixture_path", _URL_OPAQUE_DATA_FIXTURES)
    def test_opaque_scheme_fixture_token_stream(self, fixture_path: str):
        """
        Given: input from rejecting/<name>.txt containing an opaque-data scheme
        When: tokenize() is called
        Then: output matches rejecting/<name>.tokens.json exactly (INVALID_URL for the span)
        """
        input_text, expected = _load_fixture_pair(fixture_path)
        result = _tokens_to_dicts(tokenize(input_text))
        assert result == expected, f"Fixture {fixture_path!r}: expected {expected!r}, got {result!r}"

    @pytest.mark.parametrize("fixture_path", _URL_OPAQUE_DATA_FIXTURES)
    def test_opaque_scheme_fixture_has_invalid_url_token(self, fixture_path: str):
        """
        Given: an opaque-data fixture input
        When: tokenize() is called
        Then: at least one token has kind INVALID_URL
        """
        input_text, _ = _load_fixture_pair(fixture_path)
        assert any(t.kind == TokenKind.INVALID_URL for t in tokenize(input_text)), (
            f"Fixture {fixture_path!r}: expected INVALID_URL token, got none"
        )

    def test_mailto_plain_emits_invalid_url_token(self):
        """
        Given: "mailto:user@example.com" in prose
        When: tokenize() is called
        Then: INVALID_URL token with value "mailto:user@example.com"

        mailto: is a contact-exposure vector; it resolves to the user's mail
        client in browsers. All contact references belong in externalReferences.
        """
        _require_module()
        tokens = tokenize("contact mailto:user@example.com here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "mailto: must produce INVALID_URL"
        assert url_tokens[0].value == "mailto:user@example.com"

    def test_mailto_with_query_emits_invalid_url_token(self):
        """
        Given: "mailto:user@example.com?subject=Hello" in prose
        When: tokenize() is called
        Then: INVALID_URL token covering the full mailto: span including query string
        """
        _require_module()
        tokens = tokenize("contact mailto:user@example.com?subject=Hello here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "mailto: with query must produce INVALID_URL"
        assert url_tokens[0].value == "mailto:user@example.com?subject=Hello"

    def test_javascript_scheme_emits_invalid_url_token(self):
        """
        Given: "javascript:alert(1)" in prose
        When: tokenize() is called
        Then: INVALID_URL token with value "javascript:alert(1)"

        javascript: is an XSS vector; it executes script when used as an href.
        The named list catches it as a defense-in-depth measure even if the
        primary regex would also match (javascript: lacks //; primary regex
        requires ://).
        """
        _require_module()
        tokens = tokenize("avoid javascript:alert(1) here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "javascript: must produce INVALID_URL"
        assert url_tokens[0].value == "javascript:alert(1)"

    def test_data_uri_emits_invalid_url_token(self):
        """
        Given: "data:image/png;base64,iVBORw0KGgo..." in prose
        When: tokenize() is called
        Then: INVALID_URL token covering the full data: span

        data: URIs are an XSS vector via the data URI scheme; they embed
        executable content directly in prose.
        """
        _require_module()
        tokens = tokenize("avoid data:image/png;base64,iVBORw0KGgo... here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "data: URI must produce INVALID_URL"
        assert url_tokens[0].value == "data:image/png;base64,iVBORw0KGgo..."

    def test_tel_scheme_emits_invalid_url_token(self):
        """
        Given: "tel:+1-555-0100" in prose
        When: tokenize() is called
        Then: INVALID_URL token with value "tel:+1-555-0100"

        tel: is a contact-exposure vector; it resolves to the device's phone
        dialler in mobile browsers.
        """
        _require_module()
        tokens = tokenize("call tel:+1-555-0100 here")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert url_tokens, "tel: must produce INVALID_URL"
        assert url_tokens[0].value == "tel:+1-555-0100"

    # ------------------------------------------------------------------
    # Boundary and edge cases
    # ------------------------------------------------------------------

    def test_uppercase_http_rejected_case_insensitively(self):
        """
        Given: "HTTP://EXAMPLE.COM" in prose (uppercase scheme)
        When: tokenize() is called
        Then: INVALID_URL token is produced

        Case-sensitivity: case-insensitive matching applies. Real-world authors
        write HTTP://, HTTPS://, MAILTO: etc. A lowercase-only rule would
        silently pass these as TEXT, defeating the categorical intent of
        ADR-017 D4 rule 2. Implementations must apply case-insensitive detection
        (re.IGNORECASE flag or str.lower() pre-check).
        """
        _require_module()
        tokens = tokenize("see HTTP://EXAMPLE.COM here")
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "HTTP:// (uppercase) must produce INVALID_URL (case-insensitive rule)"
        )

    def test_uppercase_mailto_rejected_case_insensitively(self):
        """
        Given: "MAILTO:user@example.com" in prose (uppercase opaque scheme)
        When: tokenize() is called
        Then: INVALID_URL token is produced

        Same case-sensitivity decision as for scheme-with-authority URLs.
        The named list must be matched case-insensitively.
        """
        _require_module()
        tokens = tokenize("contact MAILTO:user@example.com here")
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "MAILTO: (uppercase) must produce INVALID_URL (case-insensitive rule)"
        )

    def test_mixed_case_ftp_rejected_case_insensitively(self):
        """
        Given: "Ftp://example.com" in prose (mixed-case scheme)
        When: tokenize() is called
        Then: INVALID_URL token is produced

        Case normalisation applies to the scheme part regardless of the case
        pattern. Ftp://, FTP://, fTp:// are all the same scheme.
        """
        _require_module()
        tokens = tokenize("see Ftp://example.com here")
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "Ftp:// (mixed case) must produce INVALID_URL (case-insensitive rule)"
        )

    def test_ftp_url_inside_bold_is_flagged(self):
        """
        Given: "**ftp://example.com**" (URL inside bold span)
        When: tokenize() is called
        Then: INVALID_URL token is produced OR the BOLD token value contains the URL

        This test is permissive: it accepts either of two implementation
        choices — emitting INVALID_URL nested inside the bold span, or
        absorbing the URL into the BOLD token's value. The current tokenizer
        absorbs into BOLD. Once a follow-up decides whether URL detection
        inside bold spans belongs at the tokenizer level or in the wrapper
        linter, a tighter assertion can replace this one.
        """
        _require_module()
        tokens = tokenize("**ftp://example.com**")
        has_invalid_url = any(t.kind == TokenKind.INVALID_URL for t in tokens)
        # If BOLD swallows the URL, check the BOLD token's value contains it
        has_url_in_bold = any(t.kind == TokenKind.BOLD and "ftp://" in t.value for t in tokens)
        assert has_invalid_url or has_url_in_bold, (
            "ftp:// URL inside **bold** must be detectable — "
            "either as INVALID_URL token or embedded in BOLD token value"
        )

    def test_mailto_inside_italic_is_flagged(self):
        """
        Given: "*mailto:foo@bar*" (opaque-scheme URL inside italic span)
        When: tokenize() is called
        Then: INVALID_URL token is produced OR the ITALIC token value contains the URL

        This test is permissive: it accepts either of two implementation
        choices — emitting INVALID_URL nested inside the italic span, or
        absorbing the URL into the ITALIC token's value. The current
        tokenizer absorbs into ITALIC. Once a follow-up decides whether URL
        detection inside italic spans belongs at the tokenizer level or in
        the wrapper linter, a tighter assertion can replace this one.
        """
        _require_module()
        tokens = tokenize("*mailto:foo@bar*")
        has_invalid_url = any(t.kind == TokenKind.INVALID_URL for t in tokens)
        has_url_in_italic = any(t.kind == TokenKind.ITALIC and "mailto:" in t.value for t in tokens)
        assert has_invalid_url or has_url_in_italic, (
            "mailto: URL inside *italic* must be detectable — "
            "either as INVALID_URL token or embedded in ITALIC token value"
        )

    def test_url_adjacent_to_sentinel_both_processed(self):
        """
        Given: "See {{ref:cve-2024-1234}} or ftp://backup"
               (sentinel in first span, URL in tail text)
        When: tokenize() is called
        Then: stream contains SENTINEL_REF and INVALID_URL as separate tokens;
              the sentinel resolves first without interference from the URL

        This tests that the sentinel-first precedence model does not suppress
        URL detection in the trailing text.
        """
        _require_module()
        tokens = tokenize("See {{ref:cve-2024-1234}} or ftp://backup")
        kinds = [t.kind for t in tokens]
        assert TokenKind.SENTINEL_REF in kinds, "Expected SENTINEL_REF in stream"
        assert TokenKind.INVALID_URL in kinds, "Expected INVALID_URL for ftp:// in tail text after sentinel"

    def test_ref_colon_inside_sentinel_does_not_trip_named_list(self):
        """
        Given: "{{ref:cwe-89}}" (ref: prefix inside sentinel braces)
        When: tokenize() is called
        Then: stream contains SENTINEL_REF, NOT INVALID_URL

        The 'ref:' prefix lives inside the sentinel braces. The named-list
        rule must not match it, because the sentinel tokenisation runs first
        at higher precedence (Rule 11 before URL rules). This is a regression
        guard for the named-list implementation: naive substring matching on
        ':' would misfire on valid sentinel syntax.
        """
        _require_module()
        tokens = tokenize("{{ref:cwe-89}}")
        kinds = [t.kind for t in tokens]
        assert TokenKind.SENTINEL_REF in kinds, "Expected SENTINEL_REF for {{ref:cwe-89}}"
        assert TokenKind.INVALID_URL not in kinds, "ref: inside sentinel must NOT produce INVALID_URL"

    def test_unknown_scheme_at_start_of_string_is_rejected(self):
        """
        Given: "xftp://example.com" (unknown scheme name "xftp" at start of string)
        When: tokenize() is called
        Then: INVALID_URL token with value "xftp://example.com"

        Per ADR-017 D4 rule 2, the categorical regex
        \\b[a-z][a-z0-9+.\\-]*:// rejects any RFC-3986 authority-bearing
        scheme — known or unknown. "xftp" is a syntactically valid scheme
        name; the rule is intentionally scheme-name-agnostic, because the
        architectural answer is the same in every case: a scheme in prose
        means a structured externalReferences entry was missed (ADR-016 D4).
        Start-of-string is always a word boundary, so the \\b anchor fires.
        """
        _require_module()
        tokens = tokenize("xftp://example.com")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert len(url_tokens) == 1, (
            f"xftp://example.com must produce exactly one INVALID_URL; got {len(url_tokens)}"
        )
        assert url_tokens[0].value == "xftp://example.com", (
            f"INVALID_URL value must be the full URL; got {url_tokens[0].value!r}"
        )

    def test_scheme_with_space_after_authority_separator_not_matched(self):
        """
        Given: "ftp:// example.com" (space immediately after ://)
        When: tokenize() is called
        Then: NO INVALID_URL token is produced

        The primary regex uses \\S+ after ://, requiring at least one
        non-whitespace character immediately after the authority separator.
        "ftp:// example.com" has a space at that position; the regex should
        not match, and the text should pass through as TEXT tokens.

        This prevents false positives on prose like "two colons: // in text".
        """
        _require_module()
        tokens = tokenize("ftp:// example.com")
        assert not any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "ftp:// with trailing space (no authority) must NOT produce INVALID_URL"
        )

    def test_mailto_alone_with_trailing_space_not_matched(self):
        """
        Given: "mailto: " (opaque scheme token with no recipient, trailing space)
        When: tokenize() is called
        Then: NO INVALID_URL token is produced

        The named-list rule must match a complete mailto: token that has
        content after the colon. "mailto:" followed by whitespace has no
        recipient and is an incomplete, harmless fragment. This prevents
        false positives if an author writes e.g. "the mailto: scheme is..."

        Implementation note: the exact boundary is implementation-defined.
        The rule may require at least one non-whitespace char after the colon
        (similar to \\S+ for the primary regex). Lock in non-rejection here.
        """
        _require_module()
        tokens = tokenize("the mailto: scheme")
        assert not any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "'mailto: ' (no recipient, trailing space) must NOT produce INVALID_URL"
        )

    def test_ftp_url_at_start_of_string_emits_invalid_url(self):
        """
        Given: "ftp://example.com is gone now." (URL at start of paragraph)
        When: tokenize() is called
        Then: INVALID_URL token at position 0 in the stream
        """
        _require_module()
        tokens = tokenize("ftp://example.com is gone now.")
        assert tokens[0].kind == TokenKind.INVALID_URL, (
            f"URL at start of string must be the first token; got {tokens[0]!r}"
        )

    def test_s3_url_at_end_of_string_emits_invalid_url(self):
        """
        Given: "Use the s3://bucket reference." (URL at end of paragraph)
        When: tokenize() is called
        Then: INVALID_URL token appears in the stream; the trailing '.' is absorbed
              into the URL or left as TEXT — either is acceptable, but INVALID_URL
              must be present
        """
        _require_module()
        tokens = tokenize("Use the s3://bucket reference.")
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "s3:// URL at end of string must produce INVALID_URL"
        )

    def test_multiple_urls_per_paragraph_both_flagged(self):
        """
        Given: "Try ftp://a or gs://b" (two URLs in one paragraph)
        When: tokenize() is called
        Then: exactly two INVALID_URL tokens are produced, one per URL

        This verifies that the tokenizer does not stop at the first URL
        rejection and that the partition-of-input invariant holds for
        multi-URL inputs.
        """
        _require_module()
        tokens = tokenize("Try ftp://a or gs://b")
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert len(url_tokens) == 2, (
            f"Expected 2 INVALID_URL tokens for two URLs, got {len(url_tokens)}: {url_tokens!r}"
        )
        values = {t.value for t in url_tokens}
        assert "ftp://a" in values, f"Expected ftp://a in INVALID_URL values; got {values!r}"
        assert "gs://b" in values, f"Expected gs://b in INVALID_URL values; got {values!r}"

    # ------------------------------------------------------------------
    # Gap 1 — git+https full-token value (scheme-prefix lock)
    # ------------------------------------------------------------------

    def test_git_plus_https_full_token_value(self):
        """
        Given: "see git+https://github.com/user/repo for more"
        When: tokenize() is called
        Then: exactly one INVALID_URL token whose value is the full
              "git+https://github.com/user/repo" string (prefix included)

        This test locks in that the `git+` prefix is treated as part of the
        scheme and therefore part of the token value. The existing tokenizer's
        narrow `https?://\\S+` regex partial-matches the `https://github.com/user/repo`
        substring inside `git+https://github.com/user/repo` (splitting at the `+`),
        producing INVALID_URL("https://github.com/user/repo") — missing the `git+`
        prefix. The categorical regex `\\b[a-z][a-z0-9+.\\-]*://\\S+` must
        produce exactly one token with value "git+https://github.com/user/repo".

        The parametrized `test_primary_scheme_fixture_has_invalid_url_token` for
        `rejecting/url_scheme_plus` passes against a narrow `https?://` regex
        because `any(kind == INVALID_URL)` fires on the partial match. This
        standalone test closes that leak by asserting the exact token value.
        """
        _require_module()
        tokens = list(tokenize("see git+https://github.com/user/repo for more"))
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert len(url_tokens) == 1, f"Expected exactly 1 INVALID_URL token, got {len(url_tokens)}: {url_tokens!r}"
        assert url_tokens[0].value == "git+https://github.com/user/repo", (
            f"Expected full git+https:// token value; got {url_tokens[0].value!r} "
            "(existing tokenizer produces 'https://...' without the 'git+' prefix)"
        )

    # ------------------------------------------------------------------
    # Gap 2 — trailing punctuation absorbed by \S+ greediness
    # ------------------------------------------------------------------

    def test_url_at_end_of_sentence_absorbs_trailing_period(self):
        """
        Given: "Visit ftp://example.com." (URL exactly at end of string, period terminates)
        When: tokenize() is called
        Then: INVALID_URL token value is "ftp://example.com." (period IS part of the value)

        Architectural decision: lock in the simpler greedy-with-period-absorbed
        behaviour. The primary regex `\\S+` is non-whitespace greedy and includes the
        trailing period. No special-case stripping logic is required — the linter
        rejects the URL regardless of whether the period is part of the value; the
        token value is for diagnostic output only.

        The fixture `rejecting/url_ftp_trailing_period` encodes the same decision for
        the mid-sentence variant ("ftp://example.com. for more"). This inline test
        covers the end-of-string variant where no trailing text follows the period.
        """
        _require_module()
        tokens = list(tokenize("Visit ftp://example.com."))
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        assert len(url_tokens) == 1, f"Expected exactly 1 INVALID_URL token, got {len(url_tokens)}: {url_tokens!r}"
        assert url_tokens[0].value == "ftp://example.com.", (
            f"Expected period absorbed into URL value; got {url_tokens[0].value!r}"
        )

    # ------------------------------------------------------------------
    # Gap 3 — URL-then-sentinel with no space (sentinel precedence)
    # ------------------------------------------------------------------

    def test_url_followed_immediately_by_sentinel_does_not_absorb_sentinel(self):
        """
        Given: "see ftp://example.com{{ref:cve-2024-1234}} done"
               (URL and sentinel adjacent with no space between them)
        When: tokenize() is called
        Then: exactly one INVALID_URL token with value "ftp://example.com" (stops at {),
              and a SENTINEL_REF token for {{ref:cve-2024-1234}};
              the URL token must NOT absorb the sentinel characters

        This locks in the representational decision that sentinel tokenisation runs
        first (higher precedence) over URL-regex greediness. Without this, `\\S+` in
        the primary regex would absorb the entire `{{ref:cve-2024-1234}}` suffix into
        the URL token value, swallowing the sentinel and suppressing SENTINEL_REF.

        Precedence source: project_a3_launch_context.md locked representational
        decision — "sentinel tokenisation runs first".
        """
        _require_module()
        tokens = list(tokenize("see ftp://example.com{{ref:cve-2024-1234}} done"))
        url_tokens = [t for t in tokens if t.kind == TokenKind.INVALID_URL]
        sentinel_tokens = [t for t in tokens if t.kind == TokenKind.SENTINEL_REF]
        assert len(url_tokens) == 1, f"Expected exactly 1 INVALID_URL token, got {len(url_tokens)}: {url_tokens!r}"
        assert url_tokens[0].value == "ftp://example.com", (
            f"URL token must stop at the sentinel boundary; got {url_tokens[0].value!r} "
            "(if sentinel chars were absorbed, value would contain '{{ref:...')"
        )
        assert len(sentinel_tokens) == 1, (
            f"Expected exactly 1 SENTINEL_REF token, got {len(sentinel_tokens)}: {sentinel_tokens!r}; "
            "sentinel must not be swallowed by URL greediness"
        )

    # ------------------------------------------------------------------
    # Negative cases — must NOT produce INVALID_URL
    # These lock in the "named list is non-exhaustive" boundary per
    # ADR-017 D4 rule 2 ("at minimum" wording).
    # ------------------------------------------------------------------

    def test_urn_scheme_not_in_named_list_is_allowed(self):
        """
        Given: "urn:cve:2024:1234" in prose
        When: tokenize() is called
        Then: NO INVALID_URL token is produced

        urn: is NOT in the named list at minimum {mailto:, javascript:, data:, tel:}.
        Current behaviour is to pass it as TEXT. This test locks in that boundary
        and documents the intentional gap: adding urn: to the named list is a
        future tokenizer change + one-line ADR amendment per ADR-017 D4 rule 2.
        If urn: is added to the named list, this test must be updated to
        expect INVALID_URL and the ADR amendment cited.
        """
        _require_module()
        tokens = tokenize("see urn:cve:2024:1234 here")
        assert not any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "urn: is not in the named list (non-exhaustive by design); must NOT produce INVALID_URL"
        )

    def test_doi_scheme_not_in_named_list_is_allowed(self):
        """
        Given: "doi:10.1234/foo" in prose
        When: tokenize() is called
        Then: NO INVALID_URL token is produced

        doi: is a scholarly-citation scheme not in the named list. Same
        intentional-gap rationale as urn:.
        """
        _require_module()
        tokens = tokenize("see doi:10.1234/foo here")
        assert not any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "doi: is not in the named list; must NOT produce INVALID_URL"
        )

    def test_isbn_scheme_not_in_named_list_is_allowed(self):
        """
        Given: "isbn:978-0-306-40615-7" in prose
        When: tokenize() is called
        Then: NO INVALID_URL token is produced
        """
        _require_module()
        tokens = tokenize("see isbn:978-0-306-40615-7 here")
        assert not any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "isbn: is not in the named list; must NOT produce INVALID_URL"
        )

    def test_arn_scheme_not_in_named_list_is_allowed(self):
        """
        Given: "arn:aws:s3:::bucket" in prose
        When: tokenize() is called
        Then: NO INVALID_URL token is produced

        ARN identifiers are used in AWS contexts. arn: has no // component
        and is not in the named list. Architects noted that cloud references
        belong in externalReferences (ADR-016 D4), but the enforcement path
        is the named list, which does not yet include arn:. Lock in current
        behaviour with this note.
        """
        _require_module()
        tokens = tokenize("see arn:aws:s3:::bucket here")
        assert not any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "arn: is not in the named list; must NOT produce INVALID_URL"
        )

    def test_colon_after_category_word_is_not_a_scheme(self):
        """
        Given: "Category: subcategory" (colon after a word, space follows)
        When: tokenize() is called
        Then: NO INVALID_URL token is produced

        A colon followed by a space is a common prose pattern (e.g., headers,
        enumeration labels). The named list must not fire on arbitrary words
        that contain a colon.
        """
        _require_module()
        tokens = tokenize("Category: subcategory")
        assert not any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "'Category: subcategory' must not produce INVALID_URL — colon-space is not a scheme"
        )

    def test_double_colon_is_not_a_scheme(self):
        """
        Given: "time::now" (double colon, C++ scope-resolution style)
        When: tokenize() is called
        Then: NO INVALID_URL token is produced

        A double colon (::) has no scheme structure. The primary regex requires
        :// and the named list matches specific scheme prefixes with a single
        colon; neither should match :: alone.
        """
        _require_module()
        tokens = tokenize("time::now")
        assert not any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "'time::now' must not produce INVALID_URL — :: is not a URI scheme separator"
        )

    # ------------------------------------------------------------------
    # Regression — existing http/https/markdown-link coverage must hold
    # ------------------------------------------------------------------

    def test_regression_http_still_produces_invalid_url(self):
        """
        Regression: existing http:// detection must still fire after the
        categorical rule replaces the narrow _RE_RAW_URL = re.compile(r'https?://\\S+').

        Given: "http://example.com" in prose
        When: tokenize() is called
        Then: INVALID_URL token (identical behaviour to current tokenizer)
        """
        _require_module()
        tokens = tokenize("http://example.com")
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "http:// regression: must still produce INVALID_URL after categorical rule lands"
        )

    def test_regression_https_still_produces_invalid_url(self):
        """
        Regression: existing https:// detection must still fire.

        Given: "https://example.com" in prose
        When: tokenize() is called
        Then: INVALID_URL token
        """
        _require_module()
        tokens = tokenize("https://example.com")
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "https:// regression: must still produce INVALID_URL after categorical rule lands"
        )

    def test_regression_markdown_link_still_produces_invalid_url(self):
        """
        Regression: existing [text](url) markdown-link detection must still fire.

        Given: "[click here](https://example.com)" in prose
        When: tokenize() is called
        Then: INVALID_URL token covering the full [text](url) span
        """
        _require_module()
        tokens = tokenize("[click here](https://example.com)")
        assert any(t.kind == TokenKind.INVALID_URL for t in tokens), (
            "markdown link regression: must still produce INVALID_URL after categorical rule lands"
        )


class TestEmptyAndWhitespace:
    """
    Verify edge cases: empty string, whitespace-only, single-character inputs.

    Given: minimal or degenerate inputs
    When: tokenize() is called
    Then: returns a list (possibly empty or containing TEXT) without raising
    """

    def test_empty_string_returns_empty_list(self):
        """
        Given: an empty string ""
        When: tokenize() is called
        Then: returns [] (no tokens to emit for empty input)
        """
        _require_module()
        result = tokenize("")
        assert result == []

    def test_whitespace_only_returns_text_or_empty(self):
        """
        Given: a whitespace-only string "   "
        When: tokenize() is called
        Then: returns either [] or a single TEXT token; does not raise

        Whitespace-only strings may appear after YAML scalar decoding of
        folded blocks; the tokenizer must not crash.
        """
        _require_module()
        result = tokenize("   ")
        assert isinstance(result, list)
        # Either empty or a single TEXT token containing only whitespace
        if result:
            assert len(result) == 1
            assert result[0].kind == TokenKind.TEXT
            assert result[0].value.strip() == ""

    def test_single_character_word(self):
        """
        Given: a single printable character "a"
        When: tokenize() is called
        Then: returns a single TEXT token with value "a"
        """
        _require_module()
        result = tokenize("a")
        assert len(result) == 1
        assert result[0].kind == TokenKind.TEXT
        assert result[0].value == "a"

    def test_newline_only(self):
        """
        Given: a string containing only a newline "\\n"
        When: tokenize() is called
        Then: returns a list without raising; no INVALID token for bare newline
        """
        _require_module()
        result = tokenize("\n")
        assert isinstance(result, list)
        # A bare newline is not a disallowed construct; it may produce TEXT or []
        if result:
            for token in result:
                assert not token.kind.name.startswith("INVALID"), (
                    f"Bare newline should not produce INVALID token, got {token!r}"
                )
