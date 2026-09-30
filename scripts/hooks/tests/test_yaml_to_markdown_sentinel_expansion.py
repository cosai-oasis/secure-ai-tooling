#!/usr/bin/env python3
"""
Tests for A7 sentinel expansion in scripts/hooks/yaml_to_markdown.py

Covers task 2.5.1 (collapse_column sentinel wiring) and task 2.5.3
(hard-fail on unresolved sentinel) for the markdown-generator side.

Contracts pinned by this test suite:

collapse_column wiring:
  - Gains keyword-only arguments `intra_lookup=None` and `ref_lookup=None`.
    When both are None (the default), sentinels pass through unchanged so
    pre-A7 call sites keep working until the table generators are wired up.
  - When lookups are supplied, sentinels are expanded via
    expand_sentinels_to_text: intra → plain title, ref → [title](url) link.
  - An unresolved sentinel raises UnresolvedSentinelError (never swallowed).

format_external_references helper:
  - New public function on yaml_to_markdown module.
  - Accepts a list of dicts (the externalReferences array from YAML) or None.
  - Returns a markdown sub-section string:
      ## References\n- [title](url) (type)\n...
    or "" when refs are empty/None.

## References emission in table generators:
  - FullDetailTableGenerator.generate() and SummaryTableGenerator.generate()
    each accept optional `intra_lookup` and `ref_lookup` constructor parameters
    (or keyword arguments); these are forwarded to collapse_column.
  - After the main markdown table, each entry that has a non-empty
    externalReferences list gets a sub-section header:
      ## References for {entry-id}
    followed by one bullet per reference in source order.
  - XRef generators (RiskXRefTableGenerator, ComponentXRefTableGenerator,
    FlatRiskXRefTableGenerator, FlatComponentXRefTableGenerator) do NOT emit
    References sub-sections — they operate on structural mapping fields only.

intra_lookup / ref_lookup constructor plumbing:
  - FullDetailTableGenerator and SummaryTableGenerator each accept an
    `intra_lookup` and `ref_lookup` keyword argument in their constructors.
    Both default to None (backward-compatible: no expansion when not supplied).
  - The table generator does NOT auto-load the corpus files internally;
    callers (yaml_to_markdown_table / convert_type) are responsible for
    supplying lookups. This keeps the generator classes unit-testable with
    pure synthesized data.

Wire-format sentinels used in fixtures (real tokenizer form, NOT ADR meta):
  - {{riskPromptInjection}}                          intra
  - {{controlInputValidationAndSanitization}}        intra
  - {{componentModelServing}}                        intra
  - {{personaModelCreator}}                          intra
  - {{ref:cwe-89}}                                   external
  - {{ref:zhou-2023-poisoning}}                      external

Do NOT use {{idRiskFoo}} — that is ADR-016 meta-notation, not wire format.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------------------
# Decoupled imports: if the sentinel helper or new yaml_to_markdown symbols
# fail to import (e.g. dependency drift), tests fail individually with clear
# messages rather than producing a collection-time error. Mirrors the A3
# pattern in test_prose_tokens.py.
# ---------------------------------------------------------------------------

_SENTINEL_MODULE_ERROR: ImportError | None = None
try:
    from scripts.hooks._sentinel_expansion import UnresolvedSentinelError  # noqa: E402
except ImportError as _e:
    _SENTINEL_MODULE_ERROR = _e
    UnresolvedSentinelError = None  # type: ignore[assignment,misc]

# yaml_to_markdown itself exists pre-A7, so this import should succeed now;
# the individual symbol lookups below fail at test-call time, not at collection.
import scripts.hooks.yaml_to_markdown as _ytm  # noqa: E402


def _require_sentinel_module() -> None:
    """Fail clearly if the sentinel helper is not importable."""
    if _SENTINEL_MODULE_ERROR is not None:
        pytest.fail(f"scripts/hooks/_sentinel_expansion.py is not importable: {_SENTINEL_MODULE_ERROR}")


def _get_collapse_column():
    """Return collapse_column; fails if the A7 keyword args are not present."""
    fn = getattr(_ytm, "collapse_column", None)
    if fn is None:
        pytest.fail("yaml_to_markdown.collapse_column is not defined")
    return fn


def _get_format_external_references():
    """Return format_external_references; fails if function does not exist yet."""
    fn = getattr(_ytm, "format_external_references", None)
    if fn is None:
        pytest.fail(
            "yaml_to_markdown.format_external_references does not exist — "
            "SWE must add this public helper (task 2.5.1)"
        )
    return fn


def _get_full_detail_generator():
    return getattr(_ytm, "FullDetailTableGenerator")


def _get_summary_generator():
    return getattr(_ytm, "SummaryTableGenerator")


# ---------------------------------------------------------------------------
# Shared test fixtures / inline data
# ---------------------------------------------------------------------------

# Synthetic lookups used by direct collapse_column / helper tests.
_INTRA_LOOKUP = {
    "riskPromptInjection": "Prompt Injection",
    "controlInputValidationAndSanitization": "Input Validation And Sanitization",
    "componentModelServing": "Model Serving Infrastructure",
    "personaModelCreator": "Model Creator",
}

_REF_LOOKUP = {
    "cwe-89": {
        "title": "CWE-89: Improper Neutralization of SQL Commands",
        "url": "https://cwe.mitre.org/data/definitions/89.html",
    },
    "zhou-2023-poisoning": {
        "title": "Zhou et al. 2023 - Data Poisoning",
        "url": "https://example.com/zhou-2023",
    },
}


def _make_risks_yaml_data(**overrides):
    """Return minimal risks YAML dict suitable for FullDetailTableGenerator."""
    base = {
        "risks": [
            {
                "id": "riskTestAlpha",
                "title": "Alpha Risk",
                "category": "riskCatTest",
                "shortDescription": ["Short description of alpha risk."],
                "longDescription": ["Long description of alpha risk."],
                "examples": ["Example of alpha risk."],
                "personas": [],
                "controls": [],
            }
        ]
    }
    base.update(overrides)
    return base


# ============================================================================
# TestCollapseColumnSentinelExpansion
# ============================================================================


class TestCollapseColumnSentinelExpansion:
    """
    Direct tests of collapse_column after A7 wiring.

    Contract: collapse_column gains keyword-only `intra_lookup` and `ref_lookup`
    parameters (both default to None). When None (or not supplied), sentinels are
    passed through unchanged — preserving backward compat with all pre-A7 call
    sites. When dicts are supplied, sentinel spans are expanded via
    expand_sentinels_to_text before the usual newline/dash normalisation.
    """

    def test_plain_text_passthrough_no_kwargs(self):
        """
        Test pre-A7 behavior: plain string returns unchanged when no lookups given.

        Given: A plain prose string with no {{ }} markers and no lookup kwargs
        When: collapse_column is called with only the entry argument
        Then: The result contains the original text (newlines become <br>, "- >" stripped)
        """
        fn = _get_collapse_column()
        result = fn("Plain description text.")
        assert "Plain description text" in result
        # No crashes, no sentinel artifacts
        assert "{{" not in result

    def test_string_with_newlines_no_kwargs(self):
        """
        Test that newlines are still normalised to <br> with no lookup kwargs.

        Given: A string with embedded newlines and no lookup kwargs
        When: collapse_column is called
        Then: Newlines are replaced with <br>; pre-A7 behavior unchanged
        """
        fn = _get_collapse_column()
        result = fn("Line 1\nLine 2")
        assert "<br>" in result
        assert "Line 1" in result
        assert "Line 2" in result

    def test_plain_text_passthrough_with_lookups(self):
        """
        Test that plain text (no sentinels) is unaffected even when lookups are provided.

        Given: A plain string with no {{ }} markers and non-None lookup dicts
        When: collapse_column is called with intra_lookup and ref_lookup
        Then: The result equals the pre-A7 result for the same input
        """
        fn = _get_collapse_column()
        result = fn("No sentinels here.", intra_lookup=_INTRA_LOOKUP, ref_lookup=_REF_LOOKUP)
        assert "No sentinels here" in result
        assert "{{" not in result

    def test_intra_sentinel_resolves_to_plain_title(self):
        """
        Test that {{riskPromptInjection}} expands to the entity title as plain text.

        Given: An entry string containing {{riskPromptInjection}} and a matching intra_lookup
        When: collapse_column is called with intra_lookup and ref_lookup
        Then: The sentinel span is replaced by "Prompt Injection" (no link markup)
              and the original sentinel span does not appear in the output
        """
        _require_sentinel_module()
        fn = _get_collapse_column()
        result = fn(
            "Relates to {{riskPromptInjection}} category.",
            intra_lookup=_INTRA_LOOKUP,
            ref_lookup=_REF_LOOKUP,
        )
        assert "Prompt Injection" in result
        assert "{{riskPromptInjection}}" not in result
        # Intra sentinels become plain title, not a markdown link
        assert "[Prompt Injection](" not in result

    def test_ref_sentinel_resolves_to_markdown_link(self):
        """
        Test that {{ref:cwe-89}} expands to a [title](url) markdown link.

        Given: An entry string containing {{ref:cwe-89}} and a matching ref_lookup
        When: collapse_column is called with intra_lookup and ref_lookup
        Then: The sentinel span is replaced by "[CWE-89: ...](url)" markdown link
        """
        _require_sentinel_module()
        fn = _get_collapse_column()
        result = fn(
            "See {{ref:cwe-89}} for the classification.",
            intra_lookup=_INTRA_LOOKUP,
            ref_lookup=_REF_LOOKUP,
        )
        assert "[CWE-89: Improper Neutralization of SQL Commands]" in result
        assert "https://cwe.mitre.org/data/definitions/89.html" in result
        assert "{{ref:cwe-89}}" not in result

    def test_mixed_sentinels_both_expanded(self):
        """
        Test that a string with both intra and ref sentinels expands both.

        Given: A string containing {{riskPromptInjection}} and {{ref:cwe-89}}
        When: collapse_column is called with both lookup dicts
        Then: Both sentinels are expanded; neither raw sentinel span remains
        """
        _require_sentinel_module()
        fn = _get_collapse_column()
        result = fn(
            "{{riskPromptInjection}} is covered by {{ref:cwe-89}}.",
            intra_lookup=_INTRA_LOOKUP,
            ref_lookup=_REF_LOOKUP,
        )
        assert "Prompt Injection" in result
        assert "CWE-89" in result
        assert "{{riskPromptInjection}}" not in result
        assert "{{ref:cwe-89}}" not in result

    def test_multi_element_list_collapses_and_expands(self):
        """
        Test that a list of strings is collapsed and sentinels are expanded.

        Given: A list where one element contains {{componentModelServing}} and
               lookups are provided
        When: collapse_column is called with the list and lookup kwargs
        Then: The collapsed output contains the expanded title and uses <br> separators
        """
        _require_sentinel_module()
        fn = _get_collapse_column()
        entry = [
            "First plain item.",
            "References {{componentModelServing}}.",
        ]
        result = fn(entry, intra_lookup=_INTRA_LOOKUP, ref_lookup=_REF_LOOKUP)
        assert "First plain item" in result
        assert "Model Serving Infrastructure" in result
        assert "{{componentModelServing}}" not in result
        assert "<br>" in result

    def test_none_lookups_leave_sentinels_unchanged(self):
        """
        Test that when intra_lookup and ref_lookup are None (default), sentinels
        are passed through unchanged — they are not resolved and no error is raised.

        Given: An entry string containing {{riskPromptInjection}} and NO lookup kwargs
        When: collapse_column is called without lookup arguments
        Then: The raw sentinel span appears verbatim in the output (no resolution)
              and no exception is raised

        This is the backward-compat contract: pre-A7 callers don't supply lookups
        so they get sentinel pass-through until the table generators are wired up.
        """
        fn = _get_collapse_column()
        # Must not raise even though the sentinel has no lookup to resolve against.
        result = fn("Has {{riskPromptInjection}} in it.")
        # Sentinel passes through unchanged when lookups are None.
        assert "{{riskPromptInjection}}" in result

    def test_explicit_none_lookups_leave_sentinels_unchanged(self):
        """
        Test that passing None explicitly for both lookups leaves sentinels unchanged.

        Given: A string with a sentinel and explicit None for both lookup kwargs
        When: collapse_column is called with intra_lookup=None, ref_lookup=None
        Then: The sentinel is NOT expanded and no error is raised
        """
        fn = _get_collapse_column()
        result = fn(
            "Has {{ref:cwe-89}} in it.",
            intra_lookup=None,
            ref_lookup=None,
        )
        assert "{{ref:cwe-89}}" in result

    def test_unresolved_intra_sentinel_raises_with_lookups(self):
        """
        Test that an unknown intra sentinel raises UnresolvedSentinelError when lookups
        are provided (not None).

        Given: A string containing {{riskTypoFooBar}} (not in intra_lookup) and
               non-None lookup dicts
        When: collapse_column is called
        Then: UnresolvedSentinelError is raised with .sentinel == "{{riskTypoFooBar}}"

        This is the task 2.5.3 hard-fail gate: collapse_column must never swallow
        an unresolved sentinel when the caller has opted in by supplying lookups.
        """
        _require_sentinel_module()
        fn = _get_collapse_column()
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            fn(
                "References {{riskTypoFooBar}} which does not exist.",
                intra_lookup={"riskOtherRisk": "Other Risk"},
                ref_lookup={},
            )
        assert exc_info.value.sentinel == "{{riskTypoFooBar}}"

    def test_unresolved_ref_sentinel_raises_with_lookups(self):
        """
        Test that an unknown ref sentinel raises UnresolvedSentinelError when lookups
        are provided (not None).

        Given: A string containing {{ref:cve-2024-99999}} with an empty ref_lookup
        When: collapse_column is called with non-None lookup dicts
        Then: UnresolvedSentinelError is raised with .sentinel == "{{ref:cve-2024-99999}}"
        """
        _require_sentinel_module()
        fn = _get_collapse_column()
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            fn(
                "See {{ref:cve-2024-99999}}.",
                intra_lookup=_INTRA_LOOKUP,
                ref_lookup={},
            )
        assert exc_info.value.sentinel == "{{ref:cve-2024-99999}}"

    def test_field_path_kwarg_accepted(self):
        """
        Test that collapse_column accepts an optional field_path kwarg (for error messages).

        Given: A call with a field_path kwarg supplied
        When: collapse_column is called on plain text
        Then: No error is raised; the field_path is accepted silently (used only
              in UnresolvedSentinelError messages if a sentinel fails to resolve)
        """
        fn = _get_collapse_column()
        # Should not raise
        result = fn(
            "Plain text.",
            intra_lookup=_INTRA_LOOKUP,
            ref_lookup=_REF_LOOKUP,
            field_path="risks[0].description[0]",
        )
        assert "Plain text" in result

    def test_field_path_in_unresolved_error_when_provided(self):
        """
        Test that the field_path kwarg is propagated to UnresolvedSentinelError.

        Given: A string with an unknown sentinel and a field_path kwarg
        When: collapse_column raises UnresolvedSentinelError
        Then: exc.field_path matches the supplied field_path string
        """
        _require_sentinel_module()
        fn = _get_collapse_column()
        fp = "risks[3].longDescription[0]"
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            fn(
                "{{riskBadRef}} is wrong.",
                intra_lookup={},
                ref_lookup={},
                field_path=fp,
            )
        assert exc_info.value.field_path == fp


# ============================================================================
# TestFormatExternalReferences
# ============================================================================


class TestFormatExternalReferences:
    """
    Direct tests of the new public helper format_external_references(refs) -> str.

    Contracted output format:
      "## References\\n- [title](url) (type)\\n- [title](url) (type)\\n"

    When refs is empty or None, the function returns "" (empty string, no header).
    Items are emitted in source order (no sorting).

    Known limitation: title and url are author-controlled (schema-validated) fields.
    Brackets and parens in titles are not escaped; this is intentional since the
    content is trusted YAML author input and escaping would corrupt intentional
    formatting.
    """

    def test_empty_list_returns_empty_string(self):
        """
        Test that an empty list returns "" with no header.

        Given: refs=[]
        When: format_external_references([])
        Then: Returns exactly "" — no markdown is emitted
        """
        fn = _get_format_external_references()
        assert fn([]) == ""

    def test_none_returns_empty_string(self):
        """
        Test that None input returns "".

        Given: refs=None
        When: format_external_references(None)
        Then: Returns exactly ""
        """
        fn = _get_format_external_references()
        assert fn(None) == ""

    def test_single_entry_produces_header_and_one_bullet(self):
        """
        Test that a single-entry list produces a header and exactly one bullet.

        Given: refs=[{type: "cwe", title: "CWE-89: SQL Injection", url: "https://..."}]
        When: format_external_references is called
        Then: Output starts with "## References" and contains exactly one "- [" bullet

        Output shape pinned:
          ## References
          - [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) (cwe)
        """
        fn = _get_format_external_references()
        refs = [
            {
                "type": "cwe",
                "id": "cwe-89",
                "title": "CWE-89: SQL Injection",
                "url": "https://cwe.mitre.org/data/definitions/89.html",
            }
        ]
        result = fn(refs)
        assert result.startswith("## References")
        assert "- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)" in result
        assert "(cwe)" in result
        # Exactly one bullet
        assert result.count("- [") == 1

    def test_multiple_entries_in_source_order(self):
        """
        Test that multiple entries produce multiple bullets in source order.

        Given: refs with two entries (entry A then entry B)
        When: format_external_references is called
        Then: Both bullets appear; entry A's bullet precedes entry B's bullet

        Source-order contract: the function must NOT sort entries.
        """
        fn = _get_format_external_references()
        refs = [
            {
                "type": "paper",
                "id": "zhou-2023-poisoning",
                "title": "Zhou et al. 2023 - Data Poisoning",
                "url": "https://example.com/zhou-2023",
            },
            {
                "type": "cwe",
                "id": "cwe-89",
                "title": "CWE-89: SQL Injection",
                "url": "https://cwe.mitre.org/data/definitions/89.html",
            },
        ]
        result = fn(refs)
        assert result.count("- [") == 2
        zhou_pos = result.index("Zhou et al.")
        cwe_pos = result.index("CWE-89:")
        assert zhou_pos < cwe_pos, "First entry (Zhou) must appear before second entry (CWE-89) in output"

    def test_output_contains_type_annotation(self):
        """
        Test that the reference type (e.g. "paper", "cwe") appears in parentheses.

        Given: A ref entry with type="atlas"
        When: format_external_references is called
        Then: "(atlas)" appears in the output
        """
        fn = _get_format_external_references()
        refs = [
            {
                "type": "atlas",
                "id": "aml-t0020",
                "title": "MITRE ATLAS AML.T0020",
                "url": "https://atlas.mitre.org/techniques/AML.T0020",
            }
        ]
        result = fn(refs)
        assert "(atlas)" in result

    def test_output_header_is_h2_references(self):
        """
        Test that the section header is exactly "## References" (H2, not H1 or H3).

        Given: Any non-empty refs list
        When: format_external_references is called
        Then: The output contains "## References" (two hashes, not one or three)
        """
        fn = _get_format_external_references()
        refs = [{"type": "cwe", "id": "cwe-89", "title": "CWE-89", "url": "https://example.com"}]
        result = fn(refs)
        assert "## References" in result
        assert "### References" not in result
        assert result.count("# References") == 1  # only one header occurrence

    def test_special_chars_in_title_not_escaped(self):
        """
        Test that special characters in titles are NOT escaped.

        Given: A ref entry whose title contains angle brackets and ampersands
        When: format_external_references is called
        Then: The raw title string appears verbatim in the output

        Known limitation: author-controlled titles are trusted. The schema validates
        externalReferences[].title as a string but does not restrict characters.
        Escaping would corrupt intentional formatting (e.g. "<br>" in a title).
        """
        fn = _get_format_external_references()
        refs = [
            {
                "type": "spec",
                "id": "spec-abc",
                "title": "A & B <spec>",
                "url": "https://example.com/spec",
            }
        ]
        result = fn(refs)
        # Title appears verbatim (not HTML-escaped)
        assert "A & B <spec>" in result

    def test_three_entries_produces_three_bullets(self):
        """
        Test that three entries produce three bullets.

        Given: refs list with three entries
        When: format_external_references is called
        Then: The output contains exactly three "- [" bullet lines
        """
        fn = _get_format_external_references()
        refs = [
            {"type": "cwe", "id": f"cwe-{i}", "title": f"CWE-{i}", "url": f"https://example.com/{i}"}
            for i in range(3)
        ]
        result = fn(refs)
        assert result.count("- [") == 3


# ============================================================================
# TestFullDetailTableSentinelIntegration
# ============================================================================


class TestFullDetailTableSentinelIntegration:
    """
    End-to-end tests via FullDetailTableGenerator.generate(yaml_data, ytype).

    The generator accepts optional `intra_lookup` and `ref_lookup` constructor
    parameters (both default None). When None, sentinels pass through unchanged.
    When supplied, sentinels are expanded via collapse_column's new keyword args.

    Fixture design: all intra sentinels in YAML data reference ids that are
    ALSO present in the same synthesized yaml_data dict. This avoids any
    dependency on the live corpus for cross-file resolution in generator tests.
    Tests that require cross-file refs test through collapse_column directly
    (see TestCollapseColumnSentinelExpansion above).
    """

    def test_no_sentinels_output_unchanged_from_pre_a7(self):
        """
        Test that YAML data without any sentinels produces the same output
        regardless of whether lookups are supplied or omitted.

        Given: YAML data with plain-text prose fields (no {{ }} spans)
        When: FullDetailTableGenerator.generate is called with and without lookups
        Then: Both calls succeed and produce identical output — no regression

        This is the no-op guard: A7 wiring must not break any pre-existing output.
        """
        gen_cls = _get_full_detail_generator()
        yaml_data = _make_risks_yaml_data()

        gen_no_lookup = gen_cls()
        gen_with_lookup = gen_cls(intra_lookup=_INTRA_LOOKUP, ref_lookup=_REF_LOOKUP)

        out_no_lookup = gen_no_lookup.generate(yaml_data, "risks")
        out_with_lookup = gen_with_lookup.generate(yaml_data, "risks")

        assert out_no_lookup == out_with_lookup

    def test_intra_sentinel_in_description_expanded_in_output(self):
        """
        Test that an intra sentinel in a prose field is expanded in the table output
        when intra_lookup is supplied.

        Given: YAML data where longDescription contains "{{riskPromptInjection}}"
               and intra_lookup has riskPromptInjection → "Prompt Injection"
        When: FullDetailTableGenerator.generate is called with that intra_lookup
        Then: The table output contains "Prompt Injection" and does NOT contain
              the raw sentinel span "{{riskPromptInjection}}"

        Note: longDescription is in the 'collapsable' set at line 229 of yaml_to_markdown.py.
        """
        _require_sentinel_module()
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskPromptInjection",
                    "title": "Prompt Injection",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["See {{riskPromptInjection}} risk category."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }
        intra = {"riskPromptInjection": "Prompt Injection"}

        gen = gen_cls(intra_lookup=intra, ref_lookup={})
        output = gen.generate(yaml_data, "risks")

        assert "Prompt Injection" in output
        assert "{{riskPromptInjection}}" not in output

    def test_ref_sentinel_in_description_expanded_to_link(self):
        """
        Test that a ref sentinel in a prose field is expanded to a markdown link
        when ref_lookup is supplied.

        Given: YAML data where description contains "{{ref:cwe-89}}" and
               ref_lookup has cwe-89 → {title, url}
        When: FullDetailTableGenerator.generate is called with that ref_lookup
        Then: The table output contains the linked title and does NOT contain
              the raw "{{ref:cwe-89}}" sentinel span
        """
        _require_sentinel_module()
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskTestBeta",
                    "title": "Beta Risk",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Covered by {{ref:cwe-89}}."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }
        ref = {
            "cwe-89": {
                "title": "CWE-89: Improper Neutralization of SQL Commands",
                "url": "https://cwe.mitre.org/data/definitions/89.html",
            }
        }

        gen = gen_cls(intra_lookup={}, ref_lookup=ref)
        output = gen.generate(yaml_data, "risks")

        assert "CWE-89: Improper Neutralization of SQL Commands" in output
        assert "https://cwe.mitre.org/data/definitions/89.html" in output
        assert "{{ref:cwe-89}}" not in output

    def test_external_references_sub_section_emitted_after_table(self):
        """
        Test that a ## References for {id} sub-section appears after the main table
        when an entry has a non-empty externalReferences array.

        Given: YAML data with one risk that has two externalReferences entries
        When: FullDetailTableGenerator.generate is called
        Then: The output contains a "## References for riskTestGamma" section
              with two bullet lines; this section appears AFTER the markdown table
              (i.e., the index of "## References for" in the output is greater
              than the index where the markdown table ends)

        Contract for position: the output is structured as:
          <markdown table>\n\n## References for {id}\n- [title](url) (type)\n...

        The markdown table ends at the last "|" line before the References section.
        """
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskTestGamma",
                    "title": "Gamma Risk",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Long."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    "externalReferences": [
                        {
                            "type": "cwe",
                            "id": "cwe-89",
                            "title": "CWE-89: SQL Injection",
                            "url": "https://cwe.mitre.org/data/definitions/89.html",
                        },
                        {
                            "type": "paper",
                            "id": "zhou-2023-poisoning",
                            "title": "Zhou et al. 2023 - Data Poisoning",
                            "url": "https://example.com/zhou-2023",
                        },
                    ],
                }
            ]
        }

        gen = gen_cls()
        output = gen.generate(yaml_data, "risks")

        # Sub-section header uses the entry id
        assert "## References for riskTestGamma" in output

        # Both reference bullets appear
        assert "CWE-89: SQL Injection" in output
        assert "Zhou et al. 2023 - Data Poisoning" in output

        # Sub-section is AFTER the main table
        table_end_idx = output.rfind("|")
        refs_idx = output.index("## References for riskTestGamma")
        assert refs_idx > table_end_idx, (
            f"## References for section (pos {refs_idx}) must appear after "
            f"the last table pipe (pos {table_end_idx})"
        )

    def test_unresolved_intra_sentinel_raises_error(self):
        """
        Test that FullDetailTableGenerator.generate raises UnresolvedSentinelError
        when a prose field contains an intra sentinel that is not in intra_lookup.

        Given: YAML data where longDescription contains {{riskTypoFooBar}} (no such key
               in the supplied intra_lookup)
        When: FullDetailTableGenerator.generate is called with a non-None intra_lookup
        Then: UnresolvedSentinelError is raised with .sentinel == "{{riskTypoFooBar}}"

        This is the task 2.5.3 markdown-side hard-fail gate.
        """
        _require_sentinel_module()
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskBadSentinel",
                    "title": "Bad Sentinel",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Mentions {{riskTypoFooBar}} which is unknown."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }

        gen = gen_cls(intra_lookup={}, ref_lookup={})
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            gen.generate(yaml_data, "risks")

        assert exc_info.value.sentinel == "{{riskTypoFooBar}}"

    def test_unresolved_ref_sentinel_raises_error(self):
        """
        Test that FullDetailTableGenerator.generate raises UnresolvedSentinelError
        when a prose field contains a ref sentinel with no matching ref_lookup entry.

        Given: YAML data where longDescription contains {{ref:cve-2024-99999}} and
               ref_lookup is empty
        When: FullDetailTableGenerator.generate is called with non-None lookups
        Then: UnresolvedSentinelError is raised with .sentinel == "{{ref:cve-2024-99999}}"
        """
        _require_sentinel_module()
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskBadRef",
                    "title": "Bad Ref",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["See {{ref:cve-2024-99999}}."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }

        gen = gen_cls(intra_lookup={}, ref_lookup={})
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            gen.generate(yaml_data, "risks")

        assert exc_info.value.sentinel == "{{ref:cve-2024-99999}}"


# ============================================================================
# TestUnresolvedSentinelMarkdownSide
# ============================================================================


class TestUnresolvedSentinelMarkdownSide:
    """
    Explicit task 2.5.3 gate: unresolved sentinels are hard build failures on the
    markdown side. These tests reach through the table generator's generate() call.
    """

    def test_intra_typo_in_long_description_raises(self):
        """
        Test that a risk with a typo'd intra sentinel in longDescription raises
        UnresolvedSentinelError when FullDetailTableGenerator.generate is called
        with non-None lookups.

        Given: risks YAML containing {{riskTypoFooBar}} in longDescription[0]
               and no risk having id "riskTypoFooBar" in intra_lookup
        When: FullDetailTableGenerator.generate is called
        Then: UnresolvedSentinelError is raised
              .sentinel == "{{riskTypoFooBar}}"
              .field_path contains the entry id and field name
        """
        _require_sentinel_module()
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskWithTypo",
                    "title": "Risk With Typo",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Contains {{riskTypoFooBar}} sentinel."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }

        gen = gen_cls(intra_lookup={}, ref_lookup={})
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            gen.generate(yaml_data, "risks")

        exc = exc_info.value
        assert exc.sentinel == "{{riskTypoFooBar}}"
        # field_path must be non-empty and informative
        assert exc.field_path, "field_path must be non-empty"
        # Should reference the entry id and/or the field name
        assert "riskWithTypo" in exc.field_path or "longDescription" in exc.field_path, (
            f"field_path should reference entry id or field name; got: {exc.field_path!r}"
        )

    def test_ref_typo_in_description_raises(self):
        """
        Test that a risk with an unknown ref id in description raises
        UnresolvedSentinelError.

        Given: risks YAML containing {{ref:cve-2024-99999}} in longDescription[0]
               and no externalReferences entry with id "cve-2024-99999" in ref_lookup
        When: FullDetailTableGenerator.generate is called with non-None lookups
        Then: UnresolvedSentinelError is raised
              .sentinel == "{{ref:cve-2024-99999}}"
        """
        _require_sentinel_module()
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskWithBadRef",
                    "title": "Risk With Bad Ref",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["See {{ref:cve-2024-99999}}."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }

        gen = gen_cls(intra_lookup={}, ref_lookup={})
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            gen.generate(yaml_data, "risks")

        exc = exc_info.value
        assert exc.sentinel == "{{ref:cve-2024-99999}}"

    def test_error_field_path_includes_entry_id_and_field_name(self):
        """
        Test that the UnresolvedSentinelError field_path identifies the entry id
        and the YAML field name so the author can pinpoint the problem.

        Given: risks YAML where entry "riskFindMe" has {{riskTypoXyz}} in longDescription[0]
        When: FullDetailTableGenerator.generate raises UnresolvedSentinelError
        Then: exc.field_path includes "riskFindMe" (entry id) and "longDescription" (field)
              OR includes a positional reference such as "risks[0].longDescription[0]"
        """
        _require_sentinel_module()
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskFindMe",
                    "title": "Find Me",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Contains {{riskTypoXyz}}."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }

        gen = gen_cls(intra_lookup={}, ref_lookup={})
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            gen.generate(yaml_data, "risks")

        exc = exc_info.value
        assert exc.field_path, "field_path must be non-empty"
        has_entry_ref = "riskFindMe" in exc.field_path or "risks[0]" in exc.field_path
        has_field_ref = "longDescription" in exc.field_path
        assert has_entry_ref or has_field_ref, (
            f"field_path should identify entry 'riskFindMe' or field 'longDescription'; got: {exc.field_path!r}"
        )

    def test_error_is_not_caught_by_summary_generator_either(self):
        """
        Test that SummaryTableGenerator also propagates UnresolvedSentinelError.

        Given: YAML data with a typo'd intra sentinel in description and non-None lookups
        When: SummaryTableGenerator.generate is called
        Then: UnresolvedSentinelError propagates (is not caught internally)

        Both FullDetailTableGenerator and SummaryTableGenerator must hard-fail.
        """
        _require_sentinel_module()
        gen_cls = _get_summary_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskSummaryBad",
                    "title": "Summary Bad",
                    "category": "riskCatTest",
                    "shortDescription": ["Contains {{riskBogusId}}."],
                    "longDescription": ["Long."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }

        gen = gen_cls(intra_lookup={}, ref_lookup={})
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            gen.generate(yaml_data, "risks")

        assert exc_info.value.sentinel == "{{riskBogusId}}"


# ============================================================================
# TestConvertTypeSurfacing
# ============================================================================


class TestConvertTypeSurfacing:
    """
    Tests for the convert_type() user-facing CLI surface.

    convert_type catches all exceptions, prints an error, and returns False.
    The task 2.5.3 contract for this surface:
      - convert_type returns False when a sentinel is unresolved.
      - The error printed to stdout includes the sentinel span.

    Design note: convert_type reads from a YAML file on disk, so these tests use
    tmp_path to write synthesized YAML files with bad sentinels.
    """

    def test_convert_type_returns_false_on_unresolved_sentinel(self, tmp_path: Path):
        """
        Test that convert_type returns False when a YAML file contains an unresolved
        intra sentinel and the generator is wired with non-None lookups.

        Given: A temporary YAML file with a risk whose longDescription contains
               {{riskTypoFooBar}} (no such id exists)
        When: convert_type is called targeting that file with full format
        Then: Returns False and prints an error message to stdout

        Note: convert_type's current try/except at line 1112 catches all exceptions
        and prints "❌ Error converting {ytype}: {e}". After A7, the error message
        should include the unresolved sentinel span.
        """
        _require_sentinel_module()

        # Write a minimal risks YAML with a bad sentinel
        yaml_data = {
            "risks": [
                {
                    "id": "riskBadForConvert",
                    "title": "Bad Sentinel Risk",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Contains {{riskTypoFooBar}}."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }
        import yaml as _yaml

        input_file = tmp_path / "risks.yaml"
        input_file.write_text(_yaml.dump(yaml_data), encoding="utf-8")
        output_file = tmp_path / "out.md"

        result = _ytm.convert_type(
            ytype="risks",
            table_format="full",
            input_file=input_file,
            output_file=output_file,
            quiet=True,
        )

        assert result is False

    def test_convert_type_error_message_contains_sentinel(self, tmp_path: Path, capsys):
        """
        Test that the error message printed by convert_type includes the unresolved
        sentinel span so the author can identify the problem.

        Given: A YAML file with {{riskTypoFooBar}} in a prose field
        When: convert_type is called and returns False
        Then: The captured stdout contains the sentinel span "{{riskTypoFooBar}}"
              (or at minimum the outer riskTypoFooBar id)

        The existing error-print surface is:
          print(f"❌ Error converting {ytype}: {e}")
        where {e} is str(UnresolvedSentinelError). Since UnresolvedSentinelError's
        __str__ always includes both .sentinel and .field_path (per test contract in
        test_sentinel_expansion.py), the sentinel span will appear in stdout.
        """
        _require_sentinel_module()

        import yaml as _yaml

        yaml_data = {
            "risks": [
                {
                    "id": "riskSentinelMsg",
                    "title": "Sentinel Msg Risk",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Bad ref: {{riskTypoFooBar}}."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }
        input_file = tmp_path / "risks.yaml"
        input_file.write_text(_yaml.dump(yaml_data), encoding="utf-8")
        output_file = tmp_path / "out.md"

        # quiet=False so error is printed
        result = _ytm.convert_type(
            ytype="risks",
            table_format="full",
            input_file=input_file,
            output_file=output_file,
            quiet=False,
        )
        captured = capsys.readouterr()

        assert result is False
        # Error message should mention the sentinel or its id fragment
        assert "riskTypoFooBar" in captured.out, (
            f"Expected sentinel id in error output; got stdout:\n{captured.out!r}"
        )


# ============================================================================
# TestExternalReferencesIntegration
# ============================================================================


class TestExternalReferencesIntegration:
    """
    Confirms that ## References for {id} sub-sections render correctly in the
    combined output from FullDetailTableGenerator.generate.
    """

    def test_single_risk_with_refs_emits_sub_section(self):
        """
        Test that a single risk with two externalReferences produces a
        "## References for {id}" sub-section with two bullets.

        Given: YAML with one risk having externalReferences=[{cwe-89}, {zhou-2023-poisoning}]
        When: FullDetailTableGenerator.generate is called
        Then: Output contains:
              - "## References for riskWithExtRefs"
              - A bullet for CWE-89 in source order
              - A bullet for zhou-2023-poisoning in source order
        """
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskWithExtRefs",
                    "title": "Risk With Ext Refs",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Long."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    "externalReferences": [
                        {
                            "type": "cwe",
                            "id": "cwe-89",
                            "title": "CWE-89: SQL Injection",
                            "url": "https://cwe.mitre.org/data/definitions/89.html",
                        },
                        {
                            "type": "paper",
                            "id": "zhou-2023-poisoning",
                            "title": "Zhou et al. 2023 - Data Poisoning",
                            "url": "https://example.com/zhou-2023",
                        },
                    ],
                }
            ]
        }

        gen = gen_cls()
        output = gen.generate(yaml_data, "risks")

        assert "## References for riskWithExtRefs" in output
        assert "CWE-89: SQL Injection" in output
        assert "Zhou et al. 2023 - Data Poisoning" in output
        # Two bullets
        bullets_after_header = output[output.index("## References for riskWithExtRefs") :]
        assert bullets_after_header.count("- [") >= 2

    def test_multiple_risks_with_refs_emit_multiple_sub_sections(self):
        """
        Test that multiple risks each with externalReferences produce
        multiple distinct ## References for {id} sub-sections.

        Given: YAML with two risks: riskAlpha (one ext ref) and riskBeta (one ext ref)
        When: FullDetailTableGenerator.generate is called
        Then: Output contains both "## References for riskAlpha" and
              "## References for riskBeta"
        """
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskAlpha",
                    "title": "Alpha",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Long."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    "externalReferences": [
                        {"type": "cwe", "id": "cwe-1", "title": "CWE-1 Title", "url": "https://example.com/1"}
                    ],
                },
                {
                    "id": "riskBeta",
                    "title": "Beta",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Long."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    "externalReferences": [
                        {
                            "type": "paper",
                            "id": "paper-2",
                            "title": "Paper 2 Title",
                            "url": "https://example.com/2",
                        }
                    ],
                },
            ]
        }

        gen = gen_cls()
        output = gen.generate(yaml_data, "risks")

        assert "## References for riskAlpha" in output
        assert "## References for riskBeta" in output

    def test_no_external_references_no_sub_sections(self):
        """
        Test that YAML data where no entry has externalReferences produces
        no ## References for headers in the output.

        Given: YAML with one risk that has no externalReferences field
        When: FullDetailTableGenerator.generate is called
        Then: "## References for" does NOT appear anywhere in the output
        """
        gen_cls = _get_full_detail_generator()

        yaml_data = _make_risks_yaml_data()
        gen = gen_cls()
        output = gen.generate(yaml_data, "risks")

        assert "## References for" not in output

    def test_references_sections_appear_after_main_table(self):
        """
        Test that all ## References for sub-sections appear AFTER the main markdown
        table in the output string.

        Given: YAML with one risk that has externalReferences
        When: FullDetailTableGenerator.generate is called
        Then: The string index of "## References for" is greater than the index
              of the last "|" character in the output (which marks end of the table)
        """
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskPositionCheck",
                    "title": "Position Check",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Long."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    "externalReferences": [
                        {
                            "type": "cwe",
                            "id": "cwe-89",
                            "title": "CWE-89",
                            "url": "https://cwe.mitre.org/data/definitions/89.html",
                        }
                    ],
                }
            ]
        }

        gen = gen_cls()
        output = gen.generate(yaml_data, "risks")

        table_end_idx = output.rfind("|")
        refs_idx = output.index("## References for riskPositionCheck")
        assert refs_idx > table_end_idx, (
            f"## References for section (pos {refs_idx}) must appear after "
            f"the last table pipe (pos {table_end_idx})"
        )

    def test_empty_external_references_list_no_sub_section(self):
        """
        Test that an empty externalReferences list on an entry does NOT emit
        a ## References for sub-section.

        Given: YAML with one risk that has externalReferences=[]
        When: FullDetailTableGenerator.generate is called
        Then: "## References for" does NOT appear in the output
        """
        gen_cls = _get_full_detail_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskEmptyExtRefs",
                    "title": "Empty Ext Refs",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Long."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    "externalReferences": [],
                }
            ]
        }

        gen = gen_cls()
        output = gen.generate(yaml_data, "risks")

        assert "## References for" not in output


# ============================================================================
# TestSummaryTableSentinelIntegration
# ============================================================================


class TestSummaryTableSentinelIntegration:
    """
    Integration tests for SummaryTableGenerator (parallel to FullDetail tests).

    SummaryTableGenerator uses collapse_column on shortDescription/description.
    The same sentinel-wiring and References-emission contract applies.
    """

    def test_summary_generator_constructor_accepts_lookup_kwargs(self):
        """
        Test that SummaryTableGenerator accepts intra_lookup and ref_lookup kwargs.

        Given: Calls to SummaryTableGenerator() with and without lookup kwargs
        When: Both constructors are called
        Then: No TypeError is raised — both signatures are accepted

        This is the backward-compat smoke test for the constructor change.
        """
        gen_cls = _get_summary_generator()
        # No kwargs — pre-A7 call site
        gen1 = gen_cls()
        assert gen1 is not None

        # With kwargs — post-A7 wired call
        gen2 = gen_cls(intra_lookup=_INTRA_LOOKUP, ref_lookup=_REF_LOOKUP)
        assert gen2 is not None

    def test_summary_generator_expands_intra_sentinel_in_short_desc(self):
        """
        Test that SummaryTableGenerator expands an intra sentinel in shortDescription.

        Given: YAML data where a risk's shortDescription contains {{riskPromptInjection}}
               and intra_lookup has that id
        When: SummaryTableGenerator.generate is called with non-None intra_lookup
        Then: Output contains "Prompt Injection" and NOT the raw sentinel span
        """
        _require_sentinel_module()
        gen_cls = _get_summary_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskPromptInjection",
                    "title": "Prompt Injection",
                    "category": "riskCatTest",
                    "shortDescription": ["See {{riskPromptInjection}} category."],
                    "longDescription": ["Long."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                }
            ]
        }
        intra = {"riskPromptInjection": "Prompt Injection"}

        gen = gen_cls(intra_lookup=intra, ref_lookup={})
        output = gen.generate(yaml_data, "risks")

        assert "Prompt Injection" in output
        assert "{{riskPromptInjection}}" not in output

    def test_summary_generator_external_references_section_emitted(self):
        """
        Test that SummaryTableGenerator emits ## References for {id} after the table.

        Given: YAML data with one risk having one externalReferences entry
        When: SummaryTableGenerator.generate is called
        Then: Output contains "## References for {risk-id}" sub-section with one bullet
        """
        gen_cls = _get_summary_generator()

        yaml_data = {
            "risks": [
                {
                    "id": "riskSummaryWithRefs",
                    "title": "Summary With Refs",
                    "category": "riskCatTest",
                    "shortDescription": ["Short."],
                    "longDescription": ["Long."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    "externalReferences": [
                        {
                            "type": "cwe",
                            "id": "cwe-89",
                            "title": "CWE-89: SQL Injection",
                            "url": "https://cwe.mitre.org/data/definitions/89.html",
                        }
                    ],
                }
            ]
        }

        gen = gen_cls()
        output = gen.generate(yaml_data, "risks")

        assert "## References for riskSummaryWithRefs" in output
        assert "CWE-89: SQL Injection" in output


# ============================================================================
# TestPerEntryRefLookupCollision  (RED — ADR-016 D6 per-entry scope)
# ============================================================================


def _write_sibling_yamls(directory: Path) -> None:
    """Write minimal sibling YAML files so yaml_to_markdown_table's intra_lookup build succeeds.

    yaml_to_markdown_table scans risks.yaml, controls.yaml, components.yaml, and personas.yaml
    in the same directory to populate intra_lookup.  The collision tests use a synthesised
    risks.yaml as the primary file; the other three are empty stubs so the scan is silent.
    """
    import yaml as _yaml

    (directory / "controls.yaml").write_text(_yaml.dump({"controls": []}), encoding="utf-8")
    (directory / "components.yaml").write_text(_yaml.dump({"components": []}), encoding="utf-8")
    (directory / "personas.yaml").write_text(_yaml.dump({"personas": []}), encoding="utf-8")


def _write_sibling_yamls_for_controls(directory: Path) -> None:
    """Write minimal sibling YAML files when controls.yaml is the primary file under test."""
    import yaml as _yaml

    (directory / "risks.yaml").write_text(_yaml.dump({"risks": []}), encoding="utf-8")
    (directory / "components.yaml").write_text(_yaml.dump({"components": []}), encoding="utf-8")
    (directory / "personas.yaml").write_text(_yaml.dump({"personas": []}), encoding="utf-8")


class TestPerEntryRefLookupCollision:
    """
    RED-phase tests for ADR-016 D6 rule 3: ref-lookup scope is per-entry.

    The current implementation at yaml_to_markdown.py:1051-1063 builds a single
    flat ref_lookup by iterating all entries' externalReferences with last-write-wins
    on id collision.  This violates the per-entry scope rule: if risk-A and risk-B
    both declare externalReferences[].id = "shared" with different titles/urls, then
    risk-A's {{ref:shared}} resolves to whichever entry was loaded last.

    These tests assert the correct post-fix behaviour:
    - A1/A2: each entry's {{ref:shared}} resolves to THAT entry's own ref metadata,
      not a sibling's.
    - B1: a sentinel that references an id declared only in a different entry must
      raise UnresolvedSentinelError (per-entry scope: unknown to this entry = unresolved).

    On HEAD ebe4504 all tests in this class are expected to FAIL (RED phase).

    Generators under test reach yaml_to_markdown_table, not the generator classes
    directly, because the bug lives in yaml_to_markdown_table's ref_lookup build
    logic (lines 1051-1063), not inside the generator classes themselves.
    """

    def test_a1_full_detail_risks_collision_each_entry_resolves_own_ref(self, tmp_path: Path):
        """
        A1: FullDetailTableGenerator via yaml_to_markdown_table resolves {{ref:shared}}
        to the declaring entry's own ref, not the last-loaded one.

        Given: risks.yaml with two risks:
               - riskAlpha: externalReferences [{id:"shared", title:"CWE-A Title", url:".../A"}]
                            longDescription: "... see {{ref:shared}} for details ..."
               - riskBeta:  externalReferences [{id:"shared", title:"CWE-B Title", url:".../B"}]
                            longDescription: "... see {{ref:shared}} as well ..."
        When: yaml_to_markdown_table(risks_yaml, "risks", table_format="full") is called
        Then: (post-fix contract)
              - The row for riskAlpha contains "CWE-A Title" and does NOT contain "CWE-B Title"
              - The row for riskBeta  contains "CWE-B Title" and does NOT contain "CWE-A Title"

        RED failure (HEAD ebe4504):
              The flat last-write-wins lookup means BOTH rows resolve to the last-loaded
              ref ("CWE-B Title" if riskBeta is last in YAML order).  The assertion
              "riskAlpha row contains CWE-A Title" fails.
        """
        _require_sentinel_module()
        import yaml as _yaml

        risks_data = {
            "risks": [
                {
                    "id": "riskAlpha",
                    "title": "Alpha Risk",
                    "category": "riskCatTest",
                    "shortDescription": ["Short alpha."],
                    "longDescription": ["Alpha: see {{ref:shared}} for details."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    "externalReferences": [
                        {
                            "id": "shared",
                            "type": "cwe",
                            "title": "CWE-A Title",
                            "url": "https://cwe.mitre.org/A",
                        }
                    ],
                },
                {
                    "id": "riskBeta",
                    "title": "Beta Risk",
                    "category": "riskCatTest",
                    "shortDescription": ["Short beta."],
                    "longDescription": ["Beta: see {{ref:shared}} as well."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    "externalReferences": [
                        {
                            "id": "shared",
                            "type": "cwe",
                            "title": "CWE-B Title",
                            "url": "https://cwe.mitre.org/B",
                        }
                    ],
                },
            ]
        }
        risks_file = tmp_path / "risks.yaml"
        risks_file.write_text(_yaml.dump(risks_data), encoding="utf-8")
        _write_sibling_yamls(tmp_path)

        output = _ytm.yaml_to_markdown_table(risks_file, "risks", table_format="full")

        # Bound the row-isolation slice to the table portion only — the
        # post-table "## References for {id}" sub-sections legitimately list
        # both entries' titles and would defeat row isolation if included.
        table_end = output.find("## References for")
        table = output if table_end == -1 else output[:table_end]
        alpha_idx = table.find("riskAlpha")
        beta_idx = table.find("riskBeta")
        assert alpha_idx != -1, "riskAlpha not found in table"
        assert beta_idx != -1, "riskBeta not found in table"

        # The table is sorted by id, so riskAlpha row comes before riskBeta row.
        alpha_region = table[alpha_idx:beta_idx]
        beta_region = table[beta_idx:]

        assert "CWE-A Title" in alpha_region, (
            f"riskAlpha row must resolve {{{{ref:shared}}}} to its own 'CWE-A Title'; "
            f"alpha_region:\n{alpha_region!r}"
        )
        assert "CWE-B Title" not in alpha_region, (
            "riskAlpha row must NOT contain 'CWE-B Title' (cross-entry collision)"
        )
        assert "CWE-B Title" in beta_region, (
            f"riskBeta row must resolve {{{{ref:shared}}}} to its own 'CWE-B Title'; beta_region:\n{beta_region!r}"
        )
        assert "CWE-A Title" not in beta_region, (
            "riskBeta row must NOT contain 'CWE-A Title' (cross-entry collision)"
        )

    def test_a2_summary_controls_collision_each_entry_resolves_own_ref(self, tmp_path: Path):
        """
        A2: SummaryTableGenerator via yaml_to_markdown_table resolves {{ref:shared}}
        to the declaring entry's own ref (controls, summary format).

        Given: controls.yaml with two controls sharing externalReferences[].id = "shared":
               - controlAlpha: ref title "NIST-A Title"; description "... {{ref:shared}} ..."
               - controlBeta:  ref title "NIST-B Title"; description "... {{ref:shared}} ..."
        When: yaml_to_markdown_table(controls_yaml, "controls", table_format="summary") is called
        Then: (post-fix contract)
              - controlAlpha's row contains "NIST-A Title" and does NOT contain "NIST-B Title"
              - controlBeta's row contains "NIST-B Title" and does NOT contain "NIST-A Title"

        RED failure (HEAD ebe4504):
              The flat lookup means both rows resolve to the last-loaded ref.
              The per-entry assertion fails.
        """
        _require_sentinel_module()
        import yaml as _yaml

        controls_data = {
            "controls": [
                {
                    "id": "controlAlpha",
                    "title": "Alpha Control",
                    "category": "controlsData",
                    "description": ["Alpha uses {{ref:shared}} specification."],
                    "risks": [],
                    "components": [],
                    "externalReferences": [
                        {
                            "id": "shared",
                            "type": "nist",
                            "title": "NIST-A Title",
                            "url": "https://nist.gov/A",
                        }
                    ],
                },
                {
                    "id": "controlBeta",
                    "title": "Beta Control",
                    "category": "controlsData",
                    "description": ["Beta follows {{ref:shared}} guidelines."],
                    "risks": [],
                    "components": [],
                    "externalReferences": [
                        {
                            "id": "shared",
                            "type": "nist",
                            "title": "NIST-B Title",
                            "url": "https://nist.gov/B",
                        }
                    ],
                },
            ]
        }
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(_yaml.dump(controls_data), encoding="utf-8")
        _write_sibling_yamls_for_controls(tmp_path)

        output = _ytm.yaml_to_markdown_table(controls_file, "controls", table_format="summary")

        # Bound row isolation to the table portion only (References sections
        # come after the table and would sweep both entries' titles).
        table_end = output.find("## References for")
        table = output if table_end == -1 else output[:table_end]
        alpha_idx = table.find("controlAlpha")
        beta_idx = table.find("controlBeta")
        assert alpha_idx != -1, "controlAlpha not found in table"
        assert beta_idx != -1, "controlBeta not found in table"

        alpha_region = table[alpha_idx:beta_idx]
        beta_region = table[beta_idx:]

        assert "NIST-A Title" in alpha_region, (
            f"controlAlpha row must resolve {{{{ref:shared}}}} to 'NIST-A Title'; alpha_region:\n{alpha_region!r}"
        )
        assert "NIST-B Title" not in alpha_region, (
            "controlAlpha row must NOT contain 'NIST-B Title' (cross-entry collision)"
        )
        assert "NIST-B Title" in beta_region, (
            f"controlBeta row must resolve {{{{ref:shared}}}} to 'NIST-B Title'; beta_region:\n{beta_region!r}"
        )
        assert "NIST-A Title" not in beta_region, (
            "controlBeta row must NOT contain 'NIST-A Title' (cross-entry collision)"
        )

    def test_b1_cross_entry_ref_id_raises_unresolved_error(self, tmp_path: Path):
        """
        B1: A {{ref:id}} sentinel that is declared in a different entry but NOT in
        the entry that uses it must raise UnresolvedSentinelError after the fix.

        Given: risks.yaml with two risks:
               - riskAlpha: externalReferences=[]  (declares NO refs)
                            longDescription: "... see {{ref:cve-2024-99999}} ..."
               - riskBeta:  externalReferences=[{id:"cve-2024-99999", ...}]
                            longDescription: (no sentinel)
        When: yaml_to_markdown_table(risks_yaml, "risks", table_format="full") is called
        Then: (post-fix contract)
              UnresolvedSentinelError is raised for riskAlpha's reference to
              "cve-2024-99999" because that id is not in riskAlpha's own
              externalReferences (per-entry scope).

        RED failure (HEAD ebe4504):
              The flat lookup contains "cve-2024-99999" from riskBeta, so riskAlpha's
              sentinel resolves successfully and NO exception is raised.
              pytest.raises sees "DID NOT RAISE" — the correct RED failure signal.
        """
        _require_sentinel_module()
        import yaml as _yaml

        risks_data = {
            "risks": [
                {
                    "id": "riskAlpha",
                    "title": "Alpha Risk",
                    "category": "riskCatTest",
                    "shortDescription": ["Short alpha."],
                    "longDescription": ["Alpha mentions {{ref:cve-2024-99999}} for context."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    # riskAlpha declares NO externalReferences — it doesn't own this ref
                    "externalReferences": [],
                },
                {
                    "id": "riskBeta",
                    "title": "Beta Risk",
                    "category": "riskCatTest",
                    "shortDescription": ["Short beta."],
                    "longDescription": ["Beta description with no sentinel."],
                    "examples": [],
                    "personas": [],
                    "controls": [],
                    "externalReferences": [
                        {
                            "id": "cve-2024-99999",
                            "type": "cve",
                            "title": "CVE-2024-99999 Title",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-99999",
                        }
                    ],
                },
            ]
        }
        risks_file = tmp_path / "risks.yaml"
        risks_file.write_text(_yaml.dump(risks_data), encoding="utf-8")
        _write_sibling_yamls(tmp_path)

        # Post-fix: riskAlpha's {{ref:cve-2024-99999}} must raise because
        # cve-2024-99999 is NOT in riskAlpha's own externalReferences.
        # RED: on HEAD ebe4504 the flat lookup resolves it via riskBeta → no exception.
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            _ytm.yaml_to_markdown_table(risks_file, "risks", table_format="full")

        assert "cve-2024-99999" in str(exc_info.value), (
            f"Error message must identify the unresolved ref id; got: {exc_info.value!r}"
        )


# ============================================================================
# Test Summary
# ============================================================================
"""
Test Summary
============
Total test classes: 7
Total tests:        41

- TestCollapseColumnSentinelExpansion (13):
    plain text passthrough (no kwargs), newlines normalised (no kwargs),
    plain text unchanged with lookups, intra sentinel → plain title,
    ref sentinel → markdown link, mixed sentinels both expanded,
    multi-element list collapsed + expanded, None lookups pass-through (no error),
    explicit None pass-through, unresolved intra raises, unresolved ref raises,
    field_path kwarg accepted, field_path propagated to error

- TestFormatExternalReferences (8):
    empty list → "", None → "", single entry → header + one bullet,
    multiple entries in source order, type annotation in parens,
    H2 header (not H1/H3), special chars not escaped, three entries → three bullets

- TestFullDetailTableSentinelIntegration (6):
    no sentinels → output unchanged pre/post-A7, intra sentinel expanded in table,
    ref sentinel expanded to link in table, externalReferences sub-section emitted
    after table, unresolved intra raises UnresolvedSentinelError,
    unresolved ref raises UnresolvedSentinelError

- TestUnresolvedSentinelMarkdownSide (4):
    intra typo in longDescription raises (field_path check),
    ref typo in description raises, field_path names entry+field,
    SummaryTableGenerator also propagates error

- TestConvertTypeSurfacing (2):
    convert_type returns False on unresolved sentinel,
    error message stdout contains sentinel id

- TestExternalReferencesIntegration (5):
    single risk with refs → sub-section with two bullets,
    multiple risks with refs → multiple sub-sections,
    no externalReferences → no sub-section headers,
    sub-sections appear after main table (position check),
    empty externalReferences list → no sub-section

- TestSummaryTableSentinelIntegration (3):
    constructor accepts lookup kwargs (backward compat),
    intra sentinel expanded in shortDescription,
    externalReferences sub-section emitted

Coverage target: 90%+ on the new A7 wiring in yaml_to_markdown.py

Key contracts pinned:
  - collapse_column(entry, *, intra_lookup=None, ref_lookup=None, field_path=...)
    → when lookups are None, sentinels pass through; when non-None, sentinels expand
  - format_external_references(refs) -> str  (new public helper)
  - FullDetailTableGenerator(intra_lookup=None, ref_lookup=None)
  - SummaryTableGenerator(intra_lookup=None, ref_lookup=None)
  - ## References for {entry-id} sub-section after the markdown table
  - UnresolvedSentinelError propagates through generate(); convert_type returns False
  - Per-control guidance is expanded in the full table with the same rules as
    description (TestGuidanceSentinelExpansionInFullTable)
"""


# ============================================================================
# TestGuidanceSentinelExpansionInFullTable
# ============================================================================
# The optional per-control ``guidance`` field (ADR-020 D9 amendment; design
# record control-description-and-guidance.md) is resolved by every consumer
# that resolves sentinels in ``description``. The full-detail table therefore
# expands guidance per row with the same lookups, and an unresolved sentinel
# in guidance raises with a field_path naming guidance.
# ============================================================================


class TestGuidanceSentinelExpansionInFullTable:
    """Sentinels in a control's guidance are expanded in the full-detail table."""

    @staticmethod
    def _controls_yaml_data(guidance: list, ext_refs: list | None = None) -> dict:
        """Two synthetic controls so intra sentinels can resolve within the same data."""
        guided = {
            "id": "controlTestAlpha",
            "title": "Alpha Control",
            "category": "controlsTest",
            "description": ["What alpha is."],
            "personas": [],
            "components": [],
            "risks": [],
            "guidance": guidance,
        }
        if ext_refs is not None:
            guided["externalReferences"] = ext_refs
        sibling = {
            "id": "controlTestBeta",
            "title": "Beta Control",
            "category": "controlsTest",
            "description": ["What beta is."],
            "personas": [],
            "components": [],
            "risks": [],
        }
        return {"controls": [guided, sibling]}

    def test_intra_sentinel_in_guidance_expanded_in_output(self):
        """
        Given: A control whose guidance contains "{{controlTestBeta}}" and an intra_lookup
               mapping controlTestBeta -> "Beta Control"
        When: FullDetailTableGenerator.generate is called with that lookup
        Then: The output contains "Pair with Beta Control" and not the raw sentinel
        """
        _require_sentinel_module()
        gen_cls = _get_full_detail_generator()
        yaml_data = self._controls_yaml_data(["Pair with {{controlTestBeta}} for depth."])
        intra = {"controlTestAlpha": "Alpha Control", "controlTestBeta": "Beta Control"}

        output = gen_cls(intra_lookup=intra, ref_lookup={}).generate(yaml_data, "controls")

        assert "Pair with Beta Control" in output, output
        assert "{{controlTestBeta}}" not in output

    def test_ref_sentinel_in_guidance_expanded_to_link(self):
        """
        Given: A control whose guidance contains "{{ref:cwe-89}}" and a matching
               externalReferences entry on that control
        When: FullDetailTableGenerator.generate is called with lookups
        Then: The output contains the reference URL and not the raw sentinel
        """
        _require_sentinel_module()
        gen_cls = _get_full_detail_generator()
        yaml_data = self._controls_yaml_data(
            ["Addresses {{ref:cwe-89}} directly."],
            ext_refs=[
                {
                    "type": "cwe",
                    "id": "cwe-89",
                    "title": "CWE-89: SQL Injection",
                    "url": "https://cwe.mitre.org/data/definitions/89.html",
                }
            ],
        )

        output = gen_cls(intra_lookup={}, ref_lookup={}).generate(yaml_data, "controls")

        assert "https://cwe.mitre.org/data/definitions/89.html" in output, output
        assert "{{ref:cwe-89}}" not in output

    def test_unresolved_sentinel_in_guidance_raises_with_guidance_field_path(self):
        """
        Given: A control whose guidance contains "{{controlDoesNotExist}}"
        When: FullDetailTableGenerator.generate is called with lookups
        Then: UnresolvedSentinelError is raised and its message names "guidance"
        """
        _require_sentinel_module()
        gen_cls = _get_full_detail_generator()
        yaml_data = self._controls_yaml_data(["See {{controlDoesNotExist}}."])

        gen = gen_cls(intra_lookup={"controlTestBeta": "Beta Control"}, ref_lookup={})
        with pytest.raises(UnresolvedSentinelError) as exc_info:
            gen.generate(yaml_data, "controls")

        assert "guidance" in str(exc_info.value), f"error must name the guidance field: {exc_info.value}"
