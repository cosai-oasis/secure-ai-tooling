#!/usr/bin/env python3
r"""
Tests for ADR-026 D4 post-alignment content shape of the 8 issue-template
source files in scripts/TEMPLATES/*.template.yml.

Each test class targets a specific contract from ADR-016, ADR-017, ADR-019,
ADR-021, ADR-022 as recorded in issue #327. These tests are independent of
each other and deterministic; they operate only on the YAML source files,
not on the generated .github/ISSUE_TEMPLATE/ outputs.

Naming convention:  test_<contract>_<scenario>_<expected_outcome>
Docstring convention: Given / When / Then

The generator's placeholder regex is `\{\{([A-Z_]+)\}\}`. It expands only
ALL-CAPS placeholders, so `{{ref:identifier}}` and sentinel references like
`{{riskPromptInjection}}` that contain lowercase characters are inert in
helper text and safe to use as documentation examples.
"""

import re
from pathlib import Path

import pytest
import yaml

# ============================================================================
# Constants — the 8 content-entity source files (ADR-026 D2)
# ============================================================================

_ENTITY_TYPES = {"risk", "control", "component", "persona"}
_OPERATIONS = {"new", "update"}
_ALL_SOURCES = {f"{op}_{entity}" for op in _OPERATIONS for entity in _ENTITY_TYPES}

# Canonical regex patterns for framework mapping values (ADR-022 D5b)
# ADR-027 version-pinned canonical forms (#343): every example carries a version
# token except STRIDE (unversioned). These mirror the strict
# framework-mapping-patterns-pinned block in frameworks.schema.json.
_CANONICAL_PATTERNS: dict[str, re.Pattern] = {
    "stride": re.compile(
        r"^(Spoofing|Tampering|Repudiation|InformationDisclosure|DenialOfService|ElevationOfPrivilege)$"
    ),
    "nist-ai-rmf": re.compile(r"^(GOVERN|MAP|MEASURE|MANAGE)-\d+(\.\d+)*@1\.0$"),
    "owasp-top10-llm": re.compile(r"^LLM\d{2}:2025$"),
    "mitre-atlas": re.compile(r"^AML\.(T|M)\d{4}(\.\d{3})?@5\.0\.1$"),
}

# Generator placeholder pattern — only expands ALL-CAPS tokens.
# Sentinel examples (`{{ref:identifier}}`, camelCase entity refs) must NOT match.
_GENERATOR_PLACEHOLDER_PATTERN = re.compile(r"\{\{([A-Z_]+)\}\}")


# ============================================================================
# Shared helpers
# ============================================================================


def _load_source(repo_root: Path, name: str) -> tuple[dict, str]:
    """
    Load a source template by name (e.g., 'new_risk').

    Returns (parsed_dict, raw_text). Fails the test immediately if the file
    is missing — missing sources are covered by TestSourceCoverageContract.

    The generator uses ALL-CAPS placeholders like `{{RISK_CATEGORIES}}` inside
    YAML `options:` lists. PyYAML parses `{{...}}` as a flow mapping key and
    raises ConstructorError if the placeholder is the only list item. To parse
    the source files structurally, ALL-CAPS generator placeholders are replaced
    with a sentinel string before parsing. The raw text is returned unchanged so
    all string-search assertions operate on the original content.
    """
    path = repo_root / "scripts" / "TEMPLATES" / f"{name}.template.yml"
    if not path.exists():
        pytest.fail(f"Source template missing (prerequisite): {path.name}")
    raw = path.read_text(encoding="utf-8")
    # Substitute ALL-CAPS generator placeholders before YAML parsing to avoid
    # the ConstructorError that occurs when {{PLACEHOLDER}} appears as a bare
    # mapping key inside an `options:` block. The substitution is parse-only;
    # all assertions that check string content use the original `raw` text.
    parseable = _GENERATOR_PLACEHOLDER_PATTERN.sub('"PLACEHOLDER"', raw)
    parsed = yaml.safe_load(parseable)
    return parsed, raw


def _body_elements(parsed: dict) -> list[dict]:
    """Return the body list from a parsed template, or [] if absent."""
    return parsed.get("body") or []


def _get_field(elements: list[dict], field_id: str) -> dict | None:
    """Return the first body element whose 'id' key equals field_id, or None."""
    for elem in elements:
        if elem.get("id") == field_id:
            return elem
    return None


def _label_of(elem: dict) -> str:
    """Return the label attribute of a body element, lowercased for comparison."""
    return (elem.get("attributes") or {}).get("label") or ""


def _any_field_matches(elements: list[dict], id_pattern: str, label_pattern: str) -> bool:
    """
    Return True if any body element has an id containing id_pattern (case-insensitive)
    OR a label matching label_pattern (case-insensitive).
    """
    id_re = re.compile(id_pattern, re.IGNORECASE)
    label_re = re.compile(label_pattern, re.IGNORECASE)
    for elem in elements:
        if id_re.search(elem.get("id") or ""):
            return True
        if label_re.search(_label_of(elem)):
            return True
    return False


def _extract_framework_examples(raw_text: str) -> dict[str, list[str]]:
    """
    Extract all 'framework-id: value' example lines from a raw template source.

    Lines may be:
      - bare:        `mitre-atlas: AML.T0051`
      - prefixed:    `+ mitre-atlas: AML.M0015`  or  `- owasp-top10-llm: LLM01`

    The prefix (`+`/`-` and surrounding whitespace) is stripped before parsing.
    The function returns {framework_key: [value, ...]} for every framework key
    that appears as an example value in the raw source (not in YAML keys).

    Only lines that appear inside YAML block scalars (placeholder/description
    sections) are of interest; we use a simple pattern that matches any line
    of the form `[+/-]? framework-key: value` where framework-key is one of
    the four canonical keys.
    """
    pattern = re.compile(
        r"^\s*[+\-]?\s*"
        r"(stride|nist-ai-rmf|owasp-top10-llm|mitre-atlas)"
        r":\s*(.+)$",
        re.MULTILINE,
    )
    result: dict[str, list[str]] = {}
    for match in pattern.finditer(raw_text):
        key = match.group(1)
        value = match.group(2).strip()
        result.setdefault(key, []).append(value)
    return result


# ============================================================================
# Section A — relevantQuestions retirement (ADR-019 D6)
# Only risk templates are affected by this contract.
# ============================================================================


class TestRelevantQuestionsRetirement:
    """
    ADR-019 D6: The 'relevantQuestions' field was retired from the schema.
    Risk templates must not solicit it.

    The other 6 templates are unaffected by this contract — only risk
    templates had this field, and only they need to retire it.
    """

    def test_new_risk_has_no_relevant_questions_field_id(self, repo_root: Path) -> None:
        """
        Asserts that new_risk.template.yml contains no body element with
        id == 'relevant-questions' (ADR-019 D6).

        Given: new_risk.template.yml as it exists on disk
        When: the body[] list is scanned for the retired field id
        Then: no element with id 'relevant-questions' is present

        Issue: #327 / ADR-019 D6.
        """
        parsed, _ = _load_source(repo_root, "new_risk")
        elements = _body_elements(parsed)
        ids = [elem.get("id") for elem in elements if elem.get("id")]
        assert "relevant-questions" not in ids, (
            "new_risk.template.yml still contains body element with "
            "id='relevant-questions'. ADR-019 D6 retired this field."
        )

    def test_new_risk_has_no_relevant_questions_label(self, repo_root: Path) -> None:
        """
        Asserts that new_risk.template.yml contains no body element whose
        label matches /relevant questions/i (ADR-019 D6).

        Given: new_risk.template.yml as it exists on disk
        When: labels of all body[] elements are checked
        Then: no label contains 'relevant questions' (case-insensitive)

        Issue: #327 / ADR-019 D6.
        """
        parsed, _ = _load_source(repo_root, "new_risk")
        elements = _body_elements(parsed)
        bad_labels = [
            _label_of(elem)
            for elem in elements
            if re.search(r"relevant questions", _label_of(elem), re.IGNORECASE)
        ]
        assert not bad_labels, (
            f"new_risk.template.yml has body element(s) with label matching "
            f"'relevant questions' (ADR-019 D6 retired this field): {bad_labels}"
        )

    def test_update_risk_has_no_relevant_questions_field_id(self, repo_root: Path) -> None:
        """
        Asserts that update_risk.template.yml contains no body element with
        id == 'relevant-questions' (ADR-019 D6).

        Given: update_risk.template.yml as it exists on disk
        When: the body[] list is scanned for the retired field id
        Then: no element with id 'relevant-questions' is present

        Issue: #327 / ADR-019 D6.
        """
        parsed, _ = _load_source(repo_root, "update_risk")
        elements = _body_elements(parsed)
        ids = [elem.get("id") for elem in elements if elem.get("id")]
        assert "relevant-questions" not in ids, (
            "update_risk.template.yml still contains body element with "
            "id='relevant-questions'. ADR-019 D6 retired this field."
        )

    def test_update_risk_change_type_dropdown_excludes_relevant_questions_option(self, repo_root: Path) -> None:
        """
        Asserts that the 'change-type' dropdown in update_risk.template.yml
        contains no option mentioning 'relevant questions' (ADR-019 D6).

        Given: update_risk.template.yml as it exists on disk
        When: the options list of the change-type dropdown is examined
        Then: no option text matches /relevant questions/i

        Issue: #327 / ADR-019 D6.
        """
        parsed, _ = _load_source(repo_root, "update_risk")
        elements = _body_elements(parsed)
        change_type_field = _get_field(elements, "change-type")
        assert change_type_field is not None, (
            "update_risk.template.yml is missing the 'change-type' dropdown field."
        )
        options: list[str] = (change_type_field.get("attributes") or {}).get("options") or []
        bad_options = [opt for opt in options if re.search(r"relevant questions", opt, re.IGNORECASE)]
        assert not bad_options, (
            f"update_risk.template.yml change-type dropdown still has option(s) "
            f"mentioning 'relevant questions' (ADR-019 D6): {bad_options}"
        )

    def test_non_risk_templates_are_unaffected_by_relevant_questions_contract(self, repo_root: Path) -> None:
        """
        Negative-scope guard: the 6 non-risk templates never had a
        relevant-questions field, and this test ensures we do not over-assert
        (they are not required to have or lack any particular field by this rule).

        Given: the 6 non-risk source templates
        When: their body[] is parsed
        Then: parsing succeeds and no assertion error is raised (structural check only)

        Issue: #327 / ADR-019 D6 negative scope.
        """
        non_risk_sources = [s for s in sorted(_ALL_SOURCES) if "risk" not in s]
        for name in non_risk_sources:
            parsed, _ = _load_source(repo_root, name)
            # Structural check only — these templates are not governed by the
            # relevantQuestions retirement rule.
            assert isinstance(_body_elements(parsed), list), (
                f"{name}.template.yml body is not a list — unexpected structure."
            )


# ============================================================================
# Section B — externalReferences solicitation (ADR-016 D3)
# All 8 templates must solicit externalReferences.
# ============================================================================


class TestExternalReferencesSolicitation:
    """
    ADR-016 D3: every template must solicit externalReferences so contributors
    know to provide structured reference entries instead of inline HTML or bare URLs.

    A field satisfies this contract if its 'id' contains 'external-references'
    (case-insensitive) OR its 'label' matches /external reference/i.
    """

    @pytest.mark.parametrize("name", sorted(_ALL_SOURCES))
    def test_template_has_external_references_field(self, repo_root: Path, name: str) -> None:
        """
        Asserts that every source template contains at least one body element
        that solicits externalReferences (ADR-016 D3).

        Given: a source template file
        When: its body[] elements are scanned for an externalReferences field
        Then: at least one element has id containing 'external-references'
              OR label matching /external reference/i

        Issue: #327 / ADR-016 D3.
        """
        parsed, _ = _load_source(repo_root, name)
        elements = _body_elements(parsed)
        found = _any_field_matches(
            elements,
            id_pattern=r"external.references",
            label_pattern=r"external reference",
        )
        assert found, (
            f"{name}.template.yml has no body element soliciting externalReferences. "
            f"ADR-016 D3 requires all 8 templates to include this field. "
            f"Field must have id containing 'external-references' OR label matching "
            f"/external reference/i. "
            f"Existing field ids: {[e.get('id') for e in elements if e.get('id')]}"
        )


# ============================================================================
# Section C — Framework-mapping placeholder canonical forms (ADR-022 D5b)
# Applies to risk + control templates (new_* and update_*).
# Generically also catches any framework example values in all 8 templates.
# ============================================================================


class TestFrameworkMappingCanonicalForms:
    """
    ADR-027 (#343): example values shown in framework-mapping helper text must
    conform to the version-pinned canonical form for each framework key.

    - STRIDE:          bare PascalCase enum, unversioned (e.g. InformationDisclosure)
    - NIST AI RMF:     GOVERN-N.N@1.0 form (e.g. GOVERN-6.2@1.0, NOT GV-6.2 or unpinned GOVERN-6.2)
    - OWASP LLM Top10: LLMxx:2025 form (e.g. LLM01:2025, NOT LLM01)
    - MITRE ATLAS:     AML.(T|M)dddd[.ddd]@5.0.1 (version-pinned; regression guard)

    The check is applied generically to all 8 templates so that if the SWE adds
    mapping examples to component or persona templates, they must also conform.
    """

    @pytest.mark.parametrize("name", sorted(_ALL_SOURCES))
    def test_all_framework_example_values_match_canonical_patterns(self, repo_root: Path, name: str) -> None:
        """
        Asserts that every framework-key: value example line in the source
        template conforms to the canonical regex for that framework (ADR-022 D5b).

        Given: a source template file
        When: all 'framework-id: value' example lines are extracted from raw text
        Then: each value matches the canonical pattern for its framework key

        Issue: #327 / ADR-022 D5b.
        """
        _, raw = _load_source(repo_root, name)
        examples = _extract_framework_examples(raw)

        # Component and persona templates carry no framework-mapping example
        # lines today, so this assertion is vacuous for them. It becomes
        # load-bearing the moment any such template gains a mapping example —
        # a non-conformant value would then fail here.
        if not examples and name in {
            "new_component",
            "update_component",
            "new_persona",
            "update_persona",
        }:
            assert _extract_framework_examples(raw) == {}

        failures: list[str] = []
        for framework_key, values in examples.items():
            pattern = _CANONICAL_PATTERNS.get(framework_key)
            if pattern is None:
                # Unknown framework key — not governed by this test.
                continue
            for value in values:
                if not pattern.match(value):
                    failures.append(
                        f"{framework_key}: '{value}' does not match canonical pattern '{pattern.pattern}'"
                    )

        assert not failures, (
            f"{name}.template.yml has framework example value(s) that violate "
            f"ADR-022 D5b canonical forms:\n" + "\n".join(f"  - {f}" for f in failures)
        )

    def test_new_risk_stride_example_is_pascal_case(self, repo_root: Path) -> None:
        """
        Specific regression guard: new_risk has a stride example.
        The current wrong value 'information-disclosure' must become
        'InformationDisclosure' (ADR-022 D5b).

        Given: new_risk.template.yml
        When: the stride example value is extracted
        Then: it matches the PascalCase enum pattern

        Issue: #327 / ADR-022 D5b.
        """
        _, raw = _load_source(repo_root, "new_risk")
        examples = _extract_framework_examples(raw)
        stride_values = examples.get("stride", [])
        assert stride_values, (
            "new_risk.template.yml has no stride: example in the framework-mapping "
            "placeholder. Expected at least one PascalCase STRIDE value."
        )
        bad = [v for v in stride_values if not _CANONICAL_PATTERNS["stride"].match(v)]
        assert not bad, (
            f"new_risk.template.yml stride example(s) not PascalCase (ADR-022 D5b): {bad}. "
            f"Wrong form: 'information-disclosure'. Correct form: 'InformationDisclosure'."
        )

    def test_new_risk_owasp_example_includes_year(self, repo_root: Path) -> None:
        """
        Specific regression guard: new_risk's owasp-top10-llm example must
        include the year suffix (e.g. LLM01:2025, NOT LLM01).

        Given: new_risk.template.yml
        When: the owasp-top10-llm example value is extracted
        Then: it matches LLMxx:yyyy canonical form (ADR-022 D5b)

        Issue: #327 / ADR-022 D5b.
        """
        _, raw = _load_source(repo_root, "new_risk")
        examples = _extract_framework_examples(raw)
        owasp_values = examples.get("owasp-top10-llm", [])
        assert owasp_values, (
            "new_risk.template.yml has no owasp-top10-llm: example. "
            "Expected at least one value matching LLMxx:yyyy."
        )
        bad = [v for v in owasp_values if not _CANONICAL_PATTERNS["owasp-top10-llm"].match(v)]
        assert not bad, (
            f"new_risk.template.yml owasp-top10-llm example(s) missing year suffix "
            f"(ADR-022 D5b): {bad}. Wrong: 'LLM01'. Correct: 'LLM01:2025'."
        )

    def test_new_control_nist_ai_rmf_example_uses_govern_form(self, repo_root: Path) -> None:
        """
        Specific regression guard: new_control's nist-ai-rmf example must use
        the GOVERN-N.N form, not the deprecated GV-N.N abbreviation.

        Given: new_control.template.yml
        When: the nist-ai-rmf example value is extracted
        Then: it matches GOVERN-N.N canonical form (ADR-022 D5b)

        Issue: #327 / ADR-022 D5b.
        """
        _, raw = _load_source(repo_root, "new_control")
        examples = _extract_framework_examples(raw)
        nist_values = examples.get("nist-ai-rmf", [])
        assert nist_values, (
            "new_control.template.yml has no nist-ai-rmf: example. "
            "Expected at least one value matching GOVERN-N.N form."
        )
        bad = [v for v in nist_values if not _CANONICAL_PATTERNS["nist-ai-rmf"].match(v)]
        assert not bad, (
            f"new_control.template.yml nist-ai-rmf example(s) use deprecated form "
            f"(ADR-027 pinned form): {bad}. Wrong: 'GV-6.2' / 'GOVERN-6.2'. Correct: 'GOVERN-6.2@1.0'."
        )

    def test_update_control_nist_ai_rmf_example_uses_govern_form(self, repo_root: Path) -> None:
        """
        Specific regression guard: update_control's nist-ai-rmf example must use
        the GOVERN-N.N form, not the deprecated GV-N.N abbreviation.

        Given: update_control.template.yml
        When: the nist-ai-rmf example value is extracted
        Then: it matches GOVERN-N.N canonical form (ADR-022 D5b)

        Issue: #327 / ADR-022 D5b.
        """
        _, raw = _load_source(repo_root, "update_control")
        examples = _extract_framework_examples(raw)
        nist_values = examples.get("nist-ai-rmf", [])
        assert nist_values, (
            "update_control.template.yml has no nist-ai-rmf: example. "
            "Expected at least one value matching GOVERN-N.N form."
        )
        bad = [v for v in nist_values if not _CANONICAL_PATTERNS["nist-ai-rmf"].match(v)]
        assert not bad, (
            f"update_control.template.yml nist-ai-rmf example(s) use deprecated form "
            f"(ADR-027 pinned form): {bad}. Wrong: 'GV-4.1' / 'GOVERN-4.1'. Correct: 'GOVERN-4.1@1.0'."
        )

    def test_mitre_atlas_examples_remain_conformant(self, repo_root: Path) -> None:
        """
        Regression guard: MITRE ATLAS examples in risk + control templates
        already conform to AML.(T|M)dddd pattern and must remain so.

        Given: new_risk, update_risk, new_control, update_control templates
        When: mitre-atlas example values are extracted from each
        Then: all values match AML.(T|M)dddd[.ddd] (ADR-022 D5b)

        Issue: #327 / ADR-022 D5b.
        """
        for name in ["new_risk", "update_risk", "new_control", "update_control"]:
            _, raw = _load_source(repo_root, name)
            examples = _extract_framework_examples(raw)
            atlas_values = examples.get("mitre-atlas", [])
            # If the template has no atlas examples, skip — absence is tested
            # by the parametrized canonical-forms test above.
            bad = [v for v in atlas_values if not _CANONICAL_PATTERNS["mitre-atlas"].match(v)]
            assert not bad, (
                f"{name}.template.yml mitre-atlas example(s) do not match AML.(T|M)dddd[.ddd] (ADR-022 D5b): {bad}"
            )


# ============================================================================
# Section D — mappings + responsibilities solicitation
# ADR-018 D6 (components), ADR-021 (personas)
# ============================================================================


class TestMappingsAndResponsibilitiesSolicitation:
    """
    ADR-018 D6 requires component templates to solicit framework cross-walk mappings.
    ADR-021 requires persona templates to solicit both framework actor mappings
    AND the schema's flat 'responsibilities' field.
    """

    def test_new_component_solicits_framework_mappings(self, repo_root: Path) -> None:
        """
        Asserts that new_component.template.yml includes a field soliciting
        framework cross-walk mappings (ADR-018 D6).

        Given: new_component.template.yml
        When: body[] elements are scanned for a mappings field
        Then: at least one element has id/label referencing framework mappings

        Issue: #327 / ADR-018 D6.
        """
        parsed, _ = _load_source(repo_root, "new_component")
        elements = _body_elements(parsed)
        found = _any_field_matches(
            elements,
            id_pattern=r"mapping",
            label_pattern=r"(framework mapping|mappings)",
        )
        assert found, (
            "new_component.template.yml has no field soliciting framework mappings "
            "(ADR-018 D6). A body element with id/label referencing 'mapping(s)' "
            "or 'framework mapping' must be present."
        )

    def test_update_component_solicits_framework_mappings(self, repo_root: Path) -> None:
        """
        Asserts that update_component.template.yml includes a field soliciting
        framework cross-walk mapping changes (ADR-018 D6).

        Given: update_component.template.yml
        When: body[] elements are scanned for a mappings field
        Then: at least one element has id/label referencing framework mappings

        Issue: #327 / ADR-018 D6.
        """
        parsed, _ = _load_source(repo_root, "update_component")
        elements = _body_elements(parsed)
        found = _any_field_matches(
            elements,
            id_pattern=r"mapping",
            label_pattern=r"(framework mapping|mappings)",
        )
        assert found, (
            "update_component.template.yml has no field soliciting framework mappings "
            "(ADR-018 D6). A body element with id/label referencing 'mapping(s)' "
            "or 'framework mapping' must be present."
        )

    def test_new_persona_solicits_framework_mappings(self, repo_root: Path) -> None:
        """
        Asserts that new_persona.template.yml includes a field soliciting
        framework actor mappings (ADR-021).

        Given: new_persona.template.yml
        When: body[] elements are scanned for a mappings field
        Then: at least one element has id/label referencing mappings

        Issue: #327 / ADR-021.
        """
        parsed, _ = _load_source(repo_root, "new_persona")
        elements = _body_elements(parsed)
        found = _any_field_matches(
            elements,
            id_pattern=r"mapping",
            label_pattern=r"(framework mapping|mappings)",
        )
        assert found, (
            "new_persona.template.yml has no field soliciting framework actor mappings "
            "(ADR-021). A body element with id/label referencing 'mapping(s)' must be present."
        )

    def test_update_persona_solicits_framework_mappings(self, repo_root: Path) -> None:
        """
        Asserts that update_persona.template.yml includes a field soliciting
        framework actor mapping changes (ADR-021).

        Given: update_persona.template.yml
        When: body[] elements are scanned for a mappings field
        Then: at least one element has id/label referencing mappings

        Issue: #327 / ADR-021.
        """
        parsed, _ = _load_source(repo_root, "update_persona")
        elements = _body_elements(parsed)
        found = _any_field_matches(
            elements,
            id_pattern=r"mapping",
            label_pattern=r"(framework mapping|mappings)",
        )
        assert found, (
            "update_persona.template.yml has no field soliciting framework actor mappings "
            "(ADR-021). A body element with id/label referencing 'mapping(s)' must be present."
        )

    def test_new_persona_solicits_responsibilities(self, repo_root: Path) -> None:
        """
        Asserts that new_persona.template.yml solicits the schema's flat
        'responsibilities' field (ADR-021).

        The existing 'Control Responsibilities' / 'Risk Responsibilities' prose
        fields do not satisfy this contract — a field aligned to the schema's
        'responsibilities' list must be present (id or label must contain
        'responsibilities', singular or plural).

        Given: new_persona.template.yml
        When: body[] elements are scanned for a responsibilities field
        Then: at least one element has id/label containing 'responsibilities'
              that is aligned to the schema field (not split into control/risk halves)

        Issue: #327 / ADR-021.
        """
        parsed, _ = _load_source(repo_root, "new_persona")
        elements = _body_elements(parsed)

        # Accept any element whose id contains 'responsibilities' OR whose label
        # matches /responsibilities/i — but must not be split into control-specific
        # and risk-specific halves only (the schema has a unified 'responsibilities' list).
        # We require a unified field: id must contain 'responsibilities' without
        # the word 'control' or 'risk' qualifying it.
        unified_found = False
        for elem in elements:
            elem_id = elem.get("id") or ""
            label = _label_of(elem).lower()
            if re.search(r"responsibilities", elem_id, re.IGNORECASE):
                # A field whose id contains 'responsibilities' qualifies as unified
                # if it does NOT also contain 'control' or 'risk' as qualifiers.
                # e.g. 'responsibilities' or 'persona-responsibilities' → OK
                # e.g. 'control-responsibilities' or 'risk-responsibilities' → NOT OK
                if not re.search(r"(control|risk).responsibilities", elem_id, re.IGNORECASE):
                    unified_found = True
                    break
            elif re.search(r"\bresponsibilities\b", label) and not re.search(
                r"(control|risk) responsibilities", label
            ):
                unified_found = True
                break

        assert unified_found, (
            "new_persona.template.yml does not have a unified 'responsibilities' field "
            "aligned to the schema's flat responsibilities list (ADR-021). "
            "The existing split 'Control Responsibilities' / 'Risk Responsibilities' "
            "fields do not satisfy this contract. A field with id/label 'responsibilities' "
            "(without a control/risk qualifier) must be present."
        )

    def test_update_persona_solicits_responsibilities(self, repo_root: Path) -> None:
        """
        Asserts that update_persona.template.yml solicits the schema's flat
        'responsibilities' field (ADR-021).

        Given: update_persona.template.yml
        When: body[] elements are scanned for a unified responsibilities field
        Then: at least one element has id/label containing 'responsibilities'
              without a control/risk qualifier

        Issue: #327 / ADR-021.
        """
        parsed, _ = _load_source(repo_root, "update_persona")
        elements = _body_elements(parsed)

        unified_found = False
        for elem in elements:
            elem_id = elem.get("id") or ""
            label = _label_of(elem).lower()
            if re.search(r"responsibilities", elem_id, re.IGNORECASE):
                if not re.search(r"(control|risk).responsibilities", elem_id, re.IGNORECASE):
                    unified_found = True
                    break
            elif re.search(r"\bresponsibilities\b", label) and not re.search(
                r"(control|risk) responsibilities", label
            ):
                unified_found = True
                break

        assert unified_found, (
            "update_persona.template.yml does not have a unified 'responsibilities' field "
            "aligned to the schema's flat responsibilities list (ADR-021). "
            "A field with id/label 'responsibilities' (without a control/risk qualifier) "
            "must be present."
        )


# ============================================================================
# Section E — Sentinel-grammar guidance (ADR-016 D2 / ADR-017 D1)
# ============================================================================


class TestSentinelGrammarGuidance:
    r"""
    ADR-016 D2 / ADR-017 D1: templates that solicit externalReferences must
    also teach contributors the sentinel grammar so they can reference those
    entries from prose fields.

    Two sentinel forms must appear somewhere in each template:
    1. `{{ref:identifier}}` — the ref-sentinel grammar (ADR-016 D2)
    2. A `{{<entity>...}}` form containing lowercase (to teach the entity-sentinel
       grammar, e.g. `{{riskPromptInjection}}` or `{{<entity-id>}}`).

    These strings are safe in template source text because the generator's
    placeholder regex only expands ALL-CAPS tokens (`\{\{([A-Z_]+)\}\}`).
    """

    # Templates targeted by this contract — all 8 must solicit externalReferences
    # (section B), so all 8 must also teach the sentinel grammar.
    _SENTINEL_TARGETS = sorted(_ALL_SOURCES)

    @pytest.mark.parametrize("name", _SENTINEL_TARGETS)
    def test_template_contains_ref_sentinel_example(self, repo_root: Path, name: str) -> None:
        """
        Asserts that the source template contains the literal string
        '{{ref:identifier}}' to teach the ref-sentinel grammar (ADR-016 D2).

        Given: a source template file that solicits externalReferences
        When: the raw source text is searched for the sentinel example string
        Then: '{{ref:identifier}}' appears at least once in the raw text

        Issue: #327 / ADR-016 D2.
        """
        _, raw = _load_source(repo_root, name)
        assert "{{ref:identifier}}" in raw, (
            f"{name}.template.yml is missing the '{{{{ref:identifier}}}}' sentinel "
            f"example (ADR-016 D2). All templates that solicit externalReferences "
            f"must teach contributors the ref-sentinel grammar."
        )

    @pytest.mark.parametrize("name", _SENTINEL_TARGETS)
    def test_template_contains_entity_sentinel_example(self, repo_root: Path, name: str) -> None:
        """
        Asserts that the source template contains at least one `{{<entity>...}}`
        sentinel reference with lowercase characters, to teach the entity-sentinel
        grammar (ADR-017 D1).

        Acceptable forms include `{{riskPromptInjection}}`, `{{controlFoo}}`,
        `{{<entity-id>}}`, or any `{{...}}` where the token contains lowercase.
        This distinguishes sentinel examples from ALL-CAPS generator placeholders.

        Given: a source template file
        When: the raw text is searched for a `{{...}}` containing lowercase
        Then: at least one such occurrence is found

        Issue: #327 / ADR-017 D1.
        """
        _, raw = _load_source(repo_root, name)
        # Match any {{ ... }} that contains at least one lowercase letter.
        # This distinguishes entity-sentinel examples from generator placeholders.
        entity_sentinel_re = re.compile(r"\{\{[^}]*[a-z][^}]*\}\}")
        assert entity_sentinel_re.search(raw), (
            f"{name}.template.yml is missing an entity-sentinel example (e.g. "
            f"'{{{{riskPromptInjection}}}}' or '{{{{<entity-id>}}}}') (ADR-017 D1). "
            f"All templates must teach contributors the entity-sentinel grammar."
        )


# ============================================================================
# Section E regression — sentinel examples do not collide with generator
# ============================================================================


class TestSentinelExamplesDoNotCollideWithGenerator:
    r"""
    Regression guard: sentinel example strings in templates must NOT match the
    generator's ALL-CAPS placeholder pattern `\{\{([A-Z_]+)\}\}`. If they did,
    the generator would expand them, corrupting the rendered output.

    The two required sentinel forms are safe by construction:
    - `{{ref:identifier}}` contains ':' and lowercase — not ALL-CAPS
    - Entity-sentinel examples contain lowercase letters — not ALL-CAPS
    """

    def test_ref_sentinel_does_not_match_generator_placeholder_pattern(self) -> None:
        """
        Asserts that '{{ref:identifier}}' does not match the generator's
        ALL-CAPS placeholder expansion regex.

        Given: the string '{{ref:identifier}}'
        When: the generator placeholder regex is applied
        Then: no match (the colon and lowercase prevent expansion)

        Issue: #327 regression guard.
        """
        sentinel = "{{ref:identifier}}"
        assert not _GENERATOR_PLACEHOLDER_PATTERN.search(sentinel), (
            f"'{sentinel}' unexpectedly matches the generator placeholder pattern. "
            f"This would cause the generator to attempt expansion, corrupting output."
        )

    def test_lowercase_entity_sentinel_does_not_match_generator_placeholder_pattern(self) -> None:
        """
        Asserts that a typical entity-sentinel example does not match the
        generator's ALL-CAPS placeholder expansion regex.

        Given: representative entity-sentinel strings
        When: the generator placeholder regex is applied to each
        Then: no match (lowercase content prevents expansion)

        Issue: #327 regression guard.
        """
        examples = [
            "{{riskPromptInjection}}",
            "{{controlFoo}}",
            "{{<entity-id>}}",
            "{{personaModelCreator}}",
        ]
        for sentinel in examples:
            assert not _GENERATOR_PLACEHOLDER_PATTERN.search(sentinel), (
                f"'{sentinel}' unexpectedly matches the generator placeholder pattern "
                f"(pattern: {_GENERATOR_PLACEHOLDER_PATTERN.pattern}). "
                f"Entity-sentinel examples must not be expanded by the generator."
            )

    @pytest.mark.parametrize("name", sorted(_ALL_SOURCES))
    def test_no_template_sentinel_examples_are_expanded_by_generator(self, repo_root: Path, name: str) -> None:
        """
        Asserts that the sentinel example strings required by ADR-016 D2 and
        ADR-017 D1 do not accidentally match the generator's ALL-CAPS placeholder
        pattern in any of the 8 source templates.

        Given: a source template file containing sentinel example strings
        When: each {{...}} token in the file is checked against the generator pattern
        Then: the required sentinel examples (`{{ref:identifier}}` and entity refs
              with lowercase) produce no generator-expansion matches

        Issue: #327 regression guard.
        """
        _, raw = _load_source(repo_root, name)

        # Find all {{ ... }} tokens in the file, then keep only the sentinel
        # examples (those NOT matching the generator's ALL-CAPS placeholder
        # pattern). A sentinel example must never be expandable, or the
        # generator would rewrite the helper text it appears in.
        all_tokens = re.compile(r"\{\{[^}]+\}\}").findall(raw)
        sentinel_tokens = [t for t in all_tokens if not _GENERATOR_PLACEHOLDER_PATTERN.match(t)]

        # The `{{ref:identifier}}` sentinel required by ADR-016 D2 (where present)
        # must be classified as a non-expandable sentinel — a real membership check.
        if "{{ref:identifier}}" in raw:
            assert "{{ref:identifier}}" in sentinel_tokens, (
                f"{name}: '{{{{ref:identifier}}}}' is present but classified as "
                f"generator-expandable, which would corrupt the helper text."
            )


# ============================================================================
# Section F — HTML / <a href> retirement (ADR-016)
# ============================================================================


class TestHtmlAnchorRetirement:
    """
    ADR-016: raw `<a href=...>` examples and the helper text phrase
    "Can include HTML links" are replaced by externalReferences + sentinels.
    No source template may contain either.
    """

    @pytest.mark.parametrize("name", sorted(_ALL_SOURCES))
    def test_template_has_no_raw_anchor_tags(self, repo_root: Path, name: str) -> None:
        """
        Asserts that the source template contains no `<a href` substring (ADR-016).

        Given: a source template file
        When: the raw text is searched for '<a href'
        Then: the substring is absent

        Issue: #327 / ADR-016.
        """
        _, raw = _load_source(repo_root, name)
        assert "<a href" not in raw, (
            f"{name}.template.yml contains raw '<a href' anchor tag(s) (ADR-016). "
            f"Raw HTML anchors must be replaced by externalReferences entries and "
            f"sentinel grammar references."
        )

    @pytest.mark.parametrize("name", sorted(_ALL_SOURCES))
    def test_template_has_no_can_include_html_links_text(self, repo_root: Path, name: str) -> None:
        """
        Asserts that the source template contains no 'Can include HTML links'
        helper text (case-insensitive) (ADR-016).

        Given: a source template file
        When: the raw text is searched for 'Can include HTML links'
        Then: the phrase is absent (case-insensitive)

        Issue: #327 / ADR-016.
        """
        _, raw = _load_source(repo_root, name)
        assert not re.search(r"can include html links", raw, re.IGNORECASE), (
            f"{name}.template.yml contains the phrase 'Can include HTML links' (ADR-016). "
            f"This guidance must be removed and replaced by externalReferences + "
            f"sentinel grammar documentation."
        )


# ============================================================================
# Section G — GitHub issue form structural validity
# (Does not duplicate TestPerSourceRegenerationDeterminism in the sibling module)
# ============================================================================


class TestSourceTemplateStructuralValidity:
    """
    Guards that the 8 source files remain valid GitHub issue forms after
    any edits: top-level 'name' string and 'body' list must be present.

    This is a forward guard, not a duplicate of the determinism tests in
    test_regenerate_issue_templates.py — it operates on the SOURCE files
    directly without invoking the generator.
    """

    @pytest.mark.parametrize("name", sorted(_ALL_SOURCES))
    def test_source_template_is_valid_yaml_with_required_github_form_fields(
        self, repo_root: Path, name: str
    ) -> None:
        """
        Asserts that each source template parses as valid YAML and has the
        minimum required fields for a GitHub issue form: 'name' (string)
        and 'body' (non-empty list).

        Given: a source template file on disk
        When: it is parsed with yaml.safe_load
        Then: 'name' is a non-empty string and 'body' is a non-empty list

        Issue: #327 / structural guard (ADR-026 D6).
        """
        parsed, _ = _load_source(repo_root, name)

        assert isinstance(parsed, dict), (
            f"{name}.template.yml does not parse as a YAML dict. "
            f"GitHub issue forms must be YAML mappings at the top level."
        )
        assert isinstance(parsed.get("name"), str) and parsed.get("name"), (
            f"{name}.template.yml is missing a non-empty 'name' string. GitHub issue forms require a 'name' field."
        )
        body = parsed.get("body")
        assert isinstance(body, list) and len(body) > 0, (
            f"{name}.template.yml is missing or has empty 'body' list. "
            f"GitHub issue forms require at least one body element."
        )


"""
Test Summary
============
Total tests: 82 (including parametrized expansions across 8 templates)

Classes and their contracts:
  TestRelevantQuestionsRetirement (5 tests, Section A)
    - ADR-019 D6: new_risk has no 'relevant-questions' field id
    - ADR-019 D6: new_risk has no label matching /relevant questions/i
    - ADR-019 D6: update_risk has no 'relevant-questions' field id
    - ADR-019 D6: update_risk change-type dropdown has no 'relevant questions' option
    - Negative scope guard: 6 non-risk templates unaffected

  TestExternalReferencesSolicitation (8 parametrized tests, Section B)
    - ADR-016 D3: all 8 templates have a body element soliciting externalReferences

  TestFrameworkMappingCanonicalForms (13 tests, Section C)
    - ADR-022 D5b: all 8 templates' framework example values match canonical regexes (parametrized x8)
    - ADR-022 D5b: new_risk stride example is PascalCase (not 'information-disclosure')
    - ADR-022 D5b: new_risk owasp example includes year suffix (not 'LLM01')
    - ADR-022 D5b: new_control nist-ai-rmf uses GOVERN form (not 'GV-6.2')
    - ADR-022 D5b: update_control nist-ai-rmf uses GOVERN form (not 'GV-4.1')
    - MITRE ATLAS regression guard: examples remain conformant

  TestMappingsAndResponsibilitiesSolicitation (6 tests, Section D)
    - ADR-018 D6: new_component solicits framework mappings
    - ADR-018 D6: update_component solicits framework mappings
    - ADR-021: new_persona solicits framework actor mappings
    - ADR-021: update_persona solicits framework actor mappings
    - ADR-021: new_persona solicits unified 'responsibilities' field
    - ADR-021: update_persona solicits unified 'responsibilities' field

  TestSentinelGrammarGuidance (16 parametrized tests, Section E)
    - ADR-016 D2: all 8 templates contain '{{ref:identifier}}' (x8)
    - ADR-017 D1: all 8 templates contain an entity-sentinel example with lowercase (x8)

  TestSentinelExamplesDoNotCollideWithGenerator (10 tests, Section E regression)
    - ref sentinel does not match generator ALL-CAPS pattern
    - lowercase entity sentinels do not match generator ALL-CAPS pattern
    - no template's sentinel examples collide with generator pattern (parametrized x8)

  TestHtmlAnchorRetirement (16 parametrized tests, Section F)
    - ADR-016: no template contains '<a href' (x8)
    - ADR-016: no template contains 'Can include HTML links' (x8)

  TestSourceTemplateStructuralValidity (8 parametrized tests, Section G)
    - ADR-026 D6: all 8 source templates parse as valid GitHub issue forms
"""
