"""
Drift guard: assert the ADR-027 validator/hook names appear in their expected doc files.

Pure string-presence assertions — no imports of the validators, no code execution.
If a new ADR-027 validator is added without updating the docs, these tests fail.

A second block (``test_adr027_docs_consistency_*``) guards the post-#343 mandatory
mapping-pinning reconciliation: that the authoring guides show only version-pinned
mapping values (Class A) and that the validator-behavior docs describe the shipped
skip->fail purity flip and the widened pre-commit triggers (Class B).
"""

import re
from pathlib import Path

# Resolve the repo root from this test file's location:
# scripts/hooks/tests/ -> scripts/hooks/ -> scripts/ -> repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

_HOOK_VALIDATIONS = _REPO_ROOT / "scripts" / "docs" / "hook-validations.md"
_SCRIPTS_README = _REPO_ROOT / "scripts" / "README.md"
_VALIDATION_MD = _REPO_ROOT / "risk-map" / "docs" / "validation.md"
_DEVELOPING_MD = _REPO_ROOT / "risk-map" / "docs" / "developing.md"

# Class A — contributor-facing authoring guides that show mapping examples.
_GUIDE_FRAMEWORKS = _REPO_ROOT / "risk-map" / "docs" / "guide-frameworks.md"
_GUIDE_METADATA = _REPO_ROOT / "risk-map" / "docs" / "guide-metadata.md"
_GUIDE_PERSONAS = _REPO_ROOT / "risk-map" / "docs" / "guide-personas.md"
_COMMON_REVIEW = _REPO_ROOT / "risk-map" / "docs" / "contributing" / "common-review-findings.md"
_ISSUE_TEMPLATES = _REPO_ROOT / "risk-map" / "docs" / "contributing" / "issue-templates-guide.md"

_CLASS_A_DOCS = (
    _GUIDE_FRAMEWORKS,
    _GUIDE_METADATA,
    _GUIDE_PERSONAS,
    _COMMON_REVIEW,
    _ISSUE_TEMPLATES,
)


def _read(path: Path) -> str:
    """Read a file and return its text content."""
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Class A — unpinned mapping-value detector (ADR-027 mandatory pinning)
# ---------------------------------------------------------------------------
#
# Post-#343 every framework mapping VALUE must carry its version token
# (mitre-atlas @5.0.1, nist-ai-rmf @1.0, owasp-top10-llm :2025, iso-22989 @2022,
# eu-ai-act @2024) — STRIDE is the sole exception (a tokenless PascalCase enum).
# An unpinned value now FAILs both check-jsonschema and validate-mapping-purity,
# so an authoring guide that shows one teaches a contributor to write YAML that is
# rejected at commit. This detector mirrors the gap-analysis appendix sweep,
# refined so it yields zero matches on a correctly-pinned doc.
#
# Two preprocessing passes strip legitimately-tokenless contexts before matching:
#   1. URLs — a constructed technique URI strips the @-token before {id}
#      substitution, so a tokenless id inside an http(s) URL is a stripped URI,
#      not a mapping value (guide-frameworks Example 5 / URI guidelines).
#   2. "(not <x>)" negative-example callouts — review-finding prose teaches the
#      WRONG form on purpose (e.g. "(not `tampering`)", "(not `LLM01`)").
_URL_RE = re.compile(r"https?://\S+")
_NEG_EXAMPLE_RE = re.compile(r"\(not [^)]*\)")

# Per-framework unpinned patterns: each matches a base ref NOT followed by its
# version delimiter. Legacy NIST abbreviations (GV/MP/MS/MG) are intentionally
# excluded — they survive only inside the "(not `GV-1.1`)" teaching callout; the
# real unpinned canonical forms (GOVERN/MAP/MEASURE/MANAGE-x.y) are caught here.
_UNPINNED_PATTERNS = {
    # MITRE ATLAS: AML.T#### / AML.M#### (+ optional .### subtechnique), no @-token.
    "mitre-atlas": re.compile(r"AML\.(?:T|M)\d{4}(?:\.\d{3})?(?![@.\d])"),
    # NIST AI RMF: canonical GOVERN/MAP/MEASURE/MANAGE-N(.N)*, no @-token.
    "nist-ai-rmf": re.compile(r"\b(?:GOVERN|MAP|MEASURE|MANAGE)-\d+(?:\.\d+)*(?![@.\d])"),
    # OWASP Top 10 LLM: LLM## with no :year token.
    "owasp-top10-llm": re.compile(r"\bLLM\d{2}(?![:\d])"),
    # STRIDE legacy lowercase/kebab list items (canonical is PascalCase, tokenless).
    "stride": re.compile(
        r"(?m)^\s*-\s+(?:tampering|spoofing|repudiation|"
        r"elevation-of-privilege|denial-of-service|information-disclosure)\b"
    ),
}

# ISO 22989 bare role names are handled separately: greedily match the role and
# its optional "(qualifier)", then flag it only when NOT immediately followed by
# the @ token. (Greedy match + end-of-match check avoids optional-group backtrack
# false-negatives on "AI Partner (data supplier)@2022".)
_ISO_ROLE_RE = re.compile(r"AI (?:Producer|Partner|Customer)(?: \([^)]*\))?")


def _find_unpinned(path: Path) -> list[str]:
    """Return every unpinned framework mapping value in a doc (empty list == clean)."""
    text = _NEG_EXAMPLE_RE.sub("", _URL_RE.sub("", _read(path)))
    hits: list[str] = []
    for pattern in _UNPINNED_PATTERNS.values():
        hits.extend(pattern.findall(text))
    for match in _ISO_ROLE_RE.finditer(text):
        if text[match.end() : match.end() + 1] != "@":
            hits.append(match.group(0))
    return hits


def _hook_validations_mapping_sections(text: str) -> str:
    """Slice hook-validations.md to the mapping purity (§17) + drift (§18) sections."""
    start = text.index("## 17.")
    end = text.index("**Related:**", start)
    return text[start:end]


# Current (post-#343) pre-commit trigger for both mapping validators
# (.pre-commit-config.yaml:349,356) — the widened two-source alternation.
_CURRENT_TRIGGER = r"personas|frameworks)\.yaml|schemas/frameworks\.schema\.json"


# ---------------------------------------------------------------------------
# Class A consistency guards — authoring guides show only pinned mapping values
# ---------------------------------------------------------------------------


def test_adr027_docs_consistency_class_a_no_unpinned_mapping_values() -> None:
    """Authoring guides must show only ADR-027 version-pinned mapping values."""
    offenders = {path.name: hits for path in _CLASS_A_DOCS if (hits := _find_unpinned(path))}
    assert not offenders, f"unpinned framework mapping values found in authoring guides: {offenders}"


def test_adr027_docs_consistency_class_a_no_false_fallthrough_clause() -> None:
    """common-review-findings.md must drop the removed STRIDE/NIST/OWASP fall-through claim."""
    assert "fall through pending content migration" not in _read(_COMMON_REVIEW)


def test_adr027_docs_consistency_class_a_guide_frameworks_points_to_style_guide() -> None:
    """guide-frameworks.md must defer to the canonical framework-mappings style guide."""
    assert "framework-mappings-style-guide.md" in _read(_GUIDE_FRAMEWORKS)


# ---------------------------------------------------------------------------
# Class B consistency guards — validator-behavior docs match shipped behavior
# ---------------------------------------------------------------------------


def test_adr027_docs_consistency_class_b_hook_validations_purity_says_fail() -> None:
    """hook-validations.md §17 purity must describe skip->fail, not the retired skip tolerance."""
    text = _read(_HOOK_VALIDATIONS)
    # The pre-migration "skip" tolerance for unpinned-on-versioned is retired.
    assert "no delimiter (`@` or `:`) → skip (legacy unpinned" not in text
    # The purity section now cites the ADR-027 D7/M1 "block" (fail) phase.
    assert "D7/M1" in text


def test_adr027_docs_consistency_class_b_validation_md_purity_says_fail() -> None:
    """validation.md purity prose must say unpinned-on-versioned now fails, not 'skipped'."""
    text = _read(_VALIDATION_MD)
    assert "skipped without error until migration" not in text
    assert "D7/M1" in text


def test_adr027_docs_consistency_class_b_hook_validations_triggers_current() -> None:
    """hook-validations.md §17+§18 trigger lines must match the widened pass_filenames:false form."""
    sections = _hook_validations_mapping_sections(_read(_HOOK_VALIDATIONS))
    # Both mapping validators carry the current two-source alternation trigger.
    assert sections.count(_CURRENT_TRIGGER) >= 2
    # Both run with pass_filenames:false (they read the four consumer YAMLs, never argv).
    assert "pass_filenames: false" in sections
    assert "pass_filenames: true" not in sections


# ---------------------------------------------------------------------------
# hook-validations.md assertions
# ---------------------------------------------------------------------------


def test_hook_validations_contains_versionid_generator() -> None:
    """versionid_generator.py and its hook id appear in hook-validations.md."""
    text = _read(_HOOK_VALIDATIONS)
    assert "versionid_generator.py" in text
    assert "regenerate-frameworks-versionid" in text


def test_hook_validations_contains_validate_versionid_purity() -> None:
    """validate_versionid_purity.py and its hook id appear in hook-validations.md."""
    text = _read(_HOOK_VALIDATIONS)
    assert "validate_versionid_purity.py" in text
    assert "validate-frameworks-versionid-purity" in text


def test_hook_validations_contains_validate_mapping_purity() -> None:
    """validate_mapping_purity.py and its hook id appear in hook-validations.md."""
    text = _read(_HOOK_VALIDATIONS)
    assert "validate_mapping_purity.py" in text
    assert "validate-mapping-purity" in text


def test_hook_validations_contains_validate_mapping_drift() -> None:
    """validate_mapping_drift.py and its hook id appear in hook-validations.md."""
    text = _read(_HOOK_VALIDATIONS)
    assert "validate_mapping_drift.py" in text
    assert "validate-mapping-drift" in text


# ---------------------------------------------------------------------------
# scripts/README.md assertions
# ---------------------------------------------------------------------------


def test_scripts_readme_contains_versionid_generator() -> None:
    """versionid_generator.py appears in scripts/README.md Key Files list."""
    assert "versionid_generator.py" in _read(_SCRIPTS_README)


def test_scripts_readme_contains_validate_versionid_purity() -> None:
    """validate_versionid_purity.py appears in scripts/README.md Key Files list."""
    assert "validate_versionid_purity.py" in _read(_SCRIPTS_README)


def test_scripts_readme_contains_validate_mapping_purity() -> None:
    """validate_mapping_purity.py appears in scripts/README.md Key Files list."""
    assert "validate_mapping_purity.py" in _read(_SCRIPTS_README)


def test_scripts_readme_contains_validate_mapping_drift() -> None:
    """validate_mapping_drift.py appears in scripts/README.md Key Files list."""
    assert "validate_mapping_drift.py" in _read(_SCRIPTS_README)


def test_scripts_readme_contains_framework_mapping_maintainer() -> None:
    """framework_mapping_maintainer.py appears in scripts/README.md Key Files list."""
    assert "framework_mapping_maintainer.py" in _read(_SCRIPTS_README)


# ---------------------------------------------------------------------------
# risk-map/docs/developing.md assertions
# ---------------------------------------------------------------------------


def test_developing_md_contains_framework_mapping_maintainer() -> None:
    """framework_mapping_maintainer.py appears in risk-map/docs/developing.md."""
    assert "framework_mapping_maintainer.py" in _read(_DEVELOPING_MD)


# ---------------------------------------------------------------------------
# risk-map/docs/validation.md assertions
# ---------------------------------------------------------------------------


def test_validation_md_contains_versionid_generator() -> None:
    """versionid_generator.py appears in risk-map/docs/validation.md."""
    assert "versionid_generator.py" in _read(_VALIDATION_MD)


def test_validation_md_contains_validate_versionid_purity() -> None:
    """validate_versionid_purity.py appears in risk-map/docs/validation.md."""
    assert "validate_versionid_purity.py" in _read(_VALIDATION_MD)


def test_validation_md_contains_validate_mapping_purity() -> None:
    """validate_mapping_purity.py appears in risk-map/docs/validation.md."""
    assert "validate_mapping_purity.py" in _read(_VALIDATION_MD)


def test_validation_md_contains_validate_mapping_drift() -> None:
    """validate_mapping_drift.py appears in risk-map/docs/validation.md."""
    assert "validate_mapping_drift.py" in _read(_VALIDATION_MD)
