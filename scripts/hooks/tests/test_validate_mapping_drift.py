#!/usr/bin/env python3
"""
Tests for the ADR-027 D5/D5a mapping-value drift validator.

Tooling under test:
  scripts/hooks/precommit/validate_mapping_drift.py

  Exposes:
    classify_value(fw_id, value, *, registry, pinned_patterns) -> tuple[str, str|None]
      Returns (state, detail) where state is one of:
        "skip"              — legacy/unpinned value or unknown framework; not drift's concern (#343).
        "current"           — pinned token equals framework current version, or framework is
                             unversioned (STRIDE) and value is in its closed enum.
        "valid-but-superseded" — pinned token is in the framework's priorVersions set.
        "invalid"           — delimiter-bearing value whose token is in neither current nor
                             priorVersions, or non-ID base ref outside the closed enum for
                             the pinned edition.

    main(argv: list[str]) -> int
      Positional args are file paths to validate (risks/controls/components/personas).
      Defaults to the four standard content files when no paths given.
      Returns 1 if ANY value classifies "invalid", else 0.
      "valid-but-superseded" does NOT cause exit 1 — it is informational only.

Authoritative spec: docs/adr/027-framework-versioning-and-mapping-convention.md
  D5  — drift-detection validator design and tier split.
  D5a — the three-state classification table (current/valid-but-superseded/invalid).
  D3a — version-token grammar: the normalized version string, delimiter-per-framework.
  H3  — parse invariant: `@` and `:` never appear in any base ref, concept id, or
         controlled-vocab entry; their presence is the sole pinned-intent signal.

Classification algorithm (D5/D5a):
  1. fw_id not in registry → ("skip", None).  Unknown-framework is D4c's concern.
  2. Framework unversioned (STRIDE, version is None):
       value in closed PascalCase enum → ("current", None).
       value NOT in enum (legacy lowercase/kebab) → ("skip", None).
  3. Framework versioned + value has neither `@` nor `:` → ("skip", None).
     (Legacy unpinned form; migration is #343; D3a/H3 delimiter-absence signal.)
  4. Framework versioned + value has `@` or `:` (pinned-intent):
       split_pinned_value raises FrameworkMappingError → ("invalid", detail).
       split succeeds, token == current version → ("current", None).
       split succeeds, token in priorVersions set → ("valid-but-superseded", detail).

Import strategy: module-level import so a ModuleNotFoundError at collection time
signals that the production module is absent.

Note on live corpus: all current mapping values are legacy pre-ADR-027 forms —
no `@` or `:` in versioned framework values; bare PascalCase/lowercase for STRIDE.
The validator must skip them all, so the live corpus is entirely green.
Migration to pinned forms is #343.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Module-level imports — the validate_mapping_drift import raises
# ModuleNotFoundError at collection time, failing the entire file,
# until that module is created.
# ---------------------------------------------------------------------------
from precommit.framework_mapping import (
    known_versions,
    load_pinned_patterns,
    load_registry,
)
from precommit.validate_mapping_drift import classify_value, main

# ---------------------------------------------------------------------------
# Paths and shared fixtures
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent

FRAMEWORKS_YAML = REPO_ROOT / "risk-map" / "yaml" / "frameworks.yaml"
FRAMEWORKS_SCHEMA = REPO_ROOT / "risk-map" / "schemas" / "frameworks.schema.json"

RISKS_YAML = REPO_ROOT / "risk-map" / "yaml" / "risks.yaml"
CONTROLS_YAML = REPO_ROOT / "risk-map" / "yaml" / "controls.yaml"
COMPONENTS_YAML = REPO_ROOT / "risk-map" / "yaml" / "components.yaml"
PERSONAS_YAML = REPO_ROOT / "risk-map" / "yaml" / "personas.yaml"

_REAL_REGISTRY: dict = {}
_REAL_PINNED_PATTERNS: dict = {}


def _registry() -> dict:
    """Lazy-load the real registry (read-only across all tests)."""
    global _REAL_REGISTRY
    if not _REAL_REGISTRY:
        _REAL_REGISTRY = load_registry(FRAMEWORKS_YAML)
    return _REAL_REGISTRY


def _pinned() -> dict:
    """Lazy-load the real pinned patterns (read-only across all tests)."""
    global _REAL_PINNED_PATTERNS
    if not _REAL_PINNED_PATTERNS:
        _REAL_PINNED_PATTERNS = load_pinned_patterns(FRAMEWORKS_SCHEMA)
    return _REAL_PINNED_PATTERNS


# ---------------------------------------------------------------------------
# Helper: build a minimal cosai content YAML tmp file
# ---------------------------------------------------------------------------


def _write_content_yaml(path: Path, entity_type: str, entities: list[dict]) -> None:
    """
    Write a minimal cosai content YAML to `path`.

    `entity_type` is the plural list key: "risks", "controls", "components",
    or "personas". Each entity dict must include at minimum "id" and, if
    relevant, "mappings".
    """
    content = {entity_type: entities}
    path.write_text(yaml.dump(content, default_flow_style=False, sort_keys=False), encoding="utf-8")


# ---------------------------------------------------------------------------
# Synthetic fixture builders for valid-but-superseded tests.
#
# The live registry has NO priorVersions on any framework, and the live schema's
# pinned alternation only admits the CURRENT version.  To produce a
# "valid-but-superseded" result we must:
#   1. deep-copy the real registry and inject a priorVersions entry in versionId
#      form, e.g. registry["nist-ai-rmf"]["priorVersions"] = ["nist-ai-rmf@0.9"].
#   2. deep-copy the real pinned patterns and WIDEN the matching pattern so
#      split_pinned_value's belt-and-suspenders schema check passes for the old
#      version token.
# Neither the real registry nor the real schema is modified.
# ---------------------------------------------------------------------------


def _synthetic_nist_fixtures() -> tuple[dict, dict]:
    """
    Return (synthetic_registry, synthetic_patterns) with nist-ai-rmf@0.9 as a
    recognized prior version.

    synthetic_registry has priorVersions = ["nist-ai-rmf@0.9"].
    synthetic_patterns has the nist-ai-rmf pattern widened to also accept @0.9.
    """
    reg = copy.deepcopy(_registry())
    reg["nist-ai-rmf"]["priorVersions"] = ["nist-ai-rmf@0.9"]

    pat = copy.deepcopy(_pinned())
    # Widen the alternation so split_pinned_value schema check accepts @0.9 tokens.
    pat["nist-ai-rmf"] = {
        "type": "string",
        "pattern": r"^(GOVERN|MAP|MEASURE|MANAGE)-\d+(\.\d+)*@(1\.0|0\.9)$",
    }
    return reg, pat


def _synthetic_owasp_fixtures() -> tuple[dict, dict]:
    """
    Return (synthetic_registry, synthetic_patterns) with owasp-top10-llm@2023
    as a recognized prior version.

    synthetic_registry has priorVersions = ["owasp-top10-llm@2023"].
    synthetic_patterns has the owasp pattern widened to accept :2023 tokens.
    """
    reg = copy.deepcopy(_registry())
    reg["owasp-top10-llm"]["priorVersions"] = ["owasp-top10-llm@2023"]

    pat = copy.deepcopy(_pinned())
    # Widen the alternation to accept year 2023 via : delimiter (OWASP uses :YYYY).
    pat["owasp-top10-llm"] = {
        "type": "string",
        "pattern": r"^LLM\d{2}:(2025|2023)$",
    }
    return reg, pat


# ===========================================================================
# 1. classify_value — "current" cases (one per framework, live registry)
# ===========================================================================


class TestClassifyValueCurrent:
    """
    classify_value returns ("current", None) for each of the six correctly-pinned
    ground-truth examples using the live registry and live pinned patterns.

    These are the ADR-027 D3 canonical pinned forms — one per supported framework.
    For versioned frameworks the value carries the current version token (D3a).
    For STRIDE (unversioned, D6) the bare PascalCase value is in the closed enum.
    """

    def test_mitre_atlas_current_pinned_technique(self):
        """
        Given: a MITRE ATLAS technique pinned at the registry's current `version`
        When: classify_value is called with live registry/patterns
        Then: state is "current", detail is None

        D3a: `@` delimiter, version token equals the current registry version.
        The version is read from frameworks.yaml, not hardcoded, so the test
        holds across an edition flip.
        """
        atlas_version = next(
            e
            for e in yaml.safe_load(FRAMEWORKS_YAML.read_text(encoding="utf-8"))["frameworks"]
            if e["id"] == "mitre-atlas"
        )["version"]
        state, detail = classify_value(
            "mitre-atlas",
            f"AML.T0043@{atlas_version}",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "current"
        assert detail is None

    def test_nist_ai_rmf_current_pinned_subcategory(self):
        """
        Given: correctly-pinned NIST AI RMF subcategory `GOVERN-6.2@1.0`
        When: classify_value is called with live registry/patterns
        Then: state is "current", detail is None

        D3a: `@` delimiter, version token `1.0` equals the current registry version.
        """
        state, detail = classify_value(
            "nist-ai-rmf",
            "GOVERN-6.2@1.0",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "current"
        assert detail is None

    def test_owasp_top10_llm_current_colon_delimiter(self):
        """
        Given: correctly-pinned OWASP LLM Top 10 entry `LLM02:2025`
        When: classify_value is called with live registry/patterns
        Then: state is "current", detail is None

        D3a/D6/M1: OWASP uses `:` delimiter (framework-determined divergence
        retained as the prototype per D6). Year `2025` is the current version.
        """
        state, detail = classify_value(
            "owasp-top10-llm",
            "LLM02:2025",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "current"
        assert detail is None

    def test_stride_current_pascalcase_in_enum(self):
        """
        Given: STRIDE value `Tampering` in canonical PascalCase
        When: classify_value is called with live registry/patterns
        Then: state is "current", detail is None

        D6: STRIDE is unversioned (version: null).  Bare PascalCase membership
        in the closed D5b enum is the integrity guarantee — "pinned by enum rather
        than by token".  Classification is "current" because the value is in the
        recognized set and the framework is unversioned.
        """
        state, detail = classify_value(
            "stride",
            "Tampering",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "current"
        assert detail is None

    def test_iso_22989_current_pinned_role(self):
        """
        Given: correctly-pinned ISO 22989 role `AI Producer@2022`
        When: classify_value is called with live registry/patterns
        Then: state is "current", detail is None

        D8: controlled-vocab enum for ISO 22989; `@` delimiter; version `2022`
        equals the current registry version.
        """
        state, detail = classify_value(
            "iso-22989",
            "AI Producer@2022",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "current"
        assert detail is None

    def test_eu_ai_act_current_pinned_article(self):
        """
        Given: correctly-pinned EU AI Act article reference `Article 50@2024`
        When: classify_value is called with live registry/patterns
        Then: state is "current", detail is None

        D3a: `@` delimiter, version token `2024` equals the current registry version.
        """
        state, detail = classify_value(
            "eu-ai-act",
            "Article 50@2024",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "current"
        assert detail is None


# ===========================================================================
# 2. classify_value — "skip" cases (legacy forms and unknown framework)
# ===========================================================================


class TestClassifyValueSkip:
    """
    classify_value returns ("skip", None) for:
      - Legacy pre-ADR-027 values (no `@` or `:` in versioned framework values;
        lowercase/kebab STRIDE values not in the closed PascalCase enum).
      - Unknown framework keys (drift is not drift's concern to fail-loud on; that
        is the purity validator's D4c concern — the drift validator must not crash
        or double-report on unknown framework keys).

    The skip decision for versioned frameworks rests on the delimiter-presence test
    (D3a / H3): absence of both `@` and `:` is the unambiguous legacy signal.
    Migration of these values is #343.
    """

    def test_mitre_atlas_legacy_no_version_token(self):
        """
        Given: legacy MITRE ATLAS value `AML.T0020` (no `@` delimiter)
        When: classify_value is called
        Then: state is "skip" (legacy unpinned form; D3a / H3 delimiter absence)

        Version drift cannot be detected without a pinned version token.
        The migration to `AML.T0020@5.0.1` is #343.
        """
        state, detail = classify_value(
            "mitre-atlas",
            "AML.T0020",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "skip"
        assert detail is None

    def test_nist_ai_rmf_legacy_short_prefix(self):
        """
        Given: legacy NIST AI RMF value `GV-6.2` (short prefix, no `@`)
        When: classify_value is called
        Then: state is "skip" (legacy form; no delimiter signal of pinned intent)

        Real value from controls.yaml. The canonical pinned form is
        `GOVERN-6.2@1.0`; migration is #343.
        """
        state, detail = classify_value(
            "nist-ai-rmf",
            "GV-6.2",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "skip"
        assert detail is None

    def test_owasp_legacy_unversioned(self):
        """
        Given: legacy OWASP value `LLM06` (no `:` delimiter, no year)
        When: classify_value is called
        Then: state is "skip" (legacy form; D3a: no `:` → legacy)

        Real value from risks.yaml. The canonical pinned form is `LLM06:2025`.
        """
        state, detail = classify_value(
            "owasp-top10-llm",
            "LLM06",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "skip"
        assert detail is None

    def test_stride_lowercase_kebab(self):
        """
        Given: legacy STRIDE value `tampering` (lowercase, not PascalCase)
        When: classify_value is called
        Then: state is "skip"

        STRIDE is unversioned (version: null).  `tampering` is not in the closed
        PascalCase enum.  For an unversioned framework, a value outside the enum
        has no version-token signal; classification is "skip" not "invalid" because
        "tampering" is a legacy spelling, not a delimiter-bearing tamper.
        """
        state, detail = classify_value(
            "stride",
            "tampering",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "skip"
        assert detail is None

    def test_iso_22989_bare_role_no_delimiter(self):
        """
        Given: legacy ISO 22989 role `AI Producer` (no `@`, no version token)
        When: classify_value is called
        Then: state is "skip" (legacy form; H3 / D3a delimiter absence)

        Real value from personas.yaml. The canonical pinned form is
        `AI Producer@2022`. No delimiter → no drift to check.
        """
        state, detail = classify_value(
            "iso-22989",
            "AI Producer",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "skip"
        assert detail is None

    def test_eu_ai_act_legacy_no_version_token(self):
        """
        Given: legacy EU AI Act reference `Article 52` (no `@` delimiter)
        When: classify_value is called
        Then: state is "skip" (legacy form; D3a / H3 delimiter absence)

        eu-ai-act is versioned.  Without `@` or `:` the value is legacy unpinned.
        Migration to `Article 52@2024` (or the corrected article, per D3 context)
        is #343.
        """
        state, detail = classify_value(
            "eu-ai-act",
            "Article 52",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "skip"
        assert detail is None

    def test_unknown_framework_key_is_skip_not_invalid(self):
        """
        Given: a value under framework key `does-not-exist` (not in registry)
        When: classify_value is called
        Then: state is "skip" (unknown-framework is D4c purity's concern, not drift's)

        The drift validator must not crash or double-report on unknown framework keys.
        An unknown key yields no version information to check drift against; the
        correct behaviour is to skip silently so only the purity validator's
        fail-loud report fires (never both).
        """
        state, detail = classify_value(
            "does-not-exist",
            "some-value",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "skip"
        assert detail is None

    def test_unknown_framework_key_with_delimiter_still_skip(self):
        """
        Given: a delimiter-bearing value `SomeRef@1.0` under unknown framework `bogus-fw`
        When: classify_value is called
        Then: state is "skip"

        Even with a pinned-intent delimiter, an unknown framework key has no
        registry entry to classify drift against.  Skip rather than invalid so
        the purity validator remains the sole reporter for unknown-framework failures.
        """
        state, detail = classify_value(
            "bogus-fw",
            "SomeRef@1.0",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "skip"
        assert detail is None


# ===========================================================================
# 3. classify_value — "valid-but-superseded" cases (SYNTHETIC fixtures)
# ===========================================================================


class TestClassifyValueValidButSuperseded:
    """
    classify_value returns ("valid-but-superseded", non-None detail) when the
    pinned version token is in the framework's priorVersions set — a sanctioned
    retention from a prior edition (D2c).

    The live registry has NO priorVersions on any framework, so all tests in this
    class use synthetic fixtures (deep copies of the real registry/patterns with
    injected priorVersions entries and widened patterns — see module-level helpers).

    D5a semantics:
      - "valid-but-superseded" is NOT a failure.  A PR carrying a superseded pin
        must NOT break CI.  main() must return 0 for a file containing only
        valid-but-superseded values (the informational-report path).
      - The detail string must be non-None and must mention the superseded token so
        a maintainer can audit which mappings need re-pinning decisions (D10b step 4).
    """

    def test_nist_at_delimiter_prior_version_is_superseded(self):
        """
        Given: synthetic registry with nist-ai-rmf priorVersions = ["nist-ai-rmf@0.9"]
               and widened pattern accepting @0.9; value `GOVERN-6.2@0.9`
        When: classify_value is called
        Then: state is "valid-but-superseded", detail is non-None and mentions "0.9"

        D5a: `0.9` is in priorVersions → sanctioned retention, not invalid.
        The detail must name the superseded token so maintainers can audit (D10b step 4).
        """
        reg, pat = _synthetic_nist_fixtures()
        state, detail = classify_value(
            "nist-ai-rmf",
            "GOVERN-6.2@0.9",
            registry=reg,
            pinned_patterns=pat,
        )
        assert state == "valid-but-superseded"
        assert detail is not None
        assert "0.9" in detail

    def test_owasp_colon_delimiter_prior_version_is_superseded(self):
        """
        Given: synthetic registry with owasp-top10-llm priorVersions = ["owasp-top10-llm@2023"]
               and widened pattern accepting :2023; value `LLM02:2023`
        When: classify_value is called
        Then: state is "valid-but-superseded", detail is non-None

        D5a: OWASP uses `:` delimiter (D6/M1).  Year `2023` is in priorVersions →
        sanctioned retention.  Tests the `:` delimiter path for superseded classification.
        """
        reg, pat = _synthetic_owasp_fixtures()
        state, detail = classify_value(
            "owasp-top10-llm",
            "LLM02:2023",
            registry=reg,
            pinned_patterns=pat,
        )
        assert state == "valid-but-superseded"
        assert detail is not None
        # D5a/D10b: the detail must name the superseded token so a maintainer can audit.
        assert "2023" in detail

    def test_nist_current_version_still_current_with_synthetic_fixtures(self):
        """
        Given: the same synthetic nist-ai-rmf fixtures (priorVersions = ["nist-ai-rmf@0.9"])
               but value `GOVERN-6.2@1.0` (the CURRENT version)
        When: classify_value is called
        Then: state is "current", detail is None

        The synthetic priorVersions injection must not reclassify the current edition.
        A value pinned to the current version is always "current" regardless of what
        priorVersions contains.
        """
        reg, pat = _synthetic_nist_fixtures()
        state, detail = classify_value(
            "nist-ai-rmf",
            "GOVERN-6.2@1.0",
            registry=reg,
            pinned_patterns=pat,
        )
        assert state == "current"
        assert detail is None

    def test_owasp_current_version_still_current_with_synthetic_fixtures(self):
        """
        Given: the same synthetic owasp fixtures (priorVersions = ["owasp-top10-llm@2023"])
               but value `LLM02:2025` (the CURRENT version)
        When: classify_value is called
        Then: state is "current", detail is None

        Synthetic priorVersions must not reclassify values pinned to the current year.
        """
        reg, pat = _synthetic_owasp_fixtures()
        state, detail = classify_value(
            "owasp-top10-llm",
            "LLM02:2025",
            registry=reg,
            pinned_patterns=pat,
        )
        assert state == "current"
        assert detail is None

    def test_synthetic_known_versions_sanity(self):
        """
        Sanity: the synthetic nist registry correctly reports {1.0, 0.9} from
        known_versions().

        This validates the fixture builder's priorVersions injection before the
        classify_value tests depend on it.  known_versions() extracts the version
        token from each priorVersions entry (the part after `@`).
        """
        reg, _ = _synthetic_nist_fixtures()
        versions = known_versions("nist-ai-rmf", reg)
        assert versions == {"1.0", "0.9"}, (
            f"Expected {{'1.0', '0.9'}} from synthetic nist fixture, got {versions!r}."
            " Check priorVersions injection in _synthetic_nist_fixtures()."
        )


# ===========================================================================
# 4. classify_value — "invalid" cases (delimiter-bearing, bad token / out-of-vocab)
# ===========================================================================


class TestClassifyValueInvalid:
    """
    classify_value returns ("invalid", non-None detail) for delimiter-bearing values
    whose version token is in NEITHER the current version NOR priorVersions, or
    (non-ID frameworks) whose base ref is outside the closed enum for the pinned edition.

    These are the failure cases the drift validator is built to detect (D5a invalid state).
    They represent typos, stale copies, or pins to versions CoSAI never recorded.

    All tests use the LIVE registry (no priorVersions on any framework), so any
    unrecognized version token is automatically "invalid".
    """

    def test_nist_unknown_version_token_is_invalid(self):
        """
        Given: `GOVERN-6.2@9.9` where `9.9` is not in nist-ai-rmf's known versions
        When: classify_value is called
        Then: state is "invalid", detail is non-None and contains the bad token "9.9"

        D5a: `@` signals pinned intent; `9.9` not in {current=1.0} ∪ priorVersions={}
        → token is in neither set → invalid.  detail must name the bad token so the
        contributor knows what is wrong.
        """
        state, detail = classify_value(
            "nist-ai-rmf",
            "GOVERN-6.2@9.9",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "invalid"
        assert detail is not None
        assert "9.9" in detail

    def test_mitre_atlas_unknown_version_token_is_invalid(self):
        """
        Given: `AML.T0043@9.9.9` where `9.9.9` is not in mitre-atlas known versions
        When: classify_value is called
        Then: state is "invalid", detail is non-None

        D5a: version token `9.9.9` not recognized → invalid.
        """
        state, detail = classify_value(
            "mitre-atlas",
            "AML.T0043@9.9.9",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "invalid"
        assert detail is not None

    def test_owasp_unknown_year_token_is_invalid(self):
        """
        Given: `LLM02:2099` where year `2099` is not in owasp-top10-llm known versions
        When: classify_value is called
        Then: state is "invalid", detail is non-None

        D5a: `:` signals pinned intent for OWASP (D6/M1); `2099` not in known
        versions → invalid.
        """
        state, detail = classify_value(
            "owasp-top10-llm",
            "LLM02:2099",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "invalid"
        assert detail is not None

    def test_iso_22989_unknown_version_token_is_invalid(self):
        """
        Given: `AI Producer@9999` where `9999` is not in iso-22989 known versions
        When: classify_value is called
        Then: state is "invalid", detail is non-None

        D5a: `@` present → pinned intent; `9999` not recognized → invalid.
        """
        state, detail = classify_value(
            "iso-22989",
            "AI Producer@9999",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "invalid"
        assert detail is not None

    def test_eu_ai_act_unknown_version_token_is_invalid(self):
        """
        Given: `Article 50@9999` where `9999` is not in eu-ai-act known versions
        When: classify_value is called
        Then: state is "invalid", detail is non-None

        D5a: `@` present → pinned intent; `9999` not recognized → invalid.
        """
        state, detail = classify_value(
            "eu-ai-act",
            "Article 50@9999",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "invalid"
        assert detail is not None

    def test_iso_22989_out_of_vocab_base_ref_with_known_version_is_invalid(self):
        """
        Given: `AI Part (data supplier)@2022` — truncated role, valid version token
        When: classify_value is called
        Then: state is "invalid", detail is non-None

        D5a / D8: `@` present and `2022` is in the known-version set, but
        `AI Part (data supplier)` is not in the closed controlled-vocab enum for
        iso-22989@2022 (D8). The value does not validate — whether split raises
        FrameworkMappingError or a separate vocab-membership check surfaces it,
        the classification is "invalid" regardless of the internal path.
        """
        state, detail = classify_value(
            "iso-22989",
            "AI Part (data supplier)@2022",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "invalid"
        assert detail is not None

    def test_mitre_atlas_unknown_version_bad_trailing_segment_is_invalid(self):
        """
        Given: `AML.T0043@5.0.1.0` — extra trailing segment, so version is `5.0.1.0`
        When: classify_value is called
        Then: state is "invalid", detail is non-None

        `5.0.1.0` is not the known `5.0.1` → token not in recognized set → invalid.
        """
        state, detail = classify_value(
            "mitre-atlas",
            "AML.T0043@5.0.1.0",
            registry=_registry(),
            pinned_patterns=_pinned(),
        )
        assert state == "invalid"
        assert detail is not None


# ===========================================================================
# 5. main() integration — tmp YAML fixtures
# ===========================================================================


class TestMainWithTmpYaml:
    """
    main() integration tests using tmp_path fixtures.

    All invalid/superseded values are in temporary files — the live content
    files are never modified.  Each test builds a minimal cosai entity YAML
    with a `mappings:` dict carrying bare-string lists.

    Key contracts (D5/D5a):
      - exit 1 if ANY value classifies "invalid".
      - exit 0 if only legacy ("skip") or current ("current") values.
      - exit 0 if only "valid-but-superseded" values (informational, NOT a failure).
      - "invalid" values are reported to stderr (the offending value must appear).
      - "valid-but-superseded" values appear in stderr as informational (not failure).
      - legacy values are NOT reported in stderr as errors or failures.
    """

    def test_main_only_legacy_values_exits_zero(self, tmp_path):
        """
        Given: a risks.yaml with only legacy (no-delimiter) mapping values
        When: main([path]) is called
        Then: returns 0

        Legacy values are all "skip" → no drift detectable → clean pass (#343).
        """
        risks_file = tmp_path / "risks.yaml"
        _write_content_yaml(
            risks_file,
            "risks",
            [
                {
                    "id": "riskFoo",
                    "title": "Foo Risk",
                    "mappings": {
                        "mitre-atlas": ["AML.T0020", "AML.T0043"],
                        "stride": ["tampering"],
                        "owasp-top10-llm": ["LLM06"],
                        "nist-ai-rmf": ["GV-6.2"],
                    },
                }
            ],
        )
        rc = main([str(risks_file)])
        assert rc == 0

    def test_main_invalid_value_exits_one(self, tmp_path, capsys):
        """
        Given: a risks.yaml with one invalid value `GOVERN-6.2@9.9`
        When: main([path]) is called
        Then: returns 1 and the offending value appears on stderr

        D5a: `@` present → pinned intent; version `9.9` not recognized → invalid → exit 1.
        """
        risks_file = tmp_path / "risks.yaml"
        _write_content_yaml(
            risks_file,
            "risks",
            [
                {
                    "id": "riskFoo",
                    "title": "Foo Risk",
                    "mappings": {
                        "nist-ai-rmf": ["GOVERN-6.2@9.9"],
                    },
                }
            ],
        )
        rc = main([str(risks_file)])
        assert rc == 1
        captured = capsys.readouterr()
        assert "GOVERN-6.2@9.9" in captured.err

    def test_main_mixed_legacy_and_invalid_exits_one(self, tmp_path, capsys):
        """
        Given: a controls.yaml with some legacy values and one invalid value
        When: main([path]) is called
        Then: returns 1; the invalid value appears on stderr; legacy values are silent

        D5a: only "invalid" causes exit 1; "skip" values must not pollute stderr.
        """
        controls_file = tmp_path / "controls.yaml"
        _write_content_yaml(
            controls_file,
            "controls",
            [
                {
                    "id": "controlFoo",
                    "title": "Foo Control",
                    "mappings": {
                        "mitre-atlas": ["AML.T0020"],  # legacy → skip
                        "nist-ai-rmf": ["GOVERN-6.2@9.9"],  # invalid → fail
                        "owasp-top10-llm": ["LLM06"],  # legacy → skip
                    },
                }
            ],
        )
        rc = main([str(controls_file)])
        assert rc == 1
        captured = capsys.readouterr()
        assert "GOVERN-6.2@9.9" in captured.err
        # Legacy values must not appear as failures in stderr.
        assert "AML.T0020" not in captured.err
        assert "LLM06" not in captured.err

    def test_main_all_current_pinned_values_exits_zero(self, tmp_path):
        """
        Given: a risks.yaml with all-current pinned values (live registry, live schema)
        When: main([path]) is called
        Then: returns 0

        Current pinned values (the ATLAS value at the registry's current
        version, LLM02:2025, Tampering) are recognized by the live registry and
        schema → "current" → exit 0. The ATLAS version is read from
        frameworks.yaml so the test holds across an edition flip.
        """
        atlas_version = next(
            e
            for e in yaml.safe_load(FRAMEWORKS_YAML.read_text(encoding="utf-8"))["frameworks"]
            if e["id"] == "mitre-atlas"
        )["version"]
        risks_file = tmp_path / "risks.yaml"
        _write_content_yaml(
            risks_file,
            "risks",
            [
                {
                    "id": "riskFoo",
                    "title": "Foo Risk",
                    "mappings": {
                        "mitre-atlas": [f"AML.T0043@{atlas_version}"],
                        "owasp-top10-llm": ["LLM02:2025"],
                        "stride": ["Tampering"],
                        "nist-ai-rmf": ["GOVERN-6.2@1.0"],
                    },
                }
            ],
        )
        rc = main([str(risks_file)])
        assert rc == 0

    def test_main_empty_mapping_list_exits_zero(self, tmp_path):
        """
        Given: a risks.yaml where a framework key maps to an empty list
        When: main([path]) is called
        Then: returns 0

        An empty mapping list has zero values to classify; validator must not error.
        """
        risks_file = tmp_path / "risks.yaml"
        _write_content_yaml(
            risks_file,
            "risks",
            [{"id": "riskFoo", "mappings": {"mitre-atlas": []}}],
        )
        rc = main([str(risks_file)])
        assert rc == 0

    def test_main_no_mappings_key_exits_zero(self, tmp_path):
        """
        Given: a risks.yaml where entities have no `mappings` key
        When: main([path]) is called
        Then: returns 0

        The mappings field is optional; absent key must be handled gracefully.
        """
        risks_file = tmp_path / "risks.yaml"
        _write_content_yaml(
            risks_file,
            "risks",
            [
                {"id": "riskFoo", "title": "Foo Risk"},
                {"id": "riskBar", "title": "Bar Risk"},
            ],
        )
        rc = main([str(risks_file)])
        assert rc == 0

    def test_main_multiple_files_one_invalid_exits_one(self, tmp_path, capsys):
        """
        Given: two files where one has only legacy values and one has an invalid value
        When: main([clean_path, invalid_path]) is called
        Then: returns 1 and the invalid value appears on stderr

        Multi-file scans must surface failures in any file, not just the first.
        """
        clean_file = tmp_path / "risks.yaml"
        invalid_file = tmp_path / "controls.yaml"
        _write_content_yaml(
            clean_file,
            "risks",
            [{"id": "riskFoo", "mappings": {"mitre-atlas": ["AML.T0020"]}}],
        )
        _write_content_yaml(
            invalid_file,
            "controls",
            [
                {
                    "id": "controlFoo",
                    "mappings": {
                        "owasp-top10-llm": ["LLM02:2099"],  # invalid year
                    },
                }
            ],
        )
        rc = main([str(clean_file), str(invalid_file)])
        assert rc == 1
        captured = capsys.readouterr()
        assert "LLM02:2099" in captured.err


# ===========================================================================
# 6. main() — valid-but-superseded does NOT cause exit 1
# ===========================================================================


class TestMainSupersededIsNotFailure:
    """
    "valid-but-superseded" mappings are informational — they pass the drift
    validator (D5a: "Pass + report informationally") and must never cause exit 1.

    All tests use synthetic fixtures so the superseded path is reachable.
    The live YAML files are never modified.

    IMPLEMENTATION CONSTRAINT (binding on the implementation): the monkey-patch helper below
    replaces `load_registry` / `load_pinned_patterns` as module-level names on
    `precommit.validate_mapping_drift`. This is only effective if `main()` calls
    those loaders through their module-level names at RUNTIME (i.e. imported with
    `from precommit.framework_mapping import load_registry, load_pinned_patterns`
    and called as bare names inside main(), exactly as validate_mapping_purity.py
    does). If the implementation caches the registry at import time, or aliases/renames the
    imports so the patch cannot reach them, this test would still exit 0 — but for
    the WRONG reason (the live registry has no priorVersions, so every value would
    classify "skip"), giving false confidence. The implementation must mirror the purity
    validator's import-and-call pattern so the override actually takes effect.
    """

    def _write_content_yaml_with_override_path(
        self,
        tmp_path: Path,
        entity_type: str,
        entities: list[dict],
        override_registry: dict,
        override_patterns: dict,
    ) -> tuple[Path, int, str]:
        """
        Write a tmp YAML and run main() with monkey-patched registry/patterns.

        Returns (path, returncode, stderr_text).
        This helper writes the YAML and calls main() directly while temporarily
        replacing the module-level registry and patterns used by _scan_file.
        We call classify_value directly with synthetic fixtures to verify the
        superseded contract, then confirm main() also exits 0 for the same value.
        """
        import precommit.validate_mapping_drift as _mod  # type: ignore[import]

        path = tmp_path / f"{entity_type}.yaml"
        _write_content_yaml(path, entity_type, entities)

        # Patch the loader functions used by main() for the duration of this call.
        orig_load_registry = _mod.load_registry  # type: ignore[attr-defined]
        orig_load_pinned = _mod.load_pinned_patterns  # type: ignore[attr-defined]
        _mod.load_registry = lambda _p: override_registry  # type: ignore[attr-defined]
        _mod.load_pinned_patterns = lambda _p: override_patterns  # type: ignore[attr-defined]
        import io
        import sys

        captured_err = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured_err
        try:
            rc = main([str(path)])
        finally:
            sys.stderr = old_stderr
            _mod.load_registry = orig_load_registry  # type: ignore[attr-defined]
            _mod.load_pinned_patterns = orig_load_pinned  # type: ignore[attr-defined]

        return path, rc, captured_err.getvalue()

    def test_superseded_value_exits_zero(self, tmp_path):
        """
        Given: a risks.yaml with only a valid-but-superseded pinned value
               using synthetic nist-ai-rmf priorVersions = ["nist-ai-rmf@0.9"]
               and value `GOVERN-6.2@0.9`
        When: main([path]) is called (with synthetic registry/patterns injected)
        Then: returns 0 (valid-but-superseded is informational, NOT a failure)

        D5a: "valid-but-superseded" → "Pass + report informationally".  The CI
        must not break because a pin is on a prior recognized version.
        """
        reg, pat = _synthetic_nist_fixtures()
        _path, rc, stderr = self._write_content_yaml_with_override_path(
            tmp_path,
            "risks",
            [
                {
                    "id": "riskFoo",
                    "mappings": {"nist-ai-rmf": ["GOVERN-6.2@0.9"]},
                }
            ],
            reg,
            pat,
        )
        assert rc == 0, (
            "Expected exit 0 for valid-but-superseded value GOVERN-6.2@0.9. "
            "Exit 1 would incorrectly treat a sanctioned prior-version pin as a failure."
        )
        # D5a: superseded pins must be "reported informationally" — the value must
        # surface in the informational stderr report, not be silently swallowed.
        assert "GOVERN-6.2@0.9" in stderr, (
            "Expected the superseded value in the informational stderr report. "
            "A silent pass (empty stderr) violates D5a's 'Pass + report informationally'."
        )


# ===========================================================================
# 7. Real-shape silent-skip regression (mirrors TestMainRealShapeSilentSkip)
# ===========================================================================


class TestMainRealShapeSilentSkip:
    """
    Regression guard for the silent-skip bug in _scan_file (#347 / D5).

    Mirrors the same structure used in the purity validator's tests.

    The real content files have `description:` (list) BEFORE the entity key
    (risks:/controls:/personas:); controls.yaml also has `categories:` (list)
    before `controls:`.  A naive first-list-valued-key scan would always pick
    `description`, never reach the entity mappings, and return exit 0 silently.

    These tests assert that _scan_file reaches and correctly classifies entity
    mappings even when non-entity list keys precede the entity key.
    """

    def test_real_shape_risks_invalid_caught(self, tmp_path, capsys):
        """
        Given: a YAML with description (list) BEFORE risks (list), where a risks
               entity carries the invalid pinned value `GOVERN-6.2@9.9`
        When: main([path]) is called
        Then: returns 1 and the offending value appears on stderr

        If _scan_file takes description (first list-valued key), it exits 0 —
        the wrong answer.  The fix must scan ALL list keys, not just the first.
        """
        risks_file = tmp_path / "risks.yaml"
        content = {
            "title": "Risks",
            "description": [
                "Prose paragraph one.",
                "Prose paragraph two.",
            ],
            "risks": [
                {
                    "id": "riskX",
                    "title": "Risk X",
                    "mappings": {
                        "nist-ai-rmf": ["GOVERN-6.2@9.9"],  # invalid: version 9.9 unknown
                    },
                }
            ],
        }
        risks_file.write_text(yaml.dump(content, default_flow_style=False, sort_keys=False), encoding="utf-8")

        rc = main([str(risks_file)])

        assert rc == 1, (
            "Expected exit 1 for invalid value GOVERN-6.2@9.9. "
            "Exit 0 indicates _scan_file picked description instead of risks "
            "and silently skipped all entity mappings (silent-skip bug)."
        )
        captured = capsys.readouterr()
        assert "GOVERN-6.2@9.9" in captured.err

    def test_real_shape_controls_invalid_caught_categories_before_controls(self, tmp_path, capsys):
        """
        Given: a YAML with description (list) and categories (list) BEFORE
               controls (list), where a controls entity has invalid value `LLM02:2099`
        When: main([path]) is called
        Then: returns 1 and the offending value appears on stderr

        controls.yaml has both description and categories as lists preceding the
        controls list — the most adversarial ordering for the first-list-key bug.
        """
        controls_file = tmp_path / "controls.yaml"
        content = {
            "title": "Controls",
            "description": ["Prose paragraph one.", "Prose paragraph two."],
            "categories": [
                {"id": "controlsData", "title": "Data Controls"},
                {"id": "controlsModel", "title": "Model Controls"},
            ],
            "controls": [
                {
                    "id": "controlY",
                    "title": "Control Y",
                    "mappings": {
                        "owasp-top10-llm": ["LLM02:2099"],  # invalid: year 2099 unknown
                    },
                }
            ],
        }
        controls_file.write_text(yaml.dump(content, default_flow_style=False, sort_keys=False), encoding="utf-8")

        rc = main([str(controls_file)])

        assert rc == 1, (
            "Expected exit 1 for invalid value LLM02:2099. "
            "Exit 0 indicates _scan_file picked description or categories "
            "instead of controls and silently skipped all entity mappings."
        )
        captured = capsys.readouterr()
        assert "LLM02:2099" in captured.err

    def test_real_shape_legacy_values_stay_green(self, tmp_path):
        """
        Given: a YAML with description (list) BEFORE risks (list), where risks
               entities carry only legacy (no-delimiter) mapping values
        When: main([path]) is called
        Then: returns 0

        Confirms that the fix for the silent-skip bug does not false-positive on
        prose items in description/categories, and that legacy values in the entity
        list still classify as "skip" cleanly.
        """
        risks_file = tmp_path / "risks.yaml"
        content = {
            "title": "Risks",
            "description": ["Prose paragraph one.", "Prose paragraph two."],
            "risks": [
                {
                    "id": "riskLegacy",
                    "title": "Legacy Risk",
                    "mappings": {
                        "nist-ai-rmf": ["GV-6.2"],  # legacy → skip
                        "mitre-atlas": ["AML.T0020"],  # legacy → skip
                        "owasp-top10-llm": ["LLM06"],  # legacy → skip
                        "stride": ["tampering"],  # legacy → skip
                    },
                }
            ],
        }
        risks_file.write_text(yaml.dump(content, default_flow_style=False, sort_keys=False), encoding="utf-8")

        rc = main([str(risks_file)])

        assert rc == 0, (
            "Expected exit 0 for all-legacy values in real-shape YAML. "
            "A non-zero exit indicates false positives from prose in "
            "description or categories being scanned as entity mappings."
        )


# ===========================================================================
# 8. Live corpus green (all four content files must produce zero failures)
# ===========================================================================


@pytest.mark.live_corpus
class TestLiveCorpusGreen:
    """
    The live corpus (risks/controls/components/personas.yaml on this branch)
    must produce zero drift failures from main() — all files return exit 0.

    Rationale: every mapping value currently in the corpus is a legacy
    pre-ADR-027 form with no `@` or `:` in versioned framework values and
    no PascalCase enum match needed for STRIDE (all lowercase-kebab):
      - mitre-atlas:     `AML.T0020`, `AML.M0007`, ...  (no `@`)
      - nist-ai-rmf:     `GV-6.2`, `GV-1.6`, ...        (no `@`)
      - owasp-top10-llm: `LLM06`, `LLM04`, ...          (no `:`)
      - stride:          `tampering`, ...                (lowercase-kebab → skip)
      - iso-22989:       `AI Producer`, ...              (no `@`)

    None of these carry the delimiter that D3a / H3 defines as the pinned-intent
    signal.  The drift validator classifies every live value as "skip" → zero
    invalid → exit 0.

    Migration to pinned forms is #343.  Until that migration lands, this test is
    the regression guard confirming that the drift validator does not break the
    existing corpus.

    components.yaml currently has zero mapping values; it is included to confirm
    the validator handles a mappings-free file gracefully.
    """

    def test_risks_yaml_live_corpus_zero_failures(self):
        """
        Given: the live risk-map/yaml/risks.yaml as it exists on this branch
        When: main([risks_path]) is called
        Then: returns 0 (all legacy values are "skip", none are "invalid")
        """
        assert RISKS_YAML.is_file(), f"risks.yaml not found at {RISKS_YAML}"
        rc = main([str(RISKS_YAML)])
        assert rc == 0

    def test_controls_yaml_live_corpus_zero_failures(self):
        """
        Given: the live risk-map/yaml/controls.yaml as it exists on this branch
        When: main([controls_path]) is called
        Then: returns 0 (all legacy values are "skip", none are "invalid")
        """
        assert CONTROLS_YAML.is_file(), f"controls.yaml not found at {CONTROLS_YAML}"
        rc = main([str(CONTROLS_YAML)])
        assert rc == 0

    def test_components_yaml_live_corpus_zero_failures(self):
        """
        Given: the live risk-map/yaml/components.yaml as it exists on this branch
        When: main([components_path]) is called
        Then: returns 0 (components.yaml has zero mapping values; graceful no-op)
        """
        assert COMPONENTS_YAML.is_file(), f"components.yaml not found at {COMPONENTS_YAML}"
        rc = main([str(COMPONENTS_YAML)])
        assert rc == 0

    def test_personas_yaml_live_corpus_zero_failures(self):
        """
        Given: the live risk-map/yaml/personas.yaml as it exists on this branch
        When: main([personas_path]) is called
        Then: returns 0 (bare ISO 22989 roles have no `@` delimiter → "skip")
        """
        assert PERSONAS_YAML.is_file(), f"personas.yaml not found at {PERSONAS_YAML}"
        rc = main([str(PERSONAS_YAML)])
        assert rc == 0

    def test_all_four_content_files_zero_failures(self):
        """
        Given: all four live content files passed together
        When: main([risks, controls, components, personas]) is called
        Then: returns 0

        Crux regression guard: the entire current corpus stays clean (zero findings).  Every
        legacy value classifies "skip"; migration to pinned forms is #343.
        """
        for path in (RISKS_YAML, CONTROLS_YAML, COMPONENTS_YAML, PERSONAS_YAML):
            assert path.is_file(), f"content file not found: {path}"

        rc = main([str(RISKS_YAML), str(CONTROLS_YAML), str(COMPONENTS_YAML), str(PERSONAS_YAML)])
        assert rc == 0

    def test_main_default_no_args_zero_failures(self):
        """
        Given: no CLI arguments (default mode)
        When: main([]) is called
        Then: returns 0

        When invoked with no positional args, main() defaults to the four standard
        content files.  On this branch all values are legacy → zero failures.
        """
        rc = main([])
        assert rc == 0


"""
Test Summary
============
Total tests: 43
  current cases (classify_value):            6  (TestClassifyValueCurrent)
  skip cases (classify_value):               8  (TestClassifyValueSkip)
  valid-but-superseded cases:                5  (TestClassifyValueValidButSuperseded)
  invalid cases (classify_value):            7  (TestClassifyValueInvalid)
  main() integration (tmp_path):             7  (TestMainWithTmpYaml)
  main() superseded-not-failure:             1  (TestMainSupersededIsNotFailure)
  real-shape silent-skip regression:         3  (TestMainRealShapeSilentSkip)
  live corpus green:                         6  (TestLiveCorpusGreen)

Coverage areas:
  - Per-framework "current" classification: all 6 live frameworks
  - Per-framework "skip": versioned no-delimiter (mitre, nist, owasp, iso, eu-ai-act),
    unversioned not-in-enum (stride), unknown framework key (x2)
  - "valid-but-superseded": nist @-delimiter, owasp :-delimiter (SYNTHETIC fixtures);
    current version unaffected by priorVersions injection (x2); known_versions sanity
  - "invalid": nist (with bad-token assertion in detail), mitre, owasp, iso, eu-ai-act,
    iso out-of-vocab-with-known-version, mitre extra-segment
  - main() exit-0 paths: legacy-only, all-current, empty-list, no-mappings-key
  - main() exit-1 paths: invalid value (stderr check), mixed-legacy+invalid (stderr
    selectivity), multi-file one-invalid
  - main() superseded-is-not-failure: exit 0 with synthetic fixtures
  - Silent-skip regression: real-shape risks (description-before-risks),
    real-shape controls (description+categories-before-controls), legacy-stays-green
  - Live corpus: all four files individually + combined + default no-args

API contract:
  classify_value(
      fw_id: str,
      value: str,
      *,
      registry: dict[str, dict],
      pinned_patterns: dict[str, dict],
  ) -> tuple[str, str | None]
      state in {"skip", "current", "valid-but-superseded", "invalid"}.
      detail is a human-readable string (non-None for invalid and valid-but-superseded).

  main(argv: list[str]) -> int
      Positional args: file paths to scan.
      Defaults to RISKS/CONTROLS/COMPONENTS/PERSONAS yaml when none given.
      Returns 1 on any "invalid"; 0 otherwise (skip/current/valid-but-superseded all pass).
      Prints "invalid" failures to stderr (offending value included).
      Prints "valid-but-superseded" informationally to stderr (not a failure).
"""
