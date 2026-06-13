#!/usr/bin/env python3
"""
Tests for ADR-027 D4 / D4a / D4b / D3a / D6 / D8 tooling.

(D4c — the mapping-value purity validator — is a separate deliverable tested
alongside its own module; it is intentionally out of scope here.)

Tooling under test:
  - scripts/hooks/precommit/framework_mapping.py
      Shared module: compose_pinned_value, split_pinned_value,
      derive_mapping_id, load_registry, load_pinned_patterns,
      known_versions, exception hierarchy.

  - scripts/framework_mapping_maintainer.py
      CLI with subcommands add / update / remove. Validates --framework
      against the registry, --version against the framework's known
      version set, --framework-specific-ref against the pinned-value
      schema pattern/enum; composes and writes pinned values into a
      consumer YAML file.

Authoritative spec:
  docs/adr/027-framework-versioning-and-mapping-convention.md

D-section citations in every test trace the test's "why" to the ADR.

Test-first: these tests were authored before the production code
(framework_mapping.py, framework_mapping_maintainer.py) existed, so each fails or
errors until those two files land.

Import strategy: import the shared module at the top level — if it raises ImportError
the whole module fails to collect, which is the correct signal for a missing module.
Subprocess CLI tests do not depend on the import succeeding, but they do assert
the script path exists (so a missing-script error is not mistaken for a validator
rejection in negative-case tests).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import jsonschema
import pytest
import yaml

# ---------------------------------------------------------------------------
# Module-level import — fails to collect if the shared module is absent
# ---------------------------------------------------------------------------
# Do NOT use importorskip (that would skip instead of failing). An ImportError
# here makes the whole file fail to collect, which is the right signal when the
# shared module is absent.
from precommit.framework_mapping import (
    DEFAULT_FRAMEWORKS_PATH,
    DEFAULT_SCHEMA_PATH,
    LEGACY_NIST_PREFIX_MAP,
    LEGACY_STRIDE_KEBAB_MAP,
    FrameworkMappingError,
    InvalidRefError,
    UnknownFrameworkError,
    UnknownVersionError,
    compose_pinned_value,
    derive_mapping_id,
    known_versions,
    load_pinned_patterns,
    load_registry,
    migrate_legacy_value,
    split_pinned_value,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# REPO_ROOT = scripts/hooks/tests/<this>/../../../..
REPO_ROOT = Path(__file__).parent.parent.parent.parent

FRAMEWORKS_YAML = REPO_ROOT / "risk-map" / "yaml" / "frameworks.yaml"
FRAMEWORKS_SCHEMA = REPO_ROOT / "risk-map" / "schemas" / "frameworks.schema.json"
CLI = REPO_ROOT / "scripts" / "framework_mapping_maintainer.py"

# Real registry and schema — loaded once; tests must NOT mutate these objects.
_REAL_REGISTRY: dict[str, dict] = {}
_REAL_PINNED_PATTERNS: dict[str, dict] = {}


def _get_registry() -> dict[str, dict]:
    """Lazy-load the real registry (read-only)."""
    global _REAL_REGISTRY
    if not _REAL_REGISTRY:
        _REAL_REGISTRY = load_registry(FRAMEWORKS_YAML)
    return _REAL_REGISTRY


def _get_pinned_patterns() -> dict[str, dict]:
    """Lazy-load the real pinned patterns from the schema (read-only)."""
    global _REAL_PINNED_PATTERNS
    if not _REAL_PINNED_PATTERNS:
        _REAL_PINNED_PATTERNS = load_pinned_patterns(FRAMEWORKS_SCHEMA)
    return _REAL_PINNED_PATTERNS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(
    *args: str,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess:
    """
    Invoke the CLI under the current Python interpreter.

    Asserts the script exists before invoking so a non-zero exit from a
    missing-script path can never be mistaken for a validator rejection in
    a negative-case test. The TestArtifactsExist class covers existence
    directly; this helper enforces the precondition for every other CLI test.
    """
    assert CLI.is_file(), (
        f"required CLI {CLI.relative_to(REPO_ROOT)} is missing — negative-case "
        "CLI tests would otherwise pass for the wrong reason"
    )
    cmd = [sys.executable, str(CLI), *args]
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )


def _write_consumer_fixture(path: Path, content: str) -> None:
    """Write a consumer YAML fixture string to a tmp path."""
    path.write_text(textwrap.dedent(content), encoding="utf-8")


def _load_yaml(path: Path) -> dict:
    """Parse a YAML file and return the root mapping."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _make_controls_fixture(tmp_path: Path) -> Path:
    """
    Build a small controls.yaml fixture with 3 entities, comments,
    and pre-existing mappings. Used to test format preservation, order
    preservation, and add/remove/update round-trips.
    """
    dst = tmp_path / "controls.yaml"
    _write_consumer_fixture(
        dst,
        """\
        # Copyright notice preserved
        title: Controls
        description:
          - >
            Test controls fixture for framework_mapping_maintainer tests.
        categories:
          - id: controlsData
            title: Data Controls
        controls:
          - id: controlFoo
            title: Foo Control
            description:
              - Foo description.
            # sibling comment
            category: controlsData
            personas: []
            components: []
            risks: []
            mappings:
              nist-ai-rmf:
                - GOVERN-6.2@1.0
              mitre-atlas:
                - AML.M0007@5.0.1

          - id: controlBar
            title: Bar Control
            description:
              - Bar description.
            category: controlsData
            personas: []
            components: []
            risks: []

          - id: controlBaz
            title: Baz Control
            description:
              - Baz description.
            category: controlsData
            personas: []
            components: []
            risks: []
            mappings:
              mitre-atlas:
                - AML.T0002@5.0.1
        """,
    )
    return dst


def _make_risks_fixture(tmp_path: Path) -> Path:
    """Build a small risks.yaml fixture for entity-not-found and prefix-routing tests."""
    dst = tmp_path / "risks.yaml"
    _write_consumer_fixture(
        dst,
        """\
        title: Risks
        description:
          - Test risks fixture.
        categories:
          - id: risksCategory
            title: Risks
        risks:
          - id: riskFoo
            title: Foo Risk
            description:
              - Foo risk description.
            category: risksCategory
            likelihoods: []
            impacts: []
            personas: []
            components: []
        """,
    )
    return dst


# Synthetic registry with a priorVersions entry — used to test known_versions union.
_SYNTHETIC_REGISTRY_WITH_PRIOR: dict[str, dict] = {
    "mitre-atlas": {
        "version": "6.0.0",
        "priorVersions": ["mitre-atlas@5.0.1"],
    },
    "stride": {
        "version": None,
        "priorVersions": [],
    },
    "nist-ai-rmf": {
        "version": "1.0",
        "priorVersions": [],
    },
}

# ---------------------------------------------------------------------------
# Schema cross-check helpers
# ---------------------------------------------------------------------------


def _validate_against_pinned_subschema(framework_id: str, value: str) -> None:
    """
    Assert that `value` validates against the `framework-mapping-patterns-pinned`
    sub-schema for `framework_id`.

    Uses jsonschema Draft7 — the same $schema the frameworks.schema.json declares.
    This is the schema cross-check test requested by the orchestrator.
    """
    full_schema = json.loads(FRAMEWORKS_SCHEMA.read_text(encoding="utf-8"))
    pinned_block = full_schema["definitions"]["framework-mapping-patterns-pinned"]
    sub_schema = pinned_block["properties"][framework_id]
    jsonschema.validate(instance=value, schema=sub_schema)


# ===========================================================================
# 1. Artifacts exist
# ===========================================================================


class TestArtifactsExist:
    """
    Both the CLI and the shared module must be present at documented paths.

    ADR-027 D4a specifies framework-mapping-maintainer.py as the CLI.
    ADR-027 D4 specifies the generate-not-author contract implemented in
    the shared library.
    """

    def test_cli_script_exists(self):
        """
        The CLI entry-point must exist at scripts/framework_mapping_maintainer.py.

        ADR-027 D4a: contributor workflow requires a runnable maintainer tool.
        """
        assert CLI.is_file(), (
            f"CLI missing at {CLI.relative_to(REPO_ROOT)}; ADR-027 D4a requires framework-mapping-maintainer.py."
        )

    def test_shared_module_exists(self):
        """
        The shared module must exist at scripts/hooks/precommit/framework_mapping.py.

        ADR-027 D4: reusable compose logic is needed by the D4c/D5 validators.
        """
        module_path = REPO_ROOT / "scripts" / "hooks" / "precommit" / "framework_mapping.py"
        assert module_path.is_file(), (
            f"Shared module missing at {module_path.relative_to(REPO_ROOT)}; "
            "ADR-027 D4 requires a reusable compose module."
        )

    def test_shared_module_importable(self):
        """
        The shared module must be importable from the precommit package.

        This test verifies the import at the top of this file succeeded
        (it would have caused a collection error if it failed). If we
        reach here the import is live.
        """
        # If we got here the module-level import succeeded.
        assert FrameworkMappingError is not None
        assert UnknownFrameworkError is not None
        assert UnknownVersionError is not None
        assert InvalidRefError is not None


# ===========================================================================
# 2. compose_pinned_value — happy path per framework
# ===========================================================================


class TestComposePinnedValueHappyPath:
    """
    compose_pinned_value correctly composes pinned values for each framework.

    ADR-027 D3: pinned value = spec-native canonical ref + version token.
    ADR-027 D3a: token is the normalized `version` string verbatim.
    ADR-027 D6: ID-bearing frameworks use `@`; OWASP uses `:`; STRIDE bare.
    ADR-027 D8: ISO 22989 uses closed enum + `@<version>`.
    """

    def test_compose_mitre_atlas_technique(self):
        """
        MITRE ATLAS technique ref + @5.0.1 token.

        ADR-027 D3 / D6: spec-native ref (AML.T0043) + @ + version (5.0.1).
        """
        result = compose_pinned_value(
            "mitre-atlas",
            "5.0.1",
            "AML.T0043",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert result == "AML.T0043@5.0.1"

    def test_compose_mitre_atlas_mitigation(self):
        """
        MITRE ATLAS mitigation ref (M-prefix).

        ADR-027 D3 / D6: mitre-atlas pattern covers both T and M prefixes.
        """
        result = compose_pinned_value(
            "mitre-atlas",
            "5.0.1",
            "AML.M0007",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert result == "AML.M0007@5.0.1"

    def test_compose_nist_ai_rmf(self):
        """
        NIST AI RMF subcategory ref + @1.0 token.

        ADR-027 D3 / D6: GOVERN-6.2 + @ + 1.0 = GOVERN-6.2@1.0.
        """
        result = compose_pinned_value(
            "nist-ai-rmf",
            "1.0",
            "GOVERN-6.2",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert result == "GOVERN-6.2@1.0"

    def test_compose_owasp_top10_llm(self):
        """
        OWASP Top 10 LLM uses `:` delimiter, not `@`.

        ADR-027 D6 / D3: OWASP's year-in-value form LLM06:2025.
        The delimiter is `:` because that is OWASP's upstream-recognizable
        convention retained deliberately (D6).
        """
        result = compose_pinned_value(
            "owasp-top10-llm",
            "2025",
            "LLM06",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert result == "LLM06:2025"

    def test_compose_eu_ai_act(self):
        """
        EU AI Act Article reference + @2024 token.

        ADR-027 D3 / D6: Article 50 + @ + 2024 = Article 50@2024.
        """
        result = compose_pinned_value(
            "eu-ai-act",
            "2024",
            "Article 50",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert result == "Article 50@2024"

    def test_compose_stride_unversioned_bare(self):
        """
        STRIDE is unversioned (version: null); composed value is the bare ref.

        ADR-027 D6: STRIDE carries no version token. `version` arg may be None.
        The value is `Tampering`, not `Tampering@...`.
        """
        result = compose_pinned_value(
            "stride",
            None,
            "Tampering",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert result == "Tampering"

    def test_compose_iso_22989_controlled_vocab(self):
        """
        ISO 22989 uses closed enum + @2022 token.

        ADR-027 D8: ISO 22989 roles are a controlled vocabulary, encoded as
        a closed inline enum. `AI Partner (data supplier)@2022` is the pinned form.
        """
        result = compose_pinned_value(
            "iso-22989",
            "2022",
            "AI Partner (data supplier)",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert result == "AI Partner (data supplier)@2022"

    def test_compose_eu_ai_act_with_subparagraph(self):
        """
        EU AI Act Article with sub-paragraph notation `Article 3(3)@2024`.

        ADR-027 D3 / D6: the pattern ^Article\\s\\d+(\\(\\d+\\))?@(2024)$
        covers both `Article N` and `Article N(n)`.
        """
        result = compose_pinned_value(
            "eu-ai-act",
            "2024",
            "Article 3(3)",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert result == "Article 3(3)@2024"


# ===========================================================================
# 2b. compose_pinned_value — delimiter correctness
# ===========================================================================


class TestComposePinnedValueDelimiter:
    """
    Delimiter is framework-determined: OWASP uses `:`, all others use `@`.

    ADR-027 D3 / D6: "the value-token delimiter (`@` for most, `:` for OWASP)
    does NOT match the versionId delimiter for OWASP."
    Consumers parsing a pinned value must select the delimiter per framework
    (M1 / D3a).
    """

    def test_owasp_uses_colon_delimiter(self):
        """
        OWASP composed value contains `:` not `@`.

        ADR-027 D6: OWASP's `:` delimiter is upstream-recognizable and deliberately
        retained — harmonizing it to `@` would churn the one already-correct framework.
        """
        result = compose_pinned_value(
            "owasp-top10-llm",
            "2025",
            "LLM01",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert ":" in result
        assert "@" not in result

    def test_atlas_uses_at_delimiter(self):
        """
        MITRE ATLAS composed value contains `@` not `:`.

        ADR-027 D3 / D6: every framework except OWASP uses the `@` token.
        """
        result = compose_pinned_value(
            "mitre-atlas",
            "5.0.1",
            "AML.T0043",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert "@" in result
        assert result.count("@") == 1
        assert ":" not in result

    def test_stride_has_no_delimiter(self):
        """
        STRIDE composed value has neither `@` nor `:`.

        ADR-027 D6: STRIDE is unversioned; the value is the bare PascalCase ref.
        """
        result = compose_pinned_value(
            "stride",
            None,
            "Spoofing",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert "@" not in result
        assert ":" not in result
        assert result == "Spoofing"


# ===========================================================================
# 2c. compose_pinned_value — error cases
# ===========================================================================


class TestComposePinnedValueErrors:
    """
    compose_pinned_value raises the correct exception types for invalid input.

    ADR-027 D4a: the tool "(1) validates --framework, (2) validates --version
    against that framework's recognized version set, (3) validates
    --framework-specific-ref against the framework's value constraint."
    """

    def test_unknown_framework_raises_unknown_framework_error(self):
        """
        Bogus framework id raises UnknownFrameworkError (not KeyError or generic).

        ADR-027 D4a step 1: --framework is validated against the frameworks.yaml
        id enum; a value not in that enum is rejected at authoring time.
        """
        with pytest.raises(UnknownFrameworkError):
            compose_pinned_value(
                "not-a-real-framework",
                "1.0",
                "SOME-REF",
                registry=_get_registry(),
                pinned_patterns=_get_pinned_patterns(),
            )

    def test_unknown_version_raises_unknown_version_error(self):
        """
        A --version not in the framework's recognized version set raises
        UnknownVersionError.

        ADR-027 D4a step 2 / D3a: the recognized version set is
        {current version} ∪ {priorVersions members}. Version 9.9.9 is not
        in the MITRE ATLAS recognized set.
        """
        with pytest.raises(UnknownVersionError):
            compose_pinned_value(
                "mitre-atlas",
                "9.9.9",
                "AML.T0043",
                registry=_get_registry(),
                pinned_patterns=_get_pinned_patterns(),
            )

    def test_out_of_vocab_iso_ref_raises_invalid_ref_error(self):
        """
        A misspelled ISO 22989 role not in the closed enum raises InvalidRefError.

        ADR-027 D8: "a --framework-specific-ref not in the closed set is rejected,
        so `AI Part (Data supplier)` cannot be authored."
        """
        with pytest.raises(InvalidRefError):
            compose_pinned_value(
                "iso-22989",
                "2022",
                "AI Part (Data supplier)",  # typo: "Part" not "Partner"
                registry=_get_registry(),
                pinned_patterns=_get_pinned_patterns(),
            )

    def test_malformed_atlas_ref_raises_invalid_ref_error(self):
        """
        A malformed MITRE ATLAS ref that does not match the pattern raises
        InvalidRefError.

        ADR-027 D4a step 3 / D6: spec-native regex `^AML\\.(T|M)\\d{4}(...)?$`
        is applied to the base ref before the version token; `AMLT0043` (missing
        dot) does not match.
        """
        with pytest.raises(InvalidRefError):
            compose_pinned_value(
                "mitre-atlas",
                "5.0.1",
                "AMLT0043",  # malformed: missing `.` after AML
                registry=_get_registry(),
                pinned_patterns=_get_pinned_patterns(),
            )

    def test_versioned_framework_absent_from_pinned_patterns_does_not_crash(self):
        """
        A versioned framework present in the registry but absent from the
        pinned-patterns block must not raise TypeError.

        Scenario: a new framework id is added to frameworks.yaml (and the id
        enum) but the framework-mapping-patterns-pinned block is not yet
        extended, so pinned_patterns.get(id) is None. _try_delimiters must
        guard the None sub_schema (as split_pinned_value already does) rather
        than passing schema=None to jsonschema.validate (TypeError). compose
        then returns its unvalidated default candidate, matching its own
        step-5 None-sub_schema handling.
        """
        synthetic_registry = {
            "ghost-framework": {
                "id": "ghost-framework",
                "version": "1.0",
                "priorVersions": [],
            }
        }
        result = compose_pinned_value(
            "ghost-framework",
            "1.0",
            "SOME-REF",
            registry=synthetic_registry,
            pinned_patterns={},  # no entry for ghost-framework -> sub_schema is None
        )
        assert result == "SOME-REF@1.0"

    def test_error_hierarchy_unknown_framework_is_mapping_error(self):
        """
        UnknownFrameworkError must be a subclass of FrameworkMappingError.

        Required by the public API spec so callers can catch the base type.
        """
        assert issubclass(UnknownFrameworkError, FrameworkMappingError)

    def test_error_hierarchy_unknown_version_is_mapping_error(self):
        """UnknownVersionError must be a subclass of FrameworkMappingError."""
        assert issubclass(UnknownVersionError, FrameworkMappingError)

    def test_error_hierarchy_invalid_ref_is_mapping_error(self):
        """InvalidRefError must be a subclass of FrameworkMappingError."""
        assert issubclass(InvalidRefError, FrameworkMappingError)


# ===========================================================================
# 3. split_pinned_value — round-trips
# ===========================================================================


class TestSplitPinnedValue:
    """
    split_pinned_value correctly recovers (base_ref, version) from pinned values.

    ADR-027 D3a: H3 parse invariant guarantees the delimiter `@` (or `:` for OWASP)
    never appears in the base ref, so splitting cleanly recovers the pair.
    """

    def test_round_trip_mitre_atlas(self):
        """
        split_pinned_value is the inverse of compose_pinned_value for MITRE ATLAS.

        ADR-027 D3a: splitting `AML.T0043@5.0.1` on `@` recovers `AML.T0043`.
        """
        pinned = compose_pinned_value(
            "mitre-atlas",
            "5.0.1",
            "AML.T0043",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        base_ref, version = split_pinned_value(
            "mitre-atlas",
            pinned,
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert base_ref == "AML.T0043"
        assert version == "5.0.1"

    def test_round_trip_nist_ai_rmf(self):
        """
        split_pinned_value round-trip for NIST AI RMF subcategory.

        ADR-027 D3a: `GOVERN-6.2@1.0` splits to (`GOVERN-6.2`, `1.0`).
        """
        pinned = compose_pinned_value(
            "nist-ai-rmf",
            "1.0",
            "GOVERN-6.2",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        base_ref, version = split_pinned_value(
            "nist-ai-rmf",
            pinned,
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert base_ref == "GOVERN-6.2"
        assert version == "1.0"

    def test_round_trip_owasp(self):
        """
        split_pinned_value round-trip for OWASP (`:` delimiter).

        ADR-027 D3 / D6: `LLM06:2025` splits to (`LLM06`, `2025`).
        The consumer must select the `:` delimiter per-framework for OWASP.
        """
        pinned = compose_pinned_value(
            "owasp-top10-llm",
            "2025",
            "LLM06",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        base_ref, version = split_pinned_value(
            "owasp-top10-llm",
            pinned,
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert base_ref == "LLM06"
        assert version == "2025"

    def test_round_trip_eu_ai_act(self):
        """
        split_pinned_value round-trip for EU AI Act.

        ADR-027 D3: `Article 50@2024` splits to (`Article 50`, `2024`).
        The space in `Article 50` must be preserved in the base_ref.
        """
        pinned = compose_pinned_value(
            "eu-ai-act",
            "2024",
            "Article 50",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        base_ref, version = split_pinned_value(
            "eu-ai-act",
            pinned,
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert base_ref == "Article 50"
        assert version == "2024"

    def test_round_trip_iso_22989_with_parens(self):
        """
        split_pinned_value round-trip for ISO 22989 with spaces and parens.

        ADR-027 D3a / D8: H3 invariant — `@` never appears in controlled-vocab
        base values even when they contain spaces and parentheses, so splitting
        on `@` cleanly recovers `AI Partner (data supplier)`.
        """
        pinned = compose_pinned_value(
            "iso-22989",
            "2022",
            "AI Partner (data supplier)",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        base_ref, version = split_pinned_value(
            "iso-22989",
            pinned,
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert base_ref == "AI Partner (data supplier)"
        assert version == "2022"

    def test_stride_returns_none_version(self):
        """
        split_pinned_value for STRIDE returns (ref, None).

        ADR-027 D6: STRIDE is unversioned; the split returns (bare_ref, None).
        """
        base_ref, version = split_pinned_value(
            "stride",
            "Tampering",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert base_ref == "Tampering"
        assert version is None


# ===========================================================================
# 4. derive_mapping_id — determinism, uniqueness, charset, stability
# ===========================================================================


class TestDeriveMappingId:
    """
    derive_mapping_id produces a stable, deterministic SHA-256 hex digest.

    ADR-027 D4b: "join cosai-id|framework-id|pinned-value; SHA-256 hex digest."
    The mappingId is never written to YAML (D4b binding decision).
    """

    def test_deterministic_same_inputs_same_digest(self):
        """
        Calling derive_mapping_id twice with identical inputs returns the same digest.

        ADR-027 D4b: the handle is "deterministically composed from cosai-id +
        framework + pinned-value." Non-determinism would break CLI re-invocations.
        """
        id1 = derive_mapping_id("controlFoo", "mitre-atlas", "AML.T0043@5.0.1")
        id2 = derive_mapping_id("controlFoo", "mitre-atlas", "AML.T0043@5.0.1")
        assert id1 == id2

    def test_different_cosai_id_different_digest(self):
        """
        Different cosai-id with same framework + pinned-value yields different digest.

        ADR-027 D4b: the canonical string `<cosai-id>|<framework-id>|<pinned-value>`
        includes the cosai-id, so distinct entities must not collide.
        """
        id1 = derive_mapping_id("controlFoo", "mitre-atlas", "AML.T0043@5.0.1")
        id2 = derive_mapping_id("controlBar", "mitre-atlas", "AML.T0043@5.0.1")
        assert id1 != id2

    def test_different_framework_different_digest(self):
        """
        Different framework with same cosai-id + value yields different digest.

        ADR-027 D4b: all three tuple components feed into the canonical string.
        """
        id1 = derive_mapping_id("controlFoo", "mitre-atlas", "AML.T0043@5.0.1")
        id2 = derive_mapping_id("controlFoo", "nist-ai-rmf", "AML.T0043@5.0.1")
        assert id1 != id2

    def test_different_pinned_value_different_digest(self):
        """
        Different pinned value with same cosai-id + framework yields different digest.

        ADR-027 D4b: the pinned value (including version token) is part of the
        canonical string so different values within the same (entity, framework)
        pair are distinct.
        """
        id1 = derive_mapping_id("controlFoo", "mitre-atlas", "AML.T0043@5.0.1")
        id2 = derive_mapping_id("controlFoo", "mitre-atlas", "AML.T0043@6.0.0")
        assert id1 != id2

    def test_hex_charset(self):
        """
        derive_mapping_id returns a lowercase hex string (token-safe).

        ADR-027 D4b: "a stable hash (a hex digest) as the handle... token-safe
        regardless of the spaces/parens/@/: in the pinned value."
        """
        mapping_id = derive_mapping_id("controlFoo", "mitre-atlas", "AML.T0043@5.0.1")
        assert re.fullmatch(r"[0-9a-f]+", mapping_id), f"mappingId must be lowercase hex; got {mapping_id!r}"

    def test_stability_with_spaces_and_parens_in_value(self):
        """
        derive_mapping_id is stable for a pinned value containing spaces and parens.

        ADR-027 D4b: the `|` separator is the reserved join character;
        `AI Partner (data supplier)@2022` contains spaces and parens but not `|`,
        so the canonical string `cosai-id|framework|AI Partner (data supplier)@2022`
        is unambiguous.
        """
        mapping_id = derive_mapping_id("personaFoo", "iso-22989", "AI Partner (data supplier)@2022")
        # Must be non-empty hex
        assert re.fullmatch(r"[0-9a-f]+", mapping_id)
        # Repeat call must give same result
        assert derive_mapping_id("personaFoo", "iso-22989", "AI Partner (data supplier)@2022") == mapping_id

    def test_sha256_correctness(self):
        """
        derive_mapping_id uses SHA-256 of the `|`-joined canonical string.

        ADR-027 D4b: "SHA-256 hex digest of cosai-id|framework-id|pinned-value."
        We verify against a known reference digest.
        """
        canonical = "controlFoo|mitre-atlas|AML.T0043@5.0.1"
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert derive_mapping_id("controlFoo", "mitre-atlas", "AML.T0043@5.0.1") == expected


# ===========================================================================
# 5. known_versions — current, empty for unversioned, union with priorVersions
# ===========================================================================


class TestKnownVersions:
    """
    known_versions returns the correct recognized version set for each framework.

    ADR-027 D3a: "the recognized version set is the framework's current version
    plus any priorVersions members."
    ADR-027 D2c: priorVersions members are extracted as version tokens.
    """

    def test_versioned_framework_returns_current_version(self):
        """
        A versioned framework with no priorVersions returns {current version}.

        ADR-027 D3a: recognized set = {current version} when priorVersions is empty.
        """
        versions = known_versions("mitre-atlas", _get_registry())
        assert "5.0.1" in versions

    def test_unversioned_stride_returns_empty_set(self):
        """
        STRIDE (version: null) returns an empty set.

        ADR-027 D3a / D6: STRIDE carries no version token; known_versions
        returns empty set to signal unversioned (no token-based recognition).
        """
        versions = known_versions("stride", _get_registry())
        assert len(versions) == 0

    def test_prior_versions_included_in_known_set(self):
        """
        priorVersions entries contribute their version tokens to the known set.

        ADR-027 D2c / D3a: "the recognized set is the current version PLUS
        priorVersions members." A pin to an old version in priorVersions is
        valid-but-superseded (D5a), not invalid.

        Uses a synthetic registry dict (not the real frameworks.yaml) with a
        priorVersions entry, so we do not need to edit the live file.
        """
        versions = known_versions("mitre-atlas", _SYNTHETIC_REGISTRY_WITH_PRIOR)
        # Current version in synthetic registry is 6.0.0; prior is mitre-atlas@5.0.1
        # The version token extracted from "mitre-atlas@5.0.1" should be "5.0.1"
        assert "6.0.0" in versions
        assert "5.0.1" in versions

    def test_nist_ai_rmf_current_version(self):
        """
        NIST AI RMF returns {1.0} from the real registry.

        ADR-027 D3a: using the real on-disk registry to verify end-to-end.
        """
        versions = known_versions("nist-ai-rmf", _get_registry())
        assert "1.0" in versions

    def test_owasp_current_version(self):
        """
        OWASP Top 10 LLM returns {2025} from the real registry.

        ADR-027 D3a / D6: OWASP version token in the value is `2025`.
        """
        versions = known_versions("owasp-top10-llm", _get_registry())
        assert "2025" in versions


# ===========================================================================
# 6. Schema cross-check: expected pinned values validate against the schema
# ===========================================================================


class TestSchemaCrossCheck:
    """
    Each pinned value composed from spec inputs validates against the
    framework-mapping-patterns-pinned sub-schema.

    ADR-027 D3a: "the anchored alternation is what lets check-jsonschema
    enforce version-known at the schema layer."

    This class is the orchestrator gate: it proves our expected values are
    schema-correct, satisfying D4a step 3 independently of the compose path.
    """

    def test_atlas_pinned_value_validates_against_schema(self):
        """AML.T0043@5.0.1 validates against the pinned mitre-atlas sub-schema (D3a/D7)."""
        _validate_against_pinned_subschema("mitre-atlas", "AML.T0043@5.0.1")

    def test_nist_pinned_value_validates_against_schema(self):
        """GOVERN-6.2@1.0 validates against the pinned nist-ai-rmf sub-schema (D3a/D7)."""
        _validate_against_pinned_subschema("nist-ai-rmf", "GOVERN-6.2@1.0")

    def test_owasp_pinned_value_validates_against_schema(self):
        """LLM06:2025 validates against the pinned owasp-top10-llm sub-schema (D3a/D6)."""
        _validate_against_pinned_subschema("owasp-top10-llm", "LLM06:2025")

    def test_stride_pinned_value_validates_against_schema(self):
        """Tampering validates against the pinned stride sub-schema (D6 / frozen enum)."""
        _validate_against_pinned_subschema("stride", "Tampering")

    def test_eu_ai_act_pinned_value_validates_against_schema(self):
        """Article 50@2024 validates against the pinned eu-ai-act sub-schema (D3a/D7)."""
        _validate_against_pinned_subschema("eu-ai-act", "Article 50@2024")

    def test_iso_22989_pinned_value_validates_against_schema(self):
        """
        AI Partner (data supplier)@2022 validates against the iso-22989 enum (D7/D8).

        ADR-027 D8: the closed inline enum encodes all six ISO 22989:2022 roles
        with their @2022 version token.
        """
        _validate_against_pinned_subschema("iso-22989", "AI Partner (data supplier)@2022")

    def test_iso_22989_all_six_enum_members_validate(self):
        """
        All six ISO 22989:2022 controlled-vocabulary members validate.

        ADR-027 D8: the closed set sourced from ISO/IEC 22989:2022 role taxonomy
        must match exactly the inline enum in the schema.
        """
        members = [
            "AI Producer@2022",
            "AI Customer (application builder)@2022",
            "AI Customer (end user)@2022",
            "AI Partner (data supplier)@2022",
            "AI Partner (infrastructure provider)@2022",
            "AI Partner (tooling provider)@2022",
        ]
        for member in members:
            _validate_against_pinned_subschema("iso-22989", member)

    def test_out_of_vocab_iso_value_fails_schema(self):
        """
        A misspelled ISO 22989 role fails schema validation.

        ADR-027 D8: "a --framework-specific-ref not in the closed set is rejected."
        The schema's closed enum is the enforcement surface.
        """
        with pytest.raises(jsonschema.ValidationError):
            _validate_against_pinned_subschema("iso-22989", "AI Part (Data supplier)@2022")

    def test_atlas_wrong_version_token_fails_schema(self):
        """
        An MITRE ATLAS value with an unrecognized version token fails schema.

        ADR-027 D3a: the anchored alternation only admits the recognized version
        set. `@9.9.9` is not in `(5\\.0\\.1)`.
        """
        with pytest.raises(jsonschema.ValidationError):
            _validate_against_pinned_subschema("mitre-atlas", "AML.T0043@9.9.9")


# ===========================================================================
# 7. load_registry — structure and defaults
# ===========================================================================


class TestLoadRegistry:
    """
    load_registry returns the framework registry indexed by framework id.

    ADR-027 D1 / D2: the registry is the source of truth for known versions.
    """

    def test_load_registry_from_real_file_returns_dict(self):
        """
        load_registry(FRAMEWORKS_YAML) returns a dict keyed by framework id.

        ADR-027 D1: frameworks.yaml is the authoritative registry.
        """
        registry = load_registry(FRAMEWORKS_YAML)
        assert isinstance(registry, dict)
        assert "mitre-atlas" in registry
        assert "stride" in registry

    def test_registry_entry_has_version_and_prior(self):
        """
        Each registry entry exposes `version` and `priorVersions` keys.

        ADR-027 D2 / D3a: load_registry must surface version + priorVersions
        so known_versions and compose_pinned_value can use them.
        """
        registry = load_registry(FRAMEWORKS_YAML)
        entry = registry["mitre-atlas"]
        assert "version" in entry
        assert "priorVersions" in entry

    def test_stride_entry_has_null_version(self):
        """
        STRIDE entry has version == None.

        ADR-027 D6: STRIDE is unversioned (version: null in frameworks.yaml).
        """
        registry = load_registry(FRAMEWORKS_YAML)
        assert registry["stride"]["version"] is None

    def test_default_frameworks_path_points_at_real_file(self):
        """
        DEFAULT_FRAMEWORKS_PATH resolves to the real frameworks.yaml.

        Module must expose a usable default path for callers that do not
        specify --frameworks-file.
        """
        assert DEFAULT_FRAMEWORKS_PATH.is_file(), (
            f"DEFAULT_FRAMEWORKS_PATH {DEFAULT_FRAMEWORKS_PATH!r} does not exist"
        )

    def test_default_schema_path_points_at_real_file(self):
        """
        DEFAULT_SCHEMA_PATH resolves to the real frameworks.schema.json.

        Module must expose a usable default path for callers that do not
        specify --schema-file.
        """
        assert DEFAULT_SCHEMA_PATH.is_file(), f"DEFAULT_SCHEMA_PATH {DEFAULT_SCHEMA_PATH!r} does not exist"


# ===========================================================================
# 8. CLI `add` subcommand
# ===========================================================================


class TestCLIAdd:
    """
    CLI `add` composes a pinned value and appends it to the entity's mappings.

    ADR-027 D4 / D4a: the CLI is the authoring entry-point; contributors
    supply a structured selection; tooling emits the pinned value.
    """

    def test_add_creates_mapping_value_in_entity(self, tmp_path: Path):
        """
        After `add`, the pinned value appears in the entity's mappings block.

        ADR-027 D4a: `add` locates the entity by --cosai-id, creates
        `mappings.<framework>:` if absent, and appends the pinned value.
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode == 0, f"add must succeed; stderr=\n{result.stderr}\nstdout=\n{result.stdout}"
        data = _load_yaml(fixture)
        controls = {c["id"]: c for c in data["controls"]}
        assert "mappings" in controls["controlBar"]
        assert "AML.T0043@5.0.1" in controls["controlBar"]["mappings"]["mitre-atlas"]

    def test_add_creates_mappings_key_when_absent(self, tmp_path: Path):
        """
        `add` creates the `mappings:` key when the entity has none.

        ADR-027 D4a: "create `mappings:` and `mappings.<framework>:` if absent."
        `controlBar` in the fixture has no mappings block initially.
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "nist-ai-rmf",
            "--version",
            "1.0",
            "--framework-specific-ref",
            "GOVERN-6.2",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode == 0
        data = _load_yaml(fixture)
        controls = {c["id"]: c for c in data["controls"]}
        assert "mappings" in controls["controlBar"]
        assert "nist-ai-rmf" in controls["controlBar"]["mappings"]
        assert "GOVERN-6.2@1.0" in controls["controlBar"]["mappings"]["nist-ai-rmf"]

    def test_add_creates_framework_key_when_absent(self, tmp_path: Path):
        """
        `add` creates the framework key inside mappings when absent.

        ADR-027 D4a: `controlFoo` already has mappings but not an owasp-top10-llm key.
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "add",
            "--cosai-id",
            "controlFoo",
            "--framework",
            "owasp-top10-llm",
            "--version",
            "2025",
            "--framework-specific-ref",
            "LLM01",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode == 0
        data = _load_yaml(fixture)
        controls = {c["id"]: c for c in data["controls"]}
        assert "owasp-top10-llm" in controls["controlFoo"]["mappings"]
        assert "LLM01:2025" in controls["controlFoo"]["mappings"]["owasp-top10-llm"]

    def test_add_is_idempotent(self, tmp_path: Path):
        """
        Re-adding an identical value is a byte-level no-op.

        ADR-027 D4a: "re-adding an identical value is a byte-level no-op."
        This prevents duplicate list entries and commit churn.
        """
        fixture = _make_controls_fixture(tmp_path)
        # First add — should succeed and modify the file.
        _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        after_first = fixture.read_bytes()

        # Second identical add — must be a no-op.
        result = _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode == 0
        after_second = fixture.read_bytes()
        assert after_second == after_first, "re-adding must leave the file byte-identical (idempotency)"

    def test_add_preserves_sibling_entities(self, tmp_path: Path):
        """
        After `add`, sibling entities are structurally unchanged.

        ADR-027 D4a: writes must preserve YAML structure outside the touched block.
        """
        fixture = _make_controls_fixture(tmp_path)
        original = _load_yaml(fixture)
        baz_before = next(c for c in original["controls"] if c["id"] == "controlBaz")

        _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )

        reloaded = _load_yaml(fixture)
        baz_after = next(c for c in reloaded["controls"] if c["id"] == "controlBaz")
        assert baz_before == baz_after, "sibling entity must not be modified by add"

    def test_add_preserves_sibling_frameworks_order(self, tmp_path: Path):
        """
        `add` preserves the order of existing framework keys in the mappings block.

        ADR-027 D4a: "preserve existing taxonomy order."
        `controlFoo` has nist-ai-rmf before mitre-atlas in the fixture;
        adding owasp must not reorder the existing keys.
        """
        fixture = _make_controls_fixture(tmp_path)
        _run(
            "add",
            "--cosai-id",
            "controlFoo",
            "--framework",
            "owasp-top10-llm",
            "--version",
            "2025",
            "--framework-specific-ref",
            "LLM06",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        data = _load_yaml(fixture)
        controls = {c["id"]: c for c in data["controls"]}
        keys = list(controls["controlFoo"]["mappings"].keys())
        # nist-ai-rmf and mitre-atlas must appear before owasp-top10-llm
        assert keys.index("nist-ai-rmf") < keys.index("owasp-top10-llm")
        assert keys.index("mitre-atlas") < keys.index("owasp-top10-llm")


# ===========================================================================
# 9. CLI `remove` subcommand
# ===========================================================================


class TestCLIRemove:
    """
    CLI `remove` uses mappingId-addressed removal to delete a pinned value.

    ADR-027 D4a / D4b: `remove` addresses the mapping by (cosai-id, framework,
    version, ref) tuple; internal handle is the derived mappingId.
    """

    def test_remove_round_trip(self, tmp_path: Path):
        """
        add then remove returns the entity to its pre-add state.

        ADR-027 D4 / D4b: remove addresses by tuple (cosai-id, framework,
        version, framework-specific-ref) and deletes the matching entry.
        """
        fixture = _make_controls_fixture(tmp_path)
        before_bytes = fixture.read_bytes()

        # Add first.
        add_result = _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert add_result.returncode == 0

        # Remove what we just added.
        remove_result = _run(
            "remove",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert remove_result.returncode == 0, f"remove must succeed; stderr=\n{remove_result.stderr}"

        after_bytes = fixture.read_bytes()
        # The file should be back to its pre-add state. This requires remove to
        # delete the now-empty framework key AND the now-empty `mappings:` block
        # (the entity had no mappings before add), with no ruamel reflow drift.
        assert after_bytes == before_bytes, "add+remove must return the file to its prior byte state"

    def test_remove_nonexistent_value_exits_nonzero(self, tmp_path: Path):
        """
        Removing a value that is not present exits non-zero with a diagnostic.

        ADR-027 D4a: "If no match → exit non-zero with diagnostic."
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "remove",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode != 0
        # A non-zero exit must carry a diagnostic so a bare crash (no output)
        # cannot masquerade as a clean "not found" rejection.
        assert (result.stderr + result.stdout).strip(), "must emit a diagnostic message"

    def test_remove_empties_framework_key_removes_key(self, tmp_path: Path):
        """
        When remove empties a framework's list, the framework key is deleted.

        ADR-027 D4a: "If list becomes empty, remove the framework key."
        `controlBaz` has exactly one mitre-atlas value in the fixture.
        """
        fixture = _make_controls_fixture(tmp_path)
        remove_result = _run(
            "remove",
            "--cosai-id",
            "controlBaz",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0002",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert remove_result.returncode == 0, f"remove must succeed; stderr=\n{remove_result.stderr}"
        data = _load_yaml(fixture)
        controls = {c["id"]: c for c in data["controls"]}
        # mappings block may be absent or present but without mitre-atlas
        mappings = controls["controlBaz"].get("mappings", {})
        assert "mitre-atlas" not in mappings, "an emptied framework key must be removed from the mappings block"


# ===========================================================================
# 10. CLI `update` subcommand (re-pin semantic)
# ===========================================================================


class TestCLIUpdate:
    """
    CLI `update` re-pins a mapping: finds an existing entry by base-ref and
    replaces it with a new pinned value composed from --version.

    NOTE (spec ambiguity): the ADR (D4a) specifies add/remove verbs with
    explicit tuple-addressing, but does not detail the update verb's resolution
    logic beyond "update ... addresses by tuple." The interpretation tested here
    is:
      - `update` locates the existing entry whose base-ref (via split_pinned_value)
        matches --framework-specific-ref, then replaces it with
        compose_pinned_value(framework, --version, --ref).
      - "nothing to update" (no base-ref match) → exit non-zero.
      - "ambiguous" (multiple base-ref matches, different version tokens) → exit
        non-zero.
    This is the re-pin interpretation. Tests are labeled to flag this.

    ADR-027 D4 / D4a / D4b: re-pin semantic (maintainer interpretation).
    """

    def _fixture_with_old_version(self, tmp_path: Path) -> Path:
        """
        Build a controls fixture that declares a prior version of atlas to re-pin.

        We use a synthetic frameworks.yaml + schema for this test so we can
        declare a priorVersions entry without editing the live files.
        """
        # Synthetic frameworks.yaml with mitre-atlas having version 6.0.0
        # and priorVersions: [mitre-atlas@5.0.1]
        fw_yaml = tmp_path / "frameworks_with_prior.yaml"
        fw_yaml.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: mitre-atlas
                    name: MITRE ATLAS
                    fullName: MITRE ATLAS Full
                    description: desc
                    baseUri: https://atlas.mitre.org
                    version: '6.0.0'
                    versionId: mitre-atlas@6.0.0
                    priorVersions:
                      - mitre-atlas@5.0.1
                    applicableTo:
                      - controls
                      - risks
                """
            ),
            encoding="utf-8",
        )
        return fw_yaml

    def _synthetic_schema(self, tmp_path: Path) -> Path:
        """
        Build a minimal frameworks.schema.json that admits both 5.0.1 and 6.0.0.
        """
        import json

        schema_path = tmp_path / "frameworks_update.schema.json"
        schema = {
            "$id": "frameworks_update.schema.json",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "definitions": {
                "framework-mapping-patterns-pinned": {
                    "type": "object",
                    "properties": {
                        "mitre-atlas": {
                            "type": "string",
                            "pattern": r"^AML\.(T|M)\d{4}(\.\d{3})?@(5\.0\.1|6\.0\.0)$",
                        }
                    },
                }
            },
        }
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        return schema_path

    def test_update_repin_changes_version_token(self, tmp_path: Path):
        """
        `update` replaces a 5.0.1-pinned value with a 6.0.0-pinned value in place.

        ADR-027 D4 re-pin interpretation: `update` finds the existing entry by
        base-ref and replaces its version token. The value count for the framework
        key stays the same (replace, not append).
        """
        fw_yaml = self._fixture_with_old_version(tmp_path)
        schema_path = self._synthetic_schema(tmp_path)

        fixture = tmp_path / "controls.yaml"
        _write_consumer_fixture(
            fixture,
            """\
            title: Controls
            description:
              - Test update fixture.
            controls:
              - id: controlFoo
                title: Foo
                description:
                  - desc
                mappings:
                  mitre-atlas:
                    - AML.T0043@5.0.1
            """,
        )

        result = _run(
            "update",
            "--cosai-id",
            "controlFoo",
            "--framework",
            "mitre-atlas",
            "--version",
            "6.0.0",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(fw_yaml),
            "--schema-file",
            str(schema_path),
        )
        assert result.returncode == 0, f"update must succeed on a valid re-pin; stderr=\n{result.stderr}"
        data = _load_yaml(fixture)
        atlas_values = data["controls"][0]["mappings"]["mitre-atlas"]
        assert "AML.T0043@6.0.0" in atlas_values
        assert "AML.T0043@5.0.1" not in atlas_values

    def test_update_nothing_to_update_exits_nonzero(self, tmp_path: Path):
        """
        `update` exits non-zero when no existing base-ref matches --framework-specific-ref.

        ADR-027 D4 re-pin interpretation: "nothing to update" error path.
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "update",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T9999",  # no such entry in fixture
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode != 0
        # Diagnostic must appear in stderr or stdout.
        combined = result.stderr + result.stdout
        assert combined.strip(), "non-zero exit must produce a diagnostic message"

    def test_update_ambiguous_exits_nonzero(self, tmp_path: Path):
        """
        `update` exits non-zero when multiple entries share the same base-ref.

        ADR-027 D4 re-pin interpretation: "ambiguous" error path — two entries
        with the same base-ref but different version tokens (multi-version
        coexistence during a migration window, D3) are ambiguous for a base-ref
        search; the caller must remove+add to disambiguate.
        """
        fw_yaml = self._fixture_with_old_version(tmp_path)
        schema_path = self._synthetic_schema(tmp_path)

        fixture = tmp_path / "controls_ambiguous.yaml"
        _write_consumer_fixture(
            fixture,
            """\
            title: Controls
            description:
              - Ambiguous update fixture.
            controls:
              - id: controlFoo
                title: Foo
                description:
                  - desc
                mappings:
                  mitre-atlas:
                    - AML.T0043@5.0.1
                    - AML.T0043@6.0.0
            """,
        )

        result = _run(
            "update",
            "--cosai-id",
            "controlFoo",
            "--framework",
            "mitre-atlas",
            "--version",
            "6.0.0",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(fw_yaml),
            "--schema-file",
            str(schema_path),
        )
        assert result.returncode != 0, (
            "update must exit non-zero when multiple entries share the same base-ref (ambiguous)"
        )
        # The ambiguity must be reported, not silently swallowed by a bare exit.
        assert (result.stderr + result.stdout).strip(), "must emit a diagnostic message"


# ===========================================================================
# 11. CLI rejection cases — validation failures
# ===========================================================================


class TestCLIRejectionCases:
    """
    The CLI exits non-zero with a stderr diagnostic for all validation failures.

    ADR-027 D4a: "(1) validates --framework, (2) validates --version,
    (3) validates --framework-specific-ref."
    """

    def test_unknown_framework_exits_nonzero(self, tmp_path: Path):
        """
        --framework not in frameworks.yaml id enum → non-zero exit + diagnostic.

        ADR-027 D4a step 1: framework must be validated against the id enum.
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "not-a-framework",
            "--version",
            "1.0",
            "--framework-specific-ref",
            "SOME-REF",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode != 0
        assert result.stderr.strip(), "must emit a diagnostic to stderr"

    def test_unknown_version_exits_nonzero(self, tmp_path: Path):
        """
        --version not in the framework's recognized version set → non-zero exit.

        ADR-027 D4a step 2: version is rejected at authoring time,
        the earliest possible point.
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "9.9.9",  # not a recognized version
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode != 0
        assert result.stderr.strip()

    def test_out_of_vocab_iso_ref_exits_nonzero(self, tmp_path: Path):
        """
        A --framework-specific-ref outside the ISO 22989 closed enum → non-zero exit.

        ADR-027 D8: "`AI Part (Data supplier)` cannot be authored" — the CLI
        must reject out-of-vocab ISO refs at step 3.
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "iso-22989",
            "--version",
            "2022",
            "--framework-specific-ref",
            "AI Part (Data supplier)",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode != 0
        assert result.stderr.strip()

    def test_entity_not_found_exits_nonzero(self, tmp_path: Path):
        """
        --cosai-id that does not exist in the content file → non-zero exit.

        ADR-027 D4a: the tool must locate the entity by --cosai-id; if absent,
        it is a validation failure not a silent create.
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "add",
            "--cosai-id",
            "controlDoesNotExist",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode != 0
        assert result.stderr.strip()

    def test_malformed_atlas_ref_exits_nonzero(self, tmp_path: Path):
        """
        A malformed MITRE ATLAS ref (pattern mismatch) → non-zero exit.

        ADR-027 D4a step 3: spec-native regex rejects `AMLT0043` (missing dot).
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AMLT0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode != 0
        assert result.stderr.strip()


# ===========================================================================
# 12. Format preservation
# ===========================================================================


class TestFormatPreservation:
    """
    After an `add`, comments and sibling content outside the touched block survive.

    ADR-027 D4: "writes must preserve YAML formatting/comments (e.g. via
    ruamel.yaml)." A full yaml.dump round-trip would destroy comments; the
    implementation must do surgical insertion.
    """

    def test_comment_lines_survive_add(self, tmp_path: Path):
        """
        Comments present in the fixture file survive an `add` operation.

        ADR-027 D4: the implementation must preserve formatting/comments.
        """
        fixture = _make_controls_fixture(tmp_path)
        original_text = fixture.read_text(encoding="utf-8")
        original_comment_lines = [line for line in original_text.splitlines() if line.lstrip().startswith("#")]
        assert original_comment_lines, "fixture must contain comments for this test to be meaningful"

        _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )

        rewritten_text = fixture.read_text(encoding="utf-8")
        rewritten_comment_lines = [line for line in rewritten_text.splitlines() if line.lstrip().startswith("#")]
        missing = [c for c in original_comment_lines if c not in rewritten_comment_lines]
        assert not missing, "all comment lines must survive an add; missing:\n" + "\n".join(missing)

    def test_file_parses_as_valid_yaml_after_add(self, tmp_path: Path):
        """
        The file is still valid YAML after an `add` operation.

        ADR-027 D4: the output must be parseable by PyYAML.
        """
        fixture = _make_controls_fixture(tmp_path)
        result = _run(
            "add",
            "--cosai-id",
            "controlBaz",
            "--framework",
            "nist-ai-rmf",
            "--version",
            "1.0",
            "--framework-specific-ref",
            "MAP-2.1",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode == 0
        try:
            data = _load_yaml(fixture)
        except yaml.YAMLError as exc:
            pytest.fail(f"file is not valid YAML after add: {exc}")
        assert "controls" in data

    def test_expected_structure_intact_after_add(self, tmp_path: Path):
        """
        All original entities and top-level keys survive an `add`.

        ADR-027 D4: non-target content must be preserved.
        """
        fixture = _make_controls_fixture(tmp_path)
        original = _load_yaml(fixture)
        original_ids = {c["id"] for c in original["controls"]}

        _run(
            "add",
            "--cosai-id",
            "controlBar",
            "--framework",
            "mitre-atlas",
            "--version",
            "5.0.1",
            "--framework-specific-ref",
            "AML.T0043",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )

        reloaded = _load_yaml(fixture)
        reloaded_ids = {c["id"] for c in reloaded["controls"]}
        assert reloaded_ids == original_ids, "no entities must be added or removed by add"
        # Top-level keys preserved
        assert set(reloaded.keys()) == set(original.keys())


# ===========================================================================
# 13. compose_pinned_value — unversioned-version WARNING observability (D6)
# ===========================================================================


class TestComposePinnedValueUnversionedWarning:
    """
    compose_pinned_value must emit a `warning:`-prefixed message to stderr when
    a non-None version argument is supplied for an unversioned framework.

    ADR-027 D6: STRIDE carries no version token; the return value is the bare ref
    (contract unchanged). The warning is observability-only — it does NOT alter
    the return value. It surfaces a likely caller mistake: supplying a version
    string for a framework that has none.

    The warning format mirrors the CLI's error style:
      `warning: framework '<id>' is unversioned; supplied version '<v>' ignored (D6).`
    """

    def test_unversioned_framework_with_version_emits_warning_to_stderr(self, capsys):
        """
        Given: an unversioned framework (stride, version: null in registry) and a
               non-None version argument ('2.0')
        When:  compose_pinned_value is called
        Then:  stderr contains 'warning:', 'stride', and '2.0'
               stdout is empty (warning goes to stderr only)

        D6: the version token is dropped (return is the bare ref); the warning
        makes the silent drop explicit so callers notice the mismatch.
        """
        result = compose_pinned_value(
            "stride",
            "2.0",
            "Tampering",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        # Return contract unchanged: bare ref (D6).
        assert result == "Tampering"

        captured = capsys.readouterr()
        assert "warning:" in captured.err, (
            "compose_pinned_value must emit a 'warning:'-prefixed message to stderr "
            "when a version is supplied for an unversioned framework (D6 observability)"
        )
        assert "stride" in captured.err, "the warning must name the unversioned framework id"
        assert "2.0" in captured.err, "the warning must include the ignored version string"
        assert captured.out == "", "warning must go to stderr only, not stdout"

    def test_unversioned_framework_with_none_version_no_warning(self, capsys):
        """
        Given: an unversioned framework (stride) and version=None
        When:  compose_pinned_value is called
        Then:  stderr is empty (no warning — None is the correct caller behaviour)
               return is the bare ref

        D6: None is the correct version argument for an unversioned framework.
        Validators calling compose via split→compose always pass version=None for
        STRIDE legacy values, so the warning must never fire on that path.
        """
        result = compose_pinned_value(
            "stride",
            None,
            "Tampering",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert result == "Tampering"
        captured = capsys.readouterr()
        assert captured.err == "", (
            "No warning must be emitted when version=None for an unversioned "
            "framework (D6: None is the correct call-site argument)"
        )

    def test_versioned_framework_with_valid_version_no_warning(self, capsys):
        """
        Given: a versioned framework (mitre-atlas, version: '5.0.1' in registry) and
               a recognized version argument ('5.0.1')
        When:  compose_pinned_value is called
        Then:  return is 'AML.T0020@5.0.1', stderr is empty

        Regression guard: the warning mechanism must not fire for versioned
        frameworks with valid versions — only the unversioned-but-version-supplied
        case triggers the D6 observability warning.
        """
        result = compose_pinned_value(
            "mitre-atlas",
            "5.0.1",
            "AML.T0020",
            registry=_get_registry(),
            pinned_patterns=_get_pinned_patterns(),
        )
        assert result == "AML.T0020@5.0.1"
        captured = capsys.readouterr()
        assert captured.err == "", (
            "No warning must be emitted for a versioned framework with a valid "
            "version argument (D6 warning is only for unversioned-with-version calls)"
        )


# ===========================================================================
# 14. migrate_legacy_value — per-framework legacy→pinned transforms
# ===========================================================================


class TestMigrateLegacyValueTransforms:
    """
    migrate_legacy_value maps each framework's legacy representation to its
    ADR-027 pinned form, using compose_pinned_value as the canonical compose path.

    ADR-027 D3 / D3a / D4 / D6 / D8: pinned form = spec-native canonical ref +
    version token (or bare PascalCase for STRIDE). The migration function never
    hand-spells the output — it routes through compose_pinned_value.

    #343 fail-loud rule: the function must raise FrameworkMappingError (or a
    subclass) for any value it cannot map; it never silently passes through.
    """

    # --- mitre-atlas: append @5.0.1 token only ---

    def test_mitre_atlas_technique_legacy_to_pinned(self):
        """
        A bare ATLAS technique ref gains the @5.0.1 token.

        Given: mitre-atlas legacy value 'AML.T0020' (no version token)
        When:  migrate_legacy_value is called
        Then:  returns ('AML.T0020@5.0.1', True)

        ADR-027 D3 / D4: migration routes through compose_pinned_value;
        the only transform for ATLAS is appending the current version token.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "mitre-atlas",
            "AML.T0020",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "AML.T0020@5.0.1"
        assert changed is True

    def test_mitre_atlas_mitigation_legacy_to_pinned(self):
        """
        A bare ATLAS mitigation ref (M-prefix) gains the @5.0.1 token.

        Given: mitre-atlas legacy value 'AML.M0003'
        When:  migrate_legacy_value is called
        Then:  returns ('AML.M0003@5.0.1', True)

        ADR-027 D3 / D4: the ATLAS pattern covers both T and M prefixes.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "mitre-atlas",
            "AML.M0003",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "AML.M0003@5.0.1"
        assert changed is True

    def test_mitre_atlas_subtechnique_legacy_to_pinned(self):
        """
        A bare ATLAS sub-technique ref (T####.###) gains the @5.0.1 token.

        Given: mitre-atlas legacy value 'AML.T0010.001'
        When:  migrate_legacy_value is called
        Then:  returns ('AML.T0010.001@5.0.1', True)

        ADR-027 D3: the ATLAS pinned pattern includes optional .### sub-id.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "mitre-atlas",
            "AML.T0010.001",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "AML.T0010.001@5.0.1"
        assert changed is True

    # --- nist-ai-rmf: respell prefix + append @1.0 ---

    def test_nist_gv_prefix_to_govern(self):
        """
        Legacy NIST GV prefix is respelled to GOVERN and token @1.0 is appended.

        Given: nist-ai-rmf legacy value 'GV-6.2'
        When:  migrate_legacy_value is called
        Then:  returns ('GOVERN-6.2@1.0', True)

        ADR-027 D3 / D4: LEGACY_NIST_PREFIX_MAP GV→GOVERN; compose adds @1.0.
        #343 plan: NIST is lossy if the prefix map is incomplete → fail-loud required.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "nist-ai-rmf",
            "GV-6.2",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "GOVERN-6.2@1.0"
        assert changed is True

    def test_nist_ms_prefix_to_measure(self):
        """
        Legacy NIST MS prefix is respelled to MEASURE.

        Given: nist-ai-rmf legacy value 'MS-2.3'
        When:  migrate_legacy_value is called
        Then:  returns ('MEASURE-2.3@1.0', True)

        ADR-027 D3 / D4: LEGACY_NIST_PREFIX_MAP MS→MEASURE.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "nist-ai-rmf",
            "MS-2.3",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "MEASURE-2.3@1.0"
        assert changed is True

    def test_nist_mp_prefix_to_map(self):
        """
        Legacy NIST MP prefix is respelled to MAP.

        Given: nist-ai-rmf legacy value 'MP-3.4'
        When:  migrate_legacy_value is called
        Then:  returns ('MAP-3.4@1.0', True)

        ADR-027 D3 / D4: LEGACY_NIST_PREFIX_MAP MP→MAP.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "nist-ai-rmf",
            "MP-3.4",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "MAP-3.4@1.0"
        assert changed is True

    def test_nist_mg_prefix_to_manage(self):
        """
        Legacy NIST MG prefix is respelled to MANAGE.

        Given: nist-ai-rmf legacy value 'MG-2.1'
        When:  migrate_legacy_value is called
        Then:  returns ('MANAGE-2.1@1.0', True)

        ADR-027 D3 / D4: LEGACY_NIST_PREFIX_MAP MG→MANAGE.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "nist-ai-rmf",
            "MG-2.1",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "MANAGE-2.1@1.0"
        assert changed is True

    def test_nist_ms_multi_dot_rest(self):
        """
        Legacy NIST value with a multi-part sub-id (e.g. MS-2.10) is correctly
        mapped: only the prefix portion before the FIRST '-' is respelled.

        Given: nist-ai-rmf legacy value 'MS-2.10'
        When:  migrate_legacy_value is called
        Then:  returns ('MEASURE-2.10@1.0', True)

        ADR-027 D3 / D4: split on FIRST '-' only; remainder '2.10' is preserved.
        #343 plan: a naive split on last '-' would corrupt the sub-id.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "nist-ai-rmf",
            "MS-2.10",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "MEASURE-2.10@1.0"
        assert changed is True

    # --- owasp-top10-llm: append :2025 token (colon delimiter) ---

    def test_owasp_legacy_to_pinned(self):
        """
        A bare OWASP LLM ref gains the :2025 token (colon delimiter, not @).

        Given: owasp-top10-llm legacy value 'LLM06'
        When:  migrate_legacy_value is called
        Then:  returns ('LLM06:2025', True)

        ADR-027 D6 / D3: OWASP uses the : delimiter; Decision 1 locks to :2025.
        The issue body's ':2024' is a stale erratum — migrate to ':2025' per
        frameworks.yaml source of truth.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "owasp-top10-llm",
            "LLM06",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "LLM06:2025"
        assert changed is True

    # --- stride: respell kebab to PascalCase (no version token — D6) ---

    def test_stride_information_disclosure_to_pascal(self):
        """
        Stride kebab 'information-disclosure' becomes bare PascalCase 'InformationDisclosure'.

        Given: stride legacy value 'information-disclosure'
        When:  migrate_legacy_value is called
        Then:  returns ('InformationDisclosure', True)

        ADR-027 D6: STRIDE is unversioned; the migrated value is bare PascalCase.
        LEGACY_STRIDE_KEBAB_MAP encodes the canonical respelling.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "stride",
            "information-disclosure",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "InformationDisclosure"
        assert changed is True

    def test_stride_denial_of_service_to_pascal(self):
        """
        Stride kebab 'denial-of-service' becomes 'DenialOfService'.

        Given: stride legacy value 'denial-of-service'
        When:  migrate_legacy_value is called
        Then:  returns ('DenialOfService', True)

        ADR-027 D6 / #343 plan.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "stride",
            "denial-of-service",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "DenialOfService"
        assert changed is True

    def test_stride_elevation_of_privilege_to_pascal(self):
        """
        Stride kebab 'elevation-of-privilege' becomes 'ElevationOfPrivilege'.

        Given: stride legacy value 'elevation-of-privilege'
        When:  migrate_legacy_value is called
        Then:  returns ('ElevationOfPrivilege', True)

        ADR-027 D6 / #343 plan.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "stride",
            "elevation-of-privilege",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "ElevationOfPrivilege"
        assert changed is True

    def test_stride_spoofing_to_pascal(self):
        """
        Stride kebab 'spoofing' becomes 'Spoofing'.

        Given: stride legacy value 'spoofing'
        When:  migrate_legacy_value is called
        Then:  returns ('Spoofing', True)

        ADR-027 D6 / #343 plan.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "stride",
            "spoofing",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "Spoofing"
        assert changed is True

    def test_stride_tampering_to_pascal(self):
        """
        Stride kebab 'tampering' becomes 'Tampering'.

        Given: stride legacy value 'tampering'
        When:  migrate_legacy_value is called
        Then:  returns ('Tampering', True)

        ADR-027 D6 / #343 plan.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "stride",
            "tampering",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "Tampering"
        assert changed is True

    def test_stride_repudiation_to_pascal(self):
        """
        Stride kebab 'repudiation' becomes 'Repudiation'.

        Given: stride legacy value 'repudiation'
        When:  migrate_legacy_value is called
        Then:  returns ('Repudiation', True)

        ADR-027 D6 / #343 plan.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "stride",
            "repudiation",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "Repudiation"
        assert changed is True

    # --- iso-22989: bare phrase → enum@2022 ---

    def test_iso_ai_producer_to_pinned(self):
        """
        ISO 22989 bare role 'AI Producer' gains the @2022 token.

        Given: iso-22989 legacy value 'AI Producer'
        When:  migrate_legacy_value is called
        Then:  returns ('AI Producer@2022', True)

        ADR-027 D8: ISO 22989 uses a closed enum + @2022 token.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "iso-22989",
            "AI Producer",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "AI Producer@2022"
        assert changed is True

    def test_iso_ai_partner_data_supplier_to_pinned(self):
        """
        ISO 22989 bare role 'AI Partner (data supplier)' gains the @2022 token.

        Given: iso-22989 legacy value 'AI Partner (data supplier)'
        When:  migrate_legacy_value is called
        Then:  returns ('AI Partner (data supplier)@2022', True)

        ADR-027 D8: spaces and parens in the role are preserved verbatim (D3a H3).
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "iso-22989",
            "AI Partner (data supplier)",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "AI Partner (data supplier)@2022"
        assert changed is True


# ===========================================================================
# 15. migrate_legacy_value — idempotency
# ===========================================================================


class TestMigrateLegacyValueIdempotency:
    """
    migrate_legacy_value returns (value, False) unchanged when the input
    already validates against the framework's pinned subschema.

    ADR-027 D3 / D4: the function is idempotent — running it twice on an
    already-migrated corpus is a no-op. The 'changed' flag will be False.

    #343 fail-loud rule: idempotency must not mask an error; a value that
    looks pinned but is actually invalid must still raise, not silently pass.
    """

    def test_already_pinned_atlas_is_unchanged(self):
        """
        A value already in pinned form for ATLAS returns unchanged.

        Given: mitre-atlas already-pinned value 'AML.T0020@5.0.1'
        When:  migrate_legacy_value is called
        Then:  returns ('AML.T0020@5.0.1', False)

        ADR-027 D3 / D4: idempotency gate via schema validation.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "mitre-atlas",
            "AML.T0020@5.0.1",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "AML.T0020@5.0.1"
        assert changed is False

    def test_already_pinned_nist_is_unchanged(self):
        """
        A value already in pinned NIST form returns unchanged.

        Given: nist-ai-rmf already-pinned value 'GOVERN-6.2@1.0'
        When:  migrate_legacy_value is called
        Then:  returns ('GOVERN-6.2@1.0', False)

        ADR-027 D3 / D4: idempotency — the canonical NIST form passes
        the pinned subschema check and is left alone.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "nist-ai-rmf",
            "GOVERN-6.2@1.0",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "GOVERN-6.2@1.0"
        assert changed is False

    def test_already_pinned_owasp_is_unchanged(self):
        """
        A value already in pinned OWASP form (colon delimiter) returns unchanged.

        Given: owasp-top10-llm already-pinned value 'LLM06:2025'
        When:  migrate_legacy_value is called
        Then:  returns ('LLM06:2025', False)

        ADR-027 D6 / D3: OWASP pinned form uses colon; already-correct values
        must not be touched.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "owasp-top10-llm",
            "LLM06:2025",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "LLM06:2025"
        assert changed is False

    def test_already_pinned_stride_is_unchanged(self):
        """
        A value already in PascalCase STRIDE form returns unchanged.

        Given: stride already-pinned value 'InformationDisclosure'
        When:  migrate_legacy_value is called
        Then:  returns ('InformationDisclosure', False)

        ADR-027 D6: STRIDE is unversioned; the bare PascalCase form is the
        pinned form and must be left alone.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "stride",
            "InformationDisclosure",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "InformationDisclosure"
        assert changed is False

    def test_already_pinned_iso_is_unchanged(self):
        """
        A value already in pinned ISO 22989 form returns unchanged.

        Given: iso-22989 already-pinned value 'AI Producer@2022'
        When:  migrate_legacy_value is called
        Then:  returns ('AI Producer@2022', False)

        ADR-027 D8: closed enum @2022 form is the pinned form.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        result, changed = migrate_legacy_value(
            "iso-22989",
            "AI Producer@2022",
            registry=registry,
            pinned_patterns=pinned_patterns,
        )
        assert result == "AI Producer@2022"
        assert changed is False


# ===========================================================================
# 16. migrate_legacy_value — fail-loud (never silent pass-through)
# ===========================================================================


class TestMigrateLegacyValueFailLoud:
    """
    migrate_legacy_value raises FrameworkMappingError (or a specific subclass)
    for any value it cannot map. It NEVER silently returns an unmappable value.

    This mirrors the #347 P4 silent-skip bug. The #343 plan states:
    "the migrate tool must fail loud on any legacy value it can't map,
    never silently skip."

    ADR-027 D3 / D4: the function is the single compose path; an unmappable
    value indicates a data integrity problem that must surface immediately.
    """

    def test_nist_unknown_prefix_raises(self):
        """
        A NIST legacy value with a prefix not in LEGACY_NIST_PREFIX_MAP raises.

        Given: nist-ai-rmf value 'XY-1.2' (prefix 'XY' not in the map)
        When:  migrate_legacy_value is called
        Then:  raises InvalidRefError

        #343 fail-loud rule: an incomplete prefix map must never silently
        pass through — it must raise so the data problem surfaces.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        with pytest.raises(InvalidRefError):
            migrate_legacy_value(
                "nist-ai-rmf",
                "XY-1.2",
                registry=registry,
                pinned_patterns=pinned_patterns,
            )

    def test_stride_unknown_kebab_raises(self):
        """
        A STRIDE legacy value not in LEGACY_STRIDE_KEBAB_MAP raises.

        Given: stride value 'unknown-category' (not a valid STRIDE kebab form)
        When:  migrate_legacy_value is called
        Then:  raises InvalidRefError

        #343 fail-loud rule: any unrecognized STRIDE kebab form must raise,
        never be passed through silently or mapped to a guess.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        with pytest.raises(InvalidRefError):
            migrate_legacy_value(
                "stride",
                "unknown-category",
                registry=registry,
                pinned_patterns=pinned_patterns,
            )

    def test_mitre_off_pattern_raises(self):
        """
        A MITRE ATLAS value that does not match the expected pattern raises.

        Given: mitre-atlas value 'GARBAGE' (no AML prefix, no pattern match)
        When:  migrate_legacy_value is called
        Then:  raises InvalidRefError (compose_pinned_value rejects the ref)

        ADR-027 D4a step 3: spec-native regex rejects refs that don't match.
        #343 fail-loud rule: off-pattern refs must never silently pass through.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        with pytest.raises(InvalidRefError):
            migrate_legacy_value(
                "mitre-atlas",
                "GARBAGE",
                registry=registry,
                pinned_patterns=pinned_patterns,
            )

    def test_unknown_framework_raises(self):
        """
        A framework key not in the registry raises UnknownFrameworkError.

        Given: framework 'not-a-framework' (not in registry) with any value
        When:  migrate_legacy_value is called
        Then:  raises UnknownFrameworkError

        ADR-027 D4a step 1: framework id is validated against the registry.
        #343 fail-loud rule: an unknown framework key must raise immediately.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        with pytest.raises(UnknownFrameworkError):
            migrate_legacy_value(
                "not-a-framework",
                "SOME-VALUE",
                registry=registry,
                pinned_patterns=pinned_patterns,
            )

    def test_fail_loud_is_framework_mapping_error_subclass(self):
        """
        All migrate_legacy_value failures are catchable as FrameworkMappingError.

        This checks the exception hierarchy guarantees that callers catching the
        base type will catch both InvalidRefError and UnknownFrameworkError.

        ADR-027 D4a / exception hierarchy.
        """
        registry = _get_registry()
        pinned_patterns = _get_pinned_patterns()
        with pytest.raises(FrameworkMappingError):
            migrate_legacy_value(
                "not-a-framework",
                "ANY-VALUE",
                registry=registry,
                pinned_patterns=pinned_patterns,
            )


# ===========================================================================
# 17. LEGACY_NIST_PREFIX_MAP and LEGACY_STRIDE_KEBAB_MAP constants
# ===========================================================================


class TestMigrateLookupTables:
    """
    The lookup-table constants must have exactly the expected keys and values.

    An incomplete table causes silent lossy migration (a NIST prefix with no
    entry would cause compose to receive a wrong base-ref, or the fail-loud
    path to miss valid legacy values). The #343 plan specifically flags this
    as a risk.

    ADR-027 D3 / D4 / #343 plan §5: "NIST/STRIDE respelling is lossy if the
    lookup tables are incomplete — the migrate tool must fail loud on any
    legacy value it can't map."
    """

    def test_nist_prefix_map_has_exactly_four_entries(self):
        """
        LEGACY_NIST_PREFIX_MAP must have exactly 4 entries.

        Given: the four NIST AI RMF function prefixes in the live corpus:
               GV (GOVERN), MS (MEASURE), MP (MAP), MG (MANAGE)
        Then:  LEGACY_NIST_PREFIX_MAP has exactly those four keys.

        An entry count != 4 signals either an incomplete or incorrectly expanded map.
        """
        assert len(LEGACY_NIST_PREFIX_MAP) == 4, (
            f"LEGACY_NIST_PREFIX_MAP must have exactly 4 entries; "
            f"got {len(LEGACY_NIST_PREFIX_MAP)}: {LEGACY_NIST_PREFIX_MAP}"
        )

    def test_nist_prefix_map_gv_maps_to_govern(self):
        """
        LEGACY_NIST_PREFIX_MAP['GV'] must be 'GOVERN'.

        ADR-027 D3 / D4: GV→GOVERN is the canonical NIST AI RMF function name.
        """
        assert LEGACY_NIST_PREFIX_MAP["GV"] == "GOVERN"

    def test_nist_prefix_map_ms_maps_to_measure(self):
        """LEGACY_NIST_PREFIX_MAP['MS'] must be 'MEASURE'."""
        assert LEGACY_NIST_PREFIX_MAP["MS"] == "MEASURE"

    def test_nist_prefix_map_mp_maps_to_map(self):
        """LEGACY_NIST_PREFIX_MAP['MP'] must be 'MAP'."""
        assert LEGACY_NIST_PREFIX_MAP["MP"] == "MAP"

    def test_nist_prefix_map_mg_maps_to_manage(self):
        """LEGACY_NIST_PREFIX_MAP['MG'] must be 'MANAGE'."""
        assert LEGACY_NIST_PREFIX_MAP["MG"] == "MANAGE"

    def test_stride_kebab_map_has_exactly_six_entries(self):
        """
        LEGACY_STRIDE_KEBAB_MAP must have exactly 6 entries — one per STRIDE threat.

        Given: the six STRIDE threat categories in the live corpus:
               spoofing, tampering, repudiation, information-disclosure,
               denial-of-service, elevation-of-privilege
        Then:  LEGACY_STRIDE_KEBAB_MAP has exactly those six keys.

        #343 plan §5: an incomplete STRIDE map causes fail-loud failures
        on valid legacy values (desired), but a map that is too large
        would silently admit invalid kebab forms.
        """
        assert len(LEGACY_STRIDE_KEBAB_MAP) == 6, (
            f"LEGACY_STRIDE_KEBAB_MAP must have exactly 6 entries; "
            f"got {len(LEGACY_STRIDE_KEBAB_MAP)}: {LEGACY_STRIDE_KEBAB_MAP}"
        )

    def test_stride_kebab_map_all_values(self):
        """
        LEGACY_STRIDE_KEBAB_MAP maps all six kebab forms to the correct PascalCase.

        ADR-027 D6 / #343 plan: the canonical PascalCase forms are those accepted
        by the pinned STRIDE subschema (closed enum).
        """
        expected = {
            "spoofing": "Spoofing",
            "tampering": "Tampering",
            "repudiation": "Repudiation",
            "information-disclosure": "InformationDisclosure",
            "denial-of-service": "DenialOfService",
            "elevation-of-privilege": "ElevationOfPrivilege",
        }
        assert LEGACY_STRIDE_KEBAB_MAP == expected, (
            f"LEGACY_STRIDE_KEBAB_MAP mismatch.\nExpected: {expected}\nGot:      {LEGACY_STRIDE_KEBAB_MAP}"
        )


# ===========================================================================
# 18. CLI `migrate` subcommand — subprocess tests
# ===========================================================================


def _make_legacy_controls_fixture(tmp_path: Path) -> Path:
    """
    Build a small controls.yaml fixture with LEGACY values for migrate tests.

    Contains:
      - controlLegacy: four legacy mappings (nist GV-1.6, stride information-disclosure,
        owasp LLM06, mitre AML.T0020) plus a comment to test preservation.
      - controlAlreadyPinned: one already-pinned mitre value (sibling preservation).

    The fixture is self-contained — not reusing _make_controls_fixture() because
    the migrate subcommand operates on the mappings values themselves, not on
    adding/removing individual entries.
    """
    dst = tmp_path / "controls_legacy.yaml"
    _write_consumer_fixture(
        dst,
        """\
        # Copyright notice preserved
        title: Controls
        description:
          - >
            Legacy controls fixture for migrate subcommand tests.
        categories:
          - id: controlsData
            title: Data Controls
        controls:
          - id: controlLegacy
            title: Legacy Control
            description:
              - Control with legacy mapping values.
            # sibling comment preserved
            category: controlsData
            personas: []
            components: []
            risks: []
            mappings:
              nist-ai-rmf:
                - GV-1.6
              stride:
                - information-disclosure
              owasp-top10-llm:
                - LLM06
              mitre-atlas:
                - AML.T0020

          - id: controlAlreadyPinned
            title: Already Pinned Control
            description:
              - Control with an already-pinned mapping value (sibling).
            category: controlsData
            personas: []
            components: []
            risks: []
            mappings:
              mitre-atlas:
                - AML.T0043@5.0.1
        """,
    )
    return dst


def _make_unmappable_controls_fixture(tmp_path: Path) -> Path:
    """
    Build a controls.yaml fixture containing an unmappable NIST legacy value (XY-9.9).

    Used to test the fail-loud path: migrate must exit non-zero and not write
    a partially migrated file silently.
    """
    dst = tmp_path / "controls_unmappable.yaml"
    _write_consumer_fixture(
        dst,
        """\
        title: Controls
        description:
          - Unmappable fixture.
        categories:
          - id: controlsData
            title: Data Controls
        controls:
          - id: controlUnmappable
            title: Unmappable Control
            description:
              - Has a NIST value with an unknown prefix.
            category: controlsData
            personas: []
            components: []
            risks: []
            mappings:
              nist-ai-rmf:
                - XY-9.9
        """,
    )
    return dst


def _make_long_prose_fixture(tmp_path: Path) -> Path:
    """
    Build a controls fixture with a long single-line folded-scalar description
    and exactly one legacy mapping value.

    The description line is far wider than ruamel's default 80-column wrap, so a
    full YAML re-emit would re-fold it. The migrate tool must change ONLY the
    mapping value and leave every prose byte untouched (value-only diff).
    """
    dst = tmp_path / "controls_long_prose.yaml"
    long_line = (
        "This is a deliberately long single physical line of folded prose that exceeds "
        "the default eighty column ruamel wrap width so a naive full re-emit would re-fold it."
    )
    _write_consumer_fixture(
        dst,
        f"""\
        title: Controls
        description:
          - Long-prose migrate fixture.
        categories:
          - id: controlsData
            title: Data Controls
        controls:
          - id: controlLongProse
            title: Long Prose Control
            description:
              - >
                {long_line}
            category: controlsData
            personas: []
            components: []
            risks: []
            mappings:
              nist-ai-rmf:
                - GV-1.6
        """,
    )
    return dst


class TestCLIMigrate:
    """
    CLI `migrate` subcommand subprocess tests.

    Tests: happy-path migration, idempotency, --dry-run, comment/sibling
    preservation, and fail-loud on unmappable values.

    ADR-027 D3 / D4 / D6 / D8 / #343 Decision 2 / fail-loud rule.
    """

    def test_migrate_rewrites_legacy_values_to_pinned(self, tmp_path: Path):
        """
        `migrate` rewrites each legacy value in the fixture to its pinned form.

        Given: a controls fixture with legacy values for nist, stride, owasp, mitre
        When:  migrate --content-file <fixture> is run
        Then:  exits 0 and each legacy value is replaced with its pinned form

        ADR-027 D3 / D4 / #343 Decision 2: migrate routes through
        compose_pinned_value; the tool must never hand-spell pinned values.
        """
        fixture = _make_legacy_controls_fixture(tmp_path)
        result = _run(
            "migrate",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode == 0, (
            f"migrate must succeed on a valid legacy fixture; stderr=\n{result.stderr}\nstdout=\n{result.stdout}"
        )
        data = _load_yaml(fixture)
        controls = {c["id"]: c for c in data["controls"]}
        mappings = controls["controlLegacy"]["mappings"]
        # NIST GV-1.6 → GOVERN-1.6@1.0
        assert "GOVERN-1.6@1.0" in mappings["nist-ai-rmf"]
        assert "GV-1.6" not in mappings["nist-ai-rmf"]
        # stride information-disclosure → InformationDisclosure
        assert "InformationDisclosure" in mappings["stride"]
        assert "information-disclosure" not in mappings["stride"]
        # OWASP LLM06 → LLM06:2025
        assert "LLM06:2025" in mappings["owasp-top10-llm"]
        assert "LLM06" not in mappings["owasp-top10-llm"]
        # ATLAS AML.T0020 → AML.T0020@5.0.1
        assert "AML.T0020@5.0.1" in mappings["mitre-atlas"]
        assert "AML.T0020" not in mappings["mitre-atlas"]

    def test_migrate_is_idempotent(self, tmp_path: Path):
        """
        Running `migrate` twice produces byte-identical output on the second run.

        Given: a controls fixture with legacy values
        When:  migrate is run twice
        Then:  file bytes after first run == file bytes after second run

        ADR-027 D4 / #343 Decision 2: a second migrate pass on an already-migrated
        corpus must be a byte-level no-op.
        """
        fixture = _make_legacy_controls_fixture(tmp_path)
        first = _run(
            "migrate",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert first.returncode == 0, f"first migrate run must succeed; stderr=\n{first.stderr}"
        bytes_after_first = fixture.read_bytes()

        second = _run(
            "migrate",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert second.returncode == 0, f"second migrate run must succeed; stderr=\n{second.stderr}"
        bytes_after_second = fixture.read_bytes()

        assert bytes_after_second == bytes_after_first, (
            "migrate must be idempotent: a second run on an already-migrated file "
            "must produce byte-identical output"
        )

    def test_migrate_dry_run_does_not_write(self, tmp_path: Path):
        """
        `migrate --dry-run` exits 0, does NOT modify the file, and prints a summary.

        Given: a controls fixture with legacy values
        When:  migrate --dry-run is run
        Then:  exits 0; file bytes unchanged; stdout is non-empty (summary printed)

        ADR-027 D4 / #343 Decision 2: --dry-run is an observability mode that
        shows what would change without writing.
        """
        fixture = _make_legacy_controls_fixture(tmp_path)
        original_bytes = fixture.read_bytes()

        result = _run(
            "migrate",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
            "--dry-run",
        )
        assert result.returncode == 0, (
            f"migrate --dry-run must exit 0; stderr=\n{result.stderr}\nstdout=\n{result.stdout}"
        )
        assert fixture.read_bytes() == original_bytes, (
            "migrate --dry-run must NOT write the file; file was modified"
        )
        assert result.stdout.strip(), "migrate --dry-run must print a non-empty summary to stdout"

    def test_migrate_preserves_comments_and_already_pinned_sibling(self, tmp_path: Path):
        """
        After `migrate`, comments in the fixture survive and the already-pinned
        sibling entity's mapping is unchanged.

        Given: a controls fixture with comments and a pre-pinned sibling entity
        When:  migrate runs
        Then:  comment lines survive; sibling entity's pinned value is unchanged

        ADR-027 D4: "writes must preserve YAML formatting/comments."
        #343 Decision 2: migrate uses ruamel round-trip (same as add/remove/update).
        """
        fixture = _make_legacy_controls_fixture(tmp_path)
        original_text = fixture.read_text(encoding="utf-8")
        comment_lines = [ln for ln in original_text.splitlines() if ln.lstrip().startswith("#")]
        assert comment_lines, "fixture must contain comments for this test to be meaningful"

        result = _run(
            "migrate",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode == 0

        rewritten_text = fixture.read_text(encoding="utf-8")
        rewritten_comment_lines = [ln for ln in rewritten_text.splitlines() if ln.lstrip().startswith("#")]
        missing_comments = [c for c in comment_lines if c not in rewritten_comment_lines]
        assert not missing_comments, "all comment lines must survive migrate; missing:\n" + "\n".join(
            missing_comments
        )

        # Already-pinned sibling must be unchanged.
        data = _load_yaml(fixture)
        controls = {c["id"]: c for c in data["controls"]}
        assert controls["controlAlreadyPinned"]["mappings"]["mitre-atlas"] == ["AML.T0043@5.0.1"], (
            "already-pinned sibling entity must not be modified by migrate"
        )

    def test_migrate_fail_loud_on_unmappable_value(self, tmp_path: Path):
        """
        `migrate` exits non-zero with a stderr diagnostic when it encounters an
        unmappable legacy value; it must NOT silently write a partial file.

        Given: a controls fixture containing NIST value 'XY-9.9' (unknown prefix)
        When:  migrate is run
        Then:  exits non-zero AND stderr is non-empty (diagnostic printed)

        #343 fail-loud rule / mirrors #347 P4 silent-skip bug: the migrate tool
        must NEVER silently pass through a value it cannot map.
        ADR-027 D4: validation failures must surface as diagnostics, not silent skips.
        """
        fixture = _make_unmappable_controls_fixture(tmp_path)
        result = _run(
            "migrate",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode != 0, "migrate must exit non-zero when it encounters an unmappable legacy value"
        assert result.stderr.strip(), "migrate must emit a diagnostic to stderr for unmappable values (fail-loud)"

    def test_migrate_does_not_reflow_prose(self, tmp_path: Path):
        """
        `migrate` changes ONLY the mapping value, never re-wraps surrounding prose.

        Given: a fixture with a folded-scalar line far wider than ruamel's default
               80-column wrap and exactly one legacy value (GV-1.6)
        When:  migrate runs
        Then:  the output equals the original with ONLY `GV-1.6` -> `GOVERN-1.6@1.0`
               replaced; every other byte (including the long prose line) is intact

        #343: a value migration is a value-only diff. A full YAML re-emit re-folds
        folded scalars (ruamel cannot losslessly round-trip the live corpus's
        prose), so the write path must be line-anchored, not a whole-file dump.
        """
        fixture = _make_long_prose_fixture(tmp_path)
        original = fixture.read_text(encoding="utf-8")
        result = _run(
            "migrate",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
        )
        assert result.returncode == 0, f"migrate must succeed; stderr=\n{result.stderr}"
        migrated = fixture.read_text(encoding="utf-8")
        expected = original.replace("- GV-1.6", "- GOVERN-1.6@1.0")
        assert migrated == expected, (
            "migrate must produce a value-only diff (no prose re-wrap). "
            f"Got:\n{migrated!r}\nExpected:\n{expected!r}"
        )


# ===========================================================================
# 19. CLI `migrate --report-legacy` mode
# ===========================================================================


class TestCLIMigrateReportLegacy:
    """
    `migrate --report-legacy` prints a corpus inventory and exits 0 without
    modifying any file.

    ADR-027 D4 / #343 Decision 2: --report-legacy satisfies the Gap-B
    audit enabler from draft-mapping-purity-audit-mode-issue: it allows
    a maintainer to inspect the scope of the migration before running it.
    """

    def test_report_legacy_exits_zero(self, tmp_path: Path):
        """
        `migrate --report-legacy` exits 0.

        Given: a controls fixture with legacy values
        When:  migrate --report-legacy is run
        Then:  exits 0

        ADR-027 D4 / #343 Decision 2: report mode is read-only inventory.
        """
        fixture = _make_legacy_controls_fixture(tmp_path)
        result = _run(
            "migrate",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
            "--report-legacy",
        )
        assert result.returncode == 0, (
            f"migrate --report-legacy must exit 0; stderr=\n{result.stderr}\nstdout=\n{result.stdout}"
        )

    def test_report_legacy_does_not_modify_file(self, tmp_path: Path):
        """
        `migrate --report-legacy` does NOT modify the content file.

        Given: a controls fixture with legacy values
        When:  migrate --report-legacy is run
        Then:  file bytes are unchanged

        ADR-027 D4: --report-legacy is a read-only audit mode.
        """
        fixture = _make_legacy_controls_fixture(tmp_path)
        original_bytes = fixture.read_bytes()
        _run(
            "migrate",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
            "--report-legacy",
        )
        assert fixture.read_bytes() == original_bytes, "migrate --report-legacy must NOT write the file"

    def test_report_legacy_prints_inventory_counts(self, tmp_path: Path):
        """
        `migrate --report-legacy` prints a non-empty inventory to stdout.

        Given: a controls fixture with 4 legacy values across 4 frameworks
        When:  migrate --report-legacy is run
        Then:  stdout is non-empty (inventory printed)

        ADR-027 D4 / #343 Decision 2: the report must contain per-framework
        legacy vs already-pinned counts so a maintainer can assess scope.
        """
        fixture = _make_legacy_controls_fixture(tmp_path)
        result = _run(
            "migrate",
            "--content-file",
            str(fixture),
            "--frameworks-file",
            str(FRAMEWORKS_YAML),
            "--schema-file",
            str(FRAMEWORKS_SCHEMA),
            "--report-legacy",
        )
        assert result.stdout.strip(), "migrate --report-legacy must print a non-empty inventory to stdout"


# ===========================================================================
# 20. Live corpus inventory (--report-legacy on real 4 consumer YAMLs)
# ===========================================================================


# Paths to all four live consumer YAMLs (default content-file set for migrate).
_CONTENT_FILES = [
    REPO_ROOT / "risk-map" / "yaml" / "risks.yaml",
    REPO_ROOT / "risk-map" / "yaml" / "controls.yaml",
    REPO_ROOT / "risk-map" / "yaml" / "personas.yaml",
    REPO_ROOT / "risk-map" / "yaml" / "components.yaml",
]


@pytest.mark.live_corpus
class TestLiveCorpusInventory:
    """
    Run `migrate --report-legacy` against the real 4 consumer YAMLs and assert
    the corpus-scale counts and — the load-bearing guard — that the corpus is
    FULLY MIGRATED (zero legacy values remaining).

    The TOTAL line reports blocks/values across BOTH legacy and pinned classes,
    so it stays `96 blocks / 146 values` after migration; those numbers are a
    corpus-scale sanity check, not a migration-progress signal. The real
    regression guard is per-framework `legacy=0`: if anyone reintroduces an
    unpinned/off-pattern value, its framework's `legacy=` count goes positive and
    test_live_corpus_fully_migrated_no_legacy fails.

    Breakdown (verified in-worktree):
      risks:      65 blocks / 100 values
      controls:   25 blocks /  40 values
      personas:    6 blocks /   6 values
      components:  0 blocks /   0 values

    ADR-027 D4 / #343 plan §1. The tests search for numbers in the report output
    rather than matching exact whitespace, so the report format may evolve.
    """

    def test_live_corpus_report_exits_zero(self):
        """
        `migrate --report-legacy` on the real 4 consumer YAMLs exits 0.

        ADR-027 D4 / #343 plan §1: the report mode must always succeed on a
        valid corpus — it is a read-only audit, not a validation gate.
        """
        args = ["migrate", "--report-legacy"]
        for f in _CONTENT_FILES:
            args += ["--content-file", str(f)]
        args += ["--frameworks-file", str(FRAMEWORKS_YAML), "--schema-file", str(FRAMEWORKS_SCHEMA)]
        result = _run(*args)
        assert result.returncode == 0, (
            f"migrate --report-legacy on live corpus must exit 0; "
            f"stderr=\n{result.stderr}\nstdout=\n{result.stdout}"
        )

    def test_live_corpus_report_contains_total_block_count(self):
        """
        The report output contains the total framework-sub-block count: 96.

        Given: the 4 live consumer YAMLs
        When:  migrate --report-legacy is run
        Then:  the string '96' appears in the report output

        #343 plan §1 / issue body: "96 framework-sub-blocks across 4 consumer YAMLs."
        This is a corpus-scale sanity check — the TOTAL counts legacy + pinned, so
        it stays 96 after migration. The migration-completeness guard is
        test_live_corpus_fully_migrated_no_legacy.
        """
        args = ["migrate", "--report-legacy"]
        for f in _CONTENT_FILES:
            args += ["--content-file", str(f)]
        args += ["--frameworks-file", str(FRAMEWORKS_YAML), "--schema-file", str(FRAMEWORKS_SCHEMA)]
        result = _run(*args)
        assert result.returncode == 0
        combined_output = result.stdout + result.stderr
        assert "96" in combined_output, (
            f"Expected '96' (total legacy block count) in report output; got:\n{combined_output}"
        )

    def test_live_corpus_report_contains_total_value_count(self):
        """
        The report output contains the total value count: 146.

        Given: the 4 live consumer YAMLs
        When:  migrate --report-legacy is run
        Then:  the string '146' appears in the report output

        #343 plan §1 / issue body: "146 total values across 4 consumer YAMLs."
        Corpus-scale sanity check (legacy + pinned); see
        test_live_corpus_fully_migrated_no_legacy for the completeness guard.
        """
        args = ["migrate", "--report-legacy"]
        for f in _CONTENT_FILES:
            args += ["--content-file", str(f)]
        args += ["--frameworks-file", str(FRAMEWORKS_YAML), "--schema-file", str(FRAMEWORKS_SCHEMA)]
        result = _run(*args)
        assert result.returncode == 0
        combined_output = result.stdout + result.stderr
        assert "146" in combined_output, (
            f"Expected '146' (total legacy value count) in report output; got:\n{combined_output}"
        )

    def test_live_corpus_fully_migrated_no_legacy(self):
        """
        Every framework in the live corpus reports `legacy=0` — the corpus is
        fully migrated to the pinned form and stays that way.

        Given: the migrated 4 live consumer YAMLs
        When:  migrate --report-legacy is run
        Then:  no per-framework `legacy=N` line has N > 0

        #343: the load-bearing regression guard. A newly-introduced unpinned /
        off-pattern / out-of-enum value classifies as legacy, so its framework's
        `legacy=` count goes positive and this test fails — catching corpus drift
        away from the pinned form that the substring count checks cannot.
        """
        args = ["migrate", "--report-legacy"]
        for f in _CONTENT_FILES:
            args += ["--content-file", str(f)]
        args += ["--frameworks-file", str(FRAMEWORKS_YAML), "--schema-file", str(FRAMEWORKS_SCHEMA)]
        result = _run(*args)
        assert result.returncode == 0, f"report-legacy must exit 0; stderr=\n{result.stderr}"
        combined_output = result.stdout + result.stderr
        nonzero_legacy = re.findall(r"legacy=([1-9]\d*)", combined_output)
        assert not nonzero_legacy, (
            "live corpus has unmigrated (legacy) framework-mapping values — every framework "
            f"must report legacy=0. Offending legacy counts: {nonzero_legacy}\nReport:\n{combined_output}"
        )

    def test_live_corpus_report_does_not_modify_files(self):
        """
        `migrate --report-legacy` on the live corpus does not modify any file.

        Given: the 4 live consumer YAMLs
        When:  migrate --report-legacy is run
        Then:  every file's bytes are unchanged

        ADR-027 D4: --report-legacy is strictly read-only.
        """
        original_bytes = {f: f.read_bytes() for f in _CONTENT_FILES}
        args = ["migrate", "--report-legacy"]
        for f in _CONTENT_FILES:
            args += ["--content-file", str(f)]
        args += ["--frameworks-file", str(FRAMEWORKS_YAML), "--schema-file", str(FRAMEWORKS_SCHEMA)]
        _run(*args)
        for f in _CONTENT_FILES:
            assert f.read_bytes() == original_bytes[f], f"migrate --report-legacy must NOT modify {f.name}"


# ===========================================================================
# Test Summary
# ===========================================================================
#
# Total Tests: 76 (pre-#343, from #347) + 49 (new #343 tests) = 125
# - Artifacts exist:                    3
# - compose_pinned_value happy path:    8
# - compose delimiter correctness:      3
# - compose error cases:                5 (+ 3 hierarchy checks)
# - split_pinned_value:                 6
# - derive_mapping_id:                  7
# - known_versions:                     5
# - Schema cross-check:                 9
# - load_registry / defaults:           5
# - CLI add:                            6
# - CLI remove:                         3
# - CLI update (re-pin interpretation): 3
# - CLI rejection cases:                5
# - Format preservation:                3
# - migrate_legacy_value transforms:   17  [NEW — Phase 1 §14]
# - migrate_legacy_value idempotency:   5  [NEW — Phase 1 §15]
# - migrate_legacy_value fail-loud:     5  [NEW — Phase 1 §16]
# - Lookup table constants:             8  [NEW — Phase 1 §17]
# - CLI migrate (subprocess):           6  [NEW — Phase 1 §18, incl. prose-preservation]
# - CLI migrate --report-legacy:        3  [NEW — Phase 1 §19]
# - Live corpus inventory:              5  [NEW — Phase 1 §20, @live_corpus]
#
# New symbols under test (must be added to precommit/framework_mapping.py):
#   LEGACY_NIST_PREFIX_MAP, LEGACY_STRIDE_KEBAB_MAP, migrate_legacy_value
#
# New CLI subcommand under test (must be added to framework_mapping_maintainer.py):
#   migrate [--content-file FILE ...] [--frameworks-file F] [--schema-file F]
#           [--dry-run] [--report-legacy]
#
# Coverage areas (new):
# - migrate_legacy_value: all 6 frameworks, idempotency, fail-loud (4 error paths)
# - LEGACY_NIST_PREFIX_MAP: exact key/value set (4 entries)
# - LEGACY_STRIDE_KEBAB_MAP: exact key/value set (6 entries)
# - CLI migrate: happy path, idempotency, dry-run, comment preservation,
#                sibling preservation, fail-loud on unmappable value
# - CLI migrate --report-legacy: exits 0, no-write, non-empty inventory
# - Live corpus inventory: 96 blocks / 146 values count pins (#343 plan §1)
#
# Spec ambiguity noted: the `update` verb's resolution logic is not fully
# specified in ADR-027 D4a. The tests implement and test the "re-pin by
# base-ref match" interpretation (find existing entry by split_pinned_value
# base-ref == --framework-specific-ref; replace its version token). Error
# paths (nothing-to-update, ambiguous) are tested as sentinel contracts.
# The implementation may use a slightly different update semantic but must satisfy
# at minimum the round-trip (old token replaced by new token) and the two
# error paths.
