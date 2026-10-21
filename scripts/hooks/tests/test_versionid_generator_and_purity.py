#!/usr/bin/env python3
"""
Tests for the ADR-027 D2b versionId generator and purity validator.

Tooling under test:
  - scripts/hooks/precommit/versionid_generator.py
      Reads risk-map/yaml/frameworks.yaml, derives a `versionId` for every
      framework entry per D2b (`id if version is null else f"{id}@{version}"`),
      and writes the materialized value back in place, preserving non-target
      formatting / comments.

  - scripts/hooks/precommit/validate_versionid_purity.py
      Re-derives each entry's `versionId` and asserts on-disk equality
      (fails on hand-edit), charset (D2a `^[a-z0-9.@-]+$`), cross-registry
      uniqueness, and lineage well-formedness for `supersedes` /
      `priorVersions` (charset-valid, uniqueness within a list, same
      concept-id family per D2c).

Authoritative spec: docs/adr/027-framework-versioning-and-mapping-convention.md
D-section citations in each test trace the test's "why" to the ADR.

The frameworks.yaml `version` field is intentionally quoted (string), not a
YAML-coerced scalar — `version: 1.0` would parse as float 1.0 and silently
truncate to `@1` (D2b note). The generator asserts string-type before composing
and the purity validator additionally guards the same invariant.

These tests are written test-first: until the generator + validator land they
fail. The fixture-driven tests use a tmp_path-cloned frameworks.yaml so the
real registry is never mutated.
"""

from __future__ import annotations

import re
import subprocess
import sys
import textwrap
from pathlib import Path

import yaml

# Repo root = scripts/hooks/tests/<this>/../../../..
REPO_ROOT = Path(__file__).parent.parent.parent.parent
FRAMEWORKS_YAML = REPO_ROOT / "risk-map" / "yaml" / "frameworks.yaml"

GENERATOR = REPO_ROOT / "scripts" / "hooks" / "precommit" / "versionid_generator.py"
PURITY_VALIDATOR = REPO_ROOT / "scripts" / "hooks" / "precommit" / "validate_versionid_purity.py"

# D2a invariant. Mirrored from the frameworks.schema.json charset constraint.
VERSION_ID_CHARSET_RE = re.compile(r"^[a-z0-9.@-]+$")

# The current ATLAS edition, read from the registry's `version` field. The
# expected versionId below is recomputed from it by the D2b rule, so it is
# compared against the `versionId` the generator wrote (a differential, not an
# identity): hand-editing either field in the registry makes the tests fail.
ATLAS_VERSION = str(
    next(
        e
        for e in yaml.safe_load(FRAMEWORKS_YAML.read_text(encoding="utf-8"))["frameworks"]
        if e["id"] == "mitre-atlas"
    )["version"]
)
ATLAS_VERSION_ID = f"mitre-atlas@{ATLAS_VERSION}"

# Expected materialized versionId values for the 6 current registry entries (D2b).
# STRIDE has version: null → bare concept id (D2a "unversioned" leg).
EXPECTED_VERSION_IDS = {
    "mitre-atlas": ATLAS_VERSION_ID,
    "nist-ai-rmf": "nist-ai-rmf@1.0",
    "stride": "stride",
    "owasp-top10-llm": "owasp-top10-llm@2025",
    "iso-22989": "iso-22989@2022",
    "eu-ai-act": "eu-ai-act@2024",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clone_frameworks_yaml(tmp_path: Path) -> Path:
    """Copy the real frameworks.yaml into tmp_path for non-destructive tests."""
    dst = tmp_path / "frameworks.yaml"
    dst.write_text(FRAMEWORKS_YAML.read_text(encoding="utf-8"), encoding="utf-8")
    return dst


def _run(script: Path, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """
    Invoke a tool script under python3 and capture output.

    Asserts the script exists before invoking so a non-zero exit from a
    missing-file ImportError can never be mistaken for a validator rejection
    in a negative-case test. The TestToolingArtifactsExist class covers the
    existence assertion directly; this helper enforces the precondition for
    every other test.
    """
    assert script.is_file(), (
        f"required tool {script.relative_to(REPO_ROOT)} is missing — negative-case "
        "tests would otherwise pass for the wrong reason (missing script vs validator reject)"
    )
    cmd = [sys.executable, str(script), *args]
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )


def _load_frameworks(path: Path) -> dict:
    """Parse a frameworks.yaml; returns the top-level mapping."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _entry_by_id(data: dict, fw_id: str) -> dict:
    """Return the first framework entry with the given id (raises if missing)."""
    for entry in data["frameworks"]:
        if entry.get("id") == fw_id:
            return entry
    raise KeyError(fw_id)


# ===========================================================================
# Existence + CLI shape
# ===========================================================================


class TestToolingArtifactsExist:
    """Both the generator and purity validator scripts must be present at the documented paths."""

    def test_generator_script_exists(self):
        assert GENERATOR.is_file(), (
            f"versionId generator missing at {GENERATOR.relative_to(REPO_ROOT)}; "
            "ADR-027 D2b requires a pre-commit generator hook for the registry."
        )

    def test_purity_validator_script_exists(self):
        assert PURITY_VALIDATOR.is_file(), (
            f"versionId purity validator missing at {PURITY_VALIDATOR.relative_to(REPO_ROOT)}; "
            "ADR-027 D2b pairs the generator with a purity check (same class as the "
            "table/diagram generators per ADR-005/013)."
        )


# ===========================================================================
# Generator — D2b derivation rule
# ===========================================================================


class TestGeneratorDerivationRule:
    """The generator derives versionId per D2b: id alone if version is null."""

    def test_generator_writes_expected_versionids_for_all_entries(self, tmp_path: Path):
        """
        Given: a clone of the real frameworks.yaml (no pre-materialized versionId)
        When:  the generator runs with --path pointing at the clone
        Then:  every entry carries the D2b-derived versionId

        D2a: `<id>@<version>` for versioned, bare `<id>` for unversioned (STRIDE).
        """
        clone = _clone_frameworks_yaml(tmp_path)
        result = _run(GENERATOR, "--path", str(clone))
        assert result.returncode == 0, (
            f"generator must succeed; stderr=\n{result.stderr}\nstdout=\n{result.stdout}"
        )

        data = _load_frameworks(clone)
        for fw_id, expected in EXPECTED_VERSION_IDS.items():
            entry = _entry_by_id(data, fw_id)
            assert entry.get("versionId") == expected, (
                f"versionId mismatch for `{fw_id}`: expected {expected!r}, got {entry.get('versionId')!r}"
            )

    def test_generator_is_idempotent(self, tmp_path: Path):
        """
        Given: a frameworks.yaml that already carries the materialized versionIds
        When:  the generator runs a second time
        Then:  the file is byte-identical to the first-run output (no churn)

        Idempotency is mandatory for a pre-commit generator — without it, every
        unrelated commit that staged frameworks.yaml would write a diff.
        """
        clone = _clone_frameworks_yaml(tmp_path)
        first = _run(GENERATOR, "--path", str(clone))
        assert first.returncode == 0
        first_content = clone.read_text(encoding="utf-8")

        second = _run(GENERATOR, "--path", str(clone))
        assert second.returncode == 0
        second_content = clone.read_text(encoding="utf-8")

        assert second_content == first_content, (
            "generator must be idempotent on already-materialized input (diff would churn unrelated commits)"
        )

    def test_generator_overwrites_stale_versionid(self, tmp_path: Path):
        """
        Given: a frameworks.yaml with a hand-edited (stale) versionId
        When:  the generator runs
        Then:  the stale value is replaced by the D2b-derived value

        The pre-commit pairing is generator-then-purity (D2b): if the generator
        does not overwrite, the purity check fails on every otherwise-legit
        registry edit. Stale-overwrite is the contract.
        """
        clone = _clone_frameworks_yaml(tmp_path)
        # First materialize correctly so a versionId line exists to corrupt.
        first = _run(GENERATOR, "--path", str(clone))
        assert first.returncode == 0

        # Corrupt mitre-atlas by hand-editing its versionId in the text.
        text = clone.read_text(encoding="utf-8")
        corrupted = text.replace(f"versionId: {ATLAS_VERSION_ID}", "versionId: mitre-atlas@9.9.9")
        assert corrupted != text, "test fixture set-up failed: original versionId line not present"
        clone.write_text(corrupted, encoding="utf-8")

        second = _run(GENERATOR, "--path", str(clone))
        assert second.returncode == 0
        data = _load_frameworks(clone)
        assert _entry_by_id(data, "mitre-atlas")["versionId"] == ATLAS_VERSION_ID, (
            "generator must overwrite a stale versionId — that is the source of "
            "truth restoration the generator-plus-purity pattern relies on (D2b)"
        )


# ===========================================================================
# Generator — formatting and structural preservation
# ===========================================================================


class TestGeneratorPreservesStructure:
    """
    The generator must mint versionIds without churning unrelated lines.

    frameworks.yaml carries comments and a deliberate field ordering; a full
    yaml.dump round-trip would destroy both. The generator is expected to do
    a surgical insertion/update of the versionId line per entry.
    """

    def test_existing_comments_are_preserved(self, tmp_path: Path):
        """
        Given: frameworks.yaml with leading comments and field-order remarks
        When:  the generator runs
        Then:  every comment present in the original is present in the output
        """
        clone = _clone_frameworks_yaml(tmp_path)
        original = clone.read_text(encoding="utf-8")
        original_comments = [line for line in original.splitlines() if line.lstrip().startswith("#")]
        assert original_comments, "fixture sanity: frameworks.yaml has comments"

        result = _run(GENERATOR, "--path", str(clone))
        assert result.returncode == 0

        rewritten = clone.read_text(encoding="utf-8")
        rewritten_comments = [line for line in rewritten.splitlines() if line.lstrip().startswith("#")]
        missing = [c for c in original_comments if c not in rewritten_comments]
        assert not missing, "generator must preserve frameworks.yaml comments verbatim; missing:\n" + "\n".join(
            missing
        )

    def test_other_fields_unchanged_for_each_entry(self, tmp_path: Path):
        """
        Given: a clone of the real frameworks.yaml
        When:  the generator runs
        Then:  every non-versionId field on every entry retains its original value
        """
        clone = _clone_frameworks_yaml(tmp_path)
        original = _load_frameworks(clone)

        result = _run(GENERATOR, "--path", str(clone))
        assert result.returncode == 0

        rewritten = _load_frameworks(clone)
        assert len(rewritten["frameworks"]) == len(original["frameworks"])

        # Compare per-entry, dropping the generated field.
        for orig_entry, new_entry in zip(original["frameworks"], rewritten["frameworks"]):
            stripped_new = {k: v for k, v in new_entry.items() if k != "versionId"}
            # Original may not yet have versionId; strip from both to compare.
            stripped_orig = {k: v for k, v in orig_entry.items() if k != "versionId"}
            assert stripped_new == stripped_orig, (
                f"entry `{orig_entry.get('id')}` had a non-versionId field mutated"
            )


# ===========================================================================
# Generator — D2b string-type guard (no YAML-float coercion)
# ===========================================================================


class TestGeneratorStringTypeGuard:
    """
    D2b: read `version` as a string, not a YAML-coerced scalar.

    The fixture `version: 1.0` (unquoted) parses as float 1.0 in PyYAML and
    would silently truncate to versionId `<id>@1` (trailing zero lost). The
    generator must fail loudly when version is non-null and non-string.
    """

    def test_generator_rejects_yaml_float_version(self, tmp_path: Path):
        """
        Given: a synthetic frameworks.yaml with an unquoted (float) version
        When:  the generator runs
        Then:  it exits non-zero and the stderr names the offending entry
        """
        bad = tmp_path / "frameworks.yaml"
        # Note: 1.0 unquoted → PyYAML parses as float; the generator must catch this.
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: 1.0
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )

        result = _run(GENERATOR, "--path", str(bad))
        assert result.returncode != 0, (
            "generator must fail on a non-string version field (D2b string-type guard); "
            "an unquoted `version: 1.0` parses as float and would silently truncate."
        )
        assert "nist-ai-rmf" in (result.stderr + result.stdout), (
            "diagnostic must name the offending framework entry"
        )

    def test_generator_accepts_quoted_string_version(self, tmp_path: Path):
        """
        Given: a synthetic frameworks.yaml with a quoted string version
        When:  the generator runs
        Then:  it succeeds and produces the expected versionId

        Positive companion to the float-rejection test.
        """
        good = tmp_path / "frameworks.yaml"
        good.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: '1.0'
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        result = _run(GENERATOR, "--path", str(good))
        assert result.returncode == 0, f"generator must succeed on a quoted version; stderr=\n{result.stderr}"
        data = _load_frameworks(good)
        assert _entry_by_id(data, "nist-ai-rmf")["versionId"] == "nist-ai-rmf@1.0"


# ===========================================================================
# Generator — charset assertion (D2a)
# ===========================================================================


class TestGeneratorCharsetAssertion:
    """
    D2a: the composed versionId must match `^[a-z0-9.@-]+$`.

    A pathological version string ('5 0 1' with whitespace, or uppercase chars)
    would mint a charset-invalid versionId. The generator must reject before
    write so the on-disk value is always charset-clean.
    """

    def test_generator_rejects_charset_invalid_version(self, tmp_path: Path):
        """
        Given: an entry whose version string contains whitespace
        When:  the generator runs
        Then:  it exits non-zero and the stderr identifies the offending entry
        """
        bad = tmp_path / "frameworks.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: mitre-atlas
                    name: ATLAS
                    fullName: ATLAS Long
                    description: desc
                    baseUri: https://example.test
                    version: '5 0 1'
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        result = _run(GENERATOR, "--path", str(bad))
        assert result.returncode != 0, (
            "generator must reject a version that yields a charset-invalid versionId (D2a)"
        )

    def test_generator_rejects_uppercase_concept_id(self, tmp_path: Path):
        """
        Given: an entry whose `id` contains uppercase characters
        When:  the generator runs
        Then:  it exits non-zero (D2a charset is `[a-z0-9.@-]`, uppercase rejected)
        """
        bad = tmp_path / "frameworks.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: MITRE-ATLAS
                    name: ATLAS
                    fullName: ATLAS Long
                    description: desc
                    baseUri: https://example.test
                    version: '5.0.1'
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        result = _run(GENERATOR, "--path", str(bad))
        assert result.returncode != 0, "generator must reject an uppercase id (D2a charset constraint)"


# ===========================================================================
# Generator — cross-registry uniqueness (D2b)
# ===========================================================================


class TestGeneratorUniqueness:
    """
    D2b: the set of versionIds across the registry must be unique.

    Two entries that mint the same versionId are a registry error the generator
    must catch before write.
    """

    def test_generator_rejects_duplicate_versionid(self, tmp_path: Path):
        """
        Given: two synthetic entries that would mint the same versionId
        When:  the generator runs
        Then:  it exits non-zero
        """
        bad = tmp_path / "frameworks.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: dup
                    name: A
                    fullName: A
                    description: a
                    baseUri: https://example.test
                    version: '1.0'
                    applicableTo:
                      - controls
                  - id: dup
                    name: B
                    fullName: B
                    description: b
                    baseUri: https://example.test
                    version: '1.0'
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        result = _run(GENERATOR, "--path", str(bad))
        assert result.returncode != 0, "generator must reject a registry that mints duplicate versionIds (D2b)"


# ===========================================================================
# Generator — STRIDE unversioned leg (D2a, D6)
# ===========================================================================


class TestGeneratorUnversionedLeg:
    """
    D2a / D6: when `version` is null the versionId is the bare concept id.

    STRIDE is the live case; the generator's null-handling is tested via the
    real registry clone in TestGeneratorDerivationRule, but the explicit
    contract is asserted here on a minimal fixture so failure messages name
    the unversioned leg directly.
    """

    def test_null_version_yields_bare_concept_id(self, tmp_path: Path):
        good = tmp_path / "frameworks.yaml"
        good.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: stride
                    name: STRIDE
                    fullName: STRIDE Threat Model
                    description: desc
                    baseUri: https://example.test
                    version: null
                    applicableTo:
                      - risks
                """
            ),
            encoding="utf-8",
        )
        result = _run(GENERATOR, "--path", str(good))
        assert result.returncode == 0, (
            f"generator must accept version: null and mint the bare id; stderr=\n{result.stderr}"
        )
        data = _load_frameworks(good)
        assert _entry_by_id(data, "stride")["versionId"] == "stride", (
            "STRIDE's null version must yield versionId == 'stride' (D2a unversioned leg)"
        )


# ===========================================================================
# Purity validator — passes on materialized output
# ===========================================================================


class TestPurityPasses:
    """The purity validator must accept the generator's own output."""

    def test_purity_passes_after_generator_materializes(self, tmp_path: Path):
        """
        Given: a clone the generator just ran against
        When:  the purity validator runs against the same file
        Then:  exit code 0 (no hand-edit, no charset violation, no duplicate)
        """
        clone = _clone_frameworks_yaml(tmp_path)
        gen = _run(GENERATOR, "--path", str(clone))
        assert gen.returncode == 0

        check = _run(PURITY_VALIDATOR, "--path", str(clone))
        assert check.returncode == 0, (
            f"purity validator must accept the generator's own output; stderr=\n{check.stderr}"
        )


# ===========================================================================
# Purity validator — hand-edit detection
# ===========================================================================


class TestPurityDetectsHandEdit:
    """
    D2b: the purity validator's purpose is to fail commits where an on-disk
    versionId does not equal the derived value.
    """

    def test_handedited_versionid_fails_purity(self, tmp_path: Path):
        """
        Given: a frameworks.yaml whose mitre-atlas versionId was hand-edited
        When:  the purity validator runs
        Then:  exit code is non-zero and the diagnostic names the entry
        """
        clone = _clone_frameworks_yaml(tmp_path)
        gen = _run(GENERATOR, "--path", str(clone))
        assert gen.returncode == 0

        text = clone.read_text(encoding="utf-8")
        # Same corruption pattern as TestGeneratorDerivationRule.
        corrupted = text.replace(f"versionId: {ATLAS_VERSION_ID}", "versionId: mitre-atlas@9.9.9")
        assert corrupted != text
        clone.write_text(corrupted, encoding="utf-8")

        check = _run(PURITY_VALIDATOR, "--path", str(clone))
        assert check.returncode != 0, "purity validator must fail on a hand-edited versionId (D2b contract)"
        assert "mitre-atlas" in (check.stdout + check.stderr), "diagnostic must name the entry with the drift"


# ===========================================================================
# Purity validator — string-type and charset guards
# ===========================================================================


class TestPurityStringTypeGuard:
    """The purity validator must also catch the YAML-float-coercion footgun."""

    def test_purity_fails_on_float_version_even_if_versionid_present(self, tmp_path: Path):
        """
        Given: a synthetic frameworks.yaml with an unquoted float version and a
               hand-typed versionId that happens to match what naive composition
               would emit
        When:  the purity validator runs
        Then:  exit code is non-zero (the string-type guard fires before the
               equality check, so the float input is rejected regardless)
        """
        bad = tmp_path / "frameworks.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: 1.0
                    versionId: nist-ai-rmf@1
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        check = _run(PURITY_VALIDATOR, "--path", str(bad))
        assert check.returncode != 0, "purity validator must reject a non-string version field (D2b)"


class TestPurityCharsetGuard:
    """The purity validator independently asserts charset conformance (D2a)."""

    def test_purity_fails_on_charset_invalid_versionid(self, tmp_path: Path):
        """
        Given: a frameworks.yaml whose on-disk versionId contains uppercase
        When:  the purity validator runs
        Then:  exit code is non-zero
        """
        bad = tmp_path / "frameworks.yaml"
        # Hand-crafted bad versionId despite a valid id+version pair.
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: '1.0'
                    versionId: NIST-AI-RMF@1.0
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        check = _run(PURITY_VALIDATOR, "--path", str(bad))
        assert check.returncode != 0


# ===========================================================================
# Purity validator — cross-registry uniqueness
# ===========================================================================


class TestPurityUniqueness:
    """D2b uniqueness applies on read too: same constraint, second check point."""

    def test_purity_fails_on_duplicate_versionid_across_entries(self, tmp_path: Path):
        bad = tmp_path / "frameworks.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: a
                    name: A
                    fullName: A
                    description: a
                    baseUri: https://example.test
                    version: '1.0'
                    versionId: a@1.0
                    applicableTo:
                      - controls
                  - id: b
                    name: B
                    fullName: B
                    description: b
                    baseUri: https://example.test
                    version: '1.0'
                    versionId: a@1.0
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        check = _run(PURITY_VALIDATOR, "--path", str(bad))
        assert check.returncode != 0, "purity validator must reject duplicate versionIds across entries (D2b)"


# ===========================================================================
# Purity validator — supersedes / priorVersions lineage (D2c)
# ===========================================================================


class TestPuritySupersedesCharset:
    """`supersedes` is a single versionId; it must satisfy the D2a charset."""

    def test_charset_invalid_supersedes_fails(self, tmp_path: Path):
        bad = tmp_path / "frameworks.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: '1.1'
                    versionId: nist-ai-rmf@1.1
                    supersedes: NIST-AI-RMF@1.0
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        check = _run(PURITY_VALIDATOR, "--path", str(bad))
        assert check.returncode != 0


class TestPuritySupersedesFamilyConsistency:
    """`supersedes` must belong to the same concept-id family (D2b lineage rule)."""

    def test_cross_family_supersedes_fails(self, tmp_path: Path):
        bad = tmp_path / "frameworks.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: '1.1'
                    versionId: nist-ai-rmf@1.1
                    supersedes: mitre-atlas@5.0.1
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        check = _run(PURITY_VALIDATOR, "--path", str(bad))
        assert check.returncode != 0, "supersedes must reference a versionId of the same concept-id family"

    def test_same_family_supersedes_passes(self, tmp_path: Path):
        good = tmp_path / "frameworks.yaml"
        good.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: '1.1'
                    versionId: nist-ai-rmf@1.1
                    supersedes: nist-ai-rmf@1.0
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        check = _run(PURITY_VALIDATOR, "--path", str(good))
        assert check.returncode == 0, f"same-family supersedes must pass; stderr=\n{check.stderr}"


class TestPurityPriorVersionsList:
    """`priorVersions` is an array; each member is charset-valid, unique, same family."""

    def test_charset_invalid_member_fails(self, tmp_path: Path):
        bad = tmp_path / "frameworks.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: '1.1'
                    versionId: nist-ai-rmf@1.1
                    priorVersions:
                      - nist-ai-rmf@1.0
                      - NIST-AI-RMF@0.9
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        check = _run(PURITY_VALIDATOR, "--path", str(bad))
        assert check.returncode != 0

    def test_duplicate_members_fail(self, tmp_path: Path):
        bad = tmp_path / "frameworks.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: '1.2'
                    versionId: nist-ai-rmf@1.2
                    priorVersions:
                      - nist-ai-rmf@1.0
                      - nist-ai-rmf@1.0
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        check = _run(PURITY_VALIDATOR, "--path", str(bad))
        assert check.returncode != 0

    def test_cross_family_member_fails(self, tmp_path: Path):
        bad = tmp_path / "frameworks.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: '1.2'
                    versionId: nist-ai-rmf@1.2
                    priorVersions:
                      - nist-ai-rmf@1.0
                      - mitre-atlas@5.0.1
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        check = _run(PURITY_VALIDATOR, "--path", str(bad))
        assert check.returncode != 0

    def test_wellformed_prior_versions_pass(self, tmp_path: Path):
        good = tmp_path / "frameworks.yaml"
        good.write_text(
            textwrap.dedent(
                """\
                title: Frameworks
                description:
                  - test
                frameworks:
                  - id: nist-ai-rmf
                    name: NIST AI RMF
                    fullName: NIST AI RMF Long
                    description: desc
                    baseUri: https://example.test
                    version: '1.2'
                    versionId: nist-ai-rmf@1.2
                    supersedes: nist-ai-rmf@1.1
                    priorVersions:
                      - nist-ai-rmf@1.0
                      - nist-ai-rmf@1.1
                    applicableTo:
                      - controls
                """
            ),
            encoding="utf-8",
        )
        check = _run(PURITY_VALIDATOR, "--path", str(good))
        assert check.returncode == 0, f"well-formed lineage must pass; stderr=\n{check.stderr}"


# ===========================================================================
# Materialization on the real registry
# ===========================================================================


class TestMaterializedRegistry:
    """
    The on-disk frameworks.yaml must carry the materialized versionIds for all
    6 current entries once materialization lands.

    The real frameworks.yaml is updated by the versionId generator (D2b) so
    downstream consumers can read a stable on-disk field
    (D2b: "Materializing it at pre-commit (not build-only)...").
    """

    def test_real_frameworks_yaml_carries_expected_versionids(self):
        data = yaml.safe_load(FRAMEWORKS_YAML.read_text(encoding="utf-8"))
        for fw_id, expected in EXPECTED_VERSION_IDS.items():
            entry = _entry_by_id(data, fw_id)
            assert entry.get("versionId") == expected, (
                f"frameworks.yaml entry `{fw_id}` must carry materialized "
                f"versionId {expected!r}; got {entry.get('versionId')!r}"
            )

    def test_real_frameworks_yaml_passes_purity(self):
        result = _run(PURITY_VALIDATOR, "--path", str(FRAMEWORKS_YAML))
        assert result.returncode == 0, (
            f"the live frameworks.yaml must pass the purity validator (D2b "
            f"materialization invariant); stderr=\n{result.stderr}"
        )

    def test_every_materialized_versionid_matches_charset(self):
        """Belt-and-suspenders: every minted versionId conforms to D2a."""
        data = yaml.safe_load(FRAMEWORKS_YAML.read_text(encoding="utf-8"))
        for entry in data["frameworks"]:
            vid = entry.get("versionId")
            assert vid, f"entry `{entry.get('id')}` missing materialized versionId"
            assert VERSION_ID_CHARSET_RE.match(vid), (
                f"entry `{entry.get('id')}` versionId {vid!r} violates D2a charset"
            )

    def test_real_frameworks_yaml_passes_schema_validation(self):
        """
        The materialized frameworks.yaml must validate against the
        schema. The schema added `versionId` as an optional string with the
        D2a charset constraint; the generator fills it. A schema break here would
        mean the optional field's pattern and the materialization disagree.

        Uses `check-jsonschema` via subprocess (same surface the pre-commit
        framework uses) because frameworks.schema.json carries cross-schema
        $refs into riskmap.schema.json that require a base-uri to resolve.
        """
        result = subprocess.run(
            [
                "check-jsonschema",
                "--schemafile",
                "risk-map/schemas/frameworks.schema.json",
                "--base-uri",
                "file://./risk-map/schemas/",
                "risk-map/yaml/frameworks.yaml",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"check-jsonschema rejected the materialized frameworks.yaml:\n"
            f"stdout=\n{result.stdout}\nstderr=\n{result.stderr}"
        )


# ===========================================================================
# Pre-commit framework wiring — config presence + trigger
# ===========================================================================

CONFIG_PATH = REPO_ROOT / ".pre-commit-config.yaml"

GENERATOR_HOOK_ID = "regenerate-frameworks-versionid"
PURITY_HOOK_ID = "validate-frameworks-versionid-purity"


def _load_config() -> dict:
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))


def _all_hooks() -> list[dict]:
    config = _load_config()
    hooks: list[dict] = []
    for repo in config.get("repos", []):
        hooks.extend(repo.get("hooks", []))
    return hooks


def _hook_by_id(hook_id: str) -> dict | None:
    matching = [h for h in _all_hooks() if h.get("id") == hook_id]
    if not matching:
        return None
    assert len(matching) == 1, f"multiple hooks share id `{hook_id}`"
    return matching[0]


class TestPreCommitConfigWiring:
    """Both hooks must be wired in `.pre-commit-config.yaml` with correct trigger."""

    def test_generator_hook_declared(self):
        hook = _hook_by_id(GENERATOR_HOOK_ID)
        assert hook is not None, (
            f"hook id `{GENERATOR_HOOK_ID}` missing from .pre-commit-config.yaml; "
            "ADR-027 D2b wires the generator + purity pair into pre-commit."
        )
        assert "versionid_generator.py" in hook.get("entry", ""), (
            f"hook `{GENERATOR_HOOK_ID}` entry must invoke versionid_generator.py"
        )

    def test_purity_hook_declared(self):
        hook = _hook_by_id(PURITY_HOOK_ID)
        assert hook is not None, f"hook id `{PURITY_HOOK_ID}` missing from .pre-commit-config.yaml"
        assert "validate_versionid_purity.py" in hook.get("entry", ""), (
            f"hook `{PURITY_HOOK_ID}` entry must invoke validate_versionid_purity.py"
        )

    def test_generator_triggers_on_frameworks_yaml(self):
        """The scope memo binds the trigger regex to frameworks.yaml."""
        hook = _hook_by_id(GENERATOR_HOOK_ID)
        assert hook is not None
        files = hook.get("files", "")
        assert re.search(files, "risk-map/yaml/frameworks.yaml"), (
            f"`{GENERATOR_HOOK_ID}` must match risk-map/yaml/frameworks.yaml; got files={files!r}"
        )

    def test_purity_triggers_on_frameworks_yaml(self):
        hook = _hook_by_id(PURITY_HOOK_ID)
        assert hook is not None
        files = hook.get("files", "")
        assert re.search(files, "risk-map/yaml/frameworks.yaml"), (
            f"`{PURITY_HOOK_ID}` must match risk-map/yaml/frameworks.yaml; got files={files!r}"
        )

    def test_generator_runs_before_purity(self):
        """
        Generator-plus-purity pattern (D2b): the generator materializes; the
        purity check guards. Declaration order in the config must put the
        generator first so a fresh edit is materialized and then checked in
        the same hook run.
        """
        config = _load_config()
        order: list[str] = []
        for repo in config.get("repos", []):
            for hook in repo.get("hooks", []):
                hid = hook.get("id")
                if hid in (GENERATOR_HOOK_ID, PURITY_HOOK_ID):
                    order.append(hid)
        assert order == [GENERATOR_HOOK_ID, PURITY_HOOK_ID], (
            f"generator must be declared before purity validator; got order={order}"
        )


# ===========================================================================
# Item 2 — generator regex tolerance: comment and bare-version forms
# ===========================================================================
# These tests import the compiled regex objects directly and assert tolerance
# for inline trailing comments (_ID_LINE_RE) and bare/null version lines
# (_VERSION_LINE_RE). The cases that fail until the regexes are widened are
# noted in their docstrings.


from precommit.versionid_generator import _ID_LINE_RE, _VERSION_LINE_RE  # noqa: E402


class TestIdLineReCommentTolerance:
    """
    _ID_LINE_RE must tolerate an inline trailing `#`-comment after the value.

    The real frameworks.yaml entries may carry inline comments on any line.
    Without comment tolerance the generator's _partition_entries() silently
    fails to recognise the `- id:` boundary and the entry is never rewritten.

    D2b: the surgical text-level update relies on _ID_LINE_RE to locate entry
    boundaries; a comment-bearing `- id:` line must be treated as a boundary.
    """

    def test_id_line_re_matches_id_with_trailing_comment(self):
        """
        Given: a `- id:` line with a trailing inline comment
        When:  _ID_LINE_RE.match() is called
        Then:  match is not None AND group('value') is the id without the comment

        D2b: a comment after the value must not be captured into the 'value'
        group; the boundary detection must see `mitre-atlas` not
        `mitre-atlas  # note`.

        This test fails until _ID_LINE_RE is widened to allow a trailing
        inline comment after the value.
        """
        line = "    - id: mitre-atlas  # note\n"
        m = _ID_LINE_RE.match(line)
        assert m is not None, (
            "_ID_LINE_RE must match a `- id:` line with a trailing inline comment "
            "without capturing the comment into the 'value' group."
        )
        assert m.group("value") == "mitre-atlas", (
            f"group('value') must capture only the id token, not the trailing comment; got {m.group('value')!r}"
        )

    def test_id_line_re_still_matches_plain_id_line(self):
        """
        Given: a plain `- id:` line with no comment
        When:  _ID_LINE_RE.match() is called
        Then:  match is not None AND group('value') == 'mitre-atlas'

        Regression guard: the existing plain form must keep matching after the
        regex is widened.
        """
        line = "    - id: mitre-atlas\n"
        m = _ID_LINE_RE.match(line)
        assert m is not None, "_ID_LINE_RE must still match a plain `- id:` line"
        assert m.group("value") == "mitre-atlas"

    def test_id_line_re_does_not_match_unrelated_keys(self):
        """
        Given: lines that are NOT `- id:` entry boundaries
        When:  _ID_LINE_RE.match() is called on each
        Then:  all matches return None (no false positives)

        Non-matching guard: the widened regex must not over-match YAML keys
        that happen to start with `-` or contain `id:` in another context.
        """
        non_matching = [
            "    title: Frameworks\n",
            "    version: '5.0.1'\n",
            "    # this is a comment line\n",
            "    - AML.T0020@5.0.1\n",  # list item, not an `id:` mapping
        ]
        for line in non_matching:
            assert _ID_LINE_RE.match(line) is None, (
                f"_ID_LINE_RE must NOT match {line!r} — only `- id: <value>` lines are boundaries"
            )


class TestVersionLineReBareTolerance:
    """
    _VERSION_LINE_RE must match a bare `version:` line (no value after the colon).

    A bare `version:` — equivalent to `version: null` in block-scalar YAML —
    is a legal way to represent an unversioned framework. The generator must
    still locate the `version:` line in an entry so it can insert `versionId:`
    immediately after it.

    D2b: _rewrite_entry inserts the versionId line after the version line; if
    _VERSION_LINE_RE does not match a bare form, the insert is skipped and the
    purity validator later fails on a missing versionId.
    """

    def test_version_line_re_matches_bare_version(self):
        """
        Given: a bare `version:` line (no value, representing null/empty)
        When:  _VERSION_LINE_RE.match() is called
        Then:  match is not None AND group('indent') == '    '

        D2b: the generator must locate a bare `version:` line to determine where
        to insert `versionId:`. This test fails until _VERSION_LINE_RE is widened
        to accept a `version:` line with no value after the colon.
        """
        line = "    version:\n"
        m = _VERSION_LINE_RE.match(line)
        assert m is not None, (
            "_VERSION_LINE_RE must match a bare `version:` line (no value after colon) "
            "so the generator can still locate the insertion point for versionId."
        )
        assert m.group("indent") == "    ", (
            f"group('indent') must be the leading whitespace; got {m.group('indent')!r}"
        )

    def test_version_line_re_matches_quoted_value(self):
        """
        Given: a normal `version: '5.0.1'` line
        When:  _VERSION_LINE_RE.match() is called
        Then:  match is not None AND group('indent') == '    '

        Regression guard: the existing form with a quoted string value must
        keep matching after the regex is widened.
        """
        line = "    version: '5.0.1'\n"
        m = _VERSION_LINE_RE.match(line)
        assert m is not None, "_VERSION_LINE_RE must still match a normal version line"
        assert m.group("indent") == "    "

    def test_version_line_re_matches_version_with_comment(self):
        """
        Given: a `version:` line with a trailing inline comment
        When:  _VERSION_LINE_RE.match() is called
        Then:  match is not None

        This already passes because the `.*` tail swallows the comment text after
        the value. It is included as a regression guard so future narrowing of
        the regex does not accidentally break comment-bearing version lines.
        D2b: no captured group for value, only 'indent'; comments are irrelevant.
        """
        line = "    version: '1.0'  # note\n"
        m = _VERSION_LINE_RE.match(line)
        assert m is not None, (
            "_VERSION_LINE_RE must match a version line with a trailing comment "
            "(the `.*` tail swallows the comment — this test serves as a regression guard)"
        )

    def test_version_line_re_does_not_match_versionid_lines(self):
        """
        Given: a `versionId:` line (a generated field, not the source `version:` field)
        When:  _VERSION_LINE_RE.match() is called
        Then:  match is None

        Non-matching guard: _VERSION_LINE_RE must NOT match `versionId:` lines;
        _VERSIONID_LINE_RE handles those. Over-matching `versionId:` would cause
        the generator to insert a duplicate versionId line below itself.
        """
        non_matching = [
            "    versionId: mitre-atlas@5.0.1\n",
            "    title: x\n",
            "    description: some text\n",
        ]
        for line in non_matching:
            assert _VERSION_LINE_RE.match(line) is None, f"_VERSION_LINE_RE must NOT match {line!r}"


# ===========================================================================
# Item 3 — _validate_registry_uniqueness contract lock (D2b)
# ===========================================================================
# This test does NOT test that the dead guard exists — it locks the contract
# that the function enforces after the guard is removed. It exercises the
# real input shape: list[tuple[str, str]].


from precommit.validate_versionid_purity import _validate_registry_uniqueness  # noqa: E402


class TestValidateRegistryUniquenessContractLock:
    """
    _validate_registry_uniqueness contract lock: duplicates are flagged,
    unique sets pass cleanly — exercised with the real input type
    list[tuple[str, str]].

    D2b: the set of materialized versionIds across the registry must be distinct.

    This class is a NO-BEHAVIOR-CHANGE lock. The production fix removes the dead
    guard `if vid is None: continue` (the input tuples always carry a materialized
    non-None string vid — the caller only appends tuples when on_disk is not None).
    The contract — duplicates flagged, uniques pass — must hold before AND after
    the dead-guard removal.
    """

    def test_duplicate_versionid_adds_error(self):
        """
        Given: two tuples sharing the same versionId string
        When:  _validate_registry_uniqueness is called with errors=[]
        Then:  errors gains exactly one 'duplicate versionId' message

        D2b: duplicate versionIds across entries are a registry error.
        This contract must continue to hold after the dead-guard removal.
        """
        errors: list[str] = []
        _validate_registry_uniqueness(
            [("fw-a", "fw-a@1.0"), ("fw-b", "fw-a@1.0")],
            errors,
        )
        assert len(errors) == 1, f"Expected exactly one duplicate error; got {errors!r}"
        assert "duplicate" in errors[0].lower() or "fw-a@1.0" in errors[0], (
            f"Error message must reference the duplicate versionId; got {errors[0]!r}"
        )

    def test_all_unique_versionids_no_error(self):
        """
        Given: three tuples each with a distinct versionId string
        When:  _validate_registry_uniqueness is called with errors=[]
        Then:  errors stays empty

        D2b: unique versionIds must not produce any error.
        This contract must continue to hold after the dead-guard removal.
        """
        errors: list[str] = []
        _validate_registry_uniqueness(
            [
                ("mitre-atlas", "mitre-atlas@5.0.1"),
                ("nist-ai-rmf", "nist-ai-rmf@1.0"),
                ("stride", "stride"),
            ],
            errors,
        )
        assert errors == [], f"No errors expected for all-unique versionIds; got {errors!r}"

    def test_multiple_duplicates_each_flagged(self):
        """
        Given: two separate duplicate pairs
        When:  _validate_registry_uniqueness is called
        Then:  two duplicate-error messages appear (one per duplicate versionId)

        D2b: each distinct duplicate versionId must produce a separate error message
        so the contributor knows all the affected entries, not just the first.
        """
        errors: list[str] = []
        _validate_registry_uniqueness(
            [
                ("fw-a", "dup-one@1.0"),
                ("fw-b", "dup-one@1.0"),
                ("fw-c", "dup-two@2.0"),
                ("fw-d", "dup-two@2.0"),
            ],
            errors,
        )
        assert len(errors) == 2, (
            f"Expected two duplicate errors (one per distinct duplicate versionId); got {errors!r}"
        )
