#!/usr/bin/env python3
"""
Tests for scripts/hooks/precommit/validate_eval_pairing.py.

ADR-033 D6/D8 and ADR-031 D6 require every shipped authoring surface to carry
a portable eval alongside it:
  - `scripts/agents/<name>.md`      -> `scripts/agents-evals/<name>/evals.json`
  - `scripts/skills/<name>/`        -> `scripts/skills/<name>/evals/evals.json`

Nothing currently enforces this pairing (no hook, no CI check). PR #434
shipped an agent with no eval, caught only by a human reviewer. This module
is the corpus-completeness validator that closes that gap: given the two
authoring surfaces on disk, does every entry have its required eval sibling.

This test file was authored before `scripts/hooks/precommit/validate_eval_pairing.py`
existed, as the behavioral spec an implementation step then built against
and confirmed as-is (no API changes were needed).

Public API this module provides:

    - `HOOK_NAME = "validate-eval-pairing"`
    - `EXEMPT_AGENT_NAMES: frozenset[str]` — the 6 agents grandfathered in
      before the eval requirement existed: architect, code-reviewer,
      content-reviewer, issue-response-reviewer, swe, testing. Skills have no
      equivalent exemption set — every skill on `main` already ships an eval.
    - `Violation` frozen dataclass: `surface` ("agent" | "skill"), `name`
      (the agent/skill identifier), `path` (the filesystem path the finding
      is anchored to — the expected-but-missing eval path for a "missing"
      finding, or the eval path that unexpectedly exists for a "stale
      exemption" finding), `message` (human-readable, actionable text).
    - `discover_shipped_agents(root: Path) -> list[str]` — names of
      top-level `scripts/agents/<name>.md` files (stem only, no nested
      files).
    - `discover_shipped_skills(root: Path) -> list[str]` — names of
      `scripts/skills/<name>/` directories that contain a `SKILL.md` (a
      stray non-skill file directly under `scripts/skills/`, e.g. the real
      corpus's `README.md`, is not a skill and must not be treated as one).
    - `find_pairing_violations(root: Path) -> list[Violation]` — the
      corpus-completeness check. Self-scanning: it walks `root` itself
      (mirroring `discover_neutral_surface_files` in validate_neutrality.py)
      rather than taking file arguments, and it collects every violation in
      one pass rather than stopping at the first (matching this repo's
      established pattern in both validate_neutrality.py's `main()`, which
      accumulates `all_violations` across every discovered file, and
      validate_control_risk_references.py's `compare_control_maps()`, which
      accumulates every mismatch into one `errors` list).
    - `format_violation(violation: Violation) -> str` — one rendered line
      for stderr/CLI output, prefixed with `HOOK_NAME`.
    - `main(argv: list[str]) -> int` — CLI entry point. This validator takes
      no file arguments at all (it is a corpus-completeness check, not a
      per-file scanner), so it always
      self-discovers from the current working directory; `argv` is accepted
      only for shape-consistency with the other two precommit validators'
      `main(argv: list[str]) -> int` signature. Returns 0 if no violations,
      else 1.

Two distinguishable failure classes, by design:
  - "missing eval": a shipped agent (not in EXEMPT_AGENT_NAMES) or a shipped
    skill (no exemption ever applies) has no matching eval file. Fix: add
    the eval.
  - "stale exemption": a name in EXEMPT_AGENT_NAMES already has an eval on
    disk. Fix: remove the name from the exemption set, not add an eval (it
    already has one). This can only happen on the agent surface; skills have
    no exemption set to go stale.
A maintainer reading a failure must be able to tell which of the two applies
without reading the validator's source, so this suite asserts the two
message classes are lexically distinguishable (a "missing" message never
also reads as a stale-exemption message and vice versa), not just that *a*
violation exists.

Structural analog: this validator's discovery step (walk `scripts/agents/`
and `scripts/skills/` on disk to build the "what should have an eval" set)
is modeled on `discover_neutral_surface_files` in validate_neutrality.py —
same filesystem-walk shape, same tolerance for an absent/empty subtree, same
`Violation` dataclass + `format_violation` + `main(argv) -> int` CLI
convention (all in the `precommit/` package, unlike the older top-level
`scripts/hooks/validate_control_risk_references.py`). The specific
"does-every-X-have-a-matching-Y" comparison semantics — collect every
mismatch in one pass, never fail fast — mirrors
validate_control_risk_references.py's `compare_control_maps()`, which is the
closer analog for that part of the behavior even though its inputs are two
parsed YAML dicts rather than a filesystem walk. This suite follows the
filesystem/dataclass shape of the neutrality checker since the pairing check
is fundamentally about directory/file presence, not YAML field
cross-referencing.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "precommit"))

import validate_eval_pairing  # noqa: E402
from validate_eval_pairing import (  # noqa: E402
    EXEMPT_AGENT_NAMES,
    discover_shipped_agents,
    discover_shipped_skills,
    find_pairing_violations,
    format_violation,
    main,
)


def _write_agent(tmp_path: Path, name: str, content: str = "# Example Agent\n\nBody.\n") -> Path:
    """Write scripts/agents/<name>.md under tmp_path and return its path."""
    agents_dir = tmp_path / "scripts" / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    path = agents_dir / f"{name}.md"
    path.write_text(content, encoding="utf-8")
    return path


def _write_agent_eval(tmp_path: Path, agent_name: str, content: str = '{"cases": []}\n') -> Path:
    """Write scripts/agents-evals/<agent_name>/evals.json under tmp_path and return its path."""
    path = tmp_path / "scripts" / "agents-evals" / agent_name / "evals.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_skill(tmp_path: Path, name: str, content: str = "---\nname: x\ndescription: y\n---\nBody.\n") -> Path:
    """Write scripts/skills/<name>/SKILL.md under tmp_path and return the skill directory path."""
    skill_dir = tmp_path / "scripts" / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")
    return skill_dir


def _write_skill_eval(tmp_path: Path, skill_name: str, content: str = '{"cases": []}\n') -> Path:
    """Write scripts/skills/<skill_name>/evals/evals.json under tmp_path and return its path."""
    path = tmp_path / "scripts" / "skills" / skill_name / "evals" / "evals.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestExemptAgentNamesRegressionGuard:
    """
    Cheap regression guard on the exemption set itself (mirrors
    TestFrameworkAllowlist.test_allowlist_terms_are_present_in_the_data_module
    in test_validate_neutrality.py — the one test in that suite that reaches
    into a fixed vocabulary and locks its exact membership).
    """

    def test_exempt_agent_names_matches_the_six_grandfathered_agents(self):
        """
        Given: The EXEMPT_AGENT_NAMES set
        When: its membership is inspected
        Then: It contains exactly the 6 agents that shipped before the eval
              requirement existed, no more, no fewer

        A silent drift here (someone adding a 7th exemption instead of
        shipping an eval, or removing one of the 6 without adding its eval)
        is exactly the kind of governance regression this validator exists
        to prevent, so the exemption set itself is locked.
        """
        assert EXEMPT_AGENT_NAMES == frozenset(
            {
                "architect",
                "code-reviewer",
                "content-reviewer",
                "issue-response-reviewer",
                "swe",
                "testing",
            }
        )


class TestAgentEvalPairingPasses:
    """An agent with a matching eval directory passes (case 1)."""

    def test_agent_with_matching_eval_produces_no_violation_for_that_agent(self, tmp_path):
        """
        Given: scripts/agents/example-agent.md and a matching
               scripts/agents-evals/example-agent/evals.json
        When: find_pairing_violations scans the fixture root
        Then: No violation names "example-agent"
        """
        _write_agent(tmp_path, "example-agent")
        _write_agent_eval(tmp_path, "example-agent")

        violations = find_pairing_violations(tmp_path)

        assert all(v.name != "example-agent" for v in violations)

    def test_clean_single_agent_corpus_returns_empty_list_not_none(self, tmp_path):
        """
        Given: A fixture root with exactly one agent and its matching eval
        When: find_pairing_violations scans the fixture root
        Then: It returns [] (an empty list), not None or another falsy value

        Mirrors test_clean_file_returns_empty_list_not_none in
        test_validate_neutrality.py: callers rely on list semantics
        (`len`, iteration), not just truthiness.
        """
        _write_agent(tmp_path, "example-agent")
        _write_agent_eval(tmp_path, "example-agent")

        violations = find_pairing_violations(tmp_path)

        assert violations == []
        assert isinstance(violations, list)


class TestAgentEvalPairingMissing:
    """An agent with no eval, not in the exemption set, fails (case 2)."""

    def test_non_exempt_agent_with_no_eval_produces_a_missing_violation(self, tmp_path):
        """
        Given: scripts/agents/example-agent.md with no scripts/agents-evals/
               tree at all for it, and "example-agent" is not in
               EXEMPT_AGENT_NAMES
        When: find_pairing_violations scans the fixture root
        Then: Exactly one violation names "example-agent", on the "agent"
              surface, actionable enough to name both the agent and what is
              missing
        """
        assert "example-agent" not in EXEMPT_AGENT_NAMES
        _write_agent(tmp_path, "example-agent")

        violations = find_pairing_violations(tmp_path)

        matches = [v for v in violations if v.name == "example-agent"]
        assert len(matches) == 1
        violation = matches[0]
        assert violation.surface == "agent"
        assert "example-agent" in violation.message
        assert "missing" in violation.message.lower() or "no eval" in violation.message.lower()

    def test_missing_violation_path_names_the_expected_eval_location(self, tmp_path):
        """
        Given: A non-exempt agent with no eval
        When: find_pairing_violations scans the fixture root
        Then: The violation's path points at the expected (absent)
              scripts/agents-evals/<name>/evals.json location, so a
              maintainer can act on it without reading the validator source
        """
        _write_agent(tmp_path, "example-agent")

        violations = find_pairing_violations(tmp_path)

        matches = [v for v in violations if v.name == "example-agent"]
        assert len(matches) == 1
        expected_path = tmp_path / "scripts" / "agents-evals" / "example-agent" / "evals.json"
        assert matches[0].path == expected_path


class TestExemptAgentGrandfathered:
    """An exempted agent with no eval directory passes (case 3)."""

    @pytest.mark.parametrize("exempt_name", sorted(EXEMPT_AGENT_NAMES) if EXEMPT_AGENT_NAMES else [])
    def test_exempt_agent_with_no_eval_produces_no_violation(self, tmp_path, exempt_name):
        """
        Given: A shipped agent whose name is one of the 6 grandfathered
               exemptions, with no matching eval directory
        When: find_pairing_violations scans the fixture root
        Then: No violation names that agent

        Parametrized across all 6 real exemption names (not just one) since
        the exemption set is a fixed enumeration, not a pattern — each entry
        is independently load-bearing.
        """
        _write_agent(tmp_path, exempt_name)

        violations = find_pairing_violations(tmp_path)

        assert all(v.name != exempt_name for v in violations)


class TestStaleExemption:
    """An exempted agent that already has an eval is a stale-exemption failure (case 4)."""

    @pytest.mark.parametrize("exempt_name", sorted(EXEMPT_AGENT_NAMES) if EXEMPT_AGENT_NAMES else [])
    def test_exempt_agent_with_unexpected_eval_produces_a_stale_exemption_violation(self, tmp_path, exempt_name):
        """
        Given: A shipped agent whose name is in EXEMPT_AGENT_NAMES, which
               unexpectedly already has a matching eval on disk
        When: find_pairing_violations scans the fixture root
        Then: Exactly one violation names that agent, distinguishable from
              the "missing eval" message class (a maintainer must be able to
              tell "remove the exemption" from "add the eval" without
              reading source)
        """
        _write_agent(tmp_path, exempt_name)
        _write_agent_eval(tmp_path, exempt_name)

        violations = find_pairing_violations(tmp_path)

        matches = [v for v in violations if v.name == exempt_name]
        assert len(matches) == 1
        violation = matches[0]
        assert violation.surface == "agent"
        assert "stale exemption" in violation.message.lower() or "stale" in violation.message.lower()
        # Distinguishable from the "missing eval" wording used in case 2/4 tests above.
        assert "missing" not in violation.message.lower()

    def test_stale_exemption_message_differs_from_missing_message_for_the_same_agent_name(self, tmp_path):
        """
        Given: Two separate fixture roots for the same exempt agent name —
               one where it has no eval (grandfathered pass) and one where
               it unexpectedly has an eval (stale exemption failure)
        When: find_pairing_violations scans each root
        Then: The stale-exemption root produces a violation whose message is
              lexically distinct from what a "missing eval" violation for a
              non-exempt agent of the same name would read as — proving the
              two failure classes are not rendered with interchangeable text

        This directly covers the task's "distinguishable failure message"
        requirement: a maintainer fixing this must be able to tell which
        remedy applies (add an eval vs. remove the exemption entry) from the
        message text alone.
        """
        exempt_name = next(iter(EXEMPT_AGENT_NAMES))

        stale_root = tmp_path / "stale"
        _write_agent(stale_root, exempt_name)
        _write_agent_eval(stale_root, exempt_name)
        stale_violations = [v for v in find_pairing_violations(stale_root) if v.name == exempt_name]

        missing_root = tmp_path / "missing"
        # Use a synthetic non-exempt name sharing no exemption ambiguity, so this
        # arm exercises the "missing eval" message text in isolation.
        _write_agent(missing_root, "non-exempt-example")
        missing_violations = [v for v in find_pairing_violations(missing_root) if v.name == "non-exempt-example"]

        assert len(stale_violations) == 1
        assert len(missing_violations) == 1
        assert stale_violations[0].message != missing_violations[0].message
        assert "stale" in stale_violations[0].message.lower()
        assert "missing" not in stale_violations[0].message.lower()
        assert "stale" not in missing_violations[0].message.lower()


class TestSkillEvalPairingPasses:
    """A skill with a matching evals/evals.json passes (case 5)."""

    def test_skill_with_matching_eval_produces_no_violation_for_that_skill(self, tmp_path):
        """
        Given: scripts/skills/example-skill/SKILL.md and a matching
               scripts/skills/example-skill/evals/evals.json
        When: find_pairing_violations scans the fixture root
        Then: No violation names "example-skill"
        """
        _write_skill(tmp_path, "example-skill")
        _write_skill_eval(tmp_path, "example-skill")

        violations = find_pairing_violations(tmp_path)

        assert all(v.name != "example-skill" for v in violations)


class TestSkillEvalPairingMissing:
    """A skill with no evals/evals.json fails, unconditionally (case 6)."""

    def test_skill_with_no_eval_produces_a_missing_violation(self, tmp_path):
        """
        Given: scripts/skills/example-skill/SKILL.md with no evals/ subdirectory
        When: find_pairing_violations scans the fixture root
        Then: Exactly one violation names "example-skill" on the "skill"
              surface — skills have no exemption set, so this is unconditional
        """
        _write_skill(tmp_path, "example-skill")

        violations = find_pairing_violations(tmp_path)

        matches = [v for v in violations if v.name == "example-skill"]
        assert len(matches) == 1
        violation = matches[0]
        assert violation.surface == "skill"
        assert "example-skill" in violation.message
        assert "missing" in violation.message.lower() or "no eval" in violation.message.lower()

    def test_skill_named_like_an_exempt_agent_still_requires_its_own_eval(self, tmp_path):
        """
        Given: A skill directory sharing its name with one of the 6
               agent-surface exemptions (e.g. "architect"), with no
               evals/evals.json
        When: find_pairing_violations scans the fixture root
        Then: A "skill" surface violation is still produced for that name —
              the agent-only exemption set must not leak across surfaces

        Guards against an implementation bug where EXEMPT_AGENT_NAMES is
        checked without also gating on `surface == "agent"`.
        """
        exempt_name = next(iter(EXEMPT_AGENT_NAMES))
        _write_skill(tmp_path, exempt_name)

        violations = find_pairing_violations(tmp_path)

        matches = [v for v in violations if v.name == exempt_name and v.surface == "skill"]
        assert len(matches) == 1

    def test_non_skill_file_directly_under_skills_root_is_not_treated_as_a_skill(self, tmp_path):
        """
        Given: A plain file (e.g. README.md, matching the real corpus's
               scripts/skills/README.md) directly under scripts/skills/,
               alongside one real skill with a matching eval
        When: find_pairing_violations scans the fixture root
        Then: No violation is produced for "README" or "README.md" — a
              stray non-skill file must not be misdiscovered as an unpaired
              skill
        """
        skills_dir = tmp_path / "scripts" / "skills"
        skills_dir.mkdir(parents=True, exist_ok=True)
        (skills_dir / "README.md").write_text("# Skills\n\nIndex of skills.\n", encoding="utf-8")
        _write_skill(tmp_path, "example-skill")
        _write_skill_eval(tmp_path, "example-skill")

        violations = find_pairing_violations(tmp_path)

        assert all("README" not in v.name for v in violations)


class TestMultipleViolationsCollectedInOneRun:
    """
    The validator collects every violation in one pass rather than stopping
    at the first (case 7).

    Confirmed against this repo's established pattern: both
    validate_neutrality.py's `main()` (accumulates `all_violations` across
    every discovered file before reporting any of them) and
    validate_control_risk_references.py's `compare_control_maps()`
    (accumulates every mismatch into one `errors` list, e.g.
    test_compare_multiple_errors_returns_all /
    test_end_to_end_catches_universal_violations) collect-all-then-report;
    neither validator in this repo fails fast. This validator matches that
    established pattern.
    """

    def test_mixed_corpus_reports_every_failure_not_just_the_first(self, tmp_path):
        """
        Given: A fixture corpus mixing all four agent-side outcomes (clean
               pass, non-exempt missing, exempt grandfathered pass, exempt
               stale) and both skill-side outcomes (clean pass, missing) in
               one run
        When: find_pairing_violations scans the fixture root once
        Then: All 3 expected violations are present in a single returned
              list — a maintainer does not have to re-run the validator 3
              times to discover all 3 problems
        """
        exempt_pass_name = "architect"
        exempt_stale_name = "swe"
        assert exempt_pass_name in EXEMPT_AGENT_NAMES
        assert exempt_stale_name in EXEMPT_AGENT_NAMES

        # Agent surface: alpha passes, beta is missing, architect is grandfathered
        # (passes), swe is a stale exemption (fails).
        _write_agent(tmp_path, "alpha")
        _write_agent_eval(tmp_path, "alpha")
        _write_agent(tmp_path, "beta")
        _write_agent(tmp_path, exempt_pass_name)
        _write_agent(tmp_path, exempt_stale_name)
        _write_agent_eval(tmp_path, exempt_stale_name)

        # Skill surface: gamma passes, delta is missing.
        _write_skill(tmp_path, "gamma")
        _write_skill_eval(tmp_path, "gamma")
        _write_skill(tmp_path, "delta")

        violations = find_pairing_violations(tmp_path)

        flagged_names = {v.name for v in violations}
        assert flagged_names == {"beta", exempt_stale_name, "delta"}
        assert len(violations) == 3, f"expected exactly 3 violations, got {len(violations)}: {violations}"

        by_name = {v.name: v for v in violations}
        beta_msg = by_name["beta"].message.lower()
        assert "missing" in beta_msg or "no eval" in beta_msg
        assert "stale" in by_name[exempt_stale_name].message.lower()
        delta_msg = by_name["delta"].message.lower()
        assert "missing" in delta_msg or "no eval" in delta_msg
        assert by_name["delta"].surface == "skill"


class TestAbsenceTolerance:
    """
    An absent/optional tree does not crash the validator (case 8).

    Mirrors the tolerance documented and locked for
    `discover_neutral_surface_files` in validate_neutrality.py ("Either
    subtree may be empty (or absent) without error" —
    test_absent_skills_subtree_contributes_nothing_without_erroring /
    test_absent_agents_evals_subtree_contributes_nothing_without_erroring).
    """

    def test_absent_agents_evals_tree_does_not_crash_and_flags_non_exempt_agents(self, tmp_path):
        """
        Given: scripts/agents/ present (one exempt, one non-exempt agent)
               and scripts/agents-evals/ entirely absent from the fixture root
        When: find_pairing_violations scans the fixture root
        Then: It does not raise; the non-exempt agent is flagged missing
              (there is nowhere for its eval to be, so it is unpaired) and
              the exempt agent is not flagged (grandfathered)
        """
        exempt_name = next(iter(EXEMPT_AGENT_NAMES))
        _write_agent(tmp_path, exempt_name)
        _write_agent(tmp_path, "non-exempt-example")
        assert not (tmp_path / "scripts" / "agents-evals").exists()

        violations = find_pairing_violations(tmp_path)

        flagged_names = {v.name for v in violations}
        assert flagged_names == {"non-exempt-example"}

    def test_wholly_absent_agents_and_skills_trees_pass_vacuously(self, tmp_path):
        """
        Given: A fixture root with no scripts/agents/, scripts/skills/, or
               scripts/agents-evals/ trees at all
        When: find_pairing_violations scans the fixture root
        Then: It does not raise and returns no violations — nothing shipped,
              nothing to pair
        """
        assert not (tmp_path / "scripts").exists()

        violations = find_pairing_violations(tmp_path)

        assert violations == []

    def test_absent_agents_tree_with_skills_present_only_checks_skills(self, tmp_path):
        """
        Given: scripts/agents/ entirely absent, scripts/skills/ present with
               one clean skill
        When: find_pairing_violations scans the fixture root
        Then: It does not raise and returns no violations (nothing on the
              agent surface to check, the skill surface is clean)
        """
        _write_skill(tmp_path, "example-skill")
        _write_skill_eval(tmp_path, "example-skill")
        assert not (tmp_path / "scripts" / "agents").exists()

        violations = find_pairing_violations(tmp_path)

        assert violations == []


class TestDiscoveryHelpers:
    """Light coverage of the two discovery helpers in isolation from the comparison logic."""

    def test_discover_shipped_agents_returns_stem_names(self, tmp_path):
        """
        Given: Two agent files under scripts/agents/
        When: discover_shipped_agents scans the fixture root
        Then: It returns their stem names (no .md suffix, no directory prefix)
        """
        _write_agent(tmp_path, "alpha")
        _write_agent(tmp_path, "beta")

        names = discover_shipped_agents(tmp_path)

        assert set(names) == {"alpha", "beta"}

    def test_discover_shipped_skills_excludes_non_skill_files(self, tmp_path):
        """
        Given: One real skill directory and one stray file (README.md)
               directly under scripts/skills/
        When: discover_shipped_skills scans the fixture root
        Then: Only the real skill directory name is returned
        """
        skills_dir = tmp_path / "scripts" / "skills"
        skills_dir.mkdir(parents=True, exist_ok=True)
        (skills_dir / "README.md").write_text("# Skills\n", encoding="utf-8")
        _write_skill(tmp_path, "example-skill")

        names = discover_shipped_skills(tmp_path)

        assert names == ["example-skill"]

    def test_discover_functions_tolerate_absent_trees(self, tmp_path):
        """
        Given: Neither scripts/agents/ nor scripts/skills/ exists
        When: discover_shipped_agents and discover_shipped_skills scan the root
        Then: Both return an empty list without raising
        """
        assert discover_shipped_agents(tmp_path) == []
        assert discover_shipped_skills(tmp_path) == []


class TestCli:
    """
    main(argv: list[str]) -> int shape (case 9), matching the
    `main(argv) -> int` return-code contract validate_neutrality.py
    establishes (0 on success, non-zero on any violation).
    validate_control_risk_references.py's `main()` takes no `argv` and
    calls `sys.exit()` directly, so it is not a precedent for this shape —
    only its collect-all-violations behavior (cited elsewhere in this file)
    carries over from that script.

    This validator is self-scanning only — it does not accept file
    arguments — so, mirroring how test_validate_neutrality.py
    tests self-discovery (`monkeypatch.chdir(tmp_path)` then `main([])`),
    every test here drives `main` via a chdir'd fixture root rather than an
    explicit path argument or an environment variable.
    """

    def test_main_returns_zero_on_a_fully_paired_corpus(self, tmp_path, monkeypatch, capsys):
        """
        Given: A fixture root where every shipped agent and skill has a
               matching eval (or is grandfathered)
        When: main([]) runs with that root as cwd
        Then: It returns 0 and writes no violation output to stderr
        """
        exempt_name = next(iter(EXEMPT_AGENT_NAMES))
        _write_agent(tmp_path, "alpha")
        _write_agent_eval(tmp_path, "alpha")
        _write_agent(tmp_path, exempt_name)
        _write_skill(tmp_path, "example-skill")
        _write_skill_eval(tmp_path, "example-skill")
        monkeypatch.chdir(tmp_path)

        exit_code = main([])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert captured.err == ""

    def test_main_returns_nonzero_and_reports_violations_on_stderr(self, tmp_path, monkeypatch, capsys):
        """
        Given: A fixture root with one non-exempt agent missing its eval
        When: main([]) runs with that root as cwd
        Then: It returns a non-zero exit code and the agent's name appears
              in the stderr output
        """
        _write_agent(tmp_path, "beta")
        monkeypatch.chdir(tmp_path)

        exit_code = main([])
        captured = capsys.readouterr()

        assert exit_code != 0
        assert "beta" in captured.err

    def test_format_violation_includes_hook_name_and_message(self, tmp_path):
        """
        Given: A violation produced by find_pairing_violations
        When: format_violation renders it
        Then: The rendered line is prefixed with the validator's HOOK_NAME
              and includes the violation's message text
        """
        _write_agent(tmp_path, "beta")

        violations = find_pairing_violations(tmp_path)
        rendered = format_violation(violations[0])

        assert rendered.startswith(f"{validate_eval_pairing.HOOK_NAME}: ")
        assert violations[0].message in rendered


@pytest.mark.live_corpus
class TestLiveCorpus:
    """
    Runs the validator against the real repository's scripts/agents/ and
    scripts/skills/ trees.

    As of this branch, scripts/agents-evals/ does not exist anywhere in the
    real repository, so every real shipped agent is currently covered only
    by grandfathering (all 6 real agents are in EXEMPT_AGENT_NAMES and none
    have an eval yet — exactly the state the exemption set exists to
    tolerate). Every real skill under scripts/skills/ already ships
    evals/evals.json. So the live corpus is expected to be fully clean
    today; this is a regression guard, not a design assertion — the moment a
    7th agent ships (necessarily non-exempt) or scripts/agents-evals/ lands
    with a stale exemption, this test is meant to start failing.
    """

    def test_live_corpus_has_no_pairing_violations(self, repo_root):
        """
        Given: The real repository's scripts/agents/ and scripts/skills/ trees
        When: find_pairing_violations scans repo_root
        Then: No violations are produced
        """
        violations = find_pairing_violations(repo_root)

        assert violations == [], (
            f"expected a fully clean live corpus, got: {[(v.surface, v.name, v.message) for v in violations]}"
        )
