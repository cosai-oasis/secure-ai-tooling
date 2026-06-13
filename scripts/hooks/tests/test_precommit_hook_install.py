#!/usr/bin/env python3
"""
Structural validation tests for the pre-commit framework integration (#211).

Replaces the prior test suite for the deleted bash installer
(scripts/install-precommit-hook.sh). The framework migration moved hook
installation to `python3 -m pre_commit install` and hook configuration to
.pre-commit-config.yaml, so these tests assert that:

  - `pre-commit` is a pinned dependency in requirements.txt
  - .pre-commit-config.yaml is present at the repo root and parses as YAML
  - all expected hook ids are declared
  - each local hook has the spec-required entry, files regex, and pass_filenames
  - install-deps.sh Step 8 invokes `pre-commit install`

These are static checks: nothing is executed. Behavioral parity with the
prior bash hook is verified separately by the parity harness at
scripts/hooks/tests/precommit_parity.sh.
"""

import re
from pathlib import Path

import yaml

# Repo root is four levels up from this file (scripts/hooks/tests/<here>).
REPO_ROOT = Path(__file__).parent.parent.parent.parent

CONFIG_PATH = REPO_ROOT / ".pre-commit-config.yaml"
REQUIREMENTS_PATH = REPO_ROOT / "requirements.txt"
INSTALL_DEPS_PATH = REPO_ROOT / "scripts" / "tools" / "install-deps.sh"


def _load_config() -> dict:
    """Return the parsed .pre-commit-config.yaml as a dict."""
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))


def _all_hooks() -> list[dict]:
    """Return every hook declaration across all repos in the config."""
    config = _load_config()
    hooks: list[dict] = []
    for repo in config.get("repos", []):
        hooks.extend(repo.get("hooks", []))
    return hooks


def _hooks_by_id(hook_id: str) -> list[dict]:
    """Return all hook declarations matching the given id (may be multiple)."""
    return [h for h in _all_hooks() if h.get("id") == hook_id]


# ===========================================================================
# Dependency declarations
# ===========================================================================


class TestRequirementsPinning:
    """The pre-commit Python package must be pinned in requirements.txt."""

    def test_requirements_txt_exists(self):
        assert REQUIREMENTS_PATH.exists(), f"requirements.txt missing at {REQUIREMENTS_PATH}"

    def test_pre_commit_is_pinned(self):
        """
        Given: requirements.txt
        When: searching for the pre-commit dependency
        Then: a `pre-commit==<version>` line is present (exact pin, not range)
        """
        content = REQUIREMENTS_PATH.read_text(encoding="utf-8")
        match = re.search(r"^pre-commit==(\S+)$", content, re.MULTILINE)
        assert match, "pre-commit must be pinned with `==` in requirements.txt"


# ===========================================================================
# Config file existence and parseability
# ===========================================================================


class TestConfigFile:
    """The framework config must exist at the repo root and be valid YAML."""

    def test_config_file_present(self):
        assert CONFIG_PATH.exists(), f".pre-commit-config.yaml missing at {CONFIG_PATH}"

    def test_config_parses_as_yaml(self):
        config = _load_config()
        assert isinstance(config, dict), "Top-level YAML structure must be a mapping"
        assert "repos" in config, "Config must declare a `repos:` list"
        assert isinstance(config["repos"], list), "`repos` must be a list"
        assert len(config["repos"]) > 0, "Config declares no repos"


# ===========================================================================
# Required hook ids
# ===========================================================================

# Hooks the framework must declare for behavioral parity with the prior bash
# orchestrator. Each id maps to the bash section it replaces.
_REQUIRED_HOOK_IDS = {
    # Schema validation (one entry per yaml/schema pair, all share id):
    "check-jsonschema",
    # Meta-validate schema files themselves against their declared $schema:
    "check-metaschema",
    # Custom schema-master trigger:
    "validate-all-yaml-on-master-schema-change",
    # Format/lint:
    "prettier-yaml",
    "ruff",
    "ruff-format",
    # Local validators:
    "validate-component-edges",
    "validate-control-risk-references",
    "validate-framework-references",
    # Lifecycle uniqueness — dedicated hook so a lifecycle-only commit
    # (touching only risk-map/yaml/lifecycle-stage.yaml) is reachable.
    # Replaces the inline lifecycle-uniqueness call previously gated on
    # validate-component-edges (validate_riskmap.py:184-212), which only
    # triggers when components.yaml is staged. Architect-recommended Fix B
    # for PR #277 reviewer feedback (item 2): split into a separate hook
    # rather than widen validate-component-edges (would force a misleading
    # hook-name scope).
    "validate-lifecycle-stage",
    "validate-workflow-uses-pinning",
    # Issue templates:
    "regenerate-issue-templates",
    "validate-issue-templates",
    # Generators (Mode B auto-stage):
    "regenerate-graphs",
    "regenerate-tables",
    "regenerate-svgs",
    # ADR-027 D2b: frameworks.yaml versionId materialization + purity check.
    "regenerate-frameworks-versionid",
    "validate-frameworks-versionid-purity",
    # ADR-027 D4c/D5: framework mapping-value purity + Tier-1 drift checks.
    "validate-mapping-purity",
    "validate-mapping-drift",
}


class TestRequiredHookIds:
    """Every hook id required for parity must be present in the config."""

    def test_all_required_ids_present(self):
        declared_ids = {h.get("id") for h in _all_hooks()}
        missing = _REQUIRED_HOOK_IDS - declared_ids
        assert not missing, f"Missing required hook ids: {sorted(missing)}"


# ===========================================================================
# Local wrapper hook contracts
# ===========================================================================

# (id, expected entry substring, expected files regex substring, pass_filenames)
# Substring match keeps the test stable against minor wording changes.
_WRAPPER_CONTRACTS = [
    (
        "regenerate-graphs",
        "scripts/hooks/precommit/regenerate_graphs.py",
        "(components|controls|risks)",
        True,
    ),
    (
        "regenerate-tables",
        "scripts/hooks/precommit/regenerate_tables.py",
        "(components|controls|risks|personas)",
        True,
    ),
    (
        "regenerate-svgs",
        "scripts/hooks/precommit/regenerate_svgs.py",
        r"\.\(mmd\|mermaid\)",
        True,
    ),
    (
        # regenerate-issue-templates uses pass_filenames: false to avoid
        # pre-commit batching the hook into parallel invocations that would
        # fight over .git/index.lock when running against --all-files.
        "regenerate-issue-templates",
        "scripts/hooks/precommit/regenerate_issue_templates.py",
        "TEMPLATES",
        False,
    ),
    (
        "prettier-yaml",
        "scripts/hooks/precommit/prettier_yaml.py",
        r"risk-map/yaml/.*\\.ya\?ml",
        True,
    ),
]


class TestWrapperHookContracts:
    """Each wrapper hook must point at the right script with the right trigger."""

    def test_each_wrapper_has_expected_entry_and_files(self):
        all_hooks = {h.get("id"): h for h in _all_hooks() if h.get("id")}
        for hook_id, entry_substr, files_substr, pass_filenames in _WRAPPER_CONTRACTS:
            hook = all_hooks.get(hook_id)
            assert hook is not None, f"Hook `{hook_id}` not declared"
            assert entry_substr in hook.get("entry", ""), (
                f"Hook `{hook_id}` entry must reference `{entry_substr}`; got: {hook.get('entry')!r}"
            )
            files_value = hook.get("files", "")
            assert re.search(files_substr, files_value), (
                f"Hook `{hook_id}` files regex must contain `{files_substr}`; got: {files_value!r}"
            )
            assert hook.get("pass_filenames") is pass_filenames, (
                f"Hook `{hook_id}` pass_filenames must be {pass_filenames}; got: {hook.get('pass_filenames')!r}"
            )


# ===========================================================================
# Local validator hook contracts (pass_filenames: false; validators self-scan)
# ===========================================================================


class TestValidatorHookContracts:
    """Local validator hooks shell out to the existing validators with no argv."""

    def test_validate_component_edges_targets_components_yaml(self):
        """
        Test that validate-component-edges matches components.yaml (preserved behavior).

        Given: the validate-component-edges hook in .pre-commit-config.yaml
        When:  applying the hook's files: regex against risk-map/yaml/components.yaml
        Then:  the regex matches (re.search semantics, mirroring the pre-commit framework)

        This is the baseline assertion that must hold both before and after
        the trigger widening introduced by issue #279 / PR #277 follow-up.
        """
        hooks = _hooks_by_id("validate-component-edges")
        assert len(hooks) == 1, "Exactly one component-edge validator hook expected"
        hook = hooks[0]
        assert "validate_riskmap.py" in hook.get("entry", "")
        assert hook.get("pass_filenames") is False
        files_regex = hook.get("files", "")
        assert re.search(files_regex, "risk-map/yaml/components.yaml"), (
            f"validate-component-edges files regex must match risk-map/yaml/components.yaml; got: {files_regex!r}"
        )

    def test_validate_component_edges_matches_controls_yaml(self):
        """
        Test that validate-component-edges matches controls.yaml (new behavior, issue #279).

        Given: the validate-component-edges hook after trigger widening
        When:  applying the hook's files: regex against risk-map/yaml/controls.yaml
        Then:  the regex matches

        The validate_riskmap.py validator reads controls.yaml as part of its
        get_staged_yaml_files() target_files constant (utils.py:221-225). A
        controls-only commit must trigger the hook so the validator's full
        check suite (including A4 controls-components mirror and nesting checks)
        runs. Without this match, a controls-only commit silently skips all
        component-edge consistency checks.

        RED-PHASE: this test fails on the current config (files: targets
        components.yaml only) and passes once the trigger is widened per #279.
        """
        hooks = _hooks_by_id("validate-component-edges")
        assert len(hooks) == 1, "Exactly one component-edge validator hook expected"
        files_regex = hooks[0].get("files", "")
        assert re.search(files_regex, "risk-map/yaml/controls.yaml"), (
            f"validate-component-edges files regex must match "
            f"risk-map/yaml/controls.yaml (issue #279: trigger must cover the "
            f"full validator read set); got: {files_regex!r}. "
            f"Expected: ^risk-map/yaml/(components|controls|risks)\\.yaml$"
        )

    def test_validate_component_edges_matches_risks_yaml(self):
        """
        Test that validate-component-edges matches risks.yaml (new behavior, issue #279).

        Given: the validate-component-edges hook after trigger widening
        When:  applying the hook's files: regex against risk-map/yaml/risks.yaml
        Then:  the regex matches

        The validate_riskmap.py validator reads risks.yaml as part of its
        get_staged_yaml_files() target_files constant (utils.py:221-225). A
        risks-only commit must trigger the hook for the same reason as
        controls-only commits.

        RED-PHASE: this test fails on the current config and passes once the
        trigger is widened per issue #279.
        """
        hooks = _hooks_by_id("validate-component-edges")
        assert len(hooks) == 1, "Exactly one component-edge validator hook expected"
        files_regex = hooks[0].get("files", "")
        assert re.search(files_regex, "risk-map/yaml/risks.yaml"), (
            f"validate-component-edges files regex must match "
            f"risk-map/yaml/risks.yaml (issue #279: trigger must cover the "
            f"full validator read set); got: {files_regex!r}. "
            f"Expected: ^risk-map/yaml/(components|controls|risks)\\.yaml$"
        )

    def test_validate_component_edges_does_not_match_personas_yaml(self):
        """
        Test that validate-component-edges does NOT match personas.yaml (over-match guard).

        Given: the validate-component-edges hook after trigger widening
        When:  applying the hook's files: regex against risk-map/yaml/personas.yaml
        Then:  the regex does NOT match

        personas.yaml is not in the validator's read set and must not be added
        to the trigger to avoid running expensive validation on persona-only
        commits. This is an over-matching guard to ensure the widening is
        precisely scoped.
        """
        hooks = _hooks_by_id("validate-component-edges")
        assert len(hooks) == 1, "Exactly one component-edge validator hook expected"
        files_regex = hooks[0].get("files", "")
        assert not re.search(files_regex, "risk-map/yaml/personas.yaml"), (
            f"validate-component-edges files regex must NOT match "
            f"risk-map/yaml/personas.yaml (personas.yaml is not in the "
            f"validator read set); got: {files_regex!r}"
        )

    def test_validate_control_risk_targets_controls_and_risks(self):
        hooks = _hooks_by_id("validate-control-risk-references")
        assert len(hooks) == 1
        hook = hooks[0]
        assert "validate_control_risk_references.py" in hook.get("entry", "")
        assert "controls" in hook.get("files", "")
        assert "risks" in hook.get("files", "")
        assert hook.get("pass_filenames") is False

    def test_validate_framework_references_targets_relevant_yamls(self):
        hooks = _hooks_by_id("validate-framework-references")
        assert len(hooks) == 1
        hook = hooks[0]
        assert "validate_framework_references.py" in hook.get("entry", "")
        # Framework refs depend on multiple yamls
        files = hook.get("files", "")
        for token in ("controls", "frameworks", "personas", "risks"):
            assert token in files, f"framework refs files regex missing `{token}`: {files!r}"
        assert hook.get("pass_filenames") is False

    def test_validate_lifecycle_stage_dedicated_hook_present(self):
        """
        Test that a dedicated `validate-lifecycle-stage` hook is declared.

        Given: .pre-commit-config.yaml after the Fix B split
        When:  searching for the lifecycle-stage hook
        Then:  Exactly one hook with id `validate-lifecycle-stage` exists.

        This pins the architectural intent that lifecycle uniqueness has
        its own hook entry rather than being bundled into another hook.
        Lifecycle-only commits (which touch only lifecycle-stage.yaml and
        not components.yaml) must be able to trigger the check.
        """
        hooks = _hooks_by_id("validate-lifecycle-stage")
        assert len(hooks) == 1, (
            f"Exactly one validate-lifecycle-stage hook expected; got {len(hooks)}. "
            f"Architect-recommended Fix B requires a dedicated hook with a narrow "
            f"`files:` regex that fires on lifecycle-only commits."
        )

    def test_validate_lifecycle_stage_entry_invokes_validate_riskmap_in_lifecycle_mode(self):
        """
        Test that the lifecycle hook entry invokes validate_riskmap.py with
        the dedicated `--mode lifecycle` flag.

        Given: the `validate-lifecycle-stage` hook in .pre-commit-config.yaml
        When:  inspecting the `entry:` field
        Then:  The entry contains both `validate_riskmap.py` and
               `--mode lifecycle` (substring match keeps the test stable
               against minor wording changes such as `python3 ` prefix).

        The `--mode lifecycle` flag is the SWE contract: lifecycle mode
        bypasses get_staged_yaml_files / ComponentEdgeValidator and runs
        only the uniqueness check. See TestMainLifecycleMode in
        test_validate_riskmap.py.
        """
        hooks = _hooks_by_id("validate-lifecycle-stage")
        assert len(hooks) == 1, "validate-lifecycle-stage hook missing"
        entry = hooks[0].get("entry", "")
        assert "validate_riskmap.py" in entry, (
            f"validate-lifecycle-stage entry must invoke validate_riskmap.py; got: {entry!r}"
        )
        assert "--mode lifecycle" in entry, (
            f"validate-lifecycle-stage entry must pass --mode lifecycle so the script "
            f"runs the dedicated short-circuit path; got: {entry!r}"
        )

    def test_validate_lifecycle_stage_files_regex_anchored_on_lifecycle_yaml(self):
        """
        Test that the lifecycle hook's `files:` regex is narrowly scoped to
        lifecycle-stage.yaml.

        Given: the `validate-lifecycle-stage` hook
        When:  inspecting the `files:` regex
        Then:  The regex matches risk-map/yaml/lifecycle-stage.yaml and is
               anchored. Specifically the regex must be exactly
               `^risk-map/yaml/lifecycle-stage\\.yaml$` so the hook does not
               misfire on unrelated yaml writes.

        Anchoring matters: an unanchored `lifecycle-stage` substring would
        match any future file name containing the phrase. The exact-match
        requirement also disambiguates the architectural intent —
        lifecycle mode is single-file scoped.
        """
        hooks = _hooks_by_id("validate-lifecycle-stage")
        assert len(hooks) == 1, "validate-lifecycle-stage hook missing"
        files_regex = hooks[0].get("files", "")
        assert files_regex == r"^risk-map/yaml/lifecycle-stage\.yaml$", (
            f"validate-lifecycle-stage files regex must be "
            f"`^risk-map/yaml/lifecycle-stage\\.yaml$` (anchored, exact); "
            f"got: {files_regex!r}"
        )

    def test_validate_lifecycle_stage_pass_filenames_is_false(self):
        """
        Test that the lifecycle hook sets pass_filenames: false.

        Given: the `validate-lifecycle-stage` hook
        When:  inspecting `pass_filenames`
        Then:  Value is False.

        The validator self-discovers risk-map/yaml/lifecycle-stage.yaml
        from a fixed path; passing the staged filename as argv would be
        redundant and risks the framework batching multiple invocations.
        Matches the pattern used by validate-component-edges,
        validate-control-risk-references, and validate-framework-references.
        """
        hooks = _hooks_by_id("validate-lifecycle-stage")
        assert len(hooks) == 1, "validate-lifecycle-stage hook missing"
        assert hooks[0].get("pass_filenames") is False, (
            f"validate-lifecycle-stage must set pass_filenames: false; got: {hooks[0].get('pass_filenames')!r}"
        )

    def test_validate_workflow_uses_pinning_targets_workflow_yml_files(self):
        hooks = _hooks_by_id("validate-workflow-uses-pinning")
        assert len(hooks) == 1
        hook = hooks[0]
        assert "validate_workflow_uses_pinning.py" in hook.get("entry", "")
        files = hook.get("files", "")
        assert ".github/workflows" in files
        assert "yml" in files
        assert hook.get("pass_filenames") is True


# ===========================================================================
# Persona-site-build hook contracts (Task 2 — regression-lock)
# ===========================================================================


class TestPersonaSiteBuildHookContracts:
    """
    Regression-lock tests for the validate-persona-site-build hook.

    The trigger was correct from initial commit 93cc22b — controls.yaml was
    already included. These tests lock in that correctness so a future edit
    to the files: regex cannot silently drop controls.yaml.

    All tests in this class should PASS on the current config (green from day
    one). They are regression guards, not red-phase TDD tests.
    """

    def test_validate_persona_site_build_hook_exists_exactly_once(self):
        """
        Test that exactly one validate-persona-site-build hook is declared.

        Given: .pre-commit-config.yaml
        When:  searching for hooks with id `validate-persona-site-build`
        Then:  exactly one hook is found
        """
        hooks = _hooks_by_id("validate-persona-site-build")
        assert len(hooks) == 1, f"Exactly one validate-persona-site-build hook expected; got {len(hooks)}"

    def test_validate_persona_site_build_references_validator_script(self):
        """
        Test that the hook entry points at validate_persona_site_build.py.

        Given: the validate-persona-site-build hook
        When:  inspecting the entry: field
        Then:  the entry contains `validate_persona_site_build.py`
        """
        hook = _hooks_by_id("validate-persona-site-build")[0]
        assert "validate_persona_site_build.py" in hook.get("entry", ""), (
            f"validate-persona-site-build entry must reference "
            f"validate_persona_site_build.py; got: {hook.get('entry')!r}"
        )

    def test_validate_persona_site_build_pass_filenames_is_false(self):
        """
        Test that the hook sets pass_filenames: false.

        Given: the validate-persona-site-build hook
        When:  inspecting pass_filenames
        Then:  the value is False

        The validator ignores argv (it discards sys.argv) and runs the full
        builder pipeline against a temp directory; passing filenames would be
        redundant and risks multiple parallel invocations via framework batching.
        """
        hook = _hooks_by_id("validate-persona-site-build")[0]
        assert hook.get("pass_filenames") is False, (
            f"validate-persona-site-build must set pass_filenames: false; got: {hook.get('pass_filenames')!r}"
        )

    def test_validate_persona_site_build_matches_personas_yaml(self):
        """
        Test that the hook's files: regex matches personas.yaml.

        Given: the validate-persona-site-build hook
        When:  applying the files: regex against risk-map/yaml/personas.yaml
        Then:  the regex matches

        personas.yaml is a primary input to build_persona_site_data.py
        (DEFAULT_PERSONAS_PATH). A personas-only commit must trigger the hook.
        """
        hook = _hooks_by_id("validate-persona-site-build")[0]
        files_regex = hook.get("files", "")
        assert re.search(files_regex, "risk-map/yaml/personas.yaml"), (
            f"validate-persona-site-build files regex must match risk-map/yaml/personas.yaml; got: {files_regex!r}"
        )

    def test_validate_persona_site_build_matches_risks_yaml(self):
        """
        Test that the hook's files: regex matches risks.yaml.

        Given: the validate-persona-site-build hook
        When:  applying the files: regex against risk-map/yaml/risks.yaml
        Then:  the regex matches

        risks.yaml is read via DEFAULT_RISKS_PATH in build_persona_site_data.py.
        """
        hook = _hooks_by_id("validate-persona-site-build")[0]
        files_regex = hook.get("files", "")
        assert re.search(files_regex, "risk-map/yaml/risks.yaml"), (
            f"validate-persona-site-build files regex must match risk-map/yaml/risks.yaml; got: {files_regex!r}"
        )

    def test_validate_persona_site_build_matches_controls_yaml(self):
        """
        Test that the hook's files: regex matches controls.yaml (regression lock).

        Given: the validate-persona-site-build hook
        When:  applying the files: regex against risk-map/yaml/controls.yaml
        Then:  the regex matches

        controls.yaml is read via DEFAULT_CONTROLS_PATH in build_persona_site_data.py
        (validate_persona_site_build.py:41 calls builder.load_yaml(builder.DEFAULT_CONTROLS_PATH)).
        A controls-only commit must trigger the persona-site build re-run.

        This test locks in the correct trigger that was present from commit
        93cc22b. It was NOT in an earlier draft of the files: regex and was
        surfaced as a gap during the PR #277 review. The regression lock
        prevents this from being silently dropped by a future regex edit.
        """
        hook = _hooks_by_id("validate-persona-site-build")[0]
        files_regex = hook.get("files", "")
        assert re.search(files_regex, "risk-map/yaml/controls.yaml"), (
            f"validate-persona-site-build files regex must match "
            f"risk-map/yaml/controls.yaml (controls.yaml is in the builder "
            f"read set via DEFAULT_CONTROLS_PATH); got: {files_regex!r}"
        )

    def test_validate_persona_site_build_matches_risks_schema(self):
        """
        Test that the hook's files: regex matches the risks schema file.

        Given: the validate-persona-site-build hook
        When:  applying the files: regex against risk-map/schemas/risks.schema.json
        Then:  the regex matches
        """
        hook = _hooks_by_id("validate-persona-site-build")[0]
        files_regex = hook.get("files", "")
        assert re.search(files_regex, "risk-map/schemas/risks.schema.json"), (
            f"validate-persona-site-build files regex must match "
            f"risk-map/schemas/risks.schema.json; got: {files_regex!r}"
        )

    def test_validate_persona_site_build_matches_persona_site_data_schema(self):
        """
        Test that the hook's files: regex matches the persona-site-data schema file.

        Given: the validate-persona-site-build hook
        When:  applying the files: regex against risk-map/schemas/persona-site-data.schema.json
        Then:  the regex matches
        """
        hook = _hooks_by_id("validate-persona-site-build")[0]
        files_regex = hook.get("files", "")
        assert re.search(files_regex, "risk-map/schemas/persona-site-data.schema.json"), (
            f"validate-persona-site-build files regex must match "
            f"risk-map/schemas/persona-site-data.schema.json; got: {files_regex!r}"
        )

    def test_validate_persona_site_build_matches_builder_script(self):
        """
        Test that the hook's files: regex matches scripts/build_persona_site_data.py.

        Given: the validate-persona-site-build hook
        When:  applying the files: regex against scripts/build_persona_site_data.py
        Then:  the regex matches

        Changes to the builder itself must re-run the validation even when no
        YAML file changes.
        """
        hook = _hooks_by_id("validate-persona-site-build")[0]
        files_regex = hook.get("files", "")
        assert re.search(files_regex, "scripts/build_persona_site_data.py"), (
            f"validate-persona-site-build files regex must match "
            f"scripts/build_persona_site_data.py; got: {files_regex!r}"
        )

    def test_validate_persona_site_build_does_not_match_components_yaml(self):
        """
        Test that the hook's files: regex does NOT match components.yaml.

        Given: the validate-persona-site-build hook
        When:  applying the files: regex against risk-map/yaml/components.yaml
        Then:  the regex does NOT match

        components.yaml is not in the builder's read set. Matching it would
        cause unnecessary persona-site build re-runs on component-only commits.
        This is an over-matching guard to keep the trigger precisely scoped.
        """
        hook = _hooks_by_id("validate-persona-site-build")[0]
        files_regex = hook.get("files", "")
        assert not re.search(files_regex, "risk-map/yaml/components.yaml"), (
            f"validate-persona-site-build files regex must NOT match "
            f"risk-map/yaml/components.yaml (not in builder read set); "
            f"got: {files_regex!r}"
        )


# ===========================================================================
# Trigger coverage invariant (Task 4 — structural enforcement, issue #279)
# ===========================================================================

# Mapping: hook id -> trigger coverage set (repo-relative paths that must match
# the hook's files: regex).
#
# When adding a new local validator hook with pass_filenames: false, register
# the fixed path surface that must trigger it here. This set includes fixed
# check-input paths and fixed staged-file discovery surfaces such as
# get_staged_yaml_files() target_files. It is intentionally not limited to files
# literally opened during the default hook path.
#
# Use None as the sentinel value for hooks that are exempt from the invariant:
#   - Fan-out / generator hooks that use a variable or glob-determined set
#     of files (e.g., validate-all-yaml-on-master-schema-change discovers
#     all yaml/schema pairs at runtime).
#   - Hooks whose trigger coverage is determined by the staged files list at runtime
#     rather than a fixed set of paths (e.g., validate-issue-templates reads
#     whichever .github/ISSUE_TEMPLATE/*.yml files are staged).
#   - Hooks that do not have pass_filenames: false (not in scope; trigger-to-
#     scope coupling is implicit for pass_filenames: true hooks).
#
# Every local hook with pass_filenames: false MUST be registered here.
# Failure to register causes TestTriggerCoverageInvariant to fail with a
# clear diagnostic naming the unregistered hook id.
_LOCAL_VALIDATOR_TRIGGER_COVERAGE: dict[str, set[str] | None] = {
    # validate-component-edges: these are the fixed target files in
    # get_staged_yaml_files() (utils.py:221-225). The default pre-commit path
    # parses components.yaml and controls.yaml; risks.yaml is retained because
    # issue #279 explicitly preserves the legacy staged-file discovery surface
    # so risks-only changes still exercise the validator. lifecycle-stage.yaml
    # is covered by the dedicated validate-lifecycle-stage hook below; the
    # default-mode belt-and-suspenders lifecycle check in validate_riskmap.py is
    # intentionally out of this hook's trigger contract.
    "validate-component-edges": {
        "risk-map/yaml/components.yaml",
        "risk-map/yaml/controls.yaml",
        "risk-map/yaml/risks.yaml",
    },
    # validate-control-risk-references: reads both YAMLs every run
    # (validate_control_risk_references.py:25-28).
    "validate-control-risk-references": {
        "risk-map/yaml/controls.yaml",
        "risk-map/yaml/risks.yaml",
    },
    # validate-framework-references: reads all four YAMLs every run
    # (validate_framework_references.py:28-33).
    "validate-framework-references": {
        "risk-map/yaml/controls.yaml",
        "risk-map/yaml/frameworks.yaml",
        "risk-map/yaml/personas.yaml",
        "risk-map/yaml/risks.yaml",
    },
    # validate-lifecycle-stage: reads only lifecycle-stage.yaml via a fixed
    # path constant. Narrow trigger is architecturally intentional.
    "validate-lifecycle-stage": {
        "risk-map/yaml/lifecycle-stage.yaml",
    },
    # validate-persona-site-build: trigger coverage has two layers:
    #   (1) Three YAMLs opened per run via DEFAULT_*_PATH constants
    #       (build_persona_site_data.py:20-22; validate_persona_site_build.py:38-41).
    #   (2) The output schema, opened at module-import time
    #       (build_persona_site_data.py:31-37 _load_output_schema()).
    # Trigger-only (NOT in read set, intentionally — included in the trigger
    # for defensive re-run on edits but never opened by the builder):
    #   - risk-map/schemas/risks.schema.json: validated by check-jsonschema in
    #     a separate hook; the persona-site builder does not load it.
    #   - scripts/build_persona_site_data.py: imported as a Python module by
    #     the wrapper; not opened as a file at runtime.
    # The Task 2 regression-lock tests (TestPersonaSiteBuildHookContracts)
    # cover the full trigger surface; this entry covers the fixed runtime inputs.
    "validate-persona-site-build": {
        "risk-map/yaml/personas.yaml",
        "risk-map/yaml/risks.yaml",
        "risk-map/yaml/controls.yaml",
        "risk-map/schemas/persona-site-data.schema.json",
    },
    # validate-issue-templates: SENTINEL — the validator's coverage set is not
    # a fixed list of repo-relative paths. It queries git-staged files at
    # runtime (get_staged_files() in validate_issue_templates.py:72-98) and
    # validates whichever .github/ISSUE_TEMPLATE/*.yml files are staged. The
    # trigger files: regex covers the two directory roots (.github/ISSUE_TEMPLATE/
    # and scripts/TEMPLATES/) that the staged-file query may return. Exempt per
    # ADR-005 § Addendum 2026-05-08: Hook trigger-vs-read-set invariant.
    "validate-issue-templates": None,
    # regenerate-issue-templates: SENTINEL — generator hook, not a validator.
    # Reads template sources and schema files discovered at runtime; the trigger
    # covers sources and schemas but the full read set is glob-determined.
    "regenerate-issue-templates": None,
    # validate-all-yaml-on-master-schema-change: SENTINEL — fan-out hook.
    # Discovers (schema, yaml) pairs from the filesystem at runtime; the read
    # set is not a fixed list of paths.
    "validate-all-yaml-on-master-schema-change": None,
    # validate-frameworks-versionid-purity: reads only frameworks.yaml at the
    # canonical path. Trigger is anchored on the same path.
    "validate-frameworks-versionid-purity": {
        "risk-map/yaml/frameworks.yaml",
    },
    # validate-mapping-purity / validate-mapping-drift (ADR-027 D4c / D5/D5a):
    # both scan the four consumer YAMLs (_DEFAULT_CONTENT_FILES) AND read TWO
    # COMPARISON ORACLES, each via its own path constant:
    #   - frameworks.yaml via DEFAULT_FRAMEWORKS_PATH — the registry oracle. A
    #     version bump there (e.g. ATLAS 5.0.1->6.0.0) can flip a pinned consumer
    #     value's verdict current->invalid.
    #   - frameworks.schema.json via DEFAULT_SCHEMA_PATH / load_pinned_patterns()
    #     — the schema oracle. An edit to the strict pinned patterns or the ISO
    #     controlled-vocab enum there (the kind Work 2 made, and future D10
    #     version bumps) can likewise flip a pinned consumer value's verdict
    #     without ever touching the data file.
    # Neither oracle is in the scanned-content set; each is read every run via its
    # path constant, so editing either alone must trigger the hook. Per ADR-005
    # § Addendum 2026-06-08 (comparison-oracle inputs), this forces
    # pass_filenames: false so an oracle-only commit default-scans the four
    # consumer YAMLs instead of scanning an oracle file as argv.
    "validate-mapping-purity": {
        "risk-map/yaml/risks.yaml",
        "risk-map/yaml/controls.yaml",
        "risk-map/yaml/components.yaml",
        "risk-map/yaml/personas.yaml",
        "risk-map/yaml/frameworks.yaml",  # registry oracle (DEFAULT_FRAMEWORKS_PATH)
        "risk-map/schemas/frameworks.schema.json",  # schema oracle (DEFAULT_SCHEMA_PATH)
    },
    "validate-mapping-drift": {
        "risk-map/yaml/risks.yaml",
        "risk-map/yaml/controls.yaml",
        "risk-map/yaml/components.yaml",
        "risk-map/yaml/personas.yaml",
        "risk-map/yaml/frameworks.yaml",  # registry oracle (DEFAULT_FRAMEWORKS_PATH)
        "risk-map/schemas/frameworks.schema.json",  # schema oracle (DEFAULT_SCHEMA_PATH)
    },
}


def _local_hooks_with_pass_filenames_false() -> list[dict]:
    """Return local-repo hooks that have pass_filenames: false."""
    config = _load_config()
    result: list[dict] = []
    for repo in config.get("repos", []):
        if repo.get("repo") != "local":
            continue
        for hook in repo.get("hooks", []):
            if hook.get("pass_filenames") is False:
                result.append(hook)
    return result


class TestTriggerCoverageInvariant:
    """
    Structural enforcement of trigger coverage for pass_filenames: false hooks (ADR-005
    § Addendum 2026-05-08: Hook trigger-vs-read-set invariant, issue #279).

    For every local validator hook with pass_filenames: false, the hook's
    files: regex must match every fixed path in its declared trigger coverage
    set. If the trigger is narrower than the fixed coverage set, commits that
    touch only the unmatched paths silently skip validation.

    The metadata table _LOCAL_VALIDATOR_TRIGGER_COVERAGE is the contract surface.
    When adding a new local hook with pass_filenames: false, register its
    fixed trigger coverage there. Hooks with a None value are exempt (fan-out or
    runtime-discovered coverage sets; see table comments for rationale).

    Tests in this class:

      test_all_local_pass_filenames_false_hooks_are_registered
        — prevents drift where a new hook is added without a table entry.

      test_trigger_covers_declared_coverage_for_each_registered_hook
        — asserts files: regex covers every fixed non-None entry.
    """

    def test_all_local_pass_filenames_false_hooks_are_registered(self):
        """
        Test that every local hook with pass_filenames: false is registered in
        the metadata table.

        Given: .pre-commit-config.yaml with one or more local hooks with
               pass_filenames: false
        When:  comparing hook ids against _LOCAL_VALIDATOR_TRIGGER_COVERAGE keys
        Then:  every such hook id appears in the table (either with a real set
               or with the None sentinel)

        This prevents a new hook from being added without its fixed coverage
        being declared. A missing registration means the trigger coverage check
        cannot run for that hook, defeating the structural guarantee.
        """
        local_false_hooks = _local_hooks_with_pass_filenames_false()
        declared_ids = {h.get("id") for h in local_false_hooks}
        registered_ids = set(_LOCAL_VALIDATOR_TRIGGER_COVERAGE.keys())
        unregistered = declared_ids - registered_ids
        assert not unregistered, (
            f"Hook(s) {sorted(unregistered)} declared with pass_filenames: false "
            f"but missing from _LOCAL_VALIDATOR_TRIGGER_COVERAGE — register each hook's "
            f"fixed coverage set (or None sentinel for fan-out/runtime-discovered sets) per "
            f"ADR-005 § Addendum 2026-05-08: Hook trigger-vs-read-set invariant (issue #279)."
        )

    def test_trigger_covers_declared_coverage_for_each_registered_hook(self):
        """
        Test that each registered hook's files: regex matches all paths in its
        declared fixed trigger coverage set.

        Given: _LOCAL_VALIDATOR_TRIGGER_COVERAGE entries with non-None sets
        When:  applying each hook's files: regex against each declared path
               using re.search (mirroring the pre-commit framework's match behavior)
        Then:  every path matches

        Failure message names the hook id, the missing path, and a pointer to
        the ADR-005 addendum so the fix is unambiguous.

        RED-PHASE: before issue #279's trigger fix lands, this test fails on
        validate-component-edges because controls.yaml and risks.yaml are in its
        fixed staged-file discovery surface but not in files:. Once the trigger is widened
        to ^risk-map/yaml/(components|controls|risks)\\.yaml$ the test passes.
        """
        local_false_hooks = _local_hooks_with_pass_filenames_false()
        hooks_by_id = {h.get("id"): h for h in local_false_hooks}

        failures: list[str] = []
        for hook_id, coverage_set in _LOCAL_VALIDATOR_TRIGGER_COVERAGE.items():
            # Skip None sentinels — exempt from mechanical check.
            if coverage_set is None:
                continue

            hook = hooks_by_id.get(hook_id)
            if hook is None:
                # Hook declared in table but not in config — not this test's
                # concern (test_all_local_pass_filenames_false_hooks_are_registered
                # would have caught a missing registration; a table entry with no
                # matching hook is stale but not a trigger coverage violation).
                continue

            files_regex = hook.get("files", "")
            for path in sorted(coverage_set):
                if not re.search(files_regex, path):
                    failures.append(
                        f"Hook `{hook_id}`: files: regex {files_regex!r} does not "
                        f"match declared trigger coverage path `{path}`. A commit that only touches "
                        f"`{path}` will not trigger `{hook_id}`, silently skipping "
                        f"validation. Widen the trigger per ADR-005 § Addendum 2026-05-08: "
                        f"Hook trigger-vs-read-set invariant (issue #279)."
                    )

        assert not failures, "Trigger coverage invariant violated:\n" + "\n".join(f"  - {f}" for f in failures)


# ===========================================================================
# install-deps.sh integration
# ===========================================================================


class TestInstallDepsIntegration:
    """install-deps.sh Step 8 must invoke `pre-commit install`."""

    def test_install_deps_present(self):
        assert INSTALL_DEPS_PATH.exists(), f"install-deps.sh missing at {INSTALL_DEPS_PATH}"

    def test_step_8_invokes_pre_commit_install(self):
        """
        Given: scripts/tools/install-deps.sh
        When: searching Step 8 for the pre-commit install invocation
        Then: a `pre_commit install` invocation is present (module form)
        """
        content = INSTALL_DEPS_PATH.read_text(encoding="utf-8")
        # Step 8 header must exist
        assert re.search(r"step_msg 8", content), "install-deps.sh Step 8 header missing"
        # The install invocation must use the python3 module form so it works
        # regardless of whether pre-commit's CLI shim is on PATH.
        assert re.search(r"python3 -m pre_commit install", content), (
            "install-deps.sh must invoke `python3 -m pre_commit install`"
        )

    def test_step_8_does_not_reference_legacy_installer(self):
        """The bash installer (install-precommit-hook.sh) was deleted in #211."""
        content = INSTALL_DEPS_PATH.read_text(encoding="utf-8")
        assert "install-precommit-hook.sh" not in content, (
            "install-deps.sh still references the deleted bash installer"
        )


# ===========================================================================
# Sweep-validator block-mode posture lock
# ===========================================================================


class TestSweepValidatorsBlockMode:
    """
    Config-posture lock: sweep validators must carry --block in their entry.

    Each of the five sweep validators supports a dual-mode CLI: bare invocation
    warns and exits 0; --block causes a non-zero exit on violations so the
    pre-commit framework fails the commit.  The hook entry must include --block
    so staged violations are not silently swallowed.

    Two hooks that do not have dual-mode logic (validate-lifecycle-stage and
    validate-control-risk-references) must NOT carry --block; the guard tests
    below pin that invariant to prevent accidental mirroring.
    """

    def test_validate_component_edges_entry_has_block_flag(self):
        """
        Test that validate-component-edges hook entry contains --block.

        Given: .pre-commit-config.yaml validate-component-edges hook
        When:  inspecting the entry: field
        Then:  the entry contains the --block token
        """
        hooks = _hooks_by_id("validate-component-edges")
        assert len(hooks) == 1, "Exactly one validate-component-edges hook expected"
        entry = hooks[0].get("entry", "")
        assert "--block" in entry, (
            "validate-component-edges entry must contain --block so staged violations "
            "fail the commit rather than warn-and-continue; got: " + repr(entry)
        )

    def test_validate_framework_references_entry_has_block_flag(self):
        """
        Test that validate-framework-references hook entry contains --block.

        Given: .pre-commit-config.yaml validate-framework-references hook
        When:  inspecting the entry: field
        Then:  the entry contains the --block token
        """
        hooks = _hooks_by_id("validate-framework-references")
        assert len(hooks) == 1, "Exactly one validate-framework-references hook expected"
        entry = hooks[0].get("entry", "")
        assert "--block" in entry, (
            "validate-framework-references entry must contain --block so staged violations "
            "fail the commit rather than warn-and-continue; got: " + repr(entry)
        )

    def test_validate_identification_questions_entry_has_block_flag(self):
        """
        Test that validate-identification-questions hook entry contains --block.

        Given: .pre-commit-config.yaml validate-identification-questions hook
        When:  inspecting the entry: field
        Then:  the entry contains the --block token
        """
        hooks = _hooks_by_id("validate-identification-questions")
        assert len(hooks) == 1, "Exactly one validate-identification-questions hook expected"
        entry = hooks[0].get("entry", "")
        assert "--block" in entry, (
            "validate-identification-questions entry must contain --block so staged violations "
            "fail the commit rather than warn-and-continue; got: " + repr(entry)
        )

    def test_validate_yaml_prose_subset_entry_has_block_flag(self):
        """
        Test that validate-yaml-prose-subset hook entry contains --block.

        Given: .pre-commit-config.yaml validate-yaml-prose-subset hook
        When:  inspecting the entry: field
        Then:  the entry contains the --block token
        """
        hooks = _hooks_by_id("validate-yaml-prose-subset")
        assert len(hooks) == 1, "Exactly one validate-yaml-prose-subset hook expected"
        entry = hooks[0].get("entry", "")
        assert "--block" in entry, (
            "validate-yaml-prose-subset entry must contain --block so staged violations "
            "fail the commit rather than warn-and-continue; got: " + repr(entry)
        )

    def test_validate_prose_references_entry_has_block_flag(self):
        """
        Test that validate-prose-references hook entry contains --block.

        Given: .pre-commit-config.yaml validate-prose-references hook
        When:  inspecting the entry: field
        Then:  the entry contains the --block token
        """
        hooks = _hooks_by_id("validate-prose-references")
        assert len(hooks) == 1, "Exactly one validate-prose-references hook expected"
        entry = hooks[0].get("entry", "")
        assert "--block" in entry, (
            "validate-prose-references entry must contain --block so staged violations "
            "fail the commit rather than warn-and-continue; got: " + repr(entry)
        )

    def test_validate_lifecycle_stage_entry_does_not_have_block_flag(self):
        """
        Test that validate-lifecycle-stage hook entry does NOT contain --block.

        Given: .pre-commit-config.yaml validate-lifecycle-stage hook
        When:  inspecting the entry: field
        Then:  the entry does NOT contain --block

        validate-lifecycle-stage has no dual-mode logic; it exits non-zero on
        any violation regardless.  Adding --block would be meaningless noise and
        risks confusing future maintainers about which hooks are sweep validators.
        """
        hooks = _hooks_by_id("validate-lifecycle-stage")
        assert len(hooks) == 1, "Exactly one validate-lifecycle-stage hook expected"
        entry = hooks[0].get("entry", "")
        assert "--block" not in entry, (
            "validate-lifecycle-stage entry must NOT contain --block "
            "(not a sweep validator; has no dual-mode logic); got: " + repr(entry)
        )

    def test_validate_control_risk_references_entry_does_not_have_block_flag(self):
        """
        Test that validate-control-risk-references hook entry does NOT contain --block.

        Given: .pre-commit-config.yaml validate-control-risk-references hook
        When:  inspecting the entry: field
        Then:  the entry does NOT contain --block

        validate-control-risk-references has no dual-mode logic; it exits non-zero
        on any violation regardless.  This guard prevents accidental --block
        mirroring from a sweep-validator bulk edit.
        """
        hooks = _hooks_by_id("validate-control-risk-references")
        assert len(hooks) == 1, "Exactly one validate-control-risk-references hook expected"
        entry = hooks[0].get("entry", "")
        assert "--block" not in entry, (
            "validate-control-risk-references entry must NOT contain --block "
            "(not a sweep validator; has no dual-mode logic); got: " + repr(entry)
        )


# ===========================================================================
# require_serial guard for prettier hooks (issue #357)
# ===========================================================================

# Hooks that perform a per-file `git add` after formatting must run serially
# so concurrent invocations under `pre-commit run --all-files` do not race on
# .git/index.lock. Both prettier wrappers post-stage their output, so both
# require require_serial: true.
#
# Option B (focused set + class) was chosen over extending _WRAPPER_CONTRACTS
# because adding a 5th tuple element would widen every existing row and change
# the unpack loop — higher blast radius for a single-property invariant.
_REQUIRE_SERIAL_HOOKS = {
    # Both prettier wrappers run a per-file `git add` after formatting; parallel
    # batches under `pre-commit run --all-files` race on .git/index.lock
    # (issue #357). require_serial: true on each prevents the race.
    "prettier-yaml",
    "prettier-site-assets",
}


class TestRequireSerialPrettierHooks:
    """
    Both prettier wrapper hooks must declare require_serial: true.

    prettier_yaml.py and prettier_site_assets.py each run `git add` after
    formatting a file. Under `pre-commit run --all-files`, pre-commit batches
    pass_filenames: true hooks into parallel invocations (one per staged file).
    Concurrent `git add` calls race on .git/index.lock, causing one invocation
    to exit 128 with 'fatal: Unable to create index.lock: File exists'.
    require_serial: true forces a single serial invocation, eliminating the race.
    """

    def test_prettier_yaml_has_require_serial_true(self):
        """
        Test that the prettier-yaml hook declares require_serial: true.

        Given: .pre-commit-config.yaml with the prettier-yaml hook
        When:  inspecting the require_serial field
        Then:  the value is True

        Without require_serial: true, pre-commit batches --all-files runs into
        parallel invocations that race on .git/index.lock (issue #357). This
        guard ensures the property stays on the hook.
        """
        hooks = _hooks_by_id("prettier-yaml")
        assert len(hooks) == 1, "Exactly one prettier-yaml hook expected"
        hook = hooks[0]
        assert hook.get("require_serial") is True, (
            "prettier-yaml must declare require_serial: true to prevent concurrent "
            "`git add` calls from racing on .git/index.lock under --all-files "
            "(issue #357); got: " + repr(hook.get("require_serial"))
        )

    def test_prettier_site_assets_has_require_serial_true(self):
        """
        Test that the prettier-site-assets hook declares require_serial: true.

        Given: .pre-commit-config.yaml with the prettier-site-assets hook
        When:  inspecting the require_serial field
        Then:  the value is True

        Same race surface as prettier-yaml: a per-file `git add` under
        `pre-commit run --all-files` parallel batching would race on
        .git/index.lock. require_serial: true keeps the hook serial.
        """
        hooks = _hooks_by_id("prettier-site-assets")
        assert len(hooks) == 1, "Exactly one prettier-site-assets hook expected"
        hook = hooks[0]
        assert hook.get("require_serial") is True, (
            "prettier-site-assets must declare require_serial: true to prevent "
            "concurrent `git add` calls from racing on .git/index.lock under "
            "--all-files (issue #357); got: " + repr(hook.get("require_serial"))
        )

    def test_all_require_serial_hooks_are_present_in_config(self):
        """
        Test that every hook in _REQUIRE_SERIAL_HOOKS is declared in the config.

        Given: _REQUIRE_SERIAL_HOOKS set
        When:  checking each id against _all_hooks()
        Then:  all ids resolve to exactly one hook

        Catches a rename or deletion of either hook that would silently make
        the per-property tests above vacuous.
        """
        declared_ids = {h.get("id") for h in _all_hooks()}
        missing = _REQUIRE_SERIAL_HOOKS - declared_ids
        assert not missing, (
            f"Hook(s) {sorted(missing)} listed in _REQUIRE_SERIAL_HOOKS are not "
            f"declared in .pre-commit-config.yaml — update _REQUIRE_SERIAL_HOOKS "
            f"to match the new id if a hook was renamed."
        )


# ADR-026 Amendment 2026-05-21: D9 — regenerate-issue-templates trigger
# widening to include risk-map/yaml/components.yaml.
#
# The authoritative tuple source for {{COMPONENT_CATEGORY_SUBCATEGORY}} is the
# categories[].subcategory[] nesting in components.yaml, not the schema.
# A taxonomy edit (new category or subcategory) must regenerate the affected
# template in the same commit per D5a. That requires components.yaml to be in
# the regenerate-issue-templates hook's files: trigger.
#
# These tests enforce the ADR-026 D9 contract: the regenerate-issue-templates
# hook's files: trigger must include risk-map/yaml/components.yaml (so a
# taxonomy edit automatically regenerates affected templates in the same
# commit per D5a). They will fail until D9 is implemented; that is
# intentional — they are the specification.
# ===========================================================================


class TestRegenerateIssueTemplatesD9Trigger:
    """
    Structural tests for the regenerate-issue-templates trigger widening
    required by ADR-026 Amendment D9.
    """

    def test_regenerate_issue_templates_matches_components_yaml(self) -> None:
        """
        Test that the regenerate-issue-templates hook's files: regex matches
        risk-map/yaml/components.yaml after D9 trigger widening.

        Given: .pre-commit-config.yaml after D9 implementation
        When:  applying the files: regex against risk-map/yaml/components.yaml
        Then:  the regex matches

        ADR-026 D9 requires components.yaml to trigger regeneration because
        the tuple-selector {{COMPONENT_CATEGORY_SUBCATEGORY}} derives its
        options from categories[].subcategory[] nesting in that file, not
        from the schema. A taxonomy edit without this trigger would produce
        stale generated templates (silent divergence).

        The current files: regex is
          ^(scripts/TEMPLATES/.*\\.yml|risk-map/schemas/.*\\.schema\\.json|
            risk-map/yaml/frameworks\\.yaml)$
        which does NOT match components.yaml — so this test fails until D9
        widening lands.
        """
        hooks = _hooks_by_id("regenerate-issue-templates")
        assert len(hooks) == 1, "Exactly one regenerate-issue-templates hook expected"
        files_regex = hooks[0].get("files", "")

        assert re.search(files_regex, "risk-map/yaml/components.yaml"), (
            f"regenerate-issue-templates files: regex must match "
            f"risk-map/yaml/components.yaml (ADR-026 D9: the tuple-selector "
            f"reads components.yaml taxonomy nesting; a taxonomy edit must "
            f"regenerate the template in the same commit per D5a). "
            f"Current regex: {files_regex!r}. "
            f"Widen to include risk-map/yaml/components.yaml."
        )

    def test_regenerate_issue_templates_still_matches_templates_dir(self) -> None:
        """
        Test that the existing scripts/TEMPLATES/ match is preserved after
        D9 trigger widening.

        Given: .pre-commit-config.yaml after D9 implementation
        When:  applying the files: regex against a scripts/TEMPLATES/ path
        Then:  the regex still matches

        This is a regression guard — D9 widens the trigger but must not drop
        the existing TEMPLATES directory coverage.
        """
        hooks = _hooks_by_id("regenerate-issue-templates")
        assert len(hooks) == 1, "Exactly one regenerate-issue-templates hook expected"
        files_regex = hooks[0].get("files", "")

        assert re.search(files_regex, "scripts/TEMPLATES/new_component.template.yml"), (
            f"regenerate-issue-templates files: regex must still match "
            f"scripts/TEMPLATES/*.yml paths after D9 widening (regression guard). "
            f"Got: {files_regex!r}"
        )

    def test_regenerate_issue_templates_still_matches_schemas_dir(self) -> None:
        """
        Test that the existing risk-map/schemas/ match is preserved after
        D9 trigger widening.

        Given: .pre-commit-config.yaml after D9 implementation
        When:  applying the files: regex against a risk-map/schemas/ path
        Then:  the regex still matches

        D9 does not change the schema trigger; only components.yaml is added.
        """
        hooks = _hooks_by_id("regenerate-issue-templates")
        assert len(hooks) == 1, "Exactly one regenerate-issue-templates hook expected"
        files_regex = hooks[0].get("files", "")

        assert re.search(files_regex, "risk-map/schemas/components.schema.json"), (
            f"regenerate-issue-templates files: regex must still match "
            f"risk-map/schemas/*.schema.json paths after D9 widening (regression guard). "
            f"Got: {files_regex!r}"
        )

    def test_regenerate_issue_templates_still_matches_frameworks_yaml(self) -> None:
        """
        Test that the existing risk-map/yaml/frameworks.yaml match is preserved
        after D9 trigger widening.

        Given: .pre-commit-config.yaml after D9 implementation
        When:  applying the files: regex against risk-map/yaml/frameworks.yaml
        Then:  the regex still matches

        D9 adds components.yaml to the trigger; it does not remove frameworks.yaml.
        """
        hooks = _hooks_by_id("regenerate-issue-templates")
        assert len(hooks) == 1, "Exactly one regenerate-issue-templates hook expected"
        files_regex = hooks[0].get("files", "")

        assert re.search(files_regex, "risk-map/yaml/frameworks.yaml"), (
            f"regenerate-issue-templates files: regex must still match "
            f"risk-map/yaml/frameworks.yaml after D9 widening (regression guard). "
            f"Got: {files_regex!r}"
        )

    def test_regenerate_issue_templates_does_not_match_unrelated_yaml(self) -> None:
        """
        Test that the D9-widened trigger does NOT match unrelated YAML files
        such as risk-map/yaml/risks.yaml.

        Given: .pre-commit-config.yaml after D9 implementation
        When:  applying the files: regex against risk-map/yaml/risks.yaml
        Then:  the regex does NOT match

        Over-matching would cause unnecessary template regeneration on every
        risks.yaml edit. D9 is a precise expansion — only components.yaml is
        added, not all of risk-map/yaml/.
        """
        hooks = _hooks_by_id("regenerate-issue-templates")
        assert len(hooks) == 1, "Exactly one regenerate-issue-templates hook expected"
        files_regex = hooks[0].get("files", "")

        assert not re.search(files_regex, "risk-map/yaml/risks.yaml"), (
            f"regenerate-issue-templates files: regex must NOT match "
            f"risk-map/yaml/risks.yaml after D9 widening (over-match guard: "
            f"risks.yaml does not contribute to the tuple-selector content). "
            f"Got: {files_regex!r}"
        )

        # Additional over-match guards: a broad D9 widening (e.g., matching all of
        # risk-map/yaml/) would silently catch controls.yaml and personas.yaml too,
        # triggering unnecessary template regeneration on every controls or personas
        # edit. D9 is a precise expansion — only components.yaml is added.
        assert not re.search(files_regex, "risk-map/yaml/controls.yaml"), (
            f"regenerate-issue-templates files: regex must NOT match "
            f"risk-map/yaml/controls.yaml after D9 widening (over-match guard: "
            f"controls.yaml does not contribute to the tuple-selector content). "
            f"Got: {files_regex!r}"
        )

        assert not re.search(files_regex, "risk-map/yaml/personas.yaml"), (
            f"regenerate-issue-templates files: regex must NOT match "
            f"risk-map/yaml/personas.yaml after D9 widening (over-match guard: "
            f"personas.yaml does not contribute to the tuple-selector content). "
            f"Got: {files_regex!r}"
        )


# ===========================================================================
# Mapping-validator comparison-oracle trigger (#343 Work 6)
# ===========================================================================


class TestMappingValidatorOracleTrigger:
    """
    validate-mapping-purity (ADR-027 D4c) and validate-mapping-drift (D5/D5a)
    must fire on BOTH framework sources and run pass_filenames: false.

    Per ADR-005 § Addendum 2026-06-08 (comparison-oracle inputs): both validators
    scan the four consumer YAMLs but read TWO comparison oracles, each via its own
    path constant:
      - frameworks.yaml via DEFAULT_FRAMEWORKS_PATH (the registry oracle): a
        version bump can flip a pinned consumer value current->invalid.
      - frameworks.schema.json via DEFAULT_SCHEMA_PATH / load_pinned_patterns()
        (the schema oracle): a strict-pattern or ISO-enum edit can likewise flip
        a pinned consumer value's verdict without touching the data file.
    After #343 pinned every consumer mapping value, an edit to either source can
    invalidate a pinned value; if an oracle-only commit does not trigger the hooks,
    that breakage is committed uncaught. The trigger must therefore include both
    framework sources, and the hooks must run pass_filenames: false (else an
    oracle-only commit hands the validator the oracle path as argv and it scans a
    non-content file — a silent miss).
    """

    _MAPPING_HOOKS = ("validate-mapping-purity", "validate-mapping-drift")
    # The four consumer YAMLs (scanned-content set) plus BOTH oracles. Editing
    # any one alone must trigger the hooks.
    _COVERAGE_PATHS = (
        "risk-map/yaml/risks.yaml",
        "risk-map/yaml/controls.yaml",
        "risk-map/yaml/components.yaml",
        "risk-map/yaml/personas.yaml",
        "risk-map/yaml/frameworks.yaml",  # registry oracle
        "risk-map/schemas/frameworks.schema.json",  # schema oracle
    )

    def test_mapping_hooks_run_pass_filenames_false(self):
        """
        Both mapping validators must declare pass_filenames: false.

        Given: the two ADR-027 mapping-validator hooks in .pre-commit-config.yaml
        When:  inspecting pass_filenames
        Then:  both are False (so an oracle-only commit default-scans the four
               consumer YAMLs instead of scanning the oracle file as argv)
        """
        for hook_id in self._MAPPING_HOOKS:
            hooks = _hooks_by_id(hook_id)
            assert len(hooks) == 1, f"Exactly one `{hook_id}` hook expected"
            assert hooks[0].get("pass_filenames") is False, (
                f"`{hook_id}` must set pass_filenames: false (ADR-005 § Addendum 2026-06-08); "
                f"got: {hooks[0].get('pass_filenames')!r}"
            )

    def test_mapping_hooks_trigger_on_frameworks_and_consumers(self):
        """
        Both mapping validators' files: regex must match all four consumer YAMLs
        AND both framework oracles (frameworks.yaml and frameworks.schema.json).

        Given: the two ADR-027 mapping-validator hooks
        When:  applying each hook's files: regex (re.search) against the six paths
        Then:  every path matches — most importantly the two oracles, whose edit
               can invalidate a pinned consumer value without touching the four
               consumer YAMLs
        """
        for hook_id in self._MAPPING_HOOKS:
            hook = _hooks_by_id(hook_id)[0]
            files_regex = hook.get("files", "")
            for path in self._COVERAGE_PATHS:
                assert re.search(files_regex, path), (
                    f"`{hook_id}` files: regex {files_regex!r} must match `{path}` "
                    f"(ADR-005 § Addendum 2026-06-08: comparison-oracle inputs). A commit "
                    f"touching only `{path}` would otherwise silently skip the validator."
                )

    def test_schema_oracle_only_change_set_is_in_scope_and_default_scans(self):
        """
        A frameworks.schema.json-only change set must put both validators in scope
        while leaving pass_filenames: false so they default-scan the four consumer
        YAMLs (mirrors the frameworks.yaml-only registry-oracle case).

        Given: the two ADR-027 mapping-validator hooks
        When:  modeling a commit that stages ONLY risk-map/schemas/frameworks.schema.json
        Then:  the hook's files: regex matches that path (the hook fires) AND
               pass_filenames is False (so the validator ignores the schema path as
               argv and default-scans the four consumer YAMLs, re-checking every
               pinned value against the edited schema oracle)

        This is the schema-oracle analog of the registry-oracle behavior: a strict
        pinned-pattern / ISO-enum edit in frameworks.schema.json that never touches
        a data file must still re-validate all pinned consumer values. With
        pass_filenames: true the validator would receive only the schema path as
        argv and scan a non-content file — a silent miss.
        """
        schema_path = "risk-map/schemas/frameworks.schema.json"
        consumer_yamls = (
            "risk-map/yaml/risks.yaml",
            "risk-map/yaml/controls.yaml",
            "risk-map/yaml/components.yaml",
            "risk-map/yaml/personas.yaml",
        )
        for hook_id in self._MAPPING_HOOKS:
            hook = _hooks_by_id(hook_id)[0]
            files_regex = hook.get("files", "")
            # The schema oracle alone is in scope (the hook fires on this commit).
            assert re.search(files_regex, schema_path), (
                f"`{hook_id}` files: regex {files_regex!r} must match `{schema_path}` "
                f"so a schema-oracle-only commit triggers the hook (ADR-005 § Addendum "
                f"2026-06-08: comparison-oracle inputs)."
            )
            # pass_filenames must stay false so the validator default-scans the
            # four consumer YAMLs rather than scanning the schema path as argv.
            assert hook.get("pass_filenames") is False, (
                f"`{hook_id}` must keep pass_filenames: false so a schema-oracle-only "
                f"commit default-scans the four consumer YAMLs; got: "
                f"{hook.get('pass_filenames')!r}"
            )
            # The four consumer YAMLs are the default scanned-content set: each is
            # also in the trigger, confirming the hook re-checks them on any edit.
            for yaml_path in consumer_yamls:
                assert re.search(files_regex, yaml_path), (
                    f"`{hook_id}` files: regex {files_regex!r} must match consumer "
                    f"YAML `{yaml_path}` (default scanned-content set)."
                )
