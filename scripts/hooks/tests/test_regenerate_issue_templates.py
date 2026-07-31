#!/usr/bin/env python3
"""
Tests for scripts/hooks/precommit/regenerate_issue_templates.py

The wrapper is invoked by the pre-commit framework with `pass_filenames:
false` after the framework's `files:` regex matches any of:

  - scripts/TEMPLATES/<anything>.yml
  - risk-map/schemas/<anything>.schema.json
  - risk-map/yaml/frameworks.yaml

When invoked, the wrapper unconditionally runs
`python3 scripts/generate_issue_templates.py` and git-adds the
`.github/ISSUE_TEMPLATE` directory. argv is ignored — the framework is the
scheduler.

Test coverage focuses on the subprocess call shape, the
generation-then-stage ordering, and failure propagation. There is no
argv-based gate to exercise (the wrapper regenerates unconditionally to
avoid the concurrent-git-add bug that a per-file gate produced when
pre-commit batched invocations on --all-files).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "precommit"))

from regenerate_issue_templates import main  # noqa: E402

CMD_GENERATE = ["python3", "scripts/generate_issue_templates.py"]
GIT_ADD_TEMPLATES = ["git", "add", ".github/ISSUE_TEMPLATE"]


def _make_subprocess_mock(returncode: int = 0) -> MagicMock:
    """Return a MagicMock for subprocess.run with the given returncode."""
    mock = MagicMock()
    mock.returncode = returncode
    return mock


# ===========================================================================
# Happy path: unconditional regeneration when invoked
# ===========================================================================


class TestHappyPath:
    def test_empty_argv_still_regenerates_and_stages(self):
        """
        The framework uses pass_filenames: false, so argv is empty. Reaching
        main() means regeneration is wanted — do not short-circuit.

        Given: main([]) is called (framework-style invocation)
        When: both subprocesses succeed
        Then: generation runs, git add runs, exit 0
        """
        # Implementation must use `subprocess.run(...)` (not `from subprocess import run`)
        # for this patch target to intercept calls.
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_subprocess_mock(0)
            result = main([])

        assert result == 0
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert calls == [CMD_GENERATE, GIT_ADD_TEMPLATES], (
            f"Expected exactly CMD_GENERATE then GIT_ADD_TEMPLATES; got: {calls}"
        )

    def test_argv_content_is_ignored(self):
        """
        Any argv — including non-trigger files — still produces exactly one
        regeneration + one git add.

        Given: argv with arbitrary paths (trigger-matching or not)
        When: main() is called
        Then: exit 0, still exactly one gen + one git add (argv ignored)
        """
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_subprocess_mock(0)
            result = main(
                [
                    "README.md",
                    "scripts/TEMPLATES/new_component.template.yml",
                    "risk-map/yaml/frameworks.yaml",
                ]
            )

        assert result == 0
        assert mock_run.call_count == 2, "Exactly one gen + one git add regardless of argv content"


# ===========================================================================
# Subprocess command shape (exact list equality)
# ===========================================================================


class TestSubprocessCommandShape:
    def test_generation_command_is_exact(self):
        """Generation command must be ["python3", "scripts/generate_issue_templates.py"]."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_subprocess_mock(0)
            main([])

        assert mock_run.call_args_list[0].args[0] == CMD_GENERATE

    def test_git_add_command_is_exact(self):
        """git add command must be ["git", "add", ".github/ISSUE_TEMPLATE"]."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_subprocess_mock(0)
            main([])

        assert mock_run.call_args_list[1].args[0] == GIT_ADD_TEMPLATES

    def test_all_commands_use_list_form(self):
        """Every subprocess call must use list form (no shell=True)."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_subprocess_mock(0)
            main([])

        for call in mock_run.call_args_list:
            assert isinstance(call.args[0], list), f"Command must be list-form: {call.args[0]!r}"
            assert call.kwargs.get("shell") is not True, "shell=True must not be passed"


# ===========================================================================
# Failure modes
# ===========================================================================


class TestFailureModes:
    def test_generation_fails_git_add_not_called(self):
        """
        Given: generation returns non-zero
        When: main() is called
        Then: git add is NOT called, exit code matches generation rc
        """

        def side_effect(cmd, **kwargs):
            if cmd == CMD_GENERATE:
                return _make_subprocess_mock(2)
            return _make_subprocess_mock(0)

        with patch("subprocess.run", side_effect=side_effect) as mock_run:
            result = main([])

        assert result == 2
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert CMD_GENERATE in calls
        assert GIT_ADD_TEMPLATES not in calls, "git add must not run when generation fails"

    def test_git_add_fails_returns_nonzero(self):
        """
        Given: generation succeeds but git add fails
        When: main() is called
        Then: exit code is the git add rc
        """

        def side_effect(cmd, **kwargs):
            if cmd == GIT_ADD_TEMPLATES:
                return _make_subprocess_mock(5)
            return _make_subprocess_mock(0)

        with patch("subprocess.run", side_effect=side_effect):
            result = main([])

        assert result == 5

    def test_both_succeed_returns_zero(self):
        """Both subprocesses succeed → exit 0."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_subprocess_mock(0)
            result = main([])

        assert result == 0
        assert mock_run.call_count == 2


# ===========================================================================
# D6 structural-contract tests (ADR-026 D2, D3, D6)
#
# These tests encode the source-coverage and orphan-prevention contracts
# defined in ADR-026. They operate on the generator package and filesystem
# directly — no subprocess mocking required.
#
# Naming note: no phasing language (RED/GREEN/phase-X) in names or docstrings.
# Issue and ADR numbers are fine as documentation references.
# ===========================================================================


# Entity-type and operation constants that define the coverage contract.
# Changing these is the authoritative act of adding/removing a template scope.
_ENTITY_TYPES = {"risk", "control", "component", "persona"}
_OPERATIONS = {"new", "update"}

# Output names excluded from the entity-template coverage contract per ADR-026 D1.
_D1_EXCLUSIONS = {"config", "infrastructure"}


class TestSourceCoverageContract:
    """
    Asserts that the generator's source inventory satisfies ADR-026 D2.

    ADR-026 D2 requires one source template for every content-entity output:
    {new, update} × {risk, control, component, persona} = 8 sources.
    """

    def test_get_available_templates_returns_all_eight_entity_sources(self, repo_root: Path) -> None:
        """
        Asserts that get_available_templates() returns exactly the 8
        content-entity source names required by ADR-026 D2.

        Given: The scripts/TEMPLATES directory after backfill is complete
        When: get_available_templates() is called on IssueTemplateGenerator
        Then: The returned set equals {new,update} × {risk,control,component,persona}

        Issue: #326 / ADR-026 D2.
        """
        import sys

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.generator import IssueTemplateGenerator

        gen = IssueTemplateGenerator(repo_root)
        available = set(gen.get_available_templates())

        expected = {f"{op}_{entity}" for op in _OPERATIONS for entity in _ENTITY_TYPES}

        missing = expected - available
        unexpected = available - expected

        assert available == expected, (
            f"Source coverage mismatch (ADR-026 D2). "
            f"Missing sources: {sorted(missing)}. "
            f"Unexpected sources: {sorted(unexpected)}. "
            f"Expected exactly: {sorted(expected)}."
        )

    def test_source_names_derive_from_operations_and_entity_types(self, repo_root: Path) -> None:
        """
        Verifies that each expected source name follows the {operation}_{entity}
        pattern — the contract is declarative, not a hardcoded name blob.

        Given: The {new,update} × {risk,control,component,persona} decision
        When: Each expected name is checked against the template source directory
        Then: All 8 template source files exist on disk

        Issue: #326 / ADR-026 D2.
        """
        templates_dir = repo_root / "scripts" / "TEMPLATES"
        for op in _OPERATIONS:
            for entity in _ENTITY_TYPES:
                source_file = templates_dir / f"{op}_{entity}.template.yml"
                assert source_file.exists(), (
                    f"Missing source template (ADR-026 D2): {source_file.name}. "
                    f"All {len(_OPERATIONS) * len(_ENTITY_TYPES)} content-entity "
                    f"sources must exist in scripts/TEMPLATES/."
                )


class TestOrphanPreventionContract:
    """
    Asserts that every content-entity output in .github/ISSUE_TEMPLATE/ has
    a matching source in scripts/TEMPLATES/, per ADR-026 D6.

    config.yml and infrastructure.yml are excluded from this contract
    per ADR-026 D1 (non-entity templates are managed directly).
    """

    def test_no_content_entity_output_exists_without_a_source(self, repo_root: Path) -> None:
        """
        Asserts that every content-entity output file has a corresponding
        source template in scripts/TEMPLATES/.

        config.yml and infrastructure.yml are excluded per ADR-026 D1.

        Given: The .github/ISSUE_TEMPLATE/ directory
        When: All .yml files except D1 exclusions are examined
        Then: Every output stem maps to an existing source .template.yml

        Issue: #326 / ADR-026 D6.
        """
        output_dir = repo_root / ".github" / "ISSUE_TEMPLATE"
        templates_dir = repo_root / "scripts" / "TEMPLATES"

        assert output_dir.exists(), f"Output directory not found: {output_dir}"

        orphans = []
        for output_file in sorted(output_dir.glob("*.yml")):
            stem = output_file.stem
            if stem in _D1_EXCLUSIONS:
                # config.yml and infrastructure.yml excluded per ADR-026 D1
                continue
            source = templates_dir / f"{stem}.template.yml"
            if not source.exists():
                orphans.append(output_file.name)

        assert not orphans, (
            f"Orphan outputs detected (ADR-026 D6): {orphans}. "
            f"Each content-entity output requires a source in scripts/TEMPLATES/. "
            f"Excluded from check (ADR-026 D1): {sorted(_D1_EXCLUSIONS)}."
        )

    def test_source_set_equals_content_entity_output_set(self, repo_root: Path) -> None:
        """
        Asserts that the set of source template names exactly equals the set
        of content-entity output names, so neither side has unmatched files.

        Given: scripts/TEMPLATES/ sources and .github/ISSUE_TEMPLATE/ outputs
        When: D1 exclusions are removed from the output set
        Then: source_names == output_names (bijection)

        Issue: #326 / ADR-026 D6.
        """
        import sys

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.generator import IssueTemplateGenerator

        gen = IssueTemplateGenerator(repo_root)
        source_names = set(gen.get_available_templates())

        output_dir = repo_root / ".github" / "ISSUE_TEMPLATE"
        output_names = {f.stem for f in output_dir.glob("*.yml") if f.stem not in _D1_EXCLUSIONS}

        assert source_names == output_names, (
            f"Source/output mismatch (ADR-026 D6). "
            f"Sources without outputs: {sorted(source_names - output_names)}. "
            f"Outputs without sources (orphans): {sorted(output_names - source_names)}."
        )


class TestPerSourceRegenerationDeterminism:
    """
    Asserts that generating each of the 8 content-entity templates twice
    produces byte-identical output and valid YAML / GitHub issue form structure
    (ADR-026 D6 determinism and correctness contract).
    """

    def test_each_source_renders_deterministically(self, repo_root: Path) -> None:
        """
        Asserts that every source template renders to byte-identical output
        on two successive calls (determinism/idempotency contract per ADR-026 D6).

        Given: All 8 source templates exist (after backfill)
        When: generate_template() is called twice for each source
        Then: Both calls return byte-identical content

        Fails for any source whose rendering is non-deterministic.
        Issue: #326 / ADR-026 D6.
        """
        import sys

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.generator import IssueTemplateGenerator

        gen = IssueTemplateGenerator(repo_root)
        expected_names = {f"{op}_{entity}" for op in _OPERATIONS for entity in _ENTITY_TYPES}

        for name in sorted(expected_names):
            template_file = repo_root / "scripts" / "TEMPLATES" / f"{name}.template.yml"
            assert template_file.exists(), (
                f"Source template missing (prerequisite for determinism test): {template_file.name}"
            )
            # dry_run=True renders without writing, so we can call it twice safely.
            render_1 = gen.generate_template(name, dry_run=True)
            render_2 = gen.generate_template(name, dry_run=True)
            # Reject the vacuous case: when no output file exists yet, dry_run
            # returns a fixed "New file: ..." string with no rendering involved,
            # which would make the equality check trivially true.
            assert not str(render_1).startswith("New file:"), (
                f"Determinism check is vacuous for {name}: output file does not exist, "
                f"so dry_run returned a placeholder string rather than rendered content."
            )
            assert render_1 == render_2, f"Non-deterministic rendering for {name}: two successive renders differ."

    def test_each_source_renders_to_valid_yaml(self, repo_root: Path, tmp_path: Path) -> None:
        """
        Asserts that every source template renders to valid YAML that parses
        without error and contains the required 'name' field (GitHub issue form
        minimum contract).

        Given: All 8 source templates exist (after backfill)
        When: Each template is rendered and the output is parsed
        Then: yaml.safe_load() succeeds and 'name' key is present

        Issue: #326 / ADR-026 D6.
        """
        import sys

        import yaml

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.generator import IssueTemplateGenerator

        # Use a tmp output dir to avoid touching the real repo during testing
        gen = IssueTemplateGenerator(repo_root)
        expected_names = {f"{op}_{entity}" for op in _OPERATIONS for entity in _ENTITY_TYPES}

        for name in sorted(expected_names):
            template_file = repo_root / "scripts" / "TEMPLATES" / f"{name}.template.yml"
            if not template_file.exists():
                # Report the missing source as a failure, not a skip
                raise AssertionError(
                    f"Source template missing (prerequisite): {template_file.name}. Cannot validate rendered YAML."
                )
            # dry_run returns the diff string or "New file: ...\n" — use write mode
            # into tmp_path to capture the rendered content
            gen.output_dir = tmp_path
            output_path = gen.generate_template(name, dry_run=False)
            assert isinstance(output_path, Path), f"generate_template returned non-Path for {name}"

            rendered = output_path.read_text(encoding="utf-8")
            try:
                parsed = yaml.safe_load(rendered)
            except Exception as exc:
                raise AssertionError(f"Rendered output for {name} is not valid YAML: {exc}") from exc

            assert isinstance(parsed, dict), f"Rendered output for {name} does not parse as a YAML dict."
            assert "name" in parsed, (
                f"Rendered output for {name} is missing the required 'name' field (GitHub issue form minimum)."
            )


# ===========================================================================
# ADR-026 Amendment 2026-05-21: Component category/subcategory valid-tuple
# selector (D8/D9/D10).
#
# D8 — tuple-selector placeholder: {{COMPONENT_CATEGORY_SUBCATEGORY}} renders
#      the valid (category, subcategory) pairs derived from the
#      categories[].subcategory[] nesting in components.yaml (eleven pairs as
#      of ADR-030 D1's componentsExternalTools category and D2's componentsIdentity
#      subcategory), formatted as
#      "<category-id>: <subcategory-id>" with ": " as delimiter.
#      {{COMPONENT_SUBCATEGORIES}} is retired.
#
# Tests in this section:
#   TestTupleSelectorRendering        — D8 coverage + order + no-invalid-pairs
#   TestTaxonomyDerivedNotInstanceDerived — D8 source contract
#   TestRetiredSubcategoriesPlaceholder   — D8 retired-placeholder contract
#   TestTupleParseBackConvention          — D8 delimiter convention round-trip
#   TestTupleSelectorDeterminism          — D8 determinism extension
#
# These tests enforce the ADR-026 D8 contract: the join-resolver must derive
# tuples from taxonomy nesting (categories[].subcategory[]) and render them as
# "<category-id>: <subcategory-id>" options. They will fail until D8 is
# implemented; that is intentional — they are the specification.
# ===========================================================================


# The authoritative tuple list per ADR-026 Amendment D8, derived from
# components.yaml categories[].subcategory[] nesting (taxonomy declaration order).
# Tuple format: "<category-id>: <subcategory-id>" with ": " delimiter.
_EXPECTED_TUPLES: list[str] = [
    "componentsInfrastructure: componentsData",
    "componentsInfrastructure: componentsModelDeployment",
    "componentsInfrastructure: componentsRegistries",
    "componentsInfrastructure: componentsIdentity",
    "componentsModel: componentsModelTraining",
    "componentsModel: componentsModelCore",
    "componentsModel: componentsOrchestration",
    "componentsApplication: componentsAgent",
    "componentsApplication: componentsApplicationCore",
    "componentsExternalTools: componentsToolNetworkControls",
    "componentsExternalTools: componentsToolInvocationPath",
]

# An example of an invalid pair — this category/subcategory crossing is not in
# the taxonomy and must be absent from any rendered output.
_INVALID_PAIR_EXAMPLE = "componentsApplication: componentsData"


class TestTupleSelectorRendering:
    """
    Asserts that {{COMPONENT_CATEGORY_SUBCATEGORY}} expands to exactly the
    eleven valid taxonomy tuples formatted as "<category-id>: <subcategory-id>",
    in taxonomy declaration order (ADR-026 D8; count includes ADR-030 D1's
    componentsExternalTools category and ADR-030 D2's componentsIdentity subcategory).
    """

    def test_component_category_subcategory_placeholder_is_registered(self, repo_root: Path) -> None:
        """
        Test that COMPONENT_CATEGORY_SUBCATEGORY is declared in PLACEHOLDER_MAPPINGS.

        Given: TemplateRenderer.PLACEHOLDER_MAPPINGS
        When: The key set is inspected
        Then: 'COMPONENT_CATEGORY_SUBCATEGORY' is present

        ADR-026 D8: the single PLACEHOLDER_MAPPINGS registry must contain
        the new join-resolver entry.
        """
        import sys

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.template_renderer import TemplateRenderer

        assert "COMPONENT_CATEGORY_SUBCATEGORY" in TemplateRenderer.PLACEHOLDER_MAPPINGS, (
            "COMPONENT_CATEGORY_SUBCATEGORY must be registered in PLACEHOLDER_MAPPINGS "
            "(ADR-026 D8 single-registry contract). "
            "Implementation has not added the placeholder yet."
        )

    def test_component_subcategories_placeholder_is_retired(self, repo_root: Path) -> None:
        """
        Test that COMPONENT_SUBCATEGORIES is no longer in PLACEHOLDER_MAPPINGS.

        Given: TemplateRenderer.PLACEHOLDER_MAPPINGS
        When: The key set is inspected
        Then: 'COMPONENT_SUBCATEGORIES' is absent

        ADR-026 Amendment D8 retires the flat seven-value dropdown in favour
        of the join-resolver COMPONENT_CATEGORY_SUBCATEGORY. Keeping both
        would mean templates could reference the retired placeholder.
        """
        import sys

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.template_renderer import TemplateRenderer

        assert "COMPONENT_SUBCATEGORIES" not in TemplateRenderer.PLACEHOLDER_MAPPINGS, (
            "COMPONENT_SUBCATEGORIES must be RETIRED from PLACEHOLDER_MAPPINGS "
            "(ADR-026 Amendment D8 supersedes D3's flat-dropdown interim). "
            "Implementation has not removed the old placeholder yet."
        )

    def test_expand_placeholder_yields_exactly_eleven_tuples(self, repo_root: Path) -> None:
        """
        Test that expanding {{COMPONENT_CATEGORY_SUBCATEGORY}} produces exactly
        eleven dropdown option lines that parse as strings.

        Given: A template containing {{COMPONENT_CATEGORY_SUBCATEGORY}} and
               a renderer backed by the real schemas and components.yaml
        When: expand_placeholders() is called for entity_type='components'
        Then: YAML-parsing the option lines yields one string per expected tuple,
              each matching a tuple from _EXPECTED_TUPLES.

        ADR-026 D8: eleven valid pairings (eight legacy + two added by ADR-030
        D1's componentsExternalTools category + one added by ADR-030 D2's
        componentsIdentity subcategory), rendered as YAML-quoted strings so
        that GitHub's check-jsonschema accepts the dropdown options block.
        Options containing ': ' must be quoted; unquoted they parse as dicts
        and fail vendor.github-issue-forms validation.
        """
        import sys

        import yaml as pyyaml

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.schema_parser import SchemaParser
        from issue_template_generator.template_renderer import TemplateRenderer

        schema_dir = repo_root / "risk-map" / "schemas"
        yaml_dir = repo_root / "risk-map" / "yaml"
        frameworks_path = yaml_dir / "frameworks.yaml"

        parser = SchemaParser(schema_dir, yaml_data_dir=yaml_dir)
        with open(frameworks_path) as fh:
            frameworks_data = pyyaml.safe_load(fh)

        renderer = TemplateRenderer(parser, frameworks_data)

        template = "      options:\n        {{COMPONENT_CATEGORY_SUBCATEGORY}}"
        result = renderer.expand_placeholders(template, "components")

        # Collect raw option lines (lines starting with "- " after stripping).
        # We need at least some lines to make the YAML-parse meaningful.
        raw_option_lines = [line.strip() for line in result.splitlines() if line.strip().startswith("- ")]
        assert len(raw_option_lines) == len(_EXPECTED_TUPLES), (
            f"Expected exactly {len(_EXPECTED_TUPLES)} option lines (one per valid pair in the taxonomy); "
            f"got {len(raw_option_lines)}: {raw_option_lines}"
        )

        # Parse the option lines as a YAML list fragment to extract string values.
        # Correct (quoted) output: "- \"category: subcategory\"" → str
        # Broken (unquoted) output: "- category: subcategory" → dict
        options_yaml = "\n".join(raw_option_lines)
        parsed_options = pyyaml.safe_load(options_yaml)

        assert isinstance(parsed_options, list), (
            f"Options block did not parse as a YAML list. Got: {type(parsed_options)}"
        )
        assert all(isinstance(opt, str) for opt in parsed_options), (
            "All options must parse as strings (not dicts). "
            "Options containing ': ' must be YAML-quoted: - \"category: subcategory\". "
            f"Got types: {[type(opt).__name__ for opt in parsed_options]} for: {parsed_options}"
        )
        assert len(parsed_options) == len(_EXPECTED_TUPLES), (
            f"Expected exactly {len(_EXPECTED_TUPLES)} string options; got {len(parsed_options)}: {parsed_options}"
        )

    def test_expand_placeholder_yields_all_expected_tuples(self, repo_root: Path) -> None:
        """
        Test that the rendered output contains every expected tuple.

        Given: A template with {{COMPONENT_CATEGORY_SUBCATEGORY}}
        When: expand_placeholders() renders it for entity_type='components'
        Then: Every string in _EXPECTED_TUPLES is present in the rendered text

        ADR-026 D8: all seven valid pairings must appear as dropdown options.
        """
        import sys

        import yaml as pyyaml

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.schema_parser import SchemaParser
        from issue_template_generator.template_renderer import TemplateRenderer

        schema_dir = repo_root / "risk-map" / "schemas"
        yaml_dir = repo_root / "risk-map" / "yaml"
        frameworks_path = yaml_dir / "frameworks.yaml"

        parser = SchemaParser(schema_dir, yaml_data_dir=yaml_dir)
        with open(frameworks_path) as fh:
            frameworks_data = pyyaml.safe_load(fh)

        renderer = TemplateRenderer(parser, frameworks_data)
        template = "      options:\n        {{COMPONENT_CATEGORY_SUBCATEGORY}}"
        result = renderer.expand_placeholders(template, "components")

        for expected in _EXPECTED_TUPLES:
            assert expected in result, (
                f"Expected tuple {expected!r} not found in rendered output. Full output:\n{result}"
            )

    def test_expand_placeholder_does_not_contain_invalid_pair(self, repo_root: Path) -> None:
        """
        Test that the rendered output does NOT contain any invalid pair.

        Given: A template with {{COMPONENT_CATEGORY_SUBCATEGORY}}
        When: expand_placeholders() renders it for entity_type='components'
        Then: The example invalid pair 'componentsApplication: componentsData'
              is absent from the rendered output

        ADR-026 D8: the join-resolver derives tuples from taxonomy nesting, so
        no cross-category pair can appear. Name-prefix heuristics would wrongly
        assign componentsData to Application; the taxonomy nesting correctly
        places it under Infrastructure.
        """
        import sys

        import yaml as pyyaml

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.schema_parser import SchemaParser
        from issue_template_generator.template_renderer import TemplateRenderer

        schema_dir = repo_root / "risk-map" / "schemas"
        yaml_dir = repo_root / "risk-map" / "yaml"
        frameworks_path = yaml_dir / "frameworks.yaml"

        parser = SchemaParser(schema_dir, yaml_data_dir=yaml_dir)
        with open(frameworks_path) as fh:
            frameworks_data = pyyaml.safe_load(fh)

        renderer = TemplateRenderer(parser, frameworks_data)
        template = "      options:\n        {{COMPONENT_CATEGORY_SUBCATEGORY}}"
        result = renderer.expand_placeholders(template, "components")

        # Guard: pre-impl expand_placeholders returns the raw placeholder unchanged,
        # so the absent-pair assertion below would be vacuously True.
        # This guard fails when the placeholder is not yet expanded, making the
        # test fail for the right reason rather than passing silently.
        assert "{{COMPONENT_CATEGORY_SUBCATEGORY}}" not in result, (
            "Placeholder not expanded — invalid-pair check would be vacuous."
        )

        assert _INVALID_PAIR_EXAMPLE not in result, (
            f"Invalid pair {_INVALID_PAIR_EXAMPLE!r} must NOT appear in rendered output. "
            f"The join-resolver must derive tuples from taxonomy nesting, not name prefixes. "
            f"Full output:\n{result}"
        )

    def test_expand_placeholder_yields_tuples_in_taxonomy_declaration_order(self, repo_root: Path) -> None:
        """
        Test that the rendered tuples appear in taxonomy declaration order,
        parsed as YAML strings.

        Given: A template with {{COMPONENT_CATEGORY_SUBCATEGORY}}
        When: expand_placeholders() renders it
        Then: YAML-parsing the option lines yields a list of strings that
              equals _EXPECTED_TUPLES in exact order.

        ADR-026 D8 requires deterministic order derived from
        categories[].subcategory[] top-to-bottom in components.yaml.
        Options must be YAML-quoted strings; unquoted ': ' lines parse as
        YAML dicts and would not match string comparison here.

        This test will FAIL against the current unquoted production renderer
        (options parse as dicts) for the right reason.
        """
        import sys

        import yaml as pyyaml

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.schema_parser import SchemaParser
        from issue_template_generator.template_renderer import TemplateRenderer

        schema_dir = repo_root / "risk-map" / "schemas"
        yaml_dir = repo_root / "risk-map" / "yaml"
        frameworks_path = yaml_dir / "frameworks.yaml"

        parser = SchemaParser(schema_dir, yaml_data_dir=yaml_dir)
        with open(frameworks_path) as fh:
            frameworks_data = pyyaml.safe_load(fh)

        renderer = TemplateRenderer(parser, frameworks_data)
        template = "      options:\n        {{COMPONENT_CATEGORY_SUBCATEGORY}}"
        result = renderer.expand_placeholders(template, "components")

        # Collect raw option lines, then YAML-parse them to get string values.
        # Correct rendering quotes options so they parse as strings.
        # Broken (unquoted) rendering produces dicts; the assertEqual below
        # catches that mismatch for the right reason.
        raw_option_lines = [line.strip() for line in result.splitlines() if line.strip().startswith("- ")]
        # Non-vacuous guard: the placeholder must have expanded to one line per pair.
        assert len(raw_option_lines) == len(_EXPECTED_TUPLES), (
            f"Expected {len(_EXPECTED_TUPLES)} option lines; got {len(raw_option_lines)}: {raw_option_lines}"
        )

        options_yaml = "\n".join(raw_option_lines)
        parsed_options = pyyaml.safe_load(options_yaml)

        assert parsed_options == _EXPECTED_TUPLES, (
            f"Tuples must appear in taxonomy declaration order as YAML strings "
            f"(ADR-026 D8 determinism). "
            f"Expected: {_EXPECTED_TUPLES}. "
            f"Got: {parsed_options}. "
            f"If options are dicts the renderer is emitting unquoted '- key: value' lines "
            f'— they must be quoted: - "category: subcategory".'
        )


class TestTaxonomyDerivedNotInstanceDerived:
    """
    Asserts that the tuple list is derived from categories[].subcategory[]
    nesting (taxonomy) rather than from component instances (components[])
    or from subcategory ID name-prefixes (ADR-026 D9).
    """

    def test_zero_instance_subcategory_still_renders_as_tuple(self, repo_root: Path, tmp_path: Path) -> None:
        """
        Test that a subcategory with zero component instances still appears
        as a dropdown option.

        Given: A temporary components.yaml where a subcategory has no
               component instances using it (but IS declared in the taxonomy
               nesting under a category)
        When:  The renderer expands {{COMPONENT_CATEGORY_SUBCATEGORY}}
        Then:  The subcategory's tuple still appears in the rendered output

        This proves the resolver reads categories[].subcategory[] nesting, not
        components[] instances. A zero-instance subcategory would vanish if the
        resolver counted instance references, but must appear if it reads the
        taxonomy. ADR-026 D9 explicit citation of this contract.
        """
        import sys

        import yaml as pyyaml

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))

        # Build a minimal components.yaml where componentsNewSub is declared in
        # the taxonomy but has ZERO component instances referencing it.
        minimal_components_yaml = tmp_path / "components.yaml"
        minimal_components_data = {
            "id": "components",
            "title": "Test components",
            "description": ["Test."],
            "categories": [
                {
                    "id": "componentsInfrastructure",
                    "title": "Infrastructure",
                    "subcategory": [
                        {"id": "componentsData", "title": "Data"},
                        # componentsNewSub: declared in taxonomy, zero instances
                        {"id": "componentsNewSub", "title": "New Sub (zero instances)"},
                    ],
                }
            ],
            "components": [
                # Only one component, using componentsData — componentsNewSub has zero instances
                {
                    "id": "componentDataSources",
                    "title": "Data Sources",
                    "description": ["Test."],
                    "category": "componentsInfrastructure",
                    "subcategory": "componentsData",
                    "edges": {"to": ["componentDataSources"]},
                }
            ],
        }
        with open(minimal_components_yaml, "w") as fh:
            pyyaml.dump(minimal_components_data, fh)

        # Build a minimal schema directory with just enough to parse.
        minimal_schema_dir = tmp_path / "schemas"
        minimal_schema_dir.mkdir()

        # Copy the real schema files we need (components + its dependencies).
        import shutil

        real_schema_dir = repo_root / "risk-map" / "schemas"
        for schema_file in real_schema_dir.glob("*.json"):
            shutil.copy(schema_file, minimal_schema_dir / schema_file.name)

        from issue_template_generator.schema_parser import SchemaParser
        from issue_template_generator.template_renderer import TemplateRenderer

        parser = SchemaParser(minimal_schema_dir, yaml_data_dir=tmp_path)

        # Use real frameworks data (the join-resolver needs it for context).
        with open(repo_root / "risk-map" / "yaml" / "frameworks.yaml") as fh:
            frameworks_data = pyyaml.safe_load(fh)

        renderer = TemplateRenderer(parser, frameworks_data)
        template = "      options:\n        {{COMPONENT_CATEGORY_SUBCATEGORY}}"
        result = renderer.expand_placeholders(template, "components")

        assert "componentsInfrastructure: componentsNewSub" in result, (
            "A subcategory declared in categories[].subcategory[] with zero component "
            "instances must still appear as a tuple option. "
            "The resolver must read taxonomy nesting, not instance counts. "
            f"Full output:\n{result}"
        )


class TestRetiredSubcategoriesPlaceholder:
    """
    Asserts that {{COMPONENT_SUBCATEGORIES}} is retired from the template
    source and replaced by {{COMPONENT_CATEGORY_SUBCATEGORY}} in both the
    source template and the generated output (ADR-026 D8).
    """

    def test_component_subcategories_not_in_template_source(self, repo_root: Path) -> None:
        """
        Test that scripts/TEMPLATES/new_component.template.yml no longer
        references {{COMPONENT_SUBCATEGORIES}}.

        Given: The new_component.template.yml source file
        When: Its content is read
        Then: The string '{{COMPONENT_SUBCATEGORIES}}' is absent

        ADR-026 Amendment D8 retires the flat-dropdown placeholder. The source
        file must not reference it after the implementation phase.
        """
        template_path = repo_root / "scripts" / "TEMPLATES" / "new_component.template.yml"
        assert template_path.exists(), (
            f"Source template not found: {template_path}. Cannot check for retired placeholder."
        )
        content = template_path.read_text(encoding="utf-8")
        assert "{{COMPONENT_SUBCATEGORIES}}" not in content, (
            "{{COMPONENT_SUBCATEGORIES}} is present in new_component.template.yml but "
            "was retired by ADR-026 Amendment D8. "
            "The implementation must replace it with {{COMPONENT_CATEGORY_SUBCATEGORY}}."
        )

    def test_component_category_subcategory_in_template_source(self, repo_root: Path) -> None:
        """
        Test that scripts/TEMPLATES/new_component.template.yml references
        {{COMPONENT_CATEGORY_SUBCATEGORY}}.

        Given: The new_component.template.yml source file
        When: Its content is read
        Then: The string '{{COMPONENT_CATEGORY_SUBCATEGORY}}' is present

        ADR-026 Amendment D8 requires the new join-resolver placeholder.
        """
        template_path = repo_root / "scripts" / "TEMPLATES" / "new_component.template.yml"
        assert template_path.exists(), f"Source template not found: {template_path}."
        content = template_path.read_text(encoding="utf-8")
        assert "{{COMPONENT_CATEGORY_SUBCATEGORY}}" in content, (
            "{{COMPONENT_CATEGORY_SUBCATEGORY}} must be present in new_component.template.yml "
            "(ADR-026 Amendment D8 replaces the retired flat-dropdown placeholder). "
            "The implementation must add the new placeholder."
        )

    def test_generated_new_component_contains_combined_dropdown(self, repo_root: Path, tmp_path: Path) -> None:
        """
        Test that the generated .github/ISSUE_TEMPLATE/new_component.yml
        contains the seven combined-category tuples and no standalone
        seven-subcategory-only dropdown.

        Given: The new_component.template.yml source with {{COMPONENT_CATEGORY_SUBCATEGORY}}
        When: The generator renders it
        Then: The output YAML contains all seven "category: subcategory" tuple
              strings and does NOT contain any of the bare subcategory IDs as
              isolated dropdown options (which would indicate the retired
              flat dropdown is still present)

        ADR-026 D8: one combined dropdown replaces the two-dropdown design.
        """
        import sys

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.generator import IssueTemplateGenerator

        # Render into a temp dir to avoid touching the real repo.
        gen = IssueTemplateGenerator(repo_root)
        gen.output_dir = tmp_path
        output_path = gen.generate_template("new_component", dry_run=False)

        assert isinstance(output_path, Path), (
            "generate_template('new_component') must return a Path (not a dry-run diff string)"
        )

        rendered = output_path.read_text(encoding="utf-8")

        # All expected tuples must appear in the rendered output.
        for expected_tuple in _EXPECTED_TUPLES:
            assert expected_tuple in rendered, (
                f"Generated new_component.yml must contain tuple {expected_tuple!r}. "
                f"The combined dropdown is missing from the output."
            )

        # The retired flat-dropdown bare subcategory IDs must NOT appear as
        # isolated options. A bare line "- componentsData" (with nothing after)
        # is the signature of the old flat dropdown. The new format has
        # "- componentsInfrastructure: componentsData".
        # We check that subcategory IDs only appear in the joined form.
        bare_subcategory_ids = [
            "componentsModelTraining",
            "componentsData",
            "componentsAgent",
            "componentsOrchestration",
            "componentsModelDeployment",
            "componentsModelCore",
            "componentsApplicationCore",
        ]
        for sub_id in bare_subcategory_ids:
            # A bare "- <sub_id>" line (possibly indented, with no trailing colon-space)
            # indicates the retired flat dropdown is still present.
            bare_option_pattern = f"- {sub_id}\n"
            assert bare_option_pattern not in rendered, (
                f"Generated new_component.yml contains a bare subcategory option "
                f"'- {sub_id}', which is the signature of the retired "
                f"{{{{COMPONENT_SUBCATEGORIES}}}} flat dropdown. "
                f"The implementation must replace it with the combined tuple dropdown."
            )


class TestTupleParseBackConvention:
    """
    Asserts that the ': ' delimiter convention documented in ADR-026 D8 allows
    each rendered option to be split into exactly (category-id, subcategory-id).

    This tests the documented convention for issue → YAML transcription
    ("splitting an option on ': ' yields the category and subcategory field
    values directly"). No parser module is built; this is a string-split assertion.
    """

    def test_each_rendered_tuple_splits_into_valid_category_and_subcategory(self, repo_root: Path) -> None:
        """
        Test that each YAML-parsed option string splits on ': ' into a valid
        (category-id, subcategory-id) pair per the taxonomy.

        The options must be YAML-quoted strings so that they parse as strings,
        not as YAML mappings. After YAML-parse, each string value is split on
        ': ' (the ADR-026 D8 documented delimiter) to recover the two IDs.

        Given: The rendered {{COMPONENT_CATEGORY_SUBCATEGORY}} output
        When: Option lines are YAML-parsed into strings, then split on ': '
        Then: Each split produces exactly two parts — a known category ID and
              its corresponding valid subcategory ID

        ADR-026 D8: "Splitting an option on ': ' yields the category and
        subcategory field values directly."

        This test will FAIL against the current unquoted production renderer
        because options parse as dicts (not strings), so the split never runs.
        """
        import sys

        import yaml as pyyaml

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.schema_parser import SchemaParser
        from issue_template_generator.template_renderer import TemplateRenderer

        schema_dir = repo_root / "risk-map" / "schemas"
        yaml_dir = repo_root / "risk-map" / "yaml"
        components_path = yaml_dir / "components.yaml"
        frameworks_path = yaml_dir / "frameworks.yaml"

        # Build the authoritative taxonomy map from components.yaml directly.
        with open(components_path) as fh:
            components_data = pyyaml.safe_load(fh)

        taxonomy: dict[str, set[str]] = {}
        for cat in components_data.get("categories", []):
            cat_id = cat["id"]
            taxonomy[cat_id] = {sub["id"] for sub in cat.get("subcategory", [])}

        parser = SchemaParser(schema_dir, yaml_data_dir=yaml_dir)
        with open(frameworks_path) as fh:
            frameworks_data = pyyaml.safe_load(fh)

        renderer = TemplateRenderer(parser, frameworks_data)
        template = "      options:\n        {{COMPONENT_CATEGORY_SUBCATEGORY}}"
        result = renderer.expand_placeholders(template, "components")

        # Collect raw option lines and YAML-parse them to get string values.
        raw_option_lines = [line.strip() for line in result.splitlines() if line.strip().startswith("- ")]

        # Non-vacuous guard: the placeholder must expand to one line per pair.
        assert len(raw_option_lines) == len(_EXPECTED_TUPLES), (
            f"Expected {len(_EXPECTED_TUPLES)} options (one per valid pair, ADR-026 D8); "
            f"got {len(raw_option_lines)}. If 0 the placeholder was not expanded."
        )

        options_yaml = "\n".join(raw_option_lines)
        option_strings = pyyaml.safe_load(options_yaml)

        # All options must be strings. If they are dicts the renderer emitted
        # unquoted 'key: value' lines; the string-type assertion fails with
        # a clear message pointing to the quoting fix needed.
        assert isinstance(option_strings, list), f"Options did not parse as a YAML list: {type(option_strings)}"
        assert all(isinstance(opt, str) for opt in option_strings), (
            "All options must parse as strings (not dicts). "
            "Options containing ': ' must be YAML-quoted: - \"category: subcategory\". "
            f"Got types: {[type(opt).__name__ for opt in option_strings]}"
        )

        for option in option_strings:
            parts = option.split(": ")
            assert len(parts) == 2, (
                f"Option {option!r} must split into exactly 2 parts on ': ' "
                f"(the documented ADR-026 D8 delimiter convention); got {len(parts)} parts."
            )
            category_id, subcategory_id = parts
            assert category_id in taxonomy, (
                f"Option {option!r}: category part {category_id!r} is not a known category ID. "
                f"Known categories: {sorted(taxonomy.keys())}"
            )
            assert subcategory_id in taxonomy[category_id], (
                f"Option {option!r}: subcategory {subcategory_id!r} is not valid for "
                f"category {category_id!r}. Valid subcategories: {sorted(taxonomy[category_id])}"
            )

    def test_no_option_contains_ambiguous_delimiter(self, repo_root: Path) -> None:
        """
        Test that no rendered option string contains more than one ': ' separator,
        which would make the split-on-': ' convention ambiguous.

        Options are YAML-parsed first (requiring quoting); the resulting string
        values are then checked for exactly one ': ' delimiter.

        Given: The rendered {{COMPONENT_CATEGORY_SUBCATEGORY}} output
        When: Option lines are YAML-parsed into strings, then split on ': '
        Then: Every split yields exactly 2 parts (exactly one ': ' per option)

        This guards against future subcategory or category IDs containing ': '.
        (Option format is ID:ID; IDs are camelCase without punctuation, so this
        should always pass; it is a canary assertion.)

        This test will FAIL against the current unquoted production renderer
        because options parse as dicts (not strings), so the string-type
        assertion fails for the right reason.
        """
        import sys

        import yaml as pyyaml

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.schema_parser import SchemaParser
        from issue_template_generator.template_renderer import TemplateRenderer

        schema_dir = repo_root / "risk-map" / "schemas"
        yaml_dir = repo_root / "risk-map" / "yaml"

        parser = SchemaParser(schema_dir, yaml_data_dir=yaml_dir)
        with open(yaml_dir / "frameworks.yaml") as fh:
            frameworks_data = pyyaml.safe_load(fh)

        renderer = TemplateRenderer(parser, frameworks_data)
        template = "      options:\n        {{COMPONENT_CATEGORY_SUBCATEGORY}}"
        result = renderer.expand_placeholders(template, "components")

        raw_option_lines = [line.strip() for line in result.splitlines() if line.strip().startswith("- ")]

        # Non-vacuous guard: placeholder must expand to one line per pair.
        assert len(raw_option_lines) == len(_EXPECTED_TUPLES), (
            f"Expected {len(_EXPECTED_TUPLES)} options (one per valid pair, ADR-026 D8); "
            f"got {len(raw_option_lines)}. If 0 the placeholder was not expanded."
        )

        options_yaml = "\n".join(raw_option_lines)
        option_strings = pyyaml.safe_load(options_yaml)

        # All options must be strings. Unquoted '- key: value' lines parse as dicts.
        assert isinstance(option_strings, list), f"Options did not parse as a YAML list: {type(option_strings)}"
        assert all(isinstance(opt, str) for opt in option_strings), (
            "All options must parse as strings (not dicts). "
            "Options containing ': ' must be YAML-quoted: - \"category: subcategory\". "
            f"Got types: {[type(opt).__name__ for opt in option_strings]}"
        )

        for option in option_strings:
            parts = option.split(": ")
            assert len(parts) == 2, (
                f"Option {option!r} contains more than one ': ' delimiter, "
                f"making the split-on-': ' convention (ADR-026 D8) ambiguous. "
                f"Option IDs must not contain the sequence ': '."
            )


class TestTupleSelectorDeterminism:
    """
    Extends the existing determinism contract to cover the
    {{COMPONENT_CATEGORY_SUBCATEGORY}} placeholder (ADR-026 D8).

    The test is state-independent: it renders the template twice into a
    tmp_path output directory (dry_run=False) so it does not depend on
    whether .github/ISSUE_TEMPLATE/new_component.yml is already current.
    """

    def test_new_component_renders_deterministically_with_tuple_selector(
        self, repo_root: Path, tmp_path: Path
    ) -> None:
        """
        Test that new_component renders byte-identically on two successive calls
        into isolated tmp directories.

        Given: new_component.template.yml containing {{COMPONENT_CATEGORY_SUBCATEGORY}}
        When: generate_template('new_component', dry_run=False) is called twice,
              each time into a fresh tmp subdirectory
        Then:
          - Both rendered outputs are byte-identical
          - At least one expected tuple string appears in the rendered content
            (non-vacuous guard: the join-resolver must have run)

        This extends the per-source determinism contract from
        TestPerSourceRegenerationDeterminism to explicitly cover the
        tuple-selector placeholder (ADR-026 D8) in a state-independent way.
        The test does not diff against .github/ISSUE_TEMPLATE/new_component.yml,
        so it passes regardless of whether the committed file is stale or current.
        """
        import sys

        sys.path.insert(0, str(repo_root / "scripts" / "hooks"))
        from issue_template_generator.generator import IssueTemplateGenerator

        template_file = repo_root / "scripts" / "TEMPLATES" / "new_component.template.yml"
        assert template_file.exists(), (
            "new_component.template.yml must exist for this test (prerequisite for D8 coverage)."
        )

        # First render into tmp_path/render_a/
        out_dir_a = tmp_path / "render_a"
        out_dir_a.mkdir()
        gen_a = IssueTemplateGenerator(repo_root)
        gen_a.output_dir = out_dir_a
        path_a = gen_a.generate_template("new_component", dry_run=False)
        assert isinstance(path_a, Path), (
            "generate_template('new_component') must return a Path when dry_run=False."
        )
        content_a = path_a.read_text(encoding="utf-8")

        # Second render into tmp_path/render_b/
        out_dir_b = tmp_path / "render_b"
        out_dir_b.mkdir()
        gen_b = IssueTemplateGenerator(repo_root)
        gen_b.output_dir = out_dir_b
        path_b = gen_b.generate_template("new_component", dry_run=False)
        assert isinstance(path_b, Path), (
            "generate_template('new_component') must return a Path on the second call."
        )
        content_b = path_b.read_text(encoding="utf-8")

        # Non-vacuous guard: the join-resolver must have run and produced
        # at least one expected tuple in the output.
        assert any(t in content_a for t in _EXPECTED_TUPLES), (
            "Determinism check is non-vacuous guard: content_a contains none of the "
            "expected (category: subcategory) tuples. "
            "The template source must reference {{COMPONENT_CATEGORY_SUBCATEGORY}} and "
            "the join-resolver must be implemented (ADR-026 D8)."
        )

        assert content_a == content_b, (
            "new_component renders non-deterministically with {{COMPONENT_CATEGORY_SUBCATEGORY}}. "
            "Two successive renders into isolated output dirs produced different content. "
            "The join-resolver must produce stable output on each call (ADR-026 D8 determinism)."
        )
