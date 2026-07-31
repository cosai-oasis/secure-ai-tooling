#!/usr/bin/env python3
"""
Tests for the real-corpus CI guard on component-category styling.

ADR-030 (docs/adr/030-agentic-component-model.md), Consequences:

  "mermaid-styles.yaml needs a componentsExternalTools style or the new category
  renders unstyled; a real-corpus guard should fail CI on a styleless
  category."

And "Migration sequencing" step 4 (Consumer wiring, fail-loud): a real-corpus
guard so an unstyled category fails CI rather than rendering silently.

An unstyled category is a real, observable break: every generated diagram
renders it without its fill/stroke definitions.

Scope note — no ownership half
------------------------------
An earlier revision of this guard also derived a "persona owns this category"
check from the controls/components graph, citing ADR-021. That requirement is
not in ADR-021, which decides the opposite: personas deliberately do not
participate in the per-category enums that risks and controls carry
(ADR-021 line 50), and personas.yaml has no category partition at all
(line 255). No schema field records category ownership because ADR-021 ruled
one out, which is why the derived check was near-tautological — any control
with any persona referencing any component in the category satisfied it. The
ownership half and its tests were removed; the ADR text asserting it carries
an erratum. Only the style half, which is well-founded, remains.

Symbol contract
----------------
Pure-function tests import `check_category_style_coverage` from
`riskmap_validator.validator`, implemented with this signature:

    check_category_style_coverage(
        schema_categories: set[str],
        styled_categories: set[str],
    ) -> list[str]

One warning per category in `schema_categories` that is absent from
`styled_categories`. Returns a list of human-readable warning strings; empty
when every schema category is styled. Order is not asserted by these tests.

CLI wiring: validate_riskmap.py runs this as a warn-only check following the
existing controls↔components-mirror / category-subcategory-nesting pattern
(same --block promotion, same print-label convention). Tests below assert on
a label containing "Category style" appearing in stdout — see TestCLIWiring
for the exact substrings asserted.

Test structure
--------------
1. TestCheckCategoryStyleCoverage — pure-function tests.
2. TestCLIWiring — subprocess end-to-end tests against validate_riskmap.py.
3. TestSchemaCategoryResolution — cwd-relative schema-category resolution.
4. TestFlattenedModuleLayout — the CI-flattened module layout.
5. TestSchemaUnavailableFailsLoud — an unreadable schema is never a pass.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from conftest import build_mermaid_styles, write_mermaid_styles  # noqa: E402

try:
    from riskmap_validator.validator import check_category_style_coverage  # noqa: E402

    _STYLE_IMPORT_ERROR: ImportError | None = None
except ImportError as _e:
    check_category_style_coverage = None  # type: ignore[assignment]
    _STYLE_IMPORT_ERROR = _e

_SCRIPT = Path(__file__).parent.parent / "validate_riskmap.py"
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


@pytest.fixture
def style_fn():
    """Return check_category_style_coverage, or raise ImportError."""
    if _STYLE_IMPORT_ERROR is not None:
        raise _STYLE_IMPORT_ERROR
    return check_category_style_coverage


# ===========================================================================
# 1. Pure-function tests
# ===========================================================================


class TestCheckCategoryStyleCoverage:
    """Pure-function tests for check_category_style_coverage()."""

    def test_clean_all_styled_returns_empty_list(self, style_fn):
        """
        Given: one schema category that has a styling entry
        When: check_category_style_coverage() is called
        Then: returns []
        """
        result = style_fn({"componentsData"}, {"componentsData"})
        assert result == [], f"Expected no warnings on clean input; got: {result}"

    def test_missing_style_produces_warning_naming_category(self, style_fn):
        """
        Given: a schema category with no styling entry
        When: check_category_style_coverage() is called
        Then: exactly one warning naming the category and mentioning styling
        """
        result = style_fn({"componentsData"}, set())
        assert len(result) == 1, f"Expected exactly 1 warning; got: {result}"
        assert "componentsData" in result[0]
        assert "styl" in result[0].lower(), f"Expected warning to mention styling; got: {result[0]!r}"

    def test_extra_styled_categories_are_not_warned_about(self, style_fn):
        """
        Given: a styling config carrying a category the schema does not declare
        When: check_category_style_coverage() is called
        Then: returns [] — the direction is schema → styling only

        A styling entry the schema no longer enumerates is dead configuration,
        not a rendering break, so it is out of this guard's scope.
        """
        result = style_fn({"componentsData"}, {"componentsData", "componentsRetired"})
        assert result == [], f"Expected no warning for an extra styling entry; got: {result}"

    def test_multiple_categories_evaluated_independently(self, style_fn):
        """
        Given: three schema categories, one of them unstyled
        When: check_category_style_coverage() is called
        Then: exactly the unstyled one is named; the styled ones are not
        """
        schema_categories = {"componentsClean", "componentsAlsoClean", "componentsNoStyle"}
        styled_categories = {"componentsClean", "componentsAlsoClean"}
        result = style_fn(schema_categories, styled_categories)

        combined = " ".join(result)
        assert "componentsNoStyle" in combined, f"Expected componentsNoStyle warning; got: {result}"
        assert "componentsClean" not in combined, f"Styled category should not be warned about; got: {result}"
        assert "componentsAlsoClean" not in combined, f"Styled category should not be warned about; got: {result}"

    def test_empty_schema_categories_is_a_failure_not_a_pass(self, style_fn):
        """
        Given: schema_categories = set()
        When: check_category_style_coverage() is called
        Then: returns a warning — an empty category set is never a clean result

        There is no corpus in which zero component categories is correct, so
        an empty schema_categories set means the caller failed to read the
        schema. Returning [] there makes the guard report success while
        checking nothing: the per-category comprehension iterates zero times,
        so no warning can ever be produced no matter how broken the corpus is.
        Every category-specific assertion in this class would still pass
        against an implementation that had been silently reduced to a no-op.
        The caller (_get_schema_categories) fails loud on an unreadable
        schema; this is the second, independent layer of that contract, so a
        future caller that reintroduces a degrade-to-empty path cannot
        resurrect the vacuous pass.
        """
        result = style_fn(set(), set())
        assert len(result) == 1, (
            f"Expected exactly 1 warning for an empty schema category set — a vacuous "
            f"pass is the failure mode this guard exists to prevent; got: {result}"
        )
        assert "categor" in result[0].lower(), (
            f"Expected the warning to name the empty category set; got: {result[0]!r}"
        )

    def test_return_type_is_list_of_str(self, style_fn):
        """
        Given: a dirty input
        When: check_category_style_coverage() is called
        Then: returns a list, and every element is a str
        """
        result = style_fn({"componentsData"}, set())
        assert isinstance(result, list)
        assert all(isinstance(w, str) for w in result)

    def test_live_corpus_every_category_is_styled(self, style_fn):
        """
        Given: the REAL components.schema.json category enum and the REAL
               mermaid-styles.yaml styled-category keys
        When: check_category_style_coverage() is called
        Then: returns [] — every category in the schema enum is styled

        Forward guard: both inputs are read from the live corpus, so a
        category added to the schema enum is picked up automatically — no
        edit to this test is needed — and it continues to assert [] as the
        CI guard's steady state.
        """
        from riskmap_validator.graphing.graph_utils import MermaidConfigLoader

        schema_path = _REPO_ROOT / "risk-map" / "schemas" / "components.schema.json"
        styles_path = _REPO_ROOT / "risk-map" / "yaml" / "mermaid-styles.yaml"

        with open(schema_path, encoding="utf-8") as fh:
            schema = json.load(fh)
        schema_categories = set(schema["definitions"]["category"]["properties"]["id"]["enum"])

        loader = MermaidConfigLoader(styles_path)
        styled_categories = set(loader.get_component_category_styles().keys())

        result = style_fn(schema_categories, styled_categories)
        assert result == [], f"Expected 0 warnings on the live corpus; got {len(result)}: {result}"


# ===========================================================================
# 2. Subprocess CLI tests — validate_riskmap.py wiring
# ===========================================================================


def _write_corpus(
    base: Path,
    components: dict[str, Any],
    controls: dict[str, Any],
    mermaid_styles: dict[str, Any] | str | None,
    write_schema: bool = True,
) -> Path:
    """Write a synthetic corpus: components/controls/risks/mermaid-styles + schema.

    The schema stub's category enum is derived from the components fixture's
    own `categories:` block, so the corpus is self-describing: the CLI reads
    the category enum from this corpus's schema (cwd-relative, like every
    other input), not from the repo the test module happens to live in.

    mermaid_styles takes a dict (written as YAML), a str (written verbatim,
    for corrupt-file cases) or None (no styles file at all).
    Set write_schema=False to exercise the schema-unavailable path.
    """
    yaml_dir = base / "risk-map" / "yaml"
    yaml_dir.mkdir(parents=True, exist_ok=True)
    (yaml_dir / "components.yaml").write_text(yaml.dump(components), encoding="utf-8")
    (yaml_dir / "controls.yaml").write_text(yaml.dump(controls), encoding="utf-8")
    (yaml_dir / "risks.yaml").write_text(yaml.dump({"risks": []}), encoding="utf-8")
    write_mermaid_styles(yaml_dir, mermaid_styles)
    if write_schema:
        category_ids = [entry["id"] for entry in components.get("categories", [])]
        _write_components_schema_stub(base, category_ids)
    return base


def _components_schema_stub(category_ids: list[str]) -> dict[str, Any]:
    """Build the minimal components.schema.json shape _get_schema_categories() reads."""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "definitions": {"category": {"properties": {"id": {"enum": sorted(category_ids)}}}},
    }


def _write_components_schema_stub(base: Path, category_ids: list[str]) -> Path:
    """Write a components.schema.json stub under base/risk-map/schemas/."""
    schemas_dir = base / "risk-map" / "schemas"
    schemas_dir.mkdir(parents=True, exist_ok=True)
    schema_path = schemas_dir / "components.schema.json"
    schema_path.write_text(json.dumps(_components_schema_stub(category_ids)), encoding="utf-8")
    return schema_path


def _flatten_module(base: Path) -> Path:
    """Reproduce validation.yml's flattened module layout under `base`.

    .github/workflows/validation.yml copies validate_riskmap.py to the repo
    root and riskmap_validator/* into a sibling riskmap_validator/ package, so
    in CI graph_utils.py sits two directory levels shallower than it does in
    the source tree. Returns the path to the flattened entry point.
    """
    entry = base / "validate_riskmap.py"
    shutil.copy(_SCRIPT, entry)
    shutil.copytree(
        _SCRIPT.parent / "riskmap_validator",
        base / "riskmap_validator",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    return entry


def _run(cwd: Path, *extra_args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), "--force", "--allow-isolated", *extra_args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )


# Minimal components covering 4 top-level categories, exercising the CLI over
# more than one category at a time. _write_corpus derives this corpus's schema
# category enum from the categories: block below, so all 4 must be styled or a
# fixture trips a warning unrelated to the scenario under test. The dirty
# styles fixture below unstyles exactly one category (componentsModel) so the
# scenario stays isolated.
#
# No edges needed — CLI tests always pass --allow-isolated. Each component
# declares a subcategory nested consistently under its category in the
# categories: block below, so the pre-existing category/subcategory nesting
# check (ADR-018 D6) stays silent and only this module's style check produces
# output.
_FOUR_CATEGORY_COMPONENTS: dict[str, Any] = {
    "components": [
        {
            "id": "compInfra",
            "title": "Infra",
            "category": "componentsInfrastructure",
            "subcategory": "componentsData",
            "edges": {},
        },
        {
            "id": "compModel",
            "title": "Model",
            "category": "componentsModel",
            "subcategory": "componentsModelTraining",
            "edges": {},
        },
        {
            "id": "compApp",
            "title": "App",
            "category": "componentsApplication",
            "subcategory": "componentsAgent",
            "edges": {},
        },
        {
            "id": "compTools",
            "title": "Tools",
            "category": "componentsExternalTools",
            "subcategory": "componentsToolInvocationPath",
            "edges": {},
        },
    ],
    "categories": [
        {
            "id": "componentsInfrastructure",
            "title": "Infrastructure",
            "subcategory": [{"id": "componentsData", "title": "Data"}],
        },
        {
            "id": "componentsModel",
            "title": "Model",
            "subcategory": [{"id": "componentsModelTraining", "title": "Model Training"}],
        },
        {
            "id": "componentsApplication",
            "title": "Application",
            "subcategory": [{"id": "componentsAgent", "title": "Agent"}],
        },
        {
            "id": "componentsExternalTools",
            "title": "Tools",
            "subcategory": [{"id": "componentsToolInvocationPath", "title": "Tool Core"}],
        },
    ],
}

# Controls referencing only components present above, so the
# controls↔components mirror check (ADR-020 D7) stays silent and only the
# style check produces output.
_FOUR_CATEGORY_CONTROLS: dict[str, Any] = {
    "controls": [
        {
            "id": "ctrlInfra",
            "title": "Infra Ctrl",
            "category": "controlsInfrastructure",
            "components": ["compInfra"],
            "risks": [],
            "personas": ["personaX"],
        },
        {
            "id": "ctrlModel",
            "title": "Model Ctrl",
            "category": "controlsModel",
            "components": ["compModel"],
            "risks": [],
            "personas": ["personaX"],
        },
        {
            "id": "ctrlApp",
            "title": "App Ctrl",
            "category": "controlsApplication",
            "components": ["compApp"],
            "risks": [],
            "personas": ["personaX"],
        },
        {
            "id": "ctrlTools",
            "title": "Tools Ctrl",
            "category": "controlsApplication",
            "components": ["compTools"],
            "risks": [],
            "personas": ["personaX"],
        },
    ]
}

# Styles all 4 real schema categories so the schema-sourced style check has no
# unrelated bystander warnings to report. Built by the shared conftest helper
# so this module's clean corpora carry a styles file that is valid against the
# real mermaid-styles.schema.json rather than an ad-hoc stub.
_FULLY_STYLED_MERMAID: dict[str, Any] = build_mermaid_styles()

# Same, but missing the componentsModel style entry — deliberately incomplete
# against the schema, which is the failure this guard reports.
_MODEL_UNSTYLED_MERMAID: dict[str, Any] = build_mermaid_styles(
    ["componentsInfrastructure", "componentsApplication", "componentsExternalTools"]
)

# A styles file that parses as YAML but is not a styles config at all. The
# loader's required-key validation rejects it, which is the "structurally
# invalid" half of the fallback case.
_STRUCTURALLY_INVALID_MERMAID_TEXT = "unexpected: shape\n"

# A styles file that does not parse as YAML at all.
_UNPARSEABLE_MERMAID_TEXT = "version: '1.0.0'\nfoundation: [unclosed\n"


class TestCLIWiring:
    """
    End-to-end tests on validate_riskmap.py.

    Every input the CLI reads here is cwd-relative and synthetic: components,
    controls, mermaid-styles, and the components.schema.json stub _write_corpus
    lays down beside them. The category ids are the real ones only so the
    fixtures read as plausible corpora; nothing in these tests depends on the
    repo the test module lives in.
    """

    def test_dirty_style_with_block_exits_1(self, tmp_path):
        """
        Given: synthetic corpus with componentsModel missing its
               mermaid-styles.yaml entry
        When: validate_riskmap.py --force --allow-isolated --block runs
        Then: exit 1 (style warning promoted to error)
        """
        _write_corpus(tmp_path, _FOUR_CATEGORY_COMPONENTS, _FOUR_CATEGORY_CONTROLS, _MODEL_UNSTYLED_MERMAID)
        result = _run(tmp_path, "--block")
        assert result.returncode == 1, (
            f"Expected exit 1 with --block on style-dirty corpus; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_clean_corpus_with_block_exits_0(self, tmp_path):
        """
        Given: synthetic corpus with all 4 real schema categories styled
        When: validate_riskmap.py --force --allow-isolated --block runs
        Then: exit 0

        Weak signal in isolation (a no-op check would also exit 0 here), but
        a necessary regression companion to the dirty tests above — see
        test_category_subcategory_nesting.py for the same acknowledged
        pattern.
        """
        _write_corpus(tmp_path, _FOUR_CATEGORY_COMPONENTS, _FOUR_CATEGORY_CONTROLS, _FULLY_STYLED_MERMAID)
        result = _run(tmp_path, "--block")
        assert result.returncode == 0, (
            f"Expected exit 0 with --block on clean corpus; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_dirty_style_no_block_exits_0_and_prints_warning_naming_category(self, tmp_path):
        """
        Given: synthetic style-dirty corpus, no --block
        When: validate_riskmap.py --force --allow-isolated runs
        Then: exit 0 (warn-only preserved) AND stdout/stderr names
              'componentsModel'

        The category-name assertion is the meaningful check here — it
        confirms the CLI actually prints the dirty category, not just that
        the exit code happens to match.
        """
        _write_corpus(tmp_path, _FOUR_CATEGORY_COMPONENTS, _FOUR_CATEGORY_CONTROLS, _MODEL_UNSTYLED_MERMAID)
        result = _run(tmp_path)
        assert result.returncode == 0, (
            f"Expected exit 0 without --block; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        combined = result.stdout + result.stderr
        assert "componentsModel" in combined, (
            f"Expected warn output naming 'componentsModel' even without --block; "
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )

    def test_live_corpus_no_block_exits_0(self):
        """
        Given: actual repo as cwd, no --block
        When: validate_riskmap.py --force --allow-isolated runs
        Then: exit 0 — the live corpus is clean
        """
        result = _run(_REPO_ROOT)
        assert result.returncode == 0, (
            f"Expected exit 0 without --block on live corpus; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_live_corpus_with_block_exits_0(self):
        """
        Given: actual repo as cwd, --block
        When: validate_riskmap.py --force --allow-isolated --block runs
        Then: exit 0 — every live category is styled, which is the guard's
              steady state
        """
        result = _run(_REPO_ROOT, "--block")
        assert result.returncode == 0, (
            f"Expected exit 0 with --block on live corpus; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    # -----------------------------------------------------------------------
    # Styles-file fallback. MermaidConfigLoader substitutes
    # _get_emergency_defaults() whenever mermaid-styles.yaml cannot be loaded,
    # and those hardcoded defaults style every real category — so a deleted or
    # unreadable styles file otherwise reads to this guard as a fully styled
    # corpus and the run reports success. Deleting a *single* category's entry
    # is caught; deleting or corrupting the whole file was not.
    # -----------------------------------------------------------------------

    def test_missing_styles_file_with_block_exits_1(self, tmp_path):
        """
        Given: a corpus with no risk-map/yaml/mermaid-styles.yaml at all
        When: validate_riskmap.py --force --allow-isolated --block runs
        Then: exit 1 — styling served from emergency defaults is not a pass
        """
        _write_corpus(tmp_path, _FOUR_CATEGORY_COMPONENTS, _FOUR_CATEGORY_CONTROLS, None)
        result = _run(tmp_path, "--block")
        assert result.returncode == 1, (
            f"Expected exit 1 with --block when mermaid-styles.yaml is missing; "
            f"got {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_missing_styles_file_does_not_print_success(self, tmp_path):
        """
        Given: the same styles-less corpus, no --block
        When: validate_riskmap.py --force --allow-isolated runs
        Then: stdout carries an explicit could-not-run error and NOT the
              success checkmark
        """
        _write_corpus(tmp_path, _FOUR_CATEGORY_COMPONENTS, _FOUR_CATEGORY_CONTROLS, None)
        result = _run(tmp_path)
        combined = result.stdout + result.stderr

        assert "Category style check passed" not in combined, (
            f"A check reading hardcoded fallback styles must not report success;\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert "Category style check could not run" in combined, (
            f"Expected an explicit could-not-run error naming the failure;\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_missing_styles_file_error_is_printed_under_quiet(self, tmp_path):
        """
        Given: the same styles-less corpus and --quiet
        When: validate_riskmap.py --force --allow-isolated --quiet runs
        Then: the could-not-run error is still printed

        --quiet suppresses routine progress output; it must not suppress the
        report that a guard did not run.
        """
        _write_corpus(tmp_path, _FOUR_CATEGORY_COMPONENTS, _FOUR_CATEGORY_CONTROLS, None)
        result = _run(tmp_path, "--quiet")
        combined = result.stdout + result.stderr
        assert "Category style check could not run" in combined, (
            f"Expected the could-not-run error even with --quiet;\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_structurally_invalid_styles_file_with_block_exits_1(self, tmp_path):
        """
        Given: a mermaid-styles.yaml that parses as YAML but lacks the
               required top-level keys
        When: validate_riskmap.py --force --allow-isolated --block runs
        Then: exit 1 — the loader silently falls back here too

        A present-but-wrong file is the harder case: the file exists, so a
        guard that only checked for the path would be satisfied by it.
        """
        _write_corpus(
            tmp_path,
            _FOUR_CATEGORY_COMPONENTS,
            _FOUR_CATEGORY_CONTROLS,
            _STRUCTURALLY_INVALID_MERMAID_TEXT,
        )
        result = _run(tmp_path, "--block")
        assert result.returncode == 1, (
            f"Expected exit 1 with --block on a structurally invalid styles file; "
            f"got {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_unparseable_styles_file_with_block_exits_1(self, tmp_path):
        """
        Given: a mermaid-styles.yaml that is not valid YAML
        When: validate_riskmap.py --force --allow-isolated --block runs
        Then: exit 1
        """
        _write_corpus(
            tmp_path,
            _FOUR_CATEGORY_COMPONENTS,
            _FOUR_CATEGORY_CONTROLS,
            _UNPARSEABLE_MERMAID_TEXT,
        )
        result = _run(tmp_path, "--block")
        assert result.returncode == 1, (
            f"Expected exit 1 with --block on an unparseable styles file; "
            f"got {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_corrupt_styles_file_does_not_print_success(self, tmp_path):
        """
        Given: a structurally invalid styles file, no --block
        When: validate_riskmap.py --force --allow-isolated runs
        Then: stdout carries an explicit could-not-run error and NOT the
              success checkmark
        """
        _write_corpus(
            tmp_path,
            _FOUR_CATEGORY_COMPONENTS,
            _FOUR_CATEGORY_CONTROLS,
            _STRUCTURALLY_INVALID_MERMAID_TEXT,
        )
        result = _run(tmp_path)
        combined = result.stdout + result.stderr

        assert "Category style check passed" not in combined, (
            f"A check reading hardcoded fallback styles must not report success;\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert "Category style check could not run" in combined, (
            f"Expected an explicit could-not-run error naming the failure;\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ===========================================================================
# 2b. Styles-loader fallback disclosure + the guard/rendering split
# ===========================================================================


class TestLoaderFallbackDisclosure:
    """MermaidConfigLoader reports whether it is serving real config.

    The guard needs this because every style lookup silently succeeds either
    way: _get_safe_value() answers from _get_emergency_defaults() when the
    configured file could not be loaded, and those defaults carry an entry for
    every real category.
    """

    def test_real_config_is_not_fallback(self, tmp_path):
        """
        Given: a loader pointed at a valid styles file
        When: is_using_emergency_defaults() is called
        Then: False
        """
        from riskmap_validator.graphing.graph_utils import MermaidConfigLoader

        styles_path = tmp_path / "mermaid-styles.yaml"
        styles_path.write_text(yaml.dump(build_mermaid_styles()), encoding="utf-8")

        assert MermaidConfigLoader(styles_path).is_using_emergency_defaults() is False

    def test_live_styles_file_is_not_fallback(self):
        """
        Given: a loader pointed at the repo's real mermaid-styles.yaml
        When: is_using_emergency_defaults() is called
        Then: False — the steady state the guard asserts on the live corpus
        """
        from riskmap_validator.graphing.graph_utils import MermaidConfigLoader

        styles_path = _REPO_ROOT / "risk-map" / "yaml" / "mermaid-styles.yaml"
        assert MermaidConfigLoader(styles_path).is_using_emergency_defaults() is False

    def test_missing_file_is_fallback(self, tmp_path):
        """
        Given: a loader pointed at a path that does not exist
        When: is_using_emergency_defaults() is called
        Then: True
        """
        from riskmap_validator.graphing.graph_utils import MermaidConfigLoader

        assert MermaidConfigLoader(tmp_path / "absent.yaml").is_using_emergency_defaults() is True

    def test_unparseable_file_is_fallback(self, tmp_path):
        """
        Given: a loader pointed at a file that is not valid YAML
        When: is_using_emergency_defaults() is called
        Then: True
        """
        from riskmap_validator.graphing.graph_utils import MermaidConfigLoader

        styles_path = tmp_path / "mermaid-styles.yaml"
        styles_path.write_text(_UNPARSEABLE_MERMAID_TEXT, encoding="utf-8")

        assert MermaidConfigLoader(styles_path).is_using_emergency_defaults() is True

    def test_structurally_invalid_file_is_fallback(self, tmp_path):
        """
        Given: a loader pointed at valid YAML missing the required top-level
               keys
        When: is_using_emergency_defaults() is called
        Then: True
        """
        from riskmap_validator.graphing.graph_utils import MermaidConfigLoader

        styles_path = tmp_path / "mermaid-styles.yaml"
        styles_path.write_text(_STRUCTURALLY_INVALID_MERMAID_TEXT, encoding="utf-8")

        assert MermaidConfigLoader(styles_path).is_using_emergency_defaults() is True

    def test_fallback_still_serves_category_styles(self, tmp_path):
        """
        Given: a loader in fallback mode
        When: get_component_category_styles() is called
        Then: the emergency defaults are returned, styling every real category

        This is the behaviour the guard must refuse and rendering must keep:
        it is exactly why a missing styles file looked clean to the guard.
        """
        from riskmap_validator.graphing.graph_utils import MermaidConfigLoader

        loader = MermaidConfigLoader(tmp_path / "absent.yaml")
        styled = set(loader.get_component_category_styles().keys())
        real_categories = {
            "componentsInfrastructure",
            "componentsApplication",
            "componentsModel",
            "componentsExternalTools",
        }

        assert real_categories <= styled, (
            f"Expected the emergency defaults to style every real category; got: {sorted(styled)}"
        )


class TestRenderingKeepsTheFallback:
    """Only the guard treats fallback as a failure; rendering must not.

    Emergency defaults exist so graph generation degrades rather than dies
    when styling configuration is unavailable. Tightening the guard must not
    leak into the renderer.
    """

    def test_component_graph_renders_without_a_styles_file(self, tmp_path):
        """
        Given: a ComponentGraph whose config loader points at a missing file
        When: to_mermaid() is called
        Then: it returns a non-empty graph rather than raising
        """
        from riskmap_validator.graphing import ComponentGraph
        from riskmap_validator.graphing.graph_utils import MermaidConfigLoader
        from riskmap_validator.models import ComponentNode

        components = {
            "compAlpha": ComponentNode(
                title="Alpha",
                category="componentsInfrastructure",
                subcategory=None,
                to_edges=["compBeta"],
                from_edges=[],
            ),
            "compBeta": ComponentNode(
                title="Beta",
                category="componentsModel",
                subcategory=None,
                to_edges=[],
                from_edges=["compAlpha"],
            ),
        }
        graph = ComponentGraph({"compAlpha": ["compBeta"]}, components)
        graph.config_loader = MermaidConfigLoader(tmp_path / "absent.yaml")

        output = graph.to_mermaid()
        assert output.strip(), "Expected rendering to degrade to emergency defaults, not produce nothing"


class TestSharedStylesFixtureIsSchemaComplete:
    """The synthetic corpora's styles fixture is valid against the real schema.

    Synthetic corpora now carry a real styles file instead of leaning on the
    loader's emergency defaults. "Real" has to mean schema-valid, or the
    fixtures would only be as good as the loader's four required top-level
    keys.
    """

    def test_build_mermaid_styles_validates_against_the_schema(self):
        """
        Given: build_mermaid_styles() with its default categories
        When: validated against risk-map/schemas/mermaid-styles.schema.json
        Then: it validates
        """
        import jsonschema

        schema_path = _REPO_ROOT / "risk-map" / "schemas" / "mermaid-styles.schema.json"
        with open(schema_path, encoding="utf-8") as fh:
            schema = json.load(fh)

        jsonschema.validate(instance=build_mermaid_styles(), schema=schema)


# ===========================================================================
# 3. Schema-category resolution — riskmap_validator.graphing.graph_utils
# ===========================================================================
#
# The guard's schema_categories input is the one input that was NOT resolved
# the way components/controls/mermaid-styles are. Resolving it against the
# module's own location instead of cwd makes the guard silently vacuous
# anywhere the module tree is relocated — most importantly under CI's
# flattened layout — and a swallowed exception hid that. These tests pin both
# halves: cwd-relative resolution, and loud failure when the schema cannot be
# read.


@pytest.fixture
def graph_utils_module():
    """Yield graph_utils with its module-level schema-category cache cleared.

    _schema_categories_cache is a module-level global that survives across
    tests in a session. Clearing it on both sides keeps cwd-sensitive cases
    from leaking a previously resolved category set into each other, or into
    unrelated modules that construct graphs.
    """
    from riskmap_validator.graphing import graph_utils

    graph_utils.clear_schema_categories_cache()
    yield graph_utils
    graph_utils.clear_schema_categories_cache()


class TestSchemaCategoryResolution:
    """_get_schema_categories() resolves cwd-relatively and fails loud."""

    def test_resolves_schema_relative_to_cwd(self, tmp_path, monkeypatch, graph_utils_module):
        """
        Given: a cwd containing its own risk-map/schemas/components.schema.json
        When: _get_schema_categories() is called
        Then: the categories come from THAT schema, not the repo the module
              happens to live in

        This is the contract every other validator input already honours
        (components, controls, mermaid-styles are all cwd-relative).
        """
        _write_components_schema_stub(tmp_path, ["componentsSynthetic"])
        monkeypatch.chdir(tmp_path)

        assert graph_utils_module._get_schema_categories() == {"componentsSynthetic"}, (
            "Expected the category set to come from the schema under cwd; a set of real "
            "repo category ids means resolution is still anchored to the module's own path."
        )

    def test_missing_schema_raises(self, tmp_path, monkeypatch, graph_utils_module):
        """
        Given: a cwd with no risk-map/schemas/components.schema.json
        When: _get_schema_categories() is called
        Then: it raises, naming the path it looked for

        Returning an empty set here is what let the guard report success while
        checking nothing.
        """
        monkeypatch.chdir(tmp_path)

        with pytest.raises(RuntimeError) as excinfo:
            graph_utils_module._get_schema_categories()
        assert "components.schema.json" in str(excinfo.value), (
            f"Expected the error to name the schema path it could not read; got: {excinfo.value}"
        )

    def test_malformed_schema_raises(self, tmp_path, monkeypatch, graph_utils_module):
        """
        Given: a components.schema.json that is not valid JSON
        When: _get_schema_categories() is called
        Then: it raises rather than degrading to an empty set
        """
        schemas_dir = tmp_path / "risk-map" / "schemas"
        schemas_dir.mkdir(parents=True)
        (schemas_dir / "components.schema.json").write_text("{not json", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        with pytest.raises(RuntimeError):
            graph_utils_module._get_schema_categories()

    def test_unexpected_schema_shape_raises(self, tmp_path, monkeypatch, graph_utils_module):
        """
        Given: valid JSON without definitions.category.properties.id.enum
        When: _get_schema_categories() is called
        Then: it raises — a restructured schema must break loudly, not
              silently disable the guard
        """
        schemas_dir = tmp_path / "risk-map" / "schemas"
        schemas_dir.mkdir(parents=True)
        (schemas_dir / "components.schema.json").write_text(json.dumps({"definitions": {}}), encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        with pytest.raises(RuntimeError):
            graph_utils_module._get_schema_categories()

    def test_empty_category_enum_raises(self, tmp_path, monkeypatch, graph_utils_module):
        """
        Given: a schema whose category id enum is empty
        When: _get_schema_categories() is called
        Then: it raises — an empty enum is indistinguishable from an
              unreadable schema for this guard's purposes, and both make it
              vacuous
        """
        _write_components_schema_stub(tmp_path, [])
        monkeypatch.chdir(tmp_path)

        with pytest.raises(RuntimeError):
            graph_utils_module._get_schema_categories()

    def test_failure_is_not_cached(self, tmp_path, monkeypatch, graph_utils_module):
        """
        Given: a first call that fails because no schema exists
        When: the schema is then written and _get_schema_categories() is
              called again
        Then: the second call succeeds

        A cached failure would make one bad cwd poison the rest of the
        process.
        """
        monkeypatch.chdir(tmp_path)
        with pytest.raises(RuntimeError):
            graph_utils_module._get_schema_categories()

        _write_components_schema_stub(tmp_path, ["componentsSynthetic"])
        assert graph_utils_module._get_schema_categories() == {"componentsSynthetic"}

    def test_successful_read_is_cached(self, tmp_path, monkeypatch, graph_utils_module):
        """
        Given: a successful first read
        When: the schema file is deleted and the function is called again
        Then: the cached set is returned (caching behaviour is preserved)
        """
        schema_path = _write_components_schema_stub(tmp_path, ["componentsSynthetic"])
        monkeypatch.chdir(tmp_path)
        first = graph_utils_module._get_schema_categories()

        schema_path.unlink()
        assert graph_utils_module._get_schema_categories() == first


class TestFlattenedModuleLayout:
    """
    The guard survives .github/workflows/validation.yml's flattened layout.

    That workflow copies validate_riskmap.py to the repo root and
    riskmap_validator/* into a sibling package directory, then runs from the
    repo root. graph_utils.py therefore sits two directory levels shallower
    than in the source tree, so any path resolved by walking up from the
    module lands outside the repo. cwd is the repo root in both layouts,
    which is why cwd-relative resolution is the one that holds.
    """

    def _run_flattened(self, base: Path, *extra_args: str) -> subprocess.CompletedProcess:
        entry = base / "validate_riskmap.py"
        return subprocess.run(
            [sys.executable, str(entry), "--force", "--allow-isolated", *extra_args],
            capture_output=True,
            text=True,
            cwd=str(base),
        )

    def test_flattened_layout_detects_dirty_category(self, tmp_path):
        """
        Given: the flattened CI module layout over a style-dirty corpus
        When: validate_riskmap.py --force --allow-isolated --block runs
        Then: exit 1 and the dirty category is named

        Exit 0 here means the guard resolved no categories and passed
        vacuously — the exact CI failure mode this test exists for.
        """
        _write_corpus(tmp_path, _FOUR_CATEGORY_COMPONENTS, _FOUR_CATEGORY_CONTROLS, _MODEL_UNSTYLED_MERMAID)
        _flatten_module(tmp_path)

        result = self._run_flattened(tmp_path, "--block")
        assert result.returncode == 1, (
            f"Expected exit 1 under the flattened CI layout on a style-dirty corpus; "
            f"got {result.returncode} — the guard passed vacuously.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        combined = result.stdout + result.stderr
        assert "componentsModel" in combined, (
            f"Expected the dirty category to be named under the flattened layout; "
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )

    def test_flattened_layout_clean_corpus_exits_0(self, tmp_path):
        """
        Given: the flattened CI module layout over a clean corpus
        When: validate_riskmap.py --force --allow-isolated --block runs
        Then: exit 0 — the fix must not make the flattened layout fail outright
        """
        _write_corpus(tmp_path, _FOUR_CATEGORY_COMPONENTS, _FOUR_CATEGORY_CONTROLS, _FULLY_STYLED_MERMAID)
        _flatten_module(tmp_path)

        result = self._run_flattened(tmp_path, "--block")
        assert result.returncode == 0, (
            f"Expected exit 0 under the flattened CI layout on a clean corpus; "
            f"got {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


class TestSchemaUnavailableFailsLoud:
    """An unreadable schema must never render as a passing check."""

    def test_missing_schema_does_not_print_success(self, tmp_path):
        """
        Given: a corpus that is clean by its own lights but has no
               risk-map/schemas/components.schema.json
        When: validate_riskmap.py --force --allow-isolated runs (no --block)
        Then: stdout carries an explicit could-not-run error and NOT the
              success checkmark

        The pre-fix code swallowed the read error inside the helper, so even
        the CLI's own "check skipped" handler never fired: the run printed an
        unqualified success line for a check that had examined nothing.
        """
        _write_corpus(
            tmp_path,
            _FOUR_CATEGORY_COMPONENTS,
            _FOUR_CATEGORY_CONTROLS,
            _FULLY_STYLED_MERMAID,
            write_schema=False,
        )
        result = _run(tmp_path)
        combined = result.stdout + result.stderr

        assert "Category style check passed" not in combined, (
            f"A check that could not read the schema must not report success;\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert "Category style check could not run" in combined, (
            f"Expected an explicit could-not-run error naming the failure;\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_missing_schema_with_block_exits_1(self, tmp_path):
        """
        Given: the same schema-less corpus
        When: validate_riskmap.py --force --allow-isolated --block runs
        Then: exit 1 — --block promotes this check's failures to errors, and a
              check that cannot run has not passed
        """
        _write_corpus(
            tmp_path,
            _FOUR_CATEGORY_COMPONENTS,
            _FOUR_CATEGORY_CONTROLS,
            _FULLY_STYLED_MERMAID,
            write_schema=False,
        )
        result = _run(tmp_path, "--block")
        assert result.returncode == 1, (
            f"Expected exit 1 with --block when the schema cannot be read; "
            f"got {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_missing_schema_error_is_printed_under_quiet(self, tmp_path):
        """
        Given: the same schema-less corpus and --quiet
        When: validate_riskmap.py --force --allow-isolated --quiet runs
        Then: the could-not-run error is still printed

        --quiet suppresses routine progress output; it must not suppress the
        report that a guard did not run.
        """
        _write_corpus(
            tmp_path,
            _FOUR_CATEGORY_COMPONENTS,
            _FOUR_CATEGORY_CONTROLS,
            _FULLY_STYLED_MERMAID,
            write_schema=False,
        )
        result = _run(tmp_path, "--quiet")
        combined = result.stdout + result.stderr
        assert "Category style check could not run" in combined, (
            f"Expected the could-not-run error even with --quiet;\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ===========================================================================
# Test Summary
# ===========================================================================
"""
Test Summary
============
TestCheckCategoryStyleCoverage (pure function): 7 tests
- clean -> []; missing style warns and names the category; an extra styling
  entry the schema does not declare is not warned about; multi-category
  independence; an empty category set is a warning, not a pass; return-type
  contract; live-corpus regression (every live category styled).

TestCLIWiring (subprocess): 11 tests
- dirty style + --block -> exit 1; clean + --block -> exit 0; dirty style
  without --block -> exit 0 + names the category; live corpus no --block ->
  exit 0; live corpus + --block -> exit 0; missing styles file + --block ->
  exit 1, without --block -> could-not-run and no success line, and the error
  survives --quiet; structurally invalid and unparseable styles files +
  --block -> exit 1, and structurally invalid without --block -> could-not-run
  and no success line.

TestLoaderFallbackDisclosure (unit): 6 tests
- a valid file and the live styles file are not fallback; missing,
  unparseable and structurally invalid files are; fallback still serves a
  style for every real category, which is why the guard has to ask.

TestRenderingKeepsTheFallback (unit): 1 test
- ComponentGraph still renders with no styles file — the guard's strictness
  must not leak into the renderer.

TestSharedStylesFixtureIsSchemaComplete (unit): 1 test
- conftest.build_mermaid_styles() validates against the real
  mermaid-styles.schema.json.

TestSchemaCategoryResolution (unit): 7 tests
- cwd-relative resolution; missing / malformed / restructured / empty-enum
  schema each raise and name the path; failures are not cached; successful
  reads are.

TestFlattenedModuleLayout (subprocess): 2 tests
- validation.yml's flattened layout over a dirty corpus -> exit 1 + names the
  category (exit 0 would mean the guard resolved no categories at all); over
  a clean corpus -> exit 0.

TestSchemaUnavailableFailsLoud (subprocess): 3 tests
- no schema -> no success checkmark + an explicit could-not-run error;
  --block promotes it to exit 1; --quiet does not suppress it.

check_category_style_coverage is implemented in riskmap_validator.validator
and wired into validate_riskmap.py as a --block-gated warn-only check. The
CLI tests that only assert exit code (test_clean_corpus_with_block_exits_0,
test_live_corpus_*_exits_0) are weak signals in isolation — an unwired or
no-op check would also exit 0 — and are retained as regression companions to
the dirty-corpus tests, which assert on the printed category name in addition
to the exit code.
"""
