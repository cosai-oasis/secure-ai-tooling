#!/usr/bin/env python3
"""
Tests for the controls↔components mirror check (task 2.3.8 / issue #268).

Per ADR-020 D7: every component ID listed in controls[].components[] must
exist as a top-level component ID in components.yaml.  The literals "all"
and "none" are escape hatches — they are valid and must not be flagged.
Direction is one-way: control → component (NOT bidirectional).

The check ships warn-only with a --block toggle:
  default (no --block): print warnings, exit 0
  --block:              warnings become errors, exit 1

This mirrors the pattern established by A3 (validate_yaml_prose_subset.py)
and A3.7 / 2.3.6 (validate_framework_references.py / check_deprecated_persona_usage).

Symbol contract
---------------
The pure-function tests import `check_controls_components_mirror` from
`riskmap_validator.validator`.  SWE must expose a callable with that name.
Signature (SWE's call, but tests assume this shape):

    check_controls_components_mirror(
        controls: dict[str, ControlNode],
        component_ids: set[str],
    ) -> list[str]

Returns a list of human-readable warning strings, one per (control_id,
missing_component_id) pair or per control (SWE's call).  Empty list means
clean.

Test structure
--------------
1. TestCheckControlsComponentsMirror
   Pure-function tests on check_controls_components_mirror().
   These tests FAIL today with ImportError (function not yet implemented).
   They pin the observable contract so SWE can implement to make them pass.

2. TestBlockToggleCLI
   Subprocess-based end-to-end tests for the --block flag on validate_riskmap.py.
   These tests FAIL today with argparse exit 2 ("unrecognised arguments: --block").

Synthesised-corpus harness
--------------------------
validate_riskmap.py's --force mode reads components.yaml at the path
risk-map/yaml/components.yaml relative to cwd.  The ComponentEdgeValidator
runs first; components.yaml must therefore be structurally valid (bidirectional
edges, no missing references).  We use --allow-isolated to skip the orphan check
so minimal corpora don't need a fully-connected graph.

Minimal components.yaml shape expected by parse_components_yaml():
  - top-level key: components (list)
  - each entry has: id (str), title (str), category (str)
  - edges: {to: [...], from: [...]}  (optional, defaults to [])

Minimal controls.yaml shape expected by parse_controls_yaml():
  - top-level key: controls (list)
  - each entry has: id (str), title (str), category (str)
  - components: list[str]  (the field under test)

Live-corpus state (verified 2026-05-13, post-#297):
  The pre-#297 debt — controls.yaml referencing componentInputHandling /
  componentOutputHandling (3 dangling instances across 3 controls) — was
  resolved by rerouting to componentApplicationInputHandling /
  componentApplicationOutputHandling. Live-corpus regression tests pinned
  to that count have been retired; the synthetic dirty fixtures below
  preserve forward-guard coverage of the warning-fires path.
"""

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# sys.path injection — same pattern as the existing test files
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "riskmap_validator"))

from riskmap_validator.models import ControlNode  # noqa: E402

# Deferred import: check_controls_components_mirror does not exist yet.
# We capture the ImportError here and re-raise it inside a pytest fixture so
# that pure-function tests fail individually while CLI test collection succeeds.
try:
    from riskmap_validator.validator import check_controls_components_mirror  # noqa: E402

    _MIRROR_IMPORT_ERROR: ImportError | None = None
except ImportError as _e:
    check_controls_components_mirror = None  # type: ignore[assignment]
    _MIRROR_IMPORT_ERROR = _e

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Absolute path to the CLI script under test.
_SCRIPT = Path(__file__).parent.parent / "validate_riskmap.py"

# Repository root (worktree root) — used as cwd for live-corpus subprocess tests.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# Escape-hatch literals that must never produce a warning.
_ESCAPE_HATCHES = ("all", "none")

# A set of component IDs that represent a minimal valid component map for
# pure-function tests — these IDs do NOT need to match any real YAML file.
_VALID_COMPONENT_IDS = {"componentAlpha", "componentBeta", "componentGamma"}


# ---------------------------------------------------------------------------
# Helpers for pure-function tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Fixture that makes the deferred import visible to pure-function tests.
# If the function does not yet exist the fixture raises, failing the test
# with an informative error (rather than AttributeError on None).
# ---------------------------------------------------------------------------


@pytest.fixture
def mirror_fn():
    """Return check_controls_components_mirror, or fail with ImportError.

    Pure-function tests request this fixture so that the ImportError from
    the deferred import surfaces as a test failure rather than a collection
    error.  This keeps the CLI tests collectible and runnable independently.
    """
    if _MIRROR_IMPORT_ERROR is not None:
        raise _MIRROR_IMPORT_ERROR
    return check_controls_components_mirror


def _make_control(
    ctrl_id: str,
    components: list[str],
    category: str = "controlsModel",
) -> ControlNode:
    """Construct a ControlNode for testing.

    Args:
        ctrl_id: Control identifier (also used as title for simplicity).
        components: The components list to attach.
        category: Category string (any non-empty value satisfies ControlNode).

    Returns:
        A ControlNode with minimal required fields populated.
    """
    return ControlNode(
        title=ctrl_id,
        category=category,
        components=components,
        risks=[],
        personas=[],
    )


# ---------------------------------------------------------------------------
# Helpers for synthesised-corpus subprocess tests
# ---------------------------------------------------------------------------

# Minimal components.yaml whose two components reference each other so
# ComponentEdgeValidator does not fail on missing back-edges. The categories
# block + subcategory fields make this corpus opaque to task 2.3.9's nesting
# check (after 2.3.9 wires, every component has a valid (category, subcategory)
# pair so the nesting check stays silent and the mirror behavior remains
# isolated).
#
# One category is enough: write_riskmap_corpus derives this corpus's schema
# category enum from the categories: block below, so the category style check
# (ADR-030 D1) only ever asks about componentsInfrastructure here. Style is not
# separately supplied: these corpora omit mermaid-styles.yaml, so
# MermaidConfigLoader falls back to its emergency defaults, which style every
# real category.
_MINIMAL_COMPONENTS: dict[str, Any] = {
    "components": [
        {
            "id": "componentAlpha",
            "title": "Alpha",
            "category": "componentsInfrastructure",
            "subcategory": "componentsData",
            "edges": {"to": ["componentBeta"], "from": []},
        },
        {
            "id": "componentBeta",
            "title": "Beta",
            "category": "componentsInfrastructure",
            "subcategory": "componentsData",
            "edges": {"to": [], "from": ["componentAlpha"]},
        },
    ],
    "categories": [
        {
            "id": "componentsInfrastructure",
            "title": "Infrastructure",
            "subcategory": [
                {"id": "componentsData", "title": "Data"},
            ],
        },
    ],
}

# controls.yaml that references only IDs present in _MINIMAL_COMPONENTS.
_CLEAN_CONTROLS: dict[str, Any] = {
    "controls": [
        {
            "id": "controlClean",
            "title": "Clean Control",
            "category": "controlsModel",
            "components": ["componentAlpha", "componentBeta"],
            "risks": [],
            "personas": [],
        }
    ]
}

# controls.yaml that references a component ID absent from _MINIMAL_COMPONENTS.
_DIRTY_CONTROLS: dict[str, Any] = {
    "controls": [
        {
            "id": "controlDirty",
            "title": "Dirty Control",
            "category": "controlsModel",
            "components": ["componentAlpha", "componentDoesNotExist"],
            "risks": [],
            "personas": [],
        }
    ]
}

# controls.yaml exercising the "all" escape hatch — must not trigger a mirror
# warning. This corpus deliberately contains nothing but the escape hatch:
# every component reference in it is "all", which is the whole point of the
# fixture. A second, specific-component control would make the corpus pass
# for a reason other than the escape hatch being honoured.
_ESCAPE_ALL_CONTROLS: dict[str, Any] = {
    "controls": [
        {
            "id": "controlAll",
            "title": "All Control",
            "category": "controlsGovernance",
            "components": ["all"],
            "risks": [],
            "personas": [],
        },
    ]
}


# Synthesised-corpus subprocess tests rely on the shared `write_riskmap_corpus`
# and `run_validate_riskmap` fixtures (see conftest.py) so every warn-only
# check test invokes the CLI through one consistent harness.


# ===========================================================================
# 1. Pure-function tests — check_controls_components_mirror()
# ===========================================================================


class TestCheckControlsComponentsMirror:
    """Pure-function tests for check_controls_components_mirror().

    Every test in this class requests the `mirror_fn` fixture which raises
    ImportError when the symbol is absent, causing each test to FAIL (not
    ERROR at collection time).  This keeps TestBlockToggleCLI collectible
    and runnable independently.

    Once SWE implements the function in riskmap_validator/validator.py,
    these tests are the green-phase acceptance criteria.
    """

    def test_clean_controls_return_empty_list(self, mirror_fn):
        """
        All controls referencing only known component IDs returns empty list.

        Given: controls dict where every component reference is in component_ids
        When: check_controls_components_mirror() is called
        Then: Returns an empty list (no warnings)
        """
        controls = {
            "controlA": _make_control("controlA", ["componentAlpha", "componentBeta"]),
            "controlB": _make_control("controlB", ["componentGamma"]),
        }
        result = mirror_fn(controls, _VALID_COMPONENT_IDS)
        assert result == [], f"Expected no warnings for clean controls; got: {result}"

    def test_single_dangling_ref_returns_warning_naming_control_and_component(self, mirror_fn):
        """
        One control referencing a missing component ID produces a warning
        that names both the control ID and the missing component ID.

        Given: controls dict with one control that references componentDoesNotExist
               which is absent from component_ids
        When: check_controls_components_mirror() is called
        Then: Returns a non-empty list; warning text contains both
              "controlMissing" and "componentDoesNotExist"
        """
        controls = {"controlMissing": _make_control("controlMissing", ["componentAlpha", "componentDoesNotExist"])}
        result = mirror_fn(controls, _VALID_COMPONENT_IDS)
        assert len(result) >= 1, f"Expected at least one warning; got: {result}"
        combined = " ".join(result)
        assert "controlMissing" in combined, f"Expected 'controlMissing' in warning text; got: {result}"
        assert "componentDoesNotExist" in combined, (
            f"Expected 'componentDoesNotExist' in warning text; got: {result}"
        )

    def test_multiple_dangling_refs_in_one_control_each_produces_warning(self, mirror_fn):
        """
        A control referencing two missing component IDs produces warnings
        that mention both missing IDs.

        Given: controlX references [componentAlpha, componentMissingA, componentMissingB]
               where only componentAlpha is in component_ids
        When: check_controls_components_mirror() is called
        Then: The combined warning text mentions componentMissingA AND componentMissingB
        """
        controls = {
            "controlX": _make_control(
                "controlX",
                ["componentAlpha", "componentMissingA", "componentMissingB"],
            )
        }
        result = mirror_fn(controls, _VALID_COMPONENT_IDS)
        assert len(result) >= 1, f"Expected at least one warning; got: {result}"
        combined = " ".join(result)
        assert "componentMissingA" in combined, f"Expected 'componentMissingA' in warnings; got: {result}"
        assert "componentMissingB" in combined, f"Expected 'componentMissingB' in warnings; got: {result}"

    def test_multiple_controls_with_dangling_refs_each_appears_in_warnings(self, mirror_fn):
        """
        Each control with a dangling reference appears in the warning output.

        Given: controlP and controlQ each reference a missing component
        When: check_controls_components_mirror() is called
        Then: The combined warning text mentions controlP AND controlQ
        """
        controls = {
            "controlP": _make_control("controlP", ["componentMissingX"]),
            "controlQ": _make_control("controlQ", ["componentMissingY"]),
        }
        result = mirror_fn(controls, _VALID_COMPONENT_IDS)
        assert len(result) >= 1, f"Expected at least one warning; got: {result}"
        combined = " ".join(result)
        assert "controlP" in combined, f"Expected 'controlP' in warnings; got: {result}"
        assert "controlQ" in combined, f"Expected 'controlQ' in warnings; got: {result}"

    def test_escape_hatch_all_produces_no_warning(self, mirror_fn):
        """
        A control with components: ["all"] produces no warning.

        "all" is a documented escape hatch meaning the control applies to
        all components.  It must not be flagged as a missing component ID.

        Given: A control with components=["all"]
        When: check_controls_components_mirror() is called
        Then: Returns empty list
        """
        controls = {"controlAll": _make_control("controlAll", ["all"])}
        result = mirror_fn(controls, _VALID_COMPONENT_IDS)
        assert result == [], f"Expected no warning for escape hatch 'all'; got: {result}"

    def test_escape_hatch_none_produces_no_warning(self, mirror_fn):
        """
        A control with components: ["none"] produces no warning.

        "none" is a documented escape hatch meaning the control applies to
        no specific component.  It must not be flagged as a missing component ID.

        Given: A control with components=["none"]
        When: check_controls_components_mirror() is called
        Then: Returns empty list
        """
        controls = {"controlNone": _make_control("controlNone", ["none"])}
        result = mirror_fn(controls, _VALID_COMPONENT_IDS)
        assert result == [], f"Expected no warning for escape hatch 'none'; got: {result}"

    def test_empty_components_list_produces_no_warning(self, mirror_fn):
        """
        A control with an empty components list produces no warning.

        There is nothing to check; the function must not raise and must
        return an empty list.

        Given: A control with components=[]
        When: check_controls_components_mirror() is called
        Then: Returns empty list
        """
        controls = {"controlEmpty": _make_control("controlEmpty", [])}
        result = mirror_fn(controls, _VALID_COMPONENT_IDS)
        assert result == [], f"Expected no warning for empty components list; got: {result}"

    def test_empty_controls_dict_returns_empty_list(self, mirror_fn):
        """
        Passing an empty controls dict returns an empty list without raising.

        Given: controls={}
        When: check_controls_components_mirror() is called
        Then: Returns empty list
        """
        result = mirror_fn({}, _VALID_COMPONENT_IDS)
        assert result == [], f"Expected empty list for empty controls dict; got: {result}"

    def test_returns_list_type(self, mirror_fn):
        """
        The function always returns a list, never None.

        Given: Any valid input
        When: check_controls_components_mirror() is called
        Then: Return value is a list instance
        """
        result = mirror_fn({}, set())
        assert isinstance(result, list), f"Expected list; got {type(result)}"

    def test_each_warning_is_a_string(self, mirror_fn):
        """
        Every element in the returned warnings list is a str.

        Given: A controls dict with at least one dangling reference
        When: check_controls_components_mirror() is called
        Then: Every element in the returned list is a str instance
        """
        controls = {"controlBad": _make_control("controlBad", ["componentGhost"])}
        result = mirror_fn(controls, _VALID_COMPONENT_IDS)
        assert len(result) >= 1, "Expected at least one warning for this input"
        for item in result:
            assert isinstance(item, str), f"Expected str element; got {type(item)!r}: {item!r}"

    def test_valid_component_refs_not_flagged_as_missing(self, mirror_fn):
        """
        Component IDs that exist in component_ids do not appear as missing refs.

        Guards against false-positives: the function must only report IDs that
        are absent from component_ids.

        Given: A control referencing componentAlpha (present) and componentGhost (absent)
        When: check_controls_components_mirror() is called
        Then: "componentGhost" appears in the combined warning text;
              the warning count does not exceed the number of missing IDs (1)
        """
        controls = {"controlMixed": _make_control("controlMixed", ["componentAlpha", "componentGhost"])}
        result = mirror_fn(controls, _VALID_COMPONENT_IDS)
        assert len(result) >= 1, "Expected a warning for componentGhost"
        combined = " ".join(result)
        assert "componentGhost" in combined, f"Expected 'componentGhost' in warning text; got: {result}"
        # The valid reference must NOT appear in any warning text — guards
        # against a false-positive where every listed component (valid or not)
        # is flagged as missing.
        assert "componentAlpha" not in combined, (
            f"Expected 'componentAlpha' (valid ref) NOT in warning text; got: {result}"
        )

    def test_live_corpus_produces_zero_warnings(self, mirror_fn):
        """
        Running against the actual controls.yaml + components.yaml on disk
        (post-#297) produces no mirror warnings.

        Given: Parsed controls from risk-map/yaml/controls.yaml
               Parsed components from risk-map/yaml/components.yaml
        When: check_controls_components_mirror() is called
        Then: Warning count == 0 — the live corpus is clean

        Forward-guard: replaces the retired count==3 regression that tracked
        the pre-#297 dangling refs. Synthetic dirty fixtures (componentGhost
        etc.) preserve coverage of the warning-emitting path.
        """
        from riskmap_validator.utils import parse_components_yaml, parse_controls_yaml

        components_path = _REPO_ROOT / "risk-map" / "yaml" / "components.yaml"
        controls_path = _REPO_ROOT / "risk-map" / "yaml" / "controls.yaml"

        components = parse_components_yaml(components_path)
        controls = parse_controls_yaml(controls_path)
        component_ids = set(components.keys())

        result = mirror_fn(controls, component_ids)

        assert result == [], f"Expected 0 mirror warnings on the live corpus; got {len(result)}: {result}"


# ===========================================================================
# 2. CLI tests — --block toggle on validate_riskmap.py
# ===========================================================================


class TestBlockToggleCLI:
    """End-to-end CLI tests for the --block flag on validate_riskmap.py.

    Live-corpus tests use _REPO_ROOT as cwd.
    Synthesised-corpus tests build a minimal two-file corpus in tmp_path.
    """

    # -----------------------------------------------------------------------
    # Live corpus: the actual risk-map/yaml/ tree in the worktree.
    # Post-#297: clean (0 dangling refs).
    # -----------------------------------------------------------------------

    def test_live_corpus_no_block_flag_exits_0(self, run_validate_riskmap):
        """
        Running without --block against the live corpus exits 0.

        Warn-only default must not be broken by adding --block.  This is a
        regression guard: validate_riskmap.py exits 0 on the live corpus.

        Given: The live risk-map/yaml/ corpus (clean post-#297)
        When: validate_riskmap.py --force --allow-isolated (no --block)
        Then: Exit code is 0
        """
        result = run_validate_riskmap(_REPO_ROOT)
        assert result.returncode == 0, (
            f"Expected exit 0 without --block on live corpus; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_live_corpus_with_block_flag_exits_0(self, run_validate_riskmap):
        """
        Running with --block against the live corpus (post-#297) exits 0
        because no dangling component refs remain.

        Forward-guard: replaces the retired count==1 expectation that tracked
        pre-#297 content debt. Synthetic dirty corpus fixtures cover the
        warning-fires path.
        """
        result = run_validate_riskmap(_REPO_ROOT, "--block")
        assert result.returncode == 0, (
            f"Expected exit 0 with --block on clean live corpus; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    # -----------------------------------------------------------------------
    # Synthesised clean corpus: no dangling refs → --block must NOT fire.
    # -----------------------------------------------------------------------

    def test_clean_corpus_with_block_flag_exits_0(self, tmp_path, write_riskmap_corpus, run_validate_riskmap):
        """
        Running with --block against a corpus with no dangling refs exits 0.

        The toggle must only promote warnings to failures when warnings
        actually exist; a clean corpus always exits 0.

        Given: A synthesised corpus where all controls reference components
               that exist in components.yaml
        When: validate_riskmap.py --force --allow-isolated --block (cwd=tmp_path)
        Then: Exit code is 0 (no mirror warnings to promote)
        """
        write_riskmap_corpus(tmp_path, _MINIMAL_COMPONENTS, _CLEAN_CONTROLS)
        result = run_validate_riskmap(tmp_path, "--block")
        assert result.returncode == 0, (
            f"Expected exit 0 with --block on clean corpus; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_clean_corpus_no_block_flag_exits_0(self, tmp_path, write_riskmap_corpus, run_validate_riskmap):
        """
        Running without --block against a clean corpus exits 0.

        Baseline sanity check that the synthesised-corpus harness is correct.

        Given: A synthesised clean corpus
        When: validate_riskmap.py --force --allow-isolated (no --block)
        Then: Exit code is 0
        """
        write_riskmap_corpus(tmp_path, _MINIMAL_COMPONENTS, _CLEAN_CONTROLS)
        result = run_validate_riskmap(tmp_path)
        assert result.returncode == 0, (
            f"Expected exit 0 on clean corpus without --block; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    # -----------------------------------------------------------------------
    # Synthesised dirty corpus: dangling refs present.
    # -----------------------------------------------------------------------

    def test_dirty_corpus_with_block_flag_exits_1(self, tmp_path, write_riskmap_corpus, run_validate_riskmap):
        """
        Running with --block against a synthesised dirty corpus exits 1.

        Cross-checks that the toggle fires on a synthetic corpus, not just
        the live one.

        Given: A synthesised corpus where controlDirty references
               componentDoesNotExist (absent from components.yaml)
        When: validate_riskmap.py --force --allow-isolated --block
        Then: Exit code is 1
        """
        write_riskmap_corpus(tmp_path, _MINIMAL_COMPONENTS, _DIRTY_CONTROLS)
        result = run_validate_riskmap(tmp_path, "--block")
        assert result.returncode == 1, (
            f"Expected exit 1 with --block on dirty corpus; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_dirty_corpus_no_block_flag_exits_0(self, tmp_path, write_riskmap_corpus, run_validate_riskmap):
        """
        Running WITHOUT --block against a dirty synthesised corpus exits 0.

        Confirms warn-only default behaviour is preserved even when dangling
        component refs exist.

        Given: A synthesised corpus where controlDirty references
               componentDoesNotExist (absent from components.yaml)
        When: validate_riskmap.py --force --allow-isolated (no --block)
        Then: Exit code is 0 (warnings only, no failure)
        """
        write_riskmap_corpus(tmp_path, _MINIMAL_COMPONENTS, _DIRTY_CONTROLS)
        result = run_validate_riskmap(tmp_path)
        assert result.returncode == 0, (
            f"Expected exit 0 without --block on dirty corpus; got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        # Warn-only must still emit the warning — exit-0 alone doesn't prove
        # the check ran. Without this assertion, a silent skip would pass.
        combined = result.stdout + result.stderr
        assert "componentDoesNotExist" in combined, (
            f"Expected warn output naming 'componentDoesNotExist' even without --block; "
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )

    def test_dirty_corpus_with_block_output_names_missing_component(
        self, tmp_path, write_riskmap_corpus, run_validate_riskmap
    ):
        """
        When --block fires, the output names the missing component ID.

        Given: A synthesised dirty corpus (componentDoesNotExist dangling)
        When: validate_riskmap.py --force --allow-isolated --block
        Then: Output mentions "componentDoesNotExist"
        """
        write_riskmap_corpus(tmp_path, _MINIMAL_COMPONENTS, _DIRTY_CONTROLS)
        result = run_validate_riskmap(tmp_path, "--block")
        combined = result.stdout + result.stderr
        assert "componentDoesNotExist" in combined, (
            f"Expected 'componentDoesNotExist' in output; stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )

    def test_escape_hatch_all_corpus_with_block_exits_0(
        self, tmp_path, write_riskmap_corpus, run_validate_riskmap
    ):
        """
        A corpus where all controls use the "all" escape hatch exits 0 with --block.

        The escape hatches must be respected end-to-end; the CLI must not
        flag "all" as a missing component.

        Given: A synthesised corpus where all controls use components: ["all"]
        When: validate_riskmap.py --force --allow-isolated --block
        Then: Exit code is 0
        """
        write_riskmap_corpus(tmp_path, _MINIMAL_COMPONENTS, _ESCAPE_ALL_CONTROLS)
        result = run_validate_riskmap(tmp_path, "--block")
        assert result.returncode == 0, (
            f"Expected exit 0 with --block when controls use 'all' escape hatch; "
            f"got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    # -----------------------------------------------------------------------
    # Flag discovery: --help must list --block
    # -----------------------------------------------------------------------

    def test_help_output_contains_block_flag(self):
        """
        The --help output documents the --block flag.

        Given: The script is invoked with --help
        When: validate_riskmap.py --help
        Then: The --help text contains '--block'
        """
        result = subprocess.run(
            [sys.executable, str(_SCRIPT), "--help"],
            capture_output=True,
            text=True,
        )
        # argparse --help exits 0
        assert result.returncode == 0, f"--help unexpectedly exited {result.returncode}"
        assert "--block" in result.stdout, f"Expected '--block' in --help output; got:\n{result.stdout}"


# ===========================================================================
# Test Summary
# ===========================================================================
#
# TestCheckControlsComponentsMirror  (pure function)
#   — clean controls return empty list; single dangling ref names control +
#     component; multiple missing refs in one control both appear; multiple
#     controls each appear; escape "all" no warning; escape "none" no warning;
#     empty components list no warning; empty controls dict no warning; return
#     type is list; each element is str; valid refs not in warnings;
#     live-corpus forward-guard (post-#297: 0 warnings on clean corpus).
#
# TestBlockToggleCLI  (subprocess CLI)
#   — live corpus + no --block -> exit 0 (regression guard);
#     live corpus + --block -> exit 0 (clean post-#297; forward-guard);
#     clean synthesised corpus + --block -> exit 0;
#     clean synthesised corpus + no --block -> exit 0;
#     dirty synthesised corpus + --block -> exit 1;
#     dirty synthesised corpus + no --block -> exit 0 (warn-only preserved);
#     dirty corpus + --block -> output names missing component;
#     escape-hatch "all" corpus + --block -> exit 0;
#     --help output contains '--block'.
