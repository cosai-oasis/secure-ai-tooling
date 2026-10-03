#!/usr/bin/env python3
"""
Tests for validate_riskmap.py

This test suite validates the main entry point for component edge validation
and graph generation. The script orchestrates ComponentEdgeValidator and provides
graph generation for the component relationship visualization.

Test Coverage:
==============
Line-number annotations against validate_riskmap.py have been dropped from
this list: they were stale by hundreds of lines and nothing kept them
honest. The previously recorded "Coverage Target: 98%+ (achieved)" claim was
also stale — it does not match a measured run — so it has been dropped
rather than replaced with another number that nothing enforces. Measure with
`pytest --cov=validate_riskmap scripts/hooks/tests/test_validate_riskmap.py`.

1. TestParseArgs - CLI argument parsing - 12 tests
   - Default arguments
   - --force/-f flag (long and short form)
   - --file PATH argument — argparse parsing only; the flag's effect on
     main() is covered by TestMainFileFlag, not here
   - --allow-isolated flag
   - --quiet/-q flag (long and short form)
   - --to-graph PATH argument
   - --debug flag
   - --mermaid-format/-m flag (long and short form)
   - Combined argument parsing

2. TestRemovedGraphFlagsRejected - #477's removed flags stay removed - 4 tests
   - --to-controls-graph/-c and --to-risk-graph/-r each exit 2, so a stub
     that parsed one and generated nothing could not pass silently

3. TestFileFlagHelpText - `--file` documents where it is not valid - 3 tests
   - --file's own help names every combination it is rejected in
   - `--help` exits 0 and carries the constraints with its epilog intact
   - the module docstring's --file entry has not drifted from --help

4. TestMainValidation - Validation orchestration - 11 tests
   - Validation success with force mode
   - Validation failure detection
   - No YAML files to validate
   - Quiet mode output suppression
   - Multiple file validation with spacing
   - ComponentEdgeValidator integration with flags
   - Validator initialization with correct options
   - components.yaml is validated on a controls-only commit, and the staged
     set is requested with target_file None (regression fence; green today)
   - the corpus is parsed exactly once per run (validated_corpus_paths
     fixture), and opened exactly once physically per run, counted by a
     subprocess-isolated sys.addaudithook rather than a named-API spy so a
     second read cannot hide behind a renamed seam or a different read
     order (currently fails: production opens it twice)
   - the nesting check must evaluate the same physical read the components
     were built from: poisoning the corpus on disk immediately after its
     first real read, through whichever of builtins.open/io.open/
     Path.read_text performs it, must not change the nesting check's
     findings, and the poison must be confirmed to have actually fired
     (currently fails)

5. TestMainFileFlag - `--file PATH` end-to-end wiring - 32 tests
   - --file selects the corpus directly, without routing through
     get_staged_yaml_files, and works outside a git repository
   - End-to-end: the corpus content decides the outcome, parametrised over
     clean, edge-inconsistent and missing-reference corpora at one path,
     plus a --quiet case; nothing mocked
   - Unusable --file paths (missing, directory, wrong shape) exit 2 with a
     message naming the file and the problem, verbose and --quiet alike,
     rather than the report-to-maintainers banner; the default corpus of the
     wrong shape must fail identically, so one function does not grow two
     user experiences
   - --force --file is rejected as contradictory; --to-graph stays allowed
     and draws the --file corpus
   - Only the checks that read other repo files (lifecycle order, controls
     mirror) skip under --file; category/subcategory nesting is
     self-contained in the corpus under test, runs, and promotes under
     --block
   - --file naming the default corpus runs every check, relative or
     absolute spelling — it must not be a weaker run than --force
   - Every unparseable corpus shape fails the same way; a failure in
     either the parse or the checking phase still reaches the crash banner
   - The corpus a run announces is the corpus it validated

6. TestParseCorpus - the parse step, directly - 14 tests
   - a well-formed corpus parses; every malformed shape, a missing file
     included, raises CorpusParseError with the original failure chained
   - defect-shaped exceptions raised during the parse propagate unchanged
     rather than being relabelled as bad input
   - validate_loaded stores the corpus it was handed, every call
   - reached directly because every main() test that mocks
     ComponentEdgeValidator makes the parse unreachable
   - validate_file (validator.py:224) must extract .components from the
     future parse_components_yaml result shape rather than treating the
     whole result as the components mapping (currently fails)

7. TestMainGraphGeneration - Graph output - 4 tests
   - Component graph generation
   - Mermaid format output for component graph
   - Component graph error handling
   - Debug flag passed to ComponentGraph

8. TestMainErrorHandling - Exception handling - 3 tests
   - KeyboardInterrupt handling (exit code 2)
   - Unexpected exceptions (exit code 2)
   - Validator initialization errors (exit code 2)

9. TestMainLifecycleMode - `--mode lifecycle` short-circuit hook - 8 tests
   - Pins the dedicated lifecycle-only entrypoint introduced to fix PR #277
     reviewer feedback (item 2): the lifecycle uniqueness check must be
     reachable on lifecycle-only commits without going through the
     components-validation pipeline.
   - Architectural intent: lifecycle mode bypasses get_staged_yaml_files,
     ComponentEdgeValidator, and graph generation entirely.
   - --mode lifecycle combined with --file is rejected rather than
     silently discarding --file; the docstring records what that test
     does not decide.

10. TestProductionInvocations - characterization of the shipped command
   forms - 13 tests. Green today by design; they lock what CI and
   pre-commit observe so the --file work cannot change it silently.
   - --block on the real corpus for each staged trigger file, including the
     validator options and the file-selection call
   - --block promotion, exercised with each warn-only check dirty alone
   - --mode lifecycle
   - --force, including outside a git repository, from a copy at the tree
     root as CI runs it, and with an isolated component present
   - --force --to-graph to an extensionless path, byte-compared with the
     committed diagram
   - the regenerate-graphs hook form (graph flag, -m, --quiet, no --force),
     including its empty-selection no-op
   Tests that read the live corpus carry the live_corpus marker.
"""

import builtins
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import Mock, mock_open, patch

import yaml

# Add scripts/hooks to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import riskmap_validator.utils
import riskmap_validator.validator
import validate_riskmap
from conftest import _REAL_COMPONENT_CATEGORIES
from riskmap_validator.config import DEFAULT_COMPONENTS_FILE
from riskmap_validator.graphing import MermaidConfigLoader, component_graph
from riskmap_validator.validator import ComponentEdgeValidator, CorpusParseError, EdgeValidationError
from validate_riskmap import main, parse_args


@pytest.fixture
def validated_corpus_paths(monkeypatch):
    """
    Record the corpus path parsed for validation, once per parse.

    Answers the question these tests actually need — which corpus reached
    validation — without naming the method that received it. main() reaches
    the corpus through more than one call today, and a single-parse
    restructure moves that seam; the question survives it, because whatever
    the shape, the corpus under validation is the one handed to
    parse_components_yaml.

    An earlier form of this fixture wrapped ComponentEdgeValidator.validate_file
    and asserted it was the method called with the corpus path. That pinned
    the call site: it made the production shape unchangeable without editing
    fifteen tests, which is a test double dictating production structure.
    The seam here is the parse itself, which every shape must perform exactly
    once on exactly the corpus being validated.

    Every module binding of parse_components_yaml is patched rather than one,
    so a new import elsewhere is covered without editing this fixture.

    Returns the list of recorded paths, which fills in as main() runs. The
    list length is meaningful: see
    test_main_parses_the_corpus_exactly_once_per_run.
    """
    calls: list[Path | None] = []
    real_parse = riskmap_validator.utils.parse_components_yaml

    def spy(file_path=None):
        calls.append(file_path)
        return real_parse(file_path)

    for module in (riskmap_validator.utils, riskmap_validator.validator, validate_riskmap):
        if getattr(module, "parse_components_yaml", None) is real_parse:
            monkeypatch.setattr(module, "parse_components_yaml", spy)

    return calls


def _assert_corpus_validated(paths: list[Path | None], expected: Path, label: str) -> None:
    """
    Assert the run validated exactly the expected corpus, however it got there.

    Identity, not call count: the number of parses per run is pinned
    separately by test_main_parses_the_corpus_exactly_once_per_run, so these
    assertions hold across a single-parse restructure without being edited.

    Args:
        paths: Recorded parse paths from the validated_corpus_paths fixture.
        expected: The corpus the invocation is required to validate.
        label: The invocation under test, for the failure message.
    """
    assert paths, f"{label} validated no corpus at all"
    assert set(paths) == {expected}, f"{label} must validate {expected}; the corpora parsed were {paths!r}"


@pytest.fixture
def validator_init_spy(monkeypatch):
    """
    Record the options main() constructs ComponentEdgeValidator with.

    Wraps __init__ rather than replacing the class, so the recorded run is the
    real one. Returns a list of (allow_isolated, verbose) tuples read back off
    the constructed instance, which is what downstream behaviour depends on —
    a test that asserted on the call's keyword shape would still pass if the
    values were computed wrongly and then overwritten.
    """
    settings: list[tuple[bool, bool]] = []
    real_init = ComponentEdgeValidator.__init__

    def spy(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        settings.append((self.allow_isolated, self.verbose))

    monkeypatch.setattr(ComponentEdgeValidator, "__init__", spy)
    return settings


class TestParseArgs:
    """Tests for parse_args() CLI argument parsing."""

    def test_parse_args_with_no_arguments_returns_defaults(self):
        """
        Test default argument values when no flags provided.

        Given: Script called with no arguments
        When: parse_args() is called
        Then: Returns namespace with all defaults (force=False, quiet=False, etc.)
        """
        with patch("sys.argv", ["script.py"]):
            args = parse_args()

        assert args.force is False
        assert args.file is None
        assert args.allow_isolated is False
        assert args.quiet is False
        assert args.to_graph is None
        assert args.debug is False
        assert args.mermaid_format is False

    def test_parse_args_with_force_flag_long_form(self):
        """
        Test --force flag sets force=True.

        Given: Script called with --force flag
        When: parse_args() is called
        Then: Returns namespace with force=True
        """
        with patch("sys.argv", ["script.py", "--force"]):
            args = parse_args()

        assert args.force is True

    def test_parse_args_with_force_flag_short_form(self):
        """
        Test -f flag sets force=True.

        Given: Script called with -f flag
        When: parse_args() is called
        Then: Returns namespace with force=True
        """
        with patch("sys.argv", ["script.py", "-f"]):
            args = parse_args()

        assert args.force is True

    def test_parse_args_with_file_path(self):
        """
        Test --file argument sets custom file path.

        Given: Script called with --file custom/path.yaml
        When: parse_args() is called
        Then: Returns namespace with file=Path("custom/path.yaml")
        """
        with patch("sys.argv", ["script.py", "--file", "custom/components.yaml"]):
            args = parse_args()

        assert args.file == Path("custom/components.yaml")

    def test_parse_args_with_allow_isolated_flag(self):
        """
        Test --allow-isolated flag sets allow_isolated=True.

        Given: Script called with --allow-isolated flag
        When: parse_args() is called
        Then: Returns namespace with allow_isolated=True
        """
        with patch("sys.argv", ["script.py", "--allow-isolated"]):
            args = parse_args()

        assert args.allow_isolated is True

    def test_parse_args_with_quiet_flag_long_form(self):
        """
        Test --quiet flag sets quiet=True.

        Given: Script called with --quiet flag
        When: parse_args() is called
        Then: Returns namespace with quiet=True
        """
        with patch("sys.argv", ["script.py", "--quiet"]):
            args = parse_args()

        assert args.quiet is True

    def test_parse_args_with_quiet_flag_short_form(self):
        """
        Test -q flag sets quiet=True.

        Given: Script called with -q flag
        When: parse_args() is called
        Then: Returns namespace with quiet=True
        """
        with patch("sys.argv", ["script.py", "-q"]):
            args = parse_args()

        assert args.quiet is True

    def test_parse_args_with_to_graph_path(self):
        """
        Test --to-graph argument sets output path.

        Given: Script called with --to-graph graph.md
        When: parse_args() is called
        Then: Returns namespace with to_graph=Path("graph.md")
        """
        with patch("sys.argv", ["script.py", "--to-graph", "output/graph.md"]):
            args = parse_args()

        assert args.to_graph == Path("output/graph.md")

    def test_parse_args_with_debug_flag(self):
        """
        Test --debug flag sets debug=True.

        Given: Script called with --debug flag
        When: parse_args() is called
        Then: Returns namespace with debug=True
        """
        with patch("sys.argv", ["script.py", "--debug"]):
            args = parse_args()

        assert args.debug is True

    def test_parse_args_with_mermaid_format_flag_long_form(self):
        """
        Test --mermaid-format flag sets mermaid_format=True.

        Given: Script called with --mermaid-format flag
        When: parse_args() is called
        Then: Returns namespace with mermaid_format=True
        """
        with patch("sys.argv", ["script.py", "--mermaid-format"]):
            args = parse_args()

        assert args.mermaid_format is True

    def test_parse_args_with_mermaid_format_flag_short_form(self):
        """
        Test -m flag sets mermaid_format=True.

        Given: Script called with -m flag
        When: parse_args() is called
        Then: Returns namespace with mermaid_format=True
        """
        with patch("sys.argv", ["script.py", "-m"]):
            args = parse_args()

        assert args.mermaid_format is True

    def test_parse_args_with_combined_arguments(self):
        """
        Test multiple arguments can be combined.

        Given: Script called with multiple flags and arguments
        When: parse_args() is called
        Then: Returns namespace with all specified values set correctly
        """
        with patch(
            "sys.argv",
            [
                "script.py",
                "--force",
                "--quiet",
                "--allow-isolated",
                "--to-graph",
                "graph.md",
                "--debug",
                "--mermaid-format",
            ],
        ):
            args = parse_args()

        assert args.force is True
        assert args.quiet is True
        assert args.allow_isolated is True
        assert args.to_graph == Path("graph.md")
        assert args.debug is True
        assert args.mermaid_format is True

    def test_parse_args_with_emission_mode_flat(self):
        """
        Test that --emission-mode flat parses to args.emission_mode == "flat".

        Given: Script called with --emission-mode flat
        When: parse_args() is called
        Then: Returns namespace with emission_mode == "flat"

        ADR-036 D3: the CLI override lever for A/B rendering the component
        graph without editing the config file.
        """
        with patch("sys.argv", ["script.py", "--emission-mode", "flat"]):
            args = parse_args()
        assert args.emission_mode == "flat"

    def test_parse_args_with_emission_mode_decoupled(self):
        """Test that --emission-mode decoupled parses to args.emission_mode == "decoupled"."""
        with patch("sys.argv", ["script.py", "--emission-mode", "decoupled"]):
            args = parse_args()
        assert args.emission_mode == "decoupled"

    def test_parse_args_without_emission_mode_defaults_to_none(self):
        """
        Test that omitting --emission-mode leaves the override unset.

        Given: argv with no --emission-mode flag
        When: parse_args() is called
        Then: args.emission_mode is None (not "flat" or "decoupled")

        ADR-036 D3: config remains the source of truth; the flag never
        persists. A default of "flat" (rather than None/absent) would force
        an override on every run even when the user never asked for one,
        silently defeating the config's own mode value. None is the only
        default that preserves "absent = use the config as-is."
        """
        with patch("sys.argv", ["script.py"]):
            args = parse_args()
        assert getattr(args, "emission_mode", None) is None, (
            f"args.emission_mode must default to None so absence of the flag never "
            f"overrides the config's own mode; got {getattr(args, 'emission_mode', 'MISSING')!r}"
        )

    def test_parse_args_rejects_invalid_emission_mode_value(self, capsys):
        """
        Test that an unrecognized --emission-mode value is rejected by argparse.

        Given: --emission-mode bogus (not "flat" or "decoupled")
        When: parse_args() is called
        Then: SystemExit(2), and argparse's error names 'bogus' as an invalid
              choice (not a generic "unrecognized arguments" -- see the
              false-positive-guard note below)

        False-positive guard: any unrecognized flag also produces SystemExit(2)
        via argparse's "unrecognized arguments" path, which would trivially
        satisfy a bare `exc_info.value.code == 2` assertion even if
        --emission-mode were not wired at all. Asserting the error text names
        'bogus' specifically (the `choices=` violation message, e.g. "invalid
        choice: 'bogus'") -- and does NOT say "unrecognized arguments" --
        proves the flag is wired with choices=["flat", "decoupled"], not just
        present as an accepted-but-unvalidated argument, mirroring the guard
        pattern used for --mode lifecycle elsewhere in this file.
        """
        with patch("sys.argv", ["script.py", "--emission-mode", "bogus"]):
            with pytest.raises(SystemExit) as exc_info:
                parse_args()

        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "unrecognized arguments" not in combined, (
            f"argparse rejected --emission-mode as an unrecognized FLAG rather than "
            f"rejecting 'bogus' as an invalid CHOICE -- the flag must be wired with "
            f"choices=['flat', 'decoupled'] before this test can validate the actual "
            f"invalid-value rejection. stderr: {combined!r}"
        )
        assert "bogus" in combined, (
            f"Expected argparse's invalid-choice error to name the offending value 'bogus'; got: {combined!r}"
        )


# ============================================================================
# TestRemovedGraphFlagsRejected — #477's flags are errors, not silent no-ops
# ============================================================================
#
# --to-controls-graph/-c and --to-risk-graph/-r were removed with their
# generators. Nothing else pins their absence: the removal shows up in this
# suite only as tests that no longer exist, and a deleted test asserts nothing.
# Re-adding either flag as a stub that parsed and did nothing would leave the
# whole suite green while a caller's `-r out.md` wrote no file and reported
# success.
#
# The short forms are asserted alongside the long ones because -c and -r are
# currently unclaimed; a later flag taking either letter would make these cases
# fail loudly, which is the intended signal — the reuse is fine, but it needs a
# deliberate edit here rather than silently restoring an old spelling.
# ============================================================================


class TestRemovedGraphFlagsRejected:
    """The control and risk graph flags removed by #477 must exit non-zero."""

    @pytest.mark.parametrize(
        "flag",
        ["--to-controls-graph", "-c", "--to-risk-graph", "-r"],
    )
    def test_removed_graph_flag_is_rejected(self, flag):
        """
        Each removed graph flag makes argparse exit 2 rather than parse.

        Given: Script called with a flag #477 removed, plus an output path
        When: parse_args() is called
        Then: argparse raises SystemExit(2), its unrecognised-argument code
        """
        with patch("sys.argv", ["script.py", flag, "out.md"]), pytest.raises(SystemExit) as exc_info:
            parse_args()

        assert exc_info.value.code == 2, f"`{flag}` must be rejected with argparse's exit code 2"


# ============================================================================
# TestFileFlagHelpText — `--file` documents where it is not valid
# ============================================================================
#
# --file is rejected in combination with --force and in --mode lifecycle
# (see TestMainFileFlag and TestMainLifecycleMode). Today nothing tells a user
# that before they hit the error: --file's help reads "Path to YAML file to
# validate (default: risk-map/yaml/components.yaml)" and the epilog
# (validate_riskmap.py:50-67) lists every flag as a standalone example without
# stating any incompatibility.
#
# The contract is that a user reading `--help` learns --file is exclusive with
# --force and unavailable in lifecycle mode. The phrasing is the
# implementer's, so these tests assert on substance — the two flag/mode names
# appearing in --file's own help — not on a sentence.
#
# argparse exposes no parser object here (parse_args() builds and consumes it
# internally), so both tests read the rendered `--help`. They overlap by
# construction; the split is by surface. The first pins what --file's help
# says once argparse has wrapped it, the second pins that `--help` as a whole
# still renders and exits 0 with its epilog intact, so the constraint cannot
# arrive by truncating the documentation around it.
# ============================================================================


def _render_help(capsys) -> tuple[str, int | str | None]:
    """
    Run `--help` through parse_args() and return (rendered text, exit code).

    argparse prints help to stdout and raises SystemExit, so this is the only
    way to see the help this script actually produces.
    """
    with patch("sys.argv", ["validate_riskmap.py", "--help"]):
        with pytest.raises(SystemExit) as exc_info:
            parse_args()

    captured = capsys.readouterr()
    return captured.out + captured.err, exc_info.value.code


def _option_help_block(help_text: str, option: str) -> str:
    """
    Return one option's help from rendered argparse output, unwrapped.

    argparse indents each option entry at a fixed column and any wrapped help
    text further right, so the block runs from the entry line until the next
    line indented no deeper — the next entry, or the end of the section.

    Lines are rejoined so an assertion on a flag name is not defeated by where
    the text happened to wrap. A continuation is joined without a space when
    the previous line ends in a hyphen: argparse formats help through textwrap,
    which breaks on hyphens by default, so "--mermaid-format" can arrive as
    "--mermaid-" + "format" and a plain space-join would silently turn every
    long flag name into an unfindable "--mermaid- format".

    Args:
        help_text: Full rendered `--help` output.
        option: Option string to extract, e.g. "--file".

    Returns:
        The option's entry and help text as a single line, or "" if absent.
    """
    joined = ""
    entry_indent: int | None = None

    for line in help_text.splitlines():
        stripped = line.strip()
        if entry_indent is None:
            # Match the option's own entry line, not its mention in the usage
            # summary (those lines start with "usage:" or a bracketed group).
            if stripped.startswith(option) and line[:1] == " ":
                entry_indent = len(line) - len(line.lstrip())
                joined = stripped
            continue
        if not stripped:
            break
        if len(line) - len(line.lstrip()) <= entry_indent:
            break
        joined += stripped if joined.endswith("-") else f" {stripped}"

    return joined


# Every combination --file is rejected in. A user has to be able to learn all
# of them from --help; which sentence carries them is the implementer's call.
_FILE_REJECTED_WITH = ("--force", "lifecycle")


class TestFileFlagHelpText:
    """Tests that --file documents the combinations it rejects."""

    def test_file_option_help_names_the_combinations_it_is_not_valid_with(self, capsys):
        """
        Test that --file's own help names every combination it is rejected in.

        Given: The script's rendered `--help`
        When:  The --file option's help block is read
        Then:  It mentions --force and lifecycle mode

        Substance, not wording: the implementer chooses the sentence. What is
        pinned is that the rejected combinations are discoverable from the
        option that they constrain, rather than only from the error a user
        gets after choosing them.

        --to-graph is deliberately absent from that list. It remains valid
        with --file, and listing it would tell a user the opposite of the
        contract.
        """
        help_text, _ = _render_help(capsys)
        block = _option_help_block(help_text, "--file")

        assert block, f"No --file entry found in the rendered help; got: {help_text!r}"
        for rejected in _FILE_REJECTED_WITH:
            assert rejected in block, (
                f"--file's help must say it cannot be combined with {rejected}; got: {block!r}"
            )

    def test_help_output_carries_the_constraint_and_still_renders(self, capsys):
        """
        Test that `--help` exits 0 and documents the constraint intact.

        Given: The script invoked with --help
        When:  argparse renders the help
        Then:  It exits 0, the --file block carries every constraint name, and
               the epilog's exit-code documentation is still present

        The epilog assertion is this test's own job: it stops the constraint
        from being introduced by rewriting or truncating the documentation
        around it. The exit-code list is what the rest of this suite cites
        when justifying 0/1/2, so it has to survive.
        """
        help_text, exit_code = _render_help(capsys)

        assert exit_code == 0, f"--help must exit 0; got {exit_code}"

        block = _option_help_block(help_text, "--file")
        for rejected in _FILE_REJECTED_WITH:
            assert rejected in block, f"The rendered --help must tie --file to {rejected}; got: {block!r}"

        assert "Exit Codes:" in help_text, f"The epilog's exit-code documentation must survive; got: {help_text!r}"
        for documented_code in ("0 - All validations passed", "1 - Validation failures found"):
            assert documented_code in help_text, (
                f"Expected {documented_code!r} to remain documented in the epilog; got: {help_text!r}"
            )

    def test_module_docstring_describes_file_consistently_with_help(self, capsys):
        """
        Test that the module docstring's --file entry has not drifted from --help.

        Given: validate_riskmap's module docstring and its rendered `--help`
        When:  The --file entry is read from each
        Then:  The docstring entry names --force and lifecycle mode, as the
               help does

        The docstring's Options block still reads "--file PATH  Custom YAML
        file path", which is now the least accurate description of the flag
        in the file: it predates the corpus-replacement semantics and every
        rejection. Two surfaces documenting the same flag should not
        contradict each other.

        Only the two modal constraints are required here, not the graph
        flags. The docstring is a summary; requiring the full list would be
        specifying its prose rather than holding it honest.
        """
        docstring = validate_riskmap.__doc__ or ""
        docstring_entry = _option_help_block(docstring, "--file")

        assert docstring_entry, f"No --file entry found in the module docstring; got: {docstring!r}"
        for rejected in ("--force", "lifecycle"):
            assert rejected in docstring_entry, (
                f"The module docstring's --file entry must not contradict --help: it needs to "
                f"name {rejected}. Got: {docstring_entry!r}"
            )


# ============================================================================
# Corpus open-count test infrastructure (PR #499 second-pass review, issue #477)
# ============================================================================
#
# A sys.addaudithook() callback has no unregister API -- once installed it
# stays for the life of the interpreter. Running the counted invocation of
# main() in a short-lived subprocess, rather than in-process under
# monkeypatch, keeps that installation from leaking into every test that
# runs after this one in the same pytest session.
#
# CPython emits the "open" audit event beneath every one of Path.read_text,
# io.open, builtins.open and os.open (verified on Python 3.14.4). Counting
# it, filtered to the resolved corpus path, is what makes this a real
# chokepoint: a builtins.open-only spy (this test's previous mechanism) is
# blind to Path.read_text, and a spy pinned to a class method
# (ComponentEdgeValidator.parse_corpus, also a previous mechanism here) is
# blind to a second read reached through a renamed or restructured seam.
#
# Both blind spots were demonstrated against this suite before this
# rewrite: a scratch implementation that hoists an early
# `components_file.read_text()` ahead of parse_corpus (two physical reads,
# differently ordered) opened the corpus twice but a builtins.open spy saw
# one; a scratch implementation that renames the read to
# ComponentEdgeValidator.parse_corpus_result while the nesting check's
# re-read switches from open() to read_text() also opened the corpus twice
# but a spy pinned to parse_corpus saw zero calls, let alone two. The audit
# hook below counts both correctly at 2, regardless of read order or which
# API performed either read.
_CORPUS_OPEN_AUDIT_RUNNER = """
import sys
from pathlib import Path

corpus_target = str(Path("{corpus}").resolve())
hits = []


def _hook(event, args):
    if event != "open" or not args:
        return
    try:
        resolved = str(Path(str(args[0])).resolve())
    except (OSError, ValueError, TypeError):
        return
    if resolved == corpus_target:
        hits.append(resolved)


sys.addaudithook(_hook)

sys.path.insert(0, {scripts_hooks_dir!r})
import validate_riskmap

sys.argv = ["script.py", "--force"]
try:
    validate_riskmap.main()
except SystemExit as exc:
    code = exc.code
else:
    code = None

print(f"__EXIT__={{code}}")
print(f"__OPENS__={{len(hits)}}")
"""


# Alias, not a redefinition: conftest._REAL_COMPONENT_CATEGORIES is the same
# four component categories mermaid-styles.schema.json's
# sharedElements.componentCategories.required declares, and this module used
# to restate them verbatim. Passed as write_riskmap_corpus's
# schema_categories override in the poisoner test below so its synthetic
# components.schema.json enum matches build_mermaid_styles()'s default
# styled categories exactly -- both names derive from the same source now,
# so they cannot drift apart the way two independent literals could. A
# mismatch here would make the category style check (validate_riskmap.py's
# ADR-030 D1 guard) report a spurious "no styling entry" finding for the
# corpus's own catData category, which --block would then promote and
# manufacture a failure this test does not intend to exercise.
_STYLE_GUARD_SCHEMA_CATEGORIES = _REAL_COMPONENT_CATEGORIES


@pytest.fixture
def _cleared_schema_categories_cache():
    """Clear graph_utils' module-level schema-category cache on both sides.

    _get_schema_categories() (riskmap_validator.graphing.graph_utils) caches
    a successful read in a module-level global keyed on nothing. Any test
    that chdirs into a synthetic corpus and exercises the category style
    check must clear this cache before AND after running, or a leaked
    cache entry from one directory's category set could make a
    later-running synthetic-corpus test trip on the wrong categories, or a
    synthetic read cached first could leak a fictional category into a
    later real-corpus run (backmerge 2026-08c plan, section 5). This
    mirrors test_category_style_guard.py's graph_utils_module fixture,
    which cannot be imported here directly: it is module-local, and pytest
    does not resolve fixtures across sibling test modules.

    This fixture is defense-in-depth, not the thing that makes
    test_main_nesting_check_is_blind_to_the_corpus_changing_after_the_parse_returns
    order-independent today: that test's corpus is built with
    _STYLE_GUARD_SCHEMA_CATEGORIES, which
    test_style_guard_schema_categories_matches_the_real_schema_enum below
    pins as set-equal to the real components.schema.json category enum. A
    cache entry warmed from the real repo root and a cache entry warmed
    from this test's synthetic corpus are therefore the same set of
    categories, so leaving a stale entry in place is unobservable here
    regardless of collection order -- removing this fixture entirely does
    not fail the test.

    Verified directly with the dependencies this repo actually pins
    (pytest, pytest-cov, pytest-timeout -- no order-randomizing plugin such
    as pytest-reverse is installed here), by giving pytest the two tests'
    node IDs in the opposite order to their order in this file. pytest runs
    explicitly-listed node IDs in the order given on the command line
    rather than file order, so this reproduces a reversed-collection run
    for this pair without any plugin:

    F="scripts/hooks/tests/test_validate_riskmap.py"
    T1="${F}::TestMainValidation::test_main_nesting_check_is_blind_to_the_corpus_changing_after_the_parse_returns"
    T2="${F}::TestStyleGuardSchemaCategoriesPin::test_style_guard_schema_categories_matches_the_real_schema_enum"
    pytest "$T1" "$T2"

    Both pass in that order, with or without this fixture's clears. A
    whole-suite version of the same property (each test file run alone and
    diffed against its in-suite result) is planned as
    scripts/tools/test-isolation-sweep.sh; cite that by name once it lands
    rather than this ad hoc two-test invocation.

    The order-independence this verifies is asymmetric, not a general
    property of the fixture -- see TestStyleGuardSchemaCategoriesPin below
    for what breaks, and how, if conftest._REAL_COMPONENT_CATEGORIES ever
    stops matching the real schema enum in either direction.

    The fixture still earns its keep against a corpus built with a
    category set that does NOT match the real enum (see
    test_category_style_guard.py's graph_utils_module fixture and its
    poisoned-cache tests for that shape); it is kept here for the same
    hygiene reason and to avoid leaking this test's synthetic categories
    forward into whichever test runs next, not because removing it
    currently turns this test red.
    """
    from riskmap_validator.graphing import graph_utils

    graph_utils.clear_schema_categories_cache()
    yield
    graph_utils.clear_schema_categories_cache()


class TestStyleGuardSchemaCategoriesPin:
    """
    Pins the property that actually delivers order-independence above.

    _cleared_schema_categories_cache's docstring used to claim its own
    clearing was what made
    test_main_nesting_check_is_blind_to_the_corpus_changing_after_the_parse_returns
    pass under any collection order. That was measured false: removing the
    fixture, or dropping its post-yield clear, changes nothing in forward
    or reversed collection (see that fixture's docstring for the runnable
    reversed-order command). What actually delivers order-independence is
    that _STYLE_GUARD_SCHEMA_CATEGORIES (imported from
    conftest._REAL_COMPONENT_CATEGORIES) is set-equal to the real
    components.schema.json category enum, so a stale cache entry warmed
    from either side is indistinguishable from a fresh one. This test
    makes that property explicit and falsifiable: if the two ever
    diverge -- conftest's tuple edited without updating the schema, or
    vice versa -- this fails, and the nesting-check test above regains a
    real dependency on _cleared_schema_categories_cache that this class
    would then need a companion mutation test to re-verify.

    This pin is an asymmetric alarm, not a symmetric drift detector: the
    two directions of divergence have different consequences downstream.

    - Shrinking conftest._REAL_COMPONENT_CATEGORIES (dropping a category
      the real schema still requires) fails this pin AND reintroduces real
      order-dependence in the nesting-check test: both this test's
      synthetic schema stub and its synthetic mermaid-styles.yaml are built
      from the same, now-smaller, tuple, so they stay mutually consistent
      -- but a schema-category cache entry warmed by an earlier test
      against the real (larger) schema would disagree with this test's
      smaller style set, reporting a spurious missing-style finding
      depending on what ran before it in the same process.
    - Growing the tuple (adding a category the real schema does not have)
      also fails this pin, but the nesting-check test stays green either
      way: the synthetic schema and synthetic styles it builds are still
      mutually consistent (both derive from the same larger tuple), so a
      stale cache entry from either side is a subset/superset difference
      the style check never trips on. This is a false alarm on the
      nesting test's actual behavior, but not on this pin, which is the
      point of having it: it is the only thing that would catch this
      direction of drift at all.

    In short: this pin fires on any drift in either direction, but only
    the shrink direction is also caught, independently, by the
    nesting-check test actually going red for a real reason.
    """

    def test_style_guard_schema_categories_matches_the_real_schema_enum(self):
        """
        Given: risk-map/schemas/components.schema.json's real category enum
        When: compared against _STYLE_GUARD_SCHEMA_CATEGORIES
        Then: the two sets are identical

        Real schema path resolved the same way
        test_category_style_guard.py's live-corpus test resolves it
        (repo-root-relative, not cwd-relative), so this assertion holds
        regardless of which directory the test process is chdir'd into by
        another test in the same session.
        """
        real_schema_path = (
            Path(__file__).parent.parent.parent.parent / "risk-map" / "schemas" / "components.schema.json"
        )
        with open(real_schema_path, encoding="utf-8") as fh:
            schema = json.load(fh)
        real_categories = set(schema["definitions"]["category"]["properties"]["id"]["enum"])

        assert set(_STYLE_GUARD_SCHEMA_CATEGORIES) == real_categories, (
            "_STYLE_GUARD_SCHEMA_CATEGORIES has drifted from the real schema enum -- "
            "the nesting-check test's order-independence depends on these matching exactly"
        )


# ============================================================================
# Differential-read poison test infrastructure (PR #499 second-pass review,
# issue #477)
# ============================================================================
#
# _install_corpus_read_poisoner patches the physical read primitives
# themselves -- builtins.open, io.open and Path.read_text -- rather than a
# named production method. A spy pinned to
# ComponentEdgeValidator.parse_corpus, which an earlier version of this test
# used, is blind to a second read reached through any other seam
# (parse_corpus_result, a fresh helper, anything else); these three are not
# a seam a refactor can route around, because every way Python reads a
# file's bytes goes through one of them.
#
# Each wrapper lets the real read complete first and captures its content
# before touching the file: poisoning happens only after the genuine
# physical read returns, so a single-read implementation's one read is
# never itself corrupted. Only read-mode calls are intercepted -- write
# calls (including the poison write triggered here) pass straight through
# untouched. Without that mode guard, the poison write's own on-disk
# mutation recurses into the same wrapper and raises: Path.read_text opens
# for 'r' via io.open internally, and write_text opens for 'w' via the same
# function, so an unguarded wrapper misreads the write as a second physical
# read of the corpus and tries to .read() a handle opened for writing
# (confirmed against a scratch reproduction: `io.UnsupportedOperation: not
# readable`).
def _install_corpus_read_poisoner(monkeypatch, corpus_target: Path, poisoned_content: str) -> list[bool]:
    """
    Rig builtins.open, io.open and Path.read_text so the first genuine physical
    read of corpus_target returns real content, then the file is rewritten to
    poisoned_content on disk.

    Returns a list that gains one element the moment that first read
    happens. Assert it is non-empty before trusting any outcome assertion
    downstream of it -- an empty list means the poison was never reachable
    and the test proved nothing.
    """
    triggered: list[bool] = []

    def _is_corpus(path_like) -> bool:
        try:
            return Path(path_like).resolve() == corpus_target
        except (OSError, ValueError, TypeError):
            return False

    def _poison_once() -> None:
        if not triggered:
            triggered.append(True)
            corpus_target.write_text(poisoned_content, encoding="utf-8")

    real_builtins_open = builtins.open
    real_io_open = io.open
    real_read_text = Path.read_text

    def open_wrapper(file, *args, **kwargs):
        mode = str(args[0] if args else kwargs.get("mode", "r"))
        if not _is_corpus(file) or not mode.startswith("r"):
            return real_builtins_open(file, *args, **kwargs)
        with real_builtins_open(file, *args, **kwargs) as fh:
            content = fh.read()
        _poison_once()
        return io.BytesIO(content) if "b" in mode else io.StringIO(content)

    def io_open_wrapper(file, *args, **kwargs):
        mode = str(args[0] if args else kwargs.get("mode", "r"))
        if not _is_corpus(file) or not mode.startswith("r"):
            return real_io_open(file, *args, **kwargs)
        with real_io_open(file, *args, **kwargs) as fh:
            content = fh.read()
        _poison_once()
        return io.BytesIO(content) if "b" in mode else io.StringIO(content)

    def read_text_wrapper(self_path, *args, **kwargs):
        if not _is_corpus(self_path):
            return real_read_text(self_path, *args, **kwargs)
        content = real_read_text(self_path, *args, **kwargs)
        _poison_once()
        return content

    monkeypatch.setattr(builtins, "open", open_wrapper)
    monkeypatch.setattr(io, "open", io_open_wrapper)
    monkeypatch.setattr(Path, "read_text", read_text_wrapper)

    return triggered


class TestMainValidation:
    """Tests for main() validation orchestration."""

    def test_main_exits_0_when_no_yaml_files_to_validate(self, capsys):
        """
        Test that main exits 0 when no YAML files need validation.

        Given: get_staged_yaml_files() returns empty list
        When: main() is called
        Then: Exits with code 0 and prints skip message
        """
        with patch("sys.argv", ["script.py"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=[]):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 0

        # Verify skip message
        captured = capsys.readouterr()
        assert "No YAML files to validate - skipping" in captured.out

    def test_main_exits_0_when_validation_passes(self, capsys):
        """
        Test that main exits 0 when validation succeeds.

        Given: YAML files are staged and ComponentEdgeValidator passes
        When: main() is called
        Then: Exits with code 0 and prints success message
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]

        with patch("sys.argv", ["script.py"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    # Mock validator instance
                    mock_validator = Mock()
                    mock_validator.validate_file.return_value = True
                    mock_validator.forward_map = {}
                    mock_validator.components = {}
                    mock_validator_class.return_value = mock_validator

                    with pytest.raises(SystemExit) as exc_info:
                        main()

        assert exc_info.value.code == 0

        # Verify success message
        captured = capsys.readouterr()
        assert "All YAML files passed component edge validation" in captured.out

    def test_main_exits_1_when_validation_fails(self, tmp_path, monkeypatch, capsys):
        """
        Test that main exits 1 when validation fails.

        Given: A staged components corpus whose edges are inconsistent
        When: main() is called
        Then: Exits with code 1 and prints failure message

        The corpus is real and really fails, rather than a mocked validator
        stubbed to return False. Stubbing the return value of a named method
        makes the outcome depend on main() calling that method: it decides
        how the parse and the checks are split, which is not what this test
        is about. A corpus that fails its edge checks produces the same
        guarantee under any arrangement.
        """
        _write_repo_layout_corpus(tmp_path, _COMPONENTS_EDGE_INCONSISTENT, _CLEAN_LOCAL_CONTROLS)
        monkeypatch.chdir(tmp_path)
        file_paths = [Path("risk-map/yaml/components.yaml")]

        with patch("sys.argv", ["script.py"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 1

        # Verify failure message
        captured = capsys.readouterr()
        assert "Component edge validation failed!" in captured.out
        assert "Fix the above errors before committing" in captured.out

    def test_main_force_mode_uses_default_file(self, capsys):
        """
        Test that force mode validates default components file.

        Given: Script called with --force flag
        When: main() is called
        Then: Uses DEFAULT_COMPONENTS_FILE for validation
        """
        with patch("sys.argv", ["script.py", "--force"]):
            with patch("validate_riskmap.get_staged_yaml_files") as mock_get_files:
                mock_get_files.return_value = [Path("risk-map/yaml/components.yaml")]
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    mock_validator = Mock()
                    mock_validator.validate_file.return_value = True
                    mock_validator.forward_map = {}
                    mock_validator.components = {}
                    mock_validator_class.return_value = mock_validator

                    with pytest.raises(SystemExit) as exc_info:
                        main()

        # Verify force mode was used
        from riskmap_validator.config import DEFAULT_COMPONENTS_FILE

        mock_get_files.assert_called_once_with(DEFAULT_COMPONENTS_FILE, True)

        # Verify force message
        captured = capsys.readouterr()
        assert "Force checking components" in captured.out

        assert exc_info.value.code == 0

    def test_main_quiet_mode_suppresses_output(self, capsys):
        """
        Test that quiet mode suppresses non-error output.

        Given: Script called with --quiet flag and validation passes
        When: main() is called
        Then: No informational messages printed
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]

        with patch("sys.argv", ["script.py", "--quiet"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    mock_validator = Mock()
                    mock_validator.validate_file.return_value = True
                    mock_validator.forward_map = {}
                    mock_validator.components = {}
                    mock_validator_class.return_value = mock_validator

                    with pytest.raises(SystemExit) as exc_info:
                        main()

        assert exc_info.value.code == 0

        # Verify no informational output
        captured = capsys.readouterr()
        assert "Checking for staged YAML files" not in captured.out
        assert "Found" not in captured.out
        assert "All YAML files passed" not in captured.out

    def test_main_initializes_validator_with_correct_options(self):
        """
        Test that ComponentEdgeValidator is initialized with correct options.

        Given: Script called with --allow-isolated and --quiet flags
        When: main() is called
        Then: Validator initialized with allow_isolated=True, verbose=False
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]

        with patch("sys.argv", ["script.py", "--allow-isolated", "--quiet"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    mock_validator = Mock()
                    mock_validator.validate_file.return_value = True
                    mock_validator.forward_map = {}
                    mock_validator.components = {}
                    mock_validator_class.return_value = mock_validator

                    with pytest.raises(SystemExit):
                        main()

        # Verify validator was initialized with correct options
        mock_validator_class.assert_called_once_with(allow_isolated=True, verbose=False)

    def test_main_adds_spacing_between_multiple_file_validation(self, capsys):
        """
        Test that spacing is added between file validations when multiple files.

        Given: Multiple YAML files are staged (non-force mode)
        When: main() is called without quiet mode
        Then: Empty line is printed between files for readability
        """
        # Simulate multiple files being staged
        file_paths = [Path("risk-map/yaml/components.yaml"), Path("risk-map/yaml/controls.yaml")]

        with patch("sys.argv", ["script.py"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    mock_validator = Mock()
                    mock_validator.validate_file.return_value = True
                    mock_validator.forward_map = {}
                    mock_validator.components = {}
                    mock_validator_class.return_value = mock_validator

                    with pytest.raises(SystemExit) as exc_info:
                        main()

        assert exc_info.value.code == 0

        # Verify output shows multiple files
        captured = capsys.readouterr()
        assert "Found 2 YAML files to validate" in captured.out

    def test_main_validates_components_file_when_only_controls_staged(
        self, tmp_path, monkeypatch, validated_corpus_paths
    ):
        """
        Test that a controls-only commit still validates components.yaml.

        Given: A tmp cwd holding a components and a controls corpus, no
               --file, and get_staged_yaml_files returning only
               risk-map/yaml/controls.yaml
        When:  main() is called
        Then:  get_staged_yaml_files is asked for the staged set (target_file
               None, force False), and the corpus that reaches validation is
               DEFAULT_COMPONENTS_FILE

        The validator is real here rather than mocked, and the assertion is on
        the corpus parsed rather than on which method received it. Mocking the
        validator and asserting `validate_file` was called would pin main()'s
        call site: the guarantee is about which corpus gets validated on a
        controls-only commit, and that has to hold however the parse and the
        checks are split up.

        The call-argument assertion is half the fence: passing
        DEFAULT_COMPONENTS_FILE as target_file on the non-force path would
        make the hook ignore staging entirely (utils.py:254-258 returns the
        target whenever it exists, without consulting the staged list), and
        nothing else in the repository would notice.

        Regression fence, and it passes today. validate_riskmap.py:228
        validates DEFAULT_COMPONENTS_FILE regardless of what
        get_staged_yaml_files returned, and that is deliberate: the
        validate-component-edges hook fires on components.yaml, controls.yaml
        and risks.yaml alike (.pre-commit-config.yaml:211-213), and edge
        consistency is a property of components.yaml whichever of the three
        was touched. Nothing in the suite asserted this, so
        `validate_file(yaml_files[0])` looks like a clean simplification
        while silently breaking every controls-only and risks-only commit —
        parse_components_yaml raises KeyError on a controls corpus,
        ComponentEdgeValidator.validate_loaded catches only EdgeValidationError,
        and the hook runs with --block.
        """
        _write_repo_layout_corpus(tmp_path, _CLEAN_LOCAL_COMPONENTS, _CLEAN_LOCAL_CONTROLS)
        monkeypatch.chdir(tmp_path)
        staged = [Path("risk-map/yaml/controls.yaml")]

        with patch("sys.argv", ["script.py"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=staged) as mock_get_files:
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 0
        mock_get_files.assert_called_once_with(None, False)
        _assert_corpus_validated(validated_corpus_paths, DEFAULT_COMPONENTS_FILE, "a controls-only commit")

    def test_main_parses_the_corpus_exactly_once_per_run(self, tmp_path, monkeypatch, validated_corpus_paths):
        """
        Test that a run reads the components corpus once.

        Given: A tmp cwd holding a clean components corpus
        When:  main() is called with --force
        Then:  parse_components_yaml is called exactly once

        main() once parsed twice: a "will this parse?" probe whose failure
        could be caught as CorpusParseError and reported cleanly, and then a
        second parse inside validate_file. The probe duplicated the work it
        was checking, and the two reads were not atomic — a corpus changing
        between them landed on the maintainers banner, the precise failure
        the probe existed to remove. main() now parses once and hands the
        result to validate_loaded; this test is what keeps it that way.

        Counts parse calls, not file reads. The corpus is opened once per
        run, and test_main_opens_the_corpus_exactly_once_per_run holds that
        separate number; a re-parse inside validate_loaded, or a second
        parse in main(), trips this one.

        The count is asserted here rather than folded into
        _assert_corpus_validated so that the identity assertions elsewhere
        stay agnostic about how the parse and the checks are arranged. This
        is the one place the parse count matters, and it is the reason the
        fixture's list length is meaningful.
        """
        _write_repo_layout_corpus(tmp_path, _CLEAN_LOCAL_COMPONENTS, _CLEAN_LOCAL_CONTROLS)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--force"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0
        assert validated_corpus_paths == [DEFAULT_COMPONENTS_FILE], (
            f"The corpus must be parsed once per run; it was parsed {len(validated_corpus_paths)} "
            f"time(s): {validated_corpus_paths!r}. A second parse duplicates the first and opens "
            f"a window for the file to change between them."
        )

    def test_main_opens_the_corpus_exactly_once_per_run(self, tmp_path):
        """
        Test that the corpus file is physically read exactly once per run.

        Given: A tmp cwd holding a clean components corpus
        When:  main() is called with --force, in a subprocess that counts
               CPython's own "open" audit event against the resolved corpus
               path (see _CORPUS_OPEN_AUDIT_RUNNER's module comment for why
               a subprocess and why an audit hook rather than a
               monkeypatched spy)
        Then:  Exactly one physical read of that path is observed

        One read means one file state: the ComponentNode map validated for
        edge consistency and the `categories:` block the nesting check
        compares components against both come from the same physical read,
        so there is no window in which the file can change between them.
        Today's production does not guarantee this: it opens the corpus
        twice, once in parse_corpus and again for the nesting check's own
        `categories:` read, which is exactly the gap PR #499's reviewer
        reproduced as manufactured nesting/promotion failures on a clean
        corpus (issue #477).

        The count is exact, not a maximum, so a regression in either
        direction is caught: dropping below one would mean the corpus was
        never actually read, and rising above one reopens the window this
        test exists to close, whatever API performs the extra read and
        whenever in the run it happens.

        Counts physical opens, not parse calls;
        test_main_parses_the_corpus_exactly_once_per_run holds the parse
        count, which a correct single-read implementation may still call
        more than once against the same in-memory result without touching
        the file again.
        """
        _write_repo_layout_corpus(tmp_path, _CLEAN_LOCAL_COMPONENTS, _CLEAN_LOCAL_CONTROLS)

        scripts_hooks_dir = str(Path(__file__).resolve().parent.parent)
        runner_source = _CORPUS_OPEN_AUDIT_RUNNER.format(
            corpus=str(DEFAULT_COMPONENTS_FILE),
            scripts_hooks_dir=scripts_hooks_dir,
        )
        runner_path = tmp_path / "_corpus_open_audit_runner.py"
        runner_path.write_text(runner_source, encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(runner_path)],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )

        assert result.returncode == 0, (
            f"the audit-hook runner subprocess must exit cleanly; got {result.returncode}. "
            f"stdout: {result.stdout!r} stderr: {result.stderr!r}"
        )

        stdout_lines = result.stdout.splitlines()
        exit_line = next((line for line in stdout_lines if line.startswith("__EXIT__=")), None)
        opens_line = next((line for line in stdout_lines if line.startswith("__OPENS__=")), None)
        assert exit_line is not None and opens_line is not None, (
            f"the runner must report both result markers; got stdout: {result.stdout!r}"
        )

        main_exit_code = exit_line.split("=", 1)[1]
        open_count = int(opens_line.split("=", 1)[1])

        assert main_exit_code == "0", (
            f"main() must exit 0 on a clean corpus; the runner reported {main_exit_code!r}. "
            f"Full stdout: {result.stdout!r}"
        )
        assert open_count == 1, (
            f"the corpus must be opened exactly once per run, counted by CPython's own 'open' "
            f"audit event rather than by intercepting a named API; it was opened {open_count} "
            f"time(s). A second physical read -- through open(), io.open(), Path.read_text(), "
            f"os.open(), or any other API -- reopens the window for the file to change between "
            f"the components parse and the nesting check's categories read."
        )

    def test_main_nesting_check_is_blind_to_the_corpus_changing_after_the_parse_returns(
        self, tmp_path, monkeypatch, capsys, write_riskmap_corpus, _cleared_schema_categories_cache
    ):
        """
        Test that the nesting check cannot observe the corpus changing after its first read.

        Given: A tmp cwd holding a clean components corpus PLUS the two
               comparison oracles the category style check reads
               (mermaid-styles.yaml and components.schema.json, supplied by
               write_riskmap_corpus) -- without both, the style check itself
               fails to run and --block promotes that failure, manufacturing
               an exit 1 unrelated to the nesting-check seam this test
               targets. Wired via _install_corpus_read_poisoner so the first
               physical read of components.yaml -- through whichever of
               builtins.open, io.open or Path.read_text the implementation
               uses -- is followed by a disk rewrite to a `categories:`
               block declaring neither category the real components use.
        When:  main() is called with --force --block
        Then:  Exit code 0, stdout shows the nesting check actually ran and
               reported no findings, and the poison is confirmed to have
               fired

        Order-independence (backmerge 2026-08c plan, section 5):
        _get_schema_categories() caches its result in a module-level global
        that survives across tests. This test's corpus is deliberately
        built with _STYLE_GUARD_SCHEMA_CATEGORIES (imported from
        conftest._REAL_COMPONENT_CATEGORIES), which
        TestStyleGuardSchemaCategoriesPin pins as set-equal to the real
        components.schema.json category enum -- so a cache entry warmed
        from either this synthetic corpus or the real repo root carries the
        same category set, and this test passes under any collection order
        with or without _cleared_schema_categories_cache. Verified directly
        by running this test and the pin test with their node IDs reversed
        on the command line (no order-randomizing plugin is installed in
        this repo; see _cleared_schema_categories_cache's docstring above
        for the exact invocation) -- both pass either order. That
        order-independence is asymmetric on conftest._REAL_COMPONENT_CATEGORIES
        staying set-equal to the real schema enum: see
        TestStyleGuardSchemaCategoriesPin's docstring for which direction of
        drift actually breaks this test versus which direction only fails
        the pin. The fixture is retained anyway: it stops this run from
        leaking its synthetic categories forward into a later test whose
        corpus categories genuinely diverge from the real enum -- the same
        shape
        test_category_style_guard.py::TestSchemaCategoryResolution::test_resolves_schema_relative_to_cwd
        depends on its own graph_utils_module fixture's pre-clear for,
        using a fictional "componentsSynthetic" category that would read
        back wrong if a stale real-root or other-synthetic entry survived
        from an earlier test.

        This is the failure PR #499's reviewer reproduced directly: a
        second read of components.yaml, after the first, observing
        different (but individually valid) content manufactured
        nesting/promotion findings on a corpus that has none, and --block
        turned that into exit 1 (issue #477).

        Non-vacuity: an earlier version of this test monkeypatched
        ComponentEdgeValidator.parse_corpus and asserted only the outcome.
        A scratch implementation that reads the corpus through a renamed
        method (parse_corpus_result) while the nesting check's own re-read
        moved from open() to read_text() left that patch target uncalled --
        the poison was never written, and the old test passed at exit 0
        having exercised nothing (reproduced directly: `poison_applied`
        stayed empty, and the run still reported 2 manufactured nesting
        issues under a spy pinned to builtins.open alone). The `poisoned`
        assertion below closes that gap: it fails loudly if the corpus is
        never physically read at all, rather than passing by default.

        This test does not, by itself, catch every second-read shape. A
        scratch implementation that hoists an early
        `components_file.read_text()` ahead of the components parse, and
        feeds the nesting check from that early result, is immune to it:
        the poison lands after the FIRST physical read, and in that shape
        the first read is the one feeding the nesting check, so it is
        captured before the disk changes underneath it, while the
        components parse's later read observes the poisoned `categories:`
        block harmlessly (parse_components_yaml never looks at
        `categories:`). Reproduced directly against that scratch shape:
        this test passes at exit 0 with the poison confirmed applied, even
        though the corpus was genuinely read twice. That is exactly why
        test_main_opens_the_corpus_exactly_once_per_run is the primary
        chokepoint for read *ordering* -- it counts every physical read of
        the corpus regardless of when in the run each one happens, so it
        fails on that same scratch shape at open_count == 2 -- and this
        test's job is narrower: given that a read happened, prove nothing
        after it can change the answer.
        """
        # schema_categories is pinned to the same four categories
        # build_mermaid_styles()'s default body styles (rather than left to
        # derive from _CLEAN_LOCAL_COMPONENTS's own "catData"), so the
        # category style check's schema-vs-styled comparison matches and
        # does not itself report a finding -- see
        # _STYLE_GUARD_SCHEMA_CATEGORIES above.
        write_riskmap_corpus(
            tmp_path,
            _CLEAN_LOCAL_COMPONENTS,
            _CLEAN_LOCAL_CONTROLS,
            schema_categories=list(_STYLE_GUARD_SCHEMA_CATEGORIES),
        )
        monkeypatch.chdir(tmp_path)

        # `components:` carries the real, unmodified list forward so a second
        # physical read that happens to feed component parsing (rather than
        # nesting) still parses cleanly instead of raising KeyError -- a
        # crash would exit 2, not 1, and hide the mismatch this test checks
        # for. Only `categories:` needs to differ: the nesting check's
        # source data extracts nothing else from it (validate_riskmap.py
        # builds category_to_subcategories from
        # `_components_data.get("categories", [])` alone). Declaring a
        # category neither real component uses manufactures a Class 1
        # mismatch for both components.
        poisoned_content = yaml.dump(
            {
                "components": _CLEAN_LOCAL_COMPONENTS["components"],
                "categories": [{"id": "catOther", "subcategory": [{"id": "subOther"}]}],
            }
        )
        corpus_target = DEFAULT_COMPONENTS_FILE.resolve()
        poisoned = _install_corpus_read_poisoner(monkeypatch, corpus_target, poisoned_content)

        with patch("sys.argv", ["script.py", "--force", "--block"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()

        assert poisoned, (
            "the poison wrapper never observed a physical read of the corpus; nothing was "
            "proven, because the seam this test targets was never exercised"
        )
        assert exc_info.value.code == 0, (
            "The corpus changing on disk after its first physical read must not manufacture "
            f"nesting findings; got exit {exc_info.value.code}. stdout: {captured.out!r}"
        )
        assert "✅ Category/subcategory nesting check passed" in captured.out, (
            "the nesting check must actually run and report success against the components "
            f"the first read returned, not be silently skipped; stdout: {captured.out!r}"
        )


# ============================================================================
# TestMainFileFlag — `--file PATH` end-to-end wiring
# ============================================================================
#
# Background: parse_args() accepts --file PATH but main() never reads
# args.file. The value is parsed into the namespace and dropped: main()
# selects DEFAULT_COMPONENTS_FILE under --force and None otherwise, so
# `--file X` silently validates either the default corpus or nothing at all.
# Observed against the epilog's own documented example:
#
#   $ validate_riskmap.py --file risk-map/yaml/components.yaml
#   🔍 Checking for staged YAML files...
#      No YAML files to validate - skipping        # exit 0
#
#   $ validate_riskmap.py --file /nonexistent/nope.yaml
#   (identical output, exit 0)
#
# The existing suite missed this because every main() test stubs
# get_staged_yaml_files wholesale and no test passes --file into main().
# TestParseArgs::test_parse_args_with_file_path covers argparse only — it
# would still pass if every line after parse_args() were deleted.
#
# Decided contracts
# -----------------
# C1. `--force --file X` is rejected as contradictory (exit 2). Both flags
#     answer the same question — which corpus to validate — and the epilog
#     presents them as alternatives, so accepting both means silently
#     picking one.
#
#     No branch of get_staged_yaml_files dies with C1. An earlier draft of
#     this comment said the force branch (utils.py:227-233) becomes
#     unreachable; that is wrong and acting on it would reintroduce this
#     issue's own signature. `--force` alone still calls
#     get_staged_yaml_files(DEFAULT_COMPONENTS_FILE, True) and lands in that
#     branch, whose distinguishing property is that it never shells out to
#     git — delete it and `--force` outside a git repository exits 0 having
#     validated nothing. It also carries
#     test_utils.py::test_get_staged_files_force_check_with_existing_file_returns_file
#     and test_validate_component_edges.py::test_get_staged_yaml_files_force_mode.
#     The branch that C2 makes unreachable is the non-force target_file
#     branch at utils.py:254-258, since main() will no longer pass a
#     non-None target_file with force False.
#
#     Correcting the record: an earlier draft of these tests recommended
#     composing the two flags on the grounds that they are orthogonal —
#     --force selecting whether staging is consulted, --file selecting the
#     corpus. That is false against the source. Once target_file is
#     non-None, get_staged_yaml_files ignores staged_files entirely
#     (utils.py:254-258), so --file alone already bypasses staging; there is
#     nothing left for --force to add. The companion argument, that the
#     force branch "already implements the combination", is
#     non-differentiating for the same reason: the non-force branch accepts
#     target_file identically.
#
# C2. `--file` short-circuits inside main(). It selects the corpus directly
#     and does not route through get_staged_yaml_files. "This corpus,
#     ignore staging" has to hold outside a git repository as well, which
#     the routed design cannot deliver: get_staged_yaml_files shells out to
#     `git diff --cached` with check=True and returns [] when that call
#     fails, so a routed --file exits 0 with a git warning in any
#     non-repository directory.
#
# C3. `--file` swaps the components corpus only. The lifecycle-order,
#     controls↔components mirror and category/subcategory nesting checks
#     read hardcoded repo paths (validate_riskmap.py:249, 281-282) and are
#     gated on validator.components, which a working --file populates. Run
#     from the repo root, `--file custom.yaml --block` would otherwise
#     cross-check the repo's controls.yaml against an unrelated corpus and
#     fail on manufactured findings. Those checks therefore skip when --file
#     is set, and say so rather than vanishing.
#
# Exit-code contract for an unusable --file path (missing, a directory, or
# a file that is not a components corpus): non-zero, reported cleanly.
# Justified against the exit codes the script documents in its own epilog —
# 0 = all validations passed, 1 = validation failures found, 2 =
# configuration or runtime error. A --file path that cannot be used is a bad
# invocation, not a finding about the corpus, so folding it into 1 would make
# a pre-commit hook report "your YAML is broken" when the real problem is
# "your command names a file that isn't there". 2 also matches argparse's own
# exit code for CLI misuse, keeping all invocation errors on one code.
#
# Exit 2 has to be reached deliberately, not by crashing: the broad handler
# at validate_riskmap.py:424-427 also exits 2 and prints "Please report this
# issue to the maintainers", so `raise FileNotFoundError(args.file)` would
# satisfy a bare exit-code assertion while telling a user with a typo to file
# a bug report. Every test below that expects a non-zero exit therefore also
# asserts the crash banner is absent. yaml_to_markdown.py:1350 shows the
# intended shape: name the offending path, return the failure code.
# ============================================================================


# Minimal component corpora for the end-to-end --file tests. Edge shape
# matches parse_components_yaml: edges.to / edges.from per component.
# Component IDs are deliberately absent from the repo corpus so that the C3
# repo-scoped-skip tests, run from the repo root, would produce mirror warnings
# if those checks were not skipped.
_COMPONENTS_CONSISTENT: dict[str, Any] = {
    "components": [
        {
            "id": "componentAlpha",
            "title": "Alpha",
            "category": "componentsData",
            "edges": {"to": ["componentBeta"]},
        },
        {
            "id": "componentBeta",
            "title": "Beta",
            "category": "componentsData",
            "edges": {"from": ["componentAlpha"]},
        },
    ]
}

# Both components declare an outgoing edge and neither declares the
# reciprocal incoming edge, so validate_edge_consistency reports
# "has outgoing edges but no corresponding incoming edges" for each.
# Both still carry edges, so this is an edge-consistency failure rather
# than an isolated-component failure (which --allow-isolated could mask).
_COMPONENTS_EDGE_INCONSISTENT: dict[str, Any] = {
    "components": [
        {
            "id": "componentAlpha",
            "title": "Alpha",
            "category": "componentsData",
            "edges": {"to": ["componentBeta"]},
        },
        {
            "id": "componentBeta",
            "title": "Beta",
            "category": "componentsData",
            "edges": {"to": ["componentAlpha"]},
        },
    ]
}

# Edges point at a component ID that the file never declares, so
# find_missing_components reports it by name. The name appears nowhere in the
# invocation, only inside the corpus: echoing it back is proof the file was
# parsed rather than merely opened or named.
_COMPONENTS_MISSING_REFERENCE: dict[str, Any] = {
    "components": [
        {
            "id": "componentAlpha",
            "title": "Alpha",
            "category": "componentsData",
            "edges": {"to": ["componentGhost"]},
        },
        {
            "id": "componentBeta",
            "title": "Beta",
            "category": "componentsData",
            "edges": {"from": ["componentAlpha"]},
        },
    ]
}

# Well-formed YAML that is not a components corpus: parse_components_yaml
# indexes data["components"] and raises KeyError, which validate_file does
# not catch (ComponentEdgeValidator.validate_loaded handles EdgeValidationError only).
_NOT_A_COMPONENTS_CORPUS: dict[str, Any] = {"controls": [{"id": "controlSomething", "title": "Something"}]}

# Two components, bidirectionally linked, whose (category, subcategory) pairs
# are declared in the categories block: the nesting check finds nothing.
# controlOne references only IDs that exist: the mirror check finds nothing.
_CLEAN_LOCAL_COMPONENTS: dict[str, Any] = {
    "categories": [{"id": "catData", "subcategory": [{"id": "subStorage"}]}],
    "components": [
        {
            "id": "componentLocalA",
            "title": "Local A",
            "category": "catData",
            "subcategory": "subStorage",
            "edges": {"to": ["componentLocalB"]},
        },
        {
            "id": "componentLocalB",
            "title": "Local B",
            "category": "catData",
            "subcategory": "subStorage",
            "edges": {"from": ["componentLocalA"]},
        },
    ],
}

# Same corpus with the subcategories removed: check_category_subcategory_nesting
# emits its "missing a subcategory" warning for both components while the
# mirror check stays clean.
_NESTING_DIRTY_COMPONENTS: dict[str, Any] = {
    "categories": [{"id": "catData", "subcategory": [{"id": "subStorage"}]}],
    "components": [
        {
            "id": "componentLocalA",
            "title": "Local A",
            "category": "catData",
            "edges": {"to": ["componentLocalB"]},
        },
        {
            "id": "componentLocalB",
            "title": "Local B",
            "category": "catData",
            "edges": {"from": ["componentLocalA"]},
        },
    ],
}

_CLEAN_LOCAL_CONTROLS: dict[str, Any] = {
    "controls": [
        {
            "id": "controlOne",
            "title": "Control One",
            "category": "controlsData",
            "components": ["componentLocalA", "componentLocalB"],
            "risks": [],
            "personas": [],
        }
    ]
}

# References a component ID that the components corpus does not declare, so
# the mirror check warns while the nesting check stays clean.
_MIRROR_DIRTY_CONTROLS: dict[str, Any] = {
    "controls": [
        {
            "id": "controlOne",
            "title": "Control One",
            "category": "controlsData",
            "components": ["componentLocalA", "componentVanished"],
            "risks": [],
            "personas": [],
        }
    ]
}


def _write_repo_layout_corpus(base: Path, components: dict[str, Any], controls: dict[str, Any]) -> Path:
    """
    Write components.yaml and controls.yaml under <base>/risk-map/yaml/.

    Used by the --block promotion tests, which need the warn-only checks to
    run against a corpus whose findings are known. lifecycle-stage.yaml is
    left out so the lifecycle check takes its documented graceful skip and
    only the mirror and nesting checks can affect the exit code.

    Args:
        base: Temporary directory root (pytest tmp_path).
        components: Parsed components YAML content.
        controls: Parsed controls YAML content.

    Returns:
        The base path, for use as cwd.
    """
    yaml_dir = base / "risk-map" / "yaml"
    yaml_dir.mkdir(parents=True)
    (yaml_dir / "components.yaml").write_text(yaml.dump(components), encoding="utf-8")
    (yaml_dir / "controls.yaml").write_text(yaml.dump(controls), encoding="utf-8")
    return base


# The three post-validation checks, by the sentence each prints on success.
_DOWNSTREAM_CHECK_SENTENCES = (
    "Lifecycle stage order uniqueness check passed",
    "mirror check passed",
    "nesting check passed",
)

# Exceptions the parse guard must NOT catch. Two stand for a defect in this
# tool, one for a domain error surfacing where it does not belong; none is a
# statement about the user's file, so none may be reported as an unusable
# corpus. The guard's tuple is narrow on purpose and these hold it there.
_DEFECT_EXCEPTIONS = (NameError, ImportError, EdgeValidationError)

_CRASH_BANNER_MARKERS = ("Unexpected error", "report this issue to the maintainers")

# Printed by ComponentEdgeValidator only after a corpus parses and every edge
# check passes. Asserting it keeps the clean-corpus cases from being
# satisfiable by an implementation that prints the --file path and exits.
_EDGES_CONSISTENT = "Component edges are consistent"

# The line naming the corpus about to be validated. Part of the output of 72
# shipped invocations, and the only place a user is told which file the run
# is about, so it is a contract rather than a debug aid.
_ANNOUNCEMENT_PREFIX = "Validating component edges in:"


def _announced_corpus(combined: str) -> str:
    """
    Return the corpus path the run announced it was validating.

    Args:
        combined: Captured stdout and stderr from a run.

    Returns:
        The path as printed, or "" when the run announced nothing.
    """
    for line in combined.splitlines():
        if _ANNOUNCEMENT_PREFIX in line:
            return line.split(_ANNOUNCEMENT_PREFIX, 1)[1].strip()
    return ""


def _write_custom_components(base: Path, components: dict[str, Any], name: str = "custom-components.yaml") -> Path:
    """
    Write a components corpus to <base>/<name> and return its absolute path.

    The corpus is deliberately NOT written to the default location
    (risk-map/yaml/components.yaml). With no default corpus under base,
    "the --file path was validated" cannot be confused with "the default
    corpus happened to be validated and happened to give the same result".

    No git repository is created: per C2, --file must not depend on one.

    Args:
        base: Temporary directory root (pytest tmp_path).
        components: Parsed components YAML content.
        name: File name to write under base.

    Returns:
        Absolute path to the written corpus.
    """
    corpus = base / name
    corpus.write_text(yaml.dump(components), encoding="utf-8")
    return corpus


def _assert_not_crash_shaped(combined: str) -> None:
    """
    Fail if output carries the unexpected-exception banner.

    Guards every non-zero-exit expectation in this module: the broad handler
    at validate_riskmap.py:424-427 exits 2 for any escaping exception, so an
    exit-code assertion alone cannot tell a deliberate rejection from a crash.
    """
    for marker in _CRASH_BANNER_MARKERS:
        assert marker not in combined, (
            f"Output carries the unexpected-exception banner ({marker!r}); a bad argument or "
            f"an unusable corpus must be reported as a usage error, not as an internal bug. "
            f"Output: {combined!r}"
        )


def _line_reports_skip(combined: str, keyword: str) -> bool:
    """
    True if some output line names keyword (case-insensitive) and says it was skipped.

    Line-scoped rather than whole-output substring matching so an unrelated
    skip message elsewhere cannot satisfy the assertion. Wording-agnostic on
    purpose: C3 fixes that the checks announce their skip, not how.
    """
    return any(keyword in line.lower() and "skip" in line.lower() for line in combined.splitlines())


class TestMainFileFlag:
    """
    Tests for the `--file PATH` argument reaching main()'s corpus selection.

    Every test here must fail against an implementation that parses --file
    and discards it, with one deliberate exception:
    test_main_with_force_on_wrong_shape_default_corpus_fails_cleanly passes no
    --file at all. It sits here so it reads next to its --file counterpart,
    because the pairing is the point — both are the same error through the
    same call, and they must reach the user the same way.
    """

    def test_main_with_file_flag_does_not_route_through_get_staged_yaml_files(self, tmp_path, monkeypatch, capsys):
        """
        Test that --file selects the corpus directly (C2).

        Given: A tmp cwd holding an edge-consistent corpus, and
               get_staged_yaml_files patched to return no files
        When:  main() is called with --file <that corpus>
        Then:  get_staged_yaml_files is never called, the run exits 0, and
               the named corpus appears in the validation output

        The patched return value is [] so that a routed implementation fails
        loudly here (it would take the "no files to validate" skip path)
        rather than passing on a truthy Mock.
        """
        corpus = _write_custom_components(tmp_path, _COMPONENTS_CONSISTENT)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--file", str(corpus)]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=[]) as mock_get_files:
                with pytest.raises(SystemExit) as exc_info:
                    main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        mock_get_files.assert_not_called()
        assert exc_info.value.code == 0, (
            f"Expected exit 0 on an edge-consistent corpus; got {exc_info.value.code}. Output: {combined!r}"
        )
        assert str(corpus) in combined, (
            f"Expected the --file corpus to appear in the validation output; got: {combined!r}"
        )
        assert _EDGES_CONSISTENT in combined, (
            f"Expected the edge checks to have run against the corpus, not just the path to be "
            f"echoed; got: {combined!r}"
        )

    def test_main_with_file_flag_works_outside_a_git_repository(self, tmp_path, monkeypatch, capsys):
        """
        Test that --file works in a directory that is not a git repository (C2).

        Given: A tmp cwd that has never been git-initialised, holding an
               edge-consistent corpus
        When:  main() is called with --file <that corpus>, nothing mocked
        Then:  Exits 0, the corpus is validated, and no git error surfaces

        This is the flag's main use case — validating a corpus that is not
        part of a checkout. A design that routes --file through
        get_staged_yaml_files cannot satisfy it: `git diff --cached` fails
        outside a repository, the CalledProcessError branch prints
        "Make sure you're in a git repository" and returns [], and the run
        exits 0 having validated nothing.
        """
        corpus = _write_custom_components(tmp_path, _COMPONENTS_CONSISTENT)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--file", str(corpus)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert "Make sure you're in a git repository" not in combined, (
            f"--file must not depend on git status; got a git warning: {combined!r}"
        )
        assert "No YAML files to validate" not in combined, (
            f"--file named an existing corpus but main() took the skip path; output: {combined!r}"
        )
        assert exc_info.value.code == 0, (
            f"Expected exit 0 on an edge-consistent corpus; got {exc_info.value.code}. Output: {combined!r}"
        )
        assert _EDGES_CONSISTENT in combined, (
            f"Expected the edge checks to have run against the corpus; got: {combined!r}"
        )

    @pytest.mark.parametrize(
        "corpus_content,expected_code,expected_markers",
        [
            (_COMPONENTS_CONSISTENT, 0, (_EDGES_CONSISTENT,)),
            (_COMPONENTS_EDGE_INCONSISTENT, 1, ("componentAlpha", "componentBeta")),
            (_COMPONENTS_MISSING_REFERENCE, 1, ("componentGhost",)),
        ],
        ids=["consistent", "edge-inconsistent", "missing-reference"],
    )
    def test_main_with_file_flag_validates_the_named_file(
        self, corpus_content, expected_code, expected_markers, tmp_path, monkeypatch, capsys
    ):
        """
        Test end-to-end that the content of the --file corpus decides the outcome.

        Given: A tmp cwd holding one of three corpora at the same path, and
               no corpus at the default location
        When:  main() is called with --file <that corpus>, nothing mocked
        Then:  The exit code and the reported findings follow the file's
               content, the named path appears in the output, and the "no
               files to validate" skip path is not taken

        Parametrised on content rather than split into separate cases so the
        argv is identical across all three: an implementation that opens or
        merely names the file cannot produce three different outcomes from
        it. The missing-reference case is the sharpest — "componentGhost"
        exists only inside the corpus, so echoing it back cannot be faked
        from the invocation.

        Exit 1 is the script's documented "validation failures found".
        """
        corpus = _write_custom_components(tmp_path, corpus_content)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--file", str(corpus)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert "No YAML files to validate" not in combined, (
            f"--file named an existing corpus but main() took the skip path; output: {combined!r}"
        )
        assert str(corpus) in combined, (
            f"Expected the --file path to appear in the validation output; got: {combined!r}"
        )
        assert exc_info.value.code == expected_code, (
            f"Expected exit {expected_code} for this corpus; got {exc_info.value.code}. Output: {combined!r}"
        )
        for marker in expected_markers:
            assert marker in combined, (
                f"Expected {marker!r} in the output — the corpus content must drive what is "
                f"reported. Got: {combined!r}"
            )

    def test_main_with_file_flag_and_quiet_still_validates(self, tmp_path, monkeypatch, capsys):
        """
        Test that --quiet suppresses narration without disabling --file.

        Given: A tmp cwd holding an edge-inconsistent corpus
        When:  main() is called with --file <that corpus> --quiet
        Then:  Exits 1, and the informational narration is suppressed

        The outcome, not the narration, is the evidence that the corpus was
        read: under --quiet the validator's per-file log line is suppressed
        (ComponentEdgeValidator.log is verbose-gated), so this test cannot
        assert the path appears in output the way its siblings do. Asserting
        the exit code the corpus dictates keeps the same guarantee without
        weakening the --quiet contract.
        """
        corpus = _write_custom_components(tmp_path, _COMPONENTS_EDGE_INCONSISTENT)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--file", str(corpus), "--quiet"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 1, (
            f"Expected exit 1 on an edge-inconsistent corpus named by --file --quiet; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert "Checking for staged YAML files" not in combined, (
            f"--quiet must suppress the file-selection narration; got: {combined!r}"
        )
        assert "Found" not in combined, f"--quiet must suppress the file-count line; got: {combined!r}"

    def test_main_with_missing_file_path_exits_2_and_reports_the_path(self, tmp_path, monkeypatch, capsys):
        """
        Test that a --file path that does not exist is reported, not skipped.

        Given: A tmp cwd containing no YAML corpus at all, and a --file path
               pointing at a file that does not exist
        When:  main() is called
        Then:  Exits with code 2, names the missing path, and does not print
               the unexpected-exception banner

        Exit-code contract: 2 (configuration error) per the module comment
        above. Current behaviour: exits 0 with "No YAML files to validate -
        skipping", indistinguishable from a clean run.
        """
        monkeypatch.chdir(tmp_path)
        missing = tmp_path / "no-such-dir" / "components.yaml"

        with patch("sys.argv", ["script.py", "--file", str(missing)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"Expected exit 2 (configuration error) for a --file path that does not exist; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert str(missing) in combined, (
            f"Expected the missing --file path to be named in the output; got: {combined!r}"
        )
        _assert_not_crash_shaped(combined)

    def test_main_with_file_flag_on_a_directory_exits_2_cleanly(self, tmp_path, monkeypatch, capsys):
        """
        Test that --file pointing at a directory is rejected as a usage error.

        Given: A tmp cwd containing a directory, and --file naming it
        When:  main() is called
        Then:  Exits with code 2, names the path, and does not print the
               unexpected-exception banner

        A directory passes an exists()-only guard, so this pins that the
        guard is is_file()-shaped. Today the path reaches open() and the
        IsADirectoryError escapes into the broad handler, which exits 2 with
        "Please report this issue to the maintainers" — the right code for
        the wrong reason, which is why the banner assertion carries this test.
        """
        monkeypatch.chdir(tmp_path)
        directory = tmp_path / "corpus-dir"
        directory.mkdir()

        with patch("sys.argv", ["script.py", "--file", str(directory)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"Expected exit 2 for a --file path that is a directory; got {exc_info.value.code}. "
            f"Output: {combined!r}"
        )
        assert str(directory) in combined, (
            f"Expected the offending --file path to be named in the output; got: {combined!r}"
        )
        _assert_not_crash_shaped(combined)

    @pytest.mark.parametrize("extra_args", [[], ["--quiet"]], ids=["verbose", "quiet"])
    def test_main_with_file_flag_on_non_components_yaml_fails_cleanly(
        self, extra_args, tmp_path, monkeypatch, capsys
    ):
        """
        Test that a --file corpus of the wrong shape reports why, and exits 2.

        Given: A tmp cwd holding well-formed YAML with no top-level
               "components" key
        When:  main() is called with --file <that file>, with and without
               --quiet
        Then:  Exits 2, names the offending path, names the field it could
               not find, and does not print the unexpected-exception banner

        Exit 2: the file exists but could not be validated, which is the same
        category as a path that does not exist. Exit 1 would tell a
        contributor their edges are wrong when the real problem is that the
        file is not a components corpus at all.

        Naming the field is the load-bearing half. Asserting only the path is
        satisfiable through the validator's verbose log line — a collaborator
        side effect that carries no diagnosis and vanishes under --quiet — so
        an implementation could swallow the exception and fall through
        without ever saying what was wrong. The --quiet case is where that
        shows: the message has to come from the failure itself. The corpus
        file is deliberately named without the word "components" so that
        echoing the path cannot satisfy the field assertion.

        Today parse_components_yaml raises KeyError, validate_file does not
        catch it (ComponentEdgeValidator.validate_loaded handles
        EdgeValidationError only), and the
        broad handler turns a bad input file into a request to file a bug.
        """
        corpus = _write_custom_components(tmp_path, _NOT_A_COMPONENTS_CORPUS, name="wrong-shape.yaml")
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--file", str(corpus), *extra_args]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"Expected exit 2 (configuration error) for a --file corpus of the wrong shape; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert str(corpus) in combined, (
            f"Expected the offending --file path to be named in the output; got: {combined!r}"
        )
        assert "components" in combined, (
            f"Expected the failure to name the field it could not find, not just the path — "
            f"the file's name does not contain it. Got: {combined!r}"
        )
        _assert_not_crash_shaped(combined)

    @pytest.mark.parametrize(
        "raw_corpus",
        [
            pytest.param(b"components: hello\n", id="scalar-string"),
            pytest.param(b"components:\n  - alpha\n  - beta\n", id="list-of-scalars"),
            pytest.param(b"components:\n  alpha: {}\n", id="mapping"),
            pytest.param(b"components: 5\n", id="scalar-int"),
            pytest.param(b"\x89PNG\r\n\x1a\ncomponents:\n", id="not-utf8"),
        ],
    )
    def test_main_with_file_flag_on_unparseable_corpus_shapes_fails_cleanly(
        self, raw_corpus, tmp_path, monkeypatch, capsys
    ):
        """
        Test that every unparseable corpus shape gets the same clean failure.

        Given: A tmp cwd holding a file that parse_components_yaml cannot
               turn into components — a scalar, a list of scalars, a mapping,
               an int, or bytes that are not UTF-8
        When:  main() is called with --file <that file>
        Then:  Each exits 2, names the file, and never prints the
               unexpected-exception banner

        These are the same class of problem as the missing-key case above and
        must be reported the same way. They are not today: the guard catches
        a narrow tuple of exception types, so `components: 5` raises
        TypeError and is reported cleanly while `components: hello` raises
        AttributeError and `not-utf8` raises UnicodeDecodeError — both of
        which escape to the banner. An int scalar being "your file is bad"
        and a string scalar being "file a bug" is exactly the arbitrary split
        this contract exists to remove.

        The shapes are written as raw bytes rather than dumped from Python
        objects so the not-utf8 case is expressible alongside the others.
        """
        corpus = tmp_path / "wrong-shape.yaml"
        corpus.write_bytes(raw_corpus)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--file", str(corpus)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"Expected exit 2 (configuration error) for an unparseable corpus; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert str(corpus) in combined, f"Expected the offending path to be named in the output; got: {combined!r}"
        _assert_not_crash_shaped(combined)

    def test_main_checking_phase_failure_still_reaches_the_crash_banner(self, tmp_path, monkeypatch, capsys):
        """
        Test that a defect in the checking phase is still reported as a bug.

        Given: A tmp cwd holding a corpus that parses cleanly, and
               ComponentEdgeValidator.build_edge_maps raising KeyError, which
               stands in for a defect in the checking phase
        When:  main() is called with --force
        Then:  Exits 2 with the unexpected-exception banner, and not with the
               unusable-corpus message

        The other half of the exception contract, and the reason the guard
        belongs around the parse rather than around the whole validate_file
        call. With it wrapping the call, an injected defect in
        build_edge_maps run against the unmodified committed corpus reports
        "Could not validate risk-map/yaml/components.yaml: componentDataSources"
        and exits 2 — a provably good corpus blamed on the user, with the
        route to report the bug removed and the exception type stripped, so
        the message reads like a data finding.

        KeyError is the injected type on purpose: an exception outside the
        guard's tuple would reach the banner today and prove nothing.
        """
        _write_repo_layout_corpus(tmp_path, _CLEAN_LOCAL_COMPONENTS, _CLEAN_LOCAL_CONTROLS)
        monkeypatch.chdir(tmp_path)

        def raise_from_checking_phase(self, components):
            raise KeyError("componentLocalA")

        monkeypatch.setattr(ComponentEdgeValidator, "build_edge_maps", raise_from_checking_phase)

        with patch("sys.argv", ["script.py", "--force"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"Expected exit 2 for an internal failure; got {exc_info.value.code}. Output: {combined!r}"
        )
        for marker in _CRASH_BANNER_MARKERS:
            assert marker in combined, (
                f"Expected {marker!r}: a failure in the checking phase is a bug in this tool, "
                f"and the user needs the route to report it. Got: {combined!r}"
            )
        assert "Could not validate" not in combined, (
            f"A checking-phase defect must not be reported as an unusable corpus — the corpus "
            f"parsed fine. Got: {combined!r}"
        )

    @pytest.mark.parametrize("use_file_flag", [False, True], ids=["default-corpus", "file-flag"])
    def test_main_announces_the_corpus_it_validates(
        self, use_file_flag, tmp_path, monkeypatch, capsys, validated_corpus_paths
    ):
        """
        Test that the announced corpus is the corpus actually validated.

        Given: A tmp cwd holding a corpus at the default path and another
               elsewhere
        When:  main() is called with --force, and again with --file naming
               the other corpus
        Then:  The run announces a corpus, and the path it announces is the
               one that was parsed

        Splitting the parse from the checks decoupled two things that used to
        travel together: validate_loaded takes the components and the path to
        announce as separate arguments, so nothing but this test stops them
        disagreeing. Passing DEFAULT_COMPONENTS_FILE as the path while
        handing over a --file corpus validates one file and tells the user
        about another, and the rest of the suite stays green — every other
        assertion checks either the outcome or the parsed path, never both
        against each other.

        The announcement's presence is pinned here too. Deleting the line
        leaves the suite green otherwise, and it is the only place a run says
        which file it is about.
        """
        _write_repo_layout_corpus(tmp_path, _CLEAN_LOCAL_COMPONENTS, _CLEAN_LOCAL_CONTROLS)
        elsewhere = _write_custom_components(tmp_path, _CLEAN_LOCAL_COMPONENTS, name="elsewhere.yaml")
        monkeypatch.chdir(tmp_path)

        argv = ["script.py", "--file", str(elsewhere)] if use_file_flag else ["script.py", "--force"]

        with patch("sys.argv", argv):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 0, (
            f"Expected exit 0 on a clean corpus; got {exc_info.value.code}. Output: {combined!r}"
        )

        announced = _announced_corpus(combined)
        assert announced, (
            f"The run must say which corpus it is validating; no {_ANNOUNCEMENT_PREFIX!r} line in: {combined!r}"
        )
        assert validated_corpus_paths, "The run parsed no corpus at all"
        assert Path(announced) == validated_corpus_paths[0], (
            f"The announced corpus and the validated corpus must be the same file: announced "
            f"{announced!r}, parsed {validated_corpus_paths[0]!r}"
        )

    @pytest.mark.parametrize("defect", _DEFECT_EXCEPTIONS, ids=[e.__name__ for e in _DEFECT_EXCEPTIONS])
    def test_main_parse_phase_defects_still_reach_the_crash_banner(self, defect, tmp_path, monkeypatch, capsys):
        """
        Test that a defect raised during the parse is reported as a defect.

        Given: A tmp cwd holding a parseable corpus, and
               parse_components_yaml raising NameError, ImportError or
               EdgeValidationError
        When:  main() is called with --force
        Then:  Exits 2 with the maintainers banner, and not with the clean
               "Could not validate" message

        The companion to the checking-phase test above, and the one that
        pins the guard's membership rather than its position. That test
        injects downstream of the guard, so it passes even if the guard
        catches everything; this one injects into the parse the guard wraps,
        where a widened tuple changes the answer.

        Widening it is not hypothetical: reverting the tuple to a bare
        `except Exception` leaves the entire suite green today. These three
        exceptions are the ones the tuple's own comment names as defects, so
        this is the assertion that comment needs to keep it honest.
        """
        _write_repo_layout_corpus(tmp_path, _CLEAN_LOCAL_COMPONENTS, _CLEAN_LOCAL_CONTROLS)
        monkeypatch.chdir(tmp_path)

        def raise_defect(file_path=None):
            raise defect("injected defect")

        monkeypatch.setattr(riskmap_validator.validator, "parse_components_yaml", raise_defect)

        with patch("sys.argv", ["script.py", "--force"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"Expected exit 2 for an internal failure; got {exc_info.value.code}. Output: {combined!r}"
        )
        for marker in _CRASH_BANNER_MARKERS:
            assert marker in combined, (
                f"Expected {marker!r}: {defect.__name__} during the parse is a defect, not a "
                f"statement about the user's file. Got: {combined!r}"
            )
        assert "Could not validate" not in combined, (
            f"{defect.__name__} must not be relabelled as an unusable corpus — that is what a "
            f"bare `except Exception` in the parse guard would do. Got: {combined!r}"
        )

    def test_main_with_force_on_wrong_shape_default_corpus_fails_cleanly(self, tmp_path, monkeypatch, capsys):
        """
        Test that the default corpus fails the same way --file's does.

        Given: A tmp cwd whose risk-map/yaml/components.yaml is well-formed
               YAML with no top-level "components" key
        When:  main() is called with --force and no --file
        Then:  Exits 2, identifies the file, names the field it could not
               find, and does not print the unexpected-exception banner

        The counterpart to the --file case above, and the reason it is here
        rather than in TestMainValidation: both are the same failure — a
        components corpus that will not parse — reached through the same
        validate_file call. Scoping the fix to `args.file is not None` would
        ship one function with two user experiences depending on which flag
        was passed. This test forecloses that.

        Only _assert_not_crash_shaped drives this test red today. The other
        three assertions already hold: the run exits 2 through the broad
        handler at validate_riskmap.py:424-427, the validator's verbose log
        line names the file on the way past, and the field name is echoed
        inside the banner text itself, since parse_components_yaml re-raises
        as "Missing required field in <path>: 'components'" — the field name
        comes from the KeyError's own argument and is independent of the
        filename. A reader checking only the exit code would think
        this test was already green. What has to change is that a corpus the
        tool cannot parse stops being reported to the user as an internal
        bug.
        """
        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "components.yaml").write_text(yaml.dump(_NOT_A_COMPONENTS_CORPUS), encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--force"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"Expected exit 2 (configuration error) for a default corpus of the wrong shape; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert str(DEFAULT_COMPONENTS_FILE) in combined, (
            f"Expected the offending corpus to be identified in the output; got: {combined!r}"
        )
        assert "components" in combined, (
            f"Expected the failure to name the field it could not find; got: {combined!r}"
        )
        _assert_not_crash_shaped(combined)

    def test_main_with_force_and_file_flags_is_rejected(self, tmp_path, capsys):
        """
        Test that --force --file PATH is rejected as a contradictory combination (C1).

        Given: Script called with --force and --file <an existing corpus>
        When:  main() is called
        Then:  Exits with code 2, names both flags, never reaches corpus
               selection, and does not print the unexpected-exception banner

        Both flags answer "which corpus?", so accepting them together means
        silently preferring one. Exit 2 for the same reason as the
        unusable-path cases: an unsupported flag combination is a bad
        invocation, not a corpus finding. The corpus file is real so the
        rejection cannot be confused with the missing-path branch.

        ComponentEdgeValidator is patched for the same reason its siblings
        patch it: an unpatched run reaches the live repo corpus, which makes
        the test's outcome depend on repository state it is not testing.
        """
        corpus = _write_custom_components(tmp_path, _COMPONENTS_CONSISTENT)

        with patch("sys.argv", ["script.py", "--force", "--file", str(corpus)]):
            with patch("validate_riskmap.get_staged_yaml_files") as mock_get_files:
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    mock_validator = Mock()
                    mock_validator.validate_file.return_value = True
                    mock_validator.forward_map = {}
                    mock_validator.components = {}
                    mock_validator_class.return_value = mock_validator

                    with pytest.raises(SystemExit) as exc_info:
                        main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"Expected exit 2 for the contradictory --force --file combination; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert "--force" in combined and "--file" in combined, (
            f"Expected both flag names in the rejection message; got: {combined!r}"
        )
        _assert_not_crash_shaped(combined)
        mock_get_files.assert_not_called()
        mock_validator.validate_file.assert_not_called()

    def test_main_with_file_flag_skips_only_the_repo_scoped_checks(self, tmp_path, repo_root, monkeypatch, capsys):
        """
        Test that --file skips the two checks that read other repo files, and
        only those.

        Given: The repo root as cwd, so risk-map/yaml/{controls,components,
               lifecycle-stage}.yaml all exist, and a --file corpus that
               declares its own categories block and whose component IDs
               appear nowhere in the repo's controls
        When:  main() is called with --file <that corpus>
        Then:  Exits 0; the lifecycle and mirror checks announce that they
               skipped and report no result; the nesting check reports a
               result

        Lifecycle order and the controls↔components mirror read files other
        than the corpus under test — lifecycle-stage.yaml and controls.yaml —
        so under --file they would cross-check the repo against an unrelated
        file. Category/subcategory nesting does not: it compares each
        component's (category, subcategory) pair against the categories block
        declared in the same file, so both halves live inside whatever --file
        names. It is not repo-scoped and must run.

        That the nesting check *passes* here is the discriminator. The corpus
        declares category "catData" with subcategory "subStorage", neither of
        which exists in the repo's components.yaml. If the check read its
        categories from the repo path while taking components from --file, it
        would report "subcategory 'subStorage' is not nested under that
        category". A clean pass is only possible if both halves came from the
        --file corpus.
        """
        corpus = _write_custom_components(tmp_path, _CLEAN_LOCAL_COMPONENTS)
        monkeypatch.chdir(repo_root)

        with patch("sys.argv", ["script.py", "--file", str(corpus)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert _EDGES_CONSISTENT in combined, (
            f"Expected the --file corpus to have been validated before the repo-scoped checks "
            f"were skipped; got: {combined!r}"
        )
        assert exc_info.value.code == 0, (
            f"Expected exit 0: the --file corpus is edge-consistent and nesting-clean. "
            f"Got {exc_info.value.code}. Output: {combined!r}"
        )
        for keyword, result_line in (
            ("lifecycle", "Lifecycle stage order uniqueness check passed"),
            ("mirror", "mirror check passed"),
        ):
            assert _line_reports_skip(combined, keyword), (
                f"Expected the {keyword} check to announce that --file made it skip; got: {combined!r}"
            )
            assert result_line not in combined, (
                f"The {keyword} check reported a result against the repo corpus while --file "
                f"named a different one; got: {combined!r}"
            )

        assert not _line_reports_skip(combined, "nesting"), (
            f"The nesting check is self-contained within the --file corpus and must not skip; got: {combined!r}"
        )
        assert "nesting check passed" in combined, (
            f"Expected the nesting check to run against the --file corpus and pass — its "
            f"categories block is declared in that same file. Got: {combined!r}"
        )

    def test_main_with_file_flag_and_block_promotes_nothing_from_skipped_checks(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that --block cannot promote findings from the two skipped checks.

        Given: The repo root as cwd and a --file corpus that is nesting-clean
               and whose component IDs appear nowhere in the repo's controls,
               so the mirror check would produce warnings for every control
               if it ran
        When:  main() is called with --file <that corpus> --block
        Then:  Exits 0

        --block is the production pre-commit form
        (.pre-commit-config.yaml:211), so a --file run that left the
        repo-scoped checks live would not merely warn — it would block on
        findings manufactured by comparing two unrelated corpora.

        The premise is narrower than it once was: this covers only the
        lifecycle and mirror checks. Nesting is self-contained in the --file
        corpus, runs, and does promote under --block —
        test_main_with_file_flag_runs_the_nesting_check pins that. The corpus
        here is deliberately nesting-clean so the exit code speaks only to
        the two checks this test is about.
        """
        corpus = _write_custom_components(tmp_path, _CLEAN_LOCAL_COMPONENTS)
        monkeypatch.chdir(repo_root)

        with patch("sys.argv", ["script.py", "--file", str(corpus), "--block"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert "No YAML files to validate" not in combined, (
            f"--file named an existing corpus but main() took the skip path; output: {combined!r}"
        )
        assert _EDGES_CONSISTENT in combined, (
            f"Expected the --file corpus to have been validated; got: {combined!r}"
        )
        assert _line_reports_skip(combined, "mirror"), (
            f"Expected the mirror check to skip — it is the finding source this test is about. Got: {combined!r}"
        )
        assert exc_info.value.code == 0, (
            f"Expected exit 0: the mirror check is skipped under --file and the corpus is "
            f"nesting-clean, so --block has nothing to promote. "
            f"Got {exc_info.value.code}. Output: {combined!r}"
        )

    @pytest.mark.parametrize(
        "corpus_content,extra_args,expected_code,expected_marker",
        [
            (_CLEAN_LOCAL_COMPONENTS, [], 0, "nesting check passed"),
            (_NESTING_DIRTY_COMPONENTS, [], 0, "nesting check found"),
            (_NESTING_DIRTY_COMPONENTS, ["--block"], 1, "nesting check found"),
        ],
        ids=["clean", "dirty-warns", "dirty-blocks"],
    )
    def test_main_with_file_flag_runs_the_nesting_check(
        self, corpus_content, extra_args, expected_code, expected_marker, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that the nesting check applies to the corpus --file names.

        Given: The repo root as cwd and a --file corpus that is either
               nesting-clean or has a component missing its subcategory
        When:  main() is called with --file <that corpus>, with and without
               --block
        Then:  A clean corpus passes at exit 0; a violation is reported at
               exit 0 as a warning; and with --block it is promoted to exit 1

        This is what `--file` is for: validating a corpus before it lands.
        The nesting check is the only warn-only check that applies to a
        corpus in isolation, so skipping it left --file unable to report the
        one class of finding it could legitimately report. The consequence
        was that the same bytes gave opposite answers —
        `--file corpus.yaml --block` said "skipped" and exited 0 where
        `--force --block` over an identical components.yaml exited 1.
        """
        corpus = _write_custom_components(tmp_path, corpus_content)
        monkeypatch.chdir(repo_root)

        with patch("sys.argv", ["script.py", "--file", str(corpus), *extra_args]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert not _line_reports_skip(combined, "nesting"), (
            f"The nesting check must run against the --file corpus, not skip; got: {combined!r}"
        )
        assert expected_marker in combined, f"Expected {expected_marker!r} in the output; got: {combined!r}"
        assert exc_info.value.code == expected_code, (
            f"Expected exit {expected_code}; got {exc_info.value.code}. Output: {combined!r}"
        )
        if expected_code == 1:
            assert "promoted to errors" in combined, (
                f"Expected --block to say it promoted the nesting findings; got: {combined!r}"
            )

    def test_main_with_file_flag_runs_the_nesting_check_outside_a_repo_layout(self, tmp_path, monkeypatch, capsys):
        """
        Test that the nesting check follows the --file corpus, not the cwd.

        Given: A tmp cwd with no risk-map/ tree at all, holding a --file
               corpus with a component missing its subcategory
        When:  main() is called with --file <that corpus>
        Then:  The nesting finding is reported

        Every other --file test chdirs to the repo root, where
        risk-map/yaml/components.yaml exists. That makes them blind to which
        path the check opens: reverting the guard to the hardcoded repo path
        keeps them all green, because the file it names happens to be there.
        Here it is not, so a check that consults the cwd finds nothing to
        open and drops out silently — no finding, and no skip line either,
        since nothing decided to skip.
        """
        corpus = _write_custom_components(tmp_path, _NESTING_DIRTY_COMPONENTS)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--file", str(corpus)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert "nesting check found" in combined, (
            f"The nesting check must read the corpus --file names, wherever the run happens "
            f"to be started from. Got: {combined!r}"
        )
        assert exc_info.value.code == 0, (
            f"Expected exit 0 without --block; got {exc_info.value.code}. Output: {combined!r}"
        )

    def test_main_with_file_flag_and_to_graph_is_allowed(self, tmp_path, repo_root, monkeypatch, capsys):
        """
        Test that --to-graph still works with --file and draws that corpus.

        Given: The repo root as cwd and a --file corpus whose component IDs
               appear nowhere in the repo's components.yaml
        When:  main() is called with --file <corpus> --to-graph <path>
        Then:  Exits 0 and writes a graph containing the --file corpus's
               components and none of the repo's

        The component graph is built from validator.forward_map and
        validator.components, both populated from the corpus that was
        validated, so it is the one graph --file can legitimately produce.
        Asserting on which component IDs appear is what separates "the graph
        was written" from "the graph is of the right corpus".
        """
        corpus = _write_custom_components(tmp_path, _CLEAN_LOCAL_COMPONENTS)
        output = tmp_path / "graph-output.md"
        monkeypatch.chdir(repo_root)

        with patch("sys.argv", ["script.py", "--file", str(corpus), "--to-graph", str(output)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 0, (
            f"--to-graph is derived from the --file corpus and must stay allowed; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert output.is_file(), f"Expected a graph at {output}; output: {combined!r}"

        graph = output.read_text(encoding="utf-8")
        assert "componentLocalA" in graph, f"Expected the --file corpus's components in the graph; got: {graph!r}"
        assert "componentDataSources" not in graph, (
            f"The graph must be drawn from the --file corpus, not the repo's components.yaml; got: {graph!r}"
        )

    @pytest.mark.parametrize("spelling", ["relative", "absolute"])
    def test_main_with_file_naming_the_default_corpus_runs_every_check(
        self, spelling, repo_root, monkeypatch, capsys
    ):
        """
        Test that naming the default corpus with --file does not weaken the run.

        Given: The repo root as cwd
        When:  main() is called with --file pointing at
               risk-map/yaml/components.yaml, spelled relatively and
               absolutely
        Then:  Exits 0 and all three checks report a result, with none of
               them announcing a --file skip

        A guard written as `args.file is not None` is path-blind, so
        `--file risk-map/yaml/components.yaml` produced a strictly weaker run
        than bare --force over the same file: three checks skipped, the
        repo's own corpus described as "custom", exit 0. The comparison has
        to be on resolved paths, which is why both spellings of the same file
        are exercised — a string comparison against DEFAULT_COMPONENTS_FILE
        would pass the relative case and fail the absolute one.
        """
        monkeypatch.chdir(repo_root)
        target = DEFAULT_COMPONENTS_FILE if spelling == "relative" else (repo_root / DEFAULT_COMPONENTS_FILE)

        with patch("sys.argv", ["script.py", "--file", str(target)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 0, (
            f"The repo corpus is clean, so naming it explicitly must still exit 0; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        for keyword in ("lifecycle", "mirror", "nesting"):
            assert not _line_reports_skip(combined, keyword), (
                f"--file naming the default corpus must not skip the {keyword} check — that is "
                f"a weaker run than --force over the same bytes. Got: {combined!r}"
            )
        for sentence in _DOWNSTREAM_CHECK_SENTENCES:
            assert sentence in combined, (
                f"Expected {sentence!r} when --file names the default corpus; got: {combined!r}"
            )

    def test_file_flag_skips_emission_drift_even_against_a_populated_real_styles_file(
        self, repo_root, tmp_path, monkeypatch, capsys
    ):
        """
        Test that --file's emission-drift skip (ADR-036 D7,
        `validate_riskmap.py`'s `skip_repo_scoped` guard) holds even once the
        repo's own `risk-map/yaml/mermaid-styles.yaml` carries a populated
        `emission` block: a custom --file corpus is validated in isolation from
        that repo file, so the skip line must print and no drift line may ever
        appear, regardless of what that file happens to contain.

        Given: cwd is the real repo root (so a relative
               `risk-map/yaml/mermaid-styles.yaml` resolves to the real,
               committed file), and --file names an unrelated, edge-consistent
               tmp_path corpus
        When:  main() is called with --file <that corpus>
        Then:  the output announces the emission drift check as skipped and
               prints no "Emission drift check found" line

        The skip-line assertion alone would pass vacuously whether or not the real
        file has an emission block at all, so this test also reads the real repo
        file directly and requires `graphTypes.component.emission.concerns` to be
        non-empty. That proves the skip is a genuine skip of real content, not a
        skip of nothing.
        """
        corpus = _write_custom_components(tmp_path, _COMPONENTS_CONSISTENT)
        monkeypatch.chdir(repo_root)

        with patch("sys.argv", ["script.py", "--file", str(corpus)]):
            with pytest.raises(SystemExit):
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert _line_reports_skip(combined, "emission"), (
            f"expected the emission drift check to announce a skip under --file "
            f"naming a custom corpus; got: {combined!r}"
        )
        assert "Emission drift check found" not in combined, (
            f"--file must never run the emission drift check against the repo's own "
            f"mermaid-styles.yaml, populated or not; got: {combined!r}"
        )

        with open(repo_root / "risk-map" / "yaml" / "mermaid-styles.yaml", encoding="utf-8") as fh:
            styles_doc = yaml.safe_load(fh)
        emission = styles_doc.get("graphTypes", {}).get("component", {}).get("emission")
        assert emission is not None and emission.get("concerns"), (
            "expected the real, committed mermaid-styles.yaml to carry a populated "
            "graphTypes.component.emission.concerns registry -- otherwise the "
            "skip-line assertions above are vacuous, since an absent block also "
            "prints no drift line and no skip content is actually being skipped"
        )


class TestParseCorpus:
    """
    Direct tests for the parse step main() reports failures from.

    Every main() test that mocks ComponentEdgeValidator gets a MagicMock back,
    so the parse never runs and cannot raise: the suite could not see a defect
    inside this step. These tests exercise it directly.

    Naming parse_corpus here is correct — it is the unit under test. That
    is a different thing from the main() call-site assertions, which are
    deliberately method-agnostic because they are about which corpus was
    validated, not about how the work is split.
    """

    def test_parse_corpus_returns_the_parsed_corpus(self, tmp_path):
        """
        Test that a well-formed corpus parses into ComponentNode objects.

        Given: A tmp corpus with two linked components
        When:  parse_corpus() is called on it
        Then:  Both components are returned, keyed by ID

        The happy path: nothing raises and the caller gets usable data.
        """
        corpus = _write_custom_components(tmp_path, _CLEAN_LOCAL_COMPONENTS)

        components = ComponentEdgeValidator(verbose=False).parse_corpus(corpus)

        assert set(components) == {"componentLocalA", "componentLocalB"}
        assert components["componentLocalA"].to_edges == ["componentLocalB"]

    @pytest.mark.parametrize(
        "raw_corpus",
        [
            pytest.param(b"controls:\n  - id: controlSomething\n", id="missing-components-key"),
            pytest.param(b"components: hello\n", id="scalar-string"),
            pytest.param(b"components:\n  - alpha\n", id="list-of-scalars"),
            pytest.param(b"components:\n  alpha: {}\n", id="mapping"),
            pytest.param(b"components: 5\n", id="scalar-int"),
            pytest.param(b"\x89PNG\r\n\x1a\ncomponents:\n", id="not-utf8"),
            pytest.param(b"components: [unclosed\n", id="malformed-yaml"),
        ],
    )
    def test_parse_corpus_raises_one_type_for_every_bad_shape(self, raw_corpus, tmp_path):
        """
        Test that every way a corpus can fail to parse becomes CorpusParseError.

        Given: A file that parse_components_yaml cannot turn into components
        When:  parse_corpus() is called on it
        Then:  CorpusParseError is raised, carrying the original failure as
               its cause and its text in the message

        Underneath, each shape raises something different — KeyError,
        AttributeError, TypeError, UnicodeDecodeError, YAMLError. Collapsing
        them to one type is what lets main() separate "this file is unusable"
        from "this tool has a defect", so the collapse has to be total: a
        shape that escapes reaches the maintainers banner and tells a user
        with a bad file to report a bug.

        The cause assertion matters as much as the type. Losing __cause__
        would leave a caller with no way to say what was actually wrong.
        """
        corpus = tmp_path / "bad-corpus.yaml"
        corpus.write_bytes(raw_corpus)

        with pytest.raises(CorpusParseError) as exc_info:
            ComponentEdgeValidator(verbose=False).parse_corpus(corpus)

        assert exc_info.value.__cause__ is not None, (
            "CorpusParseError must chain the underlying failure, or the reason is lost"
        )
        assert str(exc_info.value.__cause__) in str(exc_info.value), (
            f"The underlying reason must survive into the message; got {str(exc_info.value)!r} "
            f"from {exc_info.value.__cause__!r}"
        )

    def test_parse_corpus_raises_for_a_missing_file(self, tmp_path):
        """
        Test that a nonexistent path is a parse failure like any other.

        Given: A path that does not exist
        When:  parse_corpus() is called on it
        Then:  CorpusParseError is raised, naming the path

        main() checks existence before it gets here, so this is the belt to
        that braces: a caller that skips the check still gets one exception
        type rather than a FileNotFoundError escaping to the banner.
        """
        missing = tmp_path / "no-such-corpus.yaml"

        with pytest.raises(CorpusParseError) as exc_info:
            ComponentEdgeValidator(verbose=False).parse_corpus(missing)

        assert str(missing) in str(exc_info.value), (
            f"Expected the missing path in the message; got {str(exc_info.value)!r}"
        )

    def test_validate_loaded_takes_its_components_from_the_argument(self, tmp_path):
        """
        Test that validate_loaded uses the corpus it was handed, every time.

        Given: A validator that has already validated one corpus
        When:  validate_loaded() is called again with a different corpus
        Then:  validator.components holds the second corpus, not the first

        The stored corpus is not private bookkeeping: main() reads
        validator.components to run the mirror and nesting checks, so a stale
        one means those checks answer about a file the run is not validating.

        The mutation this catches is `self.components = self.components or
        components`, which looks like a harmless guard and silently pins the
        validator to whatever it saw first. The whole suite stays green under
        it, because no other test calls validate_loaded twice on one
        instance — nothing else would notice until a caller reused a
        validator.
        """
        first = _write_custom_components(tmp_path, _CLEAN_LOCAL_COMPONENTS, name="first.yaml")
        second = _write_custom_components(tmp_path, _COMPONENTS_CONSISTENT, name="second.yaml")

        validator = ComponentEdgeValidator(verbose=False)
        validator.validate_loaded(validator.parse_corpus(first), first)
        validator.validate_loaded(validator.parse_corpus(second), second)

        assert set(validator.components) == {"componentAlpha", "componentBeta"}, (
            f"validate_loaded must store the corpus it was given; after a second call the "
            f"validator holds {sorted(validator.components)!r}"
        )

    @pytest.mark.parametrize("defect", _DEFECT_EXCEPTIONS, ids=[e.__name__ for e in _DEFECT_EXCEPTIONS])
    def test_parse_corpus_lets_defects_through_unchanged(self, defect, tmp_path, monkeypatch):
        """
        Test that parse_corpus catches bad input only, not every exception.

        Given: parse_components_yaml raising a defect-shaped exception —
               NameError, ImportError or EdgeValidationError
        When:  parse_corpus() is called
        Then:  That exception propagates unchanged, not relabelled as
               CorpusParseError

        The guard's tuple is deliberately narrow, and nothing enforced its
        membership: widening it to a bare `except Exception` left the whole
        suite green. The tests that look like they cover this do not — one
        injects into build_edge_maps, downstream of the guard, and one into
        get_staged_yaml_files, upstream of it. Both pin where the guard sits;
        neither pins what it catches. Injecting at the parse itself is the
        only place the membership is observable.

        NameError and ImportError stand for a defect in this tool.
        EdgeValidationError stands for a domain error surfacing where it does
        not belong. Neither is a statement about the user's file, so neither
        may be reported as an unusable corpus — which is what a bare
        `except Exception` would do to all three.
        """
        corpus = _write_custom_components(tmp_path, _CLEAN_LOCAL_COMPONENTS)

        def raise_defect(file_path=None):
            raise defect("injected defect")

        monkeypatch.setattr(riskmap_validator.validator, "parse_components_yaml", raise_defect)

        with pytest.raises(defect):
            ComponentEdgeValidator(verbose=False).parse_corpus(corpus)

    def test_validate_file_reads_components_off_the_new_parse_result_shape(self, tmp_path, monkeypatch):
        """
        Test that validate_file (validator.py:224) extracts .components rather than
        treating the whole parse_components_yaml result as the components mapping.

        Given: parse_components_yaml stubbed to return the .document/.components
               contract (an object carrying both the raw parsed YAML and the
               ComponentNode mapping)
        When:  validate_file() is called
        Then:  It still validates successfully, and validator.components
               ends up holding the dict from .components, not the result
               object itself

        The stand-in must hand validate_file a genuine dict via .components,
        built from a real parse rather than a hand-rolled fixture. It cannot
        do that by feeding the live parse_components_yaml's return value
        into `.components` unconditionally, because that return value's own
        shape depends on whether utils.py's .document/.components contract
        has landed: pre-contract it is already the bare dict this stand-in
        needs, post-contract it is itself a ComponentsParseResult wrapping
        that dict one level down. Picking either treatment unconditionally
        breaks the other side -- `.components=real_parse(file_path)` double-
        wraps once the contract lands (a nested result object where a dict
        belongs), and `.components=real_parse(file_path).components` raises
        AttributeError before the contract lands (a bare dict has no
        .components to unwrap). Normalizing with getattr keeps the stand-in
        correct on both sides of that landing, so this test pins only what
        it names: validate_file's own extraction, not utils.py's contract
        state.

        If validate_file regresses to handing validate_loaded the whole
        parse result instead of `result.components`, validate_loaded stores
        it verbatim (`self.components = components`), and the first
        membership check (`find_missing_components`, which calls
        `components.keys()`) raises AttributeError, because a
        ComponentsParseResult has no `.keys()`.

        This is call site three of parse_components_yaml (after main() and
        this class's other direct calls, both already covered by
        RED contract expectations elsewhere): two review passes named
        validator.py:224 as an unpinned consumer of the return-shape change
        and nothing closed it before this test.
        """
        corpus = _write_custom_components(tmp_path, _CLEAN_LOCAL_COMPONENTS)

        class _StandInParseResult:
            """Stands in for the parse_components_yaml return shape."""

            def __init__(self, document, components):
                self.document = document
                self.components = components

        real_parse = riskmap_validator.validator.parse_components_yaml

        def stand_in_parse(file_path=None):
            raw = real_parse(file_path)
            # Normalize across both sides of the utils.py contract landing:
            # a bare dict has no .components (pre-contract, use raw itself);
            # a ComponentsParseResult does (post-contract, unwrap it). Either
            # way `components` ends up the genuine dict this stand-in needs.
            components = getattr(raw, "components", raw)
            return _StandInParseResult(document={"categories": []}, components=components)

        monkeypatch.setattr(riskmap_validator.validator, "parse_components_yaml", stand_in_parse)

        validator = ComponentEdgeValidator(verbose=False)
        result = validator.validate_file(corpus)

        assert result is True, (
            "a clean corpus must still validate once parse_components_yaml returns .document/.components"
        )
        assert isinstance(validator.components, dict), (
            "validate_file must extract .components from the parse result before handing it to "
            f"validate_loaded; validator.components is a {type(validator.components).__name__}, "
            "meaning the whole result object leaked through instead"
        )
        assert set(validator.components) == {"componentLocalA", "componentLocalB"}


class TestMainGraphGeneration:
    """Tests for main() graph generation capabilities."""

    def test_main_generates_component_graph_when_to_graph_specified(self, capsys):
        """
        Test that component graph is generated when --to-graph is provided.

        Given: Valid validation and --to-graph output.md specified
        When: main() is called
        Then: ComponentGraph is created and written to output file
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("output/graph.md")
        mock_graph_output = "```mermaid\ngraph TD\nA-->B\n```"

        with patch("sys.argv", ["script.py", "--force", "--to-graph", str(graph_path)]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.ComponentGraph") as mock_graph_class:
                        with patch("builtins.open", mock_open()) as mock_file:
                            # Setup validator mock
                            mock_validator = Mock()
                            mock_validator.validate_file.return_value = True
                            mock_validator.forward_map = {"A": ["B"]}
                            mock_validator.components = {"A": Mock(), "B": Mock()}
                            mock_validator_class.return_value = mock_validator

                            # Setup graph mock
                            mock_graph = Mock()
                            mock_graph.to_mermaid.return_value = mock_graph_output
                            mock_graph_class.return_value = mock_graph

                            with pytest.raises(SystemExit) as exc_info:
                                main()

        assert exc_info.value.code == 0

        # Verify graph was created with correct parameters
        mock_graph_class.assert_called_once_with(
            mock_validator.forward_map, mock_validator.components, debug=False
        )

        # Verify file was written
        mock_file.assert_called_with(graph_path, "w", encoding="utf-8")
        handle = mock_file()
        handle.write.assert_called_once_with(mock_graph_output)

        # Verify success message
        captured = capsys.readouterr()
        assert f"Graph visualization saved to {graph_path}" in captured.out

    def test_main_generates_mermaid_format_files_when_flag_set(self, capsys):
        """
        Test that .mermaid format files are generated when --mermaid-format is set.

        Given: --to-graph and --mermaid-format flags are set
        When: main() is called
        Then: Both .md and .mermaid files are written
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("graph.md")
        mermaid_path = Path("graph.mermaid")
        mock_md_output = "```mermaid\ngraph TD\nA-->B\n```"
        mock_mermaid_output = "graph TD\nA-->B"

        with patch("sys.argv", ["script.py", "--force", "--to-graph", str(graph_path), "--mermaid-format"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.ComponentGraph") as mock_graph_class:
                        with patch("builtins.open", mock_open()) as mock_file:
                            # Setup validator mock
                            mock_validator = Mock()
                            mock_validator.validate_file.return_value = True
                            mock_validator.forward_map = {}
                            mock_validator.components = {}
                            mock_validator_class.return_value = mock_validator

                            # Setup graph mock - return different output based on format
                            mock_graph = Mock()

                            def to_mermaid_side_effect(output_format="markdown"):
                                if output_format == "mermaid":
                                    return mock_mermaid_output
                                return mock_md_output

                            mock_graph.to_mermaid.side_effect = to_mermaid_side_effect
                            mock_graph_class.return_value = mock_graph

                            with pytest.raises(SystemExit) as exc_info:
                                main()

        assert exc_info.value.code == 0

        # Verify both files were written
        assert mock_file.call_count == 2
        mock_file.assert_any_call(graph_path, "w", encoding="utf-8")
        mock_file.assert_any_call(mermaid_path, "w", encoding="utf-8")

        # Verify success messages
        captured = capsys.readouterr()
        assert f"Graph visualization saved to {graph_path}" in captured.out
        assert f"Mermaid format saved to {mermaid_path}" in captured.out

    def test_main_handles_graph_generation_errors_gracefully(self, capsys):
        """
        Test that graph generation errors are caught and reported.

        Given: Graph to_mermaid() raises an exception
        When: main() is called
        Then: Error is caught, warning printed, and script exits 0 (validation passed)
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("graph.md")

        with patch("sys.argv", ["script.py", "--force", "--to-graph", str(graph_path)]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.ComponentGraph") as mock_graph_class:
                        # Setup validator mock
                        mock_validator = Mock()
                        mock_validator.validate_file.return_value = True
                        mock_validator.forward_map = {}
                        mock_validator.components = {}
                        mock_validator_class.return_value = mock_validator

                        # Setup graph to raise exception during to_mermaid()
                        mock_graph = Mock()
                        mock_graph.to_mermaid.side_effect = RuntimeError("Graph generation failed")
                        mock_graph_class.return_value = mock_graph

                        with pytest.raises(SystemExit) as exc_info:
                            main()

        # Should exit 0 (validation passed, only graph failed)
        assert exc_info.value.code == 0

        # Verify error message
        captured = capsys.readouterr()
        assert "Failed to generate graph:" in captured.out
        assert "Graph generation failed" in captured.out

    def test_main_passes_debug_flag_to_component_graph(self):
        """
        Test that debug flag is passed to ComponentGraph constructor.

        Given: Script called with --debug and --to-graph flags
        When: main() is called
        Then: ComponentGraph is initialized with debug=True
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("graph.md")

        with patch("sys.argv", ["script.py", "--force", "--to-graph", str(graph_path), "--debug"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.ComponentGraph") as mock_graph_class:
                        with patch("builtins.open", mock_open()):
                            # Setup validator mock
                            mock_validator = Mock()
                            mock_validator.validate_file.return_value = True
                            mock_validator.forward_map = {}
                            mock_validator.components = {}
                            mock_validator_class.return_value = mock_validator

                            # Setup graph mock
                            mock_graph = Mock()
                            mock_graph.to_mermaid.return_value = "```mermaid\ngraph\n```"
                            mock_graph_class.return_value = mock_graph

                            with pytest.raises(SystemExit):
                                main()

        # Verify debug=True was passed
        mock_graph_class.assert_called_once_with(mock_validator.forward_map, mock_validator.components, debug=True)


class TestMainErrorHandling:
    """Tests for main() exception handling."""

    def test_main_handles_keyboard_interrupt_gracefully(self, capsys):
        """
        Test that KeyboardInterrupt is handled with exit code 2.

        Given: User interrupts with Ctrl+C during validation
        When: main() is called
        Then: Exits with code 2 and prints interrupted message
        """
        with patch("sys.argv", ["script.py", "--force"]):
            with patch("validate_riskmap.get_staged_yaml_files", side_effect=KeyboardInterrupt()):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 2

        # Verify interrupted message
        captured = capsys.readouterr()
        assert "Validation interrupted by user" in captured.out

    def test_main_handles_unexpected_exceptions_with_exit_code_2(self, capsys):
        """
        Test that unexpected exceptions exit with code 2.

        Given: Unexpected exception occurs during execution
        When: main() is called
        Then: Exits with code 2 and prints error message
        """
        with patch("sys.argv", ["script.py", "--force"]):
            with patch(
                "validate_riskmap.get_staged_yaml_files",
                side_effect=RuntimeError("Unexpected error occurred"),
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 2

        # Verify error message
        captured = capsys.readouterr()
        assert "Unexpected error:" in captured.out
        assert "Unexpected error occurred" in captured.out
        assert "Please report this issue to the maintainers" in captured.out

    def test_main_handles_validator_initialization_errors(self, capsys):
        """
        Test that errors during validator initialization are handled.

        Given: ComponentEdgeValidator initialization raises exception
        When: main() is called
        Then: Exits with code 2 and prints error message
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]

        with patch("sys.argv", ["script.py", "--force"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch(
                    "validate_riskmap.ComponentEdgeValidator",
                    side_effect=ValueError("Invalid validator configuration"),
                ):
                    with pytest.raises(SystemExit) as exc_info:
                        main()

        assert exc_info.value.code == 2

        # Verify error message
        captured = capsys.readouterr()
        assert "Unexpected error:" in captured.out
        assert "Invalid validator configuration" in captured.out


# ============================================================================
# TestMainLifecycleMode — `--mode lifecycle` short-circuit hook
# ============================================================================
#
# Background: PR #277 reviewer feedback (item 2) showed that the lifecycle
# uniqueness check is unreachable on commits that touch only
# risk-map/yaml/lifecycle-stage.yaml — the validate-component-edges hook
# only triggers when components.yaml is staged, so a lifecycle-only commit
# silently bypasses the uniqueness check entirely.
#
# Architect-recommended Fix B: split lifecycle uniqueness into its own
# dedicated `validate-lifecycle-stage` pre-commit hook with a narrow
# `files: ^risk-map/yaml/lifecycle-stage\.yaml$` regex. Implementation
# uses a new `--mode lifecycle` flag on validate_riskmap.py so the hook
# entry stays in the same script.
#
# In `--mode lifecycle`, the script must:
#   1. Skip the components-validation pipeline (no get_staged_yaml_files,
#      no ComponentEdgeValidator instantiation).
#   2. Load risk-map/yaml/lifecycle-stage.yaml directly and run
#      check_lifecycle_stage_order_uniqueness.
#   3. Skip graph generation (no ComponentGraph).
#   4. Exit 0 on clean corpus, exit 1 on duplicate orders, exit 0 with a
#      skip message when the file is absent (matches the default-mode
#      graceful-skip pattern at validate_riskmap.py:210-212).
#
# These tests pin the architectural intent. Implementation choices (exact
# argparse wiring, exit-code disposition for `--mode lifecycle` combined
# with `--to-graph`, etc.) are documented per-test below.
# ============================================================================


# Reusable in-test fixtures. Re-defined here rather than imported from
# test_lifecycle_stage_order_uniqueness.py so that file's collection is not
# perturbed by cross-module imports (no __init__.py in tests/, so cross-file
# imports go through sys.path manipulation only).
_LIFECYCLE_CLEAN: dict[str, Any] = {
    "lifecycleStages": [
        {"id": "stage-one", "title": "Stage One", "order": 1},
        {"id": "stage-two", "title": "Stage Two", "order": 2},
        {"id": "stage-three", "title": "Stage Three", "order": 3},
    ]
}

_LIFECYCLE_DUPLICATE: dict[str, Any] = {
    "lifecycleStages": [
        {"id": "stage-a", "title": "Stage A", "order": 1},
        {"id": "stage-b", "title": "Stage B", "order": 2},
        {"id": "stage-c", "title": "Stage C", "order": 2},  # duplicate
    ]
}


def _write_lifecycle_only(base: Path, lifecycle: dict[str, Any] | None) -> Path:
    """
    Write only risk-map/yaml/lifecycle-stage.yaml under base.

    Lifecycle mode must NOT depend on components.yaml / controls.yaml /
    risks.yaml being present. Writing only the lifecycle file pins that
    architectural intent: lifecycle mode is single-file scoped.

    Args:
        base: Temporary directory root (pytest tmp_path).
        lifecycle: Parsed lifecycle YAML content, or None to omit the file
                   (simulating the file-absent case).

    Returns:
        base path for use as cwd via monkeypatch.chdir.
    """
    yaml_dir = base / "risk-map" / "yaml"
    yaml_dir.mkdir(parents=True)
    if lifecycle is not None:
        (yaml_dir / "lifecycle-stage.yaml").write_text(yaml.dump(lifecycle), encoding="utf-8")
    return base


class TestMainLifecycleMode:
    """
    Tests for the `--mode lifecycle` short-circuit entrypoint.

    These tests pin the contract that lifecycle mode is a narrow,
    single-purpose entrypoint that bypasses the components-validation
    pipeline and graph-generation paths entirely.
    """

    def test_mode_lifecycle_exits_0_on_clean_corpus(self, tmp_path, monkeypatch, capsys):
        """
        Test that --mode lifecycle exits 0 against a clean lifecycle-stage.yaml.

        Given: A tmp cwd containing only a clean risk-map/yaml/lifecycle-stage.yaml
               (orders 1..3, all unique)
        When:  validate_riskmap.main() is invoked with argv ["--mode", "lifecycle"]
        Then:  Exits with code 0 (lifecycle uniqueness check passes)
        """
        _write_lifecycle_only(tmp_path, _LIFECYCLE_CLEAN)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--mode", "lifecycle"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0, (
            f"Expected exit 0 on clean lifecycle corpus; got {exc_info.value.code}. "
            f"Captured output: {capsys.readouterr()!r}"
        )

    def test_mode_lifecycle_exits_1_on_duplicate_orders(self, tmp_path, monkeypatch, capsys):
        """
        Test that --mode lifecycle exits 1 when duplicate orders are present.

        Given: A tmp cwd containing risk-map/yaml/lifecycle-stage.yaml where
               stage-b and stage-c both carry order 2
        When:  validate_riskmap.main() is invoked with argv ["--mode", "lifecycle"]
        Then:  Exits with code 1 and the duplicate is reported on stdout/stderr.
               Block-mode-immediate semantics — no --block flag required
               (matches ADR-022 D4 disposition).
        """
        _write_lifecycle_only(tmp_path, _LIFECYCLE_DUPLICATE)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--mode", "lifecycle"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1, (
            f"Expected exit 1 on duplicate lifecycle orders; got {exc_info.value.code}"
        )

        # Confirm the duplicate is reported. Substring check matches the
        # output-shape contract from check_lifecycle_stage_order_uniqueness.
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "stage-b" in combined and "stage-c" in combined, (
            f"Expected duplicate stage IDs in output; got: {combined!r}"
        )

    def test_mode_lifecycle_does_not_call_get_staged_yaml_files(self, tmp_path, monkeypatch):
        """
        Test that --mode lifecycle bypasses get_staged_yaml_files entirely.

        Given: A tmp cwd containing a clean lifecycle-stage.yaml
        When:  validate_riskmap.main() is invoked with argv ["--mode", "lifecycle"]
        Then:  validate_riskmap.get_staged_yaml_files is NOT called AND the
               script exits 0 (lifecycle uniqueness check reached and passed).

        Architectural intent: lifecycle mode is a single-file narrow check;
        the components-validation pipeline (which uses get_staged_yaml_files
        to discover components.yaml) is irrelevant and must not run.

        The exit-code assertion guards against false-positive passes: if
        argparse rejects --mode lifecycle (current state, no flag wired)
        the script exits with argparse error code 2 before any pipeline
        runs, which would trivially satisfy a bare assert_not_called.
        Pinning exit 0 forces the test to validate both the bypass AND
        the successful lifecycle check on the same run.
        """
        _write_lifecycle_only(tmp_path, _LIFECYCLE_CLEAN)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--mode", "lifecycle"]):
            with patch("validate_riskmap.get_staged_yaml_files") as mock_get_files:
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 0, (
            f"Expected exit 0 (lifecycle check passed without going through the "
            f"components pipeline); got {exc_info.value.code}. "
            f"This test pins both the bypass and the success path."
        )
        mock_get_files.assert_not_called()

    def test_mode_lifecycle_does_not_instantiate_component_edge_validator(self, tmp_path, monkeypatch):
        """
        Test that --mode lifecycle bypasses ComponentEdgeValidator entirely.

        Given: A tmp cwd containing a clean lifecycle-stage.yaml
        When:  validate_riskmap.main() is invoked with argv ["--mode", "lifecycle"]
        Then:  validate_riskmap.ComponentEdgeValidator is NOT instantiated AND
               the script exits 0.

        Architectural intent: lifecycle mode short-circuits before the
        components-validation orchestration. Even though
        ComponentEdgeValidator.components is the gating attribute for the
        existing inline lifecycle-uniqueness call (validate_riskmap.py:191),
        in dedicated mode the gating is the file's existence, not validator
        state.

        Exit-code 0 assertion is the same false-positive guard as the
        get_staged_yaml_files bypass test above.
        """
        _write_lifecycle_only(tmp_path, _LIFECYCLE_CLEAN)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--mode", "lifecycle"]):
            with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 0, (
            f"Expected exit 0 (lifecycle check reached without instantiating "
            f"ComponentEdgeValidator); got {exc_info.value.code}."
        )
        mock_validator_class.assert_not_called()

    def test_mode_lifecycle_skips_graph_generation_when_to_graph_also_passed(self, tmp_path, monkeypatch, capsys):
        """
        Test that --mode lifecycle does not run graph generation even if
        --to-graph is also provided.

        Given: A tmp cwd containing a clean lifecycle-stage.yaml
        When:  validate_riskmap.main() is invoked with argv
               ["--mode", "lifecycle", "--to-graph", "graph.md"]
        Then:  ComponentGraph is NOT instantiated, AND the script exits with
               either:
                 - exit 0  (graph silently ignored in lifecycle mode), OR
                 - exit 2  (main() rejects the combination as a misuse with
                           a clear "incompatible flags" message — also
                           acceptable per architect intent).

        Disposition note: SWE may choose either disposition. The test
        intentionally accepts both; it pins only that ComponentGraph is
        NOT constructed (graph generation is incompatible with lifecycle
        mode's narrow scope) and that the script does NOT exit 1 (which
        would mean lifecycle check failed on the clean corpus, the wrong
        signal).

        False-positive guard: this test must FAIL before --mode lifecycle
        is implemented. Without the flag, argparse rejects the unknown
        argument with `error: unrecognized arguments: --mode lifecycle`,
        which would trivially satisfy the negative assertion on
        ComponentGraph. Asserting that the argparse "unrecognized arguments"
        message is NOT in stderr forces the test to fail until SWE wires
        the flag — at which point either disposition (silent ignore or
        explicit rejection) is accepted.
        """
        _write_lifecycle_only(tmp_path, _LIFECYCLE_CLEAN)
        monkeypatch.chdir(tmp_path)

        with patch(
            "sys.argv",
            ["script.py", "--mode", "lifecycle", "--to-graph", "graph.md"],
        ):
            with patch("validate_riskmap.ComponentGraph") as mock_graph_class:
                with pytest.raises(SystemExit) as exc_info:
                    main()

        captured = capsys.readouterr()

        # False-positive guard: argparse must have RECOGNIZED --mode lifecycle.
        # Without this assertion the test passes trivially on the unimplemented
        # flag, which defeats the red-phase purpose.
        assert "unrecognized arguments" not in captured.err, (
            f"argparse rejected --mode lifecycle as unrecognized; the flag must "
            f"be wired before this test can validate the architectural intent. "
            f"stderr: {captured.err!r}"
        )

        # Filter out exit 1 (lifecycle check failed on a clean corpus would
        # be wrong) and unexpected codes. Both 0 (graph ignored) and 2
        # (main() rejects the flag combination with a clear message) are
        # acceptable architectural choices.
        assert exc_info.value.code in (0, 2), (
            f"Expected exit 0 (graph ignored) or exit 2 (flag-combo rejected); got {exc_info.value.code}."
        )
        mock_graph_class.assert_not_called()

    def test_mode_lifecycle_exits_0_with_skip_message_when_file_absent(self, tmp_path, monkeypatch, capsys):
        """
        Test that --mode lifecycle exits 0 with a skip message when
        lifecycle-stage.yaml is absent.

        Given: A tmp cwd with no risk-map/yaml/lifecycle-stage.yaml
        When:  validate_riskmap.main() is invoked with argv ["--mode", "lifecycle"]
        Then:  Exits with code 0 and prints a skip message.

        Disposition: this mirrors the current default-mode graceful-skip
        behavior at validate_riskmap.py:210-212. lifecycle-stage.yaml may
        not be present in every test environment; the dedicated mode keeps
        the same forgiving disposition rather than promoting absence to a
        hard error. Skip message wording uses the substring "skipped" to
        stay format-agnostic with the existing line at 212.
        """
        _write_lifecycle_only(tmp_path, None)  # Omit the file
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--mode", "lifecycle"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0, (
            f"Expected exit 0 (graceful skip) when lifecycle-stage.yaml is absent; got {exc_info.value.code}"
        )

        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "skipped" in combined.lower(), (
            f"Expected a skip message when lifecycle-stage.yaml is absent; got: {combined!r}"
        )

    def test_default_mode_unchanged_when_mode_flag_omitted(self):
        """
        Test that the default code path is preserved when --mode is omitted.

        Given: argv with no --mode flag and no other arguments
        When:  parse_args() is called
        Then:  args.mode either does not exist or has a value that does NOT
               equal "lifecycle".

        Smoke test guarding against the new flag's argparse default
        accidentally redirecting the existing entrypoint into lifecycle mode.
        """
        with patch("sys.argv", ["script.py"]):
            args = parse_args()

        # SWE may name the attribute `mode` (most likely) or pick a different
        # spelling. Either way the default value must not be "lifecycle"; the
        # existing default code path must be reachable without setting the flag.
        mode_value = getattr(args, "mode", None)
        assert mode_value != "lifecycle", (
            f"Default args.mode must not be 'lifecycle'; got {mode_value!r}. "
            f"Existing default-mode behavior would otherwise be silently overridden."
        )

    def test_mode_lifecycle_with_file_flag_is_rejected(self, tmp_path, monkeypatch, capsys):
        """
        Test that --mode lifecycle --file PATH is rejected, not silently ignored.

        Given: A tmp cwd containing a clean lifecycle-stage.yaml and a
               components corpus elsewhere in the tree
        When:  main() is invoked with ["--mode", "lifecycle", "--file", <corpus>]
        Then:  Exits with code 2, names both flags, does not print the
               unexpected-exception banner, and does not report a lifecycle
               result

        Same defect class as the default-mode --file bug, one branch over:
        the lifecycle short-circuit at validate_riskmap.py:196-197 runs
        before args.file is looked at, so --file is discarded there too.
        Lifecycle mode reads a fixed path (risk-map/yaml/lifecycle-stage.yaml)
        and never consults a components corpus, so --file cannot mean
        anything here; rejecting it matches the disposition chosen for
        --force --file rather than leaving a flag that appears to work.

        This is a stricter disposition than the sibling --to-graph test,
        which accepts either silent-ignore or rejection. That test predates
        the decision; --file is being wired now, so it gets the decided
        contract rather than the tolerant one.

        The asymmetry is known and deliberately unreconciled: --to-graph is
        silently ignored in this mode (validate_riskmap.py:195), --file is
        rejected. Nor does this test foreclose making --file name the
        lifecycle corpus later — lifecycle mode hardcodes
        risk-map/yaml/lifecycle-stage.yaml at validate_riskmap.py:149, which
        is the same hardcoding --file exists to relieve. That option stays
        open; what is settled is only that --file must not be accepted here
        and then discarded. --file's help text carries the constraint
        (TestFileFlagHelpText) so a user meets it before the error.
        """
        _write_lifecycle_only(tmp_path, _LIFECYCLE_CLEAN)
        corpus = _write_custom_components(tmp_path, _COMPONENTS_CONSISTENT)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--mode", "lifecycle", "--file", str(corpus)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"Expected exit 2 for --mode lifecycle combined with --file; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert "--file" in combined and "lifecycle" in combined, (
            f"Expected the rejection message to name both --file and lifecycle mode; got: {combined!r}"
        )
        assert "Lifecycle stage order uniqueness check passed" not in combined, (
            f"The run reported a lifecycle result despite the rejected flag combination; got: {combined!r}"
        )
        _assert_not_crash_shaped(combined)


# ============================================================================
# TestProductionInvocations — characterization of the shipped command forms
# ============================================================================
#
# These tests pass against the current implementation by design. They are not
# red tests. They lock the observable behaviour of every invocation that CI
# and pre-commit actually run, so that wiring --file cannot silently change
# what those callers see. None of these forms passes --file.
#
#   .pre-commit-config.yaml:211            validate_riskmap.py --block
#   .pre-commit-config.yaml:232            validate_riskmap.py --mode lifecycle
#   .pre-commit-config.yaml:403            regenerate_graphs.py, which runs
#                                            validate_riskmap.py --to-graph
#                                            <tracked path> -m --quiet
#                                            (regenerate_graphs.py:42)
#   .github/workflows/validation.yml:259   validate_riskmap.py --force --block
#   .github/workflows/validation.yml:748   validate_riskmap.py --force \
#                                            --to-graph FILE
#
# The regenerate-graphs form is the fragile one. It is the only shipped form
# that passes no --force, so it depends on staging-based selection; graph
# generation sits downstream of the "no files to validate" skip
# (validate_riskmap.py:216-219), so any regression that makes selection return
# an empty list turns the hook into a silent no-op that git-adds stale
# diagrams. It is also the only form exercising --mermaid-format and --quiet.
#
# CI runs the script from a copy at the repo root (validation.yml:44, 183 and
# 298 copy validate_riskmap.py and riskmap_validator/ into the working
# directory), so every hardcoded relative corpus path resolves against the
# repo root. Most tests here import from scripts/hooks/ and only chdir to
# repo_root, which cannot see a regression that anchors paths on the module's
# own location; test_ci_force_form_from_a_root_copy reproduces the copy
# layout in a subprocess to cover that.
#
# What is locked:
#   - exit code
#   - the path handed to ComponentEdgeValidator.validate_file (via the
#     validated_corpus_paths fixture, which observes the parse rather than
#     any one method, so the assertion outlives a restructure of the call site)
#   - the options main() constructs the validator with (validator_init_spy)
#   - how get_staged_yaml_files is called on the staging-driven forms
#   - which downstream checks ran, via their outcome sentences
#   - the headline sentences a human or a CI log grep keys on
#   - for the graph forms, that the output file matches the committed diagram
#     byte for byte, which is the diff CI actually performs
#     (validation.yml:339)
#
# What is deliberately not locked: emoji, indentation, line ordering, and
# per-run detail such as the "Found 1 YAML file to validate" count line.
# Those are incidental formatting; pinning them would make unrelated edits
# fail here for no signal.
#
# Staging state is not reproducible in-process, so the staging-driven forms
# patch get_staged_yaml_files to stand in for `git diff --cached`. Everything
# downstream of file selection runs for real.
# ============================================================================

# Graph flag → (progress message, committed diagram, committed .mermaid).
# CI diffs the generated file against the first path; the regenerate-graphs
# hook writes both and git-adds them. A single-element list, parametrised
# so a future graph type is one entry away from the same coverage.
_GRAPH_FORMS = [
    (
        "--to-graph",
        "Graph visualization saved to",
        "risk-map/diagrams/risk-map-graph.md",
        "risk-map/diagrams/risk-map-graph.mermaid",
    ),
]


class TestProductionInvocations:
    """
    Characterization tests for the CI and pre-commit invocation forms.

    Green today and expected to stay green: any drift they catch is a
    regression in a shipped caller, not a red-phase expectation.
    """

    @pytest.mark.live_corpus
    @pytest.mark.parametrize(
        "staged_name",
        ["components.yaml", "controls.yaml", "risks.yaml"],
        ids=["components-staged", "controls-staged", "risks-staged"],
    )
    def test_precommit_block_form(
        self, staged_name, repo_root, monkeypatch, capsys, validated_corpus_paths, validator_init_spy
    ):
        """
        Test the pre-commit form `validate_riskmap.py --block` on the real corpus.

        Given: The repo root as cwd and one of the three files the
               validate-component-edges hook fires on staged
        When:  main() is called with --block
        Then:  Exits 0; the staged set is requested with target_file None and
               force False; components.yaml is validated regardless of which
               file was staged; the validator is built with
               allow_isolated=False and verbose=True; and all three
               downstream checks report a result

        Parametrised over all three staged files because the hook's `files:`
        regex covers all three (.pre-commit-config.yaml:212), and the
        controls-only and risks-only cases are the ones a naive
        `validate_file(yaml_files[0])` refactor breaks.

        The validator-construction assertion is the fence for the orphan
        check. No shipped form passes --allow-isolated, so nothing else pins
        its default, and any expression that lets it read True — for
        instance `args.allow_isolated or args.file is None` written for a
        --file guard — turns isolated components from a blocking failure
        into silence, with byte-identical output on today's clean corpus.
        """
        monkeypatch.chdir(repo_root)
        staged = [Path("risk-map/yaml") / staged_name]

        with patch("sys.argv", ["script.py", "--block"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=staged) as mock_get_files:
                with pytest.raises(SystemExit) as exc_info:
                    main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 0, (
            f"The shipped --block form must stay clean on the repo corpus; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        mock_get_files.assert_called_once_with(None, False)
        _assert_corpus_validated(validated_corpus_paths, DEFAULT_COMPONENTS_FILE, "--block")
        assert validator_init_spy == [(False, True)], (
            f"--block must build the validator with allow_isolated=False, verbose=True; got {validator_init_spy!r}"
        )
        assert "All YAML files passed component edge validation" in combined
        for sentence in _DOWNSTREAM_CHECK_SENTENCES:
            assert sentence in combined, (
                f"Downstream check {sentence!r} did not report a result; output: {combined!r}"
            )

    @pytest.mark.parametrize(
        "components,controls,expected_finding",
        [
            (_NESTING_DIRTY_COMPONENTS, _CLEAN_LOCAL_CONTROLS, "nesting check found"),
            (_CLEAN_LOCAL_COMPONENTS, _MIRROR_DIRTY_CONTROLS, "mirror check found"),
        ],
        ids=["nesting-only-findings", "mirror-only-findings"],
    )
    def test_precommit_block_form_promotes_warnings(
        self, components, controls, expected_finding, tmp_path, monkeypatch, capsys
    ):
        """
        Test that --block promotes warn-only findings to a failing exit.

        Given: A tmp cwd holding a corpus in which exactly one of the two
               warn-only checks has findings
        When:  main() is called with --block and components.yaml staged
        Then:  Exits 1, names the finding, and says the promotion happened

        Promotion is the only thing --block exists to do, and the clean-corpus
        case above cannot see it. Each check is exercised alone because the
        promotion decision is deferred to a single exit after both have run
        (validate_riskmap.py:346-348): moving that exit inside either branch —
        an easy slip when re-indenting for a --file guard — leaves the other
        check's findings unpromoted, and the surviving case would still pass.
        """
        _write_repo_layout_corpus(tmp_path, components, controls)
        monkeypatch.chdir(tmp_path)
        staged = [Path("risk-map/yaml/components.yaml")]

        with patch("sys.argv", ["script.py", "--block"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=staged):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 1, (
            f"--block must fail the run when a warn-only check has findings; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert expected_finding in combined, f"Expected {expected_finding!r} in the output; got: {combined!r}"
        assert "promoted to errors" in combined, (
            f"Expected --block to say it promoted the findings; got: {combined!r}"
        )

    @pytest.mark.live_corpus
    def test_precommit_lifecycle_form(self, repo_root, monkeypatch, capsys, validated_corpus_paths):
        """
        Test the pre-commit form `validate_riskmap.py --mode lifecycle`.

        Given: The repo root as cwd
        When:  main() is called with --mode lifecycle
        Then:  Exits 0, reports the lifecycle result, and never enters the
               components pipeline — neither file selection nor validation

        The get_staged_yaml_files assertion is the load-bearing one. The
        empty-parse assertion alone is close to vacuous here:
        with nothing staged the real selection returns an empty list and
        main() exits before validating, so that assertion holds whether or
        not the short-circuit works.
        """
        monkeypatch.chdir(repo_root)

        with patch("sys.argv", ["script.py", "--mode", "lifecycle"]):
            with patch("validate_riskmap.get_staged_yaml_files") as mock_get_files:
                with pytest.raises(SystemExit) as exc_info:
                    main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 0, (
            f"The shipped lifecycle form must stay clean on the repo corpus; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert "Lifecycle stage order uniqueness check passed" in combined
        mock_get_files.assert_not_called()
        assert validated_corpus_paths == [], (
            f"Lifecycle mode must not run the components pipeline; it parsed {validated_corpus_paths!r}"
        )
        assert "All YAML files passed component edge validation" not in combined

    @pytest.mark.live_corpus
    def test_ci_force_form(self, repo_root, monkeypatch, capsys, validated_corpus_paths, validator_init_spy):
        """
        Test the CI form `validate_riskmap.py --force` (validation.yml:195).

        Given: The repo root as cwd, nothing staged
        When:  main() is called with --force
        Then:  Exits 0, validates components.yaml, builds the validator with
               allow_isolated=False and verbose=True, prints the force
               header, and all three downstream checks report a result

        Nothing is patched: --force is self-contained by design, which is why
        CI uses it.
        """
        monkeypatch.chdir(repo_root)

        with patch("sys.argv", ["script.py", "--force"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 0, (
            f"The shipped --force form must stay clean on the repo corpus; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        _assert_corpus_validated(validated_corpus_paths, DEFAULT_COMPONENTS_FILE, "--force")
        assert validator_init_spy == [(False, True)], (
            f"--force must build the validator with allow_isolated=False, verbose=True; got {validator_init_spy!r}"
        )
        assert "Force checking components" in combined
        assert "All YAML files passed component edge validation" in combined
        for sentence in _DOWNSTREAM_CHECK_SENTENCES:
            assert sentence in combined, (
                f"Downstream check {sentence!r} did not report a result; output: {combined!r}"
            )

    def test_ci_force_form_outside_a_git_repository(self, tmp_path, monkeypatch, capsys):
        """
        Test that `--force` validates without consulting git.

        Given: A tmp cwd that is not a git repository, holding a corpus at
               the default location
        When:  main() is called with --force
        Then:  Exits 0 having validated the corpus, with no git warning

        --force reaches get_staged_yaml_files' force branch
        (utils.py:227-233), which returns the target file without shelling
        out to git. That property is what makes the flag usable in CI before
        anything is staged, and it is asserted in prose elsewhere in this
        file but was not tested. Removing that branch — for instance on the
        mistaken view that --file supersedes it — would leave --force
        exiting 0 having validated nothing.
        """
        _write_repo_layout_corpus(tmp_path, _CLEAN_LOCAL_COMPONENTS, _CLEAN_LOCAL_CONTROLS)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--force"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert "Make sure you're in a git repository" not in combined, (
            f"--force must not consult git; got a git warning: {combined!r}"
        )
        assert "No YAML files to validate" not in combined, (
            f"--force found nothing to validate outside a git repository; output: {combined!r}"
        )
        assert _EDGES_CONSISTENT in combined, f"Expected the corpus to have been validated; got: {combined!r}"
        assert exc_info.value.code == 0, (
            f"Expected exit 0 on a clean corpus; got {exc_info.value.code}. Output: {combined!r}"
        )

    def test_ci_force_form_reports_isolated_components(self, tmp_path, monkeypatch, capsys):
        """
        Test that isolated components fail the default (no --allow-isolated) run.

        Given: A tmp cwd holding a corpus with one component that has no edges
        When:  main() is called with --force and no --allow-isolated
        Then:  Exits 1 and names the isolated component

        Behavioural counterpart to the validator-construction assertions: it
        pins the consequence rather than the constructor argument, so an
        allow_isolated default that drifts to True is caught even if the
        constructor's shape changes. Every shipped form runs without
        --allow-isolated, so this is the default they all rely on.
        """
        orphan_corpus = {
            "categories": _CLEAN_LOCAL_COMPONENTS["categories"],
            "components": _CLEAN_LOCAL_COMPONENTS["components"]
            + [
                {
                    "id": "componentStranded",
                    "title": "Stranded",
                    "category": "catData",
                    "subcategory": "subStorage",
                }
            ],
        }
        _write_repo_layout_corpus(tmp_path, orphan_corpus, _CLEAN_LOCAL_CONTROLS)
        monkeypatch.chdir(tmp_path)

        with patch("sys.argv", ["script.py", "--force"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 1, (
            f"An isolated component must fail the run when --allow-isolated is absent; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert "componentStranded" in combined, f"Expected the isolated component to be named; got: {combined!r}"

    @pytest.mark.live_corpus
    def test_ci_force_form_from_a_root_copy(self, tmp_path, repo_root):
        """
        Test the CI layout: the script copied to the root of the tree it validates.

        Given: A directory holding a copy of validate_riskmap.py, a copy of
               riskmap_validator/ and a copy of risk-map/yaml/, mirroring
               validation.yml:44, 183 and 298
        When:  `python3 validate_riskmap.py --force` runs there
        Then:  Exits 0 and all three downstream checks report a result

        Every other test here imports the script from scripts/hooks/, so all
        of them see a module whose location happens to sit two levels below
        the corpus. A path anchored on the module's own location instead of
        the working directory — `Path(__file__).resolve().parents[2]`, a
        natural-looking response to C3's complaint about hardcoded relative
        paths — keeps working for them and silently skips all three
        downstream checks in CI, exiting 0. A subprocess is required: the
        behaviour depends on the script's real __file__ and cwd.
        """
        shutil.copy(repo_root / "scripts" / "hooks" / "validate_riskmap.py", tmp_path)
        shutil.copytree(repo_root / "scripts" / "hooks" / "riskmap_validator", tmp_path / "riskmap_validator")
        shutil.copytree(repo_root / "risk-map" / "yaml", tmp_path / "risk-map" / "yaml")

        result = subprocess.run(
            [sys.executable, "validate_riskmap.py", "--force"],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        combined = result.stdout + result.stderr

        assert result.returncode == 0, (
            f"The CI root-copy layout must validate cleanly; got {result.returncode}. Output: {combined!r}"
        )
        assert "All YAML files passed component edge validation" in combined
        for sentence in _DOWNSTREAM_CHECK_SENTENCES:
            assert sentence in combined, (
                f"Downstream check {sentence!r} did not run in the root-copy layout; output: {combined!r}"
            )

    @pytest.mark.live_corpus
    @pytest.mark.parametrize(
        "flag,saved_message,committed_md,committed_mermaid",
        _GRAPH_FORMS,
        ids=[form[0].lstrip("-") for form in _GRAPH_FORMS],
    )
    def test_ci_graph_forms(
        self,
        flag,
        saved_message,
        committed_md,
        committed_mermaid,
        tmp_path,
        repo_root,
        monkeypatch,
        capsys,
        validated_corpus_paths,
    ):
        """
        Test the CI graph form `--force --to-graph FILE` (validation.yml:748).

        Given: The repo root as cwd and an extensionless output path, as
               produced by $(mktemp) at validation.yml:725
        When:  main() is called with --force and the graph flag
        Then:  Exits 0, validates components.yaml, writes the graph to
               exactly the path given, and that file matches the committed
               diagram byte for byte

        The output path deliberately has no extension. CI passes $(mktemp)
        output, so a normalisation such as `args.to_graph.with_suffix(".md")`
        would write somewhere else and leave CI diffing an empty file — a
        test using "graph.md" cannot see that. Byte equality is CI's real
        contract: it runs `diff -u` against the committed diagram
        (validation.yml:751) and fails the build on any difference.
        """
        monkeypatch.chdir(repo_root)
        output = tmp_path / "graph-output"

        with patch("sys.argv", ["script.py", "--force", flag, str(output)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 0, (
            f"The shipped {flag} form must stay clean on the repo corpus; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        _assert_corpus_validated(validated_corpus_paths, DEFAULT_COMPONENTS_FILE, flag)
        assert f"{saved_message} {output}" in combined
        assert output.is_file(), (
            f"{flag} wrote no output to the exact path it was given ({output}); "
            f"CI diffs that path and cannot follow a renamed file"
        )
        assert output.read_text(encoding="utf-8") == (repo_root / committed_md).read_text(encoding="utf-8"), (
            f"{flag} output no longer matches the committed {committed_md}; CI diffs these and fails"
        )
        for sentence in _DOWNSTREAM_CHECK_SENTENCES:
            assert sentence in combined, (
                f"Downstream check {sentence!r} did not report a result; output: {combined!r}"
            )

    @pytest.mark.live_corpus
    @pytest.mark.parametrize(
        "flag,saved_message,committed_md,committed_mermaid",
        _GRAPH_FORMS,
        ids=[form[0].lstrip("-") for form in _GRAPH_FORMS],
    )
    def test_precommit_regenerate_graphs_form(
        self,
        flag,
        saved_message,
        committed_md,
        committed_mermaid,
        tmp_path,
        repo_root,
        monkeypatch,
        capsys,
        validated_corpus_paths,
    ):
        """
        Test the regenerate-graphs hook form: a graph flag, -m, --quiet, no --force.

        Given: The repo root as cwd and components.yaml staged
        When:  main() is called as regenerate_graphs.py:42 calls it —
               <graph flag> <path> -m --quiet, with no --force
        Then:  Exits 0; the staged set is requested with target_file None and
               force False; components.yaml is validated; both the .md and
               the .mermaid file are written and match the committed
               diagrams; and --quiet suppresses the narration while leaving
               the saved-to progress lines

        This form depends on staging-based selection, and graph generation
        sits downstream of the "no files to validate" skip
        (validate_riskmap.py:216-219). A regression that empties the selected
        list turns the hook into a silent no-op: it exits 0, writes nothing,
        and the wrapper git-adds the stale committed diagrams. The
        .mermaid assertion is the only coverage of --mermaid-format in a
        shipped form.
        """
        monkeypatch.chdir(repo_root)
        staged = [Path("risk-map/yaml/components.yaml")]
        output = tmp_path / Path(committed_md).name

        with patch("sys.argv", ["script.py", flag, str(output), "-m", "--quiet"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=staged) as mock_get_files:
                with pytest.raises(SystemExit) as exc_info:
                    main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 0, (
            f"The regenerate-graphs form must stay clean on the repo corpus; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        mock_get_files.assert_called_once_with(None, False)
        _assert_corpus_validated(
            validated_corpus_paths, DEFAULT_COMPONENTS_FILE, f"the regenerate-graphs form ({flag})"
        )
        assert f"{saved_message} {output}" in combined

        mermaid_output = output.with_suffix(".mermaid")
        assert output.read_text(encoding="utf-8") == (repo_root / committed_md).read_text(encoding="utf-8"), (
            f"{flag} -m output no longer matches the committed {committed_md}; the hook would "
            f"git-add a diagram that differs from the corpus"
        )
        assert mermaid_output.read_text(encoding="utf-8") == (repo_root / committed_mermaid).read_text(
            encoding="utf-8"
        ), f"{flag} -m .mermaid output no longer matches the committed {committed_mermaid}"

        assert "Checking for staged YAML files" not in combined, (
            f"--quiet must suppress the file-selection narration; got: {combined!r}"
        )
        assert "All YAML files passed component edge validation" not in combined, (
            f"--quiet must suppress the success headline; got: {combined!r}"
        )

    @pytest.mark.live_corpus
    def test_precommit_regenerate_graphs_form_writes_nothing_when_nothing_staged(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that the regenerate-graphs form is a no-op when selection is empty.

        Given: The repo root as cwd and an empty staged set
        When:  main() is called with --to-graph <path> -m --quiet
        Then:  Exits 0 and writes no file

        Characterizes the coupling that makes the previous test matter: graph
        generation is downstream of the skip at validate_riskmap.py:216-219,
        so an empty selection produces a successful, silent, output-free run.
        The wrapper reads only the exit code (regenerate_graphs.py:63-70) and
        git-adds the paths regardless, so this state stages whatever was
        already committed. Pinned so that a change making selection empty in
        the staged case cannot pass unnoticed as "still exits 0".
        """
        monkeypatch.chdir(repo_root)
        output = tmp_path / "risk-map-graph.md"

        with patch("sys.argv", ["script.py", "--to-graph", str(output), "-m", "--quiet"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=[]):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 0, (
            f"An empty staged set exits 0 today; got {exc_info.value.code}. Output: {combined!r}"
        )
        assert not output.exists(), f"No graph should be written when nothing was selected; found {output}"


# ============================================================================
# TestEmissionModeCLIOverride -- `--emission-mode` (ADR-036 D3)
# ============================================================================
#
# Wiring-behavior tests for the CLI override lever, complementing the
# argparse-level parsing tests in TestParseArgs above. `--emission-mode`
# lets a contributor A/B-render the component graph without editing
# mermaid-styles.yaml: config remains the source of truth, and the flag
# never persists.
#
# Structural constraint: `ComponentGraph.
# __init__`'s signature stays unchanged, and `build_graph()`/`_emit_decoupled()`
# read emission mode ONLY via `self.config_loader.get_emission_config()`
# (never from a constructor parameter). Given those two fixed points, the
# override can only reach graph construction by passing an already-existing
# `MermaidConfigLoader`-like object through ComponentGraph's existing
# optional `config_loader=` parameter, whose `get_emission_config()` reflects
# the override. This is not an assumption about a particular implementation
# strategy so much as a structural consequence of the frozen signatures --
# but the exact mechanism (subclass, wrapper, `dataclasses.replace` on a
# copied instance, etc.) is still an implementation choice, and these tests
# only pin the externally observable contract: whatever object ends up as
# `config_loader=`, its `get_emission_config().mode` reflects the override
# when one was requested.


class TestEmissionModeCLIOverride:
    def test_emission_mode_flag_recognized_reaches_pipeline(self, capsys):
        """
        False-positive guard: --emission-mode must be recognized by argparse
        AND reach graph construction, not merely parse without crashing.

        Given: --force --to-graph out.md --emission-mode decoupled
        When: main() is called (ComponentGraph mocked)
        Then: argparse recognizes the flag (no "unrecognized arguments" in
              stderr) and the script exits 0

        Mirrors the false-positive-guard pattern used for --mode lifecycle
        elsewhere in this file (test_mode_lifecycle_skips_graph_generation_
        when_to_graph_also_passed): without this assertion, an unimplemented
        flag would make argparse itself exit before ComponentGraph is ever
        constructed, which could otherwise mask a wiring gap in later
        assertions.
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("output/graph.md")

        with patch(
            "sys.argv",
            ["script.py", "--force", "--to-graph", str(graph_path), "--emission-mode", "decoupled"],
        ):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.ComponentGraph") as mock_graph_class:
                        with patch("builtins.open", mock_open()):
                            mock_validator = Mock()
                            mock_validator.validate_file.return_value = True
                            mock_validator.forward_map = {"A": ["B"]}
                            mock_validator.components = {"A": Mock(), "B": Mock()}
                            mock_validator_class.return_value = mock_validator

                            mock_graph = Mock()
                            mock_graph.to_mermaid.return_value = "graph"
                            mock_graph_class.return_value = mock_graph

                            with pytest.raises(SystemExit) as exc_info:
                                main()

        captured = capsys.readouterr()
        assert "unrecognized arguments" not in captured.err, (
            f"argparse rejected --emission-mode as unrecognized; the flag must be "
            f"wired before this test can validate the override. stderr: {captured.err!r}"
        )
        assert exc_info.value.code == 0

    def test_emission_mode_override_reaches_component_graph_config(self):
        """
        Given: --emission-mode decoupled, and a real MermaidConfigLoader
               (`open` is mocked here, so the loader never reads the committed
               mermaid-styles.yaml -- which says "decoupled" -- and falls back to
               its own emergency default instead: MermaidConfigLoader.
               _get_emergency_defaults's graphTypes.component.emission ==
               {"mode": "flat"})
        When: main() is called with --to-graph set (ComponentGraph mocked)
        Then: ComponentGraph is constructed with a config_loader whose
              get_emission_config().mode == "decoupled" -- the override,
              not the file's own "flat" default

        See the class docstring above for why config_loader is the only
        structurally possible injection point given the frozen
        ComponentGraph.__init__ / build_graph() contract.
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("output/graph.md")

        argv = ["script.py", "--force", "--to-graph", str(graph_path), "--emission-mode", "decoupled"]
        with patch("sys.argv", argv):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.ComponentGraph") as mock_graph_class:
                        with patch("builtins.open", mock_open()):
                            mock_validator = Mock()
                            mock_validator.validate_file.return_value = True
                            mock_validator.forward_map = {"A": ["B"]}
                            mock_validator.components = {"A": Mock(), "B": Mock()}
                            mock_validator_class.return_value = mock_validator

                            mock_graph = Mock()
                            mock_graph.to_mermaid.return_value = "graph"
                            mock_graph_class.return_value = mock_graph

                            with pytest.raises(SystemExit) as exc_info:
                                main()

        assert exc_info.value.code == 0
        assert mock_graph_class.call_count == 1, "ComponentGraph must be constructed exactly once"
        _, kwargs = mock_graph_class.call_args
        config_loader = kwargs.get("config_loader")
        assert config_loader is not None, (
            "Expected ComponentGraph to be constructed with an explicit config_loader= "
            "reflecting the --emission-mode override (the only injection point given "
            "ComponentGraph.__init__'s frozen signature); got no config_loader kwarg at "
            f"all. Full call: args={mock_graph_class.call_args}"
        )
        assert config_loader.get_emission_config().mode == "decoupled", (
            f"Expected the config_loader passed to ComponentGraph to report mode "
            f"'decoupled' (the --emission-mode override), got "
            f"{config_loader.get_emission_config().mode!r}"
        )

    def test_absent_emission_mode_flag_preserves_existing_call_signature(self):
        """
        Given: no --emission-mode flag (existing behavior)
        When: main() is called with --to-graph set (ComponentGraph mocked)
        Then: ComponentGraph is still constructed as
              ComponentGraph(forward_map, components, debug=False) -- the
              exact call signature test_main_generates_component_graph_when_
              to_graph_specified already pins

        Regression guard: the flag's absence must never change existing
        behavior -- proving the override mechanism is opt-in only and never
        leaks a config_loader override into the default (no-flag) path.
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("output/graph.md")

        with patch("sys.argv", ["script.py", "--force", "--to-graph", str(graph_path)]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.ComponentGraph") as mock_graph_class:
                        with patch("builtins.open", mock_open()):
                            mock_validator = Mock()
                            mock_validator.validate_file.return_value = True
                            mock_validator.forward_map = {"A": ["B"]}
                            mock_validator.components = {"A": Mock(), "B": Mock()}
                            mock_validator_class.return_value = mock_validator

                            mock_graph = Mock()
                            mock_graph.to_mermaid.return_value = "graph"
                            mock_graph_class.return_value = mock_graph

                            with pytest.raises(SystemExit) as exc_info:
                                main()

        assert exc_info.value.code == 0
        mock_graph_class.assert_called_once_with(
            mock_validator.forward_map, mock_validator.components, debug=False
        )


# ============================================================================
# TestEmissionModeOverrideWithoutEmissionBlock -- `--emission-mode decoupled`
# against a styles file with no emission block (ADR-036 D3)
# ============================================================================
#
# Unmocked, end-to-end: ComponentGraph is constructed for real against the
# real MermaidConfigLoader pointed at a styles file with no
# graphTypes.component.emission block at all. get_emission_config() degrades
# that absence to EmissionConfig(mode="flat") (graph_utils.py), and
# _EmissionModeOverrideConfigLoader then overrides only .mode to "decoupled"
# via dataclasses.replace -- leaving aspects/concerns/port_styles at their
# flat-default (empty) values. ComponentGraph.build_graph() dispatches on
# mode == "decoupled", calling build_decoupled_plan() with no portStyles to
# draw from, and ComponentGraph's own S6 self-check raises before the render
# completes. ComponentGraph.__init__ calls build_graph() eagerly, so the
# AssertionError surfaces at the construction call inside validate_riskmap.py's
# `if args.to_graph:` block, whose handler recognises the missing-port-style
# condition and prints the named usage error (exit 2) instead of letting it
# fall through to main()'s outer `except Exception` crash banner. The classes
# below pin that routing: the named error for a config that cannot supply the
# style, the crash banner for every other construction failure.


class TestEmissionModeOverrideWithoutEmissionBlock:
    def _run_with_no_emission_block_styles(self, tmp_path, repo_root, monkeypatch, capsys):
        """
        Shared setup: a tmp cwd holding a real copy of risk-map/yaml/ with
        mermaid-styles.yaml swapped for the committed no-emission-block
        fixture, then `--force --to-graph <tmp> --emission-mode decoupled`.

        Returns (combined_output, exit_code).
        """
        shutil.copytree(repo_root / "risk-map" / "yaml", tmp_path / "risk-map" / "yaml")
        # Category style check reads components.schema.json independently of
        # mermaid-styles.yaml; without a copy it degrades to its own "could
        # not run" line, which is harmless but adds an unrelated ❌ line to
        # the captured output this test's assertions read.
        shutil.copytree(repo_root / "risk-map" / "schemas", tmp_path / "risk-map" / "schemas")
        no_emission_fixture = (
            repo_root
            / "scripts"
            / "hooks"
            / "tests"
            / "fixtures"
            / "graphing"
            / "flat-rollback"
            / "mermaid-styles-no-emission-block.yaml"
        )
        shutil.copy(no_emission_fixture, tmp_path / "risk-map" / "yaml" / "mermaid-styles.yaml")
        monkeypatch.chdir(tmp_path)

        graph_path = tmp_path / "out.md"
        argv = [
            "script.py",
            "--force",
            "--to-graph",
            str(graph_path),
            "--emission-mode",
            "decoupled",
        ]
        with patch("sys.argv", argv):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        return captured.out + captured.err, exc_info.value.code

    def test_emission_mode_override_without_emission_block_is_not_crash_shaped(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that the override never reaches the "report this issue to the
        maintainers" banner.

        Given: --force --to-graph out --emission-mode decoupled, and a
               committed mermaid-styles.yaml with NO graphTypes.component.emission
               block at all (the flat-rollback no-emission-block fixture)
        When: main() runs the real (unmocked) ComponentGraph construction
        Then: the output carries none of _CRASH_BANNER_MARKERS

        This is a bad-input/unsupported-combination case (the override asks for
        decoupled emission from a config that never declared one), not an
        internal defect -- the repo's `_assert_not_crash_shaped` contract
        (used throughout this module for --file and corpus-parse failures)
        applies here too.
        """
        combined, _ = self._run_with_no_emission_block_styles(tmp_path, repo_root, monkeypatch, capsys)
        _assert_not_crash_shaped(combined)

    def test_emission_mode_override_without_emission_block_names_the_missing_block_and_port_styles(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that the rejection names the actual gap, not a generic failure.

        Given: the same override-without-emission-block setup
        When: main() runs
        Then: the output names `graphTypes.component.emission` (the config
              path the override needs populated) and `portStyles` (the
              specific sub-key the decoupled renderer cannot draw ports
              without)

        A message that only said "graph generation failed" would leave a
        contributor to trace S6's internal assertion text back to the missing
        config themselves; naming both the dotted config path and the
        concrete missing key is what makes this actionable rather than
        merely non-crash-shaped.
        """
        combined, _ = self._run_with_no_emission_block_styles(tmp_path, repo_root, monkeypatch, capsys)
        assert "graphTypes.component.emission" in combined, (
            f"Expected the dotted config path graphTypes.component.emission named in the "
            f"rejection message; got: {combined!r}"
        )
        assert "portStyles" in combined, (
            f"Expected portStyles named as the specific missing sub-key the decoupled "
            f"renderer needs; got: {combined!r}"
        )

    def test_emission_mode_override_without_emission_block_exits_with_the_named_usage_error_code(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test the exit code matches this file's own named-usage-error convention.

        Given: the same override-without-emission-block setup
        When: main() runs
        Then: exit code == 2, non-zero and not the validation-failure code (1)

        This file already reuses exit 2 for both the crash banner
        (`main()`'s top-level `except Exception` catch-all, the "Unexpected
        error" banner) and named, non-crash usage
        errors (`--file path does not exist`, `CorpusParseError` at corpus
        parse) -- the two are distinguished by banner text
        (`_assert_not_crash_shaped`), not by exit code. Pinning 2 here matches
        that existing convention rather than inventing a third code.
        """
        _, exit_code = self._run_with_no_emission_block_styles(tmp_path, repo_root, monkeypatch, capsys)
        assert exit_code == 2, (
            f"Expected exit 2 (this file's named-usage-error convention -- see "
            f"--file-does-not-exist and CorpusParseError); got {exit_code}"
        )

    def test_emission_mode_override_without_emission_block_message_does_not_leak_internal_s6_token(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that the named usage error does not leak the emitter's internal self-check label.

        Given: the same override-without-emission-block setup
        When: main() runs
        Then: the output does not contain the internal token "S6"

        The usage-error message embeds the raw exception text via `{e}`, and the
        exception this setup actually raises is S6's own AssertionError ("S6
        violated: missing 'classDef port' ..."). A content contributor reading the
        message has no reason to know what "S6" means, and the two identifiers this
        branch already names (graphTypes.component.emission, portStyles) are enough
        to act on without it.
        """
        combined, _ = self._run_with_no_emission_block_styles(tmp_path, repo_root, monkeypatch, capsys)
        assert "S6" not in combined, (
            f"Expected the internal self-check label 'S6' not to leak into the usage-error "
            f"message; got: {combined!r}"
        )


class TestEmissionModeOverrideGenuineDefectNotMislabeled:
    """
    A construction failure that is NOT the missing-port-styles condition (S6) must
    not be reported as a missing-config usage error. With a VALID
    graphTypes.component.emission block on disk (the repo's own committed
    mermaid-styles.yaml, unmodified), any other exception escaping ComponentGraph's
    decoupled construction path -- a plain defect in the transform/emitter, or one
    of the other D7 structural guards (S1/S4/S5/S7) -- is a real bug, not a
    "you forgot to configure this" situation, and must surface the same way any
    other unexpected internal error does in this tool (the crash banner asserted
    via _CRASH_BANNER_MARKERS elsewhere in this module), with the underlying
    exception text still visible.
    """

    def _run_with_valid_emission_block(self, tmp_path, repo_root, monkeypatch, capsys, patch_name, exc):
        """
        Shared setup: a tmp cwd holding a real, unmodified copy of risk-map/yaml/
        (mermaid-styles.yaml's committed graphTypes.component.emission block is
        valid and populated, including portStyles), with `patch_name` on the
        component_graph module replaced so the decoupled construction path raises
        `exc` instead of completing.

        Returns (combined_output, exit_code).
        """
        shutil.copytree(repo_root / "risk-map" / "yaml", tmp_path / "risk-map" / "yaml")
        # Category style check reads components.schema.json independently of
        # mermaid-styles.yaml; without a copy it degrades to its own "could not
        # run" line, which is harmless but adds an unrelated line to the output
        # this test's assertions read.
        shutil.copytree(repo_root / "risk-map" / "schemas", tmp_path / "risk-map" / "schemas")
        monkeypatch.chdir(tmp_path)

        def _raise(*_args, **_kwargs):
            raise exc

        monkeypatch.setattr(component_graph, patch_name, _raise)

        graph_path = tmp_path / "out.md"
        argv = [
            "script.py",
            "--force",
            "--to-graph",
            str(graph_path),
            "--emission-mode",
            "decoupled",
        ]
        with patch("sys.argv", argv):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        return captured.out + captured.err, exc_info.value.code

    def test_generic_defect_with_valid_emission_block_is_crash_shaped_not_missing_config(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that a plain internal defect is reported as a defect, not a config gap.

        Given: --force --to-graph out --emission-mode decoupled, the repo's own
               committed mermaid-styles.yaml (a VALID, populated
               graphTypes.component.emission block, including portStyles), and
               build_decoupled_plan() patched to raise a RuntimeError unrelated to
               any missing config
        When: main() runs
        Then: the output carries the crash banner (_CRASH_BANNER_MARKERS), NOT the
              "requires a populated ... emission block" usage-error wording, and
              the underlying exception text stays visible

        A missing-config message here would send a maintainer chasing a
        mermaid-styles.yaml edit for a bug that has nothing to do with
        configuration.
        """
        combined, exit_code = self._run_with_valid_emission_block(
            tmp_path,
            repo_root,
            monkeypatch,
            capsys,
            "build_decoupled_plan",
            RuntimeError("synthetic defect"),
        )
        for marker in _CRASH_BANNER_MARKERS:
            assert marker in combined, (
                f"Expected the crash banner ({marker!r}) for a genuine internal defect "
                f"with a valid emission block; got: {combined!r}"
            )
        assert "requires a populated" not in combined, (
            f"A genuine defect must not be reported as a missing-config usage error; got: {combined!r}"
        )
        assert "synthetic defect" in combined, (
            f"Expected the underlying exception text to stay visible; got: {combined!r}"
        )
        assert exit_code == 2, f"Expected exit 2 (this file's error-exit convention); got {exit_code}"

    def test_structural_guard_violation_with_valid_emission_block_is_crash_shaped_not_missing_config(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that a content-triggered structural guard (S5, not S6) is a defect too.

        Given: the same valid-emission-block setup, and verify_plan() patched to
               raise the S5 edge-conservation AssertionError (a structural guard
               distinct from S6, the missing-port-styles check)
        When: main() runs
        Then: the output carries the crash banner, NOT the "requires a populated
              ... emission block" wording, and the S5 exception text stays visible

        S5 firing means the transform IR itself is inconsistent -- it says nothing
        about whether mermaid-styles.yaml is populated, so it must not be folded
        into the same message as the S6 missing-config case.
        """
        combined, exit_code = self._run_with_valid_emission_block(
            tmp_path,
            repo_root,
            monkeypatch,
            capsys,
            "verify_plan",
            AssertionError(
                "S5 edge conservation violated: intra_drawn(1) + 2*collapsed(0) + "
                "channelled(0) + lifted(0) = 1 != total_edges(2)"
            ),
        )
        for marker in _CRASH_BANNER_MARKERS:
            assert marker in combined, (
                f"Expected the crash banner ({marker!r}) for an S5 structural-guard "
                f"violation with a valid emission block; got: {combined!r}"
            )
        assert "requires a populated" not in combined, (
            f"An S5 violation must not be reported as a missing-config usage error; got: {combined!r}"
        )
        assert "S5 edge conservation violated" in combined, (
            f"Expected the underlying S5 exception text to stay visible; got: {combined!r}"
        )
        assert exit_code == 2, f"Expected exit 2 (this file's error-exit convention); got {exit_code}"

    def test_s6_category_style_violation_with_valid_emission_block_is_crash_shaped_not_missing_config(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that an S6 violation OTHER than the missing-port-style condition is a defect too.

        Given: the same valid-emission-block setup, and verify_plan patched to
               raise the "missing category style line" variant of S6 -- not the
               port/pepport/pepWrapOutline variants the named usage error is
               built around
        When: main() runs
        Then: the output carries the crash banner, NOT the "requires a populated
              ... emission block" wording, and the S6 category-style exception text
              stays visible

        S6 has four distinct raise sites; three of them (missing 'classDef
        port', 'classDef pepport', or the pepWrapOutline style line) are about
        a port style, and the category-style site is not. This variant proves
        the label "S6" alone is not sufficient to route a message to the
        missing-config wording -- a port-style signature is required, not just
        membership in the S6 self-check.
        """
        combined, exit_code = self._run_with_valid_emission_block(
            tmp_path,
            repo_root,
            monkeypatch,
            capsys,
            "verify_plan",
            AssertionError("S6 violated: missing category style line 'style componentData fill:#eee,stroke:#333'"),
        )
        for marker in _CRASH_BANNER_MARKERS:
            assert marker in combined, (
                f"Expected the crash banner ({marker!r}) for an S6 category-style "
                f"violation with a valid emission block; got: {combined!r}"
            )
        assert "requires a populated" not in combined, (
            f"An S6 category-style violation is not the missing-port-styles condition and "
            f"must not be reported as a missing-config usage error; got: {combined!r}"
        )
        assert "S6 violated: missing category style line" in combined, (
            f"Expected the underlying S6 category-style exception text to stay visible; got: {combined!r}"
        )
        assert exit_code == 2, f"Expected exit 2 (this file's error-exit convention); got {exit_code}"


# ============================================================================
# Config-driven decoupled mode with a missing or empty required port style
# ============================================================================
#
# When mermaid-styles.yaml declares mode: decoupled itself, a
# contributor who deletes or blanks one of the three port styles the S6
# self-check can demand (`port` for drawn channel ports, `pepport` and
# `pepWrapOutline` for PEP wrappers) reaches ComponentGraph construction with
# no --emission-mode flag at all: ComponentGraph.__init__ -> build_graph() ->
# _emit_decoupled() -> _check_s6_style_classdef_presence() raises at
# construction, exactly where the override case does. The schema hook rejects
# that file too, but the graph-regeneration hook still runs in the same
# pre-commit pass, so validate_riskmap.py --to-graph must give the same
# named, non-crash usage error for the config-driven case as for the override,
# and pepWrapOutline is a recognised case alongside port/pepport.
#
# The boundary the named error must not cross: an emitter defect in which the
# style IS configured but its line is not emitted raises the very same S6
# message, and stays crash-shaped. S6's message alone therefore cannot route
# the error; the observable contract is pinned from both sides below.

_DECOUPLED_REQUIRED_PORT_STYLE_KEYS = ("port", "pepport", "pepWrapOutline")

_CONFIG_PORT_STYLES_PATH = "graphTypes.component.emission.portStyles"


def _copy_real_corpus(tmp_path: Path, repo_root: Path) -> Path:
    """
    Copy risk-map/yaml and risk-map/schemas into tmp_path, set the copied
    emission block to `mode: decoupled`, and return the copied
    mermaid-styles.yaml path.

    The real corpus draws both channel ports and PEP wrappers, so every S6
    port-style clause is live against it. The mode is set here rather than
    read from the shipped file, so these tests exercise config-mode decoupled
    rendering whichever mode the repository ships. Schemas are copied so the
    category style check reads its enum instead of adding an unrelated line.
    """
    shutil.copytree(repo_root / "risk-map" / "yaml", tmp_path / "risk-map" / "yaml")
    shutil.copytree(repo_root / "risk-map" / "schemas", tmp_path / "risk-map" / "schemas")
    styles_path = tmp_path / "risk-map" / "yaml" / "mermaid-styles.yaml"
    with open(styles_path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    doc["graphTypes"]["component"]["emission"]["mode"] = "decoupled"
    styles_path.write_text(yaml.dump(doc), encoding="utf-8")
    return styles_path


def _rewrite_port_styles(styles_path: Path, mutate) -> None:
    """Load the copied mermaid-styles.yaml, apply `mutate(port_styles)`, write it back."""
    with open(styles_path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    mutate(doc["graphTypes"]["component"]["emission"]["portStyles"])
    styles_path.write_text(yaml.dump(doc), encoding="utf-8")


def _run_to_graph(tmp_path: Path, monkeypatch, capsys, *extra_args: str) -> tuple[str, int]:
    """Run main() with --force --to-graph <tmp>/out.md from tmp_path; return (combined output, exit code)."""
    monkeypatch.chdir(tmp_path)
    argv = ["script.py", "--force", "--to-graph", str(tmp_path / "out.md"), *extra_args]
    with patch("sys.argv", argv):
        with pytest.raises(SystemExit) as exc_info:
            main()
    captured = capsys.readouterr()
    return captured.out + captured.err, exc_info.value.code


def _assert_names_only_this_port_style_key(combined: str, key: str) -> None:
    """
    The message names the offending key as `portStyles.<key>` and no other key
    in that form.

    The dotted form is the message contract: a bare `port` is a substring of
    `portStyles` and of `pepport`, so it cannot fail, and a message that lists
    every key would satisfy a bare check for each of them. `portStyles.port`
    is not a substring of `portStyles.pepport`, so both directions are
    falsifiable.
    """
    assert f"portStyles.{key}" in combined, (
        f"Expected the missing port style named as 'portStyles.{key}' in the error:\n{combined}"
    )
    for other in _DECOUPLED_REQUIRED_PORT_STYLE_KEYS:
        if other != key:
            assert f"portStyles.{other}" not in combined, (
                f"Only the missing key may be named; 'portStyles.{other}' is present but configured:\n{combined}"
            )


def _assert_named_port_style_error(combined: str, exit_code: int, key: str) -> None:
    """Named usage error: exit 2, no crash banner, no internal label; names only the key, config path and file."""
    assert exit_code == 2, f"Expected exit 2 (named usage error); got {exit_code}\n{combined}"
    for marker in _CRASH_BANNER_MARKERS:
        assert marker not in combined, (
            f"A missing port style is a config error, not a defect ({marker!r}):\n{combined}"
        )
    assert "S6" not in combined, f"The internal self-check label must not leak into the usage error:\n{combined}"
    _assert_names_only_this_port_style_key(combined, key)
    assert "mermaid-styles.yaml" in combined, f"Expected the config file named in the error:\n{combined}"
    assert _CONFIG_PORT_STYLES_PATH in combined, (
        f"Expected the config path {_CONFIG_PORT_STYLES_PATH!r} named in the error:\n{combined}"
    )


@pytest.fixture
def _fresh_mermaid_styles_singleton(monkeypatch):
    """
    Give each in-process config-mode run its own `MermaidConfigLoader` singleton.

    Without `--emission-mode`, ComponentGraph falls back to
    `MermaidConfigLoader.get_instance()`, a per-path singleton keyed by the
    relative `risk-map/yaml/mermaid-styles.yaml`. Across in-process runs that
    chdir into different tmp copies, the first copy's config would otherwise be
    served to every later run. The override tests are immune because
    `_EmissionModeOverrideConfigLoader` is constructed fresh each time.
    """
    monkeypatch.setattr(MermaidConfigLoader, "_instances", {})


def _assert_crash_shaped_with(combined: str, exit_code: int, exception_text: str) -> None:
    """Crash banner: exit 2, both banner markers, the underlying exception text visible, no usage-error wording."""
    assert exit_code == 2, f"Expected exit 2 (crash banner); got {exit_code}\n{combined}"
    for marker in _CRASH_BANNER_MARKERS:
        assert marker in combined, f"Expected the crash banner ({marker!r}) for an emitter defect:\n{combined}"
    assert exception_text in combined, f"Expected the underlying exception text {exception_text!r}:\n{combined}"
    assert "requires a populated" not in combined, (
        f"An emitter defect must not be reported as a missing-config usage error:\n{combined}"
    )
    assert _CONFIG_PORT_STYLES_PATH not in combined, (
        f"An emitter defect must not be reported as a config error at {_CONFIG_PORT_STYLES_PATH}:\n{combined}"
    )


@pytest.mark.usefixtures("_fresh_mermaid_styles_singleton")
class TestDecoupledConfigMissingPortStyleIsANamedError:
    """
    `validate_riskmap.py --force --to-graph` against a committed
    `mode: decoupled` config whose `portStyles` lacks `port`, `pepport` or
    `pepWrapOutline` -- deleted or set to the empty string -- exits 2 with a
    named config error that points at `graphTypes.component.emission.portStyles`
    in `mermaid-styles.yaml` and names the missing key, without the crash
    banner and without the internal "S6" label. The mode comes from the
    config, not from `--emission-mode`.

    The override path is pinned separately by
    `TestEmissionModeOverrideWithoutEmissionBlock`; here it is exercised only
    to pin that `pepWrapOutline` is a recognised case on that path too.
    """

    @pytest.mark.parametrize("key", _DECOUPLED_REQUIRED_PORT_STYLE_KEYS)
    def test_config_mode_with_a_deleted_port_style_key_gives_the_named_config_error(
        self, tmp_path, repo_root, monkeypatch, capsys, key
    ):
        """
        Given: a copy of the real corpus whose mermaid-styles.yaml keeps
               mode: decoupled but has `key` deleted from portStyles
        When: main() runs --force --to-graph out.md (no --emission-mode)
        Then: exit 2, no crash banner, no "S6", and the output names `key`,
              graphTypes.component.emission.portStyles and mermaid-styles.yaml
        """
        styles_path = _copy_real_corpus(tmp_path, repo_root)
        _rewrite_port_styles(styles_path, lambda port_styles: port_styles.pop(key))

        combined, exit_code = _run_to_graph(tmp_path, monkeypatch, capsys)
        _assert_named_port_style_error(combined, exit_code, key)

    @pytest.mark.parametrize("key", _DECOUPLED_REQUIRED_PORT_STYLE_KEYS)
    def test_config_mode_with_an_empty_port_style_gives_the_named_config_error(
        self, tmp_path, repo_root, monkeypatch, capsys, key
    ):
        """
        Given: the same copy, with `key` present but set to ''
        When: main() runs --force --to-graph out.md
        Then: the same named config error naming `key`

        An empty style string emits no classDef/style line, so the renderer
        treats it exactly like an absent key; the usage error must too.
        """
        styles_path = _copy_real_corpus(tmp_path, repo_root)
        _rewrite_port_styles(styles_path, lambda port_styles: port_styles.__setitem__(key, ""))

        combined, exit_code = _run_to_graph(tmp_path, monkeypatch, capsys)
        _assert_named_port_style_error(combined, exit_code, key)

    def test_override_mode_with_a_deleted_pep_wrap_outline_gives_a_named_error(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Given: the same copy with `pepWrapOutline` deleted, and the mode
               supplied by --emission-mode decoupled
        When: main() runs --force --to-graph out.md --emission-mode decoupled
        Then: exit 2, no crash banner, no "S6", and `pepWrapOutline` is named

        Pins pepWrapOutline as a recognised missing-port-style case on the
        override path as well; the override's existing no-emission-block
        wording is pinned elsewhere and is not constrained here.
        """
        styles_path = _copy_real_corpus(tmp_path, repo_root)
        _rewrite_port_styles(styles_path, lambda port_styles: port_styles.pop("pepWrapOutline"))

        combined, exit_code = _run_to_graph(tmp_path, monkeypatch, capsys, "--emission-mode", "decoupled")
        assert exit_code == 2, f"Expected exit 2 (named usage error); got {exit_code}\n{combined}"
        for marker in _CRASH_BANNER_MARKERS:
            assert marker not in combined, f"A missing pepWrapOutline is a config gap, not a defect:\n{combined}"
        assert "S6" not in combined, f"The internal self-check label must not leak:\n{combined}"
        _assert_names_only_this_port_style_key(combined, "pepWrapOutline")

    @pytest.mark.parametrize("key", _DECOUPLED_REQUIRED_PORT_STYLE_KEYS)
    def test_config_mode_named_error_survives_the_hooks_quiet_mermaid_format_invocation(
        self, tmp_path, repo_root, monkeypatch, capsys, key
    ):
        """
        Given: the copy with `key` deleted from portStyles, and the argument
               shape the graph-regeneration hook uses
               (`scripts/hooks/precommit/regenerate_graphs.py`:
               `--force --to-graph <out> -m --quiet`)
        When: main() runs with exactly those flags
        Then: the same named config error -- exit 2, no crash banner, key,
              config path and file all printed despite --quiet

        The hook is the only production caller and it inherits stdout, so a
        usage error that --quiet suppressed would leave the contributor with a
        bare exit code.
        """
        styles_path = _copy_real_corpus(tmp_path, repo_root)
        _rewrite_port_styles(styles_path, lambda port_styles: port_styles.pop(key))

        combined, exit_code = _run_to_graph(tmp_path, monkeypatch, capsys, "-m", "--quiet")
        _assert_named_port_style_error(combined, exit_code, key)


def _drop_emitted_lines(monkeypatch, method_name: str, marker: str) -> None:
    """
    Wrap `ComponentGraph.<method_name>` so lines containing `marker` are
    dropped from its output -- an emitter defect where a configured style
    never reaches the text. The config itself is left intact.
    """
    original = getattr(component_graph.ComponentGraph, method_name)

    def _dropping(self, *args, **kwargs):
        return [line for line in original(self, *args, **kwargs) if marker not in line]

    monkeypatch.setattr(component_graph.ComponentGraph, method_name, _dropping)


@pytest.mark.usefixtures("_fresh_mermaid_styles_singleton")
class TestDecoupledConfiguredButUnemittedPortStyleStaysCrashShaped:
    """
    When the port style IS configured but the emitter fails to write its
    line, S6 raises the same message as for an unconfigured style, and the
    run must surface the crash banner with the S6 text visible -- in config
    mode and on the override path alike. The named usage error is reserved
    for a config that lacks the style; it must be decided from the resolved
    config, not from the S6 message. A non-port S6 clause (a missing
    category style line) is crash-shaped in config mode as well, matching
    the override-path pin in `TestEmissionModeOverrideGenuineDefectNotMislabeled`.
    """

    @pytest.mark.parametrize(
        ("method_name", "marker", "s6_text"),
        [
            ("_decoupled_classdefs", "classDef port ", "missing 'classDef port'"),
            ("_decoupled_classdefs", "classDef pepport ", "missing 'classDef pepport'"),
            ("_decoupled_styles", "_wrap ", "missing pepWrapOutline style line"),
        ],
        ids=["port-line-dropped", "pepport-line-dropped", "pepWrapOutline-line-dropped"],
    )
    def test_config_mode_dropped_style_line_with_style_configured_is_crash_shaped(
        self, tmp_path, repo_root, monkeypatch, capsys, method_name, marker, s6_text
    ):
        """
        Given: an unmodified copy of the real corpus (every port style
               configured) and the emitter patched to drop the configured
               style's line from its output
        When: main() runs --force --to-graph out.md (mode from the config)
        Then: exit 2 with the crash banner and the S6 text visible; no
              named config error, no pointer at portStyles
        """
        _copy_real_corpus(tmp_path, repo_root)
        _drop_emitted_lines(monkeypatch, method_name, marker)

        combined, exit_code = _run_to_graph(tmp_path, monkeypatch, capsys)
        _assert_crash_shaped_with(combined, exit_code, s6_text)

    def test_override_mode_dropped_port_line_with_style_configured_is_crash_shaped(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Given: the same unmodified copy and the emitter patched to drop the
               `classDef port` line, with --emission-mode decoupled supplied
        When: main() runs --force --to-graph out.md --emission-mode decoupled
        Then: exit 2 with the crash banner and the S6 text visible; not the
              "requires a populated ... emission block" usage error

        The override's usage error is for a config that cannot supply the
        style; a configured style that the emitter loses is a defect, on this
        path too.
        """
        _copy_real_corpus(tmp_path, repo_root)
        _drop_emitted_lines(monkeypatch, "_decoupled_classdefs", "classDef port ")

        combined, exit_code = _run_to_graph(tmp_path, monkeypatch, capsys, "--emission-mode", "decoupled")
        _assert_crash_shaped_with(combined, exit_code, "missing 'classDef port'")

    def test_config_mode_non_port_s6_failure_is_crash_shaped(self, tmp_path, repo_root, monkeypatch, capsys):
        """
        Given: an unmodified copy of the real corpus and verify_plan patched
               to raise S6's missing-category-style-line variant
        When: main() runs --force --to-graph out.md (mode from the config)
        Then: exit 2 with the crash banner and that S6 text visible; no named
              config error
        """
        _copy_real_corpus(tmp_path, repo_root)

        def _raise(*_args, **_kwargs):
            raise AssertionError("S6 violated: missing category style line 'style componentData fill:#eee'")

        monkeypatch.setattr(component_graph, "verify_plan", _raise)

        combined, exit_code = _run_to_graph(tmp_path, monkeypatch, capsys)
        _assert_crash_shaped_with(combined, exit_code, "S6 violated: missing category style line")
