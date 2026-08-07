#!/usr/bin/env python3
"""
Tests for validate_riskmap.py

This test suite validates the main entry point for component edge validation
and graph generation. The script orchestrates ComponentEdgeValidator and provides
graph generation capabilities for component, control, and risk visualizations.

Test Coverage:
==============
Total Tests: 115 across 9 test classes.

Line-number annotations against validate_riskmap.py have been dropped from
this list: they were stale by hundreds of lines and nothing kept them
honest. The previously recorded "Coverage Target: 98%+ (achieved)" claim was
also stale — it does not match a measured run — so it has been dropped
rather than replaced with another number that nothing enforces. Measure with
`pytest --cov=validate_riskmap scripts/hooks/tests/test_validate_riskmap.py`.

1. TestParseArgs - CLI argument parsing - 14 tests
   - Default arguments
   - --force/-f flag (long and short form)
   - --file PATH argument — argparse parsing only; the flag's effect on
     main() is covered by TestMainFileFlag, not here
   - --allow-isolated flag
   - --quiet/-q flag (long and short form)
   - --to-graph PATH argument
   - --to-controls-graph PATH argument
   - --to-risk-graph PATH argument
   - --debug flag
   - --mermaid-format/-m flag (long and short form)
   - Combined argument parsing

2. TestFileFlagHelpText - `--file` documents where it is not valid - 3 tests
   - --file's own help names every combination it is rejected in
   - `--help` exits 0 and carries the constraints with its epilog intact
   - the module docstring's --file entry has not drifted from --help

3. TestMainValidation - Validation orchestration - 10 tests
   - Validation success with force mode
   - Validation failure detection
   - No YAML files to validate
   - Quiet mode output suppression
   - Multiple file validation with spacing
   - ComponentEdgeValidator integration with flags
   - Validator initialization with correct options
   - components.yaml is validated on a controls-only commit, and the staged
     set is requested with target_file None (regression fence; green today)
   - the corpus is parsed exactly once per run, and opened exactly twice
     (the second read is a tracked deferral; see the test's docstring)

4. TestMainFileFlag - `--file PATH` end-to-end wiring - 35 tests
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
   - --force --file is rejected as contradictory, as are --file with
     --to-controls-graph and --to-risk-graph; --to-graph stays allowed and
     draws the --file corpus
   - Only the checks that read other repo files (lifecycle order, controls
     mirror) skip under --file; category/subcategory nesting is
     self-contained in the corpus under test, runs, and promotes under
     --block
   - --file naming the default corpus runs every check, relative or
     absolute spelling — it must not be a weaker run than --force
   - Every unparseable corpus shape fails the same way; a failure in
     either the parse or the checking phase still reaches the crash banner
   - The corpus a run announces is the corpus it validated

5. TestParseCorpus - the parse step, directly - 13 tests
   - a well-formed corpus parses; every malformed shape, a missing file
     included, raises CorpusParseError with the original failure chained
   - defect-shaped exceptions raised during the parse propagate unchanged
     rather than being relabelled as bad input
   - validate_loaded stores the corpus it was handed, every call
   - reached directly because every main() test that mocks
     ComponentEdgeValidator makes the parse unreachable

6. TestMainGraphGeneration - Graph output - 12 tests
   - Component graph generation
   - Controls graph generation
   - Risk graph generation
   - Mermaid format output for component graph
   - Mermaid format output for controls graph
   - Mermaid format output for risk graph
   - Component graph error handling
   - Controls graph error handling
   - Risk graph error handling
   - Debug flag passed to ComponentGraph
   - Debug flag passed to ControlGraph
   - Debug flag passed to RiskGraph

7. TestMainErrorHandling - Exception handling - 3 tests
   - KeyboardInterrupt handling (exit code 2)
   - Unexpected exceptions (exit code 2)
   - Validator initialization errors (exit code 2)

8. TestMainLifecycleMode - `--mode lifecycle` short-circuit hook - 8 tests
   - Pins the dedicated lifecycle-only entrypoint introduced to fix PR #277
     reviewer feedback (item 2): the lifecycle uniqueness check must be
     reachable on lifecycle-only commits without going through the
     components-validation pipeline.
   - Architectural intent: lifecycle mode bypasses get_staged_yaml_files,
     ComponentEdgeValidator, and graph generation entirely.
   - --mode lifecycle combined with --file is rejected rather than
     silently discarding --file; the docstring records what that test
     does not decide.

9. TestProductionInvocations - characterization of the shipped command
   forms - 17 tests. Green today by design; they lock what CI and
   pre-commit observe so the --file work cannot change it silently.
   - --block on the real corpus for each staged trigger file, including the
     validator options and the file-selection call
   - --block promotion, exercised with each warn-only check dirty alone
   - --mode lifecycle
   - --force, including outside a git repository, from a copy at the tree
     root as CI runs it, and with an isolated component present
   - --force --to-*-graph to an extensionless path, byte-compared with the
     committed diagrams
   - the regenerate-graphs hook form (graph flag, -m, --quiet, no --force),
     including its empty-selection no-op
   Tests that read the live corpus carry the live_corpus marker.
"""

import builtins
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
from riskmap_validator.config import DEFAULT_COMPONENTS_FILE
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
        assert args.to_controls_graph is None
        assert args.to_risk_graph is None
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

    def test_parse_args_with_to_controls_graph_path(self):
        """
        Test --to-controls-graph argument sets output path.

        Given: Script called with --to-controls-graph controls.md
        When: parse_args() is called
        Then: Returns namespace with to_controls_graph=Path("controls.md")
        """
        with patch("sys.argv", ["script.py", "--to-controls-graph", "controls.md"]):
            args = parse_args()

        assert args.to_controls_graph == Path("controls.md")

    def test_parse_args_with_to_risk_graph_path(self):
        """
        Test --to-risk-graph argument sets output path.

        Given: Script called with --to-risk-graph risk.md
        When: parse_args() is called
        Then: Returns namespace with to_risk_graph=Path("risk.md")
        """
        with patch("sys.argv", ["script.py", "--to-risk-graph", "risk.md"]):
            args = parse_args()

        assert args.to_risk_graph == Path("risk.md")

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
    which breaks on hyphens by default, so "--to-risk-graph" can arrive as
    "--to-" + "risk-graph" and a plain space-join would silently turn every
    long flag name into an unfindable "--to- risk-graph".

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
_FILE_REJECTED_WITH = ("--force", "lifecycle", "--to-controls-graph", "--to-risk-graph")


class TestFileFlagHelpText:
    """Tests that --file documents the combinations it rejects."""

    def test_file_option_help_names_the_combinations_it_is_not_valid_with(self, capsys):
        """
        Test that --file's own help names every combination it is rejected in.

        Given: The script's rendered `--help`
        When:  The --file option's help block is read
        Then:  It mentions --force, lifecycle mode, --to-controls-graph and
               --to-risk-graph

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

        Counts parse calls, not file reads. The corpus is opened twice per
        run, and test_main_opens_the_corpus_exactly_twice_per_run holds that
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

    def test_main_opens_the_corpus_exactly_twice_per_run(self, tmp_path, monkeypatch):
        """
        Test that the corpus file is read exactly twice, and pin the deferral.

        Given: A tmp cwd holding a clean components corpus
        When:  main() is called with --force
        Then:  components.yaml is opened exactly twice

        Two is not the number we want. It is the number we have, recorded so
        that changing it in either direction is deliberate.

        The two reads are: parse_components_yaml, reached through
        ComponentEdgeValidator.parse_corpus, which returns ComponentNode
        objects; and the category/subcategory nesting check's own
        yaml.safe_load, which needs the raw `categories:` block that
        parse_components_yaml does not return. The second read exists only
        because that block is unreachable from the first one's result.

        Closing it means changing utils.parse_components_yaml to expose the
        parsed document alongside the components — a contract change to a
        function with callers beyond this script, deliberately out of scope
        for this branch. It is deferred to the control/risk graph
        deprecation work (#477), which is the change that already opens
        utils.py, since it removes parse_risks_yaml, and whose stated goal is
        simplifying what is left.

        This test is the tripwire on that deferral. A fix that gets the run
        down to one read will fail here, and that failure is the point:
        whoever makes it has to read this note, update the count, and close
        the issue. A change that adds a third read fails it too. The count is
        exact for that reason — a maximum would let the first case pass
        silently and lose the deferral.

        Counts file opens, not parse calls;
        test_main_parses_the_corpus_exactly_once_per_run holds the parse
        count, which is one. The two numbers differ precisely because of the
        nesting check's re-read.
        """
        _write_repo_layout_corpus(tmp_path, _CLEAN_LOCAL_COMPONENTS, _CLEAN_LOCAL_CONTROLS)
        monkeypatch.chdir(tmp_path)

        opened: list[str] = []
        real_open = builtins.open

        def counting_open(file, *args, **kwargs):
            opened.append(str(file))
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", counting_open)

        with patch("sys.argv", ["script.py", "--force"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0
        corpus_opens = [path for path in opened if Path(path) == DEFAULT_COMPONENTS_FILE]
        assert len(corpus_opens) == 2, (
            f"The corpus is opened {len(corpus_opens)} time(s) per run; this test records the "
            f"two reads described in its docstring. If a change removed the nesting check's "
            f"re-read, update the count here and close the deferral it names. All files opened: "
            f"{opened!r}"
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

    @pytest.mark.parametrize(
        "graph_flag", ["--to-controls-graph", "--to-risk-graph"], ids=["controls-graph", "risk-graph"]
    )
    def test_main_with_file_flag_and_control_derived_graph_is_rejected(
        self, graph_flag, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that --file is rejected with the graphs it cannot supply data for.

        Given: The repo root as cwd and a small --file corpus
        When:  main() is called with --file <corpus> and --to-controls-graph
               or --to-risk-graph
        Then:  Exits 2, names --file and the graph flag, writes no output
               file, and does not print the unexpected-exception banner

        Both graphs join controls (and risks) to components, and
        parse_controls_yaml() and parse_risks_yaml() take no argument: they
        read the repo's own controls.yaml and risks.yaml regardless of
        --file. Every control whose components are not in the --file corpus
        silently loses its edges. Measured against the committed
        controls-graph, a two-component --file corpus drops all 69
        control→component edges while still rendering every control, every
        subgraph and all styling, exiting 0 with "saved to" — a finished
        looking diagram of a system with almost no controls.

        Newly reachable: before --file was wired, this invocation validated
        nothing and produced no graph. Rejecting it is the same mechanism and
        placement as the --force and lifecycle rejections. --to-graph alone
        stays allowed, since that graph is genuinely derived from the --file
        corpus — test_main_with_file_flag_and_to_graph_is_allowed pins it.
        """
        corpus = _write_custom_components(tmp_path, _CLEAN_LOCAL_COMPONENTS)
        output = tmp_path / "graph-output.md"
        monkeypatch.chdir(repo_root)

        with patch("sys.argv", ["script.py", "--file", str(corpus), graph_flag, str(output)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"Expected exit 2 for --file combined with {graph_flag}; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert "--file" in combined and graph_flag in combined, (
            f"Expected both flag names in the rejection message; got: {combined!r}"
        )
        assert not output.exists(), f"A rejected invocation must not leave a graph behind; found {output}"
        _assert_not_crash_shaped(combined)

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

    def test_main_with_file_naming_the_default_corpus_is_still_rejected_with_control_graphs(
        self, tmp_path, repo_root, monkeypatch, capsys
    ):
        """
        Test that the control-graph rejection does not exempt the default corpus.

        Given: The repo root as cwd
        When:  main() is called with --file risk-map/yaml/components.yaml and
               --to-controls-graph
        Then:  Exits 2 and writes no graph

        Two path-sensitive rules meet here and answer differently on purpose.
        The skip predicate compares resolved paths, so naming the default
        corpus is not treated as a custom one and every check still runs. The
        graph rejection does not: it fires on the presence of --file, whatever
        it names.

        That is deliberate and fail-closed. Making the rejection
        path-sensitive too would mean `--file <default> --to-controls-graph`
        quietly becoming a supported way to spell an invocation that has an
        unambiguous existing spelling (`--force --to-controls-graph`), and the
        rule a reader has to hold would grow a special case for no gain.
        Pinned so the next reader can tell the difference from an oversight.
        """
        monkeypatch.chdir(repo_root)
        output = tmp_path / "controls-graph.md"

        with patch(
            "sys.argv",
            ["script.py", "--file", str(DEFAULT_COMPONENTS_FILE), "--to-controls-graph", str(output)],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert exc_info.value.code == 2, (
            f"--file is rejected with --to-controls-graph whatever it names; "
            f"got {exc_info.value.code}. Output: {combined!r}"
        )
        assert not output.exists(), f"A rejected invocation must not leave a graph behind; found {output}"


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

    def test_main_generates_controls_graph_when_to_controls_graph_specified(self, capsys):
        """
        Test that controls graph is generated when --to-controls-graph is provided.

        Given: Valid validation and --to-controls-graph controls.md specified
        When: main() is called
        Then: ControlGraph is created and written to output file
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("controls.md")
        mock_controls = [Mock()]
        mock_graph_output = "```mermaid\ngraph TD\nCTL-->COMP\n```"

        with patch("sys.argv", ["script.py", "--force", "--to-controls-graph", str(graph_path)]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.parse_controls_yaml", return_value=mock_controls):
                        with patch("validate_riskmap.ControlGraph") as mock_graph_class:
                            with patch("builtins.open", mock_open()) as mock_file:
                                # Setup validator mock
                                mock_validator = Mock()
                                mock_validator.validate_file.return_value = True
                                mock_validator.forward_map = {}
                                mock_validator.components = {"COMP": Mock()}
                                mock_validator_class.return_value = mock_validator

                                # Setup graph mock
                                mock_graph = Mock()
                                mock_graph.to_mermaid.return_value = mock_graph_output
                                mock_graph_class.return_value = mock_graph

                                with pytest.raises(SystemExit) as exc_info:
                                    main()

        assert exc_info.value.code == 0

        # Verify controls were parsed

        # Verify graph was created
        mock_graph_class.assert_called_once_with(mock_controls, mock_validator.components, debug=False)

        # Verify file was written
        mock_file.assert_called_with(graph_path, "w", encoding="utf-8")

        # Verify success message
        captured = capsys.readouterr()
        assert f"Controls graph visualization saved to {graph_path}" in captured.out

    def test_main_generates_risk_graph_when_to_risk_graph_specified(self, capsys):
        """
        Test that risk graph is generated when --to-risk-graph is provided.

        Given: Valid validation and --to-risk-graph risk.md specified
        When: main() is called
        Then: RiskGraph is created and written to output file
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("risk.md")
        mock_risks = [Mock()]
        mock_controls = [Mock()]
        mock_graph_output = "```mermaid\ngraph TD\nRSK-->CTL-->COMP\n```"

        with patch("sys.argv", ["script.py", "--force", "--to-risk-graph", str(graph_path)]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.parse_risks_yaml", return_value=mock_risks):
                        with patch("validate_riskmap.parse_controls_yaml", return_value=mock_controls):
                            with patch("validate_riskmap.RiskGraph") as mock_graph_class:
                                with patch("builtins.open", mock_open()) as mock_file:
                                    # Setup validator mock
                                    mock_validator = Mock()
                                    mock_validator.validate_file.return_value = True
                                    mock_validator.forward_map = {}
                                    mock_validator.components = {"COMP": Mock()}
                                    mock_validator_class.return_value = mock_validator

                                    # Setup graph mock
                                    mock_graph = Mock()
                                    mock_graph.to_mermaid.return_value = mock_graph_output
                                    mock_graph_class.return_value = mock_graph

                                    with pytest.raises(SystemExit) as exc_info:
                                        main()

        assert exc_info.value.code == 0

        # Verify graph was created with all three data sources
        mock_graph_class.assert_called_once_with(mock_risks, mock_controls, mock_validator.components, debug=False)

        # Verify file was written
        mock_file.assert_called_with(graph_path, "w", encoding="utf-8")

        # Verify success message
        captured = capsys.readouterr()
        assert f"Risk graph visualization saved to {graph_path}" in captured.out

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

    def test_main_generates_controls_graph_with_mermaid_format(self, capsys):
        """
        Test that controls graph generates both .md and .mermaid files when flag is set.

        Given: Valid validation, --to-controls-graph and --mermaid-format flags
        When: main() is called
        Then: Both .md and .mermaid files are written for controls graph
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("controls.md")
        mermaid_path = Path("controls.mermaid")
        mock_controls = [Mock()]
        mock_md_output = "```mermaid\ngraph TD\nCTL-->COMP\n```"
        mock_mermaid_output = "graph TD\nCTL-->COMP"

        with patch(
            "sys.argv", ["script.py", "--force", "--to-controls-graph", str(graph_path), "--mermaid-format"]
        ):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.parse_controls_yaml", return_value=mock_controls):
                        with patch("validate_riskmap.ControlGraph") as mock_graph_class:
                            with patch("builtins.open", mock_open()) as mock_file:
                                # Setup validator mock
                                mock_validator = Mock()
                                mock_validator.validate_file.return_value = True
                                mock_validator.forward_map = {}
                                mock_validator.components = {}
                                mock_validator_class.return_value = mock_validator

                                # Setup graph mock
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
        assert f"Controls graph visualization saved to {graph_path}" in captured.out
        assert f"Mermaid format saved to {mermaid_path}" in captured.out

    def test_main_generates_risk_graph_with_mermaid_format(self, capsys):
        """
        Test that risk graph generates both .md and .mermaid files when flag is set.

        Given: Valid validation, --to-risk-graph and --mermaid-format flags
        When: main() is called
        Then: Both .md and .mermaid files are written for risk graph
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("risk.md")
        mermaid_path = Path("risk.mermaid")
        mock_risks = [Mock()]
        mock_controls = [Mock()]
        mock_md_output = "```mermaid\ngraph TD\nRSK-->CTL-->COMP\n```"
        mock_mermaid_output = "graph TD\nRSK-->CTL-->COMP"

        with patch("sys.argv", ["script.py", "--force", "--to-risk-graph", str(graph_path), "--mermaid-format"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.parse_risks_yaml", return_value=mock_risks):
                        with patch("validate_riskmap.parse_controls_yaml", return_value=mock_controls):
                            with patch("validate_riskmap.RiskGraph") as mock_graph_class:
                                with patch("builtins.open", mock_open()) as mock_file:
                                    # Setup validator mock
                                    mock_validator = Mock()
                                    mock_validator.validate_file.return_value = True
                                    mock_validator.forward_map = {}
                                    mock_validator.components = {}
                                    mock_validator_class.return_value = mock_validator

                                    # Setup graph mock
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
        assert f"Risk graph visualization saved to {graph_path}" in captured.out
        assert f"Mermaid format saved to {mermaid_path}" in captured.out

    def test_main_handles_controls_graph_generation_errors(self, capsys):
        """
        Test that controls graph generation errors are caught and reported.

        Given: Controls graph to_mermaid() raises an exception
        When: main() is called
        Then: Error is caught, warning printed, and script exits 0
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("controls.md")

        with patch("sys.argv", ["script.py", "--force", "--to-controls-graph", str(graph_path)]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.parse_controls_yaml", return_value=[Mock()]):
                        with patch("validate_riskmap.ControlGraph") as mock_graph_class:
                            # Setup validator mock
                            mock_validator = Mock()
                            mock_validator.validate_file.return_value = True
                            mock_validator.forward_map = {}
                            mock_validator.components = {}
                            mock_validator_class.return_value = mock_validator

                            # Setup graph to raise exception
                            mock_graph = Mock()
                            mock_graph.to_mermaid.side_effect = RuntimeError("Controls graph failed")
                            mock_graph_class.return_value = mock_graph

                            with pytest.raises(SystemExit) as exc_info:
                                main()

        assert exc_info.value.code == 0

        # Verify error message
        captured = capsys.readouterr()
        assert "Failed to generate controls graph:" in captured.out
        assert "Controls graph failed" in captured.out

    def test_main_handles_risk_graph_generation_errors(self, capsys):
        """
        Test that risk graph generation errors are caught and reported.

        Given: Risk graph to_mermaid() raises an exception
        When: main() is called
        Then: Error is caught, warning printed, and script exits 0
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("risk.md")

        with patch("sys.argv", ["script.py", "--force", "--to-risk-graph", str(graph_path)]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.parse_risks_yaml", return_value=[Mock()]):
                        with patch("validate_riskmap.parse_controls_yaml", return_value=[Mock()]):
                            with patch("validate_riskmap.RiskGraph") as mock_graph_class:
                                # Setup validator mock
                                mock_validator = Mock()
                                mock_validator.validate_file.return_value = True
                                mock_validator.forward_map = {}
                                mock_validator.components = {}
                                mock_validator_class.return_value = mock_validator

                                # Setup graph to raise exception
                                mock_graph = Mock()
                                mock_graph.to_mermaid.side_effect = RuntimeError("Risk graph failed")
                                mock_graph_class.return_value = mock_graph

                                with pytest.raises(SystemExit) as exc_info:
                                    main()

        assert exc_info.value.code == 0

        # Verify error message
        captured = capsys.readouterr()
        assert "Failed to generate risk graph:" in captured.out
        assert "Risk graph failed" in captured.out

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

    def test_main_passes_debug_flag_to_control_graph(self):
        """
        Test that debug flag is passed to ControlGraph constructor.

        Given: Script called with --debug and --to-controls-graph flags
        When: main() is called
        Then: ControlGraph is initialized with debug=True
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("controls.md")
        mock_controls = [Mock()]

        with patch("sys.argv", ["script.py", "--force", "--to-controls-graph", str(graph_path), "--debug"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.parse_controls_yaml", return_value=mock_controls):
                        with patch("validate_riskmap.ControlGraph") as mock_graph_class:
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
        mock_graph_class.assert_called_once_with(mock_controls, mock_validator.components, debug=True)

    def test_main_passes_debug_flag_to_risk_graph(self):
        """
        Test that debug flag is passed to RiskGraph constructor.

        Given: Script called with --debug and --to-risk-graph flags
        When: main() is called
        Then: RiskGraph is initialized with debug=True
        """
        file_paths = [Path("risk-map/yaml/components.yaml")]
        graph_path = Path("risk.md")
        mock_risks = [Mock()]
        mock_controls = [Mock()]

        with patch("sys.argv", ["script.py", "--force", "--to-risk-graph", str(graph_path), "--debug"]):
            with patch("validate_riskmap.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_riskmap.ComponentEdgeValidator") as mock_validator_class:
                    with patch("validate_riskmap.parse_risks_yaml", return_value=mock_risks):
                        with patch("validate_riskmap.parse_controls_yaml", return_value=mock_controls):
                            with patch("validate_riskmap.RiskGraph") as mock_graph_class:
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
        mock_graph_class.assert_called_once_with(mock_risks, mock_controls, mock_validator.components, debug=True)


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
#   3. Skip graph generation (no ComponentGraph / ControlGraph / RiskGraph).
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
#   .pre-commit-config.yaml:403-409        regenerate_graphs.py, which runs
#                                            validate_riskmap.py --to-graph|
#                                            --to-controls-graph|--to-risk-graph
#                                            <tracked path> -m --quiet
#                                            (regenerate_graphs.py:62, 73, 84)
#   .github/workflows/validation.yml:195   validate_riskmap.py --force
#   .github/workflows/validation.yml:336   validate_riskmap.py --force \
#                                            --to-graph|--to-controls-graph|--to-risk-graph FILE
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
# hook writes both and git-adds them.
_GRAPH_FORMS = [
    (
        "--to-graph",
        "Graph visualization saved to",
        "risk-map/diagrams/risk-map-graph.md",
        "risk-map/diagrams/risk-map-graph.mermaid",
    ),
    (
        "--to-controls-graph",
        "Controls graph visualization saved to",
        "risk-map/diagrams/controls-graph.md",
        "risk-map/diagrams/controls-graph.mermaid",
    ),
    (
        "--to-risk-graph",
        "Risk graph visualization saved to",
        "risk-map/diagrams/controls-to-risk-graph.md",
        "risk-map/diagrams/controls-to-risk-graph.mermaid",
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
        Test the CI graph forms `--force --to-*-graph FILE` (validation.yml:336).

        Given: The repo root as cwd and an extensionless output path, as
               produced by $(mktemp) at validation.yml:309-311
        When:  main() is called with --force and one of the three graph flags
        Then:  Exits 0, validates components.yaml, writes the graph to
               exactly the path given, and that file matches the committed
               diagram byte for byte

        The output path deliberately has no extension. CI passes $(mktemp)
        output, so a normalisation such as `args.to_graph.with_suffix(".md")`
        would write somewhere else and leave CI diffing an empty file — a
        test using "graph.md" cannot see that. Byte equality is CI's real
        contract: it runs `diff -u` against the committed diagram
        (validation.yml:339) and fails the build on any difference.
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
        When:  main() is called as regenerate_graphs.py:62/73/84 calls it —
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
