#!/usr/bin/env python3
"""
Tests for scripts/hooks/precommit/regenerate_issue_templates.py

The wrapper is invoked by the pre-commit framework with `pass_filenames:
false` after the framework's `files:` regex matches any of:

  - scripts/TEMPLATES/<anything>.yml
  - risk-map/schemas/<anything>.schema.json
  - risk-map/yaml/frameworks.yaml

When invoked, the wrapper unconditionally runs
`uv run --locked --no-sync python scripts/generate_issue_templates.py` and git-adds the
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
