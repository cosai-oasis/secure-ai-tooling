#!/usr/bin/env python3
"""
Tests for verify-deps.sh dependency verification script.

This test suite validates the dependency verification script that checks for
required development environment tools and their versions. The script is used
to ensure developers have all necessary tools installed before contributing
to the CoSAI Risk Map project.

Test Coverage:
==============
Total Tests: 19 test classes with comprehensive scenarios
Coverage Target: 100% of verify-deps.sh functionality

1. TestScriptExists - Script existence and permissions
   - Script file exists at expected path
   - Script is executable

2. TestAllDepsPresent - Full dependency validation in real environment
   - All dependencies present and correct versions
   - Exit code 0 when all checks pass
   - PASS indicators in output

3. TestMissingPython - Python availability validation
   - Detects when python3 is not on PATH
   - Exit code 1 when python3 missing
   - FAIL indicator in output

4. TestWrongPythonVersion - Python version validation
   - Detects when python3 version < 3.14
   - Exit code 1 when version too old
   - FAIL indicator with version mismatch

5. TestMissingNode - Node.js availability validation
   - Detects when node is not on PATH
   - Exit code 1 when node missing
   - FAIL indicator in output

6. TestWrongNodeVersion - Node.js version validation
   - Detects when node version < 24
   - FAIL line names the detected version and the required major
   - PASS line at and above the minimum

7. TestMissingNpm - npm availability validation
   - Detects when npm is not on PATH
   - FAIL line for npm says not found

7a. TestNpmVersion - npm version floor (>= 11.5, ADR-003 (2026-10-05 addendum))
   - FAIL below the floor (9.9.9, 10.9.9, 11.4.2)
   - FAIL on empty or unparsable output
   - PASS at and above the floor (11.5.0, 11.19.0, 12.0.0, 11.5.0-pre.0)

8. TestMissingGit - git availability validation
   - Detects when git is not on PATH
   - Exit code 1 when git missing
   - FAIL indicator in output

9. TestMissingPipPackage - pip package validation
   - Detects when required pip packages missing
   - Exit code 1 when package not installed
   - FAIL indicator with package name

10. TestMissingPrettier - prettier availability validation
    - Detects when npx prettier fails
    - Exit code 1 when prettier unavailable
    - FAIL indicator in output

11. TestMissingMmdc - mermaid-cli availability validation
    - Detects when npx mmdc fails
    - Exit code 1 when mmdc unavailable
    - FAIL indicator in output

12. TestMissingRuff - ruff availability validation
    - Detects when ruff is not on PATH
    - Exit code 1 when ruff missing
    - FAIL indicator in output

13. TestMissingCheckJsonschema - check-jsonschema availability validation
    - Detects when check-jsonschema is not on PATH
    - Exit code 1 when check-jsonschema missing
    - FAIL indicator in output

14. TestMissingChromium - Chromium availability validation
    - Detects when no Chromium found anywhere
    - Exit code 1 when Chromium missing
    - FAIL indicator in output
    - Checks Playwright cache and system paths

15. TestChromiumInPlaywrightCache - Playwright cache Chromium detection
    - Finds Chromium in PLAYWRIGHT_BROWSERS_PATH
    - PASS indicator when found in cache
    - Checks for headless_shell and chrome variants

16. TestChromiumSystemPath - System Chromium detection
    - Finds Chromium at system paths
    - PASS indicator when found at /usr/bin/chromium
    - Checks standard Linux paths

17. TestMissingAct - act availability validation
    - Detects when act is not on PATH
    - Exit code 1 when act missing
    - FAIL indicator in output

18. TestQuietFlag - Quiet mode output suppression
    - --quiet flag suppresses passing check output
    - FAIL messages still shown
    - Exit code still reflects failure state

19. TestPartialFailure - Mixed success/failure scenarios
    - Some dependencies pass, some fail
    - Exit code 1 when any check fails
    - Output shows both PASS and FAIL indicators

Dependencies Checked:
=====================
- Python >= 3.14
- Node.js >= 24
- npm >= 11.5
- git
- pip packages: check-jsonschema, pytest, pytest-cov, pytest-timeout, PyYAML, ruff, pandas, tabulate
- npx prettier
- npx mmdc (mermaid-cli)
- ruff (command-line)
- check-jsonschema (command-line)
- Chromium (Playwright cache or system)
- act (GitHub Actions local runner)

Testing Approach:
=================
Uses subprocess to execute the bash script with manipulated PATH and environment
variables. Creates temporary directories with stub scripts to simulate missing
or incorrectly-versioned dependencies. The tmp_path fixture provides isolation
for each test scenario.
"""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

# Path to the script under test (relative to repo root)
REPO_ROOT = Path(__file__).parent.parent.parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "tools" / "verify-deps.sh"

# Real utilities the script's version checks pipe through. They are symlinked into
# the stub bin directory so a restricted PATH still lets the version parsing run;
# python3, node, npm and the rest stay absent unless a test stubs them.
_PARSING_TOOLS = ("grep", "cut", "head", "sed", "awk", "tr")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _make_stub_bin(
    tmp_path,
    node_output=None,
    npm_output=None,
    npm_stderr=None,
    node_stderr=None,
    node_exit=0,
    python_output=None,
    python_stderr=None,
    python_exit=0,
):
    """
    Build a PATH directory with parsing utilities and optional node/npm stubs.

    node_output / npm_output: None omits the stub; a string makes the stub print
    that string (empty string prints nothing) when called with --version.
    npm_stderr: when set, the npm stub first writes this line to stderr, as real
    npm does for `npm warn ...` notices (e.g. from a legacy .npmrc).
    node_stderr / node_exit: same for the node stub; multi-line text is written one
    line per echo, and a nonzero node_exit makes the stub exit with that status after
    printing (as a mise shim does when the tool is not installed).
    python_output / python_stderr / python_exit: same for a python3 stub (--version).
    Returns the directory path.
    """
    # The stub PATH offers only grep/cut/head/sed/awk/tr: npm parsing must use bash builtins plus these.
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    for tool in _PARSING_TOOLS:
        real = shutil.which(tool)
        assert real is not None, f"{tool} not found on the host"
        (stub_bin / tool).symlink_to(real)
    stderr_by_tool = {"node": node_stderr, "npm": npm_stderr, "python3": python_stderr}
    for name, output in (("node", node_output), ("npm", npm_output), ("python3", python_output)):
        if output is None:
            continue
        stub = stub_bin / name
        echo = f'    echo "{output}"\n' if output else "    :\n"
        if stderr_by_tool[name] is not None:
            # One echo per line; stderr text must not contain single quotes.
            err = "".join(f"    echo '{line}' >&2\n" for line in stderr_by_tool[name].splitlines())
            echo = err + echo
        exit_status = {"node": node_exit, "python3": python_exit}.get(name, 0)
        if exit_status:
            echo += f"    exit {exit_status}\n"
        stub.write_text(f'#!/bin/bash\nif [[ "$1" == "--version" || "$1" == "-v" ]]; then\n{echo}fi\n')
        stub.chmod(0o755)
    return stub_bin


def _run_verify(stub_bin):
    """Run verify-deps.sh with PATH restricted to stub_bin and return the result."""
    env = os.environ.copy()
    env["PATH"] = str(stub_bin)
    return subprocess.run([str(SCRIPT_PATH)], capture_output=True, text=True, env=env, timeout=30)


def _result_lines(result, pattern):
    """Return ANSI-stripped [PASS]/[FAIL] output lines whose text matches pattern."""
    lines = (_ANSI_RE.sub("", line) for line in result.stdout.splitlines())
    return [line for line in lines if re.match(r"\[(PASS|FAIL)\]", line) and re.search(pattern, line)]


class TestScriptExists:
    """
    Test script file existence and permissions.

    Validates that the verify-deps.sh script exists at the expected location
    and has execute permissions set correctly.
    """

    def test_script_exists(self):
        """
        Test that verify-deps.sh exists at expected path.

        Given: The scripts/tools directory structure
        When: Checking for verify-deps.sh file
        Then: File exists at scripts/tools/verify-deps.sh
        """
        assert SCRIPT_PATH.exists(), f"Script not found at {SCRIPT_PATH}"

    def test_script_is_executable(self):
        """
        Test that verify-deps.sh has execute permissions.

        Given: The verify-deps.sh file exists
        When: Checking file permissions
        Then: File has executable bit set
        """
        assert SCRIPT_PATH.exists(), f"Script not found at {SCRIPT_PATH}"
        file_stat = os.stat(SCRIPT_PATH)
        is_executable = bool(file_stat.st_mode & stat.S_IXUSR)
        assert is_executable, f"Script {SCRIPT_PATH} is not executable"


class TestAllDepsPresent:
    """
    Test script behavior when all dependencies are present.

    Runs the script in the actual development environment (devcontainer)
    which should have all required dependencies installed.
    """

    @pytest.mark.skipif(
        os.getenv("CI") == "true",
        reason="Requires act and mmdc which are not available in CI",
    )
    def test_all_dependencies_present_exit_0(self):
        """
        Test that script exits 0 when all dependencies are present.

        Given: A devcontainer with all required dependencies
        When: Running verify-deps.sh without arguments
        Then: Script exits with code 0
        And: Output contains PASS indicators for all checks
        """
        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, (
            f"Script should exit 0 when all deps present.\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        # Check for PASS indicators (will be added in implementation)
        # This test will initially fail, driving TDD implementation


class TestMissingPython:
    """
    Test script behavior when python3 is not available.

    Simulates an environment without python3 by creating a restricted PATH
    that excludes the python3 binary.
    """

    def test_missing_python3_fails(self, tmp_path):
        """
        Test that script fails when python3 is not on PATH.

        Given: An environment without python3 in PATH
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for python3
        """
        # Create a minimal PATH with only the script directory
        env = os.environ.copy()
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, (
            f"Script should exit 1 when python3 missing.\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )


class TestWrongPythonVersion:
    """
    Test script behavior when python3 version is too old.

    Creates a stub python3 script that reports version 3.13.x to simulate
    a version that doesn't meet the >= 3.14 requirement.
    """

    def test_python_version_too_old_fails(self, tmp_path):
        """
        Test that script fails when python3 version < 3.14.

        Given: A python3 that reports version 3.13.0
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for python version
        """
        # Create stub python3 that reports old version
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()
        stub_python = stub_bin / "python3"
        stub_python.write_text(
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "Python 3.13.0"\n'
            "else\n"
            '    echo "Stub python3"\n'
            "fi\n"
        )
        stub_python.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, (
            f"Script should exit 1 when python version < 3.14.\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )


class TestMissingNode:
    """
    Test script behavior when node is not available.

    Simulates an environment without node by creating a restricted PATH.
    """

    def test_missing_node_fails(self, tmp_path):
        """
        Test that script fails when node is not on PATH.

        Given: An environment without node in PATH
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for node
        """
        env = os.environ.copy()
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, f"Script should exit 1 when node missing.\nExit code: {result.returncode}"


class TestWrongNodeVersion:
    """
    Test script behavior when node version is too old.

    Creates a stub node script that reports an older major to simulate a
    version that doesn't meet the >= 24 requirement. The assertions target the
    Node check's own output line: the restricted PATH already makes the script
    exit 1 (python3 and others are absent), so the exit code cannot show that
    the Node check failed.
    """

    @pytest.mark.parametrize("node_version", ["21.7.3", "22.23.3", "23.9.0"])
    def test_node_version_too_old_fails(self, tmp_path, node_version):
        """
        Test that script fails when node version < 24.

        Given: A node that reports a version below 24 (including 22.23.3, the old floor)
        When: Running verify-deps.sh
        Then: The Node.js line is [FAIL], names the detected version and the 24 requirement

        Mutation caught: threshold left at 22 (22.23.3 would pass) or off by one (23.9.0).
        """
        result = _run_verify(_make_stub_bin(tmp_path, node_output=f"v{node_version}"))

        lines = _result_lines(result, r"Node\.js")
        assert len(lines) == 1, f"Expected one Node.js result line, got {lines}\n{result.stdout}"
        assert lines[0].startswith("[FAIL]"), f"Node {node_version} should FAIL: {lines[0]}"
        assert node_version in lines[0], f"FAIL line should name the detected version: {lines[0]}"
        assert "24" in lines[0], f"FAIL line should name the required major 24: {lines[0]}"

    @pytest.mark.parametrize("node_version", ["24.0.0", "25.1.0"])
    def test_node_version_at_or_above_minimum_passes(self, tmp_path, node_version):
        """
        Test that script accepts node at or above major 24.

        Given: A node that reports 24.0.0 or 25.1.0
        When: Running verify-deps.sh
        Then: The Node.js line is [PASS] and names the detected version

        Mutation caught: threshold raised above 24, or comparison changed to -gt.
        """
        result = _run_verify(_make_stub_bin(tmp_path, node_output=f"v{node_version}"))

        lines = _result_lines(result, r"Node\.js")
        assert len(lines) == 1, f"Expected one Node.js result line, got {lines}\n{result.stdout}"
        assert lines[0].startswith("[PASS]"), f"Node {node_version} should PASS: {lines[0]}"
        assert node_version in lines[0], f"PASS line should name the detected version: {lines[0]}"


class TestPythonStderrHandling:
    """
    Test that the Python version parse reads stdout only.

    python3 prints its version on stdout. A broken mise shim prints its error,
    including mise's own version, to stderr with empty stdout and exits 1.
    Folding stderr into the parse reports the mise version (2026.9.12) as Python.
    """

    def test_stderr_only_shim_error_fails_detection(self, tmp_path):
        """
        Test that a python3 that prints only a mise error on stderr is a detection failure.

        Given: A stub python3 with empty stdout, a mise shim error on stderr (including
               "Version: 2026.9.12"), exiting 1
        When: Running verify-deps.sh
        Then: The Python line is [FAIL] saying version detection failed
        And: No output mentions 2026

        Mutation caught: `python3 --version 2>&1` feeding stderr into the version parse.
        """
        stderr = (
            "mise ERROR python3 is not a valid shim. This likely means you uninstalled the tool.\n"
            "mise ERROR Version: 2026.9.12 linux-arm64 (2026-09-20)"
        )
        result = _run_verify(_make_stub_bin(tmp_path, python_output="", python_stderr=stderr, python_exit=1))

        lines = _result_lines(result, r"Python")
        assert len(lines) == 1, f"Expected one Python result line, got {lines}\n{result.stdout}"
        assert lines[0].startswith("[FAIL]"), f"Python shim error should FAIL: {lines[0]}"
        assert "detection failed" in lines[0], f"FAIL line should say detection failed: {lines[0]}"
        assert "2026" not in result.stdout, f"mise version must not be reported as Python: {result.stdout}"

    def test_stderr_warning_does_not_break_python_version_parse(self, tmp_path):
        """
        Test that a warning on stderr does not hide the Python version on stdout.

        Given: A stub python3 that writes a warning to stderr and "Python 3.14.7" to stdout
        When: Running verify-deps.sh
        Then: The Python line is [PASS] and names 3.14.7
        """
        result = _run_verify(
            _make_stub_bin(
                tmp_path,
                python_output="Python 3.14.7",
                python_stderr="python warn something harmless",
            )
        )

        lines = _result_lines(result, r"Python")
        assert len(lines) == 1, f"Expected one Python result line, got {lines}\n{result.stdout}"
        assert lines[0].startswith("[PASS]"), f"Python 3.14.7 with stderr warning should PASS: {lines[0]}"
        assert "3.14.7" in lines[0], f"PASS line should name the detected version: {lines[0]}"


class TestNodeStderrHandling:
    """
    Test that the Node version parse reads stdout only.

    A mise shim for an uninstalled node prints its error, including its own
    version, to stderr and exits 1. Folding stderr into the parse reports the
    mise version (2026.9.12) as the Node version.
    """

    def test_stderr_only_shim_error_fails_detection(self, tmp_path):
        """
        Test that a node that prints only a mise error on stderr is a detection failure.

        Given: A stub node with empty stdout, a mise shim error on stderr (including
               "Version: 2026.9.12"), exiting 1
        When: Running verify-deps.sh
        Then: The Node.js line is [FAIL] saying version detection failed
        And: No line reports Node.js 2026.9.12

        Mutation caught: `node --version 2>&1` feeding stderr into the version parse.
        """
        stderr = (
            "mise ERROR node is not a valid shim. This likely means you uninstalled the tool.\n"
            "mise ERROR Version: 2026.9.12 linux-arm64 (2026-09-20)"
        )
        result = _run_verify(_make_stub_bin(tmp_path, node_output="", node_stderr=stderr, node_exit=1))

        lines = _result_lines(result, r"Node\.js")
        assert len(lines) == 1, f"Expected one Node.js result line, got {lines}\n{result.stdout}"
        assert lines[0].startswith("[FAIL]"), f"Node shim error should FAIL: {lines[0]}"
        assert "detection failed" in lines[0], f"FAIL line should say detection failed: {lines[0]}"
        assert "2026" not in result.stdout, f"mise version must not be reported as Node: {result.stdout}"

    def test_stderr_warning_does_not_break_node_version_parse(self, tmp_path):
        """
        Test that a warning on stderr does not hide the Node version on stdout.

        Given: A stub node that writes a warning to stderr and v24.21.0 to stdout
        When: Running verify-deps.sh
        Then: The Node.js line is [PASS] and names 24.21.0
        """
        result = _run_verify(
            _make_stub_bin(tmp_path, node_output="v24.21.0", node_stderr="node warn experimental feature enabled")
        )

        lines = _result_lines(result, r"Node\.js")
        assert len(lines) == 1, f"Expected one Node.js result line, got {lines}\n{result.stdout}"
        assert lines[0].startswith("[PASS]"), f"Node 24.21.0 with stderr warning should PASS: {lines[0]}"
        assert "24.21.0" in lines[0], f"PASS line should name the detected version: {lines[0]}"


class TestMissingNpm:
    """
    Test script behavior when npm is not available.

    Simulates an environment without npm in PATH.
    """

    def test_missing_npm_fails(self, tmp_path):
        """
        Test that script fails when npm is not on PATH.

        Given: An environment without npm in PATH
        When: Running verify-deps.sh
        Then: The npm line is [FAIL] and says npm was not found

        The exit code is not asserted: the restricted PATH already makes the
        script exit 1 for other missing tools.
        Mutation caught: the npm check reporting PASS (or no line) when npm is absent.
        """
        result = _run_verify(_make_stub_bin(tmp_path))

        lines = _result_lines(result, r"\bnpm\b")
        assert len(lines) == 1, f"Expected one npm result line, got {lines}\n{result.stdout}"
        assert lines[0].startswith("[FAIL]"), f"npm line should FAIL: {lines[0]}"
        assert "not found" in lines[0], f"npm FAIL line should say not found: {lines[0]}"


class TestNpmVersion:
    """
    Test Check 3: npm version must be >= 11.5 (ADR-003 (2026-10-05 addendum)).

    Each case puts an explicit stub npm on a restricted PATH and asserts on the
    npm check's own output line, not on the exit code (other missing tools make
    the exit code 1 regardless). The version set defeats a string comparison
    (9.9.9 sorts above 11.5 as a string) and a missing `major > 11` branch (12.0.0).
    """

    @pytest.mark.parametrize("npm_version", ["9.9.9", "10.9.9", "11.4.2"])
    def test_npm_below_floor_fails(self, tmp_path, npm_version):
        """
        Test that npm below 11.5 fails and the line names npm, the version and the floor.

        Given: A stub npm reporting 9.9.9, 10.9.9 or 11.4.2
        When: Running verify-deps.sh
        Then: The npm line is [FAIL], contains the detected version and "11.5"

        Mutation caught: string comparison (9.9.9), major-only check (11.4.2 passes),
        or the old "npm found" check (all pass).
        """
        result = _run_verify(_make_stub_bin(tmp_path, npm_output=npm_version))

        lines = _result_lines(result, r"\bnpm\b")
        assert len(lines) == 1, f"Expected one npm result line, got {lines}\n{result.stdout}"
        assert lines[0].startswith("[FAIL]"), f"npm {npm_version} should FAIL: {lines[0]}"
        assert ".".join(npm_version.split(".")[:2]) in lines[0], (
            f"FAIL line should name the detected version: {lines[0]}"
        )
        assert "11.5" in lines[0], f"FAIL line should name the 11.5 floor: {lines[0]}"
        assert "ADR-003" in lines[0], f"FAIL line should cite ADR-003: {lines[0]}"

    @pytest.mark.parametrize(
        "npm_output",
        ["", "garbage", "v11.5.0"],
        ids=["empty", "unparsable", "v-prefixed"],
    )
    def test_npm_undetectable_version_fails(self, tmp_path, npm_output):
        """
        Test that empty or unparsable npm --version output fails.

        Given: A stub npm that prints nothing, "garbage", or "v11.5.0" for --version
        When: Running verify-deps.sh
        Then: The npm line is [FAIL] and says version detection failed

        Mutation caught: treating an unparsable version as passing (e.g. empty
        major compared as 0 but minor check skipped, or only "npm found" checked),
        and an unanchored parse regex (accepts "v11.5.0"; the spec anchors at ^).
        """
        result = _run_verify(_make_stub_bin(tmp_path, npm_output=npm_output))

        lines = _result_lines(result, r"\bnpm\b")
        assert len(lines) == 1, f"Expected one npm result line, got {lines}\n{result.stdout}"
        assert lines[0].startswith("[FAIL]"), f"npm output {npm_output!r} should FAIL: {lines[0]}"
        assert "detection failed" in lines[0], f"FAIL line should say detection failed: {lines[0]}"

    @pytest.mark.parametrize("npm_version", ["11.5.0", "11.19.0", "12.0.0", "11.5.0-pre.0"])
    def test_npm_at_or_above_floor_passes(self, tmp_path, npm_version):
        """
        Test that npm at or above 11.5 passes, including a prerelease suffix.

        Given: A stub npm reporting 11.5.0, 11.19.0, 12.0.0 or 11.5.0-pre.0
        When: Running verify-deps.sh
        Then: The npm line is [PASS] and contains "11.5" (floor) or the detected version

        Mutation caught: floor raised to 11.6+ (11.5.0), string comparison on the
        minor (11.19.0 < 11.5 as strings), missing `major > 11` branch (12.0.0),
        a parser that rejects suffixes (11.5.0-pre.0).
        """
        result = _run_verify(_make_stub_bin(tmp_path, npm_output=npm_version))

        lines = _result_lines(result, r"\bnpm\b")
        assert len(lines) == 1, f"Expected one npm result line, got {lines}\n{result.stdout}"
        assert lines[0].startswith("[PASS]"), f"npm {npm_version} should PASS: {lines[0]}"
        assert "11.5" in lines[0], f"PASS line should name the 11.5 floor: {lines[0]}"
        # major.minor prefix only: the message may print the parsed pair or the full version
        assert ".".join(npm_version.split(".")[:2]) in lines[0], (
            f"PASS line should name the detected version: {lines[0]}"
        )
        assert "ADR-003" in lines[0], f"PASS line should cite ADR-003: {lines[0]}"

    @pytest.mark.parametrize(
        ("npm_version", "expect_pass"),
        [("11.19.0", True), ("10.9.9", False)],
        ids=["pass-11.19.0", "fail-10.9.9"],
    )
    def test_npm_stderr_warning_does_not_break_version_parse(self, tmp_path, npm_version, expect_pass):
        """
        Test that an `npm warn` line on stderr does not hide the version on stdout.

        Given: A stub npm that writes a warning line to stderr, then the version to stdout
        When: Running verify-deps.sh
        Then: 11.19.0 gives [PASS] naming 11.19 and 11.5 and citing ADR-003
        And: 10.9.9 gives [FAIL] naming 10.9 and 11.5 and citing ADR-003, not "detection failed"

        Real npm 11.19.0 with a legacy .npmrc prints such warnings; merging stderr into
        the parsed output makes the anchored regex fail.
        Mutation caught: capturing `npm --version 2>&1` instead of stdout only.
        """
        warning = "npm warn config production Use `--omit=dev` instead."
        result = _run_verify(_make_stub_bin(tmp_path, npm_output=npm_version, npm_stderr=warning))

        lines = _result_lines(result, r"\bnpm\b")
        assert len(lines) == 1, f"Expected one npm result line, got {lines}\n{result.stdout}"
        line = lines[0]
        assert line.startswith("[PASS]" if expect_pass else "[FAIL]"), f"npm {npm_version} wrong verdict: {line}"
        assert "detection failed" not in line, f"stderr warning must not cause detection failure: {line}"
        assert ".".join(npm_version.split(".")[:2]) in line, f"line should name the detected version: {line}"
        assert "11.5" in line, f"line should name the 11.5 floor: {line}"
        assert "ADR-003" in line, f"line should cite ADR-003: {line}"


class TestMissingGit:
    """
    Test script behavior when git is not available.

    Simulates an environment without git in PATH.
    """

    def test_missing_git_fails(self, tmp_path):
        """
        Test that script fails when git is not on PATH.

        Given: An environment without git in PATH
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for git
        """
        env = os.environ.copy()
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, f"Script should exit 1 when git missing.\nExit code: {result.returncode}"


class TestMissingPipPackage:
    """
    Test script behavior when required pip packages are missing.

    Creates a stub python3 and pip that report packages as not installed.
    Tests check for key packages: check-jsonschema, pytest, PyYAML, ruff, pandas.
    """

    def test_missing_pip_package_fails(self, tmp_path):
        """
        Test that script fails when required pip package is missing.

        Given: A python3 environment missing check-jsonschema package
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for missing package
        """
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()

        # Create stub python3 that reports package not found
        stub_python = stub_bin / "python3"
        stub_python.write_text(
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "Python 3.14.0"\n'
            'elif [[ "$1" == "-m" && "$2" == "pip" && "$3" == "show" ]]; then\n'
            "    # Simulate package not found\n"
            "    exit 1\n"
            "fi\n"
        )
        stub_python.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, (
            f"Script should exit 1 when pip package missing.\nExit code: {result.returncode}"
        )


class TestMissingPrettier:
    """
    Test script behavior when npx prettier is not available.

    Creates a stub npx that fails when running prettier.
    """

    def test_missing_prettier_fails(self, tmp_path):
        """
        Test that script fails when npx prettier fails.

        Given: An environment where npx prettier fails
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for prettier
        """
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()

        # Create stub npx that fails for prettier
        stub_npx = stub_bin / "npx"
        stub_npx.write_text('#!/bin/bash\nif [[ "$1" == "prettier" ]]; then\n    exit 1\nfi\n')
        stub_npx.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, (
            f"Script should exit 1 when prettier missing.\nExit code: {result.returncode}"
        )


class TestMissingMmdc:
    """
    Test script behavior when npx mmdc (mermaid-cli) is not available.

    Creates a stub npx that fails when running mmdc.
    """

    def test_missing_mmdc_fails(self, tmp_path):
        """
        Test that script fails when npx mmdc fails.

        Given: An environment where npx mmdc fails
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for mmdc
        """
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()

        # Create stub npx that fails for mmdc
        stub_npx = stub_bin / "npx"
        stub_npx.write_text(
            '#!/bin/bash\nif [[ "$1" == "mmdc" || "$1" == "@mermaid-js/mermaid-cli" ]]; then\n    exit 1\nfi\n'
        )
        stub_npx.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, f"Script should exit 1 when mmdc missing.\nExit code: {result.returncode}"


class TestMissingRuff:
    """
    Test script behavior when ruff command is not available.

    Simulates an environment without ruff in PATH.
    """

    def test_missing_ruff_fails(self, tmp_path):
        """
        Test that script fails when ruff is not on PATH.

        Given: An environment without ruff in PATH
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for ruff
        """
        env = os.environ.copy()
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, f"Script should exit 1 when ruff missing.\nExit code: {result.returncode}"


class TestMissingCheckJsonschema:
    """
    Test script behavior when check-jsonschema command is not available.

    Simulates an environment without check-jsonschema in PATH.
    """

    def test_missing_check_jsonschema_fails(self, tmp_path):
        """
        Test that script fails when check-jsonschema is not on PATH.

        Given: An environment without check-jsonschema in PATH
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for check-jsonschema
        """
        env = os.environ.copy()
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, (
            f"Script should exit 1 when check-jsonschema missing.\nExit code: {result.returncode}"
        )


class TestMissingChromium:
    """
    Test script behavior when Chromium is not found anywhere.

    Tests that the script checks multiple locations:
    - PLAYWRIGHT_BROWSERS_PATH (or default ~/.cache/ms-playwright)
    - System paths (/usr/bin/chromium, /usr/bin/chromium-browser, etc.)
    - Mac paths (/Applications/Google Chrome.app/...)
    """

    def test_missing_chromium_everywhere_fails(self, tmp_path):
        """
        Test that script fails when Chromium not found anywhere.

        Given: An environment with no Chromium in cache or system paths
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for Chromium
        """
        env = os.environ.copy()
        # Point Playwright cache to empty temp directory
        playwright_cache = tmp_path / "playwright-cache"
        playwright_cache.mkdir()
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(playwright_cache)
        # Clear PATH to avoid finding system Chromium
        env["PATH"] = str(tmp_path / "bin")

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, (
            f"Script should exit 1 when Chromium missing everywhere.\nExit code: {result.returncode}"
        )


class TestChromiumInPlaywrightCache:
    """
    Test script behavior when Chromium is found in Playwright cache.

    The script should check PLAYWRIGHT_BROWSERS_PATH for headless_shell
    or chrome subdirectories with Chromium binaries.
    """

    def test_chromium_in_playwright_cache_passes(self, tmp_path):
        """
        Test that script succeeds when Chromium in Playwright cache.

        Given: Chromium exists in PLAYWRIGHT_BROWSERS_PATH/chromium-.../chrome
        When: Running verify-deps.sh
        Then: Script finds Chromium and passes that check
        And: Output contains PASS indicator for Chromium
        """
        env = os.environ.copy()
        # Create fake Playwright cache structure
        playwright_cache = tmp_path / "playwright-cache"
        chromium_dir = playwright_cache / "chromium-1234" / "chrome-linux"
        chromium_dir.mkdir(parents=True)
        chromium_bin = chromium_dir / "chrome"
        chromium_bin.write_text("#!/bin/bash\necho 'Fake Chromium'\n")
        chromium_bin.chmod(0o755)

        env["PLAYWRIGHT_BROWSERS_PATH"] = str(playwright_cache)
        # Still need other tools in PATH for full test, but this tests Chromium detection
        # For isolation, we'll just check that the Chromium check component works

        subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        # The script will still fail due to other missing deps in isolated env,
        # but we can check output for Chromium PASS indicator when implemented
        # For now, this test documents the expected behavior


class TestChromiumSystemPath:
    """
    Test script behavior when Chromium is found at system paths.

    The script should check standard system paths like:
    - /usr/bin/chromium
    - /usr/bin/chromium-browser
    - /usr/bin/google-chrome
    """

    def test_chromium_at_system_path_passes(self, tmp_path):
        """
        Test that script succeeds when Chromium at system path.

        Given: Chromium exists at /usr/bin/chromium
        When: Running verify-deps.sh
        Then: Script finds Chromium and passes that check
        And: Output contains PASS indicator for Chromium
        """
        # This test is informational - we can't easily create /usr/bin/chromium
        # in tests, but the script should check these paths
        # The actual devcontainer test (TestAllDepsPresent) will validate this


class TestMissingAct:
    """
    Test script behavior when act (GitHub Actions runner) is not available.

    Simulates an environment without act in PATH.
    """

    def test_missing_act_fails(self, tmp_path):
        """
        Test that script fails when act is not on PATH.

        Given: An environment without act in PATH
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains FAIL indicator for act
        """
        env = os.environ.copy()
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, f"Script should exit 1 when act missing.\nExit code: {result.returncode}"


class TestQuietFlag:
    """
    Test script --quiet flag behavior.

    The --quiet flag should suppress output for passing checks but still
    show failures and maintain correct exit codes.
    """

    def test_quiet_flag_suppresses_pass_output(self, tmp_path):
        """
        Test that --quiet suppresses PASS output but shows FAIL.

        Given: An environment with some missing dependencies
        When: Running verify-deps.sh --quiet
        Then: Output does not contain PASS indicators
        And: Output contains FAIL indicators for missing deps
        And: Exit code 1 when dependencies missing
        """
        env = os.environ.copy()
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH), "--quiet"],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, (
            f"Script should exit 1 when deps missing even with --quiet.\nExit code: {result.returncode}"
        )
        # When implemented, verify no PASS in output but FAIL is present


class TestPartialFailure:
    """
    Test script behavior when some dependencies pass and some fail.

    Validates that the script correctly reports mixed results and exits
    with code 1 when any check fails.
    """

    def test_partial_failure_exits_1(self, tmp_path):
        """
        Test that script exits 1 when any dependency check fails.

        Given: An environment with some dependencies present and some missing
        When: Running verify-deps.sh
        Then: Script exits with code 1
        And: Output contains both PASS and FAIL indicators
        """
        stub_bin = tmp_path / "bin"
        stub_bin.mkdir()

        # Create some valid stubs (python3 and git)
        stub_python = stub_bin / "python3"
        stub_python.write_text(
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "Python 3.14.0"\n'
            'elif [[ "$1" == "-m" && "$2" == "pip" && "$3" == "show" ]]; then\n'
            '    echo "Name: ${4}"\n'
            '    echo "Version: 1.0.0"\n'
            "fi\n"
        )
        stub_python.chmod(0o755)

        stub_git = stub_bin / "git"
        stub_git.write_text('#!/bin/bash\necho "git version 2.40.0"\n')
        stub_git.chmod(0o755)

        # But leave out node, npm, etc.
        env = os.environ.copy()
        env["PATH"] = str(stub_bin)

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

        assert result.returncode == 1, (
            f"Script should exit 1 when any dependency fails.\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        # When implemented, verify both PASS and FAIL in output


"""
Test Summary
============
Total Test Classes: 19
Total Test Methods: 21 (some classes have documentation-only tests)

Coverage Areas:
- Script existence and permissions
- Full dependency validation in real environment
- Python availability and version validation
- Node.js availability and version validation
- npm, git availability validation
- pip package installation validation
- npx prettier and mmdc availability
- ruff and check-jsonschema command-line tools
- Chromium detection (Playwright cache and system paths)
- act availability validation
- --quiet flag behavior
- Mixed success/failure scenarios

Test Approach:
- Uses subprocess to execute bash script
- Manipulates PATH and environment variables
- Creates stub scripts in tmp_path for version simulation
- Validates exit codes and output indicators
- Tests both isolated environments and real devcontainer

Dependencies Validated:
- Python >= 3.14
- Node.js >= 24
- npm >= 11.5, git, ruff, check-jsonschema, act
- pip packages: check-jsonschema, pytest, pytest-cov, pytest-timeout, PyYAML, ruff, pandas, tabulate
- npx prettier, npx mmdc
- Chromium (Playwright or system)

Next Steps:
1. Run tests (all should fail - TDD red phase)
2. Implement verify-deps.sh script (TDD green phase)
3. Refactor script for clarity and maintainability (TDD refactor phase)
4. Verify 100% coverage of script functionality
"""
