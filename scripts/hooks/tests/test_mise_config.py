#!/usr/bin/env python3
"""
Tests for .mise.toml configuration file.

This test suite validates that the .mise.toml file at the repository root
correctly declares the tool versions required for CoSAI Risk Map development.
The file is consumed by mise (a dev tool version manager) to install and
activate the correct Python and Node.js versions.

Test Coverage:
==============
Total Tests: 16 test methods across 6 classes
Coverage Target: 100% of .mise.toml configuration requirements

1. TestMiseConfigExists - File existence and type
   - File exists at repo root
   - File is a regular file (not directory or symlink)

2. TestMiseConfigValidToml - TOML syntax and structure
   - File parses as valid TOML
   - File contains a [tools] section

3. TestMiseConfigPython - Python version specification
   - tools.python key exists
   - Python version is "3.14"
   - Python version satisfies >= 3.14 requirement

4. TestMiseConfigNode - Node.js version specification
   - tools.node key exists
   - Node.js version is "24"
   - Node.js version satisfies >= 24 requirement

5. TestMiseConfigConsistency - Cross-file version agreement
   - Python version matches verify-deps.sh threshold (>= 3.14)
   - NODE_MIN_MAJOR in verify-deps.sh and install-deps.sh equals the
     .mise.toml Node major (ADR-003, 2026-10-05 addendum)
   - Node comparisons and MISE_NODE_VERSION fallbacks use $NODE_MIN_MAJOR
     instead of a literal major

6. TestMiseInterpreterResolution - Runtime mise binary validation
   (skipped when mise-installed Python is not present, e.g., CI)
   - mise "latest" symlink exists
   - Python binary is executable
   - Python binary runs and reports version
   - Version matches .mise.toml specification

Testing Approach:
=================
Uses tomllib (Python 3.11+ stdlib) to parse the TOML file and validate its
structure and values. Consistency tests read verify-deps.sh to extract the
version thresholds and compare against .mise.toml values. Runtime integration
tests (TestMiseInterpreterResolution) are skipped in CI where mise is not
the Python provider.
"""

import re
from pathlib import Path

import pytest
import tomllib

# Path constants matching existing test patterns (test_verify_deps.py)
REPO_ROOT = Path(__file__).parent.parent.parent.parent
MISE_CONFIG_PATH = REPO_ROOT / ".mise.toml"
VERIFY_DEPS_PATH = REPO_ROOT / "scripts" / "tools" / "verify-deps.sh"
INSTALL_DEPS_PATH = REPO_ROOT / "scripts" / "tools" / "install-deps.sh"
NODE_SCRIPTS = [VERIFY_DEPS_PATH, INSTALL_DEPS_PATH]


class TestMiseConfigExists:
    """
    Test .mise.toml file existence and type.

    Validates that .mise.toml exists at the expected location and is a
    regular file, not a directory or symlink.
    """

    def test_mise_toml_exists(self):
        """
        Test that .mise.toml exists at the repo root.

        Given: The repository root directory
        When: Checking for .mise.toml file
        Then: File exists at REPO_ROOT/.mise.toml
        """
        assert MISE_CONFIG_PATH.exists(), f".mise.toml not found at {MISE_CONFIG_PATH}"

    def test_mise_toml_is_regular_file(self):
        """
        Test that .mise.toml is a regular file.

        Given: The .mise.toml path exists
        When: Checking file type
        Then: Path is a regular file (not a directory or symlink)
        """
        assert MISE_CONFIG_PATH.exists(), f".mise.toml not found at {MISE_CONFIG_PATH}"
        assert MISE_CONFIG_PATH.is_file(), f".mise.toml at {MISE_CONFIG_PATH} is not a regular file"
        assert not MISE_CONFIG_PATH.is_symlink(), (
            f".mise.toml at {MISE_CONFIG_PATH} is a symlink; expected a regular file"
        )


class TestMiseConfigValidToml:
    """
    Test .mise.toml TOML syntax and structure.

    Validates that the file is valid TOML and contains the expected
    top-level [tools] section that mise uses for tool version management.
    """

    def test_mise_toml_parses_as_valid_toml(self):
        """
        Test that .mise.toml is valid TOML syntax.

        Given: The .mise.toml file exists
        When: Parsing the file with tomllib
        Then: File parses without errors and returns a dict
        """
        assert MISE_CONFIG_PATH.exists(), f".mise.toml not found at {MISE_CONFIG_PATH}"
        with open(MISE_CONFIG_PATH, "rb") as f:
            config = tomllib.load(f)
        assert isinstance(config, dict), ".mise.toml did not parse to a dict"

    def test_mise_toml_has_tools_section(self):
        """
        Test that .mise.toml contains a [tools] section.

        Given: A valid .mise.toml file
        When: Checking for the tools key
        Then: The top-level 'tools' key exists and is a dict
        """
        with open(MISE_CONFIG_PATH, "rb") as f:
            config = tomllib.load(f)
        assert "tools" in config, ".mise.toml is missing the [tools] section"
        assert isinstance(config["tools"], dict), ".mise.toml [tools] section is not a table/dict"


class TestMiseConfigPython:
    """
    Test Python version specification in .mise.toml.

    Validates that .mise.toml declares the correct Python version.
    .mise.toml is the single source of truth; install-deps.sh and the
    Dockerfile derive versions from it dynamically.
    """

    @pytest.fixture()
    def tools(self):
        """Load and return the [tools] section from .mise.toml."""
        with open(MISE_CONFIG_PATH, "rb") as f:
            config = tomllib.load(f)
        return config.get("tools", {})

    def test_python_key_exists(self, tools):
        """
        Test that tools.python key exists in .mise.toml.

        Given: A valid .mise.toml with a [tools] section
        When: Checking for the python key
        Then: The python key exists under [tools]
        """
        assert "python" in tools, ".mise.toml [tools] section is missing the 'python' key"

    def test_python_version_is_3_14(self, tools):
        """
        Test that Python version is "3.14".

        Given: A .mise.toml with tools.python defined
        When: Reading the python version value
        Then: Value is "3.14"
        """
        python_version = str(tools.get("python", ""))
        assert python_version == "3.14", f"Expected tools.python = '3.14', got '{python_version}'"

    def test_python_version_satisfies_minimum(self, tools):
        """
        Test that Python version satisfies >= 3.14 requirement.

        Given: A .mise.toml with a numeric python version string
        When: Parsing the version as major.minor
        Then: Version is >= 3.14
        """
        python_version = str(tools.get("python", "0.0"))
        parts = python_version.split(".")
        assert len(parts) >= 2, f"Python version '{python_version}' does not have major.minor format"
        major = int(parts[0])
        minor = int(parts[1])
        satisfies = (major > 3) or (major == 3 and minor >= 14)
        assert satisfies, f"Python version {python_version} does not satisfy >= 3.14 requirement"


class TestMiseConfigNode:
    """
    Test Node.js version specification in .mise.toml.

    Validates that .mise.toml declares the correct Node.js version.
    .mise.toml is the single source of truth; install-deps.sh and the
    Dockerfile derive versions from it dynamically.
    """

    @pytest.fixture()
    def tools(self):
        """Load and return the [tools] section from .mise.toml."""
        with open(MISE_CONFIG_PATH, "rb") as f:
            config = tomllib.load(f)
        return config.get("tools", {})

    def test_node_key_exists(self, tools):
        """
        Test that tools.node key exists in .mise.toml.

        Given: A valid .mise.toml with a [tools] section
        When: Checking for the node key
        Then: The node key exists under [tools]
        """
        assert "node" in tools, ".mise.toml [tools] section is missing the 'node' key"

    def test_node_version_is_24(self, tools):
        """
        Test that Node.js version is "24".

        Given: A .mise.toml with tools.node defined
        When: Reading the node version value
        Then: Value is "24"
        """
        node_version = str(tools.get("node", ""))
        assert node_version == "24", f"Expected tools.node = '24', got '{node_version}'"

    def test_node_version_satisfies_minimum(self, tools):
        """
        Test that Node.js version satisfies >= 24 requirement.

        Given: A .mise.toml with a numeric node version string
        When: Parsing the major version
        Then: Major version is >= 24
        """
        node_version = str(tools.get("node", "0"))
        # Handle dotted versions (e.g., "24.1") and plain major (e.g., "24")
        major = int(node_version.split(".")[0])
        assert major >= 24, f"Node.js version {node_version} does not satisfy >= 24 requirement"


class TestMiseConfigConsistency:
    """
    Test that .mise.toml versions agree with verify-deps.sh thresholds.

    Reads verify-deps.sh to extract the version thresholds it checks for
    (Python >= 3.14) and confirms that .mise.toml declares a version that
    satisfies it. For Node, each script declares NODE_MIN_MAJOR once and the
    tests require it to equal the .mise.toml major, with every comparison and
    fallback reading the variable (ADR-003, 2026-10-05 addendum). This catches drift between
    the config file and the scripts.
    """

    @pytest.fixture()
    def tools(self):
        """Load and return the [tools] section from .mise.toml."""
        with open(MISE_CONFIG_PATH, "rb") as f:
            config = tomllib.load(f)
        return config.get("tools", {})

    @pytest.fixture()
    def verify_deps_content(self):
        """Read and return verify-deps.sh content as a string."""
        assert VERIFY_DEPS_PATH.exists(), f"verify-deps.sh not found at {VERIFY_DEPS_PATH}"
        return VERIFY_DEPS_PATH.read_text()

    def test_python_version_matches_verify_deps(self, tools, verify_deps_content):
        """
        Test that .mise.toml Python version satisfies verify-deps.sh threshold.

        Given: .mise.toml declares a Python version and verify-deps.sh checks >= 3.14
        When: Comparing the mise Python version against the verify-deps threshold
        Then: The mise version satisfies the verify-deps minimum

        verify-deps.sh checks: PYTHON_MINOR -ge 14 (with PYTHON_MAJOR -eq 3)
        """
        # Extract the minor version threshold from verify-deps.sh
        # Pattern: PYTHON_MINOR -ge <number>
        match = re.search(r"PYTHON_MINOR.*-ge\s+(\d+)", verify_deps_content)
        assert match is not None, "Could not find Python minor version threshold in verify-deps.sh"
        required_minor = int(match.group(1))

        python_version = str(tools.get("python", "0.0"))
        parts = python_version.split(".")
        mise_major = int(parts[0])
        mise_minor = int(parts[1])

        # mise version must satisfy the same check verify-deps.sh uses
        satisfies = (mise_major > 3) or (mise_major == 3 and mise_minor >= required_minor)
        assert satisfies, (
            f".mise.toml Python {python_version} does not satisfy verify-deps.sh threshold >= 3.{required_minor}"
        )

    @pytest.mark.parametrize("script_path", NODE_SCRIPTS, ids=lambda p: p.name)
    def test_node_min_major_equals_mise_major(self, tools, script_path):
        """
        Test that NODE_MIN_MAJOR in each script equals the .mise.toml Node major.

        Given: .mise.toml declares a Node version and a script declares NODE_MIN_MAJOR
        When: Comparing the script's value with the .mise.toml major
        Then: The script declares NODE_MIN_MAJOR exactly once and it equals the major

        Majors only: the npm >= 11.5 floor is enforced separately by verify-deps.sh.
        A trailing comment is tolerated; quoted and `readonly` forms are not (the ADR
        spells the plain `NODE_MIN_MAJOR=<major>` form).
        Mutation caught: bumping .mise.toml without bumping one script (or the reverse).
        """
        content = script_path.read_text()
        matches = re.findall(r"^\s*NODE_MIN_MAJOR=(\d+)\s*(?:#.*)?$", content, re.MULTILINE)
        assert len(matches) == 1, (
            f"{script_path.name} must declare NODE_MIN_MAJOR=<major> exactly once, found {matches}"
        )

        mise_major = int(str(tools.get("node", "0")).split(".")[0])
        assert int(matches[0]) == mise_major, (
            f"{script_path.name} NODE_MIN_MAJOR={matches[0]} does not equal .mise.toml Node major {mise_major}"
        )

    @pytest.mark.parametrize("script_path", NODE_SCRIPTS, ids=lambda p: p.name)
    def test_node_major_comparisons_use_variable(self, script_path):
        """
        Test that every NODE_MAJOR -ge comparison references NODE_MIN_MAJOR.

        Given: A script that compares NODE_MAJOR against a threshold
        When: Collecting every line with a NODE_MAJOR ... -ge comparison
        Then: At least one exists and each references $NODE_MIN_MAJOR or ${NODE_MIN_MAJOR}

        Mutation caught: a literal threshold (e.g. -ge 22 or -ge 24) left in one comparison.
        """
        lines = [line for line in script_path.read_text().splitlines() if re.search(r"NODE_MAJOR.*-ge\b", line)]
        assert lines, f"No NODE_MAJOR -ge comparison found in {script_path.name}"
        for line in lines:
            assert re.search(r"\$\{?NODE_MIN_MAJOR\}?", line), (
                f"{script_path.name} compares NODE_MAJOR against a literal: {line.strip()}"
            )

    def test_install_deps_fallbacks_use_variable(self):
        """
        Test that both MISE_NODE_VERSION fallbacks in install-deps.sh use NODE_MIN_MAJOR.

        Given: install-deps.sh falls back to a default when MISE_NODE_VERSION is empty
        When: Collecting every ${MISE_NODE_VERSION:-...} expansion
        Then: There are at least two and each default is $NODE_MIN_MAJOR

        Mutation caught: leaving one ':-22' (or ':-24') fallback while the other is converted.
        """
        content = INSTALL_DEPS_PATH.read_text()
        defaults = re.findall(r"\$\{MISE_NODE_VERSION:-([^}]*)\}", content)
        assert len(defaults) >= 2, f"Expected at least two MISE_NODE_VERSION fallbacks, found {defaults}"
        for default in defaults:
            assert default in ("$NODE_MIN_MAJOR", "${NODE_MIN_MAJOR}"), (
                f"MISE_NODE_VERSION fallback is not NODE_MIN_MAJOR: {default!r}"
            )

    @pytest.mark.parametrize("script_path", NODE_SCRIPTS, ids=lambda p: p.name)
    def test_no_literal_node_major_in_node_lines(self, script_path):
        """
        Test that no line mentioning Node carries a literal two-digit major.

        Given: A script whose Node threshold lives in NODE_MIN_MAJOR
        When: Scanning every line that mentions node (comments, messages, comparisons)
        Then: No such line other than the NODE_MIN_MAJOR declaration has a standalone
              number of 18 or more

        Mutation caught: a stale '>= 22' left in a skip/pass/fail message or header comment.
        """
        offenders = []
        for line in script_path.read_text().splitlines():
            if not re.search(r"node", line, re.IGNORECASE) or re.match(r"^\s*NODE_MIN_MAJOR=", line):
                continue
            if re.search(r"(?<![\d.])(1[89]|[2-9]\d)(?![\d])(?!\.\d)", line):
                offenders.append(line.strip())
        assert not offenders, f"{script_path.name} has literal Node majors: {offenders}"


# Skip the entire class when mise-installed Python is not present (e.g., GitHub Actions
# CI uses actions/setup-python instead of mise).
_mise_python_latest = Path.home() / ".local/share/mise/installs/python/latest"


@pytest.mark.skipif(
    not _mise_python_latest.exists(),
    reason="mise-installed Python not present (not running in devcontainer)",
)
class TestMiseInterpreterResolution:
    """
    Runtime integration tests verifying the mise Python binary resolves correctly.

    devcontainer.json sets defaultInterpreterPath to the real Python binary via
    mise's "latest" symlink. These tests verify that symlink chain actually
    resolves to a working Python interpreter inside the container.

    Skipped in CI where Python is provided by actions/setup-python rather than mise.
    """

    MISE_PYTHON_LATEST = Path.home() / ".local/share/mise/installs/python/latest"
    MISE_PYTHON_BIN = MISE_PYTHON_LATEST / "bin" / "python"

    def test_mise_python_latest_symlink_exists(self):
        """
        Given: mise installed Python from .mise.toml
        When: Checking for the "latest" symlink
        Then: Symlink exists at ~/.local/share/mise/installs/python/latest

        The "latest" symlink is managed by mise and used by
        defaultInterpreterPath in devcontainer.json.
        """
        assert self.MISE_PYTHON_LATEST.exists(), (
            f"mise 'latest' symlink missing: {self.MISE_PYTHON_LATEST}. Was 'mise install' run?"
        )
        assert self.MISE_PYTHON_LATEST.is_symlink(), (
            f"Expected symlink at {self.MISE_PYTHON_LATEST}, got regular path"
        )

    def test_mise_python_latest_binary_is_executable(self):
        """
        Given: The mise "latest" symlink exists
        When: Checking the Python binary it points to
        Then: Binary exists and is executable

        devcontainer.json defaultInterpreterPath points here. If this fails,
        VS Code will show "could not be resolved" at startup.
        """
        assert self.MISE_PYTHON_BIN.exists(), f"Python binary missing at {self.MISE_PYTHON_BIN}"
        import os

        assert os.access(self.MISE_PYTHON_BIN, os.X_OK), f"Python binary not executable: {self.MISE_PYTHON_BIN}"

    def test_mise_python_latest_binary_runs(self):
        """
        Given: The mise Python binary exists and is executable
        When: Invoking it with --version
        Then: It executes as Python and reports a version string
        """
        import subprocess

        result = subprocess.run(
            [str(self.MISE_PYTHON_BIN), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0, f"Python binary exited with {result.returncode}: {result.stderr}"
        # Python 3.4+ writes --version to stdout, but check both for robustness
        combined = result.stdout + result.stderr
        assert "Python" in combined, f"Expected 'Python' in version output, got: {combined}"

    def test_mise_python_latest_matches_mise_toml(self):
        """
        Given: .mise.toml declares a Python version
        When: Running the "latest" binary
        Then: Its version matches the .mise.toml specification

        Catches drift where mise's "latest" symlink points to a different
        Python version than what .mise.toml declares.
        """
        import subprocess

        with open(MISE_CONFIG_PATH, "rb") as f:
            config = tomllib.load(f)
        expected_minor = str(config.get("tools", {}).get("python", ""))

        result = subprocess.run(
            [str(self.MISE_PYTHON_BIN), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # "Python 3.14.3" -> "3.14" (stdout for Python 3.4+, check both for safety)
        combined = (result.stdout + result.stderr).strip()
        version_str = combined.split()[-1]
        actual_minor = ".".join(version_str.split(".")[:2])
        assert actual_minor == expected_minor, (
            f"mise 'latest' Python is {actual_minor}, but .mise.toml declares {expected_minor}"
        )
