#!/usr/bin/env python3
"""
Tests for .mise.toml configuration file.

This test suite validates that the .mise.toml file at the repository root
correctly declares the tool versions required for CoSAI Risk Map development.
The file is consumed by mise (a dev tool version manager) to install and
activate the correct Python and Node.js versions.

Test Coverage:
==============
Total Tests: 12 test methods across 5 classes
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
   - Node.js version is "22"
   - Node.js version satisfies >= 22 requirement

5. TestMiseConfigConsistency - Cross-file version agreement
   - Python version matches verify-deps.sh threshold (>= 3.14)
   - Node.js version matches verify-deps.sh threshold (>= 22)

Testing Approach:
=================
Uses tomllib (Python 3.11+ stdlib) to parse the TOML file and validate its
structure and values. Consistency tests read verify-deps.sh to extract the
version thresholds and compare against .mise.toml values.
"""

import re
from pathlib import Path

import pytest
import tomllib

# Path constants matching existing test patterns (test_verify_deps.py)
REPO_ROOT = Path(__file__).parent.parent.parent.parent
MISE_CONFIG_PATH = REPO_ROOT / ".mise.toml"
VERIFY_DEPS_PATH = REPO_ROOT / "scripts" / "tools" / "verify-deps.sh"


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

    Validates that .mise.toml declares the correct Python version matching
    what install-deps.sh installs (python@3.14) and what verify-deps.sh
    checks for (>= 3.14).
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
        Then: Value is "3.14" (matching install-deps.sh: mise install python@3.14)
        """
        python_version = str(tools.get("python", ""))
        assert python_version == "3.14", (
            f"Expected tools.python = '3.14', got '{python_version}'. "
            f"Must match install-deps.sh: mise install python@3.14"
        )

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

    Validates that .mise.toml declares the correct Node.js version matching
    what install-deps.sh installs (node@22) and what verify-deps.sh checks
    for (>= 22).
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

    def test_node_version_is_22(self, tools):
        """
        Test that Node.js version is "22".

        Given: A .mise.toml with tools.node defined
        When: Reading the node version value
        Then: Value is "22" (matching install-deps.sh: mise install node@22)
        """
        node_version = str(tools.get("node", ""))
        assert node_version == "22", (
            f"Expected tools.node = '22', got '{node_version}'. Must match install-deps.sh: mise install node@22"
        )

    def test_node_version_satisfies_minimum(self, tools):
        """
        Test that Node.js version satisfies >= 22 requirement.

        Given: A .mise.toml with a numeric node version string
        When: Parsing the major version
        Then: Major version is >= 22
        """
        node_version = str(tools.get("node", "0"))
        # Handle dotted versions (e.g., "22.1") and plain major (e.g., "22")
        major = int(node_version.split(".")[0])
        assert major >= 22, f"Node.js version {node_version} does not satisfy >= 22 requirement"


class TestMiseConfigConsistency:
    """
    Test that .mise.toml versions agree with verify-deps.sh thresholds.

    Reads verify-deps.sh to extract the version thresholds it checks for
    (Python >= 3.14, Node >= 22) and confirms that .mise.toml declares
    versions that satisfy those thresholds. This catches drift between the
    config file and the verification script.
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

    def test_node_version_matches_verify_deps(self, tools, verify_deps_content):
        """
        Test that .mise.toml Node version satisfies verify-deps.sh threshold.

        Given: .mise.toml declares a Node version and verify-deps.sh checks >= 22
        When: Comparing the mise Node version against the verify-deps threshold
        Then: The mise version satisfies the verify-deps minimum

        verify-deps.sh checks: NODE_MAJOR -ge <number>
        """
        # Extract the major version threshold from verify-deps.sh
        # Pattern: NODE_MAJOR -ge <number>
        match = re.search(r"NODE_MAJOR.*-ge\s+(\d+)", verify_deps_content)
        assert match is not None, "Could not find Node major version threshold in verify-deps.sh"
        required_major = int(match.group(1))

        node_version = str(tools.get("node", "0"))
        mise_major = int(node_version.split(".")[0])

        assert mise_major >= required_major, (
            f".mise.toml Node {node_version} does not satisfy verify-deps.sh threshold >= {required_major}"
        )


"""
Test Summary
============
Total Test Classes: 5
Total Test Methods: 12

Coverage Areas:
- File existence and type validation (2 tests)
- TOML syntax and structure validation (2 tests)
- Python version specification (3 tests)
- Node.js version specification (3 tests)
- Cross-file consistency with verify-deps.sh (2 tests)

Test Approach:
- Uses tomllib (Python 3.11+ stdlib) for TOML parsing
- Validates file existence, type, structure, and values
- Extracts version thresholds from verify-deps.sh via regex
- Confirms .mise.toml versions satisfy the thresholds
- No external dependencies beyond pytest and stdlib

Version Sources Cross-Referenced:
- install-deps.sh: mise install python@3.14, mise install node@22
- verify-deps.sh: Python >= 3.14, Node >= 22
- .mise.toml: tools.python = "3.14", tools.node = "22"

Next Steps:
1. Run tests (all should fail - TDD red phase, .mise.toml does not exist yet)
2. Create .mise.toml file (TDD green phase)
3. Verify all 12 tests pass
"""
