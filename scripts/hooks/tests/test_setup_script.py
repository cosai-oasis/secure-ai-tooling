#!/usr/bin/env python3
"""
Tests for .devcontainer/setup-script structure.

Static analysis tests that read the setup-script as text and validate its
structure. The setup-script should be a thin wrapper that delegates to
install-deps.sh for backward compatibility.

Test Coverage:
==============
Total Test Classes: 4
Total Test Methods: 10

1. TestSetupScriptExists (2): file exists, non-empty
2. TestSetupScriptDelegates (2): references install-deps.sh, is a bash script
3. TestSetupScriptNoOldLogic (4): no Python symlinks, no /usr/local/python,
   no act download, no set -e
4. TestSetupScriptMinimal (2): short file (<15 lines), no sudo commands

Testing Approach:
=================
Reads .devcontainer/setup-script as text and runs assertions against its content.
Uses a module-level fixture to load the file once per session.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent.parent
SETUP_SCRIPT_PATH = REPO_ROOT / ".devcontainer" / "setup-script"


@pytest.fixture(scope="module")
def setup_script_content():
    """Load setup-script content once per test module."""
    assert SETUP_SCRIPT_PATH.exists(), f"setup-script not found at {SETUP_SCRIPT_PATH}"
    return SETUP_SCRIPT_PATH.read_text()


@pytest.fixture(scope="module")
def setup_script_lines(setup_script_content):
    """Split setup-script into lines for line-by-line analysis."""
    return setup_script_content.splitlines()


# =============================================================================
# TestSetupScriptExists
# =============================================================================


class TestSetupScriptExists:
    """
    Validate setup-script existence and non-emptiness.
    """

    def test_setup_script_exists(self):
        """
        Given: The .devcontainer directory structure
        When: Checking for setup-script
        Then: File exists at .devcontainer/setup-script
        """
        assert SETUP_SCRIPT_PATH.exists(), f"setup-script not found at {SETUP_SCRIPT_PATH}"

    def test_setup_script_is_not_empty(self):
        """
        Given: The setup-script exists
        When: Reading its content
        Then: File is non-empty
        """
        assert SETUP_SCRIPT_PATH.exists(), f"setup-script not found at {SETUP_SCRIPT_PATH}"
        content = SETUP_SCRIPT_PATH.read_text()
        assert len(content.strip()) > 0, "setup-script should not be empty"


# =============================================================================
# TestSetupScriptDelegates
# =============================================================================


class TestSetupScriptDelegates:
    """
    Validate setup-script delegates to install-deps.sh.
    """

    def test_references_install_deps(self, setup_script_content):
        """
        Given: The setup-script content
        When: Checking for delegation logic
        Then: File references install-deps.sh
        """
        assert "install-deps.sh" in setup_script_content, "setup-script should reference install-deps.sh"

    def test_is_bash_script(self, setup_script_lines):
        """
        Given: The setup-script lines
        When: Checking the shebang line
        Then: File starts with bash shebang
        """
        if len(setup_script_lines) == 0:
            pytest.fail("setup-script should not be empty")

        first_line = setup_script_lines[0].strip()
        assert first_line.startswith("#!"), f"setup-script should start with shebang, got: {first_line}"
        assert "bash" in first_line.lower(), f"setup-script should be a bash script, got: {first_line}"


# =============================================================================
# TestSetupScriptNoOldLogic
# =============================================================================


class TestSetupScriptNoOldLogic:
    """
    Validate setup-script does NOT contain old implementation logic.
    All actual installation is handled by install-deps.sh.
    """

    def test_no_python_symlinks(self, setup_script_content):
        """
        Given: The setup-script content
        When: Checking for Python symlink commands
        Then: No ln -sf commands with python context
        """
        lines = setup_script_content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            lower = stripped.lower()
            # Check for ln command with python reference
            if "ln" in lower and "python" in lower:
                pytest.fail(f"setup-script should not contain Python symlink logic: {stripped}")

    def test_no_usr_local_python(self, setup_script_content):
        """
        Given: The setup-script content
        When: Checking for legacy Python installation paths
        Then: No reference to /usr/local/python/current
        """
        assert "/usr/local/python/current" not in setup_script_content, (
            "setup-script should not reference /usr/local/python/current -- "
            "Python is handled by mise via install-deps.sh"
        )

    def test_no_act_download(self, setup_script_content):
        """
        Given: The setup-script content
        When: Checking for act installation logic
        Then: No nektos/act references or install.sh download
        """
        lines = setup_script_content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            lower = stripped.lower()
            # Check for act-specific installation patterns
            if "nektos/act" in lower:
                pytest.fail(f"setup-script should not contain act download logic: {stripped}")
            # Check for wget/curl of install.sh in context with act
            if ("wget" in lower or "curl" in lower) and "install.sh" in lower:
                # This is suspicious -- likely the old act install pattern
                pytest.fail(
                    f"setup-script should not download install.sh -- act is handled by install-deps.sh: {stripped}"
                )

    def test_no_set_e(self, setup_script_content):
        """
        Given: The setup-script content
        When: Checking for error handling mode
        Then: No set -e (install-deps.sh handles its own error flow)
        """
        lines = setup_script_content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Check for 'set -e' as a standalone command
            if stripped == "set -e" or stripped.startswith("set -e "):
                pytest.fail(
                    "setup-script should not use 'set -e' -- "
                    "install-deps.sh uses FAILURES counter for error handling"
                )


# =============================================================================
# TestSetupScriptMinimal
# =============================================================================


class TestSetupScriptMinimal:
    """
    Validate setup-script is minimal (just a thin wrapper).
    """

    def test_file_is_short(self, setup_script_lines):
        """
        Given: The setup-script lines
        When: Counting non-empty, non-comment lines
        Then: File has fewer than 15 lines
        """
        # Count non-empty, non-comment lines
        significant_lines = [
            line for line in setup_script_lines if line.strip() and not line.strip().startswith("#")
        ]
        assert len(significant_lines) < 15, (
            f"setup-script should be a thin wrapper (<15 non-comment lines), got {len(significant_lines)} lines"
        )

    def test_no_sudo_commands(self, setup_script_content):
        """
        Given: The setup-script content
        When: Checking for privileged operations
        Then: No sudo commands (all privileged operations in Dockerfile/install-deps.sh)
        """
        lines = setup_script_content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Check for sudo usage
            if "sudo " in stripped or stripped.startswith("sudo"):
                pytest.fail(
                    f"setup-script should not use sudo -- "
                    f"privileged operations are in Dockerfile/install-deps.sh: {stripped}"
                )


"""
Test Summary
============
Total Test Classes: 4
Total Test Methods: 10

1. TestSetupScriptExists (2): file exists, non-empty
2. TestSetupScriptDelegates (2): references install-deps.sh, is a bash script
3. TestSetupScriptNoOldLogic (4): no Python symlinks, no /usr/local/python,
   no act download, no set -e
4. TestSetupScriptMinimal (2): short file (<15 lines), no sudo commands

Coverage Areas:
- File existence and basic structure
- Delegation to install-deps.sh
- No legacy Python symlink logic
- No legacy act installation logic
- No set -e (install-deps.sh handles error flow)
- Minimal wrapper (thin delegation layer)
- No privileged operations (sudo)
"""
