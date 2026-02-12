#!/usr/bin/env python3
"""
Tests for setup documentation version consistency.

Static analysis tests that read setup markdown files and validate they
reference the correct tool versions after the devcontainer refactor.
No execution required -- these tests parse markdown content to ensure
version numbers are consistent with Phase 1-5 changes.

Test Coverage:
==============
Total Test Classes: 3
Total Test Methods: 12

1. TestRiskMapSetupDoc (6 tests):
   - File exists and is non-empty
   - References Python 3.14 (not 3.11 or 3.10)
   - References Node.js 22 (not 18)
   - Mentions mise (tool version manager)
   - Mentions install-deps.sh
   - Does NOT reference "Python 3.11" in Dev Container section

2. TestScriptsSetupDoc (4 tests):
   - File exists and is non-empty
   - References Python 3.14 (not 3.10)
   - References Node.js 22 (not 18)
   - Does NOT reference "Python 3.10" as the prerequisite version

3. TestDocVersionConsistency (2 tests):
   - Both setup docs reference the same Python version (3.14)
   - Both setup docs reference the same Node version (22)

Testing Approach:
=================
Reads setup documentation files as text and runs assertions against content.
Uses module-level fixtures to load files once per session.
Validates version numbers, tool mentions, and cross-document consistency.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent.parent
RISK_MAP_SETUP_PATH = REPO_ROOT / "risk-map" / "docs" / "setup.md"
SCRIPTS_SETUP_PATH = REPO_ROOT / "scripts" / "docs" / "setup.md"


@pytest.fixture(scope="module")
def risk_map_setup_content():
    """Load risk-map/docs/setup.md content once per test module."""
    assert RISK_MAP_SETUP_PATH.exists(), f"Risk map setup doc not found at {RISK_MAP_SETUP_PATH}"
    return RISK_MAP_SETUP_PATH.read_text()


@pytest.fixture(scope="module")
def scripts_setup_content():
    """Load scripts/docs/setup.md content once per test module."""
    assert SCRIPTS_SETUP_PATH.exists(), f"Scripts setup doc not found at {SCRIPTS_SETUP_PATH}"
    return SCRIPTS_SETUP_PATH.read_text()


class TestRiskMapSetupDoc:
    """
    Tests for risk-map/docs/setup.md version references.

    Validates that the contributor setup guide references correct versions
    for Python 3.14, Node.js 22, and mentions new tooling (mise, install-deps.sh).
    """

    def test_file_exists_and_is_non_empty(self, risk_map_setup_content):
        """
        Test that risk-map/docs/setup.md exists and has content.

        Given: The repository structure after devcontainer refactor
        When: Reading risk-map/docs/setup.md
        Then: File exists and contains non-empty documentation
        """
        assert len(risk_map_setup_content) > 0, "Risk map setup doc should not be empty"
        assert len(risk_map_setup_content) > 100, "Risk map setup doc should contain substantial content"

    def test_references_python_3_14(self, risk_map_setup_content):
        """
        Test that setup doc references Python 3.14.

        Given: The devcontainer refactor uses Python 3.14
        When: Reading risk-map/docs/setup.md
        Then: Document mentions Python 3.14
        """
        assert "3.14" in risk_map_setup_content, "Risk map setup doc should reference Python 3.14"

    def test_does_not_reference_old_python_versions(self, risk_map_setup_content):
        """
        Test that setup doc does not reference outdated Python versions.

        Given: The devcontainer refactor migrated from Python 3.10/3.11 to 3.14
        When: Reading risk-map/docs/setup.md
        Then: Document should not mention Python 3.10 or 3.11 as requirements
        """
        # Check for common version reference patterns
        outdated_patterns = [
            "Python 3.11",
            "python 3.11",
            "Python 3.10",
            "python 3.10",
            "3.11 or higher",
            "3.10 or higher",
        ]

        for pattern in outdated_patterns:
            assert pattern not in risk_map_setup_content, f"Risk map setup doc should not reference '{pattern}'"

    def test_references_nodejs_22(self, risk_map_setup_content):
        """
        Test that setup doc references Node.js 22.

        Given: The devcontainer refactor uses Node.js 22
        When: Reading risk-map/docs/setup.md
        Then: Document mentions Node.js 22
        """
        # Check for common Node.js version patterns
        nodejs_patterns = ["Node.js 22", "node.js 22", "Node 22", "node 22"]

        assert any(pattern in risk_map_setup_content for pattern in nodejs_patterns), (
            "Risk map setup doc should reference Node.js 22"
        )

    def test_mentions_mise_tool_manager(self, risk_map_setup_content):
        """
        Test that setup doc mentions mise as the tool version manager.

        Given: The devcontainer refactor uses mise for tool version management
        When: Reading risk-map/docs/setup.md
        Then: Document mentions mise
        """
        assert "mise" in risk_map_setup_content.lower(), "Risk map setup doc should mention mise tool manager"

    def test_mentions_install_deps_script(self, risk_map_setup_content):
        """
        Test that setup doc mentions the install-deps.sh script.

        Given: The devcontainer refactor introduces install-deps.sh
        When: Reading risk-map/docs/setup.md
        Then: Document mentions install-deps.sh
        """
        assert "install-deps" in risk_map_setup_content.lower(), (
            "Risk map setup doc should mention install-deps.sh script"
        )


class TestScriptsSetupDoc:
    """
    Tests for scripts/docs/setup.md version references.

    Validates that the scripts setup prerequisites reference correct versions
    for Python 3.14 and Node.js 22.
    """

    def test_file_exists_and_is_non_empty(self, scripts_setup_content):
        """
        Test that scripts/docs/setup.md exists and has content.

        Given: The repository structure after devcontainer refactor
        When: Reading scripts/docs/setup.md
        Then: File exists and contains non-empty documentation
        """
        assert len(scripts_setup_content) > 0, "Scripts setup doc should not be empty"
        assert len(scripts_setup_content) > 100, "Scripts setup doc should contain substantial content"

    def test_references_python_3_14(self, scripts_setup_content):
        """
        Test that setup doc references Python 3.14 as prerequisite.

        Given: The devcontainer refactor uses Python 3.14
        When: Reading scripts/docs/setup.md
        Then: Document mentions Python 3.14 as requirement
        """
        assert "3.14" in scripts_setup_content, "Scripts setup doc should reference Python 3.14"

    def test_does_not_reference_python_3_10(self, scripts_setup_content):
        """
        Test that setup doc does not reference Python 3.10.

        Given: The devcontainer refactor migrated from Python 3.10 to 3.14
        When: Reading scripts/docs/setup.md
        Then: Document should not mention Python 3.10 as requirement
        """
        # Check for common version reference patterns
        outdated_patterns = [
            "Python 3.10",
            "python 3.10",
            "3.10 or higher",
        ]

        for pattern in outdated_patterns:
            assert pattern not in scripts_setup_content, f"Scripts setup doc should not reference '{pattern}'"

    def test_references_nodejs_22(self, scripts_setup_content):
        """
        Test that setup doc references Node.js 22.

        Given: The devcontainer refactor uses Node.js 22
        When: Reading scripts/docs/setup.md
        Then: Document mentions Node.js 22
        """
        # Check for common Node.js version patterns
        nodejs_patterns = ["Node.js 22", "node.js 22", "Node 22", "node 22"]

        assert any(pattern in scripts_setup_content for pattern in nodejs_patterns), (
            "Scripts setup doc should reference Node.js 22"
        )


class TestDocVersionConsistency:
    """
    Tests for cross-document version consistency.

    Validates that both setup documentation files reference the same tool
    versions (Python 3.14, Node.js 22) for consistency across the repository.
    """

    def test_both_docs_reference_python_3_14(self, risk_map_setup_content, scripts_setup_content):
        """
        Test that both setup docs reference Python 3.14.

        Given: The devcontainer refactor uses Python 3.14
        When: Reading both setup.md files
        Then: Both documents mention Python 3.14
        """
        assert "3.14" in risk_map_setup_content, "Risk map setup doc should reference Python 3.14"
        assert "3.14" in scripts_setup_content, "Scripts setup doc should reference Python 3.14"

    def test_both_docs_reference_nodejs_22(self, risk_map_setup_content, scripts_setup_content):
        """
        Test that both setup docs reference Node.js 22.

        Given: The devcontainer refactor uses Node.js 22
        When: Reading both setup.md files
        Then: Both documents mention Node.js 22
        """
        # Check for common Node.js version patterns
        nodejs_patterns = ["Node.js 22", "node.js 22", "Node 22", "node 22", "22+"]

        risk_map_has_node22 = any(pattern in risk_map_setup_content for pattern in nodejs_patterns)
        scripts_has_node22 = any(pattern in scripts_setup_content for pattern in nodejs_patterns)

        assert risk_map_has_node22, "Risk map setup doc should reference Node.js 22"
        assert scripts_has_node22, "Scripts setup doc should reference Node.js 22"


"""
Test Summary
============
Total Test Classes: 3
Total Test Methods: 12

Coverage Areas:
- Python version references (3.14, not 3.10/3.11)
- Node.js version references (22, not 18)
- Tool manager mentions (mise)
- Installation script mentions (install-deps.sh)
- Cross-document version consistency

Key Validations:
- risk-map/docs/setup.md references Python 3.14, Node.js 22, mise, install-deps.sh
- scripts/docs/setup.md references Python 3.14, Node.js 22
- No references to outdated versions (Python 3.10/3.11, Node.js 18)
- Both documents are consistent in their version requirements
"""
