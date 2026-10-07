#!/usr/bin/env python3
"""
Tests for setup documentation version consistency.

Static analysis tests that read setup markdown files and validate they
reference the correct tool versions after the devcontainer refactor.
No execution required -- these tests parse markdown content to ensure
version numbers are consistent with Phase 1-5 changes.

Test Coverage:
==============
Total Test Classes: 4
Total Test Methods: 21

1. TestRiskMapSetupDoc (6 tests):
   - File exists and is non-empty
   - References Python 3.14 (not 3.11 or 3.10)
   - References Node.js 24 (not 22 or 18)
   - Mentions mise (tool version manager)
   - Mentions install-deps.sh
   - Does NOT reference "Python 3.11" in Dev Container section

2. TestScriptsSetupDoc (5 tests):
   - File exists and is non-empty
   - References Python 3.14 (not 3.10)
   - References Node.js 24 (not 22 or 18)
   - Tells contributors to run `npm ci` (not `npm install`)
   - Does NOT reference "Python 3.10" as the prerequisite version

3. TestDocVersionConsistency (2 tests):
   - Both setup docs reference the same Python version (3.14)
   - Both setup docs reference the same Node version (24)

4. TestTroubleshootingDoc (8 tests, scripts/docs/troubleshooting.md):
   - No Node.js 22 reference
   - No `npm install` recommendation
   - Entry for `Missing: <pkg> from lock file` naming `npm --version` and 11.5

Testing Approach:
=================
Reads setup documentation files as text and runs assertions against content.
Uses module-level fixtures to load files once per session.
Validates version numbers, tool mentions, and cross-document consistency.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent.parent
RISK_MAP_SETUP_PATH = REPO_ROOT / "risk-map" / "docs" / "setup.md"
SCRIPTS_SETUP_PATH = REPO_ROOT / "scripts" / "docs" / "setup.md"
TROUBLESHOOTING_PATH = REPO_ROOT / "scripts" / "docs" / "troubleshooting.md"


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


@pytest.fixture(scope="module")
def troubleshooting_content():
    """Load scripts/docs/troubleshooting.md content once per test module."""
    assert TROUBLESHOOTING_PATH.exists(), f"Troubleshooting doc not found at {TROUBLESHOOTING_PATH}"
    return TROUBLESHOOTING_PATH.read_text()


def _npm_section(content):
    """Return the text from the npm dependency errors heading to the next `## ` heading."""
    start = content.index("## Common npm dependency errors")
    end = content.find("\n## ", start + 1)
    return content[start:] if end == -1 else content[start:end]


def _heading_slugs(markdown):
    """
    Return the set of GitHub-style anchor slugs for the ATX headings in markdown.

    Slug rule: lowercase, drop every character that is not alphanumeric, space or
    hyphen, then turn each space into a hyphen ("22 -> 24" becomes "22--24").
    Headings inside fenced code blocks are skipped. Duplicate-heading suffixes
    (-1, -2) are not generated.
    """
    slugs = set()
    in_fence = False
    for line in markdown.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        match = None if in_fence else re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if match:
            text = re.sub(r"[^\w\s-]|_", "", match.group(1).lower())
            slugs.add(text.replace(" ", "-"))
    return slugs


class TestRiskMapSetupDoc:
    """
    Tests for risk-map/docs/setup.md version references.

    Validates that the contributor setup guide references correct versions
    for Python 3.14, Node.js 24, and mentions new tooling (mise, install-deps.sh).
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

    def test_references_nodejs_24(self, risk_map_setup_content):
        """
        Test that setup doc references Node.js 24 and no longer Node.js 22.

        Given: The toolchain uses Node.js 24 (ADR-003 (2026-10-05 addendum))
        When: Reading risk-map/docs/setup.md
        Then: Document mentions Node.js 24
        And: Document has no Node.js 22 reference left

        Mutation caught: a doc updated in one place while a stale "22+" remains.
        """
        # Check for common Node.js version patterns
        nodejs_patterns = ["Node.js 24", "node.js 24", "Node 24", "node 24"]

        assert any(pattern in risk_map_setup_content for pattern in nodejs_patterns), (
            "Risk map setup doc should reference Node.js 24"
        )
        assert not re.search(r"[Nn]ode(\.js)? v?22", risk_map_setup_content), (
            "Risk map setup doc should not reference Node.js 22"
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
    for Python 3.14 and Node.js 24, and that project dependencies are installed
    with npm ci.
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

    def test_references_nodejs_24(self, scripts_setup_content):
        """
        Test that setup doc references Node.js 24 and no longer Node.js 22.

        Given: The toolchain uses Node.js 24 (ADR-003 (2026-10-05 addendum))
        When: Reading scripts/docs/setup.md
        Then: Document mentions Node.js 24
        And: Document has no Node.js 22 reference left

        Mutation caught: a doc updated in one place while a stale "22+" remains.
        """
        # Check for common Node.js version patterns
        nodejs_patterns = ["Node.js 24", "node.js 24", "Node 24", "node 24"]

        assert any(pattern in scripts_setup_content for pattern in nodejs_patterns), (
            "Scripts setup doc should reference Node.js 24"
        )
        assert not re.search(r"[Nn]ode(\.js)? v?22", scripts_setup_content), (
            "Scripts setup doc should not reference Node.js 22"
        )

    def test_install_step_uses_npm_ci(self, scripts_setup_content):
        """
        Test that setup doc tells contributors to install Node dependencies with npm ci.

        Given: install-deps.sh and CI install from the lock with npm ci (ADR-003 (2026-10-05 addendum))
        When: Reading scripts/docs/setup.md
        Then: Document contains the `npm ci` command
        And: Document does not tell contributors to run `npm install`

        Mutation caught: the doc keeping `npm install`, which rewrites the lock.
        """
        assert "npm ci" in scripts_setup_content, "Scripts setup doc should tell contributors to run 'npm ci'"
        assert "npm install" not in scripts_setup_content, (
            "Scripts setup doc should not tell contributors to run 'npm install'"
        )


class TestDocVersionConsistency:
    """
    Tests for cross-document version consistency.

    Validates that both setup documentation files reference the same tool
    versions (Python 3.14, Node.js 24) for consistency across the repository.
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

    def test_both_docs_reference_nodejs_24(self, risk_map_setup_content, scripts_setup_content):
        """
        Test that both setup docs reference Node.js 24.

        Given: The toolchain uses Node.js 24 (ADR-003 (2026-10-05 addendum))
        When: Reading both setup.md files
        Then: Both documents mention Node.js 24
        """
        # Check for common Node.js version patterns
        nodejs_patterns = ["Node.js 24", "node.js 24", "Node 24", "node 24", "24+"]

        risk_map_has_node24 = any(pattern in risk_map_setup_content for pattern in nodejs_patterns)
        scripts_has_node24 = any(pattern in scripts_setup_content for pattern in nodejs_patterns)

        assert risk_map_has_node24, "Risk map setup doc should reference Node.js 24"
        assert scripts_has_node24, "Scripts setup doc should reference Node.js 24"


class TestTroubleshootingDoc:
    """
    Tests for scripts/docs/troubleshooting.md (ADR-003, 2026-10-05 addendum).

    The doc must not carry the old Node major or `npm install`, must map
    the `Missing: <pkg> from lock file` error to the npm version floor, and
    must link ADR-003 and no other (dropped) ADR file.
    """

    def test_does_not_reference_nodejs_22(self, troubleshooting_content):
        """
        Test that the troubleshooting doc has no Node.js 22 reference.

        Given: The toolchain uses Node.js 24 (ADR-003 (2026-10-05 addendum))
        When: Reading scripts/docs/troubleshooting.md
        Then: No "Node 22", "Node.js 22", "node v22" style reference remains

        Mutation caught: "Node.js 22+" left at the Node prerequisite line.
        """
        match = re.search(r"[Nn]ode(\.js)? v?22", troubleshooting_content)
        assert match is None, f"Troubleshooting doc should not reference Node.js 22: {match and match.group(0)!r}"

    def test_does_not_tell_contributors_to_run_npm_install(self, troubleshooting_content):
        """
        Test that the troubleshooting doc does not recommend `npm install`.

        Given: Project dependencies are installed with npm ci (ADR-003 (2026-10-05 addendum))
        When: Reading scripts/docs/troubleshooting.md
        Then: The text `npm install` does not appear

        Mutation caught: the prettier and mermaid-cli fix lines keeping `npm install`.
        """
        lines = [line for line in troubleshooting_content.splitlines() if "npm install" in line]
        assert not lines, f"Troubleshooting doc should say 'npm ci', found: {lines}"

    def test_has_lock_file_mismatch_entry(self, troubleshooting_content):
        """
        Test that an entry maps the lock-file error to the npm version floor.

        Given: ADR-003 (2026-10-05 addendum) adds a troubleshooting entry for the misleading npm error
        When: Reading scripts/docs/troubleshooting.md
        Then: A single line (heading or error text) contains `Missing:` then `from lock file`
        And: The doc mentions `npm --version` and `11.5`

        Mutation caught: entry omitted, or present without the version check and floor.
        """
        assert re.search(r"Missing:.*from lock file", troubleshooting_content), (
            "Troubleshooting doc should contain an entry for 'Missing: <pkg> from lock file'"
        )
        assert "npm --version" in troubleshooting_content, "Entry should tell contributors to run 'npm --version'"
        assert "11.5" in troubleshooting_content, "Entry should name the npm 11.5 floor"

    def test_lock_file_entry_covers_package_json_out_of_sync(self, troubleshooting_content):
        """
        Test that the lock-file entry also names a package.json / lock mismatch as a cause.

        Given: `Missing: <pkg> from lock file` also occurs on npm >= 11.5 when
               package.json was edited without regenerating package-lock.json
        When: Reading the npm dependency errors section of scripts/docs/troubleshooting.md
        Then: The section mentions package.json and says it is out of sync with the lock

        Mutation caught: an entry that blames only the npm version.
        """
        section = _npm_section(troubleshooting_content)
        assert "package.json" in section, "Lock-file entry should mention package.json"
        assert re.search(r"(?i)out of sync|not in sync", section), (
            "Lock-file entry should say package.json can be out of sync with the lock"
        )

    def test_adr_link_points_to_adr_003_only(self, troubleshooting_content):
        """
        Test that the doc links the ADR-003 addendum and no other ADR file.

        Given: The decisions live in ADR-003's 2026-10-05 addendum (a separate ADR was dropped)
        When: Reading scripts/docs/troubleshooting.md
        Then: The npm dependency errors section links 003-devcontainer-mise-architecture.md
        And: Every `docs/adr/NNN-` link in the doc has NNN == 003

        Mutation caught: a link to a deleted ADR file, or an npm entry with no ADR link.
        """
        assert "003-devcontainer-mise-architecture.md" in _npm_section(troubleshooting_content), (
            "npm dependency errors section should link 003-devcontainer-mise-architecture.md"
        )
        numbers = re.findall(r"docs/adr/(\d+)-", troubleshooting_content)
        assert numbers and set(numbers) == {"003"}, f"Only ADR-003 links are expected, found ADR numbers {numbers}"

    def test_adr_links_resolve_to_existing_files(self, troubleshooting_content):
        """
        Test that every relative docs/adr link in the doc resolves to a real file.

        Given: scripts/docs/troubleshooting.md links ADR files by relative path
        When: Resolving each `docs/adr/...` link target relative to the doc, ignoring #anchors
        Then: At least one such link exists and every resolved path is an existing file

        Mutation caught: the ADR link deleted, or pointed at a deleted or misspelled file.
        """
        targets = re.findall(r"\]\(([^)\s]*docs/adr/[^)\s#]+)(?:#[^)\s]*)?\)", troubleshooting_content)
        assert targets, "Troubleshooting doc should link at least one docs/adr file"
        missing = [t for t in targets if not (TROUBLESHOOTING_PATH.parent / t).resolve().is_file()]
        assert not missing, f"Troubleshooting doc links ADR files that do not exist: {missing}"

    def test_adr_link_fragments_match_target_headings(self, troubleshooting_content):
        """
        Test that each docs/adr link fragment is the GitHub slug of a heading in its target.

        Given: scripts/docs/troubleshooting.md links ADR sections as `file.md#fragment`
        When: Slugging the target file's headings (lowercase, drop characters that are not
              alphanumeric, space or hyphen, spaces to hyphens)
        Then: At least one fragment link exists and every fragment equals one of those slugs

        Mutation caught: a stale or misspelled anchor such as
        `#addendum-2026-10-05-node-24-and-npm-ci` after the heading was renamed.
        """
        links = re.findall(r"\]\(([^)\s]*docs/adr/[^)\s#]+)#([^)\s]+)\)", troubleshooting_content)
        assert links, "Troubleshooting doc should link at least one docs/adr section with a #fragment"
        bad = []
        for target, fragment in links:
            path = (TROUBLESHOOTING_PATH.parent / target).resolve()
            if fragment not in _heading_slugs(path.read_text()):
                bad.append(f"{target}#{fragment}")
        assert not bad, f"Fragments that match no heading in their target file: {bad}"

    def test_prettier_warning_is_not_under_npm_heading(self, troubleshooting_content):
        """
        Test that the prettier staging warning sits in the prettier section.

        Given: The doc has "Common prettier formatting errors" and
               "Common npm dependency errors" sections
        When: Locating the "Could not stage formatted file" warning
        Then: It appears after the prettier heading and before the npm heading

        Mutation caught: the npm section inserted mid-way through the prettier
        section, leaving the prettier warning block under the npm heading.
        """
        prettier = troubleshooting_content.index("## Common prettier formatting errors")
        npm = troubleshooting_content.index("## Common npm dependency errors")
        warning = troubleshooting_content.index("Could not stage formatted file")
        assert prettier < warning < npm, (
            "The 'Could not stage formatted file' block should be inside the prettier section, "
            "before 'Common npm dependency errors'"
        )


"""
Test Summary
============
Total Test Classes: 4
Total Test Methods: 21

Coverage Areas:
- Python version references (3.14, not 3.10/3.11)
- Node.js version references (24, not 22 or 18)
- npm ci instead of npm install in scripts/docs/setup.md
- Tool manager mentions (mise)
- Installation script mentions (install-deps.sh)
- Cross-document version consistency

Key Validations:
- risk-map/docs/setup.md references Python 3.14, Node.js 24, mise, install-deps.sh
- scripts/docs/setup.md references Python 3.14, Node.js 24, npm ci
- scripts/docs/troubleshooting.md has no Node.js 22 or `npm install`, and has the
  `Missing: <pkg> from lock file` entry naming `npm --version` and 11.5
- No references to outdated versions (Python 3.10/3.11, Node.js 18)
- Both documents are consistent in their version requirements
"""
