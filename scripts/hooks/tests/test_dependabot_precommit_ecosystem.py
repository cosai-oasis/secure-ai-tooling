#!/usr/bin/env python3
"""
Channel-guard test for the Dependabot `pre-commit` ecosystem entry.

ADR-005 Addendum 2026-08-19 (D3, issue #382) replaces the custom
notification-only rev-drift workflow with Dependabot's native `pre-commit`
ecosystem support. This test locks in that the ecosystem entry exists in
.github/dependabot.yml so it cannot be silently removed — it is the minimal
structural guard that replaces the deleted workflow's role.
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent.parent.parent
DEPENDABOT_PATH = REPO_ROOT / ".github" / "dependabot.yml"


def _load_dependabot() -> dict:
    """Return the parsed .github/dependabot.yml as a dict."""
    return yaml.safe_load(DEPENDABOT_PATH.read_text(encoding="utf-8"))


def _precommit_entry() -> dict:
    """Return the pre-commit ecosystem update entry."""
    updates = _load_dependabot()["updates"]
    matches = [u for u in updates if u.get("package-ecosystem") == "pre-commit"]
    assert len(matches) == 1, f"Expected exactly one pre-commit ecosystem entry; got {len(matches)}"
    return matches[0]


class TestDependabotPrecommitEcosystem:
    """The pre-commit ecosystem channel must be declared and correctly scoped."""

    def test_precommit_ecosystem_entry_exists(self):
        """A `package-ecosystem: "pre-commit"` update entry is declared."""
        entry = _precommit_entry()
        assert entry["package-ecosystem"] == "pre-commit"
