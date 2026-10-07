#!/usr/bin/env python3
"""
Tests that every workflow Node pin matches the .mise.toml Node major (ADR-003, 2026-10-05 addendum).

Every `actions/setup-node` step in `.github/workflows/*.yml` must declare a
`node-version` whose major equals the `tools.node` major in `.mise.toml`. A
workflow left on an older Node would read `package-lock.json` with an older npm than the one that
wrote it, which is the failure the ADR-003 (2026-10-05 addendum) records.

Test Coverage:
==============
- Non-vacuity: at least one setup-node step is found
- Each setup-node step declares node-version (one case per workflow file)
- Each node-version major equals the .mise.toml major
"""

import re
from pathlib import Path

import pytest
import tomllib
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
MISE_CONFIG_PATH = REPO_ROOT / ".mise.toml"
WORKFLOW_FILES = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))


def _mise_node_major() -> int:
    """Return the Node major declared in .mise.toml."""
    with open(MISE_CONFIG_PATH, "rb") as f:
        node = tomllib.load(f)["tools"]["node"]
    return int(str(node).split(".")[0])


def _setup_node_steps(workflow_path: Path) -> list[dict]:
    """Return every `actions/setup-node` step dict in the workflow file."""
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    steps = []
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            if str(step.get("uses", "")).startswith("actions/setup-node@"):
                steps.append(step)
    return steps


def _id(path: Path) -> str:
    """Return the repo-relative path string, used as the pytest case id and in messages."""
    return str(path.relative_to(REPO_ROOT))


# Setup-node step counts that the ADR-003 (2026-10-05 addendum) names. A dropped step would otherwise leave
# nothing to check in its file and pass the per-file version test vacuously.
MIN_SETUP_NODE_STEPS = {
    ".github/workflows/validation.yml": 3,
    ".github/workflows/persona-pages.yml": 1,
    ".github/workflows/validate_mermaid.yml": 1,
}


@pytest.mark.parametrize(("relpath", "minimum"), sorted(MIN_SETUP_NODE_STEPS.items()))
def test_adr_named_workflows_keep_their_setup_node_steps(relpath, minimum):
    """
    Test that each ADR-003 (2026-10-05 addendum) workflow still has its setup-node steps.

    Given: The workflows the ADR-003 addendum names (validation.yml has three jobs)
    When: Counting actions/setup-node steps in each
    Then: The count is at least the number the ADR names

    Mutation caught: a setup-node step removed entirely, which the version
    test cannot see because it only inspects steps that exist.
    """
    found = len(_setup_node_steps(REPO_ROOT / relpath))
    assert found >= minimum, f"{relpath}: expected at least {minimum} setup-node step(s), found {found}"


def test_at_least_one_setup_node_step_is_found():
    """
    Given: The .github/workflows directory
    When: Collecting every actions/setup-node step
    Then: At least one step is found, so the per-file tests are not vacuous

    Mutation caught: a loader or glob change that silently finds no steps.
    """
    total = sum(len(_setup_node_steps(path)) for path in WORKFLOW_FILES)
    assert total >= 1, "No actions/setup-node steps found in any workflow"


@pytest.mark.parametrize("workflow_path", WORKFLOW_FILES, ids=_id)
def test_setup_node_steps_pin_the_mise_node_major(workflow_path):
    """
    Test that each setup-node step in a workflow uses the .mise.toml Node major.

    Given: A workflow file and the .mise.toml Node major
    When: Reading node-version from each actions/setup-node step
    Then: node-version is present and its leading major equals the .mise.toml major

    Mutation caught: one workflow (or one of validation.yml's three jobs) left
    on '22.x', or a step that switches to node-version-file and drops the pin.
    """
    expected = _mise_node_major()
    for step in _setup_node_steps(workflow_path):
        version = (step.get("with") or {}).get("node-version")
        assert version is not None, f"{_id(workflow_path)}: setup-node step has no node-version: {step}"
        match = re.match(r"^v?(\d+)", str(version))
        assert match is not None, f"{_id(workflow_path)}: unparsable node-version {version!r}"
        assert int(match.group(1)) == expected, (
            f"{_id(workflow_path)}: node-version {version!r} does not match .mise.toml Node major {expected}"
        )
