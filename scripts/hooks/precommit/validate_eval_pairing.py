#!/usr/bin/env python3
"""
Pre-commit lint: enforce ADR-033 D6/D8 and ADR-031 D6 eval pairing for shipped
authoring surfaces.

Every shipped agent and skill must carry a portable eval alongside it:
  - `scripts/agents/<name>.md`      -> `scripts/agents-evals/<name>/evals.json`
  - `scripts/skills/<name>/`        -> `scripts/skills/<name>/evals/evals.json`

This is a corpus-completeness check, not a per-file scanner: it always
self-discovers both authoring surfaces from the current working directory and
reports every unpaired entry in one pass, rather than taking file arguments or
stopping at the first violation. Discovery walk mirrors
`discover_neutral_surface_files` in validate_neutrality.py; the
missing/stale-exemption comparison mirrors `compare_control_maps` in
validate_control_risk_references.py (collect every mismatch, never fail
fast).

Six agents shipped before this eval requirement existed and are grandfathered
via `EXEMPT_AGENT_NAMES`. Skills have no equivalent exemption: every skill on
`main` already ships an eval, so the requirement is unconditional for that
surface. An exempted agent that unexpectedly already has an eval on disk is
flagged as a distinct "stale exemption" finding (remedy: drop the exemption,
not add another eval) so a maintainer never has to read this module's source
to know which of the two problems applies.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

HOOK_NAME = "validate-eval-pairing"

# The 6 agents grandfathered in before the eval requirement existed. Each
# entry is independently load-bearing (a fixed enumeration, not a pattern) and
# is expected to shrink over time as agents backfill evals and drop off this
# set — never grow it as a way to avoid shipping an eval for a new agent.
#
# Retrofit tracking: gh-drafts/backlog/draft-agent-eval-retrofit-6-landed-agents-issue.md
# (unfiled draft; no issue number yet, hence "TBD" below rather than a fabricated one).
EXEMPT_AGENT_NAMES: frozenset[str] = frozenset(
    {
        "architect",  # tracked: backlog issue TBD
        "code-reviewer",  # tracked: backlog issue TBD
        "content-reviewer",  # tracked: backlog issue TBD
        "issue-response-reviewer",  # tracked: backlog issue TBD
        "swe",  # tracked: backlog issue TBD
        "testing",  # tracked: backlog issue TBD
    }
)


@dataclass(frozen=True)
class Violation:
    """A single eval-pairing violation (missing eval or stale exemption)."""

    surface: str  # "agent" | "skill"
    name: str
    path: Path  # the (missing or unexpectedly-present) eval path this finding is anchored to
    message: str


def discover_shipped_agents(root: Path) -> list[str]:
    """
    Return stem names of top-level `scripts/agents/<name>.md` files under `root`.

    Only direct children of `scripts/agents/` are considered (`glob`, not
    `rglob`) — a nested file such as `scripts/agents/<name>/notes.md` is
    bundled material for that agent, not a second agent definition, so
    discovery must not recurse into it.

    Tolerates an absent `scripts/agents/` tree (returns []).
    """
    agents_dir = root / "scripts" / "agents"
    if not agents_dir.is_dir():
        return []
    return sorted(path.stem for path in agents_dir.glob("*.md"))


def discover_shipped_skills(root: Path) -> list[str]:
    """
    Return names of `scripts/skills/<name>/` directories under `root` that contain a `SKILL.md`.

    Presence of `SKILL.md` is the sole discriminator — a stray non-skill file
    directly under `scripts/skills/` (e.g. the real corpus's `README.md`) is
    not a directory and has no `SKILL.md`, so it is naturally excluded without
    an explicit denylist.

    Tolerates an absent `scripts/skills/` tree (returns []).
    """
    skills_dir = root / "scripts" / "skills"
    if not skills_dir.is_dir():
        return []
    return sorted(path.name for path in skills_dir.iterdir() if path.is_dir() and (path / "SKILL.md").is_file())


def find_pairing_violations(root: Path) -> list[Violation]:
    """
    Check every shipped agent and skill under `root` for a matching eval sibling.

    Collects every violation in one pass (never fails fast), mirroring
    `compare_control_maps` in validate_control_risk_references.py. Either
    authoring surface, or the `scripts/agents-evals/` tree itself, may be
    absent without error.

    Args:
        root: Directory to scan (contains a `scripts/` subtree, or does not).

    Returns:
        List of violations, empty if every shipped agent/skill is paired (or
        grandfathered, for agents).
    """
    violations: list[Violation] = []

    for agent_name in discover_shipped_agents(root):
        eval_path = root / "scripts" / "agents-evals" / agent_name / "evals.json"
        # Repo-relative rendering for the message text (not the absolute
        # `eval_path`): the absolute form embeds `root`, which under a pytest
        # tmp_path fixture can itself contain incidental substrings (e.g. a
        # test name), so a message built from the absolute path is not safe
        # against accidental lexical overlap between the two failure classes.
        relative_hint = f"scripts/agents-evals/{agent_name}/evals.json"
        has_eval = eval_path.is_file()
        is_exempt = agent_name in EXEMPT_AGENT_NAMES

        if is_exempt and has_eval:
            # Stale exemption: the grandfathering no longer reflects reality.
            # Remedy is to drop the name from EXEMPT_AGENT_NAMES, not add
            # another eval file (one already exists).
            violations.append(
                Violation(
                    surface="agent",
                    name=agent_name,
                    path=eval_path,
                    message=(
                        f"agent {agent_name!r} carries a stale exemption: it is still listed in "
                        f"EXEMPT_AGENT_NAMES, but an eval already exists at {relative_hint}. Drop "
                        f"{agent_name!r} from EXEMPT_AGENT_NAMES."
                    ),
                )
            )
        elif not is_exempt and not has_eval:
            # Missing eval: a non-exempt agent must ship one.
            violations.append(
                Violation(
                    surface="agent",
                    name=agent_name,
                    path=eval_path,
                    message=(
                        f"agent {agent_name!r} is missing its required eval. Add {relative_hint} (or "
                        f"add {agent_name!r} to EXEMPT_AGENT_NAMES if this is a known gap)."
                    ),
                )
            )
        # is_exempt and not has_eval: grandfathered, no violation.
        # not is_exempt and has_eval: fully paired, no violation.

    for skill_name in discover_shipped_skills(root):
        eval_path = root / "scripts" / "skills" / skill_name / "evals" / "evals.json"
        relative_hint = f"scripts/skills/{skill_name}/evals/evals.json"
        if not eval_path.is_file():
            # Skills have no exemption set: unconditional requirement.
            violations.append(
                Violation(
                    surface="skill",
                    name=skill_name,
                    path=eval_path,
                    message=f"skill {skill_name!r} is missing its required eval. Add {relative_hint}.",
                )
            )

    return violations


def format_violation(violation: Violation) -> str:
    """Format one violation for stderr, prefixed with HOOK_NAME."""
    return f"{HOOK_NAME}: {violation.surface} {violation.name!r}: {violation.message}"


def main(argv: list[str]) -> int:
    """
    CLI entry point for pre-commit and manual validation.

    This validator is a corpus-completeness check, not a per-file scanner: it
    always self-discovers both authoring surfaces from the current working
    directory. `argv` is accepted only for shape-consistency with the other
    precommit validators' `main(argv) -> int` signature. No options are
    defined, so an empty `argv` is a no-op; an unrecognized flag still raises
    via argparse's own `SystemExit(2)`, since this validator never receives
    one in its actual (`pass_filenames: false`) invocation.

    Returns:
        1 if any violations are found, else 0.
    """
    parser = argparse.ArgumentParser(description="Validate ADR-033/ADR-031 agent/skill eval pairing.")
    parser.parse_args(argv)

    violations = find_pairing_violations(Path.cwd())

    for violation in violations:
        print(format_violation(violation), file=sys.stderr)

    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
