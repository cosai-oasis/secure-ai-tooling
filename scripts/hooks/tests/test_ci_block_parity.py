#!/usr/bin/env python3
"""
Tests for ADR-037 — CI as the enforcing gate for risk-map validation.

Covers three of the ADR's testable requirements:

  D1 (coverage, then monotonicity)
      Part 1, coverage: every validator that `.pre-commit-config.yaml` invokes
      with `--block` has a CI invocation that also passes `--block`.
      Part 2, monotonicity: for validators present on both surfaces, the CI
      strictness flags are a superset of the hook's.

      The two are separate classes below because part 2 alone is satisfied
      *vacuously* by a validator CI never runs — an empty flag set is trivially
      a superset of nothing. Part 2 quantifies over the intersection of the two
      surfaces and therefore cannot see a validator missing from one of them,
      which is precisely the gap three of the five validators sit in. Part 1
      quantifies over pre-commit's `--block` hooks, so absence from CI fails
      rather than skips.

  D3 (`--block` is prohibited on graph-generation invocations)
      No workflow step may pass `--block` on an invocation that also passes
      `--to-graph`, `--to-controls-graph`, or `--to-risk-graph`. The warn-only
      `sys.exit` in `validate_riskmap.py` precedes every emission block, so the
      pairing terminates the process before any graph file is written and
      misattributes a content warning as a generation failure.

  D4 (non-vacuity)
      Asserting that the string `--block` appears in a workflow proves the
      string is present, not that behaviour changed. Every claim here is
      backed by running the validator against a corpus carrying a deliberately
      injected warn-level violation and comparing exit codes.

  D7a (CI's file lists are constructed explicitly, and are complete)
      The three validators D7 wires take file arguments, and the list that
      reaches their argv decides whether they check anything. It must be
      *derived* from the hook's own `files:` pattern rather than transcribed
      (a transcribed list drifts permissively), it must equal the hook's whole
      file set rather than a prefix of it, and every file in it must actually
      be inspected by the arguments CI passes. The third is asserted
      behaviourally, once per resolved file, because the first two can hold
      while a bad `--schema-dir` makes the validator visit nothing.

  D7b (the `precommit/` validators are invoked in place)
      No workflow may copy a validator out of `scripts/hooks/precommit/` or
      invoke one from a path other than its real location. Those validators
      derive both their `sys.path` entry and their default `--schema-dir` from
      `Path(__file__)`; relocating them makes field discovery return silently
      and the job exit 0 having inspected nothing. This does not touch the
      five existing copy-to-root steps D5 keeps — it prohibits extending the
      pattern to new call sites, which D5's own text records as not being a
      copy-to-root change.

  D8 (blocking without a flag)
      D1's coverage clause quantifies over *blocking* hooks, not over `--block`
      hooks: a validator with no warn-only tier blocks unconditionally and
      never takes the flag, so every derivation keyed on `--block` is blind to
      it. Six validators, across seven hook ids, are invoked by no workflow at
      all — one script, `validate_neutrality.py`, is named by two of the
      seven. Section 10 states D1, D7b and D7c over the six hook ids that take
      no file arguments and have to establish which corpus a run read as well
      as what it returned: three locate their corpus from `Path(__file__)`
      and three from the working directory, so a job wired to the wrong tree
      exits 0 rather than failing for the `Path(__file__)`-anchored ones. The
      seventh, `validate-neutrality`, takes an explicit file list instead and
      is governed by section 6 (D7a) alongside D7's three.

Derivation, not enumeration
---------------------------
Neither side's validator list is hardcoded. Both are parsed out of the actual
files:

  - the pre-commit side from `repos[].hooks[].entry` + `args` in
    `.pre-commit-config.yaml`;
  - the CI side from every `jobs.*.steps[].run` shell block in every
    `.github/workflows/*.yml`.

A validator added to pre-commit tomorrow with `--block` and not to CI fails
D1 without anyone editing this module. A hardcoded list would reproduce the
very gap the suite exists to catch.

Reaching variable-built invocations
-----------------------------------
`validation.yml`'s graph-validation job does not name the script inline. It
builds the command through shell variables::

    VALIDATE_CMD="validate_riskmap.py"
    GENERATE_ARGS=("--to-graph" "--to-controls-graph" "--to-risk-graph")
    ...
    gen_args="${GENERATE_ARGS[$i]}"
    if ! python3 ${VALIDATE_CMD} --force ${gen_args} "${temp_file}"; then

A check that only looks for `--block` next to a literal script name is blind
exactly where D3's risk lives. `_python_invocations` therefore tracks scalar
and array assignments and expands `${VAR}` / `$VAR` / `${ARR[$i]}` references
before classifying a command. Array references expand to the union of the
array's elements — a deliberate over-approximation: for a prohibition, seeing
a flag that only *might* be on the command line is the safe direction to err.

`TestParserFidelity` locks that this expansion actually happens, so D3 cannot
pass by failing to see the invocation it is meant to police.

Joining the two surfaces
------------------------
Invocations are joined on the script's **basename**. CI copies validator
sources to the repository root before running them (`validation.yml:44-47`,
`:183-185`, `:222`, `:259`, `:298-300`), so `scripts/hooks/validate_riskmap.py`
in the hook and `validate_riskmap.py` in the workflow are the same validator
under different paths. ADR-037 D5 decides that arrangement stays; matching on
basename works with it rather than requiring it to change.
`test_precommit_script_basenames_are_unambiguous` guards the assumption that
no two distinct validator paths share a basename.

What these tests are for, now that the gap is closed
----------------------------------------------------
D1, D2, D4 and D7's coverage half were all red when this module was written
against base commit 0d0b731, and all five `--block` validators now have CI
invocations carrying the flag. Sections 1-5 have therefore changed role: they
are standing guards, not a to-do list, and each is only as good as the edit it
would notice.

That is the whole design constraint on what follows. An assertion that a string
appears in a workflow notices a deleted string and nothing else, and every edit
that matters here — an empty file list, a truncated one, a `--schema-dir` that
resolves nowhere, a moved working directory, a step that finds the violation and
returns 0 anyway, a `paths:` filter that stops the job from running at all —
leaves every string in place. Sections 6 to 10 exist because those edits were
applied and measured, and sections 1 to 5 stayed green through all of them.

Section 8 fails as committed. Section 6's file-list assertions pass, but the
trigger rules do not: the gate does not yet re-run on changes to its own
definition, and the pytest workflow does not run on workflow edits. Everything
else here passes as committed and earns its place by the edit it would catch,
which is recorded per class.

Deliberately not a gap: lifecycle-stage order uniqueness
--------------------------------------------------------
`.pre-commit-config.yaml` declares a second hook on `validate_riskmap.py`
(`validate-lifecycle-stage`, `--mode lifecycle`), and no workflow ever passes
`--mode lifecycle`. That looks like a sixth coverage gap and is not one: the
lifecycle check also runs unconditionally in default mode
(`validate_riskmap.py:249-271`, guarded on `validator.components`), which CI's
`--force` invocation reaches, and it exits 1 directly without needing
`--block`. The hook carries no strictness flag, so D1 does not quantify over
it either. Recorded here so the next reader does not re-derive it as a missing
case and "fix" it.

Beyond the flags: what else has to hold
---------------------------------------
Three properties sit outside the command line and each fails silently on its
own, so each has a section of its own below.

  The file list (section 6). Derived, complete, and read — asserted by running
  the derivation and then running the validator once per file it names.

  The execution context (section 7). The resolver enumerates the corpus in the
  step's working directory and the validators open repo-relative paths there,
  so the step must run at the repository root; and `FILES=$(...)` only aborts
  under a shell that exits on error, which is what turns the resolver's
  exit-1-on-empty-match into a red job.

  The trigger (section 8). A workflow that does not run on a pull request is
  not a gate on it. A gate must trigger on its own definition, on the
  validators it executes, and on the config its file lists derive from;
  and the workflow running the whole pytest suite must trigger on the files
  this module asserts over, or every guard here is absent from exactly the
  pull request that disables it.

  The step's exit code (section 9). Everything above models the *validator's*
  exit code — it runs the validator and reads what it returns. The number that
  decides the job is the *step's*, produced by the `if ... else ... exit 1; fi`
  wrapper around each invocation, and nothing consumes the `status` outputs the
  steps write, so that wrapper is the entire enforcement mechanism. Deleting
  its `exit 1`, appending `|| true`, or adding `continue-on-error:` or a
  conditional `if:` each leave the violation found and printed and the job
  green — which is the warn-only soak ADR-037 D7 rejects by name, reached
  without touching a flag, a path, a file list, or a working directory.

  The inventory (section 10). Deleting a whole class from this module produced
  a smaller run and no failure. Several classes here are the only thing that
  would notice a particular edit, so what the module contains is asserted
  rather than described.

D3 passes at authoring time. ADR-037 D3 says so explicitly — it "codifies
existing practice rather than changing it". The D3 tests here are a standing
guard against a future workflow edit, and `TestGraphEmissionExclusion`'s
synthetic-detector tests establish that the guard would catch a violation in
both the literal and the variable-built form.
"""

import ast
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, NamedTuple

import pytest
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# tests -> hooks -> scripts -> repo root, matching the convention in
# test_precommit_hook_install.py and test_controls_components_mirror.py.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_HOOKS_DIR = _REPO_ROOT / "scripts" / "hooks"
_PRECOMMIT_CONFIG = _REPO_ROOT / ".pre-commit-config.yaml"
_WORKFLOW_DIR = _REPO_ROOT / ".github" / "workflows"

# ---------------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------------

# Flags that make a validator stricter. ADR-037 D1 states the invariant over
# "strictness flags" generally; `--block` is the only member today. The
# *validators* carrying these flags are derived, never listed — that derivation
# is what makes this suite self-maintaining. Adding a second strictness flag
# here extends the invariant to it on both surfaces at once.
STRICTNESS_FLAGS = frozenset({"--block"})

# Graph-emission flags named literally in ADR-037 D3. Each is confirmed to be a
# real `validate_riskmap.py` option by test_graph_emission_flags_are_real, so a
# flag rename cannot silently make the D3 prohibition vacuous.
GRAPH_EMISSION_FLAGS = frozenset({"--to-graph", "--to-controls-graph", "--to-risk-graph"})

# Filename suffixes GitHub Actions executes out of `.github/workflows/`. Both
# are honoured identically, so a scan restricted to one of them is blind to a
# workflow that runs. Every prohibition in this module quantifies over the file
# set `_workflow_files` returns, and
# `TestParserFidelity::test_the_workflow_scan_covers_every_workflow_github_would_run`
# pins that set against the directory's actual contents.
#
# Scanning both extensions is preferred here over prohibiting `.yaml` in the
# directory. A prohibition would encode a repository convention no ADR states,
# and it fails a contributor who has a legitimate reason to use the other
# spelling; scanning makes the guards true of whatever GitHub actually runs.
WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})


def _workflow_files() -> list[Path]:
    """Return every workflow file GitHub would execute, sorted by name.

    Single source of the file set for every scan in this module. Three sites
    previously globbed `*.yml` independently, and a `.github/workflows/*.yaml`
    file was therefore invisible to all of them at once — one character defeated
    the D3 prohibition, the D7b prohibition, and both file-list rules.
    """
    return sorted(
        (path for path in _WORKFLOW_DIR.iterdir() if path.is_file() and path.suffix in WORKFLOW_SUFFIXES),
        key=lambda path: path.name,
    )


def _tracked_files() -> list[str]:
    """Return every tracked repo-relative path, sorted.

    Used to resolve script basenames and to expand copied directories into the
    files a `paths:` filter has to name. Tracked rather than on-disk, so build
    artefacts (`__pycache__`) cannot become trigger requirements.
    """
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    return sorted(entry for entry in result.stdout.split("\0") if entry)


TRACKED_FILES = _tracked_files()
TRACKED_FILE_SET = frozenset(TRACKED_FILES)

# basename -> every tracked path carrying it, for script resolution.
TRACKED_BY_BASENAME: dict[str, list[str]] = {}
for _path in TRACKED_FILES:
    TRACKED_BY_BASENAME.setdefault(Path(_path).name, []).append(_path)


# ===========================================================================
# Shell-invocation parsing
# ===========================================================================

_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_TOKEN_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_INTERPRETER_RE = re.compile(r"^python[0-9.]*$")

# Tokens that terminate one simple command and begin another.
_OPERATORS = frozenset({";", "&&", "||", "|", "&"})

# Shell keywords and command prefixes that precede the real command word.
_LEADING_WORDS = frozenset(
    {"if", "elif", "while", "until", "then", "do", "else", "!", "sudo", "time", "env", "exec"}
)


class Invocation(NamedTuple):
    """One resolved Python execution found in a shell script.

    Attributes:
        script: Basename of the executed ``.py`` file (path prefixes dropped,
            so the CI copy-to-root layout and the hook's repo-relative path
            resolve to the same identity).
        path: The script path exactly as written on the command line, before
            basename reduction. D7b needs this: `validate_prose_references.py`
            and `scripts/hooks/precommit/validate_prose_references.py` are the
            same validator to D1 and different call sites to D7b.
        argv: Tokens following the script on the same simple command, after
            variable expansion.
        source: Human-readable origin, used in assertion messages.
        line: The raw (unexpanded) shell line, also for assertion messages.
        substitutions: (variable name, shell command) pairs for every
            command-substitution assignment seen in the enclosing script, and
            only populated when the parse ran with ``keep_substitutions=True``.
            A command substitution is not statically resolvable, so the default
            parse discards it; the D7a file lists live in exactly such an
            assignment, and pinning them means executing the command rather
            than reading it.
    """

    script: str
    path: str
    argv: tuple[str, ...]
    source: str
    line: str
    substitutions: tuple[tuple[str, str], ...] = ()


class CopyCommand(NamedTuple):
    """A file-relocating shell command found in a workflow step.

    Attributes:
        source_path: The path being copied or moved, as written.
        destination: The destination operand, as written.
        source: Human-readable origin, used in assertion messages.
        line: The raw shell line.
    """

    source_path: str
    destination: str
    source: str
    line: str


def _safe_split(text: str) -> list[str]:
    """Tokenize a shell fragment, degrading to whitespace splitting on failure.

    `shlex` raises on unbalanced quotes, which occurs in hand-written workflow
    shell. Falling back to whitespace splitting keeps such a line visible to
    the scan. Silently dropping it is the failure mode this suite exists to
    prevent: an unparsed line is an unpoliced line.
    """
    try:
        return shlex.split(text, comments=True)
    except ValueError:
        return [t for t in re.split(r"\s+", text.strip()) if t]


def _expand(token: str, env: dict[str, Any]) -> str:
    """Expand ``${VAR}``, ``$VAR`` and ``${ARR[...]}`` references in a token.

    Array-valued variables expand to their elements joined by spaces. An
    indexed reference such as ``${GENERATE_ARGS[$i]}`` therefore yields every
    element rather than one, because the loop index is not statically known.
    For a *prohibition* (D3) this over-approximation is the safe direction:
    a flag that might be on the command line is treated as if it is.

    Unknown variables expand to the empty string, mirroring shell behaviour
    under the default (non-``nounset``) mode used by workflow ``run`` blocks.
    """
    out = token
    # Bounded iteration resolves variables defined in terms of other variables
    # (e.g. TEMP_FILES holding "${RISK_MAP_TEMP_FILE}") without risking a cycle.
    for _ in range(5):
        expanded = _VAR_RE.sub(lambda m: _lookup(env, m.group(1) or m.group(2)), out)
        if expanded == out:
            break
        out = expanded
    return out


def _lookup(env: dict[str, Any], name: str) -> str:
    """Return a variable's expansion, joining array elements with spaces."""
    value = env.get(name)
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(value)
    return value


def _split_simple_commands(tokens: list[str]) -> list[list[str]]:
    """Split a token stream into simple commands on shell control operators.

    Redirections start a new (discarded) segment so that `>> $GITHUB_OUTPUT`
    tails are not mistaken for arguments.
    """
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        # Operators are not whitespace-separated in shell, so split them out of
        # adjoining tokens (`--force;` -> `--force`, `;`).
        for part in (p for p in re.split(r"(;|&&|\|\||\||&)", token) if p):
            if part in _OPERATORS or part.startswith(">") or part.startswith("<"):
                if current:
                    segments.append(current)
                current = []
            else:
                current.append(part)
    if current:
        segments.append(current)
    return segments


def _segments_with_operators(tokens: list[str]) -> list[tuple[list[str], str | None]]:
    """Split a token stream into (simple command, following operator) pairs.

    `_split_simple_commands` discards the operators, which is right for asking
    *what ran* and wrong for asking *what happens when it fails*. `cmd || true`
    and `cmd` produce identical segment lists there, and they are the difference
    between a step that fails the job and one that does not.

    The operator returned with a segment is the one that immediately follows it,
    or None at the end of the line.
    """
    pairs: list[tuple[list[str], str | None]] = []
    current: list[str] = []
    for token in tokens:
        for part in (p for p in re.split(r"(;|&&|\|\||\||&)", token) if p):
            if part in _OPERATORS or part.startswith(">") or part.startswith("<"):
                if current:
                    pairs.append((current, part if part in _OPERATORS else None))
                current = []
            else:
                current.append(part)
    if current:
        pairs.append((current, None))
    return pairs


def _shell_operators(text: str) -> list[str]:
    """Return the control operators present in a shell fragment.

    Used to assert that a file-list command substitution is a single simple
    command: `$(resolver || true)` neutralizes the resolver's exit-1-on-empty
    contract, and the only visible trace is the operator.
    """
    found: list[str] = []
    for token in _safe_split(text):
        found.extend(part for part in re.split(r"(;|&&|\|\||\||&)", token) if part in _OPERATORS)
    return found


def _set_options(run_block: str, sign: str) -> list[str]:
    """Return `set` option words in a shell body that use the given sign.

    A substring test for "set -e" is satisfied by the text appearing in a
    comment or an `echo`. This looks for an actual `set` simple command, which
    is what changes the shell's behaviour.
    """
    options: list[str] = []
    for raw_line in run_block.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for segment in _split_simple_commands(_safe_split(stripped)):
            while segment and (segment[0] in _LEADING_WORDS or _TOKEN_ASSIGN_RE.match(segment[0])):
                segment = segment[1:]
            if segment and segment[0] == "set":
                options.extend(word for word in segment[1:] if word.startswith(sign))
    return options


def _enables_errexit(run_block: str) -> bool:
    """True when the body itself turns on exit-on-error."""
    return any("e" in option for option in _set_options(run_block, "-"))


def _disables_errexit(run_block: str) -> bool:
    """True when the body turns exit-on-error back off."""
    return any("e" in option for option in _set_options(run_block, "+"))


_SUBSTITUTION_RE = re.compile(r"\$\((.*)\)\s*$|`(.*)`\s*$")


def _substitution_command(value: str) -> str:
    """Return the shell command inside a `$(...)` or backtick substitution."""
    match = _SUBSTITUTION_RE.search(value)
    if not match:
        return ""
    return (match.group(1) or match.group(2) or "").strip()


def _python_invocations(script_text: str, source: str, keep_substitutions: bool = False) -> list[Invocation]:
    """Return every Python execution in a shell script, with variables expanded.

    Only executions count. `cp scripts/hooks/validate_riskmap.py .` and
    `echo "... validate_riskmap.py failed"` mention a validator but do not run
    it, and must not be read as invocations — otherwise the copy step in
    `validation.yml:183-185` would masquerade as a flagless CI invocation and
    D1 would report the wrong thing.

    Args:
        script_text: The shell script body (a workflow ``run:`` block, or a
            pre-commit ``entry`` plus its ``args``).
        source: Label used in assertion messages.
        keep_substitutions: When True, a variable assigned from a command
            substitution expands to a literal `${NAME}` placeholder that
            survives into `argv`, and the substitution's command is recorded on
            each Invocation. When False (the default) such a variable expands
            to the empty string and disappears.

            The default is the conservative reading for a *prohibition*: D3 and
            D7b ask whether a forbidden flag or path is present, and inventing
            content for an unresolvable expansion could manufacture a
            violation. It is the wrong reading for a *requirement*: the D7a
            file lists reach the validators through exactly such an expansion,
            so under the default the derived argv for those three invocations is
            just `['--block']` and the file list is invisible. Callers that need
            to establish what CI actually passes set this True and execute the
            recorded command.

    Returns:
        List of Invocation records in the order encountered.
    """
    env: dict[str, Any] = {}
    substitutions: dict[str, str] = {}
    found: list[Invocation] = []

    for raw_line in script_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        assignment = _ASSIGN_RE.match(raw_line)
        if assignment:
            name, value = assignment.group(1), assignment.group(2).strip()
            if "$(" in value or "`" in value:
                # Command substitution is not statically resolvable. Either
                # record the name as known-but-empty so downstream references
                # expand away rather than being left as literal `${VAR}` text,
                # or preserve the reference so a caller can run the command.
                if keep_substitutions:
                    substitutions[name] = _substitution_command(value)
                    # Expanding to itself is a fixed point, so `_expand`'s
                    # bounded loop terminates on the first pass and the
                    # placeholder survives into argv.
                    env[name] = f"${{{name}}}"
                else:
                    env[name] = ""
            elif value.startswith("(") and value.endswith(")"):
                env[name] = [_expand(element, env) for element in _safe_split(value[1:-1])]
            else:
                parts = _safe_split(value)
                env[name] = _expand(parts[0], env) if parts else ""
            continue

        tokens: list[str] = []
        for token in _safe_split(stripped):
            expansion = _expand(token, env)
            # An expanded array reference carries several arguments in one
            # token; re-split so each becomes its own argv entry.
            tokens.extend(expansion.split())

        for segment in _split_simple_commands(tokens):
            while segment and (segment[0] in _LEADING_WORDS or _TOKEN_ASSIGN_RE.match(segment[0])):
                segment = segment[1:]
            if not segment:
                continue

            command, rest = segment[0], segment[1:]
            if _INTERPRETER_RE.match(Path(command).name):
                script = next((arg for arg in rest if arg.endswith(".py")), None)
                if script is None:
                    continue
                argv = rest[rest.index(script) + 1 :]
            elif command.endswith(".py"):
                script, argv = command, rest
            else:
                continue

            found.append(
                Invocation(
                    Path(script).name,
                    script,
                    tuple(argv),
                    source,
                    stripped,
                    tuple(sorted(substitutions.items())),
                )
            )

    return found


# Commands that relocate a file. `install` and `ln` are included because either
# would satisfy "get the script to the repository root" just as well as `cp`,
# and D7b prohibits the outcome rather than one spelling of it.
_RELOCATING_COMMANDS = frozenset({"cp", "mv", "install", "ln", "rsync"})


def _copy_commands(script_text: str, source: str) -> list[CopyCommand]:
    """Return every file-relocating command in a shell script, variables expanded.

    Shares `_python_invocations`'s assignment tracking so a copy whose source or
    destination is built from a shell variable is still seen. An implementer
    extending the copy-to-root pattern would plausibly write
    `cp ${PRECOMMIT_DIR}/validate_prose_references.py .`, and a scan that only
    matched literal paths would wave it through.

    Args:
        script_text: The shell script body.
        source: Label used in assertion messages.

    Returns:
        List of CopyCommand records, one per (source operand, destination) pair.
    """
    env: dict[str, Any] = {}
    found: list[CopyCommand] = []

    for raw_line in script_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        assignment = _ASSIGN_RE.match(raw_line)
        if assignment:
            name, value = assignment.group(1), assignment.group(2).strip()
            if "$(" in value or "`" in value:
                env[name] = ""
            elif value.startswith("(") and value.endswith(")"):
                env[name] = [_expand(element, env) for element in _safe_split(value[1:-1])]
            else:
                parts = _safe_split(value)
                env[name] = _expand(parts[0], env) if parts else ""
            continue

        tokens: list[str] = []
        for token in _safe_split(stripped):
            expansion = _expand(token, env)
            tokens.extend(expansion.split())

        for segment in _split_simple_commands(tokens):
            while segment and (segment[0] in _LEADING_WORDS or _TOKEN_ASSIGN_RE.match(segment[0])):
                segment = segment[1:]
            if not segment or Path(segment[0]).name not in _RELOCATING_COMMANDS:
                continue

            operands = [token for token in segment[1:] if not token.startswith("-")]
            if len(operands) < 2:
                continue
            # Last operand is the destination; everything before it is a source.
            destination = operands[-1]
            for operand in operands[:-1]:
                found.append(CopyCommand(operand, destination, source, stripped))

    return found


# ===========================================================================
# Derivation of both surfaces
# ===========================================================================


def _precommit_invocations() -> list[Invocation]:
    """Return every Python invocation declared in .pre-commit-config.yaml."""
    config = yaml.safe_load(_PRECOMMIT_CONFIG.read_text(encoding="utf-8"))
    invocations: list[Invocation] = []
    for repo in config.get("repos", []):
        for hook in repo.get("hooks", []):
            entry = hook.get("entry")
            if not entry:
                continue
            # `args:` are appended by the framework after `entry`, so the
            # effective command line is the concatenation of the two.
            command = " ".join([entry, *(str(a) for a in hook.get("args", []))])
            invocations.extend(_python_invocations(command, f".pre-commit-config.yaml [{hook.get('id')}]"))
    return invocations


def _iter_workflow_run_steps():
    """Yield (source_label, run_block) for every `run:` step in every workflow."""
    for workflow in _workflow_files():
        data = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        for job_id, job in (data.get("jobs") or {}).items():
            for index, step in enumerate(job.get("steps") or []):
                run_block = step.get("run")
                if not run_block:
                    continue
                label = step.get("name") or f"step[{index}]"
                yield f"{workflow.name}::{job_id}::{label}", run_block


def _workflow_invocations() -> list[Invocation]:
    """Return every Python invocation across all `run:` steps in all workflows."""
    invocations: list[Invocation] = []
    for source, run_block in _iter_workflow_run_steps():
        invocations.extend(_python_invocations(run_block, source))
    return invocations


def _workflow_copy_commands() -> list[CopyCommand]:
    """Return every file-relocating command across all `run:` steps in all workflows."""
    copies: list[CopyCommand] = []
    for source, run_block in _iter_workflow_run_steps():
        copies.extend(_copy_commands(run_block, source))
    return copies


def _strictness_flags(invocation: Invocation) -> frozenset[str]:
    """Return the strictness flags carried by an invocation."""
    return frozenset(arg for arg in invocation.argv if arg in STRICTNESS_FLAGS)


def _is_graph_emitting(invocation: Invocation) -> bool:
    """True when the invocation passes any graph-emission flag."""
    return bool(GRAPH_EMISSION_FLAGS.intersection(invocation.argv))


# Derived once at import; every parametrized case below reads from these.
# TestParserFidelity guards against either collapsing to empty, which would
# turn the whole suite green by parsing nothing.
PRECOMMIT_INVOCATIONS = _precommit_invocations()
WORKFLOW_INVOCATIONS = _workflow_invocations()
WORKFLOW_COPY_COMMANDS = _workflow_copy_commands()

# Directory whose validators ADR-037 D7b requires be invoked in place.
_PRECOMMIT_DIR_FRAGMENT = "scripts/hooks/precommit/"

# basename -> repo-relative real path, for every validator a pre-commit hook
# runs out of scripts/hooks/precommit/. Derived, not listed: D7b's reasoning
# applies to any validator in that directory — this set is not scoped to the
# ADR's own named list, so it already covers validators D7/D8 never mention —
# and a new one is governed on arrival the same way the nine ADR-037 D7/D8
# validators are today.
PRECOMMIT_VALIDATORS: dict[str, str] = {
    inv.script: inv.path for inv in PRECOMMIT_INVOCATIONS if _PRECOMMIT_DIR_FRAGMENT in inv.path
}

# script basename -> the flags pre-commit requires of it.
BLOCK_VALIDATORS: dict[str, frozenset[str]] = {}
for _inv in PRECOMMIT_INVOCATIONS:
    _flags = _strictness_flags(_inv)
    if _flags:
        BLOCK_VALIDATORS[_inv.script] = BLOCK_VALIDATORS.get(_inv.script, frozenset()) | _flags

BLOCK_VALIDATOR_NAMES = sorted(BLOCK_VALIDATORS)


def _ci_invocations_of(script: str) -> list[Invocation]:
    """Return every workflow invocation of the named script."""
    return [inv for inv in WORKFLOW_INVOCATIONS if inv.script == script]


# ===========================================================================
# 1. Parser fidelity — these guard every other assertion in this module
# ===========================================================================


class TestParserFidelity:
    """Non-vacuity guards on the derivation itself.

    Every other test here reads from PRECOMMIT_INVOCATIONS and
    WORKFLOW_INVOCATIONS. If either derivation silently returned nothing, D1
    would pass with no validators to check and D3 would pass with no
    invocations to inspect — the "wired but checking nothing" failure that
    ADR-037's Context cites as the motivating bug. These tests are expected to
    pass; their job is to make the failures of D1 and D4 mean something.
    """

    def test_precommit_derivation_finds_block_validators(self):
        """
        Given: .pre-commit-config.yaml as committed
        When: hook entries are parsed for strictness flags
        Then: at least one validator is found carrying one

        A zero result would make every D1 case vacuous, since the D1 tests are
        parametrized over exactly this set.
        """
        assert BLOCK_VALIDATOR_NAMES, (
            "Parsed no strictness-flagged validators out of .pre-commit-config.yaml. "
            f"Expected at least one hook whose entry carries one of {sorted(STRICTNESS_FLAGS)}. "
            "Either the config genuinely stopped using them, or _python_invocations "
            "stopped parsing hook entries — the second would make every D1 case vacuous."
        )

    def test_workflow_derivation_finds_python_invocations(self):
        """
        Given: every workflow under .github/workflows/
        When: each `run:` block is scanned for Python executions
        Then: at least one invocation is found

        A zero result would make D3 vacuous — no invocation to inspect means
        no invocation can violate the prohibition.
        """
        assert WORKFLOW_INVOCATIONS, (
            f"Parsed no Python invocations out of any workflow in {_WORKFLOW_DIR}. "
            "D3 inspects exactly this set, so an empty parse would pass the "
            "prohibition by having nothing to prohibit."
        )

    def test_the_workflow_scan_covers_every_workflow_github_would_run(self):
        """
        Given: the contents of .github/workflows/
        When: the file set this module scans is compared to the files GitHub
              would execute out of that directory
        Then: they are equal, and every workflow declaring a `run:` step is
              reached by the step parse

        Every prohibition here quantifies over the scanned set, so a workflow
        outside it is exempt from all of them at once. GitHub honours `.yaml`
        and `.yml` identically; a `.github/workflows/gate.yaml` copying a
        `precommit/` validator to the root, invoking it by bare basename, and
        pairing `--block` with `--to-graph` would violate D3, D7b and both
        file-list rules simultaneously, and a scan restricted to one extension
        sees none of it.

        The second assertion is the one that keeps the first honest. Equality of
        file *lists* proves nothing if a consumer re-globs the directory for
        itself, which is how the three scan sites diverged in the first place;
        comparing the workflows the step parse actually reached against an
        independent re-derivation shows the scanned set is the one in use.
        """
        on_disk = sorted(
            path.name for path in _WORKFLOW_DIR.iterdir() if path.is_file() and path.suffix in WORKFLOW_SUFFIXES
        )
        scanned = sorted(path.name for path in _workflow_files())
        assert scanned == on_disk, (
            f"The workflow scan does not cover every file GitHub would run.\n"
            f"  on disk ({len(on_disk)}): {on_disk}\n"
            f"  scanned ({len(scanned)}): {scanned}\n"
            f"  missed: {sorted(set(on_disk) - set(scanned))}\n"
            f"GitHub executes every {sorted(WORKFLOW_SUFFIXES)} file in this directory; "
            "a workflow outside the scan is exempt from every prohibition in this module."
        )

        # Independent re-derivation of which workflows declare a `run:` step.
        with_run_steps = set()
        for path in _WORKFLOW_DIR.iterdir():
            if not (path.is_file() and path.suffix in WORKFLOW_SUFFIXES):
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for job in (data.get("jobs") or {}).values():
                if any(step.get("run") for step in (job.get("steps") or [])):
                    with_run_steps.add(path.name)

        parsed = {step.workflow for step in WORKFLOW_STEPS}
        assert parsed == with_run_steps, (
            f"The step parse reached a different set of workflows than the directory "
            f"contains.\n  parsed: {sorted(parsed)}\n  expected: {sorted(with_run_steps)}\n"
            f"  unreached: {sorted(with_run_steps - parsed)}\n"
            "A consumer that enumerates the directory for itself, rather than through "
            "`_workflow_files`, reintroduces the blind spot the previous assertion closes."
        )

    def test_parser_resolves_variable_built_invocation(self):
        """
        Given: validation.yml's graph-validation job, which builds its command
               from VALIDATE_CMD and an indexed GENERATE_ARGS array rather than
               naming the script inline
        When: workflow invocations are derived
        Then: a validate_riskmap.py invocation carrying a graph-emission flag
              is found

        This is the specific blindness D3 must not have. A scan that only
        matches `--block` adjacent to a literal script name never sees this
        call site, and would report D3 satisfied while the one invocation the
        prohibition targets goes uninspected.
        """
        graph_invocations = [inv for inv in WORKFLOW_INVOCATIONS if _is_graph_emitting(inv)]
        assert graph_invocations, (
            "Found no graph-emitting invocation in any workflow. validation.yml's "
            "graph-validation job builds one through VALIDATE_CMD + GENERATE_ARGS; "
            "not seeing it means shell-variable expansion regressed and D3 is now "
            "blind at the only call site it targets."
        )
        assert any(inv.script == "validate_riskmap.py" for inv in graph_invocations), (
            "Graph-emitting invocations were found, but none resolved to "
            f"validate_riskmap.py: {[(i.script, i.source) for i in graph_invocations]}"
        )

    def test_copy_steps_are_not_read_as_invocations(self):
        """
        Given: validation.yml's `cp scripts/hooks/validate_riskmap.py .` steps
        When: workflow invocations are derived
        Then: no invocation originates from a `cp` command

        A copy step names a validator without running it. Counting it as an
        invocation would make D1 report a flagless CI invocation that does not
        exist, and would let a real gap hide behind a false positive.
        """
        copy_derived = [inv for inv in WORKFLOW_INVOCATIONS if inv.line.startswith("cp ")]
        assert not copy_derived, (
            f"`cp` steps were parsed as invocations: {[(i.script, i.line) for i in copy_derived]}. "
            "Only executions may count toward D1/D3."
        )

    def test_precommit_script_basenames_are_unambiguous(self):
        """
        Given: every Python script referenced by a pre-commit hook entry
        When: basenames are compared against full paths
        Then: no basename maps to more than one distinct path

        D1 joins the hook surface to the CI surface on basename, because CI
        copies validators to the repository root before running them (ADR-037
        D5 keeps that arrangement). Two different validators sharing a basename
        would silently conflate, letting one satisfy the other's requirement.
        """
        config = yaml.safe_load(_PRECOMMIT_CONFIG.read_text(encoding="utf-8"))
        paths_by_basename: dict[str, set[str]] = {}
        for repo in config.get("repos", []):
            for hook in repo.get("hooks", []):
                entry = hook.get("entry") or ""
                for token in _safe_split(entry):
                    if token.endswith(".py"):
                        paths_by_basename.setdefault(Path(token).name, set()).add(token)

        collisions = {name: sorted(paths) for name, paths in paths_by_basename.items() if len(paths) > 1}
        assert not collisions, (
            f"Basename collisions among pre-commit validator paths: {collisions}. "
            "D1 matches hook invocations to CI invocations by basename; distinct "
            "validators sharing one would conflate."
        )

    def test_graph_emission_flags_are_real(self):
        """
        Given: the graph-emission flag names GRAPH_EMISSION_FLAGS asserts on
        When: validate_riskmap.py --help is inspected
        Then: every named flag appears

        Renaming a flag without updating this constant would make D3 a
        prohibition on strings nothing produces — present, green, and blind.
        """
        result = subprocess.run(
            [sys.executable, str(_HOOKS_DIR / "validate_riskmap.py"), "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"--help exited {result.returncode}: {result.stderr}"
        missing = sorted(flag for flag in GRAPH_EMISSION_FLAGS if flag not in result.stdout)
        assert not missing, (
            f"GRAPH_EMISSION_FLAGS names flags validate_riskmap.py does not accept: {missing}. "
            "D3 would prohibit a pairing that can no longer occur."
        )


# ===========================================================================
# 2. D1 — strictness monotonicity between pre-commit and CI
# ===========================================================================


def _hook_sources_for(script: str) -> list[str]:
    """Return the pre-commit hook labels that invoke a script with strictness flags."""
    return sorted({inv.source for inv in PRECOMMIT_INVOCATIONS if inv.script == script and _strictness_flags(inv)})


class TestStrictnessCoverage:
    """ADR-037 D1 part 1 — coverage.

    Every validator `.pre-commit-config.yaml` invokes with `--block` has a CI
    invocation that also passes `--block`.

    Coverage is asserted separately from monotonicity, and separately first,
    because monotonicity alone is satisfied *vacuously* by a validator CI never
    runs: an empty flag set is trivially a superset of nothing. A rule
    quantified over the intersection of the two surfaces cannot see a validator
    missing from one of them — which is exactly how three blocking checks came
    to exist only on contributor machines.

    This class therefore quantifies over pre-commit's `--block` hooks. A
    validator absent from CI FAILS here; it does not skip.
    """

    @pytest.mark.parametrize("script", BLOCK_VALIDATOR_NAMES)
    def test_ci_invokes_every_block_hook_with_block(self, script):
        """
        Given: a validator that .pre-commit-config.yaml invokes with a
               strictness flag
        When: every `run:` step in every workflow is searched for an invocation
              of that validator carrying the same flags
        Then: at least one such invocation exists

        "At least one", not "every": ADR-037 D3 exempts graph-emission
        invocations, and D2 covers that exemption by requiring the dedicated
        validation job to run the same corpus with `--block` in the same CI run.
        """
        required = BLOCK_VALIDATORS[script]
        hook_sources = _hook_sources_for(script)
        ci_invocations = _ci_invocations_of(script)

        assert ci_invocations, (
            f"{script} is invoked with {sorted(required)} by {hook_sources} but is not "
            f"invoked by any workflow under {_WORKFLOW_DIR}, and no workflow runs "
            f"`pre-commit` either. The check therefore runs only for contributors who "
            f"chose to install the hooks, so the merge decision depends on their local "
            f"state. ADR-037 D1 part 1 requires a CI invocation carrying {sorted(required)}."
        )

        satisfying = [inv for inv in ci_invocations if required.issubset(_strictness_flags(inv))]
        assert satisfying, (
            f"{script} is invoked with {sorted(required)} by {hook_sources}, but no "
            f"workflow invocation carries those flags. CI invocations found:\n"
            + "\n".join(f"  - {inv.source}: {inv.line}  (argv={list(inv.argv)})" for inv in ci_invocations)
            + "\nADR-037 D1 part 1: blocking locally and advisory in CI is not a "
            "supported state, and neither is blocking locally and absent from CI."
        )


class TestStrictnessMonotonicity:
    """ADR-037 D1 part 2 — monotonicity.

    For any validator invoked from both surfaces, the CI invocation is at least
    as strict as the pre-commit invocation.

    This is deliberately the intersection-shaped rule the ADR warns about, kept
    as a distinct assertion because it is the half that generalizes: it governs
    any future strictness flag, including one CI carries partially. It is not
    load-bearing for the current gap — TestStrictnessCoverage is — and a
    validator absent from CI skips here by design, with the skip reason naming
    the class that does fail on it.
    """

    @pytest.mark.parametrize("script", BLOCK_VALIDATOR_NAMES)
    def test_ci_strictness_flags_are_a_superset_of_hook_strictness_flags(self, script):
        """
        Given: a validator present on both the pre-commit and CI surfaces
        When: the union of strictness flags on each surface is compared
        Then: the CI set is a superset of the hook set

        Skips when the validator has no CI invocation at all: that is the
        coverage failure, reported by TestStrictnessCoverage. Asserting it here
        too would duplicate one finding across two classes.
        """
        ci_invocations = _ci_invocations_of(script)
        if not ci_invocations:
            pytest.skip(
                f"{script} has no CI invocation, so it is outside the intersection this "
                f"rule quantifies over. The coverage half — "
                f"TestStrictnessCoverage::test_ci_invokes_every_block_hook_with_block — "
                f"is what fails on it, by design."
            )

        required = BLOCK_VALIDATORS[script]
        # Union across CI invocations: D3 exempts the graph-emission call site,
        # so the surface as a whole must carry the strictness, not every call.
        ci_flags: frozenset[str] = frozenset().union(*(_strictness_flags(inv) for inv in ci_invocations))

        assert required.issubset(ci_flags), (
            f"{script}: pre-commit strictness {sorted(required)} (from {_hook_sources_for(script)}) "
            f"is not a subset of CI strictness {sorted(ci_flags)}. CI invocations found:\n"
            + "\n".join(f"  - {inv.source}: {inv.line}  (argv={list(inv.argv)})" for inv in ci_invocations)
            + "\nADR-037 D1 part 2: where the two surfaces differ, CI is stricter, never laxer."
        )


# ===========================================================================
# 3. D3 — `--block` must not be paired with graph emission
# ===========================================================================


class TestGraphEmissionExclusion:
    """ADR-037 D3: no invocation pairs `--block` with a graph-emission flag.

    `validate_riskmap.py`'s warn-only `sys.exit` runs before every emission
    block, so the pairing exits without writing a graph file and reports a
    content warning as a generation failure — skipping the diff against the
    committed graph, which is the whole point of that job.

    The live-workflow test passes at authoring time; ADR-037 D3 records that it
    codifies existing practice. The two synthetic tests establish that it would
    not pass if a violation were introduced, in either the literal or the
    variable-built form.

    Deliberately kept flag-only, not widened to ADR-037 D8's flagless governed
    set: D3's own text prohibits pairing graph emission with `--block`
    specifically ("No invocation of `validate_riskmap.py` that passes
    [a graph-emission flag] may also pass `--block`"), not with blocking-ness
    in the abstract the way D1's coverage clause does. The pairing is also
    structurally impossible for a D8 member: GRAPH_EMISSION_FLAGS are options
    of `validate_riskmap.py` alone, and `validate_riskmap.py` itself carries
    `--block` (D2) — it is never a member of UNFLAGGED_BLOCKING_SCRIPTS, and no
    D8 validator defines a graph-emission flag at all. There is no invocation
    this class could miss by staying flag-keyed.
    """

    def test_no_workflow_pairs_block_with_graph_emission(self):
        """
        Given: every Python invocation across all workflows, with shell
               variables expanded
        When: invocations carrying a graph-emission flag are checked for
              `--block`
        Then: none carry both
        """
        violations = [
            inv
            for inv in WORKFLOW_INVOCATIONS
            if _is_graph_emitting(inv) and STRICTNESS_FLAGS.intersection(inv.argv)
        ]
        assert not violations, (
            "ADR-037 D3 prohibits pairing a strictness flag with graph emission:\n"
            + "\n".join(f"  - {inv.source}: {inv.line}  (argv={list(inv.argv)})" for inv in violations)
            + "\nThe warn-only exit precedes every emission block, so the process "
            "terminates before writing a graph and the job reports a generation "
            "failure for what is actually a content warning."
        )

    def test_detector_flags_literal_block_with_graph_flag(self):
        """
        Given: a synthetic `run:` block naming the script inline and passing
               both `--block` and `--to-graph`
        When: invocations are derived and checked
        Then: the pairing is detected

        Fidelity check on the plain form.
        """
        run_block = 'python3 validate_riskmap.py --force --block --to-graph "${temp_file}"\n'
        invocations = _python_invocations(run_block, "synthetic::literal")
        paired = [inv for inv in invocations if _is_graph_emitting(inv) and "--block" in inv.argv]
        assert paired, f"Detector missed a literal --block + --to-graph pairing. Parsed: {invocations}"

    def test_detector_flags_variable_built_block_with_graph_flag(self):
        """
        Given: a synthetic `run:` block in the shape validation.yml's
               graph-validation job actually uses — script name held in
               VALIDATE_CMD, emission flags in an indexed array, `--block`
               reached only after expansion
        When: invocations are derived and checked
        Then: the pairing is detected

        This is the blindness the prohibition cannot afford. If this test
        fails, test_no_workflow_pairs_block_with_graph_emission is passing
        because it cannot see the call site, not because the call site is
        clean.
        """
        run_block = (
            'VALIDATE_CMD="validate_riskmap.py"\n'
            'STRICT="--block"\n'
            'GENERATE_ARGS=("--to-graph" "--to-controls-graph" "--to-risk-graph")\n'
            'for i in "${!GENERATE_ARGS[@]}"; do\n'
            '    gen_args="${GENERATE_ARGS[$i]}"\n'
            '    if ! python3 ${VALIDATE_CMD} --force ${STRICT} ${gen_args} "${temp_file}"; then\n'
            '        echo "failed"\n'
            "    fi\n"
            "done\n"
        )
        invocations = _python_invocations(run_block, "synthetic::variable-built")
        paired = [inv for inv in invocations if _is_graph_emitting(inv) and "--block" in inv.argv]
        assert paired, (
            "Detector missed a variable-built --block + graph-emission pairing. "
            f"Parsed: {invocations}. The real graph-validation job is written in this "
            "shape, so a detector that cannot resolve it is blind exactly where D3's "
            "risk lives."
        )


# ===========================================================================
# 4. D7b — the precommit/ validators are invoked in place, never copied
# ===========================================================================


class TestPrecommitValidatorsRunInPlace:
    """ADR-037 D7b: new CI invocations run scripts at their real paths.

    Copying a `scripts/hooks/precommit/` validator to the repository root
    breaks two module-relative derivations at once:

    1. `_HOOKS_DIR = Path(__file__).resolve().parent.parent` (used by every
       validator in that directory to put `scripts/hooks` on `sys.path` for its
       `precommit.*` sibling imports).
    2. `_DEFAULT_SCHEMA_DIR = Path(__file__).resolve().parent.parent.parent.parent
       / "risk-map" / "schemas"` in `validate_yaml_prose_subset.py` and
       `validate_prose_references.py` — four levels up from
       `scripts/hooks/precommit/` lands on the repo root; four levels up from
       the repo root lands outside the repository.

    The first failure is loud, and that is what makes the second dangerous. An
    implementer who copies only the script gets an ImportError and fixes it the
    obvious way — by copying the `precommit/` package alongside, mirroring what
    `validation.yml` already does for `riskmap_validator`. That silences the
    loud failure and leaves the silent one: the schema directory now resolves
    outside the repository, `find_prose_fields` hits
    `if schema_path is None: return` (`_prose_fields.py:284-292`), and the job
    exits 0 having inspected nothing.

    This is measured, not reasoned about — see
    test_relocated_validator_goes_vacuous_while_in_place_catches below, which
    observes exit 1 with a diagnostic in place and exit 0 with empty stderr
    relocated, from the same poisoned corpus.

    D5 is untouched by this class. D5 keeps the five existing copy-to-root
    steps for `validate_riskmap.py`, `validate_control_risk_references.py`,
    `validate_framework_references.py` and `riskmap_validator/`; nothing here
    asserts anything about those. D7b prohibits *extending* the pattern to the
    `precommit/` validators, which D5's own text records as not being a
    copy-to-root change.

    The structural prohibitions pass today because D7's own CI invocations —
    `validation.yml:349`, `:385` and `:421` — already run these three
    validators at their real `scripts/hooks/precommit/` path, not because
    there is nothing yet to check: this class predates those invocations
    landing, when it was a forward guard, and it stayed green through their
    addition rather than turning vacuous. The synthetic-detector tests are
    what establish the prohibitions would actually catch a violation instead
    of passing for lack of one.
    """

    def test_no_workflow_copies_a_precommit_validator(self):
        """
        Given: every file-relocating command across all workflows
        When: sources are matched against the derived precommit/ validator set
        Then: none of them relocates one

        Forward guard: today no workflow mentions these scripts at all. The
        moment D7 wiring lands, this is the assertion that rejects the
        copy-to-root spelling of it.
        """
        violations = [
            copy
            for copy in WORKFLOW_COPY_COMMANDS
            if any(
                copy.source_path.endswith(name) or _PRECOMMIT_DIR_FRAGMENT in copy.source_path
                for name in PRECOMMIT_VALIDATORS
            )
        ]
        assert not violations, (
            "ADR-037 D7b prohibits relocating a scripts/hooks/precommit/ validator:\n"
            + "\n".join(f"  - {c.source}: {c.line}  ({c.source_path} -> {c.destination})" for c in violations)
            + "\nThese validators derive sys.path and their default --schema-dir from "
            "Path(__file__); relocating them makes field discovery return silently and "
            "the job exit 0 having inspected nothing. Invoke them in place instead."
        )

    def test_workflow_invocations_of_precommit_validators_use_real_paths(self):
        """
        Given: every workflow invocation of a derived precommit/ validator
        When: the invoked path is compared to the validator's real path
        Then: they match

        Catches the other half of the same mistake — invoking a bare basename
        from the repository root after copying it there by some means this
        suite's copy scan did not model (an archive extraction, a checkout into
        a different layout, a `python -c` shim).
        """
        violations = [
            inv
            for inv in WORKFLOW_INVOCATIONS
            if inv.script in PRECOMMIT_VALIDATORS and inv.path != PRECOMMIT_VALIDATORS[inv.script]
        ]
        assert not violations, (
            "ADR-037 D7b requires these validators to be invoked at their real paths:\n"
            + "\n".join(
                f"  - {inv.source}: invoked as {inv.path!r}, "
                f"expected {PRECOMMIT_VALIDATORS[inv.script]!r}\n      {inv.line}"
                for inv in violations
            )
            + "\nA path other than the real one changes what Path(__file__) resolves to, "
            "which is what these validators derive their schema directory from."
        )

    def test_copy_detector_flags_literal_copy_to_root(self):
        """
        Given: a synthetic `run:` block copying a precommit/ validator to the
               repository root, in the shape validation.yml's existing copy
               steps use
        When: copy commands are derived
        Then: the relocation is detected

        Fidelity check on the plain form.
        """
        run_block = (
            "cp scripts/hooks/precommit/validate_yaml_prose_subset.py .\n"
            "mkdir -p precommit\n"
            "cp -r scripts/hooks/precommit/* ./precommit/\n"
        )
        copies = _copy_commands(run_block, "synthetic::literal-copy")
        flagged = [c for c in copies if "validate_yaml_prose_subset.py" in c.source_path]
        assert flagged, f"Detector missed a literal copy-to-root of a precommit/ validator. Parsed: {copies}"

    def test_copy_detector_flags_variable_built_copy_to_root(self):
        """
        Given: a synthetic `run:` block copying a precommit/ validator through
               shell variables rather than a literal path
        When: copy commands are derived
        Then: the relocation is detected

        This is the version a real implementer writes without noticing. A
        detector that only matches literal paths would wave it through, and the
        prohibition would be present, green, and blind — the same failure mode
        the D3 detector tests guard against.
        """
        run_block = (
            'PRECOMMIT_DIR="scripts/hooks/precommit"\n'
            'VALIDATORS=("validate_yaml_prose_subset.py" "validate_prose_references.py")\n'
            'for v in "${VALIDATORS[@]}"; do\n'
            '    cp "${PRECOMMIT_DIR}/${v}" .\n'
            "done\n"
        )
        copies = _copy_commands(run_block, "synthetic::variable-built-copy")
        flagged = [c for c in copies if _PRECOMMIT_DIR_FRAGMENT in c.source_path]
        assert flagged, (
            "Detector missed a variable-built copy-to-root of a precommit/ validator. "
            f"Parsed: {copies}. Extending the copy-to-root pattern is most likely to be "
            "written this way, so a detector blind to it protects nothing."
        )

    def test_path_detector_flags_bare_basename_invocation(self):
        """
        Given: a synthetic `run:` block invoking a precommit/ validator by bare
               basename from the repository root
        When: invocations are derived
        Then: the invoked path is visibly not the real path

        Fidelity check for test_workflow_invocations_of_precommit_validators_use_real_paths,
        which is vacuous today.
        """
        run_block = "python3 validate_prose_references.py risk-map/yaml/risks.yaml --block\n"
        invocations = _python_invocations(run_block, "synthetic::bare-basename")
        assert invocations, f"Detector parsed no invocation at all from {run_block!r}"
        assert invocations[0].path == "validate_prose_references.py", (
            f"Invocation.path must preserve the path as written; got {invocations[0].path!r}"
        )
        assert invocations[0].path != PRECOMMIT_VALIDATORS.get("validate_prose_references.py"), (
            "A bare-basename invocation must not compare equal to the real path, "
            "or the D7b path check cannot distinguish them."
        )

    def test_relocated_validator_goes_vacuous_while_in_place_catches(self, tmp_path):
        """
        Given: one poisoned corpus, and validate_yaml_prose_subset.py run two
               ways against it — in place, and relocated to the corpus root
               with its precommit/ package copied alongside (the arrangement an
               implementer reaches after fixing the ImportError)
        When: both runs pass --block and no explicit --schema-dir, so each uses
              its own Path(__file__)-derived default
        Then: the in-place run exits non-zero and names the violation; the
              relocated run exits 0 and reports nothing

        The behavioural anchor. It reasons about no paths and asserts no
        string: it observes that relocation changes the verdict on identical
        input, which is the entire evidentiary basis for D7b.

        If this test ever fails because the relocated run *also* catches the
        violation, the hazard has been fixed — revisit D7b's rationale, but
        keep the prohibition, which stands independently on the sys.path
        derivation the same relocation breaks.

        tmp_path sits several levels below /tmp, so the relocated copy's
        four-levels-up schema derivation lands on a directory that does not
        contain risk-map/schemas — reproducing CI's condition rather than
        depending on it.
        """
        validator = _HOOKS_DIR / "precommit" / "validate_yaml_prose_subset.py"
        yaml_dir = _yaml_dir(tmp_path)
        # shortDescription is a prose field in the real risks.schema.json, so the
        # in-place arm resolves it through the repository's actual schemas.
        poisoned = {
            "risks": [{"id": "riskProbe", "title": "Probe", "shortDescription": ["See https://example.com here."]}]
        }
        (yaml_dir / "risks.yaml").write_text(yaml.dump(poisoned), encoding="utf-8")

        in_place = subprocess.run(
            [sys.executable, str(validator), "risk-map/yaml/risks.yaml", "--block"],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        assert in_place.returncode != 0, (
            f"Harness precondition failed: the in-place run should catch the injected "
            f"inline-URL violation; got {in_place.returncode}\n"
            f"stdout: {in_place.stdout}\nstderr: {in_place.stderr}"
        )
        assert "example.com" in in_place.stderr, (
            f"In-place run exited non-zero but did not name the violation, so it may "
            f"have failed for an unrelated reason.\nstderr: {in_place.stderr}"
        )

        # Reproduce copy-to-root the way an implementer would after hitting the
        # ImportError: script to the root, precommit/ package alongside it.
        shutil.copy2(validator, tmp_path / validator.name)
        shutil.copytree(_HOOKS_DIR / "precommit", tmp_path / "precommit", dirs_exist_ok=True)

        relocated = subprocess.run(
            [sys.executable, validator.name, "risk-map/yaml/risks.yaml", "--block"],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        assert relocated.returncode == 0 and "example.com" not in relocated.stderr, (
            "The relocated copy caught the violation. D7b's rationale rests on it NOT "
            "doing so: the four-levels-up --schema-dir derivation is expected to land "
            "outside the repository, making find_prose_fields return silently. If this "
            "assertion fails the hazard has changed — re-derive D7b's justification, and "
            "keep the prohibition on the sys.path grounds regardless.\n"
            f"exit: {relocated.returncode}\nstdout: {relocated.stdout}\n"
            f"stderr: {relocated.stderr}"
        )


# ===========================================================================
# 5. D4 — behavioural non-vacuity
# ===========================================================================
#
# Each validator gets a probe that writes two corpora into a temporary
# directory: one clean, one carrying a single deliberately injected warn-level
# violation. The probes are what turn "the flag is present" into "the flag
# changes the verdict".
#
# Argument order matters. Probe positionals are placed FIRST, before any
# derived CI arguments and before the probe's own options, because
# validate_prose_references.py declares `--id-sources` with nargs="+": a
# positional following it is swallowed as another id-source, `files` ends up
# empty, and main() exits 0 immediately. That produces a passing test that
# validated nothing. Probe options go LAST so they win over any conflicting
# derived value (argparse store actions are last-wins).
#
# Probes write their poisoned content at the canonical repo-relative paths
# (risk-map/yaml/...), so a derived CI argument naming such a path resolves
# inside the temporary corpus rather than escaping to the real one.


class BlockProbe(NamedTuple):
    """A validator plus the means to trigger exactly one of its warn-level checks.

    Attributes:
        script_path: Real on-disk path to the validator.
        write_corpus: Callable (base_dir, poisoned) -> None that materializes a
            corpus under base_dir. With poisoned=False the corpus is clean.
        positionals: File arguments, repo-relative, placed before all options.
        enabling_args: Arguments without which the validator does not examine
            the corpus at all. `validate_riskmap.py` and
            `validate_framework_references.py` gate on git-staged files unless
            given `--force`; run in a temporary directory without it, `git diff
            --cached` fails, the validator prints "skipping validation" and
            exits 0. That is a pass for the wrong reason, so the validator tier
            supplies these explicitly. The CI tier deliberately does not — see
            TestCIInvocationCatchesViolation.
        options: Non-strictness options the validator needs to read the
            temporary corpus rather than the real one.
        marker: A string that must appear in warn-mode output when poisoned —
            proves the intended check fired, not some unrelated one.
        warn_check: Which warn-only check the poison triggers, for docs.
    """

    script_path: Path
    write_corpus: Callable[[Path, bool], None]
    positionals: tuple[str, ...]
    enabling_args: tuple[str, ...]
    options: tuple[str, ...]
    marker: str
    warn_check: str


def _yaml_dir(base: Path) -> Path:
    """Create and return base/risk-map/yaml/."""
    path = base / "risk-map" / "yaml"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _schema_dir(base: Path) -> Path:
    """Create and return base/risk-map/schemas/."""
    path = base / "risk-map" / "schemas"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_mock_prose_schema(schema_dir: Path, entity: str, ids: list[str]) -> None:
    """Write a minimal schema marking `description` as a prose field.

    The prose linters discover fields by introspecting for the
    `riskmap.schema.json#/definitions/utils/text` $ref, so a mock schema
    declaring that ref is enough to make a field visible to them. Same shape
    as the helper in test_validate_yaml_prose_subset.py.
    """
    prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
    schema = {
        "$id": f"mock_{entity}s.schema.json",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {f"{entity}s": {"type": "array", "items": {"$ref": f"#/definitions/{entity}"}}},
        "definitions": {
            entity: {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "enum": ids},
                    "title": {"type": "string"},
                    "description": prose_ref,
                },
            }
        },
    }
    (schema_dir / f"{entity}s.schema.json").write_text(json.dumps(schema), encoding="utf-8")


# --- corpus writers ---------------------------------------------------------

# Two mutually-referencing components, so ComponentEdgeValidator finds valid
# back-edges and neither component is isolated. That matters: CI invokes
# validate_riskmap.py without --allow-isolated, so an isolated component would
# make the poisoned run exit 1 for the wrong reason and turn D4 falsely green.
_COMPONENTS: dict[str, Any] = {
    "components": [
        {
            "id": "componentAlpha",
            "title": "Alpha",
            "category": "componentsInfrastructure",
            "subcategory": "componentsData",
            "edges": {"to": ["componentBeta"], "from": []},
        },
        {
            "id": "componentBeta",
            "title": "Beta",
            "category": "componentsInfrastructure",
            "subcategory": "componentsData",
            "edges": {"to": [], "from": ["componentAlpha"]},
        },
    ],
    "categories": [
        {
            "id": "componentsInfrastructure",
            "title": "Infrastructure",
            "subcategory": [{"id": "componentsData", "title": "Data"}],
        }
    ],
}


def _write_riskmap_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_riskmap.py; poison = controls↔components mirror drift."""
    yaml_dir = _yaml_dir(base)
    components = (
        ["componentAlpha", "componentProbeDoesNotExist"] if poisoned else ["componentAlpha", "componentBeta"]
    )
    controls = {
        "controls": [
            {
                "id": "controlProbe",
                "title": "Probe Control",
                "category": "controlsModel",
                "components": components,
                "risks": [],
                "personas": [],
            }
        ]
    }
    (yaml_dir / "components.yaml").write_text(yaml.dump(_COMPONENTS), encoding="utf-8")
    (yaml_dir / "controls.yaml").write_text(yaml.dump(controls), encoding="utf-8")
    (yaml_dir / "risks.yaml").write_text(yaml.dump({"risks": []}), encoding="utf-8")


def _write_framework_refs_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_framework_references.py; poison = deprecated-persona reference."""
    yaml_dir = _yaml_dir(base)
    frameworks = {
        "frameworks": [
            {
                "id": "mitre-atlas",
                "name": "MITRE ATLAS",
                "fullName": "Adversarial Threat Landscape for AI Systems",
                "description": "Probe framework entry.",
                "baseUri": "https://atlas.mitre.org",
                "applicableTo": ["risks", "controls"],
            }
        ]
    }
    current = {"id": "personaModelProvider", "title": "Model Provider", "description": ["A current persona."]}
    deprecated = {
        "id": "personaModelCreator",
        "title": "Model Creator",
        "description": ["Legacy persona retained for backward compatibility."],
        "deprecated": True,
    }
    personas = {"personas": [current, deprecated] if poisoned else [current]}
    referenced = "personaModelCreator" if poisoned else "personaModelProvider"
    controls = {"controls": [{"id": "controlProbe", "title": "Probe Control", "personas": [referenced]}]}
    risks = {"risks": [{"id": "riskProbe", "title": "Probe Risk", "personas": ["personaModelProvider"]}]}

    (yaml_dir / "frameworks.yaml").write_text(yaml.dump(frameworks), encoding="utf-8")
    (yaml_dir / "personas.yaml").write_text(yaml.dump(personas), encoding="utf-8")
    (yaml_dir / "controls.yaml").write_text(yaml.dump(controls), encoding="utf-8")
    (yaml_dir / "risks.yaml").write_text(yaml.dump(risks), encoding="utf-8")


# Five questions satisfies the count floor (COUNT_MIN=5) and each uses an
# approved opener, so the clean corpus trips none of the four structural rules.
_CLEAN_IDENTIFICATION_QUESTIONS = [
    "Do you own the model weights?",
    "Do you publish the model to a registry?",
    "Do you control the training data pipeline?",
    "Are you responsible for evaluating model behaviour?",
    "Does your team operate the serving stack?",
]


def _write_identification_questions_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_identification_questions.py; poison = missing block on a live persona."""
    yaml_dir = _yaml_dir(base)
    persona: dict[str, Any] = {"id": "personaProbe", "title": "Probe Persona", "description": ["A probe persona."]}
    if not poisoned:
        persona["identificationQuestions"] = _CLEAN_IDENTIFICATION_QUESTIONS
    (yaml_dir / "personas.yaml").write_text(yaml.dump({"personas": [persona]}), encoding="utf-8")


def _write_prose_subset_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_yaml_prose_subset.py; poison = inline URL in prose (ADR-017 D4)."""
    yaml_dir = _yaml_dir(base)
    _write_mock_prose_schema(_schema_dir(base), "risk", ["riskProbe"])
    description = ["See https://example.com for details."] if poisoned else ["Clean prose with **bold** text."]
    risks = {"risks": [{"id": "riskProbe", "title": "Probe Risk", "description": description}]}
    (yaml_dir / "risks.yaml").write_text(yaml.dump(risks), encoding="utf-8")


def _write_prose_references_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_prose_references.py; poison = unresolvable intra-doc sentinel (ADR-016 D6)."""
    yaml_dir = _yaml_dir(base)
    _write_mock_prose_schema(_schema_dir(base), "risk", ["riskProbe"])
    description = ["The {{riskProbeDoesNotExist}} applies here."] if poisoned else ["Clean prose here."]
    risks = {"risks": [{"id": "riskProbe", "title": "Probe Risk", "description": description}]}
    (yaml_dir / "risks.yaml").write_text(yaml.dump(risks), encoding="utf-8")
    # An empty index makes sentinel resolution deterministic: the poisoned
    # sentinel resolves against nothing, the clean prose has none to resolve.
    (yaml_dir / "probe-index.yaml").write_text(yaml.dump({"risks": []}), encoding="utf-8")


# --- probe registry ---------------------------------------------------------

BLOCK_PROBES: dict[str, BlockProbe] = {
    "validate_riskmap.py": BlockProbe(
        script_path=_HOOKS_DIR / "validate_riskmap.py",
        write_corpus=_write_riskmap_corpus,
        positionals=(),
        enabling_args=("--force",),
        options=(),
        marker="componentProbeDoesNotExist",
        warn_check="check_controls_components_mirror (ADR-020 D7)",
    ),
    "validate_framework_references.py": BlockProbe(
        script_path=_HOOKS_DIR / "validate_framework_references.py",
        write_corpus=_write_framework_refs_corpus,
        positionals=(),
        enabling_args=("--force",),
        options=(),
        marker="personaModelCreator",
        warn_check="check_deprecated_persona_usage (ADR-021 D8)",
    ),
    "validate_identification_questions.py": BlockProbe(
        script_path=_HOOKS_DIR / "precommit" / "validate_identification_questions.py",
        write_corpus=_write_identification_questions_corpus,
        positionals=("risk-map/yaml/personas.yaml",),
        enabling_args=(),
        options=(),
        marker="personaProbe",
        warn_check="identificationQuestions presence rule (Rule 0)",
    ),
    "validate_yaml_prose_subset.py": BlockProbe(
        script_path=_HOOKS_DIR / "precommit" / "validate_yaml_prose_subset.py",
        write_corpus=_write_prose_subset_corpus,
        positionals=("risk-map/yaml/risks.yaml",),
        enabling_args=(),
        options=("--schema-dir", "risk-map/schemas"),
        marker="riskProbe",
        warn_check="inline-URL rejection (ADR-017 D4)",
    ),
    "validate_prose_references.py": BlockProbe(
        script_path=_HOOKS_DIR / "precommit" / "validate_prose_references.py",
        write_corpus=_write_prose_references_corpus,
        positionals=("risk-map/yaml/risks.yaml",),
        enabling_args=(),
        options=("--schema-dir", "risk-map/schemas", "--id-sources", "risk-map/yaml/probe-index.yaml"),
        marker="riskProbeDoesNotExist",
        warn_check="intra-doc sentinel resolution (ADR-016 D6)",
    ),
}


def _run_probe(
    probe: BlockProbe,
    cwd: Path,
    extra: tuple[str, ...],
    with_enabling_args: bool = True,
) -> subprocess.CompletedProcess:
    """Run a probe's validator against a corpus directory.

    Positionals lead, then enabling args, then any caller-supplied arguments,
    then the probe's own options — see the ordering note above the probe
    registry.

    Args:
        with_enabling_args: The CI tier passes False so that the derived
            workflow arguments stand alone. If a workflow invocation omitted
            `--force`, the validator would skip the corpus and exit 0, and that
            must surface as a failure rather than be papered over here.
    """
    command = [
        sys.executable,
        str(probe.script_path),
        *probe.positionals,
        *(probe.enabling_args if with_enabling_args else ()),
        *extra,
        *probe.options,
    ]
    return subprocess.run(command, capture_output=True, text=True, cwd=str(cwd))


class TestBlockFlagChangesBehaviour:
    """D4, validator tier: `--block` demonstrably changes the verdict.

    This is the precondition for D1 and D2 being worth anything — if the flag
    were inert, adding it to a workflow would be a no-op dressed as a fix.
    These tests are expected to pass: all five validators already implement the
    toggle correctly. What is missing is the CI wiring, which the next class
    covers.
    """

    def test_every_block_validator_has_a_behavioural_probe(self):
        """
        Given: the derived set of strictness-flagged pre-commit validators
        When: compared against the probe registry
        Then: every one has a probe

        Applies the same derive-don't-enumerate rule to D4 that D1 uses. A
        validator that gains `--block` in pre-commit tomorrow fails here until
        someone writes a probe that triggers one of its warn-level checks,
        rather than being quietly excluded from behavioural coverage.
        """
        unprobed = sorted(set(BLOCK_VALIDATOR_NAMES) - set(BLOCK_PROBES))
        assert not unprobed, (
            f"No behavioural probe for strictness-flagged validators: {unprobed}. "
            "Each needs a corpus writer that triggers one of its warn-level checks, "
            "so its --block can be shown to change a verdict rather than merely "
            "being present on a command line."
        )

        stale = sorted(set(BLOCK_PROBES) - set(BLOCK_VALIDATOR_NAMES))
        assert not stale, (
            f"Probes exist for validators no longer invoked with a strictness flag "
            f"by pre-commit: {stale}. Either the hook lost its flag or the probe is dead."
        )

    @pytest.mark.parametrize("script", sorted(BLOCK_PROBES))
    def test_block_flag_changes_exit_code_on_injected_violation(self, script, tmp_path):
        """
        Given: a temporary corpus carrying one injected warn-level violation
        When: the validator runs over it with and without `--block`
        Then: the warn run exits 0 and names the violation; the block run
              exits non-zero

        Both halves are asserted. Exit codes differing is not enough on its
        own — a validator that crashed under `--block` would also differ. The
        marker assertion pins that the intended check fired and produced
        actionable output in warn mode, per ADR-025 D10.
        """
        probe = BLOCK_PROBES[script]
        probe.write_corpus(tmp_path, True)

        warn = _run_probe(probe, tmp_path, ())
        block = _run_probe(probe, tmp_path, ("--block",))

        assert warn.returncode == 0, (
            f"{script}: warn-only mode should exit 0 on the poisoned corpus "
            f"({probe.warn_check}); got {warn.returncode}\n"
            f"stdout: {warn.stdout}\nstderr: {warn.stderr}"
        )
        combined = warn.stdout + warn.stderr
        assert probe.marker in combined, (
            f"{script}: warn-only output does not name {probe.marker!r}, so the "
            f"injected violation may not have reached {probe.warn_check} at all. "
            f"Exit 0 alone cannot distinguish 'clean' from 'never ran'.\n"
            f"stdout: {warn.stdout}\nstderr: {warn.stderr}"
        )
        assert block.returncode != 0, (
            f"{script}: --block did not change the verdict on a corpus carrying a "
            f"{probe.warn_check} violation; got {block.returncode}. The flag is inert, "
            f"so adding it to a workflow would change nothing.\n"
            f"stdout: {block.stdout}\nstderr: {block.stderr}"
        )

    @pytest.mark.parametrize("script", sorted(BLOCK_PROBES))
    def test_clean_corpus_exits_zero_with_and_without_block(self, script, tmp_path):
        """
        Given: the same corpus with the violation removed
        When: the validator runs over it with and without `--block`
        Then: both exit 0

        Controls the previous test. Without this, a validator that exited
        non-zero on everything would satisfy the block assertion for the wrong
        reason, and the poison would be proving nothing.
        """
        probe = BLOCK_PROBES[script]
        probe.write_corpus(tmp_path, False)

        warn = _run_probe(probe, tmp_path, ())
        block = _run_probe(probe, tmp_path, ("--block",))

        assert warn.returncode == 0, (
            f"{script}: clean corpus should exit 0 without --block; got {warn.returncode}\n"
            f"stdout: {warn.stdout}\nstderr: {warn.stderr}"
        )
        assert block.returncode == 0, (
            f"{script}: clean corpus should exit 0 with --block; got {block.returncode}. "
            f"--block must promote existing warnings, never manufacture one.\n"
            f"stdout: {block.stdout}\nstderr: {block.stderr}"
        )


class TestCIInvocationCatchesViolation:
    """D4, CI tier: the command CI actually runs catches the violation.

    The previous class establishes that `--block` works. This one establishes
    that CI passes it. It takes the argument list derived from the workflow and
    runs the real validator with it against the poisoned corpus: if the derived
    arguments omit the strictness flag, the run exits 0 and the test fails —
    a behavioural statement about the merge gate, not a string match on YAML.

    Graph-emitting invocations are excluded as candidates: ADR-037 D3 forbids
    `--block` there, and D2 covers the same corpus in the dedicated job during
    the same CI run.

    The validator is run from its real path rather than from a copied root, so
    this suite neither depends on nor perturbs the copy-to-root arrangement
    ADR-037 D5 keeps in place. What is under test is the argument list, which
    is where strictness lives.
    """

    @pytest.mark.parametrize("script", sorted(BLOCK_PROBES))
    def test_ci_invocations_carry_enabling_arguments(self, script):
        """
        Given: a validator whose probe declares enabling arguments
        When: every non-graph-emitting CI invocation of it is inspected
        Then: each carries those arguments

        The `--force` drift guard. `validate_riskmap.py` and
        `validate_framework_references.py` decide what to validate from
        `git diff --cached`. In a CI checkout where that command fails or
        returns nothing, they print "skipping validation" and exit 0 — a green
        job that inspected no file. `--force` is what makes them examine the
        corpus unconditionally, so losing it converts a real gate into a
        vacuous one without any visible failure.

        Both invocations carry it today; this keeps a future edit from dropping
        it. The behavioural counterpart is the marker precondition in
        test_derived_ci_arguments_fail_on_injected_violation, which fails if a
        CI invocation ever stops reaching the check at all — that assertion
        exists because this exact trap caught this suite's own harness during
        authoring.

        A validator with no enabling arguments is not thereby unconditioned.
        For the three file-argument validators the enabling input is the file
        list: handed none, `validate_yaml_prose_subset.py` and
        `validate_prose_references.py` exit 0 without opening a file. That case
        is asserted here rather than skipped past, and the list's completeness
        is established by TestCIFileListsAreDerivedAndComplete.
        """
        probe = BLOCK_PROBES[script]
        if not probe.enabling_args:
            governed = [
                hook_id for hook_id, hook in FILE_ARGUMENT_BLOCK_HOOKS.items() if _hook_script(hook) == script
            ]
            assert governed, (
                f"{script} declares no enabling arguments and its pre-commit hook passes no "
                f"filenames, so nothing establishes that a CI invocation of it examines any "
                f"input at all. Either the probe needs enabling arguments, or the hook needs "
                f"pass_filenames — as it stands this is a validator that can run, report "
                f"success, and have read nothing."
            )
            # Its enabling input is the derived file list, asserted in section 6.
            return

        candidates = [inv for inv in _ci_invocations_of(script) if not _is_graph_emitting(inv)]
        if not candidates:
            pytest.skip(f"{script} has no CI invocation; TestStrictnessCoverage is what fails on that.")

        missing = [
            (inv, sorted(set(probe.enabling_args) - set(inv.argv)))
            for inv in candidates
            if not set(probe.enabling_args).issubset(inv.argv)
        ]
        assert not missing, (
            f"{script}: CI invocations missing arguments without which the validator "
            f"does not examine the corpus at all:\n"
            + "\n".join(f"  - {inv.source}: missing {gap}\n      {inv.line}" for inv, gap in missing)
            + f"\nWithout {sorted(probe.enabling_args)} this validator skips validation and "
            f"exits 0, which is a passing job that checked nothing."
        )

    @pytest.mark.parametrize("script", BLOCK_VALIDATOR_NAMES)
    def test_derived_ci_arguments_fail_on_injected_violation(self, script, tmp_path):
        """
        Given: the argument list a workflow passes to a strictness-flagged
               validator, and a corpus carrying one injected warn-level
               violation
        When: the validator runs with exactly those arguments
        Then: it exits non-zero

        The clean corpus is checked first with the same arguments and must exit
        0. That separates "CI catches this" from "CI fails on everything", so a
        harness fault cannot masquerade as a pass.
        """
        probe = BLOCK_PROBES.get(script)
        if probe is None:
            pytest.fail(
                f"No behavioural probe registered for {script}; "
                "test_every_block_validator_has_a_behavioural_probe explains the gap."
            )

        candidates = [inv for inv in _ci_invocations_of(script) if not _is_graph_emitting(inv)]
        assert candidates, (
            f"No non-graph-emitting workflow invocation of {script} exists, so no CI "
            f"command can be run against the poisoned corpus. A {probe.warn_check} "
            f"violation reaches `main`/`develop` unopposed: pre-commit blocks it, CI "
            f"never looks, and no workflow runs `pre-commit` either.\n"
            f"All workflow invocations of {script}: "
            f"{[(i.source, list(i.argv)) for i in _ci_invocations_of(script)] or 'none'}"
        )

        failures: list[str] = []
        # Directories are named by loop index, not by a hash of the source.
        # Two invocations in one step share a source label, so a hash-derived
        # name raised FileExistsError and aborted before the second was
        # evaluated; and `hash()` is PYTHONHASHSEED-randomised, so the
        # artefacts a failure leaves behind were not reproducible either.
        for index, invocation in enumerate(candidates):
            clean_dir = tmp_path / f"clean-{index}"
            clean_dir.mkdir()
            probe.write_corpus(clean_dir, False)
            clean = _run_probe(probe, clean_dir, invocation.argv, with_enabling_args=False)
            assert clean.returncode == 0, (
                f"Harness precondition failed: {invocation.source} arguments "
                f"{list(invocation.argv)} exit {clean.returncode} on a CLEAN corpus. "
                f"The poisoned result below would be meaningless.\n"
                f"stdout: {clean.stdout}\nstderr: {clean.stderr}"
            )

            poisoned_dir = tmp_path / f"poisoned-{index}"
            poisoned_dir.mkdir()
            probe.write_corpus(poisoned_dir, True)
            poisoned = _run_probe(probe, poisoned_dir, invocation.argv, with_enabling_args=False)
            poisoned_output = poisoned.stdout + poisoned.stderr
            assert probe.marker in poisoned_output, (
                f"{invocation.source} arguments {list(invocation.argv)} never named "
                f"{probe.marker!r} on the poisoned corpus, so {probe.warn_check} did not "
                f"run at all — the invocation is reachable but vacuous, which is worse "
                f"than laxity because it reports success. "
                f"(validate_riskmap.py and validate_framework_references.py skip "
                f"validation entirely without --force.)\n"
                f"stdout: {poisoned.stdout}\nstderr: {poisoned.stderr}"
            )
            if poisoned.returncode == 0:
                failures.append(
                    f"  - {invocation.source}\n"
                    f"      line: {invocation.line}\n"
                    f"      argv: {list(invocation.argv)}\n"
                    f"      exit: 0 on a corpus carrying a {probe.warn_check} violation"
                )

        assert not failures, (
            f"{script}: the arguments CI passes do not catch an injected "
            f"{probe.warn_check} violation — the validator runs, reports the warning, "
            f"and exits 0, so the pull request merges.\n" + "\n".join(failures) + "\n"
            f"Pre-commit invokes this validator with {sorted(BLOCK_VALIDATORS[script])}; "
            f"ADR-037 D1/D2 require CI to do the same."
        )


# ===========================================================================
# 6. D7a — the CI file lists are derived, complete, and actually inspected
# ===========================================================================
#
# This section is no longer only D7's three. FILE_ARGUMENT_BLOCK_HOOKS below
# governs every hook that takes file arguments, whether strictness-flagged
# (D7's `validate_identification_questions.py`, `validate_yaml_prose_subset.py`,
# `validate_prose_references.py`) or one of ADR-037 D8's flagless validators
# that also does (`validate-neutrality`; D8's other five are self-scanning and
# take none — section 10 governs those). Everything about whether these jobs
# check anything is decided by the list that reaches their argv, and none of
# it is visible in the workflow's own output:
#
#   - an empty list is a passing job for `validate_yaml_prose_subset.py` and
#     `validate_prose_references.py`: both declare `files` with nargs="*" and
#     exit 0 on an empty one. `validate_neutrality.py` also declares
#     nargs="*", but an empty list makes it fall back to self-discovering
#     `scripts/agents|skills/**` from the working directory instead of exiting
#     0 — the wrong-tree hazard D8's own validators have, not this one's.
#   - a short list is a passing job that checked part of the corpus, and the
#     part it skipped is indistinguishable from clean.
#   - a `--schema-dir` the validator cannot read is a passing job too: the
#     shared field discovery in `_prose_fields.py` returns silently when it
#     cannot infer or read a schema, so no field is ever visited (D7's three
#     only — `validate_neutrality.py` has no `--schema-dir`).
#
# The tests below therefore run the resolver, compare its whole output against
# the hook's own patterns, and then run the real validator with the real
# argument list once per resolved file — poisoning that file and leaving the
# rest clean. A file the command never opens cannot fail, so the only way to
# pass the whole parametrization is for every file in the list to be inspected
# by the arguments CI actually passes.


def _hook_script(hook: dict[str, Any]) -> str | None:
    """Return the basename of the Python script a hook entry runs, if any."""
    for token in _safe_split(str(hook.get("entry") or "")):
        if token.endswith(".py"):
            return Path(token).name
    return None


def _iter_precommit_hooks():
    """Yield every hook mapping declared in .pre-commit-config.yaml."""
    config = yaml.safe_load(_PRECOMMIT_CONFIG.read_text(encoding="utf-8"))
    for repo in config.get("repos", []) or []:
        for hook in repo.get("hooks", []) or []:
            yield hook


# ---------------------------------------------------------------------------
# ADR-037 D1's governed-hook register, read once here. Needed this early
# because FILE_ARGUMENT_BLOCK_HOOKS below (D7a) and `_gate_steps` in section 7
# both have to recognize a flagless governed hook (D8: a validator with no
# warn-only tier blocks unconditionally and carries no flag for a
# STRICTNESS_FLAGS-keyed selector to find), and section 10 states D1, D7b and
# D7c over the same set. Defining it here means all three read one derivation
# instead of three that could drift apart.
# ---------------------------------------------------------------------------

# ADR-037's D1 instance table is the register of hooks this decision governs.
# The table is read rather than transcribed: it is the artefact that decides
# which hooks are in scope, its own text says it "is expected to grow without
# this ADR changing", and a hook added to it acquires the assertions below with
# no edit here. Reading `.pre-commit-config.yaml` alone cannot substitute —
# every local hook in it blocks, so a config-only predicate sweeps in hooks
# this decision does not reach.
_ADR_037_PATH = _REPO_ROOT / "docs" / "adr" / "037-ci-validation-authority-and-block-parity.md"

# Files this module derives its own *expectations* from, as opposed to files
# whose CI behaviour it inspects. `_ADR_037_PATH` is the one instance today:
# `_adr_governed_hook_ids` parses it into ADR_GOVERNED_HOOK_IDS, which decides
# which hooks TestUnflaggedBlockingCoverage, TestCIFileListsAreDerivedAndComplete
# and this workflow-trigger derivation itself all quantify over. Editing only
# the table's rows — adding or removing a governed hook — changes what every
# test keyed on that set asserts, with no change to any workflow, script or
# `.pre-commit-config.yaml` entry, so the source this module reads its own
# rules from has to be a pytest-workflow trigger requirement in its own right.
# A further such source (a second table this module comes to parse) belongs
# here, not folded into `_workflow_dependencies`, which answers a narrower
# question: what a *workflow's steps* execute, not what *this test module*
# reads to build its own register.
_DERIVATION_SOURCE_PATHS = frozenset({_ADR_037_PATH.relative_to(_REPO_ROOT).as_posix()})

# A table cell holding exactly one backticked hook id. The header and separator
# rows do not match, and neither does the `Validator` column (a path, and one
# containing `/`).
_ADR_HOOK_CELL_RE = re.compile(r"^`([a-z0-9][a-z0-9-]*)`$")


def _adr_governed_hook_ids() -> list[str]:
    """Return the pre-commit hook ids named in ADR-037's D1 instance table.

    Parsed from the markdown table rather than listed here, so the governed set
    is the decision's own register. Order is preserved for readable
    parametrization ids.
    """
    ids: list[str] = []
    for line in _ADR_037_PATH.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 2:
            continue
        match = _ADR_HOOK_CELL_RE.match(cells[0])
        if match and match.group(1) not in ids:
            ids.append(match.group(1))
    return ids


def _hook_invocations(hook: dict[str, Any]) -> list[Invocation]:
    """Return the Python invocations one hook mapping declares.

    Same construction `_precommit_invocations` uses for the whole config —
    `args:` are appended by the framework after `entry:` — applied to a single
    hook so its flags can be read without re-parsing the file.
    """
    command = " ".join([str(hook.get("entry") or ""), *(str(a) for a in hook.get("args") or [])])
    return _python_invocations(command, f".pre-commit-config.yaml [{hook.get('id')}]")


def _hook_strictness(hook: dict[str, Any]) -> frozenset[str]:
    """Return the strictness flags a hook mapping passes to its validator."""
    return frozenset().union(*(_strictness_flags(inv) for inv in _hook_invocations(hook)))


# hook id -> every hook mapping declaring it. A list because `check-jsonschema`
# is declared many times; the governed ids are unique, which the inventory test
# below asserts rather than assumes.
PRECOMMIT_HOOKS_BY_ID: dict[str, list[dict[str, Any]]] = {}
for _hook in _iter_precommit_hooks():
    if _hook.get("id"):
        PRECOMMIT_HOOKS_BY_ID.setdefault(str(_hook["id"]), []).append(_hook)

ADR_GOVERNED_HOOK_IDS = _adr_governed_hook_ids()

# The full ADR-037 D8 set: governed hooks that pass no strictness flag,
# blocking unconditionally, before splitting by `pass_filenames`. Ids the
# config does not declare are omitted here and reported by
# test_the_governed_hooks_resolve_to_the_precommit_config, so a rename fails
# with its own message instead of raising at import.
#
# Kept separate from UNFLAGGED_BLOCKING_HOOKS below (its self-scanning subset)
# because two different derivations need two different views of it:
# FILE_ARGUMENT_BLOCK_HOOKS needs the whole set — D8 states D7a applies to all
# six unchanged, and `validate-neutrality` takes an explicit file list, unlike
# its five siblings — while section 10's own apparatus needs only the
# self-scanning subset (see UNFLAGGED_BLOCKING_HOOKS's own comment for why).
_FLAGLESS_GOVERNED_HOOKS: dict[str, dict[str, Any]] = {
    hook_id: PRECOMMIT_HOOKS_BY_ID[hook_id][0]
    for hook_id in ADR_GOVERNED_HOOK_IDS
    if len(PRECOMMIT_HOOKS_BY_ID.get(hook_id, [])) == 1 and not _hook_strictness(PRECOMMIT_HOOKS_BY_ID[hook_id][0])
}
_FLAGLESS_GOVERNED_HOOK_IDS = sorted(_FLAGLESS_GOVERNED_HOOKS)

# The self-scanning subset of _FLAGLESS_GOVERNED_HOOKS: D8's own apparatus
# (section 10) below is shaped for a validator that resolves its own corpus
# from `Path(__file__)` or the working directory, with a probe that writes a
# small fixed set of files rather than an arbitrary resolved list.
#
# `validate-neutrality` is excluded here on purpose, not by oversight: it
# carries no strictness flag (so it is in _FLAGLESS_GOVERNED_HOOKS) but
# declares `pass_filenames: true`, unlike its five flagless siblings — it
# takes an explicit file list exactly like D7's three, and
# FILE_ARGUMENT_BLOCK_HOOKS below already governs it completely (D1's
# coverage, D7a's derived list, D7c's non-vacuity per file).
# UnflaggedProbe.write_corpus takes no file-list argument, so section 10's
# apparatus structurally cannot express "poison whichever file D7a's resolver
# names." Excluding it here also removes a hook-vs-script join hazard rather
# than requiring this section to resolve it: `validate-neutrality` and
# `validate-neutrality-policy` name the same script (`validate_neutrality.py`),
# and once both have real CI invocations, the two are indistinguishable to
# anything that keys on the script alone — `validate-neutrality-policy` is the
# only governed hook this narrower set names for that script.
UNFLAGGED_BLOCKING_HOOKS: dict[str, dict[str, Any]] = {
    hook_id: hook for hook_id, hook in _FLAGLESS_GOVERNED_HOOKS.items() if not hook.get("pass_filenames", True)
}
UNFLAGGED_BLOCKING_HOOK_IDS = sorted(UNFLAGGED_BLOCKING_HOOKS)


def _unflagged_script(hook_id: str) -> str:
    """Return the validator basename a governed flagless hook runs."""
    return _hook_script(UNFLAGGED_BLOCKING_HOOKS[hook_id]) or ""


# Basenames of the flagless governed validators, keyed by script rather than
# hook id: two ids (`validate-neutrality`, `validate-neutrality-policy`) name
# the same script, and `_gate_steps` matches a step's command line, which
# carries a script, not a hook id.
UNFLAGGED_BLOCKING_SCRIPTS = frozenset(_unflagged_script(hook_id) for hook_id in UNFLAGGED_BLOCKING_HOOK_IDS)


# hook-id -> hook, for hooks that take file arguments (`pass_filenames`
# defaults to true in pre-commit, so an absent key counts as true) and are
# either strictness-flagged or a member of ADR-037 D8's full flagless governed
# set (_FLAGLESS_GOVERNED_HOOK_IDS — not UNFLAGGED_BLOCKING_HOOK_IDS, which by
# this point has already been narrowed to the self-scanning subset).
# D8 states D7a applies to its six validators unchanged, and that set is not
# uniformly self-scanning: `validate-neutrality` declares `pass_filenames:
# true`, unlike its five flagless siblings, so its file list has to be
# constructed exactly as D7's three are — a flag-only predicate would silently
# exclude the one D8 member D7a actually reaches.
# This is exactly the set for which ADR-037 D7a requires a derived CI file
# list; the self-scanning validators (flagged or not) are excluded because
# they need none. Derived, so a further such hook — flagged or flagless — is
# governed on arrival.
FILE_ARGUMENT_BLOCK_HOOKS: dict[str, dict[str, Any]] = {
    str(hook["id"]): hook
    for hook in _iter_precommit_hooks()
    if hook.get("id")
    and hook.get("pass_filenames", True)
    and (
        STRICTNESS_FLAGS.intersection(
            " ".join([str(hook.get("entry") or ""), *(str(a) for a in hook.get("args", []) or [])]).split()
        )
        or str(hook["id"]) in _FLAGLESS_GOVERNED_HOOK_IDS
    )
}
FILE_ARGUMENT_BLOCK_HOOK_IDS = sorted(FILE_ARGUMENT_BLOCK_HOOKS)

# Workflow invocations parsed with command substitutions preserved. The default
# parse drops them, which is what makes the D7a file lists invisible.
WORKFLOW_INVOCATIONS_RESOLVABLE: list[Invocation] = []
for _source, _run_block in _iter_workflow_run_steps():
    WORKFLOW_INVOCATIONS_RESOLVABLE.extend(_python_invocations(_run_block, _source, keep_substitutions=True))

# A token that is exactly one variable reference, e.g. `${FILES}`.
_SUBST_TOKEN_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def _expected_hook_files(hook: dict[str, Any]) -> list[str]:
    """Return the tracked files a hook's own patterns select, derived here.

    Written out rather than imported from the resolver: an expectation computed
    by the code under test cannot detect a mutation to that code. The exact-list
    unit tests live in test_hook_file_list.py; this is the CI-side check that
    the list reaching argv is the same one.
    """
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\0")
    include = re.compile(hook["files"])
    exclude = re.compile(hook["exclude"]) if hook.get("exclude") else None
    return sorted(
        path for path in tracked if path and include.search(path) and not (exclude and exclude.search(path))
    )


def _run_substitution(command: str, cwd: Path) -> subprocess.CompletedProcess:
    """Run a workflow command substitution under `bash -e`, as GitHub does.

    GitHub's default shell for a `run:` block is `bash -e {0}`, so a failing
    command substitution in an assignment aborts the step. Reproducing the `-e`
    here keeps the test's notion of "the resolver failed" the same as CI's.
    """
    return subprocess.run(["bash", "-e", "-c", command], cwd=str(cwd), capture_output=True, text=True)


def _resolve_argv(invocation: Invocation) -> tuple[list[str], dict[str, list[str]]]:
    """Expand an invocation's command-substitution placeholders by running them.

    Returns the fully resolved argv and a map of variable name to the tokens it
    produced. Word-splitting is the shell's, reproduced here: the workflow
    expands `${FILES}` unquoted.
    """
    commands = dict(invocation.substitutions)
    produced: dict[str, list[str]] = {}
    argv: list[str] = []

    for token in invocation.argv:
        match = _SUBST_TOKEN_RE.match(token)
        if not (match and match.group(1) in commands):
            argv.append(token)
            continue
        name = match.group(1)
        if name not in produced:
            result = _run_substitution(commands[name], _REPO_ROOT)
            if result.returncode != 0:
                pytest.fail(
                    f"{invocation.source}: the command building {name} exited "
                    f"{result.returncode}, so the step aborts under `bash -e` and the "
                    f"validator never runs.\n  command: {commands[name]}\n"
                    f"  stdout: {result.stdout!r}\n  stderr: {result.stderr!r}"
                )
            produced[name] = result.stdout.split()
        argv.extend(produced[name])

    return argv, produced


def _neutrality_denylist_term() -> str:
    """Return one ADR-033 vendor/product denylist term, read from the policy module.

    Shared by this section's file-argument probe (`validate-neutrality`) and
    section 10's self-scanning one (`validate-neutrality-policy`) — same
    script, two hooks, one poison term, read once here rather than twice.

    Imported via `importlib` rather than a package-qualified `import` or a
    `sys.path.insert`, so this already-large test module's own import graph is
    untouched — `test_validate_neutrality.py` uses the package-qualified form
    because it is the dedicated test module for that validator; this one is
    not. Read from `_neutrality_data.VENDOR_PRODUCT_TERMS` rather than written
    out here, so a denylist edit cannot silently desync the probe from the
    policy it is meant to test — sorted for a stable pick, since which term is
    used does not matter, only that it is one of the policy's own.
    """
    spec = importlib.util.spec_from_file_location(
        "_neutrality_data_probe", _REPO_ROOT / "scripts" / "hooks" / "precommit" / "_neutrality_data.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return sorted(module.VENDOR_PRODUCT_TERMS)[0]


_NEUTRALITY_POISON_TERM = _neutrality_denylist_term()


# --- per-file corpus writers ------------------------------------------------
#
# The CI invocations run the validators in place (D7b), so the prose linters
# discover fields through the repository's real schemas. The poison must
# therefore land in a field those schemas actually mark as prose, one per
# entity file. A file whose stem is absent from these maps fails loudly rather
# than being written with a field nothing reads — a corpus the validator has no
# opinion about would make the "is it inspected" test pass vacuously.

_PROSE_FIELD_BY_STEM = {
    "components": "description",
    "controls": "description",
    "personas": "description",
    "risks": "shortDescription",
}

_PROBE_ID_BY_STEM = {
    "components": "componentProbe",
    "controls": "controlProbe",
    "personas": "personaProbe",
    "risks": "riskProbe",
}


def _write_prose_entity(base: Path, rel_path: str, text: str) -> None:
    """Write a one-entry YAML file at rel_path with `text` in its prose field."""
    stem = Path(rel_path).stem
    if stem not in _PROSE_FIELD_BY_STEM:
        pytest.fail(
            f"No prose field is known for {rel_path!r}. The hook's file list now covers "
            f"an entity this probe cannot poison, so the file would be written with no "
            f"field the validator reads and would pass whether or not it was inspected. "
            f"Add {stem!r} to _PROSE_FIELD_BY_STEM / _PROBE_ID_BY_STEM."
        )
    target = base / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    entry = {"id": _PROBE_ID_BY_STEM[stem], "title": "Probe", _PROSE_FIELD_BY_STEM[stem]: [text]}
    target.write_text(yaml.dump({stem: [entry]}), encoding="utf-8")


def _write_prose_subset_file(base: Path, rel_path: str, poisoned: bool) -> None:
    """Poison = inline URL in prose (ADR-017 D4)."""
    _write_prose_entity(
        base, rel_path, "See https://example.com for details." if poisoned else "Clean prose here."
    )


def _write_prose_references_file(base: Path, rel_path: str, poisoned: bool) -> None:
    """Poison = an intra-doc sentinel naming an id that does not exist (ADR-016 D6)."""
    _write_prose_entity(
        base, rel_path, "The {{riskProbeDoesNotExist}} applies here." if poisoned else "Clean prose here."
    )


def _write_identification_file(base: Path, rel_path: str, poisoned: bool) -> None:
    """Poison = a live persona with no identificationQuestions block (Rule 0)."""
    if Path(rel_path).stem != "personas":
        pytest.fail(
            f"The identification-questions hook now selects {rel_path!r}, which this "
            "probe cannot poison. Extend the writer before relying on the result."
        )
    persona: dict[str, Any] = {
        "id": "personaProbe",
        "title": "Probe Persona",
        "description": ["A probe persona."],
    }
    if not poisoned:
        persona["identificationQuestions"] = list(_CLEAN_IDENTIFICATION_QUESTIONS)
    target = base / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.dump({"personas": [persona]}), encoding="utf-8")


def _write_neutrality_file(base: Path, rel_path: str, poisoned: bool) -> None:
    """Poison = an ADR-033 vendor/product denylist term (validate-neutrality, D8).

    `rel_path` is one of this hook's own matched files under scripts/agents/
    or scripts/skills/ — real repo-relative paths, unlike the entity writers
    above, which is why this writer does not preserve the real file's content:
    only that a plain-prose file exists at that path for the denylist scan to
    read. No leading `---` line, so the structural frontmatter rule for a
    top-level agent .md or a canonical SKILL.md never fires regardless of
    which real path is targeted — only the denylist scan is under test here.
    """
    text = (
        f"This probe file mentions {_NEUTRALITY_POISON_TERM} for testing purposes.\n"
        if poisoned
        else "Clean, vendor-neutral prose in a probe file.\n"
    )
    target = base / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


# script basename -> writer(base_dir, repo_relative_path, poisoned)
FILE_LIST_PROBES: dict[str, Callable[[Path, str, bool], None]] = {
    "validate_identification_questions.py": _write_identification_file,
    "validate_yaml_prose_subset.py": _write_prose_subset_file,
    "validate_prose_references.py": _write_prose_references_file,
    "validate_neutrality.py": _write_neutrality_file,
}


def _file_list_candidates(hook_id: str) -> list[Invocation]:
    """Return every non-graph-emitting CI invocation of a hook's validator."""
    script = _hook_script(FILE_ARGUMENT_BLOCK_HOOKS[hook_id])
    return [inv for inv in WORKFLOW_INVOCATIONS_RESOLVABLE if inv.script == script and not _is_graph_emitting(inv)]


def _file_list_commands(invocation: Invocation) -> list[tuple[str, str]]:
    """Return the (variable, command) substitutions an invocation's argv consumes.

    Only substitutions actually referenced in argv count. A step may assign
    several; the ones that decide what the validator reads are the ones that
    reach the command line.
    """
    available = dict(invocation.substitutions)
    referenced = [
        match.group(1)
        for token in invocation.argv
        if (match := _SUBST_TOKEN_RE.match(token)) and match.group(1) in available
    ]
    return [(name, available[name]) for name in referenced]


def _invocation_names_hook(invocation: Invocation, hook_id: str) -> bool:
    """True when an invocation's own file-list command names the given hook id.

    This is what ties a CI invocation to *one* hook rather than to a validator.
    Two hooks can share a validator, and the file lists they select differ.
    """
    return any(hook_id in _safe_split(command) for _, command in _file_list_commands(invocation))


def _self_scanning_sibling_hooks(script: str, exclude_hook_id: str) -> list[str]:
    """Return governed hook ids sharing `script` with `exclude_hook_id` that take no file arguments.

    Derived from `.pre-commit-config.yaml`'s own `pass_filenames` key and
    ADR-037's governed register (`ADR_GOVERNED_HOOK_IDS`), not from any
    specific hook's name. A governed hook sharing a script with a
    file-argument one, and declaring `pass_filenames: false`, is pre-commit's
    own signal that its CI counterpart is invoked with no filename arguments
    at all — `validate_neutrality.py:507` is the concrete instance (`files =
    [...] if args.files else discover_neutral_surface_files(Path.cwd())`:
    empty argv triggers whole-corpus self-discovery, not a vacuous no-op) —
    but nothing here names it.
    """
    return sorted(
        other
        for other in ADR_GOVERNED_HOOK_IDS
        if other != exclude_hook_id
        and PRECOMMIT_HOOKS_BY_ID.get(other)
        and _hook_script(PRECOMMIT_HOOKS_BY_ID[other][0]) == script
        and not PRECOMMIT_HOOKS_BY_ID[other][0].get("pass_filenames", True)
    )


def _excuse_self_scanning_sibling_invocations(
    script: str, hook_id: str, unattributed: list[Invocation]
) -> list[Invocation]:
    """Return the subset of `unattributed` still genuinely unaccounted for.

    A bare invocation (empty argv — no file-list command exists to name any
    hook with) is excused up to the number of self-scanning sibling hooks
    that share `script`, per `.pre-commit-config.yaml`: that many bare
    invocations are exactly what those hooks' `pass_filenames: false` entries
    require CI to reproduce. Capped at that count rather than excusing every
    bare invocation unconditionally, so a genuine duplicate bare invocation —
    the original defect `test_each_governed_hook_has_exactly_one_ci_invocation`
    exists to catch — is still reported: only as many bare invocations as
    there are sibling hooks to explain them are ever excused, and a script
    with no self-scanning sibling excuses none at all.
    """
    siblings = _self_scanning_sibling_hooks(script, hook_id)
    if not siblings:
        return unattributed
    bare = [inv for inv in unattributed if not inv.argv]
    excused = bare[: len(siblings)]
    return [inv for inv in unattributed if inv not in excused]


def _file_list_invocation(hook_id: str) -> Invocation:
    """Return the CI invocation belonging to a hook, failing if it is not unique.

    Selecting `candidates[0]` conflated two distinct failures. A second,
    vacuous invocation of the same validator was accepted in silence, because
    the first candidate still satisfied everything; and a second *real* hook on
    an existing validator produced a false positive against whichever invocation
    sorted first, reported as a fault in the file list rather than as an
    ambiguity in the join.

    Resolution is therefore by hook id — the invocation whose own file-list
    command names this hook — and falls back to the validator-level match only
    when no candidate names any hook, which is the shape
    test_ci_invocation_takes_its_file_list_from_a_command exists to report.
    """
    script = _hook_script(FILE_ARGUMENT_BLOCK_HOOKS[hook_id])
    candidates = _file_list_candidates(hook_id)
    if not candidates:
        pytest.fail(
            f"No workflow invokes {script} (hook {hook_id!r}). "
            "TestStrictnessCoverage reports the coverage gap for a flagged hook and "
            "TestUnflaggedBlockingCoverage for a flagless one; this class cannot "
            "establish anything about a command that does not exist."
        )

    named = [inv for inv in candidates if _invocation_names_hook(inv, hook_id)]
    chosen = named or candidates
    if len(chosen) != 1:
        pytest.fail(
            f"{hook_id}: {len(chosen)} CI invocations of {script} match this hook, so "
            f"there is no single command whose file list can be checked against it.\n"
            + "\n".join(f"  - {inv.source}: {inv.line}  (argv={list(inv.argv)})" for inv in chosen)
            + "\nADR-037 D7 requires a failure to resolve to a single validator; that "
            "holds only while each governed hook has one invocation. Picking the first "
            "would test one command and leave the others uninspected."
        )
    return chosen[0]


class TestCIFileListsAreDerivedAndComplete:
    """ADR-037 D7a: the file list CI passes is the hook's, whole, and read.

    Three separate claims, because each fails silently on its own:

      1. the list is *derived* — it comes from a command evaluated at run time,
         not from paths transcribed into workflow YAML, which drift in the
         permissive direction;
      2. the list is *complete* — it equals the hook's own file set, not a
         prefix of it;
      3. the list is *read* — the argument list CI passes actually causes every
         file in it to be inspected.

    Claim 3 is the one that cannot be faked. It runs the real validator with the
    real argument list, once per resolved file, against a corpus where only that
    file carries a violation. A stripped file list, a truncated resolver, or a
    `--schema-dir` the validator cannot read all produce the same observable
    result — a file that was not checked — and all three fail here.
    """

    def test_file_argument_block_hooks_are_derived_and_present(self):
        """
        Given: .pre-commit-config.yaml as committed
        When: hooks that pass filenames and are either strictness-flagged or a
              member of ADR-037 D8's flagless governed set are derived
        Then: at least one is found

        Every test below is parametrized over this set. A zero result collects
        no cases, which pytest reports as success.
        """
        assert FILE_ARGUMENT_BLOCK_HOOK_IDS, (
            "Parsed no file-argument hooks out of "
            f"{_PRECOMMIT_CONFIG}. ADR-037 D7 names three flagged ones and D8 adds "
            "validate-neutrality; finding none means the derivation stopped seeing "
            "them, which makes this whole class vacuous."
        )

    def test_every_file_argument_block_hook_has_a_corpus_probe(self):
        """
        Given: the derived set of file-argument strictness hooks
        When: compared against the per-file corpus writers
        Then: every one has a writer, and no writer is orphaned

        The same derive-don't-enumerate rule the D4 tier applies. A fourth hook
        of this shape fails here until someone can express a violation in its
        files, rather than being quietly excluded from the strongest assertion
        in the module.
        """
        scripts = {_hook_script(hook) for hook in FILE_ARGUMENT_BLOCK_HOOKS.values()}
        unprobed = sorted(name for name in scripts if name not in FILE_LIST_PROBES)
        assert not unprobed, (
            f"No per-file corpus writer for {unprobed}. Without one, the file list "
            "for that hook can be checked for length but not for effect, and a "
            "list that is present but never read looks identical to a correct one."
        )
        stale = sorted(set(FILE_LIST_PROBES) - {name for name in scripts if name})
        assert not stale, f"Corpus writers exist for validators no longer governed by D7a: {stale}."

    @pytest.mark.parametrize("hook_id", FILE_ARGUMENT_BLOCK_HOOK_IDS)
    def test_ci_invocation_takes_its_file_list_from_a_command(self, hook_id):
        """
        Given: the CI invocation of a file-argument strictness-flagged validator
        When: its argv is inspected for a command-substitution reference
        Then: one is present, and the command it names is recorded

        ADR-037 D7a forbids transcribing the file list into workflow YAML: a
        transcribed list drifts in the permissive direction, because a file the
        hook covers and the workflow omits is unchecked in CI while appearing
        checked.

        This also fails if the expansion is simply dropped from the command
        line. That edit leaves the job green for two of the three validators —
        `nargs="*"` plus an immediate `exit 0` on no files — and the workflow
        prints its success message either way.
        """
        invocation = _file_list_invocation(hook_id)
        referenced = _file_list_commands(invocation)
        assert referenced, (
            f"{hook_id}: the CI invocation passes no command-derived file list.\n"
            f"  {invocation.source}: {invocation.line}\n"
            f"  argv: {list(invocation.argv)}\n"
            f"  command substitutions available in the step: "
            f"{[name for name, _ in invocation.substitutions] or 'none'}\n"
            "ADR-037 D7a requires the file set to be derived from the hook's own "
            "`files:` pattern at run time. With no file list this validator "
            "inspects nothing and still exits 0."
        )

    @pytest.mark.parametrize("hook_id", FILE_ARGUMENT_BLOCK_HOOK_IDS)
    def test_ci_file_list_command_resolves_this_hook_from_the_precommit_config(self, hook_id):
        """
        Given: the command CI uses to build a hook's file list
        When: the command itself is parsed
        Then: it runs a Python script that reads `.pre-commit-config.yaml`, and
              passes this hook's own id as an argument

        "Derived, not transcribed" is a claim about where the list comes from,
        and the previous assertion only established that it comes from *a*
        command substitution. `FILES=$(cat .github/prose-files.txt)` satisfies
        that: it is a command, it produces a list, and it is a hand-maintained
        file that drifts from the hook in exactly the permissive direction
        ADR-037 D7a names — a file the hook covers and the list omits is
        unchecked in CI while appearing checked.

        The resolver is identified by what it reads rather than by its filename,
        so renaming or replacing it does not require an edit here; substituting
        something that never opens the hook config does.

        The command must also be a single simple command. `$(resolver || true)`
        parses and runs, and it discards the resolver's non-zero exit on an
        empty match — the assertion `test_hook_file_list.py` calls the most
        important one it makes. Nothing else notices until the match actually
        goes empty, at which point the job is green and has read nothing.
        """
        invocation = _file_list_invocation(hook_id)
        commands = _file_list_commands(invocation)
        assert commands, (
            f"{hook_id}: no command substitution reaches this invocation's argv; "
            "test_ci_invocation_takes_its_file_list_from_a_command explains the gap."
        )

        for name, command in commands:
            operators = _shell_operators(command)
            assert not operators, (
                f"{hook_id}: the file-list command for {name} is not a single simple "
                f"command — it contains {operators}.\n  command: {command}\n"
                "A trailing `|| true` (or `; true`, or a pipe) discards the resolver's "
                "exit status, so an empty or failed match becomes an empty variable and "
                "a passing job instead of an aborted step."
            )

            inner = _python_invocations(command, f"{invocation.source} [{name}]")
            assert len(inner) == 1, (
                f"{hook_id}: the file-list command for {name} does not run exactly one "
                f"Python script.\n  command: {command}\n  parsed: {[i.script for i in inner]}\n"
                "ADR-037 D7a requires the list to be derived from the hook's own "
                "`files:` pattern at run time. A `cat` of a checked-in list, or a "
                "chain of commands, is a transcription with a command substitution "
                "wrapped around it."
            )

            resolved, _ = _real_script_path(inner[0].script)
            assert resolved and _reads_precommit_config(resolved), (
                f"{hook_id}: the file-list command for {name} runs "
                f"{inner[0].script!r}, which does not read {_PRECOMMIT_CONFIG.name}.\n"
                f"  command: {command}\n"
                "The list has to come from the hook's own patterns. A script that never "
                "opens the pre-commit config cannot be reproducing them."
            )
            assert hook_id in _safe_split(command), (
                f"{hook_id}: the file-list command for {name} does not name this hook.\n"
                f"  command: {command}\n"
                "Without the hook id the list belongs to some other hook's patterns, "
                "and the two drift independently."
            )

    @pytest.mark.parametrize("hook_id", FILE_ARGUMENT_BLOCK_HOOK_IDS)
    def test_each_governed_hook_has_exactly_one_ci_invocation(self, hook_id):
        """
        Given: every non-graph-emitting CI invocation of a governed hook's
               validator
        When: they are attributed to the hooks their file-list commands name,
              or excused as belonging to a self-scanning sibling hook that
              shares the script
        Then: exactly one belongs to this hook, and none is left unaccounted for

        Two failures share this shape and neither was visible before D8.

        A *second, vacuous* invocation of the same validator — one passing a
        stale or transcribed list — adds no failure anywhere else: the tests
        below resolve one invocation and check it, and the extra command runs
        in CI unexamined. ADR-037 D7's attribution constraint is the rule this
        serves: a failure must resolve to a single validator, which holds only
        while each governed hook has one command.

        A bare invocation (empty argv) is not automatically this failure,
        which is why "vacuous" above is qualified. D8 pairs a file-argument
        hook with a self-scanning sibling on the same script
        (`validate-neutrality` / `validate-neutrality-policy`, both running
        `validate_neutrality.py`), and the sibling's own correct CI
        invocation is bare by construction (`pass_filenames: false`) — for
        `validate_neutrality.py:507`, that empty argv is what triggers
        whole-corpus self-discovery rather than a no-op. Attribution by
        file-list command alone cannot see that invocation belongs to
        anything, so `_excuse_self_scanning_sibling_invocations` grants it one
        pass per self-scanning sibling the config actually declares — no more,
        so an unexplained bare invocation (the original defect) still fails
        below exactly as it did before this exception existed.

        A second *real* hook on an existing validator produces the opposite
        error — a confident failure against whichever invocation happened to
        sort first, reported as a broken file list rather than as an ambiguity.
        """
        script = _hook_script(FILE_ARGUMENT_BLOCK_HOOKS[hook_id])
        candidates = _file_list_candidates(hook_id)
        assert candidates, (
            f"No workflow invokes {script} (hook {hook_id!r}); TestStrictnessCoverage "
            "reports that as the D1 coverage gap for a flagged hook and "
            "TestUnflaggedBlockingCoverage for a flagless one."
        )

        attribution = [
            (inv, sorted(other for other in FILE_ARGUMENT_BLOCK_HOOK_IDS if _invocation_names_hook(inv, other)))
            for inv in candidates
        ]
        unattributed = [inv for inv, hooks in attribution if not hooks]
        unattributed = _excuse_self_scanning_sibling_invocations(script, hook_id, unattributed)
        assert not unattributed, (
            f"{script}: these CI invocations name no governed hook, and none is "
            f"excused as a self-scanning sibling's own bare invocation, so nothing "
            f"establishes which file set they are supposed to cover:\n"
            + "\n".join(f"  - {inv.source}: {inv.line}" for inv in unattributed)
            + "\nAn invocation of a --block validator that no hook accounts for either "
            "duplicates a gate (and runs unexamined) or replaces one with a list this "
            "suite never compares against a hook's patterns."
        )

        mine = [inv for inv, hooks in attribution if hook_id in hooks]
        assert len(mine) == 1, (
            f"{hook_id}: expected exactly one CI invocation of {script} for this hook, "
            f"found {len(mine)}:\n"
            + "\n".join(f"  - {inv.source}: {inv.line}  (argv={list(inv.argv)})" for inv in mine)
            + "\nAll non-graph-emitting invocations of this validator:\n"
            + "\n".join(f"  - {inv.source}: {inv.line}  -> hooks {hooks}" for inv, hooks in attribution)
        )

    def test_bare_invocation_is_excused_only_when_a_self_scanning_sibling_exists(self):
        """
        Given: a synthetic bare invocation (no argv)
        When: it is checked against a file-argument governed hook whose script
              has a self-scanning sibling per `.pre-commit-config.yaml`, and
              separately against one whose script has none
        Then: it is excused in the first case and still reported in the second

        Non-vacuous proof that the exception
        test_each_governed_hook_has_exactly_one_ci_invocation grants is earned,
        not asserted, and bounded in both directions:

          - it must actually excuse the shape D8 requires — a bare invocation
            of `validate_neutrality.py` is not a vacuous duplicate, it is
            `validate-neutrality-policy`'s own correct CI invocation
            (`pass_filenames: false`, `validate_neutrality.py:507` self-scans
            on empty argv) — or D8's CI wiring would fail this class again;
          - it must not excuse a bare invocation with no self-scanning sibling
            to explain it, or the original defect this class exists to catch
            — a second, unexamined invocation — would pass silently.

        Both governed hook ids used here are found by property (has a
        self-scanning sibling / does not), not named, so this stays true if
        the specific hooks that satisfy each property change.
        """
        with_sibling = next(
            (
                hook_id
                for hook_id in FILE_ARGUMENT_BLOCK_HOOK_IDS
                if _self_scanning_sibling_hooks(_hook_script(FILE_ARGUMENT_BLOCK_HOOKS[hook_id]), hook_id)
            ),
            None,
        )
        assert with_sibling is not None, (
            "No FILE_ARGUMENT_BLOCK_HOOK_IDS member has a self-scanning sibling sharing "
            "its script, so this fidelity check has nothing to exercise on that side. "
            "ADR-037 D8's validate-neutrality/validate-neutrality-policy pairing is what "
            "makes this non-vacuous; if it stopped existing, the exception "
            "test_each_governed_hook_has_exactly_one_ci_invocation grants would be dead "
            "code and should be removed along with this test."
        )
        without_sibling = next(
            (
                hook_id
                for hook_id in FILE_ARGUMENT_BLOCK_HOOK_IDS
                if not _self_scanning_sibling_hooks(_hook_script(FILE_ARGUMENT_BLOCK_HOOKS[hook_id]), hook_id)
            ),
            None,
        )
        assert without_sibling is not None, (
            "Every FILE_ARGUMENT_BLOCK_HOOK_IDS member has a self-scanning sibling, so "
            "there is no remaining case in which a bare invocation must still be "
            "reported. D7's three validators are expected to supply this case; if none "
            "of them do any more, the guard this test exists to prove has nothing left "
            "to prove."
        )

        bare = Invocation(script="probe.py", path="probe.py", argv=(), source="synthetic", line="python3 probe.py")

        excused = _excuse_self_scanning_sibling_invocations(
            _hook_script(FILE_ARGUMENT_BLOCK_HOOKS[with_sibling]), with_sibling, [bare]
        )
        assert excused == [], (
            f"{with_sibling}: a bare invocation was not excused even though its script "
            "has a self-scanning sibling per .pre-commit-config.yaml's own "
            "pass_filenames key. That sibling's own CI invocation is exactly this shape "
            "(empty argv), so it must not be reported as unattributed."
        )

        still_unattributed = _excuse_self_scanning_sibling_invocations(
            _hook_script(FILE_ARGUMENT_BLOCK_HOOKS[without_sibling]), without_sibling, [bare]
        )
        assert still_unattributed == [bare], (
            f"{without_sibling}: a bare invocation of its script was excused even though "
            "no self-scanning sibling shares that script — there is no hook it could "
            "legitimately belong to, so it is the original defect this class exists to "
            "catch (a second, unexamined invocation), and the exception must not "
            "swallow it."
        )

    @pytest.mark.parametrize("hook_id", FILE_ARGUMENT_BLOCK_HOOK_IDS)
    def test_derived_file_list_equals_the_hook_file_set(self, hook_id):
        """
        Given: the command CI uses to build the file list
        When: it is executed against the real repository
        Then: its output equals, whole, the files the hook's patterns select

        Equality, not containment. A resolver returning the first element of its
        match produces a green job that checked one file out of four, and every
        weaker assertion — non-empty, is-a-subset, has-at-least-one — passes it.
        """
        hook = FILE_ARGUMENT_BLOCK_HOOKS[hook_id]
        invocation = _file_list_invocation(hook_id)
        _, produced = _resolve_argv(invocation)

        assert produced, (
            f"{hook_id}: no command substitution was expanded for this invocation, so "
            "there is no file list to compare. "
            "test_ci_invocation_takes_its_file_list_from_a_command explains the gap."
        )
        actual = sorted(token for tokens in produced.values() for token in tokens)
        expected = _expected_hook_files(hook)

        assert actual == expected, (
            f"{hook_id}: the file list CI builds is not the file set the hook sees.\n"
            f"  files:   {hook.get('files')!r}\n"
            f"  exclude: {hook.get('exclude')!r}\n"
            f"  hook sees ({len(expected)}): {expected}\n"
            f"  CI passes ({len(actual)}): {actual}\n"
            f"  missing from CI: {sorted(set(expected) - set(actual))}\n"
            f"  extra in CI: {sorted(set(actual) - set(expected))}\n"
            "A file the hook covers and CI omits is unchecked while appearing checked."
        )

    @pytest.mark.parametrize("hook_id", FILE_ARGUMENT_BLOCK_HOOK_IDS)
    def test_every_file_in_the_derived_list_is_inspected(self, hook_id, tmp_path):
        """
        Given: the exact argument list CI passes, with its file list resolved
        When: the validator runs once per resolved file, against a corpus where
              only that file carries a violation
        Then: every run exits non-zero and names the poisoned file

        The behavioural claim the rest of the class supports. It asserts nothing
        about the workflow's text: it observes that each file CI names is a file
        whose contents can fail the build.

        One edit fails here and nowhere else in the suite: a `--schema-dir` the
        validator cannot read. Field discovery in `_prose_fields.py` returns
        silently on a schema it cannot infer or open, so no prose is visited,
        while the file list stays complete and every string in the workflow
        stays correct. Argparse store actions are last-wins, which is why this
        test runs the workflow's arguments as written rather than appending its
        own.

        Two further edits fail here *and* elsewhere, and it is worth being exact
        about which, because a maintainer trimming this suite needs to know
        which test is load-bearing for what:

          - dropping the file-list expansion from the command line. Both prose
            validators declare `files` with nargs="*" and exit 0 on an empty
            one, so the job stays green. Also caught by
            test_ci_invocation_takes_its_file_list_from_a_command.
          - a resolver that returns a prefix of its match. This test does *not*
            catch a truncation to `[:1]`: the surviving file is genuinely
            inspected, so its poisoned run fails as expected and the shortened
            list is never compared to anything here.
            test_derived_file_list_equals_the_hook_file_set is what fails on a
            short list, together with the exact-list assertions in
            test_hook_file_list.py. Truncation to a *prefix of length > 1* does
            fail here, for the files past the cut.

        The all-clean run is asserted first. Without it a validator that failed
        on everything would satisfy every poisoned assertion for the wrong
        reason.
        """
        hook = FILE_ARGUMENT_BLOCK_HOOKS[hook_id]
        script = _hook_script(hook)
        write_file = FILE_LIST_PROBES.get(script)
        if write_file is None:
            pytest.fail(
                f"No per-file corpus writer for {script} (hook {hook_id!r}); "
                "test_every_file_argument_block_hook_has_a_corpus_probe reports the same "
                "gap. Without a writer this behavioural claim cannot be made at all — "
                "not even the harness precondition below has a corpus to run against."
            )
        real_path = _REPO_ROOT / PRECOMMIT_VALIDATORS[script]
        invocation = _file_list_invocation(hook_id)
        argv, produced = _resolve_argv(invocation)
        files = [token for tokens in produced.values() for token in tokens]

        assert files, (
            f"{hook_id}: the resolved file list is empty, so there is nothing to "
            f"inspect and the command below cannot fail on any content.\n"
            f"  {invocation.source}: {invocation.line}\n"
            f"  resolved argv: {argv}"
        )

        def run(base: Path) -> subprocess.CompletedProcess:
            # The validator runs from its real path (D7b) so its Path(__file__)
            # derivations resolve against the repository, exactly as in CI; cwd
            # is the temporary corpus so the repo-relative file arguments land
            # inside it rather than on the live YAML.
            return subprocess.run(
                [sys.executable, str(real_path), *argv],
                capture_output=True,
                text=True,
                cwd=str(base),
            )

        clean_dir = tmp_path / "clean"
        for path in files:
            write_file(clean_dir, path, False)
        clean = run(clean_dir)
        assert clean.returncode == 0, (
            f"Harness precondition failed: {hook_id}'s CI arguments exit "
            f"{clean.returncode} on a corpus with no injected violation, so the "
            f"poisoned results below would prove nothing.\n"
            f"  argv: {argv}\n  stdout: {clean.stdout}\n  stderr: {clean.stderr}"
        )

        unchecked: list[str] = []
        for index, target in enumerate(files):
            poisoned_dir = tmp_path / f"poisoned-{index}"
            for path in files:
                write_file(poisoned_dir, path, path == target)
            result = run(poisoned_dir)
            output = result.stdout + result.stderr
            if result.returncode == 0 or target not in output:
                unchecked.append(
                    f"  - {target}: exit {result.returncode}, "
                    f"{'named' if target in output else 'NOT named'} in output"
                )

        assert not unchecked, (
            f"{hook_id}: the command CI runs does not catch a violation in every file "
            f"of its own file list. Those files are in the argument list and are not "
            f"being inspected, so their contents can reach main unopposed while the job "
            f"reports success.\n"
            f"  {invocation.source}: {invocation.line}\n"
            f"  argv: {argv}\n" + "\n".join(unchecked)
        )


# ===========================================================================
# 6b. D1 over third-party blocking hooks — not only the repo's own scripts
# ===========================================================================
#
# ADR-037's D1 instance table (`ADR_GOVERNED_HOOK_IDS`, section 6) is the
# register every other class in this module reads to decide which hooks D1
# governs, and the table only names hooks whose `entry:` runs a local Python
# script. `.pre-commit-config.yaml` also declares hooks from a third-party
# repo — `check-jsonschema` and `check-metaschema`, from
# python-jsonschema/check-jsonschema — and D1's own text does not carve those
# out: "a validator ... invokes as a **blocking hook**" (docs/adr/037-
# ci-validation-authority-and-block-parity.md, D1), and blocking is defined
# there as "a violation makes it exit non-zero — whether that is unconditional,
# or requires `--block`". Both third-party hooks are unconditionally blocking
# by construction: check-jsonschema's entire purpose is to exit non-zero on a
# schema violation, and no `.pre-commit-config.yaml` key changes that.
#
# A hook-id-keyed register cannot see this gap at all: `check-jsonschema` is
# declared many times over (one entry per yaml/schema pair, section 6's own
# `PRECOMMIT_HOOKS_BY_ID` comment records this), all sharing one `id`, so
# there is no per-pair hook id for ADR-037's table to name even if it wanted
# to. This section reads the pairs out of `.pre-commit-config.yaml`'s own
# `args:` instead, the same derive-don't-transcribe rule as everywhere else in
# this module.


def _check_jsonschema_pairs() -> list[tuple[str, str, str]]:
    """Return (hook name, schema path, yaml path) for every `check-jsonschema` entry.

    Each entry pins one yaml/schema pair through `--schemafile <schema>` and a
    trailing positional yaml path in `args:` — `pass_filenames: false` on every
    one makes that positional the only place either path is recorded, per the
    comment on the schema-validation block in `.pre-commit-config.yaml`.
    Entries with no `--schemafile` (there are none today) are skipped rather
    than crashing, so a future check-jsonschema hook shaped differently is
    reported as unparseable by its own absence, not by an index error here.
    """
    pairs: list[tuple[str, str, str]] = []
    for hook in PRECOMMIT_HOOKS_BY_ID.get("check-jsonschema", []):
        args = [str(a) for a in hook.get("args") or []]
        if "--schemafile" not in args:
            continue
        schema = args[args.index("--schemafile") + 1]
        yaml_path = args[-1]
        pairs.append((str(hook.get("name") or hook.get("id")), schema, yaml_path))
    return pairs


def _ci_schema_yaml_pairs() -> set[tuple[str, str]]:
    """Return the (schema, yaml) pairs `validate_all_schemas.py`'s own pairing finds.

    Run as a subprocess from the repository root, exactly the way
    `validation.yml`'s schema-validation job invokes `_find_pairs()`
    (`-c "import sys; sys.path.insert(0, 'scripts/hooks/precommit'); import
    validate_all_schemas as v; ..."`), rather than imported in-process:
    `_find_pairs()` globs relative to the process's current working directory,
    and importing the module here would glob relative to pytest's own cwd
    instead of the repository root CI actually runs it from.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, json\n"
            "sys.path.insert(0, 'scripts/hooks/precommit')\n"
            "import validate_all_schemas as v\n"
            "print(json.dumps([[str(s), str(y)] for s, y in v._find_pairs()]))\n",
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    return {(schema, yaml_path) for schema, yaml_path in json.loads(result.stdout)}


# Third-party CLI tools `.pre-commit-config.yaml` invokes directly, rather
# than through a `python3 <script>.py` line `_python_invocations` can see.
# `check-jsonschema` is the only one declared today: the repo at
# `https://github.com/python-jsonschema/check-jsonschema` provides both the
# `check-jsonschema` hook id (entry `check-jsonschema`) and the
# `check-metaschema` hook id (entry `check-jsonschema --check-metaschema`) —
# two hooks, one binary, distinguished by a flag rather than by command name.
# Neither hook supports a strictness flag, so both block a commit
# unconditionally the moment they run at all.
THIRD_PARTY_BLOCKING_COMMANDS = frozenset({"check-jsonschema"})


def _strip_leading_words(segment: list[str]) -> list[str]:
    """Drop shell keywords and variable assignments from the front of a simple command.

    `if check-jsonschema ...; then` and `FOO=bar check-jsonschema ...` both put
    a non-command token in `segment[0]`; this is what every caller below uses
    to reach the actual command word instead of matching the keyword in front
    of it.
    """
    trimmed = list(segment)
    while trimmed and (trimmed[0] in _LEADING_WORDS or _TOKEN_ASSIGN_RE.match(trimmed[0])):
        trimmed = trimmed[1:]
    return trimmed


def _segment_invokes_third_party_command(segment: list[str]) -> bool:
    """True when a simple command's head, once leading words are stripped, is a
    THIRD_PARTY_BLOCKING_COMMANDS member.

    Per-segment sibling of `_third_party_invocations`, for callers that already
    hold a split segment (from `_split_simple_commands`/`_segments_with_operators`)
    and only need a yes/no answer rather than a full `Invocation` record —
    the `||`-guard and repository-state-bypass detectors in section 9 use this
    to extend their reach to third-party blocking commands, the same way they
    already reach UNFLAGGED_BLOCKING_SCRIPTS.

    Checked against the head only, never any token in the segment: `pip
    install check-jsonschema` must read as an invocation of `pip`, not of
    check-jsonschema itself — the package name there is an argument, never the
    command word.
    """
    trimmed = _strip_leading_words(segment)
    return bool(trimmed) and Path(trimmed[0]).name in THIRD_PARTY_BLOCKING_COMMANDS


def _third_party_invocations(script_text: str, source: str, keep_substitutions: bool = False) -> list[Invocation]:
    """Return every THIRD_PARTY_BLOCKING_COMMANDS execution in a shell script.

    Structurally the same job `_python_invocations` does — line-by-line
    variable expansion, then a simple-command split, so a step's own comments
    and un-executed mentions (`echo "check-jsonschema failed"`) are excluded
    the same way `_python_invocations`'s own docstring describes — matching on
    THIRD_PARTY_BLOCKING_COMMANDS instead of a `.py` script or a `python*`
    interpreter. Kept as a separate function rather than folded into
    `_python_invocations`: that function has dozens of call sites across this
    module, all of which assume "a Python execution", and widening its match
    criteria would change what every one of them means.

    `script` and `path` are both the matched command name — there is no script
    *file* to distinguish path-on-the-command-line from basename the way a
    `.py` invocation has.
    """
    env: dict[str, Any] = {}
    substitutions: dict[str, str] = {}
    found: list[Invocation] = []

    for raw_line in script_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        assignment = _ASSIGN_RE.match(raw_line)
        if assignment:
            name, value = assignment.group(1), assignment.group(2).strip()
            if "$(" in value or "`" in value:
                if keep_substitutions:
                    substitutions[name] = _substitution_command(value)
                    env[name] = f"${{{name}}}"
                else:
                    env[name] = ""
            elif value.startswith("(") and value.endswith(")"):
                env[name] = [_expand(element, env) for element in _safe_split(value[1:-1])]
            else:
                parts = _safe_split(value)
                env[name] = _expand(parts[0], env) if parts else ""
            continue

        tokens: list[str] = []
        for token in _safe_split(stripped):
            expansion = _expand(token, env)
            tokens.extend(expansion.split())

        for segment in _split_simple_commands(tokens):
            trimmed = _strip_leading_words(segment)
            if not trimmed or Path(trimmed[0]).name not in THIRD_PARTY_BLOCKING_COMMANDS:
                continue
            command, rest = trimmed[0], trimmed[1:]
            found.append(
                Invocation(command, command, tuple(rest), source, stripped, tuple(sorted(substitutions.items())))
            )

    return found


def _check_metaschema_steps() -> list["WorkflowStep"]:
    """Return steps invoking `check-jsonschema --check-metaschema` as a real command.

    Uses the structured `_third_party_invocations` parser rather than a raw
    substring scan, so a step that keeps the flag only in a comment
    (`# ... --check-metaschema ...`) while its executable command has been
    replaced with something else — `if true; then` — is not read as covering
    the hook. A comment mentioning a flag is not a command carrying it.
    """
    return [
        step
        for step in WORKFLOW_STEPS
        if any(
            "--check-metaschema" in invocation.argv
            for invocation in _third_party_invocations(step.run, step.source, keep_substitutions=True)
        )
    ]


def _ci_runs_check_metaschema() -> bool:
    """True when some workflow step invokes check-jsonschema's metaschema mode.

    `check-metaschema` is check-jsonschema's own pre-commit hook id for
    `check-jsonschema --check-metaschema <files>` (verified against the
    installed CLI's `--help`: `--check-metaschema` is the flag that switches
    from validating instances to validating schema documents against their own
    declared metaschema). Delegates to `_check_metaschema_steps`, the
    structured derivation, rather than a raw substring scan of `step.run`: the
    substring form reads a flag left behind in a comment the same as one on a
    real command line, so a step whose actual command had been replaced with
    something else (`if true; then # ... --check-metaschema ...`) still read
    as covered.
    """
    return bool(_check_metaschema_steps())


class TestThirdPartyBlockingHookCoverage:
    """ADR-037 D1, applied to hooks pre-commit declares from a third-party repo.

    Every other class in this module resolves "does CI cover this hook" to a
    single workflow invocation it can run and inspect (sections 2, 6, 10).
    Until 23a455b, there was no such invocation for either hook here: the
    closest CI came was `validate_all_schemas.py`, itself a `check-jsonschema`
    wrapper for a different trigger (the master schema changing) with its own,
    narrower pairing logic — `check-jsonschema` proper covered nine pairs
    (missing the archived one, see `test_every_check_jsonschema_pair_has_a_ci_counterpart`)
    and `check-metaschema` had no counterpart at all. 23a455b closed both:
    switching `_find_pairs()` to `rglob` folded the archive pair into the
    pairing logic this class's tests already read, and a dedicated
    `check-jsonschema --check-metaschema` step was added to the
    schema-validation job. What these tests assert is therefore still the
    weaker but real claim D1 makes — that CI's own pairing includes every
    pair pre-commit blocks a commit on, and that some CI job performs the
    equivalent of `check-metaschema` at all — kept as a standing guard now
    that both hold, rather than as a report of the gap that used to exist.
    """

    def test_the_precommit_config_declares_both_third_party_hooks(self):
        """
        Given: `.pre-commit-config.yaml`
        When: hooks are looked up by id
        Then: at least one `check-jsonschema` entry and exactly one
              `check-metaschema` entry are declared

        Non-vacuity guard: both parametrizations below quantify over these.
        """
        assert PRECOMMIT_HOOKS_BY_ID.get("check-jsonschema"), (
            "No `check-jsonschema` hook is declared. Either the schema-validation "
            "block was removed from .pre-commit-config.yaml, or this test's "
            "assumptions about how it declares hooks no longer hold."
        )
        metaschema_hooks = PRECOMMIT_HOOKS_BY_ID.get("check-metaschema") or []
        assert len(metaschema_hooks) == 1, (
            f"Expected exactly one `check-metaschema` hook, found {len(metaschema_hooks)}. "
            "test_check_metaschema_has_a_ci_counterpart below assumes a single entry."
        )

    def test_every_check_jsonschema_pair_has_a_ci_counterpart(self):
        """
        Given: every (schema, yaml) pair a `check-jsonschema` hook blocks a
               commit on
        When: compared against the pairs `validate_all_schemas.py`'s own
              pairing logic discovers over the real tracked corpus — the only
              CI-side schema validation that exists
        Then: every pre-commit pair is among them

        `check-jsonschema` hooks are unconditionally blocking — no flag makes
        a schema violation a warning — so D1's coverage clause reaches all of
        them, not only the ones ADR-037's instance table happens to name.

        Until 23a455b, `_find_pairs()` globbed `risk-map/schemas/*.schema.json`
        non-recursively (`scripts/hooks/precommit/validate_all_schemas.py`),
        so `risk-map/schemas/archive/self-assessment-legacy.schema.json` and
        its yaml were outside it: the archive pair was validated by a blocking
        pre-commit hook and by no CI job at all — pre-existing, not introduced
        by this branch. 23a455b switched discovery to `rglob`, which is
        correct independent of CI parity (the archive schema does `$ref`
        `riskmap.schema.json`, so a master-schema change genuinely affects
        it), and folding the archive pair into `_find_pairs()`'s own return
        value is what gives it a CI counterpart here too, since this test
        reads that same function. Kept as a standing guard against the pair
        losing coverage again — e.g. a schema added under a directory
        `_find_pairs()` stops recursing into.
        """
        pairs = _check_jsonschema_pairs()
        assert pairs, (
            "No (schema, yaml) pair was parsed out of any check-jsonschema hook's "
            "`args:`. Non-vacuity guard — nothing below would be checked."
        )
        ci_pairs = _ci_schema_yaml_pairs()
        missing = [
            (name, schema, yaml_path) for name, schema, yaml_path in pairs if (schema, yaml_path) not in ci_pairs
        ]
        assert not missing, (
            "These check-jsonschema pairs block a commit locally and are not among "
            "the pairs validate_all_schemas.py's own pairing logic covers in CI:\n"
            + "\n".join(f"  - {name}: schema={schema!r} yaml={yaml_path!r}" for name, schema, yaml_path in missing)
            + f"\nCI pairs found: {sorted(ci_pairs)}\n"
            "ADR-037 D1 requires a CI invocation for every blocking pre-commit hook, "
            "not only the ones its own instance table names."
        )

    def test_check_metaschema_has_a_ci_counterpart(self):
        """
        Given: the `check-metaschema` hook, which blocks a commit whenever any
               tracked `risk-map/schemas/*.schema.json` file is not itself a
               structurally valid JSON Schema document
        When: every workflow step is searched for the equivalent check
              (`check-jsonschema --check-metaschema`)
        Then: at least one is found

        Until 23a455b, none was: `validate_all_schemas.py` validates yaml
        against schema, never a schema document against its own declared
        metaschema, and no workflow step named `--check-metaschema` at all —
        a typo'd keyword or an invalid `$ref` in a `.schema.json` file, the
        exact class of error this hook exists to catch at author time, could
        reach main unopposed by CI, contributor-hook-installation state
        deciding whether it was caught at all. 23a455b added a step to
        `validation.yml`'s schema-validation job running
        `check-jsonschema --check-metaschema` over the file list
        `hook_file_list.py` derives from this hook's own `files:` pattern —
        13 tracked schema files as of this writing. Kept as a standing guard
        against that step being removed or narrowed.
        """
        hook = (PRECOMMIT_HOOKS_BY_ID.get("check-metaschema") or [None])[0]
        if hook is None:
            pytest.fail(
                "No check-metaschema hook is declared; "
                "test_the_precommit_config_declares_both_third_party_hooks reports this."
            )
        matched = _expected_hook_files(hook)
        assert matched, (
            "check-metaschema's own `files:` pattern matched no tracked file, so "
            "there is nothing this hook would block a commit on. Non-vacuity guard — "
            "the assertion below would otherwise pass on an empty corpus."
        )
        assert _ci_runs_check_metaschema(), (
            f"check-metaschema blocks a commit whenever any of {len(matched)} tracked "
            "schema files fails metaschema validation, and no workflow step under "
            f"{_WORKFLOW_DIR} runs the equivalent `check-jsonschema --check-metaschema` "
            "check. ADR-037 D1 requires a CI invocation for every blocking pre-commit "
            "hook; this one has none."
        )

    def test_the_check_metaschema_detector_ignores_a_commented_out_invocation(self):
        """
        Given: a synthetic step whose only mention of `--check-metaschema` is
               inside a comment, with the command that actually runs replaced
               by something unrelated (`if true; then`)
        When: `_third_party_invocations` parses its body
        Then: no invocation carrying `--check-metaschema` is found

        Reproduces mutation M9: replacing the real command with `if true;
        then` while leaving `--check-metaschema` in a comment left the
        previous raw-substring form of `_ci_runs_check_metaschema` reporting
        the step as covered — a string search cannot distinguish a flag on a
        comment line from one on a command line, and a step whose actual
        command no longer runs `check-jsonschema` at all checks nothing.
        `_check_metaschema_steps` (and `_ci_runs_check_metaschema`, which now
        delegates to it) parse structurally instead, the same way
        `_python_invocations` already does for the Python half of this
        module, so a commented-out mention contributes nothing.
        """
        synthetic = WorkflowStep(
            workflow="synthetic.yml",
            job="synthetic",
            label="synthetic",
            run=(
                "# mirrors the check-metaschema hook: check-jsonschema --check-metaschema\n"
                "if true; then\n"
                '  echo "ok"\n'
                "fi\n"
            ),
            shell=None,
            working_directory=None,
            source="synthetic::commented-out-metaschema",
        )
        invocations = _third_party_invocations(synthetic.run, synthetic.source, keep_substitutions=True)
        assert not any("--check-metaschema" in invocation.argv for invocation in invocations), (
            "_third_party_invocations found a real invocation in a step whose only "
            "mention of --check-metaschema is inside a comment. The detector regressed "
            "to a substring scan, which cannot tell a comment from a command."
        )

    def test_check_metaschema_file_list_is_derived_not_transcribed(self):
        """
        Given: the CI step(s) running `check-jsonschema --check-metaschema`
        When: the file list reaching that command's argv is traced back to the
              command that built it, that command is executed, and its output
              is compared against check-metaschema's own `files:` pattern
              evaluated over the tracked corpus
        Then: the step's file list is built from a command (not transcribed
              literally into the step), and that command's output equals the
              hook's own file set exactly

        Reproduces mutation M10: transcribing the file list (one of thirteen
        tracked schemas, hand-picked) in place of
        `$(python3 scripts/tools/hook_file_list.py check-metaschema)` leaves
        every other assertion in this class satisfied — the step still runs
        `check-jsonschema --check-metaschema`, `_ci_runs_check_metaschema`
        still reports it covered — while checking one schema file CI happens
        to have listed instead of every schema check-metaschema's own `files:`
        pattern selects. A schema added, renamed, or moved after the
        transcription silently stops being checked.
        """
        steps = _check_metaschema_steps()
        assert steps, "No check-metaschema step found; test_check_metaschema_has_a_ci_counterpart reports this."

        hook = (PRECOMMIT_HOOKS_BY_ID.get("check-metaschema") or [None])[0]
        expected = set(_expected_hook_files(hook)) if hook else set()
        assert expected, (
            "check-metaschema's own `files:` pattern matched no tracked file. Non-vacuity "
            "guard — test_check_metaschema_has_a_ci_counterpart asserts the same thing."
        )

        for step in steps:
            invocations = _third_party_invocations(step.run, step.source, keep_substitutions=True)
            target = next(inv for inv in invocations if "--check-metaschema" in inv.argv)
            referenced = {match.group(1) for token in target.argv if (match := _SUBST_TOKEN_RE.match(token))}
            substitutions = [(name, command) for name, command in target.substitutions if name in referenced]
            assert substitutions, (
                f"{step.source}: check-jsonschema --check-metaschema is invoked with no "
                f"variable-substitution file list on its command line (argv: "
                f"{target.argv}). Either the list is transcribed literally (drifting "
                "from check-metaschema's own `files:` pattern the moment a schema is "
                "added, renamed, or archived) or it is empty (checking nothing)."
            )
            for name, command in substitutions:
                result = _run_substitution(command, _REPO_ROOT)
                assert result.returncode == 0, (
                    f"{step.source}: the command building {name} ({command!r}) exited "
                    f"{result.returncode}, so the step aborts under `bash -e` before the "
                    f"check ever runs.\nstdout: {result.stdout!r}\nstderr: {result.stderr!r}"
                )
                resolved = set(result.stdout.split())
                assert resolved == expected, (
                    f"{step.source}: the file list check-jsonschema --check-metaschema "
                    f"receives from {name} ({sorted(resolved)}) does not match "
                    f"check-metaschema's own `files:` pattern evaluated over the tracked "
                    f"corpus ({sorted(expected)}). A transcribed or truncated list drifts "
                    "from the hook it is meant to mirror in the permissive direction."
                )

    def test_check_metaschema_step_is_not_exempted_from_failing_the_job(self):
        """
        Given: the CI step(s) running `check-jsonschema --check-metaschema`,
               and their enclosing jobs
        When: `continue-on-error:` and `if:` are inspected at both levels
        Then: neither declares one

        `_gate_steps` now folds THIRD_PARTY_BLOCKING_COMMANDS invocations into
        GATE_STEPS (section 2), so
        `TestGateStepFailsTheJob::test_no_gate_step_is_exempted_from_failing_the_job`
        reaches this step too and this assertion is redundant with that one.
        Kept anyway: it reproduces mutation M29 directly — adding
        `if: github.event_name == 'schedule'` and `continue-on-error: true` to
        the step left every other assertion in this class satisfied on a
        pull-request run, because the step simply does not execute — no
        failure and no conspicuous absence — and this test is the one that
        would have caught it back when check-metaschema sat outside GATE_STEPS.
        A second, independent assertion of the same property costs little and
        pins the historical gap by name.
        """
        steps = _check_metaschema_steps()
        assert steps, "No check-metaschema step found; test_check_metaschema_has_a_ci_counterpart reports this."

        for step in steps:
            exemptions: list[str] = []
            if step.continue_on_error is not None:
                exemptions.append(f"step `continue-on-error: {step.continue_on_error!r}`")
            if step.job_continue_on_error is not None:
                exemptions.append(f"job `continue-on-error: {step.job_continue_on_error!r}`")
            if step.condition is not None:
                exemptions.append(f"step `if: {step.condition!r}`")
            if step.job_condition is not None:
                exemptions.append(f"job `if: {step.job_condition!r}`")
            assert not exemptions, (
                f"{step.source} is exempted from failing the workflow: {exemptions}. "
                "ADR-037 D1 requires a CI invocation of at least the same strictness as "
                "the pre-commit hook it mirrors; a step that may not run at all, or that "
                "may fail without failing its job, enforces nothing on a pull request "
                "where the exemption applies."
            )


# ===========================================================================
# 7. The gate step's own execution context
# ===========================================================================
#
# Two properties of the *step*, rather than of the command, decide whether a
# derived file list means anything.
#
#   Working directory. The resolver enumerates the corpus with `git ls-files`
#   in its working directory and reads `.pre-commit-config.yaml` relative to it,
#   and the paths it emits are repo-root-relative. All three assume the step
#   runs at the repository root. GitHub supplies that by default; nothing in the
#   workflow states it, and a `working-directory:` key or a `cd` would change it
#   without touching a flag.
#
#   Shell. `FILES=$(...)` only aborts the step when the shell exits on error.
#   Under GitHub's default `bash -e {0}` it does, which is the entire mechanism
#   by which the resolver's non-zero exit on an empty match becomes a red job.
#   A shell without `-e` converts that into an empty variable and a green job.


class WorkflowStep(NamedTuple):
    """One `run:` step with the context GitHub would execute it in.

    Attributes:
        workflow: Workflow filename.
        job: Job id.
        label: Step name, or a positional fallback.
        run: The shell body.
        shell: Effective `shell:`, after workflow and job `defaults.run`.
        working_directory: Effective `working-directory:`, same resolution.
        source: Human-readable origin for assertion messages.
        continue_on_error: The step's own `continue-on-error:`, or None.
        condition: The step's own `if:`, or None.
        job_continue_on_error: The enclosing job's `continue-on-error:`, or None.
        job_condition: The enclosing job's `if:`, or None.

    The last four decide whether this step's exit code reaches the job's
    conclusion at all. None of them appears anywhere on a command line, so a
    scan of `run:` bodies cannot see any of them.
    """

    workflow: str
    job: str
    label: str
    run: str
    shell: str | None
    working_directory: str | None
    source: str
    continue_on_error: Any = None
    condition: Any = None
    job_continue_on_error: Any = None
    job_condition: Any = None


def _iter_workflow_steps() -> list[WorkflowStep]:
    """Return every `run:` step across all workflows, with defaults resolved.

    `defaults.run` may be set at workflow and job level; the step's own keys win
    over both. Reproducing that here matters because a `working-directory:`
    declared once at job level silently moves every step in the job.
    """
    steps: list[WorkflowStep] = []
    for workflow in _workflow_files():
        data = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        workflow_defaults = ((data.get("defaults") or {}).get("run") or {}) if isinstance(data, dict) else {}
        for job_id, job in (data.get("jobs") or {}).items():
            job_defaults = (job.get("defaults") or {}).get("run") or {}
            for index, step in enumerate(job.get("steps") or []):
                run_block = step.get("run")
                if not run_block:
                    continue
                label = step.get("name") or f"step[{index}]"
                shell = step.get("shell", job_defaults.get("shell", workflow_defaults.get("shell")))
                working_directory = step.get(
                    "working-directory",
                    job_defaults.get("working-directory", workflow_defaults.get("working-directory")),
                )
                steps.append(
                    WorkflowStep(
                        workflow=workflow.name,
                        job=str(job_id),
                        label=label,
                        run=run_block,
                        shell=shell,
                        working_directory=working_directory,
                        source=f"{workflow.name}::{job_id}::{label}",
                        continue_on_error=step.get("continue-on-error"),
                        condition=step.get("if"),
                        job_continue_on_error=job.get("continue-on-error"),
                        job_condition=job.get("if"),
                    )
                )
    return steps


WORKFLOW_STEPS = _iter_workflow_steps()

# Values of `working-directory:` that are the repository root. GitHub's default
# when the key is absent is $GITHUB_WORKSPACE, which is the checkout root.
_ROOT_WORKING_DIRECTORIES = frozenset(
    {".", "./", "${{ github.workspace }}", "$GITHUB_WORKSPACE", "${GITHUB_WORKSPACE}"}
)

# Shells that exit on error. GitHub maps `bash` to
# `bash --noprofile --norc -eo pipefail {0}` and the default (no key) to
# `bash -e {0}`; both abort on a failing command substitution in an assignment.
_ABORTING_SHELLS = frozenset({"bash"})


def _gate_steps() -> list[WorkflowStep]:
    """Return steps that invoke a validator D1 makes CI's decision on.

    Three disjoint ways a validator earns that: a strictness flag on a Python
    command line (`--block`), membership in D8's flagless set — a Python
    validator with no warn-only tier, so it blocks unconditionally and carries
    no flag for the first test to find — or an invocation of one of
    THIRD_PARTY_BLOCKING_COMMANDS, a hook `.pre-commit-config.yaml` declares
    from a third-party repo rather than a local script; those also have no
    warn-only tier and carry no flag, the same shape as D8's set but for a
    command that is not a `.py` file `_python_invocations` can see. The
    flagless Python set is UNFLAGGED_BLOCKING_SCRIPTS and the third-party set
    is THIRD_PARTY_BLOCKING_COMMANDS, both read from ADR-037's own D1 instance
    table rather than listed here, so a hook that joins either with no
    strictness flag is a gate step with no edit to this function.

    Folding the third-party arm in here — rather than leaving it a special
    case TestThirdPartyBlockingHookCoverage polices on its own — is what gives
    a `check-jsonschema`-shaped hook the same `||`-guard,
    repository-state-bypass, and step-body-execution guarantees section 9
    gives every Python gate step: those are properties of *any* step D1 makes
    the decision on, not properties specific to a local script.

    Derived from the command line rather than from job names, so a gate moved
    into another job or workflow stays governed.
    """
    gates: list[WorkflowStep] = []
    for step in WORKFLOW_STEPS:
        invocations = _python_invocations(step.run, step.source, keep_substitutions=True)
        python_gate = any(
            STRICTNESS_FLAGS.intersection(inv.argv) or inv.script in UNFLAGGED_BLOCKING_SCRIPTS
            for inv in invocations
        )
        third_party_gate = bool(_third_party_invocations(step.run, step.source))
        if python_gate or third_party_gate:
            gates.append(step)
    return gates


GATE_STEPS = _gate_steps()


class TestGateStepsRunFromRepositoryRoot:
    """Every D1 gate step runs at the repository root, in a shell that aborts.

    GATE_STEPS is the union `_gate_steps` derives: steps invoking a
    `--block`-flagged validator, steps invoking one of ADR-037 D8's flagless
    governed validators (UNFLAGGED_BLOCKING_SCRIPTS), and steps invoking a
    THIRD_PARTY_BLOCKING_COMMANDS member directly. Both guards below are
    properties of the step rather than of the command, so they apply
    identically to every member of that union — a flagless or third-party
    validator's execution context is exactly as load-bearing as a flagged
    one's, which is the whole of D8's point and applies just as much to a hook
    `.pre-commit-config.yaml` declares from a third-party repo.

    Both are currently satisfied by GitHub's defaults rather than by anything
    the workflow says. That is precisely why they need pinning: an edit that
    changes either leaves the command line untouched, so every other test in
    this module keeps passing while the gate stops gating.

    The two behavioural tests at the end establish that the properties being
    pinned are load-bearing — that the file list really does change with the
    working directory, and that `bash -e` really does abort on a failing
    substitution. Without them these would be prohibitions on things that might
    not matter. Both draw their commands from `_step_substitutions`, which is
    empty for a D8 flagless step (those validators resolve their own corpus
    instead of building a file list from a command) but non-empty for the
    flagged five and for the check-metaschema step, whose resolver feeds its
    third-party validator the same way a flagged step's does.
    """

    def test_gate_steps_are_found(self):
        """
        Given: every `run:` step in every workflow
        When: steps invoking a blocking validator — one carrying a strictness
              flag, or one of ADR-037 D8's flagless governed validators — are
              selected
        Then: at least one is found

        Non-vacuity guard: the prohibitions below quantify over this set. It
        passes today on the flagged half alone; the flagless half has its own
        guard immediately below, because a set that unions two derivations can
        stay non-empty while one of them silently returns nothing.
        """
        assert GATE_STEPS, (
            "Found no workflow step invoking a blocking validator — one carrying "
            f"{sorted(STRICTNESS_FLAGS)}, or one of ADR-037 D8's flagless governed "
            "validators. Either ADR-037 D1's coverage regressed entirely, or step "
            "parsing did — the second passes every prohibition in this class by "
            "having nothing to prohibit."
        )

    def test_gate_steps_are_found_for_the_flagless_half(self):
        """
        Given: every `run:` step in every workflow
        When: steps invoking one of ADR-037 D8's flagless governed validators
              (UNFLAGGED_BLOCKING_SCRIPTS) are selected
        Then: at least one is found

        The non-vacuity guard `test_gate_steps_are_found` cannot see this gap:
        GATE_STEPS is non-empty today because of the five flagged steps, and
        would stay non-empty — silently passing every prohibition in this class
        for the flagless validators it never actually reaches — even if
        `_gate_steps`'s flagless arm returned nothing at all, whether because no
        workflow invokes one yet or because the arm itself broke.

        Expected RED as committed: ADR-037 D8 records that none of the six
        flagless validators has a CI invocation yet.
        TestUnflaggedBlockingCoverage::test_ci_invokes_every_unflagged_blocking_hook
        pins the identical gap from the pre-commit side, per hook id; this is
        the same fact stated as the precondition for the two guards below to
        mean anything for D8's half of GATE_STEPS.
        """
        flagless_gates = [
            step
            for step in GATE_STEPS
            if any(
                inv.script in UNFLAGGED_BLOCKING_SCRIPTS
                for inv in _python_invocations(step.run, step.source, keep_substitutions=True)
            )
        ]
        assert flagless_gates, (
            "No gate step invokes a flagless governed validator "
            f"({sorted(UNFLAGGED_BLOCKING_SCRIPTS)}). GATE_STEPS today is only the "
            "flagged five, so the root-working-directory and aborting-shell "
            "guards below quantify over none of D8's validators: a D8 CI step "
            "added at the wrong working directory, or under a shell that "
            "swallows failures, would pass every prohibition in this class "
            "while not gating."
        )

    def test_no_gate_step_declares_a_non_root_working_directory(self):
        """
        Given: every gate step, with workflow- and job-level defaults resolved
        When: its effective `working-directory:` is inspected
        Then: it is absent or names the repository root

        The file-list resolver runs `git ls-files` in the step's working
        directory, reads `.pre-commit-config.yaml` relative to it, and emits
        repo-root-relative paths that the validator then opens relative to it.
        A `working-directory:` anywhere in the job breaks all three at once,
        and nothing in the command line changes.
        """
        violations = [
            step
            for step in GATE_STEPS
            if step.working_directory is not None
            and step.working_directory.strip() not in _ROOT_WORKING_DIRECTORIES
        ]
        assert not violations, (
            "Gate steps must run at the repository root:\n"
            + "\n".join(f"  - {step.source}: working-directory: {step.working_directory!r}" for step in violations)
            + "\nThe derived file list, the config it comes from, and the paths it "
            "names are all resolved relative to the working directory."
        )

    def test_no_gate_step_changes_directory(self):
        """
        Given: every gate step's shell body
        When: simple commands are scanned for `cd`
        Then: none is present

        The same hazard as the previous test by a different spelling, and the
        one a `working-directory:` check alone would miss. A `cd` mid-block
        moves every command after it.
        """
        violations: list[tuple[str, str]] = []
        for step in GATE_STEPS:
            for raw_line in step.run.splitlines():
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                for segment in _split_simple_commands(_safe_split(stripped)):
                    while segment and (segment[0] in _LEADING_WORDS or _TOKEN_ASSIGN_RE.match(segment[0])):
                        segment = segment[1:]
                    if segment and segment[0] == "cd":
                        violations.append((step.source, stripped))
        assert not violations, (
            "Gate steps must not change working directory:\n"
            + "\n".join(f"  - {source}: {line}" for source, line in violations)
            + "\nEvery path in these steps — the pre-commit config, the tracked corpus, "
            "and the file arguments themselves — is resolved relative to it."
        )

    def test_gate_steps_use_a_shell_that_aborts_on_error(self):
        """
        Given: every gate step's effective `shell:`
        When: it is checked for exit-on-error behaviour
        Then: it is GitHub's default or `bash`, or the body sets `-e` itself

        `FILES=$(resolver)` carries the resolver's exit status. Under a shell
        without `-e` a failed resolution leaves `FILES` empty and execution
        continues to the validator, which — for the two `nargs="*"` validators —
        exits 0 immediately. The resolver's careful non-zero exit on an empty
        match then buys nothing.

        `set -e` in the body counts, but only as a command. A substring test
        would be satisfied by the same three characters inside a comment or an
        `echo`, which change nothing; `_enables_errexit` looks for a real `set`
        simple command. `set +e` anywhere in a gate body is a violation on its
        own, whatever the declared shell, because it undoes the property the
        rest of this class depends on.
        """
        violations = [
            step
            for step in GATE_STEPS
            if step.shell is not None and step.shell not in _ABORTING_SHELLS and not _enables_errexit(step.run)
        ]
        assert not violations, (
            "Gate steps must run under a shell that exits on error:\n"
            + "\n".join(f"  - {step.source}: shell: {step.shell!r}" for step in violations)
            + "\nOtherwise a failing file-list resolution becomes an empty variable and "
            "a green job instead of a failed step."
        )

        disabled = [step for step in GATE_STEPS if _disables_errexit(step.run)]
        assert not disabled, (
            "Gate steps must not turn exit-on-error back off:\n"
            + "\n".join(f"  - {step.source}" for step in disabled)
            + "\n`set +e` restores the failure mode the declared shell was chosen to "
            "prevent, and leaves every command line in the step untouched."
        )

    def test_the_derived_file_list_depends_on_the_working_directory(self):
        """
        Given: a gate step's file-list command
        When: it is run from the repository root and from a subdirectory
        Then: the two results differ

        Fidelity check for the two working-directory prohibitions above. They
        pass today by GitHub's default; this establishes that the default is
        load-bearing rather than incidental, so a future reader cannot conclude
        the prohibitions are guarding nothing.
        """
        commands = sorted({command for step in GATE_STEPS for _, command in _step_substitutions(step) if command})
        if not commands:
            pytest.fail(
                "No gate step builds a file list from a command, so this fidelity "
                "check has nothing to run. "
                "TestCIFileListsAreDerivedAndComplete reports that as the D7a gap."
            )

        subdirectory = _REPO_ROOT / "scripts"
        insensitive: list[str] = []
        for command in commands:
            from_root = _run_substitution(command, _REPO_ROOT)
            from_subdirectory = _run_substitution(command, subdirectory)
            if (from_root.returncode, from_root.stdout) == (
                from_subdirectory.returncode,
                from_subdirectory.stdout,
            ):
                insensitive.append(command)

        assert not insensitive, (
            "These file-list commands return the same result from a subdirectory as "
            f"from the repository root: {insensitive}. The working-directory "
            "prohibitions above would then be guarding a hazard that no longer exists "
            "— re-derive them before deleting them."
        )

    def test_a_failing_file_list_aborts_the_step_shell(self):
        """
        Given: GitHub's default shell behaviour, reproduced with `bash -e`
        When: an assignment's command substitution exits non-zero
        Then: the shell aborts before the next command

        PLATFORM ASSERTION. Unlike everything else in this module it reads no
        repository state: it pins a property of `bash`, not of this repository,
        and no edit to a workflow, a validator, or the resolver can make it
        fail. It stays because the rest of the class reasons from it — the
        resolver's non-zero exit on an empty match is only a gate if the shell
        acts on it — and because a future move to a shell without `-e` should
        break something visible. Read a failure here as "the platform changed",
        never as "the repository regressed".
        """
        result = subprocess.run(
            ["bash", "-e", "-c", "FILES=$(exit 3)\necho reached"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, (
            "A failing command substitution in an assignment did not abort `bash -e`. "
            "The resolver's exit-1-on-empty-match contract then has no effect on the "
            f"job's result.\nstdout: {result.stdout!r}"
        )
        assert "reached" not in result.stdout, (
            "Execution continued past the failed assignment, so the validator would "
            f"run with an empty file list.\nstdout: {result.stdout!r}"
        )


def _step_substitutions(step: WorkflowStep) -> list[tuple[str, str]]:
    """Return (variable, command) pairs for command substitutions a step's validator uses.

    Scans both `_python_invocations` and `_third_party_invocations` — the
    check-metaschema step's `FILES=$(python3 scripts/tools/hook_file_list.py
    check-metaschema)` resolver feeds `check-jsonschema --check-metaschema
    ${FILES}`, a THIRD_PARTY_BLOCKING_COMMANDS invocation the first scanner
    cannot see (it only recognizes `.py` files and python interpreters), so a
    Python-only scan here would leave that step's resolver-failure path
    untested even though it is a GATE_STEPS member.
    """
    pairs: list[tuple[str, str]] = []
    invocations = [
        *_python_invocations(step.run, step.source, keep_substitutions=True),
        *_third_party_invocations(step.run, step.source, keep_substitutions=True),
    ]
    for invocation in invocations:
        referenced = {match.group(1) for token in invocation.argv if (match := _SUBST_TOKEN_RE.match(token))}
        pairs.extend((name, command) for name, command in invocation.substitutions if name in referenced)
    return pairs


# ===========================================================================
# 8. Trigger coverage — the gate has to run to be a gate
# ===========================================================================
#
# ADR-037 D1 makes CI the authoritative gate. A workflow that does not run on a
# pull request is not a gate on that pull request, and `paths:` filters decide
# which pull requests it runs on. Two consequences, both of which are edits
# nothing else in this suite can see:
#
#   - a gate workflow that does not trigger on its own definition, or on the
#     validators it runs, does not re-run when either changes. The pull request
#     that removes a `--block` is then merged without the gate it removed ever
#     executing.
#   - the workflow that runs pytest is where every standing guard in this module
#     lives. If it does not trigger on the files those guards assert over, the
#     guards do not run on the pull requests that edit them.


def _workflow_data(name: str) -> dict[str, Any]:
    """Return a parsed workflow by filename."""
    return yaml.safe_load((_WORKFLOW_DIR / name).read_text(encoding="utf-8"))


def _declared_events(data: dict[str, Any]) -> set[str]:
    """Return every event name a workflow's `on:` block declares.

    `_trigger_filters` only returns events carrying a `paths:`/`paths-ignore:`
    filter — by design, since an unfiltered event cannot be the cause of a
    missed *path* trigger. It is silent on an event missing altogether, which
    is exactly what `pull_request:` being deleted from a gate workflow looks
    like: no filter is missing, because there is no event to have one.

    Handles all three spellings GitHub accepts for `on:`: a bare event name
    (which PyYAML 1.1 reads as the boolean `True` key), a list of event names,
    and a mapping keyed by event name. A workflow missing `on:` entirely
    declares no events.
    """
    triggers = data.get("on", data.get(True))
    if isinstance(triggers, dict):
        return {str(event) for event in triggers}
    if isinstance(triggers, list):
        return {str(event) for event in triggers}
    if isinstance(triggers, str):
        return {triggers}
    return set()


def _event_branches(data: dict[str, Any], event: str) -> list[str] | None:
    """Return an event's declared `branches:` filter, or None if unrestricted.

    None means the event fires against a pull request or push targeting any
    base branch — GitHub's default when the key is absent — which is at least
    as permissive as any explicit list and is therefore never itself a
    coverage gap.

    This is the enumeration half only — "which branches does `push` name as
    ones it protects" — and reads exactly the `branches:` key. It is
    deliberately blind to `branches-ignore:`: an ignore-list names branches by
    exclusion, not by enumeration, so there is no finite list to return for
    it. `_event_reaches_branch` below is the reachability half, and is what a
    caller needs to ask "would this *other* event's filter still fire for one
    of these branches" — a question `branches-ignore:` can answer without
    being enumerable.
    """
    triggers = data.get("on", data.get(True))
    if not isinstance(triggers, dict):
        return None
    config = triggers.get(event)
    if not isinstance(config, dict):
        return None
    branches = config.get("branches")
    return [str(branch) for branch in branches] if branches else None


def _event_reaches_branch(data: dict[str, Any], event: str, branch: str) -> bool:
    """True when an event's branch filter would fire for `branch`.

    GitHub accepts exactly one of `branches:` (an allow-list — the branch must
    match a listed pattern) or `branches-ignore:` (a deny-list — the branch
    must not match one) per event, never both on the same event. Absent
    either, every branch is allowed, which is GitHub's default and at least as
    permissive as any explicit filter.

    `_event_branches` only ever reads `branches:`, so a `pull_request` trigger
    rewritten as `branches-ignore: [main, develop]` reads back as `None` there
    — "unrestricted" — when it is in fact restricted to exactly the branches
    `push` does not name and is therefore unreachable for every branch `push`
    protects. This function is what closes that: it answers the reachability
    question directly, for both spellings, reusing `_filter_matches`'s glob
    semantics (the same dialect GitHub documents for branch filters as for
    `paths:`).
    """
    triggers = data.get("on", data.get(True))
    if not isinstance(triggers, dict):
        return True
    config = triggers.get(event)
    if not isinstance(config, dict):
        return True
    branches = config.get("branches")
    branches_ignore = config.get("branches-ignore")
    if branches:
        return _filter_matches([str(b) for b in branches], branch)
    if branches_ignore:
        return not _filter_matches([str(b) for b in branches_ignore], branch)
    return True


# GitHub's default `pull_request` activity types
# (https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#pull_request).
# A declared `types:` list REPLACES this default rather than extending it, so
# a workflow scoped to types outside this set never runs during a pull
# request's normal open-review-push lifecycle — `types: [closed]` is the
# sharpest case: the trigger is declared, `branches:` may be unrestricted, and
# the workflow still never produces a status check while the PR is open.
_DEFAULT_PULL_REQUEST_TYPES = frozenset({"opened", "synchronize", "reopened"})


def _event_types(data: dict[str, Any], event: str) -> list[str] | None:
    """Return an event's declared `types:` filter, or None if GitHub's default applies."""
    triggers = data.get("on", data.get(True))
    if not isinstance(triggers, dict):
        return None
    config = triggers.get(event)
    if not isinstance(config, dict):
        return None
    types = config.get("types")
    return [str(t) for t in types] if types else None


class TriggerFilter(NamedTuple):
    """One event's path filter, in whichever of the two spellings it uses.

    Attributes:
        event: Event name (`pull_request`, `push`, ...).
        kind: `"paths"` (the path must match to trigger) or `"paths-ignore"`
            (the path must NOT match to trigger).
        patterns: The declared pattern list.
    """

    event: str
    kind: str
    patterns: list[str]


def _trigger_filters(data: dict[str, Any]) -> list[TriggerFilter]:
    """Return the path filters a parsed workflow declares, per event.

    YAML 1.1 reads a bare `on:` key as the boolean True, which PyYAML preserves,
    so both spellings are looked up. Events with neither filter are omitted:
    they run unconditionally and cannot be the cause of a missed trigger.

    `paths-ignore` is modelled rather than ignored. It is the exact complement
    of `paths` — GitHub forbids declaring both on one event — and a workflow
    switching to it would make every trigger assertion here pass vacuously,
    because a filter keyed only on `paths` comes back empty and an empty filter
    set reads as "runs unconditionally".
    """
    triggers = data.get("on", data.get(True))
    if not isinstance(triggers, dict):
        return []
    filters: list[TriggerFilter] = []
    for event, config in triggers.items():
        if not isinstance(config, dict):
            continue
        if config.get("paths"):
            filters.append(TriggerFilter(str(event), "paths", list(config["paths"])))
        elif config.get("paths-ignore"):
            filters.append(TriggerFilter(str(event), "paths-ignore", list(config["paths-ignore"])))
    return filters


def _glob_to_regex(pattern: str) -> re.Pattern:
    """Translate a GitHub `paths:` filter pattern to a regex.

    Approximates the documented semantics: `*` matches within a path segment,
    `**` matches across segments, `?` matches one non-separator character. The
    `/**/` form matches zero or more intervening segments, so
    `.github/workflows/**/*.yml` matches a file directly under `workflows/`.
    """
    out: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("/**/", index):
            out.append("(?:/.*)?/")
            index += 4
        elif pattern.startswith("**/", index) and index == 0:
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("/**", index) and index + 3 == len(pattern):
            out.append("/.*")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(out) + r"\Z")


def _filter_matches(patterns: list[str], path: str) -> bool:
    """True when a GitHub `paths:` filter list selects a path.

    Patterns are applied in order; a leading `!` negates, matching GitHub's
    last-match-wins evaluation.
    """
    matched = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        body = pattern[1:] if negated else pattern
        if _glob_to_regex(body).match(path):
            matched = not negated
    return matched


def _covered_by_every_event(workflow_name: str, path: str) -> list[str]:
    """Return the events whose path filter does NOT select the given path.

    A `paths:` filter selects the path when it matches; a `paths-ignore:` filter
    selects it when it does not.
    """
    uncovered: list[str] = []
    for declared in _trigger_filters(_workflow_data(workflow_name)):
        matched = _filter_matches(declared.patterns, path)
        selected = matched if declared.kind == "paths" else not matched
        if not selected:
            uncovered.append(declared.event)
    return sorted(uncovered)


class ScriptResolution(NamedTuple):
    """The outcome of resolving an executed script basename to a tracked file.

    Attributes:
        basename: The name as it appeared on the command line.
        path: The single tracked path it resolved to, or None.
        candidates: Every tracked path carrying that basename.
        source: The step the invocation came from.
    """

    basename: str
    path: str | None
    candidates: tuple[str, ...]
    source: str


def _real_script_path(basename: str) -> tuple[str | None, tuple[str, ...]]:
    """Resolve a script basename to its tracked repo-relative path.

    CI copies some validators to the repository root before running them
    (ADR-037 D5 keeps that arrangement), so the path on the command line is not
    always the path in the repository. Trigger filters have to name the real one.

    Returns both the resolution and every candidate, so an ambiguous or absent
    basename can be *reported* rather than dropped. The previous form searched
    `scripts/**` only and returned None on zero or several matches, and the
    caller skipped None silently: a gate step running
    `python3 .github/helpers/preflight.py` lost its trigger requirement without
    a single test noticing.

    The search is over tracked files rather than a directory glob, so a script
    anywhere in the repository resolves and untracked build output cannot.
    """
    declared = PRECOMMIT_VALIDATORS.get(basename)
    if declared:
        return declared, (declared,)
    candidates = tuple(sorted(TRACKED_BY_BASENAME.get(basename, [])))
    return (candidates[0] if len(candidates) == 1 else None), candidates


def _workflow_script_resolutions(workflow_name: str) -> list[ScriptResolution]:
    """Return one resolution record per script a workflow's steps execute.

    Covers both direct executions and executions inside a command substitution
    — the file-list resolver reaches the workflow only the second way.
    """
    resolutions: list[ScriptResolution] = []
    for step in WORKFLOW_STEPS:
        if step.workflow != workflow_name:
            continue
        invocations = _python_invocations(step.run, step.source, keep_substitutions=True)
        nested = [
            inner
            for invocation in invocations
            for _, command in invocation.substitutions
            for inner in _python_invocations(command, step.source)
        ]
        for invocation in [*invocations, *nested]:
            path, candidates = _real_script_path(invocation.script)
            resolutions.append(ScriptResolution(invocation.script, path, candidates, step.source))
    return resolutions


def _copied_dependencies(workflow_name: str) -> set[str]:
    """Return the tracked files a workflow's file-relocating commands stage.

    Copy operands may be globs (`riskmap_validator/*`), and a glob match may be
    a *directory*: `cp -r scripts/hooks/riskmap_validator/*` stages the
    `graphing/` package as well as the five top-level modules. Filtering matches
    to `is_file()` dropped that whole subtree, so a pull request touching only
    `riskmap_validator/graphing/` was not required to re-run the gate that
    executes it. Directories are therefore expanded to the tracked files beneath
    them.
    """
    dependencies: set[str] = set()
    for step in WORKFLOW_STEPS:
        if step.workflow != workflow_name:
            continue
        for copy in _copy_commands(step.run, step.source):
            for match in sorted(_REPO_ROOT.glob(copy.source_path)):
                relative = match.relative_to(_REPO_ROOT).as_posix()
                if match.is_dir():
                    prefix = f"{relative}/"
                    dependencies |= {path for path in TRACKED_FILES if path.startswith(prefix)}
                elif relative in TRACKED_FILE_SET:
                    dependencies.add(relative)
    return dependencies


def _workflow_dependencies(workflow_name: str) -> set[str]:
    """Return the repo files a workflow's steps execute or stage into place.

    Fails loudly on a basename that does not resolve to exactly one tracked
    file. Returning a partial set would understate what the `paths:` filter has
    to cover, and understating it is silent in both directions: the trigger test
    passes, and the gate does not run on the pull request that changes the
    unresolved script.
    """
    resolutions = _workflow_script_resolutions(workflow_name)
    unresolved = [record for record in resolutions if record.path is None]
    if unresolved:
        pytest.fail(
            f"{workflow_name}: these executed scripts do not resolve to exactly one "
            f"tracked repository file, so their trigger requirement cannot be derived:\n"
            + "\n".join(
                f"  - {record.basename} ({record.source}): "
                f"{list(record.candidates) or 'no tracked file with that name'}"
                for record in unresolved
            )
            + "\ntest_every_executed_script_resolves_to_one_tracked_file reports the same "
            "finding with the reasoning; it is repeated here because silently skipping "
            "an unresolved script is how a gate loses a trigger requirement unnoticed."
        )

    dependencies = {record.path for record in resolutions if record.path}
    return dependencies | _copied_dependencies(workflow_name)


def _reads_precommit_config(repo_relative_script: str) -> bool:
    """True when a script's source names the pre-commit config as an input.

    A script's data dependencies are not derivable in general. This is the one
    that exists today — the file-list resolver reads `.pre-commit-config.yaml`
    to find the hook whose patterns it evaluates — and a textual check finds it
    without this module having to name the resolver.
    """
    path = _REPO_ROOT / repo_relative_script
    return path.is_file() and _PRECOMMIT_CONFIG.name in path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The corpus a gate's governed hooks scan, and the modules its scripts import
# ---------------------------------------------------------------------------
#
# `_workflow_dependencies` above answers "what does this workflow execute or
# copy". That is not the same question as "what does D1 require this workflow
# to trigger on": a hook's own `files:` pattern names the *content* it exists
# to check, which a script-execution scan never sees at all, and a validator's
# local imports are read but never appear on any command line, so the same
# scan misses them too. Both are additional trigger requirements, not a
# rewrite of `_workflow_dependencies` — nothing else in this module attributes
# a required trigger path to a hook's `files:` pattern or to an import graph,
# and folding either into the shared helper would change what every other
# test that calls it also requires.
#
# Reconciling a hook's `files:` regex against a workflow's `paths:` glob
# symbolically is not attempted here: they are different pattern languages
# (regex vs. a glob dialect with its own `**` semantics), and a translation
# between them could pass while a real file either side would actually match
# is missed. Both sides are instead evaluated against the same concrete
# input — every file `git ls-files` tracks — which is exact for both:
# `_expected_hook_files` (section 6) already evaluates a hook's `files:`/
# `exclude:` regex over that corpus, and `_covered_by_every_event` already
# evaluates a workflow's `paths:` glob over it. Sampling the tracked corpus
# rather than enumerating it here is what keeps the comparison sound as the
# corpus grows: a file added tomorrow under `scripts/agents/` is swept in by
# `_expected_hook_files` with no edit to this module.


def _governed_hook_input_paths(workflow_name: str) -> set[str]:
    """Return the tracked files ADR-037's governed hooks select, for hooks this workflow runs.

    A governed hook is in scope for a workflow only if the workflow actually
    executes that hook's validator — matched on basename against
    `_workflow_script_resolutions`, the same resolution `_workflow_dependencies`
    uses. A hook whose script this workflow never runs contributes no
    requirement to it.
    """
    executed_basenames = {Path(record.basename).name for record in _workflow_script_resolutions(workflow_name)}
    paths: set[str] = set()
    for hook_id in ADR_GOVERNED_HOOK_IDS:
        hooks = PRECOMMIT_HOOKS_BY_ID.get(hook_id) or []
        if len(hooks) != 1:
            # test_the_governed_hooks_resolve_to_the_precommit_config reports
            # a table row that does not resolve to exactly one hook; nothing
            # here can be derived from it either.
            continue
        hook = hooks[0]
        script = _hook_script(hook)
        if script is not None and script not in executed_basenames:
            continue
        paths |= set(_expected_hook_files(hook))
    return paths


# Two sys.path roots are live in this codebase's `precommit/` validators: the
# repository root (`import scripts.build_persona_site_data`,
# `from scripts.hooks._sentinel_expansion import ...`) and `scripts/hooks/`
# itself, added by each validator so `precommit.*` resolves whether it is
# executed directly (pre-commit's `entry:`, CI's command line) or imported as
# part of the `precommit` package (`import precommit._neutrality_data as
# data`). Both are tried when resolving a dotted import name below; a name
# that resolves under neither is not a local module — most commonly a
# third-party package — and contributes no trigger requirement.
_IMPORT_ROOTS = (_REPO_ROOT, _HOOKS_DIR)


def _resolve_local_import(module_name: str) -> str | None:
    """Resolve a dotted import name to a tracked repo-relative `.py` file, or None.

    Tries both the plain-module reading (`precommit._prose_fields` ->
    `precommit/_prose_fields.py`) and the package reading
    (`precommit` -> `precommit/__init__.py`), because `from precommit import
    _prose_fields` resolves `node.module` to `"precommit"` alone — the
    submodule name lives in the import's `names`, not in `module_name` here —
    and a bare `precommit` has no `.py` file of its own, only a package
    directory with an `__init__.py`. `_local_import_closure` is what supplies
    the submodule-qualified name as a second candidate for that shape; this
    function only has to resolve whichever dotted name it is given.

    Returns None for a name that does not resolve under either
    `_IMPORT_ROOTS` entry to a file `git ls-files` tracks — including every
    third-party package (`yaml`, `jsonschema`, ...), which has no repo-relative
    path to add as a trigger requirement in the first place.
    """
    parts = module_name.split(".")
    for root in _IMPORT_ROOTS:
        for candidate in (root.joinpath(*parts).with_suffix(".py"), root.joinpath(*parts, "__init__.py")):
            if candidate.is_file():
                relative = candidate.resolve().relative_to(_REPO_ROOT).as_posix()
                if relative in TRACKED_FILE_SET:
                    return relative
    return None


def _resolve_relative_import(current: str, level: int, module: str | None, alias_names: list[str]) -> list[str]:
    """Resolve a relative import (`node.level > 0`) to tracked repo-relative files.

    `level` counts leading dots: `from . import x` is level 1 (the current
    script's own package); `from .. import x` is level 2 (one package up); and
    so on. `module`, when present, is the dotted name after the dots
    (`from .foo import x` has `module="foo"`). When `module` is absent
    (`from . import x`), each name in `alias_names` is itself a candidate
    submodule of the resolved package — the same ambiguity
    `_resolve_local_import`'s package/plain-module split handles for absolute
    imports, reproduced here because a relative import's base is a directory,
    not a name `_IMPORT_ROOTS` can look up directly.
    """
    base_dir = (_REPO_ROOT / current).parent
    for _ in range(level - 1):
        base_dir = base_dir.parent

    def _candidates(parts: list[str]) -> list[Path]:
        return [base_dir.joinpath(*parts).with_suffix(".py"), base_dir.joinpath(*parts, "__init__.py")]

    resolved: list[str] = []
    name_lists = [module.split(".")] if module else [[name] for name in alias_names]
    for parts in name_lists:
        for candidate in _candidates(parts):
            if candidate.is_file():
                relative = candidate.resolve().relative_to(_REPO_ROOT).as_posix()
                if relative in TRACKED_FILE_SET:
                    resolved.append(relative)
                break
    return resolved


# Names a dynamic import can be reached under. `__import__` is Python's
# builtin, callable under that name with no import statement at all; the
# other two are `importlib`'s, and reaching either as a bare name (rather
# than through an attribute chain) requires a `from importlib import
# import_module` — with or without `as` — which `_dynamic_import_aliases`
# resolves per file.
_DYNAMIC_IMPORT_TARGETS = frozenset({"import_module", "spec_from_file_location"})


def _dynamic_import_aliases(tree: ast.AST) -> frozenset[str]:
    """Return every bare name in `tree` that could invoke a dynamic import.

    Always includes `__import__`: `__import__("precommit._prose_fields",
    fromlist=[...])` calls the builtin directly, under no import statement at
    all, and is exactly as capable of loading a module `ast.Import`/
    `ast.ImportFrom` never sees as `importlib.import_module` is.

    Also includes every name a `from importlib import import_module` (or
    `from importlib.util import spec_from_file_location`) statement binds,
    alias or not — `_is_dynamic_local_import_call`'s attribute-chain check
    only recognizes the qualified spelling (`importlib.import_module(...)`),
    and both `from importlib import import_module` (bare name, no `as`) and
    `from importlib import import_module as im` (aliased) call it as a
    `Name`, never an `Attribute`.
    """
    aliases = {"__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in _DYNAMIC_IMPORT_TARGETS:
                    aliases.add(alias.asname or alias.name)
    return frozenset(aliases)


def _is_dynamic_local_import_call(node: ast.AST, aliases: frozenset[str]) -> bool:
    """True for a call to a dynamic-import function, by attribute or bare name.

    Two call shapes, both producing no `ast.Import`/`ast.ImportFrom` node, so
    `_local_import_closure`'s walk cannot follow either no matter how it
    handles those two node types:

      - an attribute chain ending in `import_module` or
        `spec_from_file_location` (`importlib.import_module(...)`,
        `iu.spec_from_file_location(...)` after `import importlib.util as
        iu`) — detected structurally, by attribute name, rather than by a
        fixed dotted-name string, so the module alias does not matter;
      - a bare `Name` call whose name is in `aliases`
        (`_dynamic_import_aliases`) — `import_module(...)` after
        `from importlib import import_module`, an aliased spelling of either
        function, or `__import__(...)` directly.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr in _DYNAMIC_IMPORT_TARGETS
    if isinstance(func, ast.Name):
        return func.id in aliases
    return False


def _local_import_closure(repo_relative_script: str) -> set[str]:
    """Return every tracked local module a script imports, transitively.

    Parsed with `ast` rather than executed, so a scanned module's own
    import-time side effects (argument parsing, `sys.path` mutation) never
    run. Only imports `_resolve_local_import`/`_resolve_relative_import`
    resolve to a tracked file are followed; everything else — a third-party
    package, a name shadowed by a package that happens to share a prefix — is
    left alone rather than guessed at, because a false resolution would invent
    a trigger requirement that does not exist.

    Three import shapes are followed:

      - `import a.b.c` and `from a.b import c` (`node.level == 0`): resolved
        directly, and — because `from a.b import c` cannot be told apart from
        `from a.b import c` where `c` is itself a submodule rather than an
        attribute without trying both — `a.b.c` is also tried as a second
        candidate per name in `node.names`.
      - `from . import x` / `from .pkg import x` (`node.level > 0`): resolved
        relative to the current script's own package via
        `_resolve_relative_import`.

    A dynamic import — `importlib.import_module(...)`,
    `importlib.util.spec_from_file_location(...)`, or `__import__(...)`, by
    attribute chain, bare name, or alias (`_is_dynamic_local_import_call`) —
    is a fourth shape this walk cannot follow at all: none of those calls
    produces an `ast.Import`/`ast.ImportFrom` node, so it is reported loudly
    via `pytest.fail` rather than silently resolving to nothing, per the same
    reasoning `_workflow_dependencies` gives for an unresolved script
    basename: a silently incomplete closure understates a trigger requirement
    with nothing to say so.
    """
    closure: set[str] = set()
    stack = [repo_relative_script]
    while stack:
        current = stack.pop()
        path = _REPO_ROOT / current
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=current)
        dynamic_import_aliases = _dynamic_import_aliases(tree)
        for node in ast.walk(tree):
            if _is_dynamic_local_import_call(node, dynamic_import_aliases):
                pytest.fail(
                    f"{current}: calls a dynamic import (importlib.import_module, "
                    "importlib.util.spec_from_file_location, or __import__, by attribute, "
                    f"bare name, or alias) at line {getattr(node, 'lineno', '?')}. "
                    "`_local_import_closure` cannot follow any of those forms — none "
                    "produces an ast.Import/ast.ImportFrom node — so any module loaded "
                    "this way is invisible to the trigger requirement this closure builds. "
                    "Resolve it by hand and extend this function, rather than let the "
                    "closure silently omit it."
                )
            candidate_names: list[str] = []
            if isinstance(node, ast.Import):
                candidate_names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                # `node.module` alone covers `from a.b import c` where `c` is an
                # attribute of `a.b`. `f"{node.module}.{alias.name}"` covers the
                # submodule-import form `from a import b` (module="a",
                # names=["b"]), which `node.module` alone cannot reach — `a` by
                # itself resolves to the package's own `__init__.py`, not to `b`.
                candidate_names = [node.module, *(f"{node.module}.{alias.name}" for alias in node.names)]
            elif isinstance(node, ast.ImportFrom) and node.level > 0:
                for resolved in _resolve_relative_import(
                    current, node.level, node.module, [alias.name for alias in node.names]
                ):
                    if resolved != repo_relative_script and resolved not in closure:
                        closure.add(resolved)
                        stack.append(resolved)
                continue
            else:
                continue
            for module_name in candidate_names:
                resolved = _resolve_local_import(module_name)
                if resolved and resolved != repo_relative_script and resolved not in closure:
                    closure.add(resolved)
                    stack.append(resolved)
    return closure


def _executed_script_import_closure(workflow_name: str) -> set[str]:
    """Return the local import closure of every script a workflow executes."""
    closure: set[str] = set()
    for record in _workflow_script_resolutions(workflow_name):
        if record.path:
            closure |= _local_import_closure(record.path)
    return closure


class TestLocalImportClosureResolvesAllImportForms:
    """`_local_import_closure` has to see every import shape a validator can use.

    ADR-037 D1's trigger requirement
    (`TestWorkflowTriggerCoverage::test_gate_workflow_triggers_on_the_corpus_its_governed_hooks_scan`)
    reads a validator's own local imports through this closure, so an import
    shape the closure cannot follow is a trigger requirement nothing states —
    silently, since a missing entry in a derived set produces no error, only a
    smaller one.

    Every case here is isolated from the real repository tree via
    monkeypatched `_REPO_ROOT` / `_HOOKS_DIR` / `_IMPORT_ROOTS` /
    `TRACKED_FILE_SET`, pointed at a small synthetic tree under `tmp_path`.
    That is a deliberate choice, not a shortcut: today's real validators all
    use the one import shape the closure already handled
    (`from precommit._prose_fields import find_prose_fields`), so a case built
    from the real corpus would prove nothing about the other shapes — the gap
    this class exists to close is in a shape no current script uses yet (see
    each test's own docstring for the mutation it reproduces).
    """

    def _sandbox_module(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """Point the closure's globals at an isolated `scripts/hooks/precommit/` tree.

        Returns the `precommit/` directory, created empty, for the caller to
        populate.
        """
        hooks_dir = tmp_path / "scripts" / "hooks"
        precommit_dir = hooks_dir / "precommit"
        precommit_dir.mkdir(parents=True)
        module = sys.modules[__name__]
        monkeypatch.setattr(module, "_REPO_ROOT", tmp_path)
        monkeypatch.setattr(module, "_HOOKS_DIR", hooks_dir)
        monkeypatch.setattr(module, "_IMPORT_ROOTS", (tmp_path, hooks_dir))
        return precommit_dir

    def _track(self, monkeypatch: pytest.MonkeyPatch, *relative_paths: str) -> None:
        """Make the given repo-relative paths the whole tracked corpus for this test."""
        monkeypatch.setattr(sys.modules[__name__], "TRACKED_FILE_SET", frozenset(relative_paths))

    def test_package_form_import_is_followed(self, tmp_path, monkeypatch):
        """
        Given: a script importing `from precommit import _submodule` — the
               package-import form, where the submodule name lives in
               `node.names` rather than in `node.module`
        When: `_local_import_closure` walks it
        Then: the submodule's tracked path is in the closure

        Reproduces mutation M28's realistic path: a validator first written to
        import a precommit submodule this way never acquires a `paths:`
        trigger requirement for it, because `node.module` resolves to
        `"precommit"` alone — a package, not a file — and the previous form of
        this resolver tried only that reading.
        """
        precommit_dir = self._sandbox_module(tmp_path, monkeypatch)
        (precommit_dir / "__init__.py").write_text("", encoding="utf-8")
        (precommit_dir / "_submodule.py").write_text("VALUE = 1\n", encoding="utf-8")
        (precommit_dir / "validator.py").write_text("from precommit import _submodule\n", encoding="utf-8")

        self._track(
            monkeypatch,
            "scripts/hooks/precommit/validator.py",
            "scripts/hooks/precommit/__init__.py",
            "scripts/hooks/precommit/_submodule.py",
        )

        closure = _local_import_closure("scripts/hooks/precommit/validator.py")
        assert "scripts/hooks/precommit/_submodule.py" in closure, (
            f"`from precommit import _submodule` was not followed. closure: {closure}"
        )

    def test_relative_import_with_a_module_is_followed(self, tmp_path, monkeypatch):
        """
        Given: a script importing `from ._submodule import VALUE` — a
               level-1 relative import naming a module
        When: `_local_import_closure` walks it
        Then: the submodule's tracked path is in the closure

        `node.module` alone (`"_submodule"`) means nothing without knowing
        which directory it is relative to — `node.level` carries that, and
        `_resolve_local_import`'s absolute-path lookup has no way to use it.
        """
        precommit_dir = self._sandbox_module(tmp_path, monkeypatch)
        (precommit_dir / "_submodule.py").write_text("VALUE = 1\n", encoding="utf-8")
        (precommit_dir / "validator.py").write_text("from ._submodule import VALUE\n", encoding="utf-8")

        self._track(monkeypatch, "scripts/hooks/precommit/validator.py", "scripts/hooks/precommit/_submodule.py")

        closure = _local_import_closure("scripts/hooks/precommit/validator.py")
        assert "scripts/hooks/precommit/_submodule.py" in closure, (
            f"`from ._submodule import VALUE` was not followed. closure: {closure}"
        )

    def test_bare_relative_package_import_is_followed(self, tmp_path, monkeypatch):
        """
        Given: a script importing `from . import _submodule` — a level-1
               relative import with no `module`, where the submodule name is
               one of `node.names` instead
        When: `_local_import_closure` walks it
        Then: the submodule's tracked path is in the closure

        The relative counterpart of the package-form case above: with no
        `module`, each name is itself a candidate submodule of the current
        script's own package.
        """
        precommit_dir = self._sandbox_module(tmp_path, monkeypatch)
        (precommit_dir / "_submodule.py").write_text("VALUE = 1\n", encoding="utf-8")
        (precommit_dir / "validator.py").write_text("from . import _submodule\n", encoding="utf-8")

        self._track(monkeypatch, "scripts/hooks/precommit/validator.py", "scripts/hooks/precommit/_submodule.py")

        closure = _local_import_closure("scripts/hooks/precommit/validator.py")
        assert "scripts/hooks/precommit/_submodule.py" in closure, (
            f"`from . import _submodule` was not followed. closure: {closure}"
        )

    def test_dynamic_import_fails_loud_rather_than_resolving_to_nothing(self, tmp_path, monkeypatch):
        """
        Given: a script calling `importlib.import_module(...)` on a local
               module name
        When: `_local_import_closure` walks it
        Then: it fails the test rather than silently omitting the module

        A dynamic import produces no `ast.Import`/`ast.ImportFrom` node, so
        the closure structurally cannot resolve what it loads no matter how
        the two node-type branches are taught to read `node.module`/`.level`.
        Per the same reasoning `_workflow_dependencies` gives for an
        unresolved script basename, a shape this resolver cannot follow has to
        say so loudly rather than understate the trigger requirement it is
        building.
        """
        precommit_dir = self._sandbox_module(tmp_path, monkeypatch)
        (precommit_dir / "validator.py").write_text(
            'import importlib\nimportlib.import_module("precommit._submodule")\n', encoding="utf-8"
        )
        self._track(monkeypatch, "scripts/hooks/precommit/validator.py")

        with pytest.raises(pytest.fail.Exception):
            _local_import_closure("scripts/hooks/precommit/validator.py")

    def test_dunder_import_call_fails_loud_rather_than_resolving_to_nothing(self, tmp_path, monkeypatch):
        """
        Given: a script calling the builtin `__import__(...)` directly on a
               local module name — no import statement of any kind precedes it
        When: `_local_import_closure` walks it
        Then: it fails the test rather than silently omitting the module

        `__import__` needs no `import importlib` and produces no `ast.Call`
        attribute chain for the attribute-based check to inspect — it is a
        bare `Name` call from the moment Python starts. A detector matching
        only `ast.Attribute` chains ending in `import_module`/
        `spec_from_file_location` is structurally blind to this call no
        matter how those two names are spelled or aliased.
        """
        precommit_dir = self._sandbox_module(tmp_path, monkeypatch)
        (precommit_dir / "validator.py").write_text(
            '__import__("precommit._submodule", fromlist=["_submodule"])\n', encoding="utf-8"
        )
        self._track(monkeypatch, "scripts/hooks/precommit/validator.py")

        with pytest.raises(pytest.fail.Exception):
            _local_import_closure("scripts/hooks/precommit/validator.py")

    def test_unaliased_bare_name_import_module_fails_loud_rather_than_resolving_to_nothing(
        self, tmp_path, monkeypatch
    ):
        """
        Given: a script that writes `from importlib import import_module`
               (no `as`) and then calls the bare name `import_module(...)`
        When: `_local_import_closure` walks it
        Then: it fails the test rather than silently omitting the module

        This is the more idiomatic spelling of the dynamic-import form the
        module's docstring claims to catch, and the one an attribute-only
        detector (`func.attr in {...}`) cannot see at all: `import_module`
        here is a bare `ast.Name`, never an `ast.Attribute`, because it was
        imported directly rather than accessed off the `importlib` module
        object. `_dynamic_import_aliases` is what recovers this — it reads
        the `from importlib import import_module` statement itself to learn
        that the bare name `import_module` means the same function the
        attribute form already recognizes.
        """
        precommit_dir = self._sandbox_module(tmp_path, monkeypatch)
        (precommit_dir / "validator.py").write_text(
            'from importlib import import_module\nimport_module("precommit._submodule")\n', encoding="utf-8"
        )
        self._track(monkeypatch, "scripts/hooks/precommit/validator.py")

        with pytest.raises(pytest.fail.Exception):
            _local_import_closure("scripts/hooks/precommit/validator.py")

    def test_aliased_bare_name_import_module_fails_loud_rather_than_resolving_to_nothing(
        self, tmp_path, monkeypatch
    ):
        """
        Given: a script that writes `from importlib import import_module as
               im` and then calls the aliased bare name `im(...)`
        When: `_local_import_closure` walks it
        Then: it fails the test rather than silently omitting the module

        The alias itself — `im`, not `import_module` — is what a detector
        keyed on a fixed set of names (even one taught the bare-`Name` form)
        would miss without reading the `from ... import ... as ...`
        statement that binds it. `_dynamic_import_aliases` walks every
        `ast.ImportFrom` in the file first, precisely so an alias earns the
        same treatment as the name it renames.
        """
        precommit_dir = self._sandbox_module(tmp_path, monkeypatch)
        (precommit_dir / "validator.py").write_text(
            'from importlib import import_module as im\nim("precommit._submodule")\n', encoding="utf-8"
        )
        self._track(monkeypatch, "scripts/hooks/precommit/validator.py")

        with pytest.raises(pytest.fail.Exception):
            _local_import_closure("scripts/hooks/precommit/validator.py")


GATE_WORKFLOWS = sorted({step.workflow for step in GATE_STEPS})


# This module's own repo-relative path. A pytest invocation matters here only
# if the run it describes would collect this file — that is the definition of
# "the workflow where these standing guards execute", and it is derived rather
# than approximated by "no target given".
_THIS_MODULE = Path(__file__).resolve().relative_to(_REPO_ROOT).as_posix()


def _pytest_command_arguments(segment: list[str]) -> list[str] | None:
    """Return a pytest command's arguments, or None if it is not one.

    Two spellings are recognised, and recognising only the first is a live
    hazard rather than a hypothetical one: `python3 -m pytest` is the form this
    project's own guidance prescribes, because bare `pytest` over-collects
    through a symlinked working tree. A derivation blind to it silently empties
    `PYTEST_WORKFLOWS`, and an empty parametrization is reported as a skip
    rather than as a missing guard.
    """
    if not segment:
        return None
    if Path(segment[0]).name == "pytest":
        return segment[1:]
    if _INTERPRETER_RE.match(Path(segment[0]).name) and segment[1:3] == ["-m", "pytest"]:
        return segment[3:]
    return None


def _looks_like_a_test_target(token: str) -> bool:
    """True when a pytest argument is a path or node id rather than an option.

    `--junitxml=junit/test-results.xml` is a single token and is filtered by the
    leading dash before this is reached.
    """
    return token.endswith(".py") or "/" in token or "::" in token


def _target_selects_this_module(target: str) -> bool:
    """True when a pytest target argument would collect this test module.

    Node ids (`path::Class::test`) are reduced to their path, and a directory
    target selects everything beneath it.
    """
    path = target.split("::", 1)[0].strip().rstrip("/")
    if not path or path == ".":
        return True
    return _THIS_MODULE == path or _THIS_MODULE.startswith(f"{path}/")


def _pytest_workflows() -> list[str]:
    """Return the workflows whose pytest run would collect this module.

    Targeted invocations are not excluded wholesale. `pytest scripts/` is a
    targeted run that collects this module, and treating it as out of scope is
    how the set empties on an edit a contributor makes for good reasons. What is
    excluded is a target that does *not* select this file — `pytest
    scripts/hooks/tests/test_x.py` in `persona-pages.yml` and
    `validate-issue-templates.yml` — because such a run carries no obligation to
    trigger on files it never asserts over.
    """
    found: set[str] = set()
    for step in WORKFLOW_STEPS:
        for raw_line in step.run.splitlines():
            tokens = _safe_split(raw_line.strip())
            for segment in _split_simple_commands(tokens):
                while segment and (segment[0] in _LEADING_WORDS or _TOKEN_ASSIGN_RE.match(segment[0])):
                    segment = segment[1:]
                arguments = _pytest_command_arguments(segment)
                if arguments is None:
                    continue
                targets = [
                    token for token in arguments if not token.startswith("-") and _looks_like_a_test_target(token)
                ]
                if not targets or any(_target_selects_this_module(target) for target in targets):
                    found.add(step.workflow)
    return sorted(found)


PYTEST_WORKFLOWS = _pytest_workflows()


class TestWorkflowTriggerCoverage:
    """A gate that does not run on the pull request that breaks it is not a gate.

    ADR-037 D1 places the enforcement decision in CI. That is a claim about
    which workflow runs, not only about which flags it passes, and `paths:`
    filters decide the first. The failure is total rather than partial: the job
    does not appear at all, so there is no red tick to notice and no log to read.

    Both tests are derived from the workflows themselves. A validator added to
    the gate, or a script the gate starts executing, is required in the filter
    without anyone editing this module.
    """

    def test_gate_workflows_are_found(self):
        """
        Given: the derived gate steps
        When: their workflows are collected
        Then: at least one is found

        Non-vacuity guard for the two tests below.
        """
        assert GATE_WORKFLOWS, (
            "No workflow contains a gate step — one invoking a validator with "
            f"{sorted(STRICTNESS_FLAGS)}, or one of ADR-037 D8's flagless governed "
            "validators; the trigger rules below would quantify over nothing."
        )

    def test_pytest_workflows_are_found(self):
        """
        Given: every `run:` step in every workflow
        When: steps running a pytest command that would collect this module are
              selected
        Then: at least one workflow is found

        Every other derived set in this module has a guard like this one; this
        set did not, and it is the easiest of them to empty. Two edits do it,
        both of which a contributor makes for good reasons:

          - giving the run a target, e.g. `pytest scripts/ --junitxml=...`;
          - spelling it `python3 -m pytest`, which is the form this project
            prescribes because bare `pytest` over-collects through a symlinked
            working tree.

        `_pytest_workflows` handles both now. What this test adds is that the
        *next* such edit fails instead of emptying the parametrization below —
        an empty parametrize collects no cases, and pytest reports that as a
        skip, not as a missing guard.
        """
        assert PYTEST_WORKFLOWS, (
            "No workflow runs a pytest command that would collect "
            f"{_THIS_MODULE}. Every standing guard in this module therefore runs "
            "nowhere in CI, and the trigger rule below has no workflow to check. "
            "If the suite genuinely moved to another runner, the derivation in "
            "`_pytest_workflows` is what needs teaching, not this assertion."
        )

    @pytest.mark.parametrize("workflow_name", sorted(set(GATE_WORKFLOWS) | set(PYTEST_WORKFLOWS)))
    def test_workflow_declares_a_pull_request_trigger(self, workflow_name):
        """
        Given: a workflow carrying a D1 gate, or the workflow running the
               pytest suite that guards D1
        When: its declared events (`_declared_events`) are read
        Then: `pull_request` is one of them

        Every test above and below this one reasons about `paths:` filters —
        whether the workflow re-runs on the *right* pull requests. None of
        them can notice the workflow not running on pull requests *at all*:
        `_trigger_filters` only reports events that carry a path filter, so an
        event missing outright contributes nothing to look at, and a
        `pull_request:` block deleted wholesale leaves every assertion above
        with nothing to be wrong about. A `push`-only workflow runs after a
        merge to the branch it targets, not on the pull request proposing
        that merge — which is not a gate on the pull request at all.
        """
        events = _declared_events(_workflow_data(workflow_name))
        assert "pull_request" in events, (
            f"{workflow_name} declares no `pull_request` trigger (found: {sorted(events)}), "
            "so it never runs on the pull request it exists to gate — only, if at all, "
            "after a merge to a branch its `push:` trigger names."
        )

    def test_push_branches_are_found_for_at_least_one_gate_workflow(self):
        """
        Given: the same workflow set as the trigger test above
        When: each workflow's `push` trigger is read for a `branches:` filter
        Then: at least one declares one

        Non-vacuity guard for
        `test_pull_request_branch_scope_is_not_narrower_than_push`: that test
        has nothing to compare against, and silently passes, for a workflow
        whose `push` trigger names no branches at all — `validate_python.yml`
        is exactly such a workflow today. Without this guard, a `push:`
        section losing its `branches:` filter on every gate workflow at once
        would empty the comparison and nothing would say so.
        """
        found = {
            workflow_name: _event_branches(_workflow_data(workflow_name), "push")
            for workflow_name in sorted(set(GATE_WORKFLOWS) | set(PYTEST_WORKFLOWS))
        }
        assert any(found.values()), (
            "No gate or pytest workflow's `push` trigger names any `branches:`, so "
            "test_pull_request_branch_scope_is_not_narrower_than_push has nothing to "
            f"compare a `pull_request` filter against and would pass vacuously. Found: {found}"
        )

    @pytest.mark.parametrize("workflow_name", sorted(set(GATE_WORKFLOWS) | set(PYTEST_WORKFLOWS)))
    def test_pull_request_branch_scope_is_not_narrower_than_push(self, workflow_name):
        """
        Given: a workflow declaring a `push` trigger with a `branches:` filter
        When: each of those branches is checked against the `pull_request`
              trigger's own branch filter — `branches:` or `branches-ignore:`,
              whichever it declares — via `_event_reaches_branch`
        Then: every branch the `push` trigger names is reachable through
              `pull_request` too

        `push.branches` states which branches this workflow exists to
        protect. Scoping `pull_request` to a different, narrower, or
        nonexistent set of branches — `branches: [nonexistent-branch]`, or the
        deny-list spelling `branches-ignore: [main, develop]` — leaves
        `pull_request` declared (so the test above stays green) while making
        the gate unreachable for every pull request that actually targets a
        protected branch. `_event_reaches_branch` is checked directly, rather
        than comparing `_event_branches`' two enumerated lists, because
        `_event_branches` only ever reads `branches:` and reads a
        `branches-ignore:` filter as `None` — "unrestricted" — which is
        exactly backwards for a deny-list naming the protected branches
        themselves. A `pull_request` trigger with no filter at all is
        unrestricted and therefore always reaches every push branch; only a
        filter that is present and excludes one is a gap.
        """
        data = _workflow_data(workflow_name)
        push_branches = _event_branches(data, "push")
        if not push_branches:
            pytest.skip(
                f"{workflow_name}'s push trigger names no branches to compare against; "
                "test_push_branches_are_found_for_at_least_one_gate_workflow guards "
                "against every case being skipped this way."
            )
        unreachable = [
            branch for branch in push_branches if not _event_reaches_branch(data, "pull_request", branch)
        ]
        assert not unreachable, (
            f"{workflow_name}'s pull_request trigger does not reach {unreachable} — "
            "branches its own push trigger names as protected. A pull request "
            f"targeting {unreachable} never runs this workflow, even though a merge to "
            "it does."
        )

    def test_the_branch_reachability_detector_catches_a_branches_ignore_gap(self):
        """
        Given: a synthetic workflow declaring `push: branches: [main, develop]`
               and `pull_request: branches-ignore: [main, develop]`
        When: `_event_reaches_branch` checks `pull_request` against each of
              `push`'s protected branches
        Then: neither is reachable

        No workflow in this repository uses `branches-ignore:` today, so
        `test_pull_request_branch_scope_is_not_narrower_than_push` never
        exercises that half of `_event_reaches_branch` against a live
        workflow. This is the fidelity check that the reachability answer
        would actually be `False` if one did — the same non-vacuity
        discipline `TestGraphEmissionExclusion`'s synthetic-detector tests use
        for a prohibition nothing live triggers.
        """
        data = {
            "on": {
                "push": {"branches": ["main", "develop"]},
                "pull_request": {"branches-ignore": ["main", "develop"]},
            }
        }
        for branch in ("main", "develop"):
            assert not _event_reaches_branch(data, "pull_request", branch), (
                f"_event_reaches_branch reported '{branch}' reachable through a "
                "pull_request trigger that names it in branches-ignore. The detector "
                "regressed to only reading branches:, which is silent on exactly the "
                "deny-list spelling this test exists to catch."
            )

    @pytest.mark.parametrize("workflow_name", sorted(set(GATE_WORKFLOWS) | set(PYTEST_WORKFLOWS)))
    def test_pull_request_types_reach_the_default_gating_lifecycle(self, workflow_name):
        """
        Given: a workflow carrying a D1 gate, or the pytest workflow guarding
               it, and its `pull_request` trigger's `types:` filter (if any)
        When: that filter is compared against GitHub's default pull_request
              types
        Then: it is absent (so GitHub's default applies) or intersects
              {opened, synchronize, reopened}

        A declared `types:` list REPLACES GitHub's default rather than
        extending it. `types: [closed]` leaves `pull_request` declared (so
        `test_workflow_declares_a_pull_request_trigger` stays green) and any
        `branches:` filter unrestricted — but the workflow only runs once a
        pull request is closed, never while it is open for review or while
        commits are still being pushed to it. No status check is ever
        produced during the part of the PR's life a merge decision is made
        from, so the trigger exists on paper and gates nothing.
        """
        data = _workflow_data(workflow_name)
        types = _event_types(data, "pull_request")
        if types is None:
            return  # No declared `types:`; GitHub's default (opened, synchronize, reopened) applies.
        reachable = _DEFAULT_PULL_REQUEST_TYPES.intersection(types)
        assert reachable, (
            f"{workflow_name}'s pull_request trigger declares types={types}, none of "
            f"which overlap GitHub's default gating lifecycle "
            f"{sorted(_DEFAULT_PULL_REQUEST_TYPES)}. A declared types: list replaces "
            "the default rather than extending it, so this workflow never runs while "
            "the pull request it exists to gate is open."
        )

    def test_the_pull_request_types_detector_catches_a_closed_only_restriction(self):
        """
        Given: a synthetic workflow declaring `pull_request: types: [closed]`
        When: `_event_types` is read and compared against
              `_DEFAULT_PULL_REQUEST_TYPES`
        Then: the two do not intersect

        No workflow in this repository declares `types:` at all today, so
        `test_pull_request_types_reach_the_default_gating_lifecycle` returns
        early — "GitHub's default applies" — for every live case and never
        exercises the mismatch branch. Same non-vacuity discipline as
        `test_the_branch_reachability_detector_catches_a_branches_ignore_gap`.
        """
        data = {"on": {"pull_request": {"types": ["closed"]}}}
        types = _event_types(data, "pull_request")
        assert types == ["closed"], f"_event_types did not read the declared types: filter, got {types!r}"
        assert not _DEFAULT_PULL_REQUEST_TYPES.intersection(types), (
            "types=['closed'] should not overlap GitHub's default gating lifecycle "
            f"{sorted(_DEFAULT_PULL_REQUEST_TYPES)}; the detector regressed to reporting "
            "every types: filter as reachable."
        )

    @pytest.mark.parametrize("workflow_name", GATE_WORKFLOWS)
    def test_every_executed_script_resolves_to_one_tracked_file(self, workflow_name):
        """
        Given: every Python script a gate workflow's steps execute, directly or
               inside a command substitution
        When: each basename is resolved against the tracked corpus
        Then: each resolves to exactly one file

        A basename that resolves to zero or several files has no derivable
        trigger requirement, and the previous form of the resolver returned None
        for both cases while the caller skipped None without a word. Adding
        `python3 .github/helpers/preflight.py` to a gate step was therefore free:
        the script became load-bearing for the gate's result and acquired no
        obligation to re-run it.

        Ambiguity is a real case, not a hypothetical one — `__init__.py` and
        `conftest.py` already carry many tracked paths each. A script whose name
        collides has to be disambiguated before its trigger requirement means
        anything.
        """
        unresolved = [record for record in _workflow_script_resolutions(workflow_name) if record.path is None]
        assert not unresolved, (
            f"{workflow_name} executes scripts that do not resolve to exactly one "
            f"tracked file:\n"
            + "\n".join(
                f"  - {record.basename} ({record.source}): "
                f"{list(record.candidates) or 'no tracked file with that name'}"
                for record in unresolved
            )
            + "\nAn unresolved basename contributes nothing to the `paths:` requirement "
            "below, so the gate stops re-running on changes to a script it executes — "
            "and nothing says so."
        )

    @pytest.mark.parametrize("workflow_name", GATE_WORKFLOWS)
    def test_gate_workflow_triggers_on_everything_that_defines_the_gate(self, workflow_name):
        """
        Given: a workflow containing a D1 gate
        When: its `paths:` filters are checked against its own definition, every
              script its steps execute or copy into place, and the pre-commit
              config those scripts read
        Then: every one is matched, for every filtered event

        Three consequences of a filter that omits these, all silent:

          - a pull request editing the workflow does not run it, so the change
            that removes a `--block`, deletes a job, or narrows a file list is
            merged without the gate ever executing;
          - a pull request editing a validator does not re-run the gate that
            validator feeds;
          - a pull request editing `.pre-commit-config.yaml` — where the hook
            patterns the CI file lists are derived from live — does not re-run
            the jobs whose inputs it just changed.

        Sibling workflows already do this: `validate_tables.yml`,
        `validate_workflows.yml` and `persona-pages.yml` each list their own
        scripts, and two of the three list themselves.
        """
        filters = _trigger_filters(_workflow_data(workflow_name))
        assert filters, (
            f"{workflow_name} declares no `paths:` or `paths-ignore:` filter on any "
            "event, so it runs unconditionally and this rule does not apply. If that "
            "changed deliberately, this test should be removed with the filter."
        )

        required = {f".github/workflows/{workflow_name}"}
        scripts = _workflow_dependencies(workflow_name)
        required |= scripts
        if any(_reads_precommit_config(script) for script in scripts):
            required.add(_PRECOMMIT_CONFIG.name)

        uncovered = {
            path: missing for path in sorted(required) if (missing := _covered_by_every_event(workflow_name, path))
        }
        assert not uncovered, (
            f"{workflow_name} carries a D1 gate but does not re-run when its own inputs "
            f"change. Uncovered by `paths:`:\n"
            + "\n".join(
                f"  - {path}  (not matched for: {', '.join(events)})" for path, events in uncovered.items()
            )
            + f"\nDeclared filters: {[(f.event, f.kind, f.patterns) for f in filters]}\n"
            "A pull request touching any of these merges without this workflow running."
        )

    @pytest.mark.parametrize("workflow_name", GATE_WORKFLOWS)
    def test_gate_workflow_triggers_on_the_corpus_its_governed_hooks_scan(self, workflow_name):
        """
        Given: a workflow containing a D1 gate
        When: its `paths:` filters are checked against (a) every tracked file
              a governed hook this workflow runs would itself select via its
              own `files:`/`exclude:` pattern, and (b) the local import
              closure of every script the workflow executes
        Then: every one is matched, for every filtered event

        `test_gate_workflow_triggers_on_everything_that_defines_the_gate`
        covers the workflow's own path, the scripts it executes or copies, and
        the pre-commit config those scripts read. None of those is the
        *content* a hook exists to check. D1 requires a CI invocation "over at
        least the inputs the hook would see" (docs/adr/037-ci-validation-
        authority-and-block-parity.md, D1) — that is a claim about the hook's
        own `files:` pattern, and a workflow can trigger on every script it
        runs while never triggering on the corpus those scripts were added to
        scan.

        The `validate-neutrality` hook was the sharpest instance: its
        `files:` pattern is `^scripts/(agents|skills)/`, and until 42048c3
        neither directory was a `paths:` entry, so a pull request adding a
        denylisted term to an agent or skill file blocked locally, never
        triggered this workflow, and reported green. `validate-neutrality-policy`
        — the sibling hook that exists precisely to re-scan the corpus when
        the denylist itself changes — had the same gap one level up: its own
        `files:` pattern names `scripts/hooks/precommit/_neutrality_data.py`,
        a module no script-execution scan reaches, because the workflow never
        runs it directly — `validate_neutrality.py` only imports it.

        That second half — a validator's own local imports — is what the
        import-closure check adds. `_neutrality_data.py`, `_prose_fields.py`,
        `framework_mapping.py` and `scripts/build_persona_site_data.py` were
        each read by a validator this workflow runs and named on no command
        line the script-resolution scan in the sibling test above can see.
        42048c3 added all of the above — `scripts/agents/*.md`,
        `scripts/skills/**`, and the four import-closure modules — to
        `validation.yml`'s `paths:`. This test is kept as a standing guard: a
        governed hook's `files:` pattern widening, or a validator gaining a
        new local import, extends the corpus this test samples with no edit
        here, and a `paths:` filter that stops covering it is caught the same
        way the original gap was.

        Precedent for stating this rule without an ADR: commit 0df8157 on this
        branch already made the gate workflows trigger on the files that
        *define* them; this is the other half of the same idea, applied to the
        files a governed hook *reads*.
        """
        filters = _trigger_filters(_workflow_data(workflow_name))
        assert filters, (
            f"{workflow_name} declares no `paths:` or `paths-ignore:` filter on any "
            "event, so it runs unconditionally and this rule does not apply. If that "
            "changed deliberately, this test should be removed with the filter."
        )

        required = _governed_hook_input_paths(workflow_name) | _executed_script_import_closure(workflow_name)
        assert required, (
            f"No governed hook this workflow runs matched a tracked file, and none of "
            f"the scripts it executes imports a local module. Non-vacuity guard for the "
            f"assertion below — {workflow_name} would otherwise pass by quantifying "
            "over nothing."
        )

        uncovered = {
            path: missing for path in sorted(required) if (missing := _covered_by_every_event(workflow_name, path))
        }
        assert not uncovered, (
            f"{workflow_name} carries a D1 gate but does not trigger on content a "
            f"governed hook selects or a module its validator imports. Uncovered by "
            f"`paths:`:\n"
            + "\n".join(
                f"  - {path}  (not matched for: {', '.join(events)})" for path, events in uncovered.items()
            )
            + f"\nDeclared filters: {[(f.event, f.kind, f.patterns) for f in filters]}\n"
            "A pull request touching any of these merges without this workflow running, "
            "which is the same silent failure "
            "test_gate_workflow_triggers_on_everything_that_defines_the_gate reports for "
            "the workflow's own scripts, one layer further from the command line."
        )

    @pytest.mark.parametrize("workflow_name", PYTEST_WORKFLOWS)
    def test_pytest_workflow_triggers_on_the_files_the_suite_asserts_over(self, workflow_name):
        """
        Given: the workflow that runs pytest
        When: its `paths:` filters are checked against the repository files this
              suite reads as its subject matter
        Then: every one is matched, for every filtered event

        The standing guards ADR-037's follow-up section asks for — D1 coverage,
        D3's prohibition, D7a's file lists, D7b's in-place invocation — are all
        assertions *about* `.github/workflows/`. They are also all pytest tests,
        and pytest runs in exactly one workflow.

        So a pull request that edits only workflow YAML runs no pytest at all.
        Every guard in this module is absent from the one change it exists to
        catch: stripping `--block` from a job, deleting a job, or dropping a
        file-list expansion each pass CI silently.

        The subject set is not only files this module inspects the *behaviour*
        of — it also has to include files this module derives its own
        *expectations* from. ADR-037's D1 instance table
        (`docs/adr/037-ci-validation-authority-and-block-parity.md`) is the
        governed-hook register `ADR_GOVERNED_HOOK_IDS` is parsed from; editing
        only that table's rows changes what every test keyed on that set
        asserts, with no change to any workflow, script or
        `.pre-commit-config.yaml` entry for `validate_python.yml`'s own
        `paths:` (`**.py`, `.pre-commit-config.yaml`, `requirements*.txt`,
        `pyproject.toml`, `.github/workflows/**`) to catch. A pull request
        editing only the ADR's instance table therefore runs no pytest at
        all — the source this suite's governed set derives from is silent on
        the one change that resizes the set.
        """
        # Derived from the constants this module reads, so a new subject file
        # becomes a requirement without an edit here.
        subjects = {path.relative_to(_REPO_ROOT).as_posix() for path in _workflow_files()}
        subjects.add(_PRECOMMIT_CONFIG.relative_to(_REPO_ROOT).as_posix())
        subjects |= _DERIVATION_SOURCE_PATHS
        for gate_workflow in GATE_WORKFLOWS:
            subjects |= _workflow_dependencies(gate_workflow)

        uncovered = {
            path: missing for path in sorted(subjects) if (missing := _covered_by_every_event(workflow_name, path))
        }
        assert not uncovered, (
            f"{workflow_name} is the only workflow running pytest, and its `paths:` "
            f"filter does not match files this test suite asserts over:\n"
            + "\n".join(
                f"  - {path}  (not matched for: {', '.join(events)})" for path, events in uncovered.items()
            )
            + "\nA pull request touching only those files runs no tests, so every "
            "standing guard on the CI gate is silent on precisely the change that "
            "disables it."
        )


# ===========================================================================
# 9. The step's own exit code — the enforcement mechanism itself
# ===========================================================================
#
# Every other behavioural test in this module models the *validator's* exit
# code: it runs the validator directly and asserts on what it returns. Nothing
# above models the *step's*. The workflow wraps each validator in
#
#     if python3 ... --block ...; then
#       echo "OK"; echo "status=success" >> $GITHUB_OUTPUT
#     else
#       echo "FAILED"; echo "status=failed" >> $GITHUB_OUTPUT
#       exit 1
#     fi
#
# and it is that `exit 1` — not the validator's return code, and not the
# `status` output — that fails the job. The `status` outputs are not a second
# line of defence: the workflow declares nine `*_status` job outputs and
# consumes none of them, so the step's exit code is the whole mechanism.
#
# Four one-line edits reach the state ADR-037 D7 explicitly rejects — "landing
# the invocation warn-only to soak" — with the violation still found and still
# printed in the log, and with no flag, path, file list, or working directory
# touched:
#
#   - deleting `exit 1` from the `else` branch;
#   - `... --block ${FILES} || true; then`;
#   - `continue-on-error: true` on the step;
#   - a conditional `if:` on the step or its job.
#
# The first two are properties of the shell body and are asserted by executing
# it. The last two are step and job keys that appear in no command line at all,
# and are asserted structurally because there is nothing to execute.


def _write_stub_interpreter(directory: Path) -> None:
    """Write `python3`/`python` and THIRD_PARTY_BLOCKING_COMMANDS stubs.

    The `python3`/`python` stub decides which role it is playing from the
    command line rather than from a script name: an invocation is the gate's
    validator if it carries a strictness flag, or — for ADR-037 D8's flagless
    governed validators, which carry no flag at all — if one of its
    arguments' basenames is in UNFLAGGED_BLOCKING_SCRIPTS. Anything else is
    the file-list resolver. Both checks are derived (from STRICTNESS_FLAGS and
    from ADR-037's own D1 instance table), so the stub keeps working if the
    resolver is renamed, a validator moves, or a further flagless validator is
    added to the table.

    The second check matters because a flagless gate step's body has no
    resolver call to distinguish from: it is one invocation, carrying no flag,
    and without the basename check the stub would always answer as the
    resolver — so `STUB_VALIDATOR_EXIT` would never be reachable for a D8
    validator, and `test_gate_step_body_fails_when_its_validator_fails` would
    misreport a correctly-failing D8 step as green.

    The resolver arm prints one path-shaped token, because the step word-splits
    that output into the validator's argv and an empty expansion would exercise
    a different code path than the one under test.

    Each name in THIRD_PARTY_BLOCKING_COMMANDS gets its own stub, controlled
    by the same STUB_VALIDATOR_EXIT — a third-party blocking command has no
    warn-only tier and takes no flag distinguishing "this is the check" from
    anything else, so unlike the Python stub it never needs to answer as a
    resolver. Without this, `_gate_steps`'s third-party arm (section 2) would
    execute the real, unstubbed `check-jsonschema` from PATH — non-deterministic
    with respect to the test's intent, since the harness's job is to control the
    validator's outcome, not to depend on what a real schema-validation run does
    against whatever happens to be on disk.
    """
    directory.mkdir(parents=True, exist_ok=True)
    for name in THIRD_PARTY_BLOCKING_COMMANDS:
        stub = directory / name
        stub.write_text('#!/usr/bin/env bash\nexit "${STUB_VALIDATOR_EXIT:-0}"\n', encoding="utf-8")
        stub.chmod(0o755)
    flags = " ".join(f'"{flag}"' for flag in sorted(STRICTNESS_FLAGS))
    scripts = " ".join(f'"{script}"' for script in sorted(UNFLAGGED_BLOCKING_SCRIPTS))
    body = (
        "#!/usr/bin/env bash\n"
        f"for want in {flags}; do\n"
        '  for arg in "$@"; do\n'
        '    if [ "$arg" = "$want" ]; then\n'
        '      exit "${STUB_VALIDATOR_EXIT:-0}"\n'
        "    fi\n"
        "  done\n"
        "done\n"
        f"for want in {scripts}; do\n"
        '  for arg in "$@"; do\n'
        '    if [ "$(basename -- "$arg")" = "$want" ]; then\n'
        '      exit "${STUB_VALIDATOR_EXIT:-0}"\n'
        "    fi\n"
        "  done\n"
        "done\n"
        'echo "risk-map/yaml/stub.yaml"\n'
        'exit "${STUB_RESOLVER_EXIT:-0}"\n'
    )
    # Both spellings, so a step naming the interpreter either way is covered.
    for name in ("python3", "python"):
        stub = directory / name
        stub.write_text(body, encoding="utf-8")
        stub.chmod(0o755)


def _populate_checkout_shaped_sandbox(sandbox: Path) -> None:
    """Copy every tracked file into `sandbox`, preserving content and mode.

    Reproducing the *directory layout* of a checkout (a prior version of this
    function created `_TOP_LEVEL_DIRECTORIES` as empty directories) is enough
    to resolve `[ -d risk-map ]` the way a real checkout would, and not enough
    for anything else: an empty sandbox makes `[ -s risk-map/yaml/risks.yaml
    ]` false where a real checkout's non-empty tracked file makes it true, and
    a placeholder file with default permissions makes `[ -x ... ]` false for
    a script that is genuinely executable in the tree. Both are wrong answers
    that read as "no bypass" for a step that has one.

    Copying the tracked corpus itself — content via `shutil.copy2`, which also
    preserves the executable bit — is what makes every single-letter
    `test`/`[` unary operator (`-s`, `-r`, `-x`, `-L`, ...) resolve the way it
    would against a real "Checkout repository" step, without this module
    having to enumerate which operator a future gate step's condition might
    use. This is the mechanism-level fix for a repository-state bypass: it is
    not blind to a test operator or a chained (`&&`/`||`, no `if`/`elif`
    keyword) form the way a text-pattern detector necessarily is, because it
    makes the *shell itself* answer the question against a faithful
    filesystem rather than asking this module to recognize the question's
    shape in advance.
    `_repository_state_precedes_validator`'s structural scan is kept as a
    second, independent guard — it names the offending line without running
    anything — but this sandbox is what makes the behavioural tests below it
    (`test_gate_step_body_fails_when_its_validator_fails` in particular) able
    to observe a bypass that scan does not yet recognize.

    `git ls-files -s` (TRACKED_FILES's own source) reports no tracked symlink
    in this repository today, so `copy2`'s default of following symlinks does
    not misrepresent one; a tracked symlink would need `copy2(...,
    follow_symlinks=False)` added here, not a new detector.
    """
    for relative in TRACKED_FILES:
        source = _REPO_ROOT / relative
        if not source.is_file():
            continue
        destination = sandbox / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _run_step_body(
    step: WorkflowStep,
    sandbox: Path,
    validator_exit: int,
    resolver_exit: int,
) -> subprocess.CompletedProcess:
    """Execute a step's `run:` body under GitHub's default shell, with stubs.

    The body is run verbatim under `bash -e`, which is what GitHub uses for a
    `run:` block with no `shell:` key. `GITHUB_OUTPUT` is pointed at a real file
    so the `>> $GITHUB_OUTPUT` appends succeed — left unset they would produce
    an ambiguous-redirect error and a non-zero exit for a reason that has
    nothing to do with the gate.

    `sandbox` is made checkout-shaped by `_populate_checkout_shaped_sandbox`
    before the body runs, so a step that branches on repository state ahead of
    its validator — `[ -d risk-map ]`, `[ -s risk-map/yaml/risks.yaml ]`, or
    any other single-letter `test`/`[` operator — resolves that test the way
    it would against a real checkout, not against whatever an empty sandbox
    happens to produce. That is a property of the sandbox's content, and the
    shell can read it directly; no side-channel is needed to recover it after
    the fact. GATE_STEPS carries no step shaped this way today —
    TestGateStepFailsTheJob's structural guard
    (`_repository_state_precedes_validator`) is what would name one that
    started being, and this sandbox is what would make the behavioural tests
    below fail on one even if its shape did not match that guard's pattern —
    so this function's job is limited to making the sandbox a faithful
    stand-in for a checkout, not to second-guessing what the body does with
    it.
    """
    bin_dir = sandbox / "bin"
    _write_stub_interpreter(bin_dir)
    _populate_checkout_shaped_sandbox(sandbox)
    environment = {
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        "HOME": str(sandbox),
        "GITHUB_OUTPUT": str(sandbox / "github_output.txt"),
        "GITHUB_STEP_SUMMARY": str(sandbox / "github_step_summary.txt"),
        "STUB_VALIDATOR_EXIT": str(validator_exit),
        "STUB_RESOLVER_EXIT": str(resolver_exit),
    }
    return subprocess.run(
        ["bash", "-e", "-c", step.run],
        capture_output=True,
        text=True,
        cwd=str(sandbox),
        env=environment,
    )


def _gate_step_ids() -> list[str]:
    """Return stable parametrization ids for the gate steps."""
    return [step.source for step in GATE_STEPS]


def _or_guarded_validator_lines(step: WorkflowStep) -> list[str]:
    """Return lines in a step's body where the validator command is `||`-guarded.

    "The validator command" is identified the same three ways `_gate_steps`
    identifies a gate step: a simple command carrying a strictness flag, one
    naming a script in UNFLAGGED_BLOCKING_SCRIPTS (ADR-037 D8's flagless
    governed set), or one invoking a THIRD_PARTY_BLOCKING_COMMANDS member
    directly (`_segment_invokes_third_party_command`). All three are checked
    per segment, not per line, so a guard on an unrelated command earlier on
    the same line is not mistaken for one on the validator.
    """
    guarded: list[str] = []
    for raw_line in step.run.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for segment, operator in _segments_with_operators(_safe_split(stripped)):
            carries_validator = (
                STRICTNESS_FLAGS.intersection(segment)
                or any(Path(token).name in UNFLAGGED_BLOCKING_SCRIPTS for token in segment)
                or _segment_invokes_third_party_command(segment)
            )
            if carries_validator and operator == "||":
                guarded.append(stripped)
    return guarded


# A `test`/`[`/`[[` command applying any single-letter unary operator test(1)
# supports (`-a` through `-z`, optionally negated with `!`) — not an
# enumerated subset (`-d`, `-f`, `-e`). `_populate_checkout_shaped_sandbox` is
# the primary, mechanism-level guard against a repository-state bypass (it
# makes the *shell* answer the question against a faithful filesystem, so it
# is blind to no operator or shape); this pattern is the secondary,
# human-readable guard that names the offending line without executing
# anything, and an enumerated letter class would have the same blind spot the
# sandbox fix exists to close — the next operator nobody enumerated.
_REPO_STATE_TEST_PATTERN = r"(?:\[+\s*|test\s+)(?:!\s*)?-[A-Za-z]\s+\S+"

# The `if`/`elif` spelling: the test introduces the branch itself. Matches the
# *shell keyword*, not a bare `[ -d ... ]` appearing mid-body (e.g. inside an
# already-taken branch), which is not a step shape D1 needs to be suspicious
# of.
_REPO_STATE_CONDITION_RE = re.compile(rf"^\s*(?:if|elif)\s+{_REPO_STATE_TEST_PATTERN}")

# The `[ ... ] && ... || ...` spelling: no `if`/`elif` keyword at all, and the
# test's truth still decides what runs next. Matched per segment against
# `_REPO_STATE_TEST_PATTERN`, restricted to a segment immediately followed by
# `&&` or `||` — a bare `[ -s file ]` with no following operator is a no-op
# exit-status-only command, not a gate.
_REPO_STATE_CHAINED_TEST_RE = re.compile(_REPO_STATE_TEST_PATTERN)


def _line_has_repository_state_gate(stripped: str) -> bool:
    """True when a line contains a repository-state test able to gate what runs next.

    Two shapes count: `_REPO_STATE_CONDITION_RE`'s `if`/`elif` form, and a
    standalone `[ ... ]`/`test ...` segment chained to what follows by `&&` or
    `||` — `[ -s file ] && echo ok && exit 0 || <validator>` gates exactly as
    effectively as an `if` while using neither keyword.
    """
    if _REPO_STATE_CONDITION_RE.match(stripped):
        return True
    for segment, operator in _segments_with_operators(_safe_split(stripped)):
        if operator in ("&&", "||") and _REPO_STATE_CHAINED_TEST_RE.search(" ".join(segment)):
            return True
    return False


def _repository_state_precedes_validator(step: WorkflowStep) -> bool:
    """True when a repository-state test precedes this step's validator invocation.

    "Precedes" means: an earlier line in the same shell body contains a
    repository-state gate (`_line_has_repository_state_gate` — an `if`/`elif`
    condition, or a chained `[ ... ] && ... || ...` with no keyword at all),
    before the line that invokes the step's own validator (located the same
    three ways `_gate_steps` locates one — a strictness flag, a D8 flagless
    validator's basename, or a THIRD_PARTY_BLOCKING_COMMANDS invocation). Once
    a job's checkout step has run, a `[ -d risk-map ]` branch ahead of the
    validator always wins — the directory it tests for exists unconditionally
    by then — so the validator underneath an `elif` never executes and the job
    reports success without it ever having run. See
    `test_the_harness_reproduces_a_repository_state_bypass_faithfully` for why
    a bare exit code alone cannot be trusted to reveal this.
    """
    lines = step.run.splitlines()
    validator_index = None
    for index, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # `;`-joined tokens (`elif validator.py; then`) are split into simple
        # commands first — a raw token-in-line check would miss the basename
        # under a trailing `;` (`validator.py;` != `validator.py`).
        for segment in _split_simple_commands(_safe_split(stripped)):
            if (
                STRICTNESS_FLAGS.intersection(segment)
                or any(Path(token).name in UNFLAGGED_BLOCKING_SCRIPTS for token in segment)
                or _segment_invokes_third_party_command(segment)
            ):
                validator_index = index
                break
        if validator_index is not None:
            break
    if validator_index is None:
        return False
    return any(_line_has_repository_state_gate(raw_line.strip()) for raw_line in lines[:validator_index])


class TestGateStepFailsTheJob:
    """A found violation has to fail the step, and the step has to fail the job.

    ADR-037 D1 makes CI the enforcing gate and D7 refuses the warn-only soak.
    Both are claims about the *job's* conclusion, and the job's conclusion is
    decided by the step's exit code — nothing consumes the `status` outputs the
    steps write, so there is no second path by which a failure becomes a red
    tick.

    The tests below are the only ones in this module that execute the workflow's
    own shell. Everything else runs the validator and reads its return code,
    which is a different number: a step can observe exit 1 from the validator,
    print the violation, and still return 0.

    Each behavioural case is asserted against a control run in which the stub
    succeeds. Without it, "the body exited non-zero" could be a broken harness —
    an unset variable, a missing file, a `bash -e` abort on something unrelated —
    reported as enforcement.
    """

    def test_gate_steps_are_executable_in_isolation(self):
        """
        Given: the derived gate steps
        When: their shell bodies are inspected
        Then: at least one exists and each has a body to run

        Non-vacuity guard: the parametrized cases below quantify over this set,
        and an empty one collects no cases at all.
        """
        assert GATE_STEPS, (
            "No gate step was derived, so no step body can be executed. "
            "TestGateStepsRunFromRepositoryRoot::test_gate_steps_are_found "
            "explains what that means for the rest of the suite."
        )
        empty = [step.source for step in GATE_STEPS if not step.run.strip()]
        assert not empty, f"Gate steps with an empty `run:` body: {empty}"

    def test_the_validator_stub_recognizes_a_flagless_governed_script(self, tmp_path):
        """
        Given: the stub interpreter `_run_step_body` installs, invoked directly
               with one of ADR-037 D8's flagless governed validators on the
               command line and no strictness flag
        When: STUB_VALIDATOR_EXIT is set to 1 and STUB_RESOLVER_EXIT to 0
        Then: the stub exits 1 — it answered as the validator, not the resolver

        Non-vacuous proof for the half of the two behavioural cases below that
        the live parametrization cannot yet exercise: no workflow invokes a
        flagless governed validator yet (ADR-037 D8), so GATE_STEPS carries no
        such step and neither
        test_gate_step_body_succeeds_when_its_validator_succeeds nor
        test_gate_step_body_fails_when_its_validator_fails runs this code path
        today. Without this test, `_write_stub_interpreter`'s basename check
        could regress to always answering as the resolver and nothing would
        notice until a correctly-written D8 CI step started reading as green
        no matter what its validator returned.

        UNFLAGGED_BLOCKING_SCRIPTS is not empty —
        TestUnflaggedBlockingCoverage's own non-vacuity guard establishes
        that — so a script name always exists to probe with.
        """
        script = sorted(UNFLAGGED_BLOCKING_SCRIPTS)[0]
        bin_dir = tmp_path / "bin"
        _write_stub_interpreter(bin_dir)
        result = subprocess.run(
            [str(bin_dir / "python3"), f"scripts/hooks/precommit/{script}"],
            capture_output=True,
            text=True,
            env={**os.environ, "STUB_VALIDATOR_EXIT": "1", "STUB_RESOLVER_EXIT": "0"},
        )
        assert result.returncode == 1, (
            f"The stub interpreter, invoked with {script} and no strictness flag, exited "
            f"{result.returncode} instead of STUB_VALIDATOR_EXIT (1). It answered as the "
            "file-list resolver instead of the validator, which is exactly the ambiguity "
            "D8's flagless validators present on their real command line: no flag "
            "distinguishes 'this is the check' from 'this built the file list'.\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )

    @pytest.mark.parametrize("step", GATE_STEPS, ids=_gate_step_ids())
    def test_gate_step_body_succeeds_when_its_validator_succeeds(self, step, tmp_path):
        """
        Given: a gate step's shell body, with the interpreter stubbed to succeed
        When: the body runs under `bash -e`
        Then: it exits 0

        The control. It establishes that the harness can run this body at all,
        so that the non-zero result in the next test is attributable to the
        validator's failure rather than to the sandbox.
        """
        result = _run_step_body(step, tmp_path, validator_exit=0, resolver_exit=0)
        assert result.returncode == 0, (
            f"{step.source}: the step body exits {result.returncode} even when every "
            f"command it runs succeeds, so the failure assertions that follow would "
            f"prove nothing.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    @pytest.mark.parametrize("step", GATE_STEPS, ids=_gate_step_ids())
    def test_gate_step_body_fails_when_its_validator_fails(self, step, tmp_path):
        """
        Given: a gate step's shell body, with the validator stubbed to exit 1
        When: the body runs under `bash -e`
        Then: it exits non-zero

        The assertion the whole ADR rests on, and the one nothing else in this
        module makes. Deleting `exit 1` from the `else` branch, or writing
        `... --block ${FILES} || true; then`, each leave the violation found and
        printed, every flag in place, the file list complete, and the job green.

        That is precisely "land the invocation warn-only to soak", which ADR-037
        D7 rejects by name — reached without touching anything the other
        assertions in this module look at.
        """
        result = _run_step_body(step, tmp_path, validator_exit=1, resolver_exit=0)
        assert result.returncode != 0, (
            f"{step.source}: the validator exited 1 and the step body still exited 0. "
            f"The job is green with the violation found and printed.\n"
            f"  Nothing consumes the `status` outputs this step writes, so the step's "
            f"exit code is the entire enforcement mechanism (ADR-037 D1).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    @pytest.mark.parametrize("step", GATE_STEPS, ids=_gate_step_ids())
    def test_gate_step_body_fails_when_its_file_list_resolver_fails(self, step, tmp_path):
        """
        Given: a gate step that builds a file list from a command, with the
               resolver stubbed to exit 1 and the validator stubbed to exit 0
        When: the body runs under `bash -e`
        Then: it exits non-zero

        `FILES=$(resolver || true)` is the mutation this catches, and it is
        invisible everywhere else: the file list is still derived, still
        complete, still passed, and the resolver still runs. What it discards is
        the resolver's non-zero exit on an empty match — which
        `test_hook_file_list.py` calls the single most important assertion it
        makes, because the two `nargs="*"` validators exit 0 when handed no
        files.

        Nothing notices until the match actually goes empty, at which point the
        job passes having read nothing. A `files:` pattern edit, a rename, or a
        directory move is enough to get there.

        Steps with no file-list substitution are skipped: there is no resolver
        whose failure could be swallowed, and the previous test already covers
        their validator arm.
        """
        substitutions = _step_substitutions(step)
        if not substitutions:
            pytest.skip(
                f"{step.source} builds no file list from a command, so it has no "
                "resolver exit status to discard. Its validator arm is covered by "
                "test_gate_step_body_fails_when_its_validator_fails."
            )

        result = _run_step_body(step, tmp_path, validator_exit=0, resolver_exit=1)
        assert result.returncode != 0, (
            f"{step.source}: the file-list resolver exited 1 and the step body still "
            f"exited 0, so the validator ran on whatever the failed resolution left "
            f"behind.\n  file-list commands: {[command for _, command in substitutions]}\n"
            f"  The resolver's exit-1-on-empty-match contract is load-bearing only "
            f"while the step propagates it.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    @pytest.mark.parametrize("step", GATE_STEPS, ids=_gate_step_ids())
    def test_no_gate_step_guards_its_validator_against_failure(self, step):
        """
        Given: a gate step's shell body
        When: the simple command invoking the step's validator — located by a
              strictness flag or, for ADR-037 D8's flagless validators, by the
              script's basename — is found and the operator following it is
              inspected
        Then: it is not `||`

        The structural companion to the behavioural tests above, and the one
        that names the offending line. `_split_simple_commands` cannot express
        this — it discards operators, so `cmd` and `cmd || true` produce
        identical output there, and those two differ by exactly whether the job
        can fail.
        """
        guarded = _or_guarded_validator_lines(step)
        assert not guarded, (
            f"{step.source}: the validator command is guarded against its own "
            f"failure:\n" + "\n".join(f"  - {line}" for line in guarded) + "\n"
            "`|| true` (or any `||` fallback) makes the validator's non-zero exit "
            "invisible to the `if`, so the success branch runs, the job goes green, "
            "and the violation is merely printed."
        )

    def test_the_or_guard_detector_catches_a_flagless_validator(self):
        """
        Given: a synthetic step body guarding one of ADR-037 D8's flagless
               governed validators with `|| true`, carrying no strictness flag
               at all
        When: _or_guarded_validator_lines scans it
        Then: the guarded line is reported

        Non-vacuous proof for the half of test_no_gate_step_guards_its_validator_against_failure
        the live parametrization cannot yet exercise: no workflow invokes a
        flagless governed validator yet (ADR-037 D8), so every case that test
        collects today is a flagged step, and none of them reaches the
        basename branch of `_or_guarded_validator_lines`. A detector that
        regressed to flag-only matching would report nothing here, and a `||
        true` on a real D8 step would pass this class silently once one landed.

        UNFLAGGED_BLOCKING_SCRIPTS is not empty —
        TestUnflaggedBlockingCoverage's own non-vacuity guard establishes
        that — so a script name always exists to build the synthetic body
        from.
        """
        script = sorted(UNFLAGGED_BLOCKING_SCRIPTS)[0]
        synthetic = WorkflowStep(
            workflow="synthetic.yml",
            job="synthetic",
            label="synthetic",
            run=f"if python3 scripts/hooks/precommit/{script} || true; then\n  echo ok\nfi\n",
            shell=None,
            working_directory=None,
            source="synthetic::guarded-flagless",
        )
        guarded = _or_guarded_validator_lines(synthetic)
        assert guarded, (
            f"_or_guarded_validator_lines found no `||`-guarded line in a synthetic body "
            f"guarding {script} with no strictness flag on the line. The detector "
            "regressed to flag-only matching, which is silent on exactly the guard "
            "D8's flagless validators are exposed to."
        )

    @pytest.mark.parametrize("step", GATE_STEPS, ids=_gate_step_ids())
    def test_no_gate_step_is_exempted_from_failing_the_job(self, step):
        """
        Given: a gate step and its enclosing job
        When: `continue-on-error:` and `if:` are inspected at both levels
        Then: neither declares one

        These two keys sit outside the shell entirely, so no amount of executing
        the body can see them. `continue-on-error: true` lets the step exit 1
        and the job succeed anyway; an `if:` that is false — `github.event_name
        == 'schedule'` on a workflow that runs on pull requests, say — means the
        step does not run at all, which produces neither a failure nor a
        conspicuous absence.

        `if: always()` on a summary job is a legitimate pattern in this
        repository, which is exactly why the prohibition is scoped to *gate*
        steps: a summary that always runs is useful, a gate that sometimes runs
        is not a gate.
        """
        exemptions: list[str] = []
        if step.continue_on_error is not None:
            exemptions.append(f"step `continue-on-error: {step.continue_on_error!r}`")
        if step.job_continue_on_error is not None:
            exemptions.append(f"job `continue-on-error: {step.job_continue_on_error!r}`")
        if step.condition is not None:
            exemptions.append(f"step `if: {step.condition!r}`")
        if step.job_condition is not None:
            exemptions.append(f"job `if: {step.job_condition!r}`")

        assert not exemptions, (
            f"{step.source} is exempted from failing the workflow: {exemptions}.\n"
            "ADR-037 D1 makes CI the enforcing gate. A gate step that may fail without "
            "failing its job, or that may not run at all, enforces nothing — and both "
            "keys are invisible to every command-line assertion in this module."
        )

    def test_the_harness_reproduces_a_repository_state_bypass_faithfully(self):
        """
        Given: a synthetic step body that branches on whether a top-level
               repository directory exists *before* it ever reaches the
               validator — `if [ -d risk-map ]; then ...success... elif
               <validator>; then ...`
        When: the validator is stubbed to fail, and the body runs through
              `_run_step_body`'s own sandbox (nothing created by the test itself)
        Then: the step body exits 0 — the bypass happens, because
              `_populate_checkout_shaped_sandbox` already makes `risk-map`
              exist in the sandbox by the time the body runs

        This is not the assertion ADR-037 D1 needs held — it is proof that the
        harness is honest about a step shaped this way, which is the
        precondition for that assertion meaning anything. Before this test's
        history (021cc3a), `_run_step_body` forced `result.returncode = 1`
        whenever the stubbed validator was never invoked, which made this same
        synthetic body report "correctly failed" no matter what the shell
        actually did — the harness's own return code, not a property of the
        step body, is what a prior version of this test asserted. A step
        shaped like the one above is a real hazard precisely because a real
        checkout's `risk-map` (present from the job's own "Checkout
        repository" step before any gate step runs) makes the `if` branch win
        unconditionally, so the validator underneath the `elif` never runs and
        the job reports success. Asserting that here — rather than papering
        over it — is what makes
        `test_no_gate_step_lets_repository_state_bypass_its_validator` below a
        meaningful guard: it has a true bypass to distinguish itself from, not
        a harness that would have called both cases "failed".

        No real gate step is shaped this way today — the hazard is proven here
        with a synthetic body, the same non-vacuity discipline
        `test_the_or_guard_detector_catches_a_flagless_validator` uses for
        D8's flagless guard case above.
        """
        script = sorted(UNFLAGGED_BLOCKING_SCRIPTS)[0]
        synthetic = WorkflowStep(
            workflow="synthetic.yml",
            job="synthetic",
            label="synthetic",
            run=(
                "if [ -d risk-map ]; then\n"
                '  echo "status=success" >> $GITHUB_OUTPUT\n'
                f"elif python3 scripts/hooks/precommit/{script}; then\n"
                '  echo "status=success" >> $GITHUB_OUTPUT\n'
                "else\n"
                '  echo "status=failed" >> $GITHUB_OUTPUT\n'
                "  exit 1\n"
                "fi\n"
            ),
            shell=None,
            working_directory=None,
            source="synthetic::repository-state-bypass",
        )
        with tempfile.TemporaryDirectory() as sandbox_dir:
            result = _run_step_body(synthetic, Path(sandbox_dir), validator_exit=1, resolver_exit=0)
        assert result.returncode == 0, (
            f"{synthetic.source}: expected the repository-state branch to bypass the "
            f"validator and exit 0 — `_populate_checkout_shaped_sandbox` should have "
            f"made `risk-map` exist in the sandbox before the body ran. Getting a "
            "non-zero exit here means the sandbox is not checkout-shaped after all, "
            "which would make this test, and the guard below it, unable to tell a real "
            "bypass from a harness artefact.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_the_harness_reproduces_a_file_size_bypass_faithfully(self):
        """
        Given: a synthetic step body that branches on `[ -s
               risk-map/yaml/risks.yaml ]` — a real, tracked, non-empty file —
               *before* it ever reaches the validator, the same shape as the
               `-d` case above but with an operator `_REPO_STATE_CONDITION_RE`
               did not recognize before this test's history
        When: the validator is stubbed to fail, and the body runs through
              `_run_step_body`'s own sandbox
        Then: the step body exits 0 — the bypass happens, because
              `_populate_checkout_shaped_sandbox` copies the real,
              non-empty `risk-map/yaml/risks.yaml` into the sandbox, not an
              empty placeholder or nothing at all

        An empty sandbox (or one populated only with `_TOP_LEVEL_DIRECTORIES`,
        this class's previous form) makes `[ -s ... ]` false, which sends
        execution to the `elif` and lets the stubbed validator answer
        honestly — reporting a step shaped exactly like the one above as
        correctly failing when, against a real checkout where the file is
        genuinely non-empty, the `if` branch wins unconditionally and the
        validator never runs at all. That gap is what let the mutation
        `if [ -s risk-map/yaml/risks.yaml ]; then ... elif <validator>; then
        ...` survive undetected; this test is the proof that the current
        sandbox no longer produces that false negative for a file-size test,
        the same way the `-d` case proves it for a directory-existence test.
        """
        script = sorted(UNFLAGGED_BLOCKING_SCRIPTS)[0]
        synthetic = WorkflowStep(
            workflow="synthetic.yml",
            job="synthetic",
            label="synthetic",
            run=(
                "if [ -s risk-map/yaml/risks.yaml ]; then\n"
                '  echo "status=success" >> $GITHUB_OUTPUT\n'
                f"elif python3 scripts/hooks/precommit/{script}; then\n"
                '  echo "status=success" >> $GITHUB_OUTPUT\n'
                "else\n"
                '  echo "status=failed" >> $GITHUB_OUTPUT\n'
                "  exit 1\n"
                "fi\n"
            ),
            shell=None,
            working_directory=None,
            source="synthetic::repository-state-bypass-file-size",
        )
        with tempfile.TemporaryDirectory() as sandbox_dir:
            result = _run_step_body(synthetic, Path(sandbox_dir), validator_exit=1, resolver_exit=0)
        assert result.returncode == 0, (
            f"{synthetic.source}: expected the `[ -s ... ]` branch to bypass the "
            "validator and exit 0 — the sandbox should hold a real, non-empty "
            "risk-map/yaml/risks.yaml by the time the body ran. A non-zero exit here "
            "means the sandbox is not content-faithful, which is exactly the gap that "
            "let a file-size-based repository-state bypass go unnoticed.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    @pytest.mark.parametrize("step", GATE_STEPS, ids=_gate_step_ids())
    def test_no_gate_step_lets_repository_state_bypass_its_validator(self, step):
        """
        Given: a gate step's shell body
        When: it is scanned for a repository-state test — any single-letter
              `test`/`[` operator (`-d`, `-f`, `-s`, `-r`, `-x`, ...), in
              either the `if`/`elif` form or the keyword-free
              `[ ... ] && ... || ...` form — appearing before the line
              invoking this step's own validator
        Then: none is found

        The structural companion to
        `test_the_harness_reproduces_a_repository_state_bypass_faithfully`:
        that test proves the harness would expose a step shaped this way, and
        this one proves no real gate step is shaped that way today, in a form
        that would notice the next one. A `[ -d risk-map ]` branch ahead of
        the validator's own `if`/`elif` always wins once the job's checkout
        step has run — the directory it tests for exists unconditionally by
        then — so the validator underneath never executes and the job is
        green with the finding neither found nor printed.
        """
        assert not _repository_state_precedes_validator(step), (
            f"{step.source}: a repository-state test ([ -d ... ], [ -f ... ], or the "
            "`test` spelling) appears before this step's own validator invocation. "
            "Once this job's checkout step has run, the tested path exists "
            "unconditionally, so that branch always wins and the validator underneath "
            "never executes — the job reports success without the validator ever "
            "having run."
        )

    def test_the_repository_state_bypass_detector_catches_a_synthetic_case(self):
        """
        Given: a synthetic step body shaped exactly like the one
               `test_the_harness_reproduces_a_repository_state_bypass_faithfully`
               proves the harness exposes
        When: `_repository_state_precedes_validator` scans it
        Then: it reports the bypass

        Non-vacuous proof for
        `test_no_gate_step_lets_repository_state_bypass_its_validator`: no real
        gate step is shaped this way today, so every live parametrized case
        the test above collects returns False for a reason that says nothing
        about whether the detector actually works. This is the same
        discipline `test_the_or_guard_detector_catches_a_flagless_validator`
        applies to the `||`-guard detector.
        """
        script = sorted(UNFLAGGED_BLOCKING_SCRIPTS)[0]
        synthetic = WorkflowStep(
            workflow="synthetic.yml",
            job="synthetic",
            label="synthetic",
            run=(
                "if [ -d risk-map ]; then\n"
                '  echo "status=success" >> $GITHUB_OUTPUT\n'
                f"elif python3 scripts/hooks/precommit/{script}; then\n"
                '  echo "status=success" >> $GITHUB_OUTPUT\n'
                "else\n"
                '  echo "status=failed" >> $GITHUB_OUTPUT\n'
                "  exit 1\n"
                "fi\n"
            ),
            shell=None,
            working_directory=None,
            source="synthetic::repository-state-bypass",
        )
        assert _repository_state_precedes_validator(synthetic), (
            "_repository_state_precedes_validator found no bypass in a synthetic body "
            "shaped exactly like the one the harness-fidelity test above proves is a "
            "real hazard. The detector regressed to matching nothing, which is silent "
            "on exactly the shape it exists to catch."
        )

    @pytest.mark.parametrize("operator", ["-s", "-r", "-x", "-L"])
    def test_the_repository_state_bypass_detector_catches_every_test_operator(self, operator):
        """
        Given: a synthetic `if [ <operator> risk-map/yaml/risks.yaml ]; then
               ... elif <validator>; then ...` body, for each of several
               single-letter `test`/`[` operators the previous enumerated
               regex (`-[dfe]`) did not include
        When: `_repository_state_precedes_validator` scans it
        Then: it reports the bypass for every operator

        `_REPO_STATE_TEST_PATTERN` matches any single letter rather than an
        enumerated set specifically so this does not become a per-operator
        whack-a-mole; this test is what proves that generalization actually
        catches the operators the review named (`-s`, `-r`, `-x`, `-L`) and
        not only the three the previous pattern happened to list.
        """
        script = sorted(UNFLAGGED_BLOCKING_SCRIPTS)[0]
        synthetic = WorkflowStep(
            workflow="synthetic.yml",
            job="synthetic",
            label="synthetic",
            run=(
                f"if [ {operator} risk-map/yaml/risks.yaml ]; then\n"
                '  echo "status=success" >> $GITHUB_OUTPUT\n'
                f"elif python3 scripts/hooks/precommit/{script}; then\n"
                '  echo "status=success" >> $GITHUB_OUTPUT\n'
                "else\n"
                '  echo "status=failed" >> $GITHUB_OUTPUT\n'
                "  exit 1\n"
                "fi\n"
            ),
            shell=None,
            working_directory=None,
            source=f"synthetic::repository-state-bypass-{operator}",
        )
        assert _repository_state_precedes_validator(synthetic), (
            f"_repository_state_precedes_validator found no bypass in a synthetic body "
            f"using `{operator}`. The detector regressed to an enumerated letter class, "
            "which is silent on exactly the next operator nobody enumerated."
        )

    def test_the_repository_state_bypass_detector_catches_the_chained_no_keyword_form(self):
        """
        Given: a synthetic step body that gates its validator with
               `[ -s risk-map/yaml/risks.yaml ] && ... || <validator>`, using
               neither `if` nor `elif`
        When: `_repository_state_precedes_validator` scans it
        Then: it reports the bypass

        `_REPO_STATE_CONDITION_RE` alone only recognizes the `if`/`elif` form;
        `_line_has_repository_state_gate`'s second branch is what extends the
        same recognition to a bare test chained by `&&`/`||`, which gates
        execution exactly as effectively without ever writing the keyword.
        """
        script = sorted(UNFLAGGED_BLOCKING_SCRIPTS)[0]
        synthetic = WorkflowStep(
            workflow="synthetic.yml",
            job="synthetic",
            label="synthetic",
            run=(
                "[ -s risk-map/yaml/risks.yaml ] && echo already-clean && exit 0\n"
                f"python3 scripts/hooks/precommit/{script}\n"
            ),
            shell=None,
            working_directory=None,
            source="synthetic::repository-state-bypass-chained",
        )
        assert _repository_state_precedes_validator(synthetic), (
            "_repository_state_precedes_validator found no bypass in a synthetic body "
            "gating its validator with a chained `[ ... ] && ... || ...` test and no "
            "`if`/`elif` keyword. The detector regressed to the keyword-only form, which "
            "is silent on exactly the shape this test exists to catch."
        )


# ===========================================================================
# 9b. The aggregate gate — the summary job's own exit code
# ===========================================================================
#
# TestGateStepFailsTheJob (section 9) establishes that each gate step's own
# exit code fails its own job. Nothing there asks whether that job's result
# then reaches the decision a pull request's merge actually depends on.
# `validation-summary` runs `if: always()`, reads every other job's
# `needs.<job>.result`, and is the only place in the workflow any of those
# results is read at all — nothing consumes the `status` outputs individual
# gate steps write. A gate job absent from the summary's `needs:`, or a
# failing result the summary reads but does not act on, leaves the aggregate
# gate green regardless of what the gate job itself did.


def _summary_jobs(workflow_name: str) -> list[str]:
    """Return job ids in a workflow whose `if:` is exactly `always()`.

    That is the shape this repository's aggregate-gate jobs use — see
    TestGateStepFailsTheJob's own class docstring, which names `if: always()`
    on a summary job as a legitimate, load-bearing pattern: only a job that
    always runs can observe every other job's result regardless of which one
    failed. Derived rather than named, so a summary job renamed, or a second
    one added, is picked up with no edit here.
    """
    data = _workflow_data(workflow_name)
    return sorted(
        job_id for job_id, job in (data.get("jobs") or {}).items() if str(job.get("if", "")).strip() == "always()"
    )


def _jobs_with_gate_steps(workflow_name: str) -> set[str]:
    """Return the job ids in a workflow that contain at least one gate step."""
    return {step.job for step in GATE_STEPS if step.workflow == workflow_name}


# `${{ needs.<job>.result }}` and `${{ needs.<job>.outputs.<name> }}`, the two
# `needs`-context expression shapes the summary jobs in this repository read.
_NEEDS_RESULT_RE = re.compile(r"\$\{\{\s*needs\.([A-Za-z0-9_-]+)\.result\s*\}\}")
_NEEDS_OUTPUT_RE = re.compile(r"\$\{\{\s*needs\.([A-Za-z0-9_-]+)\.outputs\.[A-Za-z0-9_-]+\s*\}\}")

# Any `${{ ... }}` expression at all, for the unresolved-expression guard
# `_render_needs_expressions` runs after its own two substitutions. GitHub
# evaluates every `${{ }}` before the shell runs; one this renderer does not
# know how to resolve is not a no-op left for the shell to ignore — `${{
# github.run_id }}` is not valid bash syntax (`{` cannot start a parameter
# name), so `bash -e` aborts with "bad substitution" on the very first such
# expression, regardless of which line it is on. That abort is a non-zero
# exit for a reason that has nothing to do with the aggregate-gate logic
# under test, and it happens for *every* rendering this section performs —
# `test_summary_job_fails_when_any_gate_job_does_not_succeed` would then
# "pass" no matter what `overall_success` actually became.
_ANY_EXPRESSION_RE = re.compile(r"\$\{\{.*?\}\}")


def _referenced_needs_jobs(run: str) -> set[str]:
    """Return every job id a step's body reads through the `needs` context."""
    return {match.group(1) for match in _NEEDS_RESULT_RE.finditer(run)} | {
        match.group(1) for match in _NEEDS_OUTPUT_RE.finditer(run)
    }


def _render_needs_expressions(run: str, results: dict[str, str]) -> str:
    """Substitute `${{ needs.<job>.result }}` / `.outputs.*` the way GitHub does before the shell runs.

    GitHub evaluates every `${{ }}` expression before a runner's shell ever
    sees a `run:` block. This reproduces that for the subset of context this
    section's tests drive — a job's `result` and its `outputs.*` — so
    `_run_step_body`'s "execute the raw shell verbatim" model stays valid for
    a job that reads job-level context instead of invoking a validator. A job
    id with no entry in `results` defaults to `"success"`, matching a control
    run where nothing has failed; `outputs.*` references resolve to the empty
    string, since no test in this section reads output content.

    Raises if any `${{ }}` expression survives both substitutions, rather than
    handing the shell a literal it cannot execute — `bash -e` aborts with "bad
    substitution" on an unresolved `${{ }}`, a non-zero exit indistinguishable
    from the aggregate-gate logic actually failing. An ordinary edit —
    `echo "Run: ${{ github.run_id }}" >> $GITHUB_STEP_SUMMARY` in the same
    step — reaches an expression shape this function does not yet know, and
    the fix is to teach it that shape, not to let it pass through unrendered
    and have every case in this section "pass" for the wrong reason.
    """
    rendered = _NEEDS_RESULT_RE.sub(lambda match: results.get(match.group(1), "success"), run)
    rendered = _NEEDS_OUTPUT_RE.sub("", rendered)
    unresolved = _ANY_EXPRESSION_RE.findall(rendered)
    if unresolved:
        raise AssertionError(
            f"_render_needs_expressions left {unresolved} unresolved in:\n{run}\n"
            "GitHub evaluates every `${{ }}` expression before the shell runs. Leaving "
            "one as literal text makes bash abort with a syntax error on it, which "
            "would satisfy 'the rendered body exits non-zero' regardless of what the "
            "aggregate-gate logic under test actually does. Teach this function the "
            "expression shape rather than let it through unresolved."
        )
    return rendered


def _run_summary_step(run: str, sandbox: Path, results: dict[str, str]) -> subprocess.CompletedProcess:
    """Execute a summary step's rendered body under GitHub's default shell."""
    rendered = _render_needs_expressions(run, results)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(sandbox),
        "GITHUB_OUTPUT": str(sandbox / "github_output.txt"),
        "GITHUB_STEP_SUMMARY": str(sandbox / "github_step_summary.txt"),
    }
    return subprocess.run(
        ["bash", "-e", "-c", rendered], capture_output=True, text=True, cwd=str(sandbox), env=environment
    )


class TestAggregateGateReflectsEveryGateJob:
    """The summary job is the only place any gate job's result is read.

    ADR-037's gate steps fail their own job (section 9); that job's `result`
    then has to reach the summary job unmodified, be read there for every gate
    job, and force a non-zero exit whenever any of them is not `"success"` —
    or the aggregate gate a pull request's merge check actually depends on can
    be green while a gate job it lists is not.
    """

    def test_summary_jobs_are_found(self):
        """Non-vacuity guard: the parametrized cases below quantify over this set.

        Known gap, recorded rather than fixed: this is an `any()` over
        GATE_WORKFLOWS, not a per-workflow check. The three parametrized
        tests below each `pytest.skip()` individually for a workflow with no
        `if: always()` job, so this guard protects the class only as long as
        *some* gate workflow has one — it would stay green if `validation.yml`
        itself lost its summary job while a second, unrelated gate workflow
        kept its own, and `validation.yml`'s own three cases would then skip
        without this test, or any other, saying so. Fixing it properly means
        deciding whether every gate workflow is required to carry an
        aggregate job — a policy question ADR-037 does not settle explicitly
        — not just parametrizing this check; recorded here rather than
        answered until that question is.
        """
        found = {workflow_name: _summary_jobs(workflow_name) for workflow_name in GATE_WORKFLOWS}
        assert any(found.values()), (
            f"No workflow among {GATE_WORKFLOWS} declares a job with `if: always()`. "
            f"Found: {found}. Nothing below has an aggregate-gate job to check."
        )

    @pytest.mark.parametrize("workflow_name", GATE_WORKFLOWS)
    def test_summary_job_needs_and_reads_every_gate_job(self, workflow_name):
        """
        Given: a workflow's `if: always()` job(s)
        When: their `needs:` list, and the `needs.<job>.result` expressions in
              their own steps, are compared against every job containing a
              gate step
        Then: every gate job is present in both

        Reproduces mutation M13b: removing two gate jobs from `needs:` and
        deleting their `if [ "$x_result" = "success" ]` branches leaves the
        summary job's shell syntactically valid and every other assertion in
        this module satisfied — the two removed jobs' own steps still run,
        still fail on a real violation, and still write their own `status`
        output, which nothing else reads either. The summary simply stops
        asking about them.
        """
        summary_jobs = _summary_jobs(workflow_name)
        if not summary_jobs:
            pytest.skip(f"{workflow_name} declares no `if: always()` job.")
        gate_jobs = _jobs_with_gate_steps(workflow_name)
        assert gate_jobs, f"No gate step belongs to any job in {workflow_name}."

        data = _workflow_data(workflow_name)
        for job_id in summary_jobs:
            declared_needs = set(data["jobs"][job_id].get("needs") or [])
            missing_needs = gate_jobs - declared_needs
            assert not missing_needs, (
                f"{workflow_name}::{job_id}: `needs:` does not list {sorted(missing_needs)}, "
                "each of which contains a gate step. A job absent from `needs:` cannot be "
                "read through the `needs` context at all, and its result cannot delay or "
                "gate this job."
            )

            referenced = {
                job
                for step in WORKFLOW_STEPS
                if step.workflow == workflow_name and step.job == job_id
                for job in _referenced_needs_jobs(step.run)
            }
            missing_reads = gate_jobs - referenced
            assert not missing_reads, (
                f"{workflow_name}::{job_id}: `needs:` lists {sorted(gate_jobs)}, but its "
                f"own steps never read `needs.<job>.result` for {sorted(missing_reads)}. "
                "A job listed in `needs:` but never read contributes nothing to the "
                "aggregate result."
            )

    @pytest.mark.parametrize("workflow_name", GATE_WORKFLOWS)
    def test_summary_job_succeeds_when_every_gate_job_succeeds(self, workflow_name):
        """
        Given: an `if: always()` job's own shell body, rendered with every
               referenced job's result set to `"success"`
        When: the rendered body runs under `bash -e`
        Then: it exits 0

        The control for `test_summary_job_fails_when_any_gate_job_does_not_
        succeed` below, the same role `test_gate_step_body_succeeds_when_its_
        validator_succeeds` plays for the gate-step tests in section 9.
        Without it, a non-zero exit in the failure case could be an artefact
        of the render or the harness — an expression `_render_needs_
        expressions` cannot resolve aborts `bash -e` with "bad substitution"
        for *every* rendering this class performs, success case included, so
        this is also the test that would catch that: if it fails, the
        failure-case test below is not observing the aggregate-gate logic at
        all.
        """
        summary_jobs = _summary_jobs(workflow_name)
        if not summary_jobs:
            pytest.skip(f"{workflow_name} declares no `if: always()` job.")
        gate_jobs = _jobs_with_gate_steps(workflow_name)
        assert gate_jobs, f"No gate step belongs to any job in {workflow_name}."

        for job_id in summary_jobs:
            steps = [step for step in WORKFLOW_STEPS if step.workflow == workflow_name and step.job == job_id]
            referenced = {job for step in steps for job in _referenced_needs_jobs(step.run)}
            candidates = gate_jobs & referenced
            assert candidates, (
                f"{workflow_name}::{job_id}: none of its steps reads `needs.<job>.result` "
                f"for any job containing a gate step ({sorted(gate_jobs)}). Non-vacuity "
                "guard — this control has nothing to render otherwise."
            )
            results = {job: "success" for job in referenced}
            outcome = 0
            with tempfile.TemporaryDirectory() as sandbox_dir:
                sandbox = Path(sandbox_dir)
                for step in steps:
                    result = _run_summary_step(step.run, sandbox, results)
                    if result.returncode != 0:
                        outcome = result.returncode
                        break
            assert outcome == 0, (
                f"{workflow_name}::{job_id}: rendering with every referenced job "
                f"'success' still exits {outcome}. The failure-case test below proves "
                "nothing until this passes — a non-zero exit here means the render or "
                "the harness is broken, not the aggregate-gate logic.\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )

    @pytest.mark.parametrize("workflow_name", GATE_WORKFLOWS)
    def test_summary_job_fails_when_any_gate_job_does_not_succeed(self, workflow_name):
        """
        Given: an `if: always()` job's own shell body, rendered once per gate
               job with every referenced job's result set to `"success"`
               except that one gate job, set to `"failure"`
        When: the rendered body runs under `bash -e`
        Then: it exits non-zero

        Reproduces mutation M14: deleting a single `overall_success=false`
        line for one job leaves that job's `❌` line printed in the summary —
        the `if [ "$x_result" = "success" ]` check still runs, still takes the
        `else` branch, still echoes the failure — while the final
        `if [ "$overall_success" = "true" ]` still reads `true` and the job
        exits 0 regardless. `needs:` and every `needs.<job>.result` read stay
        intact, so `test_summary_job_needs_and_reads_every_gate_job` above
        cannot see this: the mutation is in what the job's shell *does* with a
        value it already reads correctly, not in whether it reads it.

        The control immediately above establishes that a non-zero exit here
        means the aggregate-gate logic actually failed, not that
        `_render_needs_expressions` choked on an expression it does not
        recognize — that function raises loudly on one instead (see its own
        docstring), so this test would error, not silently pass, if the real
        step ever grew an expression shape neither renderer nor control knows.
        """
        summary_jobs = _summary_jobs(workflow_name)
        if not summary_jobs:
            pytest.skip(f"{workflow_name} declares no `if: always()` job.")
        gate_jobs = _jobs_with_gate_steps(workflow_name)
        assert gate_jobs, f"No gate step belongs to any job in {workflow_name}."

        for job_id in summary_jobs:
            steps = [step for step in WORKFLOW_STEPS if step.workflow == workflow_name and step.job == job_id]
            referenced = {job for step in steps for job in _referenced_needs_jobs(step.run)}
            candidates = gate_jobs & referenced
            assert candidates, (
                f"{workflow_name}::{job_id}: none of its steps reads `needs.<job>.result` "
                f"for any job containing a gate step ({sorted(gate_jobs)}). Non-vacuity "
                "guard — the loop below would otherwise assert nothing."
            )
            for failing_job in sorted(candidates):
                results = {job: ("failure" if job == failing_job else "success") for job in referenced}
                outcome = 0
                with tempfile.TemporaryDirectory() as sandbox_dir:
                    sandbox = Path(sandbox_dir)
                    for step in steps:
                        result = _run_summary_step(step.run, sandbox, results)
                        if result.returncode != 0:
                            outcome = result.returncode
                            break
                assert outcome != 0, (
                    f"{workflow_name}::{job_id}: rendering with only {failing_job!r} set to "
                    "'failure' (every other referenced job 'success') still exits 0. "
                    "The aggregate gate reports success while a gate job it lists did not."
                )

    def test_the_needs_expression_renderer_substitutes_a_failing_result(self):
        """
        Given: a minimal shell body reading `${{ needs.some-job.result }}`
        When: `_render_needs_expressions` renders it with `some-job` set to
              `"failure"` and the rendered body runs
        Then: the shell sees the literal string `failure`

        Non-vacuous proof that the substitution
        `test_summary_job_fails_when_any_gate_job_does_not_succeed` depends on
        actually happens — GitHub performs this rewrite before a runner's
        shell ever starts, so nothing here can observe it working except by
        rendering a body and running it.
        """
        rendered = _render_needs_expressions('echo "${{ needs.some-job.result }}"', {"some-job": "failure"})
        with tempfile.TemporaryDirectory() as sandbox_dir:
            sandbox = Path(sandbox_dir)
            environment = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(sandbox),
                "GITHUB_OUTPUT": str(sandbox / "github_output.txt"),
                "GITHUB_STEP_SUMMARY": str(sandbox / "github_step_summary.txt"),
            }
            result = subprocess.run(
                ["bash", "-e", "-c", rendered], capture_output=True, text=True, cwd=str(sandbox), env=environment
            )
        assert result.stdout.strip() == "failure", (
            "_render_needs_expressions did not substitute a literal 'failure' for "
            f"needs.some-job.result. stdout: {result.stdout!r}"
        )


# ===========================================================================
# 10. D8 — blocking validators that carry no strictness flag
# ===========================================================================
#
# Every derivation above keys on `--block`. ADR-037 D8 records that keying on
# the flag reproduces one surface lower the defect D1 exists to end: `--block`
# marks a validator with a *warn-only tier to promote*, so a validator that
# blocks unconditionally never carries it and is invisible to a rule that
# quantifies over flag-bearing hooks. Three such hooks are invoked by no
# workflow at all, and a contributor without the hooks installed can land a
# violation with an all-green CI.
#
# D1's coverage clause therefore ranges over *blocking* hooks. This section
# applies it to the hooks that carry no flag, and D7a/D7b/D7c apply to them
# unchanged (D8).
#
# What is different about these three, and what the tests below have to do
# differently as a result:
#
#   They resolve their own inputs. All three are `pass_filenames: false` and
#   scan a corpus they locate themselves, so there is no file list to derive
#   and section 6 does not apply to them. Their enabling input is not an
#   argument at all — it is the checkout they resolve against.
#
#   Two of them resolve it from `Path(__file__)` and one from the working
#   directory, and that asymmetry is the hazard. A `__file__`-anchored
#   validator invoked from the wrong working directory does not fail: it
#   validates the corpus beside its own source and exits 0, so a job wired to
#   the wrong tree is green and silent. The cwd-anchored one fails loudly in
#   the same situation. Nothing on either command line distinguishes the two.
#
# The consequence for these tests is that "run it against a poisoned corpus"
# has to be spelled out as *which* corpus. Every behavioural test below builds
# a checkout-shaped mirror — the validator sources at their real relative
# paths, the framework registry and schema they read as oracles, and the
# content files under `risk-map/yaml/` — so both anchoring styles resolve
# inside it. Running the mirror's own copy is the non-vacuity case; running
# the repository's copy against the same mirror is the hazard case.


# ADR_GOVERNED_HOOK_IDS, UNFLAGGED_BLOCKING_HOOKS, UNFLAGGED_BLOCKING_HOOK_IDS,
# UNFLAGGED_BLOCKING_SCRIPTS and _unflagged_script are defined in section 6 now,
# not here: FILE_ARGUMENT_BLOCK_HOOKS (D7a) and `_gate_steps` (section 7) both
# need them to recognize a flagless governed hook, and this section still reads
# the same names.


def _unflagged_ci_invocations(hook_id: str) -> list[Invocation]:
    """Return every CI invocation of a governed flagless hook's validator, attributed to this hook.

    Reuses section 6's hook-vs-script join (`_invocation_names_hook`) rather
    than writing a second one. Matching on script alone was this function's
    original form, and it silently attributes a *sibling* hook's own CI
    invocation to `hook_id` whenever two ADR-governed hooks share a script —
    `validate-neutrality` and `validate-neutrality-policy` both name
    `validate_neutrality.py`. UNFLAGGED_BLOCKING_HOOKS excludes the
    file-argument sibling for exactly this reason (see its own definition),
    but that exclusion is a policy choice about which hooks section 10 tests,
    not a guarantee about the shape of `.pre-commit-config.yaml` — this
    function stays correct even if a future hook shares a script with a
    UNFLAGGED_BLOCKING_HOOK_IDS member some other way.

    A candidate invocation is excluded when its own file-list command names a
    *different* governed hook that shares this script: that is what an
    unrelated sibling's invocation looks like, whether the sibling is a
    file-argument hook (`_invocation_names_hook` finds its name directly) or
    another self-scanning one sharing this script (excluded by
    UNFLAGGED_BLOCKING_HOOKS, so never reaches this function as `hook_id`
    itself, but still a candidate to exclude here).

    Parsed with substitutions preserved so a file list built at run time can be
    resolved rather than passed through as a literal `${VAR}` token.
    """
    script = _unflagged_script(hook_id)
    sibling_ids = [
        other
        for other in ADR_GOVERNED_HOOK_IDS
        if other != hook_id
        and PRECOMMIT_HOOKS_BY_ID.get(other)
        and _hook_script(PRECOMMIT_HOOKS_BY_ID[other][0]) == script
    ]
    return [
        inv
        for inv in WORKFLOW_INVOCATIONS_RESOLVABLE
        if inv.script == script and not any(_invocation_names_hook(inv, sibling) for sibling in sibling_ids)
    ]


def _steps_invoking(script: str) -> list[WorkflowStep]:
    """Return every workflow step whose shell body executes the named script."""
    return [
        step
        for step in WORKFLOW_STEPS
        if any(inv.script == script for inv in _python_invocations(step.run, step.source, keep_substitutions=True))
    ]


def _changes_directory(step: WorkflowStep) -> list[str]:
    """Return the `cd` commands in a step's body, if any.

    The same scan `test_no_gate_step_changes_directory` performs, expressed
    again here rather than reused. `_gate_steps` now recognizes a flagless
    validator's invocation as a gate step (D8), so that test does reach these
    steps too — but its failure message speaks about "gate steps" in
    aggregate, and the hazard is sharper for these than for a flagged step: a
    moved working directory makes the cwd-anchored validator fail loudly and
    the two `__file__`-anchored ones pass silently on a corpus the job did not
    name. This copy exists so a failure here names the offending hook_id
    directly.
    """
    found: list[str] = []
    for raw_line in step.run.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for segment in _split_simple_commands(_safe_split(stripped)):
            while segment and (segment[0] in _LEADING_WORDS or _TOKEN_ASSIGN_RE.match(segment[0])):
                segment = segment[1:]
            if segment and segment[0] == "cd":
                found.append(stripped)
    return found


# --- checkout mirror --------------------------------------------------------
#
# The mirror is not a copy-to-root arrangement and does not test one. It
# reproduces the *relative* layout of a checkout at a different absolute path,
# which is what CI is; D7b's prohibition is on flattening that layout, not on
# the repository existing somewhere else. Running the mirror's own copy of a
# validator is therefore the faithful model of the CI invocation, and it is the
# only way to put a violation in front of a validator that locates its corpus
# from `Path(__file__)`.

# Oracles both mapping validators read through `framework_mapping`: the version
# registry and the pinned-value patterns. Copied verbatim so a poisoned mapping
# value is judged against the real registry rather than a fixture of one.
_MIRRORED_ORACLES = (
    "risk-map/yaml/frameworks.yaml",
    "risk-map/schemas/frameworks.schema.json",
)

_MIRRORED_SOURCE_DIR = "scripts/hooks/precommit"


def _mirror_checkout(base: Path) -> Path:
    """Materialize a checkout-shaped tree under `base` and return it.

    Contains the `precommit/` validator sources at their real repo-relative
    path and the framework oracles they read. Content YAML files are written by
    the per-validator corpus writers, because what counts as content differs:
    for the mapping validators it is the four consumer files, and for the
    versionId validator it is `frameworks.yaml` itself.

    Also a git repository, not just a directory tree shaped like one: a real
    checkout has a `.git`, and `validate_all_schemas.py`'s `_find_pairs()`
    reads `git ls-files` to discover its corpus, so a validator-under-test
    that depends on the index needs one here too. `git init` alone can fail
    silently from a caller's point of view (a bad `git`, a read-only `base`);
    asserted immediately so that failure is attributed here, not surfaced
    later as a confusing `git ls-files` error from inside a probe.
    """
    shutil.copytree(
        _REPO_ROOT / _MIRRORED_SOURCE_DIR,
        base / _MIRRORED_SOURCE_DIR,
        ignore=shutil.ignore_patterns("__pycache__"),
        dirs_exist_ok=True,
    )
    for relative in _MIRRORED_ORACLES:
        target = base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_REPO_ROOT / relative, target)
    subprocess.run(["git", "init", "-q"], cwd=str(base), check=True)
    assert (base / ".git").is_dir(), f"git init did not create a repository at {base}"
    return base


def _track_mirror(base: Path) -> None:
    """Stage every file under `base` so `git ls-files` reflects the corpus as written.

    Corrected rationale — the previous version of this docstring named several
    probes (mapping purity, mapping drift, the all-schemas and persona-site-
    build extra-file copies, the neutrality self-scan probe file) as the
    reason post-`write_corpus` timing matters, on the theory that each adds a
    path that needs staging. That is true about what those probes write and
    false about why it matters: none of those validators reads the git index
    at all — each resolves its corpus from `Path(__file__)` or the working
    directory, on disk, the same way with or without a `.git` present.
    `validate_all_schemas.py` is the only validator among this module's probes
    that reads `git ls-files` (via `_find_pairs()`), and the one path its own
    probe adds after `_mirror_checkout` — `riskmap.schema.json` — is excluded
    from pairing by name (`_MASTER_SCHEMA_NAME`) regardless of whether it is
    tracked; the pair that validator's clean run actually depends on
    (`frameworks.yaml`/`frameworks.schema.json`) is copied by `_mirror_checkout`
    itself, before any probe runs, so a single `git add -A` timed there would
    already cover it. Call sites after `write_corpus` are therefore not
    load-bearing for any probe registered today — reproduced as mutation G4
    (moving the `git add -A` into `_mirror_checkout` and making this function a
    no-op leaves every parametrized case passing).

    Kept as three call sites anyway, deliberately, rather than folded into
    `_mirror_checkout`: the contract this function exists to hold —
    "`git ls-files` reflects whatever is on disk in this mirror, including
    anything a probe just wrote" — is what protects the *next* validator that
    reads the index over a path `write_corpus` adds, which no probe does yet
    but nothing rules out. `test_track_mirror_stages_paths_added_after_the_
    initial_build` pins that contract directly, on a synthetic path, so a
    regression here (or a future refactor collapsing these calls) fails loud
    on its own rather than staying invisible until a probe happens to depend
    on it.
    """
    subprocess.run(["git", "add", "-A"], cwd=str(base), check=True)


# --- per-validator corpora --------------------------------------------------

_CONTENT_ENTITIES = ("risks", "controls", "components", "personas")

# A framework key the registry does not declare. Purity fails loudly on it
# (rule 1, ADR-027 D4c) and drift deliberately skips it, so it isolates the
# purity validator's own remit.
_UNKNOWN_FRAMEWORK_KEY = "frameworkProbeNotInRegistry"

# A pinned value whose version token no framework declares. Drift classifies it
# invalid — the version-token check is its remit (ADR-027 D5) — and the token is
# built from the registry rather than written out, so a version bump cannot turn
# the poison into a valid value.
_DRIFT_PROBE_TOKEN = "0.0.0-probe"

# A versionId that neither derives from its entry's id nor satisfies the D2a
# charset: uppercase and `_` are outside `^[a-z0-9.@-]+$`, and the entry's
# `version` is null so the derived value is the bare id.
_PROBE_FRAMEWORK_ID = "framework-probe"
_MALFORMED_VERSION_ID = "Framework_Probe@BOGUS"


def _versioned_framework_id() -> str:
    """Return a framework id the registry declares a version for.

    Read from the registry so the drift probe pins a value against whatever the
    corpus actually declares. Fails rather than returning a default: with no
    versioned framework there is no drift to inject, and a silently skipped
    injection is a passing test that proved nothing.
    """
    data = yaml.safe_load((_REPO_ROOT / "risk-map" / "yaml" / "frameworks.yaml").read_text(encoding="utf-8"))
    for entry in data.get("frameworks") or []:
        if isinstance(entry, dict) and entry.get("version") is not None and entry.get("id"):
            return str(entry["id"])
    pytest.fail(
        "No framework in the registry declares a version, so no value can be given a "
        "stale version token and the drift probe cannot express a violation. Drift "
        "detection would then be untestable rather than passing."
    )


def _write_mapping_content(base: Path, mappings_by_entity: dict[str, dict[str, list[str]]]) -> None:
    """Write the four consumer YAMLs, giving named entities a `mappings` block.

    All four are written whether or not they carry mappings: both validators
    exit 1 with "content file not found" on a missing default, which would be a
    red run that never reached a mapping value.
    """
    yaml_dir = _yaml_dir(base)
    for entity in _CONTENT_ENTITIES:
        item: dict[str, Any] = {"id": f"{entity[:-1]}Probe", "title": "Probe"}
        mappings = mappings_by_entity.get(entity)
        if mappings:
            item["mappings"] = mappings
        (yaml_dir / f"{entity}.yaml").write_text(yaml.dump({entity: [item]}), encoding="utf-8")


def _write_mapping_purity_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_mapping_purity.py; poison = mapping under an unregistered framework."""
    _write_mapping_content(base, {"risks": {_UNKNOWN_FRAMEWORK_KEY: ["PROBE-REF"]}} if poisoned else {})


def _write_mapping_drift_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_mapping_drift.py; poison = pinned value on an unknown version token."""
    value = f"PROBE-REF@{_DRIFT_PROBE_TOKEN}"
    _write_mapping_content(base, {"controls": {_versioned_framework_id(): [value]}} if poisoned else {})


def _write_versionid_purity_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_versionid_purity.py; poison = a hand-edited versionId.

    The clean corpus is the registry as committed, which the mirror already
    holds: this validator's subject file *is* one of the oracles, so there is
    nothing to write for the clean case.
    """
    if not poisoned:
        return
    path = _yaml_dir(base) / "frameworks.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["frameworks"].append({"id": _PROBE_FRAMEWORK_ID, "version": None, "versionId": _MALFORMED_VERSION_ID})
    path.write_text(yaml.dump(data), encoding="utf-8")


def _copy_repo_file(base: Path, relative: str) -> None:
    """Copy one real repository file into a mirror at the same relative path.

    Used by probes below whose validator has real data or source dependencies
    beyond `_MIRRORED_ORACLES` — copying the real file rather than a synthetic
    stand-in means the clean run exercises the validator's actual behaviour on
    the actual corpus, and only the deliberate poison differs from what CI
    would see.
    """
    target = base / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_REPO_ROOT / relative, target)


# A framework id outside frameworks.schema.json's own `enum` constraint on
# `frameworks[].id` — a JSON Schema violation, independent of ADR-027's
# versionId rules validate_versionid_purity.py enforces above. Verified
# empirically against check-jsonschema (the real subprocess this validator
# shells out to): a minimal `{"id": ...}` entry with no other fields reports
# both the enum violation and the fields missing to be schema-valid, and
# check-jsonschema resolves that $ref only when riskmap.schema.json is also
# on disk next to frameworks.schema.json — not part of _MIRRORED_ORACLES,
# because none of the other probes below need it.
_ALL_SCHEMAS_PROBE_FRAMEWORK_ID = "framework-not-in-schema-enum"


def _write_all_schemas_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_all_schemas.py; poison = a frameworks.yaml entry outside the schema enum."""
    _copy_repo_file(base, "risk-map/schemas/riskmap.schema.json")
    if not poisoned:
        return
    path = _yaml_dir(base) / "frameworks.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["frameworks"].append({"id": _ALL_SCHEMAS_PROBE_FRAMEWORK_ID})
    path.write_text(yaml.dump(data), encoding="utf-8")


# validate_persona_site_build.py's own real data and source dependencies.
# Copied verbatim rather than synthesized: build_site_data's transform and
# write_site_data's output-schema validation are involved enough that a
# minimal synthetic corpus risks passing or failing for reasons unrelated to
# the poison. Verified empirically: with only these copied and personas.yaml
# left as committed, the builder runs clean (exit 0).
_PERSONA_SITE_BUILD_EXTRA_FILES = (
    "scripts/build_persona_site_data.py",
    "scripts/hooks/_sentinel_expansion.py",
    "risk-map/schemas/persona-site-data.schema.json",
    "risk-map/schemas/external-references.schema.json",
    "risk-map/yaml/personas.yaml",
    "risk-map/yaml/risks.yaml",
    "risk-map/yaml/controls.yaml",
    "risk-map/yaml/components.yaml",
)

# The marker substring in build_persona_site_data.load_yaml's own error text
# for an empty/all-null YAML file — read from that message here because the
# violation this poison targets *is* "the file failed to parse", not a
# content rule with an independent spec to check the marker against.
_PERSONA_SITE_BUILD_EMPTY_MARKER = "is empty or all-null"


def _write_persona_site_build_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_persona_site_build.py; poison = an empty personas.yaml.

    `load_yaml` raises ValueError on an empty/all-null file — a real, named
    failure mode in the source (build_persona_site_data.py:76-81), not one
    inferred from validate_persona_site_build.py's own wrapper message.
    """
    for relative in _PERSONA_SITE_BUILD_EXTRA_FILES:
        _copy_repo_file(base, relative)
    if poisoned:
        (base / "risk-map" / "yaml" / "personas.yaml").write_text("", encoding="utf-8")


# Relative path a self-scanning validate-neutrality-policy corpus writes its
# probe file at. Not one of the repository's own tracked scripts/agents/**
# paths — this hook takes no file arguments, so the probe's path is this
# module's own choice, unlike FILE_LIST_PROBES below where the hook's file
# list dictates rel_path.
_NEUTRALITY_SELF_SCAN_REL_PATH = "scripts/agents/probe.md"


def _write_neutrality_self_scan_corpus(base: Path, poisoned: bool) -> None:
    """Corpus for validate_neutrality.py's self-scanning hook (validate-neutrality-policy).

    Writes one file under scripts/agents/ so discover_neutral_surface_files
    finds it from the mirror's working directory. No leading `---` line, so
    the structural frontmatter rule for a top-level agent .md never fires —
    only the denylist scan (this hook's actual remit) is under test here.
    """
    text = (
        f"This probe agent mentions {_NEUTRALITY_POISON_TERM} for testing purposes.\n"
        if poisoned
        else "Clean, vendor-neutral prose describing this probe agent.\n"
    )
    target = base / _NEUTRALITY_SELF_SCAN_REL_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


class UnflaggedProbe(NamedTuple):
    """A flagless blocking validator plus the means to make it fail.

    Attributes:
        write_corpus: Callable (mirror_root, poisoned) -> None writing content
            files into an already-materialized mirror.
        marker: A string the diagnostic must contain, proving the injected
            violation is what fired rather than some unrelated check.
        rule: The rule the poison violates, for assertion messages.
    """

    write_corpus: Callable[[Path, bool], None]
    marker: str
    rule: str


# validator basename -> probe. Keyed on the script rather than the hook id so a
# hook rename does not orphan a probe.
UNFLAGGED_PROBES: dict[str, UnflaggedProbe] = {
    "validate_mapping_purity.py": UnflaggedProbe(
        write_corpus=_write_mapping_purity_corpus,
        marker=_UNKNOWN_FRAMEWORK_KEY,
        rule="unknown framework key (ADR-027 D4c)",
    ),
    "validate_mapping_drift.py": UnflaggedProbe(
        write_corpus=_write_mapping_drift_corpus,
        marker=_DRIFT_PROBE_TOKEN,
        rule="unrecognized version token (ADR-027 D5)",
    ),
    "validate_versionid_purity.py": UnflaggedProbe(
        write_corpus=_write_versionid_purity_corpus,
        marker=_MALFORMED_VERSION_ID,
        rule="versionId derivation and D2a charset (ADR-027 D2b/D2c)",
    ),
    "validate_all_schemas.py": UnflaggedProbe(
        write_corpus=_write_all_schemas_corpus,
        marker=_ALL_SCHEMAS_PROBE_FRAMEWORK_ID,
        rule="framework id outside frameworks.schema.json's own enum (JSON Schema)",
    ),
    "validate_persona_site_build.py": UnflaggedProbe(
        write_corpus=_write_persona_site_build_corpus,
        marker=_PERSONA_SITE_BUILD_EMPTY_MARKER,
        rule="empty/unparseable personas.yaml (build_persona_site_data.load_yaml)",
    ),
    "validate_neutrality.py": UnflaggedProbe(
        write_corpus=_write_neutrality_self_scan_corpus,
        marker=_NEUTRALITY_POISON_TERM,
        rule="ADR-033 vendor/product denylist term under scripts/agents|skills/**",
    ),
}


def _governed_ci_argv(hook_id: str) -> tuple[Invocation, list[str]]:
    """Return a governed hook's single CI invocation and its resolved argv.

    Fails when there is none — every behavioural claim in this section is about
    the command CI runs, and there is nothing to run — and when there are
    several, because ADR-037 D7 requires a failure to resolve to one validator
    and this section cannot decide which of two commands the rule is about.
    """
    invocations = _unflagged_ci_invocations(hook_id)
    script = _unflagged_script(hook_id)
    if not invocations:
        pytest.fail(
            f"No workflow invokes {script} (hook {hook_id!r}), so there is no CI command "
            f"to run against a corpus. "
            f"TestUnflaggedBlockingCoverage::test_ci_invokes_every_unflagged_blocking_hook "
            f"reports this as the ADR-037 D1 coverage gap; it is repeated here because a "
            f"non-vacuity claim about a command that does not exist cannot be made at all."
        )
    if len(invocations) > 1:
        pytest.fail(
            f"{hook_id}: {len(invocations)} workflow invocations of {script}, so no single "
            f"command's behaviour can be attributed to this hook:\n"
            + "\n".join(f"  - {inv.source}: {inv.line}" for inv in invocations)
            + "\nADR-037 D7 requires a failure to resolve to a single validator."
        )
    argv, _ = _resolve_argv(invocations[0])
    return invocations[0], argv


def _run_governed(script_path: Path, argv: list[str], cwd: Path) -> subprocess.CompletedProcess:
    """Run a validator with a given argv from a given working directory."""
    return subprocess.run(
        [sys.executable, str(script_path), *argv],
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )


# ---------------------------------------------------------------------------
# Scope, for the flagless validators CI can narrow without ever going silent
# ---------------------------------------------------------------------------
#
# `test_ci_invokes_every_unflagged_blocking_hook` establishes existence — a
# workflow step invokes the validator at all — and
# `TestUnflaggedValidatorsCatchInjectedViolations` establishes that the
# invocation catches a violation *somewhere* in whatever it scans. Neither
# establishes *how much* it scans. `validate_mapping_purity.py`,
# `validate_mapping_drift.py` and `validate_versionid_purity.py` accept an
# explicit, narrower file list even though `.pre-commit-config.yaml` invokes
# each with `pass_filenames: false` (no file arguments at all): `nargs="*"`
# for the first two, `--path` for the third. A CI step handing one of them a
# single positional file instead of none passes both of the checks above —
# the invocation still exists, and the corpus probe still poisons the one
# file that survived the narrowing, because the probe was written to poison a
# file these validators scan by default. D1 requires coverage "over at least
# the inputs the hook would see" (docs/adr/037-...:34); for a hook invoked
# with no file arguments, that is the validator's own default scope, not
# whatever subset a CI step happens to pass.


def _default_scan_scope(script_basename: str) -> list[str] | None:
    """Return the repo-relative files a flagless file-taking validator scans by default.

    Imported from the validator's own module — via `importlib`, the same
    pattern `_neutrality_denylist_term` uses — rather than transcribed, so a
    changed default file set is picked up with no edit here. Only
    `validate_mapping_purity.py` and `validate_mapping_drift.py`
    (`_DEFAULT_CONTENT_FILES`) and `validate_versionid_purity.py`
    (`_DEFAULT_PATH`) declare one of these two names; the other three D8
    validators self-discover their corpus with no scannable "default file
    list" at all (`validate_all_schemas.py`, `validate_persona_site_build.py`,
    and `validate_neutrality.py`'s self-scanning hook), and this returns None
    for them — there is no narrower argument shape for CI to accidentally pass.
    """
    real_path = PRECOMMIT_VALIDATORS.get(script_basename)
    if not real_path:
        return None
    module_name = f"_{script_basename}_scope_probe"
    spec = importlib.util.spec_from_file_location(module_name, _REPO_ROOT / real_path)
    module = importlib.util.module_from_spec(spec)
    # Registered in sys.modules before exec: validate_neutrality.py declares a
    # `@dataclass`, and dataclass field introspection looks its own module up
    # by name in sys.modules, which raises if the module was never registered
    # there. Popped again once loaded so this probe leaves no lasting entry.
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)
    if hasattr(module, "_DEFAULT_CONTENT_FILES"):
        return sorted(Path(p).resolve().relative_to(_REPO_ROOT).as_posix() for p in module._DEFAULT_CONTENT_FILES)
    if hasattr(module, "_DEFAULT_PATH"):
        return [module._DEFAULT_PATH.as_posix()]
    return None


# hook id -> default scope, for the governed flagless hooks whose validator
# exposes one. Computed once at import time — like UNFLAGGED_BLOCKING_SCRIPTS
# and every other module-level derivation in this section — so a hook
# entering or leaving this set is a property of the config and the
# validator's own source, not of anything written here.
SCOPED_UNFLAGGED_HOOK_IDS = sorted(
    hook_id
    for hook_id in UNFLAGGED_BLOCKING_HOOK_IDS
    if _default_scan_scope(_unflagged_script(hook_id)) is not None
)


def _resolved_scan_scope(hook_id: str) -> list[str] | None:
    """Return the files a governed flagless hook's single CI invocation actually scans.

    None means "the invocation's own default applies" — a bare argv for the
    `nargs="*"` pair, or no `--path` for the versionId validator — which is
    exactly what `_default_scan_scope` names. A non-None result is whatever
    narrower scope the invocation's own argv declares instead.
    """
    _, argv = _governed_ci_argv(hook_id)
    if "--path" in argv:
        index = argv.index("--path")
        return [argv[index + 1]] if index + 1 < len(argv) else []
    positionals = [token for token in argv if not token.startswith("-")]
    return positionals or None


class TestUnflaggedBlockingCoverage:
    """ADR-037 D8: a hook that blocks without a flag is a D1 instance.

    D1's coverage clause quantifies over blocking hooks, not over `--block`
    hooks. `TestStrictnessCoverage` implements it for the flag-bearing half;
    this class implements it for the half that carries no flag, which that
    derivation cannot see at all.

    The shape is the same and for the same reason: it quantifies over the
    pre-commit side, so a validator absent from CI FAILS here rather than
    skipping. A rule ranging over the intersection of the two surfaces passes
    on precisely this gap — which is how these three came to live only on
    contributor machines.
    """

    def test_the_governed_hooks_resolve_to_the_precommit_config(self):
        """
        Given: the hook ids ADR-037's D1 instance table names
        When: each is looked up in .pre-commit-config.yaml
        Then: each resolves to exactly one hook, and at least one of them
              carries no strictness flag

        Two ways this section goes quiet, both silent. The table and the config
        drift apart — a renamed hook id leaves a row naming nothing — and the
        parametrizations below then quantify over a smaller set with no failure
        anywhere. And if no governed hook is flagless, every case below is
        collected from an empty set, which pytest reports as success.
        """
        assert ADR_GOVERNED_HOOK_IDS, (
            f"Parsed no hook ids out of {_ADR_037_PATH.name}. The D1 instance table is "
            "where this section's governed set comes from; an empty parse makes every "
            "assertion below quantify over nothing."
        )

        unresolved = {
            hook_id: len(PRECOMMIT_HOOKS_BY_ID.get(hook_id, []))
            for hook_id in ADR_GOVERNED_HOOK_IDS
            if len(PRECOMMIT_HOOKS_BY_ID.get(hook_id, [])) != 1
        }
        assert not unresolved, (
            f"ADR-037's D1 instance table names hook ids that do not resolve to exactly "
            f"one hook in {_PRECOMMIT_CONFIG.name}: {unresolved}.\n"
            "The table is the register of what this decision governs. An id it names and "
            "the config does not declare governs nothing, and the row reads as coverage."
        )

        assert UNFLAGGED_BLOCKING_HOOK_IDS, (
            "No governed hook passes zero strictness flags, so this section's "
            "parametrizations collect no cases. D8 exists because three of them do; "
            "either they gained a flag — in which case sections 2 and 5 now govern them "
            "— or `_hook_strictness` stopped reading hook entries."
        )

    @pytest.mark.parametrize("hook_id", UNFLAGGED_BLOCKING_HOOK_IDS)
    def test_ci_invokes_every_unflagged_blocking_hook(self, hook_id):
        """
        Given: a pre-commit hook that blocks a commit with no strictness flag to
               promote anything — a violation exits it non-zero unconditionally
        When: every `run:` step in every workflow is searched for an invocation
              of that validator
        Then: at least one exists

        ADR-037 D1 part 1, applied to the half of the rule `--block` cannot
        reach. These validators have no laxer mode to fall back to: CI either
        runs them or it does not check, and today it does not, so the whole
        check exists only for contributors who installed the hooks.

        Strictness needs no separate assertion while these carry no flag —
        "at least the same strictness" as a flagless hook is satisfied by
        invoking the validator. If one later grows a warn-only tier and a flag,
        `BLOCK_VALIDATORS` picks it up from the config and
        TestStrictnessMonotonicity governs the CI invocation from that point,
        which is what D8's Strictness paragraph says happens without an
        amendment.

        Attributed by hook (`_unflagged_ci_invocations`), not by script alone:
        `validate-neutrality` shares `validate_neutrality.py` with this hook's
        `validate-neutrality-policy` sibling, and a script-only check would let
        that sibling's own CI invocation (once it exists) satisfy this hook's
        coverage claim without this hook itself ever being invoked.
        """
        script = _unflagged_script(hook_id)
        invocations = _unflagged_ci_invocations(hook_id)
        assert invocations, (
            f"{script} is invoked by the {hook_id!r} pre-commit hook, which blocks a "
            f"commit on any violation, and by no workflow under {_WORKFLOW_DIR} attributably "
            f"to this hook. No workflow runs `pre-commit` either, so the check runs only "
            f"where the hooks were installed and the merge decision depends on a "
            f"contributor's local state.\nADR-037 D1 part 1 quantifies over blocking "
            f"hooks, not over flagged ones; D8 records these as instances of that rule "
            f"rather than exceptions to it."
        )

    def test_scoped_hooks_are_found(self):
        """
        Given: the governed flagless hooks
        When: each is checked for a validator-declared default scope
        Then: at least one is found

        Non-vacuity guard for the parametrized test below. All three of
        `validate_mapping_purity.py`, `validate_mapping_drift.py` and
        `validate_versionid_purity.py` declare one today
        (`SCOPED_UNFLAGGED_HOOK_IDS`); if none did, the scope test below would
        collect no cases and pytest would report that as success.
        """
        assert SCOPED_UNFLAGGED_HOOK_IDS, (
            "No governed flagless hook's validator exposes a default file scope "
            "(`_DEFAULT_CONTENT_FILES` or `_DEFAULT_PATH`), so "
            "test_the_ci_invocation_scans_the_hooks_whole_default_scope collects no "
            "cases and its assertion is vacuous."
        )

    @pytest.mark.parametrize("hook_id", SCOPED_UNFLAGGED_HOOK_IDS)
    def test_the_ci_invocation_scans_the_hooks_whole_default_scope(self, hook_id):
        """
        Given: a governed flagless hook whose validator, when invoked bare
               (`.pre-commit-config.yaml`'s own `pass_filenames: false`),
               falls back to a fixed default file scope of its own
        When: the CI invocation's own resolved argv is compared to that
              default
        Then: the CI invocation scans the validator's whole default scope —
              either by passing no positional/`--path` argument at all, or by
              passing exactly the same files the default would

        `test_ci_invokes_every_unflagged_blocking_hook` establishes the
        invocation exists; `TestUnflaggedValidatorsCatchInjectedViolations`
        establishes it catches a violation somewhere. Neither establishes how
        much of the corpus it reads, and that gap survives mutation M-O: handing
        `validate_mapping_purity.py` `risk-map/yaml/risks.yaml` as a single
        positional argument instead of none is invisible to both — the
        invocation still exists, and this module's own poison for that
        validator (`_write_mapping_purity_corpus`) lands under `risks`, which
        is exactly the one file a "keep only risks.yaml" narrowing leaves in
        scope. Reading the probe's own target to choose a file that survives
        the narrowing is a lookup against this module's source, not luck.

        D1 requires coverage "over at least the inputs the hook would see"
        (docs/adr/037-...:34); for a hook pre-commit invokes with
        `pass_filenames: false`, that is always the validator's own default —
        never a subset a particular CI step happens to name.
        """
        script = _unflagged_script(hook_id)
        expected = _default_scan_scope(script)
        if expected is None:
            pytest.fail(
                f"{hook_id}: no default scope was derivable for {script}; "
                "test_scoped_hooks_are_found's non-vacuity guard should have excluded "
                "this hook from SCOPED_UNFLAGGED_HOOK_IDS."
            )
        scanned = _resolved_scan_scope(hook_id)
        actual = expected if scanned is None else sorted(scanned)
        assert actual == expected, (
            f"{hook_id}: the CI invocation of {script} scans {actual}, narrower than "
            f"the validator's own default scope {expected}. `.pre-commit-config.yaml` "
            f"invokes this hook with `pass_filenames: false` — no file arguments at "
            f"all — so its own default scope is `.pre-commit-config.yaml`'s idea of "
            f"'the inputs the hook would see' (ADR-037 D1). A CI step naming an "
            f"explicit, narrower file list checks less than the hook it stands in for, "
            f"and the coverage tests elsewhere in this module cannot see the gap: the "
            f"invocation still exists, and the corpus probe still finds its own "
            f"poison if the probe's target happens to survive the narrowing."
        )


class TestUnflaggedValidatorsRunInPlace:
    """ADR-037 D7b, applied to the flagless six (D8).

    Section 4 states the same rule as a prohibition — no workflow may copy a
    `precommit/` validator or invoke one from a path other than its real one —
    and a prohibition is satisfied by a validator no workflow mentions. That is
    the state these six are in today, so section 4 passes on them while saying
    nothing.

    This class states the positive form D8 requires: the invocation exists, and
    it runs the script where it lives. The two are one assertion because for
    these validators the path is not a detail of style. Three of the six —
    `validate_mapping_purity.py`, `validate_mapping_drift.py`,
    `validate_persona_site_build.py` — locate their corpus from
    `Path(__file__)`; flattening the layout moves those three's corpus
    resolution silently, on top of the `sys.path` breakage section 4's own
    docstring already covers for every validator in the directory.
    """

    @pytest.mark.parametrize("hook_id", UNFLAGGED_BLOCKING_HOOK_IDS)
    def test_each_unflagged_blocking_validator_is_invoked_in_place(self, hook_id):
        """
        Given: a governed flagless hook's validator
        When: every workflow invocation and every file-relocating command is
              examined
        Then: at least one invocation exists, each names the validator's real
              path, and no command relocates it

        The copy scan is `WORKFLOW_COPY_COMMANDS`, the same derivation section 4
        uses, so a copy written through shell variables is seen as well as a
        literal one — `test_copy_detector_flags_variable_built_copy_to_root`
        establishes that.
        """
        script = _unflagged_script(hook_id)
        real_path = PRECOMMIT_VALIDATORS.get(script)
        assert real_path, (
            f"{script} is not among the validators derived from "
            f"{_PRECOMMIT_CONFIG.name} as living under {_PRECOMMIT_DIR_FRAGMENT}, so "
            "section 4's copy and path prohibitions do not reach it either."
        )

        invocations = _ci_invocations_of(script)
        assert invocations, (
            f"No workflow invokes {script} (hook {hook_id!r}), so ADR-037 D7b's "
            f"in-place requirement has no call site to hold. The prohibition in "
            f"TestPrecommitValidatorsRunInPlace passes on this validator for the same "
            f"reason it passes on any validator CI never runs — which is why D8 states "
            f"the requirement positively."
        )

        misplaced = [inv for inv in invocations if inv.path != real_path]
        assert not misplaced, (
            f"ADR-037 D7b requires {script} to be invoked at {real_path!r}:\n"
            + "\n".join(f"  - {inv.source}: invoked as {inv.path!r}\n      {inv.line}" for inv in misplaced)
            + "\nThis validator resolves its corpus, its framework oracles and its "
            "`sys.path` entry from its own location. A different path is a different "
            "corpus, and for the two that never consult the working directory it is a "
            "different corpus reported as success."
        )

        relocations = [copy for copy in WORKFLOW_COPY_COMMANDS if copy.source_path.endswith(script)]
        assert not relocations, (
            f"ADR-037 D7b prohibits relocating {script}:\n"
            + "\n".join(f"  - {c.source}: {c.line}  ({c.source_path} -> {c.destination})" for c in relocations)
            + "\nCopying it to the repository root moves the root its own path derivation "
            "computes four levels up, which lands outside the checkout."
        )


class TestUnflaggedValidatorsCatchInjectedViolations:
    """ADR-037 D7c, applied to the flagless three (D8).

    A green job is evidence of nothing until the red case has been observed.
    For these three the failure mode is not a missing flag — there is none to
    miss — but a command that runs against a corpus other than the one under
    test and reports success.

    Each case therefore runs the argument list the workflow passes, from the
    mirror's own copy of the validator, against a mirror carrying exactly one
    injected violation in the validator's own remit. The clean mirror is
    asserted first with the same arguments: without it, a validator that failed
    on everything would satisfy the poisoned assertion for the wrong reason.
    """

    def test_every_unflagged_blocking_hook_has_a_corpus_probe(self):
        """
        Given: the governed flagless hooks
        When: compared against the probe registry
        Then: every one has a probe, and no probe is orphaned

        The derive-don't-enumerate rule sections 5 and 6 apply, applied here. A
        fourth flagless blocking hook entering ADR-037's instance table fails
        this until someone can express a violation in its inputs, rather than
        being quietly excluded from the only assertion that observes behaviour.
        """
        scripts = {_unflagged_script(hook_id) for hook_id in UNFLAGGED_BLOCKING_HOOK_IDS}
        unprobed = sorted(name for name in scripts if name not in UNFLAGGED_PROBES)
        assert not unprobed, (
            f"No corpus probe for {unprobed}. Without one, a CI invocation of that "
            "validator can be checked for existence but not for effect, and an "
            "invocation that inspects the wrong tree looks identical to a correct one."
        )
        stale = sorted(set(UNFLAGGED_PROBES) - scripts)
        assert not stale, (
            f"Probes exist for validators ADR-037 no longer governs as flagless blocking "
            f"hooks: {stale}. Either the hook gained a strictness flag — in which case "
            "sections 5 and 6 govern it — or the probe is dead."
        )

    def test_track_mirror_stages_paths_added_after_the_initial_build(self, tmp_path):
        """
        Given: a mirror built by `_mirror_checkout`, then a new file written
               into it afterward — the same shape as a probe's `write_corpus`
               adding a path `_mirror_checkout` never laid down
        When: `_track_mirror` runs
        Then: `git ls-files` lists the newly added path

        Direct proof of `_track_mirror`'s own contract, independent of any one
        validator's behaviour — see its corrected docstring for why no probe
        registered today makes this load-bearing. Reproduces mutation G4:
        moving `git add -A` into `_mirror_checkout` (so staging happens once,
        before any probe's `write_corpus` call) and making `_track_mirror` a
        no-op leaves every case in `test_the_ci_command_fails_on_an_injected_
        violation` passing, because none of today's probes both reads the git
        index and depends on a path `write_corpus` adds. The next probe that
        does would have `_track_mirror` silently do nothing for it; this test
        pins the contract directly so that gap cannot reopen unnoticed.
        """
        mirror = _mirror_checkout(tmp_path / "mirror")
        new_file = mirror / "risk-map" / "yaml" / "track-mirror-contract-probe.yaml"
        new_file.parent.mkdir(parents=True, exist_ok=True)
        new_file.write_text("probe: true\n", encoding="utf-8")

        _track_mirror(mirror)

        tracked = subprocess.run(
            ["git", "ls-files"], cwd=str(mirror), capture_output=True, text=True, check=True
        ).stdout
        assert "risk-map/yaml/track-mirror-contract-probe.yaml" in tracked.splitlines(), (
            "_track_mirror did not stage a file written after _mirror_checkout built the "
            "base tree. A probe's write_corpus() call adds paths exactly this way, and a "
            "future index-reading validator would silently not see one left untracked."
        )

    @pytest.mark.parametrize("hook_id", UNFLAGGED_BLOCKING_HOOK_IDS)
    def test_the_ci_command_fails_on_an_injected_violation(self, hook_id, tmp_path):
        """
        Given: the argument list a workflow passes to a governed flagless
               validator, and a checkout-shaped mirror carrying one injected
               violation
        When: the mirror's own copy of the validator runs with those arguments
        Then: it exits non-zero and names the violation, having exited 0 on the
              clean mirror with the same arguments

        Running the mirror's copy is what makes the poison visible to a
        validator that locates its corpus from its own path. It is not a
        copy-to-root arrangement and does not endorse one: the mirror preserves
        the repo-relative layout, which is what a checkout is and what D7b
        requires be preserved. `test_a_poisoned_corpus_can_go_unread` runs the
        other arm — the repository's copy against the same mirror — and observes
        what happens when the layout is right and the tree is not.

        The marker assertion is what separates "the command failed" from "the
        command found this". Both mapping validators exit 1 on a missing content
        file and on an unreadable oracle, neither of which is a finding about
        the corpus.
        """
        script = _unflagged_script(hook_id)
        probe = UNFLAGGED_PROBES.get(script)
        if probe is None:
            pytest.fail(
                f"No corpus probe for {script}; "
                "test_every_unflagged_blocking_hook_has_a_corpus_probe explains the gap."
            )
        invocation, argv = _governed_ci_argv(hook_id)

        clean = _mirror_checkout(tmp_path / "clean")
        probe.write_corpus(clean, False)
        _track_mirror(clean)
        tracked_in_clean = subprocess.run(
            ["git", "ls-files"], cwd=str(clean), capture_output=True, text=True, check=True
        ).stdout
        assert tracked_in_clean.strip(), (
            f"{clean} has an empty git index after _track_mirror. Non-vacuity guard: "
            "the precondition check below (`clean_result.returncode == 0`) has to mean "
            "'a real corpus validated clean', not 'an index-reading validator found "
            "nothing tracked to inspect' — the exact shape validate_all_schemas.py's "
            "_find_pairs() collapses to over an untracked mirror. Reproduces mutation "
            "G1 (deleting this _track_mirror(clean) call): without it, this mirror's "
            "git index is empty (a fresh `git init` stages nothing on its own), so "
            "_find_pairs() would see zero tracked schema/yaml pairs and main() would "
            "return 0 having inspected nothing, which the returncode-only check below "
            "cannot tell apart from a genuine clean pass."
        )
        clean_result = _run_governed(clean / _MIRRORED_SOURCE_DIR / script, argv, clean)
        assert clean_result.returncode == 0, (
            f"Harness precondition failed: {invocation.source} arguments {argv} exit "
            f"{clean_result.returncode} on a mirror with no injected violation, so the "
            f"poisoned result below would prove nothing.\n"
            f"stdout: {clean_result.stdout}\nstderr: {clean_result.stderr}"
        )

        poisoned = _mirror_checkout(tmp_path / "poisoned")
        probe.write_corpus(poisoned, True)
        _track_mirror(poisoned)
        poisoned_result = _run_governed(poisoned / _MIRRORED_SOURCE_DIR / script, argv, poisoned)
        output = poisoned_result.stdout + poisoned_result.stderr
        assert probe.marker in output, (
            f"{invocation.source} arguments {argv} never named {probe.marker!r} on a "
            f"corpus carrying a {probe.rule} violation, so the check did not reach it. "
            f"The invocation is reachable and vacuous, which is worse than laxity "
            f"because it reports success.\n"
            f"stdout: {poisoned_result.stdout}\nstderr: {poisoned_result.stderr}"
        )
        assert poisoned_result.returncode != 0, (
            f"{invocation.source} arguments {argv} reported a {probe.rule} violation and "
            f"exited 0, so the pull request merges with the violation printed in the log. "
            f"The {hook_id!r} hook blocks the same content locally.\n"
            f"stdout: {poisoned_result.stdout}\nstderr: {poisoned_result.stderr}"
        )


class TestUnflaggedValidatorsValidateTheCheckoutUnderTest:
    """The corpus these validators judge is not named on their command line.

    Sections 6 and 7 establish for the file-argument validators that the inputs
    are derived, complete and read. These three take no file list: each locates
    its own corpus, and *how* differs between siblings that sit in the same
    directory and are wired by adjacent lines of the same config. One resolves
    from the working directory; the others from their own source path.

    Only the first of those fails when it is pointed somewhere unexpected. A
    validator that resolves from its own path validates the tree its source sits
    in, whatever the job intended, and exits 0 — so a wrongly wired job is green
    and its log looks like a clean corpus. Nothing on the command line, in the
    file list, or in the flags differs between the two cases.

    The consequence is that the step's execution context is load-bearing here.
    `_gate_steps` now recognizes one of these validator's invocations as a gate
    step too (D8), so `TestGateStepsRunFromRepositoryRoot` reaches it — but only
    with the generic root-working-directory and aborting-shell guards it states
    for every gate step. What that class cannot say is which hook_id is at
    fault or that the working directory is what a *cwd-resolving* validator
    among these depends on to fail loudly at all; the tests below say both.
    """

    @pytest.mark.parametrize("hook_id", UNFLAGGED_BLOCKING_HOOK_IDS)
    def test_a_poisoned_corpus_can_go_unread(self, hook_id, tmp_path):
        """
        Given: one mirror carrying an injected violation, and the validator run
               two ways against it — the mirror's own copy, and the
               repository's copy with the mirror as its working directory
        When: both runs use the same arguments
        Then: the mirror's copy names the violation; the repository's copy
              either names it too, or exits 0 without naming it

        CHARACTERIZATION, and the reason the next test exists. It asserts no
        wiring and passes before the CI invocations land — its subject is the
        validators' own behaviour, which is what makes the working-directory
        rule below load-bearing rather than stylistic.

        The disjunction is the finding, stated so that it cannot be satisfied by
        accident. A validator resolving its corpus from the working directory
        reports the violation; one resolving it from its own path reports
        nothing and succeeds, having read a different tree. What is prohibited
        is the third outcome — a non-zero exit that does not name the violation
        — because that is a harness fault: it would mean the poisoned run failed
        for a reason unrelated to the poison, and the first assertion's
        companion in test_the_ci_command_fails_on_an_injected_violation would be
        reading the same noise.

        If this ever fails because every validator's second arm names the
        violation, the asymmetry has been designed out — revisit the rule below,
        but keep it, since a step at the repository root is what makes the
        cwd-resolving one work at all.
        """
        script = _unflagged_script(hook_id)
        probe = UNFLAGGED_PROBES.get(script)
        if probe is None:
            pytest.fail(
                f"No corpus probe for {script}; "
                "test_every_unflagged_blocking_hook_has_a_corpus_probe explains the gap."
            )

        mirror = _mirror_checkout(tmp_path / "mirror")
        probe.write_corpus(mirror, True)
        _track_mirror(mirror)

        inside = _run_governed(mirror / _MIRRORED_SOURCE_DIR / script, [], mirror)
        inside_output = inside.stdout + inside.stderr
        assert inside.returncode != 0 and probe.marker in inside_output, (
            f"Harness precondition failed: run from inside the mirror, {script} did not "
            f"report the injected {probe.rule} violation, so this mirror establishes "
            f"nothing about where the validator looks.\n"
            f"exit: {inside.returncode}\nstdout: {inside.stdout}\nstderr: {inside.stderr}"
        )

        outside = _run_governed(_REPO_ROOT / _MIRRORED_SOURCE_DIR / script, [], mirror)
        outside_output = outside.stdout + outside.stderr
        assert probe.marker in outside_output or outside.returncode == 0, (
            f"{script}, run from the repository against the mirror as its working "
            f"directory, exited {outside.returncode} without naming {probe.marker!r}. "
            f"That is neither of the two outcomes this characterization models — it "
            f"found the violation, or it read a different tree and succeeded — so the "
            f"probe is measuring something other than which corpus was read, and the "
            f"non-vacuity assertions that share these fixtures are reading the same "
            f"noise.\nstdout: {outside.stdout}\nstderr: {outside.stderr}"
        )

    @pytest.mark.parametrize("hook_id", UNFLAGGED_BLOCKING_HOOK_IDS)
    def test_the_ci_step_runs_at_the_repository_root(self, hook_id):
        """
        Given: the workflow step invoking a governed flagless validator
        When: its effective `working-directory:` and its shell body are examined
        Then: the step runs at the repository root and does not change directory

        The working directory is the only thing that decides which tree one of
        these validators reads, and it is the thing that decides nothing at all
        for the other two — which is exactly why it has to be pinned rather than
        left to GitHub's default. Move it and the outcomes diverge: the
        cwd-resolving validator fails loudly on a tree that has no
        `risk-map/yaml/`, and the two that resolve from their own path go on
        validating the checkout while the job's other steps operate somewhere
        else. One of those is a confusing red; the other is a green job that
        never looked at what the job was about.

        Neither is visible to a command-line scan. `TestGateStepsRunFromRepositoryRoot`
        does now reach the step this test examines — `_gate_steps` recognizes a
        flagless validator's invocation as a gate step (D8) — but only as one
        entry among every gate step's; a violation there reports "a gate step",
        not which hook_id it was or which of the two failure modes above
        applies. This test exists to say both.
        """
        script = _unflagged_script(hook_id)
        steps = _steps_invoking(script)
        assert steps, (
            f"No workflow step invokes {script} (hook {hook_id!r}), so there is no "
            f"execution context to pin. Until one exists, the corpus this validator "
            f"judges in CI is not the repository's — it is nothing at all, because the "
            f"validator does not run. ADR-037 D1 requires the invocation; D8 names this "
            f"hook as an instance."
        )

        relocated = [
            step
            for step in steps
            if step.working_directory is not None
            and step.working_directory.strip() not in _ROOT_WORKING_DIRECTORIES
        ]
        assert not relocated, (
            f"{script} is invoked from a step that declares a non-root working "
            f"directory:\n"
            + "\n".join(f"  - {step.source}: working-directory: {step.working_directory!r}" for step in relocated)
            + "\nThe corpus is resolved from the working directory or from the script's "
            "own path, and the two disagree once they are not the same tree."
        )

        wandering = [(step.source, line) for step in steps for line in _changes_directory(step)]
        assert not wandering, (
            f"{script} is invoked from a step that changes directory:\n"
            + "\n".join(f"  - {source}: {line}" for source, line in wandering)
            + "\nSame hazard as a `working-directory:` key, spelled where a scan of step "
            "keys does not look."
        )


# ===========================================================================
# 11. This module's own inventory
# ===========================================================================


class TestModuleInventory:
    """The suite's description of itself is an assertion, not prose.

    Deleting an entire test class from this module produced a smaller run and
    zero failures: the count in the summary comment below is a comment, and no
    other test quantifies over what this module contains. That matters more here
    than in most suites, because several classes exist to be the only thing that
    would notice a particular edit — losing one is losing the guard, silently.

    Class *names* are pinned, not case counts. Counts are derived from
    `.pre-commit-config.yaml` and from the workflows, and pinning them would
    fight the derive-don't-enumerate rule the rest of the module is built on: a
    fourth `--block` hook should extend the parametrizations, not fail this.
    What is pinned alongside the names is that each class collects at least one
    case, which is the other way a class goes quiet — a parametrization whose
    derived set went empty.
    """

    EXPECTED_CLASSES = frozenset(
        {
            "TestParserFidelity",
            "TestStrictnessCoverage",
            "TestStrictnessMonotonicity",
            "TestGraphEmissionExclusion",
            "TestPrecommitValidatorsRunInPlace",
            "TestBlockFlagChangesBehaviour",
            "TestCIInvocationCatchesViolation",
            "TestCIFileListsAreDerivedAndComplete",
            "TestThirdPartyBlockingHookCoverage",
            "TestLocalImportClosureResolvesAllImportForms",
            "TestGateStepsRunFromRepositoryRoot",
            "TestWorkflowTriggerCoverage",
            "TestGateStepFailsTheJob",
            "TestAggregateGateReflectsEveryGateJob",
            "TestUnflaggedBlockingCoverage",
            "TestUnflaggedValidatorsRunInPlace",
            "TestUnflaggedValidatorsCatchInjectedViolations",
            "TestUnflaggedValidatorsValidateTheCheckoutUnderTest",
            "TestModuleInventory",
        }
    )

    def test_module_collects_every_class_it_declares(self):
        """
        Given: this module, collected by pytest
        When: the classes that produced collected cases are compared to
              EXPECTED_CLASSES
        Then: the two sets are equal

        Fails on a deleted class, on a class renamed without updating the set,
        and on a new class added without declaring it — the last being how the
        set stays honest rather than becoming a stale copy of a past state.
        """
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "--no-header",
                "-p",
                "no:cacheprovider",
                str(Path(__file__).resolve()),
            ],
            capture_output=True,
            text=True,
            cwd=str(_REPO_ROOT),
        )
        assert result.returncode == 0, (
            f"Collecting this module failed ({result.returncode}); the inventory cannot "
            f"be compared.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

        # `-q` node ids are `path::Class::test[param]`. Lines with fewer than
        # three components are module-level functions or summary text.
        collected: dict[str, int] = {}
        for line in result.stdout.splitlines():
            parts = line.strip().split("::")
            if len(parts) < 3 or not parts[0].endswith(".py"):
                continue
            collected[parts[1]] = collected.get(parts[1], 0) + 1

        assert set(collected) == self.EXPECTED_CLASSES, (
            "This module's declared inventory does not match what it collects.\n"
            f"  missing (declared, not collected): {sorted(self.EXPECTED_CLASSES - set(collected))}\n"
            f"  undeclared (collected, not declared): {sorted(set(collected) - self.EXPECTED_CLASSES)}\n"
            "A deleted class produces a smaller run and no failure; several classes here "
            "are the only thing that would notice a particular edit."
        )

        empty = sorted(name for name, count in collected.items() if count == 0)
        assert not empty, (
            f"These classes collected no cases: {empty}. A parametrization over a "
            "derived set that went empty is reported by pytest as success."
        )


# ===========================================================================
# Test Summary
# ===========================================================================
# Class membership is asserted by TestModuleInventory, not by this comment.
# Case counts are derived from `.pre-commit-config.yaml` and the workflows and
# move with them by design; run
# `pytest --collect-only -q scripts/hooks/tests/test_ci_block_parity.py` for the
# current figure rather than trusting a number written here.
#
# TestParserFidelity (7)
#   — pre-commit derivation finds strictness-flagged validators; workflow
#     derivation finds Python invocations; the workflow scan covers every file
#     GitHub would run out of .github/workflows/ (both `.yml` and `.yaml`) and
#     the step parse reaches each of them; parser resolves the variable-built
#     graph invocation; `cp` steps are not read as invocations; pre-commit
#     script basenames are unambiguous (the D1 join key); graph-emission flag
#     names are real options of validate_riskmap.py.
#     PASS — they exist so the D1/D4 failures mean something and so the D3
#     pass is not a blind one. The scan test is what stops one character —
#     `gate.yaml` instead of `gate.yml` — from exempting a workflow from every
#     prohibition in this module at once.
#
# TestStrictnessCoverage (5, parametrized over the derived set)
#   — D1 part 1: every validator invoked with a strictness flag by
#     .pre-commit-config.yaml has a workflow invocation carrying those flags.
#
# TestStrictnessMonotonicity (5, parametrized over the derived set)
#   — D1 part 2: for validators on both surfaces, CI strictness is a superset
#     of hook strictness.
#
# TestGraphEmissionExclusion (3)
#   — no live workflow invocation pairs a strictness flag with graph emission;
#     detector catches a literal pairing; detector catches a variable-built
#     pairing.
#     PASS — ADR-037 D3 codifies existing practice rather than changing it.
#     The two synthetic tests are what make the live-workflow pass non-vacuous.
#
# TestPrecommitValidatorsRunInPlace (6)
#   — D7b: no workflow relocates a scripts/hooks/precommit/ validator; every
#     workflow invocation of one uses its real path; detectors catch a literal
#     copy, a variable-built copy, and a bare-basename invocation; and a
#     relocated copy is observed going vacuous (exit 0, empty stderr) on the
#     same poisoned corpus the in-place run fails on (exit 1, diagnostic).
#
# TestBlockFlagChangesBehaviour (1 + 5 + 5)
#   — every strictness-flagged validator has a probe; --block changes the exit
#     code on an injected warn-level violation and the warn output names it;
#     a clean corpus exits 0 both ways.
#     PASS — the toggles already work. This tier is the precondition, not the
#     deliverable.
#
# TestCIInvocationCatchesViolation (5 + 5, parametrized over the derived set)
#   — CI invocations carry the enabling arguments (`--force`) without which the
#     validator skips the corpus and exits 0. A validator with no enabling
#     arguments is asserted to be one whose enabling input is its file list,
#     rather than skipped: "nothing enables it" and "its input is asserted
#     elsewhere" are different claims and only the second is true here.
#
#   — the argument list a workflow passes to each strictness-flagged validator
#     exits non-zero on a corpus carrying an injected warn-level violation,
#     having first exited 0 on the clean equivalent.
#     Note the scope: this tier substitutes the probe's own positionals, so it
#     establishes that `--block` reaches the validator and not that the file
#     list does. Section 6 is where the file list is established.
#
# TestCIFileListsAreDerivedAndComplete (2 + 5 x 4 governed hooks + 1 = 23)
#   — D7a: the governed hook set is derived and non-empty and every member has
#     a corpus writer; each CI invocation takes its file list from a command
#     rather than from transcribed paths; that command is a single simple
#     command running a script that reads the pre-commit config and names this
#     hook's own id; exactly one CI invocation belongs to each governed hook,
#     once a bare invocation belonging to a self-scanning sibling sharing its
#     script is excused (proven bounded by a synthetic case, not just
#     asserted); that command's whole output equals the hook's own file set;
#     and the real validator, run with the real argument list once per
#     resolved file, fails on each of them in turn.
#     "From a command" alone was satisfied by `FILES=$(cat prose-files.txt)` —
#     a transcription with a substitution wrapped round it — and by
#     `$(resolver || true)`, which discards the resolver's exit-1-on-empty.
#     The uniqueness assertion is what notices a second invocation of the same
#     validator: the resolution used to take candidates[0], so a duplicate ran
#     in CI unexamined and a second real hook produced a confident failure
#     against the wrong command.
#     The governed set is no longer only D7's flagged three: `validate-neutrality`
#     carries no strictness flag (ADR-037 D8) but declares `pass_filenames: true`
#     like they do, so D7a reaches it too and it is the fourth member, with its
#     own corpus writer (a probe drawn from ADR-033's own vendor/product
#     denylist, `_write_neutrality_file`). It shares `validate_neutrality.py`
#     with the self-scanning `validate-neutrality-policy`, whose own CI
#     invocation is correctly bare — the uniqueness assertion above would
#     misread that bare invocation as unattributed without the exception.
#
# TestThirdPartyBlockingHookCoverage (6)
#   — D1 applied to hooks pre-commit declares from a third-party repo rather
#     than a local script: every check-jsonschema (schema, yaml) pair has a CI
#     counterpart via validate_all_schemas.py's own pairing; check-metaschema
#     has a CI counterpart at all; that counterpart is found structurally
#     (`_third_party_invocations`, matching THIRD_PARTY_BLOCKING_COMMANDS) and
#     not by a raw substring scan, so a flag left behind only in a comment
#     while the real command is replaced does not read as coverage; its file
#     list is built from a command that resolves to check-metaschema's own
#     `files:` pattern exactly, not transcribed; and it carries no
#     `continue-on-error:` or `if:` at either the step or job level. The last
#     three guard a step outside GATE_STEPS — `_gate_steps` keys on
#     STRICTNESS_FLAGS and UNFLAGGED_BLOCKING_SCRIPTS, neither of which a bare
#     `check-jsonschema --check-metaschema` invocation carries — so
#     TestGateStepFailsTheJob's structural guards never reach it.
#
# TestGateStepsRunFromRepositoryRoot (7)
#   — GATE_STEPS is the union of steps invoking a `--block`-flagged validator
#     and steps invoking one of ADR-037 D8's flagless governed validators
#     (UNFLAGGED_BLOCKING_SCRIPTS), so both guards below reach either half: no
#     gate step declares a non-root working-directory or runs `cd`; every gate
#     step's shell exits on error and none turns it back off with `set +e`;
#     plus two fidelity checks scoped to the flagged half — the derived file
#     list really does change with the working directory, and `bash -e` really
#     does abort on a failing command substitution (a platform assertion,
#     flagged as such in place) — and a non-vacuity guard for each half of the
#     union.
#     The prohibitions PASS today for the flagged five because GitHub's
#     defaults supply both properties. The flagless half's non-vacuity guard is
#     RED as committed: GATE_STEPS contains none of D8's validators yet, which
#     TestUnflaggedBlockingCoverage records from the pre-commit side.
#
# TestWorkflowTriggerCoverage (2 + 1 + 1 + 1 + 2 + 1 + 1 + 3)
#   — a gate workflow triggers on its own definition, on every script its steps
#     execute or copy into place, and on the pre-commit config those scripts
#     read; every executed script resolves to exactly one tracked file, so no
#     trigger requirement is dropped in silence; the pytest-workflow set is
#     non-empty; and the workflow running the suite triggers on the files this
#     module asserts over.
#     These are about which pull requests the gate runs on at all, which no
#     other test in this module can observe. `paths-ignore` is modelled
#     alongside `paths`, because a workflow switching spelling would otherwise
#     read as "runs unconditionally" and pass every case vacuously.
#     A prior gap in the same family: every one of the above assumes the gate
#     workflow *runs* on a pull request, which none of them checks — they
#     reason about `paths:` filters, and an event with no filter (because it
#     has no event at all, `pull_request:` deleted wholesale) contributes
#     nothing to look at. Three more tests close that: a gate or pytest
#     workflow declares a `pull_request` trigger at all; at least one of them
#     has a `push.branches` filter to compare against (non-vacuity guard); and
#     a declared `pull_request.branches` filter is not narrower than the
#     workflow's own `push.branches` — `branches: [nonexistent-branch]`
#     satisfies "a filter exists" while covering nothing.
#
# TestLocalImportClosureResolvesAllImportForms (4)
#   — the import-closure resolver `_governed_hook_input_paths`'s sibling half
#     (`_executed_script_import_closure`) depends on has to follow every import
#     shape a validator can use, not only the one today's validators happen to
#     use. Isolated from the real repository tree via monkeypatched
#     `_REPO_ROOT`/`_HOOKS_DIR`/`_IMPORT_ROOTS`/`TRACKED_FILE_SET`: the
#     package-import form (`from precommit import _submodule`, where the
#     submodule name lives in `node.names` rather than `node.module`), a
#     relative import naming a module (`from ._submodule import x`), a bare
#     relative package import (`from . import _submodule`), and a dynamic
#     import (`importlib.import_module(...)`) failing loud rather than
#     resolving to an incomplete closure silently. The first is the realistic
#     path a coverage gap reopens through: a *new* helper first imported in
#     package form never acquires a `paths:` requirement at all, no rewrite or
#     deletion required.
#
# TestGateStepFailsTheJob (5 non-parametrized + 6 x 12 gate steps = 77; the
# file-list-resolver case skips for the steps with no substitution to fail)
#   — the step's own exit code, which nothing else here models. Each gate step's
#     `run:` body is executed verbatim under `bash -e` with the interpreter
#     stubbed: it exits 0 when the stub succeeds (the control), non-zero when
#     the validator fails, and non-zero when the file-list resolver fails.
#     Structurally, the validator command — located by a strictness flag or,
#     for D8's flagless validators, by script basename — is not `||`-guarded,
#     and no gate step or its job declares `continue-on-error:` or a
#     conditional `if:`. The two steps with no file-list substitution skip the
#     resolver case; their validator case covers them.
#     Two of the three non-parametrized tests are synthetic, non-vacuous proof
#     for the flagless half neither GATE_STEPS nor the parametrized cases can
#     yet exercise (no workflow invokes a D8 validator): the stub correctly
#     answers as the validator for a flagless script with no flag on the line,
#     and the `||`-guard detector catches one guarded with no flag either. Both
#     PASS today — they test the detection logic directly, not GATE_STEPS'
#     current (flagged-only) content.
#     This is the section that separates "the validator found it" from "the job
#     failed". Four one-line edits reach ADR-037 D7's rejected warn-only soak
#     with every other assertion in this module still green.
#     Several more non-parametrized tests guard a shape none of the above can
#     see: a step that branches on repository state (`[ -d risk-map ]`,
#     `[ -s risk-map/yaml/risks.yaml ]`, or the keyword-free `[ ... ] && ...
#     || ...` form) *ahead* of its own validator. `_run_step_body`'s sandbox is
#     populated with the real tracked corpus (`_populate_checkout_shaped_
#     sandbox`), content and permissions included, so any single-letter
#     `test`/`[` operator resolves the way it would in CI rather than against
#     an empty or placeholder file — the mechanism-level fix, since it is
#     blind to no operator or shape the way a text pattern is. The structural
#     detector (`_repository_state_precedes_validator`) is the second,
#     human-readable layer: harness-fidelity tests prove it and the sandbox
#     both expose a bypass on synthetic bodies (one per operator family, plus
#     the chained no-keyword form), the parametrized test over GATE_STEPS
#     proves no real gate step is shaped that way, and each has its own
#     synthetic non-vacuity proof alongside it. Before 021cc3a's revert, a
#     rescue in `_run_step_body` forced the return code whenever the stubbed
#     validator was never invoked —
#     backwards: it hid exactly the bypass a real checkout would produce,
#     rather than exposing it.
#
# TestAggregateGateReflectsEveryGateJob (1 + 1 + 1 + 1)
#   — the aggregate gate a pull request's merge decision actually depends on.
#     `validation-summary` is the only place any gate job's `needs.<job>.result`
#     is read at all (`if: always()` is what lets it observe every result
#     regardless of which job failed); every job containing a gate step is
#     both in its `needs:` and read by one of its `needs.<job>.result`
#     expressions; and rendering its shell body with each gate job in turn set
#     to `"failure"` (every other referenced job `"success"`) makes it exit
#     non-zero. The render step (`_render_needs_expressions`) reproduces
#     GitHub's own `${{ }}` evaluation ahead of the shell, proven against a
#     minimal case by its own non-vacuity test. Two edits reach this section's
#     rejected state with every test above it still green: dropping a job from
#     `needs:` and deleting its result branch (`_summary_job_needs_and_reads_
#     every_gate_job` catches this), or leaving the `needs:` entry and the read
#     intact while deleting the one `overall_success=false` line that would
#     have made that job's failure matter (`_summary_job_fails_when_any_gate_
#     job_does_not_succeed` catches this).
#
# TestUnflaggedBlockingCoverage (1 + 6, parametrized over the derived set)
#   — D8: the hooks ADR-037's D1 instance table names all resolve to the
#     pre-commit config, and at least one of them carries no strictness flag;
#     and every flagless self-scanning hook has a CI invocation, attributed to
#     it rather than to a sibling sharing its script. The second is D1 part 1
#     over the half of the rule `--block` cannot see, and it fails — rather
#     than skips — on a validator no workflow runs.
#     Six governed hooks are flagless (D8); one of them, `validate-neutrality`,
#     also takes file arguments and is governed by section 6 instead (its own
#     count there), not by this class — see UNFLAGGED_BLOCKING_HOOKS's own
#     comment for why.
#
# TestUnflaggedValidatorsRunInPlace (6)
#   — D7b stated positively: the invocation exists, names the validator's real
#     path, and no workflow relocates it. Section 4's prohibition passes on
#     these six by having no call site to police.
#
# TestUnflaggedValidatorsCatchInjectedViolations (1 + 6)
#   — D7c: every governed self-scanning hook has a corpus probe, and the
#     arguments CI passes exit non-zero and name the injected violation on a
#     checkout-shaped mirror carrying one, having exited 0 on the clean
#     mirror. Poison per validator: an unregistered framework key (purity,
#     D4c), an unknown version token (drift, D5), a hand-edited versionId
#     (versionId purity, D2b/D2c), a framework id outside frameworks.schema.json's
#     enum (JSON Schema), an empty personas.yaml (build_persona_site_data.load_yaml),
#     an ADR-033 vendor/product denylist term under scripts/agents|skills/**.
#
# TestUnflaggedValidatorsValidateTheCheckoutUnderTest (6 + 6)
#   — which corpus the run read, which no flag, file list or command line
#     states. A characterization observes that a poisoned corpus in the working
#     directory goes unread by a validator that resolves from its own path,
#     which exits 0; the rule that follows pins the step to the repository
#     root. Section 7 now reaches these steps too — `_gate_steps` recognizes a
#     flagless validator's invocation as a gate step (D8) — but only with its
#     generic guards; the per-hook_id detail stays here.
#
# TestModuleInventory (1)
#   — the classes this module collects are the classes it declares, and none
#     collects zero cases. Deleting a class was previously a smaller run with no
#     failure.
#
# Warn-path coverage note (D4 disclosure)
#   Every one of the five validators has a warn path reachable from a fixture,
#   so none required the weaker "assert the flag is parsed" substitute. The
#   checks exercised are named per probe in BlockProbe.warn_check, and per
#   entity file in _PROSE_FIELD_BY_STEM for the D7a tier.
