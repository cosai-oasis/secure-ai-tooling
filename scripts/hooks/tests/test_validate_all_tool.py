#!/usr/bin/env python3
"""
Tests for scripts/tools/validate-all.sh.

The --check-generation mode has a strict purity contract: generated artifacts
must be written only to a temporary directory, tracked files must remain
unchanged, and the git index must not be touched.
"""

import os
import re
import shlex
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import NamedTuple

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent.parent
SCRIPT_SOURCE = REPO_ROOT / "scripts" / "tools" / "validate-all.sh"
REAL_GIT = shutil.which("git")

TABLE_FILES = [
    "components-full.md",
    "components-summary.md",
    "controls-full.md",
    "controls-summary.md",
    "controls-xref-components.md",
    "controls-xref-risks.md",
    "personas-full.md",
    "personas-summary.md",
    "personas-xref-controls.md",
    "personas-xref-risks.md",
    "risks-full.md",
    "risks-summary.md",
]


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _run_git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    assert REAL_GIT is not None, "git is required for validate-all.sh purity tests"
    return subprocess.run(
        [REAL_GIT, *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _git_status(repo: Path) -> str:
    return _run_git(repo, "status", "--porcelain=v1").stdout


def _make_stubbed_repo(tmp_path: Path, table_content: str = "canonical\n") -> tuple[Path, dict[str, str]]:
    repo = tmp_path / "repo"
    repo.mkdir()

    script_path = repo / "scripts" / "tools" / "validate-all.sh"
    script_path.parent.mkdir(parents=True)
    shutil.copy2(SCRIPT_SOURCE, script_path)

    (repo / "scripts" / "hooks").mkdir(parents=True)
    (repo / "risk-map" / "schemas").mkdir(parents=True)
    (repo / "risk-map" / "tables").mkdir(parents=True)
    (repo / "risk-map" / "yaml").mkdir(parents=True)
    (repo / "risk-map" / "schemas" / "components.schema.json").write_text("{}\n", encoding="utf-8")
    (repo / "risk-map" / "yaml" / "components.yaml").write_text("components: []\n", encoding="utf-8")

    for table_file in TABLE_FILES:
        (repo / "risk-map" / "tables" / table_file).write_text(table_content, encoding="utf-8")

    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    git_log = tmp_path / "git-invocations.log"
    python_log = tmp_path / "python-invocations.log"

    _write_executable(
        stub_bin / "check-jsonschema",
        "#!/bin/bash\nexit 0\n",
    )
    _write_executable(
        stub_bin / "git",
        '#!/bin/bash\necho "$@" >> "${GIT_STUB_LOG:?}"\nexit 99\n',
    )
    _write_executable(
        stub_bin / "python3",
        "#!/bin/bash\n"
        'printf "%s\\n" "$*" >> "${PYTHON_STUB_LOG:?}"\n'
        # Opt-in failure injection: exit 1 only when argv names the given
        # script. Unset by default, so every other validator keeps passing.
        'if [[ -n "${PYTHON_STUB_FAIL_ON:-}" && "$*" == *"$PYTHON_STUB_FAIL_ON"* ]]; then\n'
        "    exit 1\n"
        "fi\n"
        'if [[ "$1" == "scripts/hooks/yaml_to_markdown.py" ]]; then\n'
        '    output_dir=""\n'
        "    while [[ $# -gt 0 ]]; do\n"
        # Tolerate both --output-dir <DIR> and --output-dir=<DIR> forms so a
        # later refactor of the script invocation doesn't silently capture
        # an empty path.
        '        if [[ "$1" == --output-dir=* ]]; then\n'
        '            output_dir="${1#*=}"\n'
        "            shift\n"
        '        elif [[ "$1" == "--output-dir" ]]; then\n'
        '            output_dir="$2"\n'
        "            shift 2\n"
        "        else\n"
        "            shift\n"
        "        fi\n"
        "    done\n"
        '    if [[ -n "${TMPDIR_CAPTURE_FILE:-}" ]]; then\n'
        '        dirname "$output_dir" > "$TMPDIR_CAPTURE_FILE"\n'
        "    fi\n"
        '    if [[ "${GENERATOR_MODE:-success}" == "failure" ]]; then\n'
        "        exit 7\n"
        "    fi\n"
        '    if [[ "${GENERATOR_MODE:-success}" == "interrupt" ]]; then\n'
        "        sleep 30\n"
        "        exit 0\n"
        "    fi\n"
        '    mkdir -p "$output_dir"\n'
        "    for table_file in " + " ".join(TABLE_FILES) + "; do\n"
        '        printf "%s" "${GENERATED_CONTENT:-canonical\\n}" > "$output_dir/$table_file"\n'
        "    done\n"
        "    exit 0\n"
        "fi\n"
        "exit 0\n",
    )

    env = os.environ.copy()
    env["PATH"] = f"{stub_bin}{os.pathsep}{env['PATH']}"
    env["GIT_STUB_LOG"] = str(git_log)
    env["PYTHON_STUB_LOG"] = str(python_log)

    _run_git(repo, "init")
    _run_git(repo, "config", "user.email", "tests@example.com")
    _run_git(repo, "config", "user.name", "Tests")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", "Initial test fixture")

    return repo, env


def _run_validate_all(repo: Path, env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "scripts/tools/validate-all.sh", *args],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )


def _assert_repo_unchanged(repo: Path, before_status: str) -> None:
    assert _git_status(repo) == before_status
    diff = _run_git(repo, "diff", "--name-only").stdout
    assert diff == ""


def test_check_generation_success_leaves_tracked_files_and_index_unchanged(tmp_path: Path):
    repo, env = _make_stubbed_repo(tmp_path)
    before_status = _git_status(repo)
    temp_capture = tmp_path / "tempdir.txt"
    env["TMPDIR_CAPTURE_FILE"] = str(temp_capture)
    env["GENERATED_CONTENT"] = "canonical\n"

    result = _run_validate_all(repo, env, "--check-generation")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "Generated markdown tables match risk-map/tables" in result.stdout
    _assert_repo_unchanged(repo, before_status)
    assert not Path(temp_capture.read_text(encoding="utf-8").strip()).exists()
    assert not (tmp_path / "git-invocations.log").exists()


def test_check_generation_drift_fails_without_mutating_tracked_files(tmp_path: Path):
    repo, env = _make_stubbed_repo(tmp_path, table_content="committed\n")
    before_status = _git_status(repo)
    temp_capture = tmp_path / "tempdir.txt"
    env["TMPDIR_CAPTURE_FILE"] = str(temp_capture)
    env["GENERATED_CONTENT"] = "generated\n"

    result = _run_validate_all(repo, env, "--check-generation")

    assert result.returncode == 1
    assert "Table drift detected:" in result.stderr
    assert "components-full.md" in result.stderr
    _assert_repo_unchanged(repo, before_status)
    assert not Path(temp_capture.read_text(encoding="utf-8").strip()).exists()
    assert not (tmp_path / "git-invocations.log").exists()


def test_check_generation_cleans_tempdir_when_generator_fails(tmp_path: Path):
    repo, env = _make_stubbed_repo(tmp_path)
    before_status = _git_status(repo)
    temp_capture = tmp_path / "tempdir.txt"
    env["TMPDIR_CAPTURE_FILE"] = str(temp_capture)
    env["GENERATOR_MODE"] = "failure"

    result = _run_validate_all(repo, env, "--check-generation")

    assert result.returncode == 1
    assert "Markdown table generation check failed" in result.stdout
    _assert_repo_unchanged(repo, before_status)
    assert not Path(temp_capture.read_text(encoding="utf-8").strip()).exists()
    assert not (tmp_path / "git-invocations.log").exists()


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM], ids=["sigint", "sigterm"])
def test_check_generation_cleans_tempdir_on_signal(tmp_path: Path, sig: signal.Signals):
    """The trap installed by check_generated_tables covers INT and TERM;
    both signal paths must clean up the temp directory.
    """
    repo, env = _make_stubbed_repo(tmp_path)
    before_status = _git_status(repo)
    temp_capture = tmp_path / "tempdir.txt"
    env["TMPDIR_CAPTURE_FILE"] = str(temp_capture)
    env["GENERATOR_MODE"] = "interrupt"

    process = subprocess.Popen(
        ["bash", "scripts/tools/validate-all.sh", "--check-generation"],
        cwd=repo,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    deadline = time.time() + 10
    while not temp_capture.exists() and time.time() < deadline:
        time.sleep(0.05)

    assert temp_capture.exists(), "generator stub did not capture the temporary directory"
    temp_dir = Path(temp_capture.read_text(encoding="utf-8").strip())
    os.killpg(process.pid, sig)
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode != 0, stderr + stdout
    _assert_repo_unchanged(repo, before_status)
    assert not temp_dir.exists()
    assert not (tmp_path / "git-invocations.log").exists()


def test_check_generation_flags_extra_file_in_tables_dir(tmp_path: Path):
    """`diff -r -q` must report drift when risk-map/tables contains a file
    that the generator does not produce (e.g. a stale rename leftover).
    """
    repo, env = _make_stubbed_repo(tmp_path)
    stale_file = repo / "risk-map" / "tables" / "stale-leftover.md"
    stale_file.write_text("orphan\n", encoding="utf-8")
    _run_git(repo, "add", "risk-map/tables/stale-leftover.md")
    _run_git(repo, "commit", "-m", "Add stale file to surface file-set drift")
    before_status = _git_status(repo)

    result = _run_validate_all(repo, env, "--check-generation")

    assert result.returncode == 1
    assert "Table drift detected:" in result.stderr
    assert "stale-leftover.md" in result.stderr
    _assert_repo_unchanged(repo, before_status)
    assert not (tmp_path / "git-invocations.log").exists()


def test_check_generation_fails_cleanly_when_mktemp_fails(tmp_path: Path):
    """A failing `mktemp -d` must surface as a clean validator failure, not
    cascade into a write outside the temp tree (e.g. mkdir -p "/tables").
    """
    repo, env = _make_stubbed_repo(tmp_path)
    before_status = _git_status(repo)

    # Override mktemp on PATH so the script's `mktemp -d` returns non-zero
    # with no stdout. This simulates a full TMPDIR or permission failure.
    stub_bin = Path(env["PATH"].split(os.pathsep)[0])
    _write_executable(stub_bin / "mktemp", "#!/bin/bash\nexit 1\n")

    result = _run_validate_all(repo, env, "--check-generation")

    assert result.returncode == 1
    assert "Could not create temporary directory" in result.stdout
    _assert_repo_unchanged(repo, before_status)
    assert not (tmp_path / "git-invocations.log").exists()


def test_help_documents_check_generation_purity_contract(tmp_path: Path):
    repo, env = _make_stubbed_repo(tmp_path)

    result = _run_validate_all(repo, env, "--help")

    assert result.returncode == 0
    assert "--check-generation" in result.stdout
    assert "does not write tracked files or change the git" in result.stdout


def test_default_mode_does_not_run_generation_check(tmp_path: Path):
    repo, env = _make_stubbed_repo(tmp_path)
    before_status = _git_status(repo)
    env["GENERATOR_MODE"] = "failure"

    result = _run_validate_all(repo, env)

    assert result.returncode == 0
    _assert_repo_unchanged(repo, before_status)
    python_log = (tmp_path / "python-invocations.log").read_text(encoding="utf-8")
    assert "yaml_to_markdown.py" not in python_log
    assert not (tmp_path / "git-invocations.log").exists()


def test_default_sweep_exits_nonzero_when_only_tier2_validator_fails(tmp_path: Path):
    """
    Pin ADR-038 D6 item 10: a Tier 2 (validate_mapping_catalogue.py) failure
    makes the default-mode sweep exit non-zero.

    Given: a stubbed repo where only validate_mapping_catalogue.py exits 1
    When: validate-all.sh runs in default mode
    Then: it exits non-zero. Control: with every stub passing it exits 0, so
          a sweep that always fails cannot satisfy the first assertion.

    Why runtime: the structural checks parse the gate's text, so they cannot
    see a FAILURES increment that is dead code (wrapped in `if false; then
    ... fi`, or inside a function that is never called). In those cases the
    text is intact and the sweep exits 0 on a real Tier 2 failure.
    """
    repo, env = _make_stubbed_repo(tmp_path)

    control = _run_validate_all(repo, env)
    assert control.returncode == 0, control.stderr + control.stdout

    python_log_path = tmp_path / "python-invocations.log"
    python_log_path.write_text("", encoding="utf-8")  # so the check below sees only the failing run
    env["PYTHON_STUB_FAIL_ON"] = "validate_mapping_catalogue.py"
    result = _run_validate_all(repo, env)

    assert "validate_mapping_catalogue.py" in python_log_path.read_text(encoding="utf-8")
    assert result.returncode != 0, result.stderr + result.stdout


def test_sweep_includes_adr027_validators():
    """
    Assert that the full-tree sweep script invokes all three ADR-027 validators.

    Given: the source of scripts/tools/validate-all.sh
    When: the source text is inspected for ADR-027 validator invocations
    Then: all three validator script names are present:
          validate_versionid_purity.py, validate_mapping_purity.py,
          validate_mapping_drift.py

    Also asserts that the invocations use explicit full-tree consumer paths:
      - validate_mapping_purity.py and validate_mapping_drift.py must reference
        at least one consumer YAML (risks.yaml, controls.yaml, etc.) so they
        are not silently invoked with no file arguments.
      - validate_versionid_purity.py must reference frameworks.yaml (its input).

    This is the conformance contract for Gap A (#347 / D5): validate-all.sh must
    invoke the ADR-027 validators in the full-tree sweep.

    It also asserts the Tier 2 catalogue-membership validator
    (validate_mapping_catalogue.py) is invoked at its real path as an `if` gate
    whose condition is exactly `--force --block` (redirections aside) and whose
    else branch has the FAILURES increment line (ADR-038 D6 item 10).
    """
    source = SCRIPT_SOURCE.read_text(encoding="utf-8")
    assert "validate_versionid_purity.py" in source, (
        "validate-all.sh does not invoke validate_versionid_purity.py. "
        "ADR-027 D2b requires the versionId purity validator in the full-tree sweep."
    )
    assert "validate_mapping_purity.py" in source, (
        "validate-all.sh does not invoke validate_mapping_purity.py. "
        "ADR-027 D4c requires the mapping-value purity validator in the full-tree sweep."
    )
    assert "validate_mapping_drift.py" in source, (
        "validate-all.sh does not invoke validate_mapping_drift.py. "
        "ADR-027 D5 requires the mapping-drift validator in the full-tree sweep."
    )
    # Confirm the invocations reference explicit full-tree paths (not silent
    # no-op defaults). Per the Gap A spec, mapping-purity and mapping-drift take
    # all four consumer YAMLs and versionId-purity takes frameworks.yaml — require
    # every consumer file by name so a partial wiring cannot pass this gate.
    for consumer in ("risks.yaml", "controls.yaml", "components.yaml", "personas.yaml"):
        assert consumer in source, (
            f"validate-all.sh does not pass {consumer} to the ADR-027 mapping validators. "
            "Mapping-purity and mapping-drift must reference all four consumer YAMLs explicitly."
        )
    assert "frameworks.yaml" in source, (
        "validate-all.sh does not reference frameworks.yaml for the versionId purity check."
    )

    # ADR-038 D6 item 10: the Tier 2 catalogue-membership validator joins the
    # sweep with --force --block as the whole condition, and its failure branch
    # counts a failure. The checks are in _tier2_gate_violations.
    tier2_script = "scripts/hooks/precommit/validate_mapping_catalogue.py"
    gate = _sweep_gate_invocation(source, tier2_script)
    assert gate is not None, (
        f"validate-all.sh does not invoke {tier2_script} as an `if python3 ...; then` gate. "
        "ADR-038 D6 item 10 requires the Tier 2 validator in the full-tree sweep."
    )
    violations = _tier2_gate_violations(gate)
    assert not violations, "\n".join(violations)


def _tier2_gate_violations(gate: "_SweepGate") -> list[str]:
    """
    Return the ways a parsed gate breaks ADR-038 D6 item 10; empty when it conforms.

    - The condition's arguments, redirections removed, are exactly `--force` and
      `--block` in either order. Without --force the validator reads nothing and
      exits 0; without --block an invalid value exits 0 too (ADR-038 D4a). A
      positional path narrows the scan to that file, and an extra flag such as
      `--help` or `--catalogue-dir X` changes what is checked, so neither is allowed.
    - The condition has no compound operator. The `if` takes the exit status of the
      condition's last pipeline element or list member, so `|| true`, `| tee log`
      or `&& true` replace the validator's status with another command's.
    - The `else` branch increments FAILURES on a line of its own. A commented-out
      line, a null-command form (`: FAILURES=...`) or an increment in `then` does
      not count a Tier 2 failure.
    """
    violations = []
    if sorted(gate.arguments) != ["--block", "--force"]:
        violations.append(
            "The Tier 2 sweep gate condition's arguments, redirections excluded, must be exactly "
            f"--force --block (ADR-038 D4a, D6 item 10): {gate.arguments}"
        )
    operators = _condition_operators(gate.argv)
    if operators:
        violations.append(
            f"The Tier 2 sweep gate condition is compound ({operators}), so the `if` does not test "
            f"the validator's own exit status (ADR-038 D6 item 10): {gate.argv}"
        )
    if not _FAILURE_INCREMENT_LINE.search(gate.else_branch):
        violations.append(
            "The Tier 2 sweep gate's else branch has no `FAILURES=$((FAILURES + 1))` line, so a "
            f"Tier 2 failure would not fail the sweep (ADR-038 D6 item 10):\n{gate.else_branch}"
        )
    return violations


# The sweep's failure counter, as a whole assignment line (re.M anchors).
_FAILURE_INCREMENT_LINE = re.compile(r"^\s*FAILURES=\$\(\(FAILURES \+ 1\)\)\s*$", re.MULTILINE)

# A shell redirection with its optional fd number and its target, e.g. `2>&1`,
# `>/dev/null`, `> out.log`. The fd digits must start a word: `2 >&1` leaves the
# `2` behind as an argument, as the shell would.
_REDIRECTION = re.compile(r"(?<!\S)\d*(?:&>>|&>|>>|>&|<&|>\||<>|>|<)\s*[^\s;|&<>]+")


class _SweepGate(NamedTuple):
    """One `if python3 <script> ...; then ... [else ...] fi` gate in validate-all.sh."""

    argv: list[str]  # condition tokens after the script path, shell punctuation split out
    arguments: list[str]  # the same condition with redirections removed
    then_branch: str
    else_branch: str  # empty when the gate has no `else`


def _sweep_gate_invocation(source: str, script: str) -> _SweepGate | None:
    """
    Find `if python3 <script> ...; then ... fi` in validate-all.sh.

    Returns the parsed gate or None. Backslash continuations are joined first so a
    multi-line argument list is one command. The tokens are lexed with shell
    punctuation kept as separate tokens (`||`, `|`, `&&`, `>&`), so
    `_condition_operators` can see an operator even when it adjoins a word; a plain
    `shlex.split` would yield `--block||true` as one word, or drop the distinction
    between an argument and an operator. `arguments` is lexed after removing
    redirections from the raw text, because the lexer drops the spacing that tells
    `2>&1` (a redirection) from `2 >&1` (an argument, then a redirection).
    """
    joined = re.sub(r"\\\n\s*", " ", source)
    match = re.search(
        rf"^\s*if python3 {re.escape(script)}(?P<args>[^;\n]*); then\n(?P<branch>.*?)^\s*fi\b",
        joined,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        return None
    # Split at the gate's own `else` line; a gate without one has an empty else branch.
    parts = re.split(r"^\s*else\s*$", match.group("branch"), maxsplit=1, flags=re.MULTILINE)
    then_branch = parts[0]
    else_branch = parts[1] if len(parts) > 1 else ""
    return _SweepGate(
        argv=_lex_condition(match.group("args")),
        arguments=_lex_condition(_REDIRECTION.sub(" ", match.group("args"))),
        then_branch=then_branch,
        else_branch=else_branch,
    )


def _lex_condition(text: str) -> list[str]:
    """Split a gate condition into words, with shell punctuation as separate tokens."""
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


# Control operators that make an `if` condition compound: the `if` then tests the
# status of the last list member or pipeline element, not the validator's.
# A redirection such as `2>&1` lexes as `>&` and is not one of these; it leaves
# the exit status unchanged. `;` cannot reach here: the gate regex stops at it.
_COMPOUND_CONDITION_OPERATORS = frozenset({"||", "&&", "|", "|&", "&"})


def _condition_operators(tokens: list[str]) -> list[str]:
    """Return the compound-condition operators among a gate condition's tokens."""
    return [token for token in tokens if token in _COMPOUND_CONDITION_OPERATORS]


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("--force --block || true", ["||"]),
        ("--force --block||true", ["||"]),
        ("--force --block 2>&1 | tee /dev/null", ["|"]),
        ("--force --block && true", ["&&"]),
        ("--force --block |& tee /dev/null", ["|&"]),
        ("--force --block", []),
        ("--force --block 2>&1", []),
        ("--force --block > /dev/null", []),
    ],
)
def test_sweep_gate_parser_flags_compound_conditions(condition, expected):
    """
    Both sides of the compound-condition rule, on synthetic gate lines.

    Given: an `if python3 <script> <condition>; then ... fi` gate
    When:  parsed with _sweep_gate_invocation and checked with _condition_operators
    Then:  `||`, `&&`, `|` and `|&` are reported, attached to a word or not;
           a bare argument list and a redirection (`2>&1`, `> /dev/null`) are not,
           because a redirection does not change the condition's exit status

    Passes on the current tree; it pins the parser, so the Tier 2 assertion in
    test_sweep_includes_adr027_validators cannot pass a compound condition as an
    argument list.
    """
    source = f"if python3 scripts/probe.py {condition}; then\n    ok\nelse\n    FAILURES=$((FAILURES + 1))\nfi\n"
    gate = _sweep_gate_invocation(source, "scripts/probe.py")
    assert gate is not None
    assert _condition_operators(gate.argv) == expected


_CONFORMING_ELSE = "else\n    fail_msg x\n    FAILURES=$((FAILURES + 1))\n"


@pytest.mark.parametrize(
    ("condition", "branches", "violation"),
    [
        # Rejected: the condition is not exactly --force --block.
        pytest.param("--force --block --help", _CONFORMING_ELSE, "exactly", id="S1-extra-help-flag"),
        pytest.param(
            "--force --block risk-map/yaml/risks.yaml", _CONFORMING_ELSE, "exactly", id="S6b-positional-path"
        ),
        pytest.param(
            "--force --block --catalogue-dir /nonexistent", _CONFORMING_ELSE, "exactly", id="S7-extra-option"
        ),
        pytest.param("--force --block 2 >&1", _CONFORMING_ELSE, "exactly", id="spaced-fd-is-an-argument"),
        pytest.param("--force", _CONFORMING_ELSE, "exactly", id="missing-block"),
        # Rejected: the else branch does not count the failure.
        pytest.param(
            "--force --block", "else\n    # FAILURES=$((FAILURES + 1))\n", "else branch", id="S3-commented-out"
        ),
        pytest.param(
            "--force --block", "else\n    : FAILURES=$((FAILURES + 1))\n", "else branch", id="S5-null-command"
        ),
        pytest.param(
            "--force --block",
            "    FAILURES=$((FAILURES + 1))\nelse\n    fail_msg x\n",
            "else branch",
            id="S4-increment-in-then",
        ),
        pytest.param("--force --block", "", "else branch", id="no-else"),
        # Accepted: the exact flags in either order, with or without redirections.
        pytest.param("--force --block", _CONFORMING_ELSE, None, id="force-block"),
        pytest.param("--block --force", _CONFORMING_ELSE, None, id="block-force"),
        pytest.param("--force --block 2>&1", _CONFORMING_ELSE, None, id="stderr-redirect"),
        pytest.param("--force --block >/dev/null 2>&1", _CONFORMING_ELSE, None, id="both-redirects"),
        pytest.param("--force --block > out.log", _CONFORMING_ELSE, None, id="spaced-file-redirect"),
    ],
)
def test_tier2_sweep_gate_requires_exact_flags_and_an_else_increment(condition, branches, violation):
    """
    Both sides of ADR-038 D6 item 10 as _tier2_gate_violations enforces it.

    Given: a synthetic `if python3 <script> <condition>; then ... fi` gate
    When:  parsed with _sweep_gate_invocation and checked with _tier2_gate_violations
    Then:  extra flags (S1 `--help`, S7 `--catalogue-dir`), a positional path (S6b),
           a commented-out (S3) or null-command (S5) increment, an increment moved
           into `then`, and a gate with no `else` each yield one violation;
           `--force --block` in either order, alone or with redirections, yields none

    Guards the Tier 2 check against being only a presence check on the flags and a
    substring check on the increment, which would let mutants S1, S3, S5, S6b and
    S7 pass. It pins the checker that test_sweep_includes_adr027_validators
    applies to the real gate.
    """
    source = f"if python3 scripts/probe.py {condition}; then\n    pass_msg x\n{branches}fi\n"
    gate = _sweep_gate_invocation(source, "scripts/probe.py")
    assert gate is not None
    violations = _tier2_gate_violations(gate)
    if violation is None:
        assert violations == []
    else:
        assert len(violations) == 1 and violation in violations[0], violations


def test_sweep_gate_parser_reads_an_existing_multiline_gate():
    """
    Control for _sweep_gate_invocation: it parses a gate the sweep already has.

    Given: the validate_mapping_drift.py gate, whose four file arguments span
           backslash continuations
    When:  parsed with _sweep_gate_invocation
    Then:  the four consumer YAMLs are its argv and its else branch has the
           FAILURES increment line, and its then branch does not

    Passes on the current tree. Without it, a parser that never matched would
    make the Tier 2 assertion above fail for a parsing reason after the line lands.
    """
    source = SCRIPT_SOURCE.read_text(encoding="utf-8")
    gate = _sweep_gate_invocation(source, "scripts/hooks/precommit/validate_mapping_drift.py")
    assert gate is not None
    assert gate.argv == [f"risk-map/yaml/{name}.yaml" for name in ("risks", "controls", "components", "personas")]
    assert _FAILURE_INCREMENT_LINE.search(gate.else_branch)
    assert not _FAILURE_INCREMENT_LINE.search(gate.then_branch)


def test_sweep_runs_content_check_jsonschema_for_consumer_yamls():
    """
    Assert the full-tree sweep validates each consumer YAML against its schema
    with check-jsonschema (CI-parity for the mandatory-pin gate).

    Given: the source of scripts/tools/validate-all.sh
    When: the source text is inspected for content check-jsonschema invocations
    Then: for each of risks/controls/components/personas, the script invokes
          `check-jsonschema --schemafile risk-map/schemas/<X>.schema.json ...
          risk-map/yaml/<X>.yaml`.

    Why this matters: post-#343 the strict consumer schemas make pinning
    mandatory — check-jsonschema rejects an unpinned value (e.g. `GOVERN-6.2`
    with no `@1.0`). But validate-all.sh previously ran check-jsonschema ONLY as
    `--check-metaschema` (validating the schema FILES), never the content YAMLs
    against the consumer schemas. So a maintainer running the manual full-tree
    sweep got a false all-clear on an unpinned value that pre-commit + CI reject.
    This test pins the content-schema steps into the sweep so the gap cannot
    silently reopen.

    Structural (reads SCRIPT_SOURCE) so it is independent of the existing
    check-jsonschema stub used by the generation-purity tests.
    """
    source = SCRIPT_SOURCE.read_text(encoding="utf-8")
    for name in ("risks", "controls", "components", "personas"):
        # The schemafile flag must name the consumer's schema, and the same
        # invocation must name the consumer's YAML. A single regex spanning
        # both (with the --schemafile flag between them) ensures they belong to
        # one check-jsonschema call rather than coincidental separate mentions.
        pattern = (
            rf"check-jsonschema\b.*--schemafile\s+risk-map/schemas/{name}\.schema\.json"
            rf".*risk-map/yaml/{name}\.yaml"
        )
        assert re.search(pattern, source, re.DOTALL), (
            f"validate-all.sh does not run content check-jsonschema for {name}: "
            f"expected a `check-jsonschema --schemafile risk-map/schemas/{name}.schema.json "
            f"... risk-map/yaml/{name}.yaml` invocation. Without it the manual full-tree "
            f"sweep skips the mandatory-pin gate that pre-commit + CI enforce (#343)."
        )
