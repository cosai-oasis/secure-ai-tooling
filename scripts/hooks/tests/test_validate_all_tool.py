#!/usr/bin/env python3
"""
Tests for scripts/tools/validate-all.sh.

The --check-generation mode has a strict purity contract: generated artifacts
must be written only to a temporary directory, tracked files must remain
unchanged, and the git index must not be touched.
"""

import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

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
