#!/usr/bin/env python3
"""
Tests for scripts/hooks/precommit/validate_all_schemas.py

The wrapper re-validates every yaml/schema pair when the master schema
changes. Tests cover the filesystem discovery (_find_pairs), subprocess
call shape, continue-on-failure semantics, and first-failure-wins exit code.
"""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "precommit"))

from validate_all_schemas import _find_pairs, main  # noqa: E402

# The precommit directory _tracked_paths lives in, for out-of-process
# subprocess invocations below that need to import it fresh in a different
# cwd/PATH than this test process's own.
_PRECOMMIT_DIR = Path(__file__).parent.parent / "precommit"

# tests -> hooks -> scripts -> repo root, matching the convention in
# test_ci_block_parity.py and test_precommit_hook_install.py.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def _make_subprocess_mock(returncode: int = 0) -> MagicMock:
    """Return a MagicMock for subprocess.run with the given returncode."""
    mock = MagicMock()
    mock.returncode = returncode
    return mock


# ===========================================================================
# _find_pairs discovery (filesystem-dependent; uses the real repo layout)
# ===========================================================================


class TestFindPairs:
    def test_pairs_is_non_empty(self):
        """
        Non-vacuity guard for the whole class, and the one nothing here pinned
        before: `test_master_schema_excluded_from_pairs` and `test_every_pair_
        has_both_files_present` both hold trivially over an empty list, and
        only `test_pairs_cover_known_source_files` would notice zero pairs —
        indirectly, via its subset check, not by name. `_tracked_paths()`
        turning a git failure into an empty tracked set (mutation F4:
        `check=True` -> `check=False`) collapses `_find_pairs()` to exactly
        this: zero pairs, `main()` returning 0, and a CI summary reading
        "Passed (0 schemas)" for a validator that inspected nothing.
        """
        pairs = _find_pairs()
        assert pairs, "_find_pairs() discovered zero pairs against the real repository layout."

    def test_master_schema_excluded_from_pairs(self):
        """riskmap.schema.json is the trigger, not a target; must not appear."""
        pairs = _find_pairs()
        assert all(s.name != "riskmap.schema.json" for s, _ in pairs), (
            "Master schema must not be paired for validation"
        )

    def test_every_pair_has_both_files_present(self):
        """Every returned pair must reference files that actually exist."""
        pairs = _find_pairs()
        for schema, yaml_file in pairs:
            assert schema.is_file(), f"Schema not found: {schema}"
            assert yaml_file.is_file(), f"Yaml not found: {yaml_file}"

    def test_pairs_cover_known_source_files(self):
        """The nine canonical yaml/schema pairs must be discovered.

        A subset check, deliberately: since 23a455b, `_find_pairs()` recurses
        (`rglob`, not `glob`) so `risk-map/schemas/archive/` is discovered
        too, and the self-assessment-legacy pair archived there per ADR-021
        D6 now comes back as a tenth pair this test does not name. Asserting
        an exact set would fail on that pair, and on any other archived or
        future schema; asserting a subset is what lets the discovered set
        grow without this test changing.
        """
        expected_stems = {
            "actor-access",
            "components",
            "controls",
            "frameworks",
            "impact-type",
            "lifecycle-stage",
            "mermaid-styles",
            "personas",
            "risks",
        }
        pairs = _find_pairs()
        discovered_stems = {s.name.removesuffix(".schema.json") for s, _ in pairs}
        missing = expected_stems - discovered_stems
        assert not missing, f"Expected pairs missing: {sorted(missing)}"


# ===========================================================================
# _find_pairs must reflect the git index, not the filesystem
# ===========================================================================
#
# ADR-037 D1 makes CI the enforcing gate and the local pre-commit hook a
# preview of it. CI validates a fresh checkout of the tracked corpus;
# `_find_pairs()` filters its `rglob` result through `git ls-files`
# (`_tracked_paths()`) precisely so an untracked schema/yaml pair sitting in
# the working tree — a scratch file, a half-finished draft, a stray editor
# backup under a nested directory — is not discovered and validated locally
# when CI will never see it.
#
# That filter is two independent checks — `schema.as_posix() not in tracked`
# and `yaml_file.as_posix() in tracked` — and `test_untracked_schema_yaml_
# pair_is_not_discovered` below writes *both* halves of its probe untracked,
# so either check alone satisfies it: dropping one leaves the other still
# excluding the pair, and the mutation survives. The two tests after it each
# leave one half tracked (via a real, reverted `git add`) so only one check
# can be doing the excluding — pinning each side independently the way the
# single mixed-state test cannot.


class TestFindPairsRespectsGitIndex:
    def test_untracked_schema_yaml_pair_is_not_discovered(self):
        """
        Given: an untracked schema+matching-yaml pair written into the real
               working tree under `risk-map/schemas/scratch/` and
               `risk-map/yaml/scratch/` — never `git add`ed
        When: `_find_pairs()` is called from the repository root, the same
              working directory `validation.yml`'s schema-validation job uses
        Then: the untracked pair is absent from the result

        Reproduces mutation M32: an untracked
        `risk-map/schemas/scratch/actor-access.schema.json` plus a malformed
        nested yaml made `_find_pairs()` return eleven pairs (ten tracked plus
        the scratch one) and `main()` exit 1 on a file CI cannot see, because
        it is not part of the tracked corpus a checkout would ever contain.
        `_find_pairs()` currently globs the filesystem with no git-index
        check at all, so this is expected to fail until it is switched to
        filter through (or discover via) `git ls-files`.

        Files are created directly under the real `risk-map/` tree, then
        removed in `finally`, rather than in an isolated `tmp_path`:
        `_find_pairs()` resolves `_SCHEMA_DIR`/`_YAML_DIR` as paths relative
        to the process's current working directory
        (`Path("risk-map/schemas")`), which only matches the repository
        layout when run from the repository root — reproducing the hazard
        requires the real tree, not a copy of it.
        """
        schema_dir = _REPO_ROOT / "risk-map" / "schemas" / "scratch"
        yaml_dir = _REPO_ROOT / "risk-map" / "yaml" / "scratch"
        schema_path = schema_dir / "untracked-probe.schema.json"
        yaml_path = yaml_dir / "untracked-probe.yaml"

        preexisting_schema_dir = schema_dir.is_dir()
        preexisting_yaml_dir = yaml_dir.is_dir()
        try:
            schema_dir.mkdir(parents=True, exist_ok=True)
            yaml_dir.mkdir(parents=True, exist_ok=True)
            schema_path.write_text(
                '{"$schema": "http://json-schema.org/draft-07/schema#", "type": "object"}\n',
                encoding="utf-8",
            )
            # Content does not need to be valid against the schema above —
            # _find_pairs() is filesystem discovery only, and the mutation
            # this test reproduces is a discovery-stage escape, not a
            # validation-stage one.
            yaml_path.write_text("untracked: true\n", encoding="utf-8")

            pairs = _find_pairs()

            discovered_schema_names = {schema.name for schema, _ in pairs}
            assert "untracked-probe.schema.json" not in discovered_schema_names, (
                f"_find_pairs() discovered an untracked schema/yaml pair "
                f"({schema_path.relative_to(_REPO_ROOT)}, "
                f"{yaml_path.relative_to(_REPO_ROOT)}) that `git ls-files` does not "
                "track. CI validates a fresh checkout of the tracked corpus and would "
                "never see this pair, so a local commit can be blocked by a file that "
                "does not exist as far as the repository — or CI — is concerned. Fix "
                "is production-side: _find_pairs() needs to filter through (or "
                "discover via) `git ls-files`, not `Path.rglob`."
            )
        finally:
            schema_path.unlink(missing_ok=True)
            yaml_path.unlink(missing_ok=True)
            if not preexisting_schema_dir:
                schema_dir.rmdir()
            if not preexisting_yaml_dir:
                yaml_dir.rmdir()

    def test_tracked_schema_with_untracked_yaml_is_not_discovered(self):
        """
        Given: a schema staged into the git index (`git add`, reverted in
               `finally`) paired with a same-stem yaml that is never staged
        When: `_find_pairs()` is called from the repository root
        Then: the pair is absent from the result

        `test_untracked_schema_yaml_pair_is_not_discovered` writes both halves
        of its probe untracked, so it cannot tell "the yaml-side check
        excluded this pair" apart from "the schema-side check did" — either
        one alone would produce the same passing result. Staging only the
        schema isolates the yaml-side check
        (`yaml_file.as_posix() in tracked`): with the schema tracked, that
        check is the only thing standing between this pair and discovery, so
        dropping it — mutation F2 — is what this test catches.

        `git add` (not `git commit`) is enough: `_tracked_paths()` reads
        `git ls-files`, which reflects the index, matching `_find_pairs()`'s
        own contract of validating what a commit-in-progress would contain.
        """
        schema_dir = _REPO_ROOT / "risk-map" / "schemas" / "scratch"
        yaml_dir = _REPO_ROOT / "risk-map" / "yaml" / "scratch"
        schema_path = schema_dir / "tracked-schema-untracked-yaml-probe.schema.json"
        yaml_path = yaml_dir / "tracked-schema-untracked-yaml-probe.yaml"

        preexisting_schema_dir = schema_dir.is_dir()
        preexisting_yaml_dir = yaml_dir.is_dir()
        staged = False
        try:
            schema_dir.mkdir(parents=True, exist_ok=True)
            yaml_dir.mkdir(parents=True, exist_ok=True)
            schema_path.write_text(
                '{"$schema": "http://json-schema.org/draft-07/schema#", "type": "object"}\n',
                encoding="utf-8",
            )
            yaml_path.write_text("untracked: true\n", encoding="utf-8")

            subprocess.run(
                ["git", "add", "--", str(schema_path.relative_to(_REPO_ROOT))],
                cwd=str(_REPO_ROOT),
                check=True,
            )
            staged = True

            pairs = _find_pairs()

            discovered_schema_names = {schema.name for schema, _ in pairs}
            assert "tracked-schema-untracked-yaml-probe.schema.json" not in discovered_schema_names, (
                "_find_pairs() discovered a pair whose schema is tracked but whose yaml "
                "is not. The yaml-side tracked check (`yaml_file.as_posix() in tracked`) "
                "is the only thing that should have excluded it here — dropping that "
                "check (mutation F2) is what this test exists to catch."
            )
        finally:
            if staged:
                subprocess.run(
                    ["git", "reset", "--", str(schema_path.relative_to(_REPO_ROOT))],
                    cwd=str(_REPO_ROOT),
                    check=True,
                )
            schema_path.unlink(missing_ok=True)
            yaml_path.unlink(missing_ok=True)
            if not preexisting_schema_dir:
                schema_dir.rmdir()
            if not preexisting_yaml_dir:
                yaml_dir.rmdir()

    def test_untracked_schema_with_tracked_yaml_is_not_discovered(self):
        """
        Given: a yaml staged into the git index (`git add`, reverted in
               `finally`) paired with a same-stem schema that is never staged
        When: `_find_pairs()` is called from the repository root
        Then: the pair is absent from the result

        The mirror of the test above, isolating the schema-side check
        (`schema.as_posix() not in tracked`) instead: with the yaml tracked,
        that check is the only thing standing between this pair and
        discovery, so dropping it — mutation F3 — is what this test catches.
        Pinning both sides independently matters operationally, not just for
        mutation coverage: a tracked schema with an untracked yaml (a draft
        sitting in the working tree) or an untracked schema some prior step
        already `git rm --cached`'d while its yaml counterpart stayed staged
        are both real states a working tree can be in, and either one being
        discovered blocks a commit over content CI will never see.
        """
        schema_dir = _REPO_ROOT / "risk-map" / "schemas" / "scratch"
        yaml_dir = _REPO_ROOT / "risk-map" / "yaml" / "scratch"
        schema_path = schema_dir / "untracked-schema-tracked-yaml-probe.schema.json"
        yaml_path = yaml_dir / "untracked-schema-tracked-yaml-probe.yaml"

        preexisting_schema_dir = schema_dir.is_dir()
        preexisting_yaml_dir = yaml_dir.is_dir()
        staged = False
        try:
            schema_dir.mkdir(parents=True, exist_ok=True)
            yaml_dir.mkdir(parents=True, exist_ok=True)
            schema_path.write_text(
                '{"$schema": "http://json-schema.org/draft-07/schema#", "type": "object"}\n',
                encoding="utf-8",
            )
            yaml_path.write_text("untracked: true\n", encoding="utf-8")

            subprocess.run(
                ["git", "add", "--", str(yaml_path.relative_to(_REPO_ROOT))],
                cwd=str(_REPO_ROOT),
                check=True,
            )
            staged = True

            pairs = _find_pairs()

            discovered_schema_names = {schema.name for schema, _ in pairs}
            assert "untracked-schema-tracked-yaml-probe.schema.json" not in discovered_schema_names, (
                "_find_pairs() discovered a pair whose yaml is tracked but whose schema "
                "is not. The schema-side tracked check (`schema.as_posix() not in "
                "tracked`) is the only thing that should have excluded it here — "
                "dropping that check (mutation F3) is what this test exists to catch."
            )
        finally:
            if staged:
                subprocess.run(
                    ["git", "reset", "--", str(yaml_path.relative_to(_REPO_ROOT))],
                    cwd=str(_REPO_ROOT),
                    check=True,
                )
            schema_path.unlink(missing_ok=True)
            yaml_path.unlink(missing_ok=True)
            if not preexisting_schema_dir:
                schema_dir.rmdir()
            if not preexisting_yaml_dir:
                yaml_dir.rmdir()


# ===========================================================================
# _tracked_paths must fail loud, not swallow a git failure into "no files"
# ===========================================================================
#
# `_tracked_paths()` calls `subprocess.run(..., check=True)` and its own
# docstring promises the two ways `git ls-files` actually fails today —
# outside a git repository, or with `git` unavailable on PATH — propagate
# rather than get caught. Nothing pinned that promise: mutation F4
# (`check=True` -> `check=False`) turns either failure into a `stdout` of
# `""`, which `_tracked_paths()` parses into an empty set exactly as it would
# for a real, empty repository. `_find_pairs()` then excludes every schema
# (`schema.as_posix() not in tracked` is true for all of them), `main()`
# returns 0 on the resulting empty pair list, and CI reports "Passed (0
# schemas)" — the exact vacuous-pass shape ADR-037 exists to close, reached
# through the one function meant to prevent it.
#
# Both tests run `_tracked_paths()` out-of-process (a fresh `python3 -c`
# subprocess) rather than via `os.chdir`/`monkeypatch.setenv` in this test's
# own process: every other test in this module, and in
# scripts/hooks/tests/test_ci_block_parity.py, assumes the test process's own
# cwd is the repository root, and mutating it in-process — even restored in a
# `finally` — risks an interleaving with a fixture or a parallel test worker
# that never sees the restore.


class TestTrackedPathsFailsLoud:
    def _run_tracked_paths(self, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
        """Invoke `_tracked_paths()` in a fresh subprocess under the given cwd/env."""
        script = (
            f"import sys\nsys.path.insert(0, {str(_PRECOMMIT_DIR)!r})\n"
            "from validate_all_schemas import _tracked_paths\n_tracked_paths()\n"
        )
        return subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
        )

    def test_raises_outside_a_git_repository(self, tmp_path):
        """
        Given: `_tracked_paths()` run with its cwd outside any git repository
        When: `git ls-files` therefore exits non-zero
        Then: a `subprocess.CalledProcessError` propagates — an uncaught
              exception that exits the subprocess non-zero and names itself
              in stderr — rather than `_tracked_paths()` returning an empty
              set

        Measured, not assumed: this is one of the two ways `_tracked_paths()`'s
        own docstring says `git ls-files` fails today.
        """
        result = self._run_tracked_paths(tmp_path, dict(os.environ))
        assert result.returncode != 0, (
            "_tracked_paths() did not fail when run outside a git repository; it should "
            f"have propagated subprocess.CalledProcessError.\nstdout: {result.stdout!r}\n"
            f"stderr: {result.stderr!r}"
        )
        assert "CalledProcessError" in result.stderr, (
            "_tracked_paths() failed for a reason other than the expected "
            f"subprocess.CalledProcessError.\nstderr: {result.stderr!r}"
        )

    def test_raises_when_git_is_unavailable(self, tmp_path):
        """
        Given: `_tracked_paths()` run with a PATH containing no `git`
               executable
        When: the subprocess call cannot find `git` at all
        Then: a `FileNotFoundError` propagates rather than `_tracked_paths()`
              returning an empty set

        The second of the two documented failure modes. `PATH` is replaced
        with an empty directory rather than cleared outright, so the
        subprocess itself (`python3`, invoked by absolute path — `sys.
        executable` — so it needs no PATH lookup) still starts; only `git`
        becomes unresolvable.
        """
        result = self._run_tracked_paths(_REPO_ROOT, {"PATH": str(tmp_path)})
        assert result.returncode != 0, (
            "_tracked_paths() did not fail when git is unavailable on PATH; it should "
            f"have propagated FileNotFoundError.\nstdout: {result.stdout!r}\n"
            f"stderr: {result.stderr!r}"
        )
        assert "FileNotFoundError" in result.stderr, (
            "_tracked_paths() failed for a reason other than the expected "
            f"FileNotFoundError.\nstderr: {result.stderr!r}"
        )


# ===========================================================================
# main() behavior (subprocess mocked)
# ===========================================================================


class TestMainBehavior:
    """
    subprocess.run is patched at `subprocess.run` — the implementation must
    use `subprocess.run(...)` (not `from subprocess import run`) for the
    patch to intercept calls.
    """

    def test_empty_pairs_returns_zero(self):
        """If no pairs are discovered (hypothetically), exit 0 with no subprocess."""
        with patch("validate_all_schemas._find_pairs", return_value=[]):
            with patch("subprocess.run") as mock_run:
                result = main([])
        assert result == 0
        assert mock_run.call_count == 0

    def test_all_pairs_succeed_returns_zero(self):
        """All check-jsonschema calls succeed → exit 0."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_subprocess_mock(0)
            result = main([])
        assert result == 0
        # One subprocess call per discovered pair (ten in the real layout as
        # of 23a455b, which made discovery recurse into risk-map/schemas/archive/;
        # left as `> 0` rather than pinned, so this does not need to change
        # every time a schema is added, archived or not).
        assert mock_run.call_count > 0

    def test_first_failure_wins_exit_code(self):
        """First non-zero returncode is preserved even if later calls also fail."""
        rcs = iter([0, 2, 5, 0])  # second pair fails with rc=2, third with rc=5

        def side_effect(cmd, **kwargs):
            return _make_subprocess_mock(next(rcs))

        # Force a known pair list so the test is deterministic regardless of repo layout
        fake_pairs = [
            (Path(f"risk-map/schemas/p{i}.schema.json"), Path(f"risk-map/yaml/p{i}.yaml")) for i in range(4)
        ]
        with patch("validate_all_schemas._find_pairs", return_value=fake_pairs):
            with patch("subprocess.run", side_effect=side_effect) as mock_run:
                result = main([])

        assert result == 2, "First failing returncode (rc=2) must win"
        assert mock_run.call_count == 4, "All pairs must be attempted, not short-circuit"

    def test_continue_on_failure(self):
        """A failure in one pair does not skip subsequent pairs."""

        def side_effect(cmd, **kwargs):
            return _make_subprocess_mock(1)  # every call fails

        fake_pairs = [
            (Path(f"risk-map/schemas/p{i}.schema.json"), Path(f"risk-map/yaml/p{i}.yaml")) for i in range(3)
        ]
        with patch("validate_all_schemas._find_pairs", return_value=fake_pairs):
            with patch("subprocess.run", side_effect=side_effect) as mock_run:
                result = main([])

        assert result == 1
        assert mock_run.call_count == 3, "All pairs attempted despite every call failing"

    def test_command_shape_includes_base_uri_and_schemafile(self):
        """Every subprocess call uses list form with --base-uri and --schemafile."""
        fake_pairs = [(Path("risk-map/schemas/foo.schema.json"), Path("risk-map/yaml/foo.yaml"))]
        with patch("validate_all_schemas._find_pairs", return_value=fake_pairs):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = _make_subprocess_mock(0)
                main([])

        call = mock_run.call_args_list[0]
        cmd = call.args[0]
        assert isinstance(cmd, list), "Command must be list-form (no shell=True)"
        assert cmd[0] == "check-jsonschema"
        assert "--base-uri" in cmd
        assert "--schemafile" in cmd
        assert "risk-map/schemas/foo.schema.json" in cmd
        assert "risk-map/yaml/foo.yaml" in cmd
