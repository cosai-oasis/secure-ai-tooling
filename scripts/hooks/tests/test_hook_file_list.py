#!/usr/bin/env python3
"""
Tests for ``scripts/tools/hook_file_list.py`` — the ADR-037 D7a file-list resolver.

Why this module exists
----------------------
D7a requires CI's file-argument validators to receive the file set their
pre-commit hook would see, derived from the hook's own ``files:``/``exclude:``
patterns rather than transcribed into workflow YAML. The resolver is the single
point where that derivation happens, and three of ``validation.yml``'s jobs
consume its stdout directly. It is therefore load-bearing for whether those
three gates inspect anything at all, and every failure mode it has is a silent
one at the consuming end:

  - an empty result hands two ``nargs="*"`` validators no files, and both exit 0
    without reading a byte;
  - a *short* result checks some files and reports success for all of them,
    which is worse, because the job's green tick is indistinguishable from a
    complete pass.

Neither shows up in the workflow's own output. The assertions below are
therefore exact-list assertions, not "non-empty" assertions: a resolver
truncated to its first element satisfies every reasonable-looking non-empty
check while dropping three quarters of the corpus.

Oracles
-------
Two independent ones, because the resolver's correctness is a claim about
agreement with pre-commit, not about its own internals:

  1. ``pre_commit.commands.run.Classifier`` — pre-commit's own file selection,
     the thing the resolver exists to reproduce. This is the authoritative
     oracle. It is skipped only if pre-commit's internals move, and the skip
     names why.
  2. An in-test re-derivation over ``git ls-files``. Written here rather than
     imported, so a mutation to the resolver's own matching cannot also mutate
     the expectation.

Derivation, not enumeration
---------------------------
The governed hook set is parsed out of ``.pre-commit-config.yaml``: every hook
whose entry carries a strictness flag *and* which passes filenames. That is
exactly the set ADR-037 D1 requires CI to cover through a derived file list. A
fourth such hook added tomorrow is tested on arrival without editing this file.
"""

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

# ---------------------------------------------------------------------------
# Paths and module loading
# ---------------------------------------------------------------------------

# tests -> hooks -> scripts -> repo root, matching the convention used by the
# sibling test modules.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_PRECOMMIT_CONFIG = _REPO_ROOT / ".pre-commit-config.yaml"
_RESOLVER_PATH = _REPO_ROOT / "scripts" / "tools" / "hook_file_list.py"


def _load_resolver():
    """Import hook_file_list.py by path.

    ``scripts/tools/`` is not on ``sys.path`` (pyproject only adds
    ``scripts/hooks``), and adding it globally would leak into every other test
    module. Loading by path keeps the import local to this file.
    """
    spec = importlib.util.spec_from_file_location("hook_file_list", _RESOLVER_PATH)
    assert spec and spec.loader, f"cannot load {_RESOLVER_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hook_file_list = _load_resolver()

# The strictness flags ADR-037 D1 quantifies over. Kept in sync with
# test_ci_block_parity.STRICTNESS_FLAGS by intent, duplicated by value so this
# module has no import dependency on that one.
STRICTNESS_FLAGS = frozenset({"--block"})


# ---------------------------------------------------------------------------
# Derivation of the governed hook set
# ---------------------------------------------------------------------------


def _load_config() -> dict[str, Any]:
    """Return the parsed .pre-commit-config.yaml."""
    return yaml.safe_load(_PRECOMMIT_CONFIG.read_text(encoding="utf-8"))


def _governed_hooks() -> dict[str, dict[str, Any]]:
    """Return hook-id -> hook mapping for every strictness-flagged file-argument hook.

    ``pass_filenames`` defaults to true in pre-commit, so an absent key counts
    as true. Hooks that set it false (the self-scanning risk-map validators)
    are excluded: they need no file list, so the resolver never runs for them.
    """
    governed: dict[str, dict[str, Any]] = {}
    for repo in _load_config().get("repos", []) or []:
        for hook in repo.get("hooks", []) or []:
            command = " ".join([str(hook.get("entry") or ""), *(str(a) for a in hook.get("args", []) or [])])
            has_strictness = any(flag in command.split() for flag in STRICTNESS_FLAGS)
            if has_strictness and hook.get("pass_filenames", True) and hook.get("id"):
                governed[str(hook["id"])] = hook
    return governed


GOVERNED_HOOKS = _governed_hooks()
GOVERNED_HOOK_IDS = sorted(GOVERNED_HOOKS)


def _tracked_files() -> list[str]:
    """Return every tracked repo-relative path, via git, sorted."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    return sorted(entry for entry in result.stdout.split("\0") if entry)


def _expected_files(hook: dict[str, Any]) -> list[str]:
    """Re-derive a hook's file set here, independently of the resolver.

    Deliberately a second implementation rather than a call into
    ``hook_file_list.matching_files``: an expectation computed by the code under
    test cannot detect a mutation to that code.
    """
    include = re.compile(hook["files"])
    exclude = re.compile(hook["exclude"]) if hook.get("exclude") else None
    return [path for path in _tracked_files() if include.search(path) and not (exclude and exclude.search(path))]


def _run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run the resolver as a subprocess, the way the workflow does."""
    return subprocess.run(
        [sys.executable, str(_RESOLVER_PATH), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or _REPO_ROOT),
    )


# ---------------------------------------------------------------------------
# Temporary-repository helpers for the error-path tests
# ---------------------------------------------------------------------------


def _init_repo(root: Path) -> None:
    """Initialise an empty git repository at root."""
    subprocess.run(["git", "init", "-q"], cwd=str(root), check=True, capture_output=True)


def _track(root: Path, rel: str, content: str = "placeholder\n") -> None:
    """Create and `git add` a file so `git ls-files` reports it.

    Staging is enough — the resolver reads the index, not a commit — which
    keeps these fixtures free of git identity configuration.
    """
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "--", rel], cwd=str(root), check=True, capture_output=True)


def _write_config(root: Path, hooks: list[dict[str, Any]], **top_level: Any) -> None:
    """Write a minimal .pre-commit-config.yaml containing the given hooks."""
    config: dict[str, Any] = {"repos": [{"repo": "local", "hooks": hooks}]}
    config.update(top_level)
    (root / ".pre-commit-config.yaml").write_text(yaml.dump(config), encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A temporary git repository with one tracked file, ready for a config."""
    _init_repo(tmp_path)
    _track(tmp_path, "risk-map/yaml/risks.yaml")
    return tmp_path


# ===========================================================================
# 1. Non-vacuity guards on the derivation itself
# ===========================================================================


class TestDerivationFidelity:
    """Guards that make every parametrized case below mean something.

    The governed hook set is parsed, not listed. If the parse silently returned
    nothing, pytest would collect zero cases from every parametrized test in
    this module and report success.
    """

    def test_governed_hook_set_is_not_empty(self):
        """
        Given: .pre-commit-config.yaml as committed
        When: hooks carrying a strictness flag and passing filenames are derived
        Then: at least one is found

        A zero result would collapse every parametrization in this module to no
        cases at all, which pytest reports as a pass.
        """
        assert GOVERNED_HOOK_IDS, (
            "Parsed no strictness-flagged file-argument hooks out of "
            f"{_PRECOMMIT_CONFIG}. Expected at least one hook whose entry carries "
            f"one of {sorted(STRICTNESS_FLAGS)} with pass_filenames true. Either the "
            "config genuinely stopped declaring them, or the derivation above "
            "stopped seeing them — the second makes this whole module vacuous."
        )

    def test_at_least_one_governed_hook_resolves_to_several_files(self):
        """
        Given: the governed hooks resolved against the real repository
        When: the resulting list lengths are inspected
        Then: at least one hook yields more than one file

        Truncation is only detectable where there is something to truncate. If
        every governed hook matched exactly one file, an exact-list assertion
        would be indistinguishable from a length-1 assertion and a resolver
        returning ``paths[:1]`` would pass everything here.
        """
        lengths = {hook_id: len(_expected_files(hook)) for hook_id, hook in GOVERNED_HOOKS.items()}
        assert any(count > 1 for count in lengths.values()), (
            f"Every governed hook resolves to at most one file: {lengths}. The "
            "exact-list assertions below can no longer distinguish a correct "
            "resolver from one that truncates its result."
        )


# ===========================================================================
# 2. The resolved list is exact — the corpus, all of it, and nothing else
# ===========================================================================


class TestResolvedListIsExact:
    """The resolver reproduces pre-commit's file selection, file for file.

    Every assertion here compares whole lists. A subset assertion, a non-empty
    assertion, or a length assertion would each pass a resolver that returns
    one file out of four, and that resolver produces a green CI job which has
    inspected a quarter of the corpus.
    """

    @pytest.mark.parametrize("hook_id", GOVERNED_HOOK_IDS)
    def test_matching_files_equals_independent_derivation(self, hook_id):
        """
        Given: a strictness-flagged file-argument hook and the tracked corpus
        When: matching_files() filters the corpus by the hook's patterns
        Then: the result equals a re-derivation written independently here

        The whole list, in order. This is the assertion a ``[:1]`` truncation
        or an unconditional ``[]`` fails.
        """
        hook = GOVERNED_HOOKS[hook_id]
        expected = _expected_files(hook)
        actual = hook_file_list.matching_files(hook, _tracked_files())

        assert actual == expected, (
            f"{hook_id}: resolved file list does not match the hook's own patterns.\n"
            f"  files:   {hook.get('files')!r}\n"
            f"  exclude: {hook.get('exclude')!r}\n"
            f"  expected ({len(expected)}): {expected}\n"
            f"  actual   ({len(actual)}): {actual}\n"
            "A short list is the dangerous direction: the validator reports success "
            "for the files it did read, and the files it never saw are indistinguishable "
            "from clean ones."
        )

    @pytest.mark.parametrize("hook_id", GOVERNED_HOOK_IDS)
    def test_matching_files_equals_precommit_classifier(self, hook_id):
        """
        Given: the same hook, classified by pre-commit's own machinery
        When: Classifier.from_config() is applied to the tracked corpus
        Then: the resolver's list matches pre-commit's, exactly

        The authoritative oracle. ADR-037 D7a's requirement is not "some
        plausible file list" but "the file set the hook would see", and only
        pre-commit can settle what that is.
        """
        hook = GOVERNED_HOOKS[hook_id]
        try:
            from pre_commit.commands.run import Classifier
        except ImportError as exc:
            # Hard failure, not a skip. `requirements.txt` pins pre-commit
            # exactly, so the version that provides this symbol is the version
            # installed; an ImportError here means the pin moved to a release
            # that relocated it, which is a real finding about the authoritative
            # oracle and not an environment quirk to route around. This module's
            # stance throughout is fail, don't skip — a skipped oracle leaves the
            # in-test re-derivation checking the resolver against a second
            # opinion of the same author.
            pytest.fail(
                f"Cannot import pre_commit.commands.run.Classifier ({exc}). "
                "pre-commit is a pinned dependency, so this is a relocation in the "
                "pinned release rather than a missing install: find the symbol's new "
                "home and update this import. Skipping would leave ADR-037 D7a's "
                "'the file set the hook would see' resting on this module's own "
                "re-derivation, with nothing independent to check it against."
            )

        # from_config applies include/exclude and drops non-existent paths, which
        # is the same pipeline filenames_for_hook() runs before its type filter.
        # The governed hooks declare no types beyond pre-commit's default, so the
        # type filter is an identity here.
        classifier = Classifier.from_config(_tracked_files(), hook["files"], hook.get("exclude") or "^$")
        expected = sorted(classifier.filenames)
        actual = sorted(hook_file_list.matching_files(hook, _tracked_files()))

        assert actual == expected, (
            f"{hook_id}: the resolver disagrees with pre-commit's own Classifier.\n"
            f"  only pre-commit selects: {sorted(set(expected) - set(actual))}\n"
            f"  only the resolver selects: {sorted(set(actual) - set(expected))}\n"
            "CI would then check a different file set than the hook does, which is "
            "the drift ADR-037 D7a exists to prevent."
        )

    @pytest.mark.parametrize("hook_id", GOVERNED_HOOK_IDS)
    def test_cli_prints_exactly_the_matching_files(self, hook_id):
        """
        Given: the resolver invoked as the workflow invokes it
        When: stdout is split into lines
        Then: the lines are exactly the hook's file set, and the exit code is 0

        The function-level tests above pin ``matching_files``; this pins the
        surface the workflow actually consumes, which additionally covers the
        printing, the exit code, and the argument plumbing between them.
        """
        expected = _expected_files(GOVERNED_HOOKS[hook_id])
        result = _run_cli(hook_id)

        assert result.returncode == hook_file_list.EXIT_OK, (
            f"{hook_id}: resolver exited {result.returncode}, expected "
            f"{hook_file_list.EXIT_OK}.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        lines = result.stdout.split()
        assert lines == expected, (
            f"{hook_id}: resolver stdout does not equal the hook's file set.\n"
            f"  expected ({len(expected)}): {expected}\n"
            f"  stdout   ({len(lines)}): {lines}\n"
            "The workflow word-splits this output straight into the validator's argv."
        )

    @pytest.mark.parametrize("hook_id", GOVERNED_HOOK_IDS)
    def test_every_resolved_path_is_a_readable_tracked_file(self, hook_id):
        """
        Given: the resolver's output for a governed hook
        When: each path is checked against the working tree
        Then: every one exists and is a file

        A path the validator cannot open is not a checked file. The two prose
        validators print a not-found diagnostic and, under ``--block``, exit 2 —
        which surfaces — but the identification validator would raise instead.
        Either way the list is wrong at the point it is produced.
        """
        result = _run_cli(hook_id)
        missing = [path for path in result.stdout.split() if not (_REPO_ROOT / path).is_file()]
        assert not missing, f"{hook_id}: resolver emitted paths that are not readable files: {missing}"


# ===========================================================================
# 3. Matching semantics
# ===========================================================================


class TestMatchingSemantics:
    """Pins the matching rules the repository's hook patterns depend on."""

    def test_matching_uses_unanchored_search(self):
        """
        Given: a pattern that matches mid-path rather than from position zero
        When: matching_files() filters a path list
        Then: the path matches

        pre-commit applies ``re.search``. Switching to ``re.match`` or
        ``re.fullmatch`` would silently drop every file for any hook whose
        pattern is not anchored at the start — an empty list, which is the
        vacuity mode this resolver is built to refuse.
        """
        hook = {"id": "probe", "files": r"yaml/risks\.yaml"}
        paths = ["risk-map/yaml/risks.yaml", "risk-map/yaml/controls.yaml"]
        assert hook_file_list.matching_files(hook, paths) == ["risk-map/yaml/risks.yaml"]

    def test_exclude_removes_paths_the_include_selected(self):
        """
        Given: a hook whose files: selects three paths and whose exclude: names one
        When: matching_files() filters them
        Then: the excluded path is absent and the others remain

        Both halves matter. An exclude that is ignored over-checks (loud); an
        exclude applied as if it were the include under-checks (silent).
        """
        hook = {
            "id": "probe",
            "files": r"^risk-map/yaml/.*\.yaml$",
            "exclude": r"^risk-map/yaml/archive/",
        }
        paths = [
            "risk-map/yaml/archive/legacy.yaml",
            "risk-map/yaml/controls.yaml",
            "risk-map/yaml/risks.yaml",
        ]
        assert hook_file_list.matching_files(hook, paths) == [
            "risk-map/yaml/controls.yaml",
            "risk-map/yaml/risks.yaml",
        ]

    def test_matching_preserves_input_order(self):
        """
        Given: a candidate list in a known order
        When: matching_files() filters it
        Then: the surviving paths keep that relative order

        The workflow word-splits the output into argv, and the validators report
        diagnostics in argument order. Stable ordering keeps a CI log diffable
        against a local hook run.
        """
        hook = {"id": "probe", "files": r"\.yaml$"}
        paths = ["b.yaml", "a.yaml", "c.txt", "d.yaml"]
        assert hook_file_list.matching_files(hook, paths) == ["b.yaml", "a.yaml", "d.yaml"]

    def test_matching_returns_empty_when_nothing_matches(self):
        """
        Given: a pattern matching none of the candidates
        When: matching_files() filters them
        Then: the result is empty

        The function reports emptiness rather than treating it as an error; the
        refusal to act on an empty set belongs to main(), which the next class
        pins. Separating the two is what lets the CLI attach the explanation.
        """
        hook = {"id": "probe", "files": r"^nothing/matches/this$"}
        assert hook_file_list.matching_files(hook, ["risk-map/yaml/risks.yaml"]) == []


# ===========================================================================
# 4. Exit-code contract
# ===========================================================================


class TestExitCodeContract:
    """The CLI's exit codes are the workflow's only signal that anything is wrong.

    ``FILES=$(... hook_file_list.py ...)`` runs under GitHub's default
    ``bash -e``, so a non-zero exit aborts the step. That is the entire
    mechanism by which a bad file list becomes a red job rather than a green one
    that checked nothing. Each code below is asserted on its own, because a
    resolver that answered 0 for everything would look identical in stdout.
    """

    def test_empty_match_exits_nonzero_and_explains_why(self, repo):
        """
        Given: a hook whose pattern matches no tracked file
        When: the resolver runs
        Then: it exits EXIT_EMPTY_MATCH, prints nothing to stdout, and says why

        The single most important assertion in this module. Two of the three
        validators D7 wires declare ``nargs="*"`` and exit 0 immediately when
        handed no files, so an empty list that exits 0 produces a passing job
        that opened no file at all. Exit 0 here is indistinguishable, from
        outside, from a clean corpus.
        """
        _write_config(repo, [{"id": "probe", "files": r"^does/not/exist/.*$"}])
        result = _run_cli("probe", cwd=repo)

        assert result.returncode == hook_file_list.EXIT_EMPTY_MATCH, (
            f"Empty match must exit {hook_file_list.EXIT_EMPTY_MATCH}, got "
            f"{result.returncode}. At exit 0 the workflow's `bash -e` does not abort, "
            f"FILES is empty, and the validator exits 0 having read nothing.\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
        assert not result.stdout.strip(), (
            f"Empty match must print no paths; got {result.stdout!r}. Anything on "
            "stdout is word-split into the validator's argv."
        )
        assert "matched no tracked file" in result.stderr, (
            "Empty match must explain itself on stderr — the workflow log is the "
            f"only place a maintainer sees this. Got: {result.stderr!r}"
        )

    def test_unknown_hook_id_exits_usage_and_lists_known_ids(self, repo):
        """
        Given: a hook id absent from the config
        When: the resolver runs
        Then: it exits EXIT_USAGE and names the ids that do exist

        This is the failure a typo in the workflow produces, and the ids listing
        is what turns it into a one-line fix rather than a config hunt.
        """
        _write_config(repo, [{"id": "probe", "files": r"^risk-map/"}])
        result = _run_cli("prboe", cwd=repo)

        assert result.returncode == hook_file_list.EXIT_USAGE, (
            f"Unknown hook id must exit {hook_file_list.EXIT_USAGE}, got {result.returncode}.\n"
            f"stderr: {result.stderr!r}"
        )
        assert "probe" in result.stderr, f"Known-id listing missing from stderr: {result.stderr!r}"

    def test_hook_without_files_pattern_exits_usage(self, repo):
        """
        Given: a hook declaring no files: pattern
        When: the resolver runs
        Then: it exits EXIT_USAGE

        In pre-commit an absent ``files:`` matches everything. Passing the whole
        repository to a scoped validator is not a plausible intent, and would
        take minutes and produce diagnostics on files nobody asked about — so it
        is rejected rather than obeyed.
        """
        _write_config(repo, [{"id": "probe", "entry": "true"}])
        result = _run_cli("probe", cwd=repo)

        assert result.returncode == hook_file_list.EXIT_USAGE, (
            f"A hook with no files: pattern must exit {hook_file_list.EXIT_USAGE}, "
            f"got {result.returncode}.\nstdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )

    @pytest.mark.parametrize("key", ["files", "exclude"])
    def test_top_level_narrowing_key_exits_usage(self, repo, key):
        """
        Given: a config declaring a top-level files: or exclude:
        When: the resolver runs
        Then: it exits EXIT_USAGE

        Top-level keys narrow every hook. The resolver does not model them, so
        obeying only the hook-level pattern would return a *wider* set than the
        hook sees — CI checking files the hook does not, which is noise, and
        worse, an answer nobody can reconcile against a local run. Failing loudly
        is the only honest option until the keys are modelled.
        """
        _write_config(repo, [{"id": "probe", "files": r"^risk-map/"}], **{key: r"^risk-map/"})
        result = _run_cli("probe", cwd=repo)

        assert result.returncode == hook_file_list.EXIT_USAGE, (
            f"Top-level {key!r} must exit {hook_file_list.EXIT_USAGE}, got {result.returncode}.\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
        assert key in result.stderr, f"Diagnostic should name the unsupported key {key!r}: {result.stderr!r}"

    def test_duplicate_hook_id_exits_usage_and_names_the_ambiguity(self, repo):
        """
        Given: two hooks sharing one id with different files: patterns
        When: the resolver runs
        Then: it exits EXIT_USAGE and says the id is declared more than once

        Silently picking the first would make the CI file list depend on hook
        ordering in a YAML file — a difference nothing in the workflow reveals.
        """
        _write_config(
            repo,
            [
                {"id": "probe", "files": r"^risk-map/yaml/risks\.yaml$"},
                {"id": "probe", "files": r"^does/not/exist$"},
            ],
        )
        result = _run_cli("probe", cwd=repo)

        assert result.returncode == hook_file_list.EXIT_USAGE, (
            f"Duplicate hook id must exit {hook_file_list.EXIT_USAGE}, got {result.returncode}.\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
        assert "ambiguous" in result.stderr or "declared" in result.stderr, (
            f"Diagnostic should name the duplication: {result.stderr!r}"
        )

    def test_uncompilable_pattern_exits_usage(self, repo):
        """
        Given: a hook whose files: value is not a valid regex
        When: the resolver runs
        Then: it exits EXIT_USAGE

        An unhandled re.error would surface as a traceback and a non-zero exit,
        which happens to be safe, but the message a maintainer reads should name
        the hook and the pattern rather than a stack.
        """
        _write_config(repo, [{"id": "probe", "files": r"^risk-map/(unclosed"}])
        result = _run_cli("probe", cwd=repo)

        assert result.returncode == hook_file_list.EXIT_USAGE, (
            f"An uncompilable pattern must exit {hook_file_list.EXIT_USAGE}, got "
            f"{result.returncode}.\nstderr: {result.stderr!r}"
        )
        assert "Traceback" not in result.stderr, f"Expected a diagnostic, not a traceback: {result.stderr!r}"

    def test_path_containing_whitespace_exits_usage(self, repo):
        """
        Given: a tracked path containing a space, selected by the hook
        When: the resolver runs
        Then: it exits EXIT_USAGE rather than printing the path

        The workflow consumes this output through an unquoted ``${FILES}``
        expansion, so a path with a space becomes two arguments. The two halves
        then fail as not-found — under ``--block`` the prose validators exit 2,
        which surfaces, but the file itself is never checked. Refusing to emit
        the path keeps the failure at the point where it can be explained.
        """
        _track(repo, "risk-map/yaml/two words.yaml")
        _write_config(repo, [{"id": "probe", "files": r"^risk-map/yaml/.*\.yaml$"}])
        result = _run_cli("probe", cwd=repo)

        assert result.returncode == hook_file_list.EXIT_USAGE, (
            f"A whitespace-bearing path must exit {hook_file_list.EXIT_USAGE}, got "
            f"{result.returncode}.\nstdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
        assert "whitespace" in result.stderr, f"Diagnostic should name the cause: {result.stderr!r}"

    def test_outside_a_git_repository_exits_usage(self, tmp_path):
        """
        Given: a directory that is not inside a git repository
        When: the resolver runs there
        Then: it exits EXIT_USAGE

        ``git ls-files`` is how the corpus is enumerated. Treating its failure as
        "no files" would produce the empty-list vacuity by a different route, and
        with an exit code that says nothing was wrong.
        """
        _write_config(tmp_path, [{"id": "probe", "files": r"^risk-map/"}])
        result = _run_cli("probe", cwd=tmp_path)

        assert result.returncode == hook_file_list.EXIT_USAGE, (
            f"Outside a git repository the resolver must exit "
            f"{hook_file_list.EXIT_USAGE}, got {result.returncode}.\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )

    def test_missing_config_exits_usage(self, tmp_path):
        """
        Given: a --config path that does not exist
        When: the resolver runs
        Then: it exits EXIT_USAGE naming the unreadable file
        """
        result = _run_cli("probe", "--config", str(tmp_path / "absent.yaml"), cwd=tmp_path)
        assert result.returncode == hook_file_list.EXIT_USAGE, (
            f"A missing config must exit {hook_file_list.EXIT_USAGE}, got {result.returncode}.\n"
            f"stderr: {result.stderr!r}"
        )
        assert "cannot read" in result.stderr, f"Diagnostic should name the read failure: {result.stderr!r}"

    def test_config_that_is_not_a_mapping_exits_usage(self, repo):
        """
        Given: a config file whose top level is not a mapping
        When: the resolver runs
        Then: it exits EXIT_USAGE

        Guards the fail-open shape: ``config.get("repos", [])`` on a non-mapping
        would raise, and on an empty document would yield "unknown hook id" —
        a confusing message for a malformed file.
        """
        (repo / ".pre-commit-config.yaml").write_text("- just\n- a list\n", encoding="utf-8")
        result = _run_cli("probe", cwd=repo)
        assert result.returncode == hook_file_list.EXIT_USAGE, (
            f"A non-mapping config must exit {hook_file_list.EXIT_USAGE}, got {result.returncode}.\n"
            f"stderr: {result.stderr!r}"
        )


# ===========================================================================
# 5. Root and config selection
# ===========================================================================


class TestRootAndConfigSelection:
    """The resolver's answer depends on where it is run and which config it reads.

    Both defaults are relative to the process working directory, which is why
    ``test_ci_block_parity.TestGateStepsRunFromRepositoryRoot`` pins the
    workflow steps' working directory. These tests establish that the
    dependency is real, so that pin is guarding something.
    """

    def test_root_option_selects_the_repository_to_enumerate(self, repo, tmp_path_factory):
        """
        Given: a repository at one path and a process working directory elsewhere
        When: --root names the repository
        Then: the resolver returns that repository's matching files

        Without --root the resolver would enumerate the wrong tree. This is the
        supported way to run it from anywhere.

        The working directory comes from `tmp_path_factory` rather than from
        `tmp_path.parent`. The parent is shared by every test in the session, so
        a directory created there outlives this test and collides with any
        sibling choosing the same name; the factory hands out a fresh isolated
        path, and — unlike a subdirectory of `repo` — one that is not inside a
        git repository, which is what "elsewhere" is supposed to mean here.
        """
        _write_config(repo, [{"id": "probe", "files": r"^risk-map/yaml/risks\.yaml$"}])
        elsewhere = tmp_path_factory.mktemp("elsewhere")

        result = _run_cli("probe", "--root", str(repo), cwd=elsewhere)
        assert result.returncode == hook_file_list.EXIT_OK, (
            f"--root should make the resolver runnable from anywhere; exited "
            f"{result.returncode}.\nstderr: {result.stderr!r}"
        )
        assert result.stdout.split() == ["risk-map/yaml/risks.yaml"]

    def test_default_root_is_the_process_working_directory(self, repo):
        """
        Given: a repository whose subdirectory is used as the working directory
        When: the resolver runs there with no --root
        Then: it does not return the repository-root answer

        The behavioural basis for the working-directory pin in the parity suite.
        ``git ls-files`` reports paths relative to the directory it runs in, and
        the config lookup is relative too, so a step that changes directory
        changes — or destroys — the file list without changing a single flag.
        """
        _write_config(repo, [{"id": "probe", "files": r"^risk-map/yaml/risks\.yaml$"}])
        subdir = repo / "risk-map"

        from_root = _run_cli("probe", cwd=repo)
        from_subdir = _run_cli("probe", cwd=subdir)

        assert from_root.returncode == hook_file_list.EXIT_OK, (
            f"Precondition: the root run should succeed; got {from_root.returncode}\n{from_root.stderr}"
        )
        assert (from_subdir.returncode, from_subdir.stdout) != (from_root.returncode, from_root.stdout), (
            "Running from a subdirectory produced the same answer as running from the "
            "repository root. The working-directory pin in test_ci_block_parity would "
            "then be guarding a hazard that no longer exists — re-derive it."
        )

    def test_config_option_selects_the_config_to_read(self, repo, tmp_path_factory):
        """
        Given: a config outside the repository root
        When: --config names it
        Then: its hooks are the ones resolved

        The alternate config is written under a factory-allocated directory
        rather than under `tmp_path.parent`, which is shared session-wide.
        """
        alternate = tmp_path_factory.mktemp("alternate") / "alternate-config.yaml"
        alternate.write_text(
            yaml.dump({"repos": [{"repo": "local", "hooks": [{"id": "alt", "files": r"^risk-map/yaml/"}]}]}),
            encoding="utf-8",
        )
        _write_config(repo, [{"id": "probe", "files": r"^does/not/exist$"}])

        result = _run_cli("alt", "--config", str(alternate), cwd=repo)
        assert result.returncode == hook_file_list.EXIT_OK, (
            f"--config should select the alternate config; exited {result.returncode}\n{result.stderr}"
        )
        assert result.stdout.split() == ["risk-map/yaml/risks.yaml"]


# ===========================================================================
# Test Summary
# ===========================================================================
# Total tests: 32 collected against the config as committed (parametrized cases
# counted per case; three governed hooks today, so the two parametrized classes
# contribute 2 + 12 + 6 = 20 of them). The count moves with
# `.pre-commit-config.yaml` by design — it is the derivation working, not drift.
# Verify with `pytest --collect-only -q scripts/hooks/tests/test_hook_file_list.py`
# rather than trusting this comment.
#
# TestDerivationFidelity (2)
#   — the governed hook set is non-empty; at least one governed hook resolves to
#     more than one file, so truncation is detectable at all.
#
# TestResolvedListIsExact (4 x 3 governed hooks = 12)
#   — matching_files equals an independent re-derivation; equals pre-commit's own
#     Classifier; the CLI prints exactly that list and exits 0; every emitted path
#     is a readable file.
#     These are the assertions a resolver returning [] or paths[:1] fails.
#
# TestMatchingSemantics (4)
#   — re.search (unanchored) semantics; exclude subtracts from include; input
#     order is preserved; no match yields an empty list at the function level.
#
# TestExitCodeContract (11, one parametrized over two keys)
#   — empty match exits 1 with an explanation and no stdout; unknown id, absent
#     files:, top-level files:/exclude:, duplicate id, uncompilable pattern,
#     whitespace-bearing path, no git repository, missing config, and a
#     non-mapping config each exit 2.
#
# TestRootAndConfigSelection (3)
#   — --root and --config select what is enumerated and read; the default root is
#     the process working directory, which is the hazard the parity suite's
#     working-directory pin exists to hold fixed.
#
# Coverage note
#   Every exit path in main() is asserted, and both oracles (pre-commit's
#   Classifier and an independent re-derivation) are compared whole-list rather
#   than by membership, because a short list is the failure this module exists
#   to catch. The Classifier oracle fails rather than skips when its import
#   moves: pre-commit is pinned, so an ImportError is a finding about the pin,
#   and a skipped oracle would leave the resolver checked only against this
#   module's own re-derivation.
