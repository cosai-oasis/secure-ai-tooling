#!/usr/bin/env python3
"""Resolve the file list a ``pass_filenames: true`` pre-commit hook would receive.

ADR-037 D7a: CI invokes several file-argument validators over the whole tracked
corpus rather than over a diff. The file set is derived here from the hook's own
``files:``/``exclude:`` patterns so the two surfaces cannot drift. A list
transcribed into workflow YAML drifts in the permissive direction — a file the
hook covers and the workflow omits is unchecked in CI while appearing checked.

Two of the validators wired under D7 exit 0 when handed no files, so an empty
result is a passing job that inspected nothing. An empty match is therefore an
error, not an empty line of output.

Paths are printed one per line and are safe to word-split in shell; the tracked
corpus contains no path with whitespace, and a path that did would be rejected
rather than silently split (see ``_check_splittable``).

Usage:
    python3 scripts/tools/hook_file_list.py <hook-id> [--config PATH] [--root PATH]

Exit codes:
    0  one or more paths written to stdout
    1  the hook's patterns matched no tracked file
    2  usage, configuration, or git error
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

# Exit codes, named so the workflow contract is readable at the call sites.
EXIT_OK = 0
EXIT_EMPTY_MATCH = 1
EXIT_USAGE = 2

_DEFAULT_CONFIG = ".pre-commit-config.yaml"


class HookFileListError(Exception):
    """Raised when the hook cannot be resolved or the corpus cannot be read."""


def load_hook(config_path: Path, hook_id: str) -> dict:
    """Return the single hook entry declaring ``hook_id``.

    Args:
        config_path: Path to .pre-commit-config.yaml.
        hook_id: The ``id:`` of the hook to resolve.

    Returns:
        The hook mapping as declared in the config.

    Raises:
        HookFileListError: If the config is unreadable, declares top-level
            ``files``/``exclude`` (which this script does not model), or the id
            is unknown or declared more than once.
    """
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise HookFileListError(f"cannot read {config_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise HookFileListError(f"cannot parse {config_path}: {exc}") from exc

    if not isinstance(config, dict):
        raise HookFileListError(f"{config_path} does not contain a mapping")

    # Top-level files/exclude narrow every hook in the config. Rather than
    # silently returning a wider set than the hook would see, fail: a wrong file
    # list here is exactly the vacuity D7a exists to prevent.
    unsupported = sorted(key for key in ("files", "exclude") if key in config)
    if unsupported:
        raise HookFileListError(
            f"{config_path} declares top-level {unsupported}, which this script does not model. "
            f"Teach it those keys before relying on the derived list."
        )

    matches = [
        hook
        for repo in config.get("repos", []) or []
        for hook in repo.get("hooks", []) or []
        if hook.get("id") == hook_id
    ]
    if not matches:
        known = sorted(
            {
                str(hook.get("id"))
                for repo in config.get("repos", []) or []
                for hook in repo.get("hooks", []) or []
                if hook.get("id")
            }
        )
        raise HookFileListError(f"no hook with id {hook_id!r} in {config_path}. Known ids: {', '.join(known)}")
    if len(matches) > 1:
        raise HookFileListError(
            f"hook id {hook_id!r} is declared {len(matches)} times in {config_path}; "
            f"the file list it should produce is ambiguous."
        )
    return matches[0]


def tracked_files(root: Path) -> list[str]:
    """Return every tracked path in the repository, repo-relative and slash-separated.

    Args:
        root: Repository root to enumerate.

    Returns:
        Sorted list of tracked paths.

    Raises:
        HookFileListError: If git is unavailable or the directory is not a repository.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = getattr(exc, "stderr", "") or ""
        raise HookFileListError(f"`git ls-files` failed in {root}: {stderr.strip() or exc}") from exc

    return sorted(entry for entry in result.stdout.split("\0") if entry)


def matching_files(hook: dict, paths: list[str]) -> list[str]:
    """Filter paths by a hook's ``files:``/``exclude:`` patterns.

    Matching uses ``re.search`` against the repo-relative path, which is what
    pre-commit itself does; the repository's patterns are anchored explicitly.

    Args:
        hook: A hook mapping from .pre-commit-config.yaml.
        paths: Repo-relative candidate paths.

    Returns:
        The subset the hook would be handed, in input order.

    Raises:
        HookFileListError: If the hook declares no ``files:`` pattern, or a
            pattern does not compile.
    """
    files_pattern = hook.get("files")
    if not files_pattern:
        # An absent files: matches everything. That is never the intent for the
        # scoped validators this script serves, so treat it as a config error.
        raise HookFileListError(
            f"hook {hook.get('id')!r} declares no `files:` pattern, so its file list is the whole "
            f"repository. Scope the hook, or invoke the validator directly."
        )

    try:
        include = re.compile(files_pattern)
        exclude = re.compile(hook["exclude"]) if hook.get("exclude") else None
    except re.error as exc:
        raise HookFileListError(f"hook {hook.get('id')!r} has an uncompilable pattern: {exc}") from exc

    return [path for path in paths if include.search(path) and not (exclude and exclude.search(path))]


def _check_splittable(paths: list[str]) -> None:
    """Reject paths that shell word-splitting would corrupt.

    Callers consume this output through an unquoted ``$(...)`` expansion, so a
    path containing whitespace would silently become two arguments — and each
    half would then fail as "file not found", or worse, match nothing.

    Args:
        paths: Resolved paths.

    Raises:
        HookFileListError: If any path contains whitespace.
    """
    unsafe = [path for path in paths if any(char.isspace() for char in path)]
    if unsafe:
        raise HookFileListError(f"resolved paths contain whitespace and cannot be word-split safely: {unsafe}")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Argument list. Defaults to ``sys.argv[1:]`` when None.

    Returns:
        One of EXIT_OK, EXIT_EMPTY_MATCH, EXIT_USAGE.
    """
    parser = argparse.ArgumentParser(
        description="Print the tracked files a pre-commit hook's `files:` pattern selects.",
        epilog="Example: %(prog)s validate-yaml-prose-subset",
    )
    parser.add_argument("hook_id", help="The `id:` of the hook in .pre-commit-config.yaml.")
    parser.add_argument("--root", default=".", help="Repository root (default: %(default)s).")
    parser.add_argument(
        "--config",
        default=None,
        help=f"Path to the pre-commit config (default: <root>/{_DEFAULT_CONFIG}).",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    root = Path(args.root)
    config_path = Path(args.config) if args.config else root / _DEFAULT_CONFIG

    try:
        hook = load_hook(config_path, args.hook_id)
        paths = matching_files(hook, tracked_files(root))
        _check_splittable(paths)
    except HookFileListError as exc:
        print(f"hook_file_list: error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not paths:
        print(
            f"hook_file_list: error: hook {args.hook_id!r} matched no tracked file under {root}. "
            f"A validator handed no files exits 0 without inspecting anything.",
            file=sys.stderr,
        )
        return EXIT_EMPTY_MATCH

    print("\n".join(paths))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
