#!/usr/bin/env python3
"""
Pre-commit framework hook that re-validates every yaml against its schema
when the master schema `risk-map/schemas/riskmap.schema.json` changes.

A change to the master schema can affect any downstream yaml's validity via
`$ref` resolution, so we run check-jsonschema for every yaml/schema pair in
one pass. Source files are discovered by pairing each `*.schema.json` under
`risk-map/schemas/` with a same-named `*.yaml` under `risk-map/yaml/` —
this avoids a hardcoded list that would drift if a file is added or renamed.

Invoked by the pre-commit framework with no filenames (`pass_filenames:
false`). Only scheduled when `risk-map/schemas/riskmap.schema.json` itself
is staged — see `.pre-commit-config.yaml`.
"""

import os
import subprocess
import sys
from pathlib import Path

_SCHEMA_DIR = Path("risk-map/schemas")
_YAML_DIR = Path("risk-map/yaml")
_MASTER_SCHEMA_NAME = "riskmap.schema.json"


def _tracked_paths() -> set[str]:
    """Return every path tracked by git, relative to the current directory.

    `git ls-files` reports paths relative to the cwd, not the repository root.
    Both sides of the comparison in `_find_pairs` are cwd-relative and every
    invocation context runs at the worktree root — pre-commit sets cwd there
    even for a subdirectory commit — so the two agree today. A caller that
    changed the cwd would need to account for it.

    `git ls-files` reads the index, not HEAD, so a schema/yaml pair a
    contributor has just `git add`ed is included even before it's committed
    — that's the pair a pre-commit hook run should check, since it's what
    the commit-in-progress will actually contain.

    Raises `subprocess.CalledProcessError` if the cwd is outside a git
    repository, or `FileNotFoundError` if `git` itself is unavailable.
    Neither is caught: falling back to a filesystem walk on either error
    would silently reintroduce the untracked-file discovery this function
    exists to prevent, under a condition nobody would notice.
    """
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    )
    return {entry for entry in result.stdout.split("\0") if entry}


def _find_pairs() -> list[tuple[Path, Path]]:
    """Discover (schema, yaml) pairs for every schema with a matching yaml.

    The master schema (riskmap.schema.json) is excluded — it is the trigger,
    not a target. Schemas without a matching yaml are skipped silently.

    Discovery recurses (`rglob`, not `glob`) so schemas nested under a
    subdirectory of `risk-map/schemas/` — e.g. `archive/` — are found too.
    A schema outside the top level can still `$ref` the master schema (the
    archive pair does: `self-assessment-legacy.schema.json` refs
    `riskmap.schema.json#/definitions/utils/text`), so it is affected by a
    master-schema change the same way a top-level schema is, and this
    validator's whole purpose is to re-check everything the master schema
    can affect.

    The `rglob` walk is filtered through the git index (`_tracked_paths()`):
    both the schema and its paired yaml must be tracked. CI validates a
    fresh checkout of the tracked corpus, so an untracked schema/yaml pair
    sitting in the working tree — a scratch file, a stray backup — must not
    be discovered here either; otherwise the local hook blocks commits over
    files CI will never see.
    """
    tracked = _tracked_paths()
    pairs: list[tuple[Path, Path]] = []
    for schema in sorted(_SCHEMA_DIR.rglob("*.schema.json")):
        if schema.name == _MASTER_SCHEMA_NAME:
            continue
        if schema.as_posix() not in tracked:
            continue
        stem = schema.name.removesuffix(".schema.json")
        yaml_file = _YAML_DIR / schema.relative_to(_SCHEMA_DIR).parent / f"{stem}.yaml"
        if yaml_file.is_file() and yaml_file.as_posix() in tracked:
            pairs.append((schema, yaml_file))
    return pairs


def main(argv: list[str]) -> int:
    """Run check-jsonschema for every yaml/schema pair.

    Returns 0 if every pair validates cleanly, the first non-zero returncode
    otherwise. All pairs are attempted regardless of earlier failures so the
    user sees every error in one pass.
    """
    del argv  # framework passes no filenames; discovery is filesystem-based

    pairs = _find_pairs()
    if not pairs:
        return 0

    base_uri = f"file://{os.getcwd()}/risk-map/schemas/"
    exit_code = 0
    for schema, yaml_file in pairs:
        cmd = [
            "check-jsonschema",
            "--base-uri",
            base_uri,
            "--schemafile",
            str(schema),
            str(yaml_file),
        ]
        result = subprocess.run(cmd)
        if result.returncode != 0 and exit_code == 0:
            exit_code = result.returncode

    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
