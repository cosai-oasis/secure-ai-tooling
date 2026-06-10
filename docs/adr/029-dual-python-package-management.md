# ADR-029: Dual Python package-management path with `uv` devcontainers

**Status:** Draft
**Date:** 2026-06-06
**Authors:** Architect agent, with maintainer review

---

## Context

Issue [#159](https://github.com/cosai-oasis/secure-ai-tooling/issues/159) proposes replacing `pip` with [`uv`](https://docs.astral.sh/uv/) across the repository's Python dependency-management surface. The issue was filed because [`scripts/tools/install-deps.sh`](../../scripts/tools/install-deps.sh) installs packages with `python3 -m pip install -r requirements.txt`, while [`scripts/tools/verify-deps.sh`](../../scripts/tools/verify-deps.sh) later verifies them with `python3 -m pip show`. In environments mediated by `mise` shims, those two commands can resolve to different Python package locations, so verification can report packages missing after installation succeeded.

The current repository is intentionally scriptable outside the devcontainer. [ADR-003](003-devcontainer-mise-architecture.md) makes `install-deps.sh` and `verify-deps.sh` separately invocable for contributors who cannot or do not use the VS Code devcontainer. [`requirements.txt`](../../requirements.txt) is the current Python dependency input; [`pyproject.toml`](../../pyproject.toml) only holds pytest and coverage configuration; [`.github/dependabot.yml`](../../.github/dependabot.yml) tracks Python dependencies through the `pip` ecosystem; and workflows such as [`.github/workflows/validate_python.yml`](../../.github/workflows/validate_python.yml) install from `requirements.txt`.

The scope this ADR records is narrower than the original issue proposal: the repository should not force every contributor to adopt `uv` instead of `pip`. The devcontainer can be opinionated because it is the repository-managed bootstrap path, but contributors working outside the container should have a supported choice between the existing `pip` path and a `uv` path.

The decision also has to preserve the pre-commit architecture. [ADR-005](005-pre-commit-framework.md) adopts the `pre-commit` framework, and [ADR-013](013-site-precommit-hooks.md) deliberately keeps local hooks on `language: system` so they use the project's Python environment instead of isolated pre-commit-managed virtual environments. A `uv` implementation that syncs packages into `.venv` but leaves hook execution resolving `python3` from the ambient shell would only move the mismatch from install/verify into commit-time validation.

This ADR is a tooling/infrastructure decision under [ADR-002](002-branching-strategy.md): it targets `main`, not `develop`.

## Decision

Adopt a **dual Python package-management path**: the devcontainer uses `uv` with a repo-local virtual environment, while non-container contributors may choose either `pip` or `uv`.

Concrete shape:

- `requirements.txt` remains the shared dependency input for this decision.
- The devcontainer invokes `install-deps.sh` in `uv` mode.
- `install-deps.sh` and `verify-deps.sh` expose an explicit package-manager selector.
- Verification and pre-commit installation use the same Python environment selected during installation.
- CI, tests, and documentation keep both modes real.

### D1. Keep `requirements.txt` as the dependency input

Python development dependency pins remain in [`requirements.txt`](../../requirements.txt). Both package-management modes consume that file:

- `pip` mode installs with `python3 -m pip install -r requirements.txt`.
- `uv` mode creates or reuses a repo-local `.venv` and syncs the same input with `uv`'s pip-compatible interface, for example `uv venv` followed by `uv pip sync requirements.txt`.

This ADR does **not** migrate dependencies into `[project.dependencies]`, introduce `uv.lock`, or remove `requirements.txt`. Those are packaging and lockfile decisions, not prerequisites for fixing issue #159. A future change may revisit them, but it must update or supersede this ADR rather than folding that migration into the bootstrap fix.

### D2. Use `uv` unconditionally in the devcontainer

The devcontainer path uses `uv` for Python package installation and package verification. `uv` is declared as a `mise`-managed tool in [`.mise.toml`](../../.mise.toml), and [`.devcontainer/devcontainer.json`](../../.devcontainer/devcontainer.json) invokes:

```bash
bash scripts/tools/install-deps.sh --python-package-manager uv
```

If `uv` is unavailable on the devcontainer path, `install-deps.sh` fails with an actionable error. It does not silently fall back to `pip`, because fallback would preserve the exact class of mismatch issue #159 is trying to remove from the managed bootstrap path.

### D3. Make the non-container choice explicit

Outside the devcontainer, `install-deps.sh` and `verify-deps.sh` support:

```bash
./scripts/tools/install-deps.sh --python-package-manager pip
./scripts/tools/install-deps.sh --python-package-manager uv
./scripts/tools/verify-deps.sh --python-package-manager pip
./scripts/tools/verify-deps.sh --python-package-manager uv
```

The non-container default remains `pip` to preserve the existing contributor path. Contributors opt into `uv` explicitly. `install-deps.sh` passes the selected mode through to its final verification step so installation and verification inspect the same package location.

### D4. Bind install, verify, and hook execution to the selected Python environment

`uv` mode is not complete when `.venv` merely exists. Commands that depend on installed Python packages must run through the selected environment:

- package verification checks packages from `.venv` in `uv` mode and from the ambient selected `python3` in `pip` mode;
- pre-commit installation runs through the selected Python environment, not a different interpreter;
- commit-time local hooks declared with `language: system` continue to resolve the same dependency environment that was verified.

The implementation may satisfy the last point by putting `.venv/bin` first on the hook execution `PATH`, by using environment-aware wrapper entries, or by another repo-local mechanism. The architectural requirement is that `uv` mode does not leave `language: system` hooks resolving an unpopulated ambient Python.

### D5. Keep both modes covered by tests, CI, and documentation

Tests cover `pip` mode, `uv` mode, mode selection, devcontainer forced-`uv` behavior, and mode-aware verification. Documentation in [`scripts/docs/setup.md`](../../scripts/docs/setup.md) and [`risk-map/docs/setup.md`](../../risk-map/docs/setup.md) shows both non-container package-management choices and states that devcontainers use `uv`.

CI may continue to use `pip` from `requirements.txt`. A future workflow may adopt `uv` for speed or parity with the devcontainer, but the repository must retain automated coverage for the `pip` path as long as `pip` remains a supported contributor choice.

## Alternatives Considered

- **Replace `pip` entirely with `uv sync`, move dependencies into `pyproject.toml`, add `uv.lock`, and remove `requirements.txt`.** Rejected because it forces every contributor and every dependency-update workflow onto `uv`. It also turns a bootstrap reliability fix into a packaging-format migration for a repository that is not currently modeled as an installable Python package.
- **Keep the current pip-only bootstrap and fix PATH ordering around `mise` shims.** Rejected because it treats the current failure as a shell-ordering bug rather than an environment-contract bug. The devcontainer would still depend on ambient interpreter resolution for install and verify.
- **Add `uv` as an optional helper but keep the devcontainer on `pip`.** Rejected because the devcontainer is the managed path and should be the most deterministic path. Leaving it on `pip` preserves the failure mode where new contributors are most likely to encounter it.
- **Maintain parallel dependency manifests for `pip` and `uv`.** Rejected because two editable sources of truth invite drift. `requirements.txt` is already consumed by scripts, CI, docs, tests, and Dependabot; `uv` can consume the same input through its pip-compatible interface.

## Consequences

**Positive**

- Devcontainer bootstrap uses one repo-local Python environment for package install, package verification, and hook setup.
- Contributors outside the devcontainer keep the existing `pip` workflow while gaining an explicit `uv` option.
- `requirements.txt` remains the dependency source of truth, so the issue #159 implementation does not need to redesign packaging metadata or dependency-update automation.
- The decision preserves ADR-003's reusable script surface while making the devcontainer path deterministic.

**Negative**

- The scripts, tests, and docs now carry two Python package-management modes.
- `pip` mode can still inherit ambient-interpreter problems on a contributor's machine. That is the accepted cost of keeping `pip` as a supported non-container choice.
- `uv` becomes a new `mise`-managed tool dependency in the devcontainer supply chain. Version pinning and upgrade cadence should be reconciled with the reserved devcontainer dependency-pinning policy in ADR-023.
- The `language: system` pre-commit hooks make the implementation sharper than a simple installer swap. The selected Python environment has to be visible at commit time, not only during `install-deps.sh`.

**Follow-up**

- Implement D1-D5 across `.mise.toml`, `.devcontainer/devcontainer.json`, `.gitignore`, `install-deps.sh`, `verify-deps.sh`, setup docs, and the relevant script/devcontainer tests.
- Add or update tests for mode selection, `.venv` creation, mode-aware package verification, devcontainer forced-`uv` behavior, pre-commit installation through the selected environment, and preservation of the `pip` path.
- If a future change wants `[project.dependencies]`, `uv.lock`, or `uv sync` as the repository-wide dependency source of truth, write a follow-up ADR or explicitly supersede this one.
