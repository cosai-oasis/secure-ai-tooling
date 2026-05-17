# ADR-003: Devcontainer + `mise` tool-management architecture

**Status:** Accepted
**Date:** 2026-04-20
**Authors:** Architect agent, with maintainer review

---

## Context

Contributors to the CoSAI Risk Map need a working development environment with a specific, sometimes narrow, set of tool versions: a current Python interpreter, a current Node.js, uv, `ruff`, `check-jsonschema`, `pytest`, `prettier`, `mermaid-cli`, `act` (for running GitHub Actions locally), and Playwright Chromium (for Mermaid SVG regeneration). The cost of "set up your machine by hand" in this repository is real: CI, pre-commit hooks, and the validators under `scripts/` all assume these tools are present at compatible versions, and a mismatched local environment produces confusing diffs and failures during review.

The repository is also sensitive to two specific failure modes that a naive setup handles poorly:

1. **VS Code Server does not source `~/.bashrc`.** Tools installed into a user-level shim directory (the usual pattern for per-project version managers) are invisible to VS Code extensions unless the shim directory is injected into the Server process's `PATH` at container-start time. This surfaces as "Python interpreter not found" and "`ruff` command failed" errors that only appear in the editor, not in the terminal.
2. **Interactive prompts break unattended container builds.** `curl | sh` installers, `uv sync`, `npm install`, `sudo`, and `mise trust` all have interactive modes that can hang when stdin is not a terminal. A devcontainer `onCreateCommand` runs non-interactively, so any step that prompts stalls the entire container build with no useful error.

A contributor should be able to clone the repo, open the folder in VS Code (or in GitHub Codespaces), and have a verified working environment without running any manual commands. That requirement is what this ADR records.

The architecture already exists — it was introduced in commit `ff43aa4` ("feat(infra): Refactor of devcontainer and Dockerfile", 2026-02-06) and has iterated through subsequent work including the `pre-commit` framework adoption (PRs #211, #221, #222) and the current `feature/architect-adr-adoption` branch. Setup and day-to-day usage are documented procedurally in [`risk-map/docs/setup.md`](../../risk-map/docs/setup.md), which covers prerequisites, tool versions, `install-deps.sh` / `verify-deps.sh` invocation, and platform-specific notes. What that document does not capture is the *design rationale* — why `mise` over alternatives, why Docker-in-Docker, why `remoteEnv` for VS Code Server PATH handling, why idempotency and non-interactive flags in the install script, why the 177-test devcontainer suite is structured the way it is. This ADR captures the rationale, under the practice established by [ADR-001](001-adopt-adrs.md); `risk-map/docs/setup.md` captures how to use it.

## Decision

Use a **devcontainer-based development environment** with [`mise`](https://mise.jdx.dev/) as the single source of truth for tool versions.

Concrete shape:

- **Base image:** `ubuntu:noble` ([`.devcontainer/Dockerfile`](../../.devcontainer/Dockerfile)). System packages installed at build time cover build toolchain, common utilities, and the 31 shared libraries Chromium needs on Noble (with `t64` suffixes).
- **Tool versions declared in [`.mise.toml`](../../.mise.toml)** at the repo root. Currently Python `3.14`, Node.js `22`, and uv `0.11.14`. This file is the single source of truth: the Dockerfile, `install-deps.sh`, and `verify-deps.sh` all derive versions from it rather than hardcoding.
- **`mise` binary installed system-wide at build time** via `curl https://mise.run | MISE_INSTALL_PATH=/usr/local/bin/mise sh`, then Python and Node are installed into the `vscode` user's `mise` store inside the Dockerfile so interpreters exist before VS Code's Python extension activates. This eliminates a race condition where the extension would activate against a partially built container.
- **Devcontainer features** ([`.devcontainer/devcontainer.json`](../../.devcontainer/devcontainer.json)): `common-utils` (creates the `vscode` user and provides `sudo`) and `docker-in-docker` (lets the container build the devcontainer itself for meta-testing and run `act` locally).
- **Build context is the repo root** (`"context": ".."`) so the Dockerfile can `COPY .mise.toml` during build.
- **Dependency install is delegated to [`scripts/tools/install-deps.sh`](../../scripts/tools/install-deps.sh)** via `onCreateCommand`. The script is idempotent (pre-checks every tool, skips if present), supports `--dry-run` and `--quiet`, and runs every install step non-interactively. A thin back-compat wrapper at [`.devcontainer/setup-script`](../../.devcontainer/setup-script) delegates to the same script so existing docs and muscle memory keep working.
- **Verification is a separate script, [`scripts/tools/verify-deps.sh`](../../scripts/tools/verify-deps.sh)**, running roughly 18 named checks across installed tools. `install-deps.sh` invokes it as its final step. Keeping verification separate means a contributor can run `verify-deps.sh` at any time without re-running installs, and CI can use it as a fast smoke check.
- **PATH handling is explicit and layered:**
  - `install-deps.sh` appends `mise` shim `PATH` to `~/.bashrc` (idempotent, guarded by a marker string) so interactive shells resolve tools.
  - `remoteEnv` in `devcontainer.json` injects `/home/vscode/.local/share/mise/shims` and `/home/vscode/.local/bin` into the VS Code Server's process environment so extensions see the tools without a window reload.
  - `mise use -g python@<minor> node@<major>` sets global defaults so shims resolve from any working directory (VS Code extensions sometimes invoke tools from outside the project root, which otherwise yields "No version is set for shim").
  - `python.defaultInterpreterPath` in `devcontainer.json` uses the absolute path to the real Python binary (`/home/vscode/.local/share/mise/installs/python/latest/bin/python`), **not** the shim, because the Python extension cannot validate a shim as a real interpreter.

This architecture is load-bearing enough that it is covered by **roughly 177 tests across 8 dedicated test suites** under [`scripts/hooks/tests/`](../../scripts/hooks/tests/): `test_verify_deps.py` (20), `test_install_deps.py` (51), `test_mise_config.py` (16), `test_dockerfile.py` (26), `test_devcontainer_json.py` (30), `test_setup_script.py` (10), `test_setup_docs.py` (12), `test_precommit_hook_install.py` (12). Any change to the files above is expected to land with a test update in the same PR.

## Alternatives Considered

- **No devcontainer — plain `venv` + README instructions.** Rejected. Contributor onboarding cost is high, and reproducibility across maintainer and contributor machines is not enforceable. Diverging local environments produce CI-only failures that are hard to debug from a clean checkout. The Risk Map repo publishes tooling (validators, graph generators) that contributors run locally, so "it works on my machine" is a recurring failure mode we explicitly want to engineer out.

- **Nix or `devbox` for tool management.** Rejected. Both are technically stronger than `mise` for pinning, but team familiarity is low and the learning curve for a contributor who only wants to make a risk-content edit is non-trivial. GitHub Codespaces also has first-class support for devcontainers; `mise` integrates cleanly inside that surface, whereas Nix inside Codespaces is workable but idiosyncratic.

- **Direct `apt-get` in the Dockerfile for each tool (no `mise`).** Rejected. Ubuntu package versions lag upstream (notably for Python and Node). Pinning to declarative versions in `.mise.toml` means CI and local environments stay identical, and upgrading a tool is a one-line change to `.mise.toml` rather than a Dockerfile surgery. `mise` also handles the shim / `PATH` gymnastics described above, which an `apt`-installed tool does not.

- **Pipenv/Poetry for Python + `nvm` for Node + `asdf` for everything else.** Rejected. `mise` is `asdf`-compatible and unifies the three with a single `.mise.toml` file. The separate-tool path works, but it multiplies the number of config files (Pipfile, `.nvmrc`, `.tool-versions`) and the number of shells-init gotchas contributors have to learn. A single tool with one config file is load-bearing for keeping the onboarding story short.

## Consequences

**Positive**

- Contributors get a verified working environment by opening the repo in VS Code or Codespaces. No manual install steps; the `onCreateCommand` and `install-deps.sh` do the work.
- `.mise.toml` is the single source of truth for Python and Node versions. Upgrading either is a one-line change that flows through the Dockerfile, `install-deps.sh`, and `verify-deps.sh` uniformly.
- The VS Code integration issues (extension not finding Python, shims missing from Server environment, tools missing when working outside the project root) are each handled at the correct layer — `remoteEnv`, `mise use -g`, and the absolute-path interpreter setting — rather than left for each contributor to rediscover.
- Docker-in-Docker enables running `act` locally and meta-testing the devcontainer itself, which keeps the `scripts/hooks/tests/test_dockerfile.py` and `test_devcontainer_json.py` suites honest.
- `install-deps.sh` and `verify-deps.sh` are separately invocable, idempotent, and scriptable — they are as useful on a non-container host (for a contributor who cannot use a devcontainer) as they are inside the container.

**Negative**

- The architecture has several subtle, interacting pieces (`mise` shims, `.bashrc`, `remoteEnv`, global defaults, absolute interpreter path). A change that looks local — for example, switching the Python extension to use the shim path — can silently break editor integration without breaking terminal usage. The test suites mitigate this, but the cost of a wrong edit is real.
- **The `< /dev/null` non-interactive pattern has a narrow exception worth calling out explicitly.** `install-deps.sh` uses `< /dev/null` on commands like `uv sync` and `npm install` to neutralize stdin prompts. This pattern **must not** be applied to piped commands (`curl https://mise.run | sh`): redirecting stdin on the pipeline target overrides the pipe and the installer receives an empty script rather than the piped download. The script currently gets this right (see the `mise` install step and the `act` install step), but future edits that "fix" the apparent inconsistency will break container builds in ways that only reproduce on a clean rebuild. This caveat is the kind of thing an ADR is for.
- Adding a new tool to the environment is a multi-file change: `.mise.toml` (if versioned), `install-deps.sh` (install step), `verify-deps.sh` (check), and the matching tests. This is by design — the verification step and its test are the load-bearing guarantees — but it is a real authoring cost for one-off tools.
- Dependency on external install endpoints (`mise.run`, the `nektos/act` install script, Playwright's download CDN) means a container build is only as reliable as those endpoints. Mitigated by idempotency (a partial failure does not corrupt state) and by the Docker layer caching the `mise` binary install, but a fully offline build is not currently supported.

**Follow-up**

- [ADR-005](005-pre-commit-framework.md) captures the **pre-commit framework adoption** that landed in PRs #211, #221, #222 as its own decision. It layers on top of this one but has its own rationale (framework vs. hand-rolled hooks, the removed parity gate).
- If the repo ever adopts an offline / airgapped build path, that is a new decision that either supersedes parts of this ADR or introduces a companion one. Out of scope here.
- Add the `install-deps.sh --dry-run` hint to [`risk-map/docs/setup.md`](../../risk-map/docs/setup.md) so contributors can inspect what the container will do without reading the script itself. Keep `setup.md` and this ADR in sync if the architecture changes — `setup.md` documents the procedure; this ADR documents the decision.
