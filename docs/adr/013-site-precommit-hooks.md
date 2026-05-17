# ADR-013: Extend the `pre-commit` framework with `site/**` hooks

**Status:** Accepted
**Date:** 2026-04-21
**Authors:** Architect agent, with maintainer review

---

## Context

The persona Pages MVP (PR #223) added a new build surface at `/site/` — browser-side ES modules, CSS, HTML, and a Python builder (`scripts/build_persona_site_data.py`) that emits JSON consumed by that renderer. The surface is governed at a module-boundary level by [ADR-010](010-site-repo-root-module-boundary.md) (location) and at a data-contract level by [ADR-011](011-persona-site-data-schema-contract.md) (schema). The PR #223 review surfaced two pre-commit coverage gaps in §8:

- **[REC-07]** — a YAML or builder edit that broke the persona-site pipeline was only caught in CI. `BLOCK-02` in the same review would have been caught locally if a pre-commit gate had re-run the builder against staged inputs.
- **[REC-08]** — `.mjs`, `.css`, `.html`, and `.md` under `site/**` had no local formatter. Prettier was configured but scoped to `risk-map/yaml/**`, so stylistic drift on the new surface would accumulate commit-by-commit.

[ADR-005](005-pre-commit-framework.md) adopted `pre-commit` as the single orchestration layer for repository-wide git hooks, and its Follow-up (line 96) left one open question:

> If the repository adds a non-Python orchestration surface in the future (for example, a site build under `risk-map/site/`), confirm that `pre-commit` remains the right orchestration layer for that surface or document the split explicitly.

[ADR-010](010-site-repo-root-module-boundary.md) superseded the *path* in that follow-up (`risk-map/site/` → `/site/`) but explicitly left the *orchestration* question open. This ADR resolves it: `pre-commit` remains the right layer for the new surface, extended via two new local hooks.

The primary evidence commit is `93cc22b` — "feat(hooks): add persona-site builder and site-assets prettier hooks" — which adds both hook entries to `.pre-commit-config.yaml`, both wrapper modules under `scripts/hooks/precommit/`, and their tests under `scripts/hooks/tests/`.

## Decision

Keep `pre-commit` as the sole orchestration layer and extend it with two new local hooks for `site/**`. The hooks land under the existing `- repo: local` block in [`.pre-commit-config.yaml`](../../.pre-commit-config.yaml) alongside `prettier-yaml`.

**`validate-persona-site-build`** — wrapper [`scripts/hooks/precommit/validate_persona_site_build.py`](../../scripts/hooks/precommit/validate_persona_site_build.py). Runs the persona-site builder end-to-end (`load_yaml` → `build_site_data` → `write_site_data`) into a `tempfile.TemporaryDirectory`, catching schema-validation failures and builder regressions at commit time rather than at CI time. Configuration:

- `language: system`, `entry: uv run --locked --no-sync python scripts/hooks/precommit/validate_persona_site_build.py`.
- `pass_filenames: false` — the wrapper does not operate per-file; it rebuilds the whole pipeline once regardless of which trigger fired. `argv` is discarded by contract.
- `files:` matches `risk-map/yaml/(personas|risks|controls).yaml`, `risk-map/schemas/(risks|persona-site-data).schema.json`, and `scripts/build_persona_site_data.py` — every input the builder reads and the code that reads them.
- Failure surfaces a single stderr line of the form `Persona-site builder failed: <ExceptionType>: <message>` and exits `1`.

**`prettier-site-assets`** — wrapper [`scripts/hooks/precommit/prettier_site_assets.py`](../../scripts/hooks/precommit/prettier_site_assets.py). Auto-format ("Pattern A") over `site/**` frontend assets, mechanically identical to `prettier-yaml`. Configuration:

- `language: system`, `entry: uv run --locked --no-sync python scripts/hooks/precommit/prettier_site_assets.py`.
- `files: ^site/.*\.(mjs|css|html|md)$`, `pass_filenames: true`.
- `require_serial: true` — matches the `regenerate-*` generators in the same config. The wrapper runs `npx prettier --write <path>` followed by `git add <path>` per file, and parallel batches would race over `.git/index.lock` (the same mechanism ADR-005 calls out for auto-staging hooks).
- Style reconciliation lives in [`.prettierrc.yml`](../../.prettierrc.yml): the repo-wide defaults are `singleQuote: true, semi: false`, but two per-file overrides set `site/**/*.{mjs,js}` to `singleQuote: false, semi: true, trailingComma: 'all'` (standard JS convention) and disable `embeddedLanguageFormatting` on `site/**/*.md` so documented code samples stay faithful to the real files. The overrides were landed in the same commit range as the hook.

The files themselves were normalized during the MVP's BLOCK-05 work, so the first run of `prettier-site-assets` on the branch produced no churn.

## Alternatives Considered

- **CI-only validation.** Rejected on the same grounds ADR-005 rejected "no hooks at all": schema and builder errors are cheap to catch locally (the builder runs sub-second) and expensive to catch at PR time after push and reviewer assignment. Pre-commit is the cheap local gate; CI remains the authoritative final gate.
- **Ignore site-asset formatting.** Rejected per [REC-08]. The MVP added ~1,020 lines of `.mjs`, ~567 lines of CSS, and ~35 lines of HTML in a single PR; stylistic drift on that volume would accumulate commit-by-commit without a local formatter, and deferring it to manual review is a standing tax on every future `site/**` edit.
- **Extend `prettier-yaml` to cover site assets.** Rejected. The two hooks operate on different file types with different style rules — YAML at the repo-wide defaults, `.mjs` under the per-file `singleQuote: false, semi: true` override. Overloading one hook would either force a single regex to match both shapes or force both file types to share a style configuration they do not share. Splitting the hooks matches the `.prettierrc.yml` split.
- **Framework-packaged `prettier` hook (e.g., `mirrors-prettier`, `rbubley/mirrors-prettier`).** Rejected for the same reason ADR-005 rejected it for `prettier-yaml`: `language: system` with `npx prettier` reuses the project's already-pinned Node environment and `.prettierrc.yml`, avoiding a second prettier version to track and avoiding a new `additional_dependencies` surface.
- **Framework-installed Python environment (`language: python` + `additional_dependencies`) for `validate-persona-site-build`.** The PR #223 implementation plan initially proposed pinning `PyYAML==6.0.3` and `jsonschema==4.26.0` under `additional_dependencies` with `language: python`, which would have created an isolated pre-commit venv for the hook. Rejected in favor of `language: system` because `pyproject.toml` and `uv.lock` already pin `jsonschema==4.26.0` as part of ADR-011's contract, and `validate_persona_site_build` imports `scripts.build_persona_site_data` directly — a separate framework-installed venv would shadow the project venv and could drift from `uv.lock`. `language: system` reuses the single source of truth and preserves ADR-005's "local hooks run in the project's own Python environment" boundary. The material cost of this choice is a `sys.path` splice in the wrapper (see Consequences).
- **Build into `site/generated/` in the working tree and diff it back.** Rejected for `validate-persona-site-build`. A working-tree build would either leak generated JSON into the repo (fighting `site/generated/`'s gitignored status) or require teardown logic that races with parallel framework invocations. `tempfile.TemporaryDirectory()` isolates the build fully: the hook writes to `<tmp>/site/<output>` via the builder's own `resolve_output_path`, the directory is cleaned up by the context manager, and a test (`test_validate_persona_site_build.py`) asserts the repo `site/generated/` stays untouched.

## Consequences

**Positive**

- **Builder drift is caught locally.** Any edit to `personas.yaml`, `risks.yaml`, `controls.yaml`, the risks or persona-site-data schema, or the builder itself re-runs the full pipeline before the commit lands. BLOCK-02-class defects (stringified nested lists silently flowing into the DOM) are now a pre-commit failure, not a CI failure.
- **Site asset formatting is consistent by construction.** Auto-format on every commit means no reviewer spends cycles on prettier diffs, and the `.mjs` convention (double quotes, semicolons, trailing commas) stays stable under edits by contributors who default to the repo-wide YAML style.
- **ADR-005's open question is closed.** `pre-commit` covers the new non-Python surface via `language: system` local hooks. No split orchestration layer is needed; the existing framework extends cleanly.
- **Consistent with prior patterns.** `require_serial: true` on `prettier-site-assets` matches the generators in the same config and the mechanism ADR-005 documents; the wrapper's body is structurally identical to `prettier_yaml.py`; `TemporaryDirectory` isolation mirrors what any sandboxed build would do.

**Negative**

- **Two more hooks for contributors to understand.** The `.pre-commit-config.yaml` already encoded `pass_filenames`, `require_serial`, and regex-filter semantics; ADR-005 flagged this learning curve. The new hooks add nothing novel but extend the surface area by two entries.
- **`validate-persona-site-build` imports the builder module directly.** `scripts.build_persona_site_data` is now load-bearing for pre-commit: a refactor that changes `load_yaml`, `build_site_data`, `write_site_data`, `resolve_output_path`, or the `DEFAULT_*_PATH` module constants will break the hook. The hook's tests assert the contract, but the coupling is real.
- **`language: system` requires a `sys.path` splice in the wrapper.** `scripts/hooks/precommit/validate_persona_site_build.py` lines 15–18 insert the repo root onto `sys.path` before importing `scripts.build_persona_site_data`, because `language: system` does not install `scripts/` as a proper package. The splice is the material cost of the venv-reuse choice above; a future move to `language: python` would need to drop it in favor of a properly installed package (and re-accept the venv-drift risk the current design avoided).
- **`npx prettier` invocation cost on `site/**` edits.** Each staged file spawns an `npx` process. For the current MVP-sized surface this is negligible; if `site/**` grows materially, a batched invocation (one `npx prettier --write` call with all paths) would be cheaper. The wrapper's current shape matches `prettier_yaml.py`; if one is batched later, the other should follow for consistency.
- **`first-failure-wins` exit semantics are soft contract.** Both wrappers preserve the earliest non-zero returncode and continue through remaining files; a contributor reading only the final stderr may miss later failures. `prettier_yaml.py` has the same property, so the behavior is consistent, but it is not loud.

**Follow-up**

- **Closes ADR-005 line 96.** The substantive question — is `pre-commit` the right orchestration layer for a non-Python site build — is resolved in the affirmative. If a future consumer surface proposes a radically different toolchain (for example, a Vite or esbuild pipeline that wants its own hook runner), revisit this ADR explicitly rather than extending local hooks unbounded.
- **Cross-refs to peer ADRs.** `validate-persona-site-build` enforces the contract ADR-011 defines; its `files:` regex names the schemas ADR-011 authors. The `site/**` globs it uses depend on ADR-010's module boundary. If ADR-011's schema is renamed, update this hook's `files:` regex in the same change.
- **Test coverage on the hook tests.** `test_validate_persona_site_build.py` and `test_prettier_site_assets.py` were authored TDD-first per the MVP implementation plan (phase 6). If either wrapper's behavior changes (for example, a move to batched `npx` invocation), those tests are the contract to update first.
