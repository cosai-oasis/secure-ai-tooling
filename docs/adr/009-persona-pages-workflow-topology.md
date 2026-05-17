# ADR-009: GitHub Pages deploy surface and persona-pages workflow topology

**Status:** Accepted
**Date:** 2026-04-21
**Authors:** Architect agent, with maintainer review

---

## Context

The persona Pages MVP (PR #223) needed a way to ship a static browser-side explorer — HTML, CSS, and ES modules under `site/` — that consumes framework data out of `risk-map/yaml/` through a Python builder. The MVP had to answer three coupled questions at once: *where* does it publish, *how* is the build/deploy pipeline shaped, and *with what authority* does it run in CI. The `site/` directory location is settled separately in [ADR-010](010-site-repo-root-module-boundary.md); this ADR covers the publishing, pipeline-shape, and authority questions together.

The MVP's initial workflow (`48565ca` / `e0dd0bb` / `0ccd701` triple, file `.github/workflows/persona-pages.yml`) already made several correct choices — deploy-from-`main` only, OIDC via `actions/deploy-pages@v4` rather than a PAT, `pull_request` (not `pull_request_target`), no secrets in `run:` blocks. The review captured the positive baseline explicitly: "GitHub Pages deploys via OIDC with correctly scoped permissions" (review §1, line 17; §9 "Correctness posture is strong").

The initial workflow also had specific gaps the review called out and which an in-PR hardening sweep (`03509eb`, "ci: harden persona-pages workflow permissions, timeouts, and summary") closed before merge:

- **Workflow-level permissions were too broad.** `pages: write` and `id-token: write` were granted at workflow scope, which meant the `build` job — a third-party action surface — inherited deploy authority it did not need (`REC-01`).
- **No per-job `timeout-minutes`.** A hung job would run to GitHub's 360-minute default (`REC-03`).
- **A single fixed `concurrency` group shared across refs** with unconditional `cancel-in-progress: true`, so a push to `main` would cancel in-flight PR builds and an author might never see their own CI result (`REC-05`).
- **No aggregator job.** The five sibling workflows in this repo define a `validation-summary` step; persona-pages didn't (`REC-28`).
- **`cp -R risk-map/site/. _site/` copied hidden files** like `.DS_Store` and `.gitignore` into the Pages artifact (`NIT-03`).
- **The `paths:` filter omitted `risk-map/schemas/**`**, so a schema change that reshapes YAML wouldn't trigger a rebuild (`REC-06`).
- **The `pull_request` trigger only watched `branches: [main]`**, missing the `develop → main` content-PR flow that `CONTRIBUTING.md` establishes and that the four sibling workflows already include (`REC-02`).

The hardening landed in the MVP PR itself, not as a fast-follow — the review's triage table (§3.1a) marks all seven workflow verdicts as APPLY and the implementation plan's Phase 5 executed them together. `5462ac2` ("ci: correct pages-summary deploy output and PR row display") followed to fix a rendering bug in the summary's "n/a (PRs don't deploy)" handling; it confirms that `pages-summary` is part of the intended topology rather than a debugging artifact.

This ADR captures the resulting shape retroactively, under the practice established by [ADR-001](001-adopt-adrs.md).

## Decision

GitHub Pages is the CoSAI Risk Map Explorer's deploy surface, served by a three-job workflow at `.github/workflows/persona-pages.yml` that splits build, deploy, and reporting concerns so each can hold the minimum authority it needs.

Concrete shape:

- **Publish surface.** GitHub Pages, deployed via OIDC using `actions/deploy-pages@v4`. No PAT, no long-lived secret. Pages is `configure-pages`-enabled from the workflow (`enablement: true`) so first-run setup is declarative.
- **Deploy gate.** The `deploy` job runs only when `github.event_name != 'pull_request' && github.ref == 'refs/heads/main'`. PRs build and run tests for preview-equivalent validation but never deploy. `workflow_dispatch` on `main` is permitted (the gate excludes PRs rather than requiring `push` specifically).
- **Job topology.** Three jobs, not one:
  - **`build`** — checks out sources, installs Python and Node toolchains, runs `pytest scripts/hooks/tests/test_build_persona_site_data.py` and `node --test site/tests/*.test.mjs`, assembles `_site/` via `rsync -a --exclude='.DS_Store' --exclude='.gitignore' site/ _site/`, runs the persona-data builder (`scripts/build_persona_site_data.py --site-dir _site`), and uploads the Pages artifact. Steps that talk to Pages infrastructure (`configure-pages`, `upload-pages-artifact`) are gated with `if: github.event_name != 'pull_request'`.
  - **`deploy`** — consumes the artifact `build` produced, calls `actions/deploy-pages@v4`, and records `page_url` as a job output for downstream jobs.
  - **`pages-summary`** — `needs: [build, deploy]` with `if: always()`, writes a markdown table of job results to `$GITHUB_STEP_SUMMARY`, and includes the deployed URL when `deploy` succeeded. It renders `"n/a (PRs don't deploy)"` for the deploy row on PR runs so the skipped-job state is not mis-read as a failure.
- **Least-privilege permissions.** Workflow-level `permissions: contents: read`. `build` redeclares `contents: read` explicitly. `pages: write` and `id-token: write` are scoped to the `deploy` job only. `pages-summary` takes `contents: read`. The blast radius of any compromised third-party action in `build` is therefore "read source and fail a build," not "deploy to Pages."
- **Operational hardening.**
  - `timeout-minutes: 10` on `build`, `5` on `deploy`. Hung work aborts promptly rather than consuming the 360-minute default.
  - Per-ref `concurrency` group: `group: persona-pages-${{ github.ref }}`, `cancel-in-progress: ${{ github.event_name == 'pull_request' }}`. PR pushes supersede earlier PR builds on the same ref; `main` deploys are never cancelled mid-flight.
  - `paths:` filter covers the full input surface: the workflow file itself, `site/**`, the three consumed YAMLs (`personas.yaml`, `risks.yaml`, `controls.yaml`), `risk-map/schemas/**`, `risk-map/docs/persona-pages.md`, the Python builder and its tests, `pyproject.toml`, `uv.lock`, and both READMEs. The same list is mirrored between the `pull_request` and `push` triggers (duplication accepted — `NIT-02` DEFER).
- **Reporting surface.** `pages-summary` is the single reporting entry point. Status and deployed URL surface in the GitHub Actions UI via `$GITHUB_STEP_SUMMARY`; there is no separate PR-comment bot or external webhook.

## Alternatives Considered

- **Deploy from any branch (including PR refs).** Rejected: PR previews would leak WIP content publicly, and a Pages environment that tracks whichever ref last pushed is indistinguishable to external visitors from the canonical site. Gating deploy on `github.ref == 'refs/heads/main'` and allowing PRs to build (but not upload) preserves the preview-validation benefit without the leak.
- **Single-job workflow** (`build-and-deploy` together). Rejected: conflates three concerns (artifact production, authority-bearing deploy, post-run reporting) into one permissions scope. Either the whole job runs with `pages: write` / `id-token: write` — re-opening the `REC-01` blast-radius problem — or the deploy step runs under elevated perms it cannot scope away. Splitting is the only way least-privilege works here.
- **Token-based deploy (PAT or `GITHUB_TOKEN` with `pages: write`).** Rejected: `actions/deploy-pages@v4` + OIDC is the modern GitHub Pages default, avoids credential storage, and produces attestable deploys. A PAT would expand the secret surface for no capability gain.
- **Fixed `concurrency` group with `cancel-in-progress: true` everywhere** (the initial MVP shape). Rejected by `REC-05`: a push to `main` would cancel any concurrent PR build on an unrelated ref, making PR CI results unreliable. Keying on `github.ref` isolates PRs from each other and from `main`; gating `cancel-in-progress` on the event type protects in-flight deploys from being cancelled by a follow-up commit.
- **`cp -R site/. _site/` for artifact staging** (initial MVP). Rejected by `NIT-03`: `cp -R` copies `.DS_Store`, `.gitignore`, and any other dotfiles into the published artifact. `rsync -a --exclude` names the excluded dotfiles explicitly; `git archive HEAD:site | tar -x -C _site` was an equivalent alternative considered in the plan (Phase 5, step 6). `rsync` was chosen for readability; either would have closed the finding.
- **No aggregator job; rely on the Actions UI per-job badge.** Rejected by `REC-28`: every sibling workflow in this repo (`validation.yml`, `validate_mermaid.yml`, `validate_tables.yml`, `validate-issue-templates.yml`) defines a summary job. Diverging here would make the persona-pages workflow the odd one out for maintainers scanning run summaries and would lose the explicit "n/a (PRs don't deploy)" disambiguation that `pages-summary` contributes.
- **Broader workflow-level permissions with per-job narrowing** (the initial MVP shape). Rejected: GitHub Actions permissions compose by replacement, not intersection, but a broad top-level still sets expectations for any contributor adding a step. Declaring `contents: read` at the top and granting elevation only where it is actually used is legible as well as safe.

## Consequences

**Positive**

- **Blast radius is bounded.** A compromised third-party action in `build` can read repo contents and fail a run; it cannot deploy to Pages. The `deploy` job's authority is the entire `id-token` / `pages` write surface and is the only job that holds it.
- **PRs get preview-equivalent validation without leaking.** PR runs exercise the full build path, run Python and Node tests, and assemble `_site/`; they just stop short of `upload-pages-artifact` and `deploy-pages`. Contributors see whether their change would deploy cleanly without publishing anything.
- **Schema changes trigger rebuilds.** Adding `risk-map/schemas/**` to both trigger lists means a schema edit that reshapes downstream YAML cannot silently slip past the Pages build.
- **Concurrency is safe in both directions.** PR supersession avoids stale PR builds; the `main` `cancel-in-progress: false` protects in-flight deploys from being clobbered by the next push.
- **Summary job disambiguates skipped vs. failed.** Without `pages-summary`'s explicit `"n/a (PRs don't deploy)"` handling, a PR run's skipped deploy shows as `skipped` alongside test failures, which reads as a pipeline problem rather than a designed outcome.

**Negative**

- **Three jobs mean three `actions/checkout` opportunities and three scheduling hops.** `pages-summary` doesn't check out, but the split does mean slightly longer wall-clock than a single-job workflow. The security posture is worth it.
- **`paths:` lists are duplicated** between the `pull_request` and `push` triggers. `NIT-02` accepted the duplication; any future path addition must be made in both places, and the two lists can drift.
- **Actions are pinned to mutable major tags** (`actions/checkout@v6`, `actions/setup-python@v6`, `actions/deploy-pages@v4`, etc.), not SHAs. This matches the repo-wide convention at the time (`NIT-01` marked OUT-OF-SCOPE pending a separate repo-wide SHA-pin PR); when that repo-wide change lands, this workflow participates.
- **`workflow_dispatch` on `main` deploys.** The gate is `event_name != 'pull_request'`, not `event_name == 'push'`, so a manual dispatch on `main` will publish. This is intended — manual re-deploys are useful for recovery — but it is broader than a strict `push`-only gate.
- **Supply-chain surface is what `deploy-pages@v4` pulls in.** OIDC trust and the deploy action itself are now on the repo's critical path for site publication. The action is GitHub-maintained, but a regression there affects deploy.

**Follow-up**

- **Pinning to SHAs.** When the repo-wide SHA-pin PR (`NIT-01`) lands, apply it to this workflow in the same sweep. A separate ADR is not needed unless the pinning posture diverges from other workflows.
- **PR-comment surface.** If contributors want in-thread deploy status (for example, when preview deploys are introduced later), that will need `pull-requests: write` scoped to a dedicated comment job — not to `pages-summary`, which deliberately holds `contents: read` only. Evaluate as a separate ADR when proposed.
- **Preview deploys.** If PR branches eventually deploy to preview URLs (a different `environment:` than `github-pages`), the publish-surface decision in this ADR is revisited, not extended — preview deploys change the "deploy only from `main`" invariant.
- **Trigger-list drift.** A lint or structural test that asserts the `pull_request` and `push` `paths:` arrays stay equal would eliminate the drift risk `NIT-02` accepted; not worth writing today, worth revisiting if a divergence bug ships.
- **Schema integrity at build time.** The workflow runs the Python builder against live YAML; schema validation itself is a pre-commit concern (see [ADR-005](005-pre-commit-framework.md)) and the builder output contract is tracked separately (ADR-011).
