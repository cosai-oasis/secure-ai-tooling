# ADR-025: Testing strategy and posture across Python, site JS, schemas, and infrastructure

**Status:** Accepted
**Date:** 2026-05-05
**Authors:** Architect agent, with maintainer review

---

## Context

The repository has accumulated multiple distinct testing surfaces — Python pytest under `scripts/hooks/tests/`, site Node tests under `site/tests/`, schema validation orchestrated by `pre-commit`, a doc-test fenced-block harness for `risk-map/docs/*.md`, the pre-commit framework itself, six CI workflows under `.github/workflows/`, and the devcontainer plus `mise` tool-pinning surface. Sibling ADRs decide individual surfaces in isolation: [ADR-005](005-pre-commit-framework.md) (pre-commit framework), [ADR-011](011-persona-site-data-schema-contract.md) (persona-site-data schema contract), [ADR-012](012-static-spa-architecture.md) (static SPA, `node --test`), [ADR-013](013-site-precommit-hooks.md) (site pre-commit hooks), and [ADRs 018-022](018-components-schema.md) (per-schema designs). No ADR records the testing strategy as a whole.

Two recent events made the gap concrete. First, a stub tracking issue ([#252](https://github.com/cosai-oasis/secure-ai-tooling/issues/252)) was filed on 2026-04-29 to capture cross-surface posture questions that no single sibling ADR resolves: RED-phase TDD codification, contributor invocation surface, `act` adoption posture, devcontainer build verification, lint scope, coverage policy, and CI/local parity. Second, the A4 sub-PR ([#277](https://github.com/cosai-oasis/secure-ai-tooling/pull/277)) full-branch review surfaced two cases where validators were defined and unit-tested but never invoked from any execution path — `check_lifecycle_stage_order_uniqueness` was not called from `validate_riskmap.py`, and `emit_missing_category_warnings` was not called from `BaseGraph.__init__`. The decision-bound fix landed in commit `069c3a4` on `feature/A4-validator-extensions`. The miss class — "function exists with passing unit tests" not equal to "function runs in CI" — is a testing-strategy concern that none of the per-surface ADRs cover.

This ADR records the project's testing strategy and posture across all surfaces, resolves the open posture questions, and pre-splits two adoption questions (`act`, devcontainer build verification) into named-trigger follow-ups rather than legislating them now. Schema validation is governed by ADRs 018-022 and runs as a pre-commit hook orchestrated by ADR-005; this ADR cites that surface and does not re-decide it.

## Decision

The project commits to a layered testing strategy: unit tests for Python wrappers and pure-logic site JS, schema validation as a co-equal correctness axis, a doc-test harness for `risk-map/docs/*.md`, RED-phase TDD discipline for agent-mediated work, three named contributor invocation surfaces, deferral with named triggers for adoption-pending surfaces, per-file coverage policy, explicit CI/local divergence, and a wire-up requirement that links new validators and runtime warnings to an execution path.

### D1. Testing pyramid scope

The project commits to **unit tests, schema validation as a co-equal axis, and doc-tests**, with no integration or end-to-end testing in the conventional sense.

- **Unit** — Python wrappers under `scripts/hooks/precommit/` and validators under `scripts/hooks/`, and pure-logic site modules (the pure-input-output module under `site/assets/`, exercised by `node --test`). DOM-touching site code is explicitly not unit-tested per ADR-012's progressive-enhancement posture.
- **Schema validation** — orthogonal correctness axis, not a "level" in the pyramid. Governed by ADRs 018-022 and orchestrated by ADR-005. The persona-site builder hook (ADR-013) exercises producer/consumer ends of the ADR-011 contract end-to-end on every commit that touches any input.
- **Doc-tests** — first-class but narrowly scoped to `risk-map/docs/*.md` fenced blocks (see D3).

The project explicitly declines integration and end-to-end test surfaces in the conventional sense: the schema-validation axis already covers the interface boundaries that integration tests would cover, and CI itself running the full hook plus workflow set is the closest the repository comes to end-to-end. New work that asks for a "real integration test" is asking for either a schema invariant or a builder-level test that fits an existing pattern; the framing is in this ADR, not in a new test surface.

### D2. RED-phase TDD codification

RED-phase Test-Driven Development — failing tests authored before the implementation that satisfies them — is **required for agent-mediated implementation work** and **encouraged but not required for human-authored work**.

The agent-mediated enforcement lives in [`scripts/agents/testing.md`](../../scripts/agents/testing.md), which fixes the testing agent's contract as authoring the Red phase of Red-Green-Refactor before any implementation exists. The standard agent workflow `testing → code-reviewer → swe → code-reviewer` (see [ADR-006](006-agent-architecture-pattern.md) for the canonical agent surface) makes RED-phase the default for any agent-driven change. The project-level posture — that RED-phase is also encouraged for human-authored work, and that mid-flight RED-phase markers are part of the discipline rather than a defect — lives here, not in the agent definition.

**Mid-flight markers.** RED-phase markers in test files (phrasings such as "currently FAILS" or task-anchored RED tags) are **acceptable on local feature branches while red→green is still in progress**. They are part of the discipline: a failing test with an explicit RED marker is the contract the implementing agent or author satisfies. The constraint is that markers must be **scrubbed before the branch becomes externally visible** — before `git push origin` and before pull-request open. Mechanical enforcement of that scrub is deferred to a queued follow-up issue (mechanical enforcement of the mid-flight-marker scrub at push or PR-open time, not at commit-time, since committing-time enforcement would fire spuriously during the legitimate red phase). The broader scope-by-decision rule that frames this discipline is captured in the architect agent's Style Conventions (see [`scripts/agents/architect.md`](../../scripts/agents/architect.md)).

### D3. Doc-test harness as a first-class surface

The doc-test harness — `test_markdown_examples.py` extracts and executes Python from `risk-map/docs/*.md` fenced code blocks — is a **first-class testing surface**. Conventions are authoritatively documented in `risk-map/docs/writing-documentation.md`, including the skip markers (`[skip-test]`, `[doc-only]`, `[documentation-only]`, `# SKIP-TEST`) that authors use to opt a fenced block out of execution.

This decision is mostly retroactive: the harness has been in production, the conventions are already published, and the blast radius is non-trivial (fenced blocks in published documentation execute as part of the test suite). The ADR-level statement makes the contract explicit so future authors have a place to point and so reviewers know the harness is not an internal helper that can be quietly retired.

### D4. Contributor invocation surface

The canonical "run the tests" experience for contributors is **three named commands**, documented together in one place:

- `pytest` — Python wrappers and validators under `scripts/hooks/tests/`.
- `node --test site/tests/*.test.mjs` — site logic per ADR-012; framework choice and zero-install property are governed there.
- `./scripts/tools/validate-all.sh` — content, schema, and edge validators (the inspection-only command preserved by ADR-005, distinct from `uv run --locked --no-sync pre-commit run --all-files`).

A single wrapper script (`test-all.sh`) was considered and rejected: the wrapper hides which surface failed and how to iterate on it, while three named commands give contributors the right mental model — Python wrappers, site logic, and content validation are different surfaces with different feedback loops.

This ADR **decides** on the three-command surface and **flags** the documentation gap as a follow-up (a `scripts/docs/testing.md` contributor doc, or an equivalent `CONTRIBUTING.md` section). This ADR does not author that doc; the surface is split off as a separate implementation issue once this ADR is `Accepted`.

### D5. `act` (local workflow testing) posture — adopt as local-validation gate for workflow PRs

The project **adopts `act` as a local-validation gate** for pull requests that materially change GitHub Actions workflows. The previously-recorded deferral trigger crossed on 2026-05-07 and was satisfied by demonstrated cost-benefit; D5 records the adoption.

**Trigger criteria.** An `act -j <job>` run is required **before push or PR-open** for any pull request that:

- Creates a net-new workflow file (`.github/workflows/<new>.yml`).
- Adds or changes a `permissions:` block.
- Adds or changes `on:` triggers (push events, pull-request events, schedule, workflow_call, etc.).
- Adds runner-OS divergence (new `runs-on:` value, matrix expansion).
- Adds shell-script-heavy job steps (more than roughly ten lines of bash logic in a single `run:`).

The gate does **not** apply to trivial workflow edits — comment changes, doc-only edits, or single-value tweaks such as a version bump on an already-SHA-pinned `uses:` reference.

**Demonstrated cost-benefit.** [PR #270](https://github.com/cosai-oasis/secure-ai-tooling/pull/270) (workflow `uses:` pinning lint) introduces a net-new `.github/workflows/validate_workflows.yml` with its own `permissions: contents: read` block, its own path-filtered `on: push` and `on: pull_request` triggers, and ADR-024 D6 SHA-pinned `uses:` references; it crosses two trigger criteria simultaneously. A maintainer ran `act -W ./.github/workflows/ -j workflow-uses-pinning` and observed approximately 30 seconds wall-time after the one-time docker pull, with sub-second per-step costs (Set-up-Python ~335ms, Install-dependencies ~414ms, Validate ~164ms). The run exercised the path-filter scope end-to-end, executed the `permissions` block, resolved and cloned the action SHA pins (e.g., `setup-python@a309ff8b...`), executed the fresh-container Python 3.14 install, and surfaced runtime quirks (a pip-as-root warning) that local pytest cannot reach. The job succeeded cleanly.

**Where the validation runs.** D5 records that `act` runs **locally before push or PR-open** as a contributor and maintainer discipline. Whether to additionally enforce the `act` run as a CI step (CI nesting CI, with runtime cost amplified across PRs) is a separate question handled by the reframed follow-up below.

The devcontainer-pinning policy (umbrella issue [#248](https://github.com/cosai-oasis/secure-ai-tooling/issues/248); ADR-023 reserved) governs *what versions* the devcontainer pins. [ADR-024](024-github-actions-pinning-posture.md) governs *how* GitHub Actions are pinned (commit SHA plus semver comment). D5 governs *whether and when the project runs those workflows locally via `act`*. The three are coordinated, not duplicative.

### D6. Devcontainer build verification posture — defer with named trigger

Devcontainer testing is currently **static-conformance only**: the `test_devcontainer_json.py`, `test_dockerfile.py`, `test_install_deps.py`, `test_verify_deps.py`, `test_mise_config.py`, and `test_setup_script.py` suites assert structure and shape. No CI job runs `devcontainer build` or `devcontainer up` end-to-end.

The project's posture is **deferral with named trigger → eventually adopt**. A follow-up ADR adopts CI build verification if and only if either (a) a real bootstrap regression lands that the static-conformance suites did not catch, or (b) a base-image, `mise`, Python, or Node version change touches install paths in `install-deps.sh` materially enough that static analysis is no longer sufficient evidence.

The devcontainer dependency-pinning policy (umbrella tracked at issue [#248](https://github.com/cosai-oasis/secure-ai-tooling/issues/248); ADR-023 reserved) governs the inputs that D6 verifies. ADR-023 will decide *what versions* the devcontainer pins and *how Dependabot keeps them current*; D6 is about *whether CI verifies the devcontainer is buildable end-to-end* given those pins. The two are complementary. When ADR-023 lands, the citation here can be a one-line swap.

### D7. Markdown lint and ESLint posture — defer both with named triggers

The project does **not adopt markdownlint or ESLint** today.

- **Markdownlint** — the project has not had real prose-format pain. Most prose lives in YAML where `prettier` already governs format, and the markdown that exists is mostly authored by people who write good markdown. **Trigger:** a real prose-format regression in a contributor PR that markdownlint would have caught.
- **ESLint** — site JS is one pure-logic module plus one DOM renderer, both small enough that lint catches noise rather than bugs. **Trigger:** `site/**` exceeding roughly five modules, or a real bug landing that lint would have caught.

The deferrals are recorded so future contributors and architects do not interpret the absence of lint as an oversight.

### D8. Coverage policy — per-file, deliberately not project-wide

Coverage policy is **per-file, deliberately not project-wide**. Coverage importance varies dramatically by module: validators that gate the commit path warrant higher coverage than one-off bootstrap scripts. A project-wide threshold either ends up too low to be useful or too high to be sustainable, and either failure mode produces test-quality theater rather than real safety.

Per-file targets are documented in test-file headers. The ADR records the posture as deliberately per-file and explicitly declines project-wide enforcement. **Follow-up:** if per-file targets ever drift inconsistently — for example, new test files landing without targets, or existing targets being silently lowered to make a PR green — the question of promoting to a project-wide minimum reopens.

### D9. CI / local parity gate — divergence is explicitly tolerated

The project documents the CI/local divergence rather than pretending parity exists.

- **CI is the authoritative final gate.** A merge requires CI green.
- **Local pre-commit + pytest + `node --test`** is the cheap iteration gate. Contributors get fast feedback before push.
- **The two are correlated but not identical.** Strict parity is not enforced. Differences include CI-only environment factors (clean checkout, fresh dependency install, runner-OS specifics) that local cannot reproduce without considerable cost. The project tolerates this divergence in exchange for keeping the local loop fast.

This is the posture that prevents "works on my machine" from being a defensible response to a CI failure: CI is the gate, local is iteration. ADR-005 already established `uv run --locked --no-sync pre-commit run --all-files` and `./scripts/tools/validate-all.sh` as the two local entry points; this ADR records the parity posture above them.

### D10. Wire-up / call-site verification

Tests for new functions that are expected to **enforce something** — validators, linters, runtime warnings — must include at least one assertion that the function is **reachable from the documented execution surface**. Unit-level "the function does the right thing when called" coverage is necessary but not sufficient. The execution-surface assertion typically takes the shape of a CLI entrypoint test, a pre-commit-hook fixture test, or a generator-runtime invocation test that exercises the path the function is supposed to be wired into.

This is the posture that prevents the A4 M1+M2 class of miss: a validator with passing unit tests that is never called from the CLI, or a runtime warning with passing unit tests that is never invoked from the constructor it is supposed to fire from. The A4 sub-PR ([PR #277](https://github.com/cosai-oasis/secure-ai-tooling/pull/277), open at this ADR's authoring time) surfaced two such cases — `check_lifecycle_stage_order_uniqueness` defined but not called from `validate_riskmap.py`, and `emit_missing_category_warnings` defined but not called from `BaseGraph.__init__`. The decision-bound fix landed in commit `069c3a4`.

ADR-022's D6a is the canonical example of why D10 matters: ADR-022 D6a requires that the missing-category warning be **visible at generator-run time**, not merely "implementable as a function." Defining `emit_missing_category_warnings()` with passing unit tests does not satisfy the ADR; only invocation from `BaseGraph.__init__` does. D10 narrows the broader scope-by-decision rule — captured in the architect agent's Style Conventions at [`scripts/agents/architect.md`](../../scripts/agents/architect.md) — to the testing-strategy axis: when the decision is "this function must enforce something," the test contract includes the call-site, not just the function body.

### Decisions deliberately not in this ADR

A few candidates were considered and rejected for inclusion:

- **Visual-regression testing for generated SVGs** — out of scope (see Consequences).
- **DOM rendering tests for the renderer module** — already decided by ADR-012's progressive-enhancement posture.
- **Schema test coverage of the schemas themselves** — governed by ADR-005's metaschema posture and ADRs 018-022.
- **Test fixture conventions** — too granular for an ADR; belongs in a contributor doc.

## Alternatives Considered

- **Inventory-shaped ADR enumerating every surface.** Rejected. An ADR is a decision record, not a directory listing. Inventories age out (file counts, test counts, fixture names all churn on every PR) and an inventory-shaped document repeats sibling-ADR content rather than building on it. The inventory survey that justified the deferrals in D6/D7 and the per-file posture in D8 was performed once at issue-authoring time (#252, 2026-04-29) and is not reproduced here; citing it is enough.

- **One ADR per testing surface (six or more separate ADRs).** Rejected. The cross-surface posture questions — RED-phase, contributor invocation, parity, coverage policy, wire-up — are inherently cross-surface; splitting them across per-surface ADRs would either duplicate content or scatter it such that no single ADR answers "what is the project's testing strategy?" The chosen shape is one strategy ADR plus pre-split named-trigger follow-ups for genuinely separate adoption questions (`act` in CI vs. local-only, devcontainer build verification).

- **Adopt CI-side `act` enforcement and devcontainer build CI inline in this ADR.** Rejected. D5 adopts `act` as a *local* gate on the strength of demonstrated cost-benefit (PR #270); whether to additionally enforce `act` in CI is a separate question with its own cost profile (CI nesting CI, runtime amplified across PRs) and is deferred. The static-conformance devcontainer suites have not produced a missed regression, so devcontainer build CI is similarly deferred. Adopting either inline today would commit infrastructure on speculation; deferral with a named trigger reopens cleanly when evidence appears.

- **Adopt project-wide coverage enforcement.** Rejected per D8. Coverage importance varies by module, and a single project-wide threshold produces either insufficient safety or unsustainable cost.

- **Codify RED-phase TDD as required for human-authored work.** Rejected per D2. The agent-mediated discipline is required because agents cannot exercise the judgment to pick between authoring-styles, but humans can; requiring RED-phase from humans would either be ignored or would slow contribution without proportionate benefit. RED-phase is encouraged for humans, required for agents.

- **Author a parallel testing-spec document under a new `specs/` surface.** Rejected. The repository uses ADRs for durable decisions and contributor docs for procedural detail; there is no separate specs surface. Procedural how-to-test detail belongs in a follow-up `scripts/docs/testing.md`, not a parallel ADR-shaped document.

## Consequences

**Positive**

- The project has a single tracked posture for testing across all surfaces. A contributor or architect asking "does the project test X?" has one document to read, not seven sibling ADRs and ad-hoc scratch notes scattered across contributor docs.
- Deferral-with-named-trigger replaces speculative adoption for CI-side `act` enforcement, devcontainer build CI, markdownlint, and ESLint. Each deferral records the evidence that would reopen the decision, so future architects do not have to reconstruct the rationale. D5's local-gate adoption is the inverse pattern: a previously-deferred adoption that flipped on the strength of a demonstrated cost-benefit signal.
- The wire-up posture (D10) closes the A4-class miss explicitly: validators and runtime warnings are not "done" when their unit tests pass; they are done when their call-site is exercised. ADR-022 D6a's "warning visible at generator-run time" requirement now has an enforcement frame at the testing-strategy level.
- The mid-flight RED-phase posture (D2) reconciles two previously-implicit norms: agent-mediated test files do contain RED markers during red→green, but those markers do not leak past push. The phase-tag-leakage gate, when it lands, has a clear specification (push-time, not commit-time) instead of triggering during legitimate red phases.
- Contributor experience improves once D4's documentation follow-up lands. Three named commands, one place to find them, predictable feedback loops.
- D5's adoption commits the project to documenting the per-workflow `act -j` invocation form (e.g., `act -j workflow-uses-pinning`) in the contributor doc that D4's follow-up names, so reviewers and contributors can apply the gate mechanically.

**Negative**

- The deferral surface (D6, D7) is real overhead to revisit. Each deferred adoption is a future ADR. The project trades immediate codification for trigger-driven adoption, and the cost is that the trigger has to be noticed and acted on rather than legislated up-front.
- The per-file coverage policy (D8) can drift inconsistently if reviewers do not enforce per-file target documentation in test-file headers. Project-wide enforcement is mechanically simpler; per-file is more correct but requires reviewer attention. The follow-up clause in D8 is the escape hatch if drift becomes pervasive.
- D10 imposes a non-obvious test-authoring requirement. A test author writing a new validator may not know that a CLI-entrypoint or hook-fixture test is also expected. Mitigated by `code-reviewer` enforcement and by the explicit D10 framing here, but the discipline is ongoing.
- The CI/local divergence posture (D9) explicitly tolerates "works on my machine" as a possibility. This is the right trade-off — strict parity is impossibly expensive — but the project must accept that a local-green / CI-red outcome is sometimes a real divergence rather than a contributor error.
- Two pre-split follow-up ADRs (`act` in CI vs. local-only, devcontainer build verification) are recorded as deferred. If neither trigger ever fires, those issues sit open indefinitely. Acceptable; "this never became necessary" is a valid conclusion for a deferred decision.

**Out of scope**

- **Visual-regression testing for generated SVGs.** Mermaid → SVG generation is structural-diff-tested today; pixel-level regression would require headless-browser tooling and a fixture corpus. Defer until a real visual regression lands and is missed by structural diff.
- **Integration tests across YAML → schema → builder → site.** The persona-site builder hook (ADR-013) already exercises this end-to-end on every commit that touches any input.
- **End-to-end persona flow tests in a real browser.** Out of scope per ADR-012's progressive-enhancement posture and the static-SPA architecture decision.
- **Performance / load testing.** This is a content repository and a static site. There is no service to load-test.
- **Mutation testing.** Powerful but expensive. Defer until per-file coverage targets prove insufficient.
- **CI matrix expansion** (multiple Python versions, multiple Node versions). Out of scope per [ADR-003](003-devcontainer-mise-architecture.md)'s pinning posture.
- **Test fixture and data conventions** beyond what ADR-013 and `site/tests/README.md` already decide. Belongs in the D4 follow-up contributor doc.
- **CI-side enforcement of `act` runs.** D5 adopts `act` as a local-only gate. Whether to additionally enforce `act` as a CI step is covered by the reframed follow-up ADR named in the Follow-up section.

**Follow-up**

- **Contributor doc for D4.** A `scripts/docs/testing.md` (or equivalent `CONTRIBUTING.md` section) documents the three named commands, when to use each, and how to interpret common failure modes. Filed as a separate implementation issue once this ADR is `Accepted`.
- **Follow-up ADR — `act` in CI vs. local-only.** D5 adopts `act` as a local-validation gate. The separate question of whether to additionally enforce the `act` run as a CI step (CI nesting CI, with runtime cost amplified across PRs) is deferred. **Trigger:** a regression that the local-only gate missed because a contributor skipped it, or a demonstrated need for CI-side enforcement.
- **Follow-up ADR — devcontainer build verification in CI.** Triggered by either a real bootstrap regression missed by static-conformance suites, or a base-image/`mise`/Python/Node version change that touches install paths. Cited against the eventual ADR-023 (issue #248) when ADR-023 lands.
- **Phase-tag-leakage gate.** D2's mid-flight-marker scrub posture is enforced mechanically by a queued follow-up issue (drafted, not yet filed). Filing-timing is at maintainer discretion; this ADR records the posture the gate will enforce.
- **D8 drift watch.** If per-file coverage targets drift inconsistently (new test files without targets, existing targets silently lowered), reopen the project-wide-minimum question.
