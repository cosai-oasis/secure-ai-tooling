# Architecture Decision Records

This directory holds Architecture Decision Records (ADRs) for **tooling, infrastructure, and process** decisions in the CoSAI Risk Map repository. Each ADR captures the context that motivated a choice, the choice itself, alternatives that were considered, and the consequences the project is now living with.

ADRs complement — not replace — two other surfaces in this repo:

| Surface | Lives in | Audience | Scope |
|---|---|---|---|
| **ADRs** (this directory) | `docs/adr/` | Maintainers, contributors, tool integrators | Tooling, infra, CI/CD, agent architecture, repo-wide conventions |
| **Framework design docs** | [`risk-map/docs/design/`](../../risk-map/docs/design/) | Risk-map framework authors and consumers | Risk taxonomy, persona model, schema semantics, migration logic |
| **Implementation plans** | Local untracked plans directory (template source at [`docs/contributing/plan-template.md`](../contributing/plan-template.md)) | Maintainer, in-flight sessions | Phased execution of a specific piece of work |

If a decision is about *how the Risk Map content model is shaped*, it belongs in `risk-map/docs/design/`. If it is about *how the repository itself is built, tested, released, or extended*, it belongs here.

## Index

| # | Title | Status | Date |
|---|---|---|---|
| [001](001-adopt-adrs.md) | Adopt ADRs for tooling/infrastructure decisions | Accepted | 2026-04-21 |
| [002](002-branching-strategy.md) | Branching strategy — `develop` for content, `main` for tooling | Accepted | 2026-04-21 |
| [003](003-devcontainer-mise-architecture.md) | Devcontainer + `mise` tool-management architecture | Accepted | 2026-04-21 |
| [004](004-ai-assistant-trailer.md) | Vendor-neutral `Co-authored-by` trailer for AI-assisted commits | Accepted | 2026-04-21 |
| [005](005-pre-commit-framework.md) | Pre-commit framework adoption | Accepted | 2026-04-21 |
| [006](006-agent-architecture-pattern.md) | Vendor-neutral agent architecture under `scripts/agents/` | Accepted | 2026-04-21 |
| [007](007-content-reviewer-modes.md) | `content-reviewer` three-mode architecture | Accepted | 2026-04-21 |
| [008](008-sub-agent-orchestration.md) | Sub-agent orchestration: composition contracts and routing boundaries | Accepted (§2 superseded in part — [amendment](008-sub-agent-orchestration.md#amendment-2026-07-12-draft-issue-comments-review-discipline-is-a-canonical-skill) Accepted) | 2026-04-21 |
| [009](009-persona-pages-workflow-topology.md) | GitHub Pages deploy surface and persona-pages workflow topology | Accepted | 2026-04-21 |
| [010](010-site-repo-root-module-boundary.md) | `site/` as a repo-root peer of `risk-map/` | Accepted | 2026-04-21 |
| [011](011-persona-site-data-schema-contract.md) | `persona-site-data.schema.json` as a versioned producer/consumer contract | Accepted | 2026-04-21 |
| [012](012-static-spa-architecture.md) | Static client-side SPA — no backend, vanilla ESM, `node --test`, progressive-enhancement a11y | Accepted | 2026-04-21 |
| [013](013-site-precommit-hooks.md) | Extend the `pre-commit` framework with `site/**` hooks | Accepted | 2026-04-21 |
| [014](014-yaml-content-security-posture.md) | YAML content security posture for the CoSAI Risk Map | Accepted | 2026-04-24 |
| [015](015-site-content-sanitization-invariants.md) | `/site/` render-time sanitization invariants — DOM allowlist with bounded emission + mandatory fixture tests | Accepted | 2026-04-25 |
| [016](016-reference-strategy.md) | Intra-document `{{idXxx}}` sentinels + structured `externalReferences` for outbound citations | Accepted | 2026-04-25 |
| [017](017-yaml-prose-authoring-subset.md) | Canonical YAML prose authoring subset — markdown tokens authors may write in prose fields | Accepted | 2026-04-25 |
| [018](018-components-schema.md) | `components.schema.json` design — closed enums, edge validator boundary, no ghost fields | Accepted | 2026-04-25 |
| [019](019-risks-schema.md) | `risks.schema.json` design — `relevantQuestions` retirement, mapping patterns, BLOCK-02 input tightening | Accepted | 2026-04-25 |
| [020](020-controls-schema.md) | `controls.schema.json` design — closed enums, controls↔components mirror, folded-bullet drift heuristic | Accepted | 2026-04-25 |
| [021](021-personas-and-self-assessment-schema.md) | `personas.schema.json` design + `self-assessment.yaml` archiving (GAP-9) | Accepted | 2026-04-25 |
| [022](022-supporting-schemas.md) | Supporting schemas grouped — actor-access, impact-type, lifecycle-stage, frameworks (mapping-ID regex), mermaid-styles | Accepted | 2026-04-25 |
| 023 | Devcontainer dependency-pinning policy and lifecycle cadence | Reserved ([#248](https://github.com/cosai-oasis/secure-ai-tooling/issues/248)) | — |
| [024](024-github-actions-pinning-posture.md) | GitHub Actions pinning posture | Accepted | 2026-05-01 |
| [025](025-testing-strategy.md) | Testing strategy and posture across Python, site JS, schemas, and infrastructure | Accepted | 2026-05-05 |
| [026](026-issue-template-domain.md) | Issue-template domain — generator scope, schema-derived enums, and ADR-content alignment contract | Accepted | 2026-05-20 |
| [027](027-framework-versioning-and-mapping-convention.md) | Per-mapping framework version pinning | Accepted | 2026-05-22 |
| [028](028-prose-linter-bracket-matching-architecture.md) | Prose-linter emphasis enforcement via bracket-matching depth pass over a Token-shape contract | Accepted | 2026-05-28 |
| [029](029-dual-python-package-management.md) | Dual Python package-management path with `uv` devcontainers | Accepted | 2026-06-06 |
| [030](030-agentic-component-model.md) | Agentic component model — external tools tier and identity grouping | Accepted | 2026-06-30 |
| [031](031-authoring-time-agents-and-skills.md) | Authoring-time agents and skills for Risk Map content — creator + critic agents, classical-lexicon / mapping-selection / altitude-check / audit-framework-mappings skills | Accepted | 2026-07-01 |
| [032](032-consumer-exploration-skills.md) | Read-only consumer exploration skill surface (explore-* skills) | Accepted | 2026-07-06 |
| [033](033-vendor-neutral-agent-skill-shipping.md) | Vendor-neutral shipping and lifecycle for CoSAI agents and skills — canonical-only neutral cloneable artifacts, the neutrality contract (machine-checkable denylist + framework-authority allowlist), consumer adaptation, required neutrality check, develop/eval/expand lifecycle | Accepted | 2026-07-08 |
| [034](034-corpus-change-landing-sequence.md) | Dependency-ordered landing sequence for risk-map corpus changes | Draft | 2026-07-09 |

## Conventions

- **File name:** `NNN-slug.md` — zero-padded sequential number, kebab-case slug.
- **Numbering:** claim the next number by adding a row to the index table in the same commit that introduces the ADR.
- **Template:** start from [`TEMPLATE.md`](TEMPLATE.md). Sections are Status / Context / Decision / Alternatives Considered / Consequences.
- **Lifecycle:** `Draft` on first commit → `Accepted` after maintainer sign-off → `Superseded by ADR-XXX` when replaced. Superseded ADRs stay in place; do not delete history.
- **Single decision per ADR.** If the draft grows two decisions, split it.
- **Decision sub-sections use a `D` prefix** (`### D1.`, `### D2.`, with sub-sub-sections like `#### D3a.` only when needed). Cross-references use the same IDs (`D3`, `D3b`). See [`TEMPLATE.md`](TEMPLATE.md) for the example shape.
- **Cite sources.** Retroactive ADRs in particular must cite the commits, PRs, and issues they summarize.

## Contributing

New ADRs are typically authored by the [`architect` agent](../../scripts/agents/architect.md) when an in-flight change trips one of its triggers: schema changes, a new top-level directory, cross-module refactors, adding or removing an external tool dependency, adding or changing a CI workflow, and new features or tools that shape how the repo is built. Maintainers can also author ADRs directly. Either way, the ADR lands as `Status: Draft` and waits for sign-off before being marked `Accepted`.
