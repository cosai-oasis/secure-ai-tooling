# ADR-008: Sub-agent orchestration: composition contracts and routing boundaries

**Status:** Accepted
**Date:** 2026-04-20
**Authors:** Architect agent, with maintainer review
**Superseded in part by:** [Amendment 2026-07-12](#amendment-2026-07-12-draft-issue-comments-review-discipline-is-a-canonical-skill) (below) — the [§2](#decision) framing of the `draft-issue-comment` flow's review discipline as "not part of the canonical pattern" is superseded by [ADR-031 D5](031-authoring-time-agents-and-skills.md) + [ADR-033 D1](033-vendor-neutral-agent-skill-shipping.md). The composition contracts and routing boundaries of D1–D3 are unchanged.

---

## Context

[ADR-006](006-agent-architecture-pattern.md) establishes that canonical sub-agent specifications live as vendor-neutral prose under [`scripts/agents/`](../../scripts/agents/). [ADR-007](007-content-reviewer-modes.md) captures the `content-reviewer` agent's three-mode architecture. Neither ADR answers the next question: *how do canonical sub-agents compose into end-to-end, contributor-facing workflows?*

Two composition shapes are already in production use in this repository:

1. **Agent-to-agent composition.** [`scripts/agents/issue-response-reviewer.md`](../../scripts/agents/issue-response-reviewer.md) (299 lines) invokes [`scripts/agents/content-reviewer.md`](../../scripts/agents/content-reviewer.md) in `issue` mode with `format: agent`, consumes the structured findings, and assembles a maintainer-facing draft review comment with field-by-field feedback, quality gates, and a summary-of-changes table. The composition is declared in `content-reviewer.md`'s `## Composition` section (line 29-31) and in `issue-response-reviewer.md`'s `## Composition with Content Reviewer` section (line 240-250).
2. **Skill-to-agent composition.** A harness-level slash command (e.g., a `/draft-issue-comment` skill under a specific harness's skills directory) receives a natural-language invocation — typically a GitHub issue URL — fetches the external context using harness-available tools (`gh` CLI, HTTP fetches, file I/O), invokes the appropriate canonical agent, and translates the agent's findings into an external side effect (a posted or drafted comment, a file written, a PR updated).

This pattern has been exercised most visibly in the batch review of risk-map issues #188-199: twelve issues processed through `issue-response-reviewer` composing `content-reviewer` in `issue` mode, producing twelve maintainer-facing draft comments. The pattern works. It is not yet recorded.

Two forces motivate capturing it now:

- **Composition contracts are load-bearing.** `issue-response-reviewer` only works because `content-reviewer` returns findings in a stable `format: agent` shape the caller can parse. If either side of that contract drifts without coordination, the composed workflow breaks. The contract needs to be named as a contract, not left implicit.
- **Routing boundaries keep canonicals portable.** A canonical agent that knows it is being consumed by a specific skill, orchestrator, or harness has been contaminated. ADR-006's vendor-neutrality guarantee depends on canonicals returning findings and letting callers translate them into external side effects. This boundary is currently upheld by convention; it should be stated.

This ADR is scoped narrowly to the composition patterns already battle-tested in live use: `issue-response-reviewer` → `content-reviewer`, and the harness-skill → canonical-agent shape demonstrated by the draft-issue-comment flow. The newer canonicals (`architect`, `testing`, `code-reviewer`, `swe`) declare composition relationships in prose but have not yet been exercised through a published orchestration flow. **Their orchestration patterns are out of scope for this ADR; they will be captured in a future ADR once the patterns are battle-tested in live use.**

## Decision

Sub-agent orchestration in this repository follows two composition shapes, each with an explicit contract and a fixed routing boundary.

**1. Agent-to-agent composition (canonical → canonical).**

A composing canonical invokes a composed canonical by name, passing explicit mode and format flags. The composed canonical returns findings in the specified format; the composing canonical assembles a higher-level artifact from those findings.

- **Contract.** The caller specifies `mode` and `format`. `issue-response-reviewer` fixes `mode=issue` and `format=agent` because its role is specifically post-issue, agent-consumable findings (see `issue-response-reviewer.md` line 248: "Invoke `content-reviewer` in `issue` mode with `format: human` when the output will be integrated into a contributor-facing review. Use `format: agent` when consuming findings programmatically inside this agent's pipeline.").
- **Return shape.** The composed canonical's output follows its documented `format: agent` schema. The composing canonical does not parse prose; it consumes structured findings.
- **Delegation vs assembly.** The composing canonical delegates what the composed canonical already does well (overlap detection, structural integrity, style-guide checklist application) and adds what is unique to its role (field-by-field feedback, quality gates, YAML drafting, summary table). It does not duplicate composed-canonical checks.
- **Reference by filename.** Composition references use the canonical filename (`scripts/agents/content-reviewer.md`) or the agent name (`content-reviewer`), never a harness-specific path.

**2. Skill-to-agent composition (harness → canonical).**

A harness-level skill receives a natural-language invocation, gathers external context using harness-specific tools, invokes the appropriate canonical agent, and translates the returned findings into an external side effect.

- **Contract.** The skill is harness-specific. It may use `gh` CLI, web fetches, file reads, editor APIs, or any other tool the harness provides. The canonical agent it invokes is harness-neutral.
- **Return shape.** The skill receives the agent's documented output (findings, draft YAML, review comment) and performs the side effect (posts a comment, writes a file, opens a PR draft). The canonical agent does not know its output is being posted anywhere.
- **Per-harness layering.** A `/draft-issue-comment` slash command is one harness's layering over `issue-response-reviewer`. A different harness could layer a Cursor command, an Aider recipe, or a plain-CLI wrapper over the same canonical. Per ADR-006, harness layering is an implementation detail of the consuming environment, not part of the canonical pattern.

**3. Routing boundaries (what canonicals never do).**

Canonical agents under `scripts/agents/` do not perform external side effects. They do not post to GitHub, write files outside their declared outputs, call external APIs, or modify the repository. They return findings. Skills and orchestrators translate findings into side effects. This separation is what keeps canonicals portable.

The architect agent is the negative example that anchors the rule. [`scripts/agents/architect.md`](../../scripts/agents/architect.md) line 24-26 declares: "The architect does not itself invoke sub-agents; its output is the input for later phases. Callers route to the architect *before* invoking `swe` or `testing` when an architectural trigger fires." Orchestration is a caller concern, not an architect concern. The same is true of every other canonical: composition is declared; orchestration is performed by the caller above the canonical.

## Alternatives Considered

- **Monolithic agent (no composition).** Have `content-reviewer` emit contributor-facing comment drafts directly in `issue` mode, eliminating `issue-response-reviewer`. Rejected: this couples framework-content-review logic (what `content-reviewer` owns) to comment-assembly logic (what `issue-response-reviewer` owns). A second caller that wants raw findings — for example, a maintainer-facing audit tool or a batch-review pipeline — would have to parse a review comment to extract structured findings. The composition split keeps findings-generation reusable.

- **Skill-only orchestration (no `issue-response-reviewer` agent).** Have the harness skill invoke `content-reviewer issue` directly and assemble the comment itself. Rejected: comment-assembly logic (field-by-field feedback, quality gates, YAML drafting, summary-of-changes table) is portable across harnesses. The same comment shape works under any AI environment that can invoke the canonical agent. Pushing assembly into each harness's skill duplicates work, invites drift, and pushes canonical knowledge (the persona model, universal-control hygiene, style-guide citations) into harness-specific code where it does not belong.

- **Tight coupling via shared state.** Have composed agents communicate through a shared scratchpad file that each writes to and reads from. Rejected: this is fragile (every agent must agree on the scratchpad schema and file location), harness-specific (file I/O conventions differ across harnesses), and contradicts the canonical-as-portable principle. Explicit input-and-output contracts via mode/format flags are simpler and more durable.

## Consequences

**Positive**

- The two published orchestration flows (`issue-response-reviewer` composing `content-reviewer`; a harness skill wrapping `issue-response-reviewer`) have named, stable contracts. Breaking changes to either side now have a documented boundary to respect.
- Canonicals remain portable. A new harness can consume `issue-response-reviewer` or `content-reviewer` without inheriting any assumption about external side effects.
- The agent-to-agent composition pattern is reusable. When a future canonical needs to compose with an existing one, the `mode` + `format` flag contract is a template: name what you want, name how you want it back.
- Routing boundaries are explicit. "Canonicals return findings; callers perform side effects" is now a stated rule, not a convention enforced only by code review.

**Negative**

- Two-layer composition (skill → composing canonical → composed canonical) has more moving parts than a single-agent shape. When a bug appears in the end-to-end output, the maintainer must triage across three layers to locate the fault.
- The `format: agent` contract is an implicit schema. If `content-reviewer`'s `agent`-format output shape evolves, every composing canonical that consumes it must be reconciled. Mitigated by keeping the format documented in `content-reviewer.md` under Output Contract, but there is no automated schema-check today.
- Skill-layer code is untracked when the harness is contributor-local (per ADR-006, harness-specific wrapper directories remain excluded via `.git/info/exclude` or equivalent). Contributors using a different harness need to write their own skill from scratch; they cannot copy a tracked reference implementation from this repo.

**Follow-up**

- When the newer canonicals (`architect`, `testing`, `code-reviewer`, `swe`) have been exercised through one or more published orchestration flows, a follow-up ADR should capture their composition patterns. Expected flows include `architect → testing → swe → code-reviewer` for test-first implementation and `architect → swe → code-reviewer` for infrastructure work. Neither is currently battle-tested; both are declared in `architect.md` but have not been run end-to-end in live contributor-facing work.
- If a second harness is officially supported, the question of whether skill-layer code becomes tracked (versus maintainer-local) is a separate decision. Not in scope here.
- The `format: agent` output schema of `content-reviewer` would benefit from a JSON schema or equivalent contract document if the number of composing canonicals grows beyond `issue-response-reviewer`. Defer until that pressure exists.

---

## Amendment 2026-07-12: `draft-issue-comment`'s review discipline is a canonical skill

**Status:** Accepted (2026-07-12). Does not alter the Accepted status of D1–D3 above; it supersedes only the §2 classification of the `draft-issue-comment` flow's review discipline.
**Authors:** Architect agent, with maintainer review.

### Context

[D2](#decision) ("Skill-to-agent composition") uses the `draft-issue-comment` flow as its worked example and, in its "Per-harness layering" clause, classifies it: "A `/draft-issue-comment` slash command is one harness's layering over `issue-response-reviewer` … Per ADR-006, harness layering is an implementation detail of the consuming environment, not part of the canonical pattern." When ADR-008 was written (2026-04-20), that classification was correct on the facts then true: there was **no canonical skill surface at all**. [ADR-006](006-agent-architecture-pattern.md) had established `scripts/agents/` for agents, but skills existed only as harness-specific wrappers, so any `draft-issue-comment` form was necessarily harness-layered.

Three later, Accepted-track decisions changed the surface that framing described:

- [ADR-031 D5](031-authoring-time-agents-and-skills.md) (Accepted, [#402](https://github.com/cosai-oasis/secure-ai-tooling/pull/402)) established `scripts/skills/` as the **canonical, vendor-neutral home** for skills, paralleling `scripts/agents/`. A skill can now be canonical; before ADR-031 it could not.
- [ADR-033 D1](033-vendor-neutral-agent-skill-shipping.md) (the canonical-only shipping standard) fixed the canonical skill as the **single tracked form** and ruled out first-party per-harness wrappers in-repo.
- The `draft-issue-comment` skill has since been promoted into `scripts/skills/` as a neutral canonical that **defers to** the [`issue-response-reviewer`](../../scripts/agents/issue-response-reviewer.md) agent (which composes `content-reviewer` in `issue` mode) — it applies that agent's spec and does not restate it.

The promotion is coherent under the later ADRs — it is a canonical skill admitted under the general ADR-031-D5 / ADR-033-D1 skill-surface rules — but nothing in the ADR record reconciled it against ADR-008 §2's "not part of the canonical pattern" framing, which now reads stale for the *review-discipline* half of the flow. This amendment closes that gap.

### Decision

#### D4. The `draft-issue-comment` review discipline is a canonical skill; only its external side effects remain harness layering

The `draft-issue-comment` flow **splits** into two parts that the later ADRs place on opposite sides of the canonical boundary. The [§2](#decision) "not part of the canonical pattern" framing is superseded for the first part and retained for the second:

- **The review discipline is a canonical skill.** Producing a structured maintainer review comment for a content-proposal issue — the discipline the flow carries — ships as the neutral canonical skill `scripts/skills/draft-issue-comment/` under [ADR-031 D5](031-authoring-time-agents-and-skills.md) (canonical skill home) and [ADR-033 D1](033-vendor-neutral-agent-skill-shipping.md) (canonical-only). This is the current governing classification; ADR-008 §2's "harness layering, not part of the canonical pattern" no longer describes this part.
- **The external side effects remain harness layering.** [D3](#decision)'s routing boundary is unchanged: the canonical skill returns a local draft; it does not post to GitHub. A harness's live GitHub-fetch and post/write mechanics — the `gh`-CLI invocation, the write of the drafted comment — stay harness-specific and out of the tracked canonical, exactly as [D2](#decision) and [D3](#decision) require. ADR-008 §2's boundary governs *these* mechanics; it no longer governs the review discipline.

#### D5. The skill *defers to* the agent — this is ADR-006's canonical-and-defer relationship, not a re-canonicalization of the review logic

The canonical skill does **not** restate the review spec. It defers to the canonical [`issue-response-reviewer`](../../scripts/agents/issue-response-reviewer.md) agent — which composes `content-reviewer` in `issue` mode ([ADR-007](007-content-reviewer-modes.md)) — as its single source of truth for the review process, feedback shape, quality gates, and output structure. The review logic remains canonical **in the agent**; the skill is a thin, canonical caller that applies it. This is the same "canonical is authoritative; the thin form defers to it" relationship [ADR-006](006-agent-architecture-pattern.md) fixes, now realized skill→agent rather than wrapper→agent. Promoting the skill therefore adds a canonical *caller*; it does not duplicate or re-canonicalize the review logic the agent already owns. [D1](#decision)'s agent-to-agent composition contract (`issue-response-reviewer` → `content-reviewer`) is untouched.

#### D6. This is the standing pattern for a promotion↔prior-ADR tension

When a promotion into the shipped set (`scripts/agents/**`, `scripts/skills/**`) reclassifies an artifact that an earlier Accepted ADR framed under the pre-canonical-skill surface, the reconciliation is recorded — not left implicit. The standing form is a dated, in-file amendment to the earlier ADR that annotates the superseded framing and points to the governing later decision, preserving the original text (the instrument this amendment uses; cf. the [ADR-026 amendment precedent](026-issue-template-domain.md#amendment-2026-05-21-component-categorysubcategory-valid-tuple-selector)). The artifact still enters the shipped set under [ADR-033 D6](033-vendor-neutral-agent-skill-shipping.md)'s expansion rule (an ADR-level admission that records D1–D5 conformance and a portable eval); this amendment records the *reconciliation of the prior framing*, which is a separate act from admission.

### Consequences

**Positive**

- The ADR record now explicitly reconciles ADR-008 §2 with the canonical-skill surface. A future reader who reaches ADR-008's harness-layering framing is pointed to the governing later decision instead of being left to infer that ADR-031/033 override it.
- The split is stated cleanly: review discipline is canonical (the skill), external side effects stay harness-specific (the routing boundary). D3's "canonicals return findings; callers perform side effects" rule is preserved intact, not weakened.
- The reconciliation instrument (D6) is now a stated pattern, so the next promotion that trips a prior-ADR framing has a recorded convention to follow rather than a case-by-case judgment call.

**Negative**

- ADR-008 §2 must now be read together with this amendment; the original clause remains in place (history is preserved) but is no longer the whole story for the `draft-issue-comment` example. The header "Superseded in part by" pointer mitigates this, but a reader who skims only §2 could miss the reconciliation.
- The split between "canonical review discipline" and "harness-specific side effects" is a distinction that must be maintained per flow. A future skill that blurs the two — putting a side effect into the canonical — would violate D3 and reopen this boundary.

**Follow-up**

- **Maintainer sign-off flips this amendment `Draft → Accepted`** and, at that point, the ADR-008 header pointer's "Draft" reference resolves to an Accepted amendment. The `Superseded in part by` header language is deliberately narrow (D1–D3 unchanged); confirm that scoping at Accept time.
- **Admission of `draft-issue-comment` into the shipped set** under [ADR-033 D6](033-vendor-neutral-agent-skill-shipping.md) is a separate question from this reconciliation. The scope doc's open Q6 (whether to bless the skill by name in a skill-surface ADR, or leave it under the general ADR-031-D5 / ADR-033-D1 rules) is the maintainer's to decide; this amendment does not resolve it and does not depend on it.
