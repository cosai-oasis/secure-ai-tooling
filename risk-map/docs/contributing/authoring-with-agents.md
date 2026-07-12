# Authoring with Agents

The CoSAI Risk Map ships a set of **authoring agents** that help you draft a
new control, risk, component, or persona and stress-test it *before* you open a
PR. They are an optional, assistive layer over the manual authoring guides —
they do not replace the schema, the style guides, or human review.

This guide explains **when to reach for each agent, what to expect from it, and
how the pieces fit together**. It does not restate what the agents do
internally — each agent's canonical definition under
[`scripts/agents/`](../../../scripts/agents/) is the source of truth for its
behavior, and the skills under [`scripts/skills/`](../../../scripts/skills/)
are the source of truth for the disciplines they apply. Read those when you
want the rules; read this when you want the workflow.

---

## Who this guide is for

- You want to add or revise a control, risk, component, or persona and would
  rather start from a strong, schema-aware draft than a blank file.
- You have a rough draft and want an independent, skeptical pass over it before
  a maintainer sees it.
- You already know the manual flow (the `guide-*.md` step-by-steps) and want to
  know where the agents slot in.

If you just want to author by hand, that path is unchanged — see
[`guide-controls.md`](../guide-controls.md),
[`guide-risks.md`](../guide-risks.md),
[`guide-components.md`](../guide-components.md), and
[`guide-personas.md`](../guide-personas.md). The agents produce the same kind
of entry those guides describe; they do not create a second format.

---

## The flow: creator → critic → content-reviewer

Authoring an entry moves through three roles. The first two are the pre-PR
authoring agents this guide covers; the third is the existing submission gate.

1. **`{type}-creator`** — turns a rough idea or stub into a conformant draft.
   It applies altitude, classical grounding, schema conformance, mapping
   selection, and counterfactual recording, and it *surfaces* governance
   questions rather than deciding them.
2. **`{type}-critic`** — adversarially stress-tests that draft from an
   independent, skeptical stance: is it really distinct, is the evidence real,
   is the altitude honest, are the edges/mappings right. It finds the weak or
   rationalized claims that still pass the mechanical rules.
3. **[`content-reviewer`](../../../scripts/agents/content-reviewer.md)** — the
   submission gate. It runs the schema/CI conformance review on the finished
   YAML (`diff` or `full` mode). This is the same reviewer that runs on your
   PR; running it yourself first is the pre-submission dry run described in
   [`submission-readiness-guide.md`](submission-readiness-guide.md).

For **reviewing an incoming content-proposal issue** (rather than authoring),
a maintainer can draft a structured review comment with the
[`draft-issue-comment`](../../../scripts/skills/draft-issue-comment/) skill,
which applies the
[`issue-response-reviewer`](../../../scripts/agents/issue-response-reviewer.md)
agent (composing `content-reviewer` in `issue` mode).

The creator and critic are **authoring-time and pre-PR**. Neither one is the
submission gate, and neither decides governance questions — those are handed to
a maintainer. You route the work: creator drafts, critic challenges, you
revise, then `content-reviewer` checks conformance.

A caller invokes each role explicitly. The creator does not itself invoke the
critic, and the critic does not itself invoke the reviewer — you (or your
harness) move the draft from one to the next, which keeps a human in the loop
at each handoff.

---

## The four verticals

There is a creator/critic pair per content type. The flow is identical across
all four; the per-type detail (schema fields, ID conventions, the exact edits)
lives in the matching `guide-*.md`.

| Type | Creator | Critic | Manual guide | Notes |
|---|---|---|---|---|
| Control | [`control-creator`](../../../scripts/agents/control-creator.md) | [`control-critic`](../../../scripts/agents/control-critic.md) | [`guide-controls.md`](../guide-controls.md) | Selects components, risks, and framework mappings. |
| Risk | [`risk-creator`](../../../scripts/agents/risk-creator.md) | [`risk-critic`](../../../scripts/agents/risk-critic.md) | [`guide-risks.md`](../guide-risks.md) | Applies merge-vs-distinct and threat-not-control-gap tests; sources real examples. |
| Component | [`component-creator`](../../../scripts/agents/component-creator.md) | [`component-critic`](../../../scripts/agents/component-critic.md) | [`guide-components.md`](../guide-components.md) | Highest blast radius — a new node cascades into reciprocal edges. Runs the absorb-or-decompose test first. |
| Persona | [`persona-creator`](../../../scripts/agents/persona-creator.md) | [`persona-critic`](../../../scripts/agents/persona-critic.md) | [`guide-personas.md`](../guide-personas.md) | Personas are rarely added and adding one is a breaking change — the creator runs a necessity test against the existing personas first. |

**When to invoke a creator:** you have a new entry in mind, a drafted
title/description, or a stub that needs to be made submission-ready. It is
worth invoking even for a well-formed idea — the value is the schema-aware,
classically-grounded first draft plus the list of questions a human must
decide.

**When to invoke a critic:** after a draft exists (whether the creator wrote it
or you did) and before `content-reviewer`. Use it whenever a draft deserves a
hard second look — a claimed-novel entry, an impact rating you are unsure of, a
citation you have not verified, an edge that might model association rather than
a real flow.

**What to expect back:** the creator returns a conformant draft plus surfaced
governance questions. The critic returns a verdict and specific findings, not a
rewrite — you decide what to change. Neither approves the entry for merge; that
is `content-reviewer` and the maintainer.

---

## The skills the agents apply

The agents are not monolithic — they compose a small set of shared
**skills** that encode the reusable authoring disciplines. You do not invoke
these directly during authoring (the agents do), but knowing they exist tells
you *why* a creator asks the questions it does, and they double as standalone
references.

**Authoring discipline** (applied by the creators):

- [`classical-lexicon`](../../../scripts/skills/classical-lexicon/) — grounds
  terminology in established security terms of art instead of coining new
  vocabulary.
- [`mapping-selection`](../../../scripts/skills/mapping-selection/) — selects an
  entry's components, addressed risks/controls, and framework mappings (control
  and risk verticals; components carry no mappings).
- [`altitude-check`](../../../scripts/skills/altitude-check/) — tests whether a
  draft sits at the right level of abstraction (absorb-or-decompose;
  merge-vs-distinct).

**Pre-submission checks** (audit disciplines, useful before you submit — see
[`submission-readiness-guide.md`](submission-readiness-guide.md)):

- [`audit-framework-mappings`](../../../scripts/skills/audit-framework-mappings/)
  — checks that framework mappings are well-formed and correctly scoped.
- [`audit-identification-questions`](../../../scripts/skills/audit-identification-questions/)
  — checks a persona's identification questions for distinguishing power
  (applied by `persona-creator`).

---

## How this complements the manual path

The agents sit **alongside**, not on top of, the existing contributor
material:

- The **`guide-*.md`** step-by-steps remain the authoritative manual procedure
  for each type. A creator produces an entry that conforms to them; when in
  doubt about a field, the guide is the reference.
- The **`contributing/*-style-guide.md`** rules
  ([control titles](control-titles-style-guide.md),
  [risk titles](risk-titles-style-guide.md),
  [component titles](component-titles-style-guide.md),
  [framework mappings](framework-mappings-style-guide.md),
  [identification questions](identification-questions-style-guide.md)) are the
  conventions the agents apply and the reviewer enforces. They remain the
  source of truth for those conventions.
- The **[submission-readiness-guide.md](submission-readiness-guide.md)**
  describes the quality bar and the `content-reviewer` dry run. The authoring
  agents help you *clear* that bar before you submit; they do not change it.

If the agents and any of these documents ever appear to disagree, the guides,
style guides, and schema win — the agents are assistive and the canonical
`scripts/agents/*` / `scripts/skills/*` definitions defer to the framework's
own rules.

---

## Invoking these in your harness

This guide is deliberately vendor-neutral: it names the agents and skills and
says *when* to use them, not *how* to wire them into a specific tool. The
agents are canonical prose definitions under
[`scripts/agents/`](../../../scripts/agents/) and the skills are Agent-Skills
definitions under [`scripts/skills/`](../../../scripts/skills/); adapting them
to your own harness (invocation mechanics, tool wiring) is the consumer's
responsibility. See [`scripts/skills/README.md`](../../../scripts/skills/README.md)
for the skill format and the neutrality contract that governs both trees.
