---
name: altitude-check
description: "Check whether a CoSAI Risk Map entry is pitched at the right altitude (granularity). For a control: objective-not-implementation, not-a-restated-risk, posture-not-mandate, solved-problem, no-duplication. For a risk: the merge-vs-distinct two-test, threat-not-control-gap, and real-not-hypothetical. For a component: the absorb-or-decompose base test, role-not-product, and reader-instructive. Use when authoring or reviewing a control/risk/component draft, when a draft reads like implementation detail or a restated threat, or to decide whether a candidate should be new, merged, or absorbed into an existing entry."
---

# Altitude Check

Altitude is the granularity an entry is pitched at. Too low and it becomes implementation detail or an instance that sprawls into siblings; too high and it dissolves the gap it was meant to name. Most authoring defects are altitude defects, so check altitude before wording.

Run the tests for the entry type. The control, risk, and component tests are all active; run the set matching the entry type.

## Control altitude tests

Apply each; report pass or adjust-with-fix.

- **T1 — Objective, not implementation.** The control states a capability or objective ("ensure delegation chains are auditable"), not a mechanism ("emit signed delegation spans with correlation IDs to a collector"). The objective survives implementation churn. *Fix:* lift the mechanism into a description example and restate the objective.
- **T2 — Not a restated risk.** A control is the defense framed as a positive capability, not the threat with "prevent" attached. If it reads like the risk inverted, rewrite it as the capability the implementer gains.
- **T3 — Posture, not mandate.** A control describes a defensive capability an implementer adopts against their risk appetite; it is not a compliance order. Watch for "must always," universal imperatives, and audit-language.
- **T4 — Solved problem.** A known technique achieves the objective. If none does, this is a research gap or a risk to document — not a control. *Fix:* flag it for the maintainer rather than drafting an aspirational control.
- **T5 — Generalized and grounded.** The control names a role/locus, not a product or protocol, and uses established terminology (defer terminology to the classical-lexicon skill). *Fix:* generalize; keep the product as an example.
- **T6 — Novelty vs absorb.** Read `risk-map/yaml/controls.yaml`. Does an existing control already cover this objective? If so, recommend **augmenting** that control rather than adding a near-duplicate. If genuinely distinct, state in one sentence what distinguishes it from the nearest existing control.

## Risk altitude tests

Apply each; report pass or adjust-with-fix.

- **R1 — Merge-vs-distinct two-test.** A candidate is a distinct risk only if it impacts a **different component locus** OR is a **distinct impact class**. If neither holds, it should merge into an existing risk (check `risk-map/yaml/risks.yaml`) — as an added paragraph or a `{{ref:}}` — rather than stand alone.
- **R2 — Wrong-home.** If a candidate resists clean merging *and* is not clearly distinct, it may belong to a domain the corpus lacks. Flag the missing domain rather than forcing it into the nearest existing risk.
- **R3 — Threat, not control-gap.** A risk names a way the system can be harmed, not the missing defense. "No input validation" is a control gap; the risk is the harm the gap enables. Rewrite a control-absence framing as the threat and its impact.
- **R4 — Real, not hypothetical.** A risk should be demonstrable — grounded in a real incident, research result, or vulnerability class, not a speculative "what if." If no such evidence exists, flag it rather than asserting the risk.

## Component altitude tests

Apply each; report pass or adjust-with-fix.

- **C1 — Absorb-or-decompose base test (both must hold to keep a new component).** (1) Can it absorb into an existing component (check `risk-map/yaml/components.yaml`)? (2) Would a reader still know *where* a control or risk applies at this grain? Outcomes: **absorb** into an existing component / **new at a de-sprawled band** / **decompose** an existing too-broad component.
- **C2 — Role, not product/protocol.** The component's identity is the role or locus it occupies; a specific product or protocol (a named framework, a vendor tool) is an attribute, not the identity. A protocol-named component invites sibling sprawl. Generalize, and keep the product only as an example. (Defer terminology to the classical-lexicon skill.)
- **C3 — Reader-instructive.** A component earns its place only if naming it tells a reader *where* a control or risk attaches. If adding it does not change where anything attaches, it is too fine-grained — absorb it.

## Output format

- Per test: **pass** or **adjust** with the specific fix.
- **Overall verdict:** one of *well-pitched* / *needs adjustment* (list the fixes) / *should merge or absorb* (name the target).
- If a test surfaces a maintainer decision (T4 unsolved problem, T6 arguable duplication), state it plainly rather than resolving it.
