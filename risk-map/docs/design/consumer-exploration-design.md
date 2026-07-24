# Consumer Exploration Design

This document records the framework-content and UX design behind the read-only
consumer exploration skill surface — the six `explore-*` skills. [ADR-032](../../../docs/adr/032-consumer-exploration-skills.md)
decided the *tooling architecture* for that surface and deliberately deferred two
content/design-shaped specifics to a companion note: the exact **query phrasings**,
and the product→component **lexicon contents and curation ownership**. This is that
note. It records design intent and curation governance; it does **not** restate
skill behavior — the canonical skills under `scripts/skills/explore-*` remain the
source of truth for what they do.

**Version:** 1.0
**Last Updated:** 2026-07-13

---

## Table of Contents

- [Overview](#overview)
- [Scope: what this note owns vs. what the skills own](#scope-what-this-note-owns-vs-what-the-skills-own)
- [The six query modes and their phrasings](#the-six-query-modes-and-their-phrasings)
- [Disambiguating the modes](#disambiguating-the-modes)
- [The product→component lexicon](#the-productcomponent-lexicon)
- [Output and UX conventions](#output-and-ux-conventions)
- [Known gaps and future work](#known-gaps-and-future-work)
- [References](#references)

---

## Overview

The exploration surface ([ADR-032](../../../docs/adr/032-consumer-exploration-skills.md))
gives framework *consumers* — security architects, developers new to the framework,
and security-literate system architects who are not assumed to know the framework
internals — a low-friction, **read-only** way to navigate the corpus (risks,
controls, components, personas) rather than author it. It is six focused skills, one
per query mode, under `scripts/skills/explore-*`, paired with a consumer how-to guide
([`exploring-the-risk-map.md`](../exploring-the-risk-map.md)).

This note is the design companion to that surface. It records the reasoning behind
the query-mode split and the trigger phrasings, and the governance model for the one
curation surface the design introduces: the product→component lexicon.

## Scope: what this note owns vs. what the skills own

The framework's skill discipline is **defer, don't duplicate** — restating a skill's
behavior in a second document is how a copy silently drifts stale. This note holds to
that. It owns:

- the **design intent** behind the six query modes and their trigger phrasings, and
  how a consumer's phrasing routes to a mode ([below](#the-six-query-modes-and-their-phrasings));
- the **design and curation governance** of the product→component lexicon — its
  structure, the curated-vs-inferred honesty rule, and (the specific deferral in
  ADR-032's Follow-up) who owns it and how it is extended ([below](#the-productcomponent-lexicon)).

It does **not** own, and does not copy:

- the runtime query procedures — those live in each `scripts/skills/explore-*/SKILL.md`;
- the **live lexicon table** — that ships bundled inside the skill (see below), so
  the skill stays self-contained and portable.

## The six query modes and their phrasings

The surface is split by **input type** — what the consumer already has in hand — not
by output type. This is the design rationale for ADR-032 D2 ("focused skills, one per
query mode, no router"): six descriptions tuned to be mutually disambiguating let the
harness pick the right skill from the consumer's phrasing without a dispatch layer.

Each mode has a canonical question form; the authoritative, live copy of each is the
`description` frontmatter of its skill (that is the runtime trigger surface). The
design intent per mode:

| Input the consumer starts with | Canonical question phrasing | Skill |
|---|---|---|
| An **activity or role** ("I develop agents", "I use an AI coding assistant", "I host third-party models") | *"what risks am I exposed to if I &lt;do X with AI&gt;?"* | `explore-risks-by-activity` |
| A **classical security concept** (PEP, least privilege, reference monitor, defense in depth, zero trust, attestation, provenance) | *"what CoSAI controls are like &lt;a classical concept&gt;?"* | `explore-controls-by-classical` |
| A **named product / technology, or a component id** (AWS Nitro, Pinecone, LangChain, or `componentReasoningCore`) | *"what risks and controls attach to &lt;a product or component&gt;?"* | `explore-exposure` |
| **Identity-first** — the consumer wants to be classified | *"which persona am I?"* (walk the persona `identificationQuestions`) | `explore-persona-self-id` |
| An **external-framework entry** (EU AI Act Article 14, MITRE ATLAS AML.T0051, NIST AI RMF GOVERN-6.2, STRIDE Tampering, ISO 22989 AI Producer) | *"what does the Risk Map map to &lt;that framework entry&gt;?"* | `explore-framework-coverage` |
| A **single entity id or name** the consumer wants defined | *"what is &lt;riskX / controlY / componentZ / personaW&gt;?"* | `explain-entity` |

## Disambiguating the modes

Three boundaries carry most of the ambiguity. The design draws them by input type, and
these are the same discriminators surfaced to consumers in the how-to guide; this note
records *why* they are drawn where they are:

- **Role/activity vs. specific product.** A generic category or role ("I build agentic
  apps") is an *activity* → `explore-risks-by-activity`. A *named* product, technology,
  or component id ("Pinecone", `componentTools`) is *exposure* → `explore-exposure`.
- **Identity-first vs. activity.** When the consumer wants to be *classified* ("where do
  I fit?") → `explore-persona-self-id`. When they already *state* what they do and want
  its risks → `explore-risks-by-activity`.
- **Define vs. expose.** "What *is* `componentX`?" (a definition) → `explain-entity`.
  "What *attaches to* `componentX`?" (its risks and controls) → `explore-exposure`.

## The product→component lexicon

The one place the exploration surface needs knowledge *outside* the corpus is
`explore-exposure`'s product→component resolution (ADR-032 D5): mapping a named product
or technology to the CoSAI component(s) it implements or protects.

**Home / source of truth for the contents.** The live lexicon ships bundled with the
skill at
[`scripts/skills/explore-exposure/references/product-component-lexicon.md`](../../../scripts/skills/explore-exposure/references/product-component-lexicon.md),
so the skill is self-contained and portable (ADR-032 D3). That file is the
authoritative copy of the *contents*. This note
deliberately does **not** reproduce the table — a second copy is exactly the drift
hazard the defer-don't-duplicate rule exists to prevent.

> **Design resolution.** ADR-032's Follow-up placed "the lexicon contents" in this
> design note. In implementation the contents ship bundled with the skill (portability
> requires it, per ADR-032 D3's self-contained skills), so this note owns the lexicon's
> **design and governance** while the skill remains the home of the **contents** — no
> second copy of the table. This split (governed here, contents shipped with the skill)
> is the intended design and needs no ADR-032 amendment.

**Structure (design).** The lexicon is a **seed**, not a comprehensive registry —
category-grouped tables (confidential/isolated compute, model serving/inference,
model & data storage/registries, agent frameworks/orchestration, retrieval/memory,
I/O handling & guardrails — these mirror the lexicon file's own `##` category
headings; resync this list if that file is reorganized). Each row maps a
product/technology to the component id(s)
it **implements** (it *is* that locus) or **protects** (it secures that locus), with a
short note that says which and why. Component ids are verified against
[`components.yaml`](../../yaml/components.yaml).

**The curated-vs-inferred honesty rule (ADR-032 D5).** A *listed* product is a
**curated** mapping. An *unlisted* product is resolved by inferring the nearest
component from its role (optionally confirmed via a live web lookup) and **must be
flagged as inferred** — never presented as corpus fact. This rule is the design's
answer to the staleness risk ADR-032 named in its Consequences: comprehensiveness is
delegated to the inferred-with-flag path so the *curated* set can stay small.

**Curation ownership (the deferral).**

- The lexicon is a **living seed**, extended as products come up. Additions are
  **content changes** routed through the normal content workflow (Content Reviewer),
  not code changes — even though the file physically lives under `scripts/skills/`.
- Every entry must (a) target a real component id, verified against
  [`components.yaml`](../../yaml/components.yaml) at review time, and (b) state whether
  the product *implements* or *protects* that component.
- **Bounded by design.** The curation burden is kept small on purpose: the seed covers
  common, stable products; the long tail is served by the inferred-with-flag path, not
  by growing the table toward completeness.
- **Staleness guard.** Component ids evolve; the file carries a "verify ids against
  `components.yaml` before relying on them" note as the runtime guard, and review-time
  id-verification is the curation-time guard.

## Output and UX conventions

Recorded as design intent (ADR-032 D2/D4); the skills implement these:

- **Adaptive output** to the query — a table for "show me all", a short narrative for
  "explain", a clarifying question when the input is ambiguous.
- Always **name specific entity ids** for drill-down, and **explain framework terms
  inline** (the audience is assumed security-literate, not framework-familiar).
- **Read-only boundary** (D4): the skills read and explain; a consumer who wants to
  *author* is redirected to the ADR-031 creator agents, and the surface stays distinct
  from `content-reviewer` (the submission gate). Three roles stay separated —
  **explore** (this surface), **author** (ADR-031), **gate** (`content-reviewer`).

## Known gaps and future work

- **Lexicon ownership cadence.** The curated-vs-inferred split bounds the curation
  burden, but the seed will need periodic pruning as component ids evolve; revisit if
  the inferred-path flag proves insufficient in practice.
- **Eval story.** An exploration eval is a *query → expected set of surfaced entities*
  (ADR-032 D1), shipped per-skill as a portable `evals/evals.json`. These run as
  docs-only specs today; whether to adopt or build an in-repo eval runner is an open,
  separately tracked decision.

## References

- [ADR-032: Read-only consumer exploration skill surface](../../../docs/adr/032-consumer-exploration-skills.md) — the tooling decision this note companions.
- [ADR-031: Authoring-time agents and skills](../../../docs/adr/031-authoring-time-agents-and-skills.md) — the `scripts/skills/` canonical home and the defer-don't-duplicate principle this note inherits.
- The six skills: `scripts/skills/explore-risks-by-activity`, `explore-controls-by-classical`, `explore-exposure`, `explore-persona-self-id`, `explore-framework-coverage`, `explain-entity`.
- [`exploring-the-risk-map.md`](../exploring-the-risk-map.md) — the consumer-facing how-to guide (the user-facing companion to this design-facing note).
- [`product-component-lexicon.md`](../../../scripts/skills/explore-exposure/references/product-component-lexicon.md) — the live lexicon contents.
- [`components.yaml`](../../yaml/components.yaml) — the component-id source the lexicon verifies against.
