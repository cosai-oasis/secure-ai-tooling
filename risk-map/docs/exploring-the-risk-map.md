# Exploring the Risk Map

The CoSAI Risk Map ships a set of **read-only exploration skills** that help
you find your way around the framework — what risks apply to you, what a
named product's exposure looks like, which persona you are, and so on. They
never change the corpus; they only read and explain it.

This guide explains **how to pick the right one for your question**. It does
not restate what each skill does internally — each skill's canonical
definition under [`scripts/skills/`](../../scripts/skills/) is the source of
truth for its behavior. Read those when you want the exact procedure; read
this when you want to know where to start.

---

## Who this guide is for

- You are new to the CoSAI Risk Map and want to find the risks, controls, or
  persona relevant to what you actually do with AI.
- You have a specific product, vendor, or technology in mind and want to know
  its risk/control exposure.
- You know classical security and want to find the framework's analogues to a
  concept you already understand.
- You are checking coverage against an external framework (NIST AI RMF, MITRE
  ATLAS, OWASP, STRIDE, ISO 22989, the EU AI Act).
- You just want a plain-language explanation of one entry.

If you want to *author or change* an entry rather than explore the existing
framework, these skills are the wrong tool — see
[the authoring guide](contributing/authoring-with-agents.md) and the
creator agents instead.

---

## The six query modes

Each skill answers one shape of question. The discriminator is **what kind of
thing you're starting from** — an activity, an identity, a named product, a
classical concept, an external-framework entry, or a single entity you want
defined.

| Your starting point | Skill |
|---|---|
| An **activity or role** ("I develop agents", "I host third-party models", "I use an AI coding assistant") | [`explore-risks-by-activity`](../../scripts/skills/explore-risks-by-activity/) |
| **Identity-first** — you don't know your role yet ("which persona am I?", "where do I fit?") | [`explore-persona-self-id`](../../scripts/skills/explore-persona-self-id/) |
| A **specific named product, vendor, technology, or component id** (e.g. a named vector database, a confidential-computing product, a component id) | [`explore-exposure`](../../scripts/skills/explore-exposure/) |
| A **classical security concept** (policy enforcement point, least privilege, reference monitor, zero trust, attestation, provenance) | [`explore-controls-by-classical`](../../scripts/skills/explore-controls-by-classical/) |
| An **external-framework entry** (a NIST AI RMF subcategory, a MITRE ATLAS technique, an OWASP LLM Top 10 item, a STRIDE category, an EU AI Act article, an ISO 22989 term) | [`explore-framework-coverage`](../../scripts/skills/explore-framework-coverage/) |
| A **single entity** you want defined (a risk, control, component, or persona by id or name) | [`explain-entity`](../../scripts/skills/explain-entity/) |

---

## The boundaries that matter

The six modes overlap in ways that are easy to miss. These are the
distinctions the skills themselves encode — worth stating explicitly here
because getting the wrong one gives you a shallower answer.

- **A role or a generic product category is an activity, not a named
  product.** "I'm a data provider" and "an AI coding assistant" both route to
  `explore-risks-by-activity`, even though the second one sounds product-like
  — it's a category, not a specific vendor/technology. Only a *specific*
  named product, vendor, or component id routes to `explore-exposure`.
- **A specific named product routes to `explore-exposure`, not
  `explore-risks-by-activity`,** even if you phrase the question as an
  activity ("I use \<specific product\> as my vector store"). The presence of
  a named product is what tips it.
- **Identity-first questions route to `explore-persona-self-id`, not
  `explore-risks-by-activity`.** If you don't yet know your role and want to
  be walked through figuring it out, start with self-ID. If you already know
  what you do and just want the risks, go straight to
  `explore-risks-by-activity` — it derives your persona along the way, it
  just doesn't lead with the identity question.
- **A single entity you want defined is `explain-entity`, not
  `explore-exposure`** — even when the entity is a component. Asking "what is
  \<component\>?" is a definition question; asking "what risks and controls
  attach to \<a product that implements this component\>?" is an exposure
  question. `explain-entity` and `explore-exposure` cross-reference each
  other for exactly this handoff.

If you're still unsure which mode fits, start with whichever skill looks
closest — each one tells you plainly when your question is really a better
fit for a sibling, and redirects you there.

---

## Read-only, and what happens next

All six skills are strictly read-only: they explain what is in the corpus and
never edit it. If exploring surfaces something you think should change — a
risk that doesn't quite fit, a control you think is missing, a persona
question that doesn't distinguish your role — that's an authoring question,
not an exploration one. See [the authoring guide](contributing/authoring-with-agents.md)
and the `{type}-creator` agents for turning that into a draft, and
`content-reviewer` for the submission gate.

---

## Invoking these in your harness

This guide is deliberately vendor-neutral: it names the skills and says *when*
to use each one, not *how* to wire it into a specific tool. The skills are
Agent-Skills definitions under [`scripts/skills/`](../../scripts/skills/);
adapting them to your own harness (invocation mechanics, tool wiring) is the
consumer's responsibility. See
[`scripts/skills/README.md`](../../scripts/skills/README.md) for the skill
format and the neutrality contract that governs the tree.
