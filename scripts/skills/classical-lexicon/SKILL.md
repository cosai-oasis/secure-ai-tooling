---
name: classical-lexicon
description: Ground CoSAI Risk Map terminology in established security terms of art. Use when authoring or critiquing a Control, Risk, Component, or Persona title or description to check a proposed term against the canonical (NIST-first) vocabulary, replace an invented term with its established equivalent, generalize a product/protocol-specific name to its role, or confirm a term is already grounded.
---

# Classical Lexicon

Check Risk Map terminology against established security terms of art. The governing rule: **never invent a term when an established term of art already exists.** This skill grounds a proposed term, regrounds an invented one, or confirms an existing term is already sound — it does not rewrite content wholesale.

## When to use

- Authoring a new Control / Risk / Component / Persona title or description.
- Critiquing a draft for coined or product-specific terminology.
- Deciding what to call a capability, role, mechanism, or locus — including a persona/role name, not only a control or risk mechanism term.

## When not to use

- Framework mapping IDs (MITRE ATLAS, NIST AI RMF, etc.) — that is the framework-mappings audit tooling's job.
- Prose style/format rules (bold, sentinels, length) — that is the prose-subset linter's job.

## Procedure

1. **Extract candidate terms** from the input: the nouns and noun-phrases that name a capability, security measure, role, mechanism, or architectural locus. These are where terminology matters.
2. **Look each up in the lexicon:** `references/lexicon.md`.
3. **Classify each candidate:**
   - **Grounded** — already an established term of art. Accept; name the source.
   - **Reground** — an invented or informal term with an established equivalent. Return the canonical term and the mapping.
   - **Generalize** — the term encodes a specific product or protocol (e.g. an `MCP`-prefixed name). The identity is the *role/locus*; the product is an attribute. Return the role-grain term; keep the product only as an example.
   - **Novel — flag** — no established term of art found. Do **not** coin one silently (see the maintainer-flag vocabulary below). "novel-flag" applies only when **no established term of art exists in the field**, not merely when the term is absent from this pinned lexicon snapshot; when you can ground a term via general NIST-first sourcing knowledge that the snapshot lacks, **ground it and propose the lexicon addition** rather than flagging it novel.
3b. **Record the international/standards equivalent — unconditionally, for grounding verdicts only.** This obligation applies to **grounded** and **reground** candidates — verdicts that ground a term in standards. For every such candidate, record its international/standards equivalent(s) (ISO/IEC, EU AI Act, ENISA, XACML, or other recognized non-US/international body). Do this every time a term is grounded or regrounded — not only when NIST is silent or the term is contested. A maintainer flag fires only when this equivalence check turns up a problem: the equivalent is missing (`D3b-parochialism`) or the equivalent conflicts with the NIST-first term (`naming-conflict` or `substantive-conflict`, see below). When the equivalent is present and agrees, record it and raise **no** maintainer flag.

   A **generalize** verdict is a naming-altitude move (product/protocol name → role/locus identity), not a grounding-in-standards move. It carries **no** international-equivalence obligation: record the international equivalent field as "not applicable" and raise **no** equivalence flag (`D3b-parochialism`, `naming-conflict`, or `substantive-conflict`) on a generalize verdict.
4. **Record the counterfactual** for every reground/generalize/novel result: `proposed → chosen → source (or "none found")`. This is inspectable reasoning, not a silent rename.

## NIST-first priority (ADR-031 D3a)

NIST's term is the term unless there is a strong, documented argument that it fails. Prefer, in order: NIST (SP 800-53 / 800-207 / 800-162, AI RMF), then other US/international standards bodies and classical literature (RFC, OWASP, MITRE, ISO, foundational papers).

If a contributor argues the NIST term fails and a new term is needed, **do not decide that here.** Surface it as a documented deviation for the maintainer to take into CoSAI governance review (issue / discussion). This skill grounds and flags; maintainers adjudicate.

## Global equivalence, unconditionally recorded (ADR-031 D3b)

A NIST label is adopted only after the concept is corroborated as globally recognized. For **every grounded or regrounded term** — not only contested or NIST-silent ones — record the cross-standard equivalence set: the canonical (NIST-first) label alongside its equivalent(s) in recognized international standards (ISO/IEC, EU AI Act, ENISA, XACML, or other national/international bodies). This is unconditional within its scope: run the equivalence check on every grounded/regrounded term, every time.

This equivalence check applies only to `grounded` and `reground` verdicts — the verdicts that ground a term in standards. A `generalize` verdict is a naming-altitude move, not a grounding move, and carries no equivalence obligation (see step 3b); never apply the equivalence check or its flags to a generalize verdict.

A maintainer flag fires only when the equivalence check itself turns up a problem, never merely because a term was checked:

- Equivalent present and agrees → record it, **no flag**.
- Equivalent missing → `D3b-parochialism`.
- Equivalent present but conflicts → `naming-conflict` or `substantive-conflict` (see the maintainer-flag vocabulary below).

The maintainer decides any flagged gap or conflict in governance review; this skill's obligation is to make sure they *see* it rather than having to watch non-US bodies by hand. Never resolve a missing or conflicting equivalent by inventing one — keep the grounded term and flag it.

## Maintainer-flag vocabulary

A closed, controlled set of four tokens. Use exactly one of these (or none) per candidate — never a free-form note in the Maintainer flag column.

- **`D3b-parochialism`** — no international/standards equivalent exists for the term (the term appears current only in one jurisdiction, or no crisp equivalent was found).
- **`naming-conflict`** — an equivalent exists but recognized standards use a materially different *label* for the same concept (e.g. "reference monitor" vs. Common Criteria's "reference validation mechanism"). A label mismatch only — the underlying concept is the same.
- **`substantive-conflict`** — same nominal concept, but the *content or scope* differs materially across standards (e.g. NIST AI RMF's seven trustworthiness characteristics vs. the EU HLEG's seven requirements — overlapping but not the same set). Distinct from `naming-conflict`, which is a label mismatch, not a scope/content mismatch.
- **`missing-pin`** — the canonical source cannot be pinned to a traceable dated edition (no stable citation to anchor the term).

Informational surfacing that broadens the base without a defect (e.g. acknowledging EU/ISO framings that agree with or extend NIST) is not a maintainer flag — record it as informational context, not one of the four tokens.

## Term verification (ADR-031 D4)

The lexicon holds **stable** canonical terms (PEP/PDP/PIP/PAP, reference monitor, least privilege) — treat these as a pinned snapshot. For a term or identifier that may have changed (a framework's evolving vocabulary), verify it against the source via WebSearch/WebFetch at use time rather than trusting the snapshot.

## Output format

For each candidate term, report:

| Candidate | Verdict | Canonical term | Canonical source | International equivalent(s) | Maintainer flag |
|---|---|---|---|---|---|

- **Verdict:** `grounded` · `reground` · `generalize` · `novel-flag`
- **International equivalent(s):** required for every `grounded`/`reground` row — the recognized non-US/international standard(s) that cover the same concept, or "none found" when the equivalence check found nothing. For a `generalize` row, record "not applicable" — generalize carries no equivalence obligation (step 3b).
- **Maintainer flag:** one of the four controlled tokens (`D3b-parochialism`, `naming-conflict`, `substantive-conflict`, `missing-pin`), or empty when the equivalence check found no problem. Never `D3b-parochialism`, `naming-conflict`, or `substantive-conflict` on a `generalize` row — that verdict is out of scope for the equivalence check entirely.

Close with the counterfactual list (`proposed → chosen → source`) for anything not already grounded.

## Reference

- `references/lexicon.md` — the canonical term set and the invented→canonical mappings, with sources.
