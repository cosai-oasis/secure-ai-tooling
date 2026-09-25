---
name: explore-controls-by-classical
description: Answer "what CoSAI controls are like <a classical security concept>?" — map an established security idea (e.g. policy enforcement point / PEP, least privilege, reference monitor, defense in depth, zero trust, attestation, provenance) to the CoSAI Risk Map controls that embody or extend it, and explain the classical→AI bridge. Read-only exploration for security architects and engineers who know classical security and want its analogues in the framework. Use when someone asks which controls correspond to a classical concept, term of art, or standard. NOT for authoring/editing (use control-creator) or grounding terminology while authoring (use classical-lexicon).
---

# Explore Controls by Classical Concept

Help someone who knows classical security find its analogues among the CoSAI controls, and see how the framework extends the concept to AI/agentic systems. **Read-only.**

This is the **consumer, read-only sibling of the `classical-lexicon` skill** (which grounds terminology at *authoring* time). Reuse its lexicon for the grounding — do not re-derive or duplicate it.

## Audience and voice

Classical-security-literate, new to CoSAI-RM. Explain framework terms (control, the risks a control addresses); **link every control id**; make the classical→AI bridge explicit.

## How to answer

1. **Ground the classical concept.** Consult the `classical-lexicon` skill for the canonical term of art and its meaning/aliases (e.g. "PEP" = Policy Enforcement Point, NIST SP 800-207 / 800-162). Confirm you're mapping the right concept.
2. **Find the controls that embody it.** Search `risk-map/yaml/controls.yaml` — the corpus already grounds many controls classically (e.g. "least-privilege principle", "reference monitor", "attestation", "provenance", "confused deputy"). Grep the canonical term and its synonyms across control titles and descriptions.
3. **Explain the bridge.** For each matching control: id + title, *how* it embodies or extends the classical concept, and the AI-specific amplifier (what's different/harder in AI/agentic systems). Distinguish "directly embodies" from "related/adjacent".
4. **Attach exposure.** Note the risks each surfaced control addresses (its `risks` field) so the reader sees what it's *for*.
5. **No clean match?** Say so plainly and point to the nearest controls; note it may be a coverage gap. Surface it — do not author.

## Output (adaptive)

- **"what controls map to X"** → table: `Control (id — title)` | how it embodies X | risks it addresses.
- **"how does X show up in the framework"** → a narrative classical→AI bridge.
- **Unknown/ambiguous concept** → confirm it via `classical-lexicon`, then answer.
- Always link control ids; note this reflects the current corpus.

## Boundaries

- **Read-only.** To author a control or reground a term, redirect to `control-creator` / `classical-lexicon`.
- Surface only controls that exist in the corpus; do not invent.
- Consumer sibling of `classical-lexicon` — reuse its grounding, don't duplicate it.

## Reference

- The `classical-lexicon` skill (canonical term set — reuse for grounding).
- `risk-map/yaml/controls.yaml`, `risks.yaml` (the live corpus — source of truth).
