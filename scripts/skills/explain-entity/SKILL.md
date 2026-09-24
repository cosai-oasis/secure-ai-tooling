---
name: explain-entity
description: Explain a specific CoSAI Risk Map entry — a risk, control, component, or persona (by id or name) — in plain language for someone new to the framework, including its classical roots and how it connects to other entries. Read-only. Use when someone asks "what is <riskX / controlY / componentZ / personaW>?", "explain this risk/control", or wants to understand an entry and its relationships — a plain-language definition of one entry. For the risks and controls that attach to a component (its exposure) rather than a definition, use explore-exposure instead. NOT for authoring or editing an entry (use the creator agents).
---

# Explain Entity

Give a framework newcomer a clear, plain-language explanation of a single risk / control / component / persona — what it is, why it matters, its classical roots, and how it connects to the rest of the map. **Read-only.**

## Audience and voice

Security-literate, new to CoSAI-RM. Plain language; explain the framework's structure terms as you use them; **link every related entity id** so the reader can drill in.

## How to answer

1. **Resolve the entity.** Find it by id or name across `risk-map/yaml/{risks,controls,components,personas}.yaml` (grep). If a name matches several, list the candidates and ask which — or explain the closest and say so.
2. **Read its full definition** — risk: `shortDescription` + `longDescription` + `examples`; control: objective/description; component: description + `edges` + category; persona: description + `responsibilities` + `identificationQuestions`.
3. **Explain plainly:**
   - **What it is** — one plain sentence.
   - **Why it matters / what it's for.**
   - **Classical roots** — consult the `classical-lexicon` skill for the established concept it extends (a control's PEP / least-privilege grounding; a risk's classical analog such as confused deputy). Bridge classical→AI.
   - **Relationships** (the map connections), by type:
     - **risk** → the controls that address it, the personas it impacts, the components where it manifests.
     - **control** → the risks it addresses, the components it applies to, the personas who implement it.
     - **component** → its `edges` (to/from), and the controls/risks that attach to it.
     - **persona** → the risks that impact it, the controls it implements, its ISO 22989 / EU AI Act mapping.
4. **Link ids** for every related entity.

## Output (adaptive)

- **Default:** a concise explanation — what / why / classical roots / the key relationships.
- **"tell me more / full"** → expand all relationships and examples.
- **Ambiguous id/name** → list the candidate entries.
- Always link ids; note this reflects the current corpus.

## Boundaries

- **Read-only.** To change the entry, redirect to the relevant creator agent (`risk-/control-/component-/persona-creator`).
- Explain only what the corpus (plus its classical grounding) says; do not embellish beyond the definition or invent relationships.

## Reference

- `risk-map/yaml/{risks,controls,components,personas}.yaml` (the live corpus — source of truth).
- The `classical-lexicon` skill (for classical roots).
