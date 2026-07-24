---
name: explore-exposure
description: "Answer \"what risks and controls attach to <a product or component> in an agentic/AI system?\" — e.g. \"AWS Nitro Enclaves\", \"Pinecone as my vector store\", \"LangChain orchestration\", or a component id directly. Maps a product/technology to the CoSAI component(s) it implements or protects (hybrid: a curated product→component lexicon plus live lookup for unknowns), then surfaces that component's exposure — the controls that apply to it and the risks those controls address. Read-only exploration for security architects and engineers. Use when a named product, vendor, technology, or component is the subject and the reader wants its risk/control exposure. The subject must be a *specific* named product, vendor, technology, or component id (e.g. Pinecone, AWS Nitro, componentReasoningCore); for a role or persona (e.g. \"I'm a data provider\") or a generic product category (e.g. \"an AI coding assistant\"), use explore-risks-by-activity instead; for a plain-language definition of a single entry, use explain-entity. NOT for authoring content (use the creator agents)."
---

# Explore Exposure (by product or component)

Given a product/technology or a component, show its CoSAI Risk Map exposure — the controls that apply to it and the risks those controls address. **Read-only.**

**Key structural fact:** risks do *not* reference components directly. Exposure flows **component → the controls that apply to it (a control's `components` field) → the risks those controls address (the control's `risks` field)**. Make that indirection explicit to the reader.

## Audience and voice

Security architects/engineers. Explain framework terms (component, how controls/risks connect); **link every entity id**. When you map a product to a component, say *why*.

## How to answer

1. **Resolve to component(s).**
   - If the input is a **component** (id or name), use it directly.
   - If it's a **product/technology** (AWS Nitro, LangChain, Pinecone, an MCP server…), map it to the component(s) it implements or protects using `references/product-component-lexicon.md` (curated). *(Explain: components are the framework's architectural building blocks — the loci where risks and controls attach.)*
   - **Hybrid — if the product isn't in the lexicon:** reason about the role it plays, optionally confirm with a live web lookup, and map it to the nearest component(s) — but **flag it as an inferred mapping**, not a curated one. Do not present inference as corpus fact.
2. **Find the controls that apply.** In `risk-map/yaml/controls.yaml`, a control lists the components it applies to (`components`, or `"all"`). Grep for the component id. These are the controls relevant to that part of the system.
3. **Find the risks in play.** Collect the risks those applying controls address (each control's `risks` field) — that is the component's exposure, reached *through* its controls. Also include risks whose descriptions clearly target that component's locus (e.g. transport, tool, or memory risks). Explain the indirection.
4. **Present the exposure.** For the component(s): the risks it's exposed to (ids + a one-line why) and the controls that apply (ids + what they do). Call out the **product-specific angle** — what about *this product* matters most.
5. **Link ids;** adaptive; read-only.

## Output (adaptive)

- **"risks & controls for X"** → table(s): `Component` | risks (ids) | applying controls (ids).
- **"explain my exposure using X"** → a narrative: the product→component mapping, then the risks and the controls that matter most.
- **Unknown product** → state the (curated or inferred) mapping, flag inferred ones, then answer.
- Always link ids; note this reflects the current corpus; note when a product→component mapping is inferred rather than curated.

## Boundaries

- **Read-only.** To author a risk/control/component, redirect to the creator agents.
- **Be honest about the bridge.** The product→component mapping is a bridge (curated or inferred); the risks/controls are from the corpus. Don't blur the two, and flag inferred mappings.
- Surface only corpus risks/controls; don't invent exposure that isn't in the map.

## Reference

- `references/product-component-lexicon.md` — the curated product→component map (a living seed; live lookup fills gaps).
- `risk-map/yaml/{components,controls,risks}.yaml` (the live corpus — source of truth).
