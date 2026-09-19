---
name: explore-persona-self-id
description: "Help someone figure out which CoSAI Risk Map persona(s) they are — by walking the framework's identificationQuestions — and then show what that role should care about: the risks that impact them and the controls they are responsible for implementing. Read-only and guided. Use when someone asks \"which persona am I?\", \"where do I fit in the framework?\", or wants a guided self-assessment of their role and responsibilities. Use this when the question is identity-first (which persona/role am I, where do I fit); for the risks of a stated activity without first pinning a persona, use explore-risks-by-activity instead. NOT for authoring or editing personas (use persona-creator)."
---

# Explore: Which Persona Am I?

Guide a reader to their CoSAI Risk Map persona(s) using the framework's own `identificationQuestions`, then orient them to what that role must care about. **Read-only.**

## Audience and voice

Security-literate, new to CoSAI-RM. Explain what a persona/risk/control is; **link entity ids**. This is a guide, not an assessment of their security posture.

## How to answer

1. **Gather signal.** If the reader described their AI activities, use that. If they gave little, or the activity is ambiguous between adjacent roles, **ask the `identificationQuestions`** — read `risk-map/yaml/personas.yaml` and pose the most-distinguishing questions (a guided walkthrough). *(Explain: a persona is a role across the AI lifecycle; its identificationQuestions are activity-based yes/no self-ID questions.)*
2. **Identify the persona(s).** Match the answers to the persona whose questions they satisfy — and cite which questions matched. A reader may map to more than one (e.g. primarily *Application Developer*, partially *Agentic Platform and Framework Providers*); explain the scoping rather than forcing a single answer.
3. **Explain the role.** The persona's `description` + `responsibilities` — what this role is accountable for.
4. **Orient to exposure *and* duties.** For the identified persona, surface **both** sides of the persona model:
   - **Risks that impact you** — risks whose `personas` list includes your persona (you bear the consequences).
   - **Controls you implement** — controls whose `personas` list includes your persona (you are responsible for deploying them). *(Explain: risks list impacted parties; controls list implementers — so your persona appears in both, meaning different things.)*
5. **Link ids** and point to `explore-risks-by-activity` (deeper exposure) or `explain-entity` (any specific entry) for drill-down.

## Output (adaptive)

- **Enough signal** → identify the persona(s) + a concise briefing: *your role · your risks · your controls*.
- **Not enough signal** → guided: ask 2–4 distinguishing `identificationQuestions`, then identify.
- **Multiple personas** → name each and explain the boundary between them.
- Always link ids; note this reflects the current corpus.

## Boundaries

- **Read-only.** To add or change a persona, redirect to `persona-creator`.
- Identify only among the corpus's defined personas; if the reader fits none well, say so and name the closest.
- Don't judge their posture — orient them to their role's risks and controls; they decide.

## Reference

- `risk-map/yaml/personas.yaml` (the `identificationQuestions` are the self-ID instrument), `risks.yaml`, `controls.yaml`.
