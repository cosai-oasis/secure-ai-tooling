---
name: explore-framework-coverage
description: Show what the CoSAI Risk Map maps to a given external-framework entry — e.g. "everything under EU AI Act Article 14", "which risks map to MITRE ATLAS AML.T0051", "our NIST AI RMF GOVERN-6.2 coverage", "STRIDE Tampering", "ISO 22989 AI Producer". A read-only reverse index over the mappings across risks, controls, and personas, for auditors/compliance and architects checking framework coverage. Use when someone asks what maps to a framework id/article/category, or wants the framework coverage for a standard. NOT for auditing mapping style/correctness (use audit-framework-mappings) or selecting mappings while authoring (use mapping-selection).
---

# Explore: Framework Coverage

Given an external-framework entry, list the CoSAI Risk Map entities mapped to it — a **read-only reverse index** over the `mappings`. Consumer sibling of `audit-framework-mappings` (which audits mapping *quality*); reuse its knowledge of which frameworks apply to which entity types — don't duplicate its format rules.

## Audience and voice

Compliance/audit and architects, who may not know CoSAI internals. Explain the framework entry briefly; **link entity ids**.

## How to answer

1. **Identify the framework and entry.** Resolve which framework and the specific entry the reader means.
2. **Know where it can appear** (applicability — reuse the framework-mappings guide): MITRE ATLAS → risks (techniques `AML.T####`) and controls (mitigations `AML.M####`); NIST AI RMF → controls; STRIDE → risks; OWASP Top 10 for LLM → risks and controls; ISO 22989 → personas; EU AI Act → controls and personas. Only search the entity types where the framework actually applies.
3. **Search the corpus mappings** for the value. Values are **version-pinned** (ADR-027) — search the pinned form, e.g. `Article 14@2024`, `GOVERN-6.2@1.0`, `AML.T0051@5.0.1`, `LLM06:2025`, `Tampering`, `AI Producer@2022`. Grep the `mappings` blocks in `risk-map/yaml/{risks,controls,personas}.yaml`.
4. **Report coverage.** The entities mapped to it (ids + titles), grouped by entity type; a one-line note of what the framework entry is; and any **coverage gap** ("no controls currently map to this" — a real and useful finding for an auditor).
5. **Link ids**; adaptive output.

## Output (adaptive)

- **"what maps to X"** → table: `Entity (id — title)` | type | brief role.
- **coverage question** → the list + an explicit gap note if the count is low/zero.
- **unknown/ambiguous entry** → confirm the framework + entry (and that the framework applies to some entity type), then answer.
- Always link ids; note this reflects the current corpus.

## Boundaries

- **Read-only, and coverage-only.** You search for a framework value and report what maps to it. Judging whether a mapping is correctly *formatted* or *version-pinned*, or *checking/fixing* a mapping's correctness, is **`audit-framework-mappings`'s job, not yours** — redirect such questions there rather than answering them, and never perform or restate format/version-pinning rules yourself (that is the drift `audit-framework-mappings` and the style guide own). To select mappings while authoring use `mapping-selection`.
- Report only what is in the corpus; flag gaps — do not author or infer mappings that aren't there.
- Consumer sibling of `audit-framework-mappings` — reuse its applicability knowledge; don't restate its format rules.

## Reference

- `risk-map/yaml/{risks,controls,personas}.yaml` (the `mappings` — source of truth).
- `risk-map/docs/contributing/framework-mappings-style-guide.md` (framework applicability + pinned forms), and the `audit-framework-mappings` skill.
