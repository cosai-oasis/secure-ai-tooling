---
name: mapping-selection
description: "Select the structured references and framework mappings for a CoSAI Risk Map control or risk — for a control: which components it applies to, which risks it addresses, and which mappings (MITRE ATLAS mitigations, NIST AI RMF subcategories, OWASP LLM) fit; for a risk: which components it impacts, which controls address it, and which mappings (MITRE ATLAS techniques, STRIDE, OWASP LLM) fit. Use when authoring or reviewing a control and choosing its components/risks/mappings, or when a mapping looks off (wrong NIST function, a technique used where a mitigation belongs, or over-mapping). Grounds every choice in the actual corpus and the framework applicability rules rather than guessing."
---

# Mapping Selection

Choose a control's structured references — **components**, **risks**, and **framework mappings** — and justify each. The failure this skill prevents is confident-but-wrong selection: mapping to "related" rather than directly-relevant items, over-mapping, mixing MITRE techniques with mitigations, or picking the wrong NIST AI RMF function.

Scope: both the **control** direction (a control's components/risks/mappings) and the **risk** direction (a risk's components/controls/mappings) — see the two sections below.

## Procedure

### 1. Components — where the defense lives

Read `risk-map/yaml/components.yaml`. Select the components where the control's mechanism actually operates — the locus of the defense. Guidance:

- Prefer the **specific** components. Each one you list should be a place the control genuinely acts, not merely a place the risk appears.
- Use `"all"` only for a universal/governance/assurance control that genuinely applies framework-wide.
- Use `"none"` only when the control applies to no specific component.
- Do not over-select. If you are tempted to list five components, check whether the control is really one control or several.

### 2. Risks — what the control addresses

Read `risk-map/yaml/risks.yaml`. Select the risks this control directly mitigates. A mapping should be defensible in one sentence ("this control reduces the likelihood/impact of risk X because…"). Flag any that are merely "related." Be selective.

If you set `risks: "all"`, the control is **universal** — and those risks must **not** list it back (application is implicit). `"none"` is not valid for `risks`.

### 3. Framework mappings — the discipline

Read `references/frameworks-applicability.md` for the rules. In brief:

- **Applicability:** map only to frameworks that apply to controls.
- **MITRE ATLAS:** controls map to **mitigations** (`AML.M####`), never techniques (`AML.T####`). If no mitigation fits cleanly, omit ATLAS rather than forcing a technique.
- **NIST AI RMF:** use the **subcategory** id (e.g., `GOVERN-6.2`), never the category alone, and pick the **right function** — this is the most common mistake:
  - **GOVERN** — policy, roles, responsibilities, oversight, culture, risk tolerance. *Most preventive design and human-oversight controls land here.*
  - **MAP** — establishing context, framing intended use, identifying impacts.
  - **MEASURE** — assessment, testing, metrics, evaluation, tracking.
  - **MANAGE** — responding to, prioritizing, treating, and recovering from identified risks (reactive/operational). *Do not use MANAGE for a preventive design control.*
- **OWASP Top 10 for LLM:** `LLMxx:2025`.
- **Selective:** soft cap of 4 per framework; one-sentence rationale each.
- **Generate, don't hand-spell:** mapping values are version-pinned. Produce them with `scripts/framework_mapping_maintainer.py` (ADR-027). If you cannot run it, state the intended mappings and mark them **for tool-generation**.

### 4. Reciprocity

For each risk in the control's `risks` list (unless universal), name the reciprocal `risks.yaml` edit: that risk's `controls` array must list this control back.

## Risk direction

For a **risk** entry, the mirror of the control procedure:

### Components — where the risk manifests
Read `risk-map/yaml/components.yaml`. Select the components where the risk actually arises or takes effect (its locus). Be specific; do not list components the risk is merely "related" to.

### Controls — what addresses it (control-selection)
Read `risk-map/yaml/controls.yaml`. Select the controls that directly mitigate this risk, each defensible in one sentence. "Related" is not "addresses." Do **not** list a universal control (one with `risks: "all"`) — its application is implicit.

### Framework mappings — the risk-side rules
- **MITRE ATLAS:** risks map to **techniques** (`AML.T####`), never mitigations (`AML.M####`) — the mirror of the control rule. Do not map both a parent technique and its sub-technique.
- **STRIDE:** one or more of the six categories (`spoofing`, `tampering`, `repudiation`, `information-disclosure`, `denial-of-service`, `elevation-of-privilege`). STRIDE is risk-side.
- **OWASP Top 10 for LLM:** `LLMxx:2025`.
- **NIST AI RMF does NOT apply to risks** — it is control-side only. Do not add a NIST AI RMF mapping to a risk.
- Selective (≤4/framework), one-sentence rationale each, `[tool-generate]` the pinned values.

### Reciprocity
For each control in the risk's `controls` list, that control's `risks` array must list this risk back (`risk.controls` ↔ `control.risks`).

## Output format

- **Components:** list, each with a one-line reason (the locus).
- **Risks:** list, each with a one-line reason (direct relevance).
- **Mappings:** per framework, each value with a one-line rationale and a `[tool-generate]` marker if not yet generated.
- **Reciprocal edits:** the exact `risks.yaml` `controls` additions.
- **Flags:** anything uncertain — a mapping that needs framework-text verification, a component you were unsure about, a possible over-map.

## Reference

- `references/frameworks-applicability.md` — applicability matrix, MITRE mitigation-vs-technique rule, and the NIST AI RMF function cheat-sheet.
- Authoritative source: `risk-map/docs/contributing/framework-mappings-style-guide.md` (canonical pinned patterns and the maintainer tool).
