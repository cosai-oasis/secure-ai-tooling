# Common Review Findings

This document lists the issues reviewers flag most often on new and updated CoSAI-RM content. Use it as a companion to [`submission-readiness-guide.md`](./submission-readiness-guide.md) — that guide tells you how to prepare a good proposal; this one tells you what goes wrong most often.

Findings are grouped by severity. Structural issues block submission until fixed. Content-quality issues are flagged for human review and usually trigger a DISCUSS verdict.

## Contents

**Structural issues (block submission)**

1. [ID convention violation or collision](#1-id-convention-violation-or-collision)
2. [Dangling references](#2-dangling-references)
3. [Bidirectional inconsistency](#3-bidirectional-inconsistency)
4. [Missing required fields](#4-missing-required-fields)
5. [Invalid enum value](#5-invalid-enum-value)
6. [Raw HTML or inline URL in prose](#6-raw-html-or-inline-url-in-prose)
7. [Bare identifier in prose (use a sentinel)](#7-bare-identifier-in-prose-use-a-sentinel)
8. [Unresolved or malformed sentinel](#8-unresolved-or-malformed-sentinel)
9. [Retired field (`relevantQuestions`)](#9-retired-field-relevantquestions)

**Content-quality issues (flagged for human review)**

1. [Under-specification: description is too generic](#1-under-specification-description-is-too-generic)
2. [Over-specification: mandates a specific vendor or technology](#2-over-specification-mandates-a-specific-vendor-or-technology)
3. [Scope creep: one entry covers 2+ distinct concerns](#3-scope-creep-one-entry-covers-2-distinct-concerns)
4. [Wrong persona model: implementers listed on a risk](#4-wrong-persona-model-implementers-listed-on-a-risk)
5. [`personaGovernance` on a risk](#5-personagovernance-on-a-risk)
6. [Universal control listed explicitly on a risk](#6-universal-control-listed-explicitly-on-a-risk)
7. [Examples are hypothetical or vendor announcements](#7-examples-are-hypothetical-or-vendor-announcements)
8. [Framework mapping ID doesn't exist or is the wrong type](#8-framework-mapping-id-doesnt-exist-or-is-the-wrong-type)
9. [Parent technique and sub-technique both listed (MITRE ATLAS)](#9-parent-technique-and-sub-technique-both-listed-mitre-atlas)
10. [Missing classical security equivalent](#10-missing-classical-security-equivalent)
11. [Title doesn't follow the style guide](#11-title-doesnt-follow-the-style-guide)
12. [Identification questions are miscalibrated (personas)](#12-identification-questions-are-miscalibrated-personas)

---

## Structural issues (block submission)

These are auto-detected by the content-reviewer agent and validation tooling. A proposal with any of these findings cannot proceed until the issue is resolved.

### 1. ID convention violation or collision

The ID derived from the title is malformed (wrong casing, separators, uppercase abbreviation) or collides with an existing entry. The fix is always in the **title**, since the ID is mechanically derived from it.

- Malformed examples: title yielding `risk_data_poisoning`, `RiskDataPoisoning`, or `riskMCPInjection`.
- Collision example: a "Prompt Injection" proposal when `riskPromptInjection` already exists.
- Fix: rewrite the title so the derived ID is lowercase prefix + camelCase and unique. To resolve collisions, add the discriminating dimension (surface, technique, scope) — do not suffix numbers or abbreviate. See [`submission-readiness-guide.md §1`](./submission-readiness-guide.md#section-1-creating-a-valid-id).

### 2. Dangling references

A field points to an ID that does not exist in the framework.

- Example: a risk lists `controlFooBar` but no such control is defined.
- Fix: verify every ID against the current YAML files. If the target entry doesn't exist yet, propose it separately.

### 3. Bidirectional inconsistency

Two entries reference each other asymmetrically — e.g., a control lists a risk but the risk doesn't list that control back.

- Fix: when you propose an update that adds a relationship, update **both sides** of the edge.

### 4. Missing required fields

A field required by the schema is empty or absent.

- Common omissions: `shortDescription`, `category`, `personas`, `examples`.
- Fix: consult the schema file and the relevant issue template. Every `required: true` field must have content.

### 5. Invalid enum value

A field constrained by schema enum (e.g., `category`, `lifecycle`, `impact`, `actorAccess`) contains a value outside the allowed set.

- Fix: copy the allowed values from the schema; do not invent new categories inline.

### 6. Raw HTML or inline URL in prose

A prose field (`description`, `shortDescription`, `longDescription`, `examples`, `responsibilities`, `tourContent.*`) contains a raw HTML tag (`<a>`, `<strong>`, `<em>`, `<br>`, …) or an inline URL of any scheme (`https://…`, `[text](url)`, `mailto:`, …). The `validate-yaml-prose-subset` and `validate-prose-references` hooks block both ([ADR-017](../../../docs/adr/017-yaml-prose-authoring-subset.md), [ADR-016](../../../docs/adr/016-reference-strategy.md)).

- Fix (emphasis): use `**bold**`, `*italic*`/`_italic_` — never `<strong>`/`<em>`.
- Fix (links/citations): move the URL into the entry's `externalReferences` array (`type`, `id`, `title`, `url`) and reference it from prose with a `{{ref:identifier}}` sentinel. There is no inline-URL form. See [`yaml-authoring-subset.md`](../yaml-authoring-subset.md).

### 7. Bare identifier in prose (use a sentinel)

Prose mentions another entity by writing its bare camelCase ID (`riskPromptInjection`, `controlInputValidationAndSanitization`) instead of a sentinel. `validate-prose-references` blocks bare IDs that match the known prefixes ([ADR-016](../../../docs/adr/016-reference-strategy.md) D6).

- Fix: wrap the mention in a `{{<entity-id>}}` sentinel — `{{riskPromptInjection}}`. The generator resolves it to the entity's title (tables) or an in-page link (site). Authors never hand-write the display title.

### 8. Unresolved or malformed sentinel

A `{{…}}` sentinel does not resolve: `{{<entity-id>}}` names an ID absent from the schema enum, or `{{ref:identifier}}` names an `id` absent from the entry's `externalReferences`. `validate-prose-references` blocks it, and both generators fail the build on an unresolved sentinel.

- Fix: correct the ID to match the schema enum, or add the missing `externalReferences` entry. Per-entry `id` values must be unique within the entry.

### 9. Retired field (`relevantQuestions`)

The proposal adds a `relevantQuestions` field to a risk. The field was removed from `risks.schema.json` in the conformance sweep ([ADR-019](../../../docs/adr/019-risks-schema.md) D6); `additionalProperties: false` now rejects it at commit.

- Fix: remove the field. It had no consumer. Reader-facing questions belong to personas (`identificationQuestions`), not risks.

---

## Content-quality issues (flagged for human review)

These are not auto-blocking but almost always trigger reviewer feedback. Addressing them upfront speeds the path to PROCEED.

### 1. Under-specification: description is too generic

The long description could apply to any software system, not specifically to AI or agentic systems.

- Symptom: no mention of model training, inference, prompts, agents, tools, or AI-specific data flows.
- Fix: state the classical security equivalent first, then name the AI-specific amplifier.

### 2. Over-specification: mandates a specific vendor or technology

The entry names a product, library, or vendor as the canonical implementation.

- Fix: describe the capability, not the implementer. Vendor examples belong in the `examples` field with citations, not in the core description.

### 3. Scope creep: one entry covers 2+ distinct concerns

The proposal bundles multiple risks or controls that should be separate entries.

- Symptom: the title contains "and," the description switches topics midway, or the personas/controls lists span unrelated domains.
- Fix: split into multiple proposals. One entry, one concern.

### 4. Wrong persona model: implementers listed on a risk

The risk's `personas` field lists who would mitigate the risk rather than who is impacted.

- Fix: re-read [`submission-readiness-guide.md §3`](./submission-readiness-guide.md#section-3-the-persona-model). Risks list impacted personas; controls list implementer personas.

### 5. `personaGovernance` on a risk

Governance is a control-side role. It should never appear on a risk's persona list.

- Fix: remove `personaGovernance` from the risk. If the governance angle is important, it belongs in an associated governance control.

### 6. Universal control listed explicitly on a risk

The risk's `controls` field includes one of the 7 universal controls (`controlRedTeaming`, `controlVulnerabilityManagement`, `controlThreatDetection`, `controlIncidentResponseManagement`, `controlInternalPoliciesAndEducation`, `controlProductGovernance`, `controlRiskGovernance`).

- Fix: remove them. Universal controls apply via `risks: all` and should never be enumerated per-risk.

### 7. Examples are hypothetical or vendor announcements

The `examples` field cites "what if" scenarios or product launch blog posts rather than real incidents or research.

- Fix: replace with published incidents, academic papers, CVEs, or post-mortems. Every example must be backed by a verifiable source — but the URL lives in the entry's `externalReferences` array, not inline. Reference it from the example prose with a `{{ref:identifier}}` sentinel ([ADR-016](../../../docs/adr/016-reference-strategy.md)). See [`yaml-authoring-subset.md`](../yaml-authoring-subset.md) for the structured-citation flow.

### 8. Framework mapping ID doesn't exist or is the wrong type

The proposal maps to an invalid MITRE ATLAS technique, a non-existent OWASP LLM entry, applies a mitigation ID to a risk (or vice versa), or uses a non-canonical identifier form (lowercase STRIDE, `GV-/MP-/MS-/MG-` NIST abbreviations, un-versioned `LLM##`).

- Fix: verify each ID against the referenced framework and use the **canonical, version-pinned** form — `Tampering` (not `tampering`), `GOVERN-1.1@1.0` (not `GV-1.1`), `LLM01:2025` (not `LLM01`). Risks use techniques (`AML.T####`), controls use mitigations (`AML.M####`). The strict consumer schemas enforce all frameworks — MITRE ATLAS, NIST AI RMF, OWASP Top 10 LLM, STRIDE, ISO 22989, and EU AI Act — with no loose fall-through; every mapping value must carry its version token (STRIDE excepted, which is tokenless). See [`framework-mappings-style-guide.md`](./framework-mappings-style-guide.md).

### 9. Parent technique and sub-technique both listed (MITRE ATLAS)

The mappings list both `AML.T0020@5.0.1` and `AML.T0020.001@5.0.1`.

- Fix: keep only the most specific applicable ID. Do not list both.

### 10. Missing classical security equivalent

The long description jumps straight into AI-specific framing without grounding the risk in a pre-AI security concept.

- Fix: open with a one-sentence mapping to the classical equivalent (e.g., "Data poisoning extends classical supply-chain tampering into the model training pipeline..."), then explain the AI-specific amplifier.

### 11. Title doesn't follow the style guide

Common symptoms: 6+ words, verb phrases, "via"/"through"/"due to" clauses, compound "X and Y" titles, "Insufficient/Missing/Failure to" framing.

- Fix: rewrite as a 2-5 word noun phrase naming the threat (for risks) or defense (for controls). See the per-type title style guides.

### 12. Identification questions are miscalibrated (personas)

Persona `identificationQuestions` are activity-based and yes/no answerable. Common defects: title-repeating questions, open-ended phrasing, or questions that overlap with another persona without scoping.

- Fix: see [`identification-questions-style-guide.md`](./identification-questions-style-guide.md).

---

## How to self-check before submitting

Run through the checklist in [`submission-readiness-guide.md`](./submission-readiness-guide.md#pre-submission-checklist). Every item on that list corresponds to a finding above. If you can confidently check all boxes, you have handled the common cases.

For maintainers: the [content-reviewer agent](../../../scripts/agents/content-reviewer.md) and the [issue-response-reviewer agent](../../../scripts/agents/issue-response-reviewer.md) operationalize most of these checks. The content-reviewer is the source of truth for structural/quality findings; the issue-response-reviewer composes feedback for individual issues. When this document drifts, those agents take precedence.
