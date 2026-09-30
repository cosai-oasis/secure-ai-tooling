# Control Description and Guidance Design

This document defines the two prose fields on a CoSAI Risk Map control, `description` and `guidance`: what each one holds, how text is placed between them, and what consumers of the corpus may rely on.

**Version:** 1.0
**Last Updated:** 2026-09-30

---

## Table of Contents

- [Overview](#overview)
- [Design Goals](#design-goals)
- [Content Kinds](#content-kinds)
- [The `description` Field](#the-description-field)
- [The `guidance` Field](#the-guidance-field)
- [Placement Rules](#placement-rules)
- [Citations](#citations)
- [Relations Between Controls](#relations-between-controls)
- [Revising an Existing Control](#revising-an-existing-control)
- [Consumer Contract](#consumer-contract)
- [Enforcement](#enforcement)
- [Relationship to Risk Prose Fields](#relationship-to-risk-prose-fields)
- [References](#references)

---

## Overview

A control has two prose fields:

| Field | Required | Holds |
|---|---|---|
| `description` | yes | What the control is: its objective and a positive statement of its scope. |
| `guidance` | no | How to meet the objective, where it applies, why it matters beyond the risks it references, and how it differs from sibling controls. |

Both fields use the shared prose shape (an array of paragraphs, with one level of nested list) and the prose authoring subset in [`yaml-authoring-subset.md`](../yaml-authoring-subset.md).

The split follows the normative-statement and informative-guidance structure used by established control catalogs: NIST SP 800-53 separates each **Control** statement from its **Discussion**, and the OSCAL catalog model carries these as the `statement` and `guidance` parts of a control.

## Design Goals

1. **A reader can determine what a control is, and what it governs, from `description` alone.** The primary field is short enough to read at a glance and does not require the reader to know any other control.
2. **Implementation detail survives without crowding the objective.** Mechanisms, examples, anti-patterns, and applicability notes are valued content. They have a defined home rather than being cut.
3. **One secondary field, not several.** Guidance, anti-patterns, applicability, rationale, and boundary text are ordered sections of one field. Do's and don'ts are usually written as pairs ("X rather than Y"), and splitting them across fields would break those sentences or duplicate them.
4. **The summary is a named field.** What a control is lives in `description`, not in "the first paragraph" of a mixed field.

## Content Kinds

Control prose contains the following kinds of content. The placement rules below refer to them by name.

| Kind | What it is | Field |
|---|---|---|
| Objective | The property that must hold, with at most one outcome clause. | `description` |
| Scope | A positive statement of what the control governs: tier, locus, responsible party (named in words; see DG4), or the dimensions that define the property. | `description` |
| Normative parts | The named sub-requirements of a compound control. | Named in `description`; elaborated in `guidance` |
| Implementation | Mechanisms, examples, acceptable equivalents, proportionality, edge-case handling. | `guidance` |
| Anti-patterns | Named wrong means, usually the negative half of an implementation sentence. | `guidance` |
| Applicability | Which instances, paths, protocols, or deployment forms the control covers. | `guidance` |
| Rationale and residual risk | Why the control exists and what it leaves to other controls, where this adds to the risks the control references. | `guidance` |
| Boundary | Distinctions from, and dependencies on, sibling controls. | `guidance` |

## The `description` Field

`description` holds only the objective and the positive scope statement. It is required on every control.

- It states the property that must hold. At most one outcome clause follows the objective, stated directly rather than as a trailing "so that" clause (DG11).
- It states positively what the control governs. It does not define the control by contrast with another control.
- It is mechanism-neutral: it names no protocol, product, or mechanism. Dimensions that define the property itself (for example, the kinds of limit a resource-ceiling control governs) are scope, not mechanism, and may stay.
- A compound control names its normative parts in one enumerating sentence. This sentence may be new text written for that purpose.
- There is no enforced length. In practice a conformant `description` is a few sentences.

## The `guidance` Field

`guidance` is optional. A control whose `description` says everything needed omits it.

When present, `guidance` is written in this order. A section with nothing to say is omitted.

1. **Implementation.** Mechanisms, acceptable equivalents, proportionality, and anti-patterns written as the negative half of a do ("X rather than Y"). Named protocols and products belong here or in applicability. For a compound control, each normative part gets its own bolded lead within this section.
2. **Applicability.** Paths, deployment forms, and protocol independence.
3. **Rationale and residual risk.** Only where it adds to the risk entries the control references. A rationale clause that sits inside an implementation sentence stays with that sentence.
4. **Boundary.** Distinctions from, and dependencies on, sibling controls, using `{{control…}}` sentinels. Always last, so a reader knows where to find it.

`guidance` carries no `{{persona…}}` sentinel. As in `description` (DG4), the `personas` field records the responsible parties; `guidance` may name a role in words.

## Placement Rules

Rules are identified `DG1`–`DG11` so that authoring and review guidance can cite them.

- **DG1 — Place by sentence or clause, not by paragraph.** A single paragraph may contribute text to both fields.
- **DG2 — `description` holds only objective and scope.** Every other kind goes to `guidance`.
- **DG3 — No negated means in `description`.** `description` does not name what the control rules out. A negated *outcome* that is the security property itself is allowed ("cannot be impersonated", "no single message can exhaust …").
- **DG4 — `description` stands alone.** No sentence in `description` needs a sibling control to make sense. This excludes `{{control…}}` sentinels and also sibling controls mentioned by name without a sentinel. `{{component…}}` references are allowed, because they state scope. A `{{risk…}}` reference is rationale, and belongs in `guidance`. A `{{persona…}}` reference is attribution, which the `personas` field records, not scope, and is excluded. `description` may still name a role in words where the objective needs it.
- **DG5 — `description` is mechanism-neutral.** No named protocol, product, or mechanism.
- **DG6 — Revision relocates text; it discards only repeats.** Text leaves `description` only by moving to `guidance`; in `guidance`, a restatement of the objective or other repeat may be removed. See [Revising an Existing Control](#revising-an-existing-control).
- **DG7 — Paired guidance stays paired.** An anti-pattern written as the negative half of a do stays in the same sentence as the do.
- **DG8 — A compound control enumerates its parts in `description`.** One sentence names the parts; `guidance` elaborates each.
- **DG9 — Length is a principle, not a gate.** Keep `description` short; no validator enforces a limit.
- **DG10 — Boundary statements are reciprocal.** When a control's boundary section distinguishes it from a sibling control, the sibling's boundary section distinguishes itself from that control, and the two statements agree about which control covers what. A mention that states a dependency rather than a distinction (for example, a control drawing on another's inventory) does not require a reciprocal.
- **DG11 — `description` states outcomes directly.** An outcome is stated with an outcome verb ("ensuring", "limiting", "preventing") or as a direct statement of the property, not as a trailing "so that" clause. A direct statement of the property may be negated where DG3 allows it.

## Citations

A `{{ref:…}}` citation follows the text it attaches to. A citation on a dimension of scope stays in `description`; a citation on a mechanism is placed in `guidance` with that mechanism. Moved text keeps its citations: moving it between the two fields does not add, remove, or relocate citations to structured fields. A citation carried only by a repeat removed under DG6 is removed with it.

## Relations Between Controls

The boundary section of `guidance` may mention sibling controls by `{{control…}}` sentinel. These are mentions, not links. Each sentinel is resolved and checked like any other, but together they are not an authoritative relation set, and tools must not treat them as one. DG10 makes boundary statements reciprocal, so a reader of either control finds the distinction; it does not make the mentions a relation set. A report that lists one-way mentions for review may be provided; such a report is a review aid, not a consumer of relations. Intra-framework links are expressed through structured-reference fields ([ADR-014](../../../docs/adr/014-yaml-content-security-posture.md) P3), and the corpus defines no structured control-to-control relation field.

A structured relation field is adopted when a validator or tool needs to consume control-to-control relations as data.

## Revising an Existing Control

When an existing control is brought into the two-field form:

- Text moves from `description` to `guidance`; it is not deleted, except for a repeat removed from `guidance` as below.
- A `description` sentence may be reworded to drop a negated means (DG3). The dropped clause is placed in `guidance`, usually folded into the do it pairs with (DG7).
- A trailing "so that" clause in `description` may be reworded to state the outcome directly (DG11).
- In `guidance`, restatements of the objective and other repeats may be removed.
- The set of `{{…}}` sentinels across the two fields is unchanged, except where a rewording under DG3 or DG4, or the exclusion of `{{persona…}}` sentinels from `guidance`, requires otherwise, where DG10 requires a reciprocal boundary statement, or where a sentinel was carried only by a repeat removed from `guidance`.

A control whose entire `description` is one conformant statement needs no change.

## Consumer Contract

These commitments apply to every consumer, including the repository's own site and tables and downstream redistributors. The redistributor-facing summary is in [`reuse-contract.md`](../reuse-contract.md).

- `description` is the control's summary and its full normative statement. Summary views use `description` only.
- `guidance` is secondary content. Renderers may present it collapsed or on demand. It is never needed to understand what the control is.
- A renderer may abbreviate `description` for display, showing its opening and offering the rest on demand. Text offered on demand from `description` remains part of the normative statement. Consumers do not treat any part of `guidance` as the summary.
- A renderer that presents `description` and `guidance` together keeps them distinguishable, for example by labelling or visibly separating the guidance, so a reader can tell where the normative statement ends.
- Sentinels in both fields are resolved by every consumer that resolves sentinels in `description`.
- A consumer that emits every field of a control (for example a full-detail table) emits `guidance` with the same prose handling it applies to `description`.

## Enforcement

| Rule | Enforcement |
|---|---|
| Field shape, optionality of `guidance` | Controls schema |
| Prose tokens and sentinel resolution in both fields | Prose authoring-subset and reference linters, which discover prose fields from the schema |
| DG4 for `{{control…}}`, `{{risk…}}`, and `{{persona…}}` sentinels in `description`; no `{{persona…}}` sentinel in `guidance` | Mechanically checkable. One check covers all of these. It is required once no control in the corpus violates any of them; until then, review. |
| DG4 for sibling controls named without a sentinel; DG1–DG3, DG5–DG11 | Judgment. Applied by the `control-creator` agent when drafting and by the `control-critic` and `content-reviewer` agents when reviewing. |
| DG10 one-way `{{control…}}` mentions between boundary sections | Review. An advisory report that lists them for review is permitted, but it must not fail a build, because whether a mention is a distinction or a dependency is judgment. |

## Relationship to Risk Prose Fields

Risks use `shortDescription` and `longDescription`. Controls keep `description` and add `guidance`. The names differ deliberately. A risk's `longDescription` elaborates the threat. A control's `guidance` holds implementation, applicability, and boundary content, which is a different kind of text. Using the same names for both would suggest the same meaning.

## References

- [ADR-020](../../../docs/adr/020-controls-schema.md): `controls.schema.json` design, including the schema-level record of the `guidance` property.
- [ADR-016](../../../docs/adr/016-reference-strategy.md): sentinel grammar and `externalReferences`.
- [ADR-017](../../../docs/adr/017-yaml-prose-authoring-subset.md): prose authoring subset.
- [Adding a Control](../guide-controls.md).
- NIST SP 800-53 Rev. 5, §2.2 (control structure: control statement, discussion, related controls).
- OSCAL Catalog Model: control `part` names `statement` and `guidance`.
