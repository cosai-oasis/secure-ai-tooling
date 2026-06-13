# Framework Mappings Style Guide

This guide covers how to write framework mappings across all entity types (risks, controls, personas) in the CoSAI Risk Map. It documents identifier formats, per-framework conventions, and the principles that should guide mapping decisions.

Identifier formats are the **canonical, version-pinned** forms committed in [ADR-027](../../../docs/adr/027-framework-versioning-and-mapping-convention.md) (which version-pins the per-framework base shapes that [ADR-022](../../../docs/adr/022-supporting-schemas.md) D5b first defined). Every mapping value carries a version token (`@5.0.1`, `@1.0`, `:2025`, `@2022`, `@2024`) except STRIDE, which is unversioned. The schema enforces these pinned forms strictly for all six frameworks — there is no longer a loose fall-through. Generate values with the maintainer tooling rather than hand-spelling them (see [Identifier Enforcement](#identifier-enforcement)).

---

## Table of Contents

1. [Purpose](#purpose)
2. [General Principles](#general-principles)
3. [Framework Applicability](#framework-applicability)
4. [Identifier Enforcement](#identifier-enforcement)
5. [Per-Framework Conventions](#per-framework-conventions)
   - [MITRE ATLAS](#mitre-atlas)
   - [NIST AI RMF](#nist-ai-rmf)
   - [STRIDE](#stride)
   - [OWASP Top 10 for LLM](#owasp-top-10-for-llm)
   - [ISO 22989](#iso-22989)
   - [EU AI Act](#eu-ai-act)
6. [Granularity Guidelines](#granularity-guidelines)
7. [Entity-Specific Guidance](#entity-specific-guidance)
8. [Adding Mappings for a New Framework](#adding-mappings-for-a-new-framework)
9. [Reviewer Checklist](#reviewer-checklist)
10. [Related Documentation](#related-documentation)

---

## Purpose

Framework mappings connect CoSAI Risk Map entities to external security and AI governance standards. They serve two purposes:

- **Cross-referencing**: Let practitioners locate CoSAI content from within the frameworks they already use (MITRE ATLAS, NIST AI RMF, etc.)
- **Validation**: Support claims about coverage — which threats does CoSAI address, and where?

Mappings are not exhaustive catalogs. Every entry should be there because it is directly relevant, not because it is adjacent or related.

---

## General Principles

**Use official identifiers.** Copy IDs exactly from the source framework. Do not paraphrase, abbreviate, or construct identifiers that don't appear in the framework's own documentation.

**Be selective.** Map to items that are directly relevant to the CoSAI entity. A mapping should be defensible with a one-sentence rationale: "This risk is an instance of [technique]" or "This control implements [mitigation]."

**Do not map to both a parent and its sub-technique.** If `AML.T0010` applies, and `AML.T0010.002` is the more specific and accurate match, use only the sub-technique. Using both creates redundancy and implies the parent covers something the sub-technique does not.

**Document non-obvious rationale in the PR description.** The YAML file is not the place for inline justification. If a mapping requires explanation (e.g., a risk maps to an ATLAS technique only partially, or a control maps to a framework category that isn't the obvious first choice), explain it in the PR body.

**If you are mapping to more than four items in one framework, pause.** Either the CoSAI entity is too broad and should be split, or the mapping criteria are too loose. Four is a soft limit, not a hard rule, but consistently exceeding it signals a problem.

**Omit a framework entirely if there is no strong match.** An empty `mappings` block is valid and common. Do not map to the closest available item just to have a mapping.

**Mappings are not authoritative endorsements.** No framework maintainer has reviewed or approved these mappings. They represent the CoSAI working group's best-effort interpretation.

**Mappings carry taxonomy IDs only — citations go in `externalReferences`.** The `mappings` block is a list of framework identifiers, never prose, URLs, or rationale ([ADR-022](../../../docs/adr/022-supporting-schemas.md) D5b — no per-mapping rationale fields). When a mapping rests on a paper, advisory, or spec the reader should be able to follow, add a structured entry to the entity's `externalReferences` array and cite it from prose with a `{{ref:identifier}}` sentinel ([ADR-016](../../../docs/adr/016-reference-strategy.md)). See [`yaml-authoring-subset.md`](../yaml-authoring-subset.md) for the structured-citation flow.

---

## Framework Applicability

Not every framework applies to every entity type. The `applicableTo` field in `frameworks.yaml` controls which entities may reference each framework. The schema enforces this — using an inapplicable framework will fail validation.

| Framework         | Risks | Controls | Personas |
|-------------------|:-----:|:--------:|:--------:|
| MITRE ATLAS       | yes   | yes      | no       |
| NIST AI RMF       | no    | yes      | no       |
| STRIDE            | yes   | no       | no       |
| OWASP Top 10 LLM  | yes   | yes      | no       |
| ISO 22989         | no    | no       | yes      |
| EU AI Act         | no    | yes      | yes      |

STRIDE, NIST AI RMF, and EU AI Act are asymmetric by design: STRIDE categorizes threats (risks), not countermeasures; NIST AI RMF is control-oriented and does not provide a threat taxonomy; EU AI Act defines obligations (controls) and roles (personas) but not a risk catalog.

---

## Identifier Enforcement

The canonical, version-pinned identifier patterns ([ADR-027](../../../docs/adr/027-framework-versioning-and-mapping-convention.md)) live in `risk-map/schemas/frameworks.schema.json` under `definitions/framework-mapping-patterns-pinned`. Each entity schema (`risks`, `controls`, `components`, `personas`) `$ref`s these pinned patterns for every `mappings` framework key, with `additionalProperties: false` — so an unpinned, off-pattern, or out-of-enum value fails `check-jsonschema` at commit. All six frameworks are enforced strictly; the prior loose fall-through for STRIDE / NIST / OWASP was removed once the content was migrated (#343).

| Framework | Canonical pinned pattern | Version token |
|-----------|--------------------------|---------------|
| MITRE ATLAS | `^AML\.(T\|M)\d{4}(\.\d{3})?@(5\.0\.1)$` | `@5.0.1` |
| NIST AI RMF | `^(GOVERN\|MAP\|MEASURE\|MANAGE)-\d+(\.\d+)*@(1\.0)$` | `@1.0` |
| STRIDE | `^(Spoofing\|Tampering\|Repudiation\|InformationDisclosure\|DenialOfService\|ElevationOfPrivilege)$` | none (unversioned) |
| OWASP Top 10 LLM | `^LLM\d{2}:2025$` | `:2025` |
| ISO 22989 | closed controlled-vocabulary enum, each member `@2022` | `@2022` |
| EU AI Act | `^Article\s\d+(\(\d+\))?@(2024)$` | `@2024` |

**Generate values with the maintainer tooling, do not hand-spell them.** `scripts/framework_mapping_maintainer.py` (subcommands `add` / `update` / `remove` / `migrate`) composes the pinned value from a structured selection and validates it against the schema before writing — the canonical compose path. The version token pins each value to the framework edition currently registered in `frameworks.yaml`; when a framework version bumps, the purity (ADR-027 D4c) and drift (D5/D5a) validators flag every consumer value the bump invalidates.

ISO 22989 is a controlled vocabulary rather than a regex: per [ADR-027](../../../docs/adr/027-framework-versioning-and-mapping-convention.md) D8 the six persona role descriptors are encoded as a closed inline enum, each pinned with `@2022` (e.g. `AI Partner (data supplier)@2022`). A role not in the closed set is rejected. (This refines the earlier ADR-021 D8 / ADR-022 D5b "bare string" treatment, which pre-dated version pinning.)

---

## Per-Framework Conventions

### MITRE ATLAS

**Applies to:** risks, controls

**Source:** [https://atlas.mitre.org](https://atlas.mitre.org) — version 5.0.1 as of October 2025

**Identifier formats** — canonical pinned pattern `^AML\.(T|M)\d{4}(\.\d{3})?@(5\.0\.1)$` (schema-enforced). The base ref is followed by the `@5.0.1` version token:
- Techniques: `AML.T####@5.0.1` (e.g., `AML.T0020@5.0.1`)
- Sub-techniques: `AML.T####.###@5.0.1` (e.g., `AML.T0010.002@5.0.1`)
- Mitigations: `AML.M####@5.0.1` (e.g., `AML.M0007@5.0.1`)

The single pattern covers techniques (`T`), mitigations (`M`), and optional sub-technique suffixes, all pinned to the registered ATLAS version. A malformed or unpinned ATLAS ID fails schema validation at commit.

**Risks map to techniques.** ATLAS techniques (`AML.T####`) describe adversary actions; a risk in CoSAI describes what can go wrong. The connection is: "An attacker using [technique] realizes [this risk]." Use the most specific technique available. If only a sub-technique applies, use the sub-technique, not the parent.

**Controls map to mitigations.** ATLAS mitigations (`AML.M####`) describe defensive actions. The connection is: "[This control] implements or contributes to [mitigation]." Some controls have no mitigation equivalent in ATLAS (ATLAS is more technique-heavy than mitigation-heavy); it is valid to leave `mitre-atlas` out of a control's mappings.

**Do not mix techniques and mitigations within one entity.** Risks reference `AML.T####`; controls reference `AML.M####`.

```yaml
# Risk — technique identifiers
mappings:
  mitre-atlas:
    - AML.T0020@5.0.1
    - AML.T0010.002@5.0.1   # sub-technique is more specific than AML.T0010

# Control — mitigation identifiers
mappings:
  mitre-atlas:
    - AML.M0007@5.0.1
```

---

### NIST AI RMF

**Applies to:** controls only

**Source:** NIST AI 100-1 — [https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf)

**Identifier format:** `[FUNCTION]-[Category].[Subcategory]@1.0` — canonical pinned pattern `^(GOVERN|MAP|MEASURE|MANAGE)-\d+(\.\d+)*@(1\.0)$`

The four functions use their **full uppercase names**, not the legacy two-letter abbreviations, and carry the `@1.0` version token:
- `GOVERN` — Govern (legacy `GV`)
- `MAP` — Map (legacy `MP`)
- `MEASURE` — Measure (legacy `MS`)
- `MANAGE` — Manage (legacy `MG`)

Examples: `GOVERN-1.1@1.0`, `MEASURE-2.7@1.0`, `MAP-4.1@1.0`, `MANAGE-4.1@1.0`

Always use the subcategory-level identifier (e.g., `MEASURE-2.7@1.0`), not the category level alone (`MEASURE-2@1.0`). The framework's subcategories are the actionable units; the category level is too coarse for meaningful mapping.

```yaml
mappings:
  nist-ai-rmf:
    - MEASURE-2.7@1.0
    - MEASURE-2.3@1.0
```

The schema enforces the full-word, version-pinned form strictly; the legacy `GV-/MP-/MS-/MG-` abbreviations and unpinned forms are rejected at commit.

**Limitation:** NIST AI RMF v1.0 is control-oriented and relatively coarse-grained. Some CoSAI controls span multiple RMF subcategories, and some have no close match. Do not force a mapping where the fit is weak.

---

### STRIDE

**Applies to:** risks only

**Source:** [https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)

**Identifier format:** PascalCase category name — canonical pattern `^(Spoofing|Tampering|Repudiation|InformationDisclosure|DenialOfService|ElevationOfPrivilege)$`

Valid values (exactly these six, PascalCase, no separators):
- `Spoofing`
- `Tampering`
- `Repudiation`
- `InformationDisclosure`
- `DenialOfService`
- `ElevationOfPrivilege`

Map based on the primary security impact of the risk. Multiple STRIDE categories are appropriate when a risk has meaningfully distinct impacts across categories. However, be conservative — most risks have one or two primary STRIDE categories.

```yaml
mappings:
  stride:
    - Tampering
    - ElevationOfPrivilege
```

STRIDE is unversioned (the registered `frameworks.yaml` version is null), so the pinned form carries **no** version token — the value is the bare PascalCase category name. The schema enforces this exact closed set strictly; the legacy lowercase-kebab form (`denial-of-service`) is rejected at commit.

**Limitation:** STRIDE was designed for traditional software systems. The categories are coarse and do not capture AI-specific threat nuances. Use MITRE ATLAS alongside STRIDE to provide more precise classification.

---

### OWASP Top 10 for LLM

**Applies to:** risks, controls

**Source:** [https://owasp.org/www-project-top-10-for-large-language-model-applications](https://owasp.org/www-project-top-10-for-large-language-model-applications) — version 2025 (released November 2024)

**Identifier format:** `LLM##:2025` (zero-padded two-digit number, colon, the pinned list year) — canonical pinned pattern `^LLM\d{2}:2025$`. Example: `LLM01:2025`, not `LLM01` or `LLM1`.

The version suffix pins the mapping to a specific edition of the list (the OWASP LLM Top 10 is re-issued; `LLM01` referred to different categories across editions). Use `:2025` for the current list.

The 2025 Top 10:
| ID    | Title |
|-------|-------|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain Vulnerabilities |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

**Risks map to OWASP categories that describe the same threat.** The OWASP list is LLM-specific; apply it only when the CoSAI risk is genuinely within scope of LLM application security. Not all CoSAI risks have an OWASP counterpart.

**Controls also map to OWASP categories** when the control directly mitigates that category's risks. The rationale is: "Implementing [this control] reduces exposure to [LLM##]."

```yaml
# Risk
mappings:
  owasp-top10-llm:
    - LLM04:2025

# Control that mitigates prompt injection
mappings:
  owasp-top10-llm:
    - LLM01:2025
```

The schema enforces the versioned `LLM##:2025` form strictly; the un-versioned `LLM##` form is rejected at commit. OWASP keeps its upstream-recognizable `:` delimiter (not `@`) deliberately.

---

### ISO 22989

**Applies to:** personas only

**Source:** ISO/IEC 22989:2022 — [https://www.iso.org/standard/74296.html](https://www.iso.org/standard/74296.html)

**Identifier format:** A role name from the standard's closed controlled vocabulary, pinned with `@2022`. ISO 22989 mappings are role descriptors rather than codes, so the schema encodes them as a closed inline enum (not a regex) per [ADR-027](../../../docs/adr/027-framework-versioning-and-mapping-convention.md) D8 — a role not in the closed set is rejected at commit. (This refines the earlier [ADR-021](../../../docs/adr/021-personas-and-self-assessment-schema.md) D8 / [ADR-022](../../../docs/adr/022-supporting-schemas.md) D5b "bare string" treatment, which pre-dated version pinning.)

The six valid values (exactly these, each `@2022`):
- `AI Producer@2022`
- `AI Partner (data supplier)@2022`
- `AI Partner (infrastructure provider)@2022`
- `AI Partner (tooling provider)@2022`
- `AI Customer (application builder)@2022`
- `AI Customer (end user)@2022`

The parenthetical qualifier (e.g., `data supplier`, `application builder`) disambiguates broad roles that ISO 22989 further divides; it is part of the enum member and must match exactly.

Some CoSAI personas have no direct ISO 22989 equivalent. Omit the `iso-22989` key rather than mapping to the closest available role.

```yaml
mappings:
  iso-22989:
    - AI Partner (data supplier)@2022
```

---

### EU AI Act

**Applies to:** personas, controls

**Source:** EUR-Lex — [https://eur-lex.europa.eu/eli/reg/2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689)

**Identifier format:** Article-level references pinned with `@2024` — canonical pinned pattern `^Article\s\d+(\(\d+\))?@(2024)$` (schema-enforced). One space after `Article`; the optional parenthetical is a paragraph number; the `@2024` token pins to the registered EU AI Act edition.

Examples:
- `Article 9@2024` (risk management system requirements)
- `Article 13@2024` (transparency and provision of information)
- `Article 13(1)@2024` (a specific paragraph within an article)
- `Article 72@2024` (obligations for providers of general-purpose AI models)

A malformed or unpinned reference (`Article9`, `Art. 9`, `Article 9.1`, `Article 9` without `@2024`) fails schema validation at commit. Use the official EUR-Lex text as the source for article numbering.

**For personas:** Map to the EU AI Act's defined roles where the CoSAI persona corresponds to a legal obligation-bearer. The Act defines roles including "provider", "deployer", "importer", "distributor", and "authorised representative" (Articles 3 and 25). Use the Act's own terminology.

**For controls:** Map to articles that impose the obligation the control helps satisfy. The goal is to answer: "Which article requires or recommends this type of control?"

The `Article {N}` / `Article {N}({paragraph})` form is the settled, schema-enforced convention. Map personas to the obligation-bearing role by mapping to the article that defines it; map controls to the article that imposes the obligation the control satisfies.

---

## Granularity Guidelines

**Prefer sub-techniques over parent techniques (MITRE ATLAS).** Sub-techniques are more precise and reduce the ambiguity of the mapping. Only use the parent when no sub-technique is specific enough, or when multiple sub-techniques apply and the parent is the accurate shared level.

**Do not map to a parent and its sub-technique simultaneously.**

```yaml
# Wrong — redundant
mappings:
  mitre-atlas:
    - AML.T0010@5.0.1
    - AML.T0010.002@5.0.1

# Correct — use only the most specific level that is accurate
mappings:
  mitre-atlas:
    - AML.T0010.002@5.0.1
```

**More than four mappings in one framework warrants review.** It often means:
- The CoSAI entity is covering too broad a concept and should be split
- The mapping criteria drifted from "directly relevant" toward "related"

There is no hard cap, but treat five or more as a prompt to re-examine the mapping, not a validation error.

---

## Entity-Specific Guidance

### Risks

Risks map to: MITRE ATLAS techniques, STRIDE categories, OWASP Top 10 for LLM categories.

The MITRE ATLAS mapping answers: "What attacker technique realizes this risk?"
The STRIDE mapping answers: "What class of security harm does this risk represent?"
The OWASP mapping answers: "Which LLM-specific risk category describes this?"

A risk with no strong ATLAS technique match (e.g., a compliance/policy-oriented risk like excessive data handling) should omit the `mitre-atlas` key rather than force a partial match.

### Controls

Controls map to: MITRE ATLAS mitigations, NIST AI RMF subcategories, OWASP Top 10 for LLM categories.

The MITRE ATLAS mapping answers: "Which ATLAS mitigation does this control implement?"
The NIST AI RMF mapping answers: "Which RMF subcategory does this control satisfy?"
The OWASP mapping answers: "Which LLM risk category does this control help mitigate?"

Controls that address broad concerns (e.g., assurance and governance controls) often lack specific framework equivalents. It is appropriate for these to have sparse or absent `mappings` sections.

### Personas

Personas map to: ISO 22989 actor roles, EU AI Act defined roles.

The ISO 22989 mapping answers: "Which standardized AI ecosystem actor corresponds to this CoSAI persona?"
The EU AI Act mapping answers: "Which legal role defined by the Act corresponds to this CoSAI persona?"

Not every CoSAI persona has a clear counterpart in these frameworks. The `personaGovernance` persona, for example, has no direct ISO 22989 equivalent and correctly omits `iso-22989` mappings.

---

## Adding Mappings for a New Framework

If you are proposing to add mappings for a framework not currently in `frameworks.yaml`, the process is:

1. **Read the framework registration process** in [guide-frameworks.md](../guide-frameworks.md). The framework must be registered before any entity can reference it.

2. **Establish identifier conventions** before adding entity-level mappings. Document the format in this file (in [Per-Framework Conventions](#per-framework-conventions)) as part of the PR that introduces the framework.

3. **Define `applicableTo`** in `frameworks.yaml` deliberately. Adding a framework to `applicableTo: [risks, controls, personas]` implies you have conventions ready for all three. Start with only the entity types you are actively mapping.

4. **Add a sample mapping** in the PR to illustrate the convention. Reviewers can evaluate whether the identifier format is correct and the mapping is well-reasoned.

5. **Note gaps and limitations** in the PR description. Every framework has areas where it does not align well with CoSAI's structure. Document known gaps so future contributors know where not to force mappings.

---

## Reviewer Checklist

When reviewing a PR that adds or modifies `mappings:` fields:

- [ ] Identifiers match the **canonical, version-pinned** format for each framework (see [Identifier Enforcement](#identifier-enforcement)) — tool-generated, not hand-spelled
- [ ] No parent technique is mapped alongside its sub-technique
- [ ] Risks reference only techniques (`AML.T####@5.0.1`) and controls reference only mitigations (`AML.M####@5.0.1`) for MITRE ATLAS
- [ ] STRIDE values are bare PascalCase and match the six valid categories exactly (`Tampering`, not `tampering` or `t`; no version token)
- [ ] NIST AI RMF uses full-word function prefixes and the `@1.0` token (`GOVERN-1.1@1.0`, not `GV-1.1`)
- [ ] OWASP identifiers are versioned (`LLM04:2025`, not `LLM04` or `LLM4`)
- [ ] EU AI Act references use the `Article {N}@2024` / `Article {N}({paragraph})@2024` form
- [ ] ISO 22989 values are one of the six closed-enum role descriptors, each pinned `@2022` (`AI Partner (data supplier)@2022`)
- [ ] Mappings carry taxonomy IDs only — no inline rationale or URLs; supporting citations live in `externalReferences` (see below) and non-obvious rationale in the PR description
- [ ] Mappings with more than four entries per framework have been scrutinized
- [ ] No framework is used for an entity type not listed in its `applicableTo`

---

## Related Documentation

- [guide-frameworks.md](../guide-frameworks.md) — How to register a new framework, framework definition file structure, validation rules
- [yaml-authoring-subset.md](../yaml-authoring-subset.md) — Prose authoring rules, the `externalReferences` structured-citation flow, and the `{{ref:identifier}}` sentinel form
- [ADR-027](../../../docs/adr/027-framework-versioning-and-mapping-convention.md) — Framework versioning + version-pinned mapping convention (source of truth for the pinned forms; supersedes ADR-022 D5b's value shapes)
- [ADR-022](../../../docs/adr/022-supporting-schemas.md) D5b — Per-framework mapping-ID base patterns (the pre-pinning shapes ADR-027 extends)
- [ADR-021](../../../docs/adr/021-personas-and-self-assessment-schema.md) D8 — Persona mappings (ISO 22989 role descriptors; pinned to the `@2022` closed enum per ADR-027 D8)
- [design/metadata-mappings.md](../design/metadata-mappings.md) — Phase 2 methodology: rationale tables for initial mappings, per-framework gap analysis, sources used (forthcoming)
- [guide-risks.md](../guide-risks.md) — Complete guide for adding or updating risks
- [guide-controls.md](../guide-controls.md) — Complete guide for adding or updating controls
- [guide-personas.md](../guide-personas.md) — Complete guide for adding or updating personas
