---
name: audit-framework-mappings
description: Audit all framework mappings in risks.yaml, controls.yaml, and personas.yaml against the framework mappings style guide. Use when reviewing or proposing changes to mappings sections.
---

# Framework Mappings Audit

Audit framework mappings for correctness, style compliance, and term validity.

## Scope

Target: a single entity id (e.g., `riskModelEvasion`, `controlInputValidationAndSanitization`, `personaEndUser`), or the whole corpus — every entity across `risks.yaml`, `controls.yaml`, `personas.yaml` (the default). If a specific entity id is given, audit only that entity's mappings.

## Reference documents

Read these before auditing:

1. **Style guide** (authoritative): `risk-map/docs/contributing/framework-mappings-style-guide.md`

## Audit checklist

For each entity with mappings, verify ALL of the following. Report pass/fail per item.

### Format and version compliance

Mapping values are **version-pinned** (ADR-027): every value carries its framework's version token. Verify each value against the **canonical pinned pattern for its framework in the authoritative style guide** — read the patterns from the guide, do not restate them from memory (restating them here is how this check previously drifted stale). As of the current guide the pinned forms are, for example:

- **MITRE ATLAS:** `AML.T####@5.0.1` / `AML.T####.###@5.0.1` (techniques), `AML.M####@5.0.1` (mitigations)
- **NIST AI RMF:** subcategory-level, full function name, version-pinned — e.g. `MEASURE-2.3@1.0`, `GOVERN-6.2@1.0` (never the category alone, never an abbreviation like `MS-2.3`)
- **STRIDE:** PascalCase, unversioned — `Spoofing`, `Tampering`, `Repudiation`, `InformationDisclosure`, `DenialOfService`, `ElevationOfPrivilege`
- **OWASP Top 10 for LLM:** `LLM##:2025`
- **ISO 22989:** the controlled role name, version-pinned `@2022`
- **EU AI Act:** `Article ##@2024` / `Article ##(#)@2024`

Flag any value whose form or version token does not match the guide's current pinned pattern.

*(This skill AUDITS existing mappings across the corpus; to SELECT mappings while authoring a single control or risk, use the `mapping-selection` skill.)*

### Structural compliance

- [ ] **No parent + sub-technique collisions**: If `AML.T0010.002` is used, `AML.T0010` must NOT appear on the same entity
- [ ] **No technique/mitigation crossover**: Risks use only `AML.T####`; controls use only `AML.M####`
- [ ] **applicableTo respected**: Each framework is only used on entity types listed in its `applicableTo` (per style guide table)

### Selectivity compliance

- [ ] **Soft limit (4 per framework)**: Flag any entity with more than 4 mappings in a single framework. Not a hard error, but requires justification.
- [ ] **Direct relevance**: Each mapping should be defensible with a one-sentence rationale. Flag mappings where the connection is "related" rather than "directly relevant."

### Term and identifier verification

- [ ] **Verify identifiers exist in the source framework.** For MITRE ATLAS, confirm technique/mitigation IDs are real. For OWASP, confirm the category title matches. For ISO 22989, confirm role names match the standard's terminology.
- [ ] **When proposing new mappings**, search the web to confirm the identifier is current and not deprecated or renamed in the latest version of the framework.

## Coverage analysis (for whole-corpus scope only)

- Count entities with vs. without mappings per entity type
- Identify unmapped entities where obvious framework matches exist
- Note underutilized frameworks (e.g., NIST AI RMF, OWASP LLM08)
- Note STRIDE categories never used

## Output format

For targeted audits (single entity), provide:

1. Current mappings listed per framework
2. Pass/fail on each checklist item
3. Any recommended additions or removals with rationale
