# ADR-022: Supporting schemas — `actor-access`, `impact-type`, `lifecycle-stage`, `frameworks`, `mermaid-styles`

**Status:** Accepted
**Date:** 2026-04-25
**Authors:** Architect agent, with maintainer review

---

## Context

The five schemas in scope sit at `risk-map/schemas/{actor-access,impact-type,lifecycle-stage,frameworks,mermaid-styles}.schema.json`. Four are *taxonomy* schemas — closed reference tables that risks and controls `$ref` for their `lifecycleStage` / `impactType` / `actorAccess` / `mappings` fields. The fifth (`mermaid-styles.schema.json`) is a *configuration* schema for the diagram-styling YAML consumed by `MermaidConfigLoader` at `scripts/hooks/riskmap_validator/graphing/base.py`. Each of the four taxonomy schemas backs a small YAML data file (`risk-map/yaml/{actor-access,impact-type,lifecycle-stage,frameworks}.yaml`); `mermaid-styles.yaml` is the styling source for `MermaidConfigLoader` and is the most settled of the five (`additionalProperties: false` everywhere, hex-colour and stroke-pattern regexes throughout).

[ADR-014](014-yaml-content-security-posture.md) establishes the security posture; ADRs 015-017 set the rendering, reference, and authoring rules. The per-file schema ADRs ([ADR-018](018-components-schema.md), [ADR-019](019-risks-schema.md), [ADR-020](020-controls-schema.md), [ADR-021](021-personas-and-self-assessment-schema.md)) document the four main content schemas and are landed as `Draft`. This ADR documents the supporting schemas as a group, declares per-rule machine-enforcement, threads in the deliverables that ADRs 018-021 deferred to `frameworks.schema.json` (per-framework mapping-ID regex patterns), and proposes a sweep-wide close-out on the [ADR-017](017-yaml-prose-authoring-subset.md) D3 optional `<>()` schema reject pattern that all four sibling per-file schema ADRs deferred.

The supporting schemas have not previously been documented as a unit. They are smaller and more reference-table-shaped than the main content schemas — closed enums on every taxonomic ID, short typed lists, no prose-bearing fields beyond the file-level `description`. Per-file ADRs would produce five thin documents that mostly repeat the same pattern; the grouped form is cheaper and is appropriate for these supporting schemas.

The discovery work that motivated this set of architectural ADRs surfaced supporting-schema-specific gaps:

- **GAP-12 (major).** `mappings.*` values in risks/controls/personas are open string arrays. No per-framework regex catches a typo'd `AML.T9999`, `aml-t0020`, or `LLM99`. ADRs 019/020 declared the regex patterns live in `frameworks.schema.json`; this ADR declares the concrete shape.
- **GAP-13 (major).** `lifecycleStage` / `impactType` / `actorAccess` accept `"all"` and `"none"` as escape hatches on risks and controls; the *taxonomy* schemas themselves do not define those literals. Three-valued semantics (populated / `none` / absent) live only in the consumer schemas and the validators. The supporting schemas pre-date the escape-hatch convention.
- **GAP-19 (major).** `frameworks.schema.json` carries `applicableTo` (which entity types a framework applies to) but the constraint is enforced only by `validate_framework_references.py:230-281`. The schema does not narrow `mappings.*` per framework based on `applicableTo`. This is a schema/validator boundary call equivalent to the `controls`↔`risks` mirror split [ADR-019](019-risks-schema.md) D3 documents.
- **GAP-25 (minor).** `frameworks.schema.json` `applicableTo` enum includes `components`. No framework lists `components` in its `applicableTo`; `components.schema.json` carries no `mappings` field. The enum value is dormant; D5c activates it during the conformance sweep by adding a `mappings` field to `components.schema.json` (coordinated with [ADR-018](018-components-schema.md) D6 / Follow-up).
- **GAP-31 (major).** `mermaid-styles.yaml` is hand-maintained alongside the components-category enum. CLAUDE.md flags `ComponentGraph`'s hardcoded category handling. Adding a new component category requires three coordinated edits (schema enum, mermaid-styles YAML, generator code) with no machine link between them.
- **GAP-32 (minor).** `frameworks.schema.json` defines `techniqueUriPattern` on MITRE ATLAS only. No consumer constructs technique URIs from it. Dead metadata.

This ADR documents the existing shape of each supporting schema under [ADR-014](014-yaml-content-security-posture.md) P2's content-class taxonomy, declares per-rule machine enforcement, scopes the conformance-sweep edits, and resolves the cross-cutting deferrals that ADRs 018-021 pushed forward.

## Decision

The five supporting schemas are documented retroactively under [ADR-014](014-yaml-content-security-posture.md) P2's content-class taxonomy. The load-bearing additions are the per-framework mapping-ID regex commitment in `frameworks.schema.json` (D5), the sweep-wide close-out on the [ADR-017](017-yaml-prose-authoring-subset.md) D3 optional schema-reject pattern (D7), and the per-rule machine-enforcement summary across all five files (D8).

### D1. Scope and grouping rationale

The five schemas are documented in a single ADR because they share a pattern — small closed-enum reference tables with a thin prose description and no cross-file referential integrity beyond `$ref` from consumer schemas. Per-file ADRs would repeat the same field-taxonomy template five times.

- **In scope:** `actor-access.schema.json`, `impact-type.schema.json`, `lifecycle-stage.schema.json`, `frameworks.schema.json`, `mermaid-styles.schema.json`.
- **Out of scope (per ADR-021 D6):** `self-assessment.schema.json`. ADR-021 archives it to `risk-map/schemas/archive/self-assessment-legacy.schema.json` as a frozen legacy artifact.
- **Out of scope (ADR-011 territory):** `riskmap.schema.json` (the aggregate root and host of `definitions/utils/text`) and `persona-site-data.schema.json` (the producer/consumer contract owned by [ADR-011](011-persona-site-data-schema-contract.md)). This ADR addresses them only as forward references where supporting schemas integrate with them.

`frameworks.schema.json` is heavier than the other four — it is the home for the per-framework mapping-ID regex commitment ADRs 019/020 declared, and it carries the `applicableTo` taxonomy that `validate_framework_references.py` enforces. The grouping survives that asymmetry: `frameworks` decisions are scoped under D5 with concrete deliverables, but the field taxonomy and the sweep-wide deferrals (D7) apply uniformly to all five. A split into `022-supporting-taxonomies.md` and `023-frameworks-schema.md` was considered and rejected — see Alternatives Considered.

### D2. `actor-access.schema.json`

**Field taxonomy under [ADR-014](014-yaml-content-security-posture.md) P2.**

| Field | P2 class | Schema shape | Enforcement |
|---|---|---|---|
| `title` (file-level) | metadata | bare `string` | schema (type only) |
| `description` (file-level) | prose | `$ref riskmap.schema.json#/definitions/utils/text` | schema (shape) + lint per [ADR-017](017-yaml-prose-authoring-subset.md) D4 |
| `actorAccessLevels` (file-level array) | structured reference | array of `actorAccessLevel` definitions | schema |
| `actorAccessLevel.id` | identifier | closed `enum`, 9 values | schema |
| `actorAccessLevel.title` | metadata | bare `string` | schema (type only) |
| `actorAccessLevel.description` | metadata (short prose) | bare `string`, no length cap | schema (type only) |
| `actorAccessLevel.category` | identifier (taxonomic) | closed `enum`, 2 values (`traditional`, `modern`) | schema |

**Closure.** `id` is closed-enum at 9 values (`external`, `api`, `user`, `privileged`, `agent`, `supply-chain`, `infrastructure-provider`, `service-provider`, `physical`); `category` is closed-enum at 2 values. Adding an access level requires a schema edit. The `risks.schema.json` and `controls.schema.json` `actorAccess` field `$ref`s this enum (the `oneOf: [array<$ref enum>, "all" | "none"]` pattern documented in [ADR-019](019-risks-schema.md) D2 and [ADR-020](020-controls-schema.md) D2).

**Consumers.** `risks.yaml` and `controls.yaml` `actorAccess` arrays. Schema-only consumer; no Python validator extracts or cross-checks `actor-access.yaml` content.

**Gaps.** Per-level `description` is a bare `string`, not the shared `riskmap.schema.json#/definitions/utils/text` shape. The descriptions are short single-sentence definitions (the longest in `actor-access.yaml` is ~25 words); the bare-string shape is correct for these fields and stays. `additionalProperties: false` is **not** set on the `actorAccessLevel` definition or at file level — a typo'd field name (`titel`, `descriptoin`) would silently pass. The conformance sweep adds it.

### D3. `impact-type.schema.json`

**Field taxonomy.** Identical structure to `actor-access.schema.json`:

| Field | P2 class | Schema shape | Enforcement |
|---|---|---|---|
| `title` (file-level) | metadata | bare `string` | schema |
| `description` (file-level) | prose | `$ref riskmap.schema.json#/definitions/utils/text` | schema + lint |
| `impactTypes` (file-level array) | structured reference | array of `impactType` definitions | schema |
| `impactType.id` | identifier | closed `enum`, 10 values | schema |
| `impactType.title` | metadata | bare `string` | schema |
| `impactType.description` | metadata (short prose) | bare `string` | schema |
| `impactType.category` | identifier (taxonomic) | closed `enum`, 2 values (`traditional-security`, `ai-specific`) | schema |

**Closure.** `id` is closed-enum at 10 values (`confidentiality`, `integrity`, `availability`, `privacy`, `safety`, `compliance`, `fairness`, `accountability`, `reliability`, `transparency`); `category` is closed at 2 values. `risks.schema.json` and `controls.schema.json` `impactType` arrays `$ref` this enum.

**Consumers.** `risks.yaml` and `controls.yaml` `impactType` arrays. Schema-only consumer.

**Gaps.** Same as actor-access: per-level `description` is a bare `string`, deliberately so (definitions are short); `additionalProperties: false` is not set; conformance sweep tightens.

### D4. `lifecycle-stage.schema.json`

**Field taxonomy.** Same shape as actor-access and impact-type with one extra field:

| Field | P2 class | Schema shape | Enforcement |
|---|---|---|---|
| `title` (file-level) | metadata | bare `string` | schema |
| `description` (file-level) | prose | `$ref riskmap.schema.json#/definitions/utils/text` | schema + lint |
| `lifecycleStages` (file-level array) | structured reference | array of `lifecycleStage` definitions | schema |
| `lifecycleStage.id` | identifier | closed `enum`, 8 values | schema |
| `lifecycleStage.title` | metadata | bare `string` | schema |
| `lifecycleStage.description` | metadata (short prose) | bare `string` | schema |
| `lifecycleStage.order` | metadata (numeric) | `integer`, no `minimum`/`maximum` | schema (type only) |

**Closure.** `id` is closed-enum at 8 values (`planning`, `data-preparation`, `model-training`, `development`, `evaluation`, `deployment`, `runtime`, `maintenance`).

**`order` field.** A 1-8 integer that conveys sequential lifecycle position. The schema currently allows any integer — `order: 99` would pass. The lifecycle-stage YAML uses `order: 1..8`, and the description on the field says "Sequential order in the lifecycle (1-8)". The conformance sweep adds `"minimum": 1, "maximum": 8` and considers a uniqueness invariant (no two stages share an order). Uniqueness across array items is awkward in JSON Schema; a small validator check is the cleaner path. Recommended: validator extension over schema-side `uniqueItems` plus extraction.

**Consumers.** `risks.yaml` and `controls.yaml` `lifecycleStage` arrays. The persona-site builder may surface lifecycle ordering in a future iteration; today no consumer reads `order` programmatically. The `order` field is therefore *latent* metadata — declared, hand-maintained, but not yet read by any generator. The conformance sweep documents this in the file header rather than removing the field; the eight-stage ordered list is a stable framework concept and the field has clear future use.

**Gaps.** `additionalProperties: false` is not set on `lifecycleStage` or at file level. The conformance sweep adds it. The `order` field tightening is a conformance-sweep deliverable per the above.

### D5. `frameworks.schema.json`

**Field taxonomy.** Heavier than the other taxonomy schemas — 8 declared `framework` fields plus the file-level envelope:

| Field | P2 class | Schema shape | Enforcement |
|---|---|---|---|
| `title` (file-level) | metadata | bare `string` | schema |
| `description` (file-level) | prose | `$ref riskmap.schema.json#/definitions/utils/text` | schema + lint |
| `frameworks` (file-level array) | structured reference | array of `framework` definitions | schema |
| `framework.id` | identifier | closed `enum`, 6 values | schema |
| `framework.name` | metadata | bare `string` | schema |
| `framework.fullName` | metadata | bare `string` | schema |
| `framework.description` | metadata (short prose) | bare `string` | schema |
| `framework.baseUri` | metadata (URI) | `string`, `format: uri` | schema |
| `framework.version` | metadata | `["string", "null"]` | schema |
| `framework.lastUpdated` | metadata | `oneOf: [date-pattern, null]` | schema |
| `framework.techniqueUriPattern` | metadata (URI template) | bare `string` | schema (type only) — currently dead (D5d) |
| `framework.documentUri` | metadata (URI) | `string`, `format: uri` | schema |
| `framework.applicableTo` | identifier (taxonomic) | array of closed `enum`, 4 values, `minItems: 1` | schema (membership) + `validate_framework_references.py` (cross-file enforcement) |
| `framework.mappingPatterns` (planned, D5b) | structured reference (regex registry) | new `definitions/framework-mapping-patterns` block | schema once D5b lands |

**Closure.** `framework.id` is closed-enum at 6 values (`mitre-atlas`, `nist-ai-rmf`, `stride`, `owasp-top10-llm`, `iso-22989`, `eu-ai-act`). Adding a framework requires a schema edit, a YAML edit in `frameworks.yaml`, and (per ADR-019/020 sweep follow-ups) a paired regex pattern entry under D5b.

#### D5a. `applicableTo` enforcement boundary

`applicableTo` declares which entity types a framework applies to (`controls`, `risks`, `components`, `personas`). The schema enforces *membership* against the closed enum. The cross-file enforcement — that `risks.yaml` does not reference a framework whose `applicableTo` excludes `risks`, and analogously for controls and personas — lives in `validate_framework_references.py:230-281`.

The split is the same boundary [ADR-018](018-components-schema.md) D3 and [ADR-019](019-risks-schema.md) D3 document for components-edge bidirectionality and controls↔risks integrity. Schema can express "every value is in this enum"; it cannot cheaply express "every framework reference in another file must be applicable to that file's entity type" without a cross-file conditional. The Python validator is the right tool; the schema/validator split is intentional and matches the precedent across the framework.

The sweep does **not** migrate `applicableTo` enforcement into the schema. The validator stays authoritative.

#### D5b. Per-framework mapping-ID regex patterns (the ADR-019 D5 / ADR-020 D5 commitment)

> **Superseded in part by [ADR-027](027-framework-versioning-and-mapping-convention.md).** The base mapping-ID shapes defined here remain the per-framework ref grammar, but ADR-027 version-pins them: every consumer value now carries a version token (`@5.0.1`, `@1.0`, `:2025`, `@2022`, `@2024`; STRIDE stays unversioned), ISO 22989 moves from a bare string to a closed `@2022` controlled-vocabulary enum (ADR-027 D8), and the consumer schemas `$ref` the strict `framework-mapping-patterns-pinned` block with `additionalProperties: false` (the loose fall-through described below was removed once the content was migrated, #343). The base `framework-mapping-patterns` block defined here is retained in the schema. See ADR-027 for the canonical pinned forms.

[ADR-019](019-risks-schema.md) D5 and [ADR-020](020-controls-schema.md) D5 declared that per-framework mapping-ID regex patterns live in `frameworks.schema.json` and are referenced from `risks.schema.json` and `controls.schema.json`. This ADR commits the concrete shape.

**Conformance-sweep deliverable.** Add a new `definitions/framework-mapping-patterns` block to `frameworks.schema.json`:

```json
"framework-mapping-patterns": {
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "mitre-atlas": {
      "type": "string",
      "pattern": "^AML\\.(T|M)\\d{4}(\\.\\d{3})?$"
    },
    "nist-ai-rmf": {
      "type": "string",
      "pattern": "^(GOVERN|MAP|MEASURE|MANAGE)-\\d+(\\.\\d+)*$"
    },
    "stride": {
      "type": "string",
      "pattern": "^(Spoofing|Tampering|Repudiation|InformationDisclosure|DenialOfService|ElevationOfPrivilege)$"
    },
    "owasp-top10-llm": {
      "type": "string",
      "pattern": "^LLM\\d{2}:\\d{4}$"
    },
    "iso-22989": {
      "type": "string"
    },
    "eu-ai-act": {
      "type": "string",
      "pattern": "^Article\\s\\d+(\\(\\d+\\))?$"
    }
  }
}
```

`risks.schema.json` and `controls.schema.json` then reference these patterns from their `mappings.additionalProperties.items` constraint. The exact reference shape — whether per-framework `if/then` on the property name, or a `$ref` to a per-property pattern, or a per-property explicit object — is a sweep-execution call. The patterns themselves are owned by this ADR and live in `frameworks.schema.json` per the single-source-of-truth principle [ADR-016](016-reference-strategy.md) D3 establishes for `external-references.schema.json`.

**Pattern commitments.**

- **MITRE ATLAS** — covers both technique (`AML.T0020`, `AML.T0020.001`) and mitigation (`AML.M0011`) IDs in a single alternation. Risks lean toward technique; controls lean toward mitigation; the framework-key is shared so the pattern is a union.
- **NIST AI RMF** — function-prefix subcategories (`GOVERN-1.1`, `MAP-2.3`, `MEASURE-1.1.1`).
- **STRIDE** — six-element enum-as-pattern; the underlying STRIDE values are fixed, not a dotted ID space.
- **OWASP LLM Top 10** — versioned (`LLM01:2025`).
- **ISO 22989** — left as bare `string` per [ADR-021](021-personas-and-self-assessment-schema.md) D8: ISO 22989 mappings on personas are role descriptors (`"AI Partner (data supplier)"`), not canonical IDs. Pinning a regex would force a content rewrite that is owned by `risk-map/docs/design/persona-design.md`. Today's content stays valid.
- **EU AI Act** — Article-style references (`Article 6`, `Article 6(2)`).

**Per-framework rationale fields are not added.** Mirrors the deliberate decision in [ADR-019](019-risks-schema.md) D5 and [ADR-020](020-controls-schema.md) D5: free-text rationale belongs in the entry's `description` / `longDescription` prose, where citations live as `externalReferences` per [ADR-016](016-reference-strategy.md). Mappings are taxonomy-ID-only.

The patterns do not require validator changes — schema-only tightening. `validate_framework_references.py` continues to enforce `applicableTo` and existence; the schema enforces ID-shape.

#### D5c. `framework.applicableTo` `components` value — activate via `mappings` on components

The enum at `frameworks.schema.json:71-74` includes `components`. No framework today lists `components` in its `applicableTo`, and `components.schema.json` does not declare a `mappings` field. The enum value is dormant, not dead.

**Decision: activate the enum value during the conformance sweep by adding a `mappings` field to `components.schema.json`.** Maintainer direction (2026-04-25): components are not exempt from framework cross-walks; the asymmetry framed in earlier drafts (no `mappings` on components, intentional) was wrong. The conformance sweep adds the field to components, mirroring the existing `mappings` shape on risks/controls/personas:

- `properties.mappings` on the component definition with the same `propertyNames` `$ref` to `frameworks.schema.json#/definitions/framework/properties/id` that risks/controls/personas use, single-sourced through that `$ref`.
- Per-framework value shape inherits from D5b's regex commitment for canonical-form frameworks (MITRE ATLAS technique-or-mitigation, NIST AI RMF, STRIDE, OWASP LLM, EU AI Act). Framework consumers that opt to map to components add the `applicableTo: components` value at that point; the enum value is the upstream pin that lets a single coordinated edit add a new components-side mapping rather than two.
- Optional, not required. Components without framework cross-walks omit the field; the array-shape constraint and per-type regex inherit from the same shared definitions risks/controls already use.

The components-side gap (no `mappings` field today) and remediation (add it in the sweep) are mirrored in [ADR-018](018-components-schema.md) D6 and its Follow-up section. ADR-018's D1 row "components carry no `mappings`" reflects the current state; the Follow-up commits the sweep edit. The two ADRs are coordinated: this ADR commits the framework-side enum activation, ADR-018 commits the component-side field addition.

No header comment in `frameworks.schema.json` is added to document latency — the value is activated, not retained as latent. This supersedes the earlier draft's "header comment for latency" deliverable.

#### D5d. `techniqueUriPattern` field

`frameworks.schema.json:58-61` declares `techniqueUriPattern` as a free-form string with a description hinting at `{id}` substitution. Only `mitre-atlas` populates it (`https://atlas.mitre.org/techniques/{id}`). No code path constructs a URI from it.

**Decision: retain, scoped for [ADR-016](016-reference-strategy.md) integration.** The field's natural consumer is the `external-references.schema.json` `type: technique` (not currently in [ADR-016](016-reference-strategy.md)'s type enum) or a future site-renderer feature that links framework mappings to their canonical sources. ADR-016 D3 covers external citations; framework-mapping-to-URL is a related but distinct surface. The conformance sweep does not remove the field; a future ADR (likely a sweep follow-up) decides whether `techniqueUriPattern` becomes the URL template that `mappings.mitre-atlas[]` IDs resolve to in the table generator and the site renderer.

This deferral is recorded so a future contributor proposing removal encounters the deliberate placeholder rather than reinventing the rationale.

### D6. `mermaid-styles.schema.json`

`mermaid-styles.schema.json` is the most settled of the five and is the only configuration schema in the group. It governs `risk-map/yaml/mermaid-styles.yaml`, which `MermaidConfigLoader` (`scripts/hooks/riskmap_validator/graphing/base.py`) parses into the styling parameters every Mermaid generator (`ComponentGraph`, `ControlGraph`, `RiskGraph`) emits.

**Distinct shape.** Unlike the four taxonomy schemas, `mermaid-styles.schema.json` is **not** a closed-enum reference table. It is a configuration object with deeply-nested per-graph-type styling, hex-colour patterns, stroke-width regexes, and ELK-layout options. It carries `additionalProperties: false` at every level (lines 8, 19, 25, 73, 96, 131, 137, etc.), pinned hex-colour patterns (`^#[0-9A-Fa-f]{6}$`), pinned stroke-width patterns (`^\\d+px$`), and pinned dash-array patterns (`^\\d+\\s+\\d+$`). It is the only schema in the group with structural strictness comparable to [ADR-011](011-persona-site-data-schema-contract.md)'s `persona-site-data.schema.json`.

**Field taxonomy under [ADR-014](014-yaml-content-security-posture.md) P2.** The classes do not map cleanly: every field is either *configuration metadata* (colours, widths, layout directives) or *structured reference* (component-category names, graph-type discriminators that tie to taxonomy enums elsewhere). No field is *prose* in the sense P2 names; the file-level `description` is absent (the schema does not declare one — the `version` field at `mermaid-styles.schema.json:10-14` is the closest analogue and is a `^\\d+\\.\\d+\\.\\d+$` regex, not a description).

| Field family | P2 class | Schema shape | Enforcement |
|---|---|---|---|
| `version` | metadata (semver) | `string`, semver regex | schema |
| `foundation.colors.*` | metadata (hex) | `string`, `^#[0-9A-Fa-f]{6}$` | schema |
| `foundation.strokeWidths.*` | metadata (px) | `string`, `^\\d+px$` | schema |
| `foundation.strokePatterns.*` | metadata (dash array) | `string`, `^\\d+\\s+\\d+$` (`solid` is empty `""`) | schema |
| `sharedElements.cssClasses.*` | metadata (CSS literal) | bare `string`, no pattern | schema (type only) |
| `sharedElements.componentCategories.<id>` | structured reference (implicit, against components category enum) | object with `fill`, `stroke`, `strokeWidth`, `subgroupFill` | schema (shape only); name-to-enum coupling not enforced (D6a) |
| `graphTypes.{component,control,risk}.*` | metadata (config) | nested per-graph-type objects with `direction` enum, `flowchartConfig`, `specialStyling` | schema |

**Consumers.** `MermaidConfigLoader` (`scripts/hooks/riskmap_validator/graphing/base.py`) loads the file via the singleton pattern. `ComponentGraph`, `ControlGraph`, and `RiskGraph` (`scripts/hooks/riskmap_validator/graphing/`) read the loader's resolved config and emit styling tokens into Mermaid front-matter and edge-style strings. `scripts/hooks/yaml_to_markdown.py` does **not** consume `mermaid-styles.yaml` directly — table generation is style-agnostic. Site renderer does not consume it either; the SPA's CSS is independent.

#### D6a. The category-coupling gap (GAP-31)

`mermaid-styles.schema.json:127-168` declares `sharedElements.componentCategories` with three required keys (`componentsInfrastructure`, `componentsApplication`, `componentsModel`) and accepts `componentsData` as optional. The keys are **string-typed property names**, not `$ref`s to `components.schema.json`'s `category.id` enum. CLAUDE.md flags `ComponentGraph`'s hardcoded category handling: adding a new component category requires three coordinated edits (the `components.schema.json` category enum, the `mermaid-styles.yaml` `sharedElements.componentCategories` block, and the generator code that reads it), with no machine link between them.

**Decision: scope the coupling tightening to the conformance sweep, not to this ADR.** The coupling is a generator-architecture concern — the right fix is either (a) `MermaidConfigLoader` consumes the components category enum at load time and provides defaults for unconfigured categories, or (b) the schema gains a `propertyNames` `$ref` to the components category enum, forcing `mermaid-styles.yaml` to keep its category set in sync with `components.schema.json`. Option (b) is cleaner from the schema's side but is fragile when a new component category lands without an immediate styling decision; Option (a) is the engineering-side fix and matches the loader's existing fallback pattern.

The conformance sweep recommends Option (a): leave the schema as-is, extend `MermaidConfigLoader` to handle the missing-key case gracefully and emit a warning rather than silently using the emergency fallback. This pushes the GAP-31 fix out of the schema layer and into the generator — which is where the existing fallback pattern lives. The schema-side `propertyNames` `$ref` option is a later candidate if generator-side handling proves insufficient.

#### D6b. Strictness preserved

Every existing constraint in `mermaid-styles.schema.json` stays. `additionalProperties: false` is set everywhere and is correct (a typo'd `flowChartConfig` would silently produce a default-styled graph). The hex-colour and stroke-pattern regexes are correct. The conformance sweep adds **no** schema constraint to `mermaid-styles.schema.json`; the only deliverable is the `MermaidConfigLoader` graceful-fallback work in D6a, which is generator-side and outside this ADR's scope to specify.

### D7. Cross-cutting observation — sweep-wide [ADR-017](017-yaml-prose-authoring-subset.md) D3 deferral close-out

[ADR-018](018-components-schema.md) D4, [ADR-019](019-risks-schema.md) D4, [ADR-020](020-controls-schema.md) D4, and [ADR-021](021-personas-and-self-assessment-schema.md) D4 each deferred the [ADR-017](017-yaml-prose-authoring-subset.md) D3 optional schema-level `<>()` reject pattern with converging rationales:

- All four cite legitimate parenthetical asides in prose. ADR-018 documents technical parentheticals on components; ADR-019 documents `(direct or indirect)` and `(such as ...)` patterns on risks; ADR-020 documents agentic-controls parentheticals; ADR-021 documents that the `identificationQuestions` style guide *requires* parentheticals for technical-term examples.
- All four note that the optional pattern lives on the shared `riskmap.schema.json#/definitions/utils/text` definition, so adopting it locally is either a fork (drift class) or a sweep-wide call.
- All four conclude the [ADR-017](017-yaml-prose-authoring-subset.md) lint is the authoritative content layer; the schema-side `<>()` filter is defense-in-depth that adds friction without adding security as long as the lint runs.

**Decision: sweep-wide indefinite deferral.** The optional `<>()` schema-reject pattern is **deferred indefinitely**, not pending per-file revisit. The four sibling ADRs converge on the rationale; this ADR records the convergence as a single durable decision so the conformance sweep does not re-litigate it.

The supporting schemas inherit this decision automatically. `actor-access.schema.json`, `impact-type.schema.json`, `lifecycle-stage.schema.json`, `frameworks.schema.json`, and `mermaid-styles.schema.json` carry no prose-bearing fields beyond the file-level `description` (which `$ref`s the shared `riskmap.schema.json#/definitions/utils/text`). The deferral applies to the shared definition; the supporting schemas need no per-schema clause.

**Revisit conditions.** This deferral is revisited if (a) the [ADR-017](017-yaml-prose-authoring-subset.md) lint regresses repeatedly (a `--no-verify` commit slips raw HTML into prose, a hook bypass ships unnoticed), or (b) a future content surface introduces a prose field that legitimately should not carry parentheticals (none currently exists). Until either condition fires, the lint stands alone.

The decision is recorded here, not in a sixth per-file ADR, because the revisit conditions are sweep-wide and the rationale is shared. A future ADR that adopts the schema-side reject pattern globally cites this one for the deferred state and the convergence.

### D8. Per-rule machine-enforcement summary across all five schemas

| Rule | Schema | Mechanism | Status |
|---|---|---|---|
| D1 grouped scope and `self-assessment` exclusion | this ADR | scope declaration | Documentation |
| D2 `actorAccessLevel.id` closed enum (9 values) | `actor-access.schema.json` | schema `enum` | Machine-enforced (existing) |
| D2 `actorAccessLevel.category` closed enum | `actor-access.schema.json` | schema `enum` | Machine-enforced (existing) |
| D2 `additionalProperties: false` on `actorAccessLevel` | `actor-access.schema.json` | schema constraint | Conformance-sweep deliverable |
| D3 `impactType.id` closed enum (10 values) | `impact-type.schema.json` | schema `enum` | Machine-enforced (existing) |
| D3 `impactType.category` closed enum | `impact-type.schema.json` | schema `enum` | Machine-enforced (existing) |
| D3 `additionalProperties: false` on `impactType` | `impact-type.schema.json` | schema constraint | Conformance-sweep deliverable |
| D4 `lifecycleStage.id` closed enum (8 values) | `lifecycle-stage.schema.json` | schema `enum` | Machine-enforced (existing) |
| D4 `lifecycleStage.order` 1-8 range | `lifecycle-stage.schema.json` | schema `minimum`/`maximum` | Conformance-sweep deliverable |
| D4 `lifecycleStage.order` uniqueness | recommended: validator extension | validator | Conformance-sweep deliverable |
| D4 `additionalProperties: false` on `lifecycleStage` | `lifecycle-stage.schema.json` | schema constraint | Conformance-sweep deliverable |
| D5a `framework.id` closed enum (6 values) | `frameworks.schema.json` | schema `enum` | Machine-enforced (existing) |
| D5a `framework.applicableTo` membership against entity-type enum | `frameworks.schema.json` | schema `enum` + `minItems: 1` | Machine-enforced (existing) |
| D5a `framework.applicableTo` cross-file enforcement | `validate_framework_references.py` | Python validator | Machine-enforced (validator) |
| D5b per-framework mapping-ID regex (MITRE ATLAS, NIST, STRIDE, OWASP, EU AI Act) | `frameworks.schema.json` `definitions/framework-mapping-patterns` | new schema definition | Conformance-sweep deliverable |
| D5b per-framework mapping-ID consumption from risks/controls | `risks.schema.json` + `controls.schema.json` | schema reference to D5b patterns | Conformance-sweep deliverable (cross-file with ADR-019/020) |
| D5b per-mapping rationale fields | not added | n/a | Decided against (per ADR-019 D5, ADR-020 D5) |
| D5c `framework.applicableTo` `components` value activated via `mappings` on components | `components.schema.json` (new field per [ADR-018](018-components-schema.md)) + `frameworks.yaml` (when a framework opts in) | schema | Conformance-sweep deliverable |
| D5d `framework.techniqueUriPattern` retained for future `external-references` integration | `frameworks.schema.json` | no schema change | Deferred to future ADR |
| D5 `additionalProperties: false` on `framework` | `frameworks.schema.json` | schema constraint | Conformance-sweep deliverable |
| D6 `mermaid-styles` semver, hex-colour, stroke-width, dash-array regexes | `mermaid-styles.schema.json` | schema `pattern` | Machine-enforced (existing) |
| D6 `mermaid-styles` `additionalProperties: false` everywhere | `mermaid-styles.schema.json` | schema constraint | Machine-enforced (existing) |
| D6a `componentCategories` ↔ `components.schema.json` category enum coupling | `MermaidConfigLoader` graceful-fallback extension | generator code | Conformance-sweep deliverable (later candidate for schema-side `propertyNames` `$ref`) |
| D7 sweep-wide deferral of [ADR-017](017-yaml-prose-authoring-subset.md) D3 optional `<>()` schema-reject pattern | shared `riskmap.schema.json#/definitions/utils/text` | not adopted | Deferred indefinitely; revisit conditions named in D7 |

Every machine-enforceable rule in scope is enforced or has a named conformance-sweep mechanism. The rows that resolve to "Deferred" are explicit deliberate carve-outs (D5d, D7) rather than rot-prone gaps.

## Alternatives Considered

- **Split `frameworks.schema.json` into its own ADR (`023-frameworks-schema.md`).** Considered because `frameworks` carries the heaviest deliverable (the per-framework mapping-ID regex commitment that ADRs 019 and 020 declared, plus the `applicableTo` validator boundary, plus the `techniqueUriPattern` and `applicableTo` `components` latency calls). Rejected because the split would produce a thin grouped ADR (four taxonomy schemas, mostly identical) plus a single-schema ADR (frameworks alone) that overlapped on the field-taxonomy template. The grouped ADR with a heavier D5 sub-section is leaner; the asymmetry between D5 (heavy) and D2/D3/D4 (light) is documented in D1 and matches the actual asymmetry in the schemas. A reader looking for per-framework regex patterns finds them under D5b without ambiguity.
- **Per-schema ADRs (five thin documents).** Rejected. Four of the five (the taxonomy schemas) share an identical field-taxonomy template; per-file ADRs would repeat the same closed-enum / schema-only-consumer / `additionalProperties: false` story five times. The grouping is cheaper for the reader and is appropriate for these supporting schemas. `mermaid-styles.schema.json` is a different shape (configuration, not taxonomy), but it is the only outlier; D6 carries that asymmetry.
- **Adopt the [ADR-017](017-yaml-prose-authoring-subset.md) D3 optional `<>()` schema-reject pattern in this ADR (close out by adoption rather than deferral).** Rejected. The four sibling per-file schema ADRs deferred with consistent rationale; their content surfaces (risks, controls, components, personas) all carry parentheticals freely. Adopting the pattern here without revisiting those ADRs would force a sweep-wide content rewrite the lint already prevents. D7 records the convergence as a durable decision; adoption is the revisit path if conditions change.
- **Encode `applicableTo`-per-mapping enforcement in the schema** (e.g., `if mappings has key X then risks-only or controls-only depending on X's applicableTo`). Rejected. JSON Schema can express per-property conditional shape via `allOf` / `if` / `then`, but the construction couples the schema to the framework set (a new framework requires extending the conditional, not just the enum) and degrades schema-validation performance. The Python validator (`validate_framework_references.py`) is the right tool; the schema/validator split mirrors [ADR-018](018-components-schema.md) D3 and [ADR-019](019-risks-schema.md) D3.
- **Tighten `mermaid-styles.schema.json`'s `componentCategories` block via `propertyNames: $ref components.schema.json#/definitions/category/properties/id` directly.** Rejected for now. Coupling `mermaid-styles.schema.json` to `components.schema.json` at schema-load time forces `mermaid-styles.yaml` to maintain a styling block for every component category — including categories that were just added without yet having a styling decision. The generator-side graceful-fallback (D6a recommended path) handles the missing-styling case without forcing the YAML to keep up. Revisit this as a later candidate if the fallback proves insufficient.
- **Remove the `applicableTo: components` enum value as dead code (GAP-25).** Rejected per D5c. The conformance sweep activates the value by adding a `mappings` field to `components.schema.json`, mirrored in [ADR-018](018-components-schema.md) D6 / Follow-up. Removing the value would block the activation path; retaining it is the upstream pin for the coordinated edit.
- **Remove `framework.techniqueUriPattern` as dead metadata (GAP-32).** Rejected per D5d. The field is a placeholder for a likely future integration with [ADR-016](016-reference-strategy.md)'s `external-references` (via a `type: technique` or analogous addition) or with the table generator's URL templating. Removing it now and re-adding it later costs more than the dead-metadata cost of leaving it in place; a future ADR decides the integration.
- **Document the [ADR-017](017-yaml-prose-authoring-subset.md) D3 deferral as a separate sixth ADR.** Rejected. The convergence is a sweep-wide observation that fits naturally in the supporting-schemas ADR (which is the natural place to land sweep-wide observations across the per-file schema ADRs). A separate ADR for a single deferral close-out would be thinner than this ADR's D7 sub-section and would force readers to chase an extra cross-reference.

## Consequences

**Positive**

- **The five supporting schemas are documented as a unit.** D1's scope declaration, D2-D6's per-schema sub-sections, and D8's machine-enforcement summary give future contributors a single reference for the closed-enum reference tables and the configuration schema. The asymmetry between the four taxonomy schemas and `mermaid-styles.schema.json` is named and contained.
- **The per-framework mapping-ID regex commitment from ADRs 019 and 020 is concrete.** D5b names the patterns, names where they live (`frameworks.schema.json` `definitions/framework-mapping-patterns`), names how they are consumed (referenced from `risks.schema.json` and `controls.schema.json`), and names what is deliberately *not* added (rationale fields, ISO 22989 pattern). The sweep-execution PR has no degrees of freedom on shape.
- **The [ADR-017](017-yaml-prose-authoring-subset.md) D3 deferral has a sweep-wide close-out.** D7 records the convergence across ADRs 018, 019, 020, 021 as a durable decision. The conformance sweep does not re-litigate it; the deferral is named-not-silent and the revisit conditions are explicit. Future contributors proposing the schema-side reject see the convergence rationale without re-deriving it from four sibling ADRs.
- **`applicableTo` schema/validator boundary is explicit.** D5a names which checks live in JSON Schema (`applicableTo` membership) and which live in `validate_framework_references.py` (cross-file enforcement). The split mirrors the precedent across the framework and is documented for future contributors who edit one layer without the other.
- **Discovered gaps have named owners.** GAP-12 (per-framework regex), GAP-13 (`"all"`/`"none"` semantics — left to risks/controls schemas where they actually live), GAP-19 (`applicableTo` boundary), GAP-25 (dormant `components` enum value, activated in the sweep via `mappings` on components), GAP-31 (mermaid coupling), GAP-32 (dead `techniqueUriPattern`) all have decisions or named scoping. The supporting-schemas surface is no longer institutional knowledge.

**Negative**

- **The grouped form means a reader interested only in `frameworks.schema.json` reads four other schemas' D-sections to find D5.** The grouping is cheaper to author and easier to keep coherent than five thin ADRs, but a reader looking for "what does the frameworks schema enforce" sees D2-D4 first. Mitigated by D5 carrying its own stable IDs (D5a, D5b, D5c, D5d) so cross-references from ADRs 019 and 020 land precisely.
- **The per-framework regex deliverable couples `frameworks.schema.json` to `risks.schema.json` / `controls.schema.json` more tightly.** Today the consumer schemas reference frameworks only by `mappings.propertyNames`; after D5b they reference per-framework value patterns as well. A new framework requires three schema edits (the `frameworks.yaml` + `frameworks.schema.json` enum addition, the `definitions/framework-mapping-patterns` pattern entry, and the consumer-schema reference shape). The coupling is the right call — a new framework with no value pattern means typo'd IDs pass validation forever — but it is a real coordination cost.
- **The `techniqueUriPattern` retention (D5d) is a soft commitment.** Kept as a latent placeholder for likely future ADR-016 integration work. If that work never materializes, the schema carries a dead-but-documented field indefinitely. The cost is small; the alternative (remove now, re-add later with a fresh ADR) is more expensive. (D5c is no longer a soft commitment — the conformance sweep activates the `applicableTo: components` value by adding `mappings` to `components.schema.json`.)
- **GAP-31 (mermaid coupling) is pushed to the generator, not the schema.** D6a recommends the `MermaidConfigLoader` graceful-fallback path. This means `mermaid-styles.schema.json` does not gain a `propertyNames` `$ref` to `components.schema.json`'s category enum, and the schema does not catch a `mermaid-styles.yaml` that omits a recently-added component category. The generator's warning emission is the new defense; if a contributor adds a category and ignores the warning, the diagram silently uses the emergency fallback. Acceptable as long as the warning is visible at generator-run time; if it proves invisible, a later schema-side tightening revisits.
- **The sweep-wide [ADR-017](017-yaml-prose-authoring-subset.md) D3 deferral pins a specific posture across four content surfaces.** If the lint regresses, all four content surfaces lose the schema-side defense-in-depth at once. D7's revisit conditions name this; the lint's reliability is now a load-bearing assumption. The lint is small (per [ADR-017](017-yaml-prose-authoring-subset.md) D4 a hand-rolled tokenizer with shared fixtures) and runs on every commit, so the assumption is reasonable — but it is an assumption.
- **The grouped ADR does not pre-empt any framework-content design questions.** The `"all"`/`"none"` three-valued semantics (GAP-13), the `mappings` value shape on personas (GAP-29 / personas D8), and the persona-ordering implicit contract (GAP-33) are *consumer-side* concerns on `risks.schema.json`, `controls.schema.json`, and `personas.schema.json`. They are not in scope here. A reader expecting D7-style sweep-wide close-outs on those will not find them; they live in the per-file ADRs (018-021) and `risk-map/docs/design/`.

**Follow-up**

- **Conformance sweep — supporting-schemas deliverables.** A coordinated commit (or sequence) that:
  1. Adds `additionalProperties: false` to `actorAccessLevel`, `impactType`, `lifecycleStage`, and `framework` definitions per D2/D3/D4/D5.
  2. Adds `"minimum": 1, "maximum": 8` to `lifecycleStage.order` per D4.
  3. Authors `frameworks.schema.json` `definitions/framework-mapping-patterns` block with the five concrete patterns named in D5b (MITRE ATLAS, NIST AI RMF, STRIDE, OWASP LLM Top 10, EU AI Act). ISO 22989 stays as bare `string` per D5b.
  4. Updates `risks.schema.json` and `controls.schema.json` to reference the per-framework patterns from D5b. The exact reference shape (per-property `if/then`, per-property explicit object, or `$ref` to a shared per-property pattern) is a sweep-execution call; the patterns themselves are owned by this ADR.
  5. Coordinates the `applicableTo: components` activation per D5c with [ADR-018](018-components-schema.md)'s addition of a `mappings` field to `components.schema.json`. The framework-side enum value already lists `components`; the components-side schema gains the field; a framework that opts to map to components adds the `applicableTo: components` value at that point.
  6. Adds a `lifecycleStage.order` uniqueness check to `riskmap_validator/validator.py` per D4.
- **Conformance sweep — mermaid-styles graceful fallback (D6a).** Extend `MermaidConfigLoader` to emit a warning when `sharedElements.componentCategories` lacks a styling entry for a category present in `components.schema.json`. The fallback already exists; the warning is the visibility addition. Tests via the testing agent per [ADR-005](005-pre-commit-framework.md) / [ADR-013](013-site-precommit-hooks.md) patterns.
- **`framework.techniqueUriPattern` integration (deferred).** A future ADR — likely a sweep follow-up or an [ADR-016](016-reference-strategy.md) sibling — decides whether `techniqueUriPattern` becomes the URL template that `mappings.mitre-atlas[]` IDs resolve to in the table generator and the site renderer. This ADR retains the field; the integration ADR uses it.
- **Sibling ADRs.** [ADR-018](018-components-schema.md), [ADR-019](019-risks-schema.md), [ADR-020](020-controls-schema.md), and [ADR-021](021-personas-and-self-assessment-schema.md) document the per-file content schemas and precede this ADR. The conformance sweep begins after this ADR is `Accepted`.
- **Sweep-wide [ADR-017](017-yaml-prose-authoring-subset.md) D3 revisit.** D7's deferral is indefinite. A future ADR that adopts the schema-side reject pattern globally cites this ADR for the deferred state; the trigger is either repeated lint regression or a new content surface that legitimately bans parentheticals.
- **If a new framework is added** (`mitre-attack-rmf`, `nist-csf`, an extension of OWASP LLM), it lands as a coordinated edit: `frameworks.yaml` entry, `frameworks.schema.json` `id` enum extension, `definitions/framework-mapping-patterns` pattern entry, and (if the framework's value space is unconstrained like ISO 22989) an explicit decision to keep the value as bare `string`. This ADR records the pattern; the framework-content design call (which framework to add) lives in `risk-map/docs/design/`.
- **If a new component category is added,** it lands as a coordinated edit: `components.schema.json` `category.id` enum extension (per [ADR-018](018-components-schema.md) D2), `components.yaml` category definition, and a `mermaid-styles.yaml` `sharedElements.componentCategories` styling entry. The D6a graceful fallback handles the transition window where styling has not yet been authored.
