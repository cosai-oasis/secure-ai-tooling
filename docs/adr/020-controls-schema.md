# ADR-020: `controls.schema.json` design and tradeoffs

**Status:** Accepted
**Date:** 2026-04-25
**Authors:** Architect agent, with maintainer review
**Extended by:** [Amendment 2026-09-30](#amendment-2026-09-30-optional-guidance-prose-field) (below) — adds D9 (the optional `guidance` prose property), adds one row to the D1 field table and three rows to the D8 enforcement table, and records that both `description` shapes named in D1 and D4 (file-level and per-control) are `utils/prose-strict`. D1–D8 are otherwise unchanged.

---

## Context

`risk-map/schemas/controls.schema.json` is the JSON Schema (Draft-07) governing `risk-map/yaml/controls.yaml`, the catalog of mitigations the framework recommends for the risks documented in `risks.yaml`. Controls are the second-largest content surface after risks, and their downstream consumers overlap closely with risks: `scripts/hooks/yaml_to_markdown.py` (table generation under `risk-map/tables/`) and `scripts/build_persona_site_data.py` (the persona-site JSON contract codified in [ADR-011](011-persona-site-data-schema-contract.md), which normalizes `controls` into the per-persona explorer at `site/`). (`scripts/hooks/riskmap_validator/graphing/` no longer has a production consumer of `controls.yaml`'s content: [#477](https://github.com/cosai-oasis/secure-ai-tooling/issues/477) removed the control graph generator, and `base.py`'s `_load_category_names` still opens the file, but perturbing a category title leaves the generated graph byte-identical — its only caller, `component_graph.py`, resolves component category display names from `components.yaml`.)

The schema carries 29 control IDs in a closed enum, six closed control category IDs, four taxonomy axes (`lifecycleStage`, `impactType`, `actorAccess`, plus `category`), three structured-reference arrays (`personas`, `components`, `risks` — the latter two with a `"all" | "none"` literal escape hatch shaped as `oneOf`), an open `mappings` object whose property names are pinned to `frameworks.schema.json` IDs but whose values are unconstrained string arrays, and a single prose field (`description`) referencing `riskmap.schema.json#/definitions/utils/text`. Like the risks schema, it has accreted incrementally without a unifying ADR; like the components schema, the validator carries the cross-cutting integrity rules.

[ADR-014](014-yaml-content-security-posture.md) establishes the security posture; ADRs 015-017 set the rendering, reference, and authoring rules that this ADR threads into the schema. [ADR-018](018-components-schema.md) documents components, [ADR-019](019-risks-schema.md) documents risks, this ADR documents controls, [ADR-021](021-personas-and-self-assessment-schema.md) documents personas, and [ADR-022](022-supporting-schemas.md) covers supporting schemas. The per-file schema ADRs are non-overlapping.

The discovery work that motivated this set of architectural ADRs surfaced controls-specific gaps:

- **Folded-bullet drift in prose.** `controlModelAndDataExecutionIntegrity.description[1]` (`controls.yaml:257-262`) was authored as folded-scalar lines that *look* like a bulleted list but render as a single soft-wrapped paragraph because the `- bullet` lines are inside a `>`-folded scalar rather than a YAML sequence. The schema's BLOCK-02 nesting model (one level of `array<string>` nesting via `riskmap.schema.json#/definitions/utils/text`) accommodates the *correct* nested-list form; the schema cannot detect this drift class because the malformed input is still a valid string. Tracked separately as issue #225.
- **`components` and `risks` `oneOf` escape hatches.** Both fields accept either a typed array or the literal `"all"` (and `components` additionally accepts `"none"`). `risks: "all"` denotes a universal control (Assurance and Governance categories), and the bidirectional integrity check in `validate_control_risk_references.py` treats `"all"`/`"none"` as skip-validation sentinels. The schema enforces the literal alternatives via `oneOf`; the *semantic* boundary (when "all" vs. "none" vs. an explicit array is appropriate) is content-style guidance.
- **`mappings` is loosely typed.** Like risks, controls accepts any string array per framework key. There is no per-framework regex; `AML.M0010` and `aml-m0010` and `AML M0010` all pass schema validation. The canonical-form discipline lives only in `framework-mappings-style-guide.md`.
- **No ghost field.** Unlike risks (`relevantQuestions`), controls carries no top-level `questions` field today and no analogous ghost field. The `risks` field at line 95 plays the structured-reference role the discovery report classified under that taxonomy.
- **Outbound citations are sparse.** Controls prose carries far fewer outbound `<a href>` citations than risks prose. A spot-check of `controls.yaml` finds none; the [ADR-016](016-reference-strategy.md) `externalReferences` integration is structurally identical to risks but operationally lighter.

This ADR documents the schema's existing shape under [ADR-014](014-yaml-content-security-posture.md) P2's content-class taxonomy, declares per-rule machine-enforcement, threads in [ADR-016](016-reference-strategy.md)'s `externalReferences` `$ref` integration and [ADR-017](017-yaml-prose-authoring-subset.md)'s prose-content boundary, and lists the tightenings the conformance sweep will apply. It does not migrate the YAML or fix the folded-bullet drift; the sweep and a separate content-fix plan execute those changes against the decisions recorded here.

## Decision

`controls.schema.json` is documented retroactively under the content-class taxonomy of [ADR-014](014-yaml-content-security-posture.md) P2, with the additions and tightenings named below. Sub-decisions follow the D-prefix convention.

### D1. Field taxonomy under ADR-014 P2

Every top-level field in the `control` definition (and on the file-level envelope) maps to one of the five P2 content classes. The classes drive enforcement: identifiers and structured references are schema-authoritative; prose is shape-only at the schema layer and content-bounded by the lint per [ADR-017](017-yaml-prose-authoring-subset.md); metadata is short scalar; the file emits no generated-artifact fields directly.

| Field | P2 class | Schema shape | Enforcement |
|---|---|---|---|
| `id` (control, category) | identifier | closed `enum` of camelCase IDs | schema |
| `title` | metadata | bare `string`, no length cap | schema (type only) |
| `description` (control, file) | prose | `$ref riskmap.schema.json#/definitions/utils/text` | schema (shape) + lint per [ADR-017](017-yaml-prose-authoring-subset.md) D4 |
| `category` (on control) | identifier (taxonomic) | `$ref` to `category.id` enum | schema |
| `personas` | structured reference | array of `$ref` to `personas.schema.json` `id` | schema (membership only) |
| `components` | structured reference | `oneOf: [array<$ref to component id>, "all" \| "none"]` | schema (membership/literal) |
| `risks` | structured reference | `oneOf: [array<$ref to risk id>, "all"]` | schema (membership/literal) + validator (bidirectional integrity, universal-control rejection) |
| `mappings` | metadata (structured) | `propertyNames: $ref frameworks.schema.json id`; values open string arrays | schema (key only); per-framework value patterns deferred (D5) |
| `lifecycleStage`, `impactType`, `actorAccess` | identifier (taxonomic) | `oneOf: [array<$ref enum>, "all" \| "none"]` | schema |
| `categories` (file-level array) | structured reference | array of `category` definitions | schema |
| `controls` (file-level array) | structured reference | array of `control` definitions | schema |
| `externalReferences` (planned, D6) | structured reference | `$ref` to shared `external-references.schema.json` | schema once D6 lands |

The control schema carries no `tourContent`, no `relevantQuestions`, no `questions`, no `version`, no `lifecycleStage`-like deprecation flag. The asymmetry against risks is intentional: a control is a recommended mitigation, not a stage-keyed narrative; the `tourContent` notion does not transfer. The asymmetry is recorded here so a future contributor proposing per-stage prose on controls encounters the deliberate choice.

The class boundary is load-bearing per [ADR-014](014-yaml-content-security-posture.md) P2: `risks` and `components` are authoritative at schema and validator layers; `description` is shape-only at the schema and content-bounded at the lint; `mappings` values are the only open string surface and are slated for per-framework tightening in the conformance sweep (D5).

### D2. Identifier and enum decisions

The schema closes every identifier surface against author-side typos by enumeration:

- **`control.id`.** Closed enum at `controls.schema.json:42-74`, currently 29 values. Each value is camelCase with a `control` prefix (`controlAdversarialTrainingAndTesting`, `controlAgentObservability`). The closed-enum form forces every new control to land via a schema-edit PR that is itself reviewable, mirroring [ADR-019](019-risks-schema.md) D2's rationale for the risk enum and matching the property the [ADR-016](016-reference-strategy.md) D6 sentinel linter relies on (the linter reads the controls enum directly to validate `{{controlXxx}}` sentinel resolution).

- **`category.id`.** Closed enum, 6 values: `controlsData`, `controlsInfrastructure`, `controlsModel`, `controlsApplication`, `controlsAssurance`, `controlsGovernance`. The last two (`controlsAssurance`, `controlsGovernance`) are *universal-control* categories: every control under them carries `risks: "all"` and `components: "all"` or `components: "none"` per author convention (`guide-risks.md` documents the seven universal controls in prose only — flagged as GAP-17 in the discovery report). New control categories are an ADR question (framework-content design lives in `risk-map/docs/design/` per [ADR-001](001-adopt-adrs.md)), not a silent schema edit.

- **`lifecycleStage`, `impactType`, `actorAccess`.** Each is `oneOf: [array<enum-id>, "all" | "none"]`. The shared shape with risks (per [ADR-019](019-risks-schema.md) D2) is deliberate: the four taxonomy axes are framework-wide, not per-content-type, and live in dedicated schemas (`lifecycle-stage.schema.json`, `impact-type.schema.json`, `actor-access.schema.json`) that controls and risks both `$ref`. The `"all" | "none"` literal escape hatch exists so authors can express "applies everywhere" / "applies nowhere" without enumerating every member; the two literal values are the only escape hatches by design.

**Closed vs. open.** All identifier and category enums are closed — additions go through schema review. The schema accepts the cost (a schema edit on every new control) in exchange for the property that every consumer (validator, Mermaid generator, table generator, persona-site builder, sentinel linter) sees the same taxonomy at the same time. An open `category` field would let `controls.yaml` introduce a category that the persona-site renderer and Mermaid generator have not been taught to colour or distinguish (GAP-28 in the discovery report flags that the SPA renderer already does not visually distinguish `controlsAssurance` from `controlsGovernance`); the closed enum is the upstream pin.

### D3. Structured-reference fields — schema/validator boundary

Three fields are structured references on controls: `personas`, `components`, `risks`. The schema enforces membership (every value is in the corresponding source enum); the validator enforces cross-file integrity:

- **`personas`** → `$ref: personas.schema.json#/definitions/persona/properties/id`. Required at the entry level. Schema enforces membership only; the schema does not enforce ordering or filter deprecated personas (`build_persona_site_data.py:147-150` filters `personaModelCreator`/`personaModelConsumer` from the site output via `active_persona_ids`). Per [ADR-014](014-yaml-content-security-posture.md) P2, ordering and deprecation semantics are content-style concerns (GAPs 3, 4, 22, 33 in the discovery report) routed to a future framework-content ADR, not the schema.

- **`components`** → `oneOf: [array<$ref component id>, "all" | "none"]`. Required at the entry level. The literal alternatives `"all"` and `"none"` are taxonomic shorthand: `"all"` declares the control applies to every component (universal controls in the Assurance/Governance categories); `"none"` declares the control acts at the policy/governance layer rather than against a specific component (e.g., `controlInternalPoliciesAndEducation` at `controls.yaml:640-651`). The schema enforces the disjoint shape; the *appropriateness* of `"all"` vs. `"none"` vs. an enumerated list is content-style guidance.

- **`risks`** → `oneOf: [array<$ref risk id>, "all"]`. Required at the entry level. Notably **`"none"` is not accepted** for `risks`: a control that addresses no risks is by definition unjustified and should not exist. The validator enforces the `"all"` semantic strictly: `validate_control_risk_references.py:204-222` emits `[ISSUE: risks.yaml]` when a risk explicitly lists a universal control (one with `risks: "all"`), because universal controls apply *implicitly* and should not be enumerated.

The schema-versus-validator boundary for D3 mirrors [ADR-019](019-risks-schema.md) D3 and the components-edge pattern from [ADR-018](018-components-schema.md) D3:

- **Schema:** identifier shape, identifier resolves to a known enum value, array typing, literal escape-hatch typing.
- **Validator:** bidirectional referential integrity (`controls[].risks` ↔ `risks[].controls`), orphaned-control detection (a control with empty `risks: []` is reported as isolated by `find_isolated_entries`), universal-control-vs-explicit-listing rejection, dangling-reference detection across files.

Per [ADR-014](014-yaml-content-security-posture.md) P2, cross-file referential integrity is a validator concern, not a schema concern: a JSON Schema cannot express "every entry in this array must also appear in another file's corresponding array." `validate_control_risk_references.py` is the enforcement point, invoked via `.pre-commit-config.yaml` per [ADR-005](005-pre-commit-framework.md) on every commit that touches `risks.yaml` or `controls.yaml`.

The validator does **not** currently mirror-check `controls[].components` against `components.yaml` (no equivalent of `validate_control_risk_references.py` exists for the controls→components edge). The schema's `$ref` against the components ID enum catches typos but no validator catches a control referencing a component that has been removed from `components.yaml` between two PRs. This is a sweep-adjacent gap noted in D7; mirroring is mechanically light to add but is out of scope for this ADR.

### D4. Prose-field shape and the optional ADR-017 D3 reject pattern

Controls prose lives in two places: file-level `description` and per-control `description`. Both reference `riskmap.schema.json#/definitions/utils/text` — `array<string | array<string>>`, one nesting level. The schema asserts shape only; content (which markdown tokens the strings may contain) is enforced by `validate-yaml-prose-subset` per [ADR-017](017-yaml-prose-authoring-subset.md) D4.

[ADR-017](017-yaml-prose-authoring-subset.md) D3 leaves a coarse `<>()` reject pattern on prose fields as an optional schema-level second filter — `<` and `>` catch raw HTML, `(` catches the `](` opening of a markdown link. The controls schema **defers** opting in. Rationale (mirrors [ADR-018](018-components-schema.md) D4 and [ADR-019](019-risks-schema.md) D4):

- Controls prose is comparatively quiet on outbound citations. Spot-check of `controls.yaml` finds no `<a href>` tags, no `<strong>`/`<em>` emphasis, and no inline URLs in `description`. The lint catches drift if it appears; the schema-side filter would be a second backstop with no current cases to backstop.
- Parenthetical asides are present and legitimate. `controlAgentPluginPermissions.description` (`controls.yaml:521-529`) uses parentheticals freely (`(e.g., agentic providers, application developers)` patterns are common in the agentic controls). A schema-level `(` reject would force a stylistic rewrite during the conformance sweep that is unrelated to the security posture.
- The optional pattern lives on the shared `riskmap.schema.json#/definitions/utils/text` definition, not on the controls schema directly. Adopting it would affect every consumer at once. This is a conformance-sweep call, and ADRs 018 and 019 already declared the same deferral; controls follows the same line. If the sweep adopts the pattern globally, controls inherits it; if the sweep declines, controls stays as-is.

The lint is the authoritative content layer for controls prose either way. Deferring the schema pattern does not weaken the eventual posture.

**Folded-bullet drift (issue #225, `controlModelAndDataExecutionIntegrity`).** `controls.yaml:257-262` reads:

```yaml
- >
  Examples include ...
  - validating expected code and model signatures / hashes at inference-time
  - limit and immutably record all modifications to runtime AI system components via
    oversight processes
  - etc
```

This passes both the schema and the canonical authoring subset because, mechanically, it is a single folded-scalar string with `- ` characters embedded — JSON Schema sees a valid `string`, the [ADR-017](017-yaml-prose-authoring-subset.md) lint sees a string with no disallowed tokens. The author intent (a sub-list under "Examples include") is the BLOCK-02 nested-list shape:

```yaml
- >
  Examples include:
- - >
    validating expected code and model signatures / hashes at inference-time
  - >
    limit and immutably record all modifications to runtime AI system components via
    oversight processes
  - >
    etc.
```

The schema's BLOCK-02 nesting model (one level of `array<string>` items inside the top-level array) accommodates the corrected form via the existing `riskmap.schema.json#/definitions/utils/text` definition. The schema **cannot** detect the malformed form because the author's bug produced a valid string. The corrective channel is:

1. **Content-side:** the existing folded-bullet-drift content fix plan (referenced in maintainer working notes) repairs `controls.yaml:257-262`. This is content work, not schema work.
2. **Conformance sweep:** if the sweep introduces a heuristic lint that flags `^\s*-\s+` patterns inside folded-scalar strings as suspicious, that lint would catch this drift class. The lint design is out of scope for this ADR; the gap is named so the sweep can decide whether to invest in the heuristic. Recommended: yes — the heuristic is cheap and the failure mode ("looks like a list but renders as one paragraph") is invisible to authors at review time.

The **input-vs-output prose-shape gap** ([ADR-019](019-risks-schema.md) D4 documents this for risks) applies identically to controls. The input schema (`riskmap.schema.json#/definitions/utils/text`) is more permissive on nesting depth than the output schema (`persona-site-data.schema.json#/definitions/prose`). The conformance sweep tightens the shared input definition (or introduces a constrained sibling) to match the output shape — `array` of `string | array<string>`, one level of nesting maximum, `array<string>` items must contain at least one element. The tightening is owned by the conformance sweep and is shared with risks/personas/components ADRs; this ADR records that controls inherits the tightening via its existing `$ref`.

### D5. Framework-mapping fields (`mappings.*`)

`mappings` on controls is structurally identical to `mappings` on risks:

```json
{
  "type": "object",
  "propertyNames": { "$ref": "frameworks.schema.json#/definitions/framework/properties/id" },
  "additionalProperties": {
    "type": "array",
    "items": { "type": "string", "description": "Framework-specific category, technique, or tactic identifier" }
  }
}
```

Property names (`mitre-atlas`, `nist-ai-rmf`, `owasp-top10-llm`) are validated against `frameworks.schema.json`. The values are open string arrays. There is **no per-framework regex** on the mapping IDs today, so `AML.M0010`, `aml-m0010`, `AML M0010`, and `M0010` all pass schema validation (the same gap GAP-12 documents for risks). Controls mappings follow the MITRE ATLAS *mitigation* convention (`AML.M`-prefixed), where risks follow the *technique* convention (`AML.T`-prefixed); the per-framework regex tightening must distinguish the two prefixes per framework consumer.

**Conformance-sweep tightening — reuse ADR-019 D5's pattern.** The conformance sweep adds per-framework ID patterns to `frameworks.schema.json` in a new `definitions/framework-mapping-patterns` block (single-source-of-truth, same pattern as `external-references.schema.json` per [ADR-016](016-reference-strategy.md) D3) and applies them via `propertyNames` plus per-property `items.pattern` constraints. The patterns themselves cover both MITRE ATLAS technique (`AML\.T\d{4}(\.\d{3})?`) and mitigation (`AML\.M\d{4}`) IDs; controls and risks share the framework-key enum but differ in which sub-pattern is appropriate (the patterns must be applied per framework, not per content type). This ADR adopts ADR-019 D5's recommended approach: regexes live in `frameworks.schema.json`, are referenced from `controls.schema.json` and `risks.schema.json` identically, and the schema-only tightening does not require validator changes.

Per-mapping rationale fields (a sentence explaining *why* `controlSecureByDefaultMLTooling` maps to MITRE ATLAS `AML.M0011`) are deliberately **not** added, mirroring [ADR-019](019-risks-schema.md) D5. Free-text rationale per mapping is prose; prose belongs in the control's `description` where citations live as `externalReferences` per [ADR-016](016-reference-strategy.md). The schema would force every mapping to grow a string field most of which would be empty or duplicative. Framework cross-walks are taxonomy-ID-only by design.

### D6. `externalReferences` integration per ADR-016

Per [ADR-016](016-reference-strategy.md) D3, the conformance sweep adds an optional `externalReferences` field to each consumer schema by `$ref`-ing the new shared `risk-map/schemas/external-references.schema.json`. Controls is one of the four consumers (alongside risks, components, personas).

Concrete edit (conformance sweep): under `definitions/control/properties`, add a single line `"externalReferences": { "$ref": "external-references.schema.json#/definitions/externalReferences" }` and leave the property out of `required`. The shape — array of objects with `type`, `id`, `title`, `url`; the `type` enum and per-type `id` patterns — lives in the shared schema and is owned by [ADR-016](016-reference-strategy.md). This ADR does not redefine it.

**Controls-specific posture.**

- **Optional, not required.** Controls are recommended mitigations and most do not carry citations today. Required-with-`minItems: 1` would force authors to fabricate citations on controls that genuinely do not need them. Mirrors [ADR-019](019-risks-schema.md) D7 and [ADR-018](018-components-schema.md) D5.
- **Empty arrays remain rejected.** [ADR-016](016-reference-strategy.md) D3 already constrains the shared definition so that an empty array fails validation; authors omit the field instead.
- **Operationally lighter than risks.** Risks carry approximately 55 outbound citations across `longDescription` and `examples`; controls carry effectively zero today. The integration is structurally identical (the `$ref` line), but the content migration burden is near-empty for controls. New citations added during or after the sweep land in `externalReferences` rather than as inline anchors per [ADR-016](016-reference-strategy.md) D2.
- **Type usage.** When citations land, the same `type` enum applies (`paper`, `advisory`, `news`, `editorial`, `cve`). Controls citations will skew toward `editorial` (best-practice references) and `advisory` (vendor guidance) more than risks, which skew toward `paper` (academic) and `news` (incident reporting). No type cap is enforced; the shape is dictated by the shared schema.

### D7. Other follow-ups from the discovery report

Three controls-specific gaps in the schema's current shape; none block the architectural posture this ADR documents; all belong to the conformance sweep.

- **`additionalProperties: false` on the `control` and `category` objects (major).** The schema does not set `additionalProperties: false` on either definition. A typo'd field name (`descripton`, `componenets`, `risk` instead of `risks`) silently passes and silently produces a missing rendered field downstream. The conformance sweep adds `"additionalProperties": false` on both objects. This must be ordered after any `externalReferences` and other planned additions land in the same PR; otherwise a stray previously-valid field would fail validation. Same strictness ADR-011 D1 applies to `persona-site-data.schema.json`'s top-level keys and that [ADR-019](019-risks-schema.md) D8 plans for risks.

- **`title` is unbounded (minor).** No `maxLength`, no `pattern`, no required-prefix rule. Every control title today is 2-7 words; the longest is `Privacy Enhancing Technologies for Model Training` (`controlModelPrivacyEnhancingTechnologies`, 7 words, ~50 chars). A maliciously long title would pass schema validation and break Mermaid layout. The conformance sweep adds `"maxLength": 100` (chosen tighter than risks' 120 because controls are recommended mitigations whose titles are inherently action-shaped and shorter than risk titles).

- **`controls[].components` ↔ `components.yaml` mirror not enforced (minor).** As noted in D3, `validate_control_risk_references.py` enforces the `risks`↔`controls` mirror but no validator enforces a `controls`↔`components` mirror. The schema's `$ref` against the components ID enum catches typos at schema-validation time, so the gap class is "a control references a component that was removed from `components.yaml` after the schema enum was extended but before the YAML was cleaned up" — a narrow window. Recommended: add a small consistency check to `riskmap_validator/validator.py` rather than a new top-level validator script; the check is mechanical (every `controls[].components[]` ID appears in `components.yaml`'s component list) and does not warrant its own pre-commit hook.

**No ghost fields on controls.** Every defined field in the controls schema is read by at least one of the validator, the persona-site builder, the table generator, or the Mermaid generator. There is no analogue of risks' `relevantQuestions` ghost field. The discovery report's note about a `questions` field — which appears in maintainer working notes alongside the [ADR-019](019-risks-schema.md) `relevantQuestions` retirement — refers to a *future-state* possibility rather than an existing field: `controls.yaml` has no `questions` field, the schema has no `questions` definition, and no consumer reads such a field. If the [ADR-019](019-risks-schema.md) D6 retirement migrates the 6 risks-side questions to controls, the migration adds a `questions` field and the schema gains a corresponding definition — but that addition is owned by the [ADR-019](019-risks-schema.md) sweep, not by this ADR. This ADR records the current state: no `questions` field exists on controls today.

### D8. Per-rule machine-enforcement summary

| Rule | Mechanism | Status |
|---|---|---|
| D1 every field maps to a P2 class | this ADR, schema structure | Documentation (machine-enforceable rules per row below) |
| D2 `control.id` and `category.id` are closed enums | `controls.schema.json` `enum` | Machine-enforced (existing) |
| D2 `control.category` `$ref`'s the category `id` enum | schema `$ref` | Machine-enforced (existing) |
| D2 `lifecycleStage`/`impactType`/`actorAccess` enum-or-literal | schema `oneOf` | Machine-enforced (existing) |
| D3 `personas` membership against `personas.schema.json` enum | schema `$ref` | Machine-enforced (existing) |
| D3 `components` membership-or-literal | schema `oneOf` + `$ref` | Machine-enforced (existing) |
| D3 `risks` membership-or-`"all"` | schema `oneOf` + `$ref` | Machine-enforced (existing) |
| D3 bidirectional `controls`↔`risks` integrity | `validate_control_risk_references.py` | Machine-enforced (validator) |
| D3 universal-control-vs-explicit-listing rejection | `validate_control_risk_references.py:204-222` | Machine-enforced (validator) |
| D3 `controls`↔`components` mirror | recommended: `riskmap_validator/validator.py` | Conformance-sweep deliverable (D7) |
| D4 prose shape (`array<string \| array<string>>`) | `riskmap.schema.json#/definitions/utils/text` | Machine-enforced (existing) |
| D4 prose content subset (markdown subset, no inline URLs) | `validate-yaml-prose-subset` ([ADR-017](017-yaml-prose-authoring-subset.md)) | Machine-enforced (conformance sweep, ADR-017) |
| D4 sentinel-ID resolution in prose | `validate_prose_references.py` ([ADR-016](016-reference-strategy.md)) | Machine-enforced (conformance sweep, ADR-016) |
| D4 schema-side `<>()` coarse reject on prose | `definitions/utils/text` pattern (optional) | Deferred to conformance sweep (matches ADRs 018/019) |
| D4 input prose nesting depth ≤ 1 (matches output schema) | `riskmap.schema.json#/definitions/utils/text` tightening | Conformance-sweep deliverable (cross-file with ADRs 018/019/021) |
| D4 folded-bullet drift heuristic | recommended: prose-subset lint extension | Conformance-sweep deliverable (D4) |
| D5 `mappings` property names resolve to known framework IDs | schema `propertyNames` `$ref` | Machine-enforced (existing) |
| D5 per-framework mapping ID regex (technique + mitigation patterns) | not enforced today; added in conformance sweep | Conformance-sweep deliverable (D5; shared with risks per ADR-019 D5) |
| D5 per-mapping rationale fields | not added | Decided against (D5) |
| D6 `externalReferences` shape | shared `external-references.schema.json` `$ref` ([ADR-016](016-reference-strategy.md)) | Machine-enforced (conformance sweep, ADR-016) |
| D6 `externalReferences` content (sentinel resolution, URL shape, type enum) | shared schema + `validate_prose_references.py` | Machine-enforced (conformance sweep, ADR-016) |
| D7 `additionalProperties: false` on `control` and `category` | schema constraint | Conformance-sweep deliverable (D7) |
| D7 `title.maxLength: 100` | schema constraint | Conformance-sweep deliverable (D7) |

Every rule above is machine-enforced or scheduled to become so under a named follow-up. There is no row that resolves to "documented in prose only"; the controls schema does not carry guidance the validator does not own.

## Alternatives Considered

- **Adopt [ADR-017](017-yaml-prose-authoring-subset.md) D3's optional `<>()` schema reject pattern for controls immediately.** Rejected; see D4. Controls prose carries legitimate parentheticals freely, and the [ADR-017](017-yaml-prose-authoring-subset.md) lint is the authoritative enforcement point. Adopting locally would either fork the shared `definitions/utils/text` definition (drift class) or affect risks/components/personas without their ADRs being authored. Defer to the sweep, matching [ADR-018](018-components-schema.md) D4 and [ADR-019](019-risks-schema.md) D4.
- **Encode the universal-control rule (`category in {controlsAssurance, controlsGovernance}` ⇔ `risks: "all"`) in the schema via `if`/`then`/`else`.** Rejected. JSON Schema can express the conditional, but the construction couples the category enum to the `risks` shape in a way that is fragile when a new universal-eligible category lands. The validator (`validate_control_risk_references.py:204-222`) already enforces the rule's *consequence* (no risk explicitly lists a universal control); the *premise* (universal controls live in Assurance/Governance categories) is content-style guidance documented in `guide-risks.md`. The current split — schema for shape, validator for cross-file enforcement, doc for category↔universality convention — is the right boundary. This matches the schema/validator split in [ADR-018](018-components-schema.md) D3 and [ADR-019](019-risks-schema.md) D3.
- **Detect folded-bullet drift in the schema directly.** Rejected. The drift case (`controlModelAndDataExecutionIntegrity.description[1]`) produces a *valid* string from the schema's perspective; no shape constraint can distinguish "a paragraph with `- ` characters" from "a paragraph the author intended as a list". A heuristic lint at the prose-content layer (recommended in D4 follow-up) is the right tool.
- **Add `tourContent` to controls (mirror risks).** Rejected. `tourContent` is risk-specific narrative — how the risk is introduced, exposed, and mitigated across the lifecycle — and does not transfer to controls, which are recommended mitigations rather than stage-keyed events. If a per-stage control narrative becomes a content need, it is a framework-content design question owned by `risk-map/docs/design/`, not a schema-uplift one. Documented as a deliberate asymmetry in D1.
- **Make `externalReferences` required on every control.** Rejected. Most controls today have no citations; required-on-every-control would force authors to fabricate references that do not underpin claims. Optional is consistent with risks/components/personas and matches actual usage. Mirrors [ADR-019](019-risks-schema.md) D7.
- **Add a `controls`↔`components` mirror via a new top-level validator script (sibling of `validate_control_risk_references.py`).** Rejected as scope. The mirror is a small consistency check that fits inside `riskmap_validator/validator.py` rather than warranting its own script and pre-commit hook entry. Recommended in D7 as a sweep deliverable.
- **Tighten `riskmap.schema.json#/definitions/utils/text` in this ADR rather than deferring to the sweep.** Rejected for the same reason [ADR-019](019-risks-schema.md) D4 rejected it: the shared definition affects every YAML schema (controls, risks, personas, components, mermaid-styles); tightening it from a per-file ADR commits decisions across surfaces without their ADRs being authored. The conformance sweep is the right scope; this ADR records the controls-side gap.

## Consequences

**Positive**

- **Controls schema is documented as a unit.** Future readers find every field's class, every enforcement layer, every gap, and every conformance-sweep deliverable in one place. The 29-control-id enum, the six-category enum, the four taxonomy axes, the `oneOf` literal escape hatches on `components` and `risks`, and the open `mappings` object are no longer institutional knowledge.
- **The schema-vs-validator boundary is explicit.** D3's split (schema for shape and membership, validator for cross-file integrity and universal-control rejection) names the same pattern [ADR-018](018-components-schema.md) D3 and [ADR-019](019-risks-schema.md) D3 document. Future per-file schema ADRs (personas in pair 2, framework-content schemas later) inherit the boundary.
- **The `externalReferences` integration is unambiguous.** D6 declares the `$ref` line; the conformance-sweep PR has no degrees of freedom on shape (it inherits from [ADR-016](016-reference-strategy.md)). The light citation load on controls means the sweep's controls-specific work is essentially the schema edit alone.
- **Folded-bullet drift has a named owner.** D4 distinguishes the schema's structural blindness from the lint's content responsibility and recommends the heuristic lint extension. Issue #225 has a documented home in the sweep's design space rather than as ambient backlog.
- **Conformance-sweep scope is enumerated for controls.** The sweep PR has a checklist: add `externalReferences` `$ref`, add `additionalProperties: false` to `control` and `category`, add `title.maxLength: 100`, add per-framework mapping-ID regex (shared with risks via `frameworks.schema.json` per ADR-019 D5), tighten `definitions/utils/text` to match output prose shape (cross-file), add a `controls`↔`components` mirror to `riskmap_validator/validator.py`, and consider the folded-bullet heuristic lint. Without this ADR, the controls portion of the sweep would re-derive scope from the schema alone.

**Negative**

- **Conformance-sweep work is committed.** Five-to-six deliverables (`externalReferences` `$ref`, `additionalProperties: false`, `title.maxLength`, per-framework mapping regex, mirror validator extension, optional folded-bullet heuristic) land as part of the sweep PR(s). Each is small individually; together they are real work. The controls-specific portion is lighter than risks' (no ghost-field retirement, no large citation migration) but heavier than components' (which has only the `$ref` and the taxonomy-nesting check).
- **Deferring the [ADR-017](017-yaml-prose-authoring-subset.md) D3 schema reject means controls lacks a defense-in-depth filter** that other per-file schemas may adopt independently. If the lint regresses (a hook bypass, a `--no-verify` commit), controls prose has only the lint as a barrier. Acceptable as long as the lint is reliable; the deferral is revisited if the lint regresses repeatedly. This is the same posture risks and components adopted.
- **Per-framework mapping-ID regex is deferred** until the conformance sweep. Until then, `AML.M0010` and `aml-m0010` and `AML M0010` continue to pass schema validation on controls. Content-reviewer is the human enforcement layer; the canonical-form discipline lives in `framework-mappings-style-guide.md`.
- **The `mappings` open-string-array shape is preserved** at the per-control level. A schema that constrained values more tightly would catch typos earlier but would block the framework from adopting a new mapping target without a coordinated schema edit. Current loose shape favours framework agility; the per-key regex tightening (D5) is the surgical compromise.
- **The schema-validator split is durable but invisible.** A reader of `controls.schema.json` alone cannot tell that bidirectional `controls`↔`risks` integrity is enforced or that universal-control listing is rejected; they must know about `validate_control_risk_references.py`. D3 makes the boundary explicit in this ADR, but the schema file itself stays terse. Future contributors editing the schema without reading this ADR may misjudge what coverage they have. Mitigated by the same documentation pattern in [ADR-018](018-components-schema.md) and [ADR-019](019-risks-schema.md).
- **`controls`↔`components` mirror is not enforced today.** Until the sweep adds the check, a control referencing a component that was removed from `components.yaml` after the schema enum was extended (a narrow window) silently passes. The schema's `$ref` against the components ID enum catches the typo class; the residual gap is the cleanup-window class.

**Follow-up**

- **Conformance sweep — controls-specific deliverables.** A coordinated commit (or sequence) that:
  1. Adds `controls.schema.json` `externalReferences` `$ref` line per D6 (depends on `external-references.schema.json` being authored first per [ADR-016](016-reference-strategy.md)).
  2. Adds `additionalProperties: false` to the `control` and `category` definitions per D7.
  3. Adds `"maxLength": 100` to `control.title` per D7.
  4. Adds per-framework mapping-ID regex patterns to `frameworks.schema.json` per D5; shared with risks per [ADR-019](019-risks-schema.md) D5. Patterns cover both technique and mitigation conventions where the framework has both (MITRE ATLAS).
  5. Tightens `riskmap.schema.json#/definitions/utils/text` (or introduces a sibling) to match the output prose shape per D4 (cross-file with components/risks/personas ADRs).
  6. Extends `riskmap_validator/validator.py` with a `controls`↔`components` mirror check per D7.
  7. Considers a folded-bullet heuristic lint as an extension to the [ADR-017](017-yaml-prose-authoring-subset.md) prose-subset lint per D4. Recommended; cheap; addresses issue #225's failure class.
- **Content sweep — folded-bullet drift fix.** `controls.yaml:257-262` migrates from the malformed folded-scalar form to the BLOCK-02 nested-list form. Tracked separately in maintainer working notes and issue #225; this ADR confirms the schema accommodates the corrected form.
- **Sibling ADRs.** [ADR-018](018-components-schema.md) and [ADR-019](019-risks-schema.md) document components and risks; [ADR-021](021-personas-and-self-assessment-schema.md) documents personas and runs alongside this ADR; [ADR-022](022-supporting-schemas.md) covers supporting schemas. Each per-file schema ADR decides independently on the [ADR-017](017-yaml-prose-authoring-subset.md) D3 opt-in question; this ADR defers, matching ADRs 018 and 019.
- **If a future controls-specific structured field is needed** (a `severity` enum, a `maturity` taxonomy, a per-stage applicability matrix), it lands as a schema-edit PR that cites this ADR and either fits one of the five P2 classes or motivates a P2 revisit. Adding open prose fields is discouraged per [ADR-014](014-yaml-content-security-posture.md) P3.
- **If [ADR-019](019-risks-schema.md) D6 migrates `relevantQuestions` content to a `controls.yaml` `questions` field** during its sweep, that addition is owned by the ADR-019 sweep and adds a `questions` definition to `controls.schema.json` at that time. This ADR records the current state (no `questions` field) and does not pre-empt the migration's design choices.

---

## Amendment 2026-09-30: optional `guidance` prose field

**Status:** Draft (2026-09-30). Extends D1 and D8 and adds D9. Does not alter the Accepted status of D1–D8.
**Authors:** Architect agent, with maintainer review.

### Context

A control carries two prose fields. `description` states what the control is: its objective and a positive statement of its scope. `guidance`, which is optional, holds how to meet the objective, where it applies, and how the control differs from sibling controls. The rules that decide which text goes in which field are framework-content design and live in [`risk-map/docs/design/control-description-and-guidance.md`](../../risk-map/docs/design/control-description-and-guidance.md).

This amendment records the schema-level consequences that ADR-020 owns: the new property's content class, its shape, and its enforcement layers. It also reconciles the property with the Follow-up note that "adding open prose fields is discouraged per [ADR-014](014-yaml-content-security-posture.md) P3".

### D9. `guidance` is an optional prose property on `control`

`definitions/control/properties/guidance` is a `$ref` to `riskmap.schema.json#/definitions/utils/prose-strict`. It is not listed in `required`. `additionalProperties: false` on `control` is unchanged, so a control can carry `guidance` only once the property is declared.

- **Content class.** `guidance` is **prose** under [ADR-014](014-yaml-content-security-posture.md) P2. It inherits the prose handling contract: shape at the schema, content at the [ADR-017](017-yaml-prose-authoring-subset.md) lint, sentinel resolution under [ADR-016](016-reference-strategy.md), and escaping at render boundaries.
- **Linter coverage follows from the declared shape.** The prose linters discover prose fields by their `$ref` to `utils/prose-strict` or `utils/text`. Declaring `guidance` with that `$ref` is what places it under lint. A property declared any other way would fall outside it.
- **Placement is content-style.** Which text belongs in `description` and which in `guidance` is owned by the design document above. D3 treats the appropriateness of `"all"` versus `"none"` versus an explicit list the same way.
- **No ghost field.** Every consumer that reads control prose reads `guidance`:
  - the persona-site builder emits it as an optional field under the [ADR-011](011-persona-site-data-schema-contract.md) contract, whose schema declares it;
  - the site renders it as secondary content;
  - the full-detail table emits it with the same prose handling as `description`.

  Summary views read `description` only.

#### D9a. Reconciliation with ADR-014 P3

P3 makes structured-reference fields authoritative for intra-framework links, including control-to-control, and prose is not a linking surface. `guidance` adds no linking surface. Its boundary section may mention sibling controls by `{{control…}}` sentinel. As under P3, those mentions are secondary and cosmetic: they are resolved and checked like any sentinel, but they do not form a relation set that tools may rely on.

The corpus has no structured control-to-control relation field. The design document sets the condition for adding one: a validator or tool needs to consume control-to-control relations as data.

The Follow-up note discouraging open prose fields guards against prose becoming a linking or taxonomy surface. `guidance` is neither. It is prose under the same class contract as `description`.

#### D9b. Both `description` shapes are `utils/prose-strict`

D1's field table (the `description` "(control, file)" row) and D4 ("Both reference `riskmap.schema.json#/definitions/utils/text`") name `utils/text` as the shape of both `description` sites. Both sites in `controls.schema.json` reference `utils/prose-strict` (commit `e188994`):

- the file-level `description` (`properties/description`);
- the per-control `description` (`definitions/control/properties/description`).

`guidance` uses the same `utils/prose-strict` shape. Read every `utils/text` reference to either `description` in D1 and D4 as `utils/prose-strict`. D4's reasoning about the shared prose definition is otherwise unchanged.

### D1 addition

| Field | P2 class | Schema shape | Enforcement |
|---|---|---|---|
| `guidance` (control) | prose | `$ref riskmap.schema.json#/definitions/utils/prose-strict`; optional | schema (shape) + lint per [ADR-017](017-yaml-prose-authoring-subset.md) D4 + sentinel resolution per [ADR-016](016-reference-strategy.md) |

### D8 additions

| Rule | Mechanism | Status |
|---|---|---|
| D9 `guidance` prose shape, optional | `controls.schema.json` `$ref` to `utils/prose-strict`, absent from `required` | Machine-enforced |
| D9 `guidance` prose content and sentinel resolution | ADR-017 / ADR-016 linters via schema-driven prose-field discovery | Machine-enforced |
| D9 no `{{control…}}` sentinel in per-control `description` | Mechanical check, owned by the design document | Scheduled: becomes machine-enforced under the named follow-up below, once no control in the corpus violates it |

D8's closing statement continues to hold: every row is machine-enforced or scheduled to become so under a named follow-up. The design document's placement rules that need judgment (for example, negated means, mechanism neutrality, sibling controls named without a sentinel, reciprocal boundary statements) are content-style guidance like D3's `"all"`/`"none"` appropriateness. They are not schema rules and have no D8 row.

### Alternatives Considered

- **A new ADR for `guidance`.** Rejected. The per-file schema ADRs are non-overlapping, and ADR-020 owns `controls.schema.json`.
- **Record the change only in the design document.** Rejected. D1's field table, the no-ghost-field statement, and D8's enforcement table would be incomplete. The Follow-up section also asks that a new control field cite this ADR and place itself in a P2 class.
- **Rename `description` to a statement-specific name.** Rejected. `description` is required and populated on every control and read by every consumer. A rename costs a corpus-wide migration and gains nothing that the design document's field contract does not already provide.

### Consequences

**Positive**

- The schema states the two-field shape, and every enforcement layer is named.
- Lint coverage of `guidance` follows from its declared shape, with no per-field wiring.

**Negative**

- Placement rules that need judgment are enforced by review, not by schema or lint.
- Controls use `description` and `guidance`; risks use `shortDescription` and `longDescription`. Contributors learn each entity's convention separately.

**Follow-up**

- The mechanical check that per-control `description` carries no `{{control…}}` sentinel. Trigger: no control on `main` or `develop` violates it.
