# ADR-016: Reference strategy for intra-document and external citations

**Status:** Accepted
**Date:** 2026-04-25
**Authors:** Architect agent, with maintainer review

---

## Context

The CoSAI Risk Map YAML content carries two kinds of references, and both are under-specified today.

**Intra-framework references.** The schemas already model authoritative edges as structured fields: `risks[].controls`, `controls[].risks`, `controls[].components`, `risks[].personas`, `components[].edges.{to,from}`, and similar. These are enum-checked against identifier lists in `risks.schema.json`, `controls.schema.json`, `components.schema.json`, and cross-file integrity is enforced by `scripts/hooks/validate_control_risk_references.py` and `ComponentEdgeValidator`. [ADR-014](014-yaml-content-security-posture.md) P3 commits the framework to structured references as the canonical linking surface; prose is not a linking surface.

In practice, prose fields still contain cross-references, and they split between two conventions with no documented rule:

- Anchored HTML (`<a href="#riskXxx">Title</a>`) — approximately 14 instances across roughly 8 entries, all in `risks.yaml`. These resolve only inside the `site/` SPA via the `renderRichParagraphs` `innerHTML` path flagged in [ADR-012](012-static-spa-architecture.md); in `risk-map/tables/risks-full.md` they render as dead links because the table generator emits no anchor targets.
- Bare camelCase identifiers (`riskAgentDelegationChainOpacity`) written mid-sentence — approximately 41 instances across roughly 14 entries. Plain text on every surface; no validator catches a typo.

Two entries (`riskToolRegistryTampering`, `riskToolSourceProvenance`) use both conventions inside a single prose field. The inconsistency predates any decision.

**External references.** Prose fields in `risks.yaml` carry approximately 55 outbound `<a href="https://...">` tags to papers, news articles, CWE entries, CVE records, vendor advisories, and framework pages. There are zero markdown-style `[text](url)` outbound references today. Neither the schemas nor any validator enforces the *type* of reference, and there is no structured field that captures canonical citations (a CWE number, a CVE ID, an ATLAS technique ID) separately from the sentence that mentions them. The existing `mappings` object on risks and controls captures framework cross-walks by keyed framework ID, but it is not designed for ad-hoc citations.

[ADR-017](017-yaml-prose-authoring-subset.md) codifies a minimal markdown subset for prose (`**bold**`, `*italic*`/`_italic_`, sentinels) and disallows raw `<a>` tags and inline URLs of any form. [ADR-015](015-site-content-sanitization-invariants.md) owns the render-time allowlist that the site emits from that subset plus the structured prose items the builder produces. Together these decisions remove the current authoring syntax for both anchored intra-document references and outbound links, leaving a gap this ADR must fill without colliding with markdown's bracket syntax or re-introducing the XSS-adjacent paths [ADR-012](012-static-spa-architecture.md) and [ADR-014](014-yaml-content-security-posture.md) are tightening.

Ecosystem precedents were surveyed: MITRE ATLAS uses `{{ create_internal_link(id) }}` sentinels in its source content; MITRE ATT&CK embeds bracketed bare IDs resolved at render; OSCAL uses structured `<link>` elements separate from prose; CWE uses a structured `Related_Weaknesses` block and names the related entry in prose separately. The common thread across the ones with machine-enforced integrity is that the authoritative edge set is structured and the prose layer is either sentinel-based (resolved at render) or descriptive text that does not carry the link itself.

The systemic gap that motivated this work was not the convention split alone. It was that every *style rule* in the repository's authoring guidance lived in prose — in contributing docs, in reviewer checklists, in ADR follow-ups — without a machine check that catches drift. Rules documented only in prose rot silently; rules enforced by a schema or a linter survive. This ADR therefore declares, per rule, whether the rule is machine-enforced or prose-only guidance.

## Decision

The Risk Map adopts a unified reference strategy with two layers — a **structured layer** that is authoritative for every consumer, and a **prose layer** that is cosmetic and lints-only. The strategy covers both intra-document and external references. Specifics follow.

### D1. Intra-document references — structured fields stay authoritative

The existing structured-reference fields (`risks[].controls`, `controls[].risks`, `controls[].components`, `risks[].personas`, `components[].edges.{to,from}`) are the complete set of authoritative intra-framework links. **No new structured fields are added for narrative cross-references** (e.g., "see also risk X" mentions that are not mitigations). A prose mention that does not correspond to an existing structured edge is cosmetic; authors who want the relationship to be authoritative add it to the appropriate structured field.

**Machine-enforced:** yes — existing enum validators and `validate_control_risk_references.py` already cover this.

### D2. Prose-mention sentinel grammar — `{{idXxx}}` and `{{ref:identifier}}`

Bare identifiers, anchored HTML, and inline URLs are all retired for prose mentions. The single authoring syntax is a **double-brace sentinel**, with two forms distinguished by an optional namespace prefix:

- **Intra-document form** — `{{idXxx}}` resolves against the framework's identifier enums (risks, controls, components, personas). Examples: `{{riskPromptInjection}}`, `{{controlInputValidationAndSanitization}}`, `{{componentModelServing}}`, `{{personaModelCreator}}`.
- **External-reference form** — `{{ref:identifier}}` resolves against the entry's own `externalReferences[].id` field (D3). The `ref:` prefix is a literal; `identifier` matches the `id` an author chose for the structured entry. Examples: `{{ref:cwe-89}}`, `{{ref:zhou-2023-poisoning}}`, `{{ref:vendor-advisory-2024-01}}`.

The sentinel carries an identifier only. Display text (the entity's `title` for the intra-document form; the `externalReferences[].title` for the reference form) is resolved at generation or render time from the referenced entry; authors do not hand-write titles inside sentinels, which eliminates a rename-drift class.

The grammar is unambiguously machine-parseable: a sentinel matches `\{\{(ref:)?[A-Za-z0-9_.\-]+\}\}`, and the namespace prefix is either present (`ref:`) or absent. The two forms cannot collide because `ref:` is a reserved prefix that no entity identifier can take (entity identifiers are camelCase, never carry colons). The dot is included in the identifier character class to support canonical-form sub-technique IDs (e.g., `AML.T0040.001` from MITRE ATLAS, `T1059.003` from MITRE ATT&CK) when used as `externalReferences[].id` values; the entity-prefix forms (`riskXxx`, `controlXxx`, etc.) are camelCase and do not use the dot.

Chosen over bare `{{cwe-89}}` (no namespace prefix, relying on uniqueness of external IDs against entity enums) because external IDs are author-chosen at the per-entry scope. Two entries can each define an `externalReferences` entry with `id: cwe-89`; the sentinel needs to know it is resolving against the *entry's* external list, not against a global enum. The `ref:` prefix makes the resolution scope explicit and keeps the linter's job a local lookup rather than a cross-entry uniqueness assertion.

Chosen over `[[idXxx]]` (wiki-link-style) for the same reason as before: double-bracket is visually close to the single-bracket markdown that surrounds it and is harder to distinguish in dense prose. The `{{ ... }}` family is also what MITRE ATLAS uses in its source content.

**Machine-enforced:** yes — see D6 (linter).

### D3. External references — structured field `externalReferences`

A new optional array-valued field `externalReferences` is added to the `risk`, `control`, `component`, and `persona` definitions. The field's shape — both the array and the per-item object — lives in a **single shared schema file** at `risk-map/schemas/external-references.schema.json`, and each consumer schema (`risks.schema.json`, `controls.schema.json`, `components.schema.json`, `personas.schema.json`) `$ref`s it for the property. This matches the existing convention in `risk-map/schemas/`, where reusable shapes live in their own `*.schema.json` files (`riskmap.schema.json#/definitions/utils/text`, `frameworks.schema.json`, `lifecycle-stage.schema.json`, `impact-type.schema.json`, `actor-access.schema.json`) and consumer schemas pull them via `$ref`. The shared-schema-with-`$ref` approach is the established pattern; not adopting it here would be the unusual choice.

Personas is included alongside risks, controls, and components because the YAML carries prose that may grow citations over time (the persona scope work in PR #212 already added prose elaborating Q2 for the Model Provider persona); excluding personas would force a later schema-uplift PR the moment a citation lands there. Walking the linter over `personas.yaml` (D6) without giving personas the field would also be inconsistent: the linter is ready to enforce sentinels in personas prose, but the schema would have nothing to resolve them against. Including it now costs one more `$ref` line and removes a future asymmetry.

Each entry is an object:

```yaml
externalReferences:
  - type: cwe                     # enum
    id: cwe-89                    # author-chosen sentinel target; shape enforced per type
    title: "Improper Neutralization of Special Elements used in an SQL Command"
    url: https://cwe.mitre.org/data/definitions/89.html
  - type: paper
    id: zhou-2023-poisoning
    title: "Poisoning Language Models During Instruction Tuning"
    url: https://arxiv.org/abs/2305.00944
  - type: editorial
    id: vendor-blog-rag-eval
    title: "Vendor blog post on RAG evaluation pitfalls"
    url: https://example.com/blog/rag-eval-pitfalls
```

Field shape:

- `type` — required enum. Values: `cwe`, `cve`, `atlas`, `attack`, `advisory`, `paper`, `news`, `spec`, `editorial`, `other`. The enum is declared once in `external-references.schema.json`. New types are added by editing that file, not by free-form adoption.
- `id` — required. Used as the sentinel target in prose (`{{ref:identifier}}`, D2). For canonical-form references (`cwe`, `cve`, `atlas`, `attack`), the `id` mirrors the canonical identifier in lowercase-kebab form (`cwe-89`, `cve-2024-0001`); for non-canonical references (`paper`, `news`, `editorial`, `other`), the author picks a stable shorthand (`zhou-2023-poisoning`, `vendor-blog-rag-eval`). Per-entry uniqueness is enforced; cross-entry uniqueness is not required. Shape is constrained per type where a canonical pattern exists; the per-type regex patterns live in `external-references.schema.json` alongside the type enum (not duplicated into each consumer schema), with concrete patterns committed in [ADR-022](022-supporting-schemas.md) D5b and authored in `frameworks.schema.json` during the conformance sweep.
- `title` — required. Display string used by generators and the renderer.
- `url` — required. Must be `https://` (HTTP is rejected); subset of allowed hosts is not defined here and is not enforced.
- Array is optional at the entry level; empty arrays are rejected (use omission instead).

**Co-evolution with this ADR.** Because `external-references.schema.json` encodes architecturally-significant choices (the `type` enum, the per-type id patterns, the URL scheme constraint, the array's required-fields set), changes to that file are ADR-revision territory rather than silent schema drift. A PR that adds a `regulation` value to the `type` enum, broadens the URL scheme rule, or relaxes a per-type pattern revises this ADR in the same change; a maintenance edit that only tightens an existing pattern (e.g., narrowing a regex without changing accepted values) does not.

The `id` is required (not optional, as in the previous draft of this ADR) because the sentinel form (D2, D4) needs a stable target for every entry. An entry with no `id` would be referenceable only by ordinal position, which is a rename-drift class this ADR exists to prevent.

**`type: editorial` — the non-citation case.** Citation-grade references (`cwe`, `cve`, `paper`, `advisory`, etc.) underpin the substance of the entry: a reader removing the reference loses information that the claim depends on. Editorial references add color, illustration, or a "see also" pointer that does not underpin substance: a reader removing it loses depth, not correctness. The distinction is an author judgment at the moment of adding the entry; the type tag captures that judgment so downstream consumers (a citation-list generator, a third-party redistributor that wants only citations) can filter on it. Authors who would previously have written an inline color link now add a structured `type: editorial` entry and reference it via sentinel; the friction is intentional, and it is the same friction every other URL incurs.

The name `editorial` was chosen over `color` (user-suggested), `illustrative`, and `note`. `color` is concise but informal — type values are read by downstream tooling and the term suggests styling rather than provenance. `illustrative` is accurate but verbose and overlaps with `paper` for examples that illustrate by demonstrating. `note` is too close to `notes` fields used elsewhere in the schemas. `editorial` names the author's intent (this is editorial content, not a citation) and reads cleanly in tooling that surfaces the type.

This mirrors CWE's `Related_Weaknesses` pattern: structured citation with a typed reference and a human-facing title. Existing `mappings` (framework cross-walks keyed by framework ID) remains the surface for bulk taxonomy-to-taxonomy mapping; `externalReferences` is for ad-hoc citations and editorial pointers that appear in prose.

**Machine-enforced:** yes — schema constrains `type`, `url`, `title`, and `id` required; per-type `id` regex patterns are declared in the schema uplift sub-deliverable. Per-entry `id` uniqueness is enforced by the schema or by `validate_prose_references.py`.

### D4. External references — sentinel-only prose, no inline URLs

Every outbound URL referenced in prose lives in the entry's `externalReferences` array. Prose references it via the sentinel form `{{ref:identifier}}` (D2), where `identifier` matches the structured entry's `id`. **Inline URL syntaxes of any scheme are not permitted in prose.** The rule is categorical: if a token in prose carries a URI scheme, the linter rejects it and the URL must move into `externalReferences`. [ADR-017](017-yaml-prose-authoring-subset.md) D4 rule 2 owns the exact tokenizer-level shape (RFC-3986 scheme-with-authority regex plus a named list for opaque-data schemes such as `mailto:`, `javascript:`, `data:`, `tel:` that lack `//` and would otherwise escape the primary regex), as the authoring-rules surface; the shared tokenizer at `scripts/hooks/precommit/_prose_tokens.py` is the implementation. Raw `<a href>` tags are blocked separately by ADR-017's HTML-tag rule. The categorical phrasing exists by design: a 3-form enumeration relies on a detection step the codebase does not have, so a non-enumerated scheme would slip through both linters as plain TEXT and ship to published artifacts. The threat profiles differ across schemes — `mailto:` and `tel:` are contact-exposure vectors, `javascript:` and `data:` are defense-in-depth XSS vectors, `ftp://` and `file://` are dead-scheme drift signals, `gs://`/`s3://`/`arn:` are legitimate cloud references that still belong in structured fields per [ADR-014](014-yaml-content-security-posture.md) P3 — but the architectural answer is the same in every case: a scheme in prose means a structured entry was missed.

The author flow is: add the structured entry first (with `type`, `id`, `title`, `url`), then reference it by sentinel in prose. Examples:

```yaml
description:
  - "The SQL-injection pattern ({{ref:cwe-89}}) applies to query construction in agent tooling."
  - "Zhou et al. ({{ref:zhou-2023-poisoning}}) demonstrated instruction-tuning poisoning at scale."
  - "A vendor write-up ({{ref:vendor-blog-rag-eval}}) walks through one evaluation pitfall in detail."
externalReferences:
  - type: cwe
    id: cwe-89
    title: "…"
    url: https://cwe.mitre.org/data/definitions/89.html
  - type: paper
    id: zhou-2023-poisoning
    title: "…"
    url: https://arxiv.org/abs/2305.00944
  - type: editorial
    id: vendor-blog-rag-eval
    title: "…"
    url: https://example.com/blog/…
```

The generators (D5) expand sentinels at build time:

- `scripts/hooks/yaml_to_markdown.py` — expands `{{ref:identifier}}` to the entry's `title` followed by the URL in the rendering convention the table generator picks (markdown link `[title](url)` or plain text `title (url)`; the specific shape is a generator-implementation choice within the table-builder ADR's scope, not this one).
- `scripts/build_persona_site_data.py` — expands `{{ref:identifier}}` to a structured prose item `{type: "link", title, url}` that the renderer turns into an outbound `<a>` per [ADR-015](015-site-content-sanitization-invariants.md)'s allowlist. The renderer constructs the `rel="noopener noreferrer" target="_blank"` attributes; authors do not write them.

The friction is intentional. Every URL gets type-tagged at the moment it enters the YAML; every URL is machine-validated for shape and scheme; every URL appears once in the structured list, not twice (once in prose, once in citations). Authors who want to add a link first commit to a type — citation or editorial — and add the structured entry. The editorial type (D3) is the destination for what previously would have been an inline color link.

**Machine-enforced:** yes — the linter (D6) blocks any inline URL form in prose unconditionally. There is no warn-only boundary to adjudicate.

### D5. Generator behavior

Both forms of sentinel — `{{idXxx}}` (intra-document) and `{{ref:identifier}}` (external) — are expanded by both generators. Neither pipeline emits raw anchor HTML, and neither tolerates an unresolved sentinel; an unknown ID is a hard failure of the build, not a silent pass-through.

- `scripts/hooks/yaml_to_markdown.py`:
  - `{{idXxx}}` expands to the entity's plain-text `title` (e.g., `{{riskPromptInjection}}` → `Prompt Injection`). Tables render on GitHub where cross-page anchors do not resolve reliably.
  - `{{ref:identifier}}` expands to the external reference's `title` plus the URL in the table-generator's chosen convention. The generator additionally emits a "References" sub-section under each entry that lists every `externalReferences` entry with its title and URL.
- `scripts/build_persona_site_data.py`:
  - `{{idXxx}}` expands to a structured prose item `{type: "ref", id: "riskPromptInjection", title: "Prompt Injection"}`, which the renderer turns into an in-page link.
  - `{{ref:identifier}}` expands to a structured prose item `{type: "link", title, url}`. The renderer emits an `<a>` with author-supplied `title` as text and the URL as `href`, with `rel="noopener noreferrer" target="_blank"` constructed by the renderer per [ADR-015](015-site-content-sanitization-invariants.md). The `externalReferences` array is also passed through unchanged so a future "References" panel can render the full list.

This is the only path by which an `<a>` element is emitted to the rendered DOM: the URL flows from the schema-validated `externalReferences[].url`, never from raw author markdown. [ADR-015](015-site-content-sanitization-invariants.md)'s bounded-emission property gains a stronger upstream guarantee — the renderer's `href` attribute is sourced from a field that has already passed schema URL-shape validation, not from an inline `[text](url)` an author wrote in prose.

**Machine-enforced:** yes — both generators fail on unresolved sentinels. The schema for `persona-site-data.schema.json` ([ADR-011](011-persona-site-data-schema-contract.md)) is extended to cover both `{type: "ref", ...}` and `{type: "link", ...}` shapes in the prose stream, plus the `externalReferences` array.

### D6. Linter — new pre-commit hook `validate_prose_references.py`

A new pre-commit hook slots alongside `validate_control_risk_references.py` in `.pre-commit-config.yaml` per [ADR-013](013-site-precommit-hooks.md)'s pattern. The hook **blocks** every rule below; there is no warn-only path.

1. Walk every prose field in `risks.yaml`, `controls.yaml`, `components.yaml`, `personas.yaml`.
2. For each `{{idXxx}}` sentinel, assert the ID resolves against the identifier enums in the corresponding schema (risk IDs for `{{risk...}}`, control IDs for `{{control...}}`, and so on). Unresolved → block.
3. For each `{{ref:identifier}}` sentinel, assert the identifier resolves against the entry's own `externalReferences[].id` list. Unresolved → block. The resolution scope is per-entry; cross-entry collisions are not checked here.
4. For any inline URL in prose — raw `http://` or `https://` strings, `[text](url)` markdown links, `<a href>` tags — block. There is no editorial-judgment boundary to adjudicate; every URL belongs in `externalReferences`.
5. For any raw HTML tag in prose (`<a>`, `<strong>`, `<em>`, `<br>`, etc.) — block. Coordinated with [ADR-017](017-yaml-prose-authoring-subset.md)'s `validate-yaml-prose-subset`; the two hooks share a tokenizer per ADR-017 D5.
6. For any bare camelCase identifier matching the known ID patterns (`risk[A-Z]`, `control[A-Z]`, `component[A-Z]`, `persona[A-Z]`) in prose that is *not* inside a sentinel — block.

The previous draft of this ADR distinguished a warn-only path for "inline outbound link that is not a citation." That distinction is removed: the editorial boundary (citation vs. color link) is captured in the structured `externalReferences[].type` field (D3, with `editorial` covering the non-citation case), not in prose-vs-structured placement. There is no remaining fuzzy boundary for the linter to adjudicate.

**Staged rollout.** Because the existing 55 outbound `<a>` tags and 14 intra-document anchors must be migrated before block-mode lands cleanly, the hook ships in **warn-only** mode for the duration of the conformance sweep, and flips to **block** in the same commit that completes the sweep. Same staging pattern as [ADR-017](017-yaml-prose-authoring-subset.md) D4, with the same gate (sweep-closing PR). Crucially, the *eventual* state is unambiguously block-everything; the warn-mode is operational, not a permanent posture.

**Machine-enforced:** yes — this hook is the enforcement mechanism for D2, D4, and the retirement of anchored HTML.

### D7. Schema enum coverage — reaffirmed, deferred for specifics

The existing identifier enums in `risks.schema.json`, `controls.schema.json`, `components.schema.json`, `personas.schema.json` are the source of truth for the sentinel linter's ID allowlist. The linter reads these enums at hook load, not a separate list, to prevent drift.

For `externalReferences.type`, the enum is declared in this ADR (D3). For per-type `id` patterns (e.g., `CWE-\d+`), [ADR-022](022-supporting-schemas.md) D5b picks the exact regex per type. This ADR commits to "there is a pattern per type that has a canonical form" without picking each pattern.

**Machine-enforced:** yes — enums are schema-enforced; patterns are schema-enforced once the conformance sweep authors them in `frameworks.schema.json` per [ADR-022](022-supporting-schemas.md) D5b.

### D8. Per-rule machine-enforcement summary

| Rule | Mechanism | Status |
|---|---|---|
| D1 structured edges authoritative | schema enums + `validate_control_risk_references.py` + `ComponentEdgeValidator` | Machine-enforced (existing) |
| D2 `{{idXxx}}` sentinel grammar | `validate_prose_references.py` (block) | Machine-enforced (new) |
| D2 `{{ref:identifier}}` sentinel grammar | `validate_prose_references.py` (block) | Machine-enforced (new) |
| D3 `externalReferences` field shape | shared schema `external-references.schema.json`, `$ref`'d from risks/controls/components/personas | Machine-enforced (new) |
| D3 `type` enum (incl. `editorial`) | schema enum (single source in `external-references.schema.json`) | Machine-enforced (new) |
| D3 per-entry `id` uniqueness | `validate_prose_references.py` (block) or schema | Machine-enforced (new) |
| D3 per-type `id` regex pattern | schema regex (single source in `external-references.schema.json`) | Machine-enforced once conformance sweep authors patterns ([ADR-022](022-supporting-schemas.md) D5b) |
| D3 `url` is `https://` | schema regex (single source in `external-references.schema.json`) | Machine-enforced (new) |
| D4 no inline URL syntaxes of any scheme in prose (categorical rule in [ADR-017](017-yaml-prose-authoring-subset.md) D4 rule 2) | `validate_prose_references.py` (block) + `validate-yaml-prose-subset` (block) | Machine-enforced (new) |
| D5 sentinel expansion in generators | generator build failure on unresolved sentinel | Machine-enforced (new) |
| D6 no raw HTML tags in prose | `validate_prose_references.py` (block) + ADR-017 | Machine-enforced (new) |
| D6 no bare camelCase IDs in prose | `validate_prose_references.py` (block) | Machine-enforced (new) |
| D6 sentinel ID resolves (intra-doc and external) | `validate_prose_references.py` (block) | Machine-enforced (new) |

Every rule in this ADR is machine-enforced. The previous draft's partial-warn entry on "URL-in-prose vs structured-citation" is gone: the editorial boundary moved into the structured field's `type` enum (`editorial` vs. citation types), and prose carries no URLs at all.

Any rule introduced by a future ADR in this space that does not appear in a row above is a prose-only rule unless the ADR explicitly claims a mechanism.

## Alternatives Considered

- **Keep bare camelCase IDs in prose, add a regex linter.** Rejected because bare identifiers are ambiguous to both reader and linter: the regex has to know every ID prefix (`risk`, `control`, `component`, `persona`) and false-positive on any word that happens to match the pattern. Sentinels are explicit; the author declares "this is a link" rather than the linter guessing.
- **Keep anchored HTML (`<a href="#riskXxx">Title</a>`).** Rejected because the `<a>` path is the same un-escaped `innerHTML` surface [ADR-014](014-yaml-content-security-posture.md) is closing and [ADR-015](015-site-content-sanitization-invariants.md) retires. The tables already render these as dead links; fixing the table generator to emit anchor targets would mean diverging table and site conventions for no benefit once the sentinel expands differently per pipeline.
- **Bracketed bare IDs `[riskXxx]` (ATT&CK-style).** Rejected because single-bracket collides with markdown reference-link syntax under [ADR-015](015-site-content-sanitization-invariants.md)'s allowed subset. An author writing `[riskPromptInjection]` would trigger the markdown parser's reference-link lookup and get undefined behavior depending on renderer.
- **Wiki-style `[[idXxx]]` sentinels.** Rejected because double-square-bracket is visually close to single-bracket markdown links that surround it; the sentinel disappears in dense prose. `{{idXxx}}` has no markdown neighbor and is scan-able.
- **Add a structured "relatedRisks" / "seeAlso" field for narrative cross-references.** Rejected because it duplicates `risks[].controls` / `controls[].risks` for the subset of cases where a cross-reference is not a direct mitigation. Downstream consumers would have two overlapping edge sets with unclear semantics. Narrative cross-references stay prose; if a relationship matters structurally, it belongs in the existing authoritative field.
- **Prose carries the URL, structured field is secondary.** Rejected because it exports two sources of truth: a consumer that parses the YAML gets the structured list, a reader of the prose sees a URL that may or may not match. `externalReferences` authoritative, prose carries the name, keeps the authoritative list single-sourced.
- **No structured external-reference field — rely on inline markdown `[text](url)` only.** Rejected because it leaves the machine-enforcement gap this ADR is addressing. A CWE number typo in prose is invisible to every validator; the same typo in a structured `externalReferences` entry with a `CWE-\d+` pattern fails at commit.
- **Allow inline `[text](url)` for "editorial color" links, structured entries for citations only.** Rejected; this was the previous draft of D4. The boundary between "editorial color" and "citation" is an author judgment that the linter cannot adjudicate, which forces a warn-only rule and an editorial-judgment carve-out in the linter. Both are exactly the smell [ADR-014](014-yaml-content-security-posture.md) P3 was supposed to eliminate. Capturing the editorial-vs-citation distinction as a `type` value on the structured entry (D3, `type: editorial`) preserves the author judgment while keeping prose URL-free and the linter unambiguous.
- **Bare external IDs in prose without a namespace prefix (e.g., `{{cwe-89}}` resolving against external IDs by global uniqueness).** Rejected because external `id` values are author-chosen at per-entry scope; two entries can each define `cwe-89`, and a global-uniqueness rule would force authors to coordinate identifier picks across the whole framework. The `{{ref:identifier}}` namespace prefix keeps resolution local to the entry and keeps the linter's job a local lookup.
- **Allow `id` to be optional on `externalReferences` entries (the previous draft's shape).** Rejected; the sentinel form needs a stable target on every entry. An entry without an `id` would be referenceable only by ordinal position, which is a rename-drift class.
- **Duplicate the `externalReferences` definition into each consumer schema (`risks.schema.json`, `controls.schema.json`, `components.schema.json`, `personas.schema.json`) rather than `$ref`'ing a shared file.** Rejected. Duplicate definitions silently diverge over time: a per-type regex tightening or a new `type` value lands in three of four files, the fourth lags, and the inconsistency surfaces as a confusing validation difference between risks and components. The repo already establishes the opposite pattern — `riskmap.schema.json#/definitions/utils/text`, `frameworks.schema.json`, `lifecycle-stage.schema.json`, `impact-type.schema.json`, and `actor-access.schema.json` are all single-source-`$ref`'d — and adopting per-file duplication just for `externalReferences` would be the unusual choice. Single source via `$ref` enforces alignment by construction and shrinks every conformance-sweep schema-uplift edit by a factor of N.

## Consequences

**Positive**

- **One authoring syntax for every prose mention.** `{{idXxx}}` covers intra-document mentions; `{{ref:identifier}}` covers external references. Bare IDs, anchored HTML, raw URLs, and inline `[text](url)` markdown all retire. Authors learn one shape with two namespaces; reviewers check one shape; the linter enforces one shape.
- **No editorial-judgment carve-out in the linter.** D6 blocks every inline URL form unconditionally. The previous draft's partial-warn boundary (citation vs. inline color link) collapses because the editorial distinction now lives in the structured `type` enum (`editorial` vs. citation types), not in prose-vs-structured placement. The linter's job is unambiguous from day one.
- **Rename-drift class eliminated for both axes.** Renaming `riskFoo` to `riskBar` updates the enum, which the schema re-validates everywhere, which the sentinel linter re-validates in prose. Renaming an `externalReferences[].id` from `cwe-89` to `cwe-89-sql-injection` updates the structured entry, and every prose `{{ref:cwe-89}}` sentinel that does not get updated fails the linter. A hand-written `<a href>` or inline URL survives a rename silently; a sentinel does not.
- **Dead links go away.** The current 14 anchored references that render as dead links in `risk-map/tables/risks-full.md` become plain-text titles in tables and in-page links on the site. Both outputs are honest to their medium.
- **All citations and editorial pointers become structured.** Downstream consumers that want to extract "which CWEs does this risk cite" get a structured answer; consumers that want to filter out editorial pointers and keep only citations can branch on `type`. Per-type regex patterns catch the "CWE-89" vs "CWE 89" vs "CWE89" drift that prose currently tolerates.
- **[ADR-015](015-site-content-sanitization-invariants.md)'s bounded-emission property strengthens.** The renderer's `<a>` element is now emitted only from generator-expanded `{{ref:identifier}}` sentinels, never from raw author markdown. The `href` attribute flows from the schema-validated `externalReferences[].url` field; ADR-015's defense-in-depth XSS surface narrows to the structured field's URL validation alone. Prose strings reaching the renderer carry no URLs at all.
- **Machine-enforcement declarations eliminate rot by omission.** Every rule in this ADR blocks at commit or fails a build. There is no "prose-only guidance" row left in the per-rule table; the ambiguous warn-mode entry is gone.
- **Single-source schema definition for `externalReferences`.** The shape, the `type` enum, the per-type id regex patterns, and the URL constraint live once in `external-references.schema.json`. Adding a new reference type or refining an id pattern touches one file rather than four; the four consumer schemas stay aligned by construction. The conformance-sweep edit shrinks accordingly — write the field once, `$ref` from each consumer.

**Negative**

- **Bulk normalization is now larger.** Approximately 14 anchored references, 41 bare-ID mentions, and ~55 outbound `<a>` tags across `risks.yaml` (and the small number in `controls.yaml`/`components.yaml`) must be rewritten to sentinels and structured entries before the linter lands block-mode. The scope expanded from the previous draft because the migration of inline `<a>` to `externalReferences` is now mandatory rather than an editorial-judgment subset. That is a content-sweep PR, not a code change; it is scoped in the follow-up.
- **Author friction increased — intentionally.** Adding a link is now a two-step move: add the structured entry first (with `type`, `id`, `title`, `url`), then reference it by sentinel in prose. The previous "just paste a URL inline for color" path is gone. The friction is the point: every URL gets type-tagged, machine-validated, and machine-referenceable. Contributing docs must make the two-step flow visible so the first PR is not a surprise rejection.
- **The sentinel is a repo-specific convention.** Contributors who copy prose from upstream sources (vendor blog posts, framework drafts) will paste `<a>` tags and `[text](url)` markdown that the linter will reject. Same risk as before; the failure message and the contributing-docs example carry the load.
- **Per-type regex patterns commit the repo to canonical-form pedantry.** `cve-2024-0001` is valid; `cve 2024-0001` is not. The pattern rejects the sloppy form at commit. This is correct but unforgiving; the linter error message needs to show the canonical form.
- **Two enforcement points per pipeline.** The sentinel linter runs at commit; the generator also refuses unresolved sentinels at build. If the two ever disagree (linter accepts, generator rejects), authors see confusing failures. Both read the same source data; drift is unlikely but not structurally impossible.
- **`externalReferences.type` enum is a commitment.** Adding a new reference type (e.g., `regulation`, `standard`) is a schema edit and a coordinated update to any consumer that branches on type. This is deliberate; it prevents the type vocabulary from fragmenting into author synonyms. The `editorial` value is the relief valve for non-citation links so the citation types stay clean.
- **Shared schema is a single point of failure.** A breaking change to `external-references.schema.json` invalidates every consumer simultaneously, where per-file duplication would have failed one entry at a time. This is the price of single-source-of-truth and is on the same footing as the existing shared schemas (`riskmap.schema.json`, `frameworks.schema.json`, etc.); the mitigation is the co-evolution rule (D3) that ties enum and shape changes to ADR revision rather than silent edits.

**Follow-up**

- **Conformance sweep — bulk normalization.** A content PR (or a coordinated sequence) that:
  - Converts the ~14 anchored intra-document references and ~41 bare-ID mentions to `{{idXxx}}` sentinels.
  - Extracts the ~55 outbound `<a href="https://...">` tags in `risks.yaml` (plus any in `controls.yaml`/`components.yaml`) to `externalReferences` entries with appropriate `type` tags (`cwe`, `cve`, `paper`, `news`, `advisory`, `editorial`, etc.) and unique per-entry `id` values, then replaces the prose with `{{ref:identifier}}` sentinels.
  - There are zero `[text](url)` markdown references in the YAML today, so no markdown-link migration is required; the rule blocking that form is preventive rather than retrospective.
  - Coordinates with [ADR-017](017-yaml-prose-authoring-subset.md)'s subset sweep (`<strong>` → `**bold**`, `<em>` → `*italic*`, `<br>` → array splits) — same PR or sequential PRs per maintainer's call.
  - Must land before the linter flips to block-mode. Scope includes per-link decisions on citation-vs-`editorial` typing, since that is now a `type` value rather than a placement decision.
- **Schema uplift in sibling ADRs (ADRs 018-022).** Authors `risk-map/schemas/external-references.schema.json` once — defining the array shape, the per-item object (`type`, `id`, `title`, `url`), the `type` enum (including `editorial`), the per-type `id` regex patterns, and the `https://`-only URL constraint. Adds a single `$ref` line to each of `risks.schema.json`, `controls.schema.json`, `components.schema.json`, and `personas.schema.json` for the `externalReferences` property. Decides whether per-entry `id` uniqueness is enforced in the shared schema (via array-item constraints) or in `validate_prose_references.py`. Co-evolved with this ADR per D3.
- **New pre-commit hook `validate_prose_references.py`.** Python, TDD via the testing agent per ADR-005 / ADR-013 patterns. Reads identifier enums from the live schemas rather than a separate constant; reads `externalReferences[].id` from the YAML entries themselves. Ships warn-only during the sweep, flips to block in the sweep-closing commit. Shares the prose tokenizer with [ADR-017](017-yaml-prose-authoring-subset.md)'s `validate-yaml-prose-subset` per ADR-017 D5.
- **Generator updates.** `yaml_to_markdown.py` sentinel expansion: `{{idXxx}}` → plain-text title; `{{ref:identifier}}` → title plus URL in the table convention; "References" sub-section under each entry listing `externalReferences`. `build_persona_site_data.py` sentinel expansion: `{{idXxx}}` → `{type: "ref", id, title}`; `{{ref:identifier}}` → `{type: "link", title, url}`; pass `externalReferences` array through. Update `persona-site-data.schema.json` (per [ADR-011](011-persona-site-data-schema-contract.md)) to cover both prose-item shapes and the `externalReferences` array. Both pipelines fail on unresolved sentinels.
- **Contributor documentation.** A section under `risk-map/docs/` (not `docs/adr/`) that states the authoring rules in plain terms: how to write each sentinel form, the two-step flow for adding a link (structured entry first, sentinel second), the `editorial` vs. citation distinction, examples for each `type` value. Coordinated with [ADR-017](017-yaml-prose-authoring-subset.md)'s consumer-facing doc at `risk-map/docs/yaml-authoring-subset.md`; either the same file or a sibling per maintainer's call.
- **Contributor helper at `scripts/tools/add-external-reference.py`.** Takes a URL, emits a paste-ready `externalReferences` YAML block plus the matching `{{ref:identifier}}` sentinel. Domain-based `type` heuristics (`cwe.mitre.org` → `cwe`; `arxiv.org` → `paper`; `nvd.nist.gov` / `cve.mitre.org` → `cve`; `atlas.mitre.org` → `atlas`; `attack.mitre.org` → `attack`; otherwise prompt or default to `editorial`). Canonical-form `id` extraction where the URL path encodes one (`CWE-89` from `/data/definitions/89.html`; `CVE-YYYY-NNNN` from CVE pages); page-title fetch with stub fallback. Output is text for the author to review and paste, not a commit or an in-place YAML edit — keeps the author in the loop on `type` and `id` choices, especially the citation-vs-`editorial` call. Same shape as existing tools under `scripts/tools/`. Reduces the manual two-step friction noted under Consequences (Negative) without weakening the discipline; the schema and linter still own correctness. Tracked as a separate issue once the shared schema and linter land.
- **Consider extending sentinels to cross-file references from `personas.yaml`.** `personas.yaml` prose is quieter today than risks/controls; the linter walks it anyway so the option is open but not a blocker.

---

### Coordination with ADR-015 and ADR-017

This ADR composes with [ADR-015](015-site-content-sanitization-invariants.md) and [ADR-017](017-yaml-prose-authoring-subset.md):

- **[ADR-017](017-yaml-prose-authoring-subset.md)** removes `[text](url)` from the canonical authoring subset. After this ADR lands, prose carries no inline URLs in any form; the only outbound-link path is `{{ref:identifier}}` resolving to a structured `externalReferences` entry. ADR-017's grammar therefore drops one production; the shared tokenizer at `scripts/hooks/precommit/_prose_tokens.py` reflects the simpler grammar.
- **[ADR-015](015-site-content-sanitization-invariants.md)**'s allowlist still includes `<a>`, but the renderer now emits `<a>` only from generator-expanded `{{ref:identifier}}` sentinels, never from raw author markdown. ADR-015's bounded-emission property strengthens: the `href` attribute flows from a schema-validated `externalReferences[].url` field, not from inline markdown. The defense-in-depth XSS check at the renderer remains in place because the stacked-posture commitment from [ADR-014](014-yaml-content-security-posture.md) P4 does not weaken.

The three ADRs together: ADR-014 sets the posture, ADR-017 defines what authors may write in prose strings (now URL-free), ADR-016 (this ADR) defines how references are structured and referenced, and ADR-015 defines what the site renderer emits to the DOM. The grammars compose: a single tokenizer recognizes ADR-017's tokens plus this ADR's two sentinel forms; the linter blocks every URL form that is not inside an `externalReferences` entry; the renderer's `<a>` emission is sourced from a structured field that has already passed schema validation.
