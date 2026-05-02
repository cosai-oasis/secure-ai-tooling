# ADR-017: Canonical YAML prose authoring subset

**Status:** Accepted
**Date:** 2026-04-25
**Authors:** Architect agent, with maintainer review

---

## Context

[ADR-014](014-yaml-content-security-posture.md) established the trust model for `risk-map/yaml/**` content but deliberately deferred the *content* of the prose-authoring rule to siblings. P2 names prose as one of five content classes; P4 commits sanitization to the generation and render boundaries and stacks three enforcement points (authoring, generation, render) without picking the subset; P5 commits the framework to "shape guarantees via the schemas" as the redistribution contract.

[ADR-015](015-site-content-sanitization-invariants.md) was originally drafted to codify the markdown subset alongside the site renderer's allowlist. The maintainer flagged a layering bug: the markdown subset is a **YAML-source** concern read by every consumer (site renderer, table generator, persona-site builder, any third-party redistributor), while the DOM allowlist is a **render-time** concern specific to `site/`. Conflating them in one ADR forced the site to own a contract that belongs to the framework.

[ADR-016](016-reference-strategy.md) introduces the `{{idXxx}}` sentinel for intra-document mentions, the `{{ref:identifier}}` sentinel for external references, and the structured `externalReferences` field that the latter resolves against. The sentinels are part of what authors write; they are therefore part of the canonical authoring subset that this ADR codifies.

The concrete state at commit `6945285`:

- `risks.yaml` carries 55 outbound `<a href="https://...">` anchors, 14 intra-document `<a href="#riskXxx">` anchors, and free use of `<strong>`, `<em>`, and `<br>` in prose strings. `controls.yaml`, `components.yaml`, and `personas.yaml` carry equivalents in smaller volume.
- [ADR-011](011-persona-site-data-schema-contract.md)'s `definitions/prose` constrains prose *shape* (`array` of `string | array<string>`, one level of nesting) but does not constrain *string contents*. Arbitrary markup passes schema validation today.
- `scripts/hooks/yaml_to_markdown.py:123` (`collapse_column`) and `scripts/build_persona_site_data.py` both pass prose strings through verbatim. Neither is the right place to re-decide the subset.

A separate question — whether prose may carry inline URLs at all, alongside structured citations — was open in earlier drafts. The maintainer concluded that the editorial boundary between "citation" and "color" is not machine-testable: a linter cannot decide whether a vendor blog link supports a claim or merely illustrates it. ADR-016 moves *all* outbound URLs into the `externalReferences` structured field and uses the `{{ref:identifier}}` sentinel for them. ADR-017 follows that decision: the authoring subset carries no inline-URL form at all. Every URL lives in `externalReferences`; prose mentions them by sentinel only.

Without ADR-017, the canonical authoring rule lives nowhere — it is implicit in ADR-015's render-time decision, and a third party reading `risks.yaml` directly has no documented contract for what tokens they may encounter. ADR-017 is the YAML *source* contract every consumer reads.

## Decision

The CoSAI Risk Map adopts a single canonical authoring subset for prose fields in `risk-map/yaml/{components,controls,risks,personas}.yaml`. The subset is defined here, enforced at authoring time by a new pre-commit lint, and consumed verbatim by every downstream surface.

### D1. Allowed authoring tokens

Authors may use exactly these forms in any prose field. Everything else is rejected at commit time.

- **Bold:** `**bold**`. Asterisk delimiter only; `__bold__` is **not** recognized. The token may contain plain text and italic; nesting another `**bold**` inside is rejected.
- **Italic:** `*italic*` or `_italic_`. Both delimiters are recognized so authors can italicize text that itself contains the other delimiter. Nesting another italic inside is rejected.
- **Sentinels:** `{{idXxx}}` for intra-document references and the external-reference sentinel form decided in [ADR-016](016-reference-strategy.md). The braces carry an identifier; the linter validates the ID against the schema enum (intra-document) or the entry's `externalReferences` array (external) at commit time. Sentinels appear in prose verbatim; generators expand them.

Bold and italic may compose (`**emphatically *not* this**` is valid). Sentinels are atomic identifier tokens; they do not nest into bold or italic. An author who wants the rendered title to appear bold relies on the renderer's stylesheet, not on wrapping `**` around `{{idXxx}}`.

The subset operates on the string contents of each prose paragraph. Paragraph and hard-break shape is carried by the YAML *array* structure ([ADR-011](011-persona-site-data-schema-contract.md) `definitions/prose`); prose strings are not list-bearing.

### D2. Disallowed by construction

The lint blocks the following at commit time. **Inline URLs in any form are disallowed.** All outbound URLs live in the entry's `externalReferences` array per [ADR-016](016-reference-strategy.md) and are referenced from prose only via the sentinel form decided there. The editorial boundary between "citation" and "color" is not machine-testable; structuring every URL collapses that boundary into a single, machine-enforceable rule.

| Disallowed | Rationale |
|---|---|
| **Inline URLs in any form** — raw `http://` / `https://` strings, `[text](url)` markdown links, autolink syntax, any author-written hyperlink | Editorial judgment about citation-vs-color is not machine-testable. URLs belong in structured `externalReferences` per [ADR-016](016-reference-strategy.md); prose references them by sentinel. |
| Raw HTML tags of any kind (`<a>`, `<strong>`, `<em>`, `<br>`, `<p>`, `<div>`, `<span>`, `<img>`, `<script>`, `<iframe>`, `on*=`, etc.) | Closes the `innerHTML` exposure flagged in [ADR-012](012-static-spa-architecture.md) and [ADR-014](014-yaml-content-security-posture.md). HTML in YAML is the exact pattern the security posture retires. |
| Markdown headings (`#`, `##`, etc. at line start) | YAML structure expresses hierarchy; prose strings are paragraph content, not document outline. |
| Markdown list markers (`- `, `* `, `1. ` at line start) | The prose-array shape ([ADR-011](011-persona-site-data-schema-contract.md) `definitions/prose`) is the list primitive. List markers in prose strings duplicate semantics and the renderer does not parse them. |
| Code blocks (fenced ``` ``` ``` or indented) and inline code (`` `code` ``) | Out of scope for the subset. If a future content class needs code, it is a schema and ADR change, not a prose-string concession. |
| Images (`![alt](url)`) | The framework does not embed images in prose. Out of scope (and subsumed by the inline-URL block above). |
| Blockquotes (`>` at line start) | YAML's folded scalars (`>` at field level) already use `>`; allowing it in prose creates parser ambiguity in the lint and editorial confusion for authors. |
| Tables (markdown pipe tables) | Out of scope; tables are generated artifacts under `risk-map/tables/`, not authored prose. |
| Bare camelCase identifiers matching `(risk\|control\|component\|persona)[A-Z]…` outside a sentinel | Per [ADR-016](016-reference-strategy.md). Sentinels are the only authoring syntax for intra-document mentions. |

ADR-011's `definitions/prose` already enforces the structure-vs-prose split (string vs. array of strings). ADR-017 enforces content-within-prose: what tokens the strings may contain.

### D3. Schema-level vs. lint-level split

Schemas are good at shape, weak at content (per [ADR-014](014-yaml-content-security-posture.md) P4). The split:

- **Schema-enforced (shape, types, enums).** ADR-011's `definitions/prose` continues to constrain prose *shape*. The schema does **not** gain a token-level pattern; a regex that matches "no markdown subset violations" is a parser, and parsers belong in the lint.
- **Schema-enforced (cheap rejection of obvious unsafe input).** `definitions/prose` may add a top-level `pattern` that rejects strings containing `<`, `>`, `(`, or `)` characters as a coarse first filter. The angle brackets catch raw HTML; the parentheses catch markdown link syntax (`](`) cheaply. This is opt-in to be decided in the schema-uplift sub-deliverable; ADR-017 does not require it. The lint covers the case authoritatively whether or not the schema rejects coarsely. The argument for adding parentheses to the optional pattern is now stronger than in the earlier draft, since markdown link syntax is no longer a permitted form anywhere in the subset; the argument against is that legitimate prose may use parenthetical asides, and a schema-level reject would force authors to rephrase. The lint is the definitive layer; the schema pattern, if adopted, is the cheap second filter.
- **Lint-enforced (full subset grammar).** A new pre-commit hook (D4) is the authoritative enforcement point. It tokenizes each prose string, accepts the three allowed forms, and blocks anything else with an actionable message naming the offending entry, field, paragraph index, and token.

Coordination with [ADR-011](011-persona-site-data-schema-contract.md): `definitions/prose` stays shape-only by default. If the schema-uplift sub-deliverable adopts the optional reject-on-`<>()` pattern, that is an additive constraint; the lint remains authoritative.

### D4. The lint — `validate-yaml-prose-subset`

A new local hook lands under `.pre-commit-config.yaml` per [ADR-013](013-site-precommit-hooks.md)'s pattern.

- **Hook id:** `validate-yaml-prose-subset`.
- **Wrapper:** `scripts/hooks/precommit/validate_yaml_prose_subset.py`.
- **Files:** `risk-map/yaml/(components|controls|risks|personas)\.yaml`.
- **Pass filenames:** true.
- **Walks every prose field** identified by the schemas as a string or `definitions/prose` reference (`description`, `shortDescription`, `longDescription`, `examples`, `responsibilities`, `tourContent.*`, and equivalents). The list of prose fields is read from the schemas, not hardcoded, to prevent drift when a sibling ADR adds a field.
- **Tokenizer:** hand-rolled, regex-driven, covering the three allowed forms. Vanilla Python, no markdown library — consistent with [ADR-015](015-site-content-sanitization-invariants.md)'s zero-dep posture for the matching site-side sanitizer.
- **Rejection format:** stderr line per offending paragraph: `validate-yaml-prose-subset: <file>:<entry-id>:<field>[<index>]: <reason> at <token-snippet>`. Exit non-zero on any rejection.
- **Rule list (block-mode end state):**
  1. Accept `**bold**` (one nesting level), `*italic*`, `_italic_`, and the sentinel forms decided in [ADR-016](016-reference-strategy.md).
  2. **Reject any prose carrying a URI scheme inline.** The rule is categorical, not an enumeration. The tokenizer applies two patterns:
     - **Primary — scheme-with-authority:** `\b[a-z][a-z0-9+.\-]*://\S+` (RFC-3986 form). Catches `http://`, `https://`, `ftp://`, `file://`, `gs://`, `s3://`, `ssh://`, and any future scheme that follows the authority-bearing shape. Plus the markdown-link suffix `]` followed by `(`, which catches `[text](url)` regardless of the URL's scheme.
     - **Secondary — opaque-data schemes:** a named list for colon-only schemes that lack `//` authority and would escape the primary regex. At minimum: `mailto:`, `javascript:`, `data:`, `tel:`. RFC-3986 permits the `scheme:opaque-data` form for any scheme; the named list captures the schemes browsers actively render as clickable actions or execute (contact-exposure for `mailto:`/`tel:`; XSS-class defense-in-depth for `javascript:`/`data:`). Adding to the named list is a tokenizer change with a one-line ADR amendment, not an architectural revisit.

     The categorical shape exists by design. A 3-form enumeration (`http://`, `https://`, `](`) relies on a detection step the codebase does not have: the wrapper linters add no URL handling beyond the tokenizer, schemas validate structured-field shape rather than free prose content, and generators read prose verbatim. A non-enumerated scheme (`mailto:`, `gs://`, `javascript:`, etc.) would pass both linters as plain TEXT and ship to published artifacts. The categorical regex closes that gap uniformly and removes the per-scheme adjudication the prior enumeration would force on contributors and reviewers.
  3. Reject raw HTML tags (any `<` followed by an alphabetic character or `/`).
  4. Reject markdown headings, list markers, code, images, blockquotes, and tables per the D2 table.
  5. Reject bare camelCase identifiers outside sentinels (delegated to [ADR-016](016-reference-strategy.md)'s reference linter, which shares the tokenizer per D5).
  6. Pair with `{{...}}` sentinel resolution per [ADR-016](016-reference-strategy.md) to verify references resolve to the right enum or `externalReferences` entry.
- **Block vs. warn — staged:** the hook ships in **warn-only** mode for the duration of the conformance sweep (the migration that converts the existing inline `<a>` tags and inline URLs into structured `externalReferences` entries). The hook flips to **block** in the same commit that completes the sweep. The eventual state is unambiguous: every rule above blocks. Block-from-day-one is rejected because it would force the sweep and the hook into a single PR; warn-only-permanent is rejected because P4 of [ADR-014](014-yaml-content-security-posture.md) commits to authoring-time blocking as the redistribution-contract layer.

Earlier drafts of this ADR had four rule families and a rule that adjudicated URL-in-prose vs. URL-in-`externalReferences`. With inline URLs disallowed unconditionally, that rule is gone; the rule list shrinks from four families plus an editorial adjudication to three families plus an unconditional URL block.

### D5. Reconciliation with ADR-016's prose-token linter

[ADR-016](016-reference-strategy.md) introduces `validate_prose_references.py`, which checks sentinel ID resolution (intra-document and external-reference forms), raw `<a>` rejection, and bare camelCase rejection. ADR-017's `validate-yaml-prose-subset` checks markdown-token grammar, HTML-tag rejection, the unconditional inline-URL block, and the disallowed-construction list above.

The two hooks have overlapping rejection sets (raw `<a>` blocked by both, bare camelCase blocked by both, inline URLs blocked by both). The reconciliation:

- **Both hooks run.** Either can produce the rejection; the contributor sees the more specific message (the reference linter's "ID does not resolve" vs. the prose-subset linter's "raw HTML tag forbidden"). Overlap is acceptable.
- **Single shared tokenizer module** at `scripts/hooks/precommit/_prose_tokens.py`. Both hooks import it. ADR-017 owns the grammar; ADR-016 owns the ID-resolution semantics on top of the grammar's sentinel-token output.
- **Test fixtures live with each hook,** but a shared corpus of prose-subset edge cases (nested bold, mixed delimiters, inline-URL attempts) is maintained at `scripts/hooks/tests/fixtures/prose_subset/` so the two hooks cannot disagree on what a token *is*, only on what it *means*.

If ADR-016 lands its hook before this one, the bare-camelCase and raw-`<a>` checks live in `validate_prose_references.py` until ADR-017's hook ships and the shared tokenizer is extracted. The end state is the two-hook-shared-tokenizer split above.

### D6. Redistribution contract surface

Per [ADR-014](014-yaml-content-security-posture.md) P5, the framework guarantees "shape via schemas" to downstream consumers. ADR-017 is the canonical statement of "content within prose strings." After the conformance sweep closes, the contract becomes strictly: **YAML prose contains no URLs at all.** Every URL lives in a structured `externalReferences` entry (ADR-016) and is referenced from prose by sentinel. This is a stronger guarantee than "YAML prose contains some URLs you must sanitize" — a third-party redistributor parsing the YAML knows that any URL it ingests came through a typed, schema-validated structured field.

The contract is documented in two places:

- **ADR-017 itself** — the durable decision, what every redistributor can cite.
- **A new section under `risk-map/docs/`** (path: `risk-map/docs/yaml-authoring-subset.md`) that summarizes D1 / D2 in author- and consumer-facing terms: the three allowed token forms, the disallowed constructions (with explicit emphasis on the inline-URL block), and the explicit statement that the YAML on disk is subset-compliant after the conformance sweep closes. The section references this ADR as source. The section lives under `risk-map/docs/`, not `risk-map/docs/design/`, because it is *consumer-facing reference documentation* (what the YAML carries) rather than *framework-content design* (what the risks mean).

Both surfaces are pointers to the same rules; the ADR is the decision, the doc is the consumer-facing summary. Drift between them is a documentation defect; the ADR is authoritative.

### D7. Per-rule machine-enforcement summary

| Rule | Mechanism | Status |
|---|---|---|
| D1 `**bold**` allowed | `validate-yaml-prose-subset` (accept) | Machine-enforced (new) |
| D1 `*italic*` and `_italic_` allowed | `validate-yaml-prose-subset` (accept) | Machine-enforced (new) |
| D1 sentinel forms allowed (grammar) | `validate-yaml-prose-subset` (accept token shape) | Machine-enforced (new) |
| D1 sentinel ID resolves to enum or `externalReferences` | `validate_prose_references.py` ([ADR-016](016-reference-strategy.md)) | Machine-enforced (new, ADR-016) |
| D2 inline URLs blocked unconditionally (categorical: any scheme-with-authority via `\b[a-z][a-z0-9+.\-]*://\S+`, opaque-data schemes via named list `mailto:`/`javascript:`/`data:`/`tel:`, plus `](` for markdown links) | `validate-yaml-prose-subset` (block) | Machine-enforced (new) |
| D2 raw HTML tags blocked | `validate-yaml-prose-subset` (block) | Machine-enforced (new) |
| D2 markdown headings / lists / code / images / blockquotes / tables blocked | `validate-yaml-prose-subset` (block) | Machine-enforced (new) |
| D2 bare camelCase identifiers blocked | `validate_prose_references.py` ([ADR-016](016-reference-strategy.md)) | Machine-enforced (new, ADR-016) |
| D3 schema `<>()` rejection (optional) | `definitions/prose` pattern | Deferred to schema-uplift |
| D4 hook lands warn-only, flips to block after sweep | Hook configuration | Machine-enforced (operational) |
| D5 shared tokenizer module | Code structure | Implementation guidance, not a content rule |
| D6 consumer-facing doc | `risk-map/docs/yaml-authoring-subset.md` | Prose-only documentation of the rules above |

Every content rule is machine-enforced. There are no warn-only rules in the end state on URL handling; the staged warn-only stage is operational, not editorial. D6 is documentation of the rules; the rules themselves live in the lint and the schemas.

## Alternatives Considered

- **Allow `[text](url)` in prose alongside structured `externalReferences`, with the linter warning on duplicates.** Rejected. The earlier draft of this ADR carried this option, and ADR-016's earlier draft warned (rather than blocked) on inline URLs that overlapped with `externalReferences` entries. The boundary between "this URL is a citation that belongs in the structured field" and "this URL is editorial color that belongs inline" is editorial: a linter cannot adjudicate it without a content classifier. The friction of structuring every URL — adding an `externalReferences` entry before a sentinel — is the point. It forces the same discipline whether the URL underpins a claim or merely illustrates it, and it gives downstream consumers a single, structured source of truth for every outbound link.
- **Codify the subset inside ADR-015 (the original draft).** Rejected. The subset is a YAML-source concern read by every consumer; binding it to the site's render-time ADR forced one downstream surface to own a contract that belongs to the framework.
- **Permissive prose, defend at every render boundary.** Rejected per [ADR-014](014-yaml-content-security-posture.md) P4 and P5. The framework cannot defend prose at boundaries it does not own (third-party redistributors). Authoring-time block is the only layer that raises the safety baseline of the published file.
- **Allow `<br>` for in-paragraph breaks.** Rejected for the same reason ADR-015 rejected it: the prose-array shape is the paragraph primitive. Authors split paragraphs by adding array items, not by inlining HTML.
- **Allow inline code (`` `code` ``).** Rejected for the present subset. No prose field today carries code samples; adding code expands the renderer's allowlist (ADR-015) and the table generator's pass-through behavior. If a future field needs code, an ADR revisit is the right path.
- **Use a markdown library (`markdown-it`, `commonmark`) inside the lint.** Rejected. The three-token grammar is small enough to hand-roll; a library brings a configuration surface larger than the replacement code, and matches ADR-015's zero-dep posture on the site side.
- **Schema-only enforcement via a regex pattern on every prose string.** Rejected. A regex that asserts "this string contains only the allowed tokens" is a parser; JSON Schema's `pattern` is not the right tool. The optional coarse `<>()` rejection (D3) is the schema's natural contribution; the full grammar lives in the lint.
- **Block from day one, no warn-only stage.** Rejected. The existing 55 outbound anchors, 14 intra-document anchors, and any inline URLs surfaced by the sweep must be migrated before a block-mode hook can be enabled. A warn-only stage with an explicit flip-to-block in the sweep-closing commit gives the migration a place to land without forcing it into the same PR as the lint.

## Consequences

**Positive**

- **One canonical subset, one source of truth.** Every consumer (site renderer, table generator, persona-site builder, third-party redistributor) reads the same rule. Drift between `site/`'s allowlist and the table generator's pass-through behavior is no longer possible by accident; both are downstream of D1.
- **The redistribution contract is concrete and stronger.** [ADR-014](014-yaml-content-security-posture.md) P5's "shape guarantees via the schemas" gains a content-class clause: the YAML on disk carries prose tokens from a three-form vocabulary with **no URLs at all**. A third party reading the YAML knows every URL came through a typed, schema-validated structured field — a stronger guarantee than "some URLs, sanitize on your side."
- **The pre-commit lint is simpler.** With inline URLs disallowed unconditionally, the lint loses the editorial-judgment rule that adjudicated citation-vs-color. One fewer judgment call in the linter; one fewer warn-only path; one fewer way for the rule to drift.
- **ADR-015's bounded-emission property strengthens.** With no inline URLs in YAML, the site renderer's `<a>` element is emitted only from generator-expanded sentinels backed by validated `externalReferences` entries. The renderer never sees an author-written URL; it constructs anchors from typed structured input. The `https:`-only constraint, the `rel="noopener noreferrer"` discipline, and the bounded-emission property all apply to a smaller, fully-typed input surface.
- **Sentinel and subset land coherently.** ADR-016's sentinel forms are first-class tokens in the grammar, not an exception layered on top. A single tokenizer covers both decisions.
- **Rule rot eliminated.** Every D1/D2 rule is machine-enforced. The consumer-facing doc at `risk-map/docs/` is a summary of the lint's behavior, not an independent source of truth that could drift.

**Negative**

- **The conformance sweep is real work.** The 55 outbound `<a>` tags in `risks.yaml` (plus equivalents in `controls.yaml`, `components.yaml`, `personas.yaml`) all migrate to `externalReferences` entries with sentinel mentions. The 14 intra-document anchors and the `<strong>` / `<em>` / `<br>` instances are also in scope. This is the scoped conformance-sweep work; it is not free, and it coordinates with ADR-016.
- **Higher friction for one-off illustrative links.** An author who wants to add a single illustrative link must add a structured `externalReferences` entry first (with `type`, `title`, `url`) and reference it from prose by sentinel. There is no quick `[text](url)` escape hatch. This friction is intentional discipline: it keeps the redistribution contract clean and removes the citation-vs-color judgment call. The workflow is documented in `risk-map/docs/yaml-authoring-subset.md`.
- **Two hooks share a tokenizer.** `validate-yaml-prose-subset` and `validate_prose_references.py` ([ADR-016](016-reference-strategy.md)) overlap on grammar. The shared module at `_prose_tokens.py` is the mitigation; without discipline, two hooks could drift into two grammars. Tests covering the shared corpus are the contract.
- **The subset is a commitment.** Adding a fourth token form (e.g., inline code, or restoring inline URLs) is an ADR revisit, a lint update, a renderer update, a schema-uplift coordination, and a content sweep. Deliberately sharp; this is what keeps the three-form vocabulary stable for redistributors.
- **Warn-then-block staging is operational complexity.** The flip-to-block must happen in the same commit that closes the sweep; if the sweep closes piecemeal across multiple PRs, the operational state is "warn-only with debt" until the final flip. The follow-up names the explicit gate.
- **Authors who copy prose from upstream sources will trip the lint.** Vendor blog HTML, framework drafts with `<strong>`, ADR text with inline URLs, and copy-paste from issues with bare links will fail. Contributing docs must make the subset visible early in the authoring path.
- **Schema-only consumers still see arbitrary strings until D3's optional pattern lands.** A consumer that runs `check-jsonschema` against the YAML without running the lint will see strings that pass shape validation but might still contain raw HTML or URLs if a contributor bypasses pre-commit. The honest contract is "subset-compliant after the lint runs"; the schema's optional `<>()` pattern is a partial backstop, not a full one.

**Follow-up**

- **Conformance sweep — YAML migration (this ADR + ADR-016).** Migrate all 55 outbound `<a href="https://…">…</a>` tags to `externalReferences` entries with sentinel mentions in prose, coordinated with [ADR-016](016-reference-strategy.md) (which owns the structured-field schema and the sentinel form). Convert `<strong>` / `<em>` to `**` / `*`; remove `<br>` by splitting paragraphs into array items. Migrate the 14 intra-document anchors and ~41 bare-camelCase mentions to `{{idXxx}}` sentinels per ADR-016. The two ADRs' sweeps coordinate in the same PR or land in sequence with explicit cross-references.
- **Conformance sweep — lint hook.** Implement `scripts/hooks/precommit/validate_yaml_prose_subset.py` and the shared `_prose_tokens.py`. TDD via the testing agent per [ADR-005](005-pre-commit-framework.md) / [ADR-013](013-site-precommit-hooks.md). Land warn-only; flip to block in the sweep-closing commit. Rule set per D4: three allowed token families, unconditional inline-URL block, plus the disallowed-construction table.
- **Per-file schema ADRs (sibling work).** [ADR-018](018-components-schema.md), [ADR-019](019-risks-schema.md), [ADR-020](020-controls-schema.md), [ADR-021](021-personas-and-self-assessment-schema.md), [ADR-022](022-supporting-schemas.md) document the per-file schemas. Each may opt into the optional `<>()` pattern on prose fields per D3; each tightens its content-class taxonomy under [ADR-014](014-yaml-content-security-posture.md) P2. Each also adds the `externalReferences` field shape per ADR-016. ADR-017 does not pre-empt those decisions; it constrains them by naming the prose-content rule the schemas may but need not encode. (Outcome at time of writing: all four main-content schema ADRs deferred the D3 opt-in; ADR-022 D7 lifted the deferral to a sweep-wide indefinite decision with revisit conditions.)
- **Conformance sweep — consumer-facing doc.** Author `risk-map/docs/yaml-authoring-subset.md` summarizing D1 / D2 for authors and redistributors, with explicit emphasis on the no-inline-URL rule and the `externalReferences` workflow. References this ADR as source. Lands in the sweep PR.
- **Coordinate with ADR-015's sanitizer.** `site/assets/sanitizer.mjs` (ADR-015 follow-up) and `validate-yaml-prose-subset` must accept the same token grammar. With inline URLs removed from D1, the sanitizer's `<a>` allowlist applies only to anchors emitted by generator sentinel-expansion; the input-grammar surface narrows correspondingly. The shared-corpus fixture under `scripts/hooks/tests/fixtures/prose_subset/` is the cross-check; the site's `node --test` suite reads the same fixtures.
- **Coordinate with ADR-016's reference linter.** `validate_prose_references.py` and `validate-yaml-prose-subset` share the tokenizer module. The hook landing later extracts `_prose_tokens.py`; the hook landing earlier carries the grammar inline until extraction.
- **Generator parity.** Both `scripts/hooks/yaml_to_markdown.py` and `scripts/build_persona_site_data.py` apply sentinel expansion per ADR-016 D5 (intra-document and external-reference forms) and otherwise pass prose strings through without additional subset transforms — per [ADR-014](014-yaml-content-security-posture.md) P4 the prose-content rule is enforced at authoring time, not at generation time. The table generator emits a "References" section per entry from `externalReferences`; the persona-site builder emits structured `{type: "ref", ...}` and `{type: "link", ...}` items for the renderer to format. Whether either pipeline applies any further per-format transform (e.g., the table generator converting `**bold**` to GitHub-rendered bold) is a generator-ADR question, not this one.
- **If a future content class needs code samples, images, inline URLs, or other tokens** outside D1, this ADR is the revisit point. Adding to D1 cascades to the lint, the sanitizer, the schema-uplift, and the conformance state of the YAML; the ADR is the right place to surface that cost.
