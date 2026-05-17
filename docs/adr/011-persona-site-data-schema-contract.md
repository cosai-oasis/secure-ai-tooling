# ADR-011: `persona-site-data.schema.json` as a versioned producer/consumer contract

**Status:** Accepted
**Date:** 2026-04-21
**Authors:** Architect agent, with maintainer review

---

## Context

The persona Pages MVP (PR #223) introduced a two-process pipeline whose two halves speak to each other only through a JSON artifact on disk:

- **Producer:** `scripts/build_persona_site_data.py` reads `risk-map/yaml/{personas,risks,controls}.yaml`, transforms the content, and writes a single JSON file (`site/generated/persona-site-data.json` by default).
- **Consumer:** the client-side renderer under `site/assets/` (`app.mjs`, `persona-logic.mjs`) fetches that JSON at page load and builds the DOM from it.

The MVP's architecture choices — "zero-backend, zero-storage of answers, zero framework churn for YAML content" (PR #223 review §1) — deliberately push all rendering into the browser. That makes the JSON artifact the only integration point, and it makes the *shape* of that artifact the thing that has to be right: the renderer is static JavaScript served from GitHub Pages with no server-side validation layer to fall back on. A producer bug that ships a malformed JSON does not fail a request — it ships a broken explorer page to every visitor until the next build.

As landed in the MVP, the contract between builder and renderer was implicit. The renderer trusted the shape `build_site_data` happened to emit; no schema document described it; nothing validated the output before it was written. Review finding **REC-27** called this out directly: "*Output JSON has no schema … `app.mjs` and `persona-logic.mjs` consume the JSON with no contract.*" The finding's scope was explicit: (1) author a schema describing the seven top-level keys and item shapes, (2) validate in `write_site_data` before writing, (3) test that valid/invalid outputs pass/fail validation.

A concurrent, pre-existing bug made the contract's absence concrete. **BLOCK-02** (fixed by commit `a66128d`) was a shape defect: three risks in `risks.yaml` used intentional nested lists (`- - >`) as a semantic sub-group primitive inside `longDescription` / `shortDescription` / `examples`. The transform had called `str(item).strip()` without type-guarding nested lists, producing Python-repr output (`'["…\\n…"]'`) that flowed through `json.dump` → `JSON.parse` → `innerHTML` and rendered in the DOM with visible brackets, quotes, and `\n` escapes. BLOCK-02's fix established the prose-field *shape invariant* — prose is an array of `string | array<string>`, one level of nesting preserved, non-strings rejected. REC-27's scope then turned that invariant into a written contract the builder enforces before any bytes hit disk.

This ADR documents the REC-27 decision retroactively, under the practice established by [ADR-001](001-adopt-adrs.md) and within the module boundary of [ADR-010](010-site-repo-root-module-boundary.md): the framework lives in `risk-map/`, the consumer site lives in `/site/`, and the schema that sits between them lives with the other framework schemas in `risk-map/schemas/`.

## Decision

The file `risk-map/schemas/persona-site-data.schema.json` is the authoritative contract between `scripts/build_persona_site_data.py` and the `site/` renderer. It is a Draft-07 JSON Schema describing the exact shape the builder emits and the renderer consumes.

Concrete shape, as landed in commit `c20e675`:

- **Top-level object with seven required keys**, `additionalProperties: false`: `personas`, `questions`, `manualFallbackPersonaIds`, `riskCategories`, `controlCategories`, `risks`, `controls`. Each is an array of tightly-typed objects with their own `additionalProperties: false` and explicit `required` lists.
- **Prose-shape invariant** (the BLOCK-02 pattern) is formalized as a reusable `definitions/prose` entry: `array` whose items are `oneOf: [{type: string}, {type: array, items: {type: string}, minItems: 1}]`. It is `$ref`-ed from persona `description` and `responsibilities`, from risk `shortDescription` / `longDescription` / `examples`, and from control `description`. This is the exact shape BLOCK-02's `normalize_text_entries` produces — strings at the top level, with one optional level of nesting for semantic sub-groups — and the only shape the renderer's `renderRichParagraphs` array-branch is written to handle.
- **Enforced in-builder, fail-before-write.** `scripts/build_persona_site_data.py` loads the schema once at module scope (`_OUTPUT_SCHEMA`). `write_site_data` calls `jsonschema.validate(data, _OUTPUT_SCHEMA)` **before** `output_path.parent.mkdir(...)` and **before** the file open. A validation failure raises `jsonschema.ValidationError` with a wrapper message naming the offending path; no file is written, no partial artifact is left on disk, the working tree is unchanged.
- **Validator pinned.** `jsonschema==4.26.0` is pinned in `pyproject.toml` and locked in `uv.lock`. The pin is part of the contract: the validator's draft-support and error shape are both stable across builder, tests, and any downstream consumer that chooses to re-validate the artifact.
- **The schema is the source of truth for the item shapes.** Renderer-side assertions and builder-side transforms both conform to the schema rather than to each other; a future schema change is a coordinated edit against one document rather than a hunt through two codebases.

Enforcement at commit-time (running the builder as a pre-commit hook so violations are caught before push) is a separate concern; that hook is the subject of ADR-013. ADR-011 establishes the contract; ADR-013 describes the gate that exercises it.

## Alternatives Considered

- **Implicit contract (the pre-REC-27 state).** Let the renderer trust whatever the builder emits; rely on `app.mjs` and `persona-logic.mjs` to cope with shape drift. Rejected because this is exactly the state BLOCK-02 exploited: the builder's `str(nested_list)` bug passed every validator the repo had and surfaced only as visible garbage in the deployed DOM. There was no artifact anywhere that said "prose is `string | array<string>`"; the invariant lived in an author's head and in three `risks.yaml` entries.
- **TypeScript types in the renderer only.** Describe the JSON shape as a `.d.ts` or inline JSDoc types in `site/assets/`. Rejected because typing the *consumer* does not constrain the *producer*. A builder bug that emits the wrong shape still writes a file; the renderer's static types at best fail silently at runtime (they are erased before the code executes in the browser). The failure mode — user sees a broken page — is unchanged.
- **Runtime assertions in `app.mjs`.** Have the renderer validate the JSON after `fetch` but before rendering. Rejected because it is too late in the pipeline: by the time the assertion fires, the artifact is already deployed, visitors are already on the page, and the best the renderer can do is show an error state. Failing *before write* means a bad artifact never ships; failing *after fetch* means every visitor pays for the bug until the next build.
- **Use `check-jsonschema` against the written artifact in CI instead of in-builder.** Rejected as the primary enforcement point because the artifact is gitignored (`site/generated/`) and built on demand; relying on CI alone means a contributor running the builder locally can happily produce a malformed file and commit YAML that generates it, with the failure deferred to PR time. A CI-layer `check-jsonschema` is still useful as belt-and-braces, but it is not the contract — the in-builder call is.
- **Inline the schema as a Python dict in `build_persona_site_data.py`.** Rejected because it buries the contract in the producer's implementation. Putting the schema on disk under `risk-map/schemas/` alongside `personas.schema.json`, `risks.schema.json`, and `controls.schema.json` keeps all the repo's JSON-Schema documents discoverable in one place and lets external consumers (future tooling, CI, docs generators) `$ref` or load it without importing Python.

## Consequences

**Positive**

- **Shape drift fails fast and fails loud.** `write_site_data` refuses to write a non-conforming object; the builder exits non-zero with an actionable `ValidationError` message naming the schema path that failed. Partial or malformed artifacts never reach disk, so the renderer never parses one.
- **The prose-shape invariant is documented exactly once.** `definitions/prose` is `$ref`-ed from every prose field on personas, risks, and controls. BLOCK-02's "one level of nesting, strings only" rule lives in the schema, in the transform's `TypeError` guards, and in the renderer's array-branch — three enforcement points that all trace back to the same definition.
- **The producer/consumer boundary is now readable from the directory layout.** `risk-map/schemas/persona-site-data.schema.json` sits with the framework's other schemas; `scripts/build_persona_site_data.py` validates against it; `site/assets/` consumes output that has been validated against it. A contributor extending either side can find the contract without reading code.
- **External re-validation is cheap.** Because the schema is on disk and draft-07, any downstream consumer (a CI belt-and-braces step, a future pre-commit hook, a contributor debugging locally) can run `check-jsonschema --schemafile risk-map/schemas/persona-site-data.schema.json site/generated/persona-site-data.json` without touching Python.
- **Fail-before-write is an asserted invariant, not just a code-path claim.** Test fixtures in `scripts/hooks/tests/test_build_persona_site_data.py` cover both valid writes and deliberately-malformed outputs — REC-27's third sub-action — so the refusal-to-write behavior is exercised on every `pytest` run rather than assumed from reading the builder.

**Negative**

- **New external dependency.** `jsonschema==4.26.0` is now pinned in `pyproject.toml` and locked in `uv.lock`. The package is widely used and well-maintained, but it is a supply-chain surface the repo did not previously depend on at runtime (`check-jsonschema` had been a dev-only pre-commit dep).
- **Every builder run pays validation cost.** `jsonschema.validate` walks the entire output on every invocation. The artifact is small enough that this is not measurable today, but it is no longer free — a future builder that emits substantially more data should check that validation has not become a hot path.
- **Schema evolution is now a migration, not a free change.** Any future change to the emitted shape requires a coordinated edit to the schema, the builder, the renderer, and the Python tests — and the schema is the one that must move first (or the builder will refuse to write). This is the cost of having a contract; it is mentioned here so that a future contributor does not reach for "just change the builder" and find the hook blocking them.
- **`additionalProperties: false` is strict by design.** Adding a new top-level key or a new per-item field is a schema edit first. This is deliberate — it's what catches typoed field names on the producer side — but it is a sharper edge than a permissive schema would have.
- **The gitignored artifact is never directly inspected by repo-wide schema hooks.** `site/generated/persona-site-data.json` is not checked in, so the `check-jsonschema` entries in `.pre-commit-config.yaml` (which match on tracked YAML paths) do not cover it. Enforcement for the generated artifact happens in-builder only, by design.
- **Referential integrity is a Python-side invariant, not a schema-enforced one.** The schema validates that `personas[].riskIds` / `controlIds` are arrays of strings; it does not check that each id actually resolves to an entry in `risks[].id` / `controls[].id`. That integrity is enforced in `build_site_data` via `active_persona_ids` / `all_risk_ids` filtering. A future schema-only consumer cannot rely on the JSON alone to catch dangling refs.

**Follow-up**

- **ADR-013 will document the pre-commit hook that runs the builder on YAML or builder changes.** The hook is the *gate* that ensures this contract is exercised before commit; this ADR is the *contract itself*. The two cross-reference each other: ADR-013 cites ADR-011 as the contract it enforces, and this ADR points to ADR-013 for the commit-time enforcement mechanism.
- **Renderer SPA architecture (ADR-012) consumes this contract.** The renderer's shape assumptions — `renderRichParagraphs` array-vs-string branch, the top-level key names — are all derived from this schema. Changes to the schema's item shapes are changes the renderer must track; ADR-012 documents the consumer side of that coupling.
- **Consider a CI belt-and-braces `check-jsonschema` step.** Running the external validator against a freshly-built artifact in the persona-Pages workflow (ADR-009) would add a second enforcement point at the cost of a few seconds of CI time. Worth considering if the in-builder enforcement ever turns out to have a blind spot (e.g., a builder path that bypasses `write_site_data`). Not pursued in the MVP because the in-builder enforcement is considered sufficient.
- **Dependabot or `uv run --locked --no-sync pre-commit autoupdate` cadence for `jsonschema==4.26.0`.** The pin matches the hygiene established by ADR-005 for other pinned tools; it needs periodic bumps and is currently not tracked by Dependabot.
- **If a future producer emits a second artifact for the same consumer** (for example, a split between persona-guided and manual-fallback data for lazy loading), apply the same pattern: one schema per artifact, in-builder validation, fail-before-write, pinned validator. Do not let the pattern decay into "most artifacts are validated."
- **Schema polish carried forward.** `$id` is a bare filename (`"persona-site-data.schema.json"`) rather than a resolvable URI, matching the repo's other schemas; and schema failures raise `jsonschema.ValidationError` directly rather than a repo-specific exception type. Revisit either choice if downstream consumers start `$ref`-ing this schema externally or if error-type uniformity across the builder becomes desirable.
