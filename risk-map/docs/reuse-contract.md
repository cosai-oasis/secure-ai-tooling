# Reuse Contract

The CoSAI Risk Map is published for wide reuse. Third parties ingest the raw YAML under
`risk-map/yaml/**` into LLM tooling, prompt libraries, vendor products, and downstream
frameworks. This page is the human-readable engineering contract for that reuse: what the
framework guarantees, what it does not, and what a downstream consumer is responsible for.

It implements [ADR-014](../../docs/adr/014-yaml-content-security-posture.md) P5 in
consumer-facing terms. ADR-014 is the policy decision; this page is its documentation.
For legal terms, see [`LICENSE.md`](../../LICENSE.md) — this page does not restate them.

---

## What the framework guarantees

**Shape.** Every field in `risk-map/yaml/**` is described by a JSON Schema under
`risk-map/schemas/*.schema.json`, and cross-file integrity (control↔risk references,
component edges, framework applicability, sentinel resolution) is enforced by the
validators in `scripts/hooks/`. A consumer that validates the YAML against the published
schemas gets the same shape guarantee the repository's own tooling relies on. This is the
load-bearing guarantee — write your parser against the schemas.

**Prose content.** Prose fields carry a small, fixed vocabulary: `**bold**`,
`*italic*`/`_italic_`, and `{{…}}` reference sentinels — and **no URLs at all**. Every
outbound URL lives in a typed, schema-validated `externalReferences` entry; prose
references it by sentinel. A redistributor parsing the YAML knows that any URL it ingests
came through a structured field, not free prose. The full rule is in
[yaml-authoring-subset.md](./yaml-authoring-subset.md) and
[ADR-017](../../docs/adr/017-yaml-prose-authoring-subset.md).

**Control prose.** A control carries a normative `description` and an optional,
informative `guidance`. The control's summary is its `description`, not the position of a
paragraph, and `guidance` is never needed to understand what the control is. Sentinels
resolve alike in both fields. See
[control-description-and-guidance.md](./design/control-description-and-guidance.md).

**Provenance.** Every change to `risk-map/yaml/**` lands through a reviewed pull request,
attributed to identifiable contributors, with AI-assisted contributions tagged per
[ADR-004](../../docs/adr/004-ai-assistant-trailer.md). The git history is the provenance
record; there is no separate signing or attestation surface.

**Identifiers are stable references.** Entity IDs (`riskPromptInjection`,
`controlInputValidationAndSanitization`, …) are closed schema enums. A rename updates the
enum, which re-validates every cross-reference and every prose sentinel across the
framework at once. An ID that resolves today resolves consistently across the YAML, the
generated tables, and the site.

## What the framework does NOT guarantee

The framework cannot tell you "this content is safe for your pipeline," because it does
not know what your pipeline is. It explicitly does **not** guarantee:

- **Safety in any specific rendering surface.** The YAML is untrusted input at every
  consumer boundary ([ADR-014](../../docs/adr/014-yaml-content-security-posture.md) P1).
  HTML escaping, prompt-injection defense, and markup stripping are the consumer's job at
  the consumer's boundary — see "What you are responsible for" below.
- **Semantic stability of mappings.** Framework cross-walks (`mappings` to MITRE ATLAS,
  NIST AI RMF, OWASP, etc.) are the working group's best-effort interpretation. No
  external framework maintainer has reviewed or endorsed them, and they may change as the
  source frameworks evolve.
- **Backwards-compatible schema evolution as a hard promise.** Schemas are maintained for
  best-effort backwards compatibility, but the YAML files carry no per-file `version`
  field today and there is no SemVer contract on the schemas. Treat the git history (and
  any future CHANGELOG) as the change record. Breaking shape changes are called out in the
  PR that makes them, not guaranteed absent.
- **Completeness.** The risk, control, component, and persona catalogs are not exhaustive
  and are not a substitute for a threat model of your own system.

## What you are responsible for (downstream sanitization)

Relative to your surface, treat the YAML prose as **untrusted input** and sanitize at your
own boundary before rendering or embedding it:

- **Web/HTML consumers** — HTML-escape or run an allowlist transform before writing prose
  into the DOM. The reference implementation is `site/assets/sanitizer.mjs` (`renderProse`),
  which emits a bounded `<strong>`/`<em>`/`<a>` allowlist with constructed attributes
  ([ADR-015](../../docs/adr/015-site-content-sanitization-invariants.md)). The on-disk YAML
  is subset-compliant, but you should still defend your own render boundary.
- **LLM consumers** — sanitize prose before embedding it in prompts. Content review screens
  for evident injection intent, but the framework cannot defend a prompt it does not
  control. Treat the content as data, not instructions.
- **Export consumers (PDF, docs, etc.)** — apply the markup transform appropriate to your
  output format. The prose vocabulary is small and documented in
  [yaml-authoring-subset.md](./yaml-authoring-subset.md); transform from that, not from an
  assumption of arbitrary markdown.

The honest summary: the framework makes the content **shape-safe and provenance-tracked**;
it does not make it **pipeline-safe**. That boundary is the contract.

## Versioning and cadence

- The YAML carries no per-file version metadata today. A future revision may add a
  top-level `_meta` block; **consumers should ignore unknown top-level keys** so that
  addition does not break them.
- Schema changes that alter shape are visible in the git history of `risk-map/schemas/`.
  Until a published CHANGELOG exists, the commit history is the change record.

## Attribution and endorsement

Attribution follows the terms in [`LICENSE.md`](../../LICENSE.md). Reuse of the content
does not imply endorsement by the Coalition for Secure AI or its member organizations, and
redistributed copies should not represent themselves as authoritative CoSAI publications.

---

## Related

- [ADR-014](../../docs/adr/014-yaml-content-security-posture.md) — YAML content security posture (P5 is the source of this contract)
- [ADR-017](../../docs/adr/017-yaml-prose-authoring-subset.md) — Prose authoring subset (the "no URLs in prose" guarantee)
- [ADR-015](../../docs/adr/015-site-content-sanitization-invariants.md) — Site render-time sanitization (reference implementation)
- [yaml-authoring-subset.md](./yaml-authoring-subset.md) — What prose strings carry
- [`LICENSE.md`](../../LICENSE.md) — Legal terms
