# YAML Prose Authoring Subset

This page is the consumer-facing summary of what prose strings in the CoSAI Risk Map
YAML may contain. It covers the three allowed token forms, the two sentinel forms,
the categorical no-inline-URL rule, and the `externalReferences` citation flow.

It is a summary of the decisions in [ADR-017](../../docs/adr/017-yaml-prose-authoring-subset.md)
(authoring subset), [ADR-016](../../docs/adr/016-reference-strategy.md) (references), and
[ADR-014](../../docs/adr/014-yaml-content-security-posture.md) (security posture). Where
this page and an ADR disagree, the ADR is authoritative — drift here is a documentation
defect.

**Who this is for**

- **Contributors** authoring `risk-map/yaml/{components,controls,risks,personas}.yaml`.
- **Redistributors** ingesting the YAML directly, who need to know what tokens the prose
  fields carry.

Prose fields are: `description`, `guidance` (controls), `shortDescription`,
`longDescription`, `examples`, `responsibilities`, `tourContent.*`, and equivalents.
Identifiers, enums, and structured-reference fields are not prose and are not covered
here.

---

## The three allowed forms

A prose string may contain exactly these token forms. Everything else is rejected at
commit time by the `validate-yaml-prose-subset` and `validate-prose-references`
pre-commit hooks (both in block mode).

| Form | Syntax | Notes |
|------|--------|-------|
| **Bold** | `**bold**` | Asterisk delimiter only. `__bold__` is not recognized. One nesting level; no nested `**…**`. |
| **Italic** | `*italic*` or `_italic_` | Both delimiters recognized. No nested italic. |
| **Sentinels** | `{{<entity-id>}}` / `{{ref:identifier}}` | Reference tokens — see below. The braces carry an identifier only. |

Bold and italic may compose: `**emphatically *not* this**` is valid. Sentinels are
atomic identifier tokens; they do not nest into bold or italic. Paragraph and
hard-break structure is carried by the YAML **array** shape (one array item per
paragraph), not by markup in the string.

---

## The two sentinel forms

References — to another framework entity, or to an external source — are written as
double-brace sentinels. There is no other syntax for a reference, and no inline URL or
HTML anchor form.

### Intra-document — `{{<entity-id>}}`

Mentions another framework entity by its canonical camelCase ID. The generator resolves
it to the entity's title (in tables) or an in-page link (on the site); authors never
hand-write the display title.

```yaml
description:
  - "This compounds {{riskPromptInjection}} when the tool output is unsanitized."
```

The ID must resolve against the schema's identifier enum (risk, control, component,
persona). An unknown ID is blocked at commit and fails the build.

### External — `{{ref:identifier}}`

Cites an external source — a paper, advisory, CWE, CVE, spec, or editorial pointer. The
`ref:` prefix is literal; `identifier` matches an `id` in the entry's own
`externalReferences` array.

```yaml
description:
  - "The SQL-injection pattern ({{ref:cwe-89}}) applies to query construction in agent tooling."
```

---

## No inline URLs — the categorical rule

**A prose string carries no URL of any scheme.** Not `https://…`, not `[text](url)`
markdown links, not `<a href>` HTML, not `mailto:` / `tel:` / `javascript:` / `data:`.
The rule is categorical: if a token carries a URI scheme, the linter rejects it.

This is deliberate. The editorial line between "this URL is a citation" and "this URL is
color" is not machine-testable, so every URL moves into a structured field and prose
references it by sentinel. A redistributor parsing the YAML then knows every URL it
ingests came through a typed, schema-validated field — not free prose.

## The `externalReferences` flow (two steps)

Adding a link is a two-step move. **Add the structured entry first, then reference it by
sentinel.**

```yaml
# Step 1 — add the structured entry
externalReferences:
  - type: paper
    id: zhou-2023-poisoning
    title: "Poisoning Language Models During Instruction Tuning"
    url: https://arxiv.org/abs/2305.00944

# Step 2 — reference it from prose by sentinel
description:
  - "Zhou et al. ({{ref:zhou-2023-poisoning}}) demonstrated instruction-tuning poisoning at scale."
```

Each `externalReferences` entry has four required fields:

- **`type`** — one of `cwe`, `cve`, `atlas`, `attack`, `advisory`, `paper`, `news`,
  `spec`, `editorial`, `other`. Use `editorial` for a non-citation "see also" / color
  pointer — the relief valve that keeps the citation types clean.
- **`id`** — the sentinel target; unique within the entry. For canonical references
  (`cwe`, `cve`, `atlas`, `attack`) mirror the canonical ID in lowercase-kebab form
  (`cwe-89`, `cve-2024-0001`); otherwise pick a stable shorthand (`zhou-2023-poisoning`).
- **`title`** — the display string generators and the site renderer use.
- **`url`** — must be `https://` (HTTP is rejected). Empty arrays are rejected; omit the
  field entirely if there are no references.

---

## Disallowed constructions

All blocked at commit. Each has an actionable alternative.

| Disallowed | Use instead |
|------------|-------------|
| Raw HTML (`<a>`, `<strong>`, `<em>`, `<br>`, `<p>`, `<div>`, `<script>`, `on*=`, …) | `**bold**`, `*italic*`, array items for breaks, sentinels for links |
| Inline URLs (any scheme), `[text](url)` markdown links | `externalReferences` entry + `{{ref:identifier}}` sentinel |
| Bare camelCase IDs (`riskPromptInjection` in a sentence) | `{{riskPromptInjection}}` sentinel |
| Markdown headings (`#`, `##`) | YAML structure expresses hierarchy |
| Markdown list markers (`- `, `* `, `1. `) | The prose-array shape is the list primitive |
| Code fences / inline code (`` `code` ``) | Out of scope for the subset |
| Images (`![alt](url)`) | Not embedded in prose |
| Blockquotes (`>`), pipe tables | Out of scope; tables are generated artifacts |

---

## The redistribution contract for prose

After the conformance sweep, the YAML carries a stronger guarantee than "some URLs you
must sanitize" ([ADR-017](../../docs/adr/017-yaml-prose-authoring-subset.md) D6):

> **YAML prose contains no URLs at all.** Every URL lives in a typed, schema-validated
> `externalReferences` entry; prose references them by sentinel only.

A redistributor parsing the YAML can rely on a three-form prose vocabulary (bold,
italic, sentinels) and a fully-typed reference surface. This is part of the broader
reuse contract — see [reuse-contract.md](./reuse-contract.md).

The framework guarantees the **shape** of this content (via the schemas and the
authoring lint); it does **not** guarantee safety in any specific downstream pipeline.
A consumer embedding this content in HTML, a prompt, or a PDF still sanitizes at its own
boundary. See [reuse-contract.md](./reuse-contract.md) and
[ADR-014](../../docs/adr/014-yaml-content-security-posture.md) P5.

---

## Related

- [ADR-017](../../docs/adr/017-yaml-prose-authoring-subset.md) — Canonical prose authoring subset (source of truth)
- [ADR-016](../../docs/adr/016-reference-strategy.md) — Sentinel grammar + `externalReferences` field
- [ADR-014](../../docs/adr/014-yaml-content-security-posture.md) — YAML content security posture
- [reuse-contract.md](./reuse-contract.md) — What the framework guarantees to downstream consumers
- [contributing/framework-mappings-style-guide.md](./contributing/framework-mappings-style-guide.md) — Framework-mapping identifier forms
- [contributing/submission-readiness-guide.md](./contributing/submission-readiness-guide.md) — Preparing a content proposal
