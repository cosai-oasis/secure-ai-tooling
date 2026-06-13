# Pre-commit Hook Validations

The pre-commit framework runs the hooks declared in `.pre-commit-config.yaml`
at the repo root. Each hook targets a specific trigger-file regex; hooks
whose regex doesn't match any staged file are skipped. This page describes
each hook's purpose, trigger, and output.

For the canonical execution order see [Validation Flow](validation-flow.md).
For running hooks without committing see [Manual Validation](manual-validation.md).

## 1. YAML Schema Validation

One `check-jsonschema` hook per yaml/schema pair. Runs when the yaml or its
schema is staged, with `--base-uri` set to `file://./risk-map/schemas/` for
cross-schema `$ref` resolution.

**Yaml/schema pairs covered:**

- `yaml/actor-access.yaml` → `schemas/actor-access.schema.json`
- `yaml/components.yaml` → `schemas/components.schema.json`
- `yaml/controls.yaml` → `schemas/controls.schema.json`
- `yaml/frameworks.yaml` → `schemas/frameworks.schema.json`
- `yaml/impact-type.yaml` → `schemas/impact-type.schema.json`
- `yaml/lifecycle-stage.yaml` → `schemas/lifecycle-stage.schema.json`
- `yaml/mermaid-styles.yaml` → `schemas/mermaid-styles.schema.json`
- `yaml/personas.yaml` → `schemas/personas.schema.json`
- `yaml/risks.yaml` → `schemas/risks.schema.json`
- `yaml/archive/self-assessment-legacy.yaml` → `schemas/archive/self-assessment-legacy.schema.json` (archived per ADR-021 D6)

## 2. Schema Meta-Validation

The `check-metaschema` hook (from `python-jsonschema/check-jsonschema`)
validates that each `risk-map/schemas/*.schema.json` file is itself a
structurally valid JSON Schema document against its declared `$schema`
metaschema. Runs whenever any schema file is staged. Catches typo'd
keywords (e.g., `requried`), invalid regex patterns, and broken `$refs`
at author time rather than at validation time.

## 3. Schema Master Trigger

When `risk-map/schemas/riskmap.schema.json` itself is staged, every yaml is
re-validated against its schema in a single pass
(`validate-all-yaml-on-master-schema-change` local hook). This catches
master-schema changes that break downstream validation.

## 4. Prettier YAML Formatting

`prettier-yaml` hook wraps `npx prettier --write` and `git add`s each
reformatted file (Mode B auto-stage), so formatting changes land in the same
commit as the source edit. Targets yaml files under `risk-map/yaml/`.

## 5. Ruff Lint + Format

Published `ruff` and `ruff-format` hooks from
`github.com/astral-sh/ruff-pre-commit`. Configuration is read from
`.ruff.toml` at the repo root (line length 115, double quotes). Lint failure
blocks the commit; format is applied and re-staged.

## 6. Component Edge Validation

`validate-component-edges` hook runs `scripts/hooks/validate_riskmap.py`
when `risk-map/yaml/components.yaml` is staged. The validator does its own
internal staged-file detection; the framework triggers the hook without
passing filenames (`pass_filenames: false`).

**Validation:**

- **Edge consistency**: if Component A has `to: [B]`, Component B must have `from: [A]`
- **Bidirectional matching**: every `to` has a corresponding `from`
- **Isolated component detection**: flags components with no edges

**Example:**

```yaml
components:
  - id: componentA
    edges:
      to: [componentB]
      from: []
  - id: componentB
    edges:
      to: []
      from: [componentA] # ✅ Matches componentA's 'to' edge
```

## 7. Control-to-Risk Reference Validation

`validate-control-risk-references` hook runs
`scripts/hooks/validate_control_risk_references.py` when
`risk-map/yaml/controls.yaml` or `risks.yaml` is staged.

**Validation:**

- **Bidirectional consistency**: if a control lists a risk, that risk lists the control
- **Isolated entry detection**: finds controls with no risks or risks with no controls
- **all/none awareness**: does not flag controls that use the `all` or `none` risk mappings

**Example:**

```yaml
# controls.yaml
controls:
  - id: CTRL-001
    risks:
      - RISK-001
      - RISK-002

# risks.yaml
risks:
  - id: RISK-001
    controls:
      - CTRL-001 # ✅ Risk references the control back
  - id: RISK-002
    controls:
      - CTRL-001
```

## 8. Framework Reference Validation

`validate-framework-references` hook runs
`scripts/hooks/validate_framework_references.py` when `controls.yaml`,
`frameworks.yaml`, `personas.yaml`, or `risks.yaml` is staged.

**Validation:**

- **Framework applicability**: frameworks only mapped to entity types listed in their `applicableTo`
- **Valid technique references**: framework technique IDs exist in the framework definitions
- **Bidirectional consistency**: framework mappings consistent across entities

**Entities checked:**

- `controls.yaml` framework mappings (MITRE ATLAS, NIST AI RMF, OWASP Top 10 for LLM)
- `risks.yaml` framework mappings (MITRE ATLAS, STRIDE, OWASP Top 10 for LLM)
- `frameworks.yaml` configuration and structure
- `personas.yaml` framework applicability

## 9. GitHub Actions `uses:` Pinning Validation

`validate-workflow-uses-pinning` hook runs
`scripts/hooks/precommit/validate_workflow_uses_pinning.py` when a workflow
file under `.github/workflows/*.yml` or `.github/workflows/**/*.yml` is
staged.

**Validation (ADR-024 D6 pin form):**

- External `uses:` references must use
  `owner/repo@<40-character-SHA> # vX.Y.Z`
- External action subpaths and reusable workflows must use
  `owner/repo/path@<40-character-SHA> # vX.Y.Z`
- Local `./...` references are allowed without a SHA or version comment
- `docker://` action references emit an advisory warning per ADR-024 D7
  (not a commit-blocking failure) until the planned ADR-023 defines Docker
  pinning

**Example:**

```yaml
# Valid external action reference
- uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v6.0.2

# Valid local reference
- uses: ./.github/actions/build

# Invalid: mutable tag
- uses: actions/checkout@v6
```

Violations name the offending workflow file and line number.

## 10. Issue Template Regeneration

`regenerate-issue-templates` hook (`scripts/hooks/precommit/regenerate_issue_templates.py`)
triggers when any of these is staged:

- Template sources: `scripts/TEMPLATES/*.yml`
- Any schema: `risk-map/schemas/*.schema.json`
- Framework config: `risk-map/yaml/frameworks.yaml`

The framework invokes the wrapper once per commit regardless of how many
trigger files are staged (`pass_filenames: false` + `require_serial: true`),
and the wrapper regenerates the full template set unconditionally. The
generated `.github/ISSUE_TEMPLATE` directory is `git add`-ed so the
regenerated templates land in the same commit.

**Generated templates:**

- `new_control.yml`, `update_control.yml`
- `new_risk.yml`, `update_risk.yml`
- `new_component.yml`, `update_component.yml`
- `new_persona.yml`, `update_persona.yml`
- `infrastructure.yml`

## 11. Issue Template Validation

`validate-issue-templates` hook runs
`scripts/hooks/validate_issue_templates.py` when anything under
`.github/ISSUE_TEMPLATE/*.yml` or `scripts/TEMPLATES/*.yml` is staged
(including the files just regenerated in step 10).

**Validates against vendored schemas:**

- Issue forms: `vendor.github-issue-forms`
- Template config: `vendor.github-issue-config`
- Dependabot: `vendor.dependabot`

**Example — catches invalid structures:**

```yaml
# Valid:
- type: dropdown
  id: category
  attributes: { label: 'Category*', options: [...] }
  validations: { required: true }   # ✅ dropdowns support validations

# Invalid:
- type: checkboxes
  id: personas
  validations: { required: true }   # ❌ checkboxes don't support top-level validations
```

## 12. Graph Regeneration

`regenerate-graphs` hook (`scripts/hooks/precommit/regenerate_graphs.py`)
produces three Mermaid graph pairs based on which source yaml is staged:

| Trigger | Output `.md` + `.mermaid` |
|---|---|
| `components.yaml` | `risk-map/diagrams/risk-map-graph.{md,mermaid}` |
| `components.yaml` OR `controls.yaml` | `risk-map/diagrams/controls-graph.{md,mermaid}` |
| `components.yaml` OR `controls.yaml` OR `risks.yaml` | `risk-map/diagrams/controls-to-risk-graph.{md,mermaid}` |

Each output pair is `git add`-ed on success. The wrapper delegates to
`validate_riskmap.py --to-graph / --to-controls-graph / --to-risk-graph`.

## 13. Table Regeneration

`regenerate-tables` hook (`scripts/hooks/precommit/regenerate_tables.py`)
produces 8 generation operations across 4 source triggers. The ordering
matches the prior bash hook exactly (components → risks → controls →
personas) and cross-trigger xref refreshes are preserved for parity:

| Source trigger | Generations (each followed by `git add`) |
|---|---|
| `components.yaml` | `components --all-formats`, `controls --format xref-components` |
| `risks.yaml` | `risks --all-formats`, `controls --format xref-risks`, `personas --format xref-risks` |
| `controls.yaml` | `controls --all-formats`, `personas --format xref-controls` |
| `personas.yaml` | `personas --all-formats` |

When multiple triggers are staged (e.g., components + controls), BOTH the
xref regen (from components trigger) AND the full regen (from controls
trigger) run — matches bash behavior.

See [Table Generation](table-generation.md) for output filename conventions.

## 14. Mermaid SVG Regeneration

`regenerate-svgs` hook (`scripts/hooks/precommit/regenerate_svgs.py`)
converts staged `.mmd` or `.mermaid` files under `risk-map/diagrams/` into
SVGs under `risk-map/svg/` via `npx mmdc`, then `git add`s each output.

**Chromium discovery (runtime, in this order):**

1. `CHROMIUM_PATH` env var (if set and non-empty) — explicit override
2. On Linux ARM64: recursive search under `$PLAYWRIGHT_BROWSERS_PATH`
   (default `~/.cache/ms-playwright`) for `headless_shell` then `chrome`
3. Otherwise: mmdc's bundled auto-detect

One shared puppeteer config is written per invocation and cleaned up in a
`finally` block.

**Dependencies:**

- `@mermaid-js/mermaid-cli` via `npx mmdc`
- A working Chromium (see discovery above)
- On Linux ARM64: Playwright Chromium (installed by `install-deps.sh` Step 7)

## 15. Framework versionId Generation

`regenerate-frameworks-versionid` hook runs
`scripts/hooks/precommit/versionid_generator.py` when
`risk-map/yaml/frameworks.yaml` is staged.

**Trigger:** `^risk-map/yaml/frameworks\.yaml$` (`pass_filenames: true`)

**What it does (ADR-027 D2b):**

Materializes the `versionId` field for every entry in `frameworks.yaml`:
`versionId = id if version is null else f"{id}@{version}"`. The field is
derived, not authored; the generator writes it and auto-stages the result so
the materialized value lands in the same commit as the source edit. Fails if
`version` is a non-string (the YAML-float footgun), if the composed `versionId`
violates the D2a charset (`^[a-z0-9.@-]+$`), or if two entries mint the same
`versionId`.

## 16. Framework versionId Purity

`validate-frameworks-versionid-purity` hook runs
`scripts/hooks/precommit/validate_versionid_purity.py` when
`risk-map/yaml/frameworks.yaml` is staged.

**Trigger:** `^risk-map/yaml/frameworks\.yaml$` (`pass_filenames: false`)

**What it validates (ADR-027 D2b/D2c):**

- On-disk `versionId` equals the derived value (D2b purity: proves no
  hand-edit has drifted the materialized field).
- `versionId` matches the D2a charset.
- `versionId` values are unique across the registry.
- If `supersedes` is present: charset-valid and belongs to the same
  concept-id family (D2c).
- If `priorVersions` is present: every member is charset-valid, list has no
  duplicates, and all members belong to the same concept-id family (D2c).

Also runs in `validate-all.sh` (`--path risk-map/yaml/frameworks.yaml`).

## 17. Framework Mapping-Value Purity

`validate-mapping-purity` hook runs
`scripts/hooks/precommit/validate_mapping_purity.py` when any of the four
content YAML files is staged.

**Trigger:**
`^risk-map/(yaml/(risks|controls|components|personas|frameworks)\.yaml|schemas/frameworks\.schema\.json)$`
(`pass_filenames: false`)

**What it validates (ADR-027 D4c):**

Classifies each `mappings.<framework>` value as `ok`, `skip`, or `fail`:

- Unknown framework key → fail (fail-loud, not drift's concern).
- Versioned framework + no delimiter (`@` or `:`) → **fail** (unpinned value;
  post-#343 the corpus is migrated and the strict consumer schemas make pinning
  mandatory — the ADR-027 D7/M1 "block" phase; the pre-migration "skip"
  tolerance is retired). `check-jsonschema` rejects the same value.
- Delimiter present: attempt split + compose round-trip. Round-trip mismatch
  or parse error on a versioned framework → fail (value is tampered). Parse
  error on an unversioned framework (STRIDE — no version token by design) → skip.

Pinned values are generated by `framework_mapping_maintainer.py`, not
hand-typed; this validator proves that invariant. Also runs in
`validate-all.sh`, which additionally runs content `check-jsonschema` against
the four consumer schemas so the manual sweep rejects an unpinned value too.

## 18. Framework Mapping-Value Drift

`validate-mapping-drift` hook runs
`scripts/hooks/precommit/validate_mapping_drift.py` when any of the four
content YAML files is staged.

**Trigger:**
`^risk-map/(yaml/(risks|controls|components|personas|frameworks)\.yaml|schemas/frameworks\.schema\.json)$`
(`pass_filenames: false`)

**What it validates (ADR-027 D5/D5a):**

Tier-1 drift detection: classifies each `mappings.<framework>` value as
`skip`, `current`, `valid-but-superseded`, or `invalid` using only data on
disk (no external catalogs):

- Unknown framework → skip (purity validator owns unknown-framework errors).
- Unversioned framework (STRIDE): value in closed PascalCase enum → current;
  legacy spelling → skip.
- Versioned + no delimiter → skip (legacy unpinned).
- Versioned + delimiter present: version token equals `version` → current;
  token in `priorVersions` → valid-but-superseded (informational, not a
  failure); token in neither → invalid (fails).

Only `invalid` causes exit 1. `valid-but-superseded` is printed
informationally to surface the D10b audit surface for maintainer review.
Also runs in `validate-all.sh` with the four content paths explicit.

---

**Related:**

- [Validation Flow](validation-flow.md) — Execution order and framework semantics
- [Manual Validation](manual-validation.md) — Running validators without committing
- [Troubleshooting](troubleshooting.md) — Common validation errors
