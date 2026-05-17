# Issue Template Generation

GitHub issue templates in `.github/ISSUE_TEMPLATE/` are generated artifacts. Some are produced from source templates; others are hand-authored and committed directly. This document explains the two-tier model, which files are generated vs. hand-authored, how to edit them safely, and how the placeholder system works.

**Audience:** Repository maintainers. For contributor-facing guidance on filling out the templates, see [issue-templates-guide.md](../../risk-map/docs/contributing/issue-templates-guide.md).

---

## Two-tier model

```
scripts/TEMPLATES/*.template.yml     <-- authored here
            |
            | uv run --locked --no-sync python scripts/generate_issue_templates.py
            v
.github/ISSUE_TEMPLATE/*.yml         <-- generated artifacts
```

Template sources live in `scripts/TEMPLATES/` and contain `{{PLACEHOLDER}}` tokens. The generator resolves each token against JSON schema enum values, applies filters, and writes the result to `.github/ISSUE_TEMPLATE/`. The generated files are committed to the repo so GitHub picks them up without a build step.

---

## Inventory

### Generated from source templates (5)

| Source template | Generated file | Entity type |
|---|---|---|
| `new_risk.template.yml` | `new_risk.yml` | risks |
| `update_risk.template.yml` | `update_risk.yml` | risks |
| `new_control.template.yml` | `new_control.yml` | controls |
| `update_control.template.yml` | `update_control.yml` | controls |
| `new_component.template.yml` | `new_component.yml` | components |

### Hand-authored (committed directly, no source template)

These four files **have no entry in `scripts/TEMPLATES/` and are not regenerated.** Edit them directly in `.github/ISSUE_TEMPLATE/`:

| File | Notes |
|---|---|
| `new_persona.yml` | Owned by `.github/ISSUE_TEMPLATE/`; not regenerated |
| `update_persona.yml` | Owned by `.github/ISSUE_TEMPLATE/`; not regenerated |
| `update_component.yml` | Owned by `.github/ISSUE_TEMPLATE/`; not regenerated |
| `infrastructure.yml` | One-off template; no placeholders; not regenerated |

The asymmetry exists for historical reasons. The five generated templates have placeholders whose values change as schemas evolve; the others were authored once and have remained stable. Any of the hand-authored files can be given a source template later if that changes — see [Adding a new generated template](#adding-a-new-generated-template).

---

## Editing rules

**DO NOT edit `.github/ISSUE_TEMPLATE/*.yml` files that have a source template.**

Any hand-edit to a generated file is silently overwritten the next time generation runs. That next run could be seconds away: the pre-commit hook regenerates templates automatically whenever a schema file (`risk-map/schemas/*.schema.json`), a template source (`scripts/TEMPLATES/*.template.yml`), or `risk-map/yaml/frameworks.yaml` is staged for commit.

The correct workflow for a generated template:

1. Edit the corresponding source in `scripts/TEMPLATES/<name>.template.yml`.
2. Run `uv run --locked --no-sync python scripts/generate_issue_templates.py` to preview the result.
3. Stage both the source and the generated file.

For hand-authored templates (`new_persona.yml`, `update_persona.yml`, `update_component.yml`, `infrastructure.yml`), edit the file in `.github/ISSUE_TEMPLATE/` directly — there is no source to update.

---

## Regenerating templates

```bash
# Generate all templates (from repo root)
uv run --locked --no-sync python scripts/generate_issue_templates.py

# Preview changes without writing
uv run --locked --no-sync python scripts/generate_issue_templates.py --dry-run

# Generate a single template
uv run --locked --no-sync python scripts/generate_issue_templates.py --template new_risk

# Validate rendered content without writing
uv run --locked --no-sync python scripts/generate_issue_templates.py --validate

# Verbose output
uv run --locked --no-sync python scripts/generate_issue_templates.py --verbose
```

The pre-commit hook auto-regenerates and stages the affected templates when any of the following files are staged:

- `risk-map/schemas/*.schema.json` — enum values used in dropdowns and checkboxes
- `scripts/TEMPLATES/*.template.yml` — template source changed
- `risk-map/yaml/frameworks.yaml` — framework applicability changed

---

## Placeholder system

Placeholders in source templates take the form `{{PLACEHOLDER_NAME}}`. The generator replaces each token with a YAML block rendered from schema enum values.

Current placeholders and their schema sources:

| Placeholder | Schema source | Field type | Notes |
|---|---|---|---|
| `{{PERSONAS}}` | `personas.schema.json` → `definitions.persona.properties.id` | checkbox | Full persona list; includes `personaGovernance`. For controls templates. |
| `{{PERSONAS_FOR_RISKS}}` | `personas.schema.json` → `definitions.persona.properties.id` | checkbox | Excludes `personaGovernance`. For risk templates. See [Why two persona placeholders](#why-two-persona-placeholders). |
| `{{LIFECYCLE_STAGE}}` | `lifecycle-stage.schema.json` → `definitions.lifecycleStage.properties.id` | checkbox | |
| `{{IMPACT_TYPE}}` | `impact-type.schema.json` → `definitions.impactType.properties.id` | checkbox | |
| `{{ACTOR_ACCESS}}` | `actor-access.schema.json` → `definitions.actorAccessLevel.properties.id` | checkbox | |
| `{{CONTROL_CATEGORIES}}` | `controls.schema.json` → `definitions.category.properties.id` | dropdown | |
| `{{RISK_CATEGORIES}}` | `risks.schema.json` → `definitions.risk.properties.category` | dropdown | |
| `{{COMPONENT_CATEGORIES}}` | `components.schema.json` → `definitions.category.properties.id` | dropdown | |
| `{{CONTROL_FRAMEWORKS_LIST}}` | `risk-map/yaml/frameworks.yaml` (entries with `controls` in `appliesTo`) | inline text | Comma-separated framework IDs for the framework-mappings field description. |
| `{{RISK_FRAMEWORKS_LIST}}` | `risk-map/yaml/frameworks.yaml` (entries with `risks` in `appliesTo`) | inline text | Comma-separated framework IDs for the framework-mappings field description. |
| `{{FRAMEWORK_MAPPINGS}}` | `risk-map/yaml/frameworks.yaml` | textarea blocks | Expands into one textarea per applicable framework. Reserved for future template surfaces; not currently used in the five active sources. |

`{{*_FRAMEWORKS_LIST}}` and `{{FRAMEWORK_MAPPINGS}}` read from `frameworks.yaml`, not a JSON schema. The other placeholders are `PLACEHOLDER_MAPPINGS` entries in `scripts/hooks/issue_template_generator/template_renderer.py`; framework placeholders are handled by dedicated branches in `expand_placeholders`.

---

## Filtering

Two independent filter mechanisms reduce the raw schema enum before rendering.

### Deprecated filter (`yaml_source`)

When a mapping declares `yaml_source: (filename, collection_key)`, the generator loads the named YAML data file from `risk-map/yaml/` and removes any enum ID whose entry carries `deprecated: true`. This keeps the issue form current when personas or other entities are retired.

Example: `personaModelCreator` and `personaModelConsumer` are marked `deprecated: true` in `personas.yaml` and are therefore absent from all rendered persona checkbox lists.

### Context exclusion (`exclude_ids`)

When a mapping declares `exclude_ids: (id, ...)`, those IDs are unconditionally removed from the rendered output regardless of their deprecated status. Use this when a value is valid in one context (e.g., controls) but should never appear in another (e.g., risks).

### Compose order

Both filters apply in sequence, preserving original schema enum ordering:

```
final_ids = enum_ids - deprecated_ids (yaml_source) - exclude_ids
```

---

## Why two persona placeholders

`personaGovernance` belongs to the controls side of the persona model. Governance actors define policy and evaluate compliance; they implement security controls. Risks, by contrast, track which personas are **harmed** by a threat — governance personas are not typically in the threat path.

- `{{PERSONAS}}` — used in control templates; includes `personaGovernance`.
- `{{PERSONAS_FOR_RISKS}}` — used in risk templates; excludes `personaGovernance` via `exclude_ids: ("personaGovernance",)`.

See [submission-readiness-guide.md §3](../../risk-map/docs/contributing/submission-readiness-guide.md) for the authoritative persona usage rules.

---

## Adding a new placeholder or variant

1. Open `scripts/hooks/issue_template_generator/template_renderer.py`.
2. Add an entry to `PLACEHOLDER_MAPPINGS`:

   ```python
   "MY_NEW_PLACEHOLDER": {
       "schema_paths": [("myschema.schema.json", "definitions.thing.properties.id")],
       "field_type": "checkbox",          # or "dropdown" or None
       # Optional:
       "yaml_source": ("mydata.yaml", "things"),   # enables deprecated-filter
       "exclude_ids": ("thingToOmit",),             # per-context exclusion
   },
   ```

3. Add tests in `scripts/hooks/issue_template_generator/tests/test_template_renderer.py`.
4. Reference the placeholder in a source template via `{{MY_NEW_PLACEHOLDER}}`.
5. Run `uv run --locked --no-sync python scripts/generate_issue_templates.py` and review the output.
6. Commit the source template and the regenerated artifact together.

---

## Adding a new generated template

1. Create `scripts/TEMPLATES/<name>.template.yml`. The generator discovers all `*.template.yml` files via glob — no registration needed.
2. Determine the entity type (`risks`, `controls`, `components`, or `personas`) and confirm that `IssueTemplateGenerator._get_entity_type()` in `scripts/hooks/issue_template_generator/generator.py` maps the new filename to the right type. Add a mapping there if needed.
3. Use `{{PLACEHOLDER_NAME}}` tokens where dynamic values belong.
4. Run `uv run --locked --no-sync python scripts/generate_issue_templates.py` to generate the first version.
5. Commit the source template and the generated file together.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Regeneration produces an unexpected diff in a generated file | The source template was not updated; only the generated file was edited | Discard the generated change, edit the source template instead, then regenerate |
| A deprecated entry still appears in a rendered checkbox | The mapping has no `yaml_source` configured | Add `yaml_source` to the entry in `PLACEHOLDER_MAPPINGS` |
| Wrong personas in the risk template | Template uses `{{PERSONAS}}` instead of `{{PERSONAS_FOR_RISKS}}` | Replace `{{PERSONAS}}` with `{{PERSONAS_FOR_RISKS}}` in `new_risk.template.yml` |
| Hook says "validator not found in worktree" | Stale bash hook left over from before #211 migration | Reinstall the framework hook with `uv run --locked --no-sync pre-commit install --overwrite` |
| `check-jsonschema` fails after regeneration | Generated template has a structural issue | Run `uv run --locked --no-sync python scripts/generate_issue_templates.py --validate` and inspect the error |

---

**Related:**
- [Hook Validations](hook-validations.md) — Issue template generation step in the pre-commit hook
- [Validation Flow](validation-flow.md) — When each hook step runs
- [issue-templates-guide.md](../../risk-map/docs/contributing/issue-templates-guide.md) — Contributor-facing guide (different audience)
