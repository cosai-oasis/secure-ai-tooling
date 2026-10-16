# Validation Flow

When you commit changes, the pre-commit framework reads `.pre-commit-config.yaml`
at the repo root, selects hooks whose `files:` regex matches the staged set,
and runs them in declaration order. The sequence below covers selected
stages and does not list every hook; `.pre-commit-config.yaml` is the
authoritative list. Each hook only runs when its trigger files are staged; unused
hooks show `(no files to check) Skipped` in the output.

1. **Schema Validation** — one `check-jsonschema` hook per yaml/schema pair
   (9 pairs: actor-access, components, controls, frameworks, impact-type,
   lifecycle-stage, mermaid-styles, personas, risks), plus a dedicated hook
   for the archived legacy self-assessment pair under
   `risk-map/(yaml|schemas)/archive/` (per ADR-021 D6).
2. **Schema Meta-Validation** — `check-metaschema` validates each
   `risk-map/schemas/*.schema.json` is itself a structurally valid JSON
   Schema against its declared `$schema` metaschema.
3. **Schema Master Trigger** — when `risk-map/schemas/riskmap.schema.json`
   itself is staged, every yaml is re-validated against its schema.
4. **Prettier Formatting** — `prettier-yaml` wrapper formats yamls under
   `risk-map/yaml/` and `git add`s the reformatted output (Mode B auto-stage).
5. **Ruff Lint** — `ruff` checks staged Python files.
6. **Ruff Format** — `ruff-format` formats staged Python files.
7. **Component Edge Validation** — `validate_riskmap.py` runs when
   `components.yaml`, `controls.yaml`, `risks.yaml`, `mermaid-styles.yaml`,
   or `components.schema.json` is staged.
8. **Control-to-Risk Reference Validation** — `validate_control_risk_references.py`
   runs when `controls.yaml` or `risks.yaml` is staged.
9. **Framework Reference Validation** — `validate_framework_references.py`
   runs when `controls`, `frameworks`, `personas`, or `risks` yaml is staged.
10. **GitHub Actions `uses:` Pinning Validation** —
    `validate_workflow_uses_pinning.py` runs when `.github/workflows/*.yml`
    or nested workflow `.yml` files are staged.
11. **Issue Template Regeneration** — `regenerate_issue_templates.py` runs
    when any template source, any schema, or `frameworks.yaml` is staged;
    generates `.github/ISSUE_TEMPLATE/*.yml` and stages them.
12. **Issue Template Validation** — `validate_issue_templates.py` runs when
    anything under `.github/ISSUE_TEMPLATE/` or `scripts/TEMPLATES/` is
    staged (including the files just regenerated in step 11).
13. **Framework Mapping Catalogue Membership** —
    `validate_mapping_catalogue.py --force --block` runs when a content YAML,
    `frameworks.yaml`, `frameworks.schema.json`, the validator or its imported
    modules, or anything under `scripts/framework_catalogues/` is staged. It
    checks that each pinned MITRE ATLAS value's id exists in the edition its
    token names, reading the vendored, checksummed catalogues (ADR-027 D5
    Tier 2, ADR-038). It scans its full read-set rather than staged
    filenames.
14. **Graph Regeneration** — `regenerate_graphs.py` produces the component
    relationship graph (1 markdown + 1 mermaid output) when `components.yaml`
    or `mermaid-styles.yaml` is staged. The output pair is `git add`-ed on
    success.
15. **Table Regeneration** — `regenerate_tables.py` regenerates 8 table
    outputs across 4 triggers (see `scripts/docs/table-generation.md`).
16. **SVG Regeneration** — `regenerate_svgs.py` converts
    `risk-map/diagrams/*.mmd`/`*.mermaid` files to SVG, including diagrams
    staged in the index by `components.yaml`/`mermaid-styles.yaml` changes
    via chained-generator discovery (ADR-005 Addendum 2026-09-28).

The commit is blocked if any hook returns non-zero.

## Running the full sequence manually

```bash
# Against the working tree (does NOT require staged files):
pre-commit run --all-files

# Against only staged files (same as what git commit does):
pre-commit run
```

Note: `pre-commit run --all-files` will also run the generators, which may
modify derivatives in your working tree. To validate without regeneration,
use `scripts/tools/validate-all.sh` (see [Manual Validation](manual-validation.md)).

---

**Related:**
- [Hook Validations](hook-validations.md) — Details of each hook
- [Manual Validation](manual-validation.md) — Running validators without committing
- [Troubleshooting](troubleshooting.md) — Handling validation failures
