# Validation Tools

This page covers all the manual validation commands and tools available for developing with the CoSAI Risk Map.

## Manual Edge Validation & Graph Generation

You can run edge validation and graph generation manually at any time:

```bash
# Validate only if components.yaml is staged for commit
python scripts/hooks/validate_riskmap.py

# Force validation regardless of git status
python scripts/hooks/validate_riskmap.py --force

# Generate component graph visualization
python scripts/hooks/validate_riskmap.py --to-graph ./my-graph.md --force

# Generate component graph with debug annotations
python scripts/hooks/validate_riskmap.py --to-graph ./debug-graph.md --debug --force
```

The validation script checks for:

- **Bidirectional edge consistency**: If Component A references Component B in its `to` edges, Component B must have Component A in its `from` edges
- **No isolated components**: Components should have at least one `to` or `from` edge
- **Valid component references**: All components referenced in edges must exist

**Automatic Graph Generation**: The pre-commit framework invokes the `regenerate-graphs` hook (`scripts/hooks/precommit/regenerate_graphs.py`) when `components.yaml` or `mermaid-styles.yaml` is staged. The generated pair is staged with `git add` so it lands in the same commit (Mode B auto-stage):

- **Component Graph**: When `components.yaml` or `mermaid-styles.yaml` is staged, generates `./risk-map/diagrams/risk-map-graph.md`
  - Uses Elk layout engine for automatic positioning and ranking
  - Organizes components into category-based subgraphs with configurable styling

The control-to-component and control-to-risk diagrams were withdrawn for low usage (#477); `controls-xref-components.md` and `controls-xref-risks.md` carry the same relationships in table form.

_See [scripts documentation](../../scripts/README.md) for more information on the git hooks and validation._

## Manual Graph Generation

Beyond automatic generation, you can manually generate the component graph using the validation script:

```bash
# Generate component relationship graph
python scripts/hooks/validate_riskmap.py --to-graph ./components.md --force
```

## Framework versionId Generation

The `regenerate-frameworks-versionid` pre-commit hook (`scripts/hooks/precommit/versionid_generator.py`) materializes the `versionId` field for every entry in `frameworks.yaml` per ADR-027 D2b:

```
versionId = id if version is null else f"{id}@{version}"
```

This is a generated-artifact hook in the same class as the table and graph generators (ADR-005/ADR-013): tooling writes the field, contributors never hand-author it. It pairs with `validate_versionid_purity.py` (see below), which guards the generated value against hand-edits. The hook triggers on `risk-map/yaml/frameworks.yaml` and auto-stages the updated file so the materialized `versionId` lands in the same commit as the source change.

**Manual invocation:**

```bash
# Materialize versionId for all framework entries (defaults to risk-map/yaml/frameworks.yaml)
python3 scripts/hooks/precommit/versionid_generator.py

# Operate on an explicit path (e.g. for testing against a copy)
python3 scripts/hooks/precommit/versionid_generator.py --path risk-map/yaml/frameworks.yaml
```

## Markdown Table Documentation

The `regenerate-tables` framework hook (`scripts/hooks/precommit/regenerate_tables.py`) automatically generates markdown tables from YAML files for easy documentation viewing:

**Automatic Generation:**

- **Triggered by**: Staging `components.yaml`, `controls.yaml`, or `risks.yaml`
- **Output location**: `risk-map/tables/`
- **Smart regeneration**: Cross-reference tables regenerated when dependencies change
- **Auto-staging**: Generated tables added to commit automatically

**Generation rules:**

- `components.yaml` → `components-full.md`, `components-summary.md`, and regenerates `controls-xref-components.md` (3 files)
- `risks.yaml` → `risks-full.md`, `risks-summary.md`, and regenerates `controls-xref-risks.md` (3 files)
- `controls.yaml` → all 4 formats: `controls-full.md`, `controls-summary.md`, `controls-xref-risks.md`, `controls-xref-components.md`

**Manual Generation:**

```bash
# Generate all formats for one type
python3 scripts/hooks/yaml_to_markdown.py components --all-formats
python3 scripts/hooks/yaml_to_markdown.py controls --all-formats

# Generate all types and formats (8 files total)
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats

# Generate to custom output directory
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats --output-dir /tmp/tables

# Generate specific format
python3 scripts/hooks/yaml_to_markdown.py controls --format xref-risks
python3 scripts/hooks/yaml_to_markdown.py components --format summary
```

**Pre-push drift check:**

```bash
# Verify committed tables match generated output without modifying the tree
./scripts/tools/validate-all.sh --check-generation
```

This strict mode generates tables in a temporary directory, compares them with
`risk-map/tables/`, and exits non-zero when drift is found. It does not update
tracked files or change the git index. Generator errors print to stdout
regardless of `--quiet`; only the generator's progress lines are suppressed.

**Available formats:**

- `full` - Complete tables with all columns (default)
- `summary` - Condensed: ID, Title, Description, Category
- `xref-risks` - Control-to-risk cross-reference (controls only)
- `xref-components` - Control-to-component cross-reference (controls only)

**Use cases:**

- Review component definitions in table format
- Export risk catalog for documentation
- Generate control mappings for compliance reports
- Create cross-reference documentation

## Manual Control-to-Risk Reference Validation

You can run control-to-risk reference validation at any time:

```bash
# Validate control-to-risk references if at least on of controls.yaml or risks.yaml is staged
python scripts/hooks/validate_control_risk_references.py

# Force control-to-risk references validation regardless of git status
python scripts/hooks/validate_control_risk_references.py --force
```

The control-to-risk validates cross-reference consistency between `controls.yaml` and `risks.yaml`:

- **Bidirectional consistency**: Ensures that if a control lists a risk, that risk also references the control
- **Isolated entry detection**: Finds controls with no risk references or risks with no control references
- **all or none awareness**: Will not flag controls that leverage the `all` or `none` risk mappings

## Manual Framework Reference Validation

You can run framework reference validation at any time:

```bash
# Validate framework references if frameworks.yaml, risks.yaml, or controls.yaml is staged
python scripts/hooks/validate_framework_references.py

# Force framework reference validation regardless of git status
python scripts/hooks/validate_framework_references.py --force
```

The framework reference validator ensures consistency between framework definitions and their usage:

- **Framework existence**: Verifies all framework IDs used in `mappings` exist in `frameworks.yaml`
- **Schema consistency**: Ensures framework IDs in YAML data match the enum in `frameworks.schema.json`
- **Required fields**: Validates that all framework definitions include required fields (`id`, `name`, `fullName`, `description`, `baseUri`)
- **No duplicates**: Detects duplicate framework IDs in framework definitions
- **Backward compatibility**: Passes validation for risks/controls without `mappings` fields

**Example output:**

```
🔍 Force checking framework references...
   Found staged frameworks.yaml, risks.yaml, and/or controls.yaml
   Validating framework references in: risk-map/yaml/frameworks.yaml, risk-map/yaml/risks.yaml, risk-map/yaml/controls.yaml
  ✅ Framework references are consistent
     - Found 4 valid frameworks: mitre-atlas, nist-ai-rmf, owasp-top10-llm, stride
     - Validated 16 risks with framework mappings
     - Validated 8 controls with framework mappings
✅ Framework reference validation passed for all files.
```

**Common validation errors:**

- `Framework 'X' references framework 'Y' which does not exist in frameworks.yaml` - The framework ID used in a mapping doesn't exist
- `Duplicate framework ID 'X' found in frameworks.yaml` - Multiple frameworks have the same ID
- `Framework 'X' is missing required field 'Y'` - A framework definition is incomplete

See the [Framework Guide](guide-frameworks.md) for detailed information on adding and using frameworks.

## Manual Framework Mapping Validators (ADR-027)

Four validators enforce the ADR-027 D2b/D4c/D5/D5a framework-mapping constraints. These run both as pre-commit hooks and in `scripts/tools/validate-all.sh`. `validate-all.sh` additionally runs content `check-jsonschema` against the four consumer schemas (`risks`, `controls`, `components`, `personas`), so the manual sweep rejects an unpinned mapping value the same way the per-file `schema:` pre-commit hooks do.

**versionId purity** (ADR-027 D2b/D2c) — asserts that the on-disk `versionId` in `frameworks.yaml` equals the derived value and that `supersedes`/`priorVersions` lineage fields are well-formed. Run it after manually editing `frameworks.yaml` to confirm the generator's output is intact:

```bash
python3 scripts/hooks/precommit/validate_versionid_purity.py

# Explicit path (same default, useful for pointing at a fixture)
python3 scripts/hooks/precommit/validate_versionid_purity.py --path risk-map/yaml/frameworks.yaml
```

**Mapping-value purity** (ADR-027 D4c) — checks that every framework mapping value in the four content files round-trips through the generator: values are generated by `framework_mapping_maintainer.py`, not hand-typed. A value that has a version delimiter (`@` or `:`) but fails round-trip is flagged as tampered. Post-#343 pinning is mandatory: a versioned framework value with no delimiter (an unpinned value) now **fails** — the ADR-027 D7/M1 "block" phase, matching `check-jsonschema`. Only STRIDE values are tokenless by design (an unversioned framework, so no version token):

```bash
# Defaults to all four content files
python3 scripts/hooks/precommit/validate_mapping_purity.py

# Explicit file list
python3 scripts/hooks/precommit/validate_mapping_purity.py \
    risk-map/yaml/risks.yaml \
    risk-map/yaml/controls.yaml \
    risk-map/yaml/components.yaml \
    risk-map/yaml/personas.yaml
```

**Mapping-value drift** (ADR-027 D5/D5a) — Tier-1 drift detection: classifies each mapping value as `skip`, `current`, `valid-but-superseded`, or `invalid` (legacy unpinned and unknown-framework values are `skip`ped by design — drift tracks currency, while "is it pinned at all" is owned by the purity validator and the strict schema; see [hook-validations.md §18](../../scripts/docs/hook-validations.md) for the full state table). Only `invalid` causes a non-zero exit. `valid-but-superseded` values (pinned to a `priorVersions` entry) are reported informationally for maintainer review but do not break CI:

```bash
# Defaults to all four content files
python3 scripts/hooks/precommit/validate_mapping_drift.py

# Explicit file list
python3 scripts/hooks/precommit/validate_mapping_drift.py \
    risk-map/yaml/risks.yaml \
    risk-map/yaml/controls.yaml \
    risk-map/yaml/components.yaml \
    risk-map/yaml/personas.yaml
```

**Mapping catalogue membership** (ADR-027 D5 Tier 2, ADR-038) — Tier-2 drift detection: for each value Tier 1 accepts, checks that its id exists in the edition its version token names, using the vendored per-edition catalogues under `scripts/framework_catalogues/`. Only frameworks in the validator's adjudicated table (`ADJUDICATED_FRAMEWORKS` in `validate_mapping_catalogue.py`, ADR-038 D5) are checked; a value of any framework outside that table is `skip`ped. A value whose id is absent from its pinned edition is `invalid`, and the detail line names any other registered edition that contains it. Before reading any value, the validator verifies the catalogues against `SHA256SUMS`; a digest mismatch or any other unreadable input exits 2 (see [hook-validations.md §19](../../scripts/docs/hook-validations.md)). `--force` is required: without it nothing is read and the exit is 0. `--block` makes an `invalid` value exit 1:

```bash
# Scans the four content files, frameworks.yaml and the vendored catalogues
python3 scripts/hooks/precommit/validate_mapping_catalogue.py --force --block
```

## Manual Prettier Formatting

You can run prettier formatting on YAML files manually:

```bash
# Format all YAML files in risk-map/yaml/
npx prettier --write risk-map/yaml/*.yaml

# Check formatting without modifying files
npx prettier --check risk-map/yaml/*.yaml
```

Prettier ensures consistent formatting across all YAML files in the `risk-map/yaml/` directory, automatically handling indentation, spacing, and other style conventions.

## Manual Ruff Linting

You can run ruff linting on Python files manually:

```bash
# Lint all Python files
ruff check .

# Lint specific directories
ruff check tools/ scripts/

# Auto-fix issues where possible
ruff check --fix .

# Check specific staged files
ruff check $(git diff --cached --name-only --diff-filter=ACM | grep '\.py$')
```

Ruff enforces Python code quality and style standards, catching potential issues before they make it into the repository.

---

**Related:** See [Graph Customization](graph-customization.md) to customize the appearance of generated graphs, or [CI/CD Validation](ci-cd.md) to learn about automatic validation in pull requests.
