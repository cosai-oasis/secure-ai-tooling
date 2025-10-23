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

# Generate control-to-component relationship graph
python scripts/hooks/validate_riskmap.py --to-controls-graph ./controls-graph.md --force
```

The validation script checks for:

- **Bidirectional edge consistency**: If Component A references Component B in its `to` edges, Component B must have Component A in its `from` edges
- **No isolated components**: Components should have at least one `to` or `from` edge
- **Valid component references**: All components referenced in edges must exist

**Automatic Graph Generation**: The pre-commit hook automatically generates graphs when relevant files are staged:

- **Component Graph**: When `components.yaml` is staged, generates `./risk-map/diagrams/risk-map-graph.md`
  - Uses Elk layout engine for automatic positioning and ranking
  - Organizes components into category-based subgraphs with configurable styling
- **Control Graph**: When `components.yaml` OR `controls.yaml` is staged, generates `./risk-map/diagrams/controls-graph.md`
  - Shows control-to-component relationships with optimization
  - Dynamic component clustering and multi-edge styling
- **Risk Graph**: When `components.yaml`, `controls.yaml` OR `risks.yaml` is staged, generates `./risk-map/diagrams/controls-to-risk-graph.md`
  - Maps controls to risks they mitigate with component context
  - Organizes risks into 5 color-coded category subgraphs
  - Visualizes three-layer relationships: risks → controls → components
- All generated graphs are automatically staged for inclusion in your commit

_See [scripts documentation](../../scripts/README.md) for more information on the git hooks and validation._

## Manual Graph Generation

Beyond automatic generation, you can manually generate both types of graphs using the validation script:

```bash
# Generate component relationship graph
python scripts/hooks/validate_riskmap.py --to-graph ./components.md --force

# Generate control-to-component graph
python scripts/hooks/validate_riskmap.py --to-controls-graph ./controls-graph.md --force

# Generate control-to-risk relationship graph
python scripts/hooks/validate_riskmap.py --to-risk-graph ./risk-graph.md --force

# Generate all three graph types
python scripts/hooks/validate_riskmap.py --to-graph ./components.md --to-controls-graph ./controls.md --to-risk-graph ./risk.md --force
```

## Markdown Table Documentation

The pre-commit hooks automatically generate markdown tables from YAML files for easy documentation viewing:

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

**Control Graph Features:**

- **Dynamic Component Clustering**: Automatically groups components that share multiple controls
- **Category Optimization**: Maps controls to entire categories when they apply to all components in that category
- **Multi-Edge Styling**: Uses different colors and patterns for controls with 3+ edges
- **Consistent Styling**: Color-coded categories and visual hierarchy
- **Mermaid Format**: Generates Mermaid-compatible diagrams ready for documentation

**Example Control Graph Output:**
The generated graph shows controls (grouped by category) connected to the components they protect, with optimization applied to reduce visual complexity while maintaining accuracy.

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
