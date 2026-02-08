# GitHub Actions Validation

In addition to local pre-commit validation, the repository includes GitHub Actions that run validation on pull requests:

## Automated PR Validation

**Automated PR Validation includes:**

- **YAML Schema Validation**: Validates all YAML files against their JSON schemas
- **YAML Format Validation**: Checks prettier formatting compliance
- **Python Linting**: Runs ruff linting on all Python files
- **Component Edge Validation**: Verifies component relationship consistency
- **Control-Risk Reference Validation**: Checks control-risk cross-reference integrity
- **Graph Validation**: Generates and compares graphs against committed versions
  - Component graph (`./risk-map/diagrams/risk-map-graph.md`)
  - Control graph (`./risk-map/diagrams/controls-graph.md`)
  - Controls-to-risk graph (`./risk-map/diagrams/controls-to-risk-graph.md`)
- **Mermaid SVG Validation**: Validates Mermaid diagram syntax and generates SVG previews
- **Markdown Table Validation**: Generates and compares markdown tables against committed versions
  - Components tables (`components-full.md`, `components-summary.md`)
  - Risks tables (`risks-full.md`, `risks-summary.md`)
  - Controls tables (`controls-full.md`, `controls-summary.md`, `controls-xref-risks.md`, `controls-xref-components.md`)

## Different Roles

**Pre-commit hooks**:
- Generate SVG files from Mermaid diagrams and stage them
- Generate markdown tables from YAML files and stage them

**GitHub Actions**:
- Validate Mermaid syntax and provide SVG previews in PR comments (does not generate files for commit)
- Validate that markdown tables match generated versions (does not generate files for commit)

## Graph Validation Process

- GitHub Actions generates fresh graphs using the validation script
- Compares generated graphs with the committed versions in the PR
- Fails the build if graphs don't match, indicating they need to be regenerated
- Provides diff output showing exactly what differences were found

## When Graph Validation Fails

```bash
# The most common cause is missing graph regeneration
# Fix by running locally and committing the updated graphs:

# For component graph issues:
python3 scripts/hooks/validate_riskmap.py --to-graph ./risk-map/diagrams/risk-map-graph.md --force

# For control graph issues:
python3 scripts/hooks/validate_riskmap.py --to-controls-graph ./risk-map/diagrams/controls-graph.md --force

# For controls-to-risk graph issues:
python3 scripts/hooks/validate_riskmap.py --to-risk-graph ./risk-map/diagrams/controls-to-risk-graph.md --force

# Then commit the updated graphs:
git add risk-map/diagrams/risk-map-graph.md risk-map/diagrams/controls-graph.md risk-map/diagrams/controls-to-risk-graph.md
git commit -m "Update generated graphs"
```

## Table Validation Process

- GitHub Actions generates fresh markdown tables from YAML files
- Compares generated tables with the committed versions in the PR
- Fails the build if tables are missing or don't match, indicating they need to be regenerated
- Provides diff output showing exactly what differences were found

## When Table Validation Fails

```bash
# The most common cause is missing table regeneration
# Fix by running locally and committing the updated tables:

# Generate all table files (recommended)
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats

# Or generate specific tables:
python3 scripts/hooks/yaml_to_markdown.py components --all-formats
python3 scripts/hooks/yaml_to_markdown.py risks --all-formats
python3 scripts/hooks/yaml_to_markdown.py controls --all-formats

# Then commit the updated tables:
git add risk-map/tables/*.md
git commit -m "Update markdown tables"
```

---

**Related:**
- [Hook Validations](hook-validations.md) - What pre-commit hooks validate
- [Graph Generation](graph-generation.md) - Generating graphs manually
- [Table Generation](table-generation.md) - Generating tables manually
- [Troubleshooting](troubleshooting.md) - Handling validation failures
