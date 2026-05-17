# CI/CD Validation

The repository includes automated GitHub Actions that validate all pull requests against the same standards as the local pre-commit framework hooks (configured in `.pre-commit-config.yaml`).

## Automated PR Validation

When you create a pull request, GitHub Actions automatically runs:

- **YAML Schema Validation**: All YAML files are validated against their JSON schemas
- **YAML Format Validation**: Ensures prettier formatting compliance
- **Python Code Quality**: Runs ruff linting on modified Python files
- **Component Edge Consistency**: Verifies bidirectional component relationships
- **Control-Risk Reference Integrity**: Validates control-risk cross-references
- **Graph Validation**: Generates and compares all three graph types
- **GitHub Config Validation**: Validates issue templates against GitHub schemas and `dependabot.yml` against `vendor.dependabot` schema

## Graph Validation in CI

The GitHub Actions workflow performs comprehensive graph validation:

1. **Generation**: Creates fresh graphs using `validate_riskmap.py`
2. **Comparison**: Compares generated graphs against committed versions in your PR
3. **Validation**: Ensures graphs are up-to-date with YAML changes
4. **Diff Output**: Provides detailed differences if validation fails

**Graphs Validated:**

- Component relationship graph (`./risk-map/diagrams/risk-map-graph.md`)
- Control-to-component graph (`./risk-map/diagrams/controls-graph.md`)
- Controls-to-risk graph (`./risk-map/diagrams/controls-to-risk-graph.md`)

## Handling CI Validation Failures

If GitHub Actions reports graph validation failures:

```bash
# Most common fix: regenerate graphs locally
uv run --locked --no-sync python scripts/hooks/validate_riskmap.py --to-graph ./risk-map/diagrams/risk-map-graph.md --force
uv run --locked --no-sync python scripts/hooks/validate_riskmap.py --to-controls-graph ./risk-map/diagrams/controls-graph.md --force
uv run --locked --no-sync python scripts/hooks/validate_riskmap.py --to-risk-graph ./risk-map/diagrams/controls-to-risk-graph.md --force

# Commit the updated graphs
git add risk-map/diagrams/risk-map-graph.md risk-map/diagrams/controls-graph.md risk-map/diagrams/controls-to-risk-graph.md
git commit -m "Update generated graphs to reflect YAML changes"
git push
```

The CI validation ensures that all contributions maintain consistency and that generated documentation stays synchronized with the underlying data.

## SVG Generation from Mermaid Diagrams

The repository handles Mermaid diagrams with different approaches for local development versus GitHub Actions:

### GitHub Actions (Pull Request Validation)

- **Syntax Validation**: Ensures all Mermaid files compile successfully
- **Preview Generation**: Creates SVG previews attached as PR comments
- **Error Reporting**: Provides detailed error messages for syntax issues
- **Does NOT generate**: GitHub Actions do not create SVG files for commit

### Pre-commit Hooks vs GitHub Actions

**Local Development (Pre-commit Hooks):**
- Automatic SVG creation when Mermaid files are staged
- SVGs auto-staged for inclusion in commits
- Requires Chrome/Chromium browser and mermaid-cli
- SVGs stored in `./risk-map/svg/` directory

**GitHub Actions:**
- Validates Mermaid syntax only
- Generates preview SVGs for review (not committed)
- No local browser requirements
- Ensures diagram syntax is valid across the project

See [Setup & Prerequisites](setup.md) for platform-specific SVG generation configuration.

---

**Related:** See [Validation Tools](validation.md) for local validation commands, or [Troubleshooting](troubleshooting.md) for help with CI failures.
