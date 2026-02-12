# Manual Table Generation

Generate markdown tables from YAML files using the table generator script:

```bash
# Generate all formats for a single type
python3 scripts/hooks/yaml_to_markdown.py components --all-formats
# Output: components-full.md, components-summary.md

python3 scripts/hooks/yaml_to_markdown.py controls --all-formats
# Output: controls-full.md, controls-summary.md, controls-xref-risks.md, controls-xref-components.md

# Generate specific format
python3 scripts/hooks/yaml_to_markdown.py controls --format summary
python3 scripts/hooks/yaml_to_markdown.py controls --format xref-risks

# Generate all types, all formats (8 files)
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats

# Generate to custom output directory
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats --output-dir /tmp/tables

# Custom output file (single type, single format only)
python3 scripts/hooks/yaml_to_markdown.py components --format full -o custom.md

# Quiet mode
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats --quiet
```

## Table Formats

- `full` - Complete detail tables with all columns
- `summary` - Condensed tables (ID, Title, Description, Category)
- `xref-risks` - Control-to-risk cross-reference (controls only)
- `xref-components` - Control-to-component cross-reference (controls only)

## Output Files

- Components: `components-full.md`, `components-summary.md` (2 files)
- Controls: `controls-full.md`, `controls-summary.md`, `controls-xref-risks.md`, `controls-xref-components.md` (4 files)
- Risks: `risks-full.md`, `risks-summary.md` (2 files)

## Debugging Table Generation

Run table generation manually to test:

```bash
# Test component table generation
python3 scripts/hooks/yaml_to_markdown.py components --all-formats

# Test controls table generation (all 4 formats)
python3 scripts/hooks/yaml_to_markdown.py controls --all-formats

# Test with verbose output
python3 scripts/hooks/yaml_to_markdown.py controls --all-formats
```

---

**Related:**
- [Hook Validations](hook-validations.md) - Automatic table generation during commits
- [GitHub Actions](github-actions.md) - Table validation in CI/CD
- [Troubleshooting](troubleshooting.md) - Table generation errors
