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

# Flat xref tables (one row per mapping instead of grouped cells)
python3 scripts/hooks/yaml_to_markdown.py personas --format xref-controls --flat
python3 scripts/hooks/yaml_to_markdown.py personas --format xref-risks --flat
python3 scripts/hooks/yaml_to_markdown.py controls --format xref-risks --flat
python3 scripts/hooks/yaml_to_markdown.py controls --format xref-components --flat
```

## Table Formats

- `full` - Complete detail tables with all columns
- `summary` - Condensed tables (ID, Title, Description, Category)
- `xref-risks` - Cross-reference to risks (controls, personas)
- `xref-components` - Control-to-component cross-reference (controls only)
- `xref-controls` - Persona-to-control cross-reference (personas only)

## Flat XRef Tables

The `--flat` flag produces one row per mapping for any xref format. Standard xref tables group multiple IDs into a single cell with `<br>` separators, which causes inconsistent cell widths. Flat tables are easier to parse and produce uniform column widths.

The flag applies to `xref-controls`, `xref-risks`, and `xref-components` formats. It is silently ignored for `full` and `summary` formats.

## Output Files

- Components: `components-full.md`, `components-summary.md` (2 files)
- Controls: `controls-full.md`, `controls-summary.md`, `controls-xref-risks.md`, `controls-xref-components.md` (4 files)
- Risks: `risks-full.md`, `risks-summary.md` (2 files)
- Personas: `personas-full.md`, `personas-summary.md`, `personas-xref-controls.md`, `personas-xref-risks.md` (4 files)

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
