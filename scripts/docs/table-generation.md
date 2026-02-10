# Manual Table Generation

Generate markdown tables from YAML files using the table generator script:

```bash
# Generate all formats for a single type (--flat produces one-row-per-mapping xref tables)
python3 scripts/hooks/yaml_to_markdown.py components --all-formats
# Output: components-full.md, components-summary.md

python3 scripts/hooks/yaml_to_markdown.py controls --all-formats --flat
# Output: controls-full.md, controls-summary.md, controls-xref-risks.md, controls-xref-components.md

# Generate specific format
python3 scripts/hooks/yaml_to_markdown.py controls --format summary
python3 scripts/hooks/yaml_to_markdown.py controls --format xref-risks --flat

# Generate all types, all formats (12 files)
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats --flat

# Generate to custom output directory
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats --flat --output-dir /tmp/tables

# Custom output file (single type, single format only)
python3 scripts/hooks/yaml_to_markdown.py components --format full -o custom.md

# Quiet mode
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats --flat --quiet
```

## Table Formats

- `full` - Complete detail tables with all columns
- `summary` - Condensed tables (ID, Title, Description, Category)
- `xref-risks` - Cross-reference to risks (controls, personas)
- `xref-components` - Control-to-component cross-reference (controls only)
- `xref-controls` - Persona-to-control cross-reference (personas only)

## Flat XRef Tables

The `--flat` flag produces one row per mapping for any xref format. This is the committed format for all xref tables in the repository. The pre-commit hook and CI workflow both use `--flat` when generating tables.

Standard (non-flat) xref tables group multiple IDs into a single cell with `<br>` separators, which causes inconsistent cell widths. Flat tables are easier to parse and produce uniform column widths.

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

# Test controls table generation (all 4 formats, flat xref)
python3 scripts/hooks/yaml_to_markdown.py controls --all-formats --flat

# Test with verbose output
python3 scripts/hooks/yaml_to_markdown.py controls --all-formats --flat
```

---

**Related:**
- [Hook Validations](hook-validations.md) - Automatic table generation during commits
- [GitHub Actions](github-actions.md) - Table validation in CI/CD
- [Troubleshooting](troubleshooting.md) - Table generation errors
