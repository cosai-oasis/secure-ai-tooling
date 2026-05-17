# Template Synchronization Procedures

This document explains how GitHub issue templates stay synchronized with JSON schemas and YAML data files in the CoSAI Risk Map repository. It provides guidance for both contributors and maintainers on managing template updates.

## Table of Contents

1. [Overview](#overview)
2. [Schema Evolution Workflow](#schema-evolution-workflow)
3. [Manual Synchronization Procedures](#manual-synchronization-procedures)
4. [Two-Week Sync Lag](#two-week-sync-lag)
5. [Testing Strategies](#testing-strategies)
6. [Automated Workflows](#automated-workflows)
7. [Troubleshooting](#troubleshooting)

---

## Overview

### The Challenge

GitHub issue templates (`.github/ISSUE_TEMPLATE/*.yml`) contain dropdown menus and checkbox options that must match enums defined in JSON schemas (`risk-map/schemas/*.schema.json`) and data from YAML files (`risk-map/yaml/*.yaml`).

When schemas or YAML files change, templates may need updates to stay synchronized.

### Types of Changes

**Schema Changes Requiring Template Updates:**

- Adding/removing enum values (e.g., new control category, new risk ID)
- Adding/removing required fields
- Changing field descriptions or constraints
- Adding new cross-reference relationships

**Schema Changes NOT Requiring Template Updates:**

- Documentation updates in schema descriptions
- Constraint changes that don't affect dropdowns
- Internal validation rule changes

---

## Schema Evolution Workflow

### When Do Templates Need Updates?

Templates must be updated when:

#### 1. Enum Additions/Removals

**Affects:** Dropdown menus and checkbox options in templates

**Examples:**

- New control category added to `controls.schema.json`
- New risk ID added to `risks.schema.json`
- New component category added to `components.schema.json`
- New framework added to `frameworks.schema.json`

**Templates to Update:**

- **`new_control.yml`** - If control categories change
- **`new_risk.yml`** - If risk categories change
- **`new_component.yml`** - If component categories change
- Framework mappings in multiple templates if frameworks change

#### 2. Required Field Changes

**Affects:** Field validation (marked with \* in templates)

**Examples:**

- Previously optional field becomes required
- Required field becomes optional
- New required field added to schema

**Templates to Update:**

- Corresponding `new_*.yml` templates
- May affect validation blocks in templates

#### 3. Framework Applicability Changes 

**Affects:** Which framework mapping fields appear in templates

**Examples:**

- STRIDE becomes applicable to controls (currently only risks)
- New framework added that applies to multiple entity types

**Templates to Update:**

- All templates with framework mapping sections

---

## Two-Week Sync Lag

### The Governance Process

The CoSAI Risk Map uses a two-stage governance process:

1. **Technical Review** (develop branch)
   - Schema changes reviewed by technical maintainers
   - Merged to `develop` branch after approval
   - Available for development and testing

2. **Community Review** (main branch)
   - ~2 weeks after `develop` merge
   - Community review period
   - Merged to `main` branch after approval

### Impact on Templates

**Problem:** GitHub issue templates are served from the `main` branch.

**Result:** Template dropdown options lag behind `develop` by up to 2 weeks.

**Timeline Example:**

```
Day 0:  New enum added to controls.schema.json
Day 0:  Schema + template changes merge to develop
Day 0-14: develop branch has updated template
Day 14: develop merges to main
Day 14+: main branch has updated template (available to users)
```

### User Impact

**For Contributors:**

If you're proposing an entity using a newly added enum:

- **Option 1:** Wait ~2 weeks for `develop` → `main` merge
- **Option 2:** Use free-form text fields (most templates have both dropdowns and textareas)
- **Option 3:** Note in "Additional Context" that you're using an enum from `develop`

**For Maintainers:**

- Clearly communicate sync lag to contributors
- Accept proposals using valid-but-not-yet-in-dropdown values
- Prioritize template updates when merging significant schema changes

### Mitigation Strategies

**Current:**

- Documentation explains the lag (this document + issue-templates-guide.md)
- Templates provide free-form alternatives to dropdowns
- Maintainers accommodate early adopters

---

## Automated Template Regeneration

**Templates automatically regenerate when you commit changes to template dependencies.**

### Pre-Commit Hook Integration

When you modify any template dependency files, the pre-commit hook:

1. Detects changes to:
   - Template sources: `scripts/TEMPLATES/*.template.yml`
   - Schema files: `risk-map/schemas/*.schema.json`
   - Framework configuration: `risk-map/yaml/frameworks.yaml`
2. Automatically runs the generator
3. Updates `.github/ISSUE_TEMPLATE/` files
4. Stages the generated templates
5. Includes them in your commit

**You don't need to manually run the generator - it happens automatically!**

This ensures templates always stay synchronized with all their dependencies. The pre-commit hook prevents template drift by regenerating templates whenever schemas, frameworks, or template sources change.

### Manual Generation (Optional)

For testing or verification, you can manually generate templates:

**Usage:**

```bash
# Generate all templates
uv run --locked --no-sync python scripts/generate_issue_templates.py

# Dry-run (show diffs without modifying)
uv run --locked --no-sync python scripts/generate_issue_templates.py --dry-run

# Generate specific template
uv run --locked --no-sync python scripts/generate_issue_templates.py --template new_control

# Validate synchronization
uv run --locked --no-sync python scripts/generate_issue_templates.py --validate
```

---

## Template Validation

**Templates are automatically validated before commit and in CI/CD pipelines.**

### GitHub Config File Validator

**Goal:** Ensure all issue templates and `dependabot.yml` conform to their respective schema requirements

#### Validator Script

**File:** `scripts/hooks/validate_issue_templates.py`

Validates issue templates against GitHub schemas and `dependabot.yml` against the `vendor.dependabot` schema using `check-jsonschema`:

```bash
# Validate all config files (manual use)
uv run --locked --no-sync python scripts/hooks/validate_issue_templates.py --force

# Validate staged files only (pre-commit)
uv run --locked --no-sync python scripts/hooks/validate_issue_templates.py

# Quiet mode (errors only)
uv run --locked --no-sync python scripts/hooks/validate_issue_templates.py --force --quiet
```

### Pre-Commit Hook Integration

**Config:** `.pre-commit-config.yaml` (hooks `regenerate-issue-templates` and `validate-issue-templates`)

The validator and generator are integrated as framework hooks. The `regenerate-issue-templates` wrapper (`scripts/hooks/precommit/regenerate_issue_templates.py`) runs first when any template source, schema, or `frameworks.yaml` is staged; it regenerates and `git add`s the output directory. The `validate-issue-templates` hook then runs `scripts/hooks/validate_issue_templates.py` against the staged files and blocks the commit on failure.

### Usage Examples

**For Contributors:**

```bash
# Before committing template changes
uv run --locked --no-sync python scripts/hooks/validate_issue_templates.py --force

# Should output:
# ✅ All GitHub config files passed validation
```

**For Maintainers:**

```bash
# Pre-commit hook runs automatically
git add .github/ISSUE_TEMPLATE/new_component.yml
git commit -m "Update new_component template"
# → Validation runs automatically
# → Commit succeeds if validation passes
# → Commit blocked if validation fails

# GitHub Actions runs automatically on PR
# - Validates all templates
# - Detects template drift
# - Runs test suite
# - Posts summary to PR
```

---

## Troubleshooting

### Common Drift Scenarios

#### Scenario 1: New Enum Added to Schema, Template Not Updated

**Symptoms:**

- User reports dropdown missing option
- New entity proposals reference invalid values

**Detection:**

```bash
# Compare schema enums to template options
# (manual comparison currently, automated in future)
```

**Resolution:**

1. Extract new enum from schema
2. Add to template dropdown options
3. Validate YAML syntax and GitHub schema
4. Format with prettier
5. Commit and deploy

#### Scenario 2: Template Has Outdated Options

**Symptoms:**

- Template shows enum that was removed from schema
- Schema validation fails for old proposals

**Detection:**

```bash
# Review schema changelog
# Compare template options to current schema
```

**Resolution:**

1. Remove outdated option from template
2. Check if any open issues use the removed option
3. Update or close affected issues
4. Commit template update

#### Scenario 3: Template Validation Fails

**Symptoms:**

```
Additional properties are not allowed ('validations' was unexpected)
```

**Cause:** `validations` block added to unsupported field type (e.g., `checkboxes`)

**Resolution:**

```yaml
# ❌ Wrong - validations not allowed on checkboxes
- type: checkboxes
  id: personas
  attributes:
    label: Applicable Personas*
    options:
      - label: Model Provider
  validations:
    required: true # <- NOT ALLOWED

# ✅ Correct - required on individual checkbox options
- type: checkboxes
  id: personas
  attributes:
    label: Applicable Personas*
    options:
      - label: Model Provider
        required: true # <- ALLOWED
```

#### Scenario 4: Reference Links Broken

**Symptoms:**

- Template links to `../../risk-map/tables/components-summary.md` return 404

**Causes:**

- Table file renamed/moved/deleted
- Relative path incorrect

**Detection:**

```bash
# Check if linked file exists
ls risk-map/tables/components-summary.md
```

**Resolution:**

1. Locate current table file location
2. Update relative path in template
3. Test link in GitHub UI
4. Commit fix

#### Scenario 5: Framework Mapping Mismatch

**Symptoms:**

- Template shows STRIDE for controls (should be risks only)
- Template shows NIST AI RMF for risks (should be controls only)

**Cause:** Incorrect framework applicability configuration

**Resolution:**

The framework applicability system is fully automated:

1. Generator reads `applicableTo` from frameworks.yaml automatically
2. Templates are dynamically filtered based on entity type
3. Framework mappings update automatically when frameworks.yaml changes
4. No manual configuration needed

**Verification:**

1. Check frameworks.yaml for correct `applicableTo` values
2. Regenerate templates to apply changes
3. Verify correct frameworks appear in each template type

---

## Maintainer Checklist

When reviewing PRs with schema changes:

- [ ] Identify which templates are affected
- [ ] Verify template updates included in same PR
- [ ] Check YAML syntax validation passes
- [ ] Check GitHub schema validation passes
- [ ] Check prettier formatting passes
- [ ] Verify enum values match schema exactly
- [ ] Verify required field changes reflected
- [ ] Verify reference links still work
- [ ] Verify bidirectionality messaging preserved
- [ ] Test template rendering in GitHub UI (if major change)

---

## Related Documentation

- [Issue Templates Guide](./issue-templates-guide.md) - User-facing guide for all templates
- [Contributing Guide](../../../../CONTRIBUTING.md) - Overall contribution workflow
- [Development Guide](../developing.md) - Development setup and procedures

---

## Questions?

If you encounter template synchronization issues not covered in this document:

1. Check existing issues for similar problems
3. Open an issue with the `infrastructure` label
4. Tag maintainers for assistance

