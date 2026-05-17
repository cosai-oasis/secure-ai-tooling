# Scripts

Development tools and utilities for this project.

---

## Documentation Index

### Getting Started

**[Setup & Prerequisites](docs/setup.md)**

- Installing Python, Node.js, and dependencies
- Installing pre-commit hooks
- Platform-specific configuration (Chrome/Chromium for ARM64)
- Required packages and dependencies

### Pre-commit Hooks

**[Hook Validations](docs/hook-validations.md)**

- What the pre-commit hook validates
- YAML schema validation, Prettier formatting, Ruff linting
- Component edge validation and graph generation
- Control-to-risk reference validation
- Framework reference validation
- Issue template generation and validation
- Mermaid SVG generation and markdown table generation

**[Validation Flow](docs/validation-flow.md)**

- Step-by-step commit flow
- When each validation runs
- Graph and table generation triggers

**[Manual Validation](docs/manual-validation.md)**

- Running validations with --force flag
- Validating unstaged files during development

### Manual Tools

**[Graph Generation](docs/graph-generation.md)**

- Manually generating component, control, and risk graphs
- Graph generation options and flags
- Debugging graph output

**[Table Generation](docs/table-generation.md)**

- Manually generating markdown tables from YAML
- Table formats (full, summary, cross-reference)
- Output files and debugging

### CI/CD

**[GitHub Actions Validation](docs/github-actions.md)**

- Automated PR validation
- Graph and table validation in CI/CD
- Handling validation failures
- Differences between pre-commit hooks and GitHub Actions

### Customization

**[Mermaid Graph Styling](docs/styling-configuration.md)**

- Customizing graph appearance via `mermaid-styles.yaml`
- Foundation design tokens and color schemes
- Graph layout and spacing configuration
- Common customization examples

### Agent-Assisted Review _(Experimental)_

**[Agent-Assisted Content Review](docs/agent-assisted-review.md)**

- Using the content-reviewer sub-agent for YAML quality checks
- LLM-neutral agent definitions in `agents/`
- Modes: diff (PR review), full (quality check), issue (proposal evaluation)

### Reference

**[Troubleshooting](docs/troubleshooting.md)**

- Installation issues
- Common validation errors (edge, control-risk, prettier, ruff)
- SVG and table generation errors
- Chrome/Chromium issues (especially ARM64)
- Debugging commands and manual testing

---

## Quick Links

**Key Files:**

- `../.pre-commit-config.yaml` - Declarative hook configuration (schemas, lint/format, validators, generators)
- `hooks/precommit/` - Wrapper scripts invoked by the framework (graphs, tables, SVGs, issue templates, prettier-yaml); each stages its output via `git add`
- `hooks/validate_riskmap.py` - Component edge validation and graph generation
- `hooks/validate_control_risk_references.py` - Control-risk cross-reference validation
- `hooks/validate_framework_references.py` - Framework reference validation
- `hooks/precommit/validate_workflow_uses_pinning.py` - GitHub Actions `uses:` pinning validation for ADR-024
- `hooks/validate_issue_templates.py` - Issue template schema validation
- `generate_issue_templates.py` - Issue template generator from sources
- `hooks/yaml_to_markdown.py` - Markdown table generation from YAML
- `tools/install-deps.sh` - Idempotent dependency installer; Step 8 invokes `uv run --locked --no-sync pre-commit install` for the framework hook
- `tools/verify-deps.sh` - Verifies all required tools are installed and correct versions
- `tools/validate-all.sh` - Dev helper: runs every validator with `--force` for non-staged verification (no regeneration)
- `agents/content-reviewer.md` - Content review agent definition (LLM-neutral structured prompt)

**Related Documentation:**

- [Risk Map Developer Guide](../risk-map/docs/developing.md) - Main contribution guide
- [Repository CONTRIBUTING.md](../CONTRIBUTING.md) - Branching strategy and PR workflow

**Schemas:**

- `../risk-map/schemas/` - JSON schemas for all YAML files
