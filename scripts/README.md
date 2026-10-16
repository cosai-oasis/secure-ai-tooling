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
- Framework mapping-value validation (purity, drift, catalogue membership)
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

- Manually generating the component graph
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
- `hooks/precommit/versionid_generator.py` - frameworks.yaml versionId generator (ADR-027 D2b)
- `hooks/precommit/validate_versionid_purity.py` - versionId purity validator (ADR-027 D2b/D2c)
- `hooks/precommit/validate_mapping_purity.py` - framework mapping-value purity validator (ADR-027 D4c)
- `hooks/precommit/validate_mapping_drift.py` - framework mapping-value drift validator (ADR-027 D5/D5a)
- `hooks/precommit/validate_mapping_catalogue.py` - framework mapping catalogue-membership validator (ADR-027 D5 Tier 2, ADR-038); checks each pinned id against the vendored catalogue of its edition
- `hooks/validate_issue_templates.py` - Issue template schema validation
- `generate_issue_templates.py` - Issue template generator from sources
- `framework_mapping_maintainer.py` - maintainer CLI to add/update/remove pinned framework mapping values (ADR-027 D4)
- `hooks/yaml_to_markdown.py` - Markdown table generation from YAML
- `tools/install-deps.sh` - Idempotent dependency installer; Step 8 invokes `pre-commit install` for the framework hook
- `tools/verify-deps.sh` - Verifies all required tools are installed and correct versions
- `tools/validate-all.sh` - Dev helper: runs every validator with `--force` for non-staged verification (no regeneration)
- `agents/content-reviewer.md` - Content review agent definition (LLM-neutral structured prompt)

**Vendored Framework Catalogues (`framework_catalogues/<framework>/`):**

Verbatim copies of upstream per-edition framework catalogues. They are the data
input of the Tier 2 catalogue-membership validator, which reads them locally;
no hook, CI job or validator fetches catalogue data (ADR-038). There is one
subdirectory per adjudicated framework; the adjudicated set is defined in the
validator, by its `ADJUDICATED_FRAMEWORKS` table (ADR-038 D5). The
`mitre-atlas/` subdirectory holds:

- `manifest.yaml` - verbatim copy of the upstream release manifest; used to resolve a registered version token to a release
- `ATLAS-<release>.yaml` - verbatim copy of the upstream catalogue for each registered edition (`version` plus every `priorVersions` entry)
- `SHA256SUMS` - sha256 record for `manifest.yaml` and every catalogue file; the validator verifies it before parsing anything and exits 2 on a mismatch
- `SOURCE` - upstream repository, the commit the files were copied from, and the licence (provenance for reviewers; not read by the validator)
- `LICENSE` - verbatim copy of the upstream licence, which must accompany the redistributed files

The root `.gitattributes` entry `scripts/framework_catalogues/** -text` exempts
the directory from end-of-line conversion so checked-out files stay
byte-identical to their recorded digests. Do not modify these files outside
a registry bump. Every registry bump of an adjudicated framework re-copies
all of its vendored files from one upstream commit, the existing catalogues
included, and regenerates `SHA256SUMS` (ADR-038 D7).

**Related Documentation:**

- [Risk Map Developer Guide](../risk-map/docs/developing.md) - Main contribution guide
- [Repository CONTRIBUTING.md](../CONTRIBUTING.md) - Branching strategy and PR workflow

**Schemas:**

- `../risk-map/schemas/` - JSON schemas for all YAML files
