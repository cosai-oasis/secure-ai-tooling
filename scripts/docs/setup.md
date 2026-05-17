# Setup & Prerequisites

> **Dev Container users:** If you are using the VS Code Dev Container, all setup is handled automatically by `install-deps.sh` (including pre-commit hooks). See [risk-map/docs/setup.md](../../risk-map/docs/setup.md) for Dev Container instructions. The manual steps below are for contributors working outside the container.

## Prerequisites

**System requirements for `install-deps.sh`:**

- `curl` — used to install mise and act
- `sudo` with passwordless (NOPASSWD) access — used to install act; if unavailable, act installation is skipped but all other steps succeed
- `bash` — the script uses bash-specific features (parameter expansion, arrays)

**Runtime tools** (installed automatically by `install-deps.sh`, or install manually):

- Python 3.14 or higher
- uv 0.11.14
- Node.js 22+ and npm
- Chrome/Chromium browser (for SVG generation from Mermaid diagrams)

## Git Hooks Setup

### Automated setup (recommended)

`install-deps.sh` installs all dependencies, pre-commit hooks, and Playwright Chromium in one step. It is idempotent — safe to re-run at any time.

```bash
# From the repository root — installs everything and verifies
./scripts/tools/install-deps.sh

# Preview what would be installed without making changes
./scripts/tools/install-deps.sh --dry-run
```

After installation, activate mise in your current shell (new shells pick this up automatically from `~/.bashrc`):

```bash
source ~/.bashrc
# or: eval "$(mise activate bash)"
```

Verify the environment:

```bash
./scripts/tools/verify-deps.sh
```

### Manual setup

If you prefer to install dependencies individually:

```bash
# Install required Python packages into the project .venv (includes pre-commit framework)
uv sync --locked

# Install Node.js dependencies (prettier, mermaid-cli, etc.)
npm ci

# Install the pre-commit framework hook into .git/hooks/pre-commit
uv run --locked --no-sync pre-commit install
```

**Platform-specific Chrome/Chromium setup:**

The `regenerate-svgs` hook converts Mermaid diagrams to SVGs via `npx mmdc`,
which needs a Chromium binary. The hook self-discovers it at runtime:

1. If `CHROMIUM_PATH` is set in your environment, it is used verbatim
2. On Linux ARM64, it auto-discovers Playwright's bundled Chromium under
   `$PLAYWRIGHT_BROWSERS_PATH` (or `~/.cache/ms-playwright` if unset)
3. Otherwise, mmdc's bundled detection runs (works on Mac / Windows /
   Linux x64 with system Chrome)

For Linux ARM64 contributors, ensure Playwright Chromium is installed
(`install-deps.sh` does this automatically; manual: `npx playwright install chromium`).

## Requirements

**Required packages** (from `pyproject.toml`, locked by `uv.lock`):

- `PyYAML` - YAML file parsing and manipulation
- `check-jsonschema` - JSON schema validation for YAML files
- `pytest` - Testing framework for validation scripts
- `ruff` - Python linting and formatting

**Additional dependencies** (from `package.json`):

- `prettier` - Code formatting for YAML files
- `@mermaid-js/mermaid-cli` - Converts Mermaid diagrams to SVG files
- `playwright` - Provides Chromium browser for ARM64 Linux (optional)
- `puppeteer-core` - Browser automation library used by mermaid-cli

## Hook Files

Hooks are configured declaratively in `.pre-commit-config.yaml` at the repo
root and installed via `uv run --locked --no-sync pre-commit install`. Validators and generators live
under `scripts/hooks/`:

- `hooks/precommit/` - Wrapper scripts invoked by the framework (graphs,
  tables, SVGs, issue templates, prettier-yaml). Each wrapper runs its
  underlying tool and `git add`s the output (Mode B auto-stage).
- `hooks/validate_riskmap.py` - Component edge validation and graph generation
- `hooks/validate_control_risk_references.py` - Control-risk cross-reference validation
- `hooks/validate_framework_references.py` - Framework reference validation
- `hooks/validate_issue_templates.py` - Issue template and dependabot.yml schema validation
- `hooks/yaml_to_markdown.py` - Markdown table generation from YAML
- `hooks/riskmap_validator/` - Python module with models, validator, graphing, and utilities

---

**Related:**
- [Hook Validations](hook-validations.md) - What the pre-commit hook does
- [Troubleshooting](troubleshooting.md) - Installation and setup issues
