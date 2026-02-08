# Setup & Prerequisites

> **Dev Container users:** If you are using the VS Code Dev Container, all setup is handled automatically by `install-deps.sh` (including pre-commit hooks). See [risk-map/docs/setup.md](../../risk-map/docs/setup.md) for Dev Container instructions. The manual steps below are for contributors working outside the container.

## Git Hooks Setup

**Prerequisites:**

- Python 3.14 or higher
- Node.js 22+ and npm
- Chrome/Chromium browser (for SVG generation from Mermaid diagrams)

### Automated setup (recommended)

`install-deps.sh` installs all dependencies, pre-commit hooks, and Playwright Chromium in one step. It is idempotent — safe to re-run at any time.

```bash
# From the repository root — installs everything and verifies
./scripts/tools/install-deps.sh

# Preview what would be installed without making changes
./scripts/tools/install-deps.sh --dry-run
```

After installation, verify the environment:

```bash
./scripts/tools/verify-deps.sh
```

### Manual setup

If you prefer to install dependencies individually:

```bash
# Install required Python packages
pip install -r requirements.txt

# Install Node.js dependencies (prettier, mermaid-cli, etc.)
npm install

# Install the pre-commit hook
./scripts/install-precommit-hook.sh
```

**Platform-specific Chrome/Chromium setup:**

- **Mac/Windows/Linux x64**: Chrome automatically handled by puppeteer (bundled with mermaid-cli dependencies)
- **Linux ARM64**: Requires manual Chromium setup since Google Chrome is not available for ARM64:

  ```bash
  # Option 1: Use Playwright Chromium (recommended)
  ./scripts/install-precommit-hook.sh --install-playwright

  # Option 2: Install system Chromium
  sudo apt install chromium-browser  # Ubuntu/Debian

  # Option 3: Specify custom Chromium path during installation
  ./scripts/install-precommit-hook.sh
  ```

## Requirements

**Required packages** (from `requirements.txt`):

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

- `hooks/pre-commit` - The main git hook script that orchestrates all validations
- `hooks/validate_riskmap.py` - Component edge validation and graph generation
- `hooks/validate_control_risk_references.py` - Control-risk cross-reference validation
- `hooks/validate_framework_references.py` - Framework reference validation
- `hooks/yaml_to_markdown.py` - Markdown table generation from YAML
- `hooks/riskmap_validator/` - Python module with models, validator, graphing, and utilities
- `install-precommit-hook.sh` - Installs all hooks to your local `.git/hooks/` (supports `--auto` flag for non-interactive install)

---

**Related:**
- [Hook Validations](hook-validations.md) - What the pre-commit hook does
- [Troubleshooting](troubleshooting.md) - Installation and setup issues
