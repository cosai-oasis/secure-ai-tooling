# Setup & Prerequisites

Before contributing to the Risk Map, ensure you have the necessary validation tools set up. You can set up your development environment either using the VS Code Dev Container (recommended) or through manual installation.

## Option 1: Using Dev Container (Recommended)

The repository includes a VS Code Dev Container configuration that provides a pre-configured development environment with all necessary dependencies.

**Prerequisites:**

- VS Code with the "Dev Containers" extension installed
- Docker Desktop or compatible container runtime
- Approximately 6GB of available disk space for the container image

**Setup:**

1. **Open the repository in VS Code**
2. **Reopen in Container**: When prompted (or use Command Palette: "Dev Containers: Reopen in Container")
3. **Wait for container build**: The first build creates the base image, then `install-deps.sh` runs automatically to install all runtime tools via mise
4. **Pre-commit hooks are installed automatically** as part of the container setup (via `install-deps.sh` Step 8). To re-install manually if needed:

   ```bash
   bash ./scripts/install-precommit-hook.sh
   ```

The Dev Container automatically provides:

- Python 3.14 with all requirements.txt dependencies (via mise)
- Node.js 22 with npm packages (prettier, mermaid-cli) (via mise)
- Playwright Chromium browser for SVG generation
- act tool for local GitHub Actions testing
- VS Code extensions: Mermaid preview, YAML validation, Ruff linting

Tool versions are managed by [mise](https://mise.jdx.dev/) and declared in `.mise.toml` at the repo root. The `install-deps.sh` script handles all runtime tool installation.

## Option 2: Manual Setup

If you prefer not to use the Dev Container or need to set up your environment manually:

**Prerequisites:**

- Python 3.14 or higher
- Node.js 22+ and npm
- Chrome/Chromium browser (for SVG generation from Mermaid diagrams)

1. **Install all dependencies (one-time setup)**:

   ```bash
   # From the repository root — installs everything including pre-commit hooks
   ./scripts/tools/install-deps.sh

   # Verify all tools are present and correct versions
   ./scripts/tools/verify-deps.sh
   ```

   The script is idempotent and supports `--dry-run` to preview changes. For individual package installation, see [scripts/docs/setup.md](../../scripts/docs/setup.md).

2. **Verify the hook is working**:
   ```bash
   # Make a test change to risk-map/yaml/components.yaml
   # Attempt to commit - the hook should run validation
   git add risk-map/yaml/components.yaml
   git commit -m "test commit"
   ```

## Platform Considerations for SVG Generation

The repository handles Mermaid diagrams with different approaches for local development versus GitHub Actions:

### Pre-commit Hooks (Local Development)

- **Automatic SVG Creation**: When Mermaid files (`.mmd`, `.mermaid`) are staged for commit, pre-commit hooks generate corresponding SVG files
- **Auto-staging**: Generated SVG files are automatically added to the commit
- **Location**: SVGs are created in `./risk-map/svg/` directory
- **Prerequisites**: Requires Chrome/Chromium browser and mermaid-cli (automatically handled in Dev Container)

### Platform-Specific Setup

**Note**: If using the Dev Container, Chrome/Chromium is pre-installed. For manual setup:

- **Mac/Windows/Linux x64**: Chrome automatically handled by puppeteer
- **Linux ARM64**: Requires manual Chromium setup:

  ```bash
  # Use the --install-playwright flag during setup
  ./scripts/install-precommit-hook.sh --install-playwright

  # Or install manually
  npx playwright install chromium --with-deps
  ```

---

**Next Steps:** See [Validation Tools](validation.md) for manual validation commands, or jump to the [General Contribution Workflow](workflow.md) to start contributing.
