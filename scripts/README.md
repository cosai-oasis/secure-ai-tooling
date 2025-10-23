# Scripts

Development tools and utilities for this project.

## Git Hooks

### Setup

**Prerequisites:**

- Python 3.10 or higher
- Node.js 18+ and npm
- Chrome/Chromium browser (for SVG generation from Mermaid diagrams)

Install dependencies and pre-commit hook (one-time setup):

```bash
# Install required Python packages
pip install -r requirements.txt

# Install Node.js dependencies (prettier, mermaid-cli, etc.)
npm install

# Install ruff (Python linter)
pip install ruff

# Install the pre-commit hook
./install-precommit-hook.sh
```

**Platform-specific Chrome/Chromium setup:**

- **Mac/Windows/Linux x64**: Chrome automatically handled by puppeteer (bundled with mermaid-cli dependencies)
- **Linux ARM64**: Requires manual Chromium setup since Google Chrome is not available for ARM64:

  ```bash
  # Option 1: Use Playwright Chromium (recommended)
  ./install-precommit-hook.sh --install-playwright

  # Option 2: Install system Chromium
  sudo apt install chromium-browser  # Ubuntu/Debian

  # Option 3: Specify custom Chromium path during installation
  ./install-precommit-hook.sh
  ```

### What it does

The pre-commit hook runs six validations before allowing commits:

#### 1. YAML Schema Validation

Validates all YAML files against their corresponding JSON schemas.

**Files validated:**

- `yaml/components.yaml` → `schemas/components.schema.json`
- `yaml/controls.yaml` → `schemas/controls.schema.json`
- `yaml/personas.yaml` → `schemas/personas.schema.json`
- `yaml/risks.yaml` → `schemas/risks.schema.json`
- `yaml/self-assessment.yaml` → `schemas/self-assessment.schema.json`
- `yaml/mermaid-styles.yaml` → `schemas/mermaid-styles.schema.json`

#### 2. Prettier YAML Formatting

Automatically formats YAML files in the `risk-map/yaml/` directory using Prettier to ensure consistent code style.

**Behavior:**

- **Normal mode**: Formats only staged YAML files in `risk-map/yaml/`
- **Force mode**: Formats all YAML files in `risk-map/yaml/`
- **Auto-staging**: Formatted files are automatically re-staged in normal mode

**Files formatted:**

- `risk-map/yaml/components.yaml`
- `risk-map/yaml/controls.yaml`
- `risk-map/yaml/personas.yaml`
- `risk-map/yaml/risks.yaml`
- `risk-map/yaml/self-assessment.yaml`
- `risk-map/yaml/mermaid-styles.yaml`

#### 3. Ruff Python Linting

Runs ruff linting on Python files to enforce code quality and style standards.

**Behavior:**

- **Normal mode**: Lints only staged Python files
- **Force mode**: Lints all Python files in the repository
- **Strict enforcement**: Commit fails if any linting issues are found

**Configuration**: Uses the project's `pyproject.toml` or `ruff.toml` configuration file.

#### 4. Component Edge Validation & Graph Generation

Validates the consistency of component relationships in `components.yaml` and generates visual graphs:

**Validation Features:**

- **Edge consistency**: Ensures that if Component A has `to: [B]`, then Component B has `from: [A]`
- **Bidirectional matching**: Verifies that all `to` edges have corresponding `from` edges and vice versa
- **Isolated component detection**: Identifies components with no edges (neither `to` nor `from`)

**Automatic Graph Generation Features:**

- **Component Graph**: When `components.yaml` is staged for commit, automatically generates `./risk-map/docs/risk-map-graph.md`
  - Topological ranking with `componentDataSources` always at rank 1
  - Category-based subgraphs (Data, Infrastructure, Model, Application)
  - Mermaid format with color coding and dynamic spacing
- **Control Graph**: When `components.yaml` OR `controls.yaml` is staged for commit, automatically generates `./risk-map/docs/controls-graph.md`
  - Shows control-to-component relationships with optimization
  - Dynamic component clustering and category-level mappings
  - Multi-edge styling with consistent color schemes
- **Risk Graph**: When `components.yaml`, `controls.yaml` OR `risks.yaml` is staged for commit, automatically generates `./risk-map/docs/controls-to-risk-graph.md`
  - Maps controls to risks they mitigate with component context
  - Organizes risks into 5 color-coded category subgraphs
  - Visualizes three-layer relationships: risks → controls → components
- **Auto-staging**: Both generated graphs are automatically added to staged files for inclusion in commit

**Example validation:**

```yaml
components:
  - id: componentA
    edges:
      to: [componentB]
      from: []
  - id: componentB
    edges:
      to: []
      from: [componentA] # ✅ Matches componentA's 'to' edge
```

#### 5. Control-to-Risk Reference Validation

Validates cross-reference consistency between `controls.yaml` and `risks.yaml`:

- **Bidirectional consistency**: Ensures that if a control lists a risk, that risk also references the control
- **Isolated entry detection**: Finds controls with no risk references or risks with no control references
- **all or none awareness**: Will not flag controls that leverage the `all` or `none` risk mappings

**Example validation:**

```yaml
# controls.yaml
controls:
  - id: CTRL-001
    risks: # Control addresses these risks
      - RISK-001
      - RISK-002

# risks.yaml
risks:
  - id: RISK-001
    controls:
      - CTRL-001 # ✅ Risk references the control back
  - id: RISK-002
    controls:
      - CTRL-001 # ✅ Bidirectional consistency maintained
```

#### 6. Mermaid SVG Generation

Automatically generates SVG files from Mermaid diagrams when `.mmd` or `.mermaid` files are staged for commit:

**Features:**

- **Automatic conversion**: Converts staged Mermaid files in `risk-map/docs/` to SVG format
- **Output location**: SVG files are saved to `risk-map/svg/` with matching filenames
- **Auto-staging**: Generated SVG files are automatically added to staged files for commit
- **Prerequisites check**: Validates that required tools (npx, mermaid-cli, Chrome/Chromium) are available
- **Platform-aware**: Handles Chrome/Chromium detection across different platforms

**Dependencies:**

- **Node.js 18+**: Required for npx and mermaid-cli execution
- **@mermaid-js/mermaid-cli**: Installed via `npm install` (converts .mmd to .svg)
- **Chrome/Chromium**: Used by mermaid-cli via puppeteer for rendering SVGs
  - **Mac/Windows/Linux x64**: Automatic Chrome detection (puppeteer bundled with dependencies handles Chrome)
  - **Linux ARM64**: Manual Chromium setup required since Google Chrome is not available for ARM64

**Example workflow:**

```bash
# Stage a mermaid file for commit
git add risk-map/docs/component-flow.mmd

# Pre-commit hook automatically:
# 1. Detects the staged .mmd file
# 2. Converts it to risk-map/svg/component-flow.svg
# 3. Stages the generated SVG for commit

git commit -m "Add component flow diagram"
# Both the .mmd source and generated .svg are committed
```

**Behavior:**

- **Normal mode**: Only processes staged `.mmd/.mermaid` files in `risk-map/docs/`
- **Force mode**: Skips SVG generation (generation only runs for actual commits)
- **Error handling**: Gracefully handles missing Chrome/Chromium with clear error messages

#### 7. Markdown Table Generation

Automatically generates markdown tables from YAML files when staged for commit:

**Features:**

- **Automatic conversion**: Converts staged YAML to multiple table formats
- **Output location**: Tables saved to `risk-map/tables/` with format-specific filenames
- **Smart regeneration**: Cross-reference tables regenerated when dependencies change
- **Auto-staging**: Generated tables automatically added to commit

**Generation rules:**

- `components.yaml` staged → generates `components-full.md`, `components-summary.md`, and regenerates `controls-xref-components.md`
- `risks.yaml` staged → generates `risks-full.md`, `risks-summary.md`, and regenerates `controls-xref-risks.md`
- `controls.yaml` staged → generates all 4 formats: `controls-full.md`, `controls-summary.md`, `controls-xref-risks.md`, `controls-xref-components.md`

**Dependencies:**

- Python 3.10+
- pandas (already in requirements.txt)

**Example workflow:**

```bash
# Edit controls.yaml
git add risk-map/yaml/controls.yaml

# Pre-commit hook automatically:
# 1. Detects staged controls.yaml
# 2. Generates all 4 control table formats
# 3. Stages the generated markdown files

git commit -m "Update controls"
# Both YAML and 4 generated tables are committed
```

**Behavior:**

- **Normal mode**: Only processes staged YAML files in `risk-map/yaml/`
- **Force mode**: Skips table generation (generation only runs for actual commits)

### Requirements

Install all required Python packages:

```bash
pip install -r requirements.txt
```

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

**Individual installation** (if needed):

```bash
pip install PyYAML check-jsonschema pytest ruff
npm install prettier @mermaid-js/mermaid-cli playwright puppeteer-core

# For ARM64 Linux specifically, install Playwright Chromium:
npx playwright install chromium --with-deps
```

### Files

- `hooks/pre-commit` - The main git hook script that orchestrates all validations
- `hooks/validate_riskmap.py` - Python script for component edge validation
- `hooks/validate_control_risk_references.py` - Python script for control-risk cross-reference validation
- `install-precommit-hook.sh` - Installs all hooks to your local `.git/hooks/`

### Validation Flow

When you commit changes, the hook will:

1. **Schema Validation** - Check YAML structure and data types
2. **Prettier Formatting** - Format YAML files in `risk-map/yaml/` and re-stage them
3. **Ruff Linting** - Lint Python files for code quality
4. **Edge Validation** - Verify component relationship consistency
5. **Graph Generation** - Generate and stage graphs based on file changes:
   - If `components.yaml` changed: generate `./risk-map/docs/risk-map-graph.md`
   - If `components.yaml` or `controls.yaml` changed: generate `./risk-map/docs/controls-graph.md`
   - If `components.yaml`, `controls.yaml` or `risks.yaml` changed: generate `./risk-map/docs/controls-to-risk-graph.md`
6. **SVG Generation** - Convert staged Mermaid files to SVG format:
   - If `.mmd/.mermaid` files changed: generate corresponding SVG files in `./risk-map/svg/`
7. **Table Generation** - Convert staged YAML files to markdown tables:
   - If `components.yaml` changed: generate component tables + regenerate controls-xref-components
   - If `risks.yaml` changed: generate risk tables + regenerate controls-xref-risks
   - If `controls.yaml` changed: generate all 4 control table formats
8. **Control-Risk Validation** - Verify control-risk cross-reference consistency
9. **Block commit** if any validation fails

**Note**: Graph and table generation only occur when relevant files are staged for commit, not in `--force` mode.

#### Manual Validation of Unstaged Files

The `pre-commit` hook and all individual validation scripts support the `--force` flag to validate all files regardless of their git staging status (useful during development).

```bash
# Validating unstaged files during development...
# Note: --force validates all relevant files, not just those staged for commit

# Run all validation steps
.git/hooks/pre-commit --force

# Run component edge validation-only
.git/hooks/validate_riskmap.py --force

# Run control-to-risk reference validation-only
.git/hooks/validate_control_risk_references.py --force

```

### GitHub Actions Validation

In addition to local pre-commit validation, the repository includes GitHub Actions that run validation on pull requests:

**Automated PR Validation includes:**

- **YAML Schema Validation**: Validates all YAML files against their JSON schemas
- **YAML Format Validation**: Checks prettier formatting compliance
- **Python Linting**: Runs ruff linting on all Python files
- **Component Edge Validation**: Verifies component relationship consistency
- **Control-Risk Reference Validation**: Checks control-risk cross-reference integrity
- **Graph Validation**: Generates and compares graphs against committed versions
  - Component graph (`./risk-map/docs/risk-map-graph.md`)
  - Control graph (`./risk-map/docs/controls-graph.md`)
  - Controls-to-risk graph (`./risk-map/docs/controls-to-risk-graph.md`)
- **Mermaid SVG Validation**: Validates Mermaid diagram syntax and generates SVG previews
- **Markdown Table Validation**: Generates and compares markdown tables against committed versions
  - Components tables (`components-full.md`, `components-summary.md`)
  - Risks tables (`risks-full.md`, `risks-summary.md`)
  - Controls tables (`controls-full.md`, `controls-summary.md`, `controls-xref-risks.md`, `controls-xref-components.md`)

**Different Roles:**

- **Pre-commit hooks**:
  - Generate SVG files from Mermaid diagrams and stage them
  - Generate markdown tables from YAML files and stage them
- **GitHub Actions**:
  - Validate Mermaid syntax and provide SVG previews in PR comments (does not generate files for commit)
  - Validate that markdown tables match generated versions (does not generate files for commit)

**Graph Validation Process:**

- GitHub Actions generates fresh graphs using the validation script
- Compares generated graphs with the committed versions in the PR
- Fails the build if graphs don't match, indicating they need to be regenerated
- Provides diff output showing exactly what differences were found

**When Graph Validation Fails:**

```bash
# The most common cause is missing graph regeneration
# Fix by running locally and committing the updated graphs:

# For component graph issues:
python3 .git/hooks/validate_riskmap.py --to-graph ./risk-map/docs/risk-map-graph.md --force

# For control graph issues:
python3 .git/hooks/validate_riskmap.py --to-controls-graph ./risk-map/docs/controls-graph.md --force

# For controls-to-risk graph issues:
python3 .git/hooks/validate_riskmap.py --to-risk-graph ./risk-map/docs/controls-to-risk-graph.md --force

# Then commit the updated graphs:
git add risk-map/docs/risk-map-graph.md risk-map/docs/controls-graph.md risk-map/docs/controls-to-risk-graph.md
git commit -m "Update generated graphs"
```

**Table Validation Process:**

- GitHub Actions generates fresh markdown tables from YAML files
- Compares generated tables with the committed versions in the PR
- Fails the build if tables are missing or don't match, indicating they need to be regenerated
- Provides diff output showing exactly what differences were found

**When Table Validation Fails:**

```bash
# The most common cause is missing table regeneration
# Fix by running locally and committing the updated tables:

# Generate all table files (recommended)
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats

# Or generate specific tables:
python3 scripts/hooks/yaml_to_markdown.py components --all-formats
python3 scripts/hooks/yaml_to_markdown.py risks --all-formats
python3 scripts/hooks/yaml_to_markdown.py controls --all-formats

# Then commit the updated tables:
git add risk-map/tables/*.md
git commit -m "Update markdown tables"
```

#### Manual Graph Generation

Generate all three graph types manually using the validation script:

```bash
# Validate edges and generate clean component graph without debug comments
.git/hooks/validate_riskmap.py --to-graph ./docs/component-map.md --force

# Generate component graph with rank debugging information
.git/hooks/validate_riskmap.py --to-graph ./docs/debug-graph.md --debug --force

# Generate control-to-component graph visualization
.git/hooks/validate_riskmap.py --to-controls-graph ./docs/controls-graph.md --force

# Generate controls-to-risk graph visualization
.git/hooks/validate_riskmap.py --to-risk-graph ./docs/controls-risk-graph.md --force
```

**Graph Generation Options:**

- `--to-graph PATH` - Output component relationship Mermaid graph to specified file
- `--to-controls-graph PATH` - Output control-to-component relationship graph to specified file
- `--to-risk-graph PATH` - Output controls-to-risk relationship graph to specified file
- `--debug` - Include rank comments for debugging (component graphs only)
- `--quiet` - Minimize output (only show errors)
- `--allow-isolated` - Allow components with no edges

#### Manual Table Generation

Generate markdown tables from YAML files using the table generator script:

```bash
# Generate all formats for a single type
python3 .git/hooks/yaml_to_markdown.py components --all-formats
# Output: components-full.md, components-summary.md

python3 .git/hooks/yaml_to_markdown.py controls --all-formats
# Output: controls-full.md, controls-summary.md, controls-xref-risks.md, controls-xref-components.md

# Generate specific format
python3 .git/hooks/yaml_to_markdown.py controls --format summary
python3 .git/hooks/yaml_to_markdown.py controls --format xref-risks

# Generate all types, all formats (8 files)
python3 .git/hooks/yaml_to_markdown.py --all --all-formats

# Generate to custom output directory
python3 .git/hooks/yaml_to_markdown.py --all --all-formats --output-dir /tmp/tables

# Custom output file (single type, single format only)
python3 .git/hooks/yaml_to_markdown.py components --format full -o custom.md

# Quiet mode
python3 .git/hooks/yaml_to_markdown.py --all --all-formats --quiet
```

**Table Formats:**

- `full` - Complete detail tables with all columns
- `summary` - Condensed tables (ID, Title, Description, Category)
- `xref-risks` - Control-to-risk cross-reference (controls only)
- `xref-components` - Control-to-component cross-reference (controls only)

**Output Files:**

- Components: `components-full.md`, `components-summary.md` (2 files)
- Controls: `controls-full.md`, `controls-summary.md`, `controls-xref-risks.md`, `controls-xref-components.md` (4 files)
- Risks: `risks-full.md`, `risks-summary.md` (2 files)

### Troubleshooting

#### Installing over existing hooks

If you already have git hooks and want to replace them:

```bash
./install-precommit-hook.sh --force
```

#### Installing with Playwright Chromium (ARM64 Linux)

For ARM64 Linux systems that need Playwright Chromium:

```bash
# Automatically install Playwright Chromium during setup
./install-precommit-hook.sh --install-playwright

# Or install manually then run setup
npx playwright install chromium
./install-precommit-hook.sh
```

#### Bypassing validation (emergencies only)

To temporarily skip all validation:

```bash
git commit --no-verify -m "emergency commit"
```

#### Common edge validation errors

```
❌ Component 'componentA': missing incoming edges for: componentB
```

**Fix**: Add `componentA` to `componentB`'s `from` list

```
❌ Found 1 isolated components (no edges): componentOrphan
```

**Fix**: Either add edges to the component or remove it if it's unused

#### Common control-to-risk validation errors

```
❌ [ISSUE: risks.yaml] Control 'CTRL-001' claims to address risks ['RISK-005'] in controls.yaml,
   but these risks don't list this control in their 'controls' section in risks.yaml
```

**Fix**: Add `CTRL-001` to the `controls` list for `RISK-005` in `risks.yaml`

```
❌ [ISSUE: controls.yaml] Risks ['RISK-003'] reference control 'CTRL-999' in risks.yaml,
   but this control doesn't list these risks in its 'risks' section in controls.yaml
```

**Fix**: Add `RISK-003` to the `risks` list for `CTRL-999` in `controls.yaml`, or remove the invalid control reference

```
❌ [ISSUE: controls.yaml] Control 'CTRL-002' is referenced by risks ['RISK-001'] in risks.yaml,
   but this control doesn't exist in controls.yaml
```

**Fix**: Either create `CTRL-002` in `controls.yaml` or remove the reference from `risks.yaml`

#### Common prettier formatting errors

```
❌ Prettier formatting failed for risk-map/yaml/components.yaml
```

**Fix**: Check that prettier is installed (`npm install -g prettier`) and the YAML file syntax is valid

```
⚠️ Warning: Could not stage formatted file risk-map/yaml/components.yaml
```

**Fix**: Check file permissions and git repository status

#### Common ruff linting errors

```
❌ Ruff linting failed for staged files
```

**Fix**: Run `ruff check --fix .` to automatically fix auto-fixable issues, or manually address the linting violations shown in the output

```
❌ Ruff linting failed
```

**Fix**: Check that ruff is installed (`pip install ruff`) and review the specific linting errors in the output

#### Common SVG generation errors

```
⚠️ Directory ./risk-map/svg does not exist - skipping SVG generation
```

**Fix**: Create the directory: `mkdir -p risk-map/svg`

```
⚠️ npx command not found - skipping SVG generation
```

**Fix**: Install Node.js 18+ and npm, then verify with `npx --version`

```
⚠️ Mermaid CLI not available - skipping SVG generation
```

**Fix**: Install mermaid-cli: `npm install -g @mermaid-js/mermaid-cli` or `npm install`

```
❌ Failed to convert diagram.mmd
```

**Fix**: Check Mermaid syntax in the file, and verify Chrome/Chromium is available. Test manually:

```bash
npx mmdc -i diagram.mmd -o test.svg
```

#### Chrome/Chromium issues (ARM64 Linux)

```
Error: Could not find browser revision
```

**Fix**: Install Playwright Chromium or system Chromium:

```bash
# Option 1: Playwright Chromium (recommended)
npx playwright install chromium --with-deps

# Option 2: System Chromium
sudo apt install chromium-browser

# Option 3: Re-run install with automatic Playwright setup
./install-precommit-hook.sh --install-playwright --force
```

```
✅ Found existing Playwright Chromium at: /path/to/chromium
# But SVG generation still fails
```

**Fix**: Verify the Chromium path is executable and has required dependencies:

```bash
# Test Chromium directly
/path/to/chromium --version

# Install system dependencies if needed (Ubuntu/Debian)
sudo apt install -y ca-certificates fonts-liberation libappindicator3-1 \
  libasound2 libatk-bridge2.0-0 libdrm2 libgtk-3-0 libnspr4 libnss3 \
  libxcomposite1 libxdamage1 libxrandr2 libgbm1 libxss1 libu2f-udev

# Re-configure pre-commit hook
./install-precommit-hook.sh --force
```

```
⚠️ Using automatic Chrome detection
# But no Chrome found on ARM64
```

**Fix**: ARM64 Linux requires manual Chromium setup since Google Chrome isn't available:

```bash
# Check your platform
uname -m  # Should show aarch64 or arm64

# Install Playwright Chromium
npx playwright install chromium --with-deps

# Re-run installation to detect Chromium
./install-precommit-hook.sh --force
```

#### Common table generation errors

```
⚠️ Directory ./risk-map/tables does not exist - skipping table generation
```

**Fix**: Create the directory: `mkdir -p risk-map/tables`

```
❌ Table generation failed for controls
```

**Fix**: Check that Python dependencies are installed and YAML files are valid:

```bash
# Install dependencies
pip install -r requirements.txt

# Test manually
python3 .git/hooks/yaml_to_markdown.py controls --all-formats
```

```
⚠️ Warning: Could not stage generated table files
```

**Fix**: Check file permissions and git repository status

#### Debugging table generation

Run table generation manually to test:

```bash
# Test component table generation
python3 .git/hooks/yaml_to_markdown.py components --all-formats

# Test controls table generation (all 4 formats)
python3 .git/hooks/yaml_to_markdown.py controls --all-formats

# Test with verbose output
python3 .git/hooks/yaml_to_markdown.py controls --all-formats
```

#### Debugging validation manually

Run the component edge validator manually:

```bash
python3 .git/hooks/validate_riskmap.py
```

Run the component edge validator even if files aren't staged:

```bash
python3 .git/hooks/validate_riskmap.py --force
```

Run the control-risk validator manually:

```bash
python3 .git/hooks/validate_control_risk_references.py
```

Force validation of control-risk references even if files aren't staged:

```bash
python3 .git/hooks/validate_control_risk_references.py --force
```

Run prettier formatting manually:

```bash
# Format all YAML files in risk-map/yaml/
npx prettier --write risk-map/yaml/*.yaml

# Check formatting without modifying files
npx prettier --check risk-map/yaml/*.yaml
```

Run ruff linting manually:

```bash
# Lint all Python files
ruff check .

# Lint specific files
ruff check tools/ scripts/

# Auto-fix issues where possible
ruff check --fix .
```

Run SVG generation manually:

```bash
# Test SVG generation for a specific file
npx mmdc -i risk-map/docs/diagram.mmd -o test.svg

# Test with custom Chrome/Chromium path
npx mmdc -i risk-map/docs/diagram.mmd -o test.svg \
  -p '{"executablePath": "/path/to/chromium"}'

# Check available browsers (Playwright)
npx playwright show-path chromium

# Verify mermaid-cli installation
npx mmdc --version
```

#### Debugging graph generation

Test graph generation without affecting git staging:

```bash
# Generate component graph to test output
python3 .git/hooks/validate_riskmap.py --to-graph ./test-graph.md --force

# Generate component graph with debug information to understand ranking
python3 .git/hooks/validate_riskmap.py --to-graph ./debug-graph.md --debug --force

# Generate control-to-component graph to test relationships
python3 .git/hooks/validate_riskmap.py --to-controls-graph ./controls-test.md --force

# Generate controls-to-risk graph to test risk relationships
python3 .git/hooks/validate_riskmap.py --to-risk-graph ./risk-test.md --force

# View help for all graph options
python3 .git/hooks/validate_riskmap.py --help
```

**Common graph generation issues:**

```
❌ Graph generation failed
```

**Fix**: Check that the component and control YAML files are valid and accessible, ensure write permissions for output directory

```
⚠️ Warning: Could not stage generated graph
```

**Fix**: This occurs during pre-commit when git staging fails - check file permissions and git repository status

**Control graph specific issues:**

```
❌ Control-to-component graph generation failed
```

**Fix**: Verify that both `controls.yaml` and `components.yaml` are accessible and properly formatted. Check that control component references are valid.

## Mermaid Graph Styling Configuration

The validation system includes a configuration system for customizing Mermaid graph styling through `risk-map/yaml/mermaid-styles.yaml`. This configuration file controls all visual aspects of both component graphs and control graphs generated by the validation scripts.

### Configuration File Structure

The `mermaid-styles.yaml` file is organized into four main sections:

#### 1. Foundation Design Tokens

```yaml
foundation:
  colors:
    primary: '#4285f4' # Google Blue - primary actions
    success: '#34a853' # Google Green - success states
    accent: '#9c27b0' # Purple - accent elements
    # ... additional semantic colors
  strokeWidths:
    thin: '1px' # Subgroup borders
    medium: '2px' # Standard borders
    thick: '3px' # Emphasis elements
  strokePatterns:
    solid: '' # Solid lines
    dashed: '5 5' # Dashed pattern
    # ... additional patterns
```

#### 2. Shared Elements

```yaml
sharedElements:
  cssClasses:
    hidden: 'display: none;'
    allControl: 'stroke:#4285f4,stroke-width:2px,stroke-dasharray: 5 5'
  componentCategories:
    componentsInfrastructure:
      fill: '#e6f3e6' # Light green
      stroke: '#333333' # Dark border
      strokeWidth: '2px'
      subgroupFill: '#d4e6d4' # Darker green for subgroups
```

#### 3. Graph-Specific Configuration

```yaml
graphTypes:
  component:
    direction: 'TD' # Top-down layout
    flowchartConfig:
      padding: 5 # Internal node padding
      wrappingWidth: 250 # Text wrapping width
  control:
    direction: 'LR' # Left-right layout
    flowchartConfig:
      nodeSpacing: 25 # Space between nodes
      rankSpacing: 150 # Space between ranks/levels
      padding: 5
      wrappingWidth: 250
    specialStyling:
      edgeStyles:
        multiEdgeStyles: # 4-color cycling for complex controls
          - stroke: '#9c27b0'
            strokeWidth: '2px'
  risk:
    direction: 'LR' # Left-right layout for three layers
    flowchartConfig:
      nodeSpacing: 30 # Increased spacing for three-layer complexity
      rankSpacing: 40 # Increased spacing between layers
      padding: 5
      wrappingWidth: 250
    specialStyling:
      # Risk category styling (single generic category)
      riskCategories:
        risks:
          fill: '#ffeef0' # Light pink background for risk category
          stroke: '#e91e63' # Pink border for risk emphasis
          strokeWidth: '2px'
          subgroupFill: '#ffe0e6' # Darker pink for risk subgroups
      # Container styling for three layers
      componentsContainer:
        fill: '#f0f0f0'
        stroke: '#666666'
        strokeWidth: '3px'
        strokeDasharray: '10 5'
      controlsContainer:
        fill: '#f0f0f0'
        stroke: '#666666'
        strokeWidth: '3px'
        strokeDasharray: '10 5'
      risksContainer:
        fill: '#f0f0f0'
        stroke: '#666666'
        strokeWidth: '3px'
        strokeDasharray: '10 5'
```

### Customizing Graph Appearance

To customize graph styling:

1. **Edit Configuration**: Modify `risk-map/yaml/mermaid-styles.yaml`
2. **Validate Changes**: The pre-commit hooks automatically validate syntax and schema
3. **Test Changes**: Use `--force` mode to test with unstaged changes:
   ```bash
   python3 scripts/hooks/validate_riskmap.py --to-graph test.md --force
   ```

### Common Customizations

#### Change Component Category Colors

```yaml
sharedElements:
  componentCategories:
    componentsInfrastructure:
      fill: '#your-color' # Background color
      stroke: '#border-color' # Border color
      strokeWidth: '2px'
      subgroupFill: '#sub-color' # Subgroup background
    componentsApplication:
      fill: '#another-color'
      stroke: '#border-color'
      strokeWidth: '2px'
      subgroupFill: '#sub-color'
```

#### Modify Graph Layout

```yaml
graphTypes:
  component:
    direction: 'LR' # Change to left-right layout
  control:
    flowchartConfig:
      nodeSpacing: 40 # Increase node spacing
      wrappingWidth: 300 # Wider text wrapping
```

#### Update Multi-Edge Control Colors

```yaml
graphTypes:
  control:
    specialStyling:
      edgeStyles:
        multiEdgeStyles:
          - stroke: '#ff0000' # Red
            strokeWidth: '3px' # Thicker lines
          - stroke: '#00ff00' # Green
            strokeDasharray: '10 5' # Custom dash pattern
```

#### Customize Risk Category Colors

```yaml
graphTypes:
  risk:
    specialStyling:
      riskCategories:
        risks:
          fill: '#ffeef0' # Light pink background for risk category
          stroke: '#e91e63' # Pink border for risk emphasis
          strokeWidth: '2px'
          subgroupFill: '#ffe0e6' # Darker pink for risk subgroups
```

**Note**: The configuration uses a single `risks` category for all risk styling. Individual risk categories (defined in `risks.yaml`) share this same visual styling.

#### Style Three-Layer Containers

```yaml
graphTypes:
  risk:
    specialStyling:
      componentsContainer:
        fill: '#e8f5e9' # Light green - bottom layer (components)
        stroke: '#4caf50' # Green border
        strokeWidth: '3px'
      controlsContainer:
        fill: '#e3f2fd' # Light blue - middle layer (controls)
        stroke: '#2196f3' # Blue border
        strokeWidth: '3px'
      risksContainer:
        fill: '#fce4ec' # Light pink - top layer (risks)
        stroke: '#e91e63' # Pink border
        strokeWidth: '3px'
```

### Validation and Schema

The configuration file is automatically validated against `risk-map/schemas/mermaid-styles.schema.json` which enforces:

- **Color format validation**: All colors must be valid hex values (#RRGGBB)
- **Required properties**: All essential configuration elements must be present
- **Value constraints**: Spacing values, direction options, and stroke patterns are validated
- **Structure validation**: Proper nesting and organization is enforced

### Error Handling

The system includes a set of fallback mechanisms:

- **Missing file**: Uses hardcoded emergency defaults matching original styling
- **Invalid configuration**: Falls back to emergency defaults while reporting errors
- **Partial configuration**: Missing elements use sensible defaults from emergency configuration

This ensures graph generation never fails due to configuration issues, maintaining system reliability while providing customization flexibility.
