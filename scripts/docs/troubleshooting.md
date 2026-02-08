# Troubleshooting

## Installing over existing hooks

If you already have git hooks and want to replace them:

```bash
./scripts/install-precommit-hook.sh --force
```

## Installing with Playwright Chromium (ARM64 Linux)

For ARM64 Linux systems that need Playwright Chromium:

```bash
# Automatically install Playwright Chromium during setup
./scripts/install-precommit-hook.sh --install-playwright

# Or install manually then run setup
npx playwright install chromium
./scripts/install-precommit-hook.sh
```

## Bypassing validation (emergencies only)

To temporarily skip all validation:

```bash
git commit --no-verify -m "emergency commit"
```

## Common edge validation errors

```
❌ Component 'componentA': missing incoming edges for: componentB
```

**Fix**: Add `componentA` to `componentB`'s `from` list

```
❌ Found 1 isolated components (no edges): componentOrphan
```

**Fix**: Either add edges to the component or remove it if it's unused

## Common control-to-risk validation errors

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

## Common prettier formatting errors

```
❌ Prettier formatting failed for risk-map/yaml/components.yaml
```

**Fix**: Check that prettier is installed (`npm install`) and the YAML file syntax is valid

```
⚠️ Warning: Could not stage formatted file risk-map/yaml/components.yaml
```

**Fix**: Check file permissions and git repository status

## Common ruff linting errors

```
❌ Ruff linting failed for staged files
```

**Fix**: Run `ruff check --fix .` to automatically fix auto-fixable issues, or manually address the linting violations shown in the output

```
❌ Ruff linting failed
```

**Fix**: Check that ruff is installed (`pip install ruff`) and review the specific linting errors in the output

## Common SVG generation errors

```
⚠️ Directory ./risk-map/svg does not exist - skipping SVG generation
```

**Fix**: Create the directory: `mkdir -p risk-map/svg`

```
⚠️ npx command not found - skipping SVG generation
```

**Fix**: Install Node.js 22+ and npm, then verify with `npx --version`

```
⚠️ Mermaid CLI not available - skipping SVG generation
```

**Fix**: Install mermaid-cli: `npm install` (installs all npm dependencies from package.json)

```
❌ Failed to convert diagram.mmd
```

**Fix**: Check Mermaid syntax in the file, and verify Chrome/Chromium is available. Test manually:

```bash
npx mmdc -i diagram.mmd -o test.svg
```

## Chrome/Chromium issues (ARM64 Linux)

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
./scripts/install-precommit-hook.sh --install-playwright --force
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
./scripts/install-precommit-hook.sh --force
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
./scripts/install-precommit-hook.sh --force
```

## Common table generation errors

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
python3 scripts/hooks/yaml_to_markdown.py controls --all-formats
```

```
⚠️ Warning: Could not stage generated table files
```

**Fix**: Check file permissions and git repository status

## Debugging validation manually

Run the component edge validator manually:

```bash
python3 scripts/hooks/validate_riskmap.py
```

Run the component edge validator even if files aren't staged:

```bash
python3 scripts/hooks/validate_riskmap.py --force
```

Run the control-risk validator manually:

```bash
python3 scripts/hooks/validate_control_risk_references.py
```

Force validation of control-risk references even if files aren't staged:

```bash
python3 scripts/hooks/validate_control_risk_references.py --force
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

---

**Related:**
- [Setup](setup.md) - Installation and prerequisites
- [Hook Validations](hook-validations.md) - What validations run
- [Graph Generation](graph-generation.md) - Debugging graph issues
- [Table Generation](table-generation.md) - Debugging table issues
