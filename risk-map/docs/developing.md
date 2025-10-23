# Expanding the CoSAI Risk Map

> This guide complements the repository-wide [`CONTRIBUTING.md`](../../CONTRIBUTING.md). Use that for branching, commit/PR workflow, code review expectations, and CLA. This document focuses on how to author and validate Risk Map content (schemas and YAML).
>
> _Note: all contributions discussed in this document would fall under the [Content Update Process](../../CONTRIBUTING.md#content-update-governance-process) covered in detail in the `CONTRIBUTING.md` document_

This guide outlines how you can contribute to the Coalition for Secure AI (CoSAI) Risk Map. By following these steps, you can help expand the framework while ensuring your contributions are consistent with the project's structure and pass all validation checks.

## Prerequisites

Before contributing to the Risk Map, ensure you have the necessary validation tools set up:

### Setting Up Pre-commit Hooks

The repository includes automated schema validation, prettier YAML formatting, ruff Python linting, component edge consistency checks, control-to-risk reference validation, automatic graph generation, and Mermaid SVG generation via git pre-commit hooks.

**Prerequisites:**

- Python 3.10 or higher
- Node.js 18+ and npm
- Chrome/Chromium browser (for SVG generation from Mermaid diagrams)

1. **Install dependencies and pre-commit hook (one-time setup)**:

   ```bash
   # From the repository root
   # Install required Python packages
   pip install -r requirements.txt

   # Install Node.js dependencies (prettier, mermaid-cli, etc.)
   npm install

   # Install the pre-commit hook
   bash ./scripts/install-precommit-hook.sh
   ```

2. **Verify the hook is working**:
   ```bash
   # Make a test change to risk-map/yaml/components.yaml
   # Attempt to commit - the hook should run validation
   git add risk-map/yaml/components.yaml
   git commit -m "test commit"
   ```

### Manual Edge Validation & Graph Generation

You can run edge validation and graph generation manually at any time:

```bash
# Validate only if components.yaml is staged for commit
python scripts/hooks/validate_riskmap.py

# Force validation regardless of git status
python scripts/hooks/validate_riskmap.py --force

# Generate component graph visualization
python scripts/hooks/validate_riskmap.py --to-graph ./my-graph.md --force

# Generate component graph with debug annotations
python scripts/hooks/validate_riskmap.py --to-graph ./debug-graph.md --debug --force

# Generate control-to-component relationship graph
python scripts/hooks/validate_riskmap.py --to-controls-graph ./controls-graph.md --force
```

The validation script checks for:

- **Bidirectional edge consistency**: If Component A references Component B in its `to` edges, Component B must have Component A in its `from` edges
- **No isolated components**: Components should have at least one `to` or `from` edge
- **Valid component references**: All components referenced in edges must exist

**Automatic Graph Generation**: The pre-commit hook automatically generates graphs when relevant files are staged:

- **Component Graph**: When `components.yaml` is staged, generates `./risk-map/diagrams/risk-map-graph.md`
  - Uses Elk layout engine for automatic positioning and ranking
  - Organizes components into category-based subgraphs with configurable styling
- **Control Graph**: When `components.yaml` OR `controls.yaml` is staged, generates `./risk-map/diagrams/controls-graph.md`
  - Shows control-to-component relationships with optimization
  - Dynamic component clustering and multi-edge styling
- **Risk Graph**: When `components.yaml`, `controls.yaml` OR `risks.yaml` is staged, generates `./risk-map/diagrams/controls-to-risk-graph.md`
  - Maps controls to risks they mitigate with component context
  - Organizes risks into 5 color-coded category subgraphs
  - Visualizes three-layer relationships: risks → controls → components
- All generated graphs are automatically staged for inclusion in your commit

_See [scripts documentation](../../scripts/README.md) for more information on the git hooks and validation._

### Manual Graph Generation

Beyond automatic generation, you can manually generate both types of graphs using the validation script:

```bash
# Generate component relationship graph
python scripts/hooks/validate_riskmap.py --to-graph ./components.md --force

# Generate control-to-component graph
python scripts/hooks/validate_riskmap.py --to-controls-graph ./controls-graph.md --force

# Generate control-to-risk relationship graph
python scripts/hooks/validate_riskmap.py --to-risk-graph ./risk-graph.md --force

# Generate all three graph types
python scripts/hooks/validate_riskmap.py --to-graph ./components.md --to-controls-graph ./controls.md --to-risk-graph ./risk.md --force
```

### Markdown Table Documentation

The pre-commit hooks automatically generate markdown tables from YAML files for easy documentation viewing:

**Automatic Generation:**

- **Triggered by**: Staging `components.yaml`, `controls.yaml`, or `risks.yaml`
- **Output location**: `risk-map/tables/`
- **Smart regeneration**: Cross-reference tables regenerated when dependencies change
- **Auto-staging**: Generated tables added to commit automatically

**Generation rules:**

- `components.yaml` → `components-full.md`, `components-summary.md`, and regenerates `controls-xref-components.md` (3 files)
- `risks.yaml` → `risks-full.md`, `risks-summary.md`, and regenerates `controls-xref-risks.md` (3 files)
- `controls.yaml` → all 4 formats: `controls-full.md`, `controls-summary.md`, `controls-xref-risks.md`, `controls-xref-components.md`

**Manual Generation:**

```bash
# Generate all formats for one type
python3 scripts/hooks/yaml_to_markdown.py components --all-formats
python3 scripts/hooks/yaml_to_markdown.py controls --all-formats

# Generate all types and formats (8 files total)
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats

# Generate to custom output directory
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats --output-dir /tmp/tables

# Generate specific format
python3 scripts/hooks/yaml_to_markdown.py controls --format xref-risks
python3 scripts/hooks/yaml_to_markdown.py components --format summary
```

**Available formats:**

- `full` - Complete tables with all columns (default)
- `summary` - Condensed: ID, Title, Description, Category
- `xref-risks` - Control-to-risk cross-reference (controls only)
- `xref-components` - Control-to-component cross-reference (controls only)

**Use cases:**

- Review component definitions in table format
- Export risk catalog for documentation
- Generate control mappings for compliance reports
- Create cross-reference documentation

**Control Graph Features:**

- **Dynamic Component Clustering**: Automatically groups components that share multiple controls
- **Category Optimization**: Maps controls to entire categories when they apply to all components in that category
- **Multi-Edge Styling**: Uses different colors and patterns for controls with 3+ edges
- **Consistent Styling**: Color-coded categories and visual hierarchy
- **Mermaid Format**: Generates Mermaid-compatible diagrams ready for documentation

**Example Control Graph Output:**
The generated graph shows controls (grouped by category) connected to the components they protect, with optimization applied to reduce visual complexity while maintaining accuracy.

### Manual Control-to-Risk Reference Validation

You can run control-to-risk reference validation at any time:

```bash
# Validate control-to-risk references if at least on of controls.yaml or risks.yaml is staged
python scripts/hooks/validate_control_risk_references.py

# Force control-to-risk references validation regardless of git status
python scripts/hooks/validate_control_risk_references.py --force
```

The control-to-risk validates cross-reference consistency between `controls.yaml` and `risks.yaml`:

- **Bidirectional consistency**: Ensures that if a control lists a risk, that risk also references the control
- **Isolated entry detection**: Finds controls with no risk references or risks with no control references
- **all or none awareness**: Will not flag controls that leverage the `all` or `none` risk mappings

### Manual Prettier Formatting

You can run prettier formatting on YAML files manually:

```bash
# Format all YAML files in risk-map/yaml/
npx prettier --write risk-map/yaml/*.yaml

# Check formatting without modifying files
npx prettier --check risk-map/yaml/*.yaml
```

Prettier ensures consistent formatting across all YAML files in the `risk-map/yaml/` directory, automatically handling indentation, spacing, and other style conventions.

### Manual Ruff Linting

You can run ruff linting on Python files manually:

```bash
# Lint all Python files
ruff check .

# Lint specific directories
ruff check tools/ scripts/

# Auto-fix issues where possible
ruff check --fix .

# Check specific staged files
ruff check $(git diff --cached --name-only --diff-filter=ACM | grep '\.py$')
```

Ruff enforces Python code quality and style standards, catching potential issues before they make it into the repository.

## Customizing Graph Appearance

The CoSAI Risk Map system generates visual Mermaid graphs of component relationships and control-to-component mappings. You can fully customize the appearance of these graphs through the `risk-map/yaml/mermaid-styles.yaml` configuration file.

### Understanding the Configuration Structure

The `mermaid-styles.yaml` file uses a hierarchical structure with four main sections:

#### Foundation Design Tokens

Define semantic colors, stroke widths, and patterns used throughout the system:

```yaml
foundation:
  colors:
    primary: '#4285f4' # Google Blue - used for primary actions and "all" controls
    success: '#34a853' # Google Green - used for success states and category mappings
    accent: '#9c27b0' # Purple - first multi-edge style color
    warning: '#ff9800' # Orange - second multi-edge style color
    error: '#e91e63' # Pink - third multi-edge style color
    neutral: '#333333' # Dark gray - used for borders and strokes
    lightGray: '#f0f0f0' # Light gray - container backgrounds
    darkGray: '#666666' # Medium gray - container borders
  strokeWidths:
    thin: '1px' # Subgroup borders
    medium: '2px' # Standard component and control borders
    thick: '3px' # Emphasis elements like container borders
  strokePatterns:
    solid: '' # No dash pattern (solid lines)
    dashed: '5 5' # Standard dashed pattern
    dotted: '8 4' # Dotted pattern for "all" control edges
    longDash: '10 2' # Long dash pattern for multi-edge styles
    longDashSpaced: '10 5' # Long dash with spacing for containers
```

#### Shared Elements

Elements used by both component graphs and control graphs:

```yaml
sharedElements:
  cssClasses:
    hidden: 'display: none;'
    allControl: 'stroke:#4285f4,stroke-width:2px,stroke-dasharray: 5 5'
  componentCategories:
    componentsInfrastructure:
      fill: '#e6f3e6' # Light green for infrastructure components
      stroke: '#333333' # Dark gray border
      strokeWidth: '2px' # Medium border width
      subgroupFill: '#d4e6d4' # Darker green for infrastructure subgroups
    componentsApplication:
      fill: '#e6f0ff' # Light blue for application components
      stroke: '#333333' # Dark gray border
      strokeWidth: '2px' # Medium border width
      subgroupFill: '#e0f0ff' # Darker blue for application subgroups
    componentsModel:
      fill: '#ffe6e6' # Light red for model components
      stroke: '#333333' # Dark gray border
      strokeWidth: '2px' # Medium border width
      subgroupFill: '#f0e6e6' # Darker red for model subgroups
```

#### Graph Type Configurations

Specific settings for component graphs and control graphs:

```yaml
graphTypes:
  component:
    direction: 'TD' # Top-down layout for component relationships
    flowchartConfig:
      padding: 5 # Internal node padding
      wrappingWidth: 250 # Text wrapping width
  control:
    direction: 'LR' # Left-right layout optimized for control-to-component flow
    flowchartConfig:
      nodeSpacing: 25 # Space between nodes
      rankSpacing: 150 # Space between ranks/levels
      padding: 5 # Internal node padding
      wrappingWidth: 250 # Text wrapping width
    specialStyling:
      edgeStyles:
        multiEdgeStyles: # 4-color cycling system for controls with 3+ edges
          - stroke: '#9c27b0' # Purple - solid
            strokeWidth: '2px'
          - stroke: '#ff9800' # Orange - dashed
            strokeWidth: '2px'
            strokeDasharray: '5 5'
          - stroke: '#e91e63' # Pink - long dash
            strokeWidth: '2px'
            strokeDasharray: '10 2'
          - stroke: '#C95792' # Magenta - long dash with spacing
            strokeWidth: '2px'
            strokeDasharray: '10 5'
```

### Common Customization Examples

#### 1. Change Component Category Color Scheme

To modify the color scheme for component categories (affects both graph types):

```yaml
sharedElements:
  componentCategories:
    componentsInfrastructure:
      fill: '#e3f2fd' # Light blue instead of green
      stroke: '#333333'
      strokeWidth: '2px'
      subgroupFill: '#bbdefb' # Darker blue for subgroups
    componentsApplication:
      fill: '#f3e5f5' # Light purple instead of blue
      stroke: '#333333'
      strokeWidth: '2px'
      subgroupFill: '#e1bee7' # Darker purple for subgroups
```

#### 2. Modify Graph Layout and Spacing

To change graph orientation and spacing:

```yaml
graphTypes:
  component:
    direction: 'LR' # Change to left-right layout
    flowchartConfig:
      nodeSpacing: 40 # Increase space between nodes
      rankSpacing: 50 # Increase space between levels
      wrappingWidth: 300 # Allow wider text labels
  control:
    direction: 'TB' # Change to top-bottom layout
```

#### 3. Customize Multi-Edge Control Styling

To modify the 4-color cycling system for complex controls:

```yaml
graphTypes:
  control:
    specialStyling:
      edgeStyles:
        multiEdgeStyles:
          - stroke: '#1976d2' # Blue theme
            strokeWidth: '3px' # Thicker lines
          - stroke: '#388e3c' # Green
            strokeWidth: '3px'
            strokeDasharray: '8 8'
          - stroke: '#f57c00' # Orange
            strokeWidth: '3px'
            strokeDasharray: '12 4'
          - stroke: '#7b1fa2' # Purple
            strokeWidth: '3px'
            strokeDasharray: '15 5'
```

#### 4. Adjust Foundation Colors for Brand Consistency

To align with organizational brand colors:

```yaml
foundation:
  colors:
    primary: '#0066cc' # Your brand primary color
    success: '#00aa44' # Your brand success color
    accent: '#6600cc' # Your brand accent color
    neutral: '#404040' # Darker borders for better contrast
```

#### 5. Customize Risk Category Appearance

To modify colors for risk categories in the controls-to-risk graph:

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

**Note**: The current configuration uses a single `risks` category. Individual risk categories (like `risksSupplyChainAndDevelopment`, `risksDeploymentAndInfrastructure`, etc.) are defined in `risks.yaml` but share the same visual styling from this single `risks` configuration.

#### 6. Style All Three Graph Containers

To create a consistent appearance across the risk graph's three layers:

```yaml
graphTypes:
  risk:
    specialStyling:
      componentsContainer:
        fill: '#e8f5e9' # Light green - bottom layer (components)
        stroke: '#4caf50' # Green border
        strokeWidth: '3px'
        strokeDasharray: '10 5'
      controlsContainer:
        fill: '#e3f2fd' # Light blue - middle layer (controls)
        stroke: '#2196f3' # Blue border
        strokeWidth: '3px'
        strokeDasharray: '10 5'
      risksContainer:
        fill: '#fce4ec' # Light pink - top layer (risks)
        stroke: '#e91e63' # Pink border
        strokeWidth: '3px'
        strokeDasharray: '10 5'
```

### Testing Your Customizations

1. **Edit the configuration**: Modify `risk-map/yaml/mermaid-styles.yaml`

2. **Validate your changes** using the pre-commit hooks:

   ```bash
   # Stage your changes
   git add risk-map/yaml/mermaid-styles.yaml

   # Commit to trigger validation
   git commit -m "Update graph styling"
   ```

3. **Generate test graphs** to preview your changes:

   ```bash
   # Generate component graph with your styling
   python3 scripts/hooks/validate_riskmap.py --to-graph test-component.md --force

   # Generate control graph with your styling
   python3 scripts/hooks/validate_riskmap.py --to-controls-graph test-control.md --force
   ```

4. **View the results** by opening the generated Markdown files in a compatible viewer (see Visualizing Graphs below).

### Configuration Validation

The system automatically validates your configuration against a JSON schema that enforces:

- **Color format**: All colors must be valid 6-digit hex codes (`#RRGGBB`)
- **Required properties**: Essential configuration elements cannot be omitted
- **Value constraints**: Node spacing must be positive integers, direction must be valid Mermaid values (`TD`, `LR`, etc.)
- **Structural integrity**: Proper YAML structure and object nesting

If your configuration is invalid, you'll see detailed error messages indicating exactly what needs to be fixed.

### Fallback and Error Handling

The system includes robust fallback mechanisms:

- **Missing configuration file**: Uses built-in defaults that match the original hardcoded styling
- **Invalid configuration**: Falls back to defaults while displaying clear error messages
- **Partial configuration**: Missing elements use sensible defaults from the emergency configuration

This ensures that graph generation never fails due to configuration issues, allowing you to iterate on styling without breaking functionality.

### Visualizing Graphs During Development

The generated Mermaid graphs use the **Elk layout engine** for automatic positioning. To properly view these graphs during development:

#### Compatible Viewers:

- **Mermaid.ink**: Online service that supports Elk layout
  - Copy the `.mermaid` file content to https://mermaid.ink/
  - Provides accurate rendering of complex layouts
- **VS Code with Mermaid extensions** that support Elk (check extension documentation)
- **GitHub**: Native Mermaid rendering does not support Elk layout and the maps will appear as poorly organized or unwieldy to review

#### Generate Both Formats:

```bash
# Generate both .md and .mermaid formats for easier viewing
python scripts/hooks/validate_riskmap.py --to-graph ./test.md --mermaid-format --force

# This creates:
# - test.md (markdown with code block)
# - test.mermaid (raw mermaid content for online viewers)
```

#### Troubleshooting Visualization:

- **Layout appears broken**: Ensure your viewer supports Elk layout engine
- **Components overlap**: Try mermaid.ink which handles Elk positioning correctly
- **Styling not applied**: Some viewers may not support all Mermaid styling features

### Advanced Customization Tips

- **Consistent color schemes**: Use the `foundation.colors` section to define a palette, then reference these colors throughout the configuration
- **Accessibility**: Choose colors with sufficient contrast ratios for accessibility compliance
- **Testing**: Generate graphs with diverse content (few vs. many components/controls) to ensure your styling works across different scenarios
- **Version control**: Document your customization rationale in commit messages for future reference

## GitHub Actions Validation

The repository includes automated GitHub Actions that validate all pull requests against the same standards as local pre-commit hooks:

### Automated PR Validation

When you create a pull request, GitHub Actions automatically runs:

- **YAML Schema Validation**: All YAML files are validated against their JSON schemas
- **YAML Format Validation**: Ensures prettier formatting compliance
- **Python Code Quality**: Runs ruff linting on modified Python files
- **Component Edge Consistency**: Verifies bidirectional component relationships
- **Control-Risk Reference Integrity**: Validates control-risk cross-references
- **Graph Validation**: Generates and compares all three graph types

### Graph Validation in CI

The GitHub Actions workflow performs comprehensive graph validation:

1. **Generation**: Creates fresh graphs using `validate_riskmap.py`
2. **Comparison**: Compares generated graphs against committed versions in your PR
3. **Validation**: Ensures graphs are up-to-date with YAML changes
4. **Diff Output**: Provides detailed differences if validation fails

**Graphs Validated:**

- Component relationship graph (`./risk-map/docs/risk-map-graph.md`)
- Control-to-component graph (`./risk-map/docs/controls-graph.md`)
- Controls-to-risk graph (`./risk-map/docs/controls-to-risk-graph.md`)

### Handling CI Validation Failures

If GitHub Actions reports graph validation failures:

```bash
# Most common fix: regenerate graphs locally
python scripts/hooks/validate_riskmap.py --to-graph ./risk-map/docs/risk-map-graph.md --force
python scripts/hooks/validate_riskmap.py --to-controls-graph ./risk-map/docs/controls-graph.md --force
python scripts/hooks/validate_riskmap.py --to-risk-graph ./risk-map/docs/controls-to-risk-graph.md --force

# Commit the updated graphs
git add risk-map/docs/risk-map-graph.md risk-map/docs/controls-graph.md risk-map/docs/controls-to-risk-graph.md
git commit -m "Update generated graphs to reflect YAML changes"
git push
```

The CI validation ensures that all contributions maintain consistency and that generated documentation stays synchronized with the underlying data.

### SVG Generation from Mermaid Diagrams

The repository handles Mermaid diagrams with different approaches for local development versus GitHub Actions:

#### Pre-commit Hooks (Local Development)

- **Automatic SVG Creation**: When Mermaid files (`.mmd`, `.mermaid`) are staged for commit, pre-commit hooks generate corresponding SVG files
- **Auto-staging**: Generated SVG files are automatically added to the commit
- **Location**: SVGs are created in `./risk-map/svg/` directory
- **Prerequisites**: Requires Chrome/Chromium browser and mermaid-cli

#### GitHub Actions (Pull Request Validation)

- **Syntax Validation**: Ensures all Mermaid files compile successfully
- **Preview Generation**: Creates SVG previews attached as PR comments
- **Error Reporting**: Provides detailed error messages for syntax issues
- **Does NOT generate**: GitHub Actions do not create SVG files for commit

#### Platform Considerations

- **Mac/Windows/Linux x64**: Chrome automatically handled by puppeteer
- **Linux ARM64**: Requires manual Chromium setup:

  ```bash
  # Use the --install-playwright flag during setup
  ./scripts/install-precommit-hook.sh --install-playwright

  # Or install manually
  npx playwright install chromium --with-deps
  ```

## General Content Contribution Workflow

1. **Create a GitHub issue** to track your work (see Best Practices below)
2. Read the repository-wide [CONTRIBUTING.md](../../CONTRIBUTING.md) and follow the [Content Update Branching Process](../../CONTRIBUTING.md#for-content-updates-two-stage-process) for all content authoring
3. **Set up pre-commit hooks** (see Prerequisites above)
4. Make content changes per the guides below (components, controls, risks, personas)
5. **Validate your changes** against all validation rules:
   - JSON Schema validation
   - Prettier YAML formatting
   - Ruff Python linting (if modifying Python files)
   - Component edge consistency
   - Control-to-risk reference consistency
6. Open a PR against the `develop` branch describing the Risk Map updates and validation performed
   - GitHub Actions will automatically run the same validations on your PR
   - Address any CI failures before requesting review

---

## Contribution Guides

1.  [Adding a new component](#adding-a-component)
2.  [Adding a new control](#adding-a-control)
3.  [Adding a new risk](#adding-a-risk)
4.  [Adding a new persona](#adding-a-persona)

---

## Adding a Component

Once you've determined the need for a new component, the following steps are required to integrate it into the framework. For this example, we'll add a new component called `componentNewComponent` to the "Application" category.

### 1. Add the new component ID to the schema

First, declare the new component's unique ID in the schema. This makes the system aware of the new component and allows for validation.

- **File to edit**: `schemas/components.schema.json`
- **Action**: Find the `enum` list under `definitions.component.properties.id` and add your new component's ID. The ID should follow the `component[Name]` convention.

```json
// In schemas/components.schema.json
"id": {
  "type": "string",
  "enum": [
    ...
    "componentAgentPlugin",
    "componentNewComponent" // Add your new component ID here
  ]
},
```

### 2. Add the new component definition to the YAML file

Next, define the properties of your new component in the main data file. This includes its ID, title, a detailed description, and its category.

- **File to edit**: `components.yaml`
- **Action**: Add a new entry to the `components` list.

```yaml
# In yaml/components.yaml
- id: componentNewComponent
  title: New Component
  description:
    - >
      A detailed description of what this new component represents in the
      AI development lifecycle and why it is important for understanding risk.
  category: componentsApplication # Must match an id from the components.schema.json#/definitions/category/properties/id
  edges:
    to: []
    from: []
```

### 3. Define Edges for the New Component

Now, define the connections for your new component within its own `edges` block. The `to` list specifies where your component sends data (outgoing), and the `from` list specifies where it receives data from (incoming).

⚠️ **Critical**: Component edges must be **bidirectionally consistent**. The pre-commit hook will enforce this rule.

- **File to edit**: `components.yaml`
- **Action**: Update the `edges` block for `componentNewComponent`. For our example, let's say it receives data from `componentInputHandling` and sends data to `componentApplication`.

```yaml
# In yaml/components.yaml, under your new component's definition
edges:
  to:
    - componentApplication # Outgoing connection
  from:
    - componentInputHandling # Incoming connection
```

### 4. Update Edges on Connected Components

To make the connections bidirectional, you must now update the corresponding `edges` on the components you just referenced. **This step is critical** - the pre-commit hook will prevent commits if edges are not bidirectionally consistent.

- **File to edit**: `components.yaml`
- **Action**:
  1.  Find the `componentInputHandling` definition and add `componentNewComponent` to its `edges.to` list.
  2.  Find the `componentApplication` definition and add `componentNewComponent` to its `edges.from` list.

```yaml
# In the componentInputHandling definition:
- id: componentInputHandling
  # other properties
  edges:
    to:
      - componentTheModel
      - componentNewComponent # Add outgoing edge to your new component
    from:
      - componentApplication

# In the componentApplication definition:
- id: componentApplication
  # other properties
  edges:
    to:
      - componentInputHandling
      - componentAgentPlugin
    from:
      - componentOutputHandling
      - componentNewComponent # Add incoming edge from your new component
```

### 5. Validate Changes & Generate Graph

Before committing, validate that your changes are consistent:

```bash
# Manual validation (recommended during development)
python scripts/hooks/validate_riskmap.py --force

# Optional: Generate component graph to visualize your changes
python scripts/hooks/validate_riskmap.py --to-graph ./preview-graph.md --force

# Optional: Generate control-to-component graph to visualize control relationships
python scripts/hooks/validate_riskmap.py --to-controls-graph ./preview-controls.md --force

# Optional: Generate controls-to-risk graph to visualize risk relationships
python scripts/hooks/validate_riskmap.py --to-risk-graph ./preview-risks.md --force

# Format YAML files (auto-runs in pre-commit but useful for preview)
npx prettier --write risk-map/yaml/components.yaml

# The pre-commit hook will also run all validations automatically when you commit
git add risk-map/yaml/components.yaml
git commit -m "Add componentNewComponent with proper edge relationships"
```

The validation will check:

- ✅ All outgoing edges (`to`) have corresponding incoming edges (`from`) in target components
- ✅ All incoming edges (`from`) have corresponding outgoing edges (`to`) in source components
- ✅ No components are isolated (unless intentionally designed)
- ✅ All referenced components exist in the YAML file

**Note**: When you commit changes to `components.yaml`, the pre-commit hook automatically generates:

- Updated component graph at `./risk-map/docs/risk-map-graph.md`
- Component tables at `./risk-map/tables/components-full.md` and `components-summary.md`
- Regenerated cross-reference at `./risk-map/tables/controls-xref-components.md`

All files are automatically staged for your commit.

### 6. Create a Pull Request

After successful validation, follow the [General Content Contribution Workflow](#general-content-contribution-workflow) to create your pull request.

---

## Adding a Control

Adding a new control involves defining it and then mapping it to the components, personas, and risks it affects. For this example, let's add a hypothetical `controlNewControl`.

### 1. Add the new control ID to the schema

First, declare the new control's unique ID in the `controls.schema.json` file. This registers the new control with the framework. The ID should follow the `control[Name]` convention.

- **File to edit**: `schemas/controls.schema.json`
- **Action**: Find the `enum` list under `definitions.control.properties.id` and add your new control ID alphabetically.

```json
// In schemas/controls.schema.json
"id": {
  "type": "string",
  "enum": [
    ...
    "controlApplicationAccessManagement",
    "controlNewControl", // Add your new control ID here
    "controlIncidentResponseManagement",
    ...
  ]
},
```

### 2. Add the new control definition to the YAML file

Next, define the control's properties in the main `controls.yaml` data file. This is where you describe what the control is and map it to other parts of the framework.

- **File to edit**: `controls.yaml`
- **Action**: Add a new entry to the `controls` list. When filling out the properties, you must select valid IDs from the other schema files.

> **Note on universal controls**: For controls that apply broadly (e.g., governance or assurance tasks), you can use the string `"all"` for `components` and `risks`. For controls that don't apply to any specific component, use `"none"`.

```yaml
# Example of a specific control
- id: controlNewControl
  title: A New and Important Control
  description:
    - >
      A clear and concise description of what this control does, how it works,
      and why it is an effective safeguard.
  category: controlsModel
  personas:
    - personaModelCreator
    - personaModelConsumer
  components:
    - componentTheModel
    - componentOutputHandling
  risks:
    - IMO # Mapped to Insecure Model Output
    - PIJ # Mapped to Prompt Injection

# Example of a universal (governance) control
- id: controlRedTeaming
  title: Red Teaming
  description:
    - >
      Drive security and privacy improvements through self-driven adversarial attacks
      on AI infrastructure and products.
  category: controlsAssurance
  personas:
    - personaModelCreator
    - personaModelConsumer
  components: all # This control applies to all components
  risks: all # This control applies to all risks
```

### 3. Update Corresponding Risks

To ensure the framework remains fully connected, every risk that your new control mitigates must be updated to include a reference to that control. (This step is not necessary if you set `risks: all` in the previous step).

- **File to edit**: `risks.yaml`
- **Action**: For each risk ID you listed in the previous step (e.g., `IMO`, `PIJ`), find its definition in `risks.yaml` and add your new `controlNewControl` ID to its `controls` list.

```yaml
# In yaml/risks.yaml, under the IMO risk definition
- id: IMO
  # other properties
  controls:
    - controlOutputValidationAndSanitization
    - controlNewControl # Add your new control here
```

### 4. Validate Control-Risk References

Before committing, validate that your control-risk cross-references are consistent:

```bash
# Manual validation (recommended during development)
python scripts/hooks/validate_control_risk_references.py --force

# Format YAML files (auto-runs in pre-commit but useful for preview)
npx prettier --write risk-map/yaml/controls.yaml risk-map/yaml/risks.yaml

# The pre-commit hook will also run all validations automatically when you commit
git add risk-map/yaml/controls.yaml risk-map/yaml/risks.yaml
git commit -m "Add new control with proper risk relationships"
```

The validation will check:

- ✅ All controls that list risks in `controls.yaml` are referenced back by those risks in `risks.yaml`
- ✅ All risks that reference controls in `risks.yaml` have those controls listing them in `controls.yaml`
- ✅ No isolated entries (controls with empty risk lists, risks with empty control lists)

**Note**: When you commit changes to `controls.yaml`, the pre-commit hook automatically generates:

- Updated control graph at `./risk-map/docs/controls-graph.md`
- Updated risk graph at `./risk-map/docs/controls-to-risk-graph.md`
- All 4 control table formats in `./risk-map/tables/` (full, summary, xref-risks, xref-components)

All files are automatically staged for your commit.

**Example of consistent cross-references:**

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
      - CTRL-001 # Risk acknowledges this control
  - id: RISK-002
    controls:
      - CTRL-001 # Bidirectional consistency ✅
```

### 5. Validate and Create a Pull Request

Once validated, follow the [General Content Contribution Workflow](#general-content-contribution-workflow) to create your pull request.

---

## Adding a Risk

Risks represent the potential security threats that can affect the components of an AI system. Adding a new risk requires defining it and then connecting it to the controls that mitigate it.

### 1. Add the new risk ID to the schema

First, add a unique ID for the new risk to the `risks.schema.json` file. The ID should be a short, memorable, all-caps acronym.

- **File to edit**: `schemas/risks.schema.json`
- **Action**: Find the `enum` list under `definitions.risk.properties.id` and add your new risk ID alphabetically.

```json
// In schemas/risks.schema.json
"id": {
  "type": "string",
  "enum": ["DMS", "DP", "EDH", "IIC", "IMO", "ISD", "MDT", "MEV", "MRE", "MST", "MXF", "NEW", "PIJ", "RA", "SDD", "UTD"]
},
```

### 2. Add the new risk definition to the YAML file

Next, provide the full definition of the risk in `risks.yaml`. This includes its title, descriptions, associated personas, mitigating controls, and contextual information.

- **File to edit**: `risks.yaml`
- **Action**: Add a new entry to the `risks` list. The `personas` and `controls` lists must contain valid IDs from their respective schema files.

```yaml
# In yaml/risks.yaml
- id: NEW
  title: New Example Risk
  shortDescription:
    - >
      A brief, one-sentence explanation of the new risk.
  longDescription:
    - >
      A more detailed explanation of the risk, including how it can manifest
      and what its potential impact is.
  category: risksSupplyChainAndDevelopment # Required: Must match one of the risk categories
  personas:
    - personaModelConsumer
  controls:
    - controlNewControl
  examples: # Provide links to real-world examples or research
    - >
      A link to a real-world example or research paper describing this risk.
  tourContent: # Describe how the risk appears in the lifecycle map
    introduced:
      - >
        Where in the lifecycle this risk is typically introduced.
    exposed:
      - >
        Where in the lifecycle this risk is typically exposed or exploited.
    mitigated:
      - >
        Where in the lifecycle this risk is typically mitigated.
```

**Available Risk Categories:**

The `category` field is required and must be one of the following:

- `risksSupplyChainAndDevelopment` - Risks related to model development, training data, and supply chain
  - Examples: Data Poisoning (DP), Excessive Data Handling (EDH), Model Source Tampering (MST), Unauthorized Training Data (UTD)

- `risksDeploymentAndInfrastructure` - Risks in deployment environments and infrastructure
  - Examples: Insecure Integrated Component (IIC), Model Deployment Tampering (MDT), Model Exfiltration (MXF), Model Reverse Engineering (MRE)

- `risksRuntimeInputSecurity` - Risks from malicious or adversarial inputs at runtime
  - Examples: Denial of ML Service (DMS), Model Evasion (MEV), Prompt Injection (PIJ)

- `risksRuntimeDataSecurity` - Risks related to data security during model operation
  - Examples: Inferred Sensitive Data (ISD), Sensitive Data Disclosure (SDD)

- `risksRuntimeOutputSecurity` - Risks from insecure or malicious model outputs
  - Examples: Insecure Model Output (IMO), Rogue Actions (RA)

When adding a new risk, select the category that best describes where in the AI lifecycle the risk occurs. The category determines how the risk is grouped in the controls-to-risk visualization graph.

**Note on visualization**: While risks are categorized individually in `risks.yaml`, the current `mermaid-styles.yaml` configuration applies a single visual style to all risk categories. Risk categories are grouped separately in the generated graphs but share the same pink color scheme.

### 3. Update Corresponding Controls

To ensure the framework remains fully connected, every control that mitigates your new risk must be updated to include a reference back to that risk.

- **File to edit**: `controls.yaml`
- **Action**: For each control ID you listed in the previous step (e.g., `controlNewControl`), find its definition in `controls.yaml` and add your new risk's ID (`NEW`) to its `risks` list.

```yaml
# In yaml/controls.yaml, under the controlNewControl definition
- id: controlNewControl
  # other properties
  risks:
    - IMO
    - PIJ
    - NEW # Add your new risk ID here
```

### 4. Validate Control-Risk References

Before committing, validate that your control-to-risk cross-references are consistent:

```bash
# Manual validation (recommended during development)
python scripts/hooks/validate_control_risk_references.py --force

# Format YAML files (auto-runs in pre-commit but useful for preview)
npx prettier --write risk-map/yaml/controls.yaml risk-map/yaml/risks.yaml

# The pre-commit hook will also run all validations automatically when you commit
git add risk-map/yaml/controls.yaml risk-map/yaml/risks.yaml
git commit -m "Add new risk with proper control relationships"
```

The validation will check:

- ✅ All controls that list risks in `controls.yaml` are referenced back by those risks in `risks.yaml`
- ✅ All risks that reference controls in `risks.yaml` have those controls listing them in `controls.yaml`
- ✅ No isolated entries (controls with empty risk lists, risks with empty control lists)

**Example of consistent cross-references:**

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
      - CTRL-001 # Risk acknowledges this control
  - id: RISK-002
    controls:
      - CTRL-001 # Bidirectional consistency ✅
```

**Note**: When you commit changes to `risks.yaml`, the pre-commit hook automatically generates:

- Updated risk graph at `./risk-map/docs/controls-to-risk-graph.md`
- Risk tables at `./risk-map/tables/risks-full.md` and `risks-summary.md`
- Regenerated cross-reference at `./risk-map/tables/controls-xref-risks.md`

All files are automatically staged for your commit.

### 5. Validate and Create a Pull Request

Once validated, follow the [General Content Contribution Workflow](#general-content-contribution-workflow) to create your pull request.

---

## Adding a Persona

Personas define the key roles and responsibilities within the AI ecosystem. Adding a new persona is a straightforward process.

### 1. Add the new persona ID to the schema

First, declare the new persona's unique ID in the `personas.schema.json` file. The ID should follow the `persona[Name]` convention.

- **File to edit**: `schemas/personas.schema.json`
- **Action**: Find the `enum` list under `definitions.persona.properties.id` and add your new persona ID.

```json
// In schemas/personas.schema.json
"id": {
  "type": "string",
  "enum": ["personaModelCreator", "personaModelConsumer", "personaNewPersona"]
},
```

### 2. Add the new persona definition to the YAML file

Next, provide the definition for the new persona in the `personas.yaml` file.

- **File to edit**: `personas.yaml`
- **Action**: Add a new entry to the `personas` list with an `id`, `title`, and `description`.

```yaml
# In yaml/personas.yaml
- id: personaNewPersona
  title: New Persona
  description:
    - >
      A description of this new role, its responsibilities, and its
      relationship to the AI lifecycle.
```

### 3. Update Existing Risks and Controls

If this new persona is affected by existing risks or is responsible for implementing existing controls, you must update the corresponding YAML files to reflect this.

- **Files to edit**: `risks.yaml`, `controls.yaml`
- **Action**: Review the existing risks and controls. Add the `personaNewPersona` ID to the `personas` list of any relevant entry.

```yaml
# In yaml/controls.yaml, for an existing control:
- id: controlRiskGovernance
  # other properties
  personas:
    - personaModelCreator
    - personaModelConsumer
    - personaNewPersona # Add the new persona if they are responsible
```

### 4. Validate and Create a Pull Request

After making your changes, use a JSON schema validator to ensure that your updated files conform to their schemas. Once validated, follow the [General Content Contribution Workflow](#general-content-contribution-workflow) to create your pull request.

---

## Troubleshooting Validation Issues

### Edge Validation Errors

If the pre-commit hook or manual validation fails with edge consistency errors:

1. **Bidirectional Edge Mismatch**:

   ```
   Component 'componentA': missing incoming edges for: componentB
   ```

   **Fix**: Add `componentA` to `componentB`'s `edges.from` list

2. **Isolated Component**:
   ```
   Found 1 isolated components (no edges): componentX
   ```
   **Fix**: Add appropriate `to` and/or `from` edges, or verify if isolation is intentional

### Graph Generation Issues

If you encounter issues with the automatic graph generation:

1. **Component graph generation failed during pre-commit**:

   ```
   ❌ Graph generation failed
   ```

   **Fix**: Check that `components.yaml` is valid and accessible. Test manually:

   ```bash
   python scripts/hooks/validate_riskmap.py --to-graph ./test-graph.md --force
   ```

2. **Control-to-component graph generation failed**:

   ```
   ❌ Control-to-component graph generation failed
   ```

   **Fix**: Verify that both `controls.yaml` and `components.yaml` are accessible and properly formatted. Test manually:

   ```bash
   python scripts/hooks/validate_riskmap.py --to-controls-graph ./test-controls.md --force
   ```

3. **Generated graph not staged**:

   ```
   ⚠️ Warning: Could not stage generated graph
   ```

   **Fix**: Check file permissions and git repository status. Ensure `./risk-map/docs/` directory is writable.

4. **Component layout seems suboptimal**:
   **Fix**: Use debug mode to inspect graph structure:

   ```bash
   python scripts/hooks/validate_riskmap.py --to-graph ./debug-graph.md --debug --force
   ```

5. **Control graph looks cluttered or confusing**:
   **Fix**: The control graph uses automatic optimization. If results seem wrong, verify:
   - Control component references are accurate in `controls.yaml`
   - Component categories are correctly assigned in `components.yaml`
   - Test the graph generation manually to inspect the output

### Bypassing Validation (Not Recommended)

If you need to commit without running the pre-commit hook (strongly discouraged):

```bash
git commit --no-verify -m "commit message"
```

However, your changes will still be validated during the PR review process.

---

## Best Practices

1. **Create a GitHub issue first** for any ongoing development work:

   ```bash
   # Before starting work, create an issue to:
   # - Document the planned changes
   # - Enable collaboration and discussion
   # - Track progress and link related PRs
   # - Provide context for reviewers
   ```

   This helps maintain project visibility and enables better collaboration.

2. **Always run manual validation** during development:

   ```bash
   python scripts/hooks/validate_riskmap.py --force
   ```

3. **Preview your changes visually** by generating graphs:

   ```bash
   # Generate component relationship graph
   python scripts/hooks/validate_riskmap.py --to-graph ./preview-graph.md --force

   # Generate control-to-component relationship graph
   python scripts/hooks/validate_riskmap.py --to-controls-graph ./preview-controls.md --force

   # Generate controls-to-risk relationship graph
   python scripts/hooks/validate_riskmap.py --to-risk-graph ./preview-risks.md --force
   ```

4. **Format files before committing** (though pre-commit handles this automatically):

   ```bash
   npx prettier --write risk-map/yaml/*.yaml
   ```

5. **Test edge changes incrementally** - add one component connection at a time

6. **Document complex edge relationships** in commit messages

7. **Use meaningful component IDs** following the `component[Name]` convention

8. **Validation against JSON schemas** is enforced by the pre-commit otherwise validate before committing

9. **Review existing components** to understand established patterns before adding new ones

10. **Leverage automatic graph generation** - when you commit changes to `components.yaml`, the updated graph is automatically generated and staged

11. **Use debug mode for troubleshooting** graph generation issues:

    ```bash
    python scripts/hooks/validate_riskmap.py --to-graph ./debug-graph.md --debug --force
    ```

12. **Use control graphs to validate control-component mappings** when adding or modifying controls:

    ```bash
    # Generate control graph to verify your control mappings are logical
    python scripts/hooks/validate_riskmap.py --to-controls-graph ./verify-controls.md --force

    # Generate risk graph to verify control-risk relationships
    python scripts/hooks/validate_riskmap.py --to-risk-graph ./verify-risks.md --force
    ```

13. **Run all validations locally** before pushing:
    ```bash
    # Run the full pre-commit suite manually
    .git/hooks/pre-commit --force
    ```
