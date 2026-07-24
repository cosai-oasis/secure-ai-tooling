# Adding a Component

Once you've determined the need for a new component, the following steps are required to integrate it into the framework. For this example, we'll add a new component called `componentNewComponent` to the "Application" category.

> **Tip:** You can draft this manually with the steps below, or start from an assisted draft — invoke the [`component-creator`](../../scripts/agents/component-creator.md) agent, stress-test the draft with [`component-critic`](../../scripts/agents/component-critic.md), then run [`content-reviewer`](../../scripts/agents/content-reviewer.md). See [Authoring with Agents](contributing/authoring-with-agents.md).

## 1. Add the new component ID to the schema

First, derive the new component ID from the component title (`component` + camelCase descriptor — e.g., "Feature Store" → `componentFeatureStore`) and declare it in the schema. This makes the system aware of the new component and allows for validation. (The issue-template flow derives this ID automatically; when authoring YAML/schema directly via PR, apply the same convention by hand.)

- **File to edit**: `schemas/components.schema.json`
- **Action**: Find the `enum` list under `definitions.component.properties.id` and add your new component's ID alphabetically.

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

## 2. Add the new component definition to the YAML file

Next, define the properties of your new component in the main data file. This includes its ID, title, a detailed description, and its category.

> **Title convention**: Component titles must be short concrete nouns (1-4 words) that name the architectural element. See the [Component Titles Style Guide](contributing/component-titles-style-guide.md) for rules and examples.

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

## 3. Define Edges for the New Component

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

## 4. Update Edges on Connected Components

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

## 5. Validate Changes & Generate Graph

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

- Updated component graph at `./risk-map/diagrams/risk-map-graph.md`
- Component tables at `./risk-map/tables/components-full.md` and `components-summary.md`
- Regenerated cross-reference at `./risk-map/tables/controls-xref-components.md`

All files are automatically staged for your commit.

## 6. Create a Pull Request

After successful validation, follow the [General Content Contribution Workflow](workflow.md) to create your pull request.

---

**Related:**
- [Component Titles Style Guide](contributing/component-titles-style-guide.md) - Title naming convention and reviewer checklist
- [Validation Tools](validation.md) - Detailed validation commands
- [Troubleshooting](troubleshooting.md) - Help with edge validation errors
- [Best Practices](best-practices.md) - Development workflow tips
