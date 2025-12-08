# Adding a Control

Adding a new control involves defining it and then mapping it to the components, personas, and risks it affects. For this example, let's add a hypothetical `controlNewControl`.

## 1. Add the new control ID to the schema

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

## 2. Add the new control definition to the YAML file

Next, define the control's properties in the main `controls.yaml` data file. This is where you describe what the control is and map it to other parts of the framework.

- **File to edit**: `controls.yaml`
- **Action**: Add a new entry to the `controls` list. When filling out the properties, you must select valid IDs from the other schema files.

> **Note on universal controls**: For controls that apply broadly (e.g., governance or assurance tasks), you can use the string `"all"` for `components` and `risks`. For controls that don't apply to any specific component, use `"none"`.

> **Optional Metadata Fields**: You can also add optional metadata fields like `mappings` (framework cross-references), `lifecycleStage`, `impactType`, and `actorAccess` to provide additional context. These fields support both specific arrays (e.g., `lifecycleStage: [planning, deployment]`) and universal values (e.g., `lifecycleStage: all`). See [Metadata Fields Guide](guide-metadata.md) for details.

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

## 3. Update Corresponding Risks

To ensure the framework remains fully connected, every risk that your new control mitigates must be updated to include a reference to that control. (This step is not necessary if you set `risks: all` in the previous step).

### ⚠️ Important: Universal Controls

Controls that apply to **all risks** should use the keyword `all`:

```yaml
- id: controlRedTeaming
  risks: all  # Universal - applies to all risks implicitly
```

**When a control has `risks: all`, it is a universal control.** This means:
- The control applies implicitly to ALL risks in the framework
- Risks should **NOT** explicitly list this control in their `controls` field
- The universal application is automatic

**Example of INCORRECT usage:**

```yaml
# ❌ WRONG - Don't do this!
# In risks.yaml
- id: DataPoisoning
  controls:
    - controlRedTeaming  # ❌ This is a universal control - don't list it!
```

**Example of CORRECT usage:**

```yaml
# ✅ CORRECT
# In risks.yaml
- id: DataPoisoning
  controls:
    - controlTrainingDataSanitization  # ✅ Only list specific controls
    # controlRedTeaming applies implicitly (don't list it)
```

**Universal Controls in the Framework:**
- controlRedTeaming
- controlVulnerabilityManagement
- controlThreatDetection
- controlIncidentResponseManagement
- controlInternalPoliciesAndEducation
- controlProductGovernance
- controlRiskGovernance

These controls apply to all risks by default and should never be explicitly listed in risks.yaml.

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

## 4. Validate Control-Risk References

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

- Updated control graph at `./risk-map/diagrams/controls-graph.md`
- Updated risk graph at `./risk-map/diagrams/controls-to-risk-graph.md`
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

## 5. Validate and Create a Pull Request

Once validated, follow the [General Content Contribution Workflow](workflow.md) to create your pull request.

---

**Related:**
- [Validation Tools](validation.md) - Detailed validation commands
- [Troubleshooting](troubleshooting.md) - Help with validation errors
- [Best Practices](best-practices.md) - Development workflow tips
