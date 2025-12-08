# Adding a Risk

Risks represent the potential security threats that can affect the components of an AI system. Adding a new risk requires defining it and then connecting it to the controls that mitigate it.

## 1. Add the new risk ID to the schema

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

## 2. Add the new risk definition to the YAML file

Next, provide the full definition of the risk in `risks.yaml`. This includes its title, descriptions, associated personas, mitigating controls, and contextual information.

- **File to edit**: `risks.yaml`
- **Action**: Add a new entry to the `risks` list. The `personas` and `controls` lists must contain valid IDs from their respective schema files.

> **Optional Metadata Fields**: You can also add optional metadata fields like `mappings` (framework cross-references), `lifecycleStage`, `impactType`, and `actorAccess` to provide additional context. These fields support both specific arrays (e.g., `lifecycleStage: [planning, deployment]`) and universal values (e.g., `lifecycleStage: all` or `lifecycleStage: none`). See [Metadata Fields Guide](guide-metadata.md) for details.

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

## 3. Update Corresponding Controls

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

### ⚠️ Important: Do NOT List Universal Controls

Some controls have `risks: all` in controls.yaml, marking them as **universal controls**. These controls apply implicitly to all risks and should **NOT** be listed in the risk's `controls` field.

**Universal Controls (Do NOT list these):**
- controlRedTeaming
- controlVulnerabilityManagement
- controlThreatDetection
- controlIncidentResponseManagement
- controlInternalPoliciesAndEducation
- controlProductGovernance
- controlRiskGovernance

**Example:**

```yaml
# ❌ WRONG
- id: DataPoisoning
  controls:
    - controlTrainingDataSanitization  # ✅ OK - specific control
    - controlRedTeaming                # ❌ NO - universal control

# ✅ CORRECT
- id: DataPoisoning
  controls:
    - controlTrainingDataSanitization  # ✅ Only list specific controls
    # Universal controls like Red Teaming apply automatically
```

If you receive a validation error about "explicitly lists universal control", remove that control from the risk's `controls` list.

## 4. Validate Control-Risk References

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

- Updated risk graph at `./risk-map/diagrams/controls-to-risk-graph.md`
- Risk tables at `./risk-map/tables/risks-full.md` and `risks-summary.md`
- Regenerated cross-reference at `./risk-map/tables/controls-xref-risks.md`

All files are automatically staged for your commit.

## 5. Validate and Create a Pull Request

Once validated, follow the [General Content Contribution Workflow](workflow.md) to create your pull request.

---

**Related:**
- [Validation Tools](validation.md) - Detailed validation commands
- [Troubleshooting](troubleshooting.md) - Help with validation errors
- [Best Practices](best-practices.md) - Development workflow tips
