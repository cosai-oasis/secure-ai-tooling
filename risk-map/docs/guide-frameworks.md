# Adding and Using Frameworks

This guide explains how to work with external security framework mappings in the CoSAI Risk Map. Frameworks allow you to cross-reference risks and controls with established security standards like MITRE ATLAS, NIST AI RMF, STRIDE, and OWASP Top 10 for LLM.

---

## Overview

The framework system provides a structured way to:
- Map risks and controls to external security frameworks
- Maintain consistent framework identifiers across the project
- Track framework versions and documentation
- Enable automated validation of framework references

## Framework Structure

### Framework Definition File

Frameworks are defined in [`risk-map/yaml/frameworks.yaml`](../yaml/frameworks.yaml) as an array. Each framework includes:

```yaml
frameworks:
  - id: framework-id
    name: "Short Name"
    fullName: "Full Official Name"
    description: "Brief description"
    baseUri: "https://example.com"
    version: "1.0"                      # Optional: or null
    lastUpdated: "2024-01-01"          # Optional: or null
    techniqueUriPattern: "https://..."  # Optional
    documentUri: "https://..."          # Optional
```

### Required vs Optional Fields

**Required:**
- `id` - Must be in the frameworks.schema.json enum
- `name` - Short name for display
- `fullName` - Full official name
- `description` - Brief description of the framework
- `baseUri` - Base URL for framework documentation

**Optional:**
- `version` - Framework version string or null
- `lastUpdated` - Date in YYYY-MM-DD format or null
- `techniqueUriPattern` - URL pattern with `{id}` placeholder
- `documentUri` - Direct link to specification document

---

## Adding a New Framework

### Step 1: Update the Schema Enum

Add your framework ID to the enum in [`risk-map/schemas/frameworks.schema.json`](../schemas/frameworks.schema.json):

```json
"enum": [
  "mitre-atlas",
  "nist-ai-rmf",
  "stride",
  "owasp-top10-llm",
  "your-new-framework-id"
]
```

### Step 2: Add Framework Definition

Add the framework to the array in [`risk-map/yaml/frameworks.yaml`](../yaml/frameworks.yaml):

```yaml
frameworks:
  # ... existing frameworks ...

  - id: your-new-framework-id
    name: "Framework Name"
    fullName: "Full Framework Name"
    description: "Brief description of the framework's purpose"
    baseUri: "https://framework-website.com"
    version: "2.0"
    lastUpdated: "2024-01-15"
    techniqueUriPattern: "https://framework-website.com/techniques/{id}"
    documentUri: "https://framework-website.com/docs/specification.pdf"
```

### Step 3: Validate

Run validation to ensure your changes are correct:

```bash
# Run framework reference validation
python scripts/hooks/validate_framework_references.py --force

# Run full validation including edge checks and cross-references
python scripts/hooks/validate_riskmap.py --force
python scripts/hooks/validate_control_risk_references.py --force
```

---

## Using Framework Mappings in Risks and Controls

Once frameworks are defined, you can reference them in risk and control definitions using the `mappings` field.

### Example: Adding Framework Mappings to Risks

In [`risk-map/yaml/risks.yaml`](../yaml/risks.yaml):

```yaml
risks:
  - id: DP
    title: Data Poisoning
    # ... other required fields ...
    mappings:
      mitre-atlas:
        - AML.T0018
        - AML.T0020
      nist-ai-rmf:
        - MS-2.7
        - MS-2.8
      stride:
        - tampering
```

### Example: Adding Framework Mappings to Controls

In [`risk-map/yaml/controls.yaml`](../yaml/controls.yaml):

```yaml
controls:
  - id: controlTrainingDataSanitization
    title: Training Data Sanitization
    # ... other required fields ...
    mappings:
      mitre-atlas:
        - AML.M0005
      nist-ai-rmf:
        - MP-4.1
```

**Note**: Risks and controls also support additional optional metadata fields (`lifecycleStage`, `impactType`, `actorAccess`). See [Metadata Fields Guide](guide-metadata.md) for details


## Examples

### Complete Risk Example

```yaml
- id: MST
  title: Model Supply Chain Compromise
  shortDescription:
    - "Compromising model artifacts or dependencies in the supply chain"
  longDescription:
    - "Attackers compromise the model supply chain by injecting malicious code..."
  category: risksSupplyChainAndDevelopment
  personas:
    - personaModelCreator
    - personaModelConsumer
  controls:
    - controlVulnerabilityManagement
    - controlModelAndDataIntegrityManagement
  mappings:
    mitre-atlas:
      - AML.T0010
    stride:
      - tampering
      - elevation-of-privilege
    owasp-top10-llm:
      - LLM05
  lifecycleStage:
    - data-preparation
    - model-training
    - deployment
  impactType:
    - integrity
    - availability
    - safety
  actorAccess:
    - supply-chain
```

### Complete Control Example

```yaml
- id: controlModelAndDataIntegrityManagement
  title: Model and Data Integrity Management
  description:
    - "Implement cryptographic signing and verification for models and datasets"
  category: controlsModel
  personas:
    - personaModelCreator
    - personaModelConsumer
  components:
    - componentModelStorage
    - componentModelServing
  risks:
    - MST
    - MDT
  mappings:
    mitre-atlas:
      - AML.M0013
    nist-ai-rmf:
      - SC-8
      - SI-7
  lifecycleStage:
    - data-preparation
    - model-training
    - deployment
    - runtime
  impactType:
    - integrity
    - accountability
  actorAccess:
    - supply-chain
    - privileged
```

---

## Validation Rules

The schema enforces these validation rules:

1. **Framework ID Validation**: All keys in the `mappings` object must match framework IDs defined in the frameworks schema enum
2. **Array Values**: Each framework mapping must be an array of strings
3. **Optional Fields**: All four metadata fields (`mappings`, `lifecycleStage`, `impactType`, `actorAccess`) are optional
4. **Enum Constraints**: Values in `lifecycleStage`, `impactType`, and `actorAccess` must match their respective schema enums
5. **Framework Definition**: Each framework in `frameworks.yaml` must include all required fields (`id`, `name`, `fullName`, `description`, `baseUri`)

---

## Common Patterns

### Mapping Multiple Techniques

```yaml
mappings:
  mitre-atlas:
    - AML.T0001
    - AML.T0002
    - AML.T0003
  stride:
    - spoofing
    - tampering
```

### Partial Metadata

You can include only the fields relevant to your risk or control:

```yaml
# Only mappings
mappings:
  mitre-atlas:
    - AML.T0015

# Only lifecycle and impact
lifecycleStage:
  - runtime
impactType:
  - confidentiality
```

### All Lifecycle Stages

For risks or controls that apply throughout the lifecycle:

```yaml
lifecycleStage:
  - planning
  - data-preparation
  - model-training
  - development
  - evaluation
  - deployment
  - runtime
  - maintenance
```

---

## Best Practices

1. **Use Official Identifiers**: When mapping to frameworks, use the official technique/control IDs from the framework documentation
2. **Keep Descriptions Current**: Update `lastUpdated` dates when frameworks release new versions
3. **Document URI Patterns**: Include `techniqueUriPattern` to enable automatic link generation
4. **Validate Regularly**: Run schema validation after adding or modifying framework mappings
5. **Be Selective**: Only include the most relevant framework mappings rather than exhaustive lists
6. **Review Impact Types**: Choose impact types that accurately reflect the primary security concerns

---

## Troubleshooting

### Invalid Framework ID Error

**Error:** `Property name does not match any enum value`

**Solution:** Ensure the framework ID is added to the enum in `frameworks.schema.json`

### Schema Validation Failure

**Error:** `Missing required field`

**Solution:** Every framework definition must include all required fields: `id`, `name`, `fullName`, `description`, `baseUri`

### Invalid Metadata Value

**Error:** `Value not in enum`

**Solution:** Ensure the value matches one of the valid options defined in the respective schema (`lifecycle-stage.schema.json`, `impact-type.schema.json`, or `actor-access.schema.json`)

---

## Query Examples

The extended metadata fields enable powerful querying and analysis capabilities. Here are practical examples demonstrating how to use these fields programmatically.

### Example 1: Filter Risks by Runtime Lifecycle Stage

Find all risks that occur during the runtime phase:

```python
import yaml

with open('risk-map/yaml/risks.yaml', 'r') as f:
    risks_data = yaml.safe_load(f)

runtime_risks = []
for risk in risks_data['risks']:
    lifecycle = risk.get('lifecycleStage', [])
    # Handle both array and string values
    if isinstance(lifecycle, list) and 'runtime' in lifecycle:
        runtime_risks.append(risk['id'])
    elif lifecycle == 'all':
        runtime_risks.append(risk['id'])

print(f"Risks occurring at runtime: {runtime_risks}")
# Output: ['MEV', 'PIJ', 'DMS', 'MRE', 'SDD', 'ISD', 'IMO', 'RA', 'MDT', 'MXF', ...]
```

### Example 2: Find Risks Mapped to MITRE ATLAS Techniques

Query all risks that map to specific MITRE ATLAS techniques:

```python
import yaml

with open('risk-map/yaml/risks.yaml', 'r') as f:
    risks_data = yaml.safe_load(f)

mitre_atlas_risks = {}
for risk in risks_data['risks']:
    mappings = risk.get('mappings', {})
    if 'mitre-atlas' in mappings:
        mitre_atlas_risks[risk['id']] = {
            'title': risk['title'],
            'techniques': mappings['mitre-atlas']
        }

# Find risks mapping to a specific technique
target_technique = 'AML.T0020'
for risk_id, info in mitre_atlas_risks.items():
    if target_technique in info['techniques']:
        print(f"{risk_id}: {info['title']} -> {target_technique}")
# Output: DP: Data Poisoning -> AML.T0020
```

### Example 3: Query Controls by Confidentiality Impact

Find controls that protect confidentiality:

```python
import yaml

with open('risk-map/yaml/controls.yaml', 'r') as f:
    controls_data = yaml.safe_load(f)

confidentiality_controls = []
for control in controls_data['controls']:
    impact = control.get('impactType', [])
    # Handle both array and string values
    if isinstance(impact, list) and 'confidentiality' in impact:
        confidentiality_controls.append({
            'id': control['id'],
            'title': control['title'],
            'impacts': impact
        })
    elif impact == 'all':
        confidentiality_controls.append({
            'id': control['id'],
            'title': control['title'],
            'impacts': 'all'
        })

print(f"Found {len(confidentiality_controls)} controls protecting confidentiality")
for ctrl in confidentiality_controls[:3]:
    print(f"  - {ctrl['id']}: {ctrl['title']}")
```

### Example 4: Get All Risks for Specific Actor Access Level

Find risks that can be exploited by external attackers:

```python
import yaml

with open('risk-map/yaml/risks.yaml', 'r') as f:
    risks_data = yaml.safe_load(f)

external_actor_risks = []
for risk in risks_data['risks']:
    actor_access = risk.get('actorAccess', [])
    # Handle both array and string values
    if isinstance(actor_access, list) and 'external' in actor_access:
        external_actor_risks.append({
            'id': risk['id'],
            'title': risk['title'],
            'access_levels': actor_access
        })
    elif actor_access == 'all':
        external_actor_risks.append({
            'id': risk['id'],
            'title': risk['title'],
            'access_levels': 'all'
        })

print(f"Risks exploitable by external actors: {len(external_actor_risks)}")
for risk in external_actor_risks[:5]:
    print(f"  - {risk['id']}: {risk['title']}")
# Output includes: PIJ, MEV, DMS, MRE, SDD, IMO, RA, IIC...
```

### Example 5: Construct URIs Using techniqueUriPattern

Generate clickable links to framework techniques:

```python
import yaml

with open('risk-map/yaml/frameworks.yaml', 'r') as f:
    frameworks_data = yaml.safe_load(f)

with open('risk-map/yaml/risks.yaml', 'r') as f:
    risks_data = yaml.safe_load(f)

# Build framework lookup
frameworks = {fw['id']: fw for fw in frameworks_data['frameworks']}

# Generate URIs for risk mappings
risk_id = 'DP'  # Data Poisoning
risk = next(r for r in risks_data['risks'] if r['id'] == risk_id)
mappings = risk.get('mappings', {})

if 'mitre-atlas' in mappings:
    framework = frameworks['mitre-atlas']
    pattern = framework.get('techniqueUriPattern')

    if pattern:
        print(f"MITRE ATLAS techniques for {risk['title']}:")
        for technique in mappings['mitre-atlas']:
            uri = pattern.replace('{id}', technique)
            print(f"  - {technique}: {uri}")
# Output:
#   MITRE ATLAS techniques for Data Poisoning:
#   - AML.T0020: https://atlas.mitre.org/techniques/AML.T0020
#   - AML.T0019: https://atlas.mitre.org/techniques/AML.T0019
#   - ...
```

### Example 6: Cross-Reference Risks, Controls, and Frameworks

Build a comprehensive mapping view:

```python
import yaml

# Load all data
with open('risk-map/yaml/risks.yaml', 'r') as f:
    risks = {r['id']: r for r in yaml.safe_load(f)['risks']}

with open('risk-map/yaml/controls.yaml', 'r') as f:
    controls = {c['id']: c for c in yaml.safe_load(f)['controls']}

with open('risk-map/yaml/frameworks.yaml', 'r') as f:
    frameworks = {fw['id']: fw for fw in yaml.safe_load(f)['frameworks']}

# Find controls for a risk and their framework mappings
risk_id = 'DP'
risk = risks[risk_id]

print(f"Risk: {risk['title']} ({risk_id})")
print(f"Framework Mappings:")
for fw_id, techniques in risk.get('mappings', {}).items():
    print(f"  {frameworks[fw_id]['name']}: {', '.join(techniques)}")

print(f"\nControls:")
for control_id in risk.get('controls', []):
    control = controls[control_id]
    print(f"  - {control['title']}")
    for fw_id, techniques in control.get('mappings', {}).items():
        print(f"    {frameworks[fw_id]['name']}: {', '.join(techniques)}")
```

### Example 7: Generate Framework Coverage Report

Analyze which frameworks are most referenced:

```python
import yaml
from collections import defaultdict

with open('risk-map/yaml/risks.yaml', 'r') as f:
    risks_data = yaml.safe_load(f)

with open('risk-map/yaml/controls.yaml', 'r') as f:
    controls_data = yaml.safe_load(f)

framework_coverage = defaultdict(lambda: {'risks': 0, 'controls': 0})

# Count risk mappings
for risk in risks_data['risks']:
    for fw_id in risk.get('mappings', {}).keys():
        framework_coverage[fw_id]['risks'] += 1

# Count control mappings
for control in controls_data['controls']:
    for fw_id in control.get('mappings', {}).keys():
        framework_coverage[fw_id]['controls'] += 1

print("Framework Coverage Report:")
for fw_id, counts in sorted(framework_coverage.items()):
    print(f"{fw_id}: {counts['risks']} risks, {counts['controls']} controls")
# Output:
#   mitre-atlas: 16 risks, 8 controls
#   stride: 14 risks, 0 controls
#   owasp-top10-llm: 12 risks, 0 controls
#   nist-ai-rmf: 0 risks, 2 controls
```

---

## URI Construction Guidelines

When using `techniqueUriPattern`, follow these guidelines:

1. **Placeholder Syntax**: Use `{id}` as the placeholder in URI patterns
   ```yaml
   techniqueUriPattern: "https://example.com/techniques/{id}"
   ```

2. **ID Format**: Ensure technique IDs in mappings match the expected format
   ```yaml
   mappings:
     mitre-atlas:
       - AML.T0020  # Will become: https://atlas.mitre.org/techniques/AML.T0020
   ```

3. **Validation**: The pattern should produce valid, accessible URIs when IDs are substituted

4. **Optional Field**: Not all frameworks require `techniqueUriPattern`
   - Include it when the framework has a consistent URL structure
   - Omit it for frameworks without online technique documentation

---

## Related Documentation

- [Adding a Risk](guide-risks.md) - Complete guide for adding new risks
- [Adding a Control](guide-controls.md) - Complete guide for adding new controls
- [Validation Tools](validation.md) - Schema validation and testing
- [Workflow](workflow.md) - General contribution workflow
