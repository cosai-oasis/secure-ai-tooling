# Metadata Fields for Risks and Controls

This guide explains the optional metadata fields that can be added to risks and controls to provide additional context and enable better analysis. These fields are defined in separate schema and YAML files for maintainability.

---

## Overview

Risks and controls in the CoSAI Risk Map support four optional metadata fields:

1. **mappings** - Cross-references to external security frameworks
2. **lifecycleStage** - AI system lifecycle phases where the risk/control is relevant
3. **impactType** - Security, privacy, or safety impact categories
4. **actorAccess** - Threat actor access level requirements

All four fields are optional. Include only the fields that are relevant to your specific risk or control.

---

## mappings

Cross-references to external security frameworks like MITRE ATLAS, NIST AI RMF, STRIDE, and OWASP Top 10 for LLM.

### Structure

```yaml
mappings:
  framework-id: ["technique-1", "technique-2"]
```

### Valid Framework IDs

Must match one of the frameworks defined in [`frameworks.yaml`](../yaml/frameworks.yaml):
- `mitre-atlas`
- `nist-ai-rmf`
- `stride`
- `owasp-top10-llm`

### Example

```yaml
mappings:
  mitre-atlas: ["AML.T0018", "AML.T0020"]
  nist-ai-rmf: ["MS-2.7", "MS-2.8"]
  stride: ["tampering"]
```

**See Also**: [Framework Guide](guide-frameworks.md) for adding new frameworks

---

## lifecycleStage

Indicates which AI system lifecycle phases are relevant to this risk or control.

### Structure

```yaml
lifecycleStage:
  - stage-id-1
  - stage-id-2
```

### Definition Files

- **Schema**: [`lifecycle-stage.schema.json`](../schemas/lifecycle-stage.schema.json)
- **YAML**: [`lifecycle-stage.yaml`](../yaml/lifecycle-stage.yaml)

### Valid Values

The 8-stage AI lifecycle model:

1. **planning** - Initial planning, design, and architecture definition
2. **data-preparation** - Data collection, cleaning, labeling, and preparation
3. **model-training** - Model training, fine-tuning, and optimization
4. **development** - Application development and AI model integration
5. **evaluation** - Testing, validation, and performance evaluation
6. **deployment** - Production deployment and initial rollout
7. **runtime** - Active operation and serving in production
8. **maintenance** - Ongoing monitoring, updates, and retraining

### Example

```yaml
lifecycleStage:
  - data-preparation
  - model-training
  - evaluation
```

---

## impactType

Categorizes the security, privacy, or safety impacts that the risk poses or the control addresses.

### Structure

```yaml
impactType:
  - impact-id-1
  - impact-id-2
```

### Definition Files

- **Schema**: [`impact-type.schema.json`](../schemas/impact-type.schema.json)
- **YAML**: [`impact-type.yaml`](../yaml/impact-type.yaml)

### Valid Values

**Traditional Security:**
- **confidentiality** - Protection from unauthorized access or disclosure
- **integrity** - Ensuring accuracy and preventing tampering
- **availability** - Maintaining system accessibility
- **privacy** - Protection of personal/sensitive information
- **compliance** - Adherence to regulations and standards

**AI-Specific:**
- **safety** - Prevention of physical harm or dangerous outcomes
- **fairness** - Equitable treatment and absence of bias
- **accountability** - Traceability and responsibility attribution
- **reliability** - Consistency and dependability of performance
- **transparency** - Explainability and interpretability

### Example

```yaml
impactType:
  - integrity
  - reliability
  - safety
```

---

## actorAccess

Specifies the level of system access required by threat actors to exploit a risk, or the access level that a control protects against.

### Structure

```yaml
actorAccess:
  - access-level-1
  - access-level-2
```

### Definition Files

- **Schema**: [`actor-access.schema.json`](../schemas/actor-access.schema.json)
- **YAML**: [`actor-access.yaml`](../yaml/actor-access.yaml)

### Valid Values

**Traditional:**
- **none** - External attackers with no direct access
- **api** - Public or authenticated API endpoint access
- **user** - Standard authenticated user access
- **privileged** - Elevated privileges (admin, operator)
- **physical** - Physical access to hardware/facilities

**Modern (AI-Specific):**
- **agent** - AI agents with tool/plugin execution capabilities
- **supply-chain** - Position in software/data/model supply chain
- **infrastructure-provider** - Cloud or infrastructure provider access
- **service-provider** - Third-party service provider access

### Example

```yaml
actorAccess:
  - supply-chain
  - privileged
```

---

## Complete Examples

### Risk with All Metadata Fields

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
    mitre-atlas: ["AML.T0010"]
    stride: ["tampering", "elevation-of-privilege"]
    owasp-top10-llm: ["LLM05"]
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

### Control with All Metadata Fields

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
    mitre-atlas: ["AML.M0013"]
    nist-ai-rmf: ["SC-8", "SI-7"]
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

### Partial Metadata (Recommended)

You can include only the fields that are relevant:

```yaml
# Only framework mappings
- id: RISK-001
  # ... required fields ...
  mappings:
    mitre-atlas: ["AML.T0015"]

# Only lifecycle and impact
- id: RISK-002
  # ... required fields ...
  lifecycleStage:
    - runtime
  impactType:
    - confidentiality
```

---

## Validation

All metadata fields are validated against their respective schemas:

```bash
# Validate all YAML files including metadata
python scripts/hooks/validate_riskmap.py --force
```

**Common validation errors:**

1. **Invalid framework ID**: Ensure the framework exists in `frameworks.yaml`
2. **Invalid lifecycle stage**: Must be one of the 8 stages defined in `lifecycle-stage.yaml`
3. **Invalid impact type**: Must be one of the 10 types defined in `impact-type.yaml`
4. **Invalid actor access**: Must be one of the 9 levels defined in `actor-access.yaml`

---

## Best Practices

1. **Be selective**: Only include metadata fields that add meaningful context
2. **Use multiple values**: Most metadata fields accept arrays - include all relevant values
3. **Consider the full lifecycle**: Think about where risks/controls apply across all 8 stages
4. **Map to multiple frameworks**: Cross-referencing helps users from different security backgrounds
5. **Choose primary impacts**: Focus on the most significant impact types rather than listing everything

---

## Related Documentation

- [Framework Guide](guide-frameworks.md) - Adding and managing external frameworks
- [Risk Guide](guide-risks.md) - Complete guide for adding risks
- [Control Guide](guide-controls.md) - Complete guide for adding controls
- [Validation Tools](validation.md) - Schema validation and testing
