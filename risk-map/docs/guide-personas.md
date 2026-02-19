# Personas Guide

This guide explains the CoSAI Risk Map persona model, which defines distinct sets of activities and responsibilities within the AI ecosystem. Personas are used to assign ownership of security controls and identify who is affected by specific risks.

---

## Overview

The CoSAI Risk Map defines eight standard personas representing distinct activity clusters across the AI system lifecycle. Each persona delineates who is impacted by specific risks and who is responsible for implementing the corresponding security controls. This structure ensures clear accountability while enabling alignment with external standards such as ISO/IEC 22989.

### Why Personas Matter

Personas provide a structured foundation for AI security governance by enabling:

- **Clear accountability** – Define well-defined security responsibilities that don't overlap ambiguously, ensuring every control has a distinct owner.
- **Lifecycle completeness** – Address all stages of the **AI system lifecycle** through activity groupings that ensure continuous oversight without excessive granularity.
- **Targeted risk assessment** – Delineate specifically who is impacted by a threat versus who is responsible for enacting the controls to mitigate it.
- **Framework interoperability** – Map directly to established international standards (such as **ISO/IEC 22989**) to ensure the Risk Map remains compatible with global compliance requirements.

---

## Current Personas

### Model Provider (`personaModelProvider`)

Actors that develop, train, evaluate, and tune AI/ML models (foundation models, specialized models, or domain-adapted models). This includes those that develop models from scratch or significantly modify existing models for distribution.

**Responsibilities:**
- Model architecture design and training
- Model evaluation and validation
- Model documentation and cards
- Model versioning and updates

**Framework Mapping:**
- ISO 22989: AI Producer

---

### Data Provider (`personaDataProvider`)

Actors that supply training data, evaluation datasets, or inference data to model providers or application developers. This includes data aggregators, data marketplaces, and those licensing datasets.

**Responsibilities:**
- Data quality assurance
- Data provenance tracking
- Data licensing and compliance
- Data privacy protections

**Framework Mapping:**
- ISO 22989: AI Partner (data supplier)

---

### AI Platform Provider (`personaPlatformProvider`)

Actors that provide infrastructure, compute resources, APIs, and platform services for AI model hosting, training, or inference. This includes internal infrastructure teams, cloud providers (AWS, Azure, GCP), MLOps platforms, and model API services.

**Responsibilities:**
- Infrastructure security and availability
- API security and rate limiting
- Compute resource allocation
- Model hosting and serving

**Framework Mapping:**
- ISO 22989: AI Partner (infrastructure provider)

---

### AI Model Serving (`personaModelServing`)

The entity responsible for provisioning, managing, and securing the runtime environment that serves AI and ML model predictions at scale. This persona covers all model types — including classical ML, statistical, optimization, and generative AI models — focusing on the secure execution of predictions, ensuring runtime integrity, confidentiality, and availability of data and outputs. It separates its duties from model training, tuning, or registry storage (Model Provider) and physical infrastructure management (AI Platform Provider), focusing on the secure orchestration and delivery of the model serving application layer.

**Responsibilities:**
- Manage and secure model serving API endpoints and enforce application access policies
- Perform runtime input validation and sanitization to prevent injection attacks and data poisoning
- Execute models within isolated or confidential computing environments to protect runtime data
- Enforce granular model and data access controls during loading and execution phases
- Verify model and data integrity at load-time and runtime to prevent execution of tampered artifacts
- Secure orchestration and routing of serving requests across distributed model instances
- Monitor, validate, and sanitize model outputs to prevent data leakage and ensure safety
- Implement runtime privacy-enhancing technologies to protect sensitive input data
- Provide transparency mechanisms regarding model serving parameters and data usage
- Facilitate red teaming and adversarial simulation to validate model serving security

---

### Agentic Platform and Framework Providers (`personaAgenticProvider`)

Actors that provide the development environments, software frameworks, and orchestration runtimes required to implement agentic reasoning, planning, and tool execution.

Examples include agentic frameworks and libraries (e.g., LangChain, Semantic Kernel), agent-native development environments (e.g., Cursor, GitHub Copilot Workspace), and managed agent orchestration platforms (e.g., Vertex AI Agent Builder, OpenAI Assistants API).

**Responsibilities:**
- Framework security and sandboxing
- Tool execution safety controls
- State management security
- API integration security
- Cognitive architecture safety guardrails

**Framework Mapping:**
- ISO 22989: AI Partner (tooling provider)

**Identification Questions:**

Use these questions to determine if this persona applies to your organization:

1. Is your system responsible for deciding which tool an AI model should use next?
2. Does your platform manage the state or history of a multi-turn agentic workflow?
3. Are you providing the glue that connects an LLM to an API?
4. Are you maintaining a library or SDK that abstracts the complexity of LLM tool-calling?
5. Does your software define the cognitive architecture (loops, reasoning steps) for an AI system?
6. Do developers import your package to enable agentic capabilities in their code?

---

### Application Developer (`personaApplicationDeveloper`)

Actors that integrate AI models (via APIs or embedded models) into applications, products, or services. They may consume models without modifying them, or perform light customization (prompt engineering, RAG, etc.).

**Responsibilities:**
- Application-level security controls
- Input validation and sanitization
- Output filtering and monitoring
- User access controls

**Framework Mapping:**
- ISO 22989: AI Consumer (application builder)

---

### AI System Governance (`personaGovernance`)

Actors responsible for defining security control objectives, measuring implementations, and enforcing compliance for AI systems across the AI system lifecycle. This includes AI risk officers, compliance teams, and governance boards.

**Responsibilities:**
- Security control objectives definition
- Implementation measurement and monitoring
- Compliance enforcement
- Risk assessment and management
- Incident response coordination

---

### AI System Users (`personaEndUser`)

Actors that use AI-powered applications or services without developing or deploying the AI components themselves. Users rely on application developers and providers for AI security controls.

**Responsibilities:**
- Appropriate use of AI systems
- Reporting issues or anomalies
- Following usage policies
- Data minimization (user inputs)

**Framework Mapping:**
- ISO 22989: AI Consumer (end user)

---

## Legacy Personas (Deprecated)

The following personas are retained for backward compatibility but are deprecated. Existing risks and controls may still reference these personas until migration to the new model is complete.

### Model Creator (`personaModelCreator`) - DEPRECATED

**Migration:** Use `personaModelProvider` for those that train/tune models, or `personaApplicationDeveloper` for those integrating models into applications.

Original description: Organizations that either train and tune foundation models for Generative AI, or tune acquired models for more domain-specific tasks.

### Model Consumer (`personaModelConsumer`) - DEPRECATED

**Migration:** Use `personaApplicationDeveloper` or `personaEndUser` depending on context.

Original description: Organizations that build AI applications, features, or products using models, but do not create or tune the models themselves.

---

## Migration Guide

When updating existing risks and controls to use the new persona model:

1. **Review each reference** to `personaModelCreator` or `personaModelConsumer`
2. **Determine the appropriate mapping:**

   | Legacy Persona | New Persona(s) | When to Use |
   |---------------|----------------|-------------|
   | `personaModelCreator` | `personaModelProvider` | Training, tuning, or distributing models |
   | `personaModelCreator` | `personaApplicationDeveloper` | Integrating models into applications |
   | `personaModelConsumer` | `personaApplicationDeveloper` | Building AI-powered applications |
   | `personaModelConsumer` | `personaEndUser` | Using AI applications without development |

3. **Consider additional personas** that may apply:
   - Does the control involve data handling? Add `personaDataProvider`
   - Does the control involve infrastructure? Add `personaPlatformProvider`
   - Does the control involve model serving? Add `personaModelServing`
   - Does the control involve agentic systems? Add `personaAgenticProvider`
   - Does the control involve governance/compliance? Add `personaGovernance`

4. **Validate your changes** using the framework validation tools

---

## Framework Mappings

Personas can be mapped to actors defined in external frameworks. Currently, the persona model supports mappings to ISO 22989 (Artificial Intelligence Concepts and Terminology).

### ISO 22989 Mapping Summary

| CoSAI Persona | ISO 22989 Actor |
|---------------|-----------------|
| Model Provider | AI Producer |
| Data Provider | AI Partner (data supplier) |
| AI Platform Provider | AI Partner (infrastructure provider) |
| AI Model Serving | (No direct mapping) |
| Agentic Platform Provider | AI Partner (tooling provider) |
| Application Developer | AI Consumer (application builder) |
| AI System Users | AI Consumer (end user) |
| AI System Governance | (No direct mapping) |

### Adding Framework Mappings

Framework mappings are defined in the `mappings` field of each persona:

```yaml
- id: personaModelProvider
  title: Model Provider
  description:
    - >
      Actors that develop, train, evaluate, and tune AI/ML models...
  mappings:
    iso-22989:
      - AI Producer
```

The framework ID must be defined in `frameworks.yaml` with `applicableTo` including `personas`.

---

## Adding a Persona

### Step 1: Add the persona ID to the schema

Declare the new persona's unique ID in `schemas/personas.schema.json`. The ID should follow the `persona[Name]` convention.

```json
// In schemas/personas.schema.json
"id": {
  "type": "string",
  "enum": [
    "personaModelProvider",
    "personaDataProvider",
    // ... existing IDs ...
    "personaNewPersona"
  ]
}
```

### Step 2: Add the persona definition

Add the definition to `yaml/personas.yaml`:

```yaml
- id: personaNewPersona
  title: New Persona Title
  description:
    - >
      A description of this persona's activities, responsibilities,
      and relationship to the AI system lifecycle.
  mappings:
    iso-22989:
      - Corresponding ISO 22989 Actor
  responsibilities:
    - First key responsibility
    - Second key responsibility
    - Third key responsibility
```

**Optional fields:**
- `mappings` - Framework actor mappings (e.g., ISO 22989)
- `responsibilities` - List of security responsibilities
- `identificationQuestions` - Questions to help identify if this persona applies
- `deprecated` - Set to `true` for legacy personas

### Step 3: Update existing risks and controls

Add the new persona ID to relevant entries in `risks.yaml` and `controls.yaml`:

```yaml
# In yaml/controls.yaml
- id: controlExample
  # other properties
  personas:
    - personaModelProvider
    - personaApplicationDeveloper
    - personaNewPersona  # Add the new persona
```

### Step 4: Validate and submit

Run validation to ensure your changes are correct:

```bash
# Schema validation
check-jsonschema --schemafile risk-map/schemas/personas.schema.json risk-map/yaml/personas.yaml

# Framework reference validation
python3 scripts/hooks/validate_framework_references.py --force

# Full validation suite
python3 scripts/hooks/validate_riskmap.py --force
```

Follow the [General Content Contribution Workflow](workflow.md) to create your pull request.

---

## Validation Rules

The validation system enforces these rules for personas:

1. **Persona ID validation** - All persona IDs in risks/controls must match IDs defined in the schema
2. **Framework applicability** - Persona mappings can only reference frameworks with `applicableTo: ["personas"]`
3. **Deprecation warnings** - Using deprecated personas generates warnings (not errors) to support gradual migration

---

## Related Documentation

- [Adding and Using Frameworks](guide-frameworks.md) - Framework mapping details
- [Adding a Risk](guide-risks.md) - How to add risks with persona assignments
- [Adding a Control](guide-controls.md) - How to add controls with persona assignments
- [Validation Tools](validation.md) - Detailed validation commands
- [General Content Contribution Workflow](workflow.md) - Overall contribution process
