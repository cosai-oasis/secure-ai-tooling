# Persona Model Design

This document describes the design decisions, rationale, and methodology behind the CoSAI Risk Map persona model expansion from 2 legacy personas to 7 CoSAI-identified standard personas.

**Version:** 1.0
**Last Updated:** 2025-01-23

---

## Table of Contents

- [Overview](#overview)
- [Design Goals](#design-goals)
- [The 7-Persona Model](#the-7-persona-model)
- [Legacy Persona Rationale](#legacy-persona-rationale)
- [ISO 22989 Framework Mapping](#iso-22989-framework-mapping)
- [Scoping Decisions](#scoping-decisions)
- [Schema Design](#schema-design)
- [Known Gaps and Future Work](#known-gaps-and-future-work)
- [References](#references)

---

## Overview

The CoSAI Risk Map originally defined two personas (Model Creator and Model Consumer) to assign responsibility for security controls. As the AI ecosystem has matured, these broad categories no longer adequately represent the diverse sets of activities involved in AI system development, deployment, and governance.

The persona model uplift expands the taxonomy to 7 distinct personas that align with:
- Real-world engineering and design approaches
- External framework views on the AI ecosystem actors
- Security responsibility boundaries
- Emerging agentic AI paradigms

### Change Summary

| Aspect | Before | After |
|--------|--------|-------|
| Total personas | 2 | 9 (7 current + 2 legacy) |
| Framework mappings | None | _Optional_<br>ISO 22989 |
| Responsibility tracking | None | _Optional_<br>Explicit per persona |
| Identification guidance | None | _Optional_<br>Questions for agentic providers |
| Deprecation support | None | _Optional_<br>Boolean flag + migration guide |

---

## Design Goals

### Primary Goals

1. **Clear accountability** - Each persona has well-defined security responsibilities that don't overlap ambiguously
2. **Framework alignment** - Personas map to established standards (ISO 22989, etc) for interoperability
3. **Lifecycle Completeness** – The framework addresses all stages of the AI system lifecycle through activity groupings that ensure continuous security oversight without excessive granularity.
4. **Backward compatibility** - Legacy personas remain valid during migration

### Secondary Goals

1. **Extensibility** - Schema supports adding new personas and framework mappings
2. **Actionable guidance** - Each persona has concrete responsibilities, not abstract descriptions
3. **Agentic AI support** - Dedicated persona for the emerging agentic framework ecosystem

---

## The 7-Persona Model

### Persona Selection Rationale

The 7 personas were selected based on:
1. Distinct security responsibility boundaries
2. Real-world engineering activities
3. External framework alignment where applicable
4. Coverage of the complete AI system lifecycle

### Persona Definitions

#### 1. Model Provider (`personaModelProvider`)

**Scope:** Actors that develop, train, and distribute AI models

**Why a distinct persona:**
- Has unique security responsibilities around model training, evaluation, and documentation
- Controls the most critical asset in the AI system (the model weights)
- Subject to specific regulatory requirements (model cards, safety testing)

**ISO 22989 mapping:** AI Producer

**Key differentiation from Application Developer (personaApplicationDeveloper):**
- Model Providers create or significantly modify models
- Application Developers consume models without training/tuning

---

#### 2. Data Provider (`personaDataProvider`)

**Scope:** Actors that supply training, evaluation, or inference data

**Why a distinct persona:**
- Data quality directly impacts model security and fairness
- Data provenance and licensing are distinct compliance concerns
- May be a separate actor from model and application providers

**ISO 22989 mapping:** AI Partner (data supplier)

**Key considerations:**
- Includes data marketplaces, aggregators, and licensors
- Responsible for data privacy and quality assurance
- May not have visibility into how data is used

---

#### 3. AI Platform Provider (`personaPlatformProvider`)

**Scope:** Actors that provide infrastructure and compute resources for AI systems

**Why a distinct persona:**
- Controls infrastructure security boundaries
- Responsible for multi-tenant isolation
- Has unique access to model inference patterns and data

**ISO 22989 mapping:** AI Partner (infrastructure provider)

**Examples:**
- Internal infrastructure providers
- Cloud providers (AWS, Azure, GCP)
- MLOps platforms
- Model API services

---

#### 4. Agentic Platform and Framework Providers (`personaAgenticProvider`)

**Scope:** Actors that provide agentic frameworks, tooling, and orchestration platforms

**Why a distinct persona:**
- Emerging category not covered by traditional personas
- Unique security responsibilities around tool execution and sandboxing
- Controls the "cognitive architecture" of AI agents

**ISO 22989 mapping:** AI Partner (tooling provider)

**Why identification questions are included:**

The agentic AI space is rapidly evolving with unclear boundaries. The identification questions help organizations determine if they fall into this category:

1. Is your system responsible for deciding which tool an AI model should use next?
2. Does your platform manage the state or history of a multi-turn agentic workflow?
3. Are you providing the glue that connects an LLM to an API?
4. Are you maintaining a library or SDK that abstracts the complexity of LLM tool-calling?
5. Does your software define the cognitive architecture (loops, reasoning steps) for an AI system?
6. Do developers import your package to enable agentic capabilities in their code?

**Examples:**
- LangChain, Semantic Kernel (frameworks)
- Cursor, GitHub Copilot Workspace (agent-native IDEs)
- Vertex AI Agent Builder, OpenAI Assistants API (managed platforms)

---

#### 5. Application Developer (`personaApplicationDeveloper`)

**Scope:** Actors integrating AI models into applications

**Why a distinct persona:**
- Responsible for application-level security controls
- Makes decisions about input/output validation
- Has user-facing security responsibilities

**ISO 22989 mapping:** AI Consumer (application builder)

**Key differentiation from Model Provider (personaModelProvider):**
- Uses models without significant modification
- May apply prompt engineering or RAG, but not model training

---

#### 6. AI System Governance (`personaGovernance`)

**Scope:** Actors responsible for AI security governance

**Why a distinct persona:**
- Cross-cutting function that oversees all other personas
- Responsible for policy, compliance, and risk management
- May not be technical but has security decision authority

**ISO 22989 mapping:** None (governance activities are not explicitly defined in ISO 22989)

**Key responsibilities:**
- Security control objectives definition
- Implementation measurement and monitoring
- Compliance enforcement
- Risk assessment and management
- Incident response coordination

---

#### 7. AI System Users (`personaEndUser`)

**Scope:** Actors that use AI-powered applications

**Why a distinct persona:**
- Has limited but important security responsibilities
- Source of user inputs that may contain sensitive data
- First line of defense for detecting anomalies

**ISO 22989 mapping:** AI Consumer (end user)

**Key considerations:**
- Relies on other personas for security controls
- Responsible for appropriate use and reporting issues
- May inadvertently introduce sensitive data

---

## Legacy Persona Rationale

### Why Deprecate Rather Than Remove

1. **Backward compatibility** - Existing controls and risks reference legacy personas
2. **Gradual migration** - Allows phased updates without breaking existing tooling
3. **Audit trail** - Preserves history of persona assignments

### Migration Path

| Legacy Persona | Primary Replacement | Secondary Replacement |
|---------------|--------------------|-----------------------|
| `personaModelCreator` | `personaModelProvider` | `personaApplicationDeveloper` (for light customization) |
| `personaModelConsumer` | `personaApplicationDeveloper` | `personaEndUser` (for pure consumption) |

### Why Two Legacy Personas Map to Multiple New Personas

The original personas were too broad:

**Model Creator** combined:
- Actors training foundation models (→ Model Provider)
- Actors fine-tuning models (→ Model Provider)
- Actors integrating models (→ Application Developer)

**Model Consumer** combined:
- Actors building AI applications (→ Application Developer)
- End users of AI applications (→ End User)

The new model separates these distinct sets of activities for clearer accountability.

---

## ISO 22989 Framework Mapping

### Why ISO 22989

ISO/IEC 22989 (Artificial Intelligence Concepts and Terminology) was selected as the primary framework mapping because:

1. **International standard** - Widely recognized and referenced in regulations
2. **Actor-focused** - Explicitly defines AI ecosystem actors
3. **Technology-neutral** - Applies to all AI system types
4. **Authoritative** - ISO standards carry regulatory weight

### Mapping Methodology

1. Reviewed ISO 22989 actor definitions
2. Identified closest conceptual match for each CoSAI persona
3. Documented where exact matches don't exist (e.g., Governance)
4. Used ISO actor terminology in persona descriptions

### Mapping Limitations

- ISO 22989 defines broad actor categories; CoSAI personas are more granular
- ISO 22989 does not explicitly define governance activities
- Agentic AI is an emerging paradigm; ISO mapping is interpretive
- ISO 22989 is evolving; mappings may need updates

---

## Scoping Decisions

### What's In Scope

1. **Persona definitions** with descriptions and responsibilities
2. **Framework mappings** to ISO 22989
3. **Deprecation mechanism** for legacy personas
4. **Schema extensions** for new fields
5. **Validation tooling** for framework applicability

### What's Out of Scope (Phase 2)

1. **Control/risk migration** - Updating existing controls and risks to use new personas (deferred to Phase 3)
2. **Additional frameworks** - Mappings to NIST, ISO 27001, etc. (future work)
3. **Persona hierarchy** - Organizational reporting structures
4. **System access control** - Personas don't define system access permissions

### WS3 Discussion Context

The persona model expansion was discussed in CoSAI Workstream 3 (WS3) meetings with the following key decisions:

1. **7 personas is sufficient** - Additional granularity (e.g., separate personas for cloud vs. on-prem providers) was deemed unnecessary
2. **Agentic persona is needed** - The rapidly growing agentic AI ecosystem warrants a dedicated persona
3. **Governance is cross-cutting** - Rather than embedding governance in other personas, it's a distinct set of activities
4. **ISO 22989 is the baseline** - Additional framework mappings can be added later

---

## Schema Design

### New Schema Fields

#### `deprecated` (boolean)

Marks legacy personas that should not be used in new content.

```json
"deprecated": {
  "type": "boolean",
  "description": "Indicates if this persona is deprecated and superseded by newer personas",
  "default": false
}
```

#### `mappings` (object)

Maps personas to external framework actors.

```json
"mappings": {
  "type": "object",
  "description": "Maps this persona to equivalent actors in external frameworks",
  "propertyNames": {
    "$ref": "frameworks.schema.json#/definitions/framework/properties/id"
  },
  "additionalProperties": {
    "type": "array",
    "items": { "type": "string" }
  }
}
```

Key design decision: `propertyNames` references the frameworks schema to ensure only valid framework IDs are used.

#### `responsibilities` (array)

Lists specific security responsibilities for the persona.

```json
"responsibilities": {
  "type": "array",
  "description": "List of security control responsibilities for this persona",
  "items": { "type": "string", "minLength": 1 }
}
```

#### `identificationQuestions` (array)

Helps identify if a persona applies.

```json
"identificationQuestions": {
  "type": "array",
  "description": "Questions to help identify if this persona applies to them",
  "items": { "type": "string", "minLength": 1 }
}
```

Currently only used for `personaAgenticProvider` where persona boundaries are less clear.

### Framework Applicability

The `frameworks.yaml` entry for ISO 22989 includes:

```yaml
applicableTo:
  - personas
```

This ensures validation catches attempts to use ISO 22989 in risks/controls (where it doesn't apply) or to use risk-focused frameworks (like MITRE ATLAS) in personas.

---

## Known Gaps and Future Work

### Current Gaps

1. **Control/risk migration incomplete** - 88 deprecated persona warnings exist; Phase 3 will address
2. **Single framework mapping** - Only ISO 22989 mapped; other standards could be added
3. **No hierarchy** - Personas are flat; organizational structures may need representation
4. **Regional variations** - Personas don't account for regulatory jurisdiction differences

### Future Work

1. **Phase 3: Controls & Risks Migration** - Update all references to deprecated personas
2. **Additional framework mappings** - NIST Cybersecurity Framework, ISO 27001, EU AI Act actors
3. **Persona relationships** - Define how personas interact in different deployment scenarios
4. **Quantitative responsibility weights** - Relative importance of each persona for specific controls
5. **Industry-specific personas** - Healthcare, financial services, autonomous vehicles

---

## Addendum: personaModelServing (GH #136)

An 8th persona, `personaModelServing` (AI Model Serving), was added to fill the gap between AI Platform Provider (infrastructure/compute) and Application Developer (application integration). This persona covers the model serving runtime layer — provisioning, managing, and securing the environment that serves AI and ML model predictions at scale. It applies to all model types (classical ML, statistical, optimization, and generative AI), not only GenAI inference.

No ISO 22989 mapping was identified for this persona. No identification questions are defined initially; the persona's scope is sufficiently distinct from its neighbors.

See [guide-personas.md](../guide-personas.md#ai-model-serving-personamodelserving) for the full definition and responsibilities.

---

## References

### Standards

1. **ISO/IEC 22989:2022** - Artificial intelligence - Artificial intelligence concepts and terminology
   - URL: https://www.iso.org/standard/74296.html
   - Defines AI ecosystem actors referenced in persona mappings

### CoSAI Documentation

2. **guide-personas.md** - User guide for working with personas
3. **guide-frameworks.md** - Framework integration guide
4. **CLAUDE.md** - Development workflow and guidelines

### Issue Tracking

5. **Issue #109** - Epic: Uplift CoSAI-RM Persona Model
6. **Issue #110** - Phase 1a: Persona Schema Updates
7. **Issue #111** - Phase 1b: Framework Applicability Schema
8. **Issue #112** - Phase 2: Content Population

---

**Document Version:** 1.0
**Last Updated:** 2025-01-23
**Authors:** CoSAI Risk Map Working Group
**License:** Apache 2.0
