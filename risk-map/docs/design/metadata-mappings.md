# Extended Metadata Field Mappings

This document describes the methodology, conventions, and rationale used for populating extended metadata fields (`mappings`, `lifecycleStage`, `impactType`, `actorAccess`) in Phase 2 of the CoSAI Risk Map development.

**Version:** 1.0
**Last Updated:** 2025-11-05
**Phase:** Phase 2 - Initial Data Population
**Status:** Completed (15 risks, 8 controls)

> **Forward note (#343):** the mapping values in the tables below are the
> as-authored Phase-2 legacy forms, retained as a provenance record. The live
> corpus has since been migrated to the ADR-027 version-pinned form (e.g.
> `AML.T0020@5.0.1`). See the [framework mappings style guide](../contributing/framework-mappings-style-guide.md).

---

## Table of Contents

- [Overview](#overview)
- [Methodology](#methodology)
- [Framework Mappings](#framework-mappings)
- [Lifecycle Stage Assignments](#lifecycle-stage-assignments)
- [Impact Type Categorization](#impact-type-categorization)
- [Actor Access Level Determination](#actor-access-level-determination)
- [Known Gaps and Limitations](#known-gaps-and-limitations)
- [Sources and References](#sources-and-references)

---

## Overview

This Phase 2 implementation populates extended metadata for high-priority AI security risks and controls using a best-effort research methodology. The goal is to provide meaningful cross-references to external frameworks and categorize risks/controls along key dimensions (lifecycle, impact, and access requirements).

### Populated Items

**Risks (15 total):**
- riskDataPoisoning (Data Poisoning)
- riskUnauthorizedTrainingData (Unauthorized Training Data)
- riskModelSourceTampering (Model Source Tampering)
- riskExcessiveDataHandling (Excessive Data Handling)
- riskModelExfiltration (Model Exfiltration)
- riskModelDeploymentTampering (Model Deployment Tampering)
- riskDenialOfMLService (Denial of ML Service)
- riskModelReverseEngineering (Model Reverse Engineering)
- riskInsecureIntegratedComponent (Insecure Integrated Component)
- riskPromptInjection (Prompt Injection)
- riskModelEvasion (Model Evasion)
- riskSensitiveDataDisclosure (Sensitive Data Disclosure)
- riskInferredSensitiveData (Inferred Sensitive Data)
- riskInsecureModelOutput (Insecure Model Output)
- riskRogueActions (Rogue Actions)

**Controls (8 total):**
- controlTrainingDataSanitization
- controlModelAndDataIntegrityManagement
- controlSecureByDefaultMLTooling
- controlInputValidationAndSanitization
- controlOutputValidationAndSanitization
- controlAdversarialTrainingAndTesting
- controlApplicationAccessManagement
- controlAgentPluginPermissions

---

## Methodology

### Research Approach

1. **Framework Analysis**: Analyzed each external framework (MITRE ATLAS, NIST AI RMF, STRIDE, OWASP Top 10 for LLM) to understand their taxonomy and scope
2. **Risk/Control Review**: Reviewed existing longDescription fields in risks.yaml and controls.yaml to understand the nature of each item
3. **Conceptual Mapping**: Mapped CoSAI risks/controls to framework concepts based on:
   - Attack techniques and tactics
   - Security impact categories
   - Real-world examples cited in descriptions
   - Industry best practices
4. **Validation**: Cross-referenced mappings with published security research and framework documentation

### Best-Effort Approach

This is a **best-effort** initial population based on:
- Public framework documentation
- Security research papers
- Industry guidance and blog posts
- Conceptual alignment between frameworks

**Important Notes:**
- Mappings are not authoritative or officially endorsed by framework maintainers
- Some mappings are approximate when exact matches don't exist
- Empty fields indicate uncertainty or lack of clear mapping
- Community feedback and iteration will improve accuracy over time

---

## Framework Mappings

### MITRE ATLAS

**Source:** [MITRE ATLAS](https://atlas.mitre.org/) - Adversarial Threat Landscape for Artificial-Intelligence Systems

**Mapping Convention:**
- Used technique IDs in format `AML.T####` or `AML.M####` (for mitigations)
- Mapped risks to attack techniques that directly enable or exemplify the risk
- Mapped controls to course-of-action mitigations where available
- Included sub-techniques (e.g., `AML.T0010.002`) when more specific than parent

**Key Mappings:**

| Risk/Control | ATLAS Technique(s) | Rationale |
|--------------|-------------------|-----------|
| riskDataPoisoning (Data Poisoning) | AML.T0020, AML.T0019, AML.T0010.002 | Direct poisoning attacks on training data and datasets |
| riskPromptInjection (Prompt Injection) | AML.T0051 | Prompt injection technique |
| riskModelEvasion (Model Evasion) | AML.T0015, AML.T0043 | Evade ML model and craft adversarial data |
| riskSensitiveDataDisclosure (Sensitive Data Disclosure) | AML.T0024.*, AML.T0024.000, AML.T0024.001 | Exfiltration via ML inference API techniques |
| riskModelExfiltration (Model Exfiltration) | AML.T0024.002, AML.T0025, AML.T0048.004 | Extract ML model, exfiltration, IP theft |
| riskDenialOfMLService (Denial of ML Service) | AML.T0029, AML.T0034 | Denial of ML service and cost harvesting |

**Gaps:**
- Some CoSAI risks (e.g., riskUnauthorizedTrainingData, riskExcessiveDataHandling, riskInferredSensitiveData, riskInsecureModelOutput) don't have direct ATLAS technique mappings as they focus on policy/compliance rather than attacks
- ATLAS is attack-focused; some defensive controls lack mitigation mappings

### NIST AI RMF

**Source:** [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) v1.0

**Mapping Convention:**
- Used category codes from the framework (e.g., `MS-2.7`, `GV-6.1`)
- Focused on controls rather than risks (RMF is control-oriented)
- Selected categories that address the control's primary function
- MS = Manage, GV = Govern, MP = Map, M = Measure

**Key Mappings:**

| Control | NIST AI RMF | Rationale |
|---------|-------------|-----------|
| controlTrainingDataSanitization | MS-2.7, MS-2.8 | Data quality and provenance management |
| controlModelAndDataIntegrityManagement | MS-2.3 | Integrity verification of AI system data and models |
| controlAdversarialTrainingAndTesting | MS-2.6 | Adversarial testing and robustness |
| controlApplicationAccessManagement | GV-6.1, MS-2.11 | Access controls and authentication |

**Gaps:**
- NIST AI RMF codes are less granular than needed for specific technical controls
- Many risk items don't map directly (framework is control-focused)
- NIST 800-53 controls (like SC-8, SI-7) are not included as AI RMF uses its own category system

### STRIDE

**Source:** Microsoft STRIDE Threat Model

**Mapping Convention:**
- Used lowercase category names: `spoofing`, `tampering`, `repudiation`, `information-disclosure`, `denial-of-service`, `elevation-of-privilege`
- Mapped based on primary security impact of the risk
- Multiple STRIDE categories used when risk affects multiple impact areas

**Key Mappings:**

| STRIDE Category | CoSAI Risks | Rationale |
|-----------------|-------------|-----------|
| tampering | riskDataPoisoning, riskModelSourceTampering, riskModelDeploymentTampering, riskPromptInjection, riskModelEvasion, riskInsecureModelOutput, riskRogueActions | Unauthorized modification of data, models, or outputs |
| information-disclosure | riskUnauthorizedTrainingData, riskExcessiveDataHandling, riskModelExfiltration, riskModelReverseEngineering, riskSensitiveDataDisclosure, riskInferredSensitiveData | Unauthorized access to sensitive information |
| denial-of-service | riskDenialOfMLService | Availability attacks on ML services |
| elevation-of-privilege | riskModelSourceTampering, riskModelDeploymentTampering, riskInsecureIntegratedComponent, riskPromptInjection, riskRogueActions | Gaining higher access than intended |

**Gaps:**
- STRIDE is coarse-grained; doesn't capture AI-specific nuances
- `repudiation` and `spoofing` categories have limited applicability to current CoSAI risks
- Originally designed for traditional software systems

### OWASP Top 10 for LLM Applications

**Source:** [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

**Mapping Convention:**
- Used 2025 version codes: `LLM01` through `LLM10`
- Mapped risks that directly align with OWASP categories
- Strong alignment as OWASP Top 10 for LLM is AI-specific

**2025 OWASP Top 10:**
1. LLM01: Prompt Injection
2. LLM02: Sensitive Information Disclosure
3. LLM03: Supply Chain Vulnerabilities
4. LLM04: Data and Model Poisoning
5. LLM05: Improper Output Handling
6. LLM06: Excessive Agency
7. LLM07: System Prompt Leakage
8. LLM08: Vector and Embedding Weaknesses
9. LLM09: Misinformation
10. LLM10: Unbounded Consumption

**Key Mappings:**

| OWASP LLM | CoSAI Risks | Rationale |
|-----------|-------------|-----------|
| LLM01 | riskPromptInjection, riskModelEvasion | Prompt injection and manipulation attacks |
| LLM02 | riskExcessiveDataHandling, riskSensitiveDataDisclosure, riskInferredSensitiveData | Sensitive data exposure and disclosure |
| LLM03 | riskModelSourceTampering, riskModelDeploymentTampering | Supply chain compromise of models/infrastructure |
| LLM04 | riskDataPoisoning, riskUnauthorizedTrainingData | Training data poisoning |
| LLM05 | riskInsecureModelOutput | Insecure model outputs |
| LLM06 | riskInsecureIntegratedComponent, riskRogueActions | Excessive permissions and rogue agent actions |
| LLM10 | riskDenialOfMLService | Resource exhaustion and DoS |

**Gaps:**
- LLM08 (Vector and Embedding Weaknesses) not yet represented in CoSAI risks
- Some OWASP categories (LLM07, LLM09) have partial overlap with CoSAI but no exact matches

---

## Lifecycle Stage Assignments

**Source:** [lifecycle-stage.yaml](../yaml/lifecycle-stage.yaml)

### 8-Stage AI Lifecycle Model

1. **planning** - Initial planning, design, and architecture definition
2. **data-preparation** - Data collection, cleaning, labeling, and preparation
3. **model-training** - Model training, fine-tuning, and optimization
4. **development** - Application development and AI model integration
5. **evaluation** - Testing, validation, and performance evaluation
6. **deployment** - Production deployment and initial rollout
7. **runtime** - Active operation and serving in production
8. **maintenance** - Ongoing monitoring, updates, and retraining

### Assignment Rationale

**Lifecycle assignments based on:**
- Where the risk is **introduced** into the system
- Where the risk is **exposed** or manifests
- Where **mitigations** are most effective

**Examples:**

| Risk/Control | Stages | Rationale |
|--------------|--------|-----------|
| riskDataPoisoning (Data Poisoning) | data-preparation, model-training, maintenance | Introduced during data collection, exposed during training, recurring risk in retraining |
| riskPromptInjection (Prompt Injection) | runtime | Runtime exploitation via user prompts |
| riskModelSourceTampering (Model Source Tampering) | development, model-training, deployment | Supply chain attacks during model development |
| controlTrainingDataSanitization | data-preparation, model-training, evaluation | Applied during data processing and model development |

**Patterns:**
- **Supply chain risks** (riskDataPoisoning, riskModelSourceTampering, riskUnauthorizedTrainingData): data-preparation, model-training
- **Runtime input risks** (riskPromptInjection, riskModelEvasion, riskDenialOfMLService): evaluation, runtime
  - Note: Evaluation stage added for risks that should be tested before deployment
- **Data security risks** (riskSensitiveDataDisclosure, riskInferredSensitiveData, riskExcessiveDataHandling): evaluation, runtime (+ training where applicable)
- **Infrastructure risks** (riskModelExfiltration, riskModelDeploymentTampering): deployment, runtime
- **Development risks** (riskInsecureIntegratedComponent): development, deployment, runtime
- **Output security risks** (riskInsecureModelOutput, riskRogueActions): evaluation, runtime
  - Testing and validation critical before production deployment

---

## Impact Type Categorization

**Source:** [impact-type.yaml](../yaml/impact-type.yaml)

### Impact Categories

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

### Assignment Rationale

**Impact types assigned based on:**
- Primary harm caused by successful exploitation of the risk
- Key security properties protected by the control
- Multiple impacts assigned when risk affects several dimensions

**Examples:**

| Risk/Control | Impact Types | Rationale |
|--------------|--------------|-----------|
| riskDataPoisoning (Data Poisoning) | integrity, reliability, safety | Corrupts model behavior, reduces reliability, can cause unsafe outputs |
| riskSensitiveDataDisclosure (Sensitive Data Disclosure) | confidentiality, privacy | Exposes sensitive personal or confidential data |
| riskDenialOfMLService (Denial of ML Service) | availability | Makes system unavailable |
| riskPromptInjection (Prompt Injection) | integrity, confidentiality, safety | Alters behavior, may expose data, can cause harm |
| riskUnauthorizedTrainingData (Unauthorized Training Data) | compliance, privacy, fairness | Legal/regulatory violations, privacy concerns, potential bias |

**Patterns:**
- **Poisoning/Tampering risks** (riskDataPoisoning, riskModelSourceTampering, riskModelDeploymentTampering): integrity, reliability, safety
- **Disclosure risks** (riskSensitiveDataDisclosure, riskModelExfiltration, riskModelReverseEngineering): confidentiality, privacy
- **DoS risks** (riskDenialOfMLService): availability
- **Inference/Fairness risks** (riskInferredSensitiveData): fairness, privacy
- **Policy/Legal risks** (riskUnauthorizedTrainingData, riskExcessiveDataHandling): compliance, privacy

---

## Actor Access Level Determination

**Source:** [actor-access.yaml](../yaml/actor-access.yaml)

### Access Levels

**Traditional:**
- **external** - External attackers with no direct system access
- **api** - Public or authenticated API endpoint access
- **user** - Standard authenticated user access
- **privileged** - Elevated privileges (admin, operator)
- **physical** - Physical access to hardware/facilities

**Modern (AI-Specific):**
- **agent** - AI agents with tool/plugin execution capabilities
- **supply-chain** - Position in software/data/model supply chain
- **infrastructure-provider** - Cloud or infrastructure provider access
- **service-provider** - Third-party service provider access

### Assignment Rationale

**Access levels based on:**
- **For risks**: Minimum access level required by attacker to exploit the vulnerability
- **For controls**: Access levels the control protects against

**Examples:**

| Risk/Control | Access Levels | Rationale |
|--------------|---------------|-----------|
| riskDataPoisoning (Data Poisoning) | supply-chain, privileged, service-provider | Requires access to training pipeline or data sources |
| riskPromptInjection (Prompt Injection) | external, api, user | Can be executed via public-facing interfaces |
| riskModelExfiltration (Model Exfiltration) | external, privileged, infrastructure-provider | Via external attack or insider/provider access |
| riskSensitiveDataDisclosure (Sensitive Data Disclosure) | external, api, user, agent | Exploitable by any user querying the model |
| riskModelEvasion (Model Evasion) | external, api, user, physical | Adversarial examples can be crafted externally or via physical access |

**Patterns:**
- **Supply chain risks** (riskDataPoisoning, riskModelSourceTampering, riskUnauthorizedTrainingData): supply-chain, service-provider
- **Runtime API risks** (riskPromptInjection, riskModelEvasion, riskDenialOfMLService, riskModelReverseEngineering): external, api, user
- **Data disclosure risks** (riskSensitiveDataDisclosure, riskInferredSensitiveData): external, api, user, (agent if applicable)
- **Infrastructure risks** (riskModelExfiltration, riskModelDeploymentTampering): privileged, infrastructure-provider
- **Agent risks** (riskRogueActions, riskInsecureIntegratedComponent): agent, api, external

**Control Perspective:**
- Control access levels indicate what level of actor the control defends against
- Example: controlApplicationAccessManagement defends against external, api, user (public-facing attacks)

---

## Known Gaps and Limitations

### Framework Coverage Gaps

1. **MITRE ATLAS**
   - Limited coverage for policy/compliance risks (riskUnauthorizedTrainingData, riskExcessiveDataHandling)
   - Newer attack techniques (prompt injection, agent risks) still evolving in framework
   - Some CoSAI risks are broader than individual ATLAS techniques

2. **NIST AI RMF**
   - Framework is control-oriented, making risk mapping difficult
   - Version 1.0 is still relatively new; mappings may evolve
   - Some specific controls lack direct RMF category equivalents

3. **STRIDE**
   - Coarse-grained categories don't capture AI-specific nuances
   - `repudiation` and `spoofing` have limited applicability
   - Better suited for infrastructure than model-level risks

4. **OWASP Top 10 for LLM**
   - Strong coverage for LLM risks but less applicable to traditional ML
   - 2025 version is recent; community consensus still forming
   - Some CoSAI risks predate or don't align with Top 10 categories

### Mapping Uncertainty

**Risks/controls with uncertain or incomplete mappings:**

1. **riskExcessiveDataHandling (Excessive Data Handling)** - Policy-focused risk with limited attack technique mappings
2. **riskInferredSensitiveData (Inferred Sensitive Data)** - Emergent risk without established framework coverage
3. **controlSecureByDefaultMLTooling** - Broad infrastructure control spanning many framework areas

### Areas for Future Work

1. **NIST AI RMF Refinement**: As the framework matures, mappings should be updated with more specific subcategories
2. **MITRE ATLAS Updates**: Track new technique additions and update mappings accordingly
3. **Cross-Framework Validation**: Engage with framework maintainers for feedback on mapping accuracy
4. **Quantitative Metrics**: Consider adding confidence scores or priority levels to mappings
5. **Additional Frameworks**: Consider mapping to ISO/IEC standards, ENISA guidelines, or regional frameworks (EU AI Act, etc.)

### Methodology Limitations

- **Subjective Interpretation**: Mappings involve judgment calls where multiple interpretations are valid
- **Framework Evolution**: External frameworks update independently; mappings require ongoing maintenance
- **No Official Endorsement**: Mappings are interpretive and not validated by framework authors
- **Best-Effort Basis**: Some assignments are provisional pending deeper research or community input

---

## Sources and References

### Primary Framework Documentation

1. **MITRE ATLAS**
   - Official Website: https://atlas.mitre.org/
   - GitHub Repository: https://github.com/mitre/advmlthreatmatrix
   - MISP Galaxy Cluster: https://github.com/MISP/misp-galaxy/blob/main/clusters/mitre-atlas-attack-pattern.json
   - Version: 5.0.1 (as of October 2025)

2. **NIST AI Risk Management Framework**
   - Official Site: https://www.nist.gov/itl/ai-risk-management-framework
   - PDF Document: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
   - Version: 1.0 (January 2023)
   - Related: NIST SP 800-53 for specific security controls

3. **STRIDE Threat Model**
   - Microsoft Threat Modeling Tool: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
   - Wikipedia: https://en.wikipedia.org/wiki/STRIDE_model
   - Original Paper: Praerit Garg and Loren Kohnfelder (Microsoft, 1999)

4. **OWASP Top 10 for LLM Applications**
   - Project Page: https://owasp.org/www-project-top-10-for-large-language-model-applications/
   - Version: 2025 (released November 2024)
   - LLM Risks Archive: https://genai.owasp.org/llm-top-10/

### Secondary Sources

5. **Academic Research**
   - Adversarial Machine Learning Survey Papers
   - Data Poisoning Attack Papers (cited in risks.yaml)
   - Prompt Injection Research (arXiv, security conferences)

6. **Industry Guidance**
   - HiddenLayer: MITRE ATLAS Implementation Guides
   - Practical DevSecOps: MITRE ATLAS Framework Guide (2025)
   - Security Vendor Blogs: Trend Micro, Bluetuple.ai, Indusface

7. **CoSAI Internal Documentation**
   - [guide-metadata.md](guide-metadata.md) - Metadata field definitions
   - [guide-frameworks.md](guide-frameworks.md) - Framework integration guide
   - [frameworks.yaml](../yaml/frameworks.yaml) - Framework registry
   - [risks.yaml](../yaml/risks.yaml) - Risk descriptions and examples
   - [controls.yaml](../yaml/controls.yaml) - Control descriptions

### Research Date

This mapping research was conducted on **November 5, 2025** and reflects the state of external frameworks as of that date.

---

## Feedback and Contributions

This mapping document represents Phase 2 initial population and is intended to evolve:

- **Community Feedback**: Corrections and improvements welcome via GitHub issues
- **Framework Expertise**: Input from framework maintainers and security practitioners encouraged
- **Ongoing Maintenance**: Mappings will be updated as frameworks evolve and new research emerges

For questions or suggestions, please open an issue in the [CoSAI secure-ai-tooling repository](https://github.com/cosai-oasis/secure-ai-tooling).

---

**Document Version:** 1.0
**Last Updated:** 2025-11-05
**Authors:** CoSAI Risk Map Working Group (Phase 2)
**License:** Apache 2.0
