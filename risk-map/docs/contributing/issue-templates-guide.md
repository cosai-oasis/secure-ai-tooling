# GitHub Issue Templates Guide

This guide explains how to use the GitHub issue templates available in the CoSAI Risk Map repository. These templates streamline the process of proposing new content or updating existing content in the AI security framework.

> **Read these first.** Templates capture the _what_; two companion documents capture the _quality bar_:
>
> - [`submission-readiness-guide.md`](./submission-readiness-guide.md) — pre-submission checklist, ID conventions, persona model, universal controls, framework mappings, and overlap checking.
> - [`common-review-findings.md`](./common-review-findings.md) — the issues reviewers flag most often, grouped by severity, with fix guidance.
>
> Every `new_*` template links to both. Working through the readiness guide before opening an issue is the fastest path to a PROCEED verdict.

## Table of Contents

1. [Overview](#overview)
2. [Recent Template Changes](#recent-template-changes)
3. [Control Templates](#control-templates)
4. [Risk Templates](#risk-templates)
5. [Component Templates](#component-templates)
6. [Persona Templates](#persona-templates)
7. [Infrastructure Template](#infrastructure-template)
8. [Key Concepts](#key-concepts)
9. [Common Pitfalls](#common-pitfalls)

---

## Overview

### Why Use Issue Templates?

GitHub issue templates provide structured forms that:

- **Capture required information** - Ensure all necessary details are provided upfront
- **Reduce back-and-forth** - Minimize clarification cycles with maintainers
- **Maintain consistency** - Standardize how content is proposed across the project
- **Enable automation** - Allow automatic labeling and validation

### Available Templates

The repository provides 9 issue templates organized into 5 categories:

| Category       | New Entity Template  | Update Entity Template   |
| -------------- | -------------------- | ------------------------ |
| **Controls**   | `new_control.yml`    | `update_control.yml`     |
| **Risks**      | `new_risk.yml`       | `update_risk.yml`        |
| **Components** | `new_component.yml`  | `update_component.yml`   |
| **Personas**   | `new_persona.yml`    | `update_persona.yml`     |
| **Other**      | `infrastructure.yml` | (framework enhancements) |

### Template Design Philosophy

- **New templates**: Comprehensive fields for creating entirely new entities
- **Update templates**: KISS (Keep It Simple, Stupid) approach with GitHub permalinks and free-form descriptions
- **Automatic bidirectionality**: The system automatically creates reverse mappings (you don't need to update both sides manually)

> **About "Required for review" counts:** Each template section below lists the fields a reviewer expects on a complete submission. GitHub Issue Forms only enforces a subset of these at submit time — it can mark individual `input`/`textarea` fields required, but it cannot require that any option in a `checkbox` group be selected. So a submission with empty Applicable Personas or Applicable Controls will pass the form but be flagged DISCUSS in review. Treat the counts as the review bar, not the form-validation bar.

---

## Recent Template Changes

_Snapshot as of 2026-04-15. This section is a history aid and will drift; consult the live `.github/ISSUE_TEMPLATE/*.yml` files for current behavior._

The following changes were applied across the issue templates alongside the introduction of the [Submission Readiness Guide](./submission-readiness-guide.md):

| Template                   | Change                                                                                                  | Rationale                                                                                                                                                            |
| -------------------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new_risk.yml`             | Removed `personaGovernance` from the persona checkbox list                                              | `personaGovernance` is a controls-only persona; risks list **impacted** personas, not implementers.                                                                  |
| `new_risk.yml`             | Personas description rewritten to "impacted by," not "need to mitigate"                                 | Aligns with the documented persona model (risks = impacted, controls = implementers).                                                                                |
| All `new_*` templates      | Removed manual ID input fields                                                                          | IDs are mechanically derived from the Title field — having both invited drift between submitted ID and title.                                                        |
| `new_persona.yml`          | Added optional `Identification Questions` textarea with style guide link                                | Personas are scoped using yes/no, second-person, activity-based questions per the [Identification Questions Style Guide](./identification-questions-style-guide.md). |
| `update_persona.yml`       | Added `Identification Questions Changes` field and "Update identification questions" change-type option | Allows targeted updates to a persona's identification questions without conflating them with description rewrites.                                                   |
| All `new_*` and `update_*` | Added pointer to `submission-readiness-guide.md` in opening markdown and submission checklist           | Surfaces the quality bar before fields are filled.                                                                                                                   |
| Title fields (`new_*`)     | Added pointer to per-entity title style guide                                                           | Title style guides are the source of truth; templates now route contributors there.                                                                                  |
| Framework mapping fields   | Added pointer to `framework-mappings-style-guide.md` and noted the technique-vs-mitigation rule inline  | Wrong-entity-type mapping (e.g., `AML.M####` on a risk) is one of the most common review findings.                                                                   |

If you maintain templates, see [`template-sync-procedures.md`](./template-sync-procedures.md) for keeping the YAML sources, schemas, and this guide in sync.

---

## Control Templates

### New Control Template

**When to use:** Proposing a brand new security control that doesn't exist in the framework.

**File:** `.github/ISSUE_TEMPLATE/new_control.yml`

**Required for review (6):**

1. **Control Title** - Concise noun phrase naming the defense (e.g., "Privacy Enhancing Technologies for Model Training"). See [`control-titles-style-guide.md`](./control-titles-style-guide.md). The Control ID is mechanically derived from this title (`control` prefix + camelCase descriptor, e.g., `controlPrivacyEnhancingTechnologiesForModelTraining`).
2. **Control Description** - Detailed explanation of purpose, implementation, and expected outcomes
3. **Control Category** - One of: `controlsData`, `controlsInfrastructure`, `controlsModel`, `controlsApplication`, `controlsAssurance`, `controlsGovernance`
4. **Applicable Personas** - Which personas **implement** this control. See [persona model](./submission-readiness-guide.md#section-3-the-persona-model).
5. **Applicable Components** - Component IDs this control applies to (one per line) or `all`/`none`
6. **Mitigated Risks** - Risk IDs this control addresses (one per line) or `all` (universal control)

**Optional Fields:**

- Framework mappings (dynamically shown based on entity type)
- Lifecycle stages
- Impact types
- Actor access levels
- Additional context

**Example Walkthrough:**

```yaml
# Illustrative — fields show the form a new-control proposal takes.
# (ID is mechanically derived from Title — submitter does not enter it.)
Control Title: Prompt Isolation
Control Description: Isolate untrusted prompt content from system instructions and tool-call surfaces so model-mediated injection cannot escalate into unintended actions.
Control Category: controlsApplication
Applicable Personas:
  ☑ personaApplicationDeveloper
  ☑ personaAgenticProvider
Applicable Components:
componentInputHandling
componentModelServing
Mitigated Risks:
riskPromptInjection
riskModelEvasion
```

**Reference Links:**

The template includes inline links to:

- [Component list](../../risk-map/tables/components-summary.md) - Browse valid component IDs
- [Risk list](../../risk-map/tables/risks-summary.md) - Browse valid risk IDs

**Automatic Cross-Mapping:**

✨ When you map this control to risks (e.g., `riskPromptInjection`), the reverse mappings are automatically created. Each risk you list will automatically get this control added to its applicable controls. You don't need to create a separate issue to update the risks.

---

### Update Control Template

**When to use:** Modifying an existing control (description changes, adding/removing mappings, updating metadata).

**File:** `.github/ISSUE_TEMPLATE/update_control.yml`

**Required for review (3):**

1. **Control Permalink** - GitHub permalink to the control in `controls.yaml` (right-click line number → Copy permalink)
2. **Change Type** - What you're changing (description, mappings, category, metadata, other)
3. **Proposed Changes** - Free-form description of what to change and why

**Optional Quick Actions:**

- **Component Changes** - Use `+` to add, `-` to remove (e.g., `+ componentModelEvaluation`, `- componentDataSources`)
- **Risk Changes** - Same syntax (e.g., `+ riskModelSourceTampering`, `- riskPromptInjection`)
- **Framework Changes** - Same syntax (e.g., `+ mitre-atlas: AML.M0015@5.0.1`, `- nist-ai-rmf: GOVERN-6.2@1.0`)
- **Supporting Evidence** - Links to discussions, standards, references

**Example Walkthrough:**

```
Control Permalink: https://github.com/cosai-oasis/secure-ai-tooling/blob/abc123/risk-map/yaml/controls.yaml#L45-L52

Change Type: Add mappings (components, risks, frameworks)

Proposed Changes:
Current state: Control only applies to training phase
Proposed change: Add componentModelEvaluation to components list
Rationale: This control is equally relevant during the evaluation phase when assessing model behavior

Component Changes:
+ componentModelEvaluation

Framework Changes:
+ mitre-atlas: AML.M0015@5.0.1
```

**GitHub Permalink Best Practices:**

1. Navigate to `risk-map/yaml/controls.yaml` in GitHub
2. Find the control you want to update
3. Click the line number(s) to highlight
4. Right-click → "Copy permalink" (includes commit hash, file path, and line numbers)
5. Paste into the template

This provides exact context for maintainers to see what you're changing.

**Automatic Cross-Mapping:**

✨ Risk and component mappings are automatically bidirectional. When you add/remove mappings here, the reverse updates happen automatically.

---

## Risk Templates

### New Risk Template

**When to use:** Proposing a brand new AI security risk that doesn't exist in the framework.

**File:** `.github/ISSUE_TEMPLATE/new_risk.yml`

**Required for review (6):**

1. **Risk Title** - Concise noun phrase naming the threat. See [`risk-titles-style-guide.md`](./risk-titles-style-guide.md). The Risk ID is mechanically derived from this title (`risk` prefix + camelCase descriptor, e.g., `riskPromptInjection`).
2. **Short Description** - One- or two-sentence summary
3. **Long Description** - Maps to a classical security concept, then names the AI-specific amplifier
4. **Risk Category** - One of: `risksSupplyChainAndDevelopment`, `risksDeploymentAndInfrastructure`, `risksRuntimeInputSecurity`, `risksRuntimeDataSecurity`, `risksRuntimeOutputSecurity`
5. **Applicable Personas** - Which personas are **impacted by** this risk (not implementers). `personaGovernance` is controls-only and is not listed here.
6. **Applicable Controls** - Control IDs that mitigate this risk (one per line). Do **not** list the 7 universal controls — see [Universal Controls](./submission-readiness-guide.md#section-4-universal-controls).

**Optional Fields:**

- Examples (real-world scenarios, with sources cited via `externalReferences`)
- Framework mappings (MITRE ATLAS, STRIDE, OWASP Top 10 for LLM)
- Lifecycle stages
- Impact types
- Actor access levels

**Example Walkthrough:**

```yaml
# Illustrative — fields show the form a new-risk proposal takes.
# (riskModelSourceTampering already exists in risks.yaml; this example shows
# what a fresh proposal of that entry would look like.)
# (ID is mechanically derived from Title — submitter does not enter it.)
Risk Title: Model Source Tampering
Short Description: An attacker modifies model weights or training artifacts before deployment, embedding hidden behaviors that activate on specific triggers at runtime.
Long Description: |
  Model source tampering is a model-supply-chain integrity risk — the classical
  equivalent is a trojaned binary in a software supply chain. The AI-specific
  amplifier is that the malicious behavior is encoded in model weights rather
  than in inspectable source code, making it difficult to detect through
  conventional code review. Tampering may occur during training, fine-tuning,
  or via tampered base models.

Risk Category: risksSupplyChainAndDevelopment
Applicable Personas:
  ☑ personaModelProvider
  ☑ personaApplicationDeveloper
  ☑ personaEndUser
Applicable Controls:
controlModelAndDataIntegrityManagement
controlAdversarialTrainingAndTesting

Examples:
  - The BadNets work ({{ref:gu-2017-badnets}}) demonstrated trojaned models in the ML supply chain.

External References:
  - type: paper
    id: gu-2017-badnets
    title: "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain (Gu et al., 2017)"
    url: https://arxiv.org/abs/1708.06733

Framework Mappings:
mitre-atlas: AML.T0018@5.0.1
stride: Tampering
```

Prose fields carry no inline URLs or HTML. Each source is a structured `externalReferences` entry referenced from prose by a `{{ref:identifier}}` sentinel ([ADR-016](../../../docs/adr/016-reference-strategy.md), [ADR-017](../../../docs/adr/017-yaml-prose-authoring-subset.md)). Framework-mapping IDs use the canonical form — `Tampering`, not `tampering`. See [`yaml-authoring-subset.md`](../yaml-authoring-subset.md) and [`framework-mappings-style-guide.md`](./framework-mappings-style-guide.md).

**Reference Links:**

- [Controls list](../../risk-map/tables/controls-summary.md) - Browse valid control IDs

**Automatic Cross-Mapping:**

✨ When you map this risk to controls, the reverse mappings are automatically created. Each control you list will automatically get this risk added to its mitigated risks.

---

### Update Risk Template

**When to use:** Modifying an existing risk (descriptions, examples, mappings, assessment questions).

**File:** `.github/ISSUE_TEMPLATE/update_risk.yml`

**Required for review (3):**

1. **Risk Permalink** - GitHub permalink to the risk in `risks.yaml`
2. **Change Type** - What you're changing (description, examples, mappings, etc.)
3. **Proposed Changes** - Free-form description

**Optional Quick Actions:**

- **Control Changes** - `+`/`-` syntax
- **Framework Changes** - `+`/`-` syntax
- **Examples Updates** - Add/modify real-world scenarios (sources cited via `externalReferences`)
- **Tour Content** - Updates for interactive risk tour
- **Supporting Evidence** - Research, CVEs, standards

**Example Walkthrough:**

```
Risk Permalink: https://github.com/cosai-oasis/secure-ai-tooling/blob/def456/risk-map/yaml/risks.yaml#L123-L145

Change Type: Add examples and framework mappings

Proposed Changes:
Add recent real-world example of this attack and map to OWASP Top 10 for LLM

Examples to Add:
- "Research paper documenting backdoor attack on image classifier (https://arxiv.org/...)"

Framework Changes:
+ owasp-top10-llm: LLM03:2025

Supporting Evidence:
- CVE-2024-XXXXX: Backdoor discovered in production model
- NIST guidance: https://nvlpubs.nist.gov/...
```

**Automatic Cross-Mapping:**

✨ Control mappings are automatically bidirectional. Updates propagate to connected controls.

---

## Component Templates

### New Component Template

**When to use:** Proposing a new AI system component that isn't in the framework.

**File:** `.github/ISSUE_TEMPLATE/new_component.yml`

**Required for review (4):**

1. **Component Title** - Human-readable name. See [`component-titles-style-guide.md`](./component-titles-style-guide.md). The Component ID is mechanically derived from this title (`component` prefix + camelCase descriptor, e.g., `componentFeatureStore`).
2. **Component Description** - What this component does and why it's important
3. **Component Category** - Data, Infrastructure, Model, or Application
4. **Edges** - Relationships to other components

**Edge Relationships:**

- **Edges To (Downstream)** - Components this component sends data/models to
- **Edges From (Upstream)** - Components this component receives data/models from

**Example Walkthrough:**

```yaml
# (ID is mechanically derived from Title — submitter does not enter it.)
Component Title: Feature Store
Component Description: Centralized repository for storing, managing, and serving features for ML training and inference.
Component Category: Data

Edges To (downstream):
componentModelTraining
componentModelServing

Edges From (upstream):
componentDataSources
componentDataProcessing
```

**Reference Links:**

- [Components summary](../../risk-map/tables/components-summary.md) - Browse existing components

**Automatic Bidirectionality:**

✨ When you specify edges, the reverse edges are automatically created. If you say `componentFeatureStore` → `componentModelTraining`, the system automatically creates `componentModelTraining` ← `componentFeatureStore`. You don't need to update both components.

---

### Update Component Template

**When to use:** Modifying an existing component (description, category, edges).

**File:** `.github/ISSUE_TEMPLATE/update_component.yml`

**Required for review (3):**

1. **Component Permalink** - GitHub permalink to component in `components.yaml`
2. **Change Type** - What you're changing
3. **Proposed Changes** - Free-form description

**Optional Quick Actions:**

- **Edges To Changes** - `+`/`-` syntax (e.g., `+ componentNewDestination`, `- componentOldDestination`)
- **Edges From Changes** - `+`/`-` syntax
- **Related Components** - Other components affected by edge changes
- **Supporting Evidence** - Architecture diagrams, discussions

**Example Walkthrough:**

```
Component Permalink: https://github.com/cosai-oasis/secure-ai-tooling/blob/ghi789/risk-map/yaml/components.yaml#L67-L74

Change Type: Update edges (add connections)

Proposed Changes:
Add edge to new componentFeatureStore since model training now pulls features from centralized store

Edges From Changes:
+ componentFeatureStore

Related Components:
- componentFeatureStore (new upstream dependency)

Supporting Evidence:
- Architecture diagram: https://example.com/diagram.png
```

**Automatic Bidirectionality:**

✨ Edge changes automatically update connected components. When you add an edge from ComponentA to ComponentB, the reverse edge is created automatically.

---

## Persona Templates

### New Persona Template

**When to use:** Proposing a new persona (user role) for the framework.

**File:** `.github/ISSUE_TEMPLATE/new_persona.yml`

**Important Note:** Personas are rarely added. The framework defines several personas covering common roles in AI development and deployment (see [`personas.yaml`](../../yaml/personas.yaml) for the current set). Before proposing a new persona, carefully justify why existing personas don't suffice. New personas should also propose `identificationQuestions` so readers can determine whether they fit — see the [Identification Questions Style Guide](./identification-questions-style-guide.md).

**Required for review (3):**

1. **Persona Title** - Human-readable name. The Persona ID is mechanically derived from this title (`persona` prefix + camelCase descriptor, e.g., `personaModelAuditor`).
2. **Persona Description** - Who this persona is and their responsibilities
3. **Justification** - Why existing personas don't cover this use case

**Additional Fields:**

- Use cases and examples
- Relationship to existing personas
- Framework impact assessment (how many controls/risks affected)
- Control responsibilities
- Risk exposure

**Example Walkthrough:**

```yaml
# (ID is mechanically derived from Title — submitter does not enter it.)
Persona Title: Model Auditor
Persona Description: External third-party auditor responsible for independent assessment and certification of AI systems for compliance and security.

Justification:
None of the existing personas (Model Provider, Data Provider, Platform Provider,
Model Serving, Agentic Provider, Application Developer, AI System Governance,
End User) cover external auditors who:
  - Don't create or deploy models themselves
  - Need read-only access to inspect training data, model artifacts, and logs
  - Assess compliance against regulatory frameworks
  - Issue certification reports
  (Distinct from personaGovernance, which sets internal policy rather than
  performing external attestation.)

Use Cases:
  - Third-party AI system certification
  - Regulatory compliance audits
  - Independent security assessments

Framework Impact:
  - ~15 controls would apply to this persona
  - ~8 risks would be relevant to auditors
```

**No Bidirectionality:**

Personas don't have bidirectional relationships, so there's no automatic cross-mapping.

---

### Update Persona Template

**When to use:** Clarifying or refining an existing persona (typically description updates).

**File:** `.github/ISSUE_TEMPLATE/update_persona.yml`

**Required for review (3):**

1. **Persona Permalink** - GitHub permalink to persona in `personas.yaml`
2. **Change Type** - What you're changing
3. **Proposed Changes** - Free-form description

**Change Type Options:** Update title (rename persona), Update description, Refine scope or responsibilities, **Update identification questions**, Other.

**Additional Fields:**

- **Identification Questions Changes** - Add or update identification questions for the persona using `+`/`-` syntax (or paste the full updated list). See the [Identification Questions Style Guide](./identification-questions-style-guide.md) for required form, scoping clauses, and reviewer checklist.
- Framework impact assessment
- Scope clarification (included/excluded roles)
- Supporting evidence (industry standards, role definitions)

**Example Walkthrough:**

```
Persona Permalink: https://github.com/cosai-oasis/secure-ai-tooling/blob/jkl012/risk-map/yaml/personas.yaml#L12-L18

Change Type: Clarify scope and responsibilities

Proposed Changes:
Clarify that Application Developer also includes organizations that fine-tune foundation models for their applications, not just those integrating off-the-shelf models.

Scope Clarification:
Included roles:
- Organizations integrating pre-trained models into applications
- Organizations fine-tuning foundation models for application-specific use
- SaaS providers building AI capabilities into their products

Excluded roles:
- End users of AI applications (covered by personaEndUser)
- Organizations training base models from scratch (covered by personaModelProvider)

Supporting Evidence:
- NIST AI RMF guidance on application-developer responsibilities
- MLOps maturity model: https://...
```

---

## Infrastructure Template

### Infrastructure Template

**When to use:** Proposing infrastructure improvements, framework enhancements, schema changes, automation, tooling, or documentation updates.

**File:** `.github/ISSUE_TEMPLATE/infrastructure.yml`

**Design Philosophy:** Maximum flexibility for diverse enhancement types with structured guidance.

**Key Fields:**

1. **Enhancement Category** - Schema, Automation, Tooling, Documentation, Validation, CI/CD, Testing, Other
2. **Scope** - Small, Medium, Large, Epic
3. **Rationale & Justification** - Why this enhancement is needed
4. **Implementation Approach** - How to implement (supports phased rollouts)
5. **Task List** - Markdown checkboxes for subtask tracking
6. **Breaking Changes** - Impact assessment
7. **Migration Plan** - If breaking changes required
8. **Dependencies & Prerequisites** - Blockers or requirements
9. **Testing & Validation Strategy**
10. **Related Issues** - Parent/child/sibling issue linking

**Use Cases:**

- Schema changes and framework architecture updates
- Automation/CI/CD improvements
- Tooling enhancements (validation scripts, generators, hooks)
- Documentation infrastructure
- Multi-phase enhancements requiring sub-issues

**Sub-Issue Pattern:**

For large enhancements (epics), the infrastructure issue serves as the parent:

```yaml
Task List:
- [ ] Step 1: Initial implementation
- [ ] Step 2: Testing and validation
- [ ] Sub-issue: #123 - Component A implementation
- [ ] Sub-issue: #124 - Component B implementation

Related Issues:
Parent issue: #100
Sub-issues:
- #123 - Component A
- #124 - Component B
```

**Example Walkthrough:**

```yaml
Enhancement Category: Automation
Scope: Medium

Rationale & Justification:
Add pre-commit hook to automatically validate YAML files against schemas before commits. This prevents invalid YAML from being committed and reduces maintainer review burden.

Implementation Approach:
1. Create validation script that runs check-jsonschema
2. Integrate script into pre-commit hook
3. Add GitHub Actions workflow for CI validation
4. Document usage in contributing guide

Task List:
- [ ] Create validation script
- [ ] Update pre-commit hook
- [ ] Add GitHub Actions workflow
- [ ] Update documentation
- [ ] Test with sample commits

Breaking Changes: No
- Pre-commit validation is optional (can be bypassed with --no-verify)
- Existing commits remain valid

Testing & Validation Strategy:
- Validation script correctly identifies invalid YAML
- Pre-commit hook blocks invalid commits
- GitHub Actions detects issues in PRs
- Documentation includes troubleshooting guidance
```

---

## Key Concepts

### Automatic Bidirectionality

The CoSAI Risk Map framework maintains bidirectional relationships automatically. You don't need to update both sides of a relationship manually.

**Component Edges:**

- ✨ When you specify `componentA` → `componentB`, the system creates `componentB` ← `componentA`
- Update templates handle reverse edges automatically
- Validation ensures consistency

**Control ↔ Risk Cross-Mapping:**

- ✨ When you map a control to risks, those risks automatically get the control added
- ✨ When you map a risk to controls, those controls automatically get the risk added
- No need to create separate issues for both sides

**Benefits:**

- Reduces user burden (no manual cross-referencing)
- Prevents errors from missing reverse mappings
- Maintains consistency across the framework

### GitHub Permalinks

Update templates require GitHub permalinks instead of entity IDs. This provides:

**Traceability:**

- Exact commit hash (historical context)
- Line numbers (precise location)
- File path (no ambiguity)

**How to Create:**

1. Navigate to the YAML file in GitHub (e.g., `controls.yaml`)
2. Click the line number(s) to highlight
3. Right-click → "Copy permalink"
4. Paste into the template

**Example:**
`https://github.com/cosai-oasis/secure-ai-tooling/blob/abc123def456/risk-map/yaml/controls.yaml#L45-L52`

### Git Diff Syntax

Update templates support quick actions using familiar git diff syntax:

**Add:** Prefix with `+`

```
+ componentNewItem
+ mitre-atlas: AML.M0015@5.0.1
```

**Remove:** Prefix with `-`

```
- componentOldItem
- nist-ai-rmf: GOVERN-6.2@1.0
```

**Benefits:**

- Familiar to developers
- Concise notation
- Easy to parse programmatically

### Framework Applicability

Different entity types map to different external frameworks:

| Framework        | Controls | Risks | Components | Personas |
| ---------------- | -------- | ----- | ---------- | -------- |
| MITRE ATLAS      | ✅       | ✅    | ❌         | ❌       |
| NIST AI RMF      | ✅       | ❌    | ❌         | ❌       |
| STRIDE           | ❌       | ✅    | ❌         | ❌       |
| OWASP Top 10 LLM | ✅       | ✅    | ❌         | ❌       |
| ISO 22989        | ❌       | ❌    | ❌         | ✅       |
| EU AI Act        | ✅       | ❌    | ❌         | ✅       |

**Controls** use MITRE ATLAS mitigations (AML.M\*), NIST AI RMF subcategories, OWASP Top 10 for LLM, and EU AI Act articles.

**Risks** use MITRE ATLAS techniques (AML.T\*), STRIDE threat categories, and OWASP Top 10 for LLM.

**Personas** use ISO 22989 actor roles and EU AI Act defined roles.

**Components** currently have no framework mappings.

Templates automatically show only applicable frameworks for each entity type based on dynamic configuration.

### Schema Evolution and Two-Week Lag

**Important:** Template dropdown options may lag behind the `develop` branch by up to 2 weeks.

**Why the Lag:**

The CoSAI Risk Map uses a two-stage governance process:

1. **Technical Review:** Changes merge to `develop` branch
2. **Community Review:** After ~2 weeks, `develop` merges to `main`

GitHub issue templates are served from the `main` branch, so new enums added to schemas in `develop` won't appear in template dropdowns until merged to `main`.

**What This Means for You:**

- If you're proposing a new entity using a recently added category/enum that's only in `develop`, it may not appear in the dropdown yet
- **Workaround:** Use the free-form text fields (most templates have both dropdowns and text areas)
- **Alternative:** Wait ~2 weeks for `develop` → `main` merge
- Maintainers understand this limitation and will accommodate proposals using valid-but-not-yet-in-dropdown values

**Example:**

```
# New control category added to develop branch but not in dropdown yet
Control Category: controlsSecurity  # Not in dropdown yet
# → Use Additional Context field to note: "Using new controlsSecurity category from develop branch"
```

---

## Common Pitfalls

### 1. Not Using Reference Links

**Problem:** Submitting invalid component IDs, risk IDs, or framework mappings.

**Solution:** Click the reference documentation links in templates:

- [Components summary](../../risk-map/tables/components-summary.md)
- [Risks summary](../../risk-map/tables/risks-summary.md)
- [Controls summary](../../risk-map/tables/controls-summary.md)

These tables show all valid IDs.

### 2. Manual Bidirectional Updates

**Problem:** Creating separate issues to update both sides of a relationship (e.g., issue to add control→risk mapping, then another issue to add risk→control mapping).

**Solution:** Only update one side. The system handles bidirectionality automatically. Read the ✨ Automatic Cross-Mapping messages in templates.

### 3. Incorrect Permalink Format

**Problem:** Linking to the latest version instead of a permalink with commit hash.

**Solution:** Use "Copy permalink" (not "Copy link"). Permalinks include commit hashes and are immutable.

❌ Wrong: `https://github.com/org/repo/blob/main/file.yaml#L10`
✅ Correct: `https://github.com/org/repo/blob/abc123def456/file.yaml#L10`

### 4. Using Reserved YAML Words

**Problem:** Proposal uses reserved YAML words (`none`, `null`, `true`, `false`, `yes`, `no`, `on`, `off`) as bare values.

**Solution:** Use descriptive alternatives or quote the value. Example: Use "N/A - No subcategory" instead of bare "None".

### 5. Incomplete New Entity Proposals

**Problem:** Missing required fields, especially references to related entities (components, risks, controls).

**Solution:** Check the template for asterisks (\*) marking required fields. Use reference links to find valid related entities.

### 6. Update Without Justification

**Problem:** Update template submissions without explaining _why_ the change is needed.

**Solution:** Always provide rationale in the "Proposed Changes" field. Explain the current state, proposed change, and why it improves the framework.

### 7. Wrong Framework for Entity Type

**Problem:** Trying to map STRIDE to a control, or NIST AI RMF to a risk.

**Solution:** Review the Framework Applicability table in [Key Concepts](#framework-applicability). Templates only show applicable frameworks.

---

## Getting Help

If you're unsure which template to use or how to fill it out:

1. **Review existing issues:** Look for similar proposals in closed issues
2. **Check documentation:**
   - [Main contribution guide](../../CONTRIBUTING.md)
   - [Development workflow](../workflow.md)
   - [Entity-specific guides](../) (guide-controls.md, guide-risks.md, etc.)
3. **Ask questions:** Open a discussion or draft issue to get feedback before formal submission

---

## Next Steps

After reading this guide:

1. Choose the appropriate template for your proposal
2. Gather necessary information (entity details, related IDs, references)
3. Fill out required fields carefully
4. Review submission checklist at the bottom of each template
5. Submit the issue

Maintainers will review your proposal, potentially ask clarifying questions, and work with you to integrate approved changes into the framework.

For more information on the overall contribution workflow and branching strategy, see [CONTRIBUTING.md](../../../../CONTRIBUTING.md).
