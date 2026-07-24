# Framework Applicability and Selection Rules

Compact grounding for selecting a control's framework mappings. The authoritative source for canonical pinned patterns and the maintainer tool is `risk-map/docs/contributing/framework-mappings-style-guide.md`; this file distills the selection judgment.

## Applicability by entity type

| Framework | Applies to controls? | Control-side target |
|---|---|---|
| MITRE ATLAS | yes | **mitigations** `AML.M####` (never techniques `AML.T####`) |
| NIST AI RMF | yes | subcategory id, correct function (see below) |
| OWASP Top 10 for LLM | yes | `LLMxx:2025` |
| STRIDE | risk-oriented; rarely on controls | — |
| ISO 22989 | terminology/roles; typically not control mitigations | — |
| EU AI Act | governance-oriented; use only when a control implements a specific obligation | `Article N@2024` |

**Non-US counterbalance (D3b):** the EU AI Act and ISO/IEC standards are the non-US framings on the mapping side. Map to the EU AI Act when a control implements a specific obligation (e.g. human oversight → Article 14; risk management → Article 9; record-keeping → Article 12; robustness/security → Article 15). Do **not** force an EU AI Act mapping onto a generic technical control that implements no specific obligation — that is over-mapping. When a control has a clear regulatory obligation and you map only NIST/US frameworks, that is a counterbalance gap worth surfacing.

Check the style guide's applicability table before mapping to a framework not listed as control-applicable.

## MITRE ATLAS: mitigation vs technique

- Risks map to **techniques** (`AML.T####`) — what the adversary does.
- Controls map to **mitigations** (`AML.M####`) — what defends against it.
- Never put a technique on a control. If no mitigation fits, omit ATLAS; a forced or approximate mitigation is worse than none.
- Do not map both a parent and its sub-technique/mitigation; use the most specific that applies.

## NIST AI RMF: pick the right function

Always use the subcategory id (e.g., `MEASURE-2.7`), never the bare category (`MEASURE-2`). Choose the function by what the control *is*:

| Function | It covers | Typical control shape |
|---|---|---|
| **GOVERN** | policies, roles, responsibilities, accountability, oversight, culture, risk tolerance | preventive design controls, human-oversight, governance/assurance controls |
| **MAP** | context-setting, intended-use framing, impact identification | controls that establish scope or classify context before action |
| **MEASURE** | assessment, testing, evaluation, metrics, tracking, red-teaming | controls that test, validate, or monitor |
| **MANAGE** | responding to / prioritizing / treating / recovering from *identified* risks | incident response, remediation, operational treatment controls |

Common mistake: mapping a **preventive design or oversight control to MANAGE**. MANAGE is reactive (you have already identified and are now treating a risk). A control that shapes how the system behaves by design is almost always **GOVERN** (policy/oversight) or **MEASURE** (assessment). When in doubt between GOVERN and MANAGE for a design-time control, prefer GOVERN.

**Scoping caveat — read the parent category, and don't map governance-*definition* to a technical control.** A subcategory is never broader than its category. **GOVERN-6** is scoped by its own statement to *"AI risks and benefits arising from **third-party software and data and other supply chain issues**"* — so **`GOVERN-6.1`** (third-party policies) and **`GOVERN-6.2`** (contingency for third-party incidents) apply **only to supply-chain / vendor controls**, never to internal authorization, identity, or credential mechanics (a common misread that turns `GOVERN-6.2` into cluster wallpaper). More generally, a GOVERN/MAP subcategory that describes *defining, assessing, or documenting* a governance process (proficiency `MAP-3.4`; policies; roles/responsibilities) maps to a **governance activity** (a `personaGovernance` responsibility), not to a technical control's mechanism — a technical control *is* the outcome, it does not *define* it. Map a technical control to GOVERN/MAP only where it genuinely operationalizes that specific policy.

Examples of good picks:
- A least-privilege / permission-scoping control → `MEASURE-2.7` (security & resilience); **do NOT use `GOVERN-6.x`** (that family is third-party/supply-chain-scoped — see the caveat above). If no NIST subcategory fits an internal technical control, omit NIST rather than force a governance-phase one.
- A human-oversight / confirmation control → a `GOVERN` subcategory on oversight (not MANAGE).
- A testing / evaluation control → `MEASURE`.
- An incident-response control → `MANAGE`.

## Selectivity

- Soft cap: 4 mappings per framework. More than that usually signals the control is too broad or the mappings include "related" rather than "directly relevant" items.
- Every mapping needs a defensible one-sentence rationale.

## Generate, don't hand-spell

Mapping values are version-pinned (ADR-027). Generate them with `scripts/framework_mapping_maintainer.py` (subcommands add/update/remove/migrate), which composes and validates the pinned value. If you propose mappings without running the tool, mark each `[tool-generate]` so the value is produced and verified before merge.
