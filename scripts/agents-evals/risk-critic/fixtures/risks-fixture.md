# Risk corpus fixture

**This is test input, not CoSAI Risk Map content.** It is a small, hand-authored, purpose-built
stand-in for `risk-map/yaml/risks.yaml`, used only to grade eval cases whose correct verdict
depends on "does an existing risk already cover this candidate" — never the live, growing corpus
(see ADR-033 Amendment 2026-07-30, D7). It must not be cited, validated, or consumed as if it were
real Risk Map content. It is refreshed only if the risk entity shape changes structurally (e.g.
a required schema field is added), never in response to the real corpus growing.

Fixture entries:

- `riskAgentToolOutputInjection` — content returned by a tool an agent has invoked (a search
  result, a fetched document, an API response) contains text crafted to be interpreted by the
  agent as a new instruction rather than as data, steering the agent's subsequent reasoning or
  actions away from what the requesting user asked for. **Deliberately broad enough to cover any
  tool-output-borne instruction injected into an agent's reasoning context** — a near-duplicate
  target for eval cases proposing a narrower version of the same capability (e.g., a single named
  tool type).
- `riskAgentCredentialOverPrivileging` — an agent is issued credentials or permission scopes
  broader than any single task requires, so a compromised or manipulated agent session carries
  standing access to resources or actions beyond what its current task needs, for the full
  lifetime of that session. **Deliberately broad enough to cover session-scoped
  over-privileging** — a near-duplicate target for eval cases proposing a narrower version of the
  same capability.
- `riskModelWeightExfiltrationViaSideChannel` — an attacker recovers a proprietary model's
  weights not by directly reading a stored artifact, but by observing indirect signals produced
  during inference — timing variation, cache-occupancy patterns, or power draw — and
  reconstructing the weights, or a functionally equivalent surrogate, from those signals.
- `riskMultiAgentTrustBoundaryCollapse` — in a system where multiple agents exchange messages, a
  receiving agent treats content authored by another agent as inherently trusted and exempt from
  the input handling it would apply to external or user-supplied content, so a compromised or
  manipulated peer agent's output flows into the receiving agent's actions without further
  scrutiny.
- `riskEvaluationDatasetContamination` — data used to certify a model's safety or performance
  through a benchmark or evaluation suite overlaps with, or closely resembles, the data the model
  was trained on, so evaluation results overstate how the model actually generalizes to novel,
  real-world inputs.
- `riskAgentSessionReplayAcrossTenants` — a captured agent session token or execution trace,
  issued for one tenant's context in a multi-tenant agent platform, is replayed against the
  platform later, causing tool calls or data access to execute as if still scoped to the original
  tenant's boundary.
