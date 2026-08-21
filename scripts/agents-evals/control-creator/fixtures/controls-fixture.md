# Control corpus fixture

**This is test input, not CoSAI Risk Map content.** It is a small, hand-authored, purpose-built
stand-in for `risk-map/yaml/controls.yaml`, used only to grade eval cases whose correct verdict
depends on "does an existing entry already cover this candidate" — never the live, growing corpus
(see ADR-033 Amendment 2026-07-30, D7). It must not be cited, validated, or consumed as if it were
real Risk Map content. It is refreshed only if the control entity shape changes structurally (e.g.
a required schema field is added), never in response to the real corpus growing.

Fixture entries:

- `controlToolCredentialLifecycleManagement` — issue, rotate, and revoke credentials granted to
  agent tool integrations, scoping credential lifetime to the session or task that requested them
  so a credential does not remain valid after the agent's task concludes. **Deliberately broad
  enough to cover session-scoped tool-credential rotation and revocation** — a near-duplicate
  target for eval cases proposing a narrower version of the same capability.
- `controlAgentActionAuthorizationGating` — require an explicit authorization decision (human or
  policy engine) before an agent executes a high-consequence action.
- `controlModelOutputProvenanceLabeling` — attach provenance metadata to model-generated output so
  downstream consumers can distinguish it from human-authored content.
- `controlDataRetentionScheduling` — enforce a defined retention and deletion schedule for stored
  data, including agent-collected data.
- `controlThirdPartyToolVettingProcess` — vet and approve third-party tools before they are made
  available for agent invocation.
- `controlAgentReasoningTraceLogging` — capture the agent's reasoning trace (not just the actions
  taken) for later audit and incident reconstruction.
