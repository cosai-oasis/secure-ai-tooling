# ADR-030: Agentic component model — external tools tier and identity grouping

**Status:** Accepted
**Date:** 2026-06-30
**Authors:** Architect agent, with maintainer review

---

## Context

The CoSAI Risk Map component graph (`risk-map/yaml/components.yaml`, governed by `risk-map/schemas/components.schema.json` and [ADR-018](018-components-schema.md)) was built before the framework had to model agentic systems with first-class tool use. Working through [MCP (Model Context Protocol) security guidance](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/7ec1306f2f55563f6eeef9d36a6bb2b531491ceb/model-context-protocol-security.md) — the CoSAI Workstream 4 (secure-design-for-agentic-systems) paper, pinned at commit `7ec1306` so the reference survives a repo reorganization — surfaced a cluster of structural gaps where risks and controls had no component to attach to: identity and access had no home; there was no first-class consent / human-in-the-loop surface; no grouping for external tools; no explicit isolation/containment modeling; no access-control policy-point set (a policy enforcement point and a policy decision point); an open question of whether to decompose `componentTools` by caller; and no home for a *specific realization* of a general component (e.g. one hosting substrate serving several workload types). Several of these recur across many risks and controls, which is the signal that the *framework shape*, not any single entry, is what needs deciding.

A redesign of the component graph addresses the cluster at once: it gathers the tool machinery into a dedicated top-level grouping, gives identity components a home, makes consent first-class, widens the deployment substrate, places a policy enforcement point at each trust boundary, decouples the agent reasoning core from orchestration, and routes the tool-call path so external tools are reachable only through the tool server. The decisions below record the resulting model and the trade-offs weighed in landing it.

Most of the components named in the decisions below are **not yet in `develop`/`main`** — the in-flight MCP decomposition introduces them (the identity provider and policy decision/enforcement points, the consent surface, the isolation runtime, the tool server, the agent-tool transport, the federation proxy, external prompt templates, and the network PEPs). This ADR decides the **target taxonomy** for the combined set: where those new components land, and how the components already in the corpus (`componentTools`, plus the model/serving/registry/orchestration/application/agent components) are regrouped around them. Statements below about a component's home are therefore **forward-looking** — they describe the model once this change and the decomposition's additions land together, not edits to today's corpus; where a component already exists in the corpus, that is called out.

**Scope boundary — shape, not representation.** This ADR decides the component *taxonomy* (categories, subcategories, the component set) and lands each component together with its edges as `{to, from}` *mappings*. It deliberately does **not** decide graphical *representation*: how an edge is typed (`kind`), how directionality is shown, how a control-intermediated flow is drawn, or whether an overview graph is a subset of per-category detail graphs. Those are routed to a separate, later **representation ADR** (D10), gated on a dedicated survey of graphical-mapping approaches, because how the model is *drawn* is a distinct problem from where components live and what connects to what.

This is the highest-blast-radius change the component taxonomy has taken. It trips multiple [ADR-018](018-components-schema.md) closed-enum surfaces at once: `category.id` is a closed enum of three values (`components.schema.json:30`), `subcategory.id` is a closed enum (`components.schema.json:47-55`), `component.id` is a closed enum, and the `allOf` category→subcategory consistency block (`components.schema.json:147-158`) constrains which subcategories nest under which category. Per [ADR-018](018-components-schema.md) D2 those enums are deliberately closed so every consumer — the validator, the Mermaid generators, the table generator — sees the same taxonomy at once; the documented cost is that a taxonomy change is a schema edit, and a *new top-level category* additionally hits the `ComponentGraph` hardcoded-category handling that [ADR-018](018-components-schema.md) names as a known coupling. Because the change is framework-shape (a new top-level category plus closed-enum edits), it is settled in an ADR before any implementation.

The component edge model carries only `{to, from}` data-flow arrays (per [ADR-018](018-components-schema.md) D3); `ComponentEdgeValidator` checks bidirectional *consistency, not semantics*. Some relationships this ADR lands are not data-flow — a policy point is *consulted* for a verdict, a workload is *contained* in an isolation boundary. They land as plain `{to, from}` mappings anyway, because the components that own them (the identity provider, the decision point, the isolation runtime) have no other edges and would otherwise be isolated — which the orphan/isolated-component validator forbids and which would make them meaningless in the graph. The cost is that the current renderer draws them as data-flow arrows until the representation ADR adds a typed `kind`; this ADR accepts and documents that interim rather than stranding the components (see D9).

This ADR is the **first of a multi-part split**. It records the taxonomy and component-mapping decisions that land now. A future **representation ADR** (D10) decides edge typing, directionality, and graph composition; a separate deferral (D10) holds an autonomy/workload attribute. Content semantics — the risk taxonomy, the persona model, the per-component descriptions and mappings — are framework-content design and belong in `risk-map/docs/design/` and the content-review workflow, not here.

## Decision

We adopt the component taxonomy described by D1–D8 below and land the components with their edges as `{to, from}` mappings (D9), and we name two deferred follow-ons — a graphical representation ADR and an autonomy/workload attribute (D10). The **`components.schema.json` and `components.yaml` edits must land together atomically** (enums, `allOf`, `categories:` block, entries, recategorizations, and edges in one step — the closed-enum coupling means a partial change fails validation). That atomic pair is the source-of-truth core, *not* the whole change: it drags in a `mermaid-styles.yaml` category entry, the `ComponentGraph` code, the regenerated diagrams/tables/SVGs, and several test suites — sequenced as fail-loud consumer wiring and a content re-mapping pass in "Migration sequencing" below.

### D1. New top-level `componentsTools` category with two subcategories

A new **top-level** category `componentsTools`, a fourth peer of `componentsInfrastructure`, `componentsModel`, and `componentsApplication`, collects the tool and tool-authorization components: the existing `componentTools` (recategorized out of `componentsModel`) together with the tool components the decomposition introduces. Top-level (a fourth peer tier, not a subcategory under an existing one) because tools are an **external trust domain** — third-party services the AI system integrates with but does not own — distinct in kind from the system's own infrastructure, model, and application tiers. (The components *inside* the tool zone are reached only via the agent path per D8; top-level reflects the external trust boundary, not a claim that tools wire into every layer.) It carries two subcategories:

- **`componentsToolControls`** (the tool control plane) — `componentToolNetworkPolicyEnforcementPoint`, `componentAuthorizationPolicyEnforcementPoint`, `componentFederationProxy`, `componentExternalPromptTemplate`.
- **`componentsToolCore`** (the tool data plane) — `componentToolServer`, `componentTools`, `componentToolInputHandling`, `componentToolOutputHandling`.

Registries (`componentModelRegistry`, `componentToolRegistry`) stay in Infrastructure — they are not tools.

Schema impact: `category.id` enum gains `componentsTools` (currently closed to three values at `components.schema.json:30`); `subcategory.id` enum gains `componentsToolControls` and `componentsToolCore`; a new `componentsTools` branch is added to the `allOf` block (`components.schema.json:147-158`) permitting those two subcategories; the file-level `categories:` block gains the category and its subcategories.

### D2. New `componentsIdentity` subcategory under Infrastructure

`componentIdentityProvider` and `componentAuthorizationPolicyDecisionPoint` — both introduced by the decomposition, neither in the corpus today — land in a new `componentsIdentity` subcategory under `componentsInfrastructure`, giving identity its own home rather than scattering it across Infrastructure (the identity-placement gap). This ADR fixes their home; the components themselves are authored through the content process.

Schema impact: `subcategory.id` enum gains `componentsIdentity`; the Infrastructure `allOf` then-block (`components.schema.json:149-150`, today `{componentsData, componentsModelDeployment}`) gains `componentsIdentity`. If `componentsRegistries` is not already present in the Infrastructure branch on the target base, it is added in the same edit so the registries keep a valid nesting.

### D3. "Model Deployment" → "Deployment" rename

The `componentsModelDeployment` subcategory title changes from "Model Deployment" to "Deployment" to reflect that it now hosts the serving/hosting substrate for model, tool, and runtime workloads, not only the model. This is a `categories:` block title edit; the subcategory `id` (`componentsModelDeployment`) is unchanged, so it is not an enum change and strands no references.

### D4. One network policy-enforcement point per trust boundary

The model places **one network policy-enforcement point at each trust boundary**:

- `componentAgentNetworkPolicyEnforcementPoint` — the agent's network boundary (in `componentsAgent`).
- `componentToolNetworkPolicyEnforcementPoint` — the tool zone's network boundary (in `componentsToolControls`).

This is the NIST SP 800-207 pattern: a single policy enforcement point sits at a trust boundary and mediates all traffic crossing it, with *direction a property of the policy it enforces, not a separate node*. The two directions attract different controls — egress: exfiltration prevention, DLP, tool-call authorization; ingress: injection defense, sanitization, schema validation — but expressing that means showing inbound and outbound flow *through a single PEP*, which the edge model cannot do today; the directionality and its per-leg control mapping are deferred to the representation ADR (D10) and the content re-mapping.

Schema impact: the `component.id` enum gains the two PEP ids.

### D5. Two consent surfaces

The model introduces **two** consent surfaces: `componentApplicationConsentSurface` (in `componentsApplicationCore`) and `componentAgentConsentSurface` (in `componentsAgent`). This is **not** a caller-duplicate of one capability (the antipattern of splitting one capability by who calls it). Autonomy gives the agent surface a distinct *risk kind* — consent fatigue / habituation, a documented human-factors failure mode in which high-volume confirmations train rubber-stamping and so defeat consent for the rare irreversible action — plus distinct controls (risk-tiering, reserve-for-irreversible) and a genuinely distinct locus (an application approval flow versus an agent elicitation flow). The two surfaces are kept on the strength of that distinct risk kind, not on structural symmetry. (The fatigue risk and its tiering control are content, authored in the risk/control re-mapping; this ADR fixes only the component shape.)

Schema impact: the `component.id` enum gains the two consent-surface ids; any control/risk mapping against a single consent surface is dual-mapped onto both, then refined.

### D6. Serving fold to `componentRuntimeHosting`

The deployment substrate lands as **three** serving/hosting components:

- **`componentModelServing`** — the one already in the corpus; unchanged (model inference).
- **`componentToolHosting`** — new; a distinct threat model (hosting untrusted external tool code — arbitrary-code-execution and sandboxing controls).
- **`componentRuntimeHosting`** — new; the runtime substrate for the AI system's own application and agent execution.

Application and agent execution share one hosting substrate with one set of hosting controls, so they are **one** component, not two. The autonomy-driven *difference in required control strength* between an application workload and a higher-autonomy agent workload is a workload attribute, not a second component, and is deferred to D10; in the interim `componentRuntimeHosting` carries the agent / high-autonomy control set as the conservative default. This keeps the workload distinction an attribute question rather than component sprawl.

Schema impact: `component.id` enum adds `componentRuntimeHosting` and `componentToolHosting`; `componentModelServing` is unchanged. `componentRuntimeHosting`, `componentToolHosting`, and the two tool I/O-handling components (D7) are net-new nodes that were not vetted by the same component-justification review the existing components went through; each must earn its place — it stays only if it carries distinct controls/risks rather than absorbing into an existing component — before its id is landed in the closed enum (see Consequences and Migration sequencing).

### D7. Dedicated tool I/O-handling layer

A tool-side request/response handling layer is added: `componentToolInputHandling` and `componentToolOutputHandling`, at the tool-server boundary. This is the natural **fourth** instance of the in-flow handling pattern the corpus already models at the application, orchestration, and agent boundaries; tool-response poisoning and tool-output injection are tool-boundary threats distinct from orchestration-context filtering. Both are net-new nodes placed in `componentsToolCore` (D1) and must clear the same net-new-component justification (D6, Consequences).

### D8. Tool-call re-anchoring and the reasoning-core / orchestration decouple

Two intentional rewires of the edge set:

- **Tool invocation is agent-exclusive.** No application node reaches the tool server; the application does not invoke tools directly, only the agent does. This shifts the Application persona's risk surface.
- **The reasoning core is decoupled from orchestration.** `componentReasoningCore` connects only via `componentAgentInputHandling` and `componentAgentOutputHandling`; the orchestration subgraph (memory, RAG, orchestration I/O handling) is reachable only via `componentTheModel`, not wired straight into the reasoning core.

These realize one control-boundary principle: the reasoning core acts only through the agent's own input/output handling, so every influence on it — tool results, retrieved context, memory — arrives through a gate it does not control directly, and external tools are touched only by `componentToolServer`. They are recorded here because they are edge-set decisions a reader of the diff alone would not recognize as deliberate, not because they change how anything is drawn.

### D9. Consult and containment edges land as mappings; typing and rendering deferred

The relationships below are not data-flow, but they land now as plain `{to, from}` mappings so their owning components are not isolated; their correct typing and rendering are deferred to the representation ADR (D10).

**Consult** (a policy point is queried; a verdict or attribute returns):
- `componentIdentityProvider → componentAuthorizationPolicyDecisionPoint` — the IdP serves identity attributes to the PDP. In ABAC terms (NIST SP 800-162) the IdP fills the *attribute-source / policy-information-point* role; this model does not introduce a separate PIP, and it introduces **no policy-administration point (PAP)** — policy-administration risks have no component home, noted here as a known gap.
- `componentAuthorizationPolicyDecisionPoint → componentAuthorizationPolicyEnforcementPoint` and `componentAuthorizationPolicyDecisionPoint → componentToolNetworkPolicyEnforcementPoint` — the PDP returns a verdict to each enforcement point. A PEP without a decision source is inert, so both the action-authorization PEP and the network PEP consult the PDP.
- `componentIdentityProvider → componentToolNetworkPolicyEnforcementPoint` — the IdP serves token attributes to the network PEP.

**Containment** (the target runs *inside* the boundary):
- `componentIsolationRuntime` (in `componentsModelDeployment`) → `componentModelServing`, `componentToolHosting`, `componentRuntimeHosting`.

These edges are mechanically valid (bidirectional consistency holds) but semantically mis-rendered by the current generator, which has no notion of edge kind. That is the interim cost the representation ADR (D10) resolves; this ADR's responsibility is only that the mappings are correct and no component is orphaned.

### D10. Deferred follow-ons — a graphical representation ADR, and an autonomy/workload attribute

Two separate deferrals, neither decided here:

- **Graphical representation (a future ADR; backlog).** A typed edge `kind` (`data` / `consult` / `contains`) plus renderer support; how to show inbound/outbound flow through a single PEP (D4); how to draw a control-intermediated full flow; and whether the overview graph is a subset of per-category detail graphs. These are a distinct problem from component shape and are gated on a dedicated survey of independent graphical-mapping approaches before an ADR is authored. Named here so the deferral is traceable; not scheduled.
- **An autonomy/workload realization attribute (a separate deferred *shape* decision).** A component attribute that re-encodes the application-versus-agent distinction `componentRuntimeHosting` (D6) folds. This is a modeling primitive, not a representation concern, and is parked as its own follow-on rather than bundled into the representation ADR.

## Alternatives Considered

- **`componentsTools` as a subcategory under an existing tier instead of a top-level category (D1).** A subcategory would dodge the closed `category` enum edit and the `ComponentGraph` hardcoded-category breakage. The challenge that tools are "agent-subordinate" (D8 makes invocation agent-exclusive) and so should nest under Application was considered and rejected: tools are *external* third-party services, not part of the application the system builds. Top-level reflects the external trust boundary; the responsibility and rendering work it forces is the honest cost of modeling tools as the peer tier they are.

- **Four directional PEPs (agent + tool ingress/egress) instead of one per boundary (D4).** Splitting each network PEP by direction — on the argument that ingress and egress attract different controls — was considered and rejected: SP 800-207 places one PEP per trust boundary and treats direction as a policy property, not a node; four nodes for two boundaries models direction as topology, and the framework's own anti-duplicate rule (applied to consent in D5) cuts against it. The per-leg control distinction is retained but expressed through control mapping and the representation ADR (D10), not extra components.

- **Category-direct PEP placement (a layout "sandwich") instead of normal subcategory nesting (D1/D4).** Placing the tool PEPs directly under `componentsTools` so a diagram renders the inner subgraphs wrapped by the perimeter was considered and rejected as drawing-driven: the PEPs nest in their subcategories like every other component, and any perimeter/flow depiction is a representation concern for D10.

- **Separate application-serving and agent-hosting components, or a realization attribute now, instead of one runtime substrate (D6).** Two separate components were rejected as component sprawl (one substrate, no per-host control delta); adding the realization attribute now was rejected as out of scope (it is the deferred attribute in D10). The chosen path is a single `componentRuntimeHosting` for both, alongside `componentModelServing` and `componentToolHosting` (each a distinct threat model), with the attribute deferred.

- **One consent surface with edges to both layers instead of two (D5).** Rejected because the agent surface carries a distinct risk *kind* (consent fatigue / habituation) and distinct controls the application surface does not — the split is justified by a mapping delta, not symmetry. Had no distinct mapping been demonstrable, the fold would have been correct.

- **Typed edges / representation now instead of landing plain mappings and deferring (D9/D10).** Adding a typed edge `kind` and resolving how the model is drawn would let the consult/containment edges land without mis-rendering. Rejected for *this* ADR: it is a renderer + schema change and an open design space the maintainer intends to survey with a dedicated agent exploration before committing. The interim cost — those edges render as data-flow until D10 — is accepted because the alternative (landing the identity/isolation components without edges) trips the orphan validator and strands them.

## Consequences

**Positive**

- The structural gaps surfaced by the MCP review get component homes: identity, a first-class consent surface, the policy-point set (enforcement and decision points), an external-tools tier, and the isolation/containment relationship — all landed as mappings now. The tool-decomposition question is resolved toward path-based modeling (single `componentTools`, layer-specificity via the invocation path), and the serving question is resolved as an attribute question rather than sprawl.
- The shape/representation split keeps this ADR decidable without committing to an unexplored graph-representation design: the contested layout, directionality, and edge-typing questions are routed to a dedicated ADR (D10) instead of being forced here.

**Negative**

- **The schema and YAML must change together atomically.** `category.id`, `subcategory.id`, and `component.id` enums; the `allOf` category→subcategory branches; and the `categories:` block all change together with the entries, recategorizations, and edges. Enum expansion must precede or accompany the edge buildout, because an edge referencing a not-yet-enumerated id fails schema validation. This is the [ADR-018](018-components-schema.md) D2 closed-enum cost at its largest — the coupling is about *ordering within one change*, not about the change being small.
- **The landing commit is large — not a two-file edit.** The atomic schema+YAML core drives the pre-commit generators to rebuild ~23 tracked artifacts from the corpus (7 diagrams + 4 SVGs + 12 tables under `risk-map/`), requires a `mermaid-styles.yaml` category entry and the `ComponentGraph` code change (both below), and forces updates across several test suites — category handling, category/subcategory nesting, graph rendering, `models`, and the controls↔components mirror.
- **The `ComponentGraph` hardcoded-category handling is a hard blocker.** [ADR-018](018-components-schema.md) names it as a known coupling; a fourth top-level category hits it hardest. Graph generation will not pick up `componentsTools` until that code is fixed.
- **`mermaid-styles.yaml` needs a `componentsTools` style** or the new category renders unstyled; a real-corpus guard should fail CI on a styleless category.
- **The fourth category needs a persona owner.** Per [ADR-021](021-personas-and-self-assessment-schema.md), a Tools category with no responsible persona is orphaned in the responsibility model; persona mappings and the persona-site must place it (the Agentic Platform / tool-provider persona is the candidate owner).
- **The edge model carries interim semantic debt.** The consult and containment edges (D9) ride data-flow `to`/`from` and the current renderer draws them as real data-flow arrows until the representation ADR (D10) adds a typed `kind`. This misleads diagram readers in the interim; it is accepted to avoid stranding the identity and isolation components.
- **Control/risk re-mapping is owed.** The two consent surfaces (D5) and the recategorizations require draft control/risk mappings to be re-targeted (dual-map, then refine) — content-reviewer work on a later branch.
- **Four net-new nodes owe a component justification before their ids enter the closed enum.** `componentRuntimeHosting`, `componentToolHosting`, `componentToolInputHandling`, `componentToolOutputHandling` — each must pass the absorb-into-existing / reader-instructive test first.
- **Near-identical ids** (`componentTools`, `componentsTools`, `componentsToolCore`, `componentsToolControls`) are easy to misread; a naming pass is worth doing before the corpus lands.

**Follow-up**

- **Representation ADR (D10):** typed edge `kind`, directionality through a single PEP, control-intermediated flow views, and overview-vs-detail graph composition — gated on the graphical-mapping survey.
- **Autonomy/workload attribute (D10):** a separate deferred shape decision.
- **Content work:** the agent consent-fatigue risk and its tiering control, and the four component justifications above.
- **Consumer wiring:** `ComponentGraph` fourth-category handling, the `componentsTools` `mermaid-styles.yaml` entry, table/SVG regeneration, persona ownership of Tools, and a CI guard that fails on an unstyled or owner-less category.

## Migration sequencing

The change lands in ordered stages; each blocks on the one before it:

1. **ADR (this record).** The taxonomy and component-mapping decisions D1–D9. Everything else blocks on sign-off here.
2. **Net-new component justification.** Run the absorb / reader-instructive test on the four net-new nodes (D6/D7) *before* their ids enter the closed enum, so the enum is not widened for a component that should have folded.
3. **Atomic schema + yaml change.** `category` enum, `subcategory` enum, `component.id` enum, the `allOf` branches, the `categories:` block, the new/renamed entries, the recategorizations, and the edges — landed together. Internal order: enums and `allOf` first, then the `categories:` block, then entries, then recategorize, then edges, then `validate_riskmap.py --force`.
4. **Consumer wiring (fail-loud).** `ComponentGraph` fourth-category handling, `mermaid-styles.yaml` + the `componentsTools` style, table/SVG regeneration, persona ownership of Tools, and tests — including a real-corpus guard so an unstyled or owner-less category fails CI rather than rendering silently.
5. **Content re-mapping (content-review).** Control/risk re-maps for the consent split and the recategorizations: dual-map then refine. The agent consent-fatigue risk/control is authored here.

The **representation ADR (D10)** is a separate, later track, not a stage of this migration; the interim edge mis-render persists until it lands.
