# ADR-030: Agentic component model — model-access boundary, enforcement-point individuation, and the external tools tier

**Status:** Draft
**Date:** 2026-07-29
**Revision:** v2 — replaces ADR-030 v1 (2026-06-30) in place, under the same number and the same decision numbering
**Authors:** Architect agent, with maintainer review

---

## Context

The CoSAI Risk Map component graph (`risk-map/yaml/components.yaml`, governed by `risk-map/schemas/components.schema.json` and [ADR-018](018-components-schema.md)) was built before the framework had to model agentic systems with first-class tool use. Working through [MCP (Model Context Protocol) security guidance](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/7ec1306f2f55563f6eeef9d36a6bb2b531491ceb/model-context-protocol-security.md) — the CoSAI Workstream 4 (secure-design-for-agentic-systems) paper, pinned at commit `7ec1306` so the reference survives a repo reorganization — surfaced a cluster of structural gaps where risks and controls had no component to attach to: identity and access had no home; there was no first-class consent surface; no grouping for external tools; no explicit isolation/containment modeling; no policy-point set; no durable audit-record locus; and no rule governing which paths may reach the model artifact. Several of these recur across many risks and controls, which is the signal that the *framework shape*, not any single entry, is what needs deciding.

This record decides that shape. The central move is a **reachability boundary around the model artifact** (D11): once the artifact is reachable only through serving, serving becomes the place where model-tier ingress is enforced (D12), the tier input/output handlers that previously wired straight into the artifact are severed, and the deployment substrate has to be re-partitioned around what actually hosts what (D6, D12). The tool tier (D1, D14), the identity grouping (D2), and the remaining component decisions are the same discipline applied at the other boundaries.

Two general rules do most of the work and are stated once, then applied:

- **Individuation by operator authority** (D4) — a distinct enforcement component exists for each authority whose reviewed policy is enforced; a shared resource under one authority stays one component.
- **Individuation by code ownership** (D6) — hosting substrates divide on whether the hosted code is the system's own or a third party's, because that is what changes the isolation design.

**Scope boundary — shape, not representation.** This ADR decides the component *taxonomy* (categories, subcategories, the component set) and lands each component together with its edges as `{to, from}` *mappings*. It does **not** decide graphical *representation*: how an edge is typed (`kind`), how directionality is shown, how a control-intermediated flow is drawn, or whether an overview graph is a subset of per-category detail graphs. Those are routed to a separate representation ADR (D10), gated on a survey of graphical-mapping approaches, because how the model is *drawn* is a distinct problem from where components live and what connects to what.

This is the highest-blast-radius change the component taxonomy has taken. It trips multiple [ADR-018](018-components-schema.md) closed-enum surfaces at once: `category.id`, `subcategory.id`, and `component.id` are all closed enums, and the `allOf` category→subcategory consistency block constrains which subcategories nest under which category. Per [ADR-018](018-components-schema.md) D2 those enums are deliberately closed so every consumer — the validator, the Mermaid generators, the table generator — sees the same taxonomy at once; the documented cost is that a taxonomy change is a schema edit.

The component edge model carries only `{to, from}` data-flow arrays (per [ADR-018](018-components-schema.md) D3); `ComponentEdgeValidator` checks bidirectional *consistency, not semantics*. Some relationships here are not data-flow — a policy point is *consulted* for a verdict, a workload is *contained* in an isolation boundary. They land as plain `{to, from}` mappings anyway (D9).

Content semantics — the risk taxonomy, the persona model, the per-component descriptions and mappings — are framework-content design and belong in `risk-map/docs/design/` and the content-review workflow, not here.

## Decision

We adopt the component model described by D1–D17. Landing mechanics — the atomic schema-plus-YAML unit, the layer sequence, and the interim absence of control coverage — are governed by [ADR-034](034-corpus-change-landing-sequence.md) and are not restated here.

**Reading order.** The decisions are numbered in the order they were made, not in the order they are best read. The table below is the reading path; the sections that follow it stay in numeric order so a citation resolves by scanning down.

*The five in bold are the rules. The rest are either their consequences or the taxonomy they operate on.*

| Read | Decision | Settles |
|---|---|---|
| 1 | **D11** | The model artifact is reachable only by training and by serving — the boundary most of the rest follows from |
| 2 | D12 | Serving is therefore the model tier's enforcement point |
| 3 | D13 | Confinement reaches serving through the hosting substrate, not directly |
| 4 | **D4** | Operator authority individuates enforcement components; shared resources stay whole |
| 5 | **D6** | Code ownership individuates hosting substrates |
| 6 | D1 | The external-tools tier and its two subcategories |
| 7 | D2 | The identity subcategory; the identity provider as information point; no administration point |
| 8 | D3 | The deployment subcategory's retitle and id rename |
| 9 | **D14** | No data path reaches the tool zone except through the tool network enforcement point |
| 10 | D7 | The tool-boundary I/O-handling layer |
| 11 | D8 | Tool-call re-anchoring and the reasoning-core decouple |
| 12 | D5 | Two consent surfaces |
| 13 | D15 | The audit record repository as a distinct storage locus |
| 14 | D9 | Consult and containment edges land as mappings; typing deferred |
| 15 | **D17** | Borrowed authority individuates a cross-domain intermediary from the authority it speaks for |
| 16 | D10 | What this record defers |
| 17 | D16 | How to read this model's zero control coverage |

### D1. New top-level `componentsExternalTools` category with two subcategories

A new **top-level** category `componentsExternalTools`, a fourth peer of `componentsInfrastructure`, `componentsModel`, and `componentsApplication`, collects the tool and tool-authorization components: the existing `componentTools` (recategorized out of `componentsModel`) together with the tool components this model introduces. Top-level because tools are an **external trust domain** — third-party services the AI system integrates with but does not own — distinct in kind from the system's own infrastructure, model, and application tiers. It carries two subcategories, divided by layer:

- **`componentsToolNetworkControls`** (connection-layer enforcement, wrapping the invocation path) — `componentToolNetworkPolicyEnforcementPoint`.
- **`componentsToolInvocationPath`** (the request path itself and the capabilities the tool server exposes) — `componentToolServer`, `componentTools`, `componentToolInputHandling`, `componentToolOutputHandling`, `componentAuthorizationPolicyEnforcementPoint`.

One placement is decided against the alternative of putting it in the network-controls subcategory:

- **`componentAuthorizationPolicyEnforcementPoint` is on the invocation path**, not in the network controls. It stands *in flow*: invocations reach it from `componentToolInputHandling` once their content has been validated, and it forwards them to `componentToolServer` or blocks them. It does not hand a verdict back for another component to apply, and it does not govern the connection — the network-controls subcategory is the connection layer.

**The three tool-server primitives do not each earn a node.** A tool server exposes executable tools, retrievable resources, and prompt templates. A component is earned by a distinct locus, not by a distinct payload class, and the three fail at two loci: a poisoned tool causes a wrong action and a poisoned resource returns wrong data, both failures of the capability the agent operates on, while a poisoned prompt template is the server steering the model, which is a failure of what the server advertises. So `componentTools` (titled *External Tool Capabilities*) covers the executable and the retrievable, and the instruction-shaped template belongs to `componentToolServer`, which already owns advertisement, discovery, and per-connection capability negotiation. The Alternatives section records the two candidate components this displaced.

`componentAgentToolTransport` is **not** in this category: it lives in `componentsAgent`, as the agent-side channel that carries the connection to the tool provider's boundary. `componentFederationProxy` is **not** in it either: it is an identity-plane intermediary (D2, D17), reachable at the tool boundary as a control-plane peer without being a member of the tool zone.

Registries (`componentModelRegistry`, `componentToolRegistry`) stay in Infrastructure — they are not tools.

Schema impact: `category.id` gains `componentsExternalTools`; `subcategory.id` gains `componentsToolNetworkControls` and `componentsToolInvocationPath`; a fourth `allOf` branch permits exactly those two subcategories under the new category; the file-level `categories:` block gains the category and its subcategories.

### D2. New `componentsIdentity` subcategory under Infrastructure

`componentIdentityProvider`, `componentAuthorizationPolicyDecisionPoint` and `componentFederationProxy` land in a new `componentsIdentity` subcategory under `componentsInfrastructure`, giving identity its own home rather than scattering it across Infrastructure. The first two are authorities; the third speaks with borrowed authority and is admitted on D17's rule, which is why the subcategory describes the identity *plane* rather than only its trust roots.

Two role assignments come with it:

- **The identity provider fills the policy-information-point role for subject attributes.** In ABAC terms the policy information point is the retrieval source for all data a policy evaluation requires (NIST SP 800-162 §2.4.3), which includes object attributes and environment conditions as well as subject ones. This model's identity provider covers the subject-identity and subject-attribute share; it introduces no separate policy information point, and object attributes and environment conditions have no component home. That is a narrower gap than the policy administration point above but the same kind, and [#467](https://github.com/cosai-oasis/secure-ai-tooling/issues/467) covers both.
- **The model introduces no policy administration point.** This is a decision, not an oversight: the policy-authoring surface is upstream of every component modeled here, and no risk or control in scope attaches to it. The consequence is real — policy-administration risks (unauthorized policy edit, policy rollback, unreviewed policy promotion) have no component home. Both absences are recorded at [#467](https://github.com/cosai-oasis/secure-ai-tooling/issues/467), closed as deferred: it states the reasoning, the resolutions available, and the criteria that would reopen it, so the decision does not lapse into an accident of what nobody wrote down.

Schema impact: `subcategory.id` gains `componentsIdentity`; the Infrastructure `allOf` branch gains it, alongside `componentsRegistries`.

### D3. `componentsDeployment` — subcategory retitle *and* id rename

The deployment subcategory is retitled from "Model Deployment" to "Deployment" and its id is renamed `componentsModelDeployment` → `componentsDeployment`. It holds the hosting and storage substrates — `componentToolHosting`, `componentRuntimeHosting`, `componentIsolationRuntime`, `componentModelStorage`, `componentAuditRecordRepository` — not only model-related ones, which is what the old name implied.

The substrates are what live here; the workloads they host do not. `componentModelServing` in particular is **not** in this subcategory — D12 places it in `componentsModel`/`componentsModelCore` with the artifact it serves, and its relationship to the substrate is carried by an edge from `componentRuntimeHosting`, not by co-location.

**The id rename is required, not cosmetic, and it is an enum change.** `ComponentGraph` derives *nested subgraph labels from the subcategory id, not from its `title`*: `_load_category_names` reads only top-level `categories[].title`, so a subcategory always falls through to the id-derived display name. The regenerated diagram renders `subgraph componentsDeployment ["Deployment"]`. Leaving the id as `componentsModelDeployment` would have rendered "Model Deployment" indefinitely and defeated the retitle.

Schema impact: `subcategory.id` and the Infrastructure `allOf` branch both carry the new id. Every component previously in `componentsModelDeployment` is re-pointed in the same content unit, per [ADR-034](034-corpus-change-landing-sequence.md).

### D4. Operator authority individuates enforcement components; shared resources stay whole

**A distinct enforcement component exists for each authority whose reviewed policy it enforces. A resource shared under a single authority stays one component.**

Three network policy enforcement points follow from the first half:

- `componentAgentNetworkPolicyEnforcementPoint` (`componentsAgent`) — the agent operator's egress policy. Carries the agent's tool-call traffic and its model-serving traffic, and peers with the application's enforcement point for handoff traffic.
- `componentApplicationNetworkPolicyEnforcementPoint` (`componentsApplicationCore`) — the application operator's egress policy. Its basis is operator authority and nothing else: it and its agent-side sibling enforce the same class of egress policy for different authorities. The application is operated by the application developer/operator; the agent is operated separately, typically by an agentic platform or framework provider. Routing the application's traffic through the agent's enforcement point would place one operator's egress under another operator's reviewed policy.
- `componentToolNetworkPolicyEnforcementPoint` (`componentsToolNetworkControls`) — the tool provider's ingress policy, at the far end of the same connection the agent-side point governs. `componentAgentToolTransport` carries the wire between them.

`componentAuthorizationPolicyEnforcementPoint` is a fourth enforcement component on a different axis: it enforces *whether an action is permitted*, not *how and to where traffic may flow* (D1, D12).

The second half of the rule is what keeps the model from sprawling:

- **Serving** absorbs model-tier ingress enforcement rather than growing a fourth network node, because no second authority is present (D12).
- **Orchestration** has no enforcement point at all. It is the served model's own machinery under the same authority as serving, so serving's ingress enforcement is what stands between orchestration and every external caller.
- **`componentAuditRecordRepository`** is one substrate written by many components (D15), not one repository per writer, because the writers do not each own a distinct retention authority.
- **`componentRuntimeHosting`** is not bisected by operator authority even though it hosts workloads run by different operators (D6).

**Deferral clause.** Where a would-be second enforcement locus differs only in required control *strength* rather than in the authority whose policy is enforced, it is a workload attribute, not a component — the same deferral D6 applies to the autonomy attribute (D10).

Schema impact: the `component.id` enum gains the three network enforcement-point ids and the authorization enforcement-point id.

### D5. Two consent surfaces

The model introduces **two** consent surfaces: `componentApplicationConsentSurface` (`componentsApplicationCore`) and `componentAgentConsentSurface` (`componentsAgent`). This is **not** a caller-duplicate of one capability.

**The split rests on locus.** An application approval flow interrupts a user who is already engaged with the application and holds the context the decision needs; an agent elicitation is raised mid-loop, on the agent's initiative, to a user who may not be present and did not ask the question. Those are two places a decision is taken, under two operators' authorities, which is the same individuation D4 applies to enforcement.

**Autonomy is the consequence, not the basis.** Because the agent surface is the one raised mid-loop, it carries a distinct *risk kind* — consent fatigue and habituation, in which high-volume confirmations train rubber-stamping and so defeat consent for the rare irreversible action — plus distinct controls (risk-tiering, reserve-for-irreversible). Stating it this way is what keeps this decision consistent with D6, where autonomy is a deferred workload attribute rather than a component-individuating one (D10): the mapping delta is evidence the loci differ, not the reason they do.

Schema impact: the `component.id` enum gains the two consent-surface ids; any control or risk mapping written against a single consent surface is dual-mapped onto both, then refined.

### D6. Code ownership individuates hosting substrates

Hosting substrates divide on **whether the hosted code is code the system owns**, because that is what changes the isolation design:

- **`componentToolHosting`** runs third-party tool backends and plugin implementations. The system did not write that code and cannot vouch for it, so the isolation goal is written against an unknown party submitting code the system does not control; arbitrary-code-execution containment is first-order.
- **`componentRuntimeHosting`** is self-hosting. Its isolation constrains adversarial inputs and mistakes arising through non-determinism in code the system *does* own.

Two different isolation elements with different designs is what earns two components rather than one hosting substrate.

**`componentRuntimeHosting` stays whole.** It carries three hosted workloads — `componentApplication`, `componentReasoningCore`, and `componentModelServing` — and they share one hosting control set: applications and agents both carry non-determinism risk, so there is no application-versus-agent control delta to split on. The fold rests on that shared control set, not on the deferred autonomy attribute.

Two further points make the fold precise:

- **One component shape is not one instance.** Modeling application and agent execution as a single component does not assert that they run in the same instance of it. The component is a reusable substrate in that space; deployment topology is not what the component set records.
- **Operator authority does not bisect hosting.** The individuation rule of D4 is about the authority whose *policy is enforced at a boundary*, and a hosting substrate enforces no such policy — the confinement it runs inside does (D13), and the egress policy its tenants cross is enforced at their own enforcement points. A bisect would also not be a bisect: with three tenants, splitting application from agent leaves `componentModelServing` unassigned to either half.

The autonomy/workload difference that would otherwise separate an application workload from a higher-autonomy agent workload remains a deferred component attribute (D10), not a second node.

Schema impact: the `component.id` enum gains `componentToolHosting` and `componentRuntimeHosting`. `componentModelServing` keeps its id and moves categories (D12).

### D7. Dedicated tool I/O-handling layer

`componentToolInputHandling` and `componentToolOutputHandling` are the **fourth** instance of the in-flow handling pattern the corpus models at the application, orchestration, and agent boundaries. They sit at the tool-server boundary, between connection-layer admission and action authorization on the way in (both D4), and at the server's egress on the way out. Their defining threats — argument injection and coerced invocations inbound, tool-response poisoning and output injection outbound — are tool-boundary threats distinct from orchestration-context filtering. Keeping them separate from the tool server preserves the validation-locus / action-locus distinction the handling pattern depends on. Both land in `componentsToolInvocationPath` (D1).

### D8. Tool-call re-anchoring and the reasoning-core / orchestration decouple

Two intentional rewires of the edge set, recorded because a reader of the diff alone would not recognize them as deliberate:

- **Tool invocation is agent-exclusive.** No application node reaches the tool server; the application does not invoke tools directly, only the agent does. Application-to-agent handoff crosses the two operators' enforcement points as peers (D4). This shifts the Application persona's risk surface.
- **The reasoning core is decoupled from orchestration.** Every path by which content reaches or leaves `componentReasoningCore` runs through `componentAgentInputHandling` or `componentAgentOutputHandling`; the orchestration subgraph — memory, RAG, orchestration I/O handling — is reachable through the model-serving path, not wired straight into the reasoning core. The claim is about the content path, not the whole edge set: the reasoning core also carries an inbound edge from the substrate that executes it (`componentRuntimeHosting`, D6) and an outbound write to `componentAuditRecordRepository` (D15), neither of which carries content it acts on.

Both realize one control-boundary principle: the reasoning core acts only through the agent's own input and output handling, so every influence on it — tool results, retrieved context, memory, tool metadata returned by a remote server — arrives through a gate it does not control directly.

### D9. Consult and containment edges land as mappings; typing and rendering deferred

The relationships below are not data-flow, but they land as plain `{to, from}` mappings so their owning components are not isolated; their correct typing and rendering are deferred to the representation ADR (D10).

**Consult** (a policy point is queried; a verdict or attribute returns):

- `componentIdentityProvider → componentAuthorizationPolicyDecisionPoint` — the identity provider serves identity attributes to the decision point (D2).
- `componentAuthorizationPolicyDecisionPoint →` each network enforcement point, the authorization enforcement point, and `componentModelServing` — a decision source for every enforcement locus (D4, D12). An enforcement point without a decision source is inert.
- `componentIdentityProvider →` each network enforcement point and `componentModelServing` — token and attribute context for connection admission.
- `componentIdentityProvider → componentFederationProxy`, and `componentFederationProxy →` the agent and tool network enforcement points — the proxy relies on the upstream authority and is in turn relied on at both ends of the tool connection, which is D17's borrowed-authority shape as edges.
- `componentToolRegistry → componentAgentNetworkPolicyEnforcementPoint` — the enumerated-endpoint consult, on the caller's side of the boundary (D14).

**Containment** (the target runs *inside* the boundary): `componentIsolationRuntime → componentToolHosting` and `componentIsolationRuntime → componentRuntimeHosting`, and those two only. The rule that fixes this set is D13.

These edges are mechanically valid — bidirectional consistency holds — but semantically mis-rendered by a generator that has no notion of edge kind. That is the interim cost the representation ADR (D10) resolves. The alternative, landing the identity and isolation components without edges, trips the isolated-component check and strands them.

### D10. Deferred follow-ons — a graphical representation ADR, and an autonomy/workload attribute

Two separate deferrals, neither decided here:

- **Graphical representation (a future ADR).** A typed edge `kind` (`data` / `consult` / `contains`) plus renderer support; how to show inbound and outbound flow through a single enforcement point; how to draw a control-intermediated full flow; and whether the overview graph is a subset of per-category detail graphs. These are a distinct problem from component shape and are gated on a survey of independent graphical-mapping approaches before an ADR is authored.
- **An autonomy/workload realization attribute.** A component attribute that re-encodes the application-versus-agent distinction `componentRuntimeHosting` folds (D6). This is a modeling primitive, not a representation concern, and is parked as its own follow-on rather than bundled into the representation ADR.

**An illustrative shape, so the deferral is inspectable rather than abstract.** The following is *not* a decision and does not bind the representation ADR — it is recorded because a deferral stated only in the abstract is one a later reader cannot evaluate, and because D9 and D14 both leave consult edges riding data-flow `to`/`from` where they render as data-flow arrows. Two optional keys nested under `edges:`, alongside `to` and `from`, so every relation stays in one place:

```yaml
- id: componentAuthorizationPolicyDecisionPoint
  edges:
    to: [...]              # data flow, unchanged
    from: [...]
    reliesOn:              # optional — authorities whose answers this component depends on
      - componentIdentityProvider
    relyingParties:        # optional — components that depend on this component's answers
      - componentAuthorizationPolicyEnforcementPoint
      - componentToolNetworkPolicyEnforcementPoint
      - componentAgentNetworkPolicyEnforcementPoint
      - componentApplicationNetworkPolicyEnforcementPoint
      - componentModelServing
```

Four properties of the sketch are worth stating, because each is a place a reader could reasonably guess wrong:

- **Both keys are available to any component; neither is reserved to a class of them.** The example is the policy decision point precisely because it carries both: it is a relying party of the identity provider and an authority to five enforcement points. A rule assigning `relyingParties` to decision points, identity providers and registries and `reliesOn` to everything else would be falsified by the first component in the model. `componentFederationProxy`'s description already states this dual shape in prose — "a relying party toward the upstream identity provider and an identity provider" downstream.
- **Classification is per-edge, not per-component.** Not every edge leaving an authority is a consult: `componentModelRegistry → componentModelStorage` is a pointer relation, and storage does not consult the registry. A migration that retyped every edge out of a registry would mis-type it.
- **The pair is reciprocal, on the same rule `to`/`from` already follow.** `A.reliesOn` contains B if and only if `B.relyingParties` contains A. This doubles the reciprocal-edit burden [ADR-034](034-corpus-change-landing-sequence.md) D2a/D2b describes, and the existing bidirectionality validator would extend to cover it.
- **`reliesOn` is trust reliance, not a build dependency.** It is deliberately not `dependsOn`, which names software dependency relationships in SBOM formats (CycloneDX, SPDX). The relation here is that one component depends on another's *assertion* to make a decision.

*Relying party* is a term of art, not a coinage: a system entity that acts on assertions it receives from an authority — the asserting party in SAML, the OpenID Provider in OIDC. [NIST SP 800-53](https://doi.org/10.6028/NIST.SP.800-53r5) Rev. 5 IA-4(8) pairs it with an identity provider in exactly this sense. Its international equivalents are recorded through the classical-lexicon skill rather than restated here, per [ADR-031](031-authoring-time-agents-and-skills.md) D3b.

Landing this shape is a schema change plus a migration, not an additive edit: roughly a dozen edges currently expressed as `to`/`from` would reclassify, and they overlap the corpus text D14 already owes.

### D11. The model artifact is reachable only by training and by serving

`componentTheModel` carries exactly four edges: `to: [componentModelEvaluation, componentModelServing]`, `from: [componentModelTrainingTuning, componentModelServing]`. Every path that reaches the model artifact is therefore either a training-tier path (training produces it; evaluation consumes it, both in `componentsModelTraining`) or a serving path. At runtime, serving is the sole toucher.

This severs four classes of edge the model previously carried directly:

- the agent, application, and orchestration input handlers no longer receive from the artifact;
- the corresponding output handlers no longer feed it;
- model storage and the model registry reach `componentModelServing` rather than the artifact;
- no consumer tier reaches the artifact at all.

The rule is what the rest of the model tier follows from. If the artifact has exactly one runtime door, that door is where model-tier ingress is enforced (D12); the consumer tiers reach it through their own egress enforcement (D4); and the substrate that runs that door is a hosting question, not a model question (D6).

### D12. Model serving is the model tier's enforcement point

`componentModelServing` is titled **"Model Serving Infrastructure & Policy Enforcement Point"** and lives in `componentsModel` / `componentsModelCore`, not in the infrastructure deployment subcategory. Its id is unchanged.

Three things follow from D11 and are decided here:

- **Placement.** Serving is the inference-time locus that touches the model artifact directly. It belongs with the artifact it serves rather than with the substrate underneath it; the substrate relationship is carried by an edge from `componentRuntimeHosting` (D6), not by co-location.
- **Enforcement role.** Because serving is the artifact's only runtime door, it is where the model tier's ingress policy is enforced. It consults `componentIdentityProvider` and `componentAuthorizationPolicyDecisionPoint` as control-plane peers, and consults `componentModelRegistry` for which model version and endpoint a request resolves to — the model-tier parallel of the registry consult `componentAgentNetworkPolicyEnforcementPoint` performs against `componentToolRegistry` before an outbound tool call (D14).
- **No separate model-tier enforcement node.** The enforcement role folds into serving rather than standing beside it as a fourth network enforcement point, because the party that operates serving is the party whose ingress policy is enforced. There is no second authority to individuate against (D4).

**The layered enforcement-point split is this model's own refinement, not something the cited standards supply.** NIST SP 800-207 §3 describes a policy enforcement point as the system "responsible for enabling, monitoring, and eventually terminating connections between a subject and an enterprise resource." NIST SP 800-162 §2.4.3 describes a policy enforcement point that "enforces policy decisions in response to a request from a subject," with the decision made by a policy decision point and returned to it.

Neither standard divides the enforcement role by *function*. SP 800-207 does describe a PEP "divided into two components" (§3.2.1) and traffic passing "through one or more PEPs" (§3.4.1), but that division is client-side and resource-side along a single connection, both performing connection admission — not a network-admission point in front of a separate action-authorization point. SP 800-162 describes a single enforcement point and no serial arrangement at all. On the consulting relationship: SP 800-207 is explicit that "the PEP is the only component that accesses the policy administrator as part of a business flow" (§3.4.1), while SP 800-162 permits an optional context handler to mediate the exchange (§2.4.3), so the enforcement point is not necessarily the consulting party there.

This model splits the role by layer — connection admission at layer 4, action authorization at layer 7 — because the two attract different control sets and different failure modes. The standards are cited for the enforcement-point concept each supplies: SP 800-207 for connection-level enforcement between a subject and a resource (D4), SP 800-162 for the decision/enforcement separation behind `componentAuthorizationPolicyEnforcementPoint`. Neither standard confines itself to one layer — SP 800-207 places its most common PEP deployment at layer 7 (§3.1.3) and SP 800-162 admits networks as objects (§2.2) — so the assignment of each citation to a layer, as well as the composition of the two, is ours.

### D13. Confinement is transitive through the hosting substrate

`componentIsolationRuntime` owns the boundary; the hosting substrates are the workloads that execute inside it. Its containment edges therefore reach `componentToolHosting` and `componentRuntimeHosting`, and nothing else.

**There is deliberately no `componentIsolationRuntime → componentModelServing` edge.** Serving is one of runtime hosting's three hosted workloads (D6), and runtime hosting runs inside the confinement, so serving's confinement is transitive. This is consistent with the other two workloads: `componentApplication` and `componentReasoningCore` likewise carry no direct isolation edge. A direct edge to serving alone would assert that serving is confined by a different mechanism than its two peer tenants, which is not what the model means.

### D14. No data path reaches the tool zone except through the tool network enforcement point

**No data path reaches the tool zone that does not traverse `componentToolNetworkPolicyEnforcementPoint`.** A path that bypasses it is a network-control bypass regardless of what it carries. The rule is scoped to data paths deliberately — control-plane consults and the hosting substrate also reach into the zone, by decision, and are treated below.

Two consequences are deliberate edge *removals* relative to the prior component graph, and are recorded here because a reader of the diff alone would not recognize them as decisions:

- **`componentToolRegistry → componentTools` is removed.** Registry data reaches the tool zone through the enforcement point, which consults the registry as a control-plane peer to admit a connection only to an endpoint the registry enumerates. The registry does not reach the tools directly.
- **`componentToolRegistry → componentOrchestrationInputHandling` is removed.** Discovery is not exempt: a discovery path that hands registry contents straight into orchestration is a bypass of the same control. Reasoning-time tool selection draws on registry data indirectly, through what the served model already knows about available tools; registry consultation itself sits at the network admission decision.

The registry retains two edges: the consult decided below, and `componentTools → componentToolRegistry`, the publication path by which a tool server's metadata enters the catalog. That second edge originates *inside* the tool zone and is not a path into it, so this rule does not reach it.

**Resolved — the consult is the caller's, and it lands on the agent enforcement point.** The tool-side enforcement point's description claimed it admits connections only to endpoints the registry enumerates. That cannot be right: D4 makes `componentToolNetworkPolicyEnforcementPoint` *the tool provider's* ingress policy, and `componentToolRegistry` is the AI system's own catalog. A remote provider does not consult the caller's catalog to decide whether to admit the caller. The vocabulary confirms it — the tool-side point enforces allowed **sources**, the registry supplies endpoints the system is permitted **to reach**, which is an allowed-destination list.

The edge therefore runs `componentToolRegistry → componentAgentNetworkPolicyEnforcementPoint`, joining the identity provider and policy decision point that node already consults, and the tool-side point keeps its own allowed-source policy. The decision point is *not* the destination: the enumerated-endpoint check is a connection-admission decision, and routing it through the decision point would separate it from the two control-plane peers it belongs with.

**This is not a policy information point in disguise.** A registry supplying object attributes at decision time would be the non-subject-attribute gap D2 records and [#467](https://github.com/cosai-oasis/secure-ai-tooling/issues/467) tracks. It is not: the consult resolves an admission decision at the connection, not an attribute for a policy evaluation.

**Consistency with D9.** D9 licenses `componentAuthorizationPolicyDecisionPoint → componentAuthorizationPolicyEnforcementPoint`, and the authorization enforcement point sits inside `componentsExternalTools` (D1) — so a control-plane verdict already informs the tool zone without traversing the network enforcement point, as does `componentToolHosting → componentToolServer`. **This rule governs the data path.** Control-plane consults and the hosting substrate are not paths by which content enters the zone, and stating the rule as absolute overstated it. The corpus text D10's sketch would retype is exactly this set.

**Corpus text this rule changes.** `componentTools`' description characterized the registry as the discovery layer "agents query". Under this rule that query traverses the enforcement point. The re-pointed sentence is carried by the component landing change ([#462](https://github.com/cosai-oasis/secure-ai-tooling/issues/462)), which lands after this record; it is a description edit, not a change to any decision here.

**How this reads once edges are typed.** The registry consult this rule creates is one of the edges D10's illustrative sketch retypes: it is a `reliesOn` relation from an enforcement point to an authority, not a data flow, and it renders as a data-flow arrow only because no edge kind exists yet. A reader meeting the misleading arrow here should follow it to D10.

### D15. `componentAuditRecordRepository` is a distinct storage locus

`componentAuditRecordRepository` (`componentsInfrastructure` / `componentsDeployment`) is the durable, tamper-evident storage substrate that other components write logs and audit records to.

**The name is the classical one.** NIST SP 800-53 calls this an *audit record repository* (AU-6(3)). A practice-shaped name attracts practice-shaped controls — "centralize your logs" — and centralization is not a control. The classical name makes such a control visibly out of family.

**The classical grounding, stated once here and cited rather than restated elsewhere.** The separation this component rests on is recorded in SP 800-53 as enhancements to AU-9, *Protection of Audit Information*: store audit records "in a repository that is part of a physically different system or system component than the system or component being audited" (AU-9(2)); authorize access to *management of the audit logging functionality* to a subset of privileged users (AU-9(4)); enforce dual authorization for movement or deletion of audit information (AU-9(5)); authorize read-only access to audit information (AU-9(6)); store audit information on a component running a different operating system (AU-9(7)).

Those enhancements are the grounding, **not** the family-level reading that the AU family assigns generation to emitters and protection to the medium. SP 800-53 does not partition obligations by architectural locus at all — every AU control is addressed to the organization or the system — and AU-9's own statement extends protection to "audit information **and audit logging tools**", which are emitter-side. A reader who checks will find that, so the record should not claim otherwise.

**Where this model departs from SP 800-53, deliberately.** AU-9(2) and AU-9(7) answer the independence question **topologically** — a different physical system, a different operating system. This model generalizes to the **control plane**: what must be separated is the authority that administers the store from the authority that operates the recorded workload, which a distinct account or tenancy can achieve without physical separation. The generalization is ours and is not what the standard says.

It also carries a residual the topological answer does not. Where a store is co-located with the workload it records, an adversary at host or hypervisor privilege holds the medium however the logical control plane is partitioned; AU-9(2) and AU-9(7) exist precisely for that case. Control-plane separation is therefore the general property, and topological separation the stronger form of it where the threat model reaches host privilege.

It is deliberately **not** aligned to a policy information point. A policy information point is consulted at decision time to supply attributes for an authorization decision; this node is written after the fact and read during investigation, and it supplies nothing to any decision — its `edges.to` is empty by design. The two differ in what fails: a corrupted decision input versus destroyed evidence. D2 records that this model introduces no separate policy information point, and this node does not become one.

**Altitude two-test.** *Absorb-into-existing fails:* no component covers durable, tamper-resistant record storage. `componentDataStorage` and `componentModelStorage` persist training data and model artifacts respectively, not the runtime record of what the system did. *Reader-instructive passes:* it carries the write-once/append-only integrity control set (WORM-style storage, hash-chained or Merkle-linked audit trails) and tells a reader that every detective control depending on record integrity for evidentiary value depends on this node.

It is the storage locus, not the practice of using it.

**What would unmake this decision.** The obligations that earn the node are the ones with no emitter to attach to: tamper-evident retention with external checkpointing and independent verification, separation of write from read and delete credentials, and an administrative plane outside the recorded workload's trust domain. An emitter cannot make its own records tamper-evident against itself, which is why security logging is deployed out of band from the workload it records. The test this decision should be held to is therefore concrete: **at least one control must list this component and state an obligation that could not have been stated on any emitter.** If the control layer produces only emission obligations — what to log, at which component — then the node is carrying edges and no obligations, and the correct response is to reconsider it rather than to stretch the requirements to fit. Components land ahead of their controls (D16), so this condition is recorded here and settled there.

**One component is not one store.** This node is a single *component shape*, not a claim that every writer's records land in one instance under one authority. A deployment will normally have several — the records a model-serving operator retains are not the records an agent's operator retains, and they answer to different retention, access, and jurisdictional rules. The model does not represent that fan-out, for the same reason D4 does not individuate shared resources by authority: what earns a node here is the integrity property, and that property is identical wherever the substrate is instantiated. A per-authority split would multiply the node without changing what any control attached to it says. Centralized and decentralized deployments both satisfy it.

Its `edges.to` is empty by design: it is a terminal sink, and no log-consumer component is modeled. It is not isolated in the validator's sense, because it carries `from` edges from every writer.

### D16. This model's components land ahead of their control coverage

Landing mechanics are [ADR-034](034-corpus-change-landing-sequence.md)'s: it decides that a layer introducing a new entity bundles its schema id-enum edit with its `*.yaml` entry as a single content unit, and that components land in Layer 1 with their edges. This record does not restate those rules; it elects to use the allowance they create, and states how the resulting interim state should be read.

**Every net-new component in this model carries zero controls, and that is the landing sequence working as designed, not a coverage gap.** Control and risk coverage arrives in [ADR-034](034-corpus-change-landing-sequence.md) Layers 4–5. Two facts make the interim state precisely readable:

- **Risks carry no `components` field at all.** `risks.schema.json` defines no such property; a risk reaches a component only through a control's `components`/`risks` pair. So component coverage is a controls-side question exclusively.
- **The null is uniform.** No control references *any* net-new component in this model, while the components already in the corpus retain their existing control references. A zero-coverage reading therefore says nothing about any individual new node — it is a property of the layer, not evidence about a component's justification.

Per [ADR-034](034-corpus-change-landing-sequence.md) D3 and D3a, a new component lands validator-green provided it carries at least one bidirectional component edge, and unreferenced components are a deliberate allowance. Every component here carries edges.

### D17. Borrowed authority individuates a cross-domain intermediary from the authority it speaks for

**A component that carries a principal's authority across a trust-domain boundary is individuated from the authority that originated it.** The reason is a failure mode, not a role name: an intermediary speaking for a principal other than itself can bind a request to the wrong principal's authorization context — the confused deputy — and a component that originates its own credentials structurally cannot make that error. Where the two are folded together, confused-deputy guidance lands on a component that cannot exhibit the failure.

This is the third individuation rule. D4 divides enforcement components by operator authority; D6 divides hosting substrates by code ownership; D17 divides the identity plane by whether authority is originated or borrowed. `componentFederationProxy` is its only instance in this model: a relying party toward the upstream identity provider and an identity provider toward the downstream tool, per SP 800-63's federation-proxy definition. `componentIdentityProvider` originates credentials for principals it has authenticated within its own domain; the proxy re-asserts that authority into another.

Two consequences are decided here rather than left implicit:

- **Placement is the identity plane.** The proxy mediates identity, so it belongs with identity (D2). It is not a tool-zone component: it stands out of flow, and the external-tools subcategory axis is layer — connection versus invocation path (D1) — which has no place for a component that sits on neither. The authority it carries is not the tool provider's either, so D4 does not reach it there.
- **The identity subcategory admits non-authorities.** Most of its members are authorities — the trust root other components ground their decisions in — but membership is the identity *plane*, not authority. A component that speaks with borrowed authority carries a different threat model, and that is what earns it a place rather than what disqualifies it.

**Why the corpus does not model the second trust domain.** A federation proxy bridges two identity domains, and only one identity authority appears in the corpus. That is not a gap: `componentIdentityProvider` is the authoritative source of identity *for a deployment*, and the corpus models component shapes rather than instances throughout (D6, D15). The second domain is another instance of the same shape, no more absent than the second hosting substrate. What the proxy mediates between is instances, which is why no second component is owed.

**Scope guard.** The rule is narrow by construction: it requires a *trust-domain* crossing and *borrowed* authority. It does not admit a component that merely forwards, carries, or terminates a connection — `componentAgentToolTransport` carries the wire without re-asserting anything, and the network enforcement points present a credential without minting or binding it. A future broker between instances of another shape — a registry federation, for instance — would be admitted by the same rule, which is the intended behaviour.

## Alternatives Considered

- **Fold the delegation role into `componentIdentityProvider` (D17).** Token exchange is an authorization-server mechanism, so the identity provider is where a reader would first look for it, and one component is cheaper than two. Rejected on the failure mode: an authority that mints credentials for principals it has itself authenticated cannot bind a request to the wrong principal's context, so the confused-deputy and constrained-delegation obligations have no meaning attached to it. Folding would place that guidance on a component structurally incapable of the error it guards against. The split carries a condition: the identity provider's scope is stated as originating and validating within its own domain, and cross-domain re-assertion as the proxy's. Without that boundary the two descriptions overlap on the same mechanism and the fold is the better answer.

- **Leave the model artifact directly reachable by the consumer tiers (D11).** The prior shape wired the agent, application, and orchestration input and output handlers straight into `componentTheModel`. Rejected: it gives the artifact many doors, so there is no locus at which model-tier ingress can be enforced, and it invites controls to attach to the artifact when the enforceable surface is serving. Collapsing to one runtime door is what makes D12 possible.

- **A separate model-tier network enforcement point beside serving (D12).** Rejected: it would be a second enforcement node under the *same* operator authority as serving, which the individuation rule of D4 explicitly does not license. It would also add a node with no distinct control set — the tenant-isolation and access-control posture it would carry is serving's own.

- **One network enforcement point per trust boundary, with the application tier sharing the agent's (D4).** This is the shape the prior revision described: two enforcement points, agent and tool. Rejected: it places the application operator's egress under the agent operator's reviewed policy. The two enforce the same class of policy for different authorities, and authority is the individuating property.

- **Separate enforcement points per direction — agent ingress, agent egress, tool ingress, tool egress (D4).** Rejected on this model's own individuation rule: a second node is earned by a second authority, not by a second traffic direction. Four nodes for two boundaries models direction as topology. SP 800-207 does not address directionality of enforcement at all; it places the enforcement point between a subject and a resource (§3). The per-direction control distinction is real — egress attracts exfiltration prevention and DLP, ingress attracts injection defense and schema validation — but it is expressed through control mapping and the representation ADR (D10), not through extra components. (This is distinct from the client-side/resource-side pair the agent and tool enforcement points form: SP 800-207 §3.2.1 describes exactly that division — "the PEP is divided into two components," a device agent and a resource-side gateway — and §4.4 contemplates "both organizations' PEPs" across a federated boundary. Those are two ends of one connection under two authorities, which the individuation rule does license.)

- **Bisect `componentRuntimeHosting` by operator authority, or split application-serving from agent-hosting (D6).** Rejected on three grounds: hosting enforces no boundary policy, so the D4 rule does not reach it; applications and agents share one hosting control set, so there is no delta to split on; and with three hosted workloads a two-way split leaves `componentModelServing` unassigned. Adding the realization attribute now was also rejected as out of scope — it is the deferred attribute in D10.

- **Fold `componentToolHosting` into `componentRuntimeHosting` or `componentModelServing` (D6).** Rejected: folding into runtime hosting conflates hosting an unknown third party's code with self-hosting; folding into serving conflates it with hosting the system's own trusted inference. The isolation designs differ, which is what earns two components.

- **A direct `componentIsolationRuntime → componentModelServing` containment edge (D13).** Rejected: serving is a hosted workload of `componentRuntimeHosting`, which already runs inside the confinement, so the edge would be redundant — and asymmetric, since the other two hosted workloads carry no such edge. The absence is the model being consistent, not an omission.

- **Keep `componentToolRegistry → componentTools` and `componentToolRegistry → componentOrchestrationInputHandling` (D14).** Rejected: both bypass the tool zone's network control. Discovery is not a privileged path; a discovery edge that reaches into the tool zone or hands registry contents into orchestration is a bypass regardless of its payload.

- **`componentsExternalTools` as a subcategory under an existing tier (D1).** A subcategory would dodge the closed `category` enum edit and the fourth-category rendering work. Rejected: tools are external third-party services, not part of the application the system builds. Nesting under Application because invocation is agent-exclusive (D8) confuses *who calls* with *who owns*. Top-level reflects the external trust boundary.

- **Place `componentAuthorizationPolicyEnforcementPoint` in `componentsToolNetworkControls` (D1).** Rejected: it stands in flow on the request path and governs actions, not connections, and the network-controls subcategory is the connection layer.

- **A distinct `componentExternalPromptTemplate` component (D1).** An earlier revision of this record gave prompt templates their own node on the invocation path, reasoning that a prompt template is provider-supplied data rather than a control and so belongs with the request path it enters on. Rejected: that argument settles *which subcategory* a node would sit in and never tests whether it should exist. The template shares its locus with the server that advertises it — the same endpoint, the same connection, the same negotiation — so the only thing individuating it was its payload class, which is not a locus. Its distinctive failure, a substituted or over-scoped template, is what `componentToolServer`'s over-advertisement threat already describes. The corpus node was withdrawn and the failure stated where it occurs.

- **A distinct retrievable-resources component (D1).** Drafted after the prompt-template withdrawal, on the argument that a resource is read where a tool is invoked, and rejected on the falsification test D15 states: both obligations it claimed already had homes. Read-scope authorization is enumerated verbatim by `componentAuthorizationPolicyEnforcementPoint`, and binding an identifier to the content served under it belongs to the tool server, since the artifact does not resolve its own identifier. `componentTools` was widened to the capability surface instead, which is what makes both the executable and the retrievable readable as one thing an agent operates on.

- **A control-plane / data-plane split of the tool category instead of a layer split (D1).** Rejected: every component in the tool category is in-flow, so none of them is a control plane. The actual control plane — the policy decision point and the identity provider — sits in `componentsInfrastructure` (D2). Layer is the honest axis.

- **Category-direct enforcement-point placement (a layout "sandwich") instead of normal subcategory nesting (D1/D4).** Placing the tool enforcement points directly under `componentsExternalTools` so a diagram renders the inner subgraphs wrapped by the perimeter was rejected as drawing-driven: the enforcement points nest in their subcategories like every other component, and any perimeter depiction is a representation concern for D10.

- **Retitle the deployment subcategory without renaming its id (D3).** Rejected on evidence: subcategory display labels derive from the id, so the retitle would not have taken effect in any generated diagram.

- **One consent surface with edges to both layers (D5).** Rejected because the agent surface carries a distinct risk kind (consent fatigue / habituation) and distinct controls the application surface does not. Had no distinct mapping been demonstrable, the fold would have been correct.

- **A server-initiated-inference component.** A candidate for a component covering server-originated inference requests was assessed and rejected as a component, and reclassified as a risk: the concern is *who may originate work on the model*, which is an authority question about traffic on an existing path rather than a distinct architectural locus. It is authored as a risk through the content process.

- **Type the edges and settle representation now (D9/D10).** Adding a typed edge `kind` would let the consult and containment edges land without mis-rendering. Rejected for this record: it is a renderer plus schema change over an unexplored design space that warrants its own survey. The interim mis-render is accepted because the alternative — landing the identity and isolation components without edges — strands them.

## Consequences

**Positive**

- The model artifact has exactly one runtime door (D11), which gives every model-tier control a single enforceable locus (D12) instead of one per consumer tier.
- Two stated rules (D4, D6) replace ad-hoc per-component argument. Three network enforcement points, one folded model-tier enforcement role, one shared logging substrate, and one whole runtime-hosting substrate are all consequences of the same two rules, and a future candidate can be tested against them rather than debated fresh.
- The structural gaps surfaced by the MCP review get component homes: identity, consent, the policy-point set, an external-tools tier, isolation and containment, and durable audit-record storage.
- The tool zone has one admission control and no bypasses (D14), so a tool-zone control has a complete set of paths to govern.
- The shape/representation split (D9, D10) keeps this record decidable without committing to an unexplored graph-representation design.

**Negative**

- **The schema and YAML must change together as one content unit**, per [ADR-034](034-corpus-change-landing-sequence.md). Three enums, four `allOf` branches, and the `categories:` block change alongside the entries, recategorizations, and edges. This is the [ADR-018](018-components-schema.md) D2 closed-enum cost at its largest.
- **The landing change is large.** The atomic core drives the pre-commit generators to rebuild the tracked diagrams, SVGs, and tables under `risk-map/`, requires a `mermaid-styles.yaml` entry for the new category, and forces updates across the category-handling, nesting, rendering, `models`, and controls↔components mirror test suites.
- **Every top-level category must carry a `mermaid-styles.yaml` entry** or it renders unstyled. The category style guard in `scripts/hooks/validate_riskmap.py` enforces this.
- **The edge model carries interim semantic debt.** The consult and containment edges (D9) ride data-flow `to`/`from` and render as data-flow arrows until the representation ADR adds a typed `kind`. This misleads diagram readers; it is accepted to avoid stranding the identity and isolation components.
- **Control and risk mapping is owed for every net-new component in this model** (D16). The two consent surfaces (D5) additionally require any mapping written against a single consent surface to be dual-mapped and then refined.
- **Policy-administration risks have no component home**, and neither do policy inputs that are not subject attributes (D2). These are decided absences, not accidents, but the gaps are real. Both are recorded at [#467](https://github.com/cosai-oasis/secure-ai-tooling/issues/467), closed as deferred, which carries the criteria that would reopen them.
- **The registry-consult edge moves** (D14). `componentToolRegistry` re-points from the tool network enforcement point to the agent network enforcement point, and the tool-side point loses its caller's-catalog enumeration claim.
- **Four descriptions change with the model, not after it.** `componentTools`' registry-query sentence and the tool-side point's enumeration claim (D14), `componentRuntimeHosting`'s workload list (D6), and `componentTools`' widening to the capability surface (D1) are all carried by the component landing change ([#462](https://github.com/cosai-oasis/secure-ai-tooling/issues/462)). Because that change lands after this record, the corpus contradicts these decisions for the interval between the two merges — a consequence of the ADR-034 layering, and the reason the landing order is fixed rather than incidental.
- **The decision numbering does not match the reading order.** D11 is the load-bearing decision and much of D1–D10 follows from it. The numbering is preserved because it is cited outside this document (see Revision history); the reading-order note at the head of the Decision section is the mitigation.

**Follow-up**

- **Representation ADR** (D10): typed edge `kind`, directionality through a single enforcement point, control-intermediated flow views, overview-versus-detail graph composition. Gated on the graphical-mapping survey.
- **Autonomy/workload attribute** (D10): a separate deferred shape decision.
- **Corpus text carried by [#462](https://github.com/cosai-oasis/secure-ai-tooling/issues/462)**: `componentTools`' registry-query sentence and widening (D14, D1), the tool-side enforcement point's enumeration claim (D14), and `componentRuntimeHosting`'s workload list (D6).
- **Content work**: control and risk mapping for every net-new component in this model (D16), including the agent consent-fatigue risk and its tiering control (D5), and the server-initiated-inference risk (Alternatives).

## Revision history

This record replaces ADR-030 v1 (2026-06-30, `Accepted`) in place, under the same number, because v1 was a single decision whose implementation diverged from it in several places; a set of errata would have obscured the model rather than clarified it. The convention in [`README.md`](README.md) — status flips to `Superseded by ADR-XXX` when a *different* ADR replaces one — does not apply, because there is no second record: the subject, scope, and number are identical.

**Decision numbers D1–D10 are preserved from v1.** Corrections are made in place under their original numbers, and the new decisions append as D11–D17. The numbering is load-bearing outside this document — commit messages, pull-request titles, production validators, and test suites cite `ADR-030 D1` and `ADR-030 D2` by number, and commit and merged-PR text cannot be rewritten — so renumbering would silently repoint an immutable record at a different decision. The cost is that the numbering no longer matches the reading order; the reading table at the head of the Decision section is the mitigation.

**Errata carried from v1.** Both corrections were made against v1 and are preserved here because they record real defects, not editorial changes.

> **Erratum (2026-07-27) — withdrawn persona-ownership requirement.** v1 carried a Negative consequence stating *"The fourth category needs a persona owner. Per [ADR-021](021-personas-and-self-assessment-schema.md), a Tools category with no responsible persona is orphaned in the responsibility model"*, and repeated it in its Follow-up and migration steps. **ADR-021 does not state that requirement.** It decides the opposite: personas deliberately do not participate in the per-category enums that risks and controls carry ([ADR-021](021-personas-and-self-assessment-schema.md) D1: "Personas do not participate in the per-category enums that risks and controls carry… This asymmetry with risks and controls is intentional"), and `personas.yaml` has no `category` partition at all. There is no per-category persona ownership in the model and no schema field records one. The CI guard built to enforce it derived ownership from the controls/components graph and was near-tautological — any control with any persona referencing any component in the category satisfied it — so the ownership half was removed and the guard narrowed to styling alone. Whether persona *mappings* should reference the tool components is ordinary content work, not a structural obligation this record imposes.

> **Erratum (2026-07-27) — tool-category naming pass.** v1 carried a consequence reading *"Near-identical ids (`componentTools`, `componentsTools`, `componentsToolCore`, `componentsToolControls`) are easy to misread; a naming pass is worth doing before the corpus lands."* That pass renamed three of the four ids — `componentsTools` → `componentsExternalTools`, `componentsToolCore` → `componentsToolInvocationPath`, `componentsToolControls` → `componentsToolNetworkControls` — leaving the leaf component `componentTools` deliberately unchanged. The subcategories were renamed in two passes with different reasoning. The first made each id the camelCase of the title it carried, resolving a rendering contradiction: `ComponentGraph` derives nested subgraph labels from the subcategory id rather than its `title`, so `componentsToolCore` rendered as "Tool Core" against its own title of "Tool data plane" (the same mechanism D3 turns on). The second changed the axis: a control-plane / data-plane split is misapplied to a category whose every member is in-flow, so the axis became layer — connection-layer network controls wrapping the invocation path. The id-matches-title property holds against each pass's own titles, but it is a consequence of the naming rather than the argument for it.
