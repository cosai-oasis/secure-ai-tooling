# ADR-033: Vendor-neutral shipping and lifecycle for CoSAI agents and skills

**Status:** Accepted
**Date:** 2026-07-08
**Authors:** Architect agent, with maintainer review
**Extended by:** [Amendment 2026-07-30](#amendment-2026-07-30-corpus-state-dependent-eval-expectations-ship-with-a-pinned-fixture) (below) — [D6](#d6-develop-evaluate-and-expand-lifecycle)'s portable-eval requirement gains a grounding rule for corpus-state-dependent expectations. D1–D6 are otherwise unchanged.

---

## Context

CoSAI ships agents and skills as vendor-neutral, cloneable artifacts. A consumer clones the repository, points their own agent runtime at `scripts/agents/**` and `scripts/skills/**`, and runs the definitions in whatever harness they operate. The value of those artifacts to a cross-provider, model-neutral coalition depends on their staying free of any single product line: the same posture [ADR-004](004-ai-assistant-trailer.md) fixed for commit trailers and [ADR-006](006-agent-architecture-pattern.md) fixed for agent bodies.

Three prior ADRs built the surfaces this standard governs. [ADR-006](006-agent-architecture-pattern.md) established `scripts/agents/` as the vendor-neutral canonical home for agent definitions and the rule that the canonical is authoritative — harness-specific invocation mechanics are environment concerns, not part of the canonical pattern. [ADR-031](031-authoring-time-agents-and-skills.md) (Accepted, [#402](https://github.com/cosai-oasis/secure-ai-tooling/pull/402)) established `scripts/skills/` as the canonical, vendor-neutral skill home in the Agent Skills open standard (`agentskills.io`, its D6) and defined the authoring corpus — creator/critic agent pairs and authoring/audit skills. [ADR-032](032-consumer-exploration-skills.md) (Accepted, [#407](https://github.com/cosai-oasis/secure-ai-tooling/pull/407)) defined the read-only consumer exploration corpus (`explore-*` skills) inheriting that home and format.

Those ADRs each answer *what a given corpus is*. None answers the cross-cutting questions that bind all of them: what makes a shipped artifact vendor-neutral, precisely enough to be enforced rather than asserted; how a consumer takes a neutral artifact and runs it in their own environment; and how a new agent or skill is developed, evaluated, and admitted into the shipped set. This ADR defines that shipping standard and lifecycle. It enumerates no corpus — ADR-031 and ADR-032 own their rosters — and selects no concrete tool; it fixes the constraints a tool must satisfy and defers the pick to downstream work.

Two forces make this an architectural decision rather than a convention note. First, "vendor-neutral" is load-bearing but under-specified: without a definition precise enough for a check to enforce, the neutral surfaces silently re-accumulate harness leakage on the next edit, and reviewers arbitrate neutrality by taste. Second, the shipped set grows — new skills and agents will be proposed — and "how does a new artifact enter the shipped set, and what must it carry?" needs a stable answer so growth stays consistent with the standard rather than drifting from it.

## Decision

We adopt a vendor-neutral shipping standard and lifecycle for the agents and skills CoSAI publishes. The shipped artifact is the neutral canonical; neutrality is defined as a contract with a mechanically-checkable core; consumers adapt the neutral artifact to their own harness; and new artifacts enter the shipped set by amending or adding an ADR that conforms to this standard.

### D1. Canonical-only, neutral, cloneable

The shipped artifact is the neutral canonical definition under `scripts/agents/**` (agents) or `scripts/skills/**` (skills). That canonical is the single, complete, authoritative form of the artifact, and it is what a consumer clones and runs. **No harness-specific wrapper files are tracked in the repository.** The repository does not ship, generate, or maintain a first-party per-harness form of any agent or skill; harness adaptation is the consumer's, not the project's (D3). This keeps the tracked surface singular — one file per artifact, no parallel copy to reconcile — and keeps the published set genuinely neutral, since there is no first-party artifact in which harness-specific mechanics could accumulate.

### D2. The neutrality contract

An artifact is vendor-neutral when it conforms to the following contract. The contract has two parts: a mechanically-enumerable core that a check can enforce (D5), and author-judgment guidance that no check can decide.

#### D2a. Mechanically-enumerable constraints (machine-checkable)

A neutral artifact contains **none** of the following, enumerated as a denylist:

- **Vendor, product, company, CLI, and model identifiers** — the name of any specific AI-assistant product, the company behind it, its command-line entry point, or any model identifier or version string.
- **Harness-invocation tokens** — harness-specific dispatch mechanics: subagent-type keys, `<uses … tool>` / `<invoke … tool>` stage directions, tool-name tokens, and "auto-loads" / "auto-triggers" phrasing that describes a specific runtime's dispatch rather than the neutral operative form ("invoke the *X* agent", "consult the *X* skill").
- **Harness config paths** — any product-named configuration directory or path. References resolve to the repo-relative canonical path (`scripts/agents/…`, `scripts/skills/…`) instead.
- **Runtime-binding frontmatter** — frontmatter beyond the neutral schema the shipping format defines (D4). The canonical carries only that neutral schema: the [ADR-006](006-agent-architecture-pattern.md) prose form for agents, and the required Agent Skills frontmatter for skills (ADR-031 D6). Any additional key encodes a specific runtime's wiring and belongs in the consumer's adaptation, not the shipped artifact — so the check enforces the neutral schema as an **allowlist** (only the schema's own keys are present) rather than chasing any one runtime's key names.

The denylist carries an explicit **allowlist carve-out** for framework-authority names that are legitimate neutral content and must **not** be flagged: **MITRE, NIST, OWASP, ISO, EU AI Act, STRIDE** (and the specific framework identifiers under them). These are the security reference frameworks the corpus legitimately names — `explore-framework-coverage` and `audit-framework-mappings` exist precisely to reference them — and they are framework authorities, not AI-harness vendors. A neutrality check must treat them as allowed content, not as vendor leakage.

#### D2b. Author-judgment guidance (not machine-checkable)

The following clauses shape a neutral artifact but cannot be decided by a check; they are review-enforced:

- **Prefer the neutral role term, and omit where the sentence reads cleanly.** Where a removed vendor or harness reference leaves a sentence that reads cleanly without any replacement, omit it rather than substituting a neutral placeholder. Substitute a neutral role term ("the AI assistant", "the model", "the harness") only where the sentence needs a referent.
- **Self-description stays neutral.** The artifact describes itself by role and behavior; it does not announce which harness it runs under or assume a specific runtime is present.
- **Capabilities in prose, not bindings.** Where a capability would have been expressed as a tool or model binding, it is re-expressed in prose that states the capability without naming the mechanism (D4).

This contract is the operative content of "vendor-neutral" wherever this ADR uses the term. It governs the shipped canonical artifacts — the canonical agents and the canonical skills with their bundled material. It does **not** govern the **adoption material** (the worked adaptation examples of D3 and the consumer adaptation / known-gaps note of D3/D6): that material is *deliberately* harness-specific — naming the harnesses it targets is its whole purpose — so it is an intentionally non-neutral surface, outside this contract and the D5 check.

### D3. Consumer leverage

After `git clone`, a consumer runs the neutral artifacts in their own harness. Adapting a neutral artifact to a specific runtime — supplying invocation mechanics, tool permissions, and whatever frontmatter that runtime expects — is the **consumer's responsibility**, not the project's. The repository ships no first-party per-harness wrapper for any artifact.

To make that responsibility tractable — and to prove it is actually tractable — the project provides a **small, curated set of worked adaptation examples that is *exercised* in at least two independent harnesses**, including at least one third-party harness independent of the standard's origin. Exercising the set (not merely writing it) is what makes it evidence that a neutral artifact runs after adaptation, rather than an untested illustration of how it might. The set is deliberately small and **contributor-extensible**: a contributor who runs a harness not yet represented can add a worked example for it. These examples are proof-of-portability for the adaptation a consumer performs, not a tracked first-party wrapper set the project commits to maintaining for every artifact; they carry no per-artifact obligation and do not reintroduce the parallel copy D1 excludes. Because a worked example must name the harness it targets, the adaptation material is an intentionally harness-specific surface — outside the D2 neutrality contract and the D5 check (see D5).

### D4. Shipping format

- **Agents** ship in the [ADR-006](006-agent-architecture-pattern.md) prose "Sub-Agent Definition" form: a header block, then `## Agent`, then `## Composition`, then body sections that define the agent's method and state its required capabilities in prose. The canonical carries the definition itself, not a runtime's binding metadata; a consumer supplies whatever wiring their runtime expects at adoption time (D3). Canonical agents reference each other by name, resolving within `scripts/agents/`.
- **Skills** ship in the Agent Skills open standard as defined in **ADR-031 D6**. That standard — the `SKILL.md` shape, its required frontmatter, its bundled-directory layout, and the pinned-revision discipline — is authoritative there and is **not restated here**; a second copy would drift from the original. This ADR requires only that shipped skills conform to it.

### D5. A neutrality check is required

A check that enforces the D2a denylist over the neutral surfaces **is required**. Its constraints:

- **Scope.** It runs over the shipped canonical artifacts — `scripts/agents/**` and `scripts/skills/**` — **not** the whole repository, and **not** the adoption material. Two categories are deliberately out of scope: the rest of the repository (devcontainer config, IDE settings, CI, dependency manifests) legitimately names specific tools; and the **adoption material — the worked adaptation examples (D3) and the consumer adaptation / known-gaps note (D3/D6) — must name the harnesses it targets to serve its purpose**, so it is an intentionally harness-specific surface, not a neutral one (D2). Those references are all correct where they are. Scoping the check to the genuinely neutral shipped artifacts is what lets both categories stay honest about their tooling while the artifacts themselves stay neutral.
- **Allowlist fidelity.** It must **not** false-fire on the D2a allowlist (MITRE, NIST, OWASP, ISO, EU AI Act, STRIDE and their identifiers). A check that flagged `audit-framework-mappings` or `explore-framework-coverage` for naming the frameworks they exist to reference would be wrong.
- **Conformance to the shipping standard.** Beyond the denylist, the check confirms each shipped skill validates against the Agent Skills standard's own reference validator and carries only the standard's required-field core (D2a; the standard itself is ADR-031 D6). This is the highest-leverage guard against *silent* incompatibility: harness-specific frontmatter beyond that core is ignored without error by harnesses that do not support it (see Consequences), so keeping shipped skills to the validated required-field core is what makes them port silently-cleanly. Validating against the standard's own reference oracle leans on the adopted standard's conformance mechanism — it is not a tool selection.
- **Enforcement point.** It gates the neutral surfaces before merge.

This ADR **requires** the check and fixes its constraints; it does **not** select or mandate a specific implementation. The linter implementation is downstream work, routed as infrastructure (`swe` → `code-reviewer`).

### D6. Develop, evaluate, and expand lifecycle

**Authoring and exercise.** A new agent or skill is authored directly in neutral canonical form (D1, D4) — there is no non-neutral intermediate to convert from. It is exercised against the corpus it operates on before it enters the shipped set.

**Portable evals travel with the artifact.** Every shipped skill (and, where applicable, agent) carries a **portable eval that ships with it** — a behavior specification, expressed independently of any runtime, that states the artifact's expected behavior on fixed inputs. An eval is **required** to ship: an artifact with no eval is not admissible to the shipped set. The eval is the artifact's portable trust anchor — the executable check a consumer runs in their own runtime to confirm an adaptation preserved behavior — the same role the conformance/reference oracle plays in every write-once-consume-anywhere standard that has succeeded.

**Constraints on any eval-runner.** Whatever runner executes the portable eval must be: **vendor-neutral** (not tied to a single product line); **permissively licensed**; **free of any dependency on a non-portable harness**; and **able to run the portable eval spec** the artifact ships. This ADR fixes those constraints; it does **not** select or build the runner. The eval spec is the durable, portable artifact; the runner is a replaceable execution detail deferred to downstream work.

**Expansion rule.** A new agent or skill enters the shipped set by an **amendment to the relevant ADR (ADR-031 for authoring, ADR-032 for exploration) or a new ADR that conforms to this standard.** The new artifact must satisfy D1–D5: neutral canonical only, conforming to the neutrality contract, in the shipping format, passing the neutrality check, and carrying a portable eval. This is the answer to "how is a new agent or skill added": not by dropping a file, but by an ADR-level decision that admits it and records that it conforms.

## Alternatives Considered

- **Ship first-party per-harness wrappers alongside the canonical.** Track, for each artifact, a project-maintained wrapper for one or more harnesses. Rejected on neutrality and maintenance grounds: a tracked first-party wrapper is a surface in which harness-specific and vendor-specific mechanics accumulate, re-coupling the published set to a product line the coalition must not privilege; and it reintroduces the parallel-copy drift [ADR-006](006-agent-architecture-pattern.md) already rejected — two files per artifact per active harness, kept in sync by discipline. D1 ships the neutral canonical only; D3 makes adaptation the consumer's, with contributor-extensible worked examples instead of a maintained wrapper set.
- **Leave "vendor-neutral" as a review-judgment call.** Define no enforceable core and let reviewers arbitrate neutrality case by case. Rejected: neutrality then rests on reviewer taste and re-accumulates silently on edits a reviewer misses. D2a gives the contract a mechanically-checkable core and D5 requires a check to enforce it, while D2b keeps the genuinely judgment-bound clauses explicitly in review's hands rather than pretending a check can decide them.
- **Select the neutrality-check implementation and the eval-runner now.** Name and mandate a specific linter and a specific eval-runner in this ADR. Rejected per the principle that an ADR constrains a choice rather than making it: naming a concrete tool binds the standard to one implementation's lifecycle and licensing, and the constraints (D5, D6) are the durable part. The picks are downstream work against the stated constraints.
- **Admit new artifacts by dropping files, no ADR.** Let a new skill or agent enter the shipped set as an ordinary PR with no decision record. Rejected: the shipped set is a governed, neutral surface with a standard to uphold; an artifact that enters without an ADR carries no record that it was checked against D1–D5. D6 makes admission an ADR-level act.

## Consequences

**Positive**

- One neutral, authoritative file per artifact, cloneable and runnable as-is. A consumer clones exactly what they run; there is no parallel first-party copy to reconcile and no product line baked into the shipped surface.
- Neutrality is enforceable, not aspirational. The D2a denylist plus the D5 check keep the shipped surfaces from silently re-accumulating harness leakage, while the D2a allowlist keeps the check honest about legitimate framework-authority content.
- The consumer's adaptation burden is bounded by worked examples that contributors can extend to new harnesses, without the project taking on a per-artifact wrapper-maintenance obligation.
- Portability is provable per artifact: a required, runtime-independent eval (D6) travels with each shipped artifact, so its behavior is checkable in any conforming runner rather than only in the environment it was authored in.
- Growth stays consistent with the standard: new artifacts enter through an ADR that records their conformance (D6), so the shipped set does not drift from the standard as it expands.

**Negative**

- **The neutrality contract is a standing obligation.** The D2a denylist and allowlist must be maintained as harnesses and their vocabularies evolve: a new harness introduces new invocation tokens and config paths to deny, and a new framework authority may need adding to the allowlist. A too-aggressive rule false-fires on legitimate content; a too-loose one lets leakage through. Scoping the D5 check to the neutral surfaces bounds the blast radius but does not remove the maintenance duty.
- **Silent frontmatter incompatibility is the residual portability risk.** A well-formed neutral skill ports cleanly, but any *extended*, harness-specific frontmatter a consumer adds during adaptation is, on a harness that does not support it, ignored **without error** rather than rejected — so a mis-adaptation surfaces as wrong behavior, not a failed load. This is why D5 validates shipped skills against the standard's required-field core and D6 requires a portable eval: the core keeps the shipped artifact silently-clean, and the eval gives the consumer an executable way to catch a silent mis-adaptation on their side.
- **Harness adaptation is the consumer's burden.** Because no first-party wrapper ships (D1, D3), a consumer must wire each neutral artifact into their runtime themselves. The worked examples lighten this but do not eliminate it, and a consumer on an unrepresented harness has more to do until someone contributes an example for it.
- **The neutrality check is a supply-chain-adjacent surface.** A merge-gating check (D5) is code in the contributor path; its denylist/allowlist is security-relevant to maintain, and its scope must stay correct as the neutral surfaces move.
- **Every shipped artifact must carry a portable eval.** Requiring an eval to ship (D6) is real authoring cost, and the eval must be kept runtime-independent or it stops being portable — a discipline that holds only as long as authors resist encoding runner-specific assumptions into the spec.
- **AI-assisted provenance stays governance-sensitive.** The shipped artifacts and their adoption docs are AI-authored; they carry the [ADR-004](004-ai-assistant-trailer.md) `Co-authored-by: AI Assistant` trailer, and neither the artifacts nor the neutrality check may introduce a vendor marker into that provenance chain.

**Follow-up**

- **Build the neutrality check (D5)** enforcing the D2a denylist and allowlist over the shipped canonical artifacts (`scripts/agents/**`, `scripts/skills/**`), without selecting it here — the harness-specific adoption material (D3/D6) is out of scope. Routed as infrastructure (`swe` → `code-reviewer`).
- **Select an eval-runner (D6)** against the stated constraints — vendor-neutral, permissively licensed, no non-portable-harness dependency, runs the portable eval spec — as a downstream decision. The portable eval spec is the durable artifact; the runner is the replaceable detail.
- **Provide and extend the worked adaptation examples (D3)** — a small, curated set *exercised* in at least two independent harnesses (one of them third-party), kept contributor-extensible.
- **Write a one-page consumer adaptation / known-gaps note (D3/D6)** documenting, by harness, where extended frontmatter is silently ignored, and pointing consumers at the existing open-source cross-harness converters and installers instead of a first-party per-harness wrapper. This is the adoption-friction lever the consumption research identified, and it keeps the project on the neutral-canonical side of D1.
- **Admit new agents and skills (D6)** via amendments to ADR-031 / ADR-032 or new ADRs that record conformance to this standard; each must satisfy D1–D5 and ship a portable eval.
---

## Amendment 2026-07-30: Corpus-state-dependent eval expectations ship with a pinned fixture

**Status:** Draft (2026-07-30). Extends [D6](#d6-develop-evaluate-and-expand-lifecycle); does not alter the Accepted status of D1–D6 above.
**Authors:** Architect agent, with maintainer review.

### Context

[D6](#d6-develop-evaluate-and-expand-lifecycle) made a portable eval a shipping precondition: every shipped artifact carries "a behavior specification, expressed independently of any runtime, that states the artifact's expected behavior **on fixed inputs**." D6 then constrained the *runner* — vendor-neutral, permissively licensed, free of a non-portable-harness dependency — and said nothing about the eval's *ground truth*. That silence held for most cases, whose expected verdict is a property of the case input alone, and broke for one class: cases whose expected verdict is a property of the **Risk Map corpus at the moment the case is graded**.

`scripts/skills/altitude-check/` is where the class is sharpest. Its `C1` test is a three-outcome judgment — **absorb** into an existing component, keep as **new**, or **decompose** an existing too-broad component — and its guidance directs the executor to "check `risk-map/yaml/components.yaml`" (`SKILL.md`, C1). Two of the three outcomes are gradeable only against a corpus state, and they are not the same kind of assertion:

- An **absorb** verdict asserts a *positive* existential: a named entry (`componentRAGContent`, `componentTools`) already covers the candidate's locus. `evals/evals.json` cases 9–11 are all of this shape.
- A **new** verdict asserts a *negative* existential: *no* entry covers the candidate's niche.

The two fail differently under corpus change. A positive existential is falsified only by a rename, merge, or removal of the named entry — infrequent, and when it does happen the failing case is a true signal that an anchor the skill's own guidance points at has moved. A negative existential is falsified by any *addition* that comes to cover the targeted niche, and addition is the corpus's routine direction of travel: [ADR-034 D1](034-corpus-change-landing-sequence.md) makes new-component additions Layer 1 of the standing landing sequence, and an in-flight corpus workstream is landing a batch of net-new components chosen precisely to cover architectural niches with no home today. A synthetic "keep as new" case graded against the live corpus is therefore pinned to a snapshot it never declares, and flips from **new** to **absorb** on ordinary corpus growth — a failing case with no defect behind it, whose diagnosis ("skill regression, or did the corpus move?") is re-derived from scratch every time it fires.

The exposure is not specific to `altitude-check`. Every artifact whose eval encodes an "already covered, or genuinely new?" judgment carries it: `altitude-check` T6 (novelty-vs-absorb for controls), R1/R2 (merge-vs-distinct, wrong-home) and C1; `draft-issue-comment`'s duplicate-detection expectation (`evals/evals.json`, the `riskCrossTenantCredentialPropagation` overlap case); and the persona **necessity test** of [ADR-031 D5](031-authoring-time-agents-and-skills.md), whose entire question is whether an existing persona already covers a proposed role. The need surfaced during review of [#431](https://github.com/cosai-oasis/secure-ai-tooling/pull/431).

### D7. A corpus-state-dependent eval expectation is grounded in a pinned fixture that ships with the artifact

#### D7a. Classify the expectation: absence-grounded cases pin, presence-grounded cases may not

The rule fires on any eval case where changing the corpus, without changing the artifact, would change the expected verdict. It does not fire on corpus-independent cases — objective-vs-implementation, threat-vs-control-gap, real-vs-hypothetical and their kin — which are graded from the case input alone and are unaffected by this amendment.

For the cases it does reach, the grounding depends on which existential the expectation asserts:

- **Absence-grounded expectations pin.** An expectation that rests on *no existing entry covering* the candidate — a "keep as new" verdict, a "the corpus lacks this domain" verdict, a "decompose the existing entry" verdict that presumes a specific too-broad entry — is graded against a **pinned fixture that ships with the artifact** (D7b), never against the live corpus file. The case states in its own prompt that the fixture is the sole ground truth for that verdict.
- **Presence-grounded expectations may use the live corpus, and name what they depend on.** An expectation that rests on a *named existing entry* is graded against the live corpus file, and the case records the entry ids it depends on. Naming the dependency converts a future failure from an open question into a one-line diagnosis: the referenced entry moved, and the case is retired or repointed.

#### D7b. What the fixture is, and where it lives

A fixture is a **small, hand-authored, purpose-built stand-in** for the corpus file the test consults — on the order of 5–10 corpus-shaped entries — not a copy of the live file and not a snapshot of it. It is constructed to contain, by design, whatever conditions the artifact's absence-grounded cases need: a deliberate coverage gap to ground a "keep as new" verdict, a deliberately over-broad entry to ground a "decompose" verdict.

- **One fixture per artifact, shared across its cases.** The artifact's absence-grounded cases draw against one consistent backdrop rather than each inventing an uncoordinated inline list, so adding the *n*th such case costs a case, not a new fixture.
- **It ships inside the artifact.** The fixture lives under the artifact's own eval tree (`scripts/skills/<skill>/evals/fixtures/`), so it travels with the artifact on clone or vendor. This is what keeps the eval portable in the [D6](#d6-develop-evaluate-and-expand-lifecycle) sense — everything the grader needs is inside the directory a consumer copies — and what keeps [D1](#d1-canonical-only-neutral-cloneable)'s "single, complete, authoritative form" true of the shipped unit.
- **It declares that it is not corpus content.** The fixture carries a header stating it is test input, is not Risk Map content, and must not be cited, validated, or consumed as corpus.
- **It is refreshed on structural change only.** A fixture is revised when the entity *shape* changes — a schema change that adds a required field, a structural revision of the entity model — never in response to corpus content growth. Immunity to content growth is the point of pinning it.
- **It is shipped material.** Fixtures sit under `scripts/skills/**` and are therefore inside the [D5](#d5-a-neutrality-check-is-required) check's scope; fixture content satisfies the [D2a](#d2a-mechanically-enumerable-constraints-machine-checkable) denylist like any other shipped material.

**Relationship to [ADR-031 D1](031-authoring-time-agents-and-skills.md).** D1's "reference the source rather than re-deriving it" governs an artifact's *guidance*: a skill points at `risk-map/yaml/components.yaml` instead of restating its contents, so the guidance and the corpus cannot drift. A fixture is not guidance — it is test input, and fixing test input is what makes a test a test. The fixture asserts nothing about the real Risk Map; it stands in for a corpus so that a case has the fixed inputs D6 already requires. D7c is what keeps the two disciplines from pulling apart.

#### D7c. Live-corpus exercise is retained, not replaced

Fixture grounding is scoped to the expectations that need it. For each test whose guidance directs the executor to read a corpus file, the artifact's eval set **retains at least one case graded against that live file** — necessarily a presence-grounded case under D7a. Without that floor, an artifact could ship an eval that never exercises the corpus lookup its own guidance mandates, and would be testing placement judgment in the abstract while claiming to test the skill.

### Alternatives considered

- **Grade absence-grounded cases against the live corpus and accept the drift.** Simplest, and it exercises the lookup an executor really performs in production. Rejected: the expectation is falsified by the corpus's routine direction of change, so the case fails without a defect behind it. Annotating the case ("if this now absorbs, that is corpus growth") shortens the diagnosis but does not prevent the false alarm.
- **Make every corpus-dependent case self-contained with an inline list, referencing no corpus at all.** Fully immune to drift. Rejected on two counts: it removes all live-corpus exercise (D7c), and it produces one uncoordinated backdrop per case, which does not scale to the several new-verdict and decompose-verdict cases the class needs.
- **Pin a historical corpus snapshot from repository history** (`git show <sha>:risk-map/yaml/components.yaml`). Durable in principle and cheap to author. Rejected on portability: [D1](#d1-canonical-only-neutral-cloneable) ships the artifact as a self-contained cloneable unit and [D6](#d6-develop-evaluate-and-expand-lifecycle) makes the eval the consumer's portable trust anchor, but a repository-history reference does not resolve from a vendored or partially-cloned artifact directory — the eval stops being portable. It is also opaque to a future reader and drags in the entity shape of the pinned era rather than a backdrop built to make the gap and the over-broad entry obvious.
- **Hold fixtures in one repo-wide eval-fixture directory outside the artifacts.** Rejected: it splits the eval from the artifact D1 requires to be a single complete cloneable form, and creates a shared surface every artifact must coordinate on for no gain — fixtures are per-artifact by construction.
- **Record the rule in a contributing guide rather than here.** Rejected: D6 makes a conforming eval a *shipping admissibility* condition, so a constraint on what makes an eval valid is a constraint on admissibility, and belongs with the standard it qualifies. A guide entry would also be invisible to a reader arriving at D6.

### Consequences

**Positive**

- An "already covered, or genuinely new?" expectation becomes stable under the corpus's routine direction of change. A failing case again means a defect.
- D6's "fixed inputs" clause becomes operable for the one class where it was ambiguous, and is tightened rather than weakened: the corpus was an unacknowledged input, and pinning it makes the input set actually fixed.
- The eval stays self-contained, so it remains portable in the D6 sense — a consumer who vendors the artifact directory gets a gradeable eval, not a dangling reference to repository state.
- One shared backdrop supports several absence-grounded cases, so the outcome coverage a three-outcome test needs is cheap to complete.

**Negative**

- **Authoring cost rises per artifact.** An artifact with absence-grounded cases now needs a hand-authored fixture on top of its eval, and the fixture has to be built well enough that the gap and the over-broad entry are unambiguous.
- **A fixture is content-shaped material that is not content.** Realistic-looking component, control, or risk entries under `scripts/skills/**` can be mistaken for corpus data by a contributor, a downstream consumer, or an authoring agent reading the directory. The non-authoritative header (D7b) mitigates this; nothing enforces it today.
- **Fixtures are outside schema validation.** A structural schema change can leave a fixture shaped like an entity generation that no longer exists, quietly degrading the case's realism. The refresh trigger (D7b) is deliberate and manual.
- **Two grounding regimes now coexist in one eval file.** A case author must classify the expectation (D7a) before writing it; misclassifying a negative existential as a presence case silently reintroduces the drift this rule exists to remove.
- **Eval sets authored before this rule are not retrofitted by it.** Until the sweep below runs, absence-grounded expectations in the shipped set remain pinned to the live corpus.

**Follow-up**

- **Sweep the shipped eval sets** (`scripts/skills/**/evals/`, and agent evals as they land) for corpus-state-dependent expectations, classify each per D7a, and retrofit the absence-grounded ones with fixtures. Tracked as a backlog issue; routed per artifact as infrastructure (`swe` → `code-reviewer`).
- **The first artifact to land a fixture fixes the pattern** — the `evals/fixtures/` layout and the non-authoritative header wording that later artifacts follow. This is the same "first PR sets the on-disk pattern" mechanism [ADR-031 D6](031-authoring-time-agents-and-skills.md) used for the skill layout itself.
- **The eval-runner selection deferred by D6 inherits a constraint from this amendment:** whatever runner is chosen must be able to grade a case against a fixture shipped alongside the eval, not only against live repository state.
- **A check that fixture files are never read or validated as corpus** is deferred. The boundary is review-enforced until one exists.

### References

- [D6](#d6-develop-evaluate-and-expand-lifecycle) — the portable-eval shipping requirement and its "fixed inputs" clause, which this amendment operationalizes
- [D1](#d1-canonical-only-neutral-cloneable) — canonical-only, self-contained cloneable artifact; why the fixture ships inside the artifact directory
- [D5](#d5-a-neutrality-check-is-required) / [D2a](#d2a-mechanically-enumerable-constraints-machine-checkable) — the neutrality check's scope, which fixtures fall inside
- [ADR-031 D1](031-authoring-time-agents-and-skills.md) — "reference the source rather than re-deriving it"; the guidance-vs-test-input boundary drawn in D7b
- [ADR-031 D5](031-authoring-time-agents-and-skills.md) — the persona necessity test, an absence-grounded judgment this rule will govern
- [ADR-034 D1](034-corpus-change-landing-sequence.md) — new-entity additions as Layer 1 of the standing landing sequence; why corpus growth is the routine direction of change
- [ADR-026 Amendment 2026-05-21](026-issue-template-domain.md#amendment-2026-05-21-component-categorysubcategory-valid-tuple-selector) — the dated in-file amendment instrument this amendment follows
- `scripts/skills/altitude-check/SKILL.md` (C1, T6, R1, R2) and `scripts/skills/altitude-check/evals/evals.json` (cases 9–11) — the artifact where the class surfaced
- [#431](https://github.com/cosai-oasis/secure-ai-tooling/pull/431) — the review in which the exposure was identified
