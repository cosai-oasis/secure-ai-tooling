# ADR-037: CI as the enforcing gate for risk-map validation — `--block` parity and the graph-generation exception

**Status:** Draft
**Date:** 2026-07-27
**Authors:** Architect agent, with maintainer review

---

## Context

[ADR-025 D9](025-testing-strategy.md) declared the project's parity posture: **CI is the authoritative final gate**, local `pre-commit` is the cheap iteration gate, and divergence between them is tolerated. The tolerated divergence was assumed to run one direction — CI reproducing a clean checkout and fresh dependency install that local cannot cheaply match.

For risk-map validation the divergence ran the *other* direction, and inverted the posture. In three cases it ran to zero: the check existed locally and nowhere else. Line references below are as of the base commit `f87db8e`; hooks are cited by id, which is stable across edits to `.pre-commit-config.yaml`.

- `.github/workflows/validation.yml:195` ran `python3 validate_riskmap.py --force` with **no** `--block`. `.pre-commit-config.yaml:211` did pass `--block`. Risk-map warn-only checks were therefore blocking locally and advisory in CI.
- The practical effect was backwards: a contributor who installed the hooks was gated by findings that a contributor who had *not* installed them could merge past. The worse-configured setup got the more permissive gate, and the merge decision depended on a contributor's local state rather than on the repository's.
- The repository already conceded that hook installation cannot be assumed. `validate_tables.yml:256` prints "The pre-commit hook should do this automatically. If tables are out of sync, the hook may not be installed."
- `--block` is **per-check, not global.** It gates a single `warn_block_triggered` boolean (`validate_riskmap.py:286`) that only warn-only checks set — `check_controls_components_mirror` (`:296-303`) and `check_category_subcategory_nesting` (`:327-336`) — consumed by a unified exit at `:346-348`. Component edge consistency, missing-component references, isolated components, and lifecycle-stage order uniqueness (`:249-271`) already exit 1 with no `--block`. The blast radius of adding the flag is confined to the warn-only tier.
- The flip was empirically safe when measured. `--force --block` exited 0 on `develop`, on `main`, and on the branch implementing [ADR-036](036-decoupled-component-graph-emission.md), with zero warnings from any warn-only check. Non-vacuity was confirmed rather than assumed: injecting a bogus component reference made the mirror check fire and exit 1.
- A hard ordering constraint blocked the naive "add `--block` everywhere" version. `sys.exit(1)` at `validate_riskmap.py:346-348` sits **before** the `if args.to_graph:` block at `:350` and the sibling emission blocks after it. Verified: `--force --block --to-graph` exits 1 and writes **no graph file**. Adding `--block` to the graph-validation job (`validation.yml:336`) would surface a content warning as "`${graph_name}` generation via `validate_riskmap.py` failed", masking the real cause and skipping the diff-against-committed comparison entirely.
- A parallel gap of the same class existed. `validate_framework_references.py` also has `--block` (promoting deprecated-persona warnings to errors, `:533-539`, `:600`); `.pre-commit-config.yaml:225` passed it and `validation.yml:269` did not.
- **The gap had two classes, and the flag class was the smaller one.** Three validators that `.pre-commit-config.yaml` invokes *with* `--block` had no CI invocation at all: `validate-identification-questions` (`scripts/hooks/precommit/validate_identification_questions.py`), `validate-yaml-prose-subset` (`scripts/hooks/precommit/validate_yaml_prose_subset.py`), and `validate-prose-references` (`scripts/hooks/precommit/validate_prose_references.py`). No workflow under `.github/workflows/` ran them.
- **No workflow ran `pre-commit` in any form**, so there was no fallback path covering them either. An identification-questions violation, a prose-subset violation, or a prose-reference violation passed CI silently. Those three checks existed only on contributor machines, and only where the hooks were installed. This is the flag gap one degree worse: the flag gap made CI advisory, the coverage gap made CI blind.
- The three differ from the two above in invocation shape, which is why "run the same command in CI" does not describe the work. They are `pass_filenames: true` file-argument validators — pre-commit supplies the file list from each hook's `files:` regex — and two of them exit 0 when handed no files. A CI invocation must construct that file list explicitly.
- Two of the three are vacuity-prone by construction, which raises the stakes on *how* they are wired. `validate_yaml_prose_subset.py` and `validate_prose_references.py` derive their default `--schema-dir` from `Path(__file__).resolve()`, and the field discovery they share (`find_prose_fields` in `scripts/hooks/precommit/_prose_fields.py`) returns silently when the schema cannot be inferred or read. A wrong schema directory yields zero diagnostics and exit 0, which is indistinguishable from a clean corpus.
- Motivating the general rule rather than the one-line fix: a path-resolution bug had made a category guard **vacuous** under CI's copy-to-root layout — it resolved its schema relative to its own module path, which the copy invalidates, then swallowed the miss and iterated an empty set. A check can be wired into CI, run, report success, and verify nothing. That is the ADR-025 D10 failure class extended one level — reachable from the execution surface, yet still not enforcing.

## Decision

### D1. CI is the enforcing gate; pre-commit is a fast preview of it

We adopt the corollary ADR-025 D9 left unstated, in two parts:

1. **Coverage.** Every validator `.pre-commit-config.yaml` invokes as a **blocking hook** has a CI invocation of at least the same strictness, over at least the inputs the hook would see. A hook is blocking if a violation makes it exit non-zero — whether that is unconditional, or requires `--block`.
2. **Monotonicity.** For any validator invoked from both surfaces, the CI invocation is at least as strict as the pre-commit invocation. Where the two differ, CI is stricter, never laxer.

Coverage is prior to monotonicity, and stating it separately is the point. Monotonicity alone is satisfied *vacuously* by a validator CI never runs — an empty flag set is trivially a superset of nothing — which is the mechanism by which three blocking checks came to live only on contributor machines. A rule that quantifies over the intersection of the two surfaces cannot see a validator missing from one of them.

The rule quantifies over pre-commit's **blocking** hooks, not over a fixed list of validators, and not over the `--block` flag. A hook added to `.pre-commit-config.yaml` that can fail a commit is governed on arrival; it does not need an amendment here to be covered, and it does not land until its CI invocation lands with it.

**The quantifier is deliberately blocking-ness rather than the flag**, because keying on the flag reproduces one surface lower the exact defect stated above. `--block` marks a validator with a *warn-only tier to promote*; a validator with no such tier blocks unconditionally and never takes the flag. A rule ranging over flag-bearing hooks cannot see those, and three of them — `validate-mapping-purity`, `validate-mapping-drift`, `validate-frameworks-versionid-purity` — are today invoked by no workflow at all, for the same reason and with the same consequence: a contributor who has not installed hooks can land a violation with an all-green CI. They are instances of this rule, not exceptions to it.

This settles the developer question directly. Contributors who have not installed hooks are fully covered, because nothing depends on their having done so. Hooks are an accelerator that moves a failure from minutes-after-push to seconds-before-commit; they are not load-bearing for correctness. "The hook may not be installed" stops being a caveat and becomes a statement about latency.

The twelve hooks the rule resolves to, and what it requires of each. The table lists the rule's *instances*, not the rule; it is expected to grow without this ADR changing. It is a dated record of what the change consisted of, not the register the rule quantifies over — see [D9c](#d9c-d1s-instance-table-is-a-dated-record-not-the-register) in the 2026-08-04 addendum, which is where the register is defined.

| pre-commit hook id | Validator | CI state before this decision | Required by D1 | Instance |
|---|---|---|---|---|
| `validate-component-edges` | `scripts/hooks/validate_riskmap.py` | invoked without `--block` | add the flag | [D2](#d2---block-is-added-to-the-risk-map-validation-job) |
| `validate-framework-references` | `scripts/hooks/validate_framework_references.py` | invoked without `--block` | add the flag | [D4](#d4-the-validate_framework_referencespy-parity-gap-closes-in-this-decision) |
| `validate-identification-questions` | `scripts/hooks/precommit/validate_identification_questions.py` | not invoked | add the invocation | [D7](#d7-the-three-uncovered-validators-gain-ci-invocations) |
| `validate-yaml-prose-subset` | `scripts/hooks/precommit/validate_yaml_prose_subset.py` | not invoked | add the invocation | D7 |
| `validate-mapping-purity` | `scripts/hooks/precommit/validate_mapping_purity.py` | not invoked | add the invocation | [D8](#d8-blocking-validators-that-take-no-flag-are-instances-not-exceptions) |
| `validate-mapping-drift` | `scripts/hooks/precommit/validate_mapping_drift.py` | not invoked | add the invocation | D8 |
| `validate-frameworks-versionid-purity` | `scripts/hooks/precommit/validate_versionid_purity.py` | not invoked | add the invocation | D8 |
| `validate-all-yaml-on-master-schema-change` | `scripts/hooks/precommit/validate_all_schemas.py` | not invoked | add the invocation | D8 |
| `validate-persona-site-build` | `scripts/hooks/precommit/validate_persona_site_build.py` | not invoked | add the invocation | D8 |
| `validate-neutrality` | `scripts/hooks/precommit/validate_neutrality.py` | not invoked | add the invocation | D8 |
| `validate-neutrality-policy` | `scripts/hooks/precommit/validate_neutrality.py` | not invoked | add the invocation | D8 |
| `validate-prose-references` | `scripts/hooks/precommit/validate_prose_references.py` | not invoked | add the invocation | D7 |

D3 carves the one exception, and it is an exception at the level of a specific *invocation* rather than of a validator: the validator D2 governs is also called for graph emission, and that call site does not take the flag.

*Testable requirement:* a config-level test parses `.pre-commit-config.yaml` and every workflow under `.github/workflows/`, and asserts both parts over the **verdict-class hook entries** [D9a](#d9a-every-hook-entry-is-classified-and-the-classification-is-total) derives from the config — not over the entries passing `--block`, and not over the rows of the table above — (1) each such entry has at least one workflow step invoking the same validator at no lower strictness; (2) for validators present on both surfaces, the CI strictness flags are a superset of the hook's. Part (1) must be written so that a validator absent from CI *fails*, not skips: the intersection-shaped form of this test passes on precisely the gap it exists to catch. Neither part needs subprocess execution. This sentence originally scoped both parts to "each hook entry passing `--block`", which contradicted the rule stated two paragraphs above from the moment D8 was written; the 2026-08-04 addendum records the correction and what the stale scoping cost.

### D2. `--block` is added to the risk-map validation job

`validation.yml:195` becomes `python3 validate_riskmap.py --force --block`.

D2 is an instance of D1, not a rule of its own; the rule lives in D1. What D2 closes is a flag gap — the job exists and runs the validator, it just runs it laxly. A warn-only check has exactly two supported states: warn everywhere (no `--block` on either surface) or block everywhere. "Blocking locally, advisory in CI" is not a supported state, and neither is "blocking locally, absent from CI".

Because all warn-only checks share the single `warn_block_triggered` boolean, adding a new warn-only check to `validate_riskmap.py` automatically makes it CI-blocking. That is intended: a new warn-only check lands block-ready or it does not land. [ADR-036](036-decoupled-component-graph-emission.md)'s emission work adds two such checks — category style/ownership and emission drift — both wired into the same boolean, and D2 governs them like any other.

### D3. `--block` is prohibited on graph-generation invocations

No invocation of `validate_riskmap.py` that passes `--to-graph`, `--to-controls-graph`, or `--to-risk-graph` may also pass `--block`. This applies to the graph-validation job at `validation.yml:336` and to any future emission call site.

The reason is the ordering constraint in Context: the warn-only exit at `:346-348` precedes every emission block, so `--block` causes the process to terminate before writing any graph. The job would then report a generation failure for what is actually a content warning, misattributing the cause, and the diff-versus-committed comparison — the entire point of that job — would never execute. A check that reports the wrong cause is worse than one that reports nothing.

This codifies existing practice rather than changing it: the local graph-regeneration hook already invokes `--to-graph` without `--block` (`scripts/hooks/precommit/regenerate_graphs.py:62`), so D3 is consistent with D1 — the two surfaces agree here.

D3 is a prohibition on the **invocation**, not an endorsement of the ordering. We deliberately do not reorder `sys.exit` relative to the emission blocks in this decision; doing so would make graph emission conditional on warn-only content state and change what a generated graph file means. That is a larger change with its own blast radius, recorded as follow-up.

D3 costs no coverage. The dedicated risk-map job under D2 runs `--block` against the same corpus in the same CI run, so a warn-only failure still fails the pull request — it just fails in the job whose error message is accurate.

*Testable requirement:* a test asserts that no workflow step passes `--block` together with any graph-emission flag.

### D4. The `validate_framework_references.py` parity gap closes in this decision

`validation.yml:269` becomes `python3 validate_framework_references.py --force --block`.

This is the same class of gap governed by the same rule, so splitting it into its own ADR would produce a second document with one rationale while leaving a known gap open in the interim. It closes here.

Safety is established the same way as D2. `--block` on this validator promotes deprecated-persona warnings to errors, and `check_deprecated_persona_usage` (`:345-388`) inspects only `controls[].personas` and `risks[].personas` against personas marked `deprecated: true`. `personaModelCreator` and `personaModelConsumer` are defined-and-deprecated in `personas.yaml` and referenced by **zero** controls and **zero** risks across the tracked corpus; the only other occurrences are in `risk-map/yaml/archive/self-assessment-legacy.yaml`, which this validator does not read. The check yields no warnings today.

*Testable requirement:* implementation confirms this empirically by running the command, not by inspection alone, and confirms non-vacuity by injecting a deprecated-persona reference and observing exit 1 — per ADR-025 D10.

One consequence to flag, narrower than it first appears: reintroducing a reference to a deprecated persona now fails CI rather than warning. This does not pre-empt the open question of whether the legacy personas are retained as `deprecated` or removed from the id enum — the gate is compatible with either. Under retention it enforces the no-new-references posture; under removal the closed id enum rejects such a reference at schema validation anyway, and the check becomes redundant rather than wrong. What changes is only that a *deliberate* re-reference — during a backward-compatibility migration, say — becomes an error requiring an explicit decision rather than a warning that can be passed over.

### D5. The copy-to-root arrangement stays, with the reasoning recorded

Five steps in `validation.yml` (`:44-47`, `:183-185`, `:222`, `:259`, `:298-300`) copy validator sources to the repository root before running them. We do not replace this with `PYTHONPATH` in this decision, and we record why the arrangement is nonetheless a liability.

The arrangement materializes a **different directory layout in CI than the one contributors and the test suite run against**. Any code that resolves a path relative to its own module location behaves differently across the two. That is precisely the mechanism behind the vacuous category guard cited in Context, and it is a standing source of the "wired but checking nothing" failure that D1 exists to prevent. A `PYTHONPATH`-based invocation that runs the validators in place would eliminate the divergence.

It is not changed here for two reasons: replacing it touches five steps across five jobs, and the fix for the vacuous guard resolves the schema relative to the working directory, which assumes the current layout. Changing the layout in the same decision would collide with that fix; the two must be sequenced, not merged.

*Constraint for implementers:* do not "improve" the copy-to-root layout as part of the `--block` flip. D2, D4, and D7 must not be blocked on D5, and the implementation diff should contain no change to an existing copy-to-root step. D7b is not such a change: adding a new invocation that runs a script in place neither touches nor endorses the five existing steps.

### D6. Landing surface

This is `main`-based infrastructure per [ADR-002](002-branching-strategy.md): the change touches `.github/workflows/` and no file under `risk-map/yaml/`. Branches based on `develop` inherit the stricter gate when `develop` next merges from `main`.

D7 can split this. If the measurement D7 requires turns up a backlog, clearing it edits `risk-map/yaml/` and is content work routing to `develop` per ADR-002, while the workflow change routing to `main` is what makes the check blocking. The two land on different branches in a fixed order — corpus clean first, gate second — because the reverse order red-lights `develop` until the cleanup catches up. A clean measurement collapses this to the single `main` change described above.

Any change that adds a warn-only check under the shared boolean (D2) carries the obligation to verify `--force --block` exits 0 against its own corpus before merging. The rule governs the change; the verification lands with it, not here. This applies to every such change, not only those open when this decision was taken.

### D7. The three uncovered validators gain CI invocations

`validate_identification_questions.py`, `validate_yaml_prose_subset.py`, and `validate_prose_references.py` each gain a CI invocation passing `--block`. This is D1's coverage half, and it is the larger half of the change: D2 and D4 make an existing gate strict, D7 creates gates that do not exist.

The invocations live in the risk-map validation workflow alongside the jobs D2 and D4 govern, one invocation per validator, so a failure names the check that failed. Whether each is a step within an existing job or a job of its own is an implementation choice bounded by the workflow's summary job, which consumes per-job `status` outputs; the binding constraint is attribution — a failure must resolve to a single validator, for the same misattribution reason D3 gives.

Three constraints bind the implementation.

#### D7a. Inputs are constructed explicitly

These validators take file arguments rather than scanning the corpus themselves. The file set for each CI invocation is the set matched by the corresponding hook's `files:` regex, evaluated over the whole tracked corpus rather than over a diff — CI is not the incremental surface, and the hook's own file list is a diff artifact D1 requires CI to meet or exceed. Two of the three exit 0 when handed no files, so an invocation whose file list resolves to empty is a passing job that checks nothing.

#### D7b. Invoke in place, not via copy-to-root

These invocations run the scripts at their real paths under `scripts/hooks/precommit/`. Two of the three derive their default `--schema-dir` from `Path(__file__).resolve()`, and copying a script to the repository root invalidates that derivation; their shared field discovery then returns silently on a schema it cannot read, and the job exits 0 having inspected nothing. That is the vacuity failure D5 describes, reproduced deliberately.

This does not reopen D5. D5 leaves the five existing copy-to-root steps in place, and D7b changes none of them. D7b is a decision not to *extend* the pattern to new call sites, which is the direction D5 already argues for and defers only because unwinding the existing steps collides with an in-flight path-resolution fix. New call sites carry no such collision.

#### D7c. Non-vacuity is demonstrated per validator

Per ADR-025 D10, each new invocation is shown to fail on a deliberately injected violation before it is accepted as covering anything. A green job is evidence of nothing until the red case has been observed, and D7b describes two specific ways these particular validators go green while inspecting an empty set.

**On the size of the change, which is not established.** Unlike D2 and D4, D7 carries no measured claim that the corpus is already clean. These three checks have never gated anything, so whatever findings they hold have accumulated unobserved; the flip is either clean or a cleanup job, and which one it is is not known from the ADR. The implementation measures each validator's finding count against the corpus before the invocation is made blocking, and reports it. D1 is then satisfied either by a clean flip or by a cleanup that precedes the flip — not by weakening the flag, and not by landing the invocation warn-only to soak.

### D8. Blocking validators that take no flag are instances, not exceptions

Six validators across seven hooks gain CI invocations on the same terms as D7's three: `validate-mapping-purity`, `validate-mapping-drift`, `validate-frameworks-versionid-purity`, `validate-all-yaml-on-master-schema-change`, `validate-persona-site-build`, and `validate_neutrality.py` under both of the hook ids that invoke it.

**No carve-out for the fan-out hook.** `validate-all-yaml-on-master-schema-change` exists to widen scope after its trigger fires — one master-schema edit validates every yaml — and [ADR-005](005-pre-commit-framework.md) carves it out of the *trigger* invariant for that reason. That carve-out does not transfer here: this rule is about coverage, not triggers. CI's schema-validation job already checks the same nine pairs, but from a list transcribed into shell rather than derived, so a schema added tomorrow is covered by the hook and missed by CI until someone edits the array. That is the drift D7a already rules on — "a file the hook covers and the workflow omits is unchecked in CI while appearing checked" — and running the validator, which derives its own pairs, is the simplest form of complying with it.

They are separated from D7 only because they were found by a different route and have a different cause. D7's three are invoked by pre-commit with `--block` and simply never wired to CI. These three are invoked with no flag at all — they have no warn-only tier, so a violation exits non-zero unconditionally — and D1 as first drafted quantified over `--block` hooks, which cannot see them. The gap was not that they were overlooked against the rule; it was that the rule could not reach them.

That is the same defect D1 records one surface lower: a rule quantifying over the intersection of two surfaces cannot see a validator missing from one of them. Keying the quantifier on a *flag* rather than on *blocking-ness* re-introduced it, and left three blocking checks living only on contributor machines — the precise condition D1 exists to end. D1's coverage clause now ranges over blocking hooks; these three follow from it rather than being carved in by name.

D7a, D7b and D7c apply unchanged: inputs constructed explicitly rather than transcribed, invoked in place rather than through the copy-to-root arrangement, and non-vacuity demonstrated per validator before the invocation is accepted as covering anything.

**Strictness.** None of the three takes a strictness flag today. If one later grows a warn-only tier and a `--block` to promote it, D1's monotonicity clause governs the CI invocation from that point; no amendment here is required.

## Alternatives Considered

- **Remove `--block` from pre-commit instead** — restore consistency by making the blocking tier advisory on both surfaces. Rejected: it restores consistency by discarding the checks. The warn-only tier exists to become blocking once the corpus is clean, and it is measured clean for the checks D2 and D4 govern; this option spends that readiness for nothing. It also resolves the coverage gap in the wrong direction: the three validators D7 covers were written to block and would instead become advisory everywhere.
- **Replace per-check `--block` with a global `--strict` flag** — rejected: `--block` is already tier-scoped with a unified exit, so this is a rename with no behavior change. It would break every pre-commit entry and every branch carrying a `--block` invocation simultaneously, to buy a nicer flag name.
- **Defer the framework-references gap (D4) to a separate ADR** — rejected: identical class, identical rule, identical safety argument. Splitting yields two documents sharing one rationale and leaves a known gap open meanwhile.
- **Reorder `sys.exit` to follow graph emission, making `--block` safe everywhere** — rejected for this decision: it makes emission depend on warn-only content state and changes the meaning of a generated graph file. D3's prohibition achieves the same safety at no risk; the reordering question is recorded as follow-up rather than resolved by omission.
- **Leave the three uncovered validators to pre-commit** — accept hook installation as the enforcement mechanism for checks CI does not run. Rejected: it is the exact state D1 exists to end, and the repository already concedes that hook installation cannot be assumed (`validate_tables.yml:256`). It is also worst where it matters most — these three have no CI backstop at all, so the checks most dependent on local configuration would be the ones left there.
- **Wire the three through the existing copy-to-root pattern**, for consistency with the surrounding jobs — rejected: two of them resolve their schema directory from their own module path and fail silently when it is wrong, so this buys visual consistency at the price of three green jobs that inspect nothing. See D7b.
- **Land the three CI invocations without `--block`, then flip once any backlog is cleared** — rejected: it recreates "advisory in CI, blocking locally" as a deliberate state rather than an accident, and a soak with no committed end date is indistinguishable from the gap this ADR closes. D7 measures the backlog and clears it before the invocation lands instead.
- **Move risk-map validation into a single `pre-commit run --all-files` CI job** — genuinely attractive, and more so under D7: it delivers coverage *and* parity by construction, needs no per-validator file lists (D7a), runs the scripts in place (D7b), and eliminates the copy-to-root problem (D5) outright. Rejected here because it collapses the per-job `status` outputs that the workflow's summary job consumes, making it a workflow-topology change rather than a strictness change. The price of rejecting it is that D1's invariant must be held by a test rather than guaranteed by construction. Worth revisiting as its own ADR.

## Consequences

**Positive**

- The merge decision no longer depends on a contributor's local configuration. What CI enforces is what the repository enforces.
- Three checks that could previously fail only on a contributor's machine become repository-enforced (D7): identification-question structure, the YAML prose authoring subset ([ADR-017](017-yaml-prose-authoring-subset.md)), and prose reference integrity ([ADR-016](016-reference-strategy.md)). Those ADRs' contracts gain a gate that does not depend on local setup.
- The warn-only tier becomes real. Controls↔components mirror drift and category/subcategory nesting violations can no longer reach `main` or `develop`.
- The rule is general and quantifies over pre-commit's blocking hooks, derived from `.pre-commit-config.yaml` ([D9](#d9-the-governed-set-is-derived-from-pre-commit-configyaml-not-declared-in-d1s-table)), rather than a fixed validator list, so the next validator that grows a strictness flag has a stated answer instead of a fresh debate, and any warn-only check added later is governed on arrival rather than needing its own decision.
- Schema-integrity axis: closes a path by which malformed cross-references between controls, components, risks, and personas could pass CI. The change strictly narrows what merges.
- No new dependency, no new network fetch, no new workflow permission, and no new use of `secrets.*`. Supply-chain and workflow-exposure surface are unchanged.

**Negative**

- CI can now fail on findings that previously passed silently, including on branches opened before this lands. The failure output is per-warning (each is printed before the unified exit line at `:347`), so messages are actionable, but the first occurrence will surprise someone.
- D7 is the sharp end of that. It makes three validators blocking that have never gated anything, so any findings they hold have accumulated unseen and their volume is not known from this decision. Whether D7 is a one-line workflow change or the front end of a content cleanup is settled by measurement during implementation, not here. D2 and D4 carry measurements; D7 deliberately does not claim one.
- The scope of D7 is a cost as well as a benefit: three checks that contributors could previously push past now block merges, and the prose validators in particular operate over authored English rather than structured fields, where a finding is more likely to be arguable than a broken cross-reference is.
- The invariant is only as strong as the test that holds it, and the natural shape of that test — compare the two surfaces where they overlap — passes on the coverage gap. D1's testable requirement names this explicitly because it is the way the gap returns quietly.
- The warn-only tier loses any "soak" capability: there is no longer a way to land a check in observe-only mode in CI while a backlog is cleaned up. This was already true locally; the decision extends it rather than introducing it.
- D3 creates a rule that is invisible at the call site — nothing in `validate_riskmap.py` prevents passing `--block` with `--to-graph`, and the failure it produces is misleading rather than loud. The prohibition depends on the test named in D3 to hold.
- D5 knowingly leaves a fragile arrangement in place, and with it the class of bug that motivated the general rule.

**Follow-up**

- Replace copy-to-root with a `PYTHONPATH`-based invocation (D5). Sequenced after the working-directory-relative schema resolution it would otherwise collide with, since that fix assumes the current layout.
- Resolve the `sys.exit` ordering relative to graph emission (D3), or record that the current ordering is intentional and permanent.
- Implement both parts of the D1 test as a standing guard — coverage first, then monotonicity — so neither a future workflow edit nor a new `--block` hook landing without its CI counterpart can silently reintroduce either gap.
- Establish whether the file lists D7a requires can be derived from the hook `files:` regexes mechanically rather than transcribed into workflow YAML. A transcribed list drifts from the hook it mirrors, and it drifts in the permissive direction: a file the hook covers and the workflow list omits is unchecked in CI while appearing checked.
- Revisit the single `pre-commit run --all-files` CI job once the workflow-summary dependency on per-job outputs is addressed. Note that `--all-files` enumerates tracked files only, so a newly added file is invisible to it until first staged — a limitation to account for if that job is adopted as the verification surface.

No follow-up is owed for the deprecated-personas terminal-state question. D4's gate holds under either resolution — retention or removal from the id enum — so it neither decides that question nor waits on it.

## Addendum 2026-08-04: The governed set is derived from the config, not declared in D1's table

**Status:** Draft (maintainer to flip to Accepted)

Authored 2026-08-04 during review of [PR #470](https://github.com/cosai-oasis/secure-ai-tooling/pull/470), which carries this ADR and the implementation stacked on it. This addendum corrects a contradiction inside D1 and adds D9. It does not renumber D1–D8 — those numbers are cited across commit messages and PR titles — and it does not reset the ADR's status.

### The contradiction

D1 states its rule over blocking-ness:

> The rule quantifies over pre-commit's **blocking** hooks, not over a fixed list of validators, and not over the `--block` flag.

D1's *testable requirement*, four paragraphs later in the same decision, still scoped both parts to "each hook entry passing `--block`". That sentence was written before D8 existed and was not updated when D8 established blocking-ness as the quantifier. The implementation followed the testable requirement, so the governed set landed in two halves with two different sources of truth:

- **The flagged half** derives from `.pre-commit-config.yaml`. `--block` appears in a hook's `entry:` or `args:`, a config-level parse finds it, and the hook acquires its coverage obligation on arrival. This half is what D1 describes.
- **The flagless half** derives from *this document's own D1 instance table*. `ADR_GOVERNED_HOOK_IDS` is parsed out of the markdown table with a regex over backticked first cells; `UNFLAGGED_BLOCKING_HOOKS`, `SCOPED_UNFLAGGED_HOOK_IDS`, `FILE_ARGUMENT_BLOCK_HOOKS` and the workflow-`paths:` derivation `_governed_hook_input_paths` all flow from it. A validator is governed because a human wrote a row.

Two mutations measured the difference. An adversarial pass added a real `repo: local` hook that blocks unconditionally — no `--block`, no warn-only tier — with a tracked content file, no CI invocation, no workflow `paths:` entry and no table row. The full suite passed, 179 tests green. The same hook carrying `--block` fails three. An earlier pass deleted a table row together with its CI job, its corpus probe and its `paths:` line: also green, with the parametrized case count falling from 170 to 161 and nothing asserting the governed set's size.

This is the defect D8 itself diagnoses — *"a rule ranging over flag-bearing hooks cannot see those"* — reproduced one surface lower, over the table instead of over the flag.

Three further consequences follow from keying the register on table rows, and all three were live before this branch:

- **Third-party blocking hooks cannot be rows.** `check-jsonschema` blocks unconditionally and is declared ten times under one `id`, once per yaml/schema pair, so there is no per-entry id for a row to name. `check-metaschema` blocks and is a single entry. The test module reaches both by naming them in its own source instead — a second hand-maintained register, in a different file, with a different shape.
- **Four repo-local hooks that block unconditionally have never been rows:** `validate-control-risk-references`, `validate-lifecycle-stage`, `validate-workflow-uses-pinning`, `validate-issue-templates`. Each appears to have a CI counterpart; none is governed by anything that would notice if it stopped having one.
- **The ADR became a runtime input to the test suite.** `validate_python.yml` lists `docs/adr/037-ci-validation-authority-and-block-parity.md` in both `paths:` filters, because editing the table's rows changes what the suite asserts with no change to any workflow, script or config entry. Prose in an accepted decision record is not a good place for a value that decides what CI enforces.

And the table's own caption already denies it this role: it "is expected to grow without this ADR changing". For the flagged half that is true. For the flagless half it is false — the table growing is the only thing that puts a hook in scope, and the table did grow, from eight rows to twelve, during review.

### D9. The governed set is derived from `.pre-commit-config.yaml`, not declared in D1's table

#### D9a. Every hook entry is classified, and the classification is total

The candidate set is every hook entry in `.pre-commit-config.yaml` — every mapping under every `repos:` item, including entries from third-party repos and including repeated ids. Entries are keyed by `(id, name)`, not by `id`: `name` is unique per entry in this config and `id` is not, and keying on `id` alone is precisely why the ten `check-jsonschema` pairs could not be addressed at all.

Each entry carries exactly one class, declared in a registry keyed on that pair. Two classes:

- **verdict** — the hook's exit status is a finding about the tree. D1 governs it in full: a CI invocation of at least equal strictness, over at least the inputs the hook would see, with D7a, D7b and D7c binding how that invocation is built.
- **mutation** — the hook can fail a commit only by writing to the tree. Its own exit status is 0 and the framework fails the run because the tree changed. Formatters and the Mode B auto-stage generators ([ADR-005](005-pre-commit-framework.md)) are this class. Running such a hook in CI with a strictness flag is not its counterpart; regenerating and comparing against the committed artefact is.

An entry the registry does not classify **fails**, naming the entry and the two classes.

**Why a classification and not a bare predicate.** Blocking-ness is a property of the validator's behaviour: a hook blocks if a violation makes it exit non-zero, and `.pre-commit-config.yaml` records an entry, its `args:` and its `pass_filenames`, not whether a violation exits 1. Every hook in this config can fail a commit, so a predicate reading the config alone resolves to "all of them" and distinguishes nothing. The classification is the part a human supplies. What the derivation supplies is that the human must supply it **for every entry**, at the moment the entry lands, in a diff that sits next to the hook — rather than for the entries someone remembered to transcribe into a markdown table in another directory.

The registry is a sidecar rather than an inline key because pre-commit's config schema rejects unrecognized hook keys, so the class cannot be declared on the entry itself. The pattern is not new here: [ADR-005's 2026-05-08 addendum](005-pre-commit-framework.md#addendum-2026-05-08-hook-trigger-vs-read-set-invariant) already establishes a hook-keyed metadata table in the test suite (`_LOCAL_VALIDATOR_TRIGGER_COVERAGE`), chosen over parsing validator internals for the same reason. D9a adds the property that addendum's table does not have and does not need: totality against the config.

**Failing closed, and what it costs.** An unclassified entry blocks the suite until someone adds one registry line with a one-clause reason. It does not block until CI is wired. Classification and coverage are separate assertions, and only the verdict class carries the coverage obligation — so the cheap remedy is available separately from the expensive one. That split is what makes failing closed affordable: a contributor adding a formatter pays a line; a contributor adding a validator pays the CI invocation D1 has required of them since it was written.

#### D9b. The mutation class is closed; the verdict class is open

The two classes are deliberately asymmetric. `verdict` carries the obligation, so an entry may join it with no amendment — that is D1's "governed on arrival", now true for both halves. `mutation` escapes the obligation, so its membership is fixed by this addendum, and a ninth member requires an amendment to it.

Members at this date: `prettier-yaml`, `prettier-site-assets`, `ruff-format`, `regenerate-issue-templates`, `regenerate-frameworks-versionid`, `regenerate-graphs`, `regenerate-tables`, `regenerate-svgs`.

This puts the cost where the risk is. Mislabelling a validator as `mutation` is the only way a blocking hook escapes coverage under D9, no static test can distinguish a mislabel from a correct label, and it is now the single edit that cannot be made without editing this document.

#### D9c. D1's instance table is a dated record, not the register

The table records the twelve instances the decision was taken over, on the date it was taken, together with each one's CI state before the decision and what D1 required of it. That fourth and fifth column is the record of what the change consisted of, which a register keyed on the current config cannot carry — which is why the table is kept rather than deleted. It confers no governance, and nothing derives scope from it.

One assertion keeps it honest, in the direction that is cheap: every row must name a hook entry the config declares and the registry classifies `verdict`. A row naming a renamed or deleted hook fails, so the table cannot rot into a claim of coverage that no longer exists. The reverse direction — a blocking entry with no row — is deliberately **not** asserted. That is the state D9a makes safe, and asserting it would make every new validator an edit to this ADR, which is exactly what the table's caption disclaims.

### Alternatives Considered

- **Keep the table authoritative and add a bidirectional config-vs-table drift test.** Genuinely closes both measured mutations, and is the smallest change. Rejected on three counts: it makes landing any new blocking hook an edit to an accepted decision record, contradicting the caption's "expected to grow without this ADR changing"; it cannot express the ten `check-jsonschema` entries that share one id, so the third-party register stays hand-written in the test source regardless; and it entrenches the ADR as a runtime input to the test suite, keeping `docs/adr/037-*.md` in `validate_python.yml`'s `paths:` so that editing prose changes what CI enforces.
- **Config-derived with the table deleted.** Rejected: D9c already removes the table's authority, so deleting it buys no enforcement, and it discards the before/after columns that are the record of what this change was. It is also churn in a document whose open PR and stacked branch cite its rows.
- **Config-derived with a bare predicate and no classification** — treat every hook entry as verdict-class. Rejected: it sweeps the eight mutation entries into a coverage rule whose stated remedy is not their counterpart, and the result is either eight regeneration-and-diff jobs inside a strictness change or eight suppressions. Suppressions are a registry with less structure and no totality requirement.
- **Declare the class in `.pre-commit-config.yaml` itself.** Not available: pre-commit's config schema rejects unknown hook keys, so an inline `class:` fails `pre-commit validate-config`. A structured comment convention (`# cosai-ci: verdict`) would parse, but is invisible to the framework's own validation and silently absent when someone copies an entry without its comment.
- **Status quo plus a size pin on the governed set** — assert the parametrized case count. Rejected: it catches the deletion mutation and not the addition mutation, which is the more likely one and the one D1 exists to prevent. A count pinned to a literal also drifts to whatever the table says at the next intentional edit, which is the moment it stops meaning anything.

### Consequences

**Positive**

- Both measured mutations fail. The added flagless hook fails classification before any coverage question is reached; the deleted row cannot shrink the governed set, because the set is the config's and the hook is still declared in it.
- Third-party blocking hooks fall under the same derivation as repo-local ones. The hand-written `check-jsonschema` / `check-metaschema` names in the test source stop being a second register.
- The ADR stops being a runtime input to the test suite. Once nothing derives scope from the table, `docs/adr/037-*.md` leaves `validate_python.yml`'s `paths:` filters, and prose edits stop changing what CI enforces.
- Pre-commit-hook-safety axis: this is the rule that prevents a hook landing with no CI counterpart, and it is the surface a contributor's local state can otherwise decide. Deriving it from the config is what makes "governed on arrival" a property of adding the hook rather than of remembering the table.
- No new dependency, no new workflow permission, no new use of `secrets.*`. Supply-chain and workflow-exposure surface are unchanged.

**Negative**

- The registry is still a declaration. D9 does not eliminate human declaration; it makes the declaration total, adjacent to the hook, and failing-closed. That is a weaker guarantee than "derived from behaviour", and it should not be described as a stronger one.
- Classification is a judgement, and the permissive misclassification — labelling a validator `mutation` — is invisible to a static test. D9b raises its price to an ADR amendment rather than eliminating it.
- Four verdict-class hooks that no table row ever named enter scope. Their CI counterparts appear to exist, but "at least the inputs the hook would see" is a measurement this addendum does not claim, in the same posture D7 takes on its own three.
- The mutation class's own CI obligation is not decided here, so D9a's classification is total while D1's coverage clause reaches only the verdict class. Until that is closed, `mutation` is a class with a defined membership and an undefined obligation.
- One more file must be kept current when a hook lands. The failure mode is loud rather than silent, which is the trade this addendum makes deliberately.

**Follow-up**

- Measure the four newly in-scope verdict hooks against D1's coverage clause rather than assuming their apparent counterparts satisfy it: `validate-control-risk-references` against `validation.yml`'s control-risk job; `validate-lifecycle-stage` against whether default-mode `validate_riskmap.py --force --block` meets the dedicated hook's contract per [ADR-005's 2026-05-08 addendum](005-pre-commit-framework.md#addendum-2026-05-08-hook-trigger-vs-read-set-invariant); `validate-workflow-uses-pinning` against `validate_workflows.yml`; `validate-issue-templates` against `validate-issue-templates.yml`. Where a counterpart is narrower than the hook's `files:` set, `scripts/tools/hook_file_list.py` is the derivation D7a already provides.
- Decide the mutation class's CI obligation — a regenerate-and-diff job per entry, or an explicit statement that artefact drift is outside D1's scope. `validate_tables.yml` is the existing instance of the former; `prettier-site-assets` has no evident counterpart. This is the one clause D9 leaves open, and it is open by name rather than by omission.
- Retire the hand-written third-party hook names in the test module once D9a's `(id, name)` enumeration covers the `check-jsonschema` pairs.
- Remove `docs/adr/037-ci-validation-authority-and-block-parity.md` from `validate_python.yml`'s `paths:` filters and from the test module's derivation-source set once nothing derives scope from the table.
