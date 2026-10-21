# ADR-038: Tier 2 catalogue data input — vendored, checksummed per-edition framework catalogues

**Status:** Draft
**Date:** 2026-10-01
**Authors:** Architect agent, with maintainer review
**Implements:** [ADR-027](027-framework-versioning-and-mapping-convention.md) D5 Tier 2. This ADR covers only the data half: where the per-edition catalogues come from, where they live, and how they are verified.
**Extends:** [ADR-027](027-framework-versioning-and-mapping-convention.md) D10c, for adjudicated frameworks only (D7a).

---

## Context

[ADR-027](027-framework-versioning-and-mapping-convention.md) D5 split drift detection into two tiers. Tier 1 shipped with the pinning migration. Tier 2 was deferred: it *"requires importing or caching per-version catalogs and is explicitly a follow-up"*. Tier 1 confirms that a value's version token is one the registry recognizes (`version` ∪ `priorVersions`). It cannot tell whether the value's id exists in the edition the token names. A value that pairs a registered token with an id the named edition never contained therefore passes every Tier 1 gate. Tier 2 exists to close that gap. The registry-currency work tracked in [#562](https://github.com/cosai-oasis/secure-ai-tooling/issues/562) (the ADR-027 D10a tracking issue for the MITRE ATLAS bump) ships Tier 2 as a blocking gate.

The data ADR-027 lacked at adoption now exists. The `mitre-atlas/atlas-data` project publishes `dist/manifest.yaml`, which lists every release. Each release entry carries `release`, `release-date` and a `versions` list of `{format-version, path}`.

- **Every release ships a v6 catalogue** at `dist/v6/ATLAS-<release>.yaml`, with format-version `6.0.0`. On 2026-10-01 the manifest listed 37 releases, the newest `2026.09`.
- **The v6 files for releases before 2026.05 are retroactive.** The v6 format arrived with release 2026.05, and the v6 files for earlier releases were produced at that point by a format converter from the earlier formats. Upstream can re-run that converter, so the bytes of an older edition's v6 file are not guaranteed to stay fixed after publication.
- **Some releases also ship a legacy file under `dist/legacy/`.** Each legacy format-version is carried by exactly one release.
- **The registry's token `5.0.1` is a format-version, not a release.** It is carried only by release `2025.10` (`release-date` `2025-10-15`), alongside that release's v6 file.
- **`dist/ATLAS.yaml` is deprecated**, frozen at 5.6.0.
- **v6 shape.** The top-level keys are `format-version`, `collection`, `matrix`, `tactics`, `techniques`, `mitigations`, `case-studies` and `relationships`. Pin-target ids are the keys of the `techniques:` and `mitigations:` maps. `collection:` and `matrix:` are metadata blocks, not id namespaces.
- **Sizes.** techniques ∪ mitigations is 156 ids at 2025.10, 236 at 2026.08 and 248 at 2026.09. The v6 files are 319,578, 808,834 and 841,482 bytes respectively.

None of the other five registered frameworks (`nist-ai-rmf`, `owasp-top10-llm`, `stride`, `iso-22989`, `eu-ai-act`) publishes a machine-readable per-edition id catalogue.

Several existing decisions bound how Tier 2 may obtain this data:

- **Tier 2 is a blocking hook, so [ADR-037](037-ci-validation-authority-and-block-parity.md) (Draft) D1 governs it.** It runs `--force --block` in pre-commit and in the required `validation.yml` job. The parity harness in `scripts/hooks/tests/test_ci_block_parity.py` (`BLOCK_PROBES`) runs every blocking validator twice and compares exit codes. It invokes the validator with a temporary corpus directory as the working directory, passing paths through each probe's `options` and `positionals`.
- **A gate that exits 0 on input it could not read is vacuous** (ADR-037 Context and D7b: a check can run, report success, and verify nothing). An unreadable catalogue must therefore fail the run. If that input came from the network, a transient outage would turn a required check red.
- **No validator under `scripts/hooks/` performed network I/O.** Hooks run on every contributor's machine, so a hook that fetches is a supply-chain vector.
- **Two hooks act on files by path, and both shape where a catalogue can live.** `prettier-yaml` (`files: ^risk-map/yaml/.*\.ya?ml$`) rewrites any YAML under `risk-map/yaml/` and stages the result. A vendored catalogue there would lose its upstream bytes on its first commit, and the hook would still exit 0. `validate-neutrality` (`files: ^scripts/(agents|skills)/`) is blocking and scans with a vendor-term denylist. A third-party catalogue under a skill directory would be scanned as authoring prose.
- **[ADR-031](031-authoring-time-agents-and-skills.md) D4 splits out-of-repo framework knowledge by volatility.** STABLE terms are pinned to dated snapshots. VOLATILE specifics, *"whether a given MITRE ATLAS technique ID still exists"*, are *"checked at use time … not trusted from a snapshot"*. D4 is scoped to a single consumer, the framework-mappings audit skill.
- **[ADR-035](035-pinned-sources-manifest.md) (Draft) is the repository's pattern for pinned, dated external material.** Its D1 excludes from `sources.yaml` *"the volatile per-technique identifiers ADR-027 governs"*. Its D5a routes a file to a branch by its role rather than by the directory it sits in.
- **The routing ruling recorded in [#563](https://github.com/cosai-oasis/secure-ai-tooling/issues/563) sends framework-registry work to `main` by role.** [ADR-002](002-branching-strategy.md) routes `risk-map/yaml/**` and `risk-map/schemas/**` to `develop` by directory. #563 tracks that divergence as known drift.
- **ADR-027 D10c sets registry cadence as "on-publish / on-demand, not scheduled".** An external publication is one of its triggers. ATLAS publishes monthly, so for a framework whose every registered edition carries a vendored catalogue, an on-publish reading of D10c would grow the repository by one catalogue a month.
- **ADR-027 D2c defines `priorVersions` as retired editions CoSAI "still recognizes as valid pin targets".** It provides no removal path.

## Decision

Tier 2 reads **vendored, verbatim copies** of the upstream per-edition catalogues. They are committed under `scripts/framework_catalogues/<framework-key>/` and guarded by a sha256 record that the validator checks on every read. No hook, CI job or validator fetches catalogue data. The maintainer adds a catalogue as part of the ADR-027 D10 registry bump that registers its edition, and an adjudicated framework is bumped on corpus need, not on every upstream release (D7a). A catalogue is retained for as long as its edition is registered. Which frameworks Tier 2 adjudicates is declared by a table in the validator. Today the table holds only `mitre-atlas`.

### D1. Vendored, never fetched by a gate

The catalogue input is committed to the repository under `scripts/framework_catalogues/`. The validator (`scripts/hooks/precommit/validate_mapping_catalogue.py`, hook id `validate-mapping-catalogue`) reads only local files. No pre-commit hook, CI job or `scripts/tools/validate-all.sh` invocation in the Tier 2 path performs network I/O.

Fetching happens in exactly one place: the maintainer's refresh step at a registry bump (D7). It is a reviewed action whose output is committed, never a runtime dependency. This is the hybrid shape: vendoring for the gate, a human-run refresh for currency.

#### D1a. Reconciliation with ADR-031 D4

D4 binds the audit skill, not validators. The question it answers still applies here, and a vendored dated catalogue does not contradict it, for the following reasons.

D4's VOLATILE half is about **currency**: does an id still exist in the framework as it stands today? Tier 2 asks a different question: was the id present in the specific published edition that a value's token names? An edition's membership is a property of that edition, which puts it in the class D4's STABLE half assigns to dated snapshots. Re-fetching it on every commit would re-verify what does not change between bumps.

The volatile question is still answered, and still not from a snapshot:

- **New editions** enter only through the ADR-027 D10 bump, which is when the maintainer fetches (D7).
- **Values that lag the current edition** are reported `valid-but-superseded` (ADR-027 D5a), as information.
- **The audit skill's use-time live verification** under D4 is unchanged.

Tier 2 never claims that a value is current. It claims only that the value is true of its own edition.

The bytes that render an edition are less fixed than its membership: the v6 files of releases before 2026.05 are converter output that upstream can regenerate (Context). The sha256 record (D4) detects changes to the local copy, not to upstream. An upstream re-publication is detected at the next bump, because D7 re-copies and re-verifies every vendored file, not only the bump's additions.

### D2. Location, layout and routing

The catalogue root is `scripts/framework_catalogues/`, a sibling of `scripts/agents/`, `scripts/skills/`, `scripts/TEMPLATES/` and `scripts/hooks/`. The location is chosen for three reasons:

- **Discoverable.** It sits beside the other top-level `scripts/` surfaces rather than several levels inside the hook package.
- **Data, not code.** The catalogues are third-party data, so they do not belong inside a Python package directory. `scripts/TEMPLATES/` is the existing precedent for non-code data under `scripts/`.
- **Shared by role, not owned by one consumer.** Tier 2 is the only consumer today. Later read-only consumers, such as `scripts/framework_mapping_maintainer.py` or the audit skill, can read the directory without reaching into the hook package.

The validator's default resolves the root from its own `__file__` (D3a). There is one subdirectory per adjudicated framework key. For `mitre-atlas`, at `scripts/framework_catalogues/mitre-atlas/`:

| File | Content | Read by the validator |
|---|---|---|
| `manifest.yaml` | Verbatim copy of upstream `dist/manifest.yaml` | yes |
| `ATLAS-<release>.yaml` | Verbatim copy of upstream `dist/v6/ATLAS-<release>.yaml`, one per registered edition (D3c) | yes |
| `SHA256SUMS` | sha256 record for `manifest.yaml` and every catalogue file in this subdirectory (D4). It does not list itself, `SOURCE` or `LICENSE`, and it covers nothing outside the subdirectory | yes |
| `SOURCE` | Upstream repository URL, the upstream commit the files were copied from, and the upstream data licence | no (provenance for reviewers) |
| `LICENSE` | Verbatim copy of the upstream `LICENSE` (Apache License 2.0, "Copyright 2021-2026 MITRE"), which Apache-2.0 §4(a) requires to accompany redistributed files | no |

"Verbatim" means byte-identical to the upstream file at the recorded commit, with no reformatting, re-indentation or line-ending change.

**No hook other than Tier 2's own selects this path.** Checked against `.pre-commit-config.yaml`:

- **Anchored elsewhere.** The per-pair `check-jsonschema` entries, `check-metaschema`, `validate-all-yaml-on-master-schema-change`, both prettier hooks, every risk-map validator and generator, and `regenerate-issue-templates` are anchored under `risk-map/`, `site/`, `.github/` or `scripts/TEMPLATES/`.
- **`validate-neutrality`** is anchored at `^scripts/(agents|skills)/`. Its policy re-scan hook names two `.py` files.
- **`ruff` and `ruff-format`** carry no `files:` in the configuration and would otherwise select by the `types_or` of their remote hook manifest. They carry `exclude: ^scripts/framework_catalogues/` (D6 item 11), so they never select the directory, whatever file types it holds.

D6 item 8 enforces the whole property from the configuration alone.

**Routing: `main`.** The directory is the oracle of a registry-class validator, which the role-based ruling in #563 sends to `main`. It is also under `scripts/`, which ADR-002's directory rule sends to `main`. The two rules agree, so this path adds no surface to the ADR-002 drift that #563 tracks. Catalogues reach `develop` through the ordinary `main` → `develop` sync. That is the same path the registry and schema already take.

### D3. Read contract

#### D3a. Inputs

Every input is a CLI option. Each default is anchored on the validator's `__file__`, never on the process working directory. The validator sits at `scripts/hooks/precommit/validate_mapping_catalogue.py`, so the `scripts/` directory is two levels above its own directory, and the repository root one level above that:

- `--frameworks` defaults to `risk-map/yaml/frameworks.yaml`.
- `--schema` defaults to `risk-map/schemas/frameworks.schema.json`.
- `--catalogue-dir` defaults to `scripts/framework_catalogues/`, resolved from `scripts/hooks/precommit/` up to `scripts/` and then down.
- The positional content paths default to the four consumer YAMLs, the shape the Tier 1 validators use.

#### D3b. Token resolution

A pin token resolves against the vendored `manifest.yaml` in two lookups:

1. **By release.** Use the entry whose `release` equals the token.
2. **By format-version.** Otherwise, use the *unique* entry that has a `versions[].format-version` equal to the token.

The catalogue read is always that entry's v6 file. A token that matches no entry, or more than one, is **unresolved**. For example, `6.0.0` is carried by every release, so it is unresolved. Under these lookups `5.0.1` resolves to release `2025.10`, and a release token such as `2026.09` resolves to itself.

A value whose token is unresolved is reported `invalid` with that reason. That per-value class is a violation, and it stays distinct from the registry-level check in D3c. Because D3c runs first, a tree that reaches value adjudication has every registered token resolved. The per-value class is kept so that no value falls through without a verdict.

#### D3c. Required set

Before adjudicating any value, the validator computes each adjudicated framework's registered token set: the current `version` plus every `priorVersions` member. `priorVersions` members are versionIds (`mitre-atlas@5.0.1`), not tokens. The validator strips them with the existing helper `known_versions` in `scripts/hooks/precommit/framework_mapping.py`, which returns `{version}` ∪ the part after the last `@` of each `priorVersions` entry. It then checks every token in that set:

- **The edition must resolve** under D3b to exactly one manifest entry. A registered edition that does not resolve is a **registry/manifest inconsistency and a read error** (exit 2, D4a). It is never downgraded to per-value `invalid`, and it does not depend on any value pinning the edition.
- **The edition's v6 catalogue must be present**, listed in `SHA256SUMS` and verified against it. A missing or unlisted catalogue is a read error.

The requirement is **eager**: it covers every registered edition, whether or not any value pins it. A registry bump that flips `version` without refreshing the vendored manifest leaves the new token unresolved. A bump that refreshes the manifest without adding the catalogue leaves the catalogue missing. Both exit 2 at the bump commit.

#### D3d. Parsing

Files are parsed with a safe YAML loader. A catalogue's id set is the union of the keys of its top-level `techniques:` and `mitigations:` maps. A catalogue in which either map is absent, is not a mapping, or is empty is unparsable, a read error (exit 2). Tactics and case studies are not pin targets.

### D4. Provenance guard and fail-closed reads

`SHA256SUMS` uses the GNU coreutils format, one `<64-hex-digest>  <basename>` line per file. Its scope is the framework subdirectory: it lists `manifest.yaml` and every catalogue file there. It does not list itself, `SOURCE` or `LICENSE`. The registry, the schema and the content YAMLs are outside its scope; they are tracked, reviewed sources, not vendored copies.

The validator checks the record in two stages, one before parsing and one after:

1. **Verify the record.** Read `SHA256SUMS`. Every listed file must be present and match its digest, and `manifest.yaml` must be listed. Nothing in the subdirectory is parsed before this stage passes.
2. **Parse the manifest and the registry.** The manifest is parsed only after its digest is verified. The registry is a tracked source and is not in the record.
3. **Require the registered editions.** For each token in the registered set (D3c), the resolved edition's catalogue must be listed in the record, and so already verified in stage 1, before it is parsed.

The required set cannot be known until the manifest and the registry are parsed, which is why the completeness check follows parsing while the digest check precedes it. Running `sha256sum -c --strict SHA256SUMS` from the framework's directory reproduces stage 1 by hand.

**Every read failure is a read error.** The read errors are:

- a missing, unreadable or unparsable `manifest.yaml`, `SHA256SUMS` or required catalogue, including a manifest entry of the wrong shape;
- a missing, unreadable or unparsable registry, schema or content file named on the command line or by default, including a schema whose pinned pattern does not compile and a content file with no entity list (empty, not a mapping, or no top-level list of entity mappings);
- a digest mismatch;
- a required file absent from the record, a record line that is malformed or duplicated, or a record name that is not a bare file name in this subdirectory;
- a registered edition that does not resolve (D3c);
- the D5 table errors.

The message names the file and, for a mismatch, both digests.

**Byte stability.** A root `.gitattributes` entry `scripts/framework_catalogues/** -text` exempts the directory from end-of-line conversion. It is necessary, not defensive: with `core.autocrlf=true` a checked-out catalogue's digest changes, and with `-text` it stays byte-identical. Without the entry, such a checkout would fail the digest check on every run.

#### D4a. Exit contract per flag

The validator has a warn tier and a `--block` tier, per ADR-037 D1 monotonicity:

- **Without `--block`,** each `invalid` value prints its detail lines, the summary line prints, and the process exits 0.
- **With `--block`,** any `invalid` value exits 1.
- **A read error** (every class listed in D4) exits 2, identically with and without `--block`. Under `--force`, the validator never exits 0 on a read error.
- **Output is identical in both modes.** The summary line with its per-verdict counts and every `invalid` detail line print with and without `--block`. Only the exit code differs.
- **`valid-but-superseded` and `skip`** are informational in both modes.

**`--force` is the enabling argument.** Without it, the validator reads nothing, prints that it examined nothing, emits no summary line, and exits 0. That is consistent with the enabling-argument rule: no input was read, so there is no read error to report. With it, the validator scans its full read-set unconditionally, with no staged-file gate. Every invocation in the tree passes `--force --block`: the hook entry, the CI job and the `validate-all.sh` line. The warn tier and the no-`--force` mode exist for the parity harness's contract. No invocation uses them.

#### D4b. Why Tier 2 is flagged, unlike its Tier 1 siblings

The three ADR-027 Tier 1 validators are flagless blocking validators: ADR-037 D8 instances, probed through `UNFLAGGED_PROBES`. Tier 2 takes the `--block` shape and a `BLOCK_PROBES` entry instead. The reason lies in the current implementation state of the parity harness, not in ADR-037's text:

- **A flagless blocking hook is today governed only through ADR-037's D1 instance table.** ADR-037 D9a/b requires an unclassified hook entry to fail, but D9 is not implemented yet; that work is [#484](https://github.com/cosai-oasis/secure-ai-tooling/issues/484), which is open. Until it lands, the harness's flagless set `_FLAGLESS_GOVERNED_HOOKS` in `scripts/hooks/tests/test_ci_block_parity.py` is derived from the D1 table's id list, so a new flagless hook the table does not name creates no CI-coverage, in-place or probe obligation.
- **A `--block` hook** is derived from `.pre-commit-config.yaml` by `test_ci_block_parity.py`. The moment the hook entry lands, the CI, aggregate and probe obligations of D6 fire, with no table edit. The trigger-filter obligation of D6 item 5 is the exception: the general trigger test reads the D1 table, so item 5 is enforced by a test targeted at this hook until ADR-037 D9 lands.

Once #484 lands, a flagless hook would need one classification line to acquire the same obligations, and the gap above closes. The flagged shape then keeps one advantage: the behavioural probe that runs the validator in the warn and `--block` tiers and requires the exit code to change on an injected violation (D6 item 7). Its cost is the per-flag contract in D4a and one probe entry.

### D5. Adjudicated-set registration: a table in the validator

The set of framework keys Tier 2 adjudicates is a module-level table in `validate_mapping_catalogue.py`. It maps each key to its catalogue subdirectory, its token resolver and its id parser. Today it holds one entry, `mitre-atlas`.

- **Values of a framework key not in the table** are `skip`. They are counted in the summary line and never receive a verdict.
- **A table key absent from `frameworks.yaml`** is a read error (exit 2).
- **A table key whose catalogue subdirectory is missing** is a read error (exit 2).

Adding a framework to Tier 2 means adding a table entry, its resolver and parser, their tests, and a catalogue subdirectory that meets D2-D4. It needs no amendment to this ADR, provided that framework's upstream publishes per-edition files. A framework whose upstream does not would need its own decision.

### D6. Wiring obligations

Every item lands in the same commit as the hook entry, per ADR-037 D1. Because Tier 2 is a `--block` hook (D4b), the test suite derives most of these obligations from the hook entry itself. A partial landing is therefore red. Each item names the tests that enforce it.

1. **Hook entry.** The `validate-mapping-catalogue` entry carries `--force --block` and `pass_filenames: false`. Its `files:` covers the full read-set ([ADR-005](005-pre-commit-framework.md) addendum 2026-06-08: trigger-set ⊇ scanned ∪ oracle). That read-set is the Tier 1 mapping hooks' alternation (the four consumer YAMLs, `frameworks.yaml`, `frameworks.schema.json`) plus the prefix `scripts/framework_catalogues/`. `SOURCE` and `LICENSE` match the prefix as trigger-only members: the validator does not read them. *Enforced by* `TestMappingValidatorOracleTrigger` in `test_precommit_hook_install.py`, with `validate-mapping-catalogue` added to `_MAPPING_HOOKS`. It is also extended to assert that the regex matches a synthetic catalogue path under `scripts/framework_catalogues/`.
2. **Required hook id.** `validate-mapping-catalogue` joins `_REQUIRED_HOOK_IDS` in `test_precommit_hook_install.py`. *Enforced by* `TestRequiredHookIds::test_all_required_ids_present`, so deleting the hook entry, which would also withdraw every derived obligation, is itself red.
3. **CI job, in place.** `.github/workflows/validation.yml` gains a job whose step runs exactly `python3 scripts/hooks/precommit/validate_mapping_catalogue.py --force --block`. The step runs at the script's real path from the repository root, never through copy-to-root (ADR-037 D7b). It sets a status output and exits 1 on failure, in the shape of the existing `mapping-drift-validation` job. The argv carries no explicit file list. ADR-037 D7a's explicit-input rule is written for file-argument validators. Tier 2 is a default scanner over its `__file__`-anchored read-set, the ADR-037 D8 shape. *Enforced by:*
   - `TestStrictnessCoverage::test_ci_invokes_every_block_hook_with_block` and `TestStrictnessMonotonicity`;
   - `TestPrecommitValidatorsRunInPlace`;
   - `TestCIInvocationCatchesViolation::test_ci_invocations_carry_enabling_arguments`, which requires `--force` in the CI argv;
   - `TestCIInvocationCatchesViolation::test_derived_ci_arguments_fail_on_injected_violation`, which requires the CI argv to exit non-zero on the poisoned probe corpus and print the probe marker;
   - `TestGateStepFailsTheJob`;
   - `TestGateStepsRunFromRepositoryRoot`.
4. **Aggregate gate.** The job is added to `validation-summary`'s `needs:`. Its result is read in the summary's aggregation, with its own summary line. *Enforced by* `TestAggregateGateReflectsEveryGateJob::test_summary_job_needs_and_reads_every_gate_job`.
5. **CI path filters.** `on.pull_request.paths` and `on.push.paths` in `validation.yml` both cover three things:
   - the validator script;
   - `scripts/framework_catalogues/**`, listed explicitly because the filters carry no `scripts/**` glob;
   - every module in the validator's local import closure. That closure includes `scripts/hooks/precommit/framework_mapping.py`, which both filters already list and which must stay listed.

   *Enforced by:*
   - `TestWorkflowTriggerCoverage::test_gate_workflow_triggers_on_everything_that_defines_the_gate`, for the script;
   - `TestWorkflowTriggerCoverage::test_catalogue_workflow_triggers_on_the_catalogue_hook_inputs`, for every tracked file the hook's `files:` selects, for a synthetic catalogue path of an unregistered edition, and for the validator's local import closure, on both events. It reads the hook from `.pre-commit-config.yaml` by id. Its closure resolver is pinned by `TestLocalImportClosureResolvesAllImportForms`.

   `TestWorkflowTriggerCoverage::test_gate_workflow_triggers_on_the_corpus_its_governed_hooks_scan` reads its hook set from ADR-037's D1 table, in which this hook has no row (ADR-037 D9c). It reaches this hook only once ADR-037 D9 derives the governed set from the configuration ([#484](https://github.com/cosai-oasis/secure-ai-tooling/issues/484)).
6. **Trigger-coverage registry.** `_LOCAL_VALIDATOR_TRIGGER_COVERAGE` in `test_precommit_hook_install.py` registers the fixed-name members:
   - the four consumer YAMLs;
   - `frameworks.yaml` and `frameworks.schema.json`;
   - `scripts/framework_catalogues/mitre-atlas/manifest.yaml` and `scripts/framework_catalogues/mitre-atlas/SHA256SUMS`.

   Its comment states that everything except the four consumer YAMLs is an oracle (ADR-005 addendum 2026-06-08, Enforcement). *Enforced by* `TestTriggerCoverageInvariant::test_all_local_pass_filenames_false_hooks_are_registered`.

   Per-edition catalogue filenames change at every bump, so they are not registered by name. The directory prefix in the hook's `files:` and the synthetic-path assertion in item 1 cover them. A registry bump therefore edits no test. An edit to a catalogue that leaves `SHA256SUMS` unchanged still triggers the hook, and the hook then fails the digest check.
7. **Block-parity probe.** The `BLOCK_PROBES` entry in `test_ci_block_parity.py` has five parts:
   - **`enabling_args=("--force",)`.** `--force` goes here, not in `options`.
   - **`options`** pass `--frameworks`, `--schema` and `--catalogue-dir`, all pointing into the temporary corpus.
   - **Non-empty `positionals`** name the temporary corpus's four content files. The harness passes positionals in the CI-tier run too, and that is how the CI argv sees the poisoned corpus.
   - **The corpus** carries a copy of the catalogue directory: `manifest.yaml`, `SHA256SUMS` and the catalogue of every edition its registry registers. The poison is one id absent from its pinned edition.
   - **The `marker`** is a string from that poisoned value's detail line.

   *Enforced by* `TestBlockFlagChangesBehaviour`:
   - `test_every_block_validator_has_a_behavioural_probe`;
   - `test_block_flag_changes_exit_code_on_injected_violation`, which requires the warn run to exit 0 and name the marker, and the `--block` run to exit non-zero;
   - `test_clean_corpus_exits_zero_with_and_without_block`;

   and by the item 3 `TestCIInvocationCatchesViolation` tests.
8. **Exclusivity guard, decided from the configuration alone.** A test computes the set of hooks pre-commit would select for each tracked path under `scripts/framework_catalogues/`, and for one synthetic catalogue path there. It asserts that the selected set is exactly `{validate-mapping-catalogue}`. The guard reads only `.pre-commit-config.yaml`: it reads no remote hook manifest and is not coupled to any hook's `rev`. It runs offline, which suits the pytest CI job, which installs only `requirements.txt` (bringing `identify` with `pre-commit`).
   - **What it evaluates.** The top-level `files` and `exclude`, and each hook's `files` and `exclude` as written in the configuration. Each hook's `types`, `types_or` and `exclude_types` are evaluated only where they are written in the configuration. They are matched against the tags `identify.tags_from_filename` assigns to the path. `tags_from_filename` is used because `tags_from_path` raises on a path that does not exist, and the synthetic path does not.
   - **Local hooks** are fully defined in the configuration, so their selection is fully decided there.
   - **Remote hooks.** A remote hook's manifest may declare `files` or types that the configuration does not show. A remote hook is therefore decided only when the configuration carries either a `files:` that does not match the catalogue paths or an `exclude:` that covers them. A remote hook with neither fails the guard, naming the hook. It is not skipped, and it is not evaluated against a guessed manifest. The fix is an `exclude:` for the catalogue root on that hook, which also protects the directory at run time.

   **Why full selection with an exact set.** A guard over `files:` alone has two options for type-selected hooks, which have no `files:` and so match every path:
   - count them, and be red on arrival;
   - exempt them, and stay blind to the next type-selected hook. `check-yaml`, `end-of-file-fixer` and `mixed-line-ending` would each select catalogue files, and the last two rewrite bytes.

   Under the exact-set assertion and the remote-hook rule, such a hook's arrival turns the guard red until it carries an `exclude:` for the catalogue root.
9. **Byte stability.** The `.gitattributes` entry from D4. *Enforced by* `TestCatalogueByteStability` in `test_precommit_hook_install.py`, which requires `git check-attr text` to resolve to `unset` for every tracked catalogue path and for a synthetic catalogue path.
10. **Manual sweep.** `scripts/tools/validate-all.sh` invokes the validator with `--force --block` as the whole condition of an `if` gate, with no `||`, `&&` or pipe. *Enforced by* `test_validate_all_tool.py::test_sweep_includes_adr027_validators`, extended to name the validator.
11. **Formatter exclusion.** The `ruff` and `ruff-format` entries in `.pre-commit-config.yaml` each gain `exclude: ^scripts/framework_catalogues/`. These are the two remote hooks that carry no `files:` today. *Enforced by* item 8: without the `exclude:`, each fails the guard as an undecided remote hook.

**Landing checks:**

- `pre-commit run --all-files` leaves the directory byte-identical.
- The validator's digest check passes on the committed tree.
- Per ADR-037 D7c (and the ADR-025 D10 rule it applies), the CI job's red case is observed from the job itself before the job is accepted as covering anything: an id injected that is absent from its pinned edition makes the job fail. The derived test in item 3 is the standing counterpart, not a substitute for that observation.

### D7. Refresh at a registry bump

Each ADR-027 D10 bump of an adjudicated framework adds the new edition's catalogue. This decision adds a step to both bump paths:

- **D10a lightweight path.** The step joins the actions the lightweight registry edit performs ("advance `version`, regenerate `versionId`, record lineage").
- **D10b full checklist.** The step extends step 1, the registry update, and a D10a tracking issue such as #562 carries it as a checklist item.

It is also what makes D10b step 3's *"Tier 2 (when catalogs exist)"* operative. Once this decision lands, catalogues exist, and step 3's drift sweep includes Tier 2.

The maintainer who owns the bump (ADR-027 D10c) does the following, in the same commit as the registry `version` flip or an earlier one:

1. **Copy the files.** Choose one upstream commit. From that commit, copy verbatim into the framework's subdirectory under `scripts/framework_catalogues/`:
   - `dist/manifest.yaml`;
   - `dist/v6/<file>` for the edition the bump registers;
   - `dist/v6/<file>` for every edition already vendored;
   - `LICENSE`.

   `SOURCE` then truthfully records one commit for every file. A diff to a previously vendored catalogue in this step is an upstream re-publication. The bump's description records it, and step 3 decides whether existing pins still hold against it.
2. **Record provenance.** Regenerate `SHA256SUMS` with `sha256sum` in text mode (`sha256sum --text`, which writes the two-space `<digest>  <name>` form; the binary-mode ` *name` form that some platforms emit by default is rejected by the validator) over `manifest.yaml` and every catalogue file in the subdirectory, excluding `SHA256SUMS`, `SOURCE` and `LICENSE`. Update `SOURCE` with the commit and the licence.
3. **Run Tier 2.** Run `--force --block` over the bumped tree. It must not exit 2.
4. **Record size.** The bump's description records the output of `du -sh` on the framework's subdirectory after the refresh.

The bump's reviewer then independently re-verifies **every** vendored file, not only the bump's additions:

- Fetch fresh copies of every vendored file at the recorded commit.
- Run `sha256sum -c --strict` against the committed `SHA256SUMS`.
- Byte-compare `LICENSE`, which the record does not cover.
- Confirm that no pre-existing `SHA256SUMS` line changed, except where the bump's description records and explains an upstream re-render. This is the mechanical detector for an upstream re-publication of an older edition.
- Confirm that every token registered before the bump still resolves to the same release under the refreshed manifest (D3b).

Because D3c requires every registered edition to resolve and its catalogue to be present, a bump that omits the manifest refresh or the catalogue exits 2 at the bump commit, not later at the first content PR that pins the new edition.

A fetch helper under `scripts/tools/` is permitted but not required. If one is added, it is invoked only by a maintainer, never by a hook or a workflow.

#### D7a. Bump cadence for adjudicated frameworks

ADR-027 D10c lists an external publication as one bump trigger. For a framework in the D5 table, this decision narrows that trigger and extends D10c accordingly: **an adjudicated framework's registry is bumped on corpus need**, when a contributor or maintainer needs to pin a value to an edition the registry does not yet carry. An upstream publication alone does not trigger a bump. A bump registers the edition the corpus needs and skips the intermediate releases; they are never registered and never vendored (D8).

Frameworks outside the D5 table keep D10c's cadence unchanged, because a bump costs them no vendored bytes.

Removing editions from `priorVersions` would cap the directory's size, but it is not available under this decision. ADR-027 D2c defines `priorVersions` as editions CoSAI still recognizes as valid pin targets and provides no removal path, so pruning requires a D2c amendment.

### D8. Retention

A catalogue is retained for as long as its edition is in the registry's `version` ∪ `priorVersions`. A catalogue is never pruned merely because no corpus value pins its edition any more. Tier 1 continues to accept new pins at any `priorVersions` edition, so Tier 2 must be able to adjudicate them. Pruning would turn such a content change into a read error.

A catalogue leaves only in the same commit that removes its edition from the registry. Whether an edition may ever leave `priorVersions` is an ADR-027 D2c question that this ADR does not decide (D7a). Releases the registry never registered are never vendored.

## Alternatives Considered

- **Fetch at runtime from upstream.** Rejected: it puts network I/O into a required gate. Under the fail-closed rule (D4a), an outage or rate limit becomes a red required check. The block-parity harness compares exit codes across two runs, and a network dependency makes that comparison nondeterministic. Offline contributors could not commit. It would also add a remote fetch to a hook that runs on every contributor's machine.
- **Fetch once and cache outside the repository** (a user cache directory or a CI cache). Rejected: the first run is still networked. The cache is untracked, so its contents are neither reviewed nor reproducible, and a poisoned or stale cache is invisible to the repository.
- **`risk-map/yaml/sources.yaml` ([ADR-035](035-pinned-sources-manifest.md), Draft).** Foreclosed by ADR-035 D1, which keeps ADR-027's per-technique identifiers out of `sources.yaml`. The manifest also records citation metadata for documents, not machine-readable id sets.
- **Under `scripts/hooks/precommit/framework_catalogues/`**, beside the validator. No hook collision. Rejected: it buries the directory several levels deep inside the hook package, where it is hard to find, and it couples data that other tools may read to one consumer's Python package.
- **Under `scripts/skills/audit-framework-mappings/`** (ADR-031 D4's consumer). Rejected: the blocking `validate-neutrality` hook scans that tree with a vendor-term denylist, and third-party catalogue text would be scanned as authoring prose. Skills are also shipped, cloneable artifacts ([ADR-033](033-vendor-neutral-agent-skill-shipping.md)), and a gate reading its oracle out of a skill bundle would couple the gate's correctness to the skill's packaging.
- **Under `risk-map/yaml/`.** Rejected: `prettier-yaml` rewrites and stages any YAML there and exits 0, so the upstream bytes would be lost on the first commit. ADR-002 would also route the path to `develop`, against the role-based ruling.
- **A new `risk-map/catalogues/` directory.** No hook collision, but rejected. It would add one more `risk-map/` surface where ADR-002's directory rule and the role-based ruling disagree (#563). Readers also take `risk-map/` to hold CoSAI-authored content, and these are third-party copies.
- **A new top-level `vendor/` or `third_party/` directory.** No hook collision, and it routes to `main` as repository plumbing. Rejected for now as premature: it creates a new top-level directory for a single vendored dataset with a single consumer. It is the natural move if a second, unrelated vendored dataset arrives.
- **Vendor a derived id list instead of the verbatim file.** A list of about 250 ids is a few kilobytes. Rejected: its digest cannot be compared with upstream bytes, so verification would rest on trusting an extraction step rather than on `sha256sum -c` against the source. It remains an escape hatch if repository growth becomes material (Follow-up).
- **Bump an adjudicated framework on every upstream publication.** Rejected: ATLAS publishes monthly, and every registered edition carries a vendored catalogue that cannot be pruned (D7a, D8). Over two years that is about 30-38 MB of checkout against about 7 MB for need-driven bumps (Consequences), for editions no corpus value pins.
- **A byte cap on the directory.** Rejected: when a needed bump would exceed the cap, the cap is raised, so it constrains nothing.
- **Adjudicated set as a per-framework field in `frameworks.yaml`.** Rejected: it is a schema change on a registry consumed by issue templates and other tooling, and a flag is meaningless without a parser and resolver in code. A framework flagged `true` with no implementation would have to fail anyway, so the registration belongs with the code that carries it.
- **Adjudicated set derived from which catalogue subdirectories exist.** Rejected: deleting a directory would silently turn every value of that framework into `skip`. That fails open.
- **Lazy required set** (catalogues only for editions some value pins). Rejected: right after a bump no value pins the new edition, so a bump that omitted the manifest refresh or the catalogue would pass. The omission would surface later as a read error on a content PR, on the branch least able to fix it. Under D3c's eager set, both omissions exit 2 at the bump commit.
- **An unresolved registered edition as per-value `invalid` only.** Rejected: right after a bump, no value pins the new edition, so a per-value rule sees nothing and the run exits 0. A registry/manifest inconsistency is a fault in the gate's own input, and D3c makes it a read error.
- **A flagless hook, matching the Tier 1 siblings (ADR-037 D8).** It would remove the warn tier and the per-flag exit contract. Rejected for the reasons in D4b: until #484 lands, a flagless hook is governed only through the D1 instance table, while a `--block` hook governs on arrival; after it lands, the flagged shape still carries the behavioural warn/block probe.
- **An exclusivity guard over `files:` alone.** Rejected: it is either red on arrival or blind to type-selected hooks (D6 item 8).
- **An exclusivity guard that runs `pre-commit run --files` over the catalogue paths.** Rejected: it executes every selected hook inside the test suite and needs each hook's environment installed. Evaluating the selection answers the same question without running anything.
- **An exclusivity guard with a hand-maintained table of remote hook types**, keyed by hook id and pinned `rev`. Rejected for two reasons. Every Dependabot or autoupdate `rev` bump of such a hook would turn the guard red on a branch the operator cannot push to, and nothing verifies the table's transcription of the remote manifest. An `exclude:` in the configuration (D6 item 11) decides the same question without either problem and also protects the files at run time.

## Consequences

**Positive**

- ADR-027 D5 Tier 2 becomes implementable. A value whose id is absent from its own pinned edition fails, which Tier 1 cannot detect.
- The gate stays offline and deterministic. It needs no new network fetch, workflow permission or `secrets.*`, and no new hook ever fetches.
- Provenance is checkable by anyone with standard tools: upstream URL, commit, verbatim bytes and `sha256sum -c`. Silent local mutation (by a formatter, an editor or a line-ending conversion) is a loud exit 2 rather than a quiet change of verdicts.
- A bump that forgets the manifest refresh or the catalogue fails at the bump commit (D3c).
- The `--block` shape makes the wiring self-enforcing: the hook entry alone creates the CI, aggregate and probe obligations (D6). The trigger obligation is enforced by a targeted test until ADR-037 D9 lands (D6 item 5).
- The exclusivity guard depends only on the repository's own configuration. Remote hook `rev` bumps do not affect it.
- The path agrees with both the directory rule and the role rule for routing, so it adds no drift to #563.

**Negative**

- **Repository growth.** Measured on 2026-10-01:
  - The v6 files for 2025.10, 2026.08 and 2026.09 are 319,578, 808,834 and 841,482 bytes; gzipped, about 76, 185 and 194 KB.
  - In a git pack after `gc --aggressive`, adding them in that order takes the pack from about 76 to 195 to 205.5 KB. A consecutive monthly edition costs about 11 KB of pack; an edition ten months later costs about 120 KB. The repository's pack is 8.72 MiB today.
  - Over two years, bumping monthly would register 24 editions, each larger than the last (about 0.85 MB growing to about 1.9 MB): about 30-38 MB of checkout and about +0.4 MB of pack. Need-driven bumps (D7a) at about three a year register about six editions: about 7 MB of checkout and about +1 MB of pack.

  The material cost is checkout bytes, not history. Git history retains every catalogue regardless of D8. D7a keeps the rate tied to corpus need, but it is a convention, not a cap. A maintainer who registers every release anyway is unbounded, and only pruning, which needs an ADR-027 D2c amendment, would bound that.
- **Reviewers cannot read a catalogue diff.** Trust moves from line review to the digest record and the reviewer's independent re-fetch (D7). A commit that changes a catalogue and `SHA256SUMS` together passes the validator. Only review catches that, which is why D7 makes the re-fetch and the changed-line check explicit reviewer steps. One residual remains: a truncated catalogue that still parses with both maps non-empty, with its digest regenerated, is caught only by that re-fetch.
- **Upstream re-publication is detected late, not never.** If upstream regenerates an older edition's file, the vendored copy diverges with no signal until the next bump of that framework. D7 then surfaces it as a diff, and the reviewer's re-verification covers every vendored file. Between bumps, Tier 2 adjudicates against the bytes vendored at the last bump.
- **A manifest refresh can change how an older token resolves.** If a future release also carried format-version `5.0.1`, that registered token would become unresolved, and the run would exit 2 at the bump commit (D3c). Failing closed is the intended behaviour. D7's reviewer check is there to catch it before the flip.
- **Every remote hook needs a catalogue decision in the configuration.** A new remote hook without a `files:` that excludes the catalogue paths, or an `exclude:` that covers them, fails the exclusivity guard (D6 item 8) until one is added.
- **`develop` lags `main`.** A content PR on `develop` that pins a newly registered edition needs that edition's catalogue, which reaches `develop` only through the `main` → `develop` sync. The registry and schema already lag the same way.
- **New per-bump work.** One more step in every bump of an adjudicated framework, now covering a re-copy of every vendored file and a size record, and one more root file (`.gitattributes`).
- **Third-party data under `scripts/`.** The catalogues sit in a tree that otherwise holds tooling. They are outside any Python package, as `scripts/TEMPLATES/` is. The formatter exclusion (D6 item 11) and the exclusivity guard (D6 item 8) keep them from interacting with type-selected hooks.

**Follow-up**

- Document the read contract (D3), the provenance guard and exit contract (D4, D4a), and the refresh procedure and cadence (D7, D7a) in `scripts/docs/hook-validations.md`. Add the catalogue step and the need-driven cadence to the ADR-027 D10 guidance in `risk-map/docs/contributing/framework-mappings-style-guide.md`, for both the lightweight path and the full checklist.
- If a framework's catalogue subdirectory exceeds about 10 MB of checkout (as recorded by D7 step 4), revisit growth in a dedicated decision: pruning `priorVersions` through an ADR-027 D2c amendment, compression, or the derived-id-list alternative.
- Decide separately whether other tools (`scripts/framework_mapping_maintainer.py` composing a value, the audit skill) should consult the vendored catalogues read-only. Nothing here requires them to.
