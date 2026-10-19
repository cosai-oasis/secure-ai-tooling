# Python Validation read-set measurement

Measured 2026-10-19 for [issue #585](https://github.com/cosai-oasis/secure-ai-tooling/issues/585), against upstream `main` at [b0d7b0658819](https://github.com/cosai-oasis/secure-ai-tooling/commit/b0d7b065881978613cc908a3d71854d3963349aa).

## Cohort and counting method

The window contains all **66 PRs merged from 2026-08-07 through the measurement on 2026-10-19**, across `main` and `develop`. **23** touched `risk-map/`. The GitHub search returned 66 results with `incomplete_results: false`; complete changed-file lists were fetched for every PR. The largest list contained 73 files.

The comparison applies the old and proposed `validate_python.yml` path filters to each PR file list and, separately, to each merge commit's first-parent diff. A run is additional only when the proposed filter selects that diff and the old filter does not. The existing trigger helper supplies the GitHub glob semantics. This includes the extra coverage from directory patterns, not only files the static detector currently identifies.

All **497 retained Python Validation runs** were searched, including runs before the merge window. PR runs were joined by PR number or head SHA; push runs by merge SHA. Paginated check-runs on each PR head and merge commit independently confirmed the absence of the `Python Testing` job for the additional events. Restricting the run lookup to the merge window would misclassify older PRs whose checks ran before they merged.

**11 PRs had no retained Python Validation PR run at all; 13 merge pushes had no Python Validation run.** The two additional pushes are #439 and #441: their PR file lists included Python tests already landed by earlier PRs, while their actual merge diffs contained only content or documentation. Their pre-merge PR runs are not counted as additional.

Counts are a **minimum of one PR run per newly selected PR and one push run per newly selected merge**. They do not reconstruct every intermediate synchronization/reopening event or count fork-repository pushes. They are not a claim that only 24 additional runs would have occurred over the full lifetime of these PRs.

## Hosted duration baseline

For each event, the sample is the 12 most recent successful first attempts created in the measurement window. Workflow elapsed time is `updated_at - run_started_at`; aggregate job time is the sum of `completed_at - started_at` over that run's jobs. Failed, cancelled, and rerun attempts are excluded.

| Event | Workflow elapsed range (s) | Workflow median (s) | Aggregate job median (s) |
| --- | ---: | ---: | ---: |
| `pull_request` | 162–274 | 239 | 255 |
| `push` | 161–269 | 218 | 235 |

| Additional event | Minimum runs | Estimated workflow minutes | Estimated aggregate job minutes |
| --- | ---: | ---: | ---: |
| `pull_request` | 11 | 43.8 | 46.8 |
| merge `push` | 13 | 47.2 | 50.9 |
| Total | 24 | **about 91** | **about 97.7** |

These estimates multiply the minimum event counts by the corresponding medians. They exclude additional PR revisions and execution overhead from the new guard. Aggregate job minutes are elapsed job time, not an invoice or billed-minute forecast; workflow time is not interchangeable with aggregate job time because jobs run in parallel.

The sample run IDs make the duration calculation independently checkable:

| Event | Run | Workflow seconds | Aggregate job seconds |
| --- | --- | ---: | ---: |
| `pull_request` | [39144378677](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/39144378677) | 237 | 253 |
| `pull_request` | [39143340499](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/39143340499) | 274 | 281 |
| `pull_request` | [38981470501](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38981470501) | 246 | 265 |
| `pull_request` | [38809139257](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38809139257) | 262 | 272 |
| `pull_request` | [38807572495](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38807572495) | 186 | 199 |
| `pull_request` | [38804685793](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38804685793) | 257 | 279 |
| `pull_request` | [38629144674](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38629144674) | 186 | 210 |
| `pull_request` | [38154466998](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38154466998) | 239 | 255 |
| `pull_request` | [38154274641](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38154274641) | 269 | 276 |
| `pull_request` | [37691638598](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/37691638598) | 189 | 203 |
| `pull_request` | [37661086226](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/37661086226) | 239 | 255 |
| `pull_request` | [37080698702](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/37080698702) | 162 | 181 |
| `push` | [39144375302](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/39144375302) | 256 | 272 |
| `push` | [39144229177](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/39144229177) | 265 | 278 |
| `push` | [39143335314](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/39143335314) | 266 | 268 |
| `push` | [38805454892](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38805454892) | 169 | 184 |
| `push` | [38805034947](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38805034947) | 269 | 263 |
| `push` | [38804677628](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38804677628) | 211 | 224 |
| `push` | [38154462419](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38154462419) | 214 | 231 |
| `push` | [38154269145](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/38154269145) | 170 | 167 |
| `push` | [37714568838](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/37714568838) | 234 | 252 |
| `push` | [37684759788](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/37684759788) | 161 | 177 |
| `push` | [37242519617](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/37242519617) | 165 | 181 |
| `push` | [37242074047](https://github.com/cosai-oasis/secure-ai-tooling/actions/runs/37242074047) | 222 | 239 |

## Historical suite replays

Each of the 13 newly selected merge commits was checked out in an isolated Git clone and ran the complete pytest suite, with `CI=true`, `PYTHONPATH=./scripts/hooks`, Python 3.14.8, and that commit's `requirements.txt`. Seven distinct sets of direct requirement pins were installed in separate environments. Transitive dependencies resolved on the measurement date; this does not reconstruct the historical runner image or its transitive package versions. The replay host was macOS with the system Bash 3.2, rather than Ubuntu.

| PR | Merge commit | Additional PR run | Passed | Failed | Skipped |
| --- | --- | --- | ---: | ---: | ---: |
| [#475](https://github.com/cosai-oasis/secure-ai-tooling/pull/475) | [8cf79c795e91](https://github.com/cosai-oasis/secure-ai-tooling/commit/8cf79c795e91896ff6d2261d5cf3bc044f96f5f3) | yes | 3467 | 2 | 11 |
| [#497](https://github.com/cosai-oasis/secure-ai-tooling/pull/497) | [d16098bc772f](https://github.com/cosai-oasis/secure-ai-tooling/commit/d16098bc772f244325baf991cdc693e538eb75ba) | yes | 3823 | 2 | 20 |
| [#434](https://github.com/cosai-oasis/secure-ai-tooling/pull/434) | [f2356cc56c97](https://github.com/cosai-oasis/secure-ai-tooling/commit/f2356cc56c97de9ce758450ada5b3da559925b00) | yes | 3698 | 2 | 20 |
| [#506](https://github.com/cosai-oasis/secure-ai-tooling/pull/506) | [351f8b19735e](https://github.com/cosai-oasis/secure-ai-tooling/commit/351f8b19735ed2934eb3c15883c75fa5a6b55ba5) | yes | 3698 | 2 | 20 |
| [#435](https://github.com/cosai-oasis/secure-ai-tooling/pull/435) | [910080ef4292](https://github.com/cosai-oasis/secure-ai-tooling/commit/910080ef4292f74c5317da156181b4cd681a48ea) | yes | 3698 | 2 | 20 |
| [#436](https://github.com/cosai-oasis/secure-ai-tooling/pull/436) | [aff404fd3f14](https://github.com/cosai-oasis/secure-ai-tooling/commit/aff404fd3f143f1aa2936500f465a88744805ba5) | yes | 3698 | 2 | 20 |
| [#437](https://github.com/cosai-oasis/secure-ai-tooling/pull/437) | [b1196f29e9d9](https://github.com/cosai-oasis/secure-ai-tooling/commit/b1196f29e9d989a74852770133cdcc0bb4bb7b92) | yes | 3705 | 2 | 20 |
| [#439](https://github.com/cosai-oasis/secure-ai-tooling/pull/439) | [3f23c9f9eff9](https://github.com/cosai-oasis/secure-ai-tooling/commit/3f23c9f9eff94ea95b0362b9c9bd968f7e9e5b70) | no; push only | 3873 | 2 | 20 |
| [#548](https://github.com/cosai-oasis/secure-ai-tooling/pull/548) | [dfb44f200fce](https://github.com/cosai-oasis/secure-ai-tooling/commit/dfb44f200fceea73214a46a3299c6462d1fb857e) | yes | 3873 | 2 | 20 |
| [#566](https://github.com/cosai-oasis/secure-ai-tooling/pull/566) | [745fb2d4e960](https://github.com/cosai-oasis/secure-ai-tooling/commit/745fb2d4e960b9a344d51f38b42c82e3c26e06d2) | yes | 4340 | 2 | 21 |
| [#441](https://github.com/cosai-oasis/secure-ai-tooling/pull/441) | [62b5a30a9344](https://github.com/cosai-oasis/secure-ai-tooling/commit/62b5a30a934442f2da136969ea162c128b04e4d1) | no; push only | 4340 | 2 | 21 |
| [#579](https://github.com/cosai-oasis/secure-ai-tooling/pull/579) | [5c50f23e576e](https://github.com/cosai-oasis/secure-ai-tooling/commit/5c50f23e576eeb9d0e3288d3ace73c60b7206e97) | yes | 4371 | 2 | 21 |
| [#596](https://github.com/cosai-oasis/secure-ai-tooling/pull/596) | [70159a3e4c79](https://github.com/cosai-oasis/secure-ai-tooling/commit/70159a3e4c79beb13760892e42645f7cada2ab78) | yes | 4768 | 2 | 21 |

Every replay reported the same two toolchain failures and no other failures:

- `test_install_deps.py::TestSkipChromiumWhenPresent::test_chromium_in_cache_emits_skip`: `install-deps.sh` uses Bash `globstar`; the macOS `/bin/bash` is 3.2 and cannot enable it. The same failure reproduces on unchanged current `main`.
- `test_verify_deps.py::TestChromiumInPlaywrightCache::test_chromium_in_playwright_cache_passes`: the script invokes real `npx` commands in a fresh checkout. Network retries under the restricted local environment exceeded the test's 30-second subprocess timeout. At #475's exact merge commit, rerunning this test with `npm_config_fetch_retries=0` passed in 5.16 seconds without editing source or assertions.

A full suite on unchanged current `main`, in an isolated checkout with `CI=true` and `npm_config_fetch_retries=0`, reported **4,769 passed, 21 skipped, and the one Bash/globstar failure**. This distinguishes the persistent platform limitation from the trigger change.

**No content, schema, or documentation assertion failure was observed in these replays. Whether any skipped hosted Ubuntu run would have failed remains unproven.** The raw local replay failures must not be reported as missed production-content regressions or as passing hosted checks. A clean hosted counterfactual requires rerunning these pinned commits on Ubuntu.

## Static guard and posture

Applied to the baseline tracked tree, the guard scans all 104 `test_*.py` modules under `scripts/hooks/`. It derives 456 candidate input paths, of which 283 were not selected by the old workflow. These are a bounded static approximation: literal directory prefixes expand to tracked descendants, so the count is not a measured runtime read count. The live guard derives its inventory anew rather than pinning these measurement counts.

The detector follows `Path(__file__)`, `resolve()`, `parent`, `parents[n]`, simple path assignments, and division by string literals. A directory prefix also covers globs and dynamic filenames under that prefix. It never imports or executes scanned tests. Only tracked paths participate. It cannot resolve helper returns, imported path constants, or arbitrary runtime-built roots; directory expansion can overmatch. Broad directory filters cover many such cases, but the guard does not prove complete Python data flow.

The guard checks both `push` and `pull_request`, rejects a deleted event, and uses the existing ordered positive/negative path-filter matcher for both `paths` and `paths-ignore`. Synthetic tests cover path derivation, newly tracked test discovery, and event/filter mutations. The integration guard was observed failing before the trigger additions.

The recommended posture is the existing full suite on the measured input directories. This avoids a separate module list or marker that must track test dependencies. The measured minimum increase is modest for this window; the replays provide no evidence for treating the silent coverage gap as safe. The decision and its residual are recorded in [ADR-037 D10c](../../docs/adr/037-ci-validation-authority-and-block-parity.md#d10c-the-full-pytest-suite-triggers-on-its-derived-test-inputs).

With the proposed workflow and tests, the full suite in the same isolated local environment reported **4,785 passed, 21 skipped, and the same one Bash/globstar failure**. All 16 added regression cases passed, as did Ruff linting and formatting checks. This local result is separate from hosted CI.

## Reproduction inputs

The cohort and Actions data came from these read-only GitHub REST endpoints (paginated wherever applicable):

```text
GET /search/issues?q=repo:cosai-oasis/secure-ai-tooling is:pr is:merged merged:2026-08-07..2026-10-19
GET /repos/cosai-oasis/secure-ai-tooling/pulls/{number}
GET /repos/cosai-oasis/secure-ai-tooling/pulls/{number}/files
GET /repos/cosai-oasis/secure-ai-tooling/commits/{head-or-merge-sha}/check-runs
GET /repos/cosai-oasis/secure-ai-tooling/actions/workflows/validate_python.yml/runs
GET /repos/cosai-oasis/secure-ai-tooling/actions/runs/{run-id}/jobs
```

For every pinned replay commit above, install its direct requirements in a fresh Python 3.14 environment, then run at that checkout's root:

```bash
CI=true PYTHONPATH=./scripts/hooks pytest --junitxml=test-results.xml
```

Compare merge-push files with `git diff --name-only <merge-sha>^ <merge-sha>`, not the PR's complete file list. Inspect the baseline workflow with `git show b0d7b065881978613cc908a3d71854d3963349aa:.github/workflows/validate_python.yml`. The path-filter matcher and detector live in [test_ci_block_parity.py](../hooks/tests/test_ci_block_parity.py).
