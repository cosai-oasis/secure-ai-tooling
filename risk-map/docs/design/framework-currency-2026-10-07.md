# Framework Currency Record: 2026-10-07

This record states, for five registered frameworks, the edition `risk-map/yaml/frameworks.yaml` registers, the edition the publisher currently issues, and the version-change determination under [ADR-027](../../../docs/adr/027-framework-versioning-and-mapping-convention.md) D10. MITRE ATLAS is out of scope here; its registry entry already carries the bumped shape (`version`, `versionId`, `supersedes`, `priorVersions`).

**Version:** 1.0
**Last Updated:** 2026-10-07
**Publisher sources read:** 2026-10-05 (UTC)

---

## Table of Contents

- [Rules applied](#rules-applied)
- [Summary](#summary)
- [nist-ai-rmf](#nist-ai-rmf)
- [owasp-top10-llm](#owasp-top10-llm)
- [eu-ai-act](#eu-ai-act)
- [iso-22989](#iso-22989)
- [stride](#stride)
- [Booked follow-ups](#booked-follow-ups)

---

## Rules applied

- **ADR-027 D10a.** "A new published edition (an ETSI EN re-issue, a NIST AI RMF 1.1, an ISO amendment, an ATLAS quarterly matrix) is the trigger. The gate's weight scales to **how many existing pinned values the bump affects**." Zero affected pins takes the lightweight path, a reviewed registry edit. One or more affected pins takes the full path, which "**requires a tracking issue carrying the full D10b checklist** before the registry `version` flips".
- **ADR-027 D10c.** Cadence is "on-publish / on-demand, not scheduled … the registry advances only when there is a reason and an owner."
- **ADR-027 D2c / D5a.** A pin whose version token is listed in `priorVersions` is `valid-but-superseded`: it passes validation and is reported informationally. Only a token in neither `version` nor `priorVersions` is `invalid`.
- **No registry or schema change is made by this record.** A determination that calls for a bump is booked as a follow-up PR on `main`. Each non-ATLAS bump has its own set of tests coupled to that framework's edition literals. The follow-up re-derives that set before the registry flips. The flip itself is the D10b step 1 registry update (advance `version`, regenerate `versionId`, set `supersedes`, append to `priorVersions`) together with widening the framework's entry in `framework-mapping-patterns-pinned` in `risk-map/schemas/frameworks.schema.json` to admit the new token.

Affected-pin counts are the values in the `mappings` blocks of `risk-map/yaml/{risks,controls,components,personas}.yaml`, counted by parsing the YAML. Prose that mentions an identifier is not counted. Each count names the SHA it was measured on. `main` at `2efec1b` and `develop` at `64c1960` have identical content for these four files. Open PR #507 (head `1a0b5d4`) queues additional values that reach `main` at the next `develop`→`main` checkpoint after it merges.

---

## Summary

| Framework | Registered | Publisher current | Determination | D10a weight |
|---|---|---|---|---|
| `nist-ai-rmf` | `1.0` | AI RMF 1.0 (NIST AI 100-1); revision announced, unpublished | No change | n/a (no trigger) |
| `owasp-top10-llm` | `2025` | Top 10 for LLM Applications 2026 | **Bump booked** to `2026`, `2025` retained in `priorVersions` | Full path |
| `eu-ai-act` | `2024` | Reg. (EU) 2024/1689 as amended by Reg. (EU) 2026/1744; consolidated `02024R1689-20260727` | Recorded no-bump; deferred bump tracked in #580 | Lightweight at `2efec1b` (zero affected pins) |
| `iso-22989` | `2022` | ISO/IEC 22989:2022 (ed. 1); amendments are drafts | Edition recorded, no change | n/a (no trigger) |
| `stride` | unversioned | STRIDE, unversioned | Recorded no-action | n/a |

---

## nist-ai-rmf

- **Registered:** `version: '1.0'`, `lastUpdated: '2023-01-26'`.
- **Publisher:** https://www.nist.gov/itl/ai-risk-management-framework, read 2026-10-05: "Released on January 26, 2023, the Framework…" and "The AI RMF 1.0 is being revised as part of the White House AI Action Plan." The publication record (https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10, read 2026-10-05) lists AI RMF 1.0, published January 26, 2023, with no errata or revision entry.
- **Determination:** no change. A revision is announced. No successor edition and no public draft exists. The Generative AI Profile (NIST-AI-600-1) and the critical-infrastructure profile concept note are separate documents, not editions of AI 100-1.
- **D10a:** no trigger. The next NIST publication of a revised AI RMF is the trigger.

## owasp-top10-llm

- **Registered:** `version: '2025'`, `versionId: owasp-top10-llm@2025`, `lastUpdated: '2024-11-18'`.
- **Publisher:** https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/, read 2026-10-05, page dated August 3, 2026: "OWASP Top 10 for LLM Applications 2026 is the latest community-driven guide to the most critical security risks facing applications powered by large language models." The publisher's press release (https://genai.owasp.org/2026/09/01/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/, read 2026-10-05; datelined Sept. 2, 2026, page metadata 2026-09-01) states that the project "Releases 2026 Top 10 for LLM Applications".
- **2026 entries (from the publisher's PDF):** `LLM01:2026` Prompt Injection, `LLM02:2026` Sensitive Information Disclosure, `LLM03:2026` Excessive Agency, `LLM04:2026` Supply Chain, `LLM05:2026` Data and Model Poisoning, `LLM06:2026` Unbounded Consumption, `LLM07:2026` Misinformation, `LLM08:2026` Hidden Context Exposure, `LLM09:2026` Vector and Embedding Weaknesses, `LLM10:2026` Improper Output Handling.
- **Renumbering.** Only `LLM01` and `LLM02` keep their 2025 titles. Every other number names a different item in 2026. For example, `LLM03` is Supply Chain in 2025 and Excessive Agency in 2026. "System Prompt Leakage" (`LLM07:2025`) has no same-titled 2026 entry. Moving a value from `:2025` to `:2026` is therefore a per-mapping content decision, not a token swap.
- **Publisher inconsistency.** The publisher's surfaces disagree about the current edition. The 2026 PDF's front matter carries unfilled placeholders ("Version 2026 [Publication date to be set]", "[2026 release date] Version 2026 Release"). The hub page https://genai.owasp.org/llm-top-10/ still lists `LLM01:2025`…`LLM10:2025` and does not link 2026. The registry's `baseUri` (the owasp.org project page) still shows "Version 2025". The follow-up confirms the edition is final, and settles the `lastUpdated` date it records, before the registry bump.
- **Affected pins:** every `LLMnn:yyyy` value in the corpus is `:2025`. There are 33 at `main` `2efec1b` and `develop` `64c1960` (25 in `risks.yaml`, 8 in `controls.yaml`). There are 54 at PR #507 head `1a0b5d4` (34 in `risks.yaml`, 20 in `controls.yaml`). That count is the total at that SHA, not a delta against `develop`.
- **Determination:** bump booked. Register `owasp-top10-llm` `version: '2026'` with `supersedes: owasp-top10-llm@2025` and `priorVersions: [owasp-top10-llm@2025]`. Under D2c/D5a, the existing `:2025` pins become `valid-but-superseded`: they pass and are reported. They are not failures.
- **D10a weight:** full path. One or more pins are affected (33 at `2efec1b`), so a tracking issue carrying the D10b checklist precedes the flip. D10b step 4, the per-mapping re-pin or retain decision, runs as a separate content track on `develop`. The registry bump on `main` closes on D10b's exit gate: no `invalid` pins, and the style guide reflects 2026. The retained `:2025` pins satisfy that gate as `valid-but-superseded`.
- **Validation hazard.** ADR-038 records that none of the five non-ATLAS frameworks publishes a machine-readable per-edition id catalogue. Validation of an OWASP value therefore checks only the `LLMnn:yyyy` shape and the version token. Once `2026` is registered, a value written with a 2025 number and a `:2026` token (`LLM03:2026` meant as Supply Chain) passes every automated check. Review in the re-mapping track is the only guard against that error.

## eu-ai-act

- **Registered:** `version: '2024'`, `versionId: eu-ai-act@2024`, `lastUpdated: '2024-06-13'`, `documentUri: https://eur-lex.europa.eu/eli/reg/2024/1689`.
- **Publisher:** https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX:32024R1689, read 2026-10-05: "In force: This act has been changed. Current consolidated version: 27/07/2026". The consolidated text is CELEX `02024R1689-20260727`. The amending act (https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX:32026R1744, read 2026-10-05) is "Regulation (EU) 2026/1744 … of 8 July 2026 amending Regulations (EU) 2024/1689 … (Digital Omnibus on AI)", published in OJ L 24.7.2026 and in force since 27/07/2026.
- **Provisions modified.** The EUR-Lex "Modified by" table lists, among others, Article 3(14) (replaced, with new 3(14a)/(14b)), Article 4 (replaced), new Article 4a, Article 10(5) (deleted), new Article 60a, and new Articles 75a-75d. **Articles 9, 14, 19 and 26 are not in the table.** This was read from the modification table, not from a text diff.
- **Affected pins:** zero `eu-ai-act` mapping values at `main` `2efec1b` and at `develop` `64c1960`. Six are queued at PR #507 head `1a0b5d4`, all in `controls.yaml` and all `@2024`: `Article 14@2024`, `Article 9@2024`, `Article 19@2024` ×2 and `Article 26(6)@2024` ×2. None cites a provision 2026/1744 modified.
- **Determination: recorded no-bump.** The registry entry, the pinned pattern `^Article\s\d+(\(\d+\))?@(2024)$` and its pattern class stay unchanged. The amending act is a D10a trigger ("an ISO amendment" is the ADR's own example of the class). Applying the process gives this result:
  1. The `2024` token keeps its D3 meaning: the text of Regulation (EU) 2024/1689 as adopted (`lastUpdated: '2024-06-13'`). It does not mean "the current consolidation", because that reading re-resolves pins whenever the act is amended, which is the latest-wins failure D3 closes.
  2. Each of the six values queued at `1a0b5d4` cites an article that is not in the 2026/1744 modification table. On that evidence a bump would not change what any value means. Its only effect would be that all six arrive as `valid-but-superseded`, which then calls for six re-pins that change nothing. Confirming this against the consolidated text is part of #580.
  3. D10c makes version metadata maintainer-owned, and the external publication is the trigger. The maintainer's determination (2026-10-07) is to defer the bump: #580 names its scope and its start gate.
  4. ADR-038 records that the act has no machine-readable per-edition catalogue, so a bump adds no Tier 2 detection.
- **D10a weight, if run:** lightweight at `2efec1b` (zero affected pins). It becomes the full path once the six #507 values reach `main`, though every one would be a meaning-preserving re-pin.
- **Re-trigger conditions.** The full bump, the re-pin of existing values and the pattern questions are tracked as a deferred item in #580. It starts once #562 is closed and #507 has reached `main`. Any of the following reopens the determination, and the bump then takes the ID-bearing shape: a new `version`, `supersedes: eu-ai-act@2024`, and `eu-ai-act@2024` retained in `priorVersions`.
  - A contribution needs to cite a provision that Regulation (EU) 2026/1744 modified or added. Such a value written `@2024` would cite the superseded text, and only review catches that.
  - A later amending act modifies an article that a pinned value cites.
  - The maintainer decides to track consolidated versions as editions.
- **Pattern-class limit.** The pinned pattern admits no lettered article numbers, so the new Articles 4a, 60a and 75a-75d are not expressible at any token. A contribution that needs one requires a pattern change as well as the bump.
- **Prose references.** PR #507's `controls.yaml` also cites the act through the `eu-ai-act-2024` external reference. That label is consistent with this determination.

## iso-22989

- **Registered:** `version: '2022'`, `versionId: iso-22989@2022`, `lastUpdated: '2022-07-01'`.
- **Publisher:** iso.org's HTML pages refused automated reads, so the publisher's per-standard detail feeds were read. https://www.iso.org/contents/data/standard/07/42/74296.detail.rss, read 2026-10-05: "ISO/IEC 22989:2022 … This document reached stage 60.60 on 2022-07-19". Amendment 1 (https://www.iso.org/contents/data/standard/08/81/88145.detail.rss, read 2026-10-05): "ISO/IEC 22989:2022/FDAmd 1 … Amendment 1: Generative AI … This document reached stage 50.00 on 2026-09-18", a final draft. Amendment 2 (https://www.iso.org/contents/data/standard/09/31/93144.detail.rss, read 2026-10-05): "ISO/IEC 22989:2022/CD Amd 2 … This document reached stage 30.20 on 2026-08-28", a committee draft.
- **Determination:** edition recorded, no change. Neither amendment is published. Publication of Amendment 1 is the next D10a trigger. Because `iso-22989` is a non-ID framework, its bump also needs the D10b step 2 controlled-vocabulary refresh, which depends on the normative text. That refresh is outside this record.
- **Observation:** the publisher's stage 60.60 date is 2022-07-19. The registry records `lastUpdated: '2022-07-01'`. This record does not change it.

## stride

- **Registered:** `version: null`, `versionId: stride`.
- **Publisher:** https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats, read 2026-10-05: "Microsoft uses the STRIDE model, which categorizes different types of threats and simplifies the overall security conversations." The page's category table has the same six values as the schema enum. The page carries no version marking.
- **Determination:** recorded no-action. STRIDE is pinned by its closed enum (ADR-027 D6). A change to the six-value set would be a D10-gated schema edit, and none has occurred.

---

## Booked follow-ups

1. **`owasp-top10-llm` registry and schema bump (`main`), #581.** The issue carries the D10b checklist. Its steps:
   - Confirm the 2026 edition is final and settle its `lastUpdated`.
   - Re-derive the tests coupled to the OWASP edition literal before the flip. A simulated bump (2026-10-08) turns seven tests red in four files:
     - `test_frameworks_schema_v027.py`: `test_pattern_contains_version_alternation[owasp-top10-llm]` (the `PINNED_PATTERN_TABLE` row's `pattern_contains`). Its `LLM01:2024`/`LLM01:2023` negative examples stay negative.
     - `test_framework_mapping_maintainer.py`: `test_owasp_legacy_to_pinned` and `test_migrate_rewrites_legacy_values_to_pinned`, because `migrate` mints the current token.
     - `test_validate_mapping_drift.py`: `test_owasp_top10_llm_current_colon_delimiter` and `test_owasp_current_version_still_current_with_synthetic_fixtures`.
     - `test_versionid_generator_and_purity.py`: the two expected-`versionId` tests.
   - `test_template_content_alignment.py` does not fail at the flip. It reads only the issue-template sources in `scripts/TEMPLATES/`, never corpus values, so re-pinning a corpus value to `:2026` cannot fail it either. It fails when a template example moves to `:2026`, because `_CANONICAL_PATTERNS` (`^LLM\d{2}:2025$`) and `test_new_risk_owasp_example_includes_year` pin the 2025 token. Unlike MITRE ATLAS, OWASP has no test asserting that template examples carry the current edition, so a stale example is not caught after the bump.
   - Update the teaching carriers that show an OWASP value as the form to use. Measured on 2026-10-08 with `git grep 'LLM[0-9]{2}:2025'`, excluding the corpus, tests and generated tables:
     - Issue-template sources `scripts/TEMPLATES/new_risk.template.yml` and `update_risk.template.yml`, then regenerate `.github/ISSUE_TEMPLATE/*`.
     - Contributor docs: `risk-map/docs/contributing/issue-templates-guide.md`, `submission-readiness-guide.md` and `common-review-findings.md`; `risk-map/docs/guide-frameworks.md` and `guide-metadata.md`.
     - Agent specs `scripts/agents/content-reviewer.md` and `issue-response-reviewer.md` (the latter says "from the current edition"), and the `audit-framework-mappings` evals.
     - ADR-022, ADR-026 and ADR-027 use `:2025` as illustration and stay. Evals that quote a specific corpus pin (`mapping-selection`) change only when the re-mapping re-pins that value.
   - Make the registry change: `version: '2026'`, `supersedes`/`priorVersions` = `owasp-top10-llm@2025`.
   - Widen `framework-mapping-patterns-pinned.owasp-top10-llm` to `^LLM\d{2}:(2025|2026)$`.
   - Run the drift sweep. The expected result is every existing pin `valid-but-superseded` and none `invalid`.
   - Update `risk-map/docs/contributing/framework-mappings-style-guide.md` (D10b step 5).

   This is a full-path bump with its own D10a call.
2. **`owasp-top10-llm` content re-mapping (`develop`), #582.** This is D10b step 4. For each `:2025` value, decide whether to re-pin to the 2026 entry with the same meaning or retain it as `valid-but-superseded`. The decision is made from the 2026 document's content, not from the number. It depends on follow-up 1 landing first so that `:2026` validates. Review in this track is the only guard against the renumbering hazard recorded above.

No follow-up is booked for `nist-ai-rmf`, `iso-22989` or `stride`. The `eu-ai-act` bump is not booked; it is deferred in #580 with the start gate stated there.
