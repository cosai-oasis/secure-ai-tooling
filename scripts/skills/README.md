# Skills

`scripts/skills/` is the canonical, vendor-neutral home for CoSAI skill
definitions (ADR-031 D6, ADR-033 D1/D4). A skill here is the single,
complete, authoritative form of that skill — a consumer clones this tree
directly and runs it in their own harness. No harness-specific wrapper for
any skill is tracked in this repository (ADR-033 D1); harness adaptation is
the consumer's responsibility (ADR-033 D3).

## Format

Skills are authored to the **Agent Skills** open standard
(`agentskills.io`; spec repo `github.com/agentskills/agentskills`), per
ADR-031 D6. A skill is a directory containing:

- `SKILL.md` — YAML frontmatter declaring only `name` and `description`,
  plus Markdown instructions. No other frontmatter key is permitted; the
  neutrality check (`scripts/hooks/precommit/validate_neutrality.py`)
  enforces this as an allowlist.
- Optional bundled directories: `scripts/`, `references/`, `assets/` (per
  the standard), and `evals/` (a project convention, not part of the
  standard itself — see below).

**Pinned spec revision:** commit `6868401b64f791e9ff565f29beb6338826b73a2b`
of `github.com/agentskills/agentskills` — the commit that last modified the
spec file `docs/specification.mdx` (2026-05-16). The repository has no tagged
releases, so the revision is pinned by commit SHA; this deliberately anchors to
the spec-content commit rather than an incidental later HEAD, and should be
re-pinned to a tagged release once the upstream project cuts one. The
`SKILL.md` shape and required-field core this tree conforms to are defined
at `docs/specification.mdx` in that revision. Later skills follow this same
revision until a maintainer deliberately re-pins it (ADR-031 D6: "the first
skill PR fixes the revision the canonical surface targets").

## `evals/` convention

Every shipped skill carries a portable eval (ADR-033 D6) at
`evals/evals.json` — a runtime-independent behavior specification
(`{skill_name, evals: [{id, prompt, expected_output, expectations[]}]}`)
that travels with the skill. An eval is required to ship; an artifact with
no eval is not admissible to this tree. `evals/` is a project extension to
the standard's optional bundled-dir list, not part of the Agent Skills
standard itself. Evals here are docs-only / run-by-hand for now — no
in-repo runner exists yet (ADR-033 D6 follow-up).

## Neutrality gate

Every file under this tree is scanned by the neutrality check
(`scripts/hooks/precommit/validate_neutrality.py`, ADR-033 D2a/D5) before
merge. Run it manually against a draft skill:

```
python3 scripts/hooks/precommit/validate_neutrality.py scripts/skills/<name>/SKILL.md scripts/skills/<name>/references/*.md
```

## Skills in this tree

- `classical-lexicon/` — grounds Risk Map terminology in established
  security terms of art (ADR-031 D2/D3).
- `mapping-selection/` — selects a control's/risk's components, addressed
  risks/controls, and framework mappings, grounded in the corpus and the
  framework applicability rules (ADR-031 D2/D4).
- `altitude-check/` — checks whether a control/risk/component draft is
  pitched at the right altitude (granularity), applying the per-type
  altitude tests and deferring terminology to `classical-lexicon`
  (ADR-031 D2).
- `audit-framework-mappings/` — audits the framework mappings across
  risks, controls, and personas against the framework-mappings style
  guide (version pinning, applicability, selectivity), deferring format
  to the style guide (ADR-031 D2, ADR-027).
- `audit-identification-questions/` — audits persona identification
  questions against the identification-questions style guide (framing,
  scoping, examples, ordering), deferring the rules to the style guide
  (ADR-031 D5, ADR-021 D7).
- `explain-entity/` — explains a single risk/control/component/persona in
  plain language, including its classical roots and relationships
  (read-only; ADR-032 D2).
- `explore-controls-by-classical/` — maps a classical security concept to
  the controls that embody or extend it, deferring terminology to
  `classical-lexicon` (read-only; ADR-032 D2/D3).
- `explore-exposure/` — maps a named product/technology or component id to
  that component's risks and controls, with a curated-plus-inferred
  product→component lexicon (read-only; ADR-032 D2/D5).
- `explore-framework-coverage/` — a reverse index over the framework
  mappings across risks, controls, and personas, deferring format/quality
  questions to `audit-framework-mappings` (read-only; ADR-032 D2/D3).
- `explore-persona-self-id/` — guides a reader to their persona(s) via the
  framework's identification questions, then surfaces the risks that
  impact them and the controls they implement (read-only; ADR-032 D2).
- `explore-risks-by-activity/` — maps a stated activity or role to the
  risks that affect it and the controls that address them (read-only;
  ADR-032 D2).
- `draft-issue-comment/` — drafts a structured maintainer review comment
  for a content-proposal issue (a proposed risk/control/component/persona),
  applying the `issue-response-reviewer` agent (which composes
  `content-reviewer` in `issue` mode) and writing a local draft to edit and
  post; citations follow ADR-016/017 (`externalReferences` + `{{ref:}}`).
  Read the issue proposal, not a PR diff (ADR-031 D6, ADR-008).
