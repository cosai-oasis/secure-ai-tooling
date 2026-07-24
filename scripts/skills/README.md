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
