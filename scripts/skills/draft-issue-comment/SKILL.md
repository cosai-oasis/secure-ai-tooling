---
name: draft-issue-comment
description: Draft a structured maintainer review comment for a CoSAI Risk Map content-proposal issue (a proposed new or updated risk, control, component, or persona), written to a local markdown file for the maintainer to edit and post. Use when reviewing a GitHub content-proposal issue and you want a ready-to-edit review draft. NOT for reviewing a PR/diff (use content-reviewer in diff mode) or authoring content from scratch (use the control-/risk-/component-creator agents).
---

# Draft Issue Review Comment

> **Source of truth:** the review process, field-by-field feedback, output structure, and quality gates live in the canonical agent spec `scripts/agents/issue-response-reviewer.md` (which composes `content-reviewer` in `issue` mode). **This skill applies that spec; it does not restate its rules.** Duplicating the spec here is what let an earlier version drift stale — this skill stays thin and lets the canonical spec remain the authority.

Produce a structured maintainer review comment for a GitHub issue proposing new or updated CoSAI-RM content, written to a local file for the maintainer to edit and post manually (this skill produces a local draft and does not post to GitHub).

## Steps

1. **Load the review spec.** Read `scripts/agents/issue-response-reviewer.md` and follow it — it defines the review workflow, the field-by-field feedback structure, the output template, and the quality gates. Do not re-derive these here.
2. **Gather issue context:**
   - `gh issue view <number> --repo cosai-oasis/secure-ai-tooling --json title,body,author,createdAt,labels,comments`
   - `gh api repos/cosai-oasis/secure-ai-tooling/issues/<number>/comments` for any discussion
   - Determine the issue type (`risk` | `control` | `component` | `persona`) from the issue's template label / title prefix, or the `--type` argument.
   - Read the relevant `risk-map/yaml/*.yaml` for overlap analysis, and the style guides the canonical spec names for that type.
3. **Produce the review** following the canonical spec's output structure and quality gates.
4. **Write the draft** to `draft-<issue-number>-comment.md` in the repo root. It is a local draft; the maintainer edits and posts it.

## Operational notes

- **Local output only.** This skill writes a local draft; the maintainer posts it manually.
- **Citations follow ADR-016/017.** Any YAML the review drafts uses `externalReferences` (`type`/`id`/`title`/`https` url) referenced by `{{ref:identifier}}` sentinels — **never** inline URLs or `<a>` HTML anchors, which the prose hooks reject at commit. The canonical spec enforces this; do not reintroduce HTML-anchor guidance.
- **Keep this skill thin.** If the review logic changes, update `scripts/agents/issue-response-reviewer.md` (the authority), not this file.

## When NOT to use

- Reviewing a PR/diff of changed YAML → `content-reviewer` in `diff` mode.
- Authoring a new entry from scratch → the `control-creator` / `risk-creator` / `component-creator` agents (then their critics).
- A pre-submission quality check on a complete file → `content-reviewer` in `full` mode.
