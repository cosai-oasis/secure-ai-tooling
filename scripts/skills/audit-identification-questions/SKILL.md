---
name: audit-identification-questions
description: Audit persona identification questions in personas.yaml against the identification questions style guide. Use when reviewing or proposing changes to identificationQuestions.
---

# Identification Questions Audit

Audit persona identification questions for style guide compliance, boundary clarity, and term validity.

## Scope

Target: a single persona id, or `all` to audit every non-deprecated persona in `personas.yaml` (default).

If a specific persona ID is provided (e.g., `personaAgenticProvider`), audit only that persona's questions.

## Reference documents

Read these before auditing:

1. **Style guide** (authoritative): `risk-map/docs/contributing/identification-questions-style-guide.md`

## Audit checklist

For each persona with `identificationQuestions`, verify ALL of the following. Report pass/fail per item.

**Passing the mechanical checks (Structure, Examples format) does not make a question conformant.** The editorial checks — Framing (an activity, not a role/title or a third party), Scoping, and especially **"including" for scope expansion** — take judgment against the style guide and are the *most common* remaining issue on a question that already looks clean. Do not return a conformant verdict until you have positively evaluated each editorial check on its merits — e.g. a base term narrow enough that a reader might wrongly exclude themselves, used without an "including" clause, is a scope-expansion flag even when structure and format are perfect.

### Structure

- [ ] **Count 5-7**: Between 5 and 7 questions inclusive
- [ ] **Yes/no answerable**: Every question can be answered with yes or no
- [ ] **No embedded conditionals**: No nested conditions requiring evaluation before answering

### Framing

- [ ] **Second-person, activity-focused**: Questions ask what *you* do — "Do you…", "Are you…", "Does your team…" — about the reader's activities. Avoid framings about a system/platform/product ("Is your system…", "Does your platform…") and third-person framings about other roles ("Do developers…").
- [ ] **Activity-focused**: Questions describe what the reader does, not what their job title is or what their product is

### Scoping and boundaries

- [ ] **Scoping clauses present**: Where an activity is shared with an adjacent persona, a scoping clause disambiguates (e.g., "as a framework author rather than as an application developer")
- [ ] **No overlapping questions**: No two questions ask effectively the same thing at different abstraction levels. If overlap exists, merge or add a scoping clause.

### Examples and terminology

- [ ] **Parenthetical examples**: Technical terms have parenthetical examples using `(e.g., item1, item2, item3)` format — NOT "such as" inline, NOT parenthetical without "e.g."
- [ ] **Example list length**: Parenthetical lists have 2-4 items
- [ ] **"including" for scope expansion**: Used where the base term might be read too narrowly

### Ordering

- [ ] **Question ordering**: Most distinguishing activity first, scope-expanding questions in the middle, boundary-clarifying questions last

## Term verification (critical)

When reviewing or proposing parenthetical examples (the `(e.g., ...)` items):

1. **Search the web** to confirm each term has strong real-world usage in the relevant ecosystem
2. Check major frameworks, tools, and documentation (e.g., LangChain, Semantic Kernel, Vertex AI, CrewAI, etc.)
3. If a proposed term is not an established concept, find the industry-standard term for the same idea
4. Flag any term that is:
   - Not used in any major framework's documentation
   - Deprecated or renamed in the latest version
   - A colloquial shorthand rather than a concrete, recognized component or pattern
5. Provide sources/evidence for term validation

## Coverage analysis (for `all` scope only)

- List all non-deprecated personas with vs. without identification questions
- Calculate per-persona compliance scores (checklist pass rate)
- Calculate aggregate compliance score
- Prioritize missing personas by disambiguation value (how adjacent they are to other personas)

## Proposing rewrites

When proposing rewritten questions:

1. Show the current question and the proposed replacement side by side
2. Identify which checklist items the rewrite fixes
3. For any new parenthetical examples, include term verification results
4. Ensure the rewrite does not introduce new violations

## Output format

For targeted audits (single persona), provide:

1. All current questions listed
2. Pass/fail on each checklist item with notes
3. Specific violations with remediation suggestions
4. Term verification results for any proposed example terms
