# CoSAI Risk Map Explorer

The **CoSAI Risk Map Explorer** is a static GitHub Pages experience for CoSAI-RM persona matching and persona-driven risk/control browsing. Its initial release is intentionally narrow in scope.

## Prerequisites

- Python 3.14+ and Node.js 24+ (matches repo CI targets per `.mise.toml`)
- Framework YAML in `risk-map/yaml/` passes existing schema validation

## Scope

What the explorer is:

- Persona-driven navigation of risks and controls
- Static GitHub Pages deployment
- Zero backend, no answer storage

What the explorer is NOT:

- Scoring or grading of responses
- Persistence of answers across sessions (no cookies, no localStorage)
- A drop-in replacement for the archived `risk-map/yaml/archive/self-assessment-legacy.yaml` — the persona explorer is its successor, per [ADR-021](../../docs/adr/021-personas-and-self-assessment-schema.md) D6

## Overview

The explorer is intentionally lightweight:

- `site/` contains the static HTML, CSS, and browser-side JavaScript.
- `scripts/build_persona_site_data.py` reads `risk-map/yaml/personas.yaml`, `risk-map/yaml/risks.yaml`, and `risk-map/yaml/controls.yaml`.
- The builder writes generated JSON to `site/generated/persona-site-data.json` for local preview, or to another site directory during CI deployment.

The site does not use a backend and does not store answers server-side. User answers are held in browser memory for the current session only.

## Data Flow

The framework YAML stays the source of truth.

1. Active personas are read from `personas.yaml`.
2. Guided persona questions come from `identificationQuestions`.
3. Manual fallback personas are the active personas with fewer than five identification questions.
4. Risks are derived from `risks.yaml.personas`.
5. Controls are derived from `controls.yaml.personas`.
6. Shared risks and controls are deduplicated client-side after persona selection.

The legacy self-assessment is archived at `risk-map/yaml/archive/self-assessment-legacy.yaml` per [ADR-021](../../docs/adr/021-personas-and-self-assessment-schema.md) D6; the persona explorer is its successor.

## Local Build And Preview

Generate the site data:

```bash
python3 scripts/build_persona_site_data.py
```

Serve the site directory locally:

```bash
python3 -m http.server --directory site 8000
```

Then open [http://localhost:8000](http://localhost:8000).

If you want to build into a different staging directory instead of `site/generated/`, pass `--site-dir` or `--output`:

```bash
python3 scripts/build_persona_site_data.py --site-dir /tmp/cosai-persona-site
python3 scripts/build_persona_site_data.py --output /tmp/persona-site-data.json
```

## Validation

Run the focused validations for the explorer:

```bash
ruff check .
pytest scripts/hooks/tests/test_build_persona_site_data.py
node --test site/tests/*.test.mjs
python3 scripts/build_persona_site_data.py
```

The Python tests cover YAML loading and transformation. The Node tests cover persona matching, manual fallback behavior, and deduplication logic.

These focused checks are the validation bar for the explorer itself. Some broader repository tests are currently environment-sensitive and may fail locally even when the explorer changes are correct:

- `scripts/hooks/tests/test_verify_deps.py -k all_dependencies_present_exit_0` expects a Python 3.14 environment on `PATH`.
- `scripts/hooks/tests/test_install_deps.py::TestSkipChromiumWhenPresent::test_chromium_in_cache_emits_skip` depends on local Chromium cache state.

## GitHub Pages Deployment

The workflow at `.github/workflows/persona-pages.yml` handles the explorer:

- Pull requests to `main` run the focused Python and Node tests and validate that the static site artifact can be assembled.
- Pushes to `main` rebuild the site artifact, enable GitHub Pages if needed, and deploy the explorer.
- Deployment builds from a clean `_site/` copy so generated JSON does not need to be committed.

## Maintenance Notes

- Update the framework YAML first. Rebuild the site data after persona, risk, or control changes.
- If additional personas gain full `identificationQuestions`, they will automatically move from the manual-fallback section into the guided question flow.
- `AI System Governance` currently has control mappings but no direct risk mappings in the framework data. The site therefore shows governance controls and a clear risks empty-state note.

## YAML Prose Rendering

Prose fields (`longDescription`, `shortDescription`, `examples`, `description`) carry a
small markdown subset, **not** raw HTML. Contributors author:

- `**bold**` and `*italic*` / `_italic_` — for emphasis (never `<strong>`/`<em>`).
- `{{<entity-id>}}` sentinels — for intra-framework references (resolve to an in-page link).
- `{{ref:identifier}}` sentinels — for external citations, backed by an `externalReferences` entry.

Raw HTML tags, inline URLs (any scheme), and bare entity IDs are **rejected at commit**
by the `validate-yaml-prose-subset` and `validate-prose-references` hooks
([ADR-017](../../docs/adr/017-yaml-prose-authoring-subset.md),
[ADR-016](../../docs/adr/016-reference-strategy.md)). The full authoring rules and the
`externalReferences` citation flow live in
[yaml-authoring-subset.md](./yaml-authoring-subset.md).

**Render-time sanitization.** The builder expands sentinels to structured prose items
(`{type:"ref"}` / `{type:"link"}`), and the renderer routes every paragraph through
`renderProse` (`site/assets/sanitizer.mjs`), which emits a bounded HTML allowlist —
`<strong>`, `<em>`, and `<a>` whose attributes are constructed (`https:`-only `href`,
`rel="noopener noreferrer"`, `target="_blank"`), never copied from input
([ADR-015](../../docs/adr/015-site-content-sanitization-invariants.md) D1/D3a). Anything
outside the allowlist is **escaped** (rendered as visible `&lt;…&gt;`) with a console
warning, not silently dropped — so a contributor who bypassed the upstream lint sees
that their markup did not land. Authors cannot widen the allowlist from YAML; growing it
is an ADR-015 revisit, not a content change.

Nested list syntax (`- - >`) encodes a logical sub-group within a prose field and
renders as a visually distinct `<div class="subsection">`. Empty list entries (`- ""`)
are silently dropped — do not use them as spacing hacks.

## Accessibility

The explorer implements:

- Visible focus rings on all interactive elements (`:focus-visible`)
- Honors `prefers-reduced-motion` to suppress animations and smooth scrolling
- Announces state changes via an aria-live status region (answer changes, step navigation, manual persona toggles, session reset)

Known gap: focus is not preserved across full-app re-renders (answering a question returns focus to `<body>`). Tracked as a follow-up issue filed alongside PR #223 (labels: `test-coverage`, `frontend`, `tech-debt`, `follow-up-from-pr-223`).

## Troubleshooting

- `Generated site data is missing` → run `python3 scripts/build_persona_site_data.py`
- `ValueError: ... is empty or all-null` → the named YAML file is empty or all-null; populate or remove it
- `TypeError: Prose items must be string or list-of-strings` (or `Nested prose items must be strings`) → a YAML prose field has an unexpected nested structure; inspect the named risk/control
- Empty risks pane for a matched persona → see the Data Flow note on governance-only personas

## Related

- [Risk Map overview](../README.md)
- [Developing the framework](./developing.md)
- [Frontend test conventions](../../site/tests/README.md)
- [Identification Questions Style Guide](./contributing/identification-questions-style-guide.md)
- [YAML Prose Authoring Subset](./yaml-authoring-subset.md)
- [Repository CONTRIBUTING.md](../../CONTRIBUTING.md)
