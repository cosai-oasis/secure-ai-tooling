# CoSAI Risk Map Explorer

The **CoSAI Risk Map Explorer** is a static GitHub Pages experience for CoSAI-RM persona matching and persona-driven risk/control browsing. Its initial release is intentionally narrow in scope.

## Prerequisites

- Python 3.14+ and Node.js 22+ (matches repo CI targets per `.mise.toml`)
- Framework YAML in `risk-map/yaml/` passes existing schema validation

## Scope

What the explorer is:

- Persona-driven navigation of risks and controls
- Static GitHub Pages deployment
- Zero backend, no answer storage

What the explorer is NOT:

- Scoring or grading of responses
- Persistence of answers across sessions (no cookies, no localStorage)
- A replacement for `risk-map/yaml/self-assessment.yaml` — the two coexist

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

The legacy `risk-map/yaml/self-assessment.yaml` remains unchanged and can coexist with the explorer.

## Local Build And Preview

Generate the site data:

```bash
uv run --locked --no-sync python scripts/build_persona_site_data.py
```

Serve the site directory locally:

```bash
python3 -m http.server --directory site 8000
```

Then open [http://localhost:8000](http://localhost:8000).

If you want to build into a different staging directory instead of `site/generated/`, pass `--site-dir` or `--output`:

```bash
uv run --locked --no-sync python scripts/build_persona_site_data.py --site-dir /tmp/cosai-persona-site
uv run --locked --no-sync python scripts/build_persona_site_data.py --output /tmp/persona-site-data.json
```

## Validation

Run the focused validations for the explorer:

```bash
ruff check .
pytest scripts/hooks/tests/test_build_persona_site_data.py
node --test site/tests/*.test.mjs
uv run --locked --no-sync python scripts/build_persona_site_data.py
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

## YAML Prose Allowed HTML

Prose fields (`longDescription`, `shortDescription`, `examples`, `description`) render as HTML without sanitization. Contributors may use:

- `<a href="..." target="_blank" rel="noopener">…</a>` — for citations and references
- `<strong>`, `<em>`, `<code>` — for emphasis and inline code

Reviewers must reject YAML containing any other tags. A future allowlist validator may codify this in automation.

Nested list syntax (`- - >`) encodes a logical sub-group within a prose field and renders as a visually distinct `<div class="subsection">`. Empty list entries (`- ""`) are silently dropped — do not use them as spacing hacks.

## Accessibility

The explorer implements:

- Visible focus rings on all interactive elements (`:focus-visible`)
- Honors `prefers-reduced-motion` to suppress animations and smooth scrolling
- Announces state changes via an aria-live status region (answer changes, step navigation, manual persona toggles, session reset)

Known gap: focus is not preserved across full-app re-renders (answering a question returns focus to `<body>`). Tracked as a follow-up issue filed alongside PR #223 (labels: `test-coverage`, `frontend`, `tech-debt`, `follow-up-from-pr-223`).

## Troubleshooting

- `Generated site data is missing` → run `uv run --locked --no-sync python scripts/build_persona_site_data.py`
- `ValueError: ... is empty or all-null` → the named YAML file is empty or all-null; populate or remove it
- `TypeError: Prose items must be string or list-of-strings` (or `Nested prose items must be strings`) → a YAML prose field has an unexpected nested structure; inspect the named risk/control
- Empty risks pane for a matched persona → see the Data Flow note on governance-only personas

## Related

- [Risk Map overview](../README.md)
- [Developing the framework](./developing.md)
- [Frontend test conventions](../../site/tests/README.md)
- [Identification Questions Style Guide](./contributing/identification-questions-style-guide.md)
- [Repository CONTRIBUTING.md](../../CONTRIBUTING.md)
