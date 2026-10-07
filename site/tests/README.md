# Frontend test conventions

Authoritative for ES-module tests under `site/tests/`. A pointer from `risk-map/docs/developing.md` leads here.

## Tooling

- **Runner:** `node --test` (Node ≥ 20; repo pins Node 24 via `.mise.toml`).
- **Assertions:** `node:assert/strict`.
- **No `package.json` devDependencies for testing.** The frontend test suite is zero-install and zero-framework.

## Scope

Pure-logic ES modules, plus the exported render helpers of `site/assets/app.mjs`. No DOM emulation, no `fetch`, no integration against a running site.

The canonical subject is `site/assets/persona-logic.mjs` — pure input→output functions. `site/assets/app.mjs` (the DOM renderer) is covered only through its exported string-returning helpers (`renderRichParagraphs`, `renderControlProse`): the test installs a minimal `document`/`window`/`fetch` stub on `globalThis` before a dynamic `import()` so the module body can load, then asserts on the returned HTML strings. Precedent: `app-render-rich-paragraphs.test.mjs`. Rendering that needs a real DOM (event wiring, `innerHTML` effects) is out of scope; see [Escalation](#escalation).

## Layout

| Piece             | Path                                             |
| ----------------- | ------------------------------------------------ |
| Test files        | `site/tests/*.test.mjs`                          |
| Module under test | `site/assets/*.mjs`                              |
| Imports from test | Relative ESM, e.g. `../assets/persona-logic.mjs` |
| CI invocation     | `.github/workflows/persona-pages.yml`            |

## Conventions

### File naming

`<module>.test.mjs` — one test file per module under test. Exception: `app.mjs` helpers get one file per helper, `app-render-<helper>.test.mjs`, because each file carries its own module-load shim.

### Imports

```js
import test from "node:test";
import assert from "node:assert/strict";
import { fn } from "../assets/<module>.mjs";
```

### Structure

Prefer flat `test("name", () => { ... })` calls. Introduce `describe()` only when nested grouping adds clarity (>10 tests in a file, or multiple distinct subjects).

### Assertions

Use the built-in `assert.equal`, `assert.deepEqual`, `assert.throws`, etc. Do not write custom matchers.

### Fixtures

Inline pure-data factories. **Do not** load real YAML or the generated `persona-site-data.json` from tests — Python tests (`scripts/hooks/tests/test_build_persona_site_data.py`) cover the data layer.

```js
function createFixture() {
  return {
    personas: [{ id: "personaExample", questionIds: ["q1"] /* ... */ }],
    risks: [{ id: "riskExample", personaIds: ["personaExample"] /* ... */ }],
    controls: [{ id: "controlExample", personaIds: ["personaExample"] /* ... */ }],
    questions: [{ id: "q1", prompt: "…" }],
    riskCategories: [{ id: "catExample", title: "Example" }],
    controlCategories: [{ id: "catExample", title: "Example" }],
    manualFallbackPersonaIds: [],
  };
}

test("buildResultsModel returns included personas", () => {
  const data = createFixture();
  const result = buildResultsModel(data, { q1: "yes" });
  assert.equal(result.includedPersonas.length, 1);
});
```

### Coverage expectation

Each exported function: at least one direct test, plus one per documented branch. See `persona-logic.test.mjs` for the reference pattern.

### Determinism

No `Math.random`, no date/time, no reliance on `Object.keys` iteration order, no network access, no filesystem writes or temp files. Read-only access to the module under test's own source text (or a checked-in fixture under `site/tests/fixtures/`) is permitted for structural assertions — precedent: the bounded-emission tests in `sanitizer.test.mjs` and the wiring test in `app-render-control-prose.test.mjs`.

## Running

### Local

From the repository root:

```
node --test site/tests/*.test.mjs
```

The shell expands the glob; no install step required. There is no built-in watch mode — rerun after edits.

### CI

`.github/workflows/persona-pages.yml` runs the same command on pull requests and pushes matching the workflow's `paths:` list.

## Concurrency

`node --test` runs each test file in its own separate process, in parallel by default. This is safe for pure-logic tests because each file's `createFixture()` constructs its own state and there is no shared global. The `app.mjs` helper tests are also safe: each file installs its own `globalThis` stub inside its own process, and no test mutates shared state.

If DOM-emulating tests are ever added (see [Escalation](#escalation)), they must be serialized — DOM globals cannot be shared safely across workers. Options at that time:

- `node --test --test-concurrency=1 <dom-test-files>` in a dedicated CI step.
- Run DOM tests from a separate runner (e.g., vitest with jsdom) isolated from the pure-logic suite.

Do **not** add locks or global mutexes to work around the default concurrency; keep each pure-logic test file hermetic, and escalate for DOM work.

## Coverage reporting

Not enforced in CI today. Available manually:

```
node --test --experimental-test-coverage site/tests/*.test.mjs
```

The flag is stable-ish in Node 24; output is verbose. Do not wire into CI without a dedicated PR that sets thresholds.

## Escalation

Adding any of the following requires its own PR, which updates this README:

- A new test framework (`vitest`, `jest`, `mocha`, etc.).
- A DOM emulator (`jsdom`, `happy-dom`).
- A browser harness (`playwright`, `cypress`).
- Coverage thresholds enforced in CI.

The PR must:

1. Justify the need with a concrete test case not expressible under `node --test`.
2. List rejected alternatives.
3. Pin the new dependency in `package.json`.
4. Update `.github/workflows/persona-pages.yml` (or a new workflow) to run it.
5. Update this README with any convention changes.

The current zero-dep property is easier to preserve than to reclaim.

## Canonical example

`site/tests/persona-logic.test.mjs` demonstrates every convention above: flat `test()` calls, inline `createFixture()` factory, `node:assert/strict` assertions, deterministic pure-logic coverage. Start there when writing a new test file.
