/**
 * Tests for site/assets/sanitizer.mjs — renderProse(input)
 *
 * RED phase: sanitizer.mjs does not yet exist. All tests fail with
 * ERR_MODULE_NOT_FOUND. The SWE agent creates the implementation.
 *
 * Test discipline per ADR-015 D3b:
 * - Per-tag positive fixtures (strong, em, a)
 * - Per-tag negative fixtures (strong, em, a)
 * - Allowlist–fixture meta-test (adding a tag without fixtures fails CI)
 * - Attack-corpus fixture tests for <a> XSS vectors
 * - Bounded-emission contract test (ALLOWED_TAGS is a literal const in source)
 * - Escape-with-warn behavior test (console.warn spy)
 * - Sentinel passthrough test
 * - Idempotence sanity test
 *
 * ---------------------------------------------------------------------------
 * SCOPE — expanded 2026-05-14 (B2 PR #295)
 * ---------------------------------------------------------------------------
 * renderProse accepts: string
 *                    | {type: "link", title: string, url: string}
 *                    | {type: "ref",  id: string,    title: string}
 * renderProse returns: string (HTML-safe prose fragment)
 *
 * Original A6 SCOPE: link items only. Ref items were OUT OF SCOPE for A6
 * with the assumption that "other site code paths" would handle them. The
 * conformance sweep's bleed-thru gate caught the unfulfilled assumption
 * (no other code path materialized; ref items leaked "[object Object]"
 * once B1 + B2 finished migrating every outbound anchor to sentinels). B2
 * extends renderProse to handle ref items as in-page fragment anchors per
 * ADR-015 D1 and ADR-016 D5. See ADR-016 D5 Addendum (2026-05-14).
 *
 * Ref-rendering shape:
 *   {type: "ref", id, title}  ->  <a href="#${escapeHtml(id)}">${escapeStructuredTitle(title)}</a>
 *
 * id is validated against ^[A-Za-z][A-Za-z0-9_-]*$ before emission. An id
 * that fails validation triggers the escape-with-warn path identically to
 * the link-item invalid-URL path.
 *
 * Fixture conventions for ref items:
 *   - positive fixtures under fixtures/sanitizer/positive/ carry tag "a"
 *     and "variant": "ref" to distinguish from link-item positive fixtures
 *   - negative fixtures under fixtures/sanitizer/negative/ carry
 *     negativeForTag "a" and (optionally) "variant": "ref"
 * ---------------------------------------------------------------------------
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// This import fails until the SWE agent creates sanitizer.mjs — correct for RED phase.
import { renderProse } from "../assets/sanitizer.mjs";

// ---------------------------------------------------------------------------
// Local reference copy of ALLOWED_TAGS.
// This is the contract the meta-test checks against: the test file's declared
// set must match the fixture set. The source-of-truth constant lives in
// sanitizer.mjs; this copy is a contract-check, not a shared dependency.
// ---------------------------------------------------------------------------
const ALLOWED_TAGS = ["strong", "em", "a"];

// Local reference copy of STRUCTURED_ITEM_TYPES. Same contract-check posture:
// source of truth is the literal const in sanitizer.mjs; this copy is checked
// against the source in the bounded-dispatch meta-test below.
const STRUCTURED_ITEM_TYPES = ["link", "ref"];

// Marker substring emitted by renderProse on unrecognised structured-item
// types. Duplicated from app-render-rich-paragraphs.test.mjs so the bleed-thru
// gate exists at this layer too — a regression that causes a known-type path
// (link or ref) to emit the marker must fail the sanitizer unit tests as well
// as the integration-layer tests, not only one of them.
const UNSUPPORTED_PROSE_ITEM_MARKER = "renderProse: unsupported prose-item type";

function countOccurrences(text, needle) {
  let count = 0;
  let position = 0;
  while ((position = text.indexOf(needle, position)) !== -1) {
    count += 1;
    position += needle.length;
  }
  return count;
}

function countHtmlCommentEndTags(html) {
  return countOccurrences(html, "-->") + countOccurrences(html, "--!>");
}

function assertNoStructuredItemBleedThrough(output) {
  assert.ok(!output.includes("[object Object]"), `Output leaked [object Object]: ${output}`);
  assert.ok(
    !output.includes(UNSUPPORTED_PROSE_ITEM_MARKER),
    `Output emitted unsupported structured-item marker on a known-type path: ${output}`,
  );
}

// ---------------------------------------------------------------------------
// Fixture loading helpers
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_ROOT = path.join(__dirname, "fixtures", "sanitizer");

/**
 * Read and parse a JSON fixture file. Throws with the file path on parse
 * error so failures are easy to locate.
 */
function loadFixture(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (err) {
    throw new Error(`Failed to parse fixture ${filePath}: ${err.message}`);
  }
}

/**
 * Enumerate all .json fixture files in a subdirectory of FIXTURE_ROOT.
 * Returns an array of {name, fixture} objects where name is the basename
 * without extension.
 */
function loadFixtures(subdir) {
  const dir = path.join(FIXTURE_ROOT, subdir);
  const entries = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
  return entries.map((f) => ({
    name: path.basename(f, ".json"),
    fixture: loadFixture(path.join(dir, f)),
  }));
}

// ---------------------------------------------------------------------------
// Positive fixtures
// Positive fixtures declare a "tag" field. The meta-test checks that every
// ALLOWED_TAGS entry has at least one positive fixture.
// ---------------------------------------------------------------------------

const positiveFixtures = loadFixtures("positive");

// Build a Map<tag, fixture[]> for the meta-test.
const positiveByTag = new Map();
for (const { fixture } of positiveFixtures) {
  const tag = fixture.tag;
  if (!positiveByTag.has(tag)) {
    positiveByTag.set(tag, []);
  }
  positiveByTag.get(tag).push(fixture);
}

// ---------------------------------------------------------------------------
// Negative fixtures
// Negative fixtures declare a "negativeForTag" field.
// ---------------------------------------------------------------------------

const negativeFixtures = loadFixtures("negative");

const negativeByTag = new Map();
for (const { fixture } of negativeFixtures) {
  const tag = fixture.negativeForTag;
  if (!negativeByTag.has(tag)) {
    negativeByTag.set(tag, []);
  }
  negativeByTag.get(tag).push(fixture);
}

// ---------------------------------------------------------------------------
// Attack-corpus fixtures
// ---------------------------------------------------------------------------

const attackFixtures = loadFixtures("attack-corpus");

// ---------------------------------------------------------------------------
// Helper: call renderProse with either a string or a structured item.
// The ADR describes renderProse(input: string): string, but for structured
// items ({type:"link",...}) the SWE agent will decide the exact calling
// convention. The most natural ESM export for the tokenizer + structured-item
// path is a single renderProse that accepts string | object. Tests use this
// wrapper so the calling convention is centralised here.
// ---------------------------------------------------------------------------

function callRenderProse(input) {
  return renderProse(input);
}

// ---------------------------------------------------------------------------
// Per-tag positive tests
// Given: an allowed input form for a tag
// When: renderProse is called
// Then: the output contains the expected HTML tag or substring
// ---------------------------------------------------------------------------

test("positive fixtures — each allowed input produces expected output substring", () => {
  for (const { name, fixture } of positiveFixtures) {
    const output = callRenderProse(fixture.input);

    if (fixture.expectedSubstring !== undefined) {
      assert.ok(
        output.includes(fixture.expectedSubstring),
        `Positive fixture '${name}': expected output to contain '${fixture.expectedSubstring}' but got: ${output}`,
      );
    }

    // Multi-attribute assertions for the <a> fixture (rel, target).
    if (fixture.expectedSubstringAlso !== undefined) {
      assert.ok(
        output.includes(fixture.expectedSubstringAlso),
        `Positive fixture '${name}': expected output to contain '${fixture.expectedSubstringAlso}' but got: ${output}`,
      );
    }
    if (fixture.expectedSubstringAndAlso !== undefined) {
      assert.ok(
        output.includes(fixture.expectedSubstringAndAlso),
        `Positive fixture '${name}': expected output to contain '${fixture.expectedSubstringAndAlso}' but got: ${output}`,
      );
    }
  }
});

// Separate targeted tests per tag so CI output names the failing tag clearly.

test("positive — **bold** input renders <strong> with no attributes", () => {
  const fixture = positiveByTag.get("strong")?.[0];
  assert.ok(fixture, "No positive fixture found for 'strong' tag");
  const output = callRenderProse(fixture.input);
  assert.ok(output.includes("<strong>"), `Expected <strong> in output: ${output}`);
  assert.ok(!output.includes("<strong "), `<strong> must have no attributes: ${output}`);
});

test("positive — *italic* input renders <em> with no attributes", () => {
  const fixture = positiveByTag.get("em")?.[0];
  assert.ok(fixture, "No positive fixture found for 'em' tag");
  const output = callRenderProse(fixture.input);
  assert.ok(output.includes("<em>"), `Expected <em> in output: ${output}`);
  assert.ok(!output.includes("<em "), `<em> must have no attributes: ${output}`);
});

test("positive — structured link item renders <a> with href, rel, target constructed by renderer", () => {
  // The a-https-link fixture declares expectedSubstring, expectedSubstringAlso, expectedSubstringAndAlso.
  const fixtures = positiveByTag.get("a");
  assert.ok(fixtures && fixtures.length > 0, "No positive fixture found for 'a' tag");
  const fixture = fixtures[0];
  const output = callRenderProse(fixture.input);

  // href must appear and start with https://
  assert.ok(output.includes('href="https://'), `Expected href=https:// in output: ${output}`);

  // rel and target are constructed by the renderer (ADR-015 D3a)
  assert.ok(output.includes('rel="noopener noreferrer"'), `Expected rel=noopener noreferrer: ${output}`);
  assert.ok(output.includes('target="_blank"'), `Expected target=_blank: ${output}`);

  // Bleed-thru gate at the unit layer: a known-type path must never emit the
  // unsupported-type marker nor leak String(object).
  assertNoStructuredItemBleedThrough(output);
});

test("positive — structured ref item renders in-page <a href='#id'> with no rel/target", () => {
  // Known-type path for the second STRUCTURED_ITEM_TYPES entry. Bleed-thru
  // gate at the unit layer mirrors the link-item assertion above.
  const output = callRenderProse({ type: "ref", id: "riskPromptInjection", title: "Prompt Injection" });
  assert.equal(output, '<a href="#riskPromptInjection">Prompt Injection</a>');
  assertNoStructuredItemBleedThrough(output);
});

test("positive — _italic_ underscore delimiter also renders <em>", () => {
  // Underscore italic is allowed per ADR-017 D1.
  const output = callRenderProse("This is _italic_ text.");
  assert.ok(output.includes("<em>"), `Expected <em> from underscore italic: ${output}`);
});

test("positive — plain text with no markup passes through as-is (no tags emitted)", () => {
  // Given: prose with no markdown tokens
  // When: renderProse is called
  // Then: output contains no HTML tags and the text is preserved
  const input = "Plain text with no special markup.";
  const output = callRenderProse(input);
  assert.ok(output.includes("Plain text"), `Expected plain text to pass through: ${output}`);
  assert.ok(!output.includes("<"), `Plain text must not produce any tags: ${output}`);
});

// ---------------------------------------------------------------------------
// Per-tag negative tests
// Given: a disallowed input related to an allowed tag
// When: renderProse is called
// Then: the disallowed form is escaped (not rendered as the tag)
// ---------------------------------------------------------------------------

test("negative fixtures — each disallowed input does not produce forbidden output", () => {
  for (const { name, fixture } of negativeFixtures) {
    const output = callRenderProse(fixture.input);

    if (fixture.mustNotContain !== undefined) {
      assert.ok(
        !output.includes(fixture.mustNotContain),
        `Negative fixture '${name}': output must NOT contain '${fixture.mustNotContain}' but got: ${output}`,
      );
    }
    if (fixture.mustNotContain2 !== undefined) {
      assert.ok(
        !output.includes(fixture.mustNotContain2),
        `Negative fixture '${name}': output must NOT contain '${fixture.mustNotContain2}' but got: ${output}`,
      );
    }
    if (fixture.expectedSubstring !== undefined) {
      assert.ok(
        output.includes(fixture.expectedSubstring),
        `Negative fixture '${name}': expected escaped form '${fixture.expectedSubstring}' in output but got: ${output}`,
      );
    }
  }
});

test("negative — __bold__ (double underscore) is not rendered as <strong>", () => {
  // ADR-017 D1: asterisk delimiter only; __bold__ is not in the subset.
  const output = callRenderProse("This is __not bold__ text.");
  assert.ok(!output.includes("<strong>"), `__bold__ must not produce <strong>: ${output}`);
});

test("negative — raw <strong> HTML is escaped, not passed through", () => {
  const output = callRenderProse("<strong>raw html</strong>");
  assert.ok(!output.includes("<strong>raw"), `Raw <strong> must not pass through: ${output}`);
  assert.ok(output.includes("&lt;strong&gt;"), `Raw <strong> must be escaped as &lt;strong&gt;: ${output}`);
});

test("negative — raw <em> HTML is escaped, not passed through", () => {
  const output = callRenderProse("<em>raw italic</em>");
  assert.ok(!output.includes("<em>raw"), `Raw <em> must not pass through: ${output}`);
  assert.ok(output.includes("&lt;em&gt;"), `Raw <em> must be escaped as &lt;em&gt;: ${output}`);
});

test("negative — markdown link [text](javascript:...) does not produce <a>", () => {
  // Authors do not write <a> markup; sentinels expanded by builder are the only path.
  // A markdown-style link in prose is disallowed by ADR-017 D2.
  const output = callRenderProse("[click me](javascript:alert(1))");
  assert.ok(!output.includes("<a "), `Markdown link must not produce <a>: ${output}`);
  assert.ok(!output.includes("javascript:"), `javascript: must not appear in output: ${output}`);
});

test("negative — structured link with http:// scheme does not produce <a>", () => {
  // ADR-015 D3a: href validated against ^https:// before insertion.
  const output = callRenderProse({ type: "link", title: "Insecure", url: "http://example.com" });
  assert.ok(!output.includes('<a href="http://'), `http:// link must not produce <a>: ${output}`);
});

test("negative — unknown structured item emits inert marker instead of object string", () => {
  const originalWarn = console.warn;
  const spy = { calls: [] };
  console.warn = (...args) => spy.calls.push(args);

  try {
    const output = callRenderProse({ type: "alien", title: "Unknown Type" });

    assert.equal(output, "<!-- renderProse: unsupported prose-item type: alien -->");
    assert.ok(!output.includes("[object Object]"), `Unknown structured item must not leak object string: ${output}`);
    assert.equal(
      spy.calls.length,
      1,
      `Unknown structured item must produce exactly one warning, got ${spy.calls.length}`,
    );
  } finally {
    console.warn = originalWarn;
  }
});

// ---------------------------------------------------------------------------
// Adversarial unknown-`type` sweep (PR #350 review items 1+6, 7-9).
//
// The inert-marker fallback is the load-bearing defence against future builder
// changes that introduce a structured-item type without simultaneously extending
// renderProse. The marker is wrapped in an HTML comment, so its containment
// depends on:
//   1. escapeHtml neutralising `>` so a hostile `type` cannot close the
//      comment early (HTML5 § 8.2.4.44 — comments end on `-->` or `--!>`).
//   2. describeUnsupportedType reducing non-string `type` to a label that
//      does not re-introduce "[object Object]".
//   3. describeUnsupportedType stripping null bytes so the raw innerHTML
//      stays greppable for the bleed-thru gate.
//
// Each fixture below pins one of those invariants. Failure means a future
// change to escapeHtml or describeUnsupportedType silently regressed the
// containment guarantee.
// ---------------------------------------------------------------------------

const ADVERSARIAL_TYPE_FIXTURES = [
  { label: "raw script tag in type", input: { type: "<script>alert(1)</script>" } },
  { label: "HTML comment terminator in type", input: { type: "-->" } },
  { label: "HTML comment opener in type", input: { type: "<!--" } },
  { label: "alternate comment terminator --!> in type", input: { type: "--!>" } },
  { label: "bare double-dash in type", input: { type: "--" } },
  { label: "quote-injection in type", input: { type: '"; alert(1); //' } },
  { label: "null byte in type", input: { type: "alien\x00js" } },
  { label: "object-valued type", input: { type: { nested: "ref" } } },
  { label: "array-valued type", input: { type: ["alien"] } },
  { label: "numeric type", input: { type: 42 } },
  { label: "boolean type", input: { type: true } },
  { label: "null type", input: { type: null } },
  { label: "missing type key", input: { foo: "bar" } },
  // Array as the whole input: enters the structured-item branch (typeof []
  // === "object", arr !== null) with input.type === undefined, so hits the
  // unknown-type path.
  { label: "array as input", input: ["a", "b"] },
];

test("adversarial — every unknown-type fixture stays HTML-inert and free of regression strings", () => {
  const originalWarn = console.warn;
  console.warn = () => {}; // silence per-fixture warns — assertion is on output, not stdout

  try {
    for (const { label, input } of ADVERSARIAL_TYPE_FIXTURES) {
      const output = callRenderProse(input);

      // Comment containment: one canonical close marker and no injected alternate terminator.
      assert.ok(output.startsWith("<!--"), `[${label}] marker must open as HTML comment: ${output}`);
      assert.ok(output.endsWith("-->"), `[${label}] marker must close as HTML comment: ${output}`);
      assert.equal(
        countHtmlCommentEndTags(output),
        1,
        `[${label}] marker must contain exactly one comment terminator: ${output}`,
      );
      assert.equal(
        countOccurrences(output, "<!--"),
        1,
        `[${label}] marker must contain exactly one comment opener: ${output}`,
      );

      // No raw script, no live HTML, no embedded null byte.
      assert.ok(!output.includes("<script>"), `[${label}] marker must not contain raw <script>: ${output}`);
      assert.ok(!output.includes("<script "), `[${label}] marker must not contain raw <script attr: ${output}`);
      assert.ok(
        !output.includes("\x00"),
        `[${label}] marker must not contain raw null byte: ${JSON.stringify(output)}`,
      );

      // Bleed-thru gate: the marker itself must not carry the regression
      // string the marker was introduced to prevent.
      assert.ok(!output.includes("[object Object]"), `[${label}] marker must not contain [object Object]: ${output}`);
    }
  } finally {
    console.warn = originalWarn;
  }
});

test("adversarial — null / primitive top-level inputs are not structured items (no marker)", () => {
  // These fall through the structured-item guard (input === null or typeof
  // input !== "object") and reach the plain-string path. They must not emit
  // the unsupported-type marker; they pass through as escaped plain text.
  for (const input of [null, undefined, 42, true, false, ""]) {
    const output = callRenderProse(input);
    assert.ok(
      !output.includes(UNSUPPORTED_PROSE_ITEM_MARKER),
      `Primitive input ${JSON.stringify(input)} must not emit the unsupported-type marker: ${output}`,
    );
  }
});

test("negative — raw <a href=...> in prose is escaped, not passed through", () => {
  // Authors do not write <a> markup; raw anchors in prose are disallowed per ADR-015 D1.
  const output = callRenderProse('<a href="https://example.com">click</a>');
  assert.ok(!output.includes("<a href="), `Raw <a href=> must be escaped: ${output}`);
  assert.ok(output.includes("&lt;a href="), `Raw <a> must appear as &lt;a href=: ${output}`);
});

// ---------------------------------------------------------------------------
// Allowlist–fixture meta-test (ADR-015 D3b)
// Asserts that every entry in ALLOWED_TAGS has at least one positive fixture
// AND at least one negative fixture. Adding a tag without fixtures fails here.
// ---------------------------------------------------------------------------

test("meta-test — every ALLOWED_TAGS entry has at least one positive and one negative fixture", () => {
  const missingPositive = ALLOWED_TAGS.filter((tag) => !positiveByTag.has(tag));
  const missingNegative = ALLOWED_TAGS.filter((tag) => !negativeByTag.has(tag));

  assert.deepEqual(
    missingPositive,
    [],
    `Tags missing positive fixtures: ${missingPositive.join(", ")}. Add a positive fixture file with "tag": "<tagname>" for each.`,
  );

  assert.deepEqual(
    missingNegative,
    [],
    `Tags missing negative fixtures: ${missingNegative.join(", ")}. Add a negative fixture file with "negativeForTag": "<tagname>" for each.`,
  );

  // Confirm the full coverage property: ALLOWED_TAGS.every(tag => fixtures.has(tag))
  const allCovered = ALLOWED_TAGS.every((tag) => positiveByTag.has(tag) && negativeByTag.has(tag));
  assert.ok(allCovered, "Not all ALLOWED_TAGS entries have both positive and negative fixtures.");
});

// ---------------------------------------------------------------------------
// Attack-corpus tests for <a> (ADR-015 D3b)
// Each fixture in attack-corpus/ must not produce <a> with the attack URL.
// Exception: the IDN homograph fixture documents a known limitation (see note
// in the fixture file) — the renderer cannot detect homograph spoofing from
// the scheme alone. That fixture uses expectedSubstring, not mustNotContain.
// ---------------------------------------------------------------------------

test("attack-corpus — each XSS vector fixture does not produce a live <a> tag", () => {
  for (const { name, fixture } of attackFixtures) {
    const output = callRenderProse(fixture.input);

    if (fixture.mustNotContain !== undefined) {
      assert.ok(
        !output.includes(fixture.mustNotContain),
        `Attack corpus '${name}': output must NOT contain '${fixture.mustNotContain}' but got: ${output}`,
      );
    }
    // Some fixtures also check that a specific second string is absent.
    if (fixture.mustNotContain2 !== undefined) {
      assert.ok(
        !output.includes(fixture.mustNotContain2),
        `Attack corpus '${name}': output must NOT contain '${fixture.mustNotContain2}' but got: ${output}`,
      );
    }
    // expectedSubstring is used in two scenarios:
    //   1. Documentation fixtures (IDN homograph): asserts the href appears for auditability.
    //   2. A4 trim-and-emit fixtures (whitespace URLs): asserts the trimmed <a href> is emitted.
    // Both cases require the assertion regardless of whether mustNotContain is also set.
    if (fixture.expectedSubstring !== undefined) {
      assert.ok(
        output.includes(fixture.expectedSubstring),
        `Attack corpus '${name}': expected '${fixture.expectedSubstring}' in output but got: ${output}`,
      );
    }
  }
});

// Targeted named tests for the mandatory vectors in the spec.

test("attack-corpus — javascript: URI (lowercase) in structured link does not produce <a>", () => {
  const output = callRenderProse({ type: "link", title: "xss", url: "javascript:alert(document.cookie)" });
  assert.ok(!output.includes("<a "), `javascript: URI must not produce <a>: ${output}`);
});

test("attack-corpus — javascript: URI (mixed case JaVaScRiPt:) does not produce <a>", () => {
  const output = callRenderProse({ type: "link", title: "xss", url: "JaVaScRiPt:alert(1)" });
  assert.ok(!output.includes("<a "), `Mixed-case javascript: URI must not produce <a>: ${output}`);
});

test("attack-corpus — javascript: URI with leading tab whitespace does not produce <a>", () => {
  const output = callRenderProse({ type: "link", title: "xss", url: "\tjavascript:alert(1)" });
  assert.ok(!output.includes("<a "), `Tab-prefixed javascript: URI must not produce <a>: ${output}`);
});

test("attack-corpus — data: URI in structured link does not produce <a>", () => {
  const output = callRenderProse({
    type: "link",
    title: "xss",
    url: "data:text/html,<script>alert(1)</script>",
  });
  assert.ok(!output.includes("<a "), `data: URI must not produce <a>: ${output}`);
});

test("attack-corpus — vbscript: URI in structured link does not produce <a>", () => {
  const output = callRenderProse({ type: "link", title: "xss", url: "vbscript:msgbox(1)" });
  assert.ok(!output.includes("<a "), `vbscript: URI must not produce <a>: ${output}`);
});

test("attack-corpus — protocol-relative URL (//evil.com) does not produce <a>", () => {
  const output = callRenderProse({ type: "link", title: "evil", url: "//evil.example.com/xss" });
  assert.ok(!output.includes("<a "), `Protocol-relative URL must not produce <a>: ${output}`);
});

test("attack-corpus — bare domain without scheme does not produce <a>", () => {
  const output = callRenderProse({ type: "link", title: "evil", url: "evil.example.com/page" });
  assert.ok(!output.includes("<a "), `Bare domain must not produce <a>: ${output}`);
});

test("attack-corpus — attribute injection via double-quote in link title does not inject onclick", () => {
  // If title is not escaped, naive interpolation breaks the element context.
  const output = callRenderProse({
    type: "link",
    title: '" onclick="alert(1)',
    url: "https://safe.example.com",
  });
  assert.ok(!output.includes("onclick="), `Title with double-quote must not inject onclick: ${output}`);
});

test("attack-corpus — URL with embedded null byte does not produce <a>", () => {
  // URL contains a null byte (U+0000) after the scheme.
  const url = "https://\x00evil.example.com";
  const output = callRenderProse({ type: "link", title: "null-byte", url });
  // Renderer must either reject the URL or strip the null byte.
  // It must not emit a raw null byte inside href.
  assert.ok(!output.includes("\x00"), `Output must not contain a null byte: ${JSON.stringify(output)}`);
});

// ---------------------------------------------------------------------------
// Bounded-emission contract test (ADR-015 D3a)
// Reads sanitizer.mjs source text and asserts ALLOWED_TAGS is declared as a
// literal const array in the module. This is structural enforcement: a reviewer
// cannot satisfy this test by deriving ALLOWED_TAGS from input or exporting it
// as mutable.
// ---------------------------------------------------------------------------

test("bounded-emission — ALLOWED_TAGS is declared as a literal const array in sanitizer.mjs source", async () => {
  const sanitizerPath = path.join(__dirname, "../assets/sanitizer.mjs");
  const source = fs.readFileSync(sanitizerPath, "utf8");

  // The pattern asserts ALLOWED_TAGS is a hard-coded const with 'strong' as the
  // first element — matching ADR-015 D3a's example literal.
  const literalConstPattern = /const\s+ALLOWED_TAGS\s*=\s*\[\s*['"]strong['"]/;

  assert.ok(
    literalConstPattern.test(source),
    "sanitizer.mjs must declare ALLOWED_TAGS as a literal const array starting with 'strong'. " +
      "It must not be a parameter, derived from input, or mutable. (ADR-015 D3a)",
  );

  // Also assert ALLOWED_TAGS includes all three required tags.
  assert.ok(source.includes("'em'") || source.includes('"em"'), "ALLOWED_TAGS must include 'em'");
  assert.ok(source.includes("'a'") || source.includes('"a"'), "ALLOWED_TAGS must include 'a'");
});

// ---------------------------------------------------------------------------
// Bounded-dispatch contract test (PR #350 review item 5).
// Mirrors the ALLOWED_TAGS bounded-emission test for structured-item types.
// Reads sanitizer.mjs source text and asserts:
//   1. STRUCTURED_ITEM_TYPES is declared as a literal const array
//   2. For each entry, a corresponding `input.type === "<type>"` dispatch arm
//      exists in source
// Adding a type to the const without extending the dispatch arms fails here.
// ---------------------------------------------------------------------------

test("bounded-dispatch — STRUCTURED_ITEM_TYPES is a literal const array in sanitizer.mjs source", () => {
  const sanitizerPath = path.join(__dirname, "../assets/sanitizer.mjs");
  const source = fs.readFileSync(sanitizerPath, "utf8");

  const literalConstPattern = /const\s+STRUCTURED_ITEM_TYPES\s*=\s*\[\s*['"]link['"]/;
  assert.ok(
    literalConstPattern.test(source),
    "sanitizer.mjs must declare STRUCTURED_ITEM_TYPES as a literal const array starting with 'link'. " +
      "It must not be a parameter, derived from input, or mutable.",
  );

  // Confirm the local copy in this test file matches the source-of-truth shape.
  for (const type of STRUCTURED_ITEM_TYPES) {
    assert.ok(
      source.includes(`'${type}'`) || source.includes(`"${type}"`),
      `STRUCTURED_ITEM_TYPES literal in source must include '${type}'`,
    );
  }
});

test("bounded-dispatch — every STRUCTURED_ITEM_TYPES entry has a matching dispatch arm in source", () => {
  // Structural enforcement of the fail-loud guarantee: adding a type to the
  // registry without extending renderProse's dispatch leaves the type
  // catch-all marker as the only handler — this meta-test catches that.
  const sanitizerPath = path.join(__dirname, "../assets/sanitizer.mjs");
  const source = fs.readFileSync(sanitizerPath, "utf8");

  for (const type of STRUCTURED_ITEM_TYPES) {
    const dispatchPattern = new RegExp(`input\\.type\\s*===\\s*['"]${type}['"]`);
    assert.ok(
      dispatchPattern.test(source),
      `sanitizer.mjs must contain a dispatch arm 'input.type === "${type}"' for STRUCTURED_ITEM_TYPES entry '${type}'.`,
    );
  }
});

// Per-type positive-coverage map. Each STRUCTURED_ITEM_TYPES entry must have
// at least one positive test case here. Adding a type without an entry fails
// the meta-test below — the test-coverage analogue of ADR-015 D3b.
const structuredTypePositiveCases = new Map([
  ["link", () => callRenderProse({ type: "link", title: "Sample", url: "https://example.com/" })],
  ["ref", () => callRenderProse({ type: "ref", id: "riskPromptInjection", title: "Prompt Injection" })],
]);

test("bounded-dispatch — every STRUCTURED_ITEM_TYPES entry has a positive test case", () => {
  for (const type of STRUCTURED_ITEM_TYPES) {
    const positiveCase = structuredTypePositiveCases.get(type);
    assert.ok(
      typeof positiveCase === "function",
      `STRUCTURED_ITEM_TYPES entry '${type}' must have a positive test case in structuredTypePositiveCases.`,
    );

    // Run the positive case and confirm it does NOT emit the unsupported-
    // type marker — i.e., the dispatch arm actually handles the type.
    const output = positiveCase();
    assert.ok(
      !output.includes(UNSUPPORTED_PROSE_ITEM_MARKER),
      `Positive case for '${type}' must not emit the unsupported-type marker; ` +
        `dispatch arm is missing or broken. Output: ${output}`,
    );
    assertNoStructuredItemBleedThrough(output);
  }
});

// ---------------------------------------------------------------------------
// Escape-with-warn behavior (ADR-015 D4)
// When renderProse encounters disallowed markup it must:
//   1. Escape the markup (not strip it)
//   2. Call console.warn("renderProse: escaped unexpected markup", ...) exactly once
// ---------------------------------------------------------------------------

test("escape-with-warn — disallowed markup is escaped and console.warn is called once per paragraph", () => {
  // Install a spy on console.warn.
  const originalWarn = console.warn;
  const spy = { calls: [] };
  console.warn = (...args) => spy.calls.push(args);

  try {
    const input = "<script>alert(1)</script>";
    const output = callRenderProse(input);

    // The disallowed markup must be escaped, not stripped.
    assert.ok(
      output.includes("&lt;script&gt;"),
      `Disallowed markup must be escaped as &lt;script&gt; but got: ${output}`,
    );
    assert.ok(!output.includes("<script>"), `Disallowed markup must not appear as raw HTML in output: ${output}`);

    // console.warn must have been called exactly once for this paragraph.
    assert.equal(
      spy.calls.length,
      1,
      `console.warn must be called exactly once per offending paragraph, got ${spy.calls.length} calls`,
    );

    // The first argument must be the canonical warning string per ADR-015 D4.
    const firstArg = spy.calls[0][0];
    assert.equal(
      firstArg,
      "renderProse: escaped unexpected markup",
      `console.warn first arg must be "renderProse: escaped unexpected markup" but got: ${firstArg}`,
    );
  } finally {
    // Always restore console.warn, even if assertions fail.
    console.warn = originalWarn;
  }
});

test("escape-with-warn — console.warn is called once for each offending paragraph, not once per token", () => {
  // Two disallowed tags in a single input string should produce exactly one warn call.
  const originalWarn = console.warn;
  const spy = { calls: [] };
  console.warn = (...args) => spy.calls.push(args);

  try {
    const input = "<strong>raw</strong> and <em>also raw</em>";
    callRenderProse(input);

    assert.equal(
      spy.calls.length,
      1,
      `Multiple disallowed tokens in one paragraph must produce exactly one warn call, got ${spy.calls.length}`,
    );
  } finally {
    console.warn = originalWarn;
  }
});

// ---------------------------------------------------------------------------
// Sentinel passthrough test (ADR-016 D5 fallback case)
// When sentinels ({{idXxx}} or {{ref:identifier}}) appear in prose that
// renderProse receives (i.e., the builder did not pre-expand them), the
// sentinel text must pass through as escaped literal text. Sentinels must NOT
// trigger tag emission and must NOT trigger console.warn.
// ---------------------------------------------------------------------------

test("sentinel passthrough — unexpanded {{idXxx}} sentinel passes through as escaped literal text", () => {
  const originalWarn = console.warn;
  const spy = { calls: [] };
  console.warn = (...args) => spy.calls.push(args);

  try {
    // Sentinel mixed with allowed bold markup.
    const input = "**important**: see {{idRisk001}} for details.";
    const output = callRenderProse(input);

    // The sentinel must appear verbatim (or HTML-escaped if it contains special chars,
    // but {{ and }} are not HTML-special so they pass through as-is).
    assert.ok(output.includes("{{idRisk001}}"), `Unexpanded sentinel must pass through as literal text: ${output}`);

    // No warn: sentinels are not disallowed markup.
    assert.equal(
      spy.calls.length,
      0,
      `Sentinels must not trigger console.warn, got ${spy.calls.length} calls: ${JSON.stringify(spy.calls)}`,
    );

    // Allowed bold markup still renders correctly alongside the sentinel.
    assert.ok(output.includes("<strong>"), `Bold markup must still render alongside sentinel: ${output}`);
  } finally {
    console.warn = originalWarn;
  }
});

test("sentinel passthrough — unexpanded {{ref:some-id}} sentinel passes through as literal text", () => {
  const input = "See {{ref:nist-800-53}} for the control baseline.";
  const output = callRenderProse(input);

  assert.ok(
    output.includes("{{ref:nist-800-53}}"),
    `Unexpanded ref sentinel must pass through as literal text: ${output}`,
  );
  // No tags produced from the sentinel.
  assert.ok(!output.includes("<a "), `Ref sentinel must not produce an <a> tag: ${output}`);
});

// ---------------------------------------------------------------------------
// Idempotence sanity test (ADR-015 D3a — bounded emission means the rendered
// output itself should not contain renderable markdown, so a second pass
// produces the same result for subset-compliant inputs).
// ---------------------------------------------------------------------------

test("idempotence — renderProse(renderProse(x)) equals renderProse(x) for a plain-text input", () => {
  // Given: a plain-text input with no markdown tokens and no HTML-special characters
  // When: renderProse is called twice
  // Then: the second call produces the same string as the first
  //
  // Idempotence holds only for plain-text inputs (locked interpretation A3).
  // Inputs containing markdown tokens (e.g. **bold**) are NOT idempotent: the
  // first pass produces <strong>bold</strong>, and the second pass correctly
  // escapes those angle brackets per ADR-015 D4, yielding a different string.
  // This test uses a plain-text input to verify the stable-point property
  // without triggering the non-idempotent markdown path.
  const input = "Plain prose with no special markup at all.";
  const firstPass = callRenderProse(input);
  const secondPass = callRenderProse(firstPass);

  assert.equal(
    secondPass,
    firstPass,
    `renderProse must be idempotent on plain-text input. ` + `First pass: ${firstPass}; Second pass: ${secondPass}`,
  );
});
