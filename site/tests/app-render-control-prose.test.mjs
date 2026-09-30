/**
 * Tests for renderControlProse in site/assets/app.mjs.
 *
 * Contract: `renderControlProse(control)` takes a site-data control record
 * ({ description, guidance? }) and returns the HTML for the control's prose
 * block (design record control-description-and-guidance.md, Consumer
 * Contract: description is the summary; guidance is secondary and may be
 * presented collapsed):
 *
 *   (a) no guidance, description.length > 1  -> description[0] visible,
 *       description[1:] inside the collapsed <details> panel
 *   (b) guidance, description.length == 1    -> description[0] visible,
 *       guidance alone inside the panel
 *   (c) guidance, description.length > 1     -> description[0] visible,
 *       panel = description[1:] then guidance, in that order
 *   (d) no guidance, description.length == 1 -> no panel at all
 *
 * When guidance is present, the panel labels it with the static text
 * "Guidance", placed before the guidance content; no label otherwise.
 *
 * Escaping holds (ADR-015): both fields route through renderProse.
 *
 * A source-text assertion (same pattern as the sanitizer bounded-emission
 * tests) pins that renderControlGroups renders control prose through this
 * helper rather than an inline description-only branch.
 *
 * app.mjs reads document.querySelector("[data-app]") at module-load time, so
 * a minimal stub is installed on globalThis before the dynamic import (same
 * shim as app-render-rich-paragraphs.test.mjs).
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APP_PATH = path.join(__dirname, "../assets/app.mjs");

const elementMock = new Proxy(
  {
    addEventListener: () => {},
    querySelector: () => elementMock,
    querySelectorAll: () => [],
    closest: () => null,
    dataset: {},
    innerHTML: "",
  },
  {
    get(target, prop) {
      if (prop in target) {
        return target[prop];
      }
      return () => elementMock;
    },
    set() {
      return true;
    },
  },
);
globalThis.document = {
  querySelector: () => elementMock,
  querySelectorAll: () => [],
};
globalThis.window = {
  addEventListener: () => {},
  matchMedia: () => ({ matches: false }),
  scrollTo: () => {},
};
globalThis.fetch = () => Promise.reject(new Error("fetch stubbed in node test"));

const appModule = await import("../assets/app.mjs");
const { renderControlProse } = appModule;

// Distinct marker sentences so ordering can be asserted by string position.
const DESC_0 = "Objective sentence zero.";
const DESC_1 = "Description paragraph one.";
const DESC_2 = "Description paragraph two.";
const GUIDE_0 = "Guidance paragraph zero.";
const GUIDE_1 = "Guidance paragraph one.";

function control(description, guidance) {
  const record = { id: "controlExample", title: "Example", description };
  if (guidance !== undefined) {
    record.guidance = guidance;
  }
  return record;
}

/** Return the always-visible HTML: everything outside the <details>…</details> panel (all of it when no panel). */
function visibleOf(html) {
  const open = html.indexOf("<details");
  if (open === -1) {
    return html;
  }
  const close = html.indexOf("</details>", open);
  assert.notEqual(close, -1, `unterminated <details> in: ${html}`);
  return html.slice(0, open) + html.slice(close + "</details>".length);
}

/** Return the substring inside the single <details>…</details> panel, or null when absent. */
function panelOf(html) {
  const open = html.indexOf("<details");
  if (open === -1) {
    return null;
  }
  const close = html.indexOf("</details>", open);
  assert.notEqual(close, -1, `unterminated <details> in: ${html}`);
  return html.slice(open, close);
}

function countDetails(html) {
  return (html.match(/<details/g) || []).length;
}

/** Return the source text of the renderControlGroups function body. */
function renderControlGroupsSource() {
  const source = fs.readFileSync(APP_PATH, "utf8");
  const start = source.indexOf("function renderControlGroups(");
  assert.notEqual(start, -1, "app.mjs must define renderControlGroups");
  // The next top-level function declaration of any form (plain, exported,
  // async) bounds the body, so a helper declared right after it is excluded.
  const nextDecl = /\n(?:export\s+)?(?:async\s+)?function\s/g;
  nextDecl.lastIndex = start + 1;
  const match = nextDecl.exec(source);
  return match === null ? source.slice(start) : source.slice(start, match.index);
}

test("renderControlProse is exported from app.mjs", () => {
  assert.equal(
    typeof renderControlProse,
    "function",
    "app.mjs must export renderControlProse(control), the control prose render helper",
  );
});

test("(a) no guidance, len > 1: [0] visible, [1:] collapsed", () => {
  const out = renderControlProse(control([DESC_0, DESC_1, DESC_2]));
  const visible = visibleOf(out);
  const panel = panelOf(out);

  assert.equal(countDetails(out), 1, `exactly one panel expected: ${out}`);
  assert.ok(visible.includes(DESC_0), `description[0] must be visible above the panel: ${out}`);
  for (const marker of [DESC_1, DESC_2]) {
    assert.ok(!visible.includes(marker), `${JSON.stringify(marker)} must be collapsed, not visible: ${out}`);
  }
  assert.ok(panel.includes(DESC_1) && panel.includes(DESC_2), "description[1:] must be inside the panel");
  assert.ok(panel.indexOf(DESC_1) < panel.indexOf(DESC_2), "panel keeps description order");
  assert.ok(!panel.includes(DESC_0), "description[0] must not be repeated inside the panel");
});

test("(b) guidance, len == 1: [0] visible, guidance collapsed", () => {
  const out = renderControlProse(control([DESC_0], [GUIDE_0, GUIDE_1]));
  const visible = visibleOf(out);
  const panel = panelOf(out);

  assert.equal(countDetails(out), 1, `exactly one panel expected: ${out}`);
  assert.ok(visible.includes(DESC_0), `description[0] must be visible above the panel: ${out}`);
  for (const marker of [GUIDE_0, GUIDE_1]) {
    assert.ok(!visible.includes(marker), `${JSON.stringify(marker)} must be collapsed, not visible: ${out}`);
  }
  assert.ok(!panel.includes(DESC_0), "the panel holds guidance alone, not description[0]");
  assert.ok(panel.includes(GUIDE_0) && panel.includes(GUIDE_1), "guidance must be inside the panel");
  assert.ok(panel.indexOf(GUIDE_0) < panel.indexOf(GUIDE_1), "panel keeps guidance order");
});

test("(c) guidance, len > 1: [0] visible, panel = [1:] then guidance, in that order", () => {
  const out = renderControlProse(control([DESC_0, DESC_1, DESC_2], [GUIDE_0, GUIDE_1]));
  const visible = visibleOf(out);
  const panel = panelOf(out);

  assert.equal(countDetails(out), 1, `exactly one panel expected: ${out}`);
  assert.ok(visible.includes(DESC_0), `description[0] must be visible above the panel: ${out}`);
  for (const marker of [DESC_1, DESC_2, GUIDE_0, GUIDE_1]) {
    assert.ok(!visible.includes(marker), `${JSON.stringify(marker)} must be collapsed, not visible: ${out}`);
  }
  assert.ok(!panel.includes(DESC_0), "description[0] must not be repeated inside the panel");
  for (const marker of [DESC_1, DESC_2, GUIDE_0, GUIDE_1]) {
    assert.ok(panel.includes(marker), `panel must contain ${JSON.stringify(marker)}`);
  }
  // Panel order: description[1:] first, then guidance.
  assert.ok(panel.indexOf(DESC_2) < panel.indexOf(GUIDE_0), "description[1:] must come before guidance");
  assert.ok(panel.indexOf(DESC_1) < panel.indexOf(DESC_2), "description order preserved");
  assert.ok(panel.indexOf(GUIDE_0) < panel.indexOf(GUIDE_1), "guidance order preserved");
});

test("(d) no guidance, len == 1: no panel", () => {
  const out = renderControlProse(control([DESC_0]));

  assert.equal(countDetails(out), 0, `no panel expected: ${out}`);
  assert.ok(out.includes(DESC_0), "description[0] must be rendered");
});

test("(d') guidance absent as an empty array behaves like no guidance", () => {
  // The builder omits the key entirely; an explicit empty array must not
  // synthesise an empty panel either.
  const out = renderControlProse(control([DESC_0], []));

  assert.equal(countDetails(out), 0, `no panel expected for empty guidance: ${out}`);
  assert.ok(out.includes(DESC_0), "description[0] must be rendered");
});

test("description[0] renders through renderRichParagraphs (structured ref item)", () => {
  const out = renderControlProse(
    control([["See ", { type: "ref", id: "riskExample", title: "Example Risk" }, "."]], [GUIDE_0]),
  );

  assert.ok(out.includes('<a href="#riskExample">Example Risk</a>'), out);
  assert.ok(!out.includes("[object Object]"), out);
});

test("guidance renders through renderRichParagraphs (nested list and link item)", () => {
  const out = renderControlProse(
    control(
      [DESC_0],
      [
        ["Sub A.", "Sub B."],
        ["Cite (", { type: "link", title: "Paper", url: "https://example.com/paper" }, ")."],
      ],
    ),
  );
  const panel = panelOf(out);

  assert.ok(
    panel.includes('<div class="subsection"><p class="body-copy">Sub A.</p><p class="body-copy">Sub B.</p></div>'),
  );
  assert.ok(panel.includes('<a href="https://example.com/paper" rel="noopener noreferrer" target="_blank">Paper</a>'));
  assert.ok(!panel.includes("[object Object]"), panel);
});

test("escaping holds in both fields (ADR-015)", () => {
  const out = renderControlProse(
    control(
      ["<script>alert(1)</script> objective", "<b onmouseover=alert(2)>para</b>"],
      ['<img src=x onerror="alert(3)">'],
    ),
  );

  assert.ok(!out.includes("<script>"), out);
  assert.ok(!out.includes("<img"), out);
  assert.ok(!out.includes("<b "), out);
  assert.ok(out.includes("&lt;script&gt;"), out);
  assert.ok(out.includes("&lt;img"), out);
});

// ---------------------------------------------------------------------------
// Guidance label inside the panel.
// When guidance is present, the collapsed panel labels the guidance block with
// the static text "Guidance", placed after all description[1:] content and
// before the first guidance content. No label when guidance is absent/empty.
// The label is matched as a text segment equal to exactly "Guidance" so the
// tag and class stay the implementer's choice; the GUIDE_* markers contain the
// word but are never an exact segment match.
// ---------------------------------------------------------------------------

/** Trimmed, non-empty text segments between tags, in document order. */
function textSegments(html) {
  return html
    .split(/<[^>]+>/)
    .map((s) => s.trim())
    .filter(Boolean);
}

const LABEL = "Guidance";

test("label — (c) panel labels guidance after description[1:] and before the first guidance paragraph", () => {
  const out = renderControlProse(control([DESC_0, DESC_1, DESC_2], [GUIDE_0, GUIDE_1]));
  const panelSegs = textSegments(panelOf(out));

  assert.equal(textSegments(out).filter((s) => s === LABEL).length, 1, `exactly one "${LABEL}" label expected: ${out}`);
  assert.ok(!textSegments(visibleOf(out)).includes(LABEL), `label must be inside the panel, not visible: ${out}`);
  const labelIdx = panelSegs.indexOf(LABEL);
  assert.notEqual(labelIdx, -1, `label must be inside the panel: ${out}`);
  // Guard the ordering comparisons against a vacuous -1 on a missing segment.
  for (const marker of [DESC_1, DESC_2, GUIDE_0]) {
    assert.notEqual(panelSegs.indexOf(marker), -1, `${JSON.stringify(marker)} must be a panel segment: ${out}`);
  }
  assert.ok(
    labelIdx > panelSegs.indexOf(DESC_1) && labelIdx > panelSegs.indexOf(DESC_2),
    "label after description[1:]",
  );
  assert.ok(labelIdx < panelSegs.indexOf(GUIDE_0), "label before the first guidance paragraph");
});

test("label — (b) panel labels guidance when description has one paragraph", () => {
  const out = renderControlProse(control([DESC_0], [GUIDE_0, GUIDE_1]));
  const panelSegs = textSegments(panelOf(out));

  assert.equal(textSegments(out).filter((s) => s === LABEL).length, 1, `exactly one label expected: ${out}`);
  assert.ok(!textSegments(visibleOf(out)).includes(LABEL), `label must be inside the panel, not visible: ${out}`);
  const labelIdx = panelSegs.indexOf(LABEL);
  assert.notEqual(labelIdx, -1, `label must be inside the panel: ${out}`);
  assert.ok(labelIdx < panelSegs.indexOf(GUIDE_0), "label before the first guidance paragraph");
});

test("label — absent when guidance is absent or empty (a, d, d')", () => {
  const records = [
    control([DESC_0, DESC_1, DESC_2]),
    control([DESC_0]),
    control([DESC_0], []),
    control([DESC_0, DESC_1], []), // a panel exists (description[1:]) but empty guidance carries no label
  ];
  for (const record of records) {
    const out = renderControlProse(record);
    assert.ok(!textSegments(out).includes(LABEL), `no "${LABEL}" label expected without guidance: ${out}`);
  }
});

test("label — static text: input cannot forge or remove it", () => {
  // Guidance whose raw text tries to inject a label is escaped (ADR-015); the
  // one real label still precedes it.
  const forged = control([DESC_0], ["<span>Guidance</span> forged"]);
  // Non-contract record fields must not influence the label text or presence.
  forged.guidanceLabel = "";
  forged.label = "Forged";
  const out = renderControlProse(forged);
  const segs = textSegments(out);

  assert.ok(!segs.includes("Forged"), `label must not be read from record fields: ${out}`);

  assert.equal(segs.filter((s) => s === LABEL).length, 1, `exactly one label expected: ${out}`);
  assert.ok(!out.includes("<span>"), out);
  assert.ok(segs.indexOf(LABEL) < segs.findIndex((s) => s.includes("forged")), "label precedes the escaped content");
});

test("wiring — renderControlGroups renders control prose via renderControlProse", () => {
  // Structural enforcement: a correct helper that the card renderer never
  // calls would pass every behavioural test above while the site still
  // showed description only.
  // The body is matched unstripped: a `//` strip would also delete the rest of
  // any line containing a URL and could hide a forbidden call. Instead the
  // positive match is anchored on the template-interpolation form
  // `${renderControlProse(x)}`, which a call inside a comment cannot satisfy.
  const body = renderControlGroupsSource();

  assert.ok(
    /\$\{\s*renderControlProse\(\s*\w+\s*\)\s*\}/.test(body),
    "renderControlGroups must interpolate renderControlProse(<control record>) for each control card",
  );
  assert.ok(
    !/renderRichParagraphs\(\s*\w+\.description\b/.test(body),
    "renderControlGroups must render control prose only through renderControlProse",
  );
  assert.ok(
    !body.includes("description.slice(1)"),
    "renderControlGroups must not keep the inline description-only slice(1) branch",
  );
});
