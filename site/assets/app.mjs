import { buildResultsModel } from "./persona-logic.mjs";

const APP_NAME = "CoSAI Risk Map Explorer";
const DATA_PATH = "./generated/persona-site-data.json";
const STEP_TITLES = ["Introduction", "Persona questions", "Matched persona summary", "Risks and controls"];

const state = {
  activeTab: "risks",
  answers: {},
  data: null,
  errorMessage: "",
  errorSteps: [],
  loading: true,
  manualSelectedIds: new Set(),
  personaOverrides: {},
  step: 0,
};

const appElement = document.querySelector("[data-app]");

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => {
    const replacements = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };

    return replacements[character] ?? character;
  });
}

function announceStatus(message) {
  const statusElement = document.getElementById("app-status");
  if (statusElement) {
    statusElement.textContent = message;
  }
}

function renderStatusCard({ eyebrow, title, copy, steps = [], note = "" }) {
  return `
    <section class="loading-card">
      <p class="eyebrow">${escapeHtml(eyebrow)}</p>
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(copy)}</p>
      ${
        steps.length
          ? `<ul class="status-list">
              ${steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}
            </ul>`
          : ""
      }
      ${note ? `<p class="status-note">${escapeHtml(note)}</p>` : ""}
    </section>
  `;
}

function getResultsModel() {
  if (!state.data) {
    return null;
  }

  return buildResultsModel(state.data, state.answers, [...state.manualSelectedIds], state.personaOverrides);
}

function renderRichParagraphs(items, className = "body-copy") {
  return items
    .map((item) => {
      if (Array.isArray(item)) {
        const inner = item.map((paragraph) => `<p class="${className}">${paragraph}</p>`).join("");
        return `<div class="subsection">${inner}</div>`;
      }
      return `<p class="${className}">${item}</p>`;
    })
    .join("");
}

function renderStepRail(resultsModel) {
  return `
    <nav class="step-rail" aria-label="Assessment steps">
      ${STEP_TITLES.map(
        (title, index) => `
          <button
            class="step-pill ${state.step === index ? "is-current" : ""} ${state.step > index ? "is-complete" : ""}"
            data-go-step="${index}"
            type="button"
          >
            <span class="step-pill-index">0${index + 1}</span>
            <span>${title}</span>
          </button>
        `,
      ).join("")}
      <div class="step-rail-card">
        <p class="eyebrow">Session state</p>
        <dl class="session-metrics">
          <div>
            <dt>Matched personas</dt>
            <dd>${resultsModel.selectedPersonas.length}</dd>
          </div>
          <div>
            <dt>Included in results</dt>
            <dd>${resultsModel.includedPersonas.length}</dd>
          </div>
          <div>
            <dt>Risk results</dt>
            <dd>${resultsModel.risks.length}</dd>
          </div>
          <div>
            <dt>Control results</dt>
            <dd>${resultsModel.controls.length}</dd>
          </div>
        </dl>
      </div>
    </nav>
  `;
}

function renderIntroduction() {
  return `
    <section class="step-panel intro-panel">
      <div class="hero-panel">
        <p class="eyebrow">${APP_NAME}</p>
        <h1>Find the CoSAI-RM personas that fit your work.</h1>
        <p class="hero-copy">
          The explorer is built for framework adoption, not for scoring. It uses the existing CoSAI-RM
          personas, risks, and controls as the source of truth and keeps every answer in your browser only.
        </p>
        <div class="hero-actions">
          <button class="primary-button" data-go-step="1" type="button">Start persona questions</button>
          <button class="ghost-button" data-go-step="3" type="button">Preview the results shape</button>
        </div>
      </div>
      <div class="card-grid">
        <article class="insight-card">
          <p class="eyebrow">How it works</p>
          <h2>Match one or more personas</h2>
          <p>
            Guided personas use role-identification questions from <code>personas.yaml</code>. Personas that do not
            yet have enough question coverage stay available through an integrated manual selector.
          </p>
        </article>
        <article class="insight-card">
          <p class="eyebrow">What you get</p>
          <h2>Risk and control views</h2>
          <p>
            The results merge and deduplicate the framework risks and controls linked to every matched persona, so you
            can browse the most relevant parts of CoSAI-RM without maintaining a separate web mapping.
          </p>
        </article>
        <article class="insight-card">
          <p class="eyebrow">Privacy posture</p>
          <h2>No backend, no server-side storage</h2>
          <p>
            Answers are held in browser memory for the current session only. Nothing is sent to a server and the site
            does not persist your answers with cookies or browser storage.
          </p>
        </article>
      </div>
    </section>
  `;
}

function renderQuestionGroups(resultsModel) {
  const guidedPersonas = state.data.personas.filter((persona) => persona.matchMode === "guided");
  const manualPersonas = state.data.personas.filter((persona) =>
    state.data.manualFallbackPersonaIds.includes(persona.id),
  );

  return `
    <section class="step-panel">
      <div class="step-header">
        <div>
          <p class="eyebrow">Step 2</p>
          <h1>Identify which personas apply.</h1>
        </div>
        <p class="step-copy">
          Answer <strong>Yes</strong> when a question describes your activity. A single yes can suggest a persona, and
          you can add manual-fallback personas in the same flow.
        </p>
      </div>

      <div class="layout-grid">
        <aside class="summary-panel">
          <p class="eyebrow">Current matches</p>
          ${
            resultsModel.selectedPersonas.length
              ? `<ul class="compact-list">
                  ${resultsModel.selectedPersonas
                    .map(
                      (persona) => `
                        <li>
                          <span>${escapeHtml(persona.title)}</span>
                          <span class="micro-tag">${persona.sourceLabel}</span>
                        </li>
                      `,
                    )
                    .join("")}
                </ul>`
              : `<p class="empty-copy">No personas are selected yet. Answer yes where a guided persona fits, or add a manual-fallback persona directly.</p>`
          }
        </aside>

        <div class="content-stack">
          ${guidedPersonas
            .map((persona) => {
              const isMatched = resultsModel.selectedPersonas.some((selected) => selected.id === persona.id);
              const questions = state.data.questions.filter((question) => question.personaId === persona.id);

              return `
                <article class="persona-question-card ${isMatched ? "is-matched" : ""}">
                  <header class="persona-card-header">
                    <div>
                      <p class="eyebrow">Guided persona</p>
                      <h2>${escapeHtml(persona.title)}</h2>
                    </div>
                    ${isMatched ? '<span class="status-tag">Suggested match</span>' : ""}
                  </header>
                  ${renderRichParagraphs(persona.description.slice(0, 1))}
                  <div class="question-stack">
                    ${questions
                      .map((question) => {
                        const currentAnswer = state.answers[question.id];

                        return `
                          <fieldset class="question-card">
                            <legend>${escapeHtml(question.prompt)}</legend>
                            <div class="answer-row">
                              <label class="answer-option ${currentAnswer === "yes" ? "is-selected" : ""}">
                                <input
                                  ${currentAnswer === "yes" ? "checked" : ""}
                                  data-question-id="${question.id}"
                                  name="${question.id}"
                                  type="radio"
                                  value="yes"
                                />
                                <span>Yes</span>
                              </label>
                              <label class="answer-option ${currentAnswer === "no" ? "is-selected" : ""}">
                                <input
                                  ${currentAnswer === "no" ? "checked" : ""}
                                  data-question-id="${question.id}"
                                  name="${question.id}"
                                  type="radio"
                                  value="no"
                                />
                                <span>No</span>
                              </label>
                            </div>
                          </fieldset>
                        `;
                      })
                      .join("")}
                  </div>
                </article>
              `;
            })
            .join("")}

          <section class="manual-selector">
            <div class="manual-selector-header">
              <div>
                <p class="eyebrow">Integrated fallback</p>
                <h2>Add personas that do not yet have full question coverage.</h2>
              </div>
              <p class="step-copy">
                The framework does not yet provide enough identification questions for every active persona. Select any
                manual-fallback persona that clearly applies to your role.
              </p>
            </div>
            <div class="manual-grid">
              ${manualPersonas
                .map((persona) => {
                  const checked = state.manualSelectedIds.has(persona.id);

                  return `
                    <label class="manual-card ${checked ? "is-selected" : ""}">
                      <input
                        ${checked ? "checked" : ""}
                        data-manual-persona-id="${persona.id}"
                        type="checkbox"
                      />
                      <span class="micro-tag">Manual fallback</span>
                      <h3>${escapeHtml(persona.title)}</h3>
                      <p>
                        Add this persona directly. The framework currently links it to
                        <strong>${persona.riskCount}</strong> risks and
                        <strong>${persona.controlCount}</strong> controls.
                      </p>
                    </label>
                  `;
                })
                .join("")}
            </div>
          </section>
        </div>
      </div>

      <div class="button-row">
        <button class="ghost-button" data-go-step="0" type="button">Back to introduction</button>
        <button
          class="primary-button"
          ${resultsModel.selectedPersonas.length ? "" : "disabled"}
          data-go-step="2"
          type="button"
        >
          Review matched personas
        </button>
      </div>
    </section>
  `;
}

function renderSummary(resultsModel) {
  return `
    <section class="step-panel">
      <div class="step-header">
        <div>
          <p class="eyebrow">Step 3</p>
          <h1>Confirm the personas you want in scope.</h1>
        </div>
        <p class="step-copy">
          Review how each persona was added, inspect the matched prompts, and remove anything that should not shape the
          results.
        </p>
      </div>

      ${
        resultsModel.selectedPersonas.length
          ? `<div class="review-grid">
              ${resultsModel.selectedPersonas
                .map(
                  (persona) => `
                    <label class="review-card ${persona.included ? "is-selected" : ""}">
                      <div class="review-card-top">
                        <input
                          ${persona.included ? "checked" : ""}
                          data-include-persona-id="${persona.id}"
                          type="checkbox"
                        />
                        <span class="status-tag">${persona.sourceLabel}</span>
                      </div>
                      <h2>${escapeHtml(persona.title)}</h2>
                      ${renderRichParagraphs(persona.description.slice(0, 1))}
                      <dl class="result-counts">
                        <div>
                          <dt>Risks</dt>
                          <dd>${persona.riskCount}</dd>
                        </div>
                        <div>
                          <dt>Controls</dt>
                          <dd>${persona.controlCount}</dd>
                        </div>
                      </dl>
                      ${
                        persona.matchedQuestionPrompts.length
                          ? `<div class="evidence-block">
                              <p class="eyebrow">Why it matched</p>
                              <ul class="bullet-list">
                                ${persona.matchedQuestionPrompts
                                  .map((prompt) => `<li>${escapeHtml(prompt)}</li>`)
                                  .join("")}
                              </ul>
                            </div>`
                          : `<div class="evidence-block">
                              <p class="eyebrow">Why it was added</p>
                              <p class="empty-copy">This persona was selected through the manual fallback path.</p>
                            </div>`
                      }
                    </label>
                  `,
                )
                .join("")}
            </div>`
          : `<div class="empty-state">
              <p class="eyebrow">Nothing selected yet</p>
              <h2>Answer the persona questions first.</h2>
              <p>You need at least one matched persona before the summary and results views have anything to show.</p>
            </div>`
      }

      <div class="button-row">
        <button class="ghost-button" data-go-step="1" type="button">Back to questions</button>
        <button
          class="primary-button"
          ${resultsModel.includedPersonas.length ? "" : "disabled"}
          data-go-step="3"
          type="button"
        >
          Open risks and controls
        </button>
      </div>
    </section>
  `;
}

function renderPersonaBadges(personas) {
  return personas.map((persona) => `<span class="persona-chip">${escapeHtml(persona.title)}</span>`).join("");
}

function renderRiskGroups(resultsModel) {
  if (!resultsModel.risks.length) {
    return `
      <div class="empty-state">
        <p class="eyebrow">No direct risks in scope</p>
        <h2>The selected personas do not currently map to persona-linked risks.</h2>
        <p>CoSAI-RM still links these personas to controls, so switch to the controls view for actionable guidance.</p>
      </div>
    `;
  }

  return resultsModel.riskGroups
    .map(
      (group) => `
        <section class="result-group">
          <header class="result-group-header">
            <p class="eyebrow">Risk category</p>
            <h2>${escapeHtml(group.category.title)}</h2>
          </header>
          <div class="result-grid">
            ${group.items
              .map(
                (risk) => `
                  <article class="result-card" id="${risk.id}">
                    <div class="result-card-top">
                      <div>
                        <p class="eyebrow">Risk</p>
                        <h3>${escapeHtml(risk.title)}</h3>
                      </div>
                      <span class="micro-tag">${escapeHtml(group.category.title)}</span>
                    </div>
                    ${renderRichParagraphs(risk.shortDescription)}
                    <div class="chip-row">
                      ${renderPersonaBadges(
                        resultsModel.includedPersonas.filter((persona) => risk.personaIds.includes(persona.id)),
                      )}
                    </div>
                    ${
                      risk.relatedControlIds.length
                        ? `<p class="link-row">
                            Relevant controls:
                            ${risk.relatedControlIds
                              .map(
                                (controlId) => `
                                  <a class="inline-link" href="#${controlId}">
                                    ${escapeHtml(
                                      resultsModel.controls.find((control) => control.id === controlId)?.title ??
                                        controlId,
                                    )}
                                  </a>
                                `,
                              )
                              .join("")}
                          </p>`
                        : ""
                    }
                    ${
                      risk.longDescription.length || risk.examples.length
                        ? `<details class="details-panel">
                            <summary>See CoSAI-RM content</summary>
                            ${renderRichParagraphs(risk.longDescription)}
                            ${
                              risk.examples.length
                                ? `<div class="examples-block">
                                    <p class="eyebrow">Examples</p>
                                    ${renderRichParagraphs(risk.examples)}
                                  </div>`
                                : ""
                            }
                          </details>`
                        : ""
                    }
                  </article>
                `,
              )
              .join("")}
          </div>
        </section>
      `,
    )
    .join("");
}

function renderControlGroups(resultsModel) {
  if (!resultsModel.controls.length) {
    return `
      <div class="empty-state">
        <p class="eyebrow">No controls in scope</p>
        <h2>The selected personas do not currently map to controls.</h2>
      </div>
    `;
  }

  return resultsModel.controlGroups
    .map(
      (group) => `
        <section class="result-group">
          <header class="result-group-header">
            <p class="eyebrow">Control category</p>
            <h2>${escapeHtml(group.category.title)}</h2>
          </header>
          <div class="result-grid">
            ${group.items
              .map(
                (control) => `
                  <article class="result-card" id="${control.id}">
                    <div class="result-card-top">
                      <div>
                        <p class="eyebrow">Control</p>
                        <h3>${escapeHtml(control.title)}</h3>
                      </div>
                      <span class="micro-tag">${escapeHtml(group.category.title)}</span>
                    </div>
                    ${
                      control.description.length > 1
                        ? `
                          ${renderRichParagraphs(control.description.slice(0, 1))}
                          <details class="details-panel">
                            <summary>See CoSAI-RM content</summary>
                            ${renderRichParagraphs(control.description.slice(1))}
                          </details>
                        `
                        : renderRichParagraphs(control.description)
                    }
                    <div class="chip-row">
                      ${renderPersonaBadges(
                        resultsModel.includedPersonas.filter((persona) => control.personaIds.includes(persona.id)),
                      )}
                    </div>
                    ${
                      control.relatedRiskIds.length
                        ? `<p class="link-row">
                            Related risks:
                            ${control.relatedRiskIds
                              .map(
                                (riskId) => `
                                  <a class="inline-link" href="#${riskId}">
                                    ${escapeHtml(
                                      resultsModel.risks.find((risk) => risk.id === riskId)?.title ?? riskId,
                                    )}
                                  </a>
                                `,
                              )
                              .join("")}
                          </p>`
                        : `<p class="empty-copy">No direct persona-linked risks are in scope for this control in the current session.</p>`
                    }
                  </article>
                `,
              )
              .join("")}
          </div>
        </section>
      `,
    )
    .join("");
}

function renderResults(resultsModel) {
  return `
    <section class="step-panel">
      <div class="step-header">
        <div>
          <p class="eyebrow">Step 4</p>
          <h1>Browse the risks and controls for your selected personas.</h1>
        </div>
        <p class="step-copy">
          This view is driven directly from the persona links already defined in the framework data. Shared risks and
          controls are merged automatically.
        </p>
      </div>

      <section class="results-overview">
        <div>
          <p class="eyebrow">Personas in scope</p>
          <div class="chip-row">${renderPersonaBadges(resultsModel.includedPersonas)}</div>
        </div>
        <dl class="session-metrics">
          <div>
            <dt>Risks</dt>
            <dd>${resultsModel.risks.length}</dd>
          </div>
          <div>
            <dt>Controls</dt>
            <dd>${resultsModel.controls.length}</dd>
          </div>
        </dl>
      </section>

      ${
        resultsModel.directRisklessPersonas.length
          ? `<div class="notice-banner">
              <p>
                <strong>${escapeHtml(resultsModel.directRisklessPersonas.map((persona) => persona.title).join(", "))}</strong>
                currently contributes controls but no direct persona-linked risks in the framework data.
              </p>
            </div>`
          : ""
      }

      <div class="tab-row" role="tablist" aria-label="Results views">
        <button
          aria-selected="${state.activeTab === "risks"}"
          class="tab-button ${state.activeTab === "risks" ? "is-active" : ""}"
          data-tab="risks"
          role="tab"
          type="button"
        >
          Risks
        </button>
        <button
          aria-selected="${state.activeTab === "controls"}"
          class="tab-button ${state.activeTab === "controls" ? "is-active" : ""}"
          data-tab="controls"
          role="tab"
          type="button"
        >
          Controls
        </button>
      </div>

      <div class="content-stack">
        ${state.activeTab === "risks" ? renderRiskGroups(resultsModel) : renderControlGroups(resultsModel)}
      </div>

      <div class="button-row">
        <button class="ghost-button" data-go-step="2" type="button">Back to persona summary</button>
        <button class="ghost-button" data-reset type="button">Start a new session</button>
      </div>
    </section>
  `;
}

function renderApp() {
  if (state.loading) {
    appElement.innerHTML = renderStatusCard({
      eyebrow: APP_NAME,
      title: "Loading framework-driven persona guidance",
      copy: "The explorer is preparing the generated CoSAI-RM dataset that drives persona matching, manual fallback coverage, and deduplicated risks and controls.",
      steps: [
        "Source of truth: framework YAML transformed into static JSON",
        "Privacy posture: answers stay in this browser session only",
        "Local preview hint: run `uv run --locked --no-sync python scripts/build_persona_site_data.py` if this never advances",
      ],
    });
    return;
  }

  if (state.errorMessage) {
    appElement.innerHTML = renderStatusCard({
      eyebrow: "Build required",
      title: "Generated site data is missing.",
      copy: state.errorMessage,
      steps: state.errorSteps,
    });
    return;
  }

  const resultsModel = getResultsModel();

  const stepContent =
    state.step === 0
      ? renderIntroduction()
      : state.step === 1
        ? renderQuestionGroups(resultsModel)
        : state.step === 2
          ? renderSummary(resultsModel)
          : renderResults(resultsModel);

  appElement.innerHTML = `
    <header class="site-header">
      <div>
        <p class="eyebrow">Coalition for Secure AI</p>
        <p class="brand-title">${APP_NAME}</p>
      </div>
      <p class="privacy-badge">Answers stay in this browser session only</p>
    </header>
    <div class="shell-layout">
      ${renderStepRail(resultsModel)}
      <div class="main-panel">${stepContent}</div>
    </div>
  `;
}

function resetSession() {
  state.activeTab = "risks";
  state.answers = {};
  state.manualSelectedIds = new Set();
  state.personaOverrides = {};
  state.step = 0;
}

async function loadSiteData() {
  try {
    const response = await fetch(DATA_PATH, { cache: "no-store" });

    if (!response.ok) {
      throw new Error(`Failed to load ${DATA_PATH}`);
    }

    state.data = await response.json();
    state.loading = false;
    renderApp();
  } catch (error) {
    state.errorMessage =
      "Run `uv run --locked --no-sync python scripts/build_persona_site_data.py` from the repository root before previewing the site locally.";
    state.loading = false;
    renderApp();
    console.error(error);
  }
}

appElement.addEventListener("click", (event) => {
  const stepTrigger = event.target.closest("[data-go-step]");
  if (stepTrigger) {
    state.step = Number(stepTrigger.dataset.goStep);
    renderApp();
    announceStatus(`Step: ${STEP_TITLES[state.step]}`);
    window.scrollTo({
      top: 0,
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    });
    return;
  }

  const tabTrigger = event.target.closest("[data-tab]");
  if (tabTrigger) {
    state.activeTab = tabTrigger.dataset.tab;
    renderApp();
    return;
  }

  if (event.target.closest("[data-reset]")) {
    resetSession();
    renderApp();
    announceStatus("Session reset. Returned to introduction.");
  }
});

appElement.addEventListener("change", (event) => {
  const questionInput = event.target.closest("[data-question-id]");
  if (questionInput) {
    const questionId = questionInput.dataset.questionId;
    state.answers[questionId] = questionInput.value;
    renderApp();
    const question = state.data?.questions.find((item) => item.id === questionId);
    if (question) {
      announceStatus(`Answer recorded: ${question.prompt}`);
    }
    return;
  }

  const manualInput = event.target.closest("[data-manual-persona-id]");
  if (manualInput) {
    const personaId = manualInput.dataset.manualPersonaId;
    const persona = state.data?.personas.find((item) => item.id === personaId);
    if (manualInput.checked) {
      state.manualSelectedIds.add(personaId);
      if (persona) {
        announceStatus(`Added persona: ${persona.title}`);
      }
    } else {
      state.manualSelectedIds.delete(personaId);
      if (persona) {
        announceStatus(`Removed persona: ${persona.title}`);
      }
    }

    renderApp();
    return;
  }

  const includeInput = event.target.closest("[data-include-persona-id]");
  if (includeInput) {
    state.personaOverrides[includeInput.dataset.includePersonaId] = includeInput.checked;
    renderApp();
  }
});

renderApp();
loadSiteData();
