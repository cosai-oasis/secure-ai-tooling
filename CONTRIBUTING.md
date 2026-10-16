# Contributing

## How to contribute?

The [Coalition for Secure AI (CoSAI)](https://www.coalitionforsecureai.org/) is an open-source project that is actively seeking contributions from any willing participants. Here are some guidelines for people that would like to contribute to the project.

In general, a CoSAI Contributor is expected to:

- be knowledgeable in one or more fields related to the project
- contribute to the developing and finalizing the workstream deliverables
- be reliable in completing issues to which they have been assigned
- show commitment over time with one or more PRs merged
- follow the project style and testing guidelines
- follow branch, PR, and code style conventions
- contribute in ways that substantially improve the quality of the project and the experience of people who use it

When contributing to any CoSAI repository, please first discuss the change you wish to make via a Github Issue, or in an email to the specific Workstream mailing list.

Please note this project follows the [OASIS Participants Code of Conduct](https://www.oasis-open.org/policies-guidelines/oasis-participants-code-of-conduct/); please be respectful of differing opinions when discussing potential contributions.

## Content Update Governance Process

CoSAI uses a two-stage governance process for content updates to our risk, control, and component framework. This process separates technical review from community governance, ensuring both code quality and community alignment.

### What Constitutes a Content Update

Content updates include changes to:

- Risk framework definitions and categories
- Security control specifications and mappings
- Component framework elements and relationships
- Framework documentation and guidance materials

### Two-Stage Process Overview

**Stage 1: Technical Review** - Content `feature` branches merge to the `develop` branch after standard PR review

**Stage 2: Community Review** - Bi-weekly CoSAI governance review of the `develop` branch's accumulated changes

```
feature-branch  →  develop    →    main
     ↑                 ↑             ↑
  Stage 1         Stage 2        Release
(Technical)       (Community)
```

### Non-Content Changes

The following types of changes are **not covered** by the two-stage content update process and continue to follow existing workflows:

- **Bug fixes** - Technical corrections and error resolution
- **Implementation changes** - Updates to code logic, algorithms, or system functionality
- **Infrastructure updates** - CI/CD, build processes, deployment configurations
- **Documentation fixes** - Corrections to technical documentation, README updates, etc.
- **Security patches** - Critical security-related fixes requiring immediate deployment
- **Dependency updates** - Library upgrades, security patches for dependencies

These excluded change types may follow direct-to-main workflows as determined by existing repository policies.

## First-time contributors

If you are new to the CoSAI project and are looking for an entry-point to make your first contribution, look at the open issues. Issues that are tagged with `good first issues` are meant to be small pieces of work that a first-time contributor can pick-up and complete. If you find one that you'd like to work on, please assign yourself or comment on the issue and one of the maintainers can assign it for you.

## Submitting a new issue

If you want to create a new issue that doesn't exist already, just open a new one.

### Using Issue Templates

This repository provides structured GitHub issue templates to streamline content proposals:

- **[Issue Templates Guide](risk-map/docs/contributing/issue-templates-guide.md)** - Complete guide for all 9 issue templates
  - Control templates (new/update)
  - Risk templates (new/update)
  - Component templates (new/update)
  - Persona templates (new/update)
  - Infrastructure template

The templates capture required information, reduce clarification cycles, and maintain consistency across proposals. They include automatic bidirectional mapping support, reference documentation links, and clear examples.

For framework content changes (controls, risks, components, personas), please use the appropriate issue template to ensure all necessary details are captured.

## Submitting a new pull request and review process

The process for submitting pull requests depends on the type of change:

### For Content Updates (Two-Stage Process)

Follow these steps when submitting content updates:

1. Fork this repo into your GitHub account. Read more about [forking a repo on Github here](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo).
2. Create a new branch, based on the `develop` branch, with a name that concisely describes what you're working on.
3. Ensure that your changes do not cause any existing tests to fail.
4. Submit a pull request against the `develop` branch.

#### Content Update PR Review

**Stage 1 Review**: Your PR to `develop` will be reviewed for technical criteria including code hygiene, formatting standards, commit message quality, and technical implementation correctness.

**Stage 2 Review**: Every 2 weeks, a PR will be created from `develop` to `main` containing all merged feature changes from the cycle period. This undergoes CoSAI community review using established consensus and voting procedures.

### For Non-Content Changes (Standard Process)

Follow these steps when submitting non-content changes (bug fixes, implementation changes, infrastructure updates, etc.):

1. Fork this repo into your GitHub account.
2. Create a new branch, based on the `main` branch, with a name that concisely describes what you're working on.
3. Ensure that your changes do not cause any existing tests to fail.
4. Submit a pull request against the `main` branch.

#### Non-Content PR Review

1. PR will be reviewed by the maintainers and approved by workstream leads or their delegates (maintainers)
2. Responses are due in 3 business days

### General Review Guidelines

The workstream maintainers are responsible for reviewing pull requests and issues in a timely manner (3 business days).

[Lazy consensus](https://openoffice.apache.org/docs/governance/lazyConsensus.html) is practiced for all projects and documents, including the main project repository and draft documents using other tools than Github.

Major changes on Github or to a WS document using any other official project platform should be accompanied by a post on the WS mailing list as appropriate. Author(s) of the proposal, Pull Requests, or issues, will give a time period of no less than seven (7) business days for comment and remain cognizant of popular observed world holidays.

## Branch naming and commit messages

### Branch naming

- `main` – main development branch and authoritative source; updated only after community approval for content changes
- `develop` - staging area for community review of content updates; feature branches for content changes target this branch
- `feature` – feature/this-is-a-new-feature-branch (target `develop` for content updates, `main` for non-content changes)
- `codebugfix` – codebugfix/name-of-the-bug (typically targets `main`)
- `languagefix` - languagefix/fix-details (typically targets `main`)
- `release` – release/1.0.0 - cut from main when ready

### Rebasing note

**For content updates**: After completing work on a feature branch, rebase `develop` before opening a PR. After PR is approved, rebase again to make sure changes from the latest `develop` are picked up before merging the PR.

**For non-content changes**: After completing work on a feature branch, rebase `main` before opening a PR. After PR is approved, rebase again to make sure changes from the latest `main` are picked up before merging the PR.

### Commit messages format

Commit messages follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>(<optional scope>): <description>

<optional body>

<optional trailers>
```

- **scope** (optional): the area changed, for example `risks`, `controls`, `components`, `personas`, `schema`, `frameworks`, `site`, `ci`, `deps`.
- **body** (optional): explains why the change is made, not only what changed.
- A breaking change adds `!` after the type or scope (`feat(schema)!: ...`) and may explain the break in a `BREAKING CHANGE:` footer.

This project also requires:

- **type**: one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- **description**: imperative mood, lowercase, no trailing period. Example: "add", not "added" or "adds".
- Trailers, such as the AI-assistance `Co-authored-by` trailer ([ADR-004](docs/adr/004-ai-assistant-trailer.md)), go at the end, separated by a blank line.

Pull request titles use the same format, because a squash merge uses the PR title as the commit subject.

Examples:

```
feat(risks): add a risk for poisoned agent memory
fix(schema): reject blank port styles in decoupled graph rendering
docs: describe the commit message format in CONTRIBUTING.md
build(deps): bump check-jsonschema to 0.38.2
```

## Signing the eCLA/iCLA

Anyone can do a pull request and commit. In order for your work to be merged, you will need to sign the iCLA (individual contributor agreement) if you are just contributing for yourself. If you are contributing on behalf of your company, you will also need to to sign the eCLA (entity contributor agreement). [Learn more about the CLAs here](https://www.oasis-open.org/open-projects/cla/).

The iCLA is administered by a bot which will comment on your PR and direct you to sign the iCLA if you haven't previously done so. This happens automatically when people submit a pull request.

### Subproject: Risk Map

If you are contributing to the CoSAI Risk Map (schemas and YAML under `risk-map/`), follow this document for branching, commits, PRs, and CLA.

- Risk Map authoring guide (schemas/YAML, IDs, validation, examples): see [`risk-map/docs/developing.md`](risk-map/docs/developing.md).

## Feedback

Questions or comments about this project's work may be composed as GitHub issues or comments or may be directed to the project's general email list at cosai-op@lists.oasis-open-projects.org. General questions about OASIS Open Projects may be directed to OASIS staff at [op-admin@lists.oasis-open-projects.org](mailto:op-admin@lists.oasis-open-projects.org).
