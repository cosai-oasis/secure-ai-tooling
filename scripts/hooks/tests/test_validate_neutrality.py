#!/usr/bin/env python3
"""
Tests for scripts/hooks/precommit/validate_neutrality.py.

ADR-033 D2a/D5/D8 establish a "vendor-neutral shipping" contract for the
three authoring surfaces that ship in this repository: `scripts/agents/**`,
`scripts/skills/**`, and `scripts/agents-evals/**`. Prose in those trees
must not name a specific AI harness
product, company, CLI entry point, or model identifier; must not embed
harness-invocation stage directions (`<invoke ... tool>`, `subagent_type`,
"auto-loads"/"auto-triggers"); and must not reference harness-specific config
paths (`.claude/`, `.cursor/`, etc.). Framework-authority references (MITRE,
NIST, OWASP, ISO, EU AI Act, STRIDE) are legitimate content and must never be
flagged, even adjacent to real denylist hits.

A distinct structural rule governs YAML frontmatter: a `SKILL.md` file may
only declare `name`/`description` in its frontmatter; an agent `.md` file
(ADR-006 prose form, ordinarily frontmatter-free) must not declare a runtime-
binding key (`tools`, `model`, `color`, `allowed-tools`/`allowed_tools`) if it
happens to have a frontmatter block at all.

Public API under test (scripts/hooks/precommit/validate_neutrality.py):
    - `HOOK_NAME = "validate-neutrality"`
    - `Violation` frozen dataclass: `path`, `line`, `token`, `message`.
      `token` carries the matched offending snippet (e.g. "Claude Code",
      ".cursor/", "subagent_type") so a maintainer can grep for it.
    - `validate_file(path: Path) -> list[Violation]` — denylist scan (with
      allowlist suppression) plus frontmatter-key checks for one file.
      Returns `[]` (not `None`) when clean.
    - `discover_neutral_surface_files(root: Path) -> list[Path]` — files
      under `root/scripts/agents/**`, `root/scripts/skills/**`, and
      `root/scripts/agents-evals/**`.
    - `format_violation(violation: Violation) -> str` — stderr line,
      `<hook_name>: <file>:<line>: <message>`.
    - `main(argv: list[str]) -> int` — CLI entry point; explicit file args or
      self-discovery; returns 1 if any violations, else 0.

`scripts/hooks/precommit/_neutrality_data.py` is the sanctioned place vendor
tokens legitimately appear as detection data. Its exact export names are not
locked by this test file (see the single regression-guard test in
`TestFrameworkAllowlist`); behavioral coverage goes through `validate_neutrality`.

CRLF line-ending handling IS covered and locked (see `TestDocumentedGapsAndLockins`
E12): `splitlines()` plus `strip()`/YAML tolerate the trailing CR, so both the
frontmatter forbidden-key check and the body denylist scan fire correctly on
CRLF files. (An earlier revision of this suite declared CRLF out of scope; the
neutrality-hardening pass verified it is handled and locked it instead.)

Out of scope for this suite (documented so it doesn't read as an oversight):
frontmatter *required*-field validation (name/description presence). The
frontmatter tests here only enforce the ceiling — no extra/binding keys, and
fail-closed on unverifiable frontmatter — not the floor — required keys
present — which is deferred to a later phase that reconciles against the Agent
Skills reference validator.
"""

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "precommit"))

import validate_neutrality  # noqa: E402
from validate_neutrality import (  # noqa: E402
    discover_neutral_surface_files,
    format_violation,
    main,
    validate_file,
)


def _write_agent_file(tmp_path: Path, content: str, name: str = "test-agent.md") -> Path:
    """Write a synthetic agent-shaped file under <tmp_path>/scripts/agents/ and return its path."""
    agents_dir = tmp_path / "scripts" / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    path = agents_dir / name
    path.write_text(content, encoding="utf-8")
    return path


def _write_skill_file(tmp_path: Path, content: str, skill_dir: str = "example-skill") -> Path:
    """Write a synthetic SKILL.md under <tmp_path>/scripts/skills/<skill_dir>/ and return its path."""
    skill_path = tmp_path / "scripts" / "skills" / skill_dir
    skill_path.mkdir(parents=True, exist_ok=True)
    path = skill_path / "SKILL.md"
    path.write_text(content, encoding="utf-8")
    return path


def _write_plain_file(tmp_path: Path, relative: str, content: str) -> Path:
    """Write content at an arbitrary repo-relative path under tmp_path; used for scope-boundary tests."""
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_skill_reference_file(tmp_path: Path, content: str, name: str = "lexicon.md") -> Path:
    """
    Write a bundled reference file under scripts/skills/<skill>/references/ and return its path.

    Reference material (non-SKILL.md, nested below a skill's top level) is
    denylist-scanned but exempt from the malformed-frontmatter structural rule:
    it may legitimately open with a `---` markdown thematic break rather than a
    YAML frontmatter fence.
    """
    ref_dir = tmp_path / "scripts" / "skills" / "example-skill" / "references"
    ref_dir.mkdir(parents=True, exist_ok=True)
    path = ref_dir / name
    path.write_text(content, encoding="utf-8")
    return path


def _write_skill_asset_bytes(tmp_path: Path, relative: str, data: bytes, skill_dir: str = "example-skill") -> Path:
    """
    Write raw bytes at scripts/skills/<skill_dir>/<relative> and return its path.

    Used for bundled non-.md skill assets (binary icons, .sh/.toml scripts)
    that PR #428 review Finding 3 concerns: the discovery/validate_file text
    vs. binary policy split.
    """
    path = tmp_path / "scripts" / "skills" / skill_dir / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _write_nested_skill_md_reference(tmp_path: Path, content: str) -> Path:
    """
    Write a file literally named SKILL.md under a skill's references/ subdirectory.

    Distinguishes the canonical skill-root SKILL.md (scripts/skills/<name>/SKILL.md,
    structurally expected to carry frontmatter) from a same-named file nested
    deeper (scripts/skills/<name>/references/SKILL.md, bundled material that is
    NOT structurally expected to carry frontmatter).
    """
    ref_dir = tmp_path / "scripts" / "skills" / "example-skill" / "references"
    ref_dir.mkdir(parents=True, exist_ok=True)
    path = ref_dir / "SKILL.md"
    path.write_text(content, encoding="utf-8")
    return path


def _write_agents_evals_file(
    tmp_path: Path, content: str, agent_name: str = "example-agent", relative: str = "evals.json"
) -> Path:
    """
    Write a synthetic file under <tmp_path>/scripts/agents-evals/<agent_name>/<relative>.

    ADR-033 Amendment D8 ships agent portable evals at
    scripts/agents-evals/<agent-name>/evals.json, a sibling tree to
    scripts/agents/ and scripts/skills/. This tree does not exist anywhere in
    the repository yet (no PR has created it), so every test that uses this
    helper builds it as a synthetic tmp_path fixture, matching how
    _write_agent_file/_write_skill_file build the other two trees.
    """
    path = tmp_path / "scripts" / "agents-evals" / agent_name / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_agents_evals_asset_bytes(
    tmp_path: Path, relative: str, data: bytes, agent_name: str = "example-agent"
) -> Path:
    """
    Write raw bytes at scripts/agents-evals/<agent_name>/<relative> and return its path.

    Mirrors _write_skill_asset_bytes; used for the agents-evals tree's
    non-text-extension discovery-exclusion test.
    """
    path = tmp_path / "scripts" / "agents-evals" / agent_name / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


class TestDenylistVendorProductNames:
    """
    Vendor/product/company/CLI identifiers are flagged (ADR-033 denylist category 1).

    Each case proves validate_file returns a non-empty violation list and the
    violation names the actual offending text so a maintainer can grep for it.
    """

    @pytest.mark.parametrize(
        "token",
        [
            "Anthropic",
            "OpenAI",
            "Claude Code",
            "GitHub Copilot",
            "ChatGPT",
            "GPT",
            "Copilot",
            "Cursor",
            "Windsurf",
            "Codeium",
            "Gemini",
            "Cody",
            "Devin",
            "Aider",
        ],
    )
    def test_vendor_product_or_company_name_is_flagged(self, tmp_path, token):
        """
        Given: An agent file mentioning a specific vendor, product, company, or CLI name
        When: validate_file scans the file
        Then: At least one violation is returned naming that token
        """
        agent = _write_agent_file(tmp_path, f"This agent was tested against {token} during development.\n")

        violations = validate_file(agent)

        assert violations != []
        assert any(token in v.token or token in v.message for v in violations)

    @pytest.mark.parametrize(
        "model_id",
        ["claude-sonnet-4-5", "gpt-4o", "gemini-1.5-pro"],
    )
    def test_model_identifier_pattern_is_flagged(self, tmp_path, model_id):
        """
        Given: An agent file mentioning a model-identifier-shaped string
        When: validate_file scans the file
        Then: One violation names the matched model identifier
        """
        agent = _write_agent_file(tmp_path, f"Pin the model to {model_id} for reproducible output.\n")

        violations = validate_file(agent)

        assert violations != []
        assert any(model_id in v.token or model_id in v.message for v in violations)

    def test_bare_word_model_in_ordinary_prose_produces_no_violations(self, tmp_path):
        """
        Given: An agent file using "model" as ordinary neutral terminology (persona name,
               threat model, model card), with no model-identifier-shaped string present
        When: validate_file scans the file
        Then: No violations are produced

        The real corpus uses "model" pervasively as neutral terminology (Model
        Provider persona, threat model, model card). Only a model-identifier
        *pattern* (e.g. `claude-sonnet-4-5`, `gpt-4o`) is denylisted, never the
        bare word "model" — this is the false-positive class the ADR-033 brief
        specifically calls out.
        """
        agent = _write_agent_file(
            tmp_path,
            "The Model Provider persona owns the threat model and model card review.\n",
        )

        violations = validate_file(agent)

        assert violations == []

    def test_cli_entrypoint_lowercase_form_is_flagged(self, tmp_path):
        """
        Given: An agent file with a shell-command-shaped line invoking a lowercase CLI entry point,
               with no other denylisted token present in the fixture
        When: validate_file scans the file
        Then: The CLI invocation is flagged despite lacking the product's capitalized form

        Decision: the vendor/product denylist match is case-insensitive for the
        CLI-entrypoint shape so that `claude --resume` in example shell commands
        is caught even when written in lowercase. The fixture deliberately
        contains no model-identifier string (unlike the parametrized cases
        above) so this test isolates the lowercase/backtick CLI-entrypoint
        behavior rather than incidentally passing on an unrelated match.
        """
        agent = _write_agent_file(tmp_path, "Run `claude --resume` to continue the session.\n")

        violations = validate_file(agent)

        assert violations != []
        assert any("claude" in v.token.lower() or "claude" in v.message.lower() for v in violations)


class TestDenylistHarnessInvocationTokens:
    """Harness-invocation stage directions are flagged (ADR-033 denylist category 1)."""

    @pytest.mark.parametrize(
        "line",
        [
            "<invoke the Bash tool>",
            "<uses the Read tool>",
            "\\<invoke the Bash tool\\>",
        ],
        ids=["invoke_unescaped", "uses_unescaped", "invoke_backslash_escaped"],
    )
    def test_invoke_tool_stage_direction_is_flagged(self, tmp_path, line):
        """
        Given: An agent file containing an angle-bracket stage direction naming a tool invocation,
               either unescaped or backslash-escaped (the corpus convention seen in
               scripts/agents/*.md worked examples, e.g. `\\<invoke ... agent\\>`)
        When: validate_file scans the file
        Then: One violation names the offending stage direction

        The backslash-escaped form is included because the real corpus escapes
        angle brackets in worked examples to keep markdown renderers from
        treating them as HTML tags; the checker must not be fooled by the
        escaping into missing a real "tool" invocation shape.
        """
        agent = _write_agent_file(tmp_path, f"{line}\n")

        violations = validate_file(agent)

        assert violations != []

    @pytest.mark.parametrize("spelling", ["subagent_type", "subagent-type"])
    def test_subagent_type_token_is_flagged(self, tmp_path, spelling):
        """
        Given: An agent file containing a subagent_type/subagent-type key or token
        When: validate_file scans the file
        Then: One violation names the offending token
        """
        agent = _write_agent_file(tmp_path, f"Dispatch with {spelling}: general-purpose\n")

        violations = validate_file(agent)

        assert violations != []
        assert any(spelling in v.token or spelling in v.message for v in violations)

    @pytest.mark.parametrize(
        "phrase",
        ["auto-loads", "auto-loaded", "auto-triggers", "auto-triggered"],
    )
    def test_auto_loads_or_auto_triggers_phrasing_is_flagged(self, tmp_path, phrase):
        """
        Given: An agent file describing runtime dispatch with "auto-loads"/"auto-triggers" phrasing
        When: validate_file scans the file
        Then: One violation names the offending phrase
        """
        agent = _write_agent_file(tmp_path, f"This skill {phrase} when the description matches.\n")

        violations = validate_file(agent)

        assert violations != []

    def test_invoke_agent_without_tool_word_is_not_flagged(self, tmp_path):
        """
        Given: An angle-bracket stage direction naming a sub-agent but NOT a tool
               (`\\<invoke architect agent\\>`, the real shape used in scripts/agents/*.md)
        When: validate_file scans the file
        Then: No harness-invocation-token violation is produced

        The denylist shape requires the literal word "tool" inside the
        brackets. "invoke <agent-name> agent" is the repo's own convention for
        describing cross-agent handoff in prose and must not collide with the
        harness-invocation-token rule, or every agent definition file would
        self-flag on its own worked examples.
        """
        agent = _write_agent_file(tmp_path, "\\<invoke architect agent\\>\n")

        violations = validate_file(agent)

        assert violations == []


class TestDenylistHarnessConfigPaths:
    """Harness-specific config-path fragments are flagged (ADR-033 denylist category 1)."""

    @pytest.mark.parametrize(
        "config_path",
        [
            ".claude/",
            ".cursor/",
            ".windsurf/",
            ".aider/",
            ".continue/",
            ".codeium/",
            ".github/copilot",
        ],
    )
    def test_harness_config_path_is_flagged(self, tmp_path, config_path):
        """
        Given: An agent file mentioning a harness-specific config-path fragment
        When: validate_file scans the file
        Then: One violation names the offending path fragment
        """
        agent = _write_agent_file(tmp_path, f"Harness config lives under `{config_path}` in that environment.\n")

        violations = validate_file(agent)

        assert violations != []
        assert any(config_path in v.token or config_path in v.message for v in violations)

    def test_bare_github_directory_mention_is_not_flagged(self, tmp_path):
        """
        Given: An agent file mentioning bare `.github/` and `.github/workflows/` (the real
               architect.md cross-module-refactor bullet lists `.github/` among ordinary
               repo directories), with no `.github/copilot` fragment present
        When: validate_file scans the file
        Then: No harness-config-path violation is produced

        `.github/copilot` is the denylisted fragment, not bare `.github/`.
        `.github/` is an ordinary repository directory (CI workflows, issue
        templates) referenced constantly in legitimate agent prose; a
        substring match on bare `.github/` would false-positive on every such
        mention, the same collision class as the CLAUDE.md-vs-Claude-Code case.
        """
        agent = _write_agent_file(
            tmp_path,
            "Cross-module refactor: changes that touch `risk-map/`, `scripts/`, `.github/`, "
            "or `.github/workflows/` in the same change.\n",
        )

        violations = validate_file(agent)

        assert violations == []


class TestFrameworkAllowlist:
    """
    Framework-authority references never produce denylist violations (ADR-033 category 2).

    MITRE/ATLAS/ATT&CK, NIST/AI RMF, OWASP/Top 10, ISO, EU AI Act, and STRIDE
    are legitimate content in agent prose and must produce zero violations,
    individually and combined in one realistic multi-sentence fixture.
    """

    _FRAMEWORK_ALLOWLIST_CASES = [
        (
            "mitre_atlas",
            "Risks map to MITRE ATLAS techniques (AML.T0051); controls map to mitigations (AML.M0051).",
        ),
        ("nist_ai_rmf", "NIST AI RMF mappings use full-word function prefixes (GOVERN-1.1) at subcategory level."),
        ("owasp_top10", "OWASP LLM Top 10 IDs are versioned, e.g. LLM01:2025, from the current edition."),
        ("iso", "ISO 22989 and ISO/IEC 42001 define terminology and management-system requirements."),
        ("eu_ai_act", "The EU AI Act obligation is cited as Article 9 in the mapping."),
        ("stride", "STRIDE categories use canonical PascalCase values such as Tampering."),
    ]

    @pytest.mark.parametrize(
        ("label", "text"),
        _FRAMEWORK_ALLOWLIST_CASES,
        # IDs use only the short `label`, not the full sentence in `text` — a bare
        # per-argvalue id lambda would otherwise echo the whole sentence into the
        # test node ID since it applies across both parametrized arguments.
        ids=[label for label, _ in _FRAMEWORK_ALLOWLIST_CASES],
    )
    def test_framework_authority_reference_alone_produces_no_violations(self, tmp_path, label, text):
        """
        Given: An agent file containing one framework-authority reference and its ID form
        When: validate_file scans the file
        Then: No violations are produced
        """
        agent = _write_agent_file(tmp_path, f"{text}\n", name=f"{label}.md")

        violations = validate_file(agent)

        assert violations == []

    def test_combined_realistic_framework_mapping_prose_produces_no_violations(self, tmp_path):
        """
        Given: A realistic multi-sentence fixture combining all six framework-authority
               references in one file (phrasing borrowed from issue-response-reviewer.md's
               framework-mapping bullets)
        When: validate_file scans the file
        Then: No violations are produced
        """
        content = (
            "Framework-mapping IDs use the canonical form: STRIDE PascalCase (Tampering), "
            "NIST AI RMF full-word prefixes (GOVERN-1.1), OWASP versioned (LLM01:2025), "
            "EU AI Act Article 9. Risks map to MITRE ATLAS techniques (AML.T0051); controls "
            "map to MITRE ATLAS mitigations (AML.M0051). ISO 22989 and ISO/IEC 42001 define "
            "the terminology baseline.\n"
        )
        agent = _write_agent_file(tmp_path, content)

        violations = validate_file(agent)

        assert violations == []

    def test_allowlist_terms_are_present_in_the_data_module(self):
        """
        Given: The `_neutrality_data` module's framework-authority allowlist
        When: its allowlisted terms are inspected
        Then: MITRE, NIST, OWASP, ISO, EU AI Act, and STRIDE are all present

        Cheap regression guard against someone quietly dropping a framework
        term from the allowlist. This is the one test that reaches into
        `_neutrality_data` internals; its export name (`FRAMEWORK_ALLOWLIST_TERMS`)
        is a naming assumption the implementation step may need to reconcile.
        """
        from _neutrality_data import FRAMEWORK_ALLOWLIST_TERMS

        joined = " ".join(FRAMEWORK_ALLOWLIST_TERMS)
        for expected in ("MITRE", "NIST", "OWASP", "ISO", "EU AI Act", "STRIDE"):
            assert expected in joined, f"{expected!r} missing from framework allowlist terms"


class TestScopeBoundaries:
    """
    The checker scans only scripts/agents/** and scripts/skills/** (ADR-033 category 4).

    Denylist-violating content outside those two trees must never be flagged
    because it is out of scope, not because it is clean.
    """

    def test_discover_returns_files_under_agents_and_skills_only(self, tmp_path):
        """
        Given: A synthetic root with files under scripts/agents/, scripts/skills/,
               scripts/hooks/, and a repo-root doc
        When: discover_neutral_surface_files scans the root
        Then: Only the scripts/agents/ and scripts/skills/ files are returned
        """
        agent = _write_agent_file(tmp_path, "content\n")
        skill = _write_skill_file(tmp_path, "---\nname: x\ndescription: y\n---\nbody\n")
        _write_plain_file(tmp_path, "scripts/hooks/precommit/_neutrality_data.py", "DENYLIST = ['Anthropic']\n")
        _write_plain_file(tmp_path, "README.md", "Anthropic Claude Code Cursor\n")

        discovered = discover_neutral_surface_files(tmp_path)

        assert set(discovered) == {agent, skill}

    def test_vendor_term_outside_scope_tree_is_never_flagged_via_discovery(self, tmp_path):
        """
        Given: A repo-root doc (outside scripts/agents/**, scripts/skills/**) containing
               dense vendor-term content
        When: discover_neutral_surface_files scans the root and each result is validated
        Then: The out-of-scope doc never appears in the discovered set, so it produces
              no violations through the normal discovery path

        This proves the doc is invisible to the checker because it is out of
        scope — not because its content happens to be clean.
        """
        _write_plain_file(
            tmp_path,
            "docs/notes.md",
            "Anthropic, OpenAI, ChatGPT, Copilot, Cursor, Windsurf, Gemini, Cody, Devin, Aider.\n",
        )

        discovered = discover_neutral_surface_files(tmp_path)

        assert all("docs" not in path.parts for path in discovered)

    def test_scripts_hooks_own_home_is_excluded_even_when_walked_from_common_ancestor(self, tmp_path):
        """
        Given: scripts/agents/, scripts/skills/, and scripts/hooks/precommit/_neutrality_data.py
               (which legitimately lists vendor tokens as detection data) all under one
               common `scripts/` ancestor
        When: discover_neutral_surface_files scans the repo root
        Then: No path under scripts/hooks/ is ever returned, even though the same
              directory tree is walked from `tmp_path` as the common ancestor

        The denylist data module is the one sanctioned place vendor tokens
        legitimately appear as detection data; scanning must never reach it.
        """
        agent = _write_agent_file(tmp_path, "clean agent content\n")
        _write_plain_file(
            tmp_path,
            "scripts/hooks/precommit/_neutrality_data.py",
            "VENDOR_TERMS = ['Anthropic', 'Claude Code', 'Cursor', 'OpenAI']\n",
        )
        _write_plain_file(
            tmp_path,
            "scripts/hooks/precommit/validate_neutrality.py",
            "# scanner implementation, mentions Claude Code and Cursor as data\n",
        )

        discovered = discover_neutral_surface_files(tmp_path)

        assert discovered == [agent]
        assert all("hooks" not in path.parts for path in discovered)

    def test_absent_skills_subtree_contributes_nothing_without_erroring(self, tmp_path):
        """
        Given: A synthetic root with scripts/agents/ present (one file) and
               scripts/skills/ entirely absent
        When: discover_neutral_surface_files scans the root
        Then: The agent file is discovered, nothing is returned under
              scripts/skills/, and discovery does not error

        This is a synthetic-tree robustness test, not a real-repo assertion:
        it does not depend on whether scripts/skills/ exists in the real
        repository. The prior version of this test (formerly in
        TestLiveCorpus) asserted the REAL repo's scripts/skills/ was absent —
        a landmine that passes only until a real skill lands (e.g. ADR-031's
        classical-lexicon), at which point it would fail on any branch past
        that merge. discover_neutral_surface_files must tolerate either
        subtree being present or absent; this test locks that tolerance
        directly rather than via a fact about the live repo's current state.
        """
        agent = _write_agent_file(tmp_path, "clean agent content\n")
        assert not (tmp_path / "scripts" / "skills").exists()

        discovered = discover_neutral_surface_files(tmp_path)

        assert agent in discovered
        assert not any("skills" in path.parts for path in discovered)


class TestAgentsEvalsSubtree:
    """
    ADR-033 Amendment D8: scripts/agents-evals/<agent-name>/evals.json ships
    portable agent evals as a third authoring surface — a sibling tree to
    scripts/agents/ and scripts/skills/ — so eval JSON and D7b-style fixture
    Markdown shipped there get the same neutrality scan the other two trees
    already get.

    `discover_neutral_surface_files` walks this tree via a three-entry
    tuple, `("scripts/agents", "scripts/skills", "scripts/agents-evals")`
    (validate_neutrality.py:471), appended last to preserve the existing
    agents/skills discovery order.

    scripts/agents-evals/ does not exist anywhere in the repository yet (no
    PR has created it) — every fixture here is synthetic, built under
    tmp_path exactly like the existing scripts/agents/ and scripts/skills/
    fixtures elsewhere in this file.
    """

    def test_evals_json_under_agents_evals_is_discovered(self, tmp_path):
        """
        Given: scripts/agents-evals/<agent-name>/evals.json in a fixture repo root
        When: discover_neutral_surface_files scans the root
        Then: The evals.json file is included in the returned list
        """
        evals = _write_agents_evals_file(tmp_path, '{"cases": []}\n')

        discovered = discover_neutral_surface_files(tmp_path)

        assert evals in discovered

    def test_nested_fixture_under_agents_evals_is_discovered(self, tmp_path):
        """
        Given: scripts/agents-evals/<agent-name>/fixtures/some-fixture.md
               (nested subdirectory, matching how scripts/agents/** and
               scripts/skills/** already support nesting)
        When: discover_neutral_surface_files scans the root
        Then: The nested fixture file is included in the returned list
        """
        fixture = _write_agents_evals_file(
            tmp_path, "# Fixture\n\nSample D7b-style fixture content.\n", relative="fixtures/some-fixture.md"
        )

        discovered = discover_neutral_surface_files(tmp_path)

        assert fixture in discovered

    def test_discover_returns_files_from_all_three_trees(self, tmp_path):
        """
        Given: A fixture repo with files under scripts/agents/, scripts/skills/,
               and scripts/agents-evals/
        When: discover_neutral_surface_files scans the root
        Then: All three trees' files are returned, not just the two legacy trees
        """
        agent = _write_agent_file(tmp_path, "content\n")
        skill = _write_skill_file(tmp_path, "---\nname: x\ndescription: y\n---\nbody\n")
        evals = _write_agents_evals_file(tmp_path, '{"cases": []}\n')

        discovered = discover_neutral_surface_files(tmp_path)

        assert set(discovered) == {agent, skill, evals}

    def test_absent_agents_evals_subtree_contributes_nothing_without_erroring(self, tmp_path):
        """
        Given: A synthetic root with scripts/agents/ and scripts/skills/
               present (one file each) and scripts/agents-evals/ entirely absent
        When: discover_neutral_surface_files scans the root
        Then: Both legacy files are discovered, nothing is returned under
              scripts/agents-evals/, and discovery does not error

        Regression guard, mirroring
        test_absent_skills_subtree_contributes_nothing_without_erroring: the
        docstring's "Either subtree may be empty (or absent) without error"
        must extend to the third tree once it is added — a repo that has not
        adopted scripts/agents-evals/ yet must keep working exactly as it
        does today.
        """
        agent = _write_agent_file(tmp_path, "clean agent content\n")
        skill = _write_skill_file(tmp_path, "---\nname: x\ndescription: y\n---\nbody\n")
        assert not (tmp_path / "scripts" / "agents-evals").exists()

        discovered = discover_neutral_surface_files(tmp_path)

        assert set(discovered) == {agent, skill}
        assert not any("agents-evals" in path.parts for path in discovered)

    def test_agents_evals_files_land_after_skills_in_discovery_order(self, tmp_path):
        """
        Given: One file each under scripts/agents/, scripts/skills/, and
               scripts/agents-evals/
        When: discover_neutral_surface_files scans the root
        Then: The returned list orders agents first, skills second,
              agents-evals third

        Design decision, not an assumption: the docstring documents "agents
        subtree first, skills subtree second, each subtree sorted" for the
        two-tree case. Appending "scripts/agents-evals" to the walk tuple is
        the natural, low-risk extension — existing callers that rely on the
        agents-first/skills-second relative order are unaffected — so this
        test locks that ordering rather than, e.g., inserting agents-evals
        between agents and skills. If a later design decision picks a
        different ordering, this is the test that decision must update.
        """
        agent = _write_agent_file(tmp_path, "content\n")
        skill = _write_skill_file(tmp_path, "---\nname: x\ndescription: y\n---\nbody\n")
        evals = _write_agents_evals_file(tmp_path, '{"cases": []}\n')

        discovered = discover_neutral_surface_files(tmp_path)

        assert discovered.index(agent) < discovered.index(skill) < discovered.index(evals)

    def test_non_text_file_under_agents_evals_is_excluded(self, tmp_path):
        """
        Given: A non-text asset (.png) under scripts/agents-evals/<agent-name>/
        When: discover_neutral_surface_files scans the root
        Then: The .png file is excluded, matching the existing text-extension
              filter behavior already locked for scripts/agents/** and
              scripts/skills/** (test_discovery_excludes_binary_asset)
        """
        icon = _write_agents_evals_asset_bytes(
            tmp_path,
            "assets/icon.png",
            b"\x89PNG\r\n\x1a\n" + b"\x00\x01\x02\x03" * 16 + b"\xff\xfe\xfd",
        )
        evals = _write_agents_evals_file(tmp_path, '{"cases": []}\n')

        discovered = discover_neutral_surface_files(tmp_path)

        assert icon not in discovered
        assert evals in discovered

    def test_dangling_symlink_under_agents_evals_is_discovered(self, tmp_path):
        """
        Given: A dangling symlink (broken target) under
               scripts/agents-evals/<agent-name>/
        When: discover_neutral_surface_files scans the root
        Then: The dangling symlink is included, matching the documented
              behavior already locked for scripts/agents/** and
              scripts/skills/** (test_e10_dangling_symlink_is_discovered_and_flagged)
        """
        target_dir = tmp_path / "scripts" / "agents-evals" / "example-agent"
        target_dir.mkdir(parents=True, exist_ok=True)
        link = target_dir / "dangling.json"
        link.symlink_to(target_dir / "nonexistent-target.json")

        discovered = discover_neutral_surface_files(tmp_path)

        assert link in discovered, (
            "a dangling symlink under scripts/agents-evals/ must be discovered, not filtered out"
        )


class TestFrontmatterRulesSkill:
    """SKILL.md frontmatter may declare only `name` and `description` (ADR-033 category 3)."""

    def test_skill_frontmatter_with_only_name_and_description_passes(self, tmp_path):
        """
        Given: A SKILL.md with a frontmatter block containing only name and description
        When: validate_file scans the file
        Then: No violations are produced
        """
        skill = _write_skill_file(
            tmp_path,
            "---\nname: example-skill\ndescription: Does one thing well.\n---\n\nBody text.\n",
        )

        violations = validate_file(skill)

        assert violations == []

    @pytest.mark.parametrize("extra_key", ["license", "version", "tools", "allowed-tools", "model"])
    def test_skill_frontmatter_with_extra_key_fails_naming_it(self, tmp_path, extra_key):
        """
        Given: A SKILL.md frontmatter block with name, description, and one extra key
        When: validate_file scans the file
        Then: One violation names the offending extra key
        """
        skill = _write_skill_file(
            tmp_path,
            f"---\nname: example-skill\ndescription: Does one thing well.\n{extra_key}: something\n---\n\nBody.\n",
        )

        violations = validate_file(skill)

        assert violations != []
        assert any(extra_key in v.token or extra_key in v.message for v in violations)


class TestFrontmatterRulesAgent:
    """Agent .md frontmatter (if present at all) must not carry a runtime-binding key."""

    def test_agent_file_with_no_frontmatter_passes(self, tmp_path):
        """
        Given: An agent .md file in the normal ADR-006 prose form (header, ## Agent,
               ## Composition, body — no frontmatter block at all)
        When: validate_file scans the file
        Then: No frontmatter-rule violations are produced

        A file with no frontmatter block at all is trivially compliant.
        """
        agent = _write_agent_file(
            tmp_path,
            "# Example Agent\n\n## Agent\n\n- **Name:** example\n\n## Composition\n\nBody.\n",
        )

        violations = validate_file(agent)

        assert violations == []

    @pytest.mark.parametrize("binding_key", ["tools", "model", "color", "allowed-tools", "allowed_tools"])
    def test_agent_frontmatter_with_binding_key_fails_naming_it(self, tmp_path, binding_key):
        """
        Given: An agent .md file with a synthetic frontmatter block containing one
               runtime-binding key
        When: validate_file scans the file
        Then: One violation names the offending key

        Both the hyphen (`allowed-tools`) and underscore (`allowed_tools`)
        spellings are treated as equivalent binding keys.
        """
        agent = _write_agent_file(
            tmp_path,
            f"---\ndescription: Example agent.\n{binding_key}: something\n---\n\n# Example Agent\n\nBody.\n",
        )

        violations = validate_file(agent)

        assert violations != []
        assert any(binding_key in v.token or binding_key in v.message for v in violations)

    def test_agent_frontmatter_with_only_neutral_keys_passes(self, tmp_path):
        """
        Given: An agent .md file with a synthetic frontmatter block containing only
               a neutral key (description)
        When: validate_file scans the file
        Then: No frontmatter-rule violations are produced

        Agents do not normally carry frontmatter, but if one legitimately does
        (e.g. a future non-binding metadata key), the rule must not blanket-fail
        every frontmatter block — only the specific binding keys.
        """
        agent = _write_agent_file(
            tmp_path,
            "---\ndescription: Example agent with benign frontmatter.\n---\n\n# Example Agent\n\nBody.\n",
        )

        violations = validate_file(agent)

        assert violations == []


class TestCli:
    """The CLI exits non-zero only when violations are present."""

    def test_main_returns_zero_on_clean_corpus(self, tmp_path, capsys):
        """
        Given: A synthetic tmp_path corpus with a clean agent file and a clean skill file
        When: main is invoked with both explicit paths
        Then: It returns 0 and emits no stderr output
        """
        agent = _write_agent_file(tmp_path, "# Clean Agent\n\n## Agent\n\nNo vendor terms here.\n")
        skill = _write_skill_file(tmp_path, "---\nname: clean-skill\ndescription: Clean.\n---\nBody.\n")

        exit_code = main([str(agent), str(skill)])

        assert exit_code == 0
        assert capsys.readouterr().err == ""

    def test_main_returns_one_and_writes_violations_to_stderr(self, tmp_path, capsys):
        """
        Given: An agent file mentioning a denylisted vendor product
        When: main is invoked with the explicit file path
        Then: It returns 1 and writes a file:line violation to stderr
        """
        agent = _write_agent_file(tmp_path, "Built and tested with Claude Code.\n")

        exit_code = main([str(agent)])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert f"{agent}:1:" in captured.err
        assert "Claude Code" in captured.err

    def test_main_honors_explicit_file_args_over_discovery(self, tmp_path, capsys):
        """
        Given: An explicit file path outside scripts/agents/**/scripts/skills/** that
               contains a denylisted vendor term
        When: main is invoked with that explicit path (as pre-commit would pass a
               matched filename directly)
        Then: The file is validated and flagged

        `main()` does not re-filter explicit args by scope; scope enforcement is
        `discover_neutral_surface_files`'s job for the no-args path. Pre-commit's
        own `files:` regex is what restricts which files ever reach this hook.
        """
        out_of_scope = _write_plain_file(tmp_path, "docs/notes.md", "Written using ChatGPT.\n")

        exit_code = main([str(out_of_scope)])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert "ChatGPT" in captured.err

    def test_main_self_discovers_from_cwd_with_no_args(self, tmp_path, monkeypatch, capsys):
        """
        Given: A synthetic tmp_path root with scripts/agents/ and scripts/skills/ subtrees,
               one of which contains a violation
        When: main is invoked with no file args from that root as cwd
        Then: It discovers the files itself and returns 1
        """
        _write_agent_file(tmp_path, "Powered by Anthropic's models.\n")
        _write_skill_file(tmp_path, "---\nname: clean-skill\ndescription: Clean.\n---\nBody.\n")
        monkeypatch.chdir(tmp_path)

        exit_code = main([])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert "Anthropic" in captured.err

    def test_main_self_discovers_clean_corpus_returns_zero(self, tmp_path, monkeypatch, capsys):
        """
        Given: A synthetic tmp_path root with only clean agent/skill files
        When: main is invoked with no file args from that root as cwd
        Then: It returns 0 with no stderr output
        """
        _write_agent_file(tmp_path, "# Clean Agent\n\n## Agent\n\nNo vendor terms.\n")
        _write_skill_file(tmp_path, "---\nname: clean-skill\ndescription: Clean.\n---\nBody.\n")
        monkeypatch.chdir(tmp_path)

        exit_code = main([])

        assert exit_code == 0
        assert capsys.readouterr().err == ""

    def test_format_violation_includes_hook_name_file_line_and_message(self, tmp_path):
        """
        Given: A violation produced by validate_file
        When: format_violation renders it
        Then: The rendered line follows `<hook_name>: <file>:<line>: <message>`
        """
        agent = _write_agent_file(tmp_path, "Uses Cursor for editing.\n")

        violations = validate_file(agent)
        rendered = format_violation(violations[0])

        assert rendered.startswith("validate-neutrality: ")
        assert f"{agent}:1:" in rendered


@pytest.mark.live_corpus
class TestLiveCorpus:
    """
    Runs the checker against the real repository's scripts/agents/ (and, when
    present, scripts/skills/) directories.

    The live corpus is expected to be CLEAN, full stop — not clean because
    scripts/skills/ happens to be absent. architect.md's former self-referential
    vendor mentions ("Claude Code"/"Cursor" and their config paths, cited as
    literal text in its style rule) were scrubbed on this branch (commit
    c774caf, "removes vendor-name leakage from the canonical architect agent"),
    so it now passes the checker with zero violations. Whatever lands under
    scripts/skills/ in the future (e.g. ADR-031's authoring-corpus skills) must
    also be clean; these tests do not assert anything about scripts/skills/'s
    presence or absence, only that the whole discovered set is clean when
    validated.

    (Discovery's tolerance of an absent scripts/skills/ subtree is a
    synthetic-tree robustness property, not a live-corpus fact, and is covered
    in TestScopeBoundaries instead — asserting it here against the real repo
    would break the moment a real skill merges.)
    """

    def test_architect_md_is_now_clean(self, repo_root):
        """
        Given: The real scripts/agents/architect.md after its vendor-name leakage
               was scrubbed on this branch (commit c774caf)
        When: discover_neutral_surface_files + validate_file scan the corpus
        Then: architect.md is discovered and produces zero violations

        Updated from the prior `test_architect_md_known_finding_is_present`: that
        test asserted architect.md still named "Claude Code"/"Cursor"/".claude/"/
        ".cursor/" as literal text. Those references were removed on this branch,
        so architect.md is now clean — which is exactly what the ADR-033 gate
        requires of a canonical artifact. Locking the clean state instead.
        """
        discovered = discover_neutral_surface_files(repo_root)
        architect = next((p for p in discovered if p.name == "architect.md"), None)
        assert architect is not None, "architect.md was not discovered under scripts/agents/"

        violations = validate_file(architect)
        assert violations == [], (
            f"architect.md is expected to be clean after the c774caf scrub, got: {[v.message for v in violations]}"
        )

    def test_no_leakage_anywhere_in_discovered_corpus(self, repo_root):
        """
        Given: The real discovered corpus under scripts/agents/ (architect.md,
               code-reviewer.md, content-reviewer.md, issue-response-reviewer.md,
               swe.md, testing.md) and scripts/skills/ (whatever, if anything,
               is present there)
        When: every discovered .md file is validated
        Then: No file produces a violation — the whole canonical corpus is clean

        Deliberately validates every discovered .md file, not just
        scripts/agents/ ones, so this stays correct once scripts/skills/
        contains real skills: it does not assume or require scripts/skills/ to
        be absent. Updated from the prior
        `test_no_other_unexpected_leakage_in_scripts_agents` (which expected
        architect.md as the sole flagged file). After the c774caf scrub the
        corpus is fully clean; this also guards that none of the Tier 3
        denylist broadenings (lowercase vendors, extra CLI names, auto-load
        paraphrases, IGNORECASE config paths) false-fire on the real corpus. The
        only cross-agent `<invoke ... agent>` stage directions name an agent,
        never a "tool", so the harness-invocation shape correctly does not fire;
        all MITRE/NIST/OWASP/ISO/EU AI Act/STRIDE mentions are legitimate
        framework-mapping content.
        """
        discovered = discover_neutral_surface_files(repo_root)
        discovered_md = [p for p in discovered if p.suffix == ".md"]
        assert discovered_md, "expected at least one .md file under scripts/agents/ (and/or scripts/skills/)"

        flagged = {p.name: validate_file(p) for p in discovered_md}
        flagged_names = {name for name, violations in flagged.items() if violations}

        assert flagged_names == set(), (
            f"expected a fully clean live corpus, but these files were flagged: "
            f"{ {name: [v.message for v in flagged[name]] for name in flagged_names} }"
        )


class TestAdversarialEdgeCases:
    """Edge cases: allowlist/denylist collisions, case sensitivity, empty-result typing."""

    def test_claude_md_filename_reference_is_not_flagged(self, tmp_path):
        """
        Given: An agent file referencing "CLAUDE.md" (this repo's own top-level
               instructions filename), with no other vendor terms present
        When: validate_file scans the file
        Then: No violations are produced

        Real corpus collision found in scripts/agents/architect.md: a naive
        case-insensitive substring match for "claude" hits "CLAUDE.md" (the
        repo's own file-naming convention, mentioned legitimately across the
        corpus), which is not a harness-product reference at all. The vendor
        denylist entry for the product is the two-word phrase "Claude Code"
        (and the company name "Anthropic"), not the bare substring "claude" —
        this is the design decision that avoids the false positive.
        """
        agent = _write_agent_file(tmp_path, "Includes ADRs, CLAUDE.md edits, and CI workflow edits.\n")

        violations = validate_file(agent)

        assert violations == []

    def test_framework_acronym_adjacent_to_denylist_term_only_flags_the_denylist_term(self, tmp_path):
        """
        Given: A single line mixing a tightly-packed framework acronym (MITRE ATLAS)
               with an unrelated denylisted product name (Copilot)
        When: validate_file scans the file
        Then: Exactly the denylisted product name is flagged; MITRE/ATLAS produce
              no violation, even sharing the same line

        Proves allowlist suppression is per-match, not a blanket "skip the whole
        line if it contains an allowlisted term" shortcut — a shortcut like that
        would silently hide real denylist hits sitting next to legitimate
        framework content.
        """
        agent = _write_agent_file(tmp_path, "MITRE ATLAS mapping was drafted with GitHub Copilot's help.\n")

        violations = validate_file(agent)

        assert violations != []
        assert all("MITRE" not in v.token and "ATLAS" not in v.token for v in violations)
        assert any("Copilot" in v.token or "Copilot" in v.message for v in violations)

    def test_suppression_requires_genuine_span_overlap_not_same_line_proximity(self, tmp_path, monkeypatch):
        """
        Given: A line containing a real allowlist match ("MITRE") and, elsewhere on the
               same line, a token that would be denylisted only under a synthetic,
               deliberately-overlapping denylist pattern substituted via monkeypatch
        When: validate_file scans the file with that substituted denylist
        Then: The match whose span overlaps the allowlist span ("MITRE") is
              suppressed, while the same-line match with a non-overlapping span
              ("FLAGGEDTOKEN") is still reported

        The real denylist/allowlist vocabularies are disjoint character sets (no
        real denylist pattern overlaps a real allowlist span), so no fixture
        built from real terms can exercise the span-overlap arithmetic in
        `_overlaps`/`_scan_line` — every "allowlist near denylist" case in this
        suite passes because the vocabularies never collide, not because
        suppression engaged. Monkeypatching `_DENYLIST_CATEGORIES` with a
        pattern that matches the literal allowlist span (`\\bMITRE\\b`, which
        `_neutrality_data.FRAMEWORK_ALLOWLIST_PATTERNS` also matches) is the
        only way to prove overlap suppression itself is correct — and that it
        stays correct if the denylist is later broadened (ADR-033 notes the
        denylist is a standing maintenance obligation).
        """
        overlapping_pattern = re.compile(r"\bMITRE\b")  # same span as the real allowlist's `\bMITRE\b`
        non_overlapping_pattern = re.compile(r"\bFLAGGEDTOKEN\b")  # matches no allowlist span on this line
        monkeypatch.setattr(
            validate_neutrality,
            "_DENYLIST_CATEGORIES",
            (
                (overlapping_pattern, "synthetic probe: overlaps a real allowlist span"),
                (non_overlapping_pattern, "synthetic probe: does not overlap any allowlist span"),
            ),
        )
        agent = _write_agent_file(tmp_path, "MITRE guidance and an unrelated FLAGGEDTOKEN sit on one line.\n")

        violations = validate_file(agent)

        tokens = {v.token for v in violations}
        assert "MITRE" not in tokens, "a denylist match overlapping a real allowlist span must be suppressed"
        assert "FLAGGEDTOKEN" in tokens, (
            "a same-line denylist match that does NOT overlap the allowlist span must still be reported"
        )

    def test_clean_file_returns_empty_list_not_none(self, tmp_path):
        """
        Given: An agent file with no denylist or frontmatter violations
        When: validate_file scans the file
        Then: It returns [] (an empty list), not None or another falsy value

        `main()` and callers rely on list semantics (`extend`, `len`); a bare
        falsy sentinel like None would break that contract even though `if not
        violations:` would still "work" by accident.
        """
        agent = _write_agent_file(tmp_path, "# Clean Agent\n\n## Agent\n\nNothing to see here.\n")

        violations = validate_file(agent)

        assert violations == []
        assert isinstance(violations, list)


class TestFailClosedNonUtf8:
    """
    LB1: non-UTF-8 input must fail closed, not crash the gate.

    `validate_file` previously did an unguarded `read_text(encoding="utf-8")`,
    so a text-extension file carrying invalid bytes raised `UnicodeDecodeError`
    and aborted the whole hook (including `main([])` self-discovery) with a
    traceback. A file whose neutrality cannot be verified must be flagged, never
    allowed to crash the gate open.
    """

    def test_invalid_utf8_file_is_flagged_not_raised(self, tmp_path):
        """
        Given: A .md file under scripts/agents/ containing invalid UTF-8 bytes
        When: validate_file scans it
        Then: A violation is returned (no exception), stating the file is not valid UTF-8
        """
        agent = _write_agent_file(tmp_path, "placeholder\n")
        agent.write_bytes(b"# Title\n\xff\xfe not valid utf-8\n")

        violations = validate_file(agent)

        assert violations != []
        assert any("UTF-8" in v.message or "utf-8" in v.message for v in violations)

    def test_main_self_discovery_does_not_raise_on_invalid_utf8(self, tmp_path, monkeypatch, capsys):
        """
        Given: A scripts/agents/ tree containing a file with invalid UTF-8 bytes
        When: main([]) self-discovers and validates from that root as cwd
        Then: It returns 1 (violation) without raising, and reports the file
        """
        agent = _write_agent_file(tmp_path, "placeholder\n")
        agent.write_bytes(b"\xff\xfe\x00 invalid\n")
        monkeypatch.chdir(tmp_path)

        exit_code = main([])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert str(agent) in captured.err


class TestFailClosedMalformedFrontmatter:
    """
    LB2: malformed / unverifiable frontmatter must fail closed on files where
    frontmatter is structurally expected.

    Frontmatter is structurally expected on `SKILL.md` files and on top-level
    agent definitions (a `.md` directly under `scripts/agents/`). For those,
    YAML that will not parse, is not a mapping, or opens a `---` fence it never
    closes is unverifiable and is flagged. Bundled reference material
    (`references/*.md`, or any non-SKILL.md nested below the top level) is NOT
    subject to this rule — it may legitimately open with a `---` markdown
    thematic break — and is exempt from the malformed-frontmatter flag (it still
    gets the denylist scan).
    """

    def test_skill_unquoted_colon_description_is_flagged(self, tmp_path):
        """
        Given: A SKILL.md whose description value contains an unquoted colon,
               making the frontmatter block invalid YAML
        When: validate_file scans it
        Then: An unverifiable-frontmatter violation is returned (fail closed)
        """
        skill = _write_skill_file(
            tmp_path,
            "---\nname: example-skill\ndescription: Does: this and that\n---\nBody.\n",
        )

        violations = validate_file(skill)

        assert violations != []
        assert any("unverifiable frontmatter" in v.message for v in violations)

    def test_skill_tab_indented_block_is_flagged(self, tmp_path):
        """
        Given: A SKILL.md frontmatter block using a tab character for indentation
               (YAML forbids tabs for indentation), making it unparseable
        When: validate_file scans it
        Then: An unverifiable-frontmatter violation is returned
        """
        skill = _write_skill_file(
            tmp_path,
            "---\nname: example-skill\ndescription:\n\tnested: value\n---\nBody.\n",
        )

        violations = validate_file(skill)

        assert violations != []
        assert any("unverifiable frontmatter" in v.message for v in violations)

    @pytest.mark.parametrize(
        ("label", "block"),
        [
            ("list", "---\n- name\n- description\n---\nBody.\n"),
            ("scalar", "---\njust a bare scalar line\n---\nBody.\n"),
        ],
    )
    def test_skill_non_mapping_frontmatter_is_flagged(self, tmp_path, label, block):
        """
        Given: A SKILL.md whose frontmatter parses to a non-dict (a list or a
               bare scalar) rather than a key/value mapping
        When: validate_file scans it
        Then: An unverifiable-frontmatter violation is returned (fail closed)
        """
        skill = _write_skill_file(tmp_path, block)

        violations = validate_file(skill)

        assert violations != []
        assert any("unverifiable frontmatter" in v.message for v in violations)

    def test_skill_missing_closing_fence_is_flagged(self, tmp_path):
        """
        Given: A SKILL.md that opens a `---` frontmatter fence but never closes it
        When: validate_file scans it
        Then: An unverifiable-frontmatter violation is returned (fail closed)
        """
        skill = _write_skill_file(
            tmp_path,
            "---\nname: example-skill\ndescription: Never closes the fence.\n\nBody with no closing fence.\n",
        )

        violations = validate_file(skill)

        assert violations != []
        assert any("unverifiable frontmatter" in v.message for v in violations)

    def test_agent_missing_closing_fence_is_flagged(self, tmp_path):
        """
        Given: A top-level agent .md that opens a `---` fence but never closes it
        When: validate_file scans it
        Then: An unverifiable-frontmatter violation is returned (fail closed)
        """
        agent = _write_agent_file(
            tmp_path,
            "---\ndescription: Opens a fence.\n\n# Agent\n\nNo closing fence anywhere.\n",
        )

        violations = validate_file(agent)

        assert violations != []
        assert any("unverifiable frontmatter" in v.message for v in violations)

    def test_forbidden_key_after_reopened_second_fence_is_flagged(self, tmp_path):
        """
        Given: An agent .md with a well-formed first frontmatter block, then a
               second `---`-delimited block that re-opens frontmatter and hides a
               runtime-binding key (`tools:`) after it
        When: validate_file scans it
        Then: A violation is returned — the forbidden key is not missed just
              because it sits after a re-opened fence

        The pre-fix parser stopped at the first closing `---` and never saw a key
        smuggled into a re-opened second block. This is treated as unverifiable
        frontmatter (fail closed) rather than silently accepted.
        """
        agent = _write_agent_file(
            tmp_path,
            "---\ndescription: Benign first block.\n---\n\n# Agent\n\n---\ntools: Bash\n---\nBody.\n",
        )

        violations = validate_file(agent)

        assert violations != []

    def test_reference_file_opening_with_thematic_break_is_not_flagged_for_frontmatter(self, tmp_path):
        """
        Given: A bundled references/*.md that opens with a `---` markdown thematic
               break (not YAML frontmatter) and carries no vendor terms
        When: validate_file scans it
        Then: No malformed-frontmatter violation is produced (false-positive guard)

        Reference material is denylist-scanned but exempt from the
        malformed-frontmatter structural rule: frontmatter is not structurally
        expected there, so a leading `---` is legitimate prose, not an unclosed
        or malformed frontmatter fence.
        """
        reference = _write_skill_reference_file(
            tmp_path,
            "---\n\n# Classical Security Lexicon\n\nCanonical security terms of art.\n\n- Spoofing\n- Tampering\n",
        )

        violations = validate_file(reference)

        assert violations == []

    def test_nested_skill_md_under_references_is_not_flagged_for_frontmatter(self, tmp_path):
        """
        Given: A file literally named SKILL.md nested under references/ (NOT the
               canonical skill root scripts/skills/<name>/SKILL.md), opening with
               a `---` markdown thematic break
        When: validate_file scans it
        Then: No malformed-frontmatter violation is produced (false-positive guard)

        `_frontmatter_is_structurally_expected` treats "SKILL.md" as structural
        only at the canonical skill root (parent's parent directory is
        `skills`), not at any depth. A same-named file bundled deeper as
        reference material is exempt, same as any other reference file — it may
        legitimately open with a `---` thematic break.
        """
        nested = _write_nested_skill_md_reference(
            tmp_path,
            "---\n\n# Reference copy of a skill card\n\nNot the canonical skill root.\n",
        )

        violations = validate_file(nested)

        assert violations == []

    def test_canonical_skill_root_skill_md_is_still_structural(self, tmp_path):
        """
        Given: The canonical skill root SKILL.md (scripts/skills/<name>/SKILL.md)
               with malformed frontmatter (a tab-indented block, distinct from
               the unterminated-fence fixture used elsewhere in this class)
        When: validate_file scans it
        Then: An unverifiable-frontmatter violation IS still produced

        Confirms the SKILL.md-root scoping fix does not weaken the original
        LB2 rule for the file it is actually meant to govern.
        """
        skill = _write_skill_file(
            tmp_path,
            "---\nname: example-skill\ndescription:\n\tnested: value\n---\nBody.\n",
        )

        violations = validate_file(skill)

        assert violations != []
        assert any("unverifiable frontmatter" in v.message for v in violations)

    def test_well_formed_nested_skill_md_is_exempt_from_the_skill_allowlist_too(self, tmp_path):
        """
        Given: A well-formed (parseable) frontmatter block on a nested
               references/SKILL.md carrying a key outside the name/description
               allowlist (e.g. `license:`)
        When: validate_file scans it
        Then: No frontmatter-structural violation is produced

        Not just the malformed-frontmatter checks but the SKILL.md
        name/description allowlist itself is scoped to the canonical skill
        root. A same-named bundled reference file is fully exempt from the
        frontmatter *structural* rule — it still gets the denylist scan, just
        not held to the skill-root's allowlist ceiling.
        """
        nested = _write_nested_skill_md_reference(
            tmp_path,
            "---\nname: x\ndescription: y\nlicense: MIT\n---\nBody.\n",
        )

        violations = validate_file(nested)

        assert violations == []


class TestFailClosedFrontmatterKeyCase:
    """
    LB3: forbidden/allowlist frontmatter-key checks must be case-insensitive.

    `key.replace("_", "-")` never lowercased, so a capitalized runtime-binding
    key (`Model:`, `Tools:`, `Color:`, `Allowed-Tools:`) evaded both the SKILL
    allowlist check and the agent forbidden-key check. Keys are now
    lowercase-normalized before both checks.
    """

    @pytest.mark.parametrize("binding_key", ["Model", "Tools", "Color", "Allowed-Tools", "Allowed_Tools"])
    def test_agent_capitalized_binding_key_with_neutral_value_is_flagged(self, tmp_path, binding_key):
        """
        Given: A top-level agent .md whose frontmatter carries a capitalized
               runtime-binding key with a deliberately neutral value (so only the
               key, not the value, could trigger a flag)
        When: validate_file scans it
        Then: One violation names the offending key

        The neutral value isolates the key-case fix: without lowercase
        normalization the capitalized key slips past the forbidden-key set.
        """
        agent = _write_agent_file(
            tmp_path,
            f"---\ndescription: Example agent.\n{binding_key}: something-neutral\n---\n\n# Agent\n\nBody.\n",
        )

        violations = validate_file(agent)

        assert violations != []
        assert any(binding_key.lower() in v.token.lower() or binding_key in v.message for v in violations)

    def test_skill_capitalized_tools_key_is_flagged(self, tmp_path):
        """
        Given: A SKILL.md frontmatter block with a capitalized `Tools:` key
               (outside the name/description allowlist) carrying a neutral value
        When: validate_file scans it
        Then: One violation names the offending key
        """
        skill = _write_skill_file(
            tmp_path,
            "---\nname: example-skill\ndescription: Does one thing.\nTools: something-neutral\n---\nBody.\n",
        )

        violations = validate_file(skill)

        assert violations != []
        assert any("Tools" in v.token or "tools" in v.token.lower() or "Tools" in v.message for v in violations)


class TestDenylistBroadenings:
    """
    Tier 3 safe denylist broadenings (E1, E3, E6, E8) — low false-positive risk.

    Each broadening is paired with a negative lock that pins an intentionally
    unflagged case, so a later over-broadening is caught.
    """

    @pytest.mark.parametrize(
        "line",
        ["import openai", "from anthropic import something", "the copilot suggestion was accepted"],
        ids=["openai", "anthropic", "copilot"],
    )
    def test_lowercase_vendor_names_are_flagged(self, tmp_path, line):
        """
        Given: An agent file with a lowercase vendor name (openai/anthropic/copilot)
               as a whole word, the shape that leaks through case-sensitive matching
        When: validate_file scans it
        Then: A vendor violation is returned (E1)
        """
        agent = _write_agent_file(tmp_path, f"{line}\n")

        violations = validate_file(agent)

        assert violations != []

    @pytest.mark.parametrize("token", ["chatgpt", "codeium"])
    def test_additional_lowercase_vendor_names_are_flagged(self, tmp_path, token):
        """
        Given: An agent file mentioning lowercase `chatgpt` / `codeium` as a whole word
        When: validate_file scans it
        Then: A vendor violation is returned (E1)
        """
        agent = _write_agent_file(tmp_path, f"Ran the pipeline through {token} for comparison.\n")

        violations = validate_file(agent)

        assert violations != []

    def test_claude_md_still_not_flagged_after_lowercase_vendor_broadening(self, tmp_path):
        """
        Given: An agent file referencing CLAUDE.md and "Claude Code" behavior
        When: validate_file scans it after the E1 lowercase-vendor broadening
        Then: CLAUDE.md is still not flagged (no regression)

        The E1 broadening adds whole-word lowercase vendor entries; it must NOT
        make the vendor regex case-insensitive, which would re-flag CLAUDE.md.
        This locks that the lowercase additions do not touch the "claude"/case
        behavior that the CLAUDE.md carve-out depends on.
        """
        agent = _write_agent_file(tmp_path, "Includes ADRs and CLAUDE.md edits in the same change.\n")

        violations = validate_file(agent)

        assert violations == []

    @pytest.mark.parametrize(
        "cli",
        ["`cursor --resume`", "`aider --message x`", "`windsurf run`", "`codex exec`", "`cline start`"],
        ids=["cursor", "aider", "windsurf", "codex", "cline"],
    )
    def test_additional_cli_entrypoints_are_flagged(self, tmp_path, cli):
        """
        Given: An agent file with a backtick-wrapped harness CLI entry point other
               than claude (cursor/aider/windsurf/codex/cline)
        When: validate_file scans it
        Then: A CLI-entrypoint violation is returned (E3)
        """
        agent = _write_agent_file(tmp_path, f"Run {cli} to continue.\n")

        violations = validate_file(agent)

        assert violations != []

    def test_claude_cli_entrypoint_still_flagged_after_broadening(self, tmp_path):
        """
        Given: The existing backtick `claude --resume` CLI form
        When: validate_file scans it after the E3 broadening
        Then: It is still flagged (no regression on the original CLI shape)
        """
        agent = _write_agent_file(tmp_path, "Run `claude --resume` to continue the session.\n")

        violations = validate_file(agent)

        assert violations != []

    @pytest.mark.parametrize(
        "phrase",
        ["auto-loading", "auto-activates", "auto-invokes", "auto-load"],
        ids=["auto-loading", "auto-activates", "auto-invokes", "bare-auto-load"],
    )
    def test_additional_auto_load_paraphrases_are_flagged(self, tmp_path, phrase):
        """
        Given: An agent file using an auto-load/auto-trigger paraphrase
               (-loading/-activates/-invokes, or bare auto-load) describing
               runtime dispatch
        When: validate_file scans it
        Then: An auto-load/auto-trigger violation is returned (E6)
        """
        agent = _write_agent_file(tmp_path, f"This skill {phrase} when the description matches.\n")

        violations = validate_file(agent)

        assert violations != []

    @pytest.mark.parametrize("config_path", [".Claude/", ".github/Copilot"])
    def test_mixed_case_config_paths_are_flagged(self, tmp_path, config_path):
        """
        Given: An agent file with a mixed-case harness config path (.Claude/,
               .github/Copilot)
        When: validate_file scans it
        Then: A config-path violation is returned (E8, IGNORECASE)
        """
        agent = _write_agent_file(tmp_path, f"Config lives under `{config_path}` there.\n")

        violations = validate_file(agent)

        assert violations != []

    def test_vscode_config_path_still_not_flagged_after_ignorecase(self, tmp_path):
        """
        Given: An agent file mentioning `.vscode/` (an ordinary editor config dir,
               not a harness config path)
        When: validate_file scans it after the E8 IGNORECASE broadening
        Then: No config-path violation is produced (negative lock)

        `.vscode/` is not in the harness-config denylist; adding IGNORECASE must
        not accidentally start matching it.
        """
        agent = _write_agent_file(tmp_path, "Editor settings live under `.vscode/` in this repo.\n")

        violations = validate_file(agent)

        assert violations == []


class TestDocumentedGapsAndLockins:
    """
    Tier 2: lock current behavior and document deliberate gaps.

    Per ADR-033, the D2a denylist is a maintained list, not an exhaustive
    classifier: some vendor/model tokens are deliberately out of scope until a
    maintainer adds them. These tests pin that current behavior so a future
    change is a conscious decision, and lock the true-positive edge cases the
    checker must keep catching.
    """

    @pytest.mark.parametrize(
        "model_token",
        ["o1-preview", "o3-mini", "phi-3", "command-r-plus", "gpt4o"],
    )
    def test_e2_unlisted_model_families_are_not_flagged_documented_gap(self, tmp_path, model_token):
        """
        Given: A model identifier from a family NOT in the maintained prefix list
               (o1/o3/phi/command-r/gpt4o-without-hyphen)
        When: validate_file scans it
        Then: No violation is produced — DOCUMENTED GAP

        The model-identifier regex keys on a maintained family-prefix list. These
        tokens are deliberately not expanded (maintainer's choice); this lock
        makes any future coverage an explicit decision, not an accident.
        """
        agent = _write_agent_file(tmp_path, f"Pin the model to {model_token} for this run.\n")

        violations = validate_file(agent)

        assert violations == []

    @pytest.mark.parametrize("vendor", ["Bard", "Grok", "Llama"])
    def test_e9_unknown_vendors_are_not_flagged_documented_gap(self, tmp_path, vendor):
        """
        Given: A vendor/product name NOT on the maintained vendor list, used as a
               bare word with no model-identifier shape
        When: validate_file scans it
        Then: No violation is produced — DOCUMENTED GAP

        `Bard`/`Grok`/`Llama` as bare product words are not on the vendor
        denylist. (`Grok`/`Llama` only match as model-identifier *shapes* like
        `grok-2`/`llama-3`, not as bare capitalized words.) Documented gap of a
        maintained denylist.
        """
        agent = _write_agent_file(tmp_path, f"The {vendor} assistant was evaluated separately.\n")

        violations = validate_file(agent)

        assert violations == []

    def test_e4_vendor_phrase_split_across_wrapped_lines_not_flagged_documented_gap(self, tmp_path):
        """
        Given: A two-word vendor phrase ("Claude Code") split by a hard line wrap
               so "Claude" ends one line and "Code" begins the next
        When: validate_file scans it (line-by-line)
        Then: No violation is produced — DOCUMENTED GAP

        The scanner matches per line, so a phrase straddling a newline is not
        reassembled. Documented limitation, not a fix target in this scope.
        """
        agent = _write_agent_file(tmp_path, "The assistant was built with Claude\nCode during development.\n")

        violations = validate_file(agent)

        assert violations == []

    def test_e5_vendor_in_code_fence_and_html_comment_is_flagged_lock(self, tmp_path):
        """
        Given: A capitalized vendor name inside a fenced code block AND, separately,
               inside an HTML comment
        When: validate_file scans it
        Then: Both are flagged — LOCK (no code-fence or comment exemption)

        The scanner has no markdown-structure awareness by design: a denylisted
        term is a leak wherever it appears, including inside code fences and HTML
        comments. This locks that there is no such exemption.
        """
        agent = _write_agent_file(
            tmp_path,
            "```\nRun with Cursor here.\n```\n\n<!-- note: drafted with OpenAI -->\n",
        )

        violations = validate_file(agent)

        tokens_and_messages = " ".join(f"{v.token} {v.message}" for v in violations)
        assert "Cursor" in tokens_and_messages
        assert "OpenAI" in tokens_and_messages

    @pytest.mark.parametrize(
        "phrase",
        ["subagent type", "sub-agent", "sub agent"],
        ids=["spaced", "sub-agent", "sub-agent-spaced"],
    )
    def test_e7_subagent_spacing_variants_not_flagged_documented_gap(self, tmp_path, phrase):
        """
        Given: A spaced ("subagent type") or `sub-agent`/"sub agent" variant, none
               of which match the `subagent[_-]type` token shape
        When: validate_file scans it
        Then: No subagent_type violation is produced — DOCUMENTED GAP

        Only the joined `subagent_type`/`subagent-type` token is denylisted. The
        spaced/`sub-agent` variants are a documented gap of the maintained token.
        """
        agent = _write_agent_file(tmp_path, f"Dispatch the {phrase} to the next role.\n")

        violations = validate_file(agent)

        assert violations == []

    def test_e10_symlink_under_tree_is_followed(self, tmp_path):
        """
        Given: A real agent file plus a symlink under scripts/agents/ pointing at it
        When: discover_neutral_surface_files scans the root
        Then: The symlink is discovered (followed) — LOCK
        """
        target = _write_agent_file(tmp_path, "Built with Cursor.\n", name="real-agent.md")
        link = tmp_path / "scripts" / "agents" / "linked-agent.md"
        link.symlink_to(target)

        discovered = discover_neutral_surface_files(tmp_path)

        assert link in discovered

    def test_e10_dangling_symlink_is_discovered_and_flagged(self, tmp_path):
        """
        Given: A dangling symlink under scripts/agents/ (target does not exist)
        When: discover_neutral_surface_files scans the root, then each discovered
              path is validated
        Then: The dangling symlink IS discovered, and validating it raises no
              exception but produces a violation (fail closed, not silently dropped)

        `path.is_file()` FOLLOWS symlinks and returns False for a broken link, so
        a naive `is_file()`-only filter silently drops a dangling symlink before
        `validate_file`'s `except OSError` handler ever runs — the exact
        fail-open class this hardening pass exists to close. Discovery must also
        accept `path.is_symlink()` so a broken link is not filtered out upstream
        of the OSError guard.
        """
        link = tmp_path / "scripts" / "agents" / "dangling.md"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(tmp_path / "scripts" / "agents" / "nonexistent-target.md")

        discovered = discover_neutral_surface_files(tmp_path)

        assert link in discovered, "a dangling symlink must be discovered, not silently filtered out"

        violations = validate_file(link)  # must not raise

        assert violations != [], "a dangling symlink must be flagged, not silently pass"
        assert any("could not be read" in v.message or "utf-8" in v.message.lower() for v in violations)

    def test_e10_main_with_explicit_dangling_symlink_path_returns_one(self, tmp_path, capsys):
        """
        Given: A dangling symlink path passed explicitly to main() (the shape
               pre-commit uses: `git add` a broken symlink, pre-commit passes its
               matched filename to the hook)
        When: main([<dangling-path>]) runs
        Then: It returns 1 and reports the file, rather than silently `continue`-ing
              past it because `path.exists()` follows the symlink and returns False

        This is the exact regression the review flagged: `main()`'s
        `if not path.exists(): continue` also follows symlinks, so a broken link
        was filtered out before validate_file ever saw it.
        """
        agents_dir = tmp_path / "scripts" / "agents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        link = agents_dir / "dangling.md"
        link.symlink_to(agents_dir / "nonexistent-target.md")

        exit_code = main([str(link)])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert str(link) in captured.err

    def test_e10_hook_shape_staged_dangling_symlink_is_flagged(self, tmp_path, monkeypatch, capsys):
        """
        Given: A repo-shaped tmp_path root where a dangling symlink has been
               created under scripts/agents/ (simulating `git add` of a broken
               symlink) and no other violation is present
        When: main([]) self-discovers from that root as cwd (the no-explicit-args
              shape pre-commit uses when it hands off to discovery)
        Then: It returns 1 and reports the dangling link — the hook does not
              exit 0 silently on a broken symlink
        """
        agents_dir = tmp_path / "scripts" / "agents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        link = agents_dir / "dangling.md"
        link.symlink_to(agents_dir / "nonexistent-target.md")
        monkeypatch.chdir(tmp_path)

        exit_code = main([])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert str(link) in captured.err

    def test_e10_directory_named_with_md_suffix_is_excluded(self, tmp_path):
        """
        Given: A directory literally named `notes.md` under scripts/agents/
        When: discover_neutral_surface_files scans the root
        Then: The directory is not returned (only files) — LOCK
        """
        agents_dir = tmp_path / "scripts" / "agents"
        (agents_dir / "notes.md").mkdir(parents=True, exist_ok=True)
        real = _write_agent_file(tmp_path, "clean\n", name="real.md")

        discovered = discover_neutral_surface_files(tmp_path)

        assert (agents_dir / "notes.md") not in discovered
        assert real in discovered

    def test_e11_empty_file_produces_no_violations_lock(self, tmp_path):
        """
        Given: An empty agent .md file (zero bytes)
        When: validate_file scans it
        Then: Zero violations — LOCK

        An empty file has no frontmatter fence and no denylist content; even under
        the LB2 fail-closed rule it must stay clean (no fence opened means nothing
        unverifiable).
        """
        agent = _write_agent_file(tmp_path, "")

        violations = validate_file(agent)

        assert violations == []

    def test_e11_no_extension_file_is_excluded_by_discovery_lock(self, tmp_path):
        """
        Given: A file with no extension under scripts/agents/ containing vendor terms
        When: discover_neutral_surface_files scans the root
        Then: The extensionless file is not discovered — LOCK

        Discovery restricts to known text extensions; an extensionless file is
        excluded, so vendor content in it is invisible via the discovery path.
        """
        agents_dir = tmp_path / "scripts" / "agents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        (agents_dir / "NOTES").write_text("Built with Cursor and OpenAI.\n", encoding="utf-8")
        real = _write_agent_file(tmp_path, "clean\n", name="real.md")

        discovered = discover_neutral_surface_files(tmp_path)

        assert (agents_dir / "NOTES") not in discovered
        assert real in discovered

    def test_e12_crlf_frontmatter_key_and_body_vendor_term_are_handled(self, tmp_path):
        """
        Given: A top-level agent .md written with CRLF line endings, carrying a
               forbidden frontmatter key AND a body line naming a vendor product
        When: validate_file scans it
        Then: BOTH are flagged — LOCK

        `splitlines()` handles CRLF, and `line.strip()`/YAML tolerate the trailing
        CR, so the frontmatter fence is recognized and the body denylist scan
        fires. This corrects the suite's earlier "CRLF out of scope" note: CRLF
        is handled correctly and is locked here.
        """
        agents_dir = tmp_path / "scripts" / "agents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        path = agents_dir / "crlf-agent.md"
        content = "---\r\ndescription: Example.\r\ntools: Bash\r\n---\r\n\r\nBuilt with Cursor.\r\n"
        path.write_bytes(content.encode("utf-8"))

        violations = validate_file(path)

        joined = " ".join(f"{v.token} {v.message}" for v in violations)
        assert "tools" in joined, "CRLF frontmatter forbidden key must be flagged"
        assert "Cursor" in joined, "CRLF body vendor term must be flagged"


class TestFalsyFrontmatterFinding1:
    """
    PR #428 review Finding 1: falsy non-mapping frontmatter fails closed.

    `_frontmatter_violations` splits YAML parsing from the empty-block default
    (`parsed = yaml.safe_load(...); frontmatter = {} if parsed is None else
    parsed`), so a falsy-but-non-mapping parse result (`False`, `0`, `[]`)
    reaches the `isinstance(..., dict)` guard instead of being coerced to `{}`
    beforehand. On a structurally-expected file (canonical skill-root
    SKILL.md, top-level agent .md) this closes a fail-open hole: a falsy
    frontmatter block is flagged as unverifiable rather than silently treated
    as empty/compliant.

    `false`/`0`/`[]` are each flagged as unverifiable frontmatter.

    Negative lock (must stay passing): a truly empty block (`---\\n---`) and a
    whitespace-only block both parse to `None` via `yaml.safe_load`, so they
    become `{}` under the split logic and remain clean.
    """

    @pytest.mark.parametrize(
        ("label", "block"),
        [
            ("false", "---\nfalse\n---\nBody.\n"),
            ("zero", "---\n0\n---\nBody.\n"),
            ("empty_list", "---\n[]\n---\nBody.\n"),
        ],
    )
    def test_falsy_non_mapping_frontmatter_is_flagged_on_skill_md(self, tmp_path, label, block):
        """
        Given: A canonical SKILL.md whose frontmatter block parses to a falsy,
               non-dict YAML value (`False`, `0`, or `[]`)
        When: validate_file scans it
        Then: An unverifiable-frontmatter violation is returned (fail closed)

        The parse/default split (`parsed = yaml.safe_load(...); frontmatter =
        {} if parsed is None else parsed`) only treats a `None` parse result
        as empty; each of these falsy-but-non-None values reaches the
        `isinstance(..., dict)` guard and is flagged.
        """
        skill = _write_skill_file(tmp_path, block)

        violations = validate_file(skill)

        assert violations != [], (
            f"falsy frontmatter ({label}) on a structurally-expected SKILL.md must be "
            f"flagged as unverifiable, not silently treated as empty/compliant"
        )
        assert any("unverifiable frontmatter" in v.message for v in violations), (
            f"expected an 'unverifiable frontmatter' violation for falsy frontmatter ({label}); "
            f"got messages: {[v.message for v in violations]}"
        )

    def test_empty_frontmatter_block_stays_clean(self, tmp_path):
        """
        Given: A canonical SKILL.md with an empty frontmatter block (`---\\n---`,
               no content between the fences at all)
        When: validate_file scans it
        Then: No violations are produced — NEGATIVE LOCK

        `yaml.safe_load("")` returns `None`, which both the current `or {}`
        coercion and the corrected `None`-only default treat as an empty
        mapping. This must stay clean after the Finding 1 fix; only a truly
        falsy-but-non-None parse result (False/0/[]) is the fail-open gap.
        """
        skill = _write_skill_file(tmp_path, "---\n---\nBody.\n")

        violations = validate_file(skill)

        assert violations == []

    def test_whitespace_only_frontmatter_block_stays_clean(self, tmp_path):
        """
        Given: A canonical SKILL.md whose frontmatter block contains only
               whitespace between the fences
        When: validate_file scans it
        Then: No violations are produced — NEGATIVE LOCK

        `yaml.safe_load("   ")` also returns `None` (whitespace-only YAML
        documents parse to null), so this must remain clean after the fix,
        same reasoning as the empty-block case above.
        """
        skill = _write_skill_file(tmp_path, "---\n   \n---\nBody.\n")

        violations = validate_file(skill)

        assert violations == []


class TestTextBinaryPolicyFinding3:
    """
    PR #428 review Finding 3: a shared text/binary policy between discovery
    and validate_file.

    `validate_file` and `discover_neutral_surface_files` share one text-
    extension set, `_TEXT_EXTENSIONS = {.md, .py, .yaml, .yml, .json, .txt,
    .sh, .js, .ts, .toml}` (renamed from `_DISCOVERABLE_TEXT_EXTENSIONS`):
      (a) `validate_file` reads a file's bytes once, and only treats a
          `UnicodeDecodeError` as "not valid UTF-8" (flag) when the file's
          extension is in `_TEXT_EXTENSIONS`; otherwise, if `_looks_binary`
          detects a NUL byte in the first 8192 bytes, the file is silently
          skipped (`[]`) rather than flagged. A binary asset (e.g. a bundled
          `assets/icon.png`) is skipped, not flagged.
      (b)/(c)/(d) `discover_neutral_surface_files` enumerates every extension
          in `_TEXT_EXTENSIONS`, so a bundled `.sh`/`.js`/`.ts`/`.toml` file's
          denylisted terms are reachable via self-discovery, not just via an
          explicit path handed to `validate_file`. The discovery-inclusion
          test below is parametrized over all four so a partial extension set
          would be caught.

    LB1 preservation (critical constraint, verified here, not regressed): a
    **known-text** file (a `.md`) with invalid UTF-8 bytes — including one
    whose bytes contain a NUL, the exact shape
    `test_main_self_discovery_does_not_raise_on_invalid_utf8` in
    TestFailClosedNonUtf8 exercises — is still flagged, not skipped, because
    the binary-skip in (a) is gated on the file NOT being a known text
    extension, not merely on NUL-byte presence.
    """

    @staticmethod
    def _png_bytes() -> bytes:
        """Real PNG file signature plus non-UTF-8 filler bytes, including a NUL."""
        return b"\x89PNG\r\n\x1a\n" + b"\x00\x01\x02\x03" * 16 + b"\xff\xfe\xfd"

    def test_binary_asset_is_skipped_not_flagged_by_validate_file(self, tmp_path):
        """
        Given: A bundled binary asset (scripts/skills/<x>/assets/icon.png) with
               real binary bytes, including a PNG header and NUL bytes
        When: validate_file scans it directly
        Then: It returns [] (skipped), not a violation and not a raised exception

        `.png` is not in `_TEXT_EXTENSIONS`, so `_looks_binary` (a NUL-byte
        check) gates the decode failure: the file is silently skipped rather
        than flagged as "not valid UTF-8" — a binary asset's neutrality was
        never a legitimate concern in the first place.
        """
        icon = _write_skill_asset_bytes(tmp_path, "assets/icon.png", self._png_bytes())

        violations = validate_file(icon)  # must not raise

        assert violations == [], (
            f"a binary asset (icon.png) must be skipped ([]), not flagged; got: {[v.message for v in violations]}"
        )

    def test_main_on_binary_asset_returns_zero(self, tmp_path):
        """
        Given: The same bundled binary asset, passed as an explicit CLI arg
               (the shape pre-commit uses: it hands the hook matched filenames)
        When: main([<png-path>]) runs
        Then: It returns 0 and raises nothing

        Confirms the skip in (a) above propagates through the CLI: a binary
        asset produces no violation, so main() exits 0.
        """
        icon = _write_skill_asset_bytes(tmp_path, "assets/icon.png", self._png_bytes())

        exit_code = main([str(icon)])  # must not raise

        assert exit_code == 0, "main() must return 0 for a skipped binary asset, not flag it"

    def test_bundled_shell_script_with_denylist_term_is_flagged(self, tmp_path):
        """
        Given: A bundled scripts/skills/<x>/scripts/setup.sh containing a
               denylisted vendor term
        When: validate_file scans it directly
        Then: A violation is returned naming the offending term

        `validate_file` has no extension gate on the *scanning* side — it
        decodes and scans a `.sh` file handed to it directly regardless of
        `_TEXT_EXTENSIONS` membership. Finding 3 (b)'s actual gap is
        discovery (see test_discovery_includes_bundled_text_extensions
        below); this is the paired positive case alongside the clean-`.sh`
        negative case.
        """
        script = _write_skill_asset_bytes(
            tmp_path,
            "scripts/setup.sh",
            b"#!/bin/bash\necho 'Built with Anthropic tooling'\n",
        )

        violations = validate_file(script)

        assert violations != []
        assert any("Anthropic" in v.token or "Anthropic" in v.message for v in violations)

    def test_clean_bundled_shell_script_is_clean(self, tmp_path):
        """
        Given: A bundled scripts/skills/<x>/scripts/setup.sh with no
               denylisted content
        When: validate_file scans it directly
        Then: No violations are produced
        """
        script = _write_skill_asset_bytes(
            tmp_path,
            "scripts/setup.sh",
            b"#!/bin/bash\necho 'Installing dependencies'\n",
        )

        violations = validate_file(script)

        assert violations == []

    def test_bundled_toml_with_denylist_term_is_flagged(self, tmp_path):
        """
        Given: A bundled scripts/skills/<x>/config.toml containing a
               denylisted vendor term
        When: validate_file scans it directly
        Then: A violation is returned naming the offending term
        """
        toml_file = _write_skill_asset_bytes(
            tmp_path,
            "config.toml",
            b'name = "example"\nvendor = "Anthropic"\n',
        )

        violations = validate_file(toml_file)

        assert violations != []
        assert any("Anthropic" in v.token or "Anthropic" in v.message for v in violations)

    def test_clean_bundled_toml_is_clean(self, tmp_path):
        """
        Given: A bundled scripts/skills/<x>/config.toml with no denylisted
               content
        When: validate_file scans it directly
        Then: No violations are produced

        Mirrors test_clean_bundled_shell_script_is_clean for .toml symmetry.
        """
        toml_file = _write_skill_asset_bytes(
            tmp_path,
            "config.toml",
            b'name = "example"\nversion = "1.0.0"\n',
        )

        violations = validate_file(toml_file)

        assert violations == []

    def test_bundled_js_with_denylist_term_is_flagged(self, tmp_path):
        """
        Given: A bundled scripts/skills/<x>/scripts/setup.js containing a
               denylisted vendor term
        When: validate_file scans it directly
        Then: A violation is returned naming the offending term

        Matches the .sh positive-scan shape: validate_file has no extension
        gate on the scanning side, so a `.js` file is decoded and scanned
        when called directly; the discovery-side coverage for `.js` is
        covered by test_discovery_includes_bundled_text_extensions below.
        """
        script = _write_skill_asset_bytes(
            tmp_path,
            "scripts/setup.js",
            b"// Built with Anthropic tooling\nconsole.log('setup');\n",
        )

        violations = validate_file(script)

        assert violations != []
        assert any("Anthropic" in v.token or "Anthropic" in v.message for v in violations)

    @pytest.mark.parametrize(
        ("extension", "content"),
        [
            (".sh", b"#!/bin/bash\necho 'Installing dependencies'\n"),
            (".js", b"// setup script\nconsole.log('setup');\n"),
            (".ts", b"// setup script\nconst x: number = 1;\n"),
            (".toml", b'name = "example"\n'),
        ],
        ids=["sh", "js", "ts", "toml"],
    )
    def test_discovery_includes_bundled_text_extensions(self, tmp_path, extension, content):
        """
        Given: A bundled scripts/skills/<x>/scripts/setup<extension> file, for
               each of the plan's Finding-3 extension set (.sh/.js/.ts/.toml)
        When: discover_neutral_surface_files scans the root
        Then: The file is included in the discovered set

        `_TEXT_EXTENSIONS` includes all four, so each is reachable via
        self-discovery — a denylisted term inside any of them is caught by
        `main([])` / the pre-commit hook's no-args self-discovery path.
        Parametrized over the full plan literal set (not just .sh/.toml) so a
        partial extension set would be caught here.
        """
        script = _write_skill_asset_bytes(tmp_path, f"scripts/setup{extension}", content)

        discovered = discover_neutral_surface_files(tmp_path)

        assert script in discovered, (
            f"expected {script} to be discovered under scripts/skills/**; discovered set: {discovered}"
        )

    def test_discovery_excludes_binary_asset(self, tmp_path):
        """
        Given: A bundled scripts/skills/<x>/assets/icon.png binary asset
        When: discover_neutral_surface_files scans the root
        Then: The .png file is NOT included in the discovered set

        Locks the desired behavior: discovery only enumerates known text
        extensions, so a binary asset is never handed to validate_file via
        the self-discovery path in the first place. `_TEXT_EXTENSIONS` grows
        to include `.sh`/`.js`/`.ts`/`.toml`, not arbitrary binary types, so
        `.png` stays excluded.
        """
        icon = _write_skill_asset_bytes(tmp_path, "assets/icon.png", self._png_bytes())

        discovered = discover_neutral_surface_files(tmp_path)

        assert icon not in discovered

    def test_known_text_md_with_invalid_utf8_is_still_flagged_lb1_preserved(self, tmp_path):
        """
        Given: A .md file under scripts/agents/ (a known text extension)
               containing invalid UTF-8 bytes, including a NUL byte — the exact
               landmine shape `test_main_self_discovery_does_not_raise_on_
               invalid_utf8` uses
        When: validate_file scans it directly
        Then: It is still flagged as not valid UTF-8 (LB1 fail-closed), NOT
              silently skipped as if it were binary

        This is the critical constraint from the review: a naive "NUL byte
        anywhere in the file ⇒ treat as binary ⇒ skip" heuristic would
        wrongly skip this known-text file too, since its bytes also contain a
        NUL. Any Finding 3 fix must gate the binary-skip decision on the file
        extension NOT being a known text type, not merely on NUL-byte
        presence, so this known-text case keeps failing closed.
        """
        agent = _write_agent_file(tmp_path, "placeholder\n")
        agent.write_bytes(b"\xff\xfe\x00 invalid\n")

        violations = validate_file(agent)

        assert violations != [], "a known-text (.md) file with invalid UTF-8 must still fail closed"
        assert any("UTF-8" in v.message or "utf-8" in v.message for v in violations)

    def test_main_self_discovery_still_does_not_raise_on_invalid_utf8_md(self, tmp_path, monkeypatch, capsys):
        """
        Given: A scripts/agents/ tree containing a .md file with invalid UTF-8
               bytes (including a NUL byte)
        When: main([]) self-discovers and validates from that root as cwd
        Then: It returns 1 (violation) without raising, and reports the file

        Re-affirms (does not weaken) the existing
        `test_main_self_discovery_does_not_raise_on_invalid_utf8` fail-closed
        lock in TestFailClosedNonUtf8, as an explicit Finding 3 regression
        guard: any change to validate_file's read-path for the binary/text
        split must keep this passing unchanged.
        """
        agent = _write_agent_file(tmp_path, "placeholder\n")
        agent.write_bytes(b"\xff\xfe\x00 invalid\n")
        monkeypatch.chdir(tmp_path)

        exit_code = main([])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert str(agent) in captured.err


"""
Test Summary
============
Total Tests: 159 (counting parametrize expansion)

Original suite (74), unchanged except the TestScopeBoundaries/TestLiveCorpus
moves noted below:
- TestDenylistVendorProductNames: 19
- TestDenylistHarnessInvocationTokens: 10
- TestDenylistHarnessConfigPaths: 8
- TestFrameworkAllowlist: 8
- TestScopeBoundaries: 4 — gained `test_absent_skills_subtree_contributes_
  nothing_without_erroring`, moved in from TestLiveCorpus (see below).
- TestAgentsEvalsSubtree: 7 (ADR-033 Amendment D8) —
  `discover_neutral_surface_files` now includes the
  scripts/agents-evals/<agent-name>/ tree (a third sibling to scripts/agents/
  and scripts/skills/, shipping portable eval JSON and D7b-style fixture
  Markdown), appended as the third entry in its walk tuple. Covers:
  evals.json discovered, a nested fixtures/*.md discovered, all three trees returned
  together, the absent-third-tree case still working (mirrors the absent-
  skills regression guard above), discovery ordering (agents, skills,
  agents-evals — the tuple-append choice, locked here rather than assumed),
  a non-text asset excluded, and a dangling symlink discovered.
- TestFrontmatterRulesSkill: 6
- TestFrontmatterRulesAgent: 7
- TestCli: 6
- TestLiveCorpus: 2 — UPDATED twice. First: the corpus is now fully clean.
  architect.md's self-referential vendor mentions were scrubbed on this branch
  (commit c774caf), so `test_architect_md_is_now_clean` and
  `test_no_leakage_anywhere_in_discovered_corpus` lock a clean corpus rather
  than the former "architect.md is the one flagged file" assumption, which is
  stale and would fight the ADR-033 gate requirement that every canonical
  artifact exit 0. Second: `test_skills_directory_does_not_exist_yet_and_
  contributes_nothing` was a landmine — it asserted the REAL repo's
  scripts/skills/ was absent, which passes only until a real skill lands (it
  is confirmed failing on the phase1/phase2 branches once
  scripts/skills/classical-lexicon/ exists). Moved to TestScopeBoundaries as a
  tmp_path-based synthetic-tree test that does not depend on live repo state,
  and the class docstring corrected to stop claiming scripts/skills/ "must
  contribute zero discovered files" as a live-corpus fact.
- TestAdversarialEdgeCases: 4

Neutrality-hardening additions (59), from the ADR-033 D2a fail-open audit plus
a code-review follow-up round that closed two residual fail-open/false-positive
gaps in the first hardening pass:
- TestFailClosedNonUtf8: 2 (LB1) — invalid-UTF-8 file flagged not raised;
  main([]) self-discovery does not crash on it.
- TestFailClosedMalformedFrontmatter: 10 (LB2) — unquoted-colon, tab-indent,
  list/scalar non-mapping, missing-closing-fence (SKILL + agent),
  forbidden-key-after-second-fence all fail closed on structurally-expected
  files; a references/*.md opening with a `---` thematic break is NOT flagged
  (false-positive guard). Review follow-up: a nested references/SKILL.md
  (same filename, NOT the canonical skill root) is exempt from BOTH the
  malformed-frontmatter fail-closed checks AND the skill name/description
  allowlist itself, while the canonical skill-root SKILL.md remains fully
  structural.
- TestFailClosedFrontmatterKeyCase: 6 (LB3) — capitalized binding keys
  (Model/Tools/Color/Allowed-Tools/Allowed_Tools) with neutral values are
  flagged on agent defs; capitalized Tools on SKILL.md is flagged.
- TestDenylistBroadenings: 19 (Tier 3) — E1 lowercase vendors
  (openai/anthropic/copilot/chatgpt/codeium) + CLAUDE.md non-regression;
  E3 extra CLI entrypoints (cursor/aider/windsurf/codex/cline) + claude
  non-regression; E6 auto-load paraphrases (-loading/-activates/-invokes/bare
  auto-load); E8 IGNORECASE config paths (.Claude/, .github/Copilot) + .vscode/
  negative lock.
- TestDocumentedGapsAndLockins: 22 (Tier 2 + review follow-up) — E2 unlisted
  model families, E9 unknown vendors, E4 wrapped-line split, E7 subagent
  spacing variants are DOCUMENTED GAPS of the maintained denylist; E5
  code-fence/HTML-comment vendor IS flagged (no exemption), E10
  symlink-followed / dir-named-*.md-excluded, E11 empty-file-clean /
  no-extension-excluded, E12 CRLF frontmatter-key + body-vendor handled are
  LOCKS. Review follow-up (E10): a dangling symlink is now DISCOVERED and
  FLAGGED, not merely non-crashing — `discover_neutral_surface_files` checks
  `is_symlink()` independently of `is_file()` (which follows a symlink and
  returns False for a broken one), and `main()` no longer `continue`s past a
  path that fails `exists()` but is a symlink, so a broken link reaches
  `validate_file`'s OSError guard instead of being filtered out upstream of it.

PR #428 review additions (19), for the three implementation findings raised
in review (treatment plan: working-plans/pr-428-review-treatment-plan.md):
- TestFalsyFrontmatterFinding1: 5 (Finding 1) — `false`/`0`/`[]` frontmatter on
  a canonical SKILL.md is flagged as unverifiable (the parse/default split,
  `parsed = yaml.safe_load(...); frontmatter = {} if parsed is None else
  parsed`, only treats a `None` parse as empty); an empty block (`---\n---`)
  and a whitespace-only block both parse to `None` and stay clean (negative
  lock — these are not part of the fail-open gap).
- TestTextBinaryPolicyFinding3: 14 (Finding 3) — shared text/binary policy
  between discover_neutral_surface_files and validate_file, via one shared
  `_TEXT_EXTENSIONS` set (renamed from `_DISCOVERABLE_TEXT_EXTENSIONS`) and
  `_looks_binary` (NUL-byte heuristic). A bundled binary asset (PNG header +
  NUL bytes) is skipped ([], not flagged, no raise) by validate_file directly
  and via main() (2 tests: a `UnicodeDecodeError` is only flagged when the
  extension is known-text, otherwise `_looks_binary` gates a silent skip).
  Bundled .sh/.js/.toml files with a denylisted term are flagged, and clean
  .sh/.toml are clean, when validate_file is called directly (validate_file
  has no extension gate on the scanning side). Discovery is parametrized over
  the plan's full extension set (.sh/.js/.ts/.toml, 4 cases) and includes a
  bundled file of each under scripts/skills/** (`_TEXT_EXTENSIONS` covers all
  four); a binary asset stays excluded from discovery (`.png` is not in
  `_TEXT_EXTENSIONS`). LB1 preservation (locked, not weakened): a known-text
  .md with invalid UTF-8 (including NUL bytes) still fails closed via both
  validate_file directly and main([]) self-discovery (2 tests) — binary-skip
  is gated on the extension not being known-text, not merely on NUL-byte
  presence.

A companion structural-drift suite for Finding 2 (policy-data/validator-logic
edits re-trigger a full corpus re-scan) lives in a separate file,
scripts/hooks/tests/test_precommit_neutrality_config.py, since it parses
.pre-commit-config.yaml rather than exercising validate_neutrality.py
directly — see that file's module docstring for its own test breakdown.

Coverage Areas:
- ADR-033 denylist categories: vendor/product/company/CLI names (incl. lowercase
  leakage), model-identifier patterns, harness-invocation tokens, subagent_type,
  auto-loads/auto-triggers (+ paraphrases), harness config paths (case-insensitive)
- ADR-033 framework-authority allowlist: MITRE/ATLAS, NIST/AI RMF, OWASP/Top 10,
  ISO, EU AI Act, STRIDE — per-match (not per-line) suppression
- ADR-033 scope boundaries: scripts/agents/**, scripts/skills/** only;
  scripts/hooks/** never scanned
- ADR-033 frontmatter structural rules, fail-closed on unverifiable input,
  scoped to the canonical skill-root SKILL.md + top-level agent defs
  (reference material — including a same-named nested SKILL.md — exempt)
- Fail-closed robustness: non-UTF-8, malformed/unterminated/non-mapping
  frontmatter, and dangling symlinks are all discovered and flagged, never
  silently dropped and never crashing the gate
- CLI contract: explicit args, self-discovery, exit codes, stderr format
- Live-corpus regression: the whole scripts/agents/ corpus is clean
"""
