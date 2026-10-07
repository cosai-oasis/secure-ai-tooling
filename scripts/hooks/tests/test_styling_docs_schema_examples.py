"""
Drift guard: styling doc YAML examples must stay valid against the mermaid-styles schema.

Coverage target: 90% branch coverage for the styling-example validation harness.

`scripts/docs/styling-configuration.md` and `risk-map/docs/graph-customization.md`
each carry fenced ```yaml examples that show contributors how to edit
`risk-map/yaml/mermaid-styles.yaml`. Nothing previously checked that those
examples still parse and validate against
`risk-map/schemas/mermaid-styles.schema.json`. Issue #477's removal of the
control and risk graph generators narrowed the schema (`graphTypes.required`
dropped to `["component"]`, `subgroupFill` removed from `componentCategory`)
without anyone re-checking the docs, so contributors following the recipes for
`graphTypes.control` / `graphTypes.risk` hit a hard schema rejection. This
guard fails loudly if that class of drift recurs.

Each fenced example declares its validation contract in its first YAML
comment. Fragments are deep-merged onto the live configuration. Complete
examples additionally validate without inheriting any required fields
within their declared scope: the entire config, or a dot-separated section
path. The schema remains the source of required fields in either case.
"""

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft7Validator

# Resolve the repo root from this test file's location:
# scripts/hooks/tests/ -> scripts/hooks/ -> scripts/ -> repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

_STYLING_CONFIGURATION_DOC = _REPO_ROOT / "scripts" / "docs" / "styling-configuration.md"
_GRAPH_CUSTOMIZATION_DOC = _REPO_ROOT / "risk-map" / "docs" / "graph-customization.md"
_LIVE_CONFIG = _REPO_ROOT / "risk-map" / "yaml" / "mermaid-styles.yaml"
_SCHEMA_FILE = _REPO_ROOT / "risk-map" / "schemas" / "mermaid-styles.schema.json"

# Matches ```yaml and ```yml fences, case-insensitively (```YAML, ```Yml, etc.),
# so a doc author using the shorter or differently-cased fence tag is still caught.
_YAML_FENCE_PATTERN = re.compile(r"```ya?ml\n(.*?)```", re.DOTALL | re.IGNORECASE)
_EXAMPLE_DECLARATION_PATTERN = re.compile(
    r"# schema-example: (fragment|complete)(?: ([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*))?"
)


def _extract_yaml_blocks(doc_path: Path) -> list[str]:
    """Return the raw text of every fenced ```yaml block in a markdown doc."""
    text = doc_path.read_text(encoding="utf-8")
    return _YAML_FENCE_PATTERN.findall(text)


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively merge overlay onto base, returning a new dict.

    Nested dicts are merged key-by-key; any other value (scalar, list) in
    overlay replaces the corresponding value in base outright. This models
    "apply this doc fragment as an edit to the live config" rather than
    requiring every fragment to be a complete, standalone document.
    """
    merged = copy.deepcopy(base)
    for key, overlay_value in overlay.items():
        base_value = merged.get(key)
        if isinstance(base_value, dict) and isinstance(overlay_value, dict):
            merged[key] = _deep_merge(base_value, overlay_value)
        else:
            merged[key] = copy.deepcopy(overlay_value)
    return merged


def _parse_example_declaration(yaml_text: str, label: str, index: int) -> tuple[str, str | None]:
    """Require an explicit fragment or complete-scope contract on the first line."""
    declaration = _EXAMPLE_DECLARATION_PATTERN.fullmatch(yaml_text.partition("\n")[0])
    assert declaration is not None, (
        f"{label} block {index} must start with '# schema-example: fragment' "
        "or '# schema-example: complete [dot.path]'"
    )
    kind, scope = declaration.groups()
    assert kind == "complete" or scope is None, (
        f"{label} block {index}: schema-example fragment cannot declare a section path"
    )
    return kind, scope


def _with_complete_section(
    merged: dict[str, Any], example: dict[str, Any], scope: str, label: str, index: int
) -> dict[str, Any]:
    """Replace a declared section wholesale, retaining merged values outside it."""
    path = scope.split(".")
    section: Any = example
    for key in path:
        assert isinstance(section, dict) and key in section, (
            f"{label} block {index}: schema-example complete path '{scope}' is missing from the example"
        )
        section = section[key]

    complete = copy.deepcopy(merged)
    parent = complete
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = copy.deepcopy(section)
    return complete


def _load_live_config() -> dict[str, Any]:
    with _LIVE_CONFIG.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_schema() -> dict[str, Any]:
    with _SCHEMA_FILE.open(encoding="utf-8") as f:
        return json.load(f)


def _collect_doc_examples() -> list[tuple[str, int, str]]:
    """
    Return (doc_label, block_index, yaml_text) for every fenced yaml block
    in the two styling docs.
    """
    examples: list[tuple[str, int, str]] = []
    for label, doc_path in (
        ("styling-configuration.md", _STYLING_CONFIGURATION_DOC),
        ("graph-customization.md", _GRAPH_CUSTOMIZATION_DOC),
    ):
        for index, block in enumerate(_extract_yaml_blocks(doc_path)):
            examples.append((label, index, block))
    return examples


_DOC_EXAMPLES = _collect_doc_examples()
_DOC_EXAMPLE_IDS = [f"{label}[{index}]" for label, index, _ in _DOC_EXAMPLES]


class TestStylingDocExamplesMatchSchema:
    """Every fenced yaml example in the styling docs validates against the schema."""

    def test_docs_contain_at_least_one_example(self):
        """
        Given the two styling doc files
        When fenced yaml blocks are extracted
        Then at least one example is found in each file

        Guards against the extraction regex silently matching nothing, which
        would make every other test in this module vacuously pass.
        """
        labels = {label for label, _, _ in _DOC_EXAMPLES}
        assert labels == {"styling-configuration.md", "graph-customization.md"}, (
            f"Expected fenced yaml examples from both doc files, found: {sorted(labels)}"
        )

    @pytest.mark.parametrize("label,index,yaml_text", _DOC_EXAMPLES, ids=_DOC_EXAMPLE_IDS)
    def test_example_is_schema_valid(self, label, index, yaml_text):
        """
        Given a fenced yaml example from a styling doc
        When its declared scope and merged configuration are schema-validated
        Then both satisfy the schema without inheritance inside complete scopes

        A failure here means the doc shows a contributor an edit the schema
        will not accept — the exact failure mode this guard exists to catch.
        """
        kind, scope = _parse_example_declaration(yaml_text, label, index)
        example = yaml.safe_load(yaml_text)
        assert isinstance(example, dict), f"{label} block {index} did not parse to a mapping: {yaml_text!r}"

        merged = _deep_merge(_load_live_config(), example)
        configurations = [("after merging onto the live config", merged)]
        if kind == "complete":
            complete = _with_complete_section(merged, example, scope, label, index) if scope else example
            configurations.append((f"as a complete example ({scope or 'entire config'})", complete))

        validator = Draft7Validator(_load_schema())
        for context, configuration in configurations:
            errors = sorted(validator.iter_errors(configuration), key=lambda e: e.path)
            assert not errors, (
                f"{label} block {index} is invalid against the schema {context}:\n"
                + "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
                + f"\n\nSource example:\n{yaml_text}"
            )


@pytest.fixture
def doc_guard():
    """Exercise the same validation surface pytest collects for real doc examples."""
    return TestStylingDocExamplesMatchSchema().test_example_is_schema_valid


@pytest.fixture
def emission_example():
    """A complete decoupled section, independent of the shipped style values."""
    return {
        "graphTypes": {
            "component": {
                "emission": {
                    "mode": "decoupled",
                    "portStyles": {
                        "port": "fill:#ffffff",
                        "pepport": "fill:#eeeeee",
                        "pepWrapOutline": "fill:none",
                    },
                }
            }
        }
    }


def _marked_example(document: dict[str, Any], declaration: str) -> str:
    """Serialize a fixture with its explicit example contract as the first line."""
    return f"# schema-example: {declaration}\n" + yaml.safe_dump(document)


class TestCompleteStylingExamples:
    """Complete examples must supply required fields within their declared scope."""

    @pytest.mark.parametrize("missing", ["port", "pepport", "pepWrapOutline", "portStyles"])
    def test_decoupled_example_cannot_inherit_required_styles(self, doc_guard, emission_example, missing):
        """
        Given a complete decoupled emission example missing a required style
        When the collected documentation guard validates that example
        Then it rejects the omission instead of borrowing the live style
        """
        emission = emission_example["graphTypes"]["component"]["emission"]
        if missing == "portStyles":
            del emission[missing]
        else:
            del emission["portStyles"][missing]
        source = _marked_example(emission_example, "complete graphTypes.component.emission")

        with pytest.raises(AssertionError, match=rf"'{missing}' is a required property"):
            doc_guard("fixture.md", 0, source)

    @pytest.mark.parametrize("mode", ["decoupled", "flat"])
    def test_valid_complete_emission_example_is_accepted(self, doc_guard, emission_example, mode):
        """
        Given a complete emission example satisfying its mode's requirements
        When the collected documentation guard validates that section
        Then decoupled styles are accepted and flat needs no port styles
        """
        emission = emission_example["graphTypes"]["component"]["emission"]
        emission["mode"] = mode
        if mode == "flat":
            del emission["portStyles"]
        source = _marked_example(emission_example, "complete graphTypes.component.emission")

        doc_guard("fixture.md", 0, source)

    def test_partial_fragment_can_inherit_required_styles(self, doc_guard):
        """
        Given an intentional fragment selecting decoupled emission only
        When the collected documentation guard merges it with the live config
        Then required styles may come from that live configuration
        """
        example = {"graphTypes": {"component": {"emission": {"mode": "decoupled"}}}}
        source = _marked_example(example, "fragment")

        doc_guard("fixture.md", 0, source)

    def test_complete_full_config_is_accepted(self, doc_guard):
        """
        Given a complete full configuration satisfying the current schema
        When the collected documentation guard validates it without a section path
        Then the standalone configuration is accepted
        """
        source = _marked_example(_load_live_config(), "complete")

        doc_guard("fixture.md", 0, source)

    def test_complete_full_config_cannot_inherit_required_root_key(self, doc_guard):
        """
        Given a full configuration example missing its required version
        When the collected documentation guard validates it as complete
        Then it rejects the missing root key instead of borrowing the live version
        """
        example = _load_live_config()
        del example["version"]
        source = _marked_example(example, "complete")

        with pytest.raises(AssertionError, match="'version' is a required property"):
            doc_guard("fixture.md", 0, source)

    def test_complete_nested_section_cannot_inherit_required_field(self, doc_guard):
        """
        Given a complete flowchart section missing its required padding
        When the collected documentation guard validates the nested section
        Then it rejects the omission while allowing base values outside the section
        """
        example = {"graphTypes": {"component": {"flowchartConfig": {"wrappingWidth": 250}}}}
        source = _marked_example(example, "complete graphTypes.component.flowchartConfig")

        with pytest.raises(AssertionError, match="'padding' is a required property"):
            doc_guard("fixture.md", 0, source)

    def test_complete_foundation_cannot_inherit_required_colors(self, doc_guard):
        """
        Given a complete foundation example missing its required colors section
        When the collected documentation guard validates that declared section
        Then it rejects the omission instead of borrowing the shipped palette
        """
        example = {"foundation": _load_live_config()["foundation"]}
        del example["foundation"]["colors"]
        source = _marked_example(example, "complete foundation")

        with pytest.raises(AssertionError, match="'colors' is a required property"):
            doc_guard("fixture.md", 0, source)

    @pytest.mark.parametrize("declaration", ["fragment", "complete graphTypes.component.emission"])
    def test_unknown_section_properties_are_rejected(self, doc_guard, emission_example, declaration):
        """
        Given a styling example with an unknown emission property
        When the collected documentation guard applies its declared contract
        Then schema validation rejects the unknown property in either mode
        """
        emission_example["graphTypes"]["component"]["emission"]["unknownStyle"] = "fill:none"
        source = _marked_example(emission_example, declaration)

        with pytest.raises(AssertionError, match="Additional properties.*unknownStyle"):
            doc_guard("fixture.md", 0, source)

    def test_complete_section_also_validates_properties_outside_its_scope(self, doc_guard, emission_example):
        """
        Given a valid complete emission section with an unknown root property
        When the collected documentation guard validates the example
        Then it rejects the root property instead of checking only the named section
        """
        emission_example["unknownRoot"] = True
        source = _marked_example(emission_example, "complete graphTypes.component.emission")

        with pytest.raises(AssertionError, match="Additional properties.*unknownRoot"):
            doc_guard("fixture.md", 0, source)


class TestStylingExampleDeclarations:
    """Every extracted block has an explicit, valid validation contract."""

    @pytest.mark.parametrize(
        "marker",
        [
            "",
            "# schema-example: typo\n",
            "# schema-example:\n",
            "# schema-example fragment\n",
            "# schema-example: fragment graphTypes.component.emission\n",
            "# schema-example: complete graphTypes..component\n",
            "# schema-example: complete .graphTypes\n",
            "# schema-example: complete graphTypes.component.\n",
        ],
        ids=[
            "missing",
            "unknown",
            "empty",
            "missing-colon",
            "fragment-path",
            "empty-segment",
            "leading-dot",
            "trailing-dot",
        ],
    )
    def test_missing_or_malformed_declaration_is_rejected(self, doc_guard, marker):
        """
        Given a schema-valid fragment with a missing or malformed declaration
        When the collected documentation guard validates the example
        Then it reports the schema-example contract error explicitly
        """
        source = marker + "graphTypes:\n  component:\n    direction: LR\n"

        with pytest.raises(AssertionError, match="schema-example"):
            doc_guard("fixture.md", 0, source)

    def test_declaration_must_start_the_example(self, doc_guard):
        """
        Given an example whose declaration appears after its YAML data
        When the collected documentation guard validates the example
        Then it rejects the misplaced declaration instead of treating it as a fragment
        """
        source = "graphTypes:\n  component:\n    direction: LR\n# schema-example: fragment\n"

        with pytest.raises(AssertionError, match="schema-example"):
            doc_guard("fixture.md", 0, source)

    def test_declared_complete_path_must_exist_in_example(self, doc_guard):
        """
        Given an example declaring a complete emission section but showing only direction
        When the collected documentation guard resolves the declared scope
        Then it rejects the absent section instead of validating the live emission
        """
        example = {"graphTypes": {"component": {"direction": "LR"}}}
        source = _marked_example(example, "complete graphTypes.component.emission")

        with pytest.raises(AssertionError, match=re.escape("graphTypes.component.emission")):
            doc_guard("fixture.md", 0, source)

    @pytest.mark.parametrize("marker", ["", "# schema-example: typo\n", "# schema-example: fragment\n"])
    def test_extraction_retains_blocks_regardless_of_declaration(self, tmp_path, marker):
        """
        Given a YAML fence with a missing, invalid, or valid declaration
        When the documentation harness extracts fenced examples
        Then the block stays available for validation instead of silently disappearing
        """
        source = marker + "graphTypes:\n  component:\n    direction: LR\n"
        document = tmp_path / "styling.md"
        document.write_text(f"```yaml\n{source}```\n", encoding="utf-8")

        assert _extract_yaml_blocks(document) == [source]
