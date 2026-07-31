#!/usr/bin/env python3
"""
Tests for the ADR-030 D1 componentsExternalTools category landing in components.yaml.

ADR-030 D1 (docs/adr/030-agentic-component-model.md) adds a fourth top-level
category, componentsExternalTools, a peer of componentsInfrastructure/componentsModel/
componentsApplication, collecting tool-and-tool-authorization components. It
carries two subcategories:

  - componentsToolNetworkControls (tool control plane)
  - componentsToolInvocationPath (tool data plane) — includes the existing componentTools

The existing componentTools entry is recategorized OUT of componentsModel /
componentsOrchestration INTO componentsExternalTools / componentsToolInvocationPath (D1: "the
existing componentTools (recategorized out of componentsModel) together with
the tool components the decomposition introduces").

This module tests the risk-map/yaml/components.yaml file-level content: the
categories: block gains the new category + 2 subcategories, and componentTools
is recategorized. Schema-level enum/allOf coverage lives in
test_components_schema_tools_category.py and the extended
TestPairingConstraintBehavior in test_components_mappings_field.py.

components.yaml now:
  1. declares a componentsExternalTools entry (title + subcategory: [componentsToolNetworkControls,
     componentsToolInvocationPath]) in the categories: block, and
  2. has componentTools' category set to componentsExternalTools and its subcategory
     set to componentsToolInvocationPath (moved from componentsModel /
     componentsOrchestration).
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_COMPONENTS_YAML = _REPO_ROOT / "risk-map" / "yaml" / "components.yaml"


@pytest.fixture(scope="module")
def components_data() -> dict:
    """Parsed risk-map/yaml/components.yaml."""
    with open(_COMPONENTS_YAML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def categories_by_id(components_data: dict) -> dict[str, dict]:
    """Map of top-level category id -> category dict from the categories: block."""
    return {cat["id"]: cat for cat in components_data.get("categories", []) if isinstance(cat.get("id"), str)}


@pytest.fixture(scope="module")
def components_by_id(components_data: dict) -> dict[str, dict]:
    """Map of component id -> component dict from the components: block."""
    return {comp["id"]: comp for comp in components_data.get("components", []) if isinstance(comp.get("id"), str)}


# ============================================================================
# categories: block — new componentsExternalTools category + subcategories
# ============================================================================


class TestCategoriesBlockDeclaresComponentsTools:
    """The file-level categories: block must declare componentsExternalTools per D1."""

    def test_componentstools_category_present(self, categories_by_id: dict[str, dict]):
        """
        Given: the live categories: block
        When: category ids are inspected
        Then: 'componentsExternalTools' is present as a top-level category
        """
        assert "componentsExternalTools" in categories_by_id, (
            "Expected a top-level 'componentsExternalTools' category in components.yaml "
            "categories: block (ADR-030 D1). Not found; got top-level categories: "
            f"{sorted(categories_by_id.keys())}"
        )

    def test_componentstools_has_nonempty_title(self, categories_by_id: dict[str, dict]):
        """
        Given: the componentsExternalTools category entry
        When: its 'title' field is inspected
        Then: it is a non-empty string
        """
        if "componentsExternalTools" not in categories_by_id:
            pytest.fail("componentsExternalTools category not present; cannot check title")
        title = categories_by_id["componentsExternalTools"].get("title")
        assert isinstance(title, str) and title.strip(), (
            f"Expected non-empty 'title' on componentsExternalTools category; got: {title!r}"
        )

    def test_componentstools_has_description(self, categories_by_id: dict[str, dict]):
        """
        Given: the componentsExternalTools category entry
        When: its 'description' field is inspected
        Then: it is present (matches the pattern of the other 3 top-level categories,
              all of which carry a description per riskmap.schema.json prose-strict)
        """
        if "componentsExternalTools" not in categories_by_id:
            pytest.fail("componentsExternalTools category not present; cannot check description")
        assert categories_by_id["componentsExternalTools"].get("description"), (
            "Expected a non-empty 'description' on the componentsExternalTools category, "
            "consistent with componentsInfrastructure/componentsModel/componentsApplication."
        )

    def test_componentstools_declares_exactly_two_subcategories(self, categories_by_id: dict[str, dict]):
        """
        Given: the componentsExternalTools category entry
        When: its nested subcategory: list is inspected
        Then: it declares exactly 2 subcategories per D1
              ('componentsToolNetworkControls' and 'componentsToolInvocationPath')
        """
        if "componentsExternalTools" not in categories_by_id:
            pytest.fail("componentsExternalTools category not present; cannot check subcategories")
        subcats = categories_by_id["componentsExternalTools"].get("subcategory", [])
        subcat_ids = {s.get("id") for s in subcats if isinstance(s, dict)}
        assert subcat_ids == {"componentsToolNetworkControls", "componentsToolInvocationPath"}, (
            f"Expected exactly {{'componentsToolNetworkControls', 'componentsToolInvocationPath'}} nested "
            f"under componentsExternalTools per ADR-030 D1; got: {subcat_ids}"
        )

    @pytest.mark.parametrize("subcategory_id", ["componentsToolNetworkControls", "componentsToolInvocationPath"])
    def test_subcategory_has_nonempty_title(self, categories_by_id: dict[str, dict], subcategory_id: str):
        """
        Given: a componentsExternalTools subcategory entry
        When: its 'title' field is inspected
        Then: it is a non-empty string
        """
        if "componentsExternalTools" not in categories_by_id:
            pytest.fail("componentsExternalTools category not present; cannot check subcategory titles")
        subcats = {
            s.get("id"): s
            for s in categories_by_id["componentsExternalTools"].get("subcategory", [])
            if isinstance(s, dict)
        }
        if subcategory_id not in subcats:
            pytest.fail(f"{subcategory_id} not declared under componentsExternalTools")
        title = subcats[subcategory_id].get("title")
        assert isinstance(title, str) and title.strip(), (
            f"Expected non-empty 'title' on {subcategory_id}; got: {title!r}"
        )


# ============================================================================
# componentTools recategorization
# ============================================================================


class TestComponentToolsRecategorized:
    """
    The existing componentTools entry must move out of componentsModel /
    componentsOrchestration into componentsExternalTools / componentsToolInvocationPath (D1:
    componentsToolInvocationPath lists componentToolServer, componentTools,
    componentToolInputHandling, componentToolOutputHandling).
    """

    def test_componenttools_entry_exists(self, components_by_id: dict[str, dict]):
        """
        Given: the live components: block
        When: component ids are inspected
        Then: 'componentTools' still exists (D1 recategorizes it; does not remove it)
        """
        assert "componentTools" in components_by_id, (
            "Expected 'componentTools' to still exist as a component entry "
            "(ADR-030 D1 recategorizes it, it does not delete it)."
        )

    def test_componenttools_category_is_componentstools(self, components_by_id: dict[str, dict]):
        """
        Given: the componentTools component entry
        When: its 'category' field is inspected
        Then: it is 'componentsExternalTools' (moved out of componentsModel per D1)
        """
        if "componentTools" not in components_by_id:
            pytest.fail("componentTools component not present; cannot check category")
        category = components_by_id["componentTools"].get("category")
        assert category == "componentsExternalTools", (
            f"Expected componentTools.category == 'componentsExternalTools' (ADR-030 D1 "
            f"recategorization out of componentsModel); got: {category!r}"
        )

    def test_componenttools_subcategory_is_componentstoolcore(self, components_by_id: dict[str, dict]):
        """
        Given: the componentTools component entry
        When: its 'subcategory' field is inspected
        Then: it is 'componentsToolInvocationPath' — D1 explicitly lists componentTools as a
              componentsToolInvocationPath (tool data plane) member, distinct from
              componentsToolNetworkControls (tool control plane: the PEP/proxy/prompt-
              template components the decomposition introduces later)
        """
        if "componentTools" not in components_by_id:
            pytest.fail("componentTools component not present; cannot check subcategory")
        subcategory = components_by_id["componentTools"].get("subcategory")
        assert subcategory == "componentsToolInvocationPath", (
            f"Expected componentTools.subcategory == 'componentsToolInvocationPath' per ADR-030 D1 "
            f"('componentsToolInvocationPath (the tool data plane) — componentToolServer, "
            f"componentTools, componentToolInputHandling, componentToolOutputHandling'); "
            f"got: {subcategory!r}"
        )

    def test_componenttools_edges_unchanged_by_recategorization(self, components_by_id: dict[str, dict]):
        """
        Given: the componentTools component entry
        When: its edges are inspected
        Then: componentToolRegistry is still present on both to/from — D1 is a
              taxonomy (category/subcategory) change only; it does not decide
              edge-set rewiring (that is D8, a separate decision, and applies to
              tool-call re-anchoring at the application/agent boundary, not to
              componentTools' existing registry edge).

        This guards against an over-eager implementation that also touches
        edges while recategorizing, which is out of D1's scope.
        """
        if "componentTools" not in components_by_id:
            pytest.fail("componentTools component not present; cannot check edges")
        edges = components_by_id["componentTools"].get("edges", {})
        to_edges = edges.get("to", [])
        from_edges = edges.get("from", [])
        assert "componentToolRegistry" in to_edges, (
            f"Expected componentToolRegistry preserved in componentTools.edges.to "
            f"(D1 is taxonomy-only, not an edge rewire); got to: {to_edges}"
        )
        assert "componentToolRegistry" in from_edges, (
            f"Expected componentToolRegistry preserved in componentTools.edges.from "
            f"(D1 is taxonomy-only, not an edge rewire); got from: {from_edges}"
        )


# ============================================================================
# Registries stay in Infrastructure (D1 explicit call-out)
# ============================================================================


class TestRegistriesStayInInfrastructure:
    """
    D1: 'Registries (componentModelRegistry, componentToolRegistry) stay in
    Infrastructure — they are not tools.' Forward guard against an
    over-eager recategorization sweeping registries into componentsExternalTools
    along with componentTools.
    """

    @pytest.mark.parametrize("registry_id", ["componentModelRegistry", "componentToolRegistry"])
    def test_registry_category_still_infrastructure(self, components_by_id: dict[str, dict], registry_id: str):
        """
        Given: a registry component entry
        When: its 'category' field is inspected
        Then: it is still 'componentsInfrastructure' (unchanged by D1)
        """
        if registry_id not in components_by_id:
            pytest.fail(f"{registry_id} component not present; cannot check category")
        category = components_by_id[registry_id].get("category")
        assert category == "componentsInfrastructure", (
            f"D1 explicitly excludes registries from componentsExternalTools ('they are not "
            f"tools'); expected {registry_id}.category == 'componentsInfrastructure', "
            f"got: {category!r}"
        )


# ============================================================================
# Live corpus still passes schema validation after recategorization
# ============================================================================


class TestLiveCorpusValidatesAfterRecategorization:
    """
    The atomic schema+yaml pairing (ADR-030 "Decision" section: 'the
    components.schema.json and components.yaml edits must land together
    atomically') means the live corpus must validate against the live
    schema post-migration. This is also covered generically by
    test_consumer_yaml_check_jsonschema_integration.py; this test pins the
    ADR-030 rationale for discoverability.
    """

    def test_live_components_yaml_passes_check_jsonschema(self):
        """
        Given: the live components.yaml and components.schema.json
        When: check-jsonschema validates the yaml against the schema
        Then: exit code 0

        The schema (category/subcategory enum + allOf) and the yaml
        (categories: block + componentTools recategorization) must stay in
        step: a partial edit (yaml without schema, or vice versa) fails this
        check, which is the intended atomicity guard (ADR-030 Consequences:
        "The schema and YAML must change together atomically").
        """
        import subprocess

        schema_path = _REPO_ROOT / "risk-map" / "schemas" / "components.schema.json"
        base_uri = f"file://{schema_path.parent}/"
        result = subprocess.run(
            [
                "check-jsonschema",
                "--base-uri",
                base_uri,
                "--schemafile",
                str(schema_path),
                str(_COMPONENTS_YAML),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"Live components.yaml must pass check-jsonschema against "
            f"components.schema.json (ADR-030 atomic schema+yaml pairing).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ============================================================================
# Category/subcategory nesting check picks up componentsExternalTools cleanly
# ============================================================================


class TestNestingCheckCoversComponentsTools:
    """
    check_category_subcategory_nesting (ADR-018 D6, riskmap_validator.validator)
    reads the categories: block to build its nesting map. Once D1 lands, it
    must recognize componentsExternalTools -> {componentsToolNetworkControls, componentsToolInvocationPath}
    as valid nesting so componentTools (now in componentsToolInvocationPath) is not
    flagged as a mismatch.
    """

    def test_live_corpus_produces_zero_nesting_warnings(self):
        """
        Given: the live components.yaml, parsed into ComponentNode objects and
               a category_to_subcategories map derived from its categories: block
        When: check_category_subcategory_nesting() is called
        Then: 0 warnings — componentTools' (componentsExternalTools,
              componentsToolInvocationPath) pairing is recognized as valid nesting

        This test parses the live corpus, so it is a regression guard on the
        live componentTools pairing plus a drift guard: if the categories:
        block is ever edited without an accompanying nesting-map-consistent
        edit, this test surfaces the mismatch.
        """
        from riskmap_validator.utils import parse_components_yaml

        components = parse_components_yaml(_COMPONENTS_YAML)

        with open(_COMPONENTS_YAML, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        nesting_map: dict[str, set[str]] = {}
        for cat in data.get("categories", []):
            cat_id = cat.get("id")
            if not isinstance(cat_id, str):
                continue
            sub_ids = {sub.get("id") for sub in cat.get("subcategory", []) if isinstance(sub.get("id"), str)}
            nesting_map[cat_id] = sub_ids

        from riskmap_validator.validator import check_category_subcategory_nesting

        result = check_category_subcategory_nesting(components, nesting_map)
        assert result == [], f"Expected 0 nesting warnings on the live corpus; got {len(result)}: {result}"

    def test_componenttools_specifically_nests_under_componentstools_toolcore(self):
        """
        Given: the live corpus's componentTools entry and its categories: block
        When: check_category_subcategory_nesting() is called against just that
              component plus the live nesting map
        Then: 0 warnings — pins the specific D1 pairing for componentTools
              (not just an aggregate zero-warning count across the whole file)
        """
        from riskmap_validator.utils import parse_components_yaml
        from riskmap_validator.validator import check_category_subcategory_nesting

        components = parse_components_yaml(_COMPONENTS_YAML)
        if "componentTools" not in components:
            pytest.fail("componentTools not found in parsed live corpus")

        with open(_COMPONENTS_YAML, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        nesting_map: dict[str, set[str]] = {}
        for cat in data.get("categories", []):
            cat_id = cat.get("id")
            if not isinstance(cat_id, str):
                continue
            sub_ids = {sub.get("id") for sub in cat.get("subcategory", []) if isinstance(sub.get("id"), str)}
            nesting_map[cat_id] = sub_ids

        result = check_category_subcategory_nesting({"componentTools": components["componentTools"]}, nesting_map)
        assert result == [], f"Expected componentTools to nest cleanly under its declared category; got: {result}"


# ============================================================================
# Test Summary
# ============================================================================
"""
Test Summary
============
Total Tests: 15

- TestCategoriesBlockDeclaresComponentsTools (6): category present, title,
  description, exactly-2-subcategories, per-subcategory titles (parametrized x2)
- TestComponentToolsRecategorized (4): entry still exists, category ==
  componentsExternalTools, subcategory == componentsToolInvocationPath, edges untouched
- TestRegistriesStayInInfrastructure (2, parametrized): componentModelRegistry
  and componentToolRegistry remain componentsInfrastructure
- TestLiveCorpusValidatesAfterRecategorization (1): atomic schema+yaml pairing
  via check-jsonschema
- TestNestingCheckCoversComponentsTools (2): aggregate zero-warning regression
  guard + componentTools-specific nesting pin

componentTools is recategorized into componentsExternalTools/componentsToolInvocationPath and
the categories: block declares componentsExternalTools with its two subcategories
(ADR-030 D1). What each test pins:
- TestCategoriesBlockDeclaresComponentsTools (6) — componentsExternalTools category
  present in the categories: block with both subcategories
- TestComponentToolsRecategorized.test_componenttools_category_is_componentstools
  and test_componenttools_subcategory_is_componentstoolcore — componentTools
  is category=componentsExternalTools, subcategory=componentsToolInvocationPath
- TestComponentToolsRecategorized.test_componenttools_entry_exists
- TestComponentToolsRecategorized.test_componenttools_edges_unchanged_by_recategorization
- TestRegistriesStayInInfrastructure (both parametrized cases) — recategorization
  is scoped to componentTools only
- TestLiveCorpusValidatesAfterRecategorization — componentTools' new
  componentsExternalTools/componentsToolInvocationPath pairing is schema-valid (ADR-030 atomic
  schema+yaml pairing)
- TestNestingCheckCoversComponentsTools (both) — componentTools' category/
  subcategory and the categories: block agree
"""
