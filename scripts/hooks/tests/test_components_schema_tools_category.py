#!/usr/bin/env python3
"""
Tests for the ADR-030 D1 componentsExternalTools category/subcategory schema enums.

ADR-030 D1 (docs/adr/030-agentic-component-model.md, "Schema impact"):

  "category.id enum gains componentsExternalTools (currently closed to three values
  at components.schema.json:30); subcategory.id enum gains
  componentsToolNetworkControls and componentsToolInvocationPath; a new componentsExternalTools branch
  is added to the allOf block (components.schema.json:147-158) permitting
  those two subcategories; the file-level categories: block gains the
  category and its subcategories."

This module tests the enum-level surface of that change:
  - definitions/category/properties/id/enum gains 'componentsExternalTools'
  - definitions/subcategory/properties/id/enum gains 'componentsToolNetworkControls'
    and 'componentsToolInvocationPath'
  - definitions/component/properties/id/enum is UNCHANGED (componentTools
    already exists there; D1 recategorizes, it does not rename)

The allOf if/then behavioral contract (the new componentsExternalTools branch
restricting subcategory to exactly {componentsToolNetworkControls,
componentsToolInvocationPath}) is covered by the extended TestSchemaContainsPairingConstraint
and TestPairingConstraintBehavior classes in test_components_mappings_field.py
(ADR-026 D10's existing pairing-constraint machinery), not duplicated here.

The file-level categories: block content (components.yaml) is covered by
test_components_yaml_tools_category.py.
"""

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError

sys.path.insert(0, str(Path(__file__).parent.parent))

SCHEMA_FILE = "components.schema.json"


@pytest.fixture(scope="module")
def components_schema(risk_map_schemas_dir: Path) -> dict:
    """Parsed components.schema.json."""
    path = risk_map_schemas_dir / SCHEMA_FILE
    if not path.is_file():
        pytest.fail(f"Schema not found: {path}")
    with open(path) as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def category_id_enum(components_schema: dict) -> list:
    """definitions/category/properties/id/enum list."""
    enum = (
        components_schema.get("definitions", {})
        .get("category", {})
        .get("properties", {})
        .get("id", {})
        .get("enum")
    )
    assert isinstance(enum, list), f"Expected definitions/category/properties/id/enum to be a list; got: {enum!r}"
    return enum


@pytest.fixture(scope="module")
def subcategory_id_enum(components_schema: dict) -> list:
    """definitions/subcategory/properties/id/enum list."""
    enum = (
        components_schema.get("definitions", {})
        .get("subcategory", {})
        .get("properties", {})
        .get("id", {})
        .get("enum")
    )
    assert isinstance(enum, list), (
        f"Expected definitions/subcategory/properties/id/enum to be a list; got: {enum!r}"
    )
    return enum


@pytest.fixture(scope="module")
def component_id_enum(components_schema: dict) -> list:
    """definitions/component/properties/id/enum list."""
    enum = (
        components_schema.get("definitions", {})
        .get("component", {})
        .get("properties", {})
        .get("id", {})
        .get("enum")
    )
    assert isinstance(enum, list), f"Expected definitions/component/properties/id/enum to be a list; got: {enum!r}"
    return enum


# ============================================================================
# Schema meta-validity
# ============================================================================


class TestSchemaMetaValidity:
    """components.schema.json must remain valid Draft-07 after the D1 edit."""

    def test_schema_passes_draft07_metaschema(self, components_schema: dict):
        """
        Given: components.schema.json loaded
        When: Draft7Validator.check_schema() is called
        Then: No SchemaError is raised

        Forward guard: catches a malformed allOf/enum edit that breaks the
        schema itself, not just the taxonomy content.
        """
        try:
            Draft7Validator.check_schema(components_schema)
        except SchemaError as exc:
            pytest.fail(f"{SCHEMA_FILE} is not valid Draft-07: {exc.message}")


# ============================================================================
# category.id enum
# ============================================================================


class TestCategoryIdEnumGainsComponentsTools:
    """definitions/category/properties/id/enum must gain 'componentsExternalTools'."""

    def test_componentstools_in_category_enum(self, category_id_enum: list):
        """
        Given: definitions/category/properties/id/enum
        When: its members are inspected
        Then: 'componentsExternalTools' is present
        """
        assert "componentsExternalTools" in category_id_enum, (
            f"Expected 'componentsExternalTools' in category.id enum (ADR-030 D1); got: {category_id_enum}"
        )

    def test_existing_three_categories_unchanged(self, category_id_enum: list):
        """
        Given: definitions/category/properties/id/enum
        When: its members are inspected
        Then: the pre-existing 3 categories are still present (additive edit,
              not a replacement)
        """
        for existing in ("componentsInfrastructure", "componentsModel", "componentsApplication"):
            assert existing in category_id_enum, (
                f"D1 is additive; expected pre-existing category '{existing}' to remain "
                f"in the enum. Got: {category_id_enum}"
            )

    def test_category_enum_has_exactly_four_members(self, category_id_enum: list):
        """
        Given: definitions/category/properties/id/enum
        When: its length is checked
        Then: it has exactly 4 members (3 existing + componentsExternalTools)

        Pins the enum to exactly the D1 target set so a stray typo'd category
        id (e.g. a copy-paste duplicate) is caught, not just presence checks.
        """
        assert len(category_id_enum) == 4, (
            f"Expected exactly 4 category ids after ADR-030 D1 (3 existing + "
            f"componentsExternalTools); got {len(category_id_enum)}: {category_id_enum}"
        )


# ============================================================================
# subcategory.id enum
# ============================================================================


class TestSubcategoryIdEnumGainsToolSubcategories:
    """definitions/subcategory/properties/id/enum must gain the 2 new ids."""

    @pytest.mark.parametrize("subcategory_id", ["componentsToolNetworkControls", "componentsToolInvocationPath"])
    def test_new_subcategory_in_enum(self, subcategory_id_enum: list, subcategory_id: str):
        """
        Given: definitions/subcategory/properties/id/enum
        When: its members are inspected
        Then: the new subcategory id is present
        """
        assert subcategory_id in subcategory_id_enum, (
            f"Expected {subcategory_id!r} in subcategory.id enum (ADR-030 D1); got: {subcategory_id_enum}"
        )

    def test_existing_eight_subcategories_unchanged(self, subcategory_id_enum: list):
        """
        Given: definitions/subcategory/properties/id/enum
        When: its members are inspected
        Then: all 8 pre-existing subcategory ids remain (additive edit)
        """
        existing_ids = {
            "componentsModelTraining",
            "componentsData",
            "componentsAgent",
            "componentsOrchestration",
            "componentsModelDeployment",
            "componentsModelCore",
            "componentsApplicationCore",
            "componentsRegistries",
        }
        missing = existing_ids - set(subcategory_id_enum)
        assert not missing, f"D1 is additive; expected pre-existing subcategory ids to remain. Missing: {missing}"

    def test_subcategory_enum_has_at_least_ten_members(self, subcategory_id_enum: list):
        """
        Given: definitions/subcategory/properties/id/enum
        When: its length is checked
        Then: it has at least 10 members (8 existing + 2 new tool subcategories)

        Not pinned to exactly 10: ADR-030 D2 (test_components_schema_identity_subcategory.py)
        lands an 11th (componentsIdentity) on the same branch. The exact
        post-D1+D2 count (11) is pinned there; this test only guards D1's own
        additive contribution.
        """
        assert len(subcategory_id_enum) >= 10, (
            f"Expected at least 10 subcategory ids after ADR-030 D1 (8 existing + "
            f"componentsToolNetworkControls + componentsToolInvocationPath); got "
            f"{len(subcategory_id_enum)}: {subcategory_id_enum}"
        )


# ============================================================================
# component.id enum — unchanged (recategorization, not renaming)
# ============================================================================


class TestComponentIdEnumUnaffectedByD1:
    """
    D1 recategorizes componentTools (moves its category/subcategory); it does
    not rename or remove it, and does not itself add new component.id values
    (the tool components the decomposition introduces — componentToolServer,
    componentToolInputHandling, etc. — are a SEPARATE, later content change
    per the ADR's "Migration sequencing": net-new component ids clear the
    absorb/reader-instructive justification test before landing in the closed
    enum. D1's schema-impact statement only names category.id and
    subcategory.id).
    """

    def test_componenttools_still_in_component_enum(self, component_id_enum: list):
        """
        Given: definitions/component/properties/id/enum
        When: its members are inspected
        Then: 'componentTools' is present (unchanged by D1)
        """
        assert "componentTools" in component_id_enum, (
            f"D1 recategorizes componentTools, it does not remove/rename it; "
            f"expected 'componentTools' still in component.id enum. Got: {component_id_enum}"
        )

    def test_component_enum_does_not_yet_gain_new_tool_component_ids(self, component_id_enum: list):
        """
        Given: definitions/component/properties/id/enum
        When: its members are inspected
        Then: none of the decomposition's net-new tool component ids
              (componentToolServer, componentToolInputHandling,
              componentToolOutputHandling, componentToolNetworkPolicyEnforcementPoint,
              componentAuthorizationPolicyEnforcementPoint, componentFederationProxy,
              componentExternalPromptTemplate) are present yet

        This is a scope-boundary guard, not a prohibition forever: D1's own
        "Schema impact" paragraph names only category.id and subcategory.id.
        Those component ids arrive with the MCP decomposition content (a
        later, separate change per "Migration sequencing" step 2 — the
        net-new component justification pass). If this test starts failing
        because the SWE added them while implementing D1, that is scope
        creep beyond D1 and should be flagged, not silently accepted.
        """
        not_yet_expected = {
            "componentToolServer",
            "componentToolInputHandling",
            "componentToolOutputHandling",
            "componentToolNetworkPolicyEnforcementPoint",
            "componentAuthorizationPolicyEnforcementPoint",
            "componentFederationProxy",
            "componentExternalPromptTemplate",
        }
        present = not_yet_expected & set(component_id_enum)
        assert not present, (
            f"D1 scope is category/subcategory taxonomy only; these net-new tool "
            f"component ids should not appear yet (they require the separate "
            f"net-new-component justification pass first): {present}"
        )


# ============================================================================
# Test Summary
# ============================================================================
"""
Test Summary
============
Total Tests: 10

- TestSchemaMetaValidity (1): Draft-07 validity
- TestCategoryIdEnumGainsComponentsTools (3): presence, existing-3-unchanged,
  exactly-4-members
- TestSubcategoryIdEnumGainsToolSubcategories (3, one parametrized x2):
  presence x2, existing-8-unchanged, at-least-10-members
- TestComponentIdEnumUnaffectedByD1 (2): componentTools still present,
  net-new tool component ids NOT yet present (scope boundary)

componentsExternalTools lands in components.schema.json's category.id and
subcategory.id enums (ADR-030 D1). What each test pins:
- TestCategoryIdEnumGainsComponentsTools.test_componentstools_in_category_enum
- TestCategoryIdEnumGainsComponentsTools.test_category_enum_has_exactly_four_members
- TestSubcategoryIdEnumGainsToolSubcategories.test_new_subcategory_in_enum[componentsToolNetworkControls]
- TestSubcategoryIdEnumGainsToolSubcategories.test_new_subcategory_in_enum[componentsToolInvocationPath]
- TestSubcategoryIdEnumGainsToolSubcategories.test_subcategory_enum_has_at_least_ten_members

Forward guards (unaffected by D1's scope, regression protection):
- TestSchemaMetaValidity, existing-unchanged checks, TestComponentIdEnumUnaffectedByD1
  (component.id enum is untouched by D1's scope)
"""
