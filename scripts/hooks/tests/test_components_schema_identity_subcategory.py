#!/usr/bin/env python3
"""
Tests for the ADR-030 D2 componentsIdentity subcategory schema enum.

ADR-030 D2 (docs/adr/030-agentic-component-model.md, "Schema impact"):

  "subcategory.id enum gains componentsIdentity; the Infrastructure allOf
  then-block (components.schema.json:149-150, today {componentsData,
  componentsModelDeployment}) gains componentsIdentity. If
  componentsRegistries is not already present in the Infrastructure branch
  on the target base, it is added in the same edit so the registries keep a
  valid nesting."

Quoted verbatim. The id it names, componentsModelDeployment, was subsequently
renamed to componentsDeployment on this branch -- ADR-030 D3 called for the
title change but stated the id was unchanged, and the rename was needed
because the renderer derives subcategory labels from the id, not the title.
That divergence is recorded as an amendment to ADR-030; the quotation above
is left as the ADR reads, not as the code stands.

This module tests the enum-level surface of that change:
  - definitions/subcategory/properties/id/enum gains 'componentsIdentity'
  - the componentsInfrastructure allOf then-block's subcategory enum gains
    'componentsIdentity' alongside the pre-existing componentsData /
    componentsDeployment / componentsRegistries members
  - definitions/component/properties/id/enum is UNCHANGED (D2 fixes the
    home for componentIdentityProvider and
    componentAuthorizationPolicyDecisionPoint; authoring those component
    ids is a separate, later content change, same boundary as D1)

D2 is subcategory-only — unlike D1, it adds no new top-level category, so
there is no new allOf branch and no mermaid-styles / componentCategories
impact (mermaid-styles keys off category, not subcategory).
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


@pytest.fixture(scope="module")
def infrastructure_subcategory_enum(components_schema: dict) -> list:
    """The componentsInfrastructure allOf branch's subcategory enum (the then-block)."""
    for branch in components_schema["definitions"]["component"]["allOf"]:
        cond = branch.get("if", {}).get("properties", {}).get("category", {})
        if cond.get("const") == "componentsInfrastructure":
            enum = branch.get("then", {}).get("properties", {}).get("subcategory", {}).get("enum")
            assert isinstance(enum, list), (
                f"Expected componentsInfrastructure branch's subcategory enum to be a list; got: {enum!r}"
            )
            return enum
    pytest.fail("No allOf branch found with if.properties.category.const == 'componentsInfrastructure'")


# ============================================================================
# Schema meta-validity
# ============================================================================


class TestSchemaMetaValidity:
    """components.schema.json must remain valid Draft-07 after the D2 edit."""

    def test_schema_passes_draft07_metaschema(self, components_schema: dict):
        """
        Given: components.schema.json loaded
        When: Draft7Validator.check_schema() is called
        Then: No SchemaError is raised
        """
        try:
            Draft7Validator.check_schema(components_schema)
        except SchemaError as exc:
            pytest.fail(f"{SCHEMA_FILE} is not valid Draft-07: {exc.message}")


# ============================================================================
# subcategory.id enum (global definition)
# ============================================================================


class TestSubcategoryIdEnumGainsIdentity:
    """definitions/subcategory/properties/id/enum must gain 'componentsIdentity'."""

    def test_componentsidentity_in_subcategory_enum(self, subcategory_id_enum: list):
        """
        Given: definitions/subcategory/properties/id/enum
        When: its members are inspected
        Then: 'componentsIdentity' is present
        """
        assert "componentsIdentity" in subcategory_id_enum, (
            f"Expected 'componentsIdentity' in subcategory.id enum (ADR-030 D2); got: {subcategory_id_enum}"
        )

    def test_existing_ten_subcategories_unchanged(self, subcategory_id_enum: list):
        """
        Given: definitions/subcategory/properties/id/enum
        When: its members are inspected
        Then: all 10 pre-existing subcategory ids (8 original + D1's 2 tool
              subcategories) remain (additive edit)
        """
        existing_ids = {
            "componentsModelTraining",
            "componentsData",
            "componentsAgent",
            "componentsOrchestration",
            "componentsDeployment",
            "componentsModelCore",
            "componentsApplicationCore",
            "componentsRegistries",
            "componentsToolNetworkControls",
            "componentsToolInvocationPath",
        }
        missing = existing_ids - set(subcategory_id_enum)
        assert not missing, f"D2 is additive; expected pre-existing subcategory ids to remain. Missing: {missing}"

    def test_subcategory_enum_has_exactly_eleven_members(self, subcategory_id_enum: list):
        """
        Given: definitions/subcategory/properties/id/enum
        When: its length is checked
        Then: it has exactly 11 members (10 existing + componentsIdentity)
        """
        assert len(subcategory_id_enum) == 11, (
            f"Expected exactly 11 subcategory ids after ADR-030 D2 (10 existing + "
            f"componentsIdentity); got {len(subcategory_id_enum)}: {subcategory_id_enum}"
        )


# ============================================================================
# componentsInfrastructure allOf branch subcategory enum
# ============================================================================


class TestInfrastructureBranchGainsIdentitySubcategory:
    """The componentsInfrastructure allOf then-block must permit componentsIdentity."""

    def test_componentsidentity_permitted_under_infrastructure(self, infrastructure_subcategory_enum: list):
        """
        Given: the componentsInfrastructure allOf branch's subcategory enum
        When: its members are inspected
        Then: 'componentsIdentity' is present
        """
        assert "componentsIdentity" in infrastructure_subcategory_enum, (
            f"Expected 'componentsIdentity' permitted under componentsInfrastructure "
            f"(ADR-030 D2); got: {infrastructure_subcategory_enum}"
        )

    def test_componentsregistries_present_in_same_branch(self, infrastructure_subcategory_enum: list):
        """
        Given: the componentsInfrastructure allOf branch's subcategory enum
        When: its members are inspected
        Then: 'componentsRegistries' is present (D2's text: added in the same
              edit if not already present on the target base, so registries
              keep a valid nesting; this pins that invariant regardless of
              which base landed it first)
        """
        assert "componentsRegistries" in infrastructure_subcategory_enum, (
            f"Expected 'componentsRegistries' to remain valid under componentsInfrastructure "
            f"(ADR-030 D2); got: {infrastructure_subcategory_enum}"
        )

    def test_infrastructure_branch_has_exactly_four_subcategories(self, infrastructure_subcategory_enum: list):
        """
        Given: the componentsInfrastructure allOf branch's subcategory enum
        When: its length is checked
        Then: it has exactly 4 members (componentsData, componentsDeployment,
              componentsRegistries, componentsIdentity)
        """
        assert len(infrastructure_subcategory_enum) == 4, (
            f"Expected exactly 4 subcategories under componentsInfrastructure after "
            f"ADR-030 D2; got {len(infrastructure_subcategory_enum)}: {infrastructure_subcategory_enum}"
        )


# ============================================================================
# component.id enum — unchanged (this ADR fixes the home, not the authoring)
# ============================================================================


class TestComponentIdEnumUnaffectedByD2:
    """
    D2 fixes the taxonomy home for componentIdentityProvider and
    componentAuthorizationPolicyDecisionPoint; it does not itself author
    those component ids into the closed component.id enum (same boundary as
    D1 — net-new component ids are a separate, later content change that
    must clear its own justification pass).
    """

    def test_component_enum_does_not_yet_gain_identity_component_ids(self, component_id_enum: list):
        """
        Given: definitions/component/properties/id/enum
        When: its members are inspected
        Then: neither 'componentIdentityProvider' nor
              'componentAuthorizationPolicyDecisionPoint' is present yet

        Scope-boundary guard, not a prohibition forever — see
        test_components_schema_tools_category.py's equivalent D1 test for
        the same rationale.
        """
        not_yet_expected = {"componentIdentityProvider", "componentAuthorizationPolicyDecisionPoint"}
        present = not_yet_expected & set(component_id_enum)
        assert not present, (
            f"D2 scope is subcategory taxonomy only; these net-new identity "
            f"component ids should not appear yet: {present}"
        )


# ============================================================================
# Test Summary
# ============================================================================
"""
Test Summary
============
Total Tests: 8

- TestSchemaMetaValidity (1): Draft-07 validity
- TestSubcategoryIdEnumGainsIdentity (3): presence, existing-10-unchanged,
  exactly-11-members
- TestInfrastructureBranchGainsIdentitySubcategory (3): componentsIdentity
  permitted, componentsRegistries still present, exactly-4-members
- TestComponentIdEnumUnaffectedByD2 (1): net-new identity component ids NOT
  yet present (scope boundary)

componentsIdentity lands in components.schema.json's subcategory.id enum
and the componentsInfrastructure allOf branch (ADR-030 D2); no top-level
category, no mermaid-styles impact (category-scoped only).
"""
