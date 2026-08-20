#!/usr/bin/env python3
"""
Placement pins for the agentic component layer added to components.yaml.

The agentic layer introduces 18 net-new components spread across three
top-level categories (componentsInfrastructure, componentsApplication,
componentsExternalTools) and six subcategories. Their placement is the
content decision -- which tier a component belongs to determines which
persona owns it, which controls are expected to reach it, and where it is
drawn in the generated graphs and tables.

Nothing else in the suite pins that decision per component. The schema pins
the *shape* of the taxonomy (which subcategories may nest under which
category), and check_category_subcategory_nesting pins that a component's
declared pair is one of the legal pairs -- but both are satisfied by any
schema-legal placement. Moving componentToolServer out of
componentsExternalTools / componentsToolInvocationPath into
componentsApplication / componentsAgent, for instance, is schema-valid and
edge-preserving: the taxonomy tests stay green while the content meaning
silently changes.

This module closes that gap for the components this layer introduces, and
only those. It deliberately does not pin the inherited corpus -- the
placement of pre-existing components is settled elsewhere and is not this
layer's decision to restate.

Related coverage, kept separate on purpose:
  - test_components_yaml_tools_category.py -- the componentsExternalTools
    category landing in the categories: block, and componentTools'
    recategorization into it
  - test_components_schema_tools_category.py /
    test_components_schema_identity_subcategory.py -- the schema enums and
    allOf branches that make these placements legal at all
  - test_category_subcategory_nesting.py -- the generic nesting check
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_COMPONENTS_YAML = _REPO_ROOT / "risk-map" / "yaml" / "components.yaml"

# Declared (category, subcategory) placement for each component the agentic
# layer introduces, in taxonomy order. This table is the assertion: an entry
# here that disagrees with components.yaml fails, in either direction.
_NET_NEW_PLACEMENTS: dict[str, tuple[str, str]] = {
    # Infrastructure -- the identity plane: authorities plus the cross-domain intermediary
    "componentIdentityProvider": ("componentsInfrastructure", "componentsIdentity"),
    "componentAuthorizationPolicyDecisionPoint": ("componentsInfrastructure", "componentsIdentity"),
    "componentFederationProxy": ("componentsInfrastructure", "componentsIdentity"),
    # Infrastructure -- runtime hosting and audit substrate
    "componentIsolationRuntime": ("componentsInfrastructure", "componentsDeployment"),
    "componentToolHosting": ("componentsInfrastructure", "componentsDeployment"),
    "componentRuntimeHosting": ("componentsInfrastructure", "componentsDeployment"),
    "componentAuditRecordRepository": ("componentsInfrastructure", "componentsDeployment"),
    # Application -- agent tier
    "componentAgentConsentSurface": ("componentsApplication", "componentsAgent"),
    "componentAgentToolTransport": ("componentsApplication", "componentsAgent"),
    "componentAgentNetworkPolicyEnforcementPoint": ("componentsApplication", "componentsAgent"),
    # Application -- application tier
    "componentApplicationConsentSurface": ("componentsApplication", "componentsApplicationCore"),
    "componentApplicationNetworkPolicyEnforcementPoint": ("componentsApplication", "componentsApplicationCore"),
    # External tools -- connection-layer enforcement, wrapping the invocation path
    "componentToolNetworkPolicyEnforcementPoint": ("componentsExternalTools", "componentsToolNetworkControls"),
    # External tools -- the invocation path itself
    "componentToolServer": ("componentsExternalTools", "componentsToolInvocationPath"),
    "componentAuthorizationPolicyEnforcementPoint": ("componentsExternalTools", "componentsToolInvocationPath"),
    "componentToolInputHandling": ("componentsExternalTools", "componentsToolInvocationPath"),
    "componentToolOutputHandling": ("componentsExternalTools", "componentsToolInvocationPath"),
}

# Subcategories introduced alongside this layer. Their membership is fully
# determined by this layer plus componentTools (recategorized onto the tool
# invocation path), so an exact-set assertion is safe here in a way it would
# not be for the pre-existing subcategories.
_EXACT_MEMBERSHIP: dict[str, set[str]] = {
    "componentsIdentity": {
        "componentIdentityProvider",
        "componentAuthorizationPolicyDecisionPoint",
        "componentFederationProxy",
    },
    "componentsToolNetworkControls": {
        "componentToolNetworkPolicyEnforcementPoint",
    },
    "componentsToolInvocationPath": {
        "componentTools",
        "componentToolServer",
        "componentAuthorizationPolicyEnforcementPoint",
        "componentToolInputHandling",
        "componentToolOutputHandling",
    },
}

# Components that already existed in the corpus but were relocated alongside
# this layer. They are pinned for the same reason as the net-new ones -- the
# moves were argued decisions and nothing else asserts they stay put -- but they
# live in their own table so _NET_NEW_PLACEMENTS keeps its literal meaning.
_RELOCATED_PLACEMENTS: dict[str, tuple[str, str]] = {
    # Subcategory id rename only; the component did not change tier.
    "componentModelStorage": ("componentsInfrastructure", "componentsDeployment"),
    # Moved out of the deployment substrate into the Model tier: it is the sole
    # inference-time toucher of the model artifact, and so the single boundary
    # standing between the model and every external caller.
    "componentModelServing": ("componentsModel", "componentsModelCore"),
}

_PLACEMENT_CASES = sorted(
    (component_id, category, subcategory)
    for component_id, (category, subcategory) in {**_NET_NEW_PLACEMENTS, **_RELOCATED_PLACEMENTS}.items()
)


@pytest.fixture(scope="module")
def components_data() -> dict:
    """Parsed risk-map/yaml/components.yaml."""
    with open(_COMPONENTS_YAML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def components_by_id(components_data: dict) -> dict[str, dict]:
    """Map of component id -> component dict from the components: block."""
    return {comp["id"]: comp for comp in components_data.get("components", []) if isinstance(comp.get("id"), str)}


@pytest.fixture(scope="module")
def declared_nesting(components_data: dict) -> dict[str, set[str]]:
    """Map of category id -> declared subcategory ids, from the categories: block."""
    nesting: dict[str, set[str]] = {}
    for category in components_data.get("categories", []):
        category_id = category.get("id")
        if not isinstance(category_id, str):
            continue
        nesting[category_id] = {
            sub.get("id") for sub in category.get("subcategory", []) if isinstance(sub.get("id"), str)
        }
    return nesting


# ============================================================================
# Per-component placement
# ============================================================================


class TestAgenticLayerComponentPlacement:
    """Each net-new component sits in the category and subcategory it declares."""

    @pytest.mark.parametrize(
        ("component_id", "expected_category", "expected_subcategory"),
        _PLACEMENT_CASES,
        ids=[case[0] for case in _PLACEMENT_CASES],
    )
    def test_component_category(
        self,
        components_by_id: dict[str, dict],
        component_id: str,
        expected_category: str,
        expected_subcategory: str,
    ):
        """
        Given: a component introduced by the agentic layer
        When: its 'category' field is read from the live components.yaml
        Then: it matches the declared top-level category
        """
        if component_id not in components_by_id:
            pytest.fail(
                f"{component_id} is absent from components.yaml. It is part of the agentic "
                f"component layer and is expected in {expected_category} / {expected_subcategory}."
            )
        category = components_by_id[component_id].get("category")
        assert category == expected_category, (
            f"{component_id} must stay in category {expected_category!r}; got {category!r}. "
            f"Changing a component's tier changes its persona ownership and its position in "
            f"the generated graphs -- update this table only alongside a deliberate content change."
        )

    @pytest.mark.parametrize(
        ("component_id", "expected_category", "expected_subcategory"),
        _PLACEMENT_CASES,
        ids=[case[0] for case in _PLACEMENT_CASES],
    )
    def test_component_subcategory(
        self,
        components_by_id: dict[str, dict],
        component_id: str,
        expected_category: str,
        expected_subcategory: str,
    ):
        """
        Given: a component introduced by the agentic layer
        When: its 'subcategory' field is read from the live components.yaml
        Then: it matches the declared subcategory
        """
        if component_id not in components_by_id:
            pytest.fail(
                f"{component_id} is absent from components.yaml. It is part of the agentic "
                f"component layer and is expected in {expected_category} / {expected_subcategory}."
            )
        subcategory = components_by_id[component_id].get("subcategory")
        assert subcategory == expected_subcategory, (
            f"{component_id} must stay in subcategory {expected_subcategory!r}; got {subcategory!r}. "
            f"The subcategory axis in the external-tools tier is layer, not control-plane versus "
            f"data-plane: connection-layer enforcement wraps the invocation path, and the "
            f"invocation path carries the request itself."
        )


# ============================================================================
# Exact membership of the subcategories this layer populates from empty
# ============================================================================


class TestNewSubcategoryMembershipIsExact:
    """
    componentsIdentity, componentsToolNetworkControls and
    componentsToolInvocationPath are fully populated by this layer, so their
    membership can be asserted exactly. The per-component tests above catch a
    component moving out; these catch one silently moving in, which no
    per-component assertion can see.
    """

    @pytest.mark.parametrize("subcategory_id", sorted(_EXACT_MEMBERSHIP))
    def test_subcategory_membership_exact(self, components_by_id: dict[str, dict], subcategory_id: str):
        """
        Given: the live components: block
        When: every component declaring this subcategory is collected
        Then: the set matches the declared membership exactly
        """
        actual = {
            component_id
            for component_id, component in components_by_id.items()
            if component.get("subcategory") == subcategory_id
        }
        expected = _EXACT_MEMBERSHIP[subcategory_id]
        assert actual == expected, (
            f"Membership of {subcategory_id} drifted. "
            f"Unexpected: {sorted(actual - expected)}; missing: {sorted(expected - actual)}."
        )


# ============================================================================
# The pinned table agrees with the declared taxonomy
# ============================================================================


class TestPinnedPlacementsAreDeclaredPairs:
    """
    Guard on the table itself: every pinned (category, subcategory) pair must
    be one the categories: block actually declares. Without this a wrong
    correction to the table above could pin a pair that the taxonomy does not
    allow, and the per-component tests would happily enforce it.
    """

    def test_every_pinned_pair_is_declared(self, declared_nesting: dict[str, set[str]]):
        """
        Given: the pinned placements and the categories: block
        When: each pinned (category, subcategory) pair is looked up
        Then: the category exists and declares that subcategory
        """
        undeclared = [
            (component_id, category, subcategory)
            for component_id, (category, subcategory) in sorted(_NET_NEW_PLACEMENTS.items())
            if subcategory not in declared_nesting.get(category, set())
        ]
        assert not undeclared, (
            "Pinned placements reference (category, subcategory) pairs that the categories: "
            f"block does not declare: {undeclared}. Declared nesting: "
            f"{ {cat: sorted(subs) for cat, subs in sorted(declared_nesting.items())} }"
        )


# ============================================================================
# Test Summary
# ============================================================================
"""
Test Summary
============
Total Tests: 40

- TestAgenticLayerComponentPlacement (36, parametrized 18x2): every net-new
  component's category and subcategory pinned individually
- TestNewSubcategoryMembershipIsExact (3, parametrized): componentsIdentity,
  componentsToolNetworkControls and componentsToolInvocationPath have exactly
  the declared members -- catches an unannounced addition as well as a removal
- TestPinnedPlacementsAreDeclaredPairs (1): the pinned table only uses
  (category, subcategory) pairs the categories: block declares

Scope: the 18 components the agentic layer introduces. The inherited corpus is
not pinned here; its placement is settled by the changes that introduced it.
"""
