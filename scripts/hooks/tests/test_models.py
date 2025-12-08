#!/usr/bin/env python3
"""
Tests for Risk Map Data Models

This test suite validates the core data model classes used throughout the
CoSAI Risk Map validation system. The models provide data integrity through
validation and enable comparison operations.

Test Coverage:
==============
1. ComponentNode Class:
   - Title validation (type, empty/whitespace)
   - Category validation (type, empty/whitespace)
   - Edge validation (list type, string elements)
   - Subcategory handling (string vs None vs other types)
   - String representations (__repr__, __str__)
   - Equality comparison with same/different types

2. ControlNode Class:
   - Title validation (type, empty/whitespace)
   - Category validation (type, empty/whitespace)
   - Components validation (list type, string elements)
   - Risks validation (list type, string elements)
   - Personas validation (list type, string elements)
   - String representations (__repr__, __str__)
   - Equality comparison with same/different types

3. RiskNode Class:
   - Title validation (type, empty/whitespace)
   - Category validation (type, default empty string)
   - String representations with empty category handling
   - Equality comparison (not implemented, testing basic behavior)

Coverage Target: 95%+ for models.py (up from 65%)
"""

import sys
from pathlib import Path

import pytest

# Add scripts/hooks directory to path
git_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(git_root / "scripts" / "hooks"))

from riskmap_validator.models import ComponentNode, ControlNode, RiskNode  # noqa: E402


class TestComponentNode:
    """
    Test ComponentNode class validation and behavior.

    ComponentNode represents AI system components with bidirectional edges.
    Tests focus on validation, string representations, and equality comparison.
    """

    @pytest.fixture
    def valid_component_data(self):
        """Provide valid component initialization data."""
        return {
            "title": "Test Component",
            "category": "Data",
            "to_edges": ["comp1", "comp2"],
            "from_edges": ["comp3"],
            "subcategory": "Storage",
        }

    @pytest.fixture
    def component_without_subcategory(self):
        """Provide component data without subcategory."""
        return {
            "title": "Simple Component",
            "category": "Model",
            "to_edges": [],
            "from_edges": [],
        }

    # Title Validation Tests

    def test_component_creation_with_valid_data_succeeds(self, valid_component_data):
        """
        Test that ComponentNode can be created with valid data.

        Given: Valid component initialization parameters
        When: ComponentNode is instantiated
        Then: Object is created successfully with all attributes set
        """
        node = ComponentNode(**valid_component_data)

        assert node.title == "Test Component"
        assert node.category == "Data"
        assert node.to_edges == ["comp1", "comp2"]
        assert node.from_edges == ["comp3"]
        assert node.subcategory == "Storage"

    def test_component_title_not_string_raises_typeerror(self):
        """
        Test that non-string title raises TypeError.

        Given: Component data with integer title
        When: ComponentNode is instantiated
        Then: TypeError is raised with descriptive message
        """
        with pytest.raises(
            TypeError,
            match="The 'title' must be a string consisting of at least one printing character.",
        ):
            ComponentNode(
                title=123,  # Invalid: not a string
                category="Data",
                to_edges=[],
                from_edges=[],
            )

    def test_component_title_empty_string_raises_typeerror(self):
        """
        Test that empty string title raises TypeError.

        Given: Component data with empty string title
        When: ComponentNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(
            TypeError,
            match="The 'title' must be a string consisting of at least one printing character.",
        ):
            ComponentNode(
                title="",  # Invalid: empty string
                category="Data",
                to_edges=[],
                from_edges=[],
            )

    def test_component_title_whitespace_only_raises_typeerror(self):
        """
        Test that whitespace-only title raises TypeError.

        Given: Component data with whitespace-only title
        When: ComponentNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(
            TypeError,
            match="The 'title' must be a string consisting of at least one printing character.",
        ):
            ComponentNode(
                title="   \t\n",  # Invalid: whitespace only
                category="Data",
                to_edges=[],
                from_edges=[],
            )

    # Category Validation Tests

    def test_component_category_not_string_raises_typeerror(self):
        """
        Test that non-string category raises TypeError.

        Given: Component data with non-string category
        When: ComponentNode is instantiated
        Then: TypeError is raised with descriptive message
        """
        with pytest.raises(
            TypeError,
            match="The 'category' must be a string consisting of at least one printing character.",
        ):
            ComponentNode(
                title="Test",
                category=None,  # Invalid: not a string
                to_edges=[],
                from_edges=[],
            )

    def test_component_category_empty_string_raises_typeerror(self):
        """
        Test that empty string category raises TypeError.

        Given: Component data with empty string category
        When: ComponentNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(
            TypeError,
            match="The 'category' must be a string consisting of at least one printing character.",
        ):
            ComponentNode(
                title="Test",
                category="",  # Invalid: empty string
                to_edges=[],
                from_edges=[],
            )

    def test_component_category_whitespace_only_raises_typeerror(self):
        """
        Test that whitespace-only category raises TypeError.

        Given: Component data with whitespace-only category
        When: ComponentNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(
            TypeError,
            match="The 'category' must be a string consisting of at least one printing character.",
        ):
            ComponentNode(
                title="Test",
                category="  \n\t  ",  # Invalid: whitespace only
                to_edges=[],
                from_edges=[],
            )

    # Edge Validation Tests

    def test_component_to_edges_not_list_raises_typeerror(self):
        """
        Test that non-list to_edges raises TypeError.

        Given: Component data with non-list to_edges
        When: ComponentNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="The 'to_edges' must be a list of strings."):
            ComponentNode(
                title="Test",
                category="Data",
                to_edges="not-a-list",  # Invalid: not a list
                from_edges=[],
            )

    def test_component_to_edges_contains_non_string_raises_typeerror(self):
        """
        Test that to_edges with non-string elements raises TypeError.

        Given: Component data with to_edges containing non-string elements
        When: ComponentNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="The 'to_edges' must be a list of strings."):
            ComponentNode(
                title="Test",
                category="Data",
                to_edges=["valid", 123, "another"],  # Invalid: contains integer
                from_edges=[],
            )

    def test_component_from_edges_not_list_raises_typeerror(self):
        """
        Test that non-list from_edges raises TypeError.

        Given: Component data with non-list from_edges
        When: ComponentNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="The 'from_edges' must be a list of strings."):
            ComponentNode(
                title="Test",
                category="Data",
                to_edges=[],
                from_edges={"edge": "dict"},  # Invalid: not a list
            )

    def test_component_from_edges_contains_non_string_raises_typeerror(self):
        """
        Test that from_edges with non-string elements raises TypeError.

        Given: Component data with from_edges containing non-string elements
        When: ComponentNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="The 'from_edges' must be a list of strings."):
            ComponentNode(
                title="Test",
                category="Data",
                to_edges=[],
                from_edges=["valid", None, "another"],  # Invalid: contains None
            )

    # Subcategory Handling Tests

    def test_component_subcategory_string_sets_value(self, valid_component_data):
        """
        Test that string subcategory is set correctly.

        Given: Component data with string subcategory
        When: ComponentNode is instantiated
        Then: Subcategory attribute is set to the provided string
        """
        node = ComponentNode(**valid_component_data)
        assert node.subcategory == "Storage"

    def test_component_subcategory_none_sets_none(self, component_without_subcategory):
        """
        Test that None subcategory is set to None.

        Given: Component data without subcategory parameter
        When: ComponentNode is instantiated
        Then: Subcategory attribute is set to None
        """
        node = ComponentNode(**component_without_subcategory)
        assert node.subcategory is None

    def test_component_subcategory_explicit_none_sets_none(self):
        """
        Test that explicit None subcategory is set to None.

        Given: Component data with subcategory=None
        When: ComponentNode is instantiated
        Then: Subcategory attribute is set to None
        """
        node = ComponentNode(
            title="Test",
            category="Data",
            to_edges=[],
            from_edges=[],
            subcategory=None,
        )
        assert node.subcategory is None

    def test_component_subcategory_non_string_sets_none(self):
        """
        Test that non-string subcategory is set to None.

        Given: Component data with non-string subcategory
        When: ComponentNode is instantiated
        Then: Subcategory attribute is set to None (silently ignored)
        """
        node = ComponentNode(
            title="Test",
            category="Data",
            to_edges=[],
            from_edges=[],
            subcategory=123,  # Not a string, should be ignored
        )
        assert node.subcategory is None

    # String Representation Tests

    def test_component_repr_returns_debug_string(self, valid_component_data):
        """
        Test that __repr__ returns proper debug representation.

        Given: A ComponentNode instance
        When: repr() is called
        Then: Returns string with constructor-like format
        """
        node = ComponentNode(**valid_component_data)
        repr_str = repr(node)

        assert "ComponentNode(title='Test Component'" in repr_str
        assert "category='Data'" in repr_str
        assert "to_edges=['comp1', 'comp2']" in repr_str
        assert "from_edges=['comp3']" in repr_str

    def test_component_str_returns_user_friendly_string(self, valid_component_data):
        """
        Test that __str__ returns user-friendly representation.

        Given: A ComponentNode instance
        When: str() is called
        Then: Returns formatted multi-line string with component details
        """
        node = ComponentNode(**valid_component_data)
        str_output = str(node)

        assert "ComponentNode 'Test Component':" in str_output
        assert "Category: 'Data'" in str_output
        assert "-> Connects To: ['comp1', 'comp2']" in str_output
        assert "<- From: ['comp3']" in str_output

    # Equality Comparison Tests

    def test_component_equality_same_attributes_returns_true(self):
        """
        Test that components with identical attributes are equal.

        Given: Two ComponentNode instances with same attributes
        When: Equality comparison is performed
        Then: Returns True
        """
        node1 = ComponentNode(
            title="Test",
            category="Data",
            to_edges=["a", "b"],
            from_edges=["c"],
        )
        node2 = ComponentNode(
            title="Test",
            category="Data",
            to_edges=["a", "b"],
            from_edges=["c"],
        )

        assert node1 == node2

    def test_component_equality_different_title_returns_false(self):
        """
        Test that components with different titles are not equal.

        Given: Two ComponentNode instances with different titles
        When: Equality comparison is performed
        Then: Returns False
        """
        node1 = ComponentNode(title="Test1", category="Data", to_edges=[], from_edges=[])
        node2 = ComponentNode(title="Test2", category="Data", to_edges=[], from_edges=[])

        assert node1 != node2

    def test_component_equality_different_edges_returns_false(self):
        """
        Test that components with different edges are not equal.

        Given: Two ComponentNode instances with different edge lists
        When: Equality comparison is performed
        Then: Returns False
        """
        node1 = ComponentNode(title="Test", category="Data", to_edges=["a"], from_edges=[])
        node2 = ComponentNode(title="Test", category="Data", to_edges=["b"], from_edges=[])

        assert node1 != node2

    def test_component_equality_with_non_component_returns_notimplemented(self):
        """
        Test that equality with non-ComponentNode returns NotImplemented.

        Given: A ComponentNode instance and a non-ComponentNode object
        When: Equality comparison is performed
        Then: Returns NotImplemented (not False)
        """
        node = ComponentNode(title="Test", category="Data", to_edges=[], from_edges=[])
        other = "not a component"

        result = node.__eq__(other)
        assert result is NotImplemented

    def test_component_equality_with_dict_returns_false(self):
        """
        Test that equality comparison with dict returns False.

        Given: A ComponentNode instance and a dict
        When: Equality operator is used
        Then: Returns False (Python handles NotImplemented)
        """
        node = ComponentNode(title="Test", category="Data", to_edges=[], from_edges=[])
        other = {"title": "Test", "category": "Data"}

        assert node != other


class TestControlNode:
    """
    Test ControlNode class validation and behavior.

    ControlNode represents security controls that mitigate risks across
    AI system components. Tests focus on validation for all required fields.
    """

    @pytest.fixture
    def valid_control_data(self):
        """Provide valid control initialization data."""
        return {
            "title": "Test Control",
            "category": "controlsData",
            "components": ["comp1", "comp2"],
            "risks": ["risk1"],
            "personas": ["persona1", "persona2"],
        }

    # Title Validation Tests

    def test_control_creation_with_valid_data_succeeds(self, valid_control_data):
        """
        Test that ControlNode can be created with valid data.

        Given: Valid control initialization parameters
        When: ControlNode is instantiated
        Then: Object is created successfully with all attributes set
        """
        control = ControlNode(**valid_control_data)

        assert control.title == "Test Control"
        assert control.category == "controlsData"
        assert control.components == ["comp1", "comp2"]
        assert control.risks == ["risk1"]
        assert control.personas == ["persona1", "persona2"]

    def test_control_title_not_string_raises_typeerror(self):
        """
        Test that non-string title raises TypeError.

        Given: Control data with non-string title
        When: ControlNode is instantiated
        Then: TypeError is raised with descriptive message
        """
        with pytest.raises(TypeError, match="Control 'title' must be a non-empty string."):
            ControlNode(
                title=None,  # Invalid: not a string
                category="controlsData",
                components=[],
                risks=[],
                personas=[],
            )

    def test_control_title_empty_string_raises_typeerror(self):
        """
        Test that empty string title raises TypeError.

        Given: Control data with empty string title
        When: ControlNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Control 'title' must be a non-empty string."):
            ControlNode(
                title="",  # Invalid: empty string
                category="controlsData",
                components=[],
                risks=[],
                personas=[],
            )

    def test_control_title_whitespace_only_raises_typeerror(self):
        """
        Test that whitespace-only title raises TypeError.

        Given: Control data with whitespace-only title
        When: ControlNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Control 'title' must be a non-empty string."):
            ControlNode(
                title="   \n\t  ",  # Invalid: whitespace only
                category="controlsData",
                components=[],
                risks=[],
                personas=[],
            )

    # Category Validation Tests

    def test_control_category_not_string_raises_typeerror(self):
        """
        Test that non-string category raises TypeError.

        Given: Control data with non-string category
        When: ControlNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Control 'category' must be a non-empty string."):
            ControlNode(
                title="Test",
                category=123,  # Invalid: not a string
                components=[],
                risks=[],
                personas=[],
            )

    def test_control_category_empty_string_raises_typeerror(self):
        """
        Test that empty string category raises TypeError.

        Given: Control data with empty string category
        When: ControlNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Control 'category' must be a non-empty string."):
            ControlNode(
                title="Test",
                category="",  # Invalid: empty string
                components=[],
                risks=[],
                personas=[],
            )

    # Components Validation Tests

    def test_control_components_not_list_raises_typeerror(self):
        """
        Test that non-list components raises TypeError.

        Given: Control data with non-list components
        When: ControlNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Control 'components' must be a list of strings."):
            ControlNode(
                title="Test",
                category="controlsData",
                components="all",  # Invalid: not a list (even though "all" is special)
                risks=[],
                personas=[],
            )

    def test_control_components_contains_non_string_raises_typeerror(self):
        """
        Test that components with non-string elements raises TypeError.

        Given: Control data with components containing non-string elements
        When: ControlNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Control 'components' must be a list of strings."):
            ControlNode(
                title="Test",
                category="controlsData",
                components=["comp1", 123, "comp2"],  # Invalid: contains integer
                risks=[],
                personas=[],
            )

    def test_control_components_empty_list_succeeds(self):
        """
        Test that empty components list is valid.

        Given: Control data with empty components list
        When: ControlNode is instantiated
        Then: Object is created successfully
        """
        control = ControlNode(
            title="Test",
            category="controlsData",
            components=[],  # Valid: empty list
            risks=[],
            personas=[],
        )
        assert control.components == []

    # Risks Validation Tests

    def test_control_risks_not_list_raises_typeerror(self):
        """
        Test that non-list risks raises TypeError.

        Given: Control data with non-list risks
        When: ControlNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Control 'risks' must be a list of strings."):
            ControlNode(
                title="Test",
                category="controlsData",
                components=[],
                risks={"risk": "dict"},  # Invalid: not a list
                personas=[],
            )

    def test_control_risks_contains_non_string_raises_typeerror(self):
        """
        Test that risks with non-string elements raises TypeError.

        Given: Control data with risks containing non-string elements
        When: ControlNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Control 'risks' must be a list of strings."):
            ControlNode(
                title="Test",
                category="controlsData",
                components=[],
                risks=["risk1", None],  # Invalid: contains None
                personas=[],
            )

    # Personas Validation Tests

    def test_control_personas_not_list_raises_typeerror(self):
        """
        Test that non-list personas raises TypeError.

        Given: Control data with non-list personas
        When: ControlNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Control 'personas' must be a list of strings."):
            ControlNode(
                title="Test",
                category="controlsData",
                components=[],
                risks=[],
                personas="persona1",  # Invalid: not a list
            )

    def test_control_personas_contains_non_string_raises_typeerror(self):
        """
        Test that personas with non-string elements raises TypeError.

        Given: Control data with personas containing non-string elements
        When: ControlNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Control 'personas' must be a list of strings."):
            ControlNode(
                title="Test",
                category="controlsData",
                components=[],
                risks=[],
                personas=["persona1", False],  # Invalid: contains boolean
            )

    # String Representation Tests

    def test_control_repr_returns_debug_string(self, valid_control_data):
        """
        Test that __repr__ returns proper debug representation.

        Given: A ControlNode instance
        When: repr() is called
        Then: Returns string with constructor-like format
        """
        control = ControlNode(**valid_control_data)
        repr_str = repr(control)

        assert "ControlNode(title='Test Control'" in repr_str
        assert "category='controlsData'" in repr_str
        assert "components=['comp1', 'comp2']" in repr_str
        assert "risks=['risk1']" in repr_str
        assert "personas=['persona1', 'persona2']" in repr_str

    def test_control_str_returns_user_friendly_string(self, valid_control_data):
        """
        Test that __str__ returns user-friendly representation.

        Given: A ControlNode instance
        When: str() is called
        Then: Returns formatted multi-line string with control details
        """
        control = ControlNode(**valid_control_data)
        str_output = str(control)

        assert "Control 'Test Control':" in str_output
        assert "Category: controlsData" in str_output
        assert "Components: ['comp1', 'comp2']" in str_output
        assert "Risks: ['risk1']" in str_output
        assert "Personas: ['persona1', 'persona2']" in str_output

    # Equality Comparison Tests

    def test_control_equality_same_attributes_returns_true(self):
        """
        Test that controls with identical attributes are equal.

        Given: Two ControlNode instances with same attributes
        When: Equality comparison is performed
        Then: Returns True
        """
        control1 = ControlNode(
            title="Test",
            category="controlsData",
            components=["a"],
            risks=["r1"],
            personas=["p1"],
        )
        control2 = ControlNode(
            title="Test",
            category="controlsData",
            components=["a"],
            risks=["r1"],
            personas=["p1"],
        )

        assert control1 == control2

    def test_control_equality_different_components_returns_false(self):
        """
        Test that controls with different components are not equal.

        Given: Two ControlNode instances with different components
        When: Equality comparison is performed
        Then: Returns False
        """
        control1 = ControlNode(
            title="Test",
            category="controlsData",
            components=["a"],
            risks=[],
            personas=[],
        )
        control2 = ControlNode(
            title="Test",
            category="controlsData",
            components=["b"],
            risks=[],
            personas=[],
        )

        assert control1 != control2

    def test_control_equality_different_order_returns_false(self):
        """
        Test that controls with same items in different order are not equal.

        Given: Two ControlNode instances with same components in different order
        When: Equality comparison is performed
        Then: Returns False (order matters for list equality)
        """
        control1 = ControlNode(
            title="Test",
            category="controlsData",
            components=["a", "b"],
            risks=[],
            personas=[],
        )
        control2 = ControlNode(
            title="Test",
            category="controlsData",
            components=["b", "a"],
            risks=[],
            personas=[],
        )

        assert control1 != control2

    def test_control_equality_with_non_control_returns_notimplemented(self):
        """
        Test that equality with non-ControlNode returns NotImplemented.

        Given: A ControlNode instance and a non-ControlNode object
        When: Equality comparison is performed
        Then: Returns NotImplemented
        """
        control = ControlNode(
            title="Test",
            category="controlsData",
            components=[],
            risks=[],
            personas=[],
        )
        other = "not a control"

        result = control.__eq__(other)
        assert result is NotImplemented

    def test_control_equality_with_component_returns_false(self):
        """
        Test that equality comparison with ComponentNode returns False.

        Given: A ControlNode instance and a ComponentNode instance
        When: Equality operator is used
        Then: Returns False
        """
        control = ControlNode(
            title="Test",
            category="controlsData",
            components=[],
            risks=[],
            personas=[],
        )
        component = ComponentNode(title="Test", category="Data", to_edges=[], from_edges=[])

        assert control != component


class TestRiskNode:
    """
    Test RiskNode class validation and behavior.

    RiskNode represents security risks in the AI system. Tests focus on
    validation and string representation with default category handling.
    """

    @pytest.fixture
    def valid_risk_data(self):
        """Provide valid risk initialization data."""
        return {
            "title": "Test Risk",
            "category": "Privacy",
        }

    # Title Validation Tests

    def test_risk_creation_with_title_and_category_succeeds(self, valid_risk_data):
        """
        Test that RiskNode can be created with valid data.

        Given: Valid risk initialization parameters
        When: RiskNode is instantiated
        Then: Object is created successfully with attributes set
        """
        risk = RiskNode(**valid_risk_data)

        assert risk.title == "Test Risk"
        assert risk.category == "Privacy"

    def test_risk_creation_with_title_only_succeeds(self):
        """
        Test that RiskNode can be created with title only.

        Given: Only title parameter (category defaults to empty string)
        When: RiskNode is instantiated
        Then: Object is created with empty category
        """
        risk = RiskNode(title="Test Risk")

        assert risk.title == "Test Risk"
        assert risk.category == ""

    def test_risk_title_not_string_raises_typeerror(self):
        """
        Test that non-string title raises TypeError.

        Given: Risk data with non-string title
        When: RiskNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Risk 'title' must be a non-empty string."):
            RiskNode(title=123)  # Invalid: not a string

    def test_risk_title_empty_string_raises_typeerror(self):
        """
        Test that empty string title raises TypeError.

        Given: Risk data with empty string title
        When: RiskNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Risk 'title' must be a non-empty string."):
            RiskNode(title="")  # Invalid: empty string

    def test_risk_title_whitespace_only_raises_typeerror(self):
        """
        Test that whitespace-only title raises TypeError.

        Given: Risk data with whitespace-only title
        When: RiskNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Risk 'title' must be a non-empty string."):
            RiskNode(title="  \n\t  ")  # Invalid: whitespace only

    # Category Validation Tests

    def test_risk_category_not_string_raises_typeerror(self):
        """
        Test that non-string category raises TypeError.

        Given: Risk data with non-string category
        When: RiskNode is instantiated
        Then: TypeError is raised
        """
        with pytest.raises(TypeError, match="Risk 'category' must be a string."):
            RiskNode(
                title="Test Risk",
                category=None,  # Invalid: not a string
            )

    def test_risk_category_empty_string_succeeds(self):
        """
        Test that empty string category is valid.

        Given: Risk data with empty string category
        When: RiskNode is instantiated
        Then: Object is created successfully
        """
        risk = RiskNode(title="Test Risk", category="")
        assert risk.category == ""

    # String Representation Tests

    def test_risk_repr_returns_debug_string(self, valid_risk_data):
        """
        Test that __repr__ returns proper debug representation.

        Given: A RiskNode instance
        When: repr() is called
        Then: Returns string with constructor-like format
        """
        risk = RiskNode(**valid_risk_data)
        repr_str = repr(risk)

        assert repr_str == "RiskNode(title='Test Risk', category='Privacy')"

    def test_risk_str_with_category_returns_formatted_string(self, valid_risk_data):
        """
        Test that __str__ returns user-friendly string with category.

        Given: A RiskNode instance with category
        When: str() is called
        Then: Returns formatted string with category
        """
        risk = RiskNode(**valid_risk_data)
        str_output = str(risk)

        assert str_output == "Risk 'Test Risk' (Category: Privacy)"

    def test_risk_str_with_empty_category_shows_unknown(self):
        """
        Test that __str__ shows 'Unknown' for empty category.

        Given: A RiskNode instance with empty category
        When: str() is called
        Then: Returns formatted string with 'Unknown' as category
        """
        risk = RiskNode(title="Test Risk", category="")
        str_output = str(risk)

        assert str_output == "Risk 'Test Risk' (Category: Unknown)"

    def test_risk_str_with_default_category_shows_unknown(self):
        """
        Test that __str__ shows 'Unknown' for default empty category.

        Given: A RiskNode instance created without category parameter
        When: str() is called
        Then: Returns formatted string with 'Unknown' as category
        """
        risk = RiskNode(title="Test Risk")
        str_output = str(risk)

        assert str_output == "Risk 'Test Risk' (Category: Unknown)"
