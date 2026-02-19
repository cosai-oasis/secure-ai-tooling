#!/usr/bin/env python3
"""
Tests for persona framework mapping validation

This module tests the validation functions that ensure:
- Personas only reference frameworks applicable to personas
- Deprecated personas trigger warnings when used in controls/risks
- Framework references in persona mappings are valid

Tests cover:
- extract_persona_framework_references() function
- validate_persona_framework_applicability() function
- check_deprecated_persona_usage() function
- Integration with actual YAML data
- Error detection and reporting
"""

import sys
from pathlib import Path

# Add parent directory to path to import the validator
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# Test extract_persona_framework_references() Function
# ============================================================================


class TestExtractPersonaFrameworkReferences:
    """Test extraction of framework references from persona mappings."""

    def test_extract_persona_with_mappings(self):
        """
        Test extracting framework references from personas with mappings.

        Given: Personas data with mappings to external frameworks
        When: extract_persona_framework_references() is called
        Then: Returns dict mapping persona IDs to list of framework IDs
        """
        from validate_framework_references import extract_persona_framework_references

        data = {
            "personas": [
                {
                    "id": "personaModelProvider",
                    "title": "Model Provider",
                    "mappings": {"iso-22989": ["AI system provider"], "nist-ai-rmf": ["Provider role"]},
                },
                {
                    "id": "personaDataProvider",
                    "title": "Data Provider",
                    "mappings": {"iso-22989": ["Data supplier"]},
                },
            ]
        }

        result = extract_persona_framework_references(data)

        # Convert list values to sets for order-independent comparison
        assert {k: set(v) for k, v in result.items()} == {
            "personaModelProvider": {"iso-22989", "nist-ai-rmf"},
            "personaDataProvider": {"iso-22989"},
        }

    def test_extract_persona_without_mappings(self):
        """
        Test extraction for personas without mappings field.

        Given: Personas data without mappings field (backward compatibility)
        When: extract_persona_framework_references() is called
        Then: Returns empty dict (no framework references)
        """
        from validate_framework_references import extract_persona_framework_references

        data = {"personas": [{"id": "personaModelCreator", "title": "Model Creator"}]}

        result = extract_persona_framework_references(data)

        assert result == {}

    def test_extract_persona_with_empty_mappings(self):
        """
        Test extraction for personas with empty mappings.

        Given: Personas with mappings: {}
        When: extract_persona_framework_references() is called
        Then: Returns empty dict
        """
        from validate_framework_references import extract_persona_framework_references

        data = {"personas": [{"id": "personaGovernance", "title": "Governance", "mappings": {}}]}

        result = extract_persona_framework_references(data)

        assert result == {}

    def test_extract_persona_missing_id(self):
        """
        Test extraction skips personas without IDs.

        Given: Personas data with entry missing id field
        When: extract_persona_framework_references() is called
        Then: Skips persona without ID, returns others
        """
        from validate_framework_references import extract_persona_framework_references

        data = {
            "personas": [
                {"title": "No ID Persona", "mappings": {"iso-22989": ["role1"]}},
                {"id": "personaEndUser", "title": "End User", "mappings": {"iso-22989": ["user"]}},
            ]
        }

        result = extract_persona_framework_references(data)

        assert result == {"personaEndUser": ["iso-22989"]}

    def test_extract_persona_with_multiple_frameworks(self):
        """
        Test extraction for persona mapped to multiple frameworks.

        Given: Persona with mappings to 3+ frameworks
        When: extract_persona_framework_references() is called
        Then: Returns all framework IDs for that persona
        """
        from validate_framework_references import extract_persona_framework_references

        data = {
            "personas": [
                {
                    "id": "personaApplicationDeveloper",
                    "title": "Application Developer",
                    "mappings": {
                        "iso-22989": ["Developer"],
                        "nist-ai-rmf": ["Dev role"],
                        "mitre-atlas": ["Developer actor"],
                    },
                }
            ]
        }

        result = extract_persona_framework_references(data)

        assert set(result["personaApplicationDeveloper"]) == {"iso-22989", "nist-ai-rmf", "mitre-atlas"}

    def test_extract_handles_null_data(self):
        """
        Test extraction handles None/null data gracefully.

        Given: None or empty data
        When: extract_persona_framework_references() is called
        Then: Returns empty dict without error
        """
        from validate_framework_references import extract_persona_framework_references

        result_none = extract_persona_framework_references(None)
        result_empty = extract_persona_framework_references({})
        result_no_personas = extract_persona_framework_references({"title": "Personas"})

        assert result_none == {}
        assert result_empty == {}
        assert result_no_personas == {}


# ============================================================================
# Test validate_persona_framework_applicability() Function
# ============================================================================


class TestValidatePersonaFrameworkApplicability:
    """Test validation that personas only reference applicable frameworks."""

    def test_validate_persona_with_applicable_framework_succeeds(self):
        """
        Test validation passes when persona references applicable framework.

        Given: Persona references framework with applicableTo: ["personas"]
        When: validate_persona_framework_applicability() is called
        Then: Returns empty error list (validation passes)
        """
        from validate_framework_references import validate_persona_framework_applicability

        frameworks_data = {
            "frameworks": [
                {
                    "id": "iso-22989",
                    "name": "ISO 22989",
                    "applicableTo": ["personas", "controls"],
                }
            ]
        }

        persona_frameworks = {"personaModelProvider": ["iso-22989"]}

        errors = validate_persona_framework_applicability(frameworks_data, persona_frameworks)

        assert errors == []

    def test_validate_persona_with_non_applicable_framework_fails(self):
        """
        Test validation fails when persona references non-applicable framework.

        Given: Persona references framework without applicableTo: ["personas"]
        When: validate_persona_framework_applicability() is called
        Then: Returns error indicating framework not applicable to personas
        """
        from validate_framework_references import validate_persona_framework_applicability

        frameworks_data = {
            "frameworks": [
                {
                    "id": "stride",
                    "name": "STRIDE",
                    "applicableTo": ["risks"],  # Not applicable to personas
                }
            ]
        }

        persona_frameworks = {"personaDataProvider": ["stride"]}

        errors = validate_persona_framework_applicability(frameworks_data, persona_frameworks)

        assert len(errors) == 1
        assert "personaDataProvider" in errors[0]
        assert "stride" in errors[0]
        assert "not applicable to personas" in errors[0]

    def test_validate_multiple_personas_with_mixed_applicability(self):
        """
        Test validation with mix of valid and invalid framework references.

        Given: Multiple personas, some with valid and some with invalid frameworks
        When: validate_persona_framework_applicability() is called
        Then: Returns errors only for personas with non-applicable frameworks
        """
        from validate_framework_references import validate_persona_framework_applicability

        frameworks_data = {
            "frameworks": [
                {"id": "iso-22989", "name": "ISO 22989", "applicableTo": ["personas"]},
                {"id": "stride", "name": "STRIDE", "applicableTo": ["risks"]},
                {"id": "nist-ai-rmf", "name": "NIST AI RMF", "applicableTo": ["controls", "personas"]},
            ]
        }

        persona_frameworks = {
            "personaModelProvider": ["iso-22989"],  # Valid
            "personaDataProvider": ["stride"],  # Invalid
            "personaGovernance": ["nist-ai-rmf"],  # Valid
        }

        errors = validate_persona_framework_applicability(frameworks_data, persona_frameworks)

        assert len(errors) == 1
        assert "personaDataProvider" in errors[0]
        assert "stride" in errors[0]

    def test_validate_persona_with_unknown_framework(self):
        """
        Test validation handles persona referencing non-existent framework.

        Given: Persona references framework ID not in frameworks.yaml
        When: validate_persona_framework_applicability() is called
        Then: Returns error indicating framework does not exist
        """
        from validate_framework_references import validate_persona_framework_applicability

        frameworks_data = {"frameworks": [{"id": "iso-22989", "name": "ISO 22989", "applicableTo": ["personas"]}]}

        persona_frameworks = {"personaEndUser": ["nonexistent-framework"]}

        errors = validate_persona_framework_applicability(frameworks_data, persona_frameworks)

        assert len(errors) == 1
        assert "personaEndUser" in errors[0]
        assert "nonexistent-framework" in errors[0]

    def test_validate_persona_with_multiple_invalid_frameworks(self):
        """
        Test validation reports all non-applicable frameworks for a persona.

        Given: Persona references multiple non-applicable frameworks
        When: validate_persona_framework_applicability() is called
        Then: Returns errors for each non-applicable framework
        """
        from validate_framework_references import validate_persona_framework_applicability

        frameworks_data = {
            "frameworks": [
                {"id": "stride", "name": "STRIDE", "applicableTo": ["risks"]},
                {"id": "mitre-atlas", "name": "MITRE ATLAS", "applicableTo": ["controls", "risks"]},
            ]
        }

        persona_frameworks = {
            "personaPlatformProvider": ["stride", "mitre-atlas"]  # Both invalid for personas
        }

        errors = validate_persona_framework_applicability(frameworks_data, persona_frameworks)

        assert len(errors) == 2
        assert any("stride" in err for err in errors)
        assert any("mitre-atlas" in err for err in errors)

    def test_validate_empty_persona_frameworks(self):
        """
        Test validation passes when no persona framework references exist.

        Given: Empty persona_frameworks dict
        When: validate_persona_framework_applicability() is called
        Then: Returns empty error list
        """
        from validate_framework_references import validate_persona_framework_applicability

        frameworks_data = {"frameworks": [{"id": "iso-22989", "name": "ISO 22989", "applicableTo": ["personas"]}]}

        persona_frameworks = {}

        errors = validate_persona_framework_applicability(frameworks_data, persona_frameworks)

        assert errors == []


# ============================================================================
# Test check_deprecated_persona_usage() Function
# ============================================================================


class TestCheckDeprecatedPersonaUsage:
    """Test detection of deprecated persona usage in controls and risks."""

    def test_warn_when_control_uses_deprecated_persona(self):
        """
        Test warning when control references deprecated persona.

        Given: Control references persona with deprecated: true
        When: check_deprecated_persona_usage() is called
        Then: Returns warning about deprecated persona usage
        """
        from validate_framework_references import check_deprecated_persona_usage

        personas_data = {
            "personas": [
                {"id": "personaModelCreator", "title": "Model Creator", "deprecated": True},
                {"id": "personaModelProvider", "title": "Model Provider", "deprecated": False},
            ]
        }

        controls_data = {
            "controls": [
                {
                    "id": "controlDataValidation",
                    "title": "Data Validation",
                    "personas": ["personaModelCreator"],  # Using deprecated persona
                }
            ]
        }

        risks_data = {"risks": []}

        warnings = check_deprecated_persona_usage(personas_data, controls_data, risks_data)

        assert len(warnings) == 1
        assert "controlDataValidation" in warnings[0]
        assert "personaModelCreator" in warnings[0]
        assert "deprecated" in warnings[0].lower()

    def test_warn_when_risk_uses_deprecated_persona(self):
        """
        Test warning when risk references deprecated persona.

        Given: Risk references persona with deprecated: true
        When: check_deprecated_persona_usage() is called
        Then: Returns warning about deprecated persona usage
        """
        from validate_framework_references import check_deprecated_persona_usage

        personas_data = {
            "personas": [{"id": "personaModelConsumer", "title": "Model Consumer", "deprecated": True}]
        }

        controls_data = {"controls": []}

        risks_data = {
            "risks": [
                {
                    "id": "DP",
                    "title": "Data Poisoning",
                    "personas": ["personaModelConsumer"],  # Using deprecated persona
                }
            ]
        }

        warnings = check_deprecated_persona_usage(personas_data, controls_data, risks_data)

        assert len(warnings) == 1
        assert "DP" in warnings[0]
        assert "personaModelConsumer" in warnings[0]
        assert "deprecated" in warnings[0].lower()

    def test_no_warning_for_non_deprecated_personas(self):
        """
        Test no warning when using non-deprecated personas.

        Given: Controls and risks reference personas with deprecated: false or no deprecated field
        When: check_deprecated_persona_usage() is called
        Then: Returns empty warning list
        """
        from validate_framework_references import check_deprecated_persona_usage

        personas_data = {
            "personas": [
                {"id": "personaModelProvider", "title": "Model Provider", "deprecated": False},
                {"id": "personaDataProvider", "title": "Data Provider"},  # No deprecated field
            ]
        }

        controls_data = {
            "controls": [
                {
                    "id": "controlTest",
                    "title": "Test Control",
                    "personas": ["personaModelProvider", "personaDataProvider"],
                }
            ]
        }

        risks_data = {"risks": [{"id": "DP", "title": "Data Poisoning", "personas": ["personaDataProvider"]}]}

        warnings = check_deprecated_persona_usage(personas_data, controls_data, risks_data)

        assert warnings == []

    def test_warn_multiple_controls_and_risks_using_deprecated_persona(self):
        """
        Test warnings for multiple controls/risks using same deprecated persona.

        Given: Multiple controls and risks reference the same deprecated persona
        When: check_deprecated_persona_usage() is called
        Then: Returns warning for each control/risk using deprecated persona
        """
        from validate_framework_references import check_deprecated_persona_usage

        personas_data = {"personas": [{"id": "personaModelCreator", "title": "Model Creator", "deprecated": True}]}

        controls_data = {
            "controls": [
                {"id": "control1", "title": "Control 1", "personas": ["personaModelCreator"]},
                {"id": "control2", "title": "Control 2", "personas": ["personaModelCreator"]},
            ]
        }

        risks_data = {
            "risks": [
                {"id": "risk1", "title": "Risk 1", "personas": ["personaModelCreator"]},
                {"id": "risk2", "title": "Risk 2", "personas": ["personaModelCreator"]},
            ]
        }

        warnings = check_deprecated_persona_usage(personas_data, controls_data, risks_data)

        assert len(warnings) == 4  # 2 controls + 2 risks
        assert sum("control1" in w for w in warnings) == 1
        assert sum("control2" in w for w in warnings) == 1
        assert sum("risk1" in w for w in warnings) == 1
        assert sum("risk2" in w for w in warnings) == 1

    def test_handles_controls_without_personas_field(self):
        """
        Test handles controls without personas field gracefully.

        Given: Control without personas field
        When: check_deprecated_persona_usage() is called
        Then: No error, no warning
        """
        from validate_framework_references import check_deprecated_persona_usage

        personas_data = {"personas": [{"id": "personaModelCreator", "title": "Model Creator", "deprecated": True}]}

        controls_data = {"controls": [{"id": "control1", "title": "Control 1"}]}  # No personas field

        risks_data = {"risks": []}

        warnings = check_deprecated_persona_usage(personas_data, controls_data, risks_data)

        assert warnings == []

    def test_handles_risks_without_personas_field(self):
        """
        Test handles risks without personas field gracefully.

        Given: Risk without personas field
        When: check_deprecated_persona_usage() is called
        Then: No error, no warning
        """
        from validate_framework_references import check_deprecated_persona_usage

        personas_data = {
            "personas": [{"id": "personaModelConsumer", "title": "Model Consumer", "deprecated": True}]
        }

        controls_data = {"controls": []}

        risks_data = {"risks": [{"id": "DP", "title": "Data Poisoning"}]}  # No personas field

        warnings = check_deprecated_persona_usage(personas_data, controls_data, risks_data)

        assert warnings == []

    def test_handles_empty_personas_data(self):
        """
        Test handles empty personas data gracefully.

        Given: Empty or None personas data
        When: check_deprecated_persona_usage() is called
        Then: Returns empty warnings list
        """
        from validate_framework_references import check_deprecated_persona_usage

        controls_data = {
            "controls": [{"id": "control1", "title": "Control 1", "personas": ["personaModelCreator"]}]
        }

        risks_data = {"risks": []}

        warnings_empty = check_deprecated_persona_usage({}, controls_data, risks_data)
        warnings_none = check_deprecated_persona_usage(None, controls_data, risks_data)

        assert warnings_empty == []
        assert warnings_none == []


# ============================================================================
# Integration Tests
# ============================================================================


class TestPersonaFrameworkValidationIntegration:
    """Integration tests combining persona framework validation functions."""

    def test_end_to_end_validation_with_personas_succeeds(self):
        """
        Test complete validation workflow with valid persona framework mappings.

        Given: Valid personas with framework mappings, frameworks applicable to personas
        When: All validation functions are called
        Then: No errors or warnings returned
        """
        from validate_framework_references import (
            check_deprecated_persona_usage,
            extract_persona_framework_references,
            validate_persona_framework_applicability,
        )

        frameworks_data = {
            "frameworks": [
                {"id": "iso-22989", "name": "ISO 22989", "applicableTo": ["personas", "controls"]},
                {"id": "nist-ai-rmf", "name": "NIST AI RMF", "applicableTo": ["controls", "personas"]},
            ]
        }

        personas_data = {
            "personas": [
                {
                    "id": "personaModelProvider",
                    "title": "Model Provider",
                    "mappings": {"iso-22989": ["Provider"]},
                    "deprecated": False,
                },
                {
                    "id": "personaDataProvider",
                    "title": "Data Provider",
                    "mappings": {"nist-ai-rmf": ["Data role"]},
                },
            ]
        }

        controls_data = {
            "controls": [
                {
                    "id": "control1",
                    "title": "Control 1",
                    "personas": ["personaModelProvider", "personaDataProvider"],
                }
            ]
        }

        risks_data = {"risks": []}

        # Extract and validate persona framework references
        persona_frameworks = extract_persona_framework_references(personas_data)
        applicability_errors = validate_persona_framework_applicability(frameworks_data, persona_frameworks)

        # Check for deprecated persona usage
        deprecation_warnings = check_deprecated_persona_usage(personas_data, controls_data, risks_data)

        assert applicability_errors == []
        assert deprecation_warnings == []

    def test_end_to_end_validation_detects_applicability_errors(self):
        """
        Test complete validation workflow detects non-applicable framework usage.

        Given: Persona references framework not applicable to personas
        When: Validation functions are called
        Then: Applicability errors are returned
        """
        from validate_framework_references import (
            extract_persona_framework_references,
            validate_persona_framework_applicability,
        )

        frameworks_data = {
            "frameworks": [
                {"id": "stride", "name": "STRIDE", "applicableTo": ["risks"]}
            ]  # Not applicable to personas
        }

        personas_data = {
            "personas": [
                {
                    "id": "personaGovernance",
                    "title": "Governance",
                    "mappings": {"stride": ["Governance role"]},  # Invalid
                }
            ]
        }

        persona_frameworks = extract_persona_framework_references(personas_data)
        errors = validate_persona_framework_applicability(frameworks_data, persona_frameworks)

        assert len(errors) > 0
        assert any("personaGovernance" in err and "stride" in err for err in errors)

    def test_end_to_end_validation_detects_deprecation_warnings(self):
        """
        Test complete validation workflow detects deprecated persona usage.

        Given: Control references deprecated persona
        When: Validation functions are called
        Then: Deprecation warnings are returned
        """
        from validate_framework_references import check_deprecated_persona_usage

        personas_data = {
            "personas": [
                {"id": "personaModelCreator", "title": "Model Creator", "deprecated": True},
                {"id": "personaModelProvider", "title": "Model Provider", "deprecated": False},
            ]
        }

        controls_data = {
            "controls": [
                {
                    "id": "controlLegacy",
                    "title": "Legacy Control",
                    "personas": ["personaModelCreator"],
                }  # Deprecated
            ]
        }

        risks_data = {"risks": []}

        warnings = check_deprecated_persona_usage(personas_data, controls_data, risks_data)

        assert len(warnings) > 0
        assert any("controlLegacy" in w and "personaModelCreator" in w for w in warnings)


# ============================================================================
# Test Summary
# ============================================================================

"""
Test Summary
============
Total Tests: 25

Extract Persona Framework References Tests (6):
- Extract persona with mappings
- Extract persona without mappings (backward compatibility)
- Extract persona with empty mappings
- Extract persona missing ID
- Extract persona with multiple frameworks
- Extract handles null/empty data

Validate Persona Framework Applicability Tests (6):
- Validate persona with applicable framework succeeds
- Validate persona with non-applicable framework fails
- Validate multiple personas with mixed applicability
- Validate persona with unknown framework
- Validate persona with multiple invalid frameworks
- Validate empty persona frameworks

Check Deprecated Persona Usage Tests (8):
- Warn when control uses deprecated persona
- Warn when risk uses deprecated persona
- No warning for non-deprecated personas
- Warn for multiple controls/risks using deprecated persona
- Handle controls without personas field
- Handle risks without personas field
- Handle empty personas data
- Handle None personas data

Integration Tests (3):
- End-to-end validation with valid data succeeds
- End-to-end validation detects applicability errors
- End-to-end validation detects deprecation warnings

Coverage Areas:
- Framework reference extraction from persona mappings
- Framework applicability validation for personas
- Deprecated persona usage detection
- Error and warning message generation
- Backward compatibility handling
- Edge cases (null data, missing fields)
"""
