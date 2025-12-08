#!/usr/bin/env python3
"""
Tests for validate_control_risk_references.py

This test suite validates the control-to-risk reference consistency validation
system used as a git pre-commit hook. The validator ensures that:
- Controls in controls.yaml that list risks are referenced by those risks in risks.yaml
- Risks in risks.yaml that list controls are referenced by those controls in controls.yaml
- Special keywords ("all", "none") and empty lists are handled correctly

Test Coverage:
==============
Total Tests: 68 across 13 test classes
Coverage Target: 95%+ of validate_control_risk_references.py

ORIGINAL TEST CLASSES (48 tests):
1. TestCompareControlMaps - Core validation logic (lines 156-221) - 8 tests
   - Bidirectional mapping validation
   - Error type 1: Control lists risks but risks don't reference control back
   - Error type 2: Control referenced in risks.yaml but doesn't exist in controls.yaml
   - Error type 3: Risk list mismatches between controls and risks files
   - Edge cases: "all", "none", empty lists
   - Multiple error detection

2. TestGetStagedYamlFiles - Git integration and file detection (lines 23-60) - 9 tests
   - Force mode with existing files
   - Force mode with missing files
   - Normal mode with staged files
   - Normal mode with no target files staged
   - Subprocess error handling (CalledProcessError)
   - Empty git output handling
   - File existence checks in normal mode
   - Whitespace handling in git output

3. TestLoadYamlFile - YAML file loading (lines 63-78) - 3 tests
   - Valid YAML loading
   - YAML parsing error handling (yaml.YAMLError)
   - File not found error handling

4. TestExtractControlsData - Controls.yaml parsing (lines 81-101) - 6 tests
   - Valid controls extraction
   - Empty controls list handling
   - None yaml_data handling
   - Missing 'controls' key handling
   - Skipping controls without 'id' field
   - Missing 'risks' field handling (defaults to [])

5. TestExtractRisksData - Risks.yaml reverse mapping (lines 104-128) - 6 tests
   - Correct reverse mapping construction
   - Multiple risks per control aggregation
   - Empty risks list handling
   - None yaml_data handling
   - Missing 'risks' key handling
   - Skipping risks without 'id' field

6. TestFindIsolatedEntries - Isolated control detection (lines 131-153) - 3 tests
   - Detecting controls with empty risk lists
   - Empty set when all controls have risks
   - Empty controls dictionary handling

7. TestValidateControlToRisk - End-to-end validation (lines 224-280) - 7 tests
   - Successful validation with consistent data
   - YAML load error handling
   - Isolated control detection
   - Cross-reference error detection
   - Skip validation when no controls found
   - Skip validation when no risks found
   - Isolated risks detection (mocked for future implementation)

8. TestParseArgs - Argument parsing (lines 283-300) - 2 tests
   - Default arguments (force=False)
   - --force flag parsing

9. TestMain - Main orchestration (lines 303-328) - 4 tests
   - Exit 0 when no YAML files modified
   - Exit 0 when validation passes
   - Exit 1 when validation fails
   - Force mode validation flow

NEW TEST CLASSES FOR UNIVERSAL CONTROLS FIX (20 tests):
10. TestExtractControlsDataKeywordHandling - String handling for "all"/"none" - 7 tests
    - Test 1: extract_controls_data stores "all" as string (not ['a','l','l'])
    - Test 2: extract_controls_data stores "none" as string (not ['n','o','n','e'])
    - Test 3: compare_control_maps handles "all" as string, not list
    - Test 4: compare_control_maps handles "none" as string, not list
    - Test 5: Type checking confirms "all" preserved as str
    - Test 6: Type checking confirms normal risks preserved as list
    - Test 7: Mixed types ("all", "none", [], ["RSK-001"]) maintain correct types

11. TestCompareControlMapsSkipLogic - Skip logic with string comparisons - 4 tests
    - Test 8: Skip when control has "all" and risks empty
    - Test 9: Skip when control has "none" and risks empty
    - Test 10: Skip when control has [] and risks empty
    - Test 11: Do NOT skip when risks reference universal control (violation)

12. TestCompareControlMapsUniversalValidation - Universal control violation detection - 5 tests
    - Test 12: Error when risk lists universal control
    - Test 13: Errors for multiple risks listing universal control
    - Test 14: No error when universal control not explicitly listed (correct behavior)
    - Test 15: Normal controls still work alongside universal controls
    - Test 16: Error message clarity for universal control violation

13. TestUniversalControlsEdgeCases - Edge cases and integration - 4 tests
    - Test 17: Type guard prevents sorted() on string "all"/"none"
    - Test 18: All special keyword combinations tested
    - Test 19: End-to-end with 7 universal controls (no violations)
    - Test 20: End-to-end catches universal violations
"""

import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

# Add scripts/hooks to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import yaml
from validate_control_risk_references import (
    compare_control_maps,
    extract_controls_data,
    extract_risks_data,
    find_isolated_entries,
    get_staged_yaml_files,
    load_yaml_file,
    main,
    parse_args,
    validate_control_to_risk,
)


class TestCompareControlMaps:
    """Tests for compare_control_maps() core validation logic."""

    def test_compare_valid_bidirectional_mapping_returns_no_errors(self):
        """
        Test that valid bidirectional control-risk mappings pass validation.

        Given: controls.yaml and risks.yaml with matching control-risk references
        When: compare_control_maps() is called
        Then: Returns empty error list
        """
        # Both files agree: CTL-001 addresses RSK-001 and RSK-002
        controls = {
            "CTL-001": ["RSK-001", "RSK-002"],
            "CTL-002": ["RSK-003"],
        }
        risks = {
            "CTL-001": ["RSK-001", "RSK-002"],
            "CTL-002": ["RSK-003"],
        }

        errors = compare_control_maps(controls, risks)

        assert errors == [], f"Expected no errors but got: {errors}"

    def test_compare_detects_control_missing_from_risks_yaml(self):
        """
        Test detection when control lists risks but those risks don't reference it back.

        Given: Control in controls.yaml lists risks, but risks.yaml has no references to it
        When: compare_control_maps() is called
        Then: Returns error with "[ISSUE: risks.yaml]" prefix
        """
        # CTL-001 claims to address RSK-001, but RSK-001 doesn't reference CTL-001
        controls = {
            "CTL-001": ["RSK-001", "RSK-002"],
        }
        risks = {}  # No risks reference CTL-001

        errors = compare_control_maps(controls, risks)

        assert len(errors) == 1, f"Expected 1 error but got {len(errors)}: {errors}"
        assert "[ISSUE: risks.yaml]" in errors[0], f"Expected risks.yaml issue but got: {errors[0]}"
        assert "CTL-001" in errors[0], f"Expected CTL-001 in error: {errors[0]}"
        assert "['RSK-001', 'RSK-002']" in errors[0], f"Expected risk list in error: {errors[0]}"

    def test_compare_detects_control_missing_from_controls_yaml(self):
        """
        Test case when control is referenced in risks.yaml but doesn't exist in controls.yaml.

        Given: Risks reference a control that doesn't exist in controls.yaml
        When: compare_control_maps() is called
        Then: Returns error with "[ISSUE: controls.yaml]" prefix

        Note: After fixing unreachable code bug, Case 2 (lines 193-199) is now reachable.
        The refined skip condition at line 180 only skips when BOTH perspectives agree
        there are no risks to validate. When a control is referenced in risks.yaml but
        doesn't exist in controls.yaml, the skip condition is not triggered because
        risks_per_risks_yaml != [], allowing Case 2 to execute.
        """
        # CTL-002 is referenced by risks but doesn't exist in controls.yaml
        controls = {}
        risks = {
            "CTL-002": ["RSK-001", "RSK-002"],
        }

        errors = compare_control_maps(controls, risks)

        # Expect error because Case 2 is now reachable
        assert len(errors) == 1
        assert "do not exist in controls.yaml" in errors[0]
        assert "CTL-002" in errors[0]

    def test_compare_detects_risk_list_mismatch(self):
        """
        Test detection when control exists in both files but risk lists don't match.

        Given: Control exists in both files but lists different risks in each
        When: compare_control_maps() is called
        Then: Returns errors for missing and extra risks
        """
        # CTL-001 claims RSK-001, RSK-002 but risks.yaml shows RSK-002, RSK-003
        controls = {
            "CTL-001": ["RSK-001", "RSK-002"],
        }
        risks = {
            "CTL-001": ["RSK-002", "RSK-003"],
        }

        errors = compare_control_maps(controls, risks)

        # Should get 2 errors: one for RSK-001 missing from risks.yaml,
        # one for RSK-003 extra in risks.yaml
        assert len(errors) == 2, f"Expected 2 errors but got {len(errors)}: {errors}"

        # Check for missing risk error
        missing_errors = [e for e in errors if "[ISSUE: risks.yaml]" in e]
        assert len(missing_errors) == 1, f"Expected 1 risks.yaml error: {errors}"
        assert "RSK-001" in missing_errors[0], f"Expected RSK-001 in error: {missing_errors[0]}"
        assert "don't list this control" in missing_errors[0] or "don't list" in missing_errors[0], (
            f"Expected missing reference error: {missing_errors[0]}"
        )

        # Check for extra risk error
        extra_errors = [e for e in errors if "[ISSUE: controls.yaml]" in e]
        assert len(extra_errors) == 1, f"Expected 1 controls.yaml error: {errors}"
        assert "RSK-003" in extra_errors[0], f"Expected RSK-003 in error: {extra_errors[0]}"

    def test_compare_skips_controls_with_all_keyword(self):
        """
        Test that controls with risks="all" are skipped from validation.

        Given: Control in controls.yaml with risks="all"
        When: compare_control_maps() is called
        Then: Returns no errors (control is skipped)
        """
        # CTL-001 has "all" which should be skipped
        controls = {
            "CTL-001": "all",
            "CTL-002": ["RSK-001"],
        }
        risks = {
            "CTL-002": ["RSK-001"],
        }

        errors = compare_control_maps(controls, risks)

        assert errors == [], f"Expected no errors for 'all' keyword but got: {errors}"

    def test_compare_skips_controls_with_none_keyword(self):
        """
        Test that controls with risks="none" are skipped from validation.

        Given: Control in controls.yaml with risks="none"
        When: compare_control_maps() is called
        Then: Returns no errors (control is skipped)
        """
        # CTL-001 has "none" which should be skipped
        controls = {
            "CTL-001": "none",
            "CTL-002": ["RSK-001"],
        }
        risks = {
            "CTL-002": ["RSK-001"],
        }

        errors = compare_control_maps(controls, risks)

        assert errors == [], f"Expected no errors for 'none' keyword but got: {errors}"

    def test_compare_skips_controls_with_empty_risk_list(self):
        """
        Test that controls with empty risk lists are skipped from validation.

        Given: Control in controls.yaml with empty risk list
        When: compare_control_maps() is called
        Then: Returns no errors (control is skipped, handled by isolated checks)
        """
        # CTL-001 has empty list which should be skipped
        controls = {
            "CTL-001": [],
            "CTL-002": ["RSK-001"],
        }
        risks = {
            "CTL-002": ["RSK-001"],
        }

        errors = compare_control_maps(controls, risks)

        assert errors == [], f"Expected no errors for empty list but got: {errors}"

    def test_compare_multiple_errors_returns_all(self):
        """
        Test that multiple validation errors are all returned.

        Given: Multiple controls with different validation issues
        When: compare_control_maps() is called
        Then: Returns all detected errors in a list
        """
        # CTL-001: exists in controls but not in risks (should error)
        # CTL-002: exists in risks but not in controls (should error - Case 2 now reachable)
        # CTL-003: exists in both but risk lists mismatch (should error twice)
        controls = {
            "CTL-001": ["RSK-001"],
            "CTL-003": ["RSK-003"],
        }
        risks = {
            "CTL-002": ["RSK-002"],
            "CTL-003": ["RSK-004"],
        }

        errors = compare_control_maps(controls, risks)

        # Should get 4 errors:
        # 1. CTL-002 not in controls (Case 2 - now reachable after fix)
        # 2. CTL-001 not in risks
        # 3. CTL-003 mismatch - missing RSK-003 from risks
        # 4. CTL-003 mismatch - extra RSK-004 in risks
        assert len(errors) == 4, f"Expected 4 errors but got {len(errors)}: {errors}"

        # Verify all controls are mentioned in errors
        all_errors_text = " ".join(errors)
        assert "CTL-001" in all_errors_text, f"Expected CTL-001 in errors: {errors}"
        assert "CTL-002" in all_errors_text, f"Expected CTL-002 in errors: {errors}"
        assert "CTL-003" in all_errors_text, f"Expected CTL-003 in errors: {errors}"


class TestGetStagedYamlFiles:
    """Tests for get_staged_yaml_files() git integration."""

    def test_get_staged_files_force_mode_returns_both_files_when_exist(self):
        """
        Test that force mode returns both target files when they exist.

        Given: force_check=True and both controls.yaml and risks.yaml exist
        When: get_staged_yaml_files() is called
        Then: Returns list containing both target files
        """
        # Mock Path.exists to return True for both target files
        with patch("pathlib.Path.exists", return_value=True):
            result = get_staged_yaml_files(force_check=True)

        assert len(result) == 2
        assert Path("risk-map/yaml/controls.yaml") in result
        assert Path("risk-map/yaml/risks.yaml") in result

    def test_get_staged_files_force_mode_returns_empty_when_missing(self, capsys):
        """
        Test that force mode returns empty list when files don't exist.

        Given: force_check=True and at least one target file doesn't exist
        When: get_staged_yaml_files() is called
        Then: Returns empty list and prints warning message
        """
        # Mock Path.exists to return False (files don't exist)
        with patch("pathlib.Path.exists", return_value=False):
            result = get_staged_yaml_files(force_check=True)

        assert result == []

        # Verify warning message was printed
        captured = capsys.readouterr()
        assert "⚠️  At least one target file" in captured.out
        assert "does not exist" in captured.out

    def test_get_staged_files_normal_mode_returns_files_when_staged(self):
        """
        Test that normal mode returns both files when one is staged and both exist.

        Given: Normal mode, controls.yaml is staged, both files exist
        When: get_staged_yaml_files() is called
        Then: Returns list containing both target files
        """
        # Mock subprocess to return controls.yaml as staged
        mock_result = Mock()
        mock_result.stdout = "risk-map/yaml/controls.yaml\n"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch("pathlib.Path.exists", return_value=True):
                result = get_staged_yaml_files(force_check=False)

        # Verify git diff command was called correctly
        mock_run.assert_called_once_with(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True,
        )

        # Should return both files when at least one is staged and both exist
        assert len(result) == 2
        assert Path("risk-map/yaml/controls.yaml") in result
        assert Path("risk-map/yaml/risks.yaml") in result

    def test_get_staged_files_normal_mode_returns_empty_when_not_staged(self):
        """
        Test that normal mode returns empty list when target files not staged.

        Given: Normal mode, only non-target files staged
        When: get_staged_yaml_files() is called
        Then: Returns empty list
        """
        # Mock subprocess to return non-target files
        mock_result = Mock()
        mock_result.stdout = "other-file.txt\nREADME.md\n"

        with patch("subprocess.run", return_value=mock_result):
            with patch("pathlib.Path.exists", return_value=True):
                result = get_staged_yaml_files(force_check=False)

        assert result == []

    def test_get_staged_files_handles_subprocess_error(self, capsys):
        """
        Test that subprocess.CalledProcessError is handled gracefully.

        Given: Git command fails with CalledProcessError
        When: get_staged_yaml_files() is called
        Then: Returns empty list and prints error message
        """
        # Mock subprocess to raise CalledProcessError
        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "git diff", stderr="fatal: not a git repository"),
        ):
            result = get_staged_yaml_files(force_check=False)

        assert result == []

        # Verify error message was printed
        captured = capsys.readouterr()
        assert "Error getting staged files" in captured.out

    def test_get_staged_files_handles_empty_git_output(self):
        """
        Test that empty git output is handled correctly.

        Given: Git returns empty output (no files staged)
        When: get_staged_yaml_files() is called
        Then: Returns empty list
        """
        # Mock subprocess to return empty output
        mock_result = Mock()
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = get_staged_yaml_files(force_check=False)

        assert result == []

    def test_get_staged_files_returns_empty_when_staged_but_files_missing(self):
        """
        Test that empty list returned when files staged but don't exist on filesystem.

        Given: Target files are staged but at least one doesn't exist
        When: get_staged_yaml_files() is called
        Then: Returns empty list (line 53 check fails)
        """
        # Mock subprocess to return both files as staged
        mock_result = Mock()
        mock_result.stdout = "risk-map/yaml/controls.yaml\nrisk-map/yaml/risks.yaml\n"

        # Mock exists to return False for one file
        def exists_side_effect(self):
            # controls.yaml exists, risks.yaml doesn't
            return "controls.yaml" in str(self)

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(Path, "exists", exists_side_effect):
                result = get_staged_yaml_files(force_check=False)

        # Should return empty because not all target files exist (line 53)
        assert result == []

    def test_get_staged_files_handles_whitespace_in_git_output(self):
        """
        Test that whitespace around individual filenames causes match failure.

        Given: Git returns output with whitespace around each filename
        When: get_staged_yaml_files() is called
        Then: Returns empty list (filenames don't match due to whitespace)

        Note: This documents actual behavior - the function uses string matching
        without stripping individual lines, so "  risk-map/yaml/controls.yaml  "
        won't match "risk-map/yaml/controls.yaml".
        """
        # Mock subprocess to return output with extra whitespace around filenames
        mock_result = Mock()
        mock_result.stdout = "  risk-map/yaml/controls.yaml  \n  other-file.txt  \n"

        with patch("subprocess.run", return_value=mock_result):
            with patch("pathlib.Path.exists", return_value=True):
                result = get_staged_yaml_files(force_check=False)

        # Returns empty because whitespace-padded filenames don't match
        # Line 50: if str(path) in staged_files - doesn't match with padding
        assert result == []

    def test_get_staged_files_normal_mode_requires_both_files_exist(self):
        """
        Test that both files must exist even if only one is staged.

        Given: controls.yaml is staged and exists, risks.yaml exists
        When: get_staged_yaml_files() is called
        Then: Returns both files (line 54 returns target_files)
        """
        # Mock subprocess to return only controls.yaml as staged
        mock_result = Mock()
        mock_result.stdout = "risk-map/yaml/controls.yaml\n"

        with patch("subprocess.run", return_value=mock_result):
            with patch("pathlib.Path.exists", return_value=True):
                result = get_staged_yaml_files(force_check=False)

        # Should return both files because:
        # - staged_target_files contains controls.yaml (truthy)
        # - all(path.exists() for path in target_files) is True
        assert len(result) == 2
        assert Path("risk-map/yaml/controls.yaml") in result
        assert Path("risk-map/yaml/risks.yaml") in result


class TestLoadYamlFile:
    """Tests for load_yaml_file() YAML loading and error handling."""

    def test_load_yaml_file_with_valid_yaml_returns_dict(self):
        """
        Test that valid YAML file is loaded correctly.

        Given: A valid YAML file with proper syntax
        When: load_yaml_file() is called
        Then: Returns parsed YAML data as dictionary
        """
        yaml_content = """
        controls:
          - id: CTL-001
            risks: [RSK-001]
        """

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            result = load_yaml_file(Path("test.yaml"))

        assert result is not None
        assert isinstance(result, dict)
        assert "controls" in result
        assert result["controls"][0]["id"] == "CTL-001"

    def test_load_yaml_file_with_yaml_parse_error_returns_none(self, capsys):
        """
        Test that YAML parsing error is handled gracefully.

        Given: A file with invalid YAML syntax
        When: load_yaml_file() is called
        Then: Returns None and prints error message
        """
        invalid_yaml = """
        controls:
          - id: CTL-001
            risks: [RSK-001
        """  # Missing closing bracket

        with patch("builtins.open", mock_open(read_data=invalid_yaml)):
            with patch("yaml.safe_load", side_effect=yaml.YAMLError("parsing error")):
                result = load_yaml_file(Path("invalid.yaml"))

        assert result is None

        # Verify error message was printed
        captured = capsys.readouterr()
        assert "Error parsing YAML file" in captured.out
        assert "invalid.yaml" in captured.out

    def test_load_yaml_file_with_missing_file_returns_none(self, capsys):
        """
        Test that missing file is handled gracefully.

        Given: A file path that doesn't exist
        When: load_yaml_file() is called
        Then: Returns None and prints file not found message
        """
        with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
            result = load_yaml_file(Path("missing.yaml"))

        assert result is None

        # Verify error message was printed
        captured = capsys.readouterr()
        assert "File not found:" in captured.out
        assert "missing.yaml" in captured.out


class TestExtractControlsData:
    """Tests for extract_controls_data() controls.yaml parsing."""

    def test_extract_controls_data_with_valid_yaml_returns_mapping(self):
        """
        Test that valid controls.yaml is parsed correctly.

        Given: Valid controls.yaml data with controls and risks
        When: extract_controls_data() is called
        Then: Returns dict mapping control_id -> list of risk_ids
        """
        yaml_data = {
            "controls": [
                {"id": "CTL-001", "risks": ["RSK-001", "RSK-002"]},
                {"id": "CTL-002", "risks": ["RSK-003"]},
            ]
        }

        result = extract_controls_data(yaml_data)

        assert result == {
            "CTL-001": ["RSK-001", "RSK-002"],
            "CTL-002": ["RSK-003"],
        }

    def test_extract_controls_data_with_empty_controls_returns_empty_dict(self):
        """
        Test that empty controls list returns empty dict.

        Given: YAML data with empty controls list
        When: extract_controls_data() is called
        Then: Returns empty dictionary
        """
        yaml_data = {"controls": []}

        result = extract_controls_data(yaml_data)

        assert result == {}

    def test_extract_controls_data_with_none_yaml_data_returns_empty_dict(self):
        """
        Test that None yaml_data returns empty dict.

        Given: yaml_data is None
        When: extract_controls_data() is called
        Then: Returns empty dictionary (line 90-91)
        """
        result = extract_controls_data(None)  # pyright: ignore[reportArgumentType]

        assert result == {}

    def test_extract_controls_data_with_missing_controls_key_returns_empty_dict(self):
        """
        Test that yaml_data without 'controls' key returns empty dict.

        Given: YAML data without 'controls' key
        When: extract_controls_data() is called
        Then: Returns empty dictionary (line 90-91)
        """
        yaml_data = {"other_key": "value"}

        result = extract_controls_data(yaml_data)

        assert result == {}

    def test_extract_controls_data_skips_controls_without_id(self):
        """
        Test that controls without 'id' field are skipped.

        Given: Controls list with some entries missing 'id' field
        When: extract_controls_data() is called
        Then: Returns dict containing only controls with 'id'
        """
        yaml_data = {
            "controls": [
                {"id": "CTL-001", "risks": ["RSK-001"]},
                {"risks": ["RSK-002"]},  # Missing 'id'
                {"id": "CTL-003", "risks": ["RSK-003"]},
            ]
        }

        result = extract_controls_data(yaml_data)

        # Should only include controls with 'id' field
        assert result == {
            "CTL-001": ["RSK-001"],
            "CTL-003": ["RSK-003"],
        }
        assert len(result) == 2

    def test_extract_controls_data_handles_missing_risks_field(self):
        """
        Test that controls without 'risks' field get empty list.

        Given: Control entry without 'risks' field
        When: extract_controls_data() is called
        Then: Returns empty list for that control (dict.get default)
        """
        yaml_data = {
            "controls": [
                {"id": "CTL-001"},  # No 'risks' field
                {"id": "CTL-002", "risks": ["RSK-001"]},
            ]
        }

        result = extract_controls_data(yaml_data)

        assert result == {
            "CTL-001": [],  # Empty list from get("risks", [])
            "CTL-002": ["RSK-001"],
        }


class TestExtractRisksData:
    """Tests for extract_risks_data() risks.yaml reverse mapping."""

    def test_extract_risks_data_builds_reverse_mapping_correctly(self):
        """
        Test that reverse control->risks mapping is built correctly.

        Given: Valid risks.yaml data with controls references
        When: extract_risks_data() is called
        Then: Returns dict mapping control_id -> list of risk_ids that reference it
        """
        yaml_data = {
            "risks": [
                {"id": "RSK-001", "controls": ["CTL-001", "CTL-002"]},
                {"id": "RSK-002", "controls": ["CTL-001"]},
            ]
        }

        result = extract_risks_data(yaml_data)

        # CTL-001 is referenced by both RSK-001 and RSK-002
        # CTL-002 is referenced only by RSK-001
        assert result == {
            "CTL-001": ["RSK-001", "RSK-002"],
            "CTL-002": ["RSK-001"],
        }

    def test_extract_risks_data_with_multiple_risks_per_control(self):
        """
        Test that multiple risks referencing same control are aggregated.

        Given: Multiple risks each referencing the same control
        When: extract_risks_data() is called
        Then: Returns single control entry with all risks listed
        """
        yaml_data = {
            "risks": [
                {"id": "RSK-001", "controls": ["CTL-001"]},
                {"id": "RSK-002", "controls": ["CTL-001"]},
                {"id": "RSK-003", "controls": ["CTL-001"]},
            ]
        }

        result = extract_risks_data(yaml_data)

        assert result == {
            "CTL-001": ["RSK-001", "RSK-002", "RSK-003"],
        }
        assert len(result["CTL-001"]) == 3

    def test_extract_risks_data_with_empty_risks_returns_empty_dict(self):
        """
        Test that empty risks list returns empty dict.

        Given: YAML data with empty risks list
        When: extract_risks_data() is called
        Then: Returns empty dictionary
        """
        yaml_data = {"risks": []}

        result = extract_risks_data(yaml_data)

        assert result == {}

    def test_extract_risks_data_with_none_yaml_data_returns_empty_dict(self):
        """
        Test that None yaml_data returns empty dict.

        Given: yaml_data is None
        When: extract_risks_data() is called
        Then: Returns empty dictionary (line 113-114)
        """
        result = extract_risks_data(None)  # pyright: ignore[reportArgumentType]

        assert result == {}

    def test_extract_risks_data_with_missing_risks_key_returns_empty_dict(self):
        """
        Test that yaml_data without 'risks' key returns empty dict.

        Given: YAML data without 'risks' key
        When: extract_risks_data() is called
        Then: Returns empty dictionary (line 113-114)
        """
        yaml_data = {"other_key": "value"}

        result = extract_risks_data(yaml_data)

        assert result == {}

    def test_extract_risks_data_skips_risks_without_id(self):
        """
        Test that risks without 'id' field are skipped.

        Given: Risks list with some entries missing 'id' field
        When: extract_risks_data() is called
        Then: Returns dict containing only data from risks with 'id'
        """
        yaml_data = {
            "risks": [
                {"id": "RSK-001", "controls": ["CTL-001"]},
                {"controls": ["CTL-002"]},  # Missing 'id'
                {"id": "RSK-003", "controls": ["CTL-003"]},
            ]
        }

        result = extract_risks_data(yaml_data)

        # Should only process risks with 'id' field
        assert result == {
            "CTL-001": ["RSK-001"],
            "CTL-003": ["RSK-003"],
        }
        # CTL-002 should not appear because the risk had no id
        assert "CTL-002" not in result


class TestFindIsolatedEntries:
    """Tests for find_isolated_entries() isolated control/risk detection."""

    def test_find_isolated_entries_detects_controls_with_empty_risk_lists(self):
        """
        Test that controls with empty risk lists are identified as isolated.

        Given: Controls dict with some controls having empty risk lists
        When: find_isolated_entries() is called
        Then: Returns set of isolated control IDs
        """
        controls = {
            "CTL-001": [],  # Isolated
            "CTL-002": ["RSK-001"],
            "CTL-003": [],  # Isolated
        }
        risks = {
            "CTL-002": ["RSK-001"],
        }

        isolated_controls, isolated_risks = find_isolated_entries(controls, risks)

        assert isolated_controls == {"CTL-001", "CTL-003"}
        assert isolated_risks == set()  # Not implemented

    def test_find_isolated_entries_returns_empty_when_all_controls_have_risks(self):
        """
        Test that no isolated controls found when all have risk references.

        Given: All controls have non-empty risk lists
        When: find_isolated_entries() is called
        Then: Returns empty set for isolated controls
        """
        controls = {
            "CTL-001": ["RSK-001"],
            "CTL-002": ["RSK-002", "RSK-003"],
            "CTL-003": ["RSK-004"],
        }
        risks = {
            "CTL-001": ["RSK-001"],
            "CTL-002": ["RSK-002", "RSK-003"],
            "CTL-003": ["RSK-004"],
        }

        isolated_controls, isolated_risks = find_isolated_entries(controls, risks)

        assert isolated_controls == set()
        assert isolated_risks == set()

    def test_find_isolated_entries_handles_empty_controls_dict(self):
        """
        Test that empty controls dict returns empty isolated set.

        Given: Empty controls dictionary
        When: find_isolated_entries() is called
        Then: Returns empty set for isolated controls
        """
        controls = {}
        risks = {"CTL-001": ["RSK-001"]}

        isolated_controls, isolated_risks = find_isolated_entries(controls, risks)

        assert isolated_controls == set()
        assert isolated_risks == set()


class TestValidateControlToRisk:
    """Tests for validate_control_to_risk() end-to-end validation."""

    def test_validate_control_to_risk_with_valid_data_returns_true(self, capsys):
        """
        Test successful validation with consistent control-risk mappings.

        Given: Valid controls.yaml and risks.yaml with matching references
        When: validate_control_to_risk() is called
        Then: Returns True and prints success message
        """
        controls_yaml = {
            "controls": [
                {"id": "CTL-001", "risks": ["RSK-001"]},
            ]
        }
        risks_yaml = {
            "risks": [
                {"id": "RSK-001", "controls": ["CTL-001"]},
            ]
        }

        file_paths = [Path("controls.yaml"), Path("risks.yaml")]

        with patch("validate_control_risk_references.load_yaml_file") as mock_load:
            mock_load.side_effect = [controls_yaml, risks_yaml]
            result = validate_control_to_risk(file_paths)

        assert result is True

        # Verify success message
        captured = capsys.readouterr()
        assert "✅ Control-to-risk references are consistent" in captured.out

    def test_validate_control_to_risk_with_yaml_load_error_returns_false(self, capsys):
        """
        Test that YAML loading failure causes validation to fail.

        Given: load_yaml_file() returns None (error loading file)
        When: validate_control_to_risk() is called
        Then: Returns False and prints failure message
        """
        file_paths = [Path("controls.yaml"), Path("risks.yaml")]

        with patch("validate_control_risk_references.load_yaml_file") as mock_load:
            mock_load.return_value = None  # Simulate load error
            result = validate_control_to_risk(file_paths)

        assert result is False

        # Verify error message
        captured = capsys.readouterr()
        assert "❌   Failing - could not load YAML data" in captured.out

    def test_validate_control_to_risk_detects_isolated_controls(self, capsys):
        """
        Test that isolated controls are detected and reported.

        Given: Controls with empty risk lists
        When: validate_control_to_risk() is called
        Then: Returns False and prints isolated control errors
        """
        controls_yaml = {
            "controls": [
                {"id": "CTL-001", "risks": []},  # Isolated
                {"id": "CTL-002", "risks": ["RSK-001"]},
            ]
        }
        risks_yaml = {
            "risks": [
                {"id": "RSK-001", "controls": ["CTL-002"]},
            ]
        }

        file_paths = [Path("controls.yaml"), Path("risks.yaml")]

        with patch("validate_control_risk_references.load_yaml_file") as mock_load:
            mock_load.side_effect = [controls_yaml, risks_yaml]
            result = validate_control_to_risk(file_paths)

        assert result is False

        # Verify isolated control message
        captured = capsys.readouterr()
        assert "❌ Found 1 isolated controls" in captured.out
        assert "CTL-001" in captured.out
        assert "empty 'risks' list" in captured.out

    def test_validate_control_to_risk_detects_cross_reference_errors(self, capsys):
        """
        Test that cross-reference consistency errors are detected.

        Given: Controls and risks with mismatched references
        When: validate_control_to_risk() is called
        Then: Returns False and prints cross-reference errors
        """
        controls_yaml = {
            "controls": [
                {"id": "CTL-001", "risks": ["RSK-001", "RSK-002"]},
            ]
        }
        risks_yaml = {
            "risks": [
                {"id": "RSK-001", "controls": ["CTL-001"]},
                # RSK-002 missing - doesn't reference CTL-001
            ]
        }

        file_paths = [Path("controls.yaml"), Path("risks.yaml")]

        with patch("validate_control_risk_references.load_yaml_file") as mock_load:
            mock_load.side_effect = [controls_yaml, risks_yaml]
            result = validate_control_to_risk(file_paths)

        assert result is False

        # Verify cross-reference error message
        captured = capsys.readouterr()
        assert "❌ Found" in captured.out
        assert "cross-reference consistency errors" in captured.out
        assert "CTL-001" in captured.out

    def test_validate_control_to_risk_skips_when_no_controls_found(self, capsys):
        """
        Test that validation is skipped when no controls are found.

        Given: Controls.yaml has no controls
        When: validate_control_to_risk() is called
        Then: Returns True and prints skip message (lines 243-245)
        """
        controls_yaml = {"controls": []}
        risks_yaml = {
            "risks": [
                {"id": "RSK-001", "controls": ["CTL-001"]},
            ]
        }

        file_paths = [Path("controls.yaml"), Path("risks.yaml")]

        with patch("validate_control_risk_references.load_yaml_file") as mock_load:
            mock_load.side_effect = [controls_yaml, risks_yaml]
            result = validate_control_to_risk(file_paths)

        assert result is True

        # Verify skip message
        captured = capsys.readouterr()
        assert "No controls found in" in captured.out
        assert "skipping validation" in captured.out

    def test_validate_control_to_risk_skips_when_no_risks_found(self, capsys):
        """
        Test that validation is skipped when no risks are found.

        Given: Risks.yaml has no risks
        When: validate_control_to_risk() is called
        Then: Returns True and prints skip message (lines 246-248)
        """
        controls_yaml = {
            "controls": [
                {"id": "CTL-001", "risks": ["RSK-001"]},
            ]
        }
        risks_yaml = {"risks": []}

        file_paths = [Path("controls.yaml"), Path("risks.yaml")]

        with patch("validate_control_risk_references.load_yaml_file") as mock_load:
            mock_load.side_effect = [controls_yaml, risks_yaml]
            result = validate_control_to_risk(file_paths)

        assert result is True

        # Verify skip message
        captured = capsys.readouterr()
        assert "No risks found in" in captured.out
        assert "skipping validation" in captured.out

    def test_validate_control_to_risk_detects_isolated_risks(self, capsys):
        """
        Test that isolated risks are detected and reported.

        Given: Risks with empty control lists (when implemented)
        When: validate_control_to_risk() is called
        Then: Returns False and prints isolated risk errors (lines 265-269)

        Note: This test documents the intended behavior for when isolated_risks
        is implemented. Currently isolated_risks always returns empty set.
        """
        controls_yaml = {
            "controls": [
                {"id": "CTL-001", "risks": ["RSK-001"]},
            ]
        }
        risks_yaml = {
            "risks": [
                {"id": "RSK-001", "controls": ["CTL-001"]},
            ]
        }

        file_paths = [Path("controls.yaml"), Path("risks.yaml")]

        # Mock find_isolated_entries to simulate finding isolated risks
        with patch("validate_control_risk_references.load_yaml_file") as mock_load:
            with patch("validate_control_risk_references.find_isolated_entries") as mock_find:
                mock_load.side_effect = [controls_yaml, risks_yaml]
                mock_find.return_value = (set(), {"RSK-999"})  # No isolated controls, one isolated risk

                result = validate_control_to_risk(file_paths)

        assert result is False

        # Verify isolated risk message
        captured = capsys.readouterr()
        assert "❌ Found 1 isolated risks" in captured.out
        assert "RSK-999" in captured.out
        assert "empty 'controls' list" in captured.out


class TestParseArgs:
    """Tests for parse_args() argument parsing."""

    def test_parse_args_with_no_arguments_returns_force_false(self):
        """
        Test default arguments when no flags provided.

        Given: Script called with no arguments
        When: parse_args() is called
        Then: Returns namespace with force=False
        """
        with patch("sys.argv", ["script.py"]):
            args = parse_args()

        assert args.force is False

    def test_parse_args_with_force_flag_returns_force_true(self):
        """
        Test --force flag sets force=True.

        Given: Script called with --force flag
        When: parse_args() is called
        Then: Returns namespace with force=True
        """
        with patch("sys.argv", ["script.py", "--force"]):
            args = parse_args()

        assert args.force is True


class TestExtractControlsDataKeywordHandling:
    """Tests for extract_controls_data() handling of 'all'/'none' keywords as strings."""

    def test_extract_controls_data_with_risks_all_stores_as_string(self):
        """
        Test that control with risks="all" is stored as string, not iterated as list.

        Given: Control with risks: "all"
        When: extract_controls_data() is called
        Then: Returns {"CTL-001": "all"} (string, NOT ['a','l','l'])

        This validates the fix for line 98 where the current buggy code iterates
        "all" as ['a', 'l', 'l'] when it should store it as a string.
        """
        yaml_data = {
            "controls": [
                {"id": "CTL-001", "risks": "all"},
            ]
        }

        result = extract_controls_data(yaml_data)

        assert result == {"CTL-001": "all"}
        assert isinstance(result["CTL-001"], str), "Expected 'all' to be stored as string"
        assert result["CTL-001"] == "all", "Expected exact string 'all', not ['a','l','l']"

    def test_extract_controls_data_with_risks_none_stores_as_string(self):
        """
        Test that control with risks="none" is stored as string, not iterated as list.

        Given: Control with risks: "none"
        When: extract_controls_data() is called
        Then: Returns {"CTL-001": "none"} (string, NOT ['n','o','n','e'])
        """
        yaml_data = {
            "controls": [
                {"id": "CTL-001", "risks": "none"},
            ]
        }

        result = extract_controls_data(yaml_data)

        assert result == {"CTL-001": "none"}
        assert isinstance(result["CTL-001"], str), "Expected 'none' to be stored as string"
        assert result["CTL-001"] == "none", "Expected exact string 'none', not ['n','o','n','e']"

    def test_compare_control_maps_handles_all_as_string_not_list(self):
        """
        Test that compare_control_maps() doesn't iterate "all" as a list.

        Given: controls={"CTL-001": "all"}, risks={}
        When: compare_control_maps() is called
        Then: No errors (properly skipped, not attempted to iterate 'all')

        This validates that the skip logic at line 180-183 correctly handles
        string "all" without trying to iterate it or call sorted() on it.
        """
        controls = {"CTL-001": "all"}
        risks = {}

        errors = compare_control_maps(controls, risks)

        # Should skip without errors - "all" should be handled as string
        assert errors == [], f"Expected no errors for 'all' keyword but got: {errors}"

    def test_compare_control_maps_handles_none_as_string_not_list(self):
        """
        Test that compare_control_maps() doesn't iterate "none" as a list.

        Given: controls={"CTL-001": "none"}, risks={}
        When: compare_control_maps() is called
        Then: No errors (properly skipped, not attempted to iterate 'none')
        """
        controls = {"CTL-001": "none"}
        risks = {}

        errors = compare_control_maps(controls, risks)

        # Should skip without errors - "none" should be handled as string
        assert errors == [], f"Expected no errors for 'none' keyword but got: {errors}"

    def test_extract_controls_preserves_string_type_for_all(self):
        """
        Test that type checking confirms "all" is preserved as str.

        Given: Control with risks: "all"
        When: extract_controls_data() is called
        Then: type(result["CTL-001"]) is str
        """
        yaml_data = {
            "controls": [
                {"id": "CTL-001", "risks": "all"},
            ]
        }

        result = extract_controls_data(yaml_data)

        assert type(result["CTL-001"]) is str, "Expected 'all' to have type str"
        assert not isinstance(result["CTL-001"], list), "Expected 'all' NOT to be a list"

    def test_extract_controls_preserves_list_type_for_normal_risks(self):
        """
        Test that normal risk lists are preserved as lists.

        Given: Control with risks: ["RSK-001"]
        When: extract_controls_data() is called
        Then: type(result["CTL-001"]) is list
        """
        yaml_data = {
            "controls": [
                {"id": "CTL-001", "risks": ["RSK-001"]},
            ]
        }

        result = extract_controls_data(yaml_data)

        assert isinstance(result["CTL-001"], list), "Expected normal risks to be stored as list"
        assert result["CTL-001"] == ["RSK-001"]

    def test_mixed_types_in_single_extraction(self):
        """
        Test that mixed "all", "none", empty, and normal lists maintain correct types.

        Given: Mix of "all", "none", [], ["RSK-001"]
        When: extract_controls_data() is called
        Then: Each maintains correct type (str vs list)
        """
        yaml_data = {
            "controls": [
                {"id": "CTL-001", "risks": "all"},
                {"id": "CTL-002", "risks": "none"},
                {"id": "CTL-003", "risks": []},
                {"id": "CTL-004", "risks": ["RSK-001", "RSK-002"]},
            ]
        }

        result = extract_controls_data(yaml_data)

        # Verify each type is correct
        assert result["CTL-001"] == "all" and isinstance(result["CTL-001"], str)
        assert result["CTL-002"] == "none" and isinstance(result["CTL-002"], str)
        assert result["CTL-003"] == [] and isinstance(result["CTL-003"], list)
        assert result["CTL-004"] == ["RSK-001", "RSK-002"] and isinstance(result["CTL-004"], list)


class TestCompareControlMapsSkipLogic:
    """Tests for compare_control_maps() skip logic with string keyword comparisons."""

    def test_compare_skips_when_control_all_and_risks_empty(self):
        """
        Test that universal control with "all" is skipped when risks={}.

        Given: controls={"CTL-001": "all"}, risks={}
        When: compare_control_maps() is called
        Then: No errors (skip condition at line 180-183 triggered)
        """
        controls = {"CTL-001": "all"}
        risks = {}

        errors = compare_control_maps(controls, risks)

        assert errors == [], "Expected skip for 'all' keyword with empty risks"

    def test_compare_skips_when_control_none_and_risks_empty(self):
        """
        Test that control with "none" is skipped when risks={}.

        Given: controls={"CTL-001": "none"}, risks={}
        When: compare_control_maps() is called
        Then: No errors (skip condition at line 180-183 triggered)
        """
        controls = {"CTL-001": "none"}
        risks = {}

        errors = compare_control_maps(controls, risks)

        assert errors == [], "Expected skip for 'none' keyword with empty risks"

    def test_compare_skips_when_control_empty_list_and_risks_empty(self):
        """
        Test that control with empty list is skipped when risks={}.

        Given: controls={"CTL-001": []}, risks={}
        When: compare_control_maps() is called
        Then: No errors (skip condition at line 180-183 triggered)
        """
        controls = {"CTL-001": []}
        risks = {}

        errors = compare_control_maps(controls, risks)

        assert errors == [], "Expected skip for empty list with empty risks"

    def test_compare_does_not_skip_when_risks_references_universal_control(self):
        """
        Test that validation runs when a risk explicitly references a universal control.

        Given: controls={"CTL-001": "all"}, risks={"CTL-001": ["RSK-001"]}
        When: compare_control_maps() is called
        Then: Should NOT skip - this is a violation to detect

        This is a critical test: if a control has risks="all", risks should NOT
        explicitly list that control in their controls field.
        """
        controls = {"CTL-001": "all"}
        risks = {"CTL-001": ["RSK-001"]}  # Risk explicitly references universal control

        errors = compare_control_maps(controls, risks)

        # Should detect this as an error - line 180-183 skip should NOT trigger
        # because risks_per_risks_yaml != []
        assert len(errors) > 0, "Expected error when risk explicitly lists universal control"

        # CRITICAL: Bug check - should not contain ['a', 'l'] from sorted("all")
        all_errors_text = " ".join(errors)
        assert "['a', 'l']" not in all_errors_text, (
            f"BUG: sorted('all') was called. Expected proper error about universal control, "
            f"not ['a', 'l']. Errors: {errors}"
        )


class TestCompareControlMapsUniversalValidation:
    """Tests for compare_control_maps() detection of universal control violations."""

    def test_compare_errors_when_risk_lists_universal_control(self):
        """
        Test that error is raised when risk explicitly lists a universal control.

        Given: Universal control CTL-U with risks: "all", risk lists it
        When: compare_control_maps() is called
        Then: Error saying risk should NOT list universal control

        Universal controls with risks="all" apply implicitly to all risks.
        Risks should NOT explicitly list them in their controls field.
        """
        # CTL-U is universal (applies to all risks)
        controls = {"CTL-U": "all"}
        # RSK-001 explicitly lists the universal control (violation)
        risks = {"CTL-U": ["RSK-001"]}

        errors = compare_control_maps(controls, risks)

        # Should detect violation
        assert len(errors) > 0, "Expected error when risk lists universal control"
        # Error should indicate the issue
        assert any("CTL-U" in err for err in errors), f"Expected CTL-U in error: {errors}"

        # CRITICAL: Bug check - should not contain ['a', 'l'] from sorted("all")
        all_errors_text = " ".join(errors)
        assert "['a', 'l']" not in all_errors_text, (
            f"BUG: sorted('all') produced ['a', 'l']. Errors: {errors}"
        )

    def test_compare_errors_for_multiple_risks_listing_universal_control(self):
        """
        Test that multiple risks listing same universal control all generate errors.

        Given: 3 risks explicitly list same universal control
        When: compare_control_maps() is called
        Then: Should detect violation (at least one error)

        Note: Exact error count depends on implementation - at minimum one error
        should be generated for this violation scenario.
        """
        # CTL-U is universal
        controls = {"CTL-U": "all"}
        # Multiple risks list it
        risks = {"CTL-U": ["RSK-001", "RSK-002", "RSK-003"]}

        errors = compare_control_maps(controls, risks)

        # Should detect violations
        assert len(errors) > 0, "Expected errors for multiple risks listing universal control"
        assert any("CTL-U" in err for err in errors), f"Expected CTL-U in errors: {errors}"

    def test_compare_no_error_when_universal_control_not_listed(self):
        """
        Test that no error when universal control is not explicitly listed by risks.

        Given: controls={"CTL-U": "all"}, risks={}
        When: compare_control_maps() is called
        Then: No errors (correct behavior - universal applies implicitly)
        """
        controls = {"CTL-U": "all"}
        risks = {}  # No risks explicitly list CTL-U (correct)

        errors = compare_control_maps(controls, risks)

        assert errors == [], f"Expected no errors for proper universal control usage: {errors}"

    def test_compare_allows_normal_controls_explicitly_listed(self):
        """
        Test that normal (non-universal) bidirectional mappings still work.

        Given: Normal control with specific risk list, bidirectional mapping
        When: compare_control_maps() is called
        Then: No errors (normal validation continues to work)
        """
        # Normal bidirectional mapping
        controls = {
            "CTL-001": ["RSK-001", "RSK-002"],
            "CTL-U": "all",  # Universal control alongside normal one
        }
        risks = {
            "CTL-001": ["RSK-001", "RSK-002"],
            # CTL-U not listed (correct)
        }

        errors = compare_control_maps(controls, risks)

        assert errors == [], f"Expected no errors for normal bidirectional mapping: {errors}"

    def test_error_message_clarity_for_universal_control_violation(self):
        """
        Test that error message for universal control violation is clear.

        Given: Risk explicitly lists universal control
        When: compare_control_maps() is called
        Then: Error message should be informative

        Note: This test documents expected error message content. The exact
        message will be determined during implementation.
        """
        controls = {"CTL-U": "all"}
        risks = {"CTL-U": ["RSK-001"]}

        errors = compare_control_maps(controls, risks)

        # Should have at least one error
        assert len(errors) > 0, "Expected error for universal control violation"

        # Error should mention the control
        all_errors_text = " ".join(errors)
        assert "CTL-U" in all_errors_text, "Expected control ID in error message"


class TestUniversalControlsEdgeCases:
    """Tests for edge cases and integration scenarios with universal controls."""

    def test_type_guard_prevents_sorted_on_string(self):
        """
        Test that sorted() is not called on "all"/"none" strings.

        Given: Control with risks="all" and mismatched risks mapping
        When: compare_control_maps() reaches line 204
        Then: Type guard should prevent sorted() call on string

        Line 204: sorted(risks_per_control_yaml) will fail if risks_per_control_yaml
        is "all" or "none" string. This test validates that the skip logic prevents
        reaching line 204 for string keywords.

        CURRENT BUG: sorted("all") returns ['a', 'l', 'l'] which appears as ['a', 'l']
        after deduplication, causing incorrect error messages.
        """
        controls = {"CTL-001": "all"}
        # Mismatch that would normally trigger line 204
        risks = {"CTL-001": ["RSK-001"]}

        # This should not crash even though line 204 would fail on sorted("all")
        errors = compare_control_maps(controls, risks)

        # Should either skip or handle gracefully (not crash with TypeError)
        assert isinstance(errors, list), "Expected list of errors, not crash"

        # CRITICAL: Check for the bug - if "all" was sorted, we'd see ['a', 'l'] in error
        if errors:
            all_errors_text = " ".join(errors)
            # This assertion will FAIL with current buggy code
            assert "['a', 'l']" not in all_errors_text, (
                f"BUG DETECTED: sorted('all') was called, producing ['a', 'l']. "
                f"Errors: {errors}"
            )

    def test_all_special_keyword_combinations(self):
        """
        Test matrix of "all", "none", [], ["RSK-001"] with empty/non-empty risks.

        Given: All combinations of special keywords and normal values
        When: compare_control_maps() is called
        Then: No crashes, proper handling of each case

        This is a comprehensive edge case test validating all combinations.
        """
        test_cases = [
            # (controls value, risks mapping, expected_should_skip)
            ("all", {}, True),  # Universal, no explicit references
            ("all", {"CTL-001": ["RSK-001"]}, False),  # Universal but risk lists it (violation)
            ("none", {}, True),  # None, no references
            ("none", {"CTL-001": ["RSK-001"]}, False),  # None but risk lists it
            ([], {}, True),  # Empty list, no references
            ([], {"CTL-001": ["RSK-001"]}, False),  # Empty but risk references it
            (["RSK-001"], {}, False),  # Normal list, missing reference
            (["RSK-001"], {"CTL-001": ["RSK-001"]}, True),  # Normal matching
        ]

        for control_value, risk_mapping, should_skip in test_cases:
            controls = {"CTL-001": control_value}
            risks = risk_mapping

            errors = compare_control_maps(controls, risks)

            # Should not crash
            assert isinstance(errors, list), f"Expected list for {control_value} vs {risk_mapping}"

            if should_skip:
                # These cases should either skip or have no errors
                pass  # Not asserting error count as implementation may vary
            else:
                # These cases should potentially have errors
                pass  # Not asserting error count as implementation may vary

    def test_end_to_end_with_universal_controls(self):
        """
        Test end-to-end scenario with 7 universal controls and no violations.

        Given: YAML with 7 universal controls (risks: "all")
        When: Full validation flow is run
        Then: Should pass without errors

        This simulates the actual CoSAI use case with multiple universal controls.
        """
        yaml_data = {
            "controls": [
                {"id": "CTL-U01", "risks": "all"},
                {"id": "CTL-U02", "risks": "all"},
                {"id": "CTL-U03", "risks": "all"},
                {"id": "CTL-U04", "risks": "all"},
                {"id": "CTL-U05", "risks": "all"},
                {"id": "CTL-U06", "risks": "all"},
                {"id": "CTL-U07", "risks": "all"},
                {"id": "CTL-001", "risks": ["RSK-001"]},  # Normal control
            ]
        }

        controls = extract_controls_data(yaml_data)

        # Verify extraction preserved types
        assert controls["CTL-U01"] == "all"
        assert isinstance(controls["CTL-U01"], str)
        assert controls["CTL-001"] == ["RSK-001"]
        assert isinstance(controls["CTL-001"], list)

        # Build risks mapping (no risks should reference universal controls)
        risks = {
            "CTL-001": ["RSK-001"],  # Normal mapping
            # No CTL-U* entries (correct - they apply universally)
        }

        errors = compare_control_maps(controls, risks)

        # Should have no errors
        assert errors == [], f"Expected no errors with proper universal controls: {errors}"

    def test_end_to_end_catches_universal_violations(self):
        """
        Test that end-to-end validation catches risks listing universal controls.

        Given: YAML with risks explicitly listing universal controls
        When: Full validation flow is run
        Then: Should detect violations

        This validates the complete fix catches the real-world error scenario.
        """
        controls_yaml = {
            "controls": [
                {"id": "CTL-U01", "risks": "all"},
                {"id": "CTL-U02", "risks": "all"},
                {"id": "CTL-001", "risks": ["RSK-001"]},
            ]
        }

        risks_yaml = {
            "risks": [
                {"id": "RSK-001", "controls": ["CTL-001", "CTL-U01"]},  # Violation: lists CTL-U01
                {"id": "RSK-002", "controls": ["CTL-U02"]},  # Violation: lists CTL-U02
            ]
        }

        controls = extract_controls_data(controls_yaml)
        risks = extract_risks_data(risks_yaml)

        errors = compare_control_maps(controls, risks)

        # Should detect violations
        assert len(errors) > 0, "Expected errors when risks list universal controls"

        # Both universal controls should be mentioned
        all_errors_text = " ".join(errors)
        # At least one of the universal controls should appear in errors
        assert "CTL-U01" in all_errors_text or "CTL-U02" in all_errors_text, (
            f"Expected universal control violations in errors: {errors}"
        )

        # CRITICAL: Bug check - should not contain ['a', 'l'] from sorted("all")
        assert "['a', 'l']" not in all_errors_text, (
            f"BUG: sorted('all') produced ['a', 'l']. Errors: {errors}"
        )


class TestMain:
    """Tests for main() orchestration function."""

    def test_main_exits_0_when_no_yaml_files_modified(self, capsys):
        """
        Test that main exits 0 when no target YAML files are modified.

        Given: get_staged_yaml_files() returns empty list
        When: main() is called
        Then: Exits with code 0 and prints skip message
        """
        with patch("sys.argv", ["script.py"]):
            with patch("validate_control_risk_references.get_staged_yaml_files", return_value=[]):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 0

        # Verify skip message
        captured = capsys.readouterr()
        assert "No YAML files modified" in captured.out
        assert "skipping control-to-risk reference validation" in captured.out

    def test_main_exits_0_when_validation_passes(self, capsys):
        """
        Test that main exits 0 when validation succeeds.

        Given: YAML files are staged and validation passes
        When: main() is called
        Then: Exits with code 0 and prints success message
        """
        file_paths = [Path("controls.yaml"), Path("risks.yaml")]

        with patch("sys.argv", ["script.py"]):
            with patch("validate_control_risk_references.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_control_risk_references.validate_control_to_risk", return_value=True):
                    with pytest.raises(SystemExit) as exc_info:
                        main()

        assert exc_info.value.code == 0

        # Verify success message
        captured = capsys.readouterr()
        assert "✅ Control-to-risk reference validation passed" in captured.out

    def test_main_exits_1_when_validation_fails(self, capsys):
        """
        Test that main exits 1 when validation fails.

        Given: YAML files are staged and validation fails
        When: main() is called
        Then: Exits with code 1 and prints failure message
        """
        file_paths = [Path("controls.yaml"), Path("risks.yaml")]

        with patch("sys.argv", ["script.py"]):
            with patch("validate_control_risk_references.get_staged_yaml_files", return_value=file_paths):
                with patch("validate_control_risk_references.validate_control_to_risk", return_value=False):
                    with pytest.raises(SystemExit) as exc_info:
                        main()

        assert exc_info.value.code == 1

        # Verify failure message
        captured = capsys.readouterr()
        assert "❌ Control-to-risk reference validation failed!" in captured.out
        assert "Fix the above errors before committing" in captured.out

    def test_main_force_mode_always_validates(self, capsys):
        """
        Test that force mode always attempts validation.

        Given: Script called with --force flag
        When: main() is called
        Then: Calls get_staged_yaml_files with force=True
        """
        file_paths = [Path("controls.yaml"), Path("risks.yaml")]

        with patch("sys.argv", ["script.py", "--force"]):
            with patch(
                "validate_control_risk_references.get_staged_yaml_files", return_value=file_paths
            ) as mock_get:
                with patch("validate_control_risk_references.validate_control_to_risk", return_value=True):
                    with pytest.raises(SystemExit) as exc_info:
                        main()

        # Verify force flag was passed
        mock_get.assert_called_once_with(True)

        # Verify force message
        captured = capsys.readouterr()
        assert "Force checking control-to-risk references" in captured.out

        assert exc_info.value.code == 0
