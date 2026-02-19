#!/usr/bin/env python3
"""
Tests for validate_framework_references.py

Tests cover:
- Schema $ref resolution validation
- Framework existence verification
- Identifier/key consistency checks
- Missing framework detection
- Backward compatibility with legacy entries
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path to import the validator
sys.path.insert(0, str(Path(__file__).parent.parent))

from validate_framework_references import (
    extract_control_framework_references,
    extract_framework_ids,
    extract_risk_framework_references,
    validate_framework_consistency,
    validate_framework_references,
)


class TestExtractFrameworkIds:
    """Test extraction of framework IDs from frameworks.yaml"""

    def test_extract_valid_frameworks(self):
        """Test extracting framework IDs from valid data"""
        data = {
            "frameworks": [
                {"id": "mitre-atlas", "name": "MITRE ATLAS"},
                {"id": "stride", "name": "STRIDE"},
                {"id": "nist-ai-rmf", "name": "NIST AI RMF"},
            ]
        }
        result = extract_framework_ids(data)
        assert result == {"mitre-atlas", "stride", "nist-ai-rmf"}

    def test_extract_empty_frameworks(self):
        """Test extraction with empty frameworks list"""
        data = {"frameworks": []}
        result = extract_framework_ids(data)
        assert result == set()

    def test_extract_missing_frameworks_key(self):
        """Test extraction when frameworks key is missing"""
        data = {"title": "Frameworks"}
        result = extract_framework_ids(data)
        assert result == set()

    def test_extract_frameworks_with_missing_ids(self):
        """Test extraction skips frameworks without IDs"""
        data = {
            "frameworks": [
                {"id": "mitre-atlas", "name": "MITRE ATLAS"},
                {"name": "No ID Framework"},
                {"id": "stride", "name": "STRIDE"},
            ]
        }
        result = extract_framework_ids(data)
        assert result == {"mitre-atlas", "stride"}


class TestExtractRiskFrameworkReferences:
    """Test extraction of framework references from risks.yaml"""

    def test_extract_risk_with_mappings(self):
        """Test extracting framework references from risks with mappings"""
        data = {
            "risks": [
                {
                    "id": "DP",
                    "title": "Data Poisoning",
                    "mappings": {"mitre-atlas": ["AML.T0020"], "stride": ["tampering"]},
                },
                {"id": "UTD", "title": "Unauthorized Training Data", "mappings": {"stride": ["info-disclosure"]}},
            ]
        }
        result = extract_risk_framework_references(data)
        # Convert list values to sets for order-independent comparison
        assert {k: set(v) for k, v in result.items()} == {"DP": {"mitre-atlas", "stride"}, "UTD": {"stride"}}

    def test_extract_risk_without_mappings(self):
        """Test extraction for risks without mappings field (backward compatibility)"""
        data = {"risks": [{"id": "DP", "title": "Data Poisoning"}]}
        result = extract_risk_framework_references(data)
        assert result == {}

    def test_extract_risk_with_empty_mappings(self):
        """Test extraction for risks with empty mappings"""
        data = {"risks": [{"id": "DP", "title": "Data Poisoning", "mappings": {}}]}
        result = extract_risk_framework_references(data)
        assert result == {}

    def test_extract_risk_missing_id(self):
        """Test extraction skips risks without IDs"""
        data = {"risks": [{"title": "No ID Risk", "mappings": {"mitre-atlas": ["AML.T0020"]}}]}
        result = extract_risk_framework_references(data)
        assert result == {}


class TestExtractControlFrameworkReferences:
    """Test extraction of framework references from controls.yaml"""

    def test_extract_control_with_mappings(self):
        """Test extracting framework references from controls with mappings"""
        data = {
            "controls": [
                {
                    "id": "controlTrainingDataSanitization",
                    "title": "Training Data Sanitization",
                    "mappings": {"mitre-atlas": ["AML.M0007"]},
                },
                {
                    "id": "controlModelIntegrity",
                    "title": "Model Integrity",
                    "mappings": {"nist-ai-rmf": ["SC-8"], "mitre-atlas": ["AML.M0013"]},
                },
            ]
        }
        result = extract_control_framework_references(data)
        # Convert list values to sets for order-independent comparison
        assert {k: set(v) for k, v in result.items()} == {
            "controlTrainingDataSanitization": {"mitre-atlas"},
            "controlModelIntegrity": {"nist-ai-rmf", "mitre-atlas"},
        }

    def test_extract_control_without_mappings(self):
        """Test extraction for controls without mappings field (backward compatibility)"""
        data = {"controls": [{"id": "controlTest", "title": "Test Control"}]}
        result = extract_control_framework_references(data)
        assert result == {}

    def test_extract_control_with_empty_mappings(self):
        """Test extraction for controls with empty mappings"""
        data = {"controls": [{"id": "controlTest", "title": "Test Control", "mappings": {}}]}
        result = extract_control_framework_references(data)
        assert result == {}


class TestValidateFrameworkReferences:
    """Test validation of framework references"""

    def test_validate_all_valid_references(self):
        """Test validation passes when all references are valid"""
        valid_frameworks = {"mitre-atlas", "stride", "nist-ai-rmf"}
        risk_frameworks = {"DP": ["mitre-atlas", "stride"], "MST": ["stride"]}
        control_frameworks = {"controlTest": ["nist-ai-rmf"]}

        errors = validate_framework_references(valid_frameworks, risk_frameworks, control_frameworks)
        assert errors == []

    def test_validate_invalid_risk_framework(self):
        """Test validation fails when risk references invalid framework"""
        valid_frameworks = {"mitre-atlas", "stride"}
        risk_frameworks = {"DP": ["invalid-framework"]}
        control_frameworks = {}

        errors = validate_framework_references(valid_frameworks, risk_frameworks, control_frameworks)
        assert len(errors) == 1
        assert "Risk 'DP'" in errors[0]
        assert "invalid-framework" in errors[0]
        assert "does not exist" in errors[0]

    def test_validate_invalid_control_framework(self):
        """Test validation fails when control references invalid framework"""
        valid_frameworks = {"mitre-atlas"}
        risk_frameworks = {}
        control_frameworks = {"controlTest": ["missing-framework"]}

        errors = validate_framework_references(valid_frameworks, risk_frameworks, control_frameworks)
        assert len(errors) == 1
        assert "Control 'controlTest'" in errors[0]
        assert "missing-framework" in errors[0]
        assert "does not exist" in errors[0]

    def test_validate_multiple_errors(self):
        """Test validation reports all errors"""
        valid_frameworks = {"mitre-atlas"}
        risk_frameworks = {"DP": ["invalid1", "mitre-atlas"], "MST": ["invalid2"]}
        control_frameworks = {"controlTest": ["invalid3"]}

        errors = validate_framework_references(valid_frameworks, risk_frameworks, control_frameworks)
        assert len(errors) == 3

    def test_validate_empty_references(self):
        """Test validation passes with no framework references (backward compatibility)"""
        valid_frameworks = {"mitre-atlas", "stride"}
        risk_frameworks = {}
        control_frameworks = {}

        errors = validate_framework_references(valid_frameworks, risk_frameworks, control_frameworks)
        assert errors == []


class TestValidateFrameworkConsistency:
    """Test validation of framework definition consistency"""

    def test_validate_consistent_frameworks(self):
        """Test validation passes for consistent framework definitions"""
        data = {
            "frameworks": [
                {
                    "id": "mitre-atlas",
                    "name": "MITRE ATLAS",
                    "fullName": "Adversarial Threat Landscape for AI Systems",
                    "description": "Framework description",
                    "baseUri": "https://atlas.mitre.org",
                },
                {
                    "id": "stride",
                    "name": "STRIDE",
                    "fullName": "STRIDE Threat Model",
                    "description": "Threat modeling framework",
                    "baseUri": "https://example.com",
                },
            ]
        }
        errors = validate_framework_consistency(data)
        assert errors == []

    def test_validate_missing_required_field(self):
        """Test validation fails when required field is missing"""
        data = {
            "frameworks": [
                {
                    "id": "mitre-atlas",
                    "name": "MITRE ATLAS",
                    "fullName": "Adversarial Threat Landscape",
                    # Missing description and baseUri
                }
            ]
        }
        errors = validate_framework_consistency(data)
        assert len(errors) >= 2
        assert any("description" in error for error in errors)
        assert any("baseUri" in error for error in errors)

    def test_validate_duplicate_framework_ids(self):
        """Test validation fails when duplicate IDs exist"""
        data = {
            "frameworks": [
                {
                    "id": "mitre-atlas",
                    "name": "MITRE ATLAS",
                    "fullName": "Framework 1",
                    "description": "Description 1",
                    "baseUri": "https://example1.com",
                },
                {
                    "id": "mitre-atlas",  # Duplicate
                    "name": "MITRE ATLAS 2",
                    "fullName": "Framework 2",
                    "description": "Description 2",
                    "baseUri": "https://example2.com",
                },
            ]
        }
        errors = validate_framework_consistency(data)
        assert len(errors) >= 1
        assert any("Duplicate framework ID" in error for error in errors)
        assert any("mitre-atlas" in error for error in errors)

    def test_validate_missing_id_field(self):
        """Test validation fails when framework is missing ID"""
        data = {
            "frameworks": [
                {
                    "name": "No ID Framework",
                    "fullName": "Framework without ID",
                    "description": "Description",
                    "baseUri": "https://example.com",
                }
            ]
        }
        errors = validate_framework_consistency(data)
        assert len(errors) >= 1
        assert any("missing 'id' field" in error for error in errors)

    def test_validate_missing_frameworks_array(self):
        """Test validation fails when frameworks array is missing"""
        data = {"title": "Frameworks"}
        errors = validate_framework_consistency(data)
        assert len(errors) == 1
        assert "No frameworks array found" in errors[0]

    def test_validate_optional_fields_allowed(self):
        """Test that optional fields don't cause validation errors"""
        data = {
            "frameworks": [
                {
                    "id": "mitre-atlas",
                    "name": "MITRE ATLAS",
                    "fullName": "Framework",
                    "description": "Description",
                    "baseUri": "https://example.com",
                    "version": "1.0",  # Optional
                    "lastUpdated": "2024-01-01",  # Optional
                    "techniqueUriPattern": "https://example.com/{id}",  # Optional
                }
            ]
        }
        errors = validate_framework_consistency(data)
        assert errors == []


class TestIntegration:
    """Integration tests combining multiple validation functions"""

    def test_end_to_end_validation_success(self):
        """Test complete validation workflow with valid data"""
        frameworks_data = {
            "frameworks": [
                {
                    "id": "mitre-atlas",
                    "name": "MITRE ATLAS",
                    "fullName": "Framework",
                    "description": "Description",
                    "baseUri": "https://example.com",
                },
                {
                    "id": "stride",
                    "name": "STRIDE",
                    "fullName": "Framework",
                    "description": "Description",
                    "baseUri": "https://example.com",
                },
            ]
        }

        risks_data = {
            "risks": [
                {"id": "DP", "title": "Data Poisoning", "mappings": {"mitre-atlas": ["AML.T0020"]}},
                {"id": "MST", "title": "Model Tampering", "mappings": {"stride": ["tampering"]}},
            ]
        }

        controls_data = {
            "controls": [
                {"id": "controlTest", "title": "Test Control", "mappings": {"mitre-atlas": ["AML.M0007"]}}
            ]
        }

        # Validate consistency
        consistency_errors = validate_framework_consistency(frameworks_data)
        assert consistency_errors == []

        # Extract and validate references
        valid_frameworks = extract_framework_ids(frameworks_data)
        risk_frameworks = extract_risk_framework_references(risks_data)
        control_frameworks = extract_control_framework_references(controls_data)

        reference_errors = validate_framework_references(valid_frameworks, risk_frameworks, control_frameworks)
        assert reference_errors == []

    def test_end_to_end_validation_failure(self):
        """Test complete validation workflow with invalid data"""
        frameworks_data = {
            "frameworks": [
                {
                    "id": "mitre-atlas",
                    "name": "MITRE ATLAS",
                    "fullName": "Framework",
                    "description": "Description",
                    "baseUri": "https://example.com",
                }
            ]
        }

        risks_data = {
            "risks": [
                {
                    "id": "DP",
                    "title": "Data Poisoning",
                    "mappings": {"invalid-framework": ["technique1"]},  # Invalid framework
                }
            ]
        }

        controls_data = {"controls": []}

        # Extract and validate references
        valid_frameworks = extract_framework_ids(frameworks_data)
        risk_frameworks = extract_risk_framework_references(risks_data)
        control_frameworks = extract_control_framework_references(controls_data)

        reference_errors = validate_framework_references(valid_frameworks, risk_frameworks, control_frameworks)
        assert len(reference_errors) > 0
        assert any("invalid-framework" in error for error in reference_errors)

    def test_backward_compatibility_no_mappings(self):
        """Test that entries without mappings field still validate successfully"""
        frameworks_data = {
            "frameworks": [
                {
                    "id": "mitre-atlas",
                    "name": "MITRE ATLAS",
                    "fullName": "Framework",
                    "description": "Description",
                    "baseUri": "https://example.com",
                }
            ]
        }

        # Legacy data without mappings fields
        risks_data = {"risks": [{"id": "DP", "title": "Data Poisoning"}]}

        controls_data = {"controls": [{"id": "controlTest", "title": "Test Control"}]}

        # Validate consistency
        consistency_errors = validate_framework_consistency(frameworks_data)
        assert consistency_errors == []

        # Extract and validate references
        valid_frameworks = extract_framework_ids(frameworks_data)
        risk_frameworks = extract_risk_framework_references(risks_data)
        control_frameworks = extract_control_framework_references(controls_data)

        # Should have no references but validation should pass
        assert risk_frameworks == {}
        assert control_frameworks == {}

        reference_errors = validate_framework_references(valid_frameworks, risk_frameworks, control_frameworks)
        assert reference_errors == []


# ============================================================================
# CLI Integration Tests
# ============================================================================


class TestGetStagedYamlFiles:
    """Test get_staged_yaml_files() function for git integration and file detection"""

    def test_force_mode_returns_all_files_when_exist(self, tmp_path, monkeypatch):
        """
        Test force mode returns all target files when they exist.

        Given: All four target YAML files exist in the file system
        When: get_staged_yaml_files(force_check=True) is called
        Then: Returns list of all four target files
        """
        # Import the module to get access to the function
        from validate_framework_references import get_staged_yaml_files

        # Create temporary files
        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")
        (yaml_dir / "personas.yaml").write_text("personas: []")

        # Change to temporary directory
        monkeypatch.chdir(tmp_path)

        # Call function with force=True
        result = get_staged_yaml_files(force_check=True)

        # Verify all four files are returned
        assert len(result) == 4
        assert Path("risk-map/yaml/frameworks.yaml") in result
        assert Path("risk-map/yaml/risks.yaml") in result
        assert Path("risk-map/yaml/controls.yaml") in result
        assert Path("risk-map/yaml/personas.yaml") in result

    def test_force_mode_returns_empty_when_files_missing(self, tmp_path, monkeypatch):
        """
        Test force mode returns empty list when files are missing.

        Given: One or more target files do not exist
        When: get_staged_yaml_files(force_check=True) is called
        Then: Returns empty list
        """
        from validate_framework_references import get_staged_yaml_files

        # Create only partial files
        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")
        # Missing risks.yaml and controls.yaml

        # Change to temporary directory
        monkeypatch.chdir(tmp_path)

        # Call function with force=True
        result = get_staged_yaml_files(force_check=True)

        # Should return empty list when not all files exist
        assert result == []

    def test_force_mode_prints_warning_for_missing_files(self, tmp_path, monkeypatch, capsys):
        """
        Test force mode prints warning for missing files.

        Given: Target files do not exist
        When: get_staged_yaml_files(force_check=True) is called
        Then: Prints warning message listing missing files
        """
        from validate_framework_references import get_staged_yaml_files

        # Change to temporary directory with no YAML files
        monkeypatch.chdir(tmp_path)

        # Call function with force=True
        get_staged_yaml_files(force_check=True)

        # Verify warning was printed
        captured = capsys.readouterr()
        assert "⚠️" in captured.out
        assert "Target file(s) do not exist" in captured.out

    def test_git_mode_returns_files_when_frameworks_staged(self, monkeypatch, tmp_path):
        """
        Test git mode returns files when frameworks.yaml is staged.

        Given: frameworks.yaml is in staged files and all target files exist
        When: get_staged_yaml_files(force_check=False) is called
        Then: Returns all four target files
        """
        from unittest.mock import MagicMock

        from validate_framework_references import get_staged_yaml_files

        # Create all target files
        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")
        (yaml_dir / "personas.yaml").write_text("personas: []")

        monkeypatch.chdir(tmp_path)

        # Mock subprocess.run to simulate frameworks.yaml being staged
        import subprocess

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "risk-map/yaml/frameworks.yaml\n"

        def mock_run(*args, **kwargs):
            return mock_result

        monkeypatch.setattr(subprocess, "run", mock_run)

        # Call function without force
        result = get_staged_yaml_files(force_check=False)

        # Should return all target files
        assert len(result) == 4

    def test_git_mode_returns_files_when_risks_staged(self, monkeypatch, tmp_path):
        """
        Test git mode returns files when risks.yaml is staged.

        Given: risks.yaml is in staged files and all target files exist
        When: get_staged_yaml_files(force_check=False) is called
        Then: Returns all four target files
        """
        from unittest.mock import MagicMock

        from validate_framework_references import get_staged_yaml_files

        # Create all target files
        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")
        (yaml_dir / "personas.yaml").write_text("personas: []")

        monkeypatch.chdir(tmp_path)

        # Mock subprocess to simulate risks.yaml being staged
        import subprocess

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "risk-map/yaml/risks.yaml\n"

        def mock_run(*args, **kwargs):
            return mock_result

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = get_staged_yaml_files(force_check=False)
        assert len(result) == 4

    def test_git_mode_returns_files_when_controls_staged(self, monkeypatch, tmp_path):
        """
        Test git mode returns files when controls.yaml is staged.

        Given: controls.yaml is in staged files and all target files exist
        When: get_staged_yaml_files(force_check=False) is called
        Then: Returns all four target files
        """
        from unittest.mock import MagicMock

        from validate_framework_references import get_staged_yaml_files

        # Create all target files
        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")
        (yaml_dir / "personas.yaml").write_text("personas: []")

        monkeypatch.chdir(tmp_path)

        # Mock subprocess to simulate controls.yaml being staged
        import subprocess

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "risk-map/yaml/controls.yaml\n"

        def mock_run(*args, **kwargs):
            return mock_result

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = get_staged_yaml_files(force_check=False)
        assert len(result) == 4

    def test_git_mode_returns_empty_when_no_target_files_staged(self, monkeypatch):
        """
        Test git mode returns empty when no target files are staged.

        Given: No framework-related files are staged
        When: get_staged_yaml_files(force_check=False) is called
        Then: Returns empty list
        """
        # Mock subprocess to return non-target files
        import subprocess
        from unittest.mock import MagicMock

        from validate_framework_references import get_staged_yaml_files

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "other/file.txt\nREADME.md\n"

        def mock_run(*args, **kwargs):
            return mock_result

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = get_staged_yaml_files(force_check=False)
        assert result == []

    def test_git_subprocess_error_handling(self, monkeypatch, capsys):
        """
        Test git subprocess error handling.

        Given: Git command fails with CalledProcessError
        When: get_staged_yaml_files(force_check=False) is called
        Then: Returns empty list and prints error message
        """
        import subprocess

        from validate_framework_references import get_staged_yaml_files

        def mock_run_error(*args, **kwargs):
            raise subprocess.CalledProcessError(1, "git")

        monkeypatch.setattr(subprocess, "run", mock_run_error)

        result = get_staged_yaml_files(force_check=False)

        assert result == []
        captured = capsys.readouterr()
        assert "Error getting staged files" in captured.out


class TestLoadYamlFile:
    """Test load_yaml_file() function with error handling"""

    def test_load_valid_yaml_file(self, tmp_path):
        """
        Test loading a valid YAML file successfully.

        Given: A valid YAML file exists with proper content
        When: load_yaml_file() is called with the file path
        Then: Returns parsed YAML data as dictionary
        """
        from validate_framework_references import load_yaml_file

        # Create valid YAML file
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("key: value\nlist:\n  - item1\n  - item2\n")

        # Load the file
        result = load_yaml_file(yaml_file)

        # Verify content
        assert result is not None
        assert result["key"] == "value"
        assert result["list"] == ["item1", "item2"]

    def test_handle_yaml_error_for_malformed_yaml(self, tmp_path, capsys):
        """
        Test handling of yaml.YAMLError for malformed YAML.

        Given: A file with invalid YAML syntax
        When: load_yaml_file() is called
        Then: Returns None and prints error message
        """
        from validate_framework_references import load_yaml_file

        # Create malformed YAML file
        yaml_file = tmp_path / "invalid.yaml"
        yaml_file.write_text("invalid: yaml: content:: :\n  bad indentation\n")

        # Attempt to load
        result = load_yaml_file(yaml_file)

        # Verify error handling
        assert result is None
        captured = capsys.readouterr()
        assert "Error parsing YAML file" in captured.out
        assert str(yaml_file) in captured.out

    def test_handle_file_not_found_error(self, tmp_path, capsys):
        """
        Test handling of FileNotFoundError for missing file.

        Given: A file path that does not exist
        When: load_yaml_file() is called
        Then: Returns None and prints error message
        """
        from validate_framework_references import load_yaml_file

        # Use non-existent file path
        missing_file = tmp_path / "nonexistent.yaml"

        # Attempt to load
        result = load_yaml_file(missing_file)

        # Verify error handling
        assert result is None
        captured = capsys.readouterr()
        assert "File not found" in captured.out
        assert str(missing_file) in captured.out


class TestValidateFrameworks:
    """Test validate_frameworks() orchestration function"""

    def test_success_case_all_valid(self, tmp_path, monkeypatch, capsys):
        """
        Test successful validation with all valid data.

        Given: Valid frameworks, risks, and controls YAML files
        When: validate_frameworks() is called
        Then: Returns True and prints success message
        """
        from validate_framework_references import validate_frameworks

        # Create valid YAML files
        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)

        (yaml_dir / "frameworks.yaml").write_text(
            """
frameworks:
  - id: mitre-atlas
    name: MITRE ATLAS
    fullName: Framework
    description: Test
    baseUri: https://example.com
"""
        )
        (yaml_dir / "risks.yaml").write_text(
            """
risks:
  - id: DP
    title: Data Poisoning
    mappings:
      mitre-atlas:
        - AML.T0020
"""
        )
        (yaml_dir / "controls.yaml").write_text(
            """
controls:
  - id: controlTest
    title: Test Control
    mappings:
      mitre-atlas:
        - AML.M0001
"""
        )

        monkeypatch.chdir(tmp_path)

        file_paths = [
            Path("risk-map/yaml/frameworks.yaml"),
            Path("risk-map/yaml/risks.yaml"),
            Path("risk-map/yaml/controls.yaml"),
        ]

        result = validate_frameworks(file_paths)

        assert result is True
        captured = capsys.readouterr()
        assert "✅ Framework references and applicability are consistent" in captured.out
        assert "mitre-atlas" in captured.out

    def test_failure_frameworks_yaml_load_error(self, tmp_path, monkeypatch, capsys):
        """
        Test failure when frameworks.yaml fails to load.

        Given: frameworks.yaml does not exist or is invalid
        When: validate_frameworks() is called
        Then: Returns False and prints error message
        """
        from validate_framework_references import validate_frameworks

        # Create directory without frameworks.yaml
        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")

        monkeypatch.chdir(tmp_path)

        file_paths = [
            Path("risk-map/yaml/frameworks.yaml"),
            Path("risk-map/yaml/risks.yaml"),
            Path("risk-map/yaml/controls.yaml"),
        ]

        result = validate_frameworks(file_paths)

        assert result is False
        captured = capsys.readouterr()
        assert "❌" in captured.out
        assert "could not load frameworks.yaml" in captured.out

    def test_failure_risks_yaml_load_error(self, tmp_path, monkeypatch, capsys):
        """
        Test failure when risks.yaml fails to load.

        Given: risks.yaml does not exist or is invalid
        When: validate_frameworks() is called
        Then: Returns False and prints error message
        """
        from validate_framework_references import validate_frameworks

        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")

        monkeypatch.chdir(tmp_path)

        file_paths = [
            Path("risk-map/yaml/frameworks.yaml"),
            Path("risk-map/yaml/risks.yaml"),
            Path("risk-map/yaml/controls.yaml"),
        ]

        result = validate_frameworks(file_paths)

        assert result is False
        captured = capsys.readouterr()
        assert "❌" in captured.out
        assert "could not load risks.yaml" in captured.out

    def test_failure_controls_yaml_load_error(self, tmp_path, monkeypatch, capsys):
        """
        Test failure when controls.yaml fails to load.

        Given: controls.yaml does not exist or is invalid
        When: validate_frameworks() is called
        Then: Returns False and prints error message
        """
        from validate_framework_references import validate_frameworks

        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []")
        (yaml_dir / "risks.yaml").write_text("risks: []")

        monkeypatch.chdir(tmp_path)

        file_paths = [
            Path("risk-map/yaml/frameworks.yaml"),
            Path("risk-map/yaml/risks.yaml"),
            Path("risk-map/yaml/controls.yaml"),
        ]

        result = validate_frameworks(file_paths)

        assert result is False
        captured = capsys.readouterr()
        assert "❌" in captured.out
        assert "could not load controls.yaml" in captured.out

    def test_success_with_empty_frameworks(self, tmp_path, monkeypatch, capsys):
        """
        Test success with empty frameworks (skip validation).

        Given: frameworks.yaml has no frameworks defined
        When: validate_frameworks() is called
        Then: Returns True and skips reference validation
        """
        from validate_framework_references import validate_frameworks

        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text("frameworks: []\n")
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")

        monkeypatch.chdir(tmp_path)

        file_paths = [
            Path("risk-map/yaml/frameworks.yaml"),
            Path("risk-map/yaml/risks.yaml"),
            Path("risk-map/yaml/controls.yaml"),
        ]

        result = validate_frameworks(file_paths)

        assert result is True
        captured = capsys.readouterr()
        assert "No frameworks found" in captured.out
        assert "skipping reference validation" in captured.out

    def test_failure_consistency_errors(self, tmp_path, monkeypatch, capsys):
        """
        Test failure when consistency errors are found.

        Given: Framework definitions have consistency errors
        When: validate_frameworks() is called
        Then: Returns False and reports consistency errors
        """
        from validate_framework_references import validate_frameworks

        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)

        # Missing required fields
        (yaml_dir / "frameworks.yaml").write_text(
            """
frameworks:
  - id: mitre-atlas
    name: MITRE ATLAS
    # Missing fullName, description, baseUri
"""
        )
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")

        monkeypatch.chdir(tmp_path)

        file_paths = [
            Path("risk-map/yaml/frameworks.yaml"),
            Path("risk-map/yaml/risks.yaml"),
            Path("risk-map/yaml/controls.yaml"),
        ]

        result = validate_frameworks(file_paths)

        assert result is False
        captured = capsys.readouterr()
        assert "❌" in captured.out
        assert "consistency errors" in captured.out

    def test_failure_reference_errors(self, tmp_path, monkeypatch, capsys):
        """
        Test failure when reference errors are found.

        Given: Risks or controls reference non-existent frameworks
        When: validate_frameworks() is called
        Then: Returns False and reports reference errors
        """
        from validate_framework_references import validate_frameworks

        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)

        (yaml_dir / "frameworks.yaml").write_text(
            """
frameworks:
  - id: mitre-atlas
    name: MITRE ATLAS
    fullName: Framework
    description: Test
    baseUri: https://example.com
"""
        )
        (yaml_dir / "risks.yaml").write_text(
            """
risks:
  - id: DP
    title: Data Poisoning
    mappings:
      invalid-framework:
        - technique1
"""
        )
        (yaml_dir / "controls.yaml").write_text("controls: []")

        monkeypatch.chdir(tmp_path)

        file_paths = [
            Path("risk-map/yaml/frameworks.yaml"),
            Path("risk-map/yaml/risks.yaml"),
            Path("risk-map/yaml/controls.yaml"),
        ]

        result = validate_frameworks(file_paths)

        assert result is False
        captured = capsys.readouterr()
        assert "❌" in captured.out
        assert "reference errors" in captured.out
        assert "invalid-framework" in captured.out

    def test_failure_both_consistency_and_reference_errors(self, tmp_path, monkeypatch, capsys):
        """
        Test failure when both consistency and reference errors exist.

        Given: Both consistency errors and reference errors exist
        When: validate_frameworks() is called
        Then: Returns False and reports both types of errors
        """
        from validate_framework_references import validate_frameworks

        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)

        # Missing required field (consistency error)
        (yaml_dir / "frameworks.yaml").write_text(
            """
frameworks:
  - id: mitre-atlas
    name: MITRE ATLAS
    fullName: Framework
    # Missing description and baseUri
"""
        )
        # Invalid reference (reference error)
        (yaml_dir / "risks.yaml").write_text(
            """
risks:
  - id: DP
    title: Data Poisoning
    mappings:
      nonexistent:
        - tech1
"""
        )
        (yaml_dir / "controls.yaml").write_text("controls: []")

        monkeypatch.chdir(tmp_path)

        file_paths = [
            Path("risk-map/yaml/frameworks.yaml"),
            Path("risk-map/yaml/risks.yaml"),
            Path("risk-map/yaml/controls.yaml"),
        ]

        result = validate_frameworks(file_paths)

        assert result is False
        captured = capsys.readouterr()
        assert "consistency errors" in captured.out
        assert "reference errors" in captured.out


class TestParseArgs:
    """Test parse_args() CLI argument parsing"""

    def test_default_arguments(self, monkeypatch):
        """
        Test default argument parsing (no --force).

        Given: No command line arguments provided
        When: parse_args() is called
        Then: Returns args with force=False
        """
        from validate_framework_references import parse_args

        monkeypatch.setattr(sys, "argv", ["script.py"])

        args = parse_args()

        assert args.force is False

    def test_force_flag_long_form(self, monkeypatch):
        """
        Test --force flag sets force=True.

        Given: --force flag is provided
        When: parse_args() is called
        Then: Returns args with force=True
        """
        from validate_framework_references import parse_args

        monkeypatch.setattr(sys, "argv", ["script.py", "--force"])

        args = parse_args()

        assert args.force is True

    def test_force_flag_short_form(self, monkeypatch):
        """
        Test -f short form sets force=True.

        Given: -f flag is provided
        When: parse_args() is called
        Then: Returns args with force=True
        """
        from validate_framework_references import parse_args

        monkeypatch.setattr(sys, "argv", ["script.py", "-f"])

        args = parse_args()

        assert args.force is True


class TestMain:
    """Test main() function orchestration and exit codes"""

    def test_exit_0_when_no_files_staged(self, monkeypatch, capsys):
        """
        Test exit code 0 when no files are staged.

        Given: No framework-related files are staged
        When: main() is called
        Then: Exits with code 0
        """
        import subprocess
        from unittest.mock import MagicMock

        from validate_framework_references import main

        # Mock subprocess to return no staged files
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        def mock_run(*args, **kwargs):
            return mock_result

        monkeypatch.setattr(subprocess, "run", mock_run)
        monkeypatch.setattr(sys, "argv", ["script.py"])

        # main() calls sys.exit(), so we catch SystemExit
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "No framework-related YAML files modified" in captured.out

    def test_exit_0_when_validation_succeeds(self, monkeypatch, tmp_path, capsys):
        """
        Test exit code 0 when validation succeeds.

        Given: Valid framework files are staged
        When: main() is called
        Then: Exits with code 0
        """
        from validate_framework_references import main

        # Create valid YAML files
        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)

        (yaml_dir / "frameworks.yaml").write_text(
            """
frameworks:
  - id: test-framework
    name: Test
    fullName: Test Framework
    description: Test description
    baseUri: https://example.com
    applicableTo:
      - controls
"""
        )
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")
        (yaml_dir / "personas.yaml").write_text("personas: []")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["script.py", "--force"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "✅" in captured.out
        assert "validation passed" in captured.out

    def test_exit_1_when_validation_fails(self, monkeypatch, tmp_path, capsys):
        """
        Test exit code 1 when validation fails.

        Given: Invalid framework files are staged
        When: main() is called
        Then: Exits with code 1
        """
        from validate_framework_references import main

        # Create invalid YAML files
        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)

        (yaml_dir / "frameworks.yaml").write_text(
            """
frameworks:
  - id: test-framework
    name: Test
    # Missing required fields
"""
        )
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")
        (yaml_dir / "personas.yaml").write_text("personas: []")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["script.py", "--force"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "❌" in captured.out
        assert "validation failed" in captured.out

    def test_force_mode_message_output(self, monkeypatch, capsys):
        """
        Test force mode prints appropriate message.

        Given: --force flag is used
        When: main() is called
        Then: Prints force mode message
        """
        import subprocess
        from unittest.mock import MagicMock

        from validate_framework_references import main

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        def mock_run(*args, **kwargs):
            return mock_result

        monkeypatch.setattr(subprocess, "run", mock_run)
        monkeypatch.setattr(sys, "argv", ["script.py", "--force"])

        with pytest.raises(SystemExit):
            main()

        captured = capsys.readouterr()
        assert "Force checking framework references" in captured.out

    def test_normal_mode_message_output(self, monkeypatch, capsys):
        """
        Test normal mode prints appropriate message.

        Given: No --force flag is used
        When: main() is called
        Then: Prints normal checking message
        """
        import subprocess
        from unittest.mock import MagicMock

        from validate_framework_references import main

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        def mock_run(*args, **kwargs):
            return mock_result

        monkeypatch.setattr(subprocess, "run", mock_run)
        monkeypatch.setattr(sys, "argv", ["script.py"])

        with pytest.raises(SystemExit):
            main()

        captured = capsys.readouterr()
        assert "Checking for framework-related YAML file changes" in captured.out

    def test_success_message_and_exit_code(self, monkeypatch, tmp_path):
        """
        Test success message and exit code together.

        Given: Validation passes
        When: main() exits
        Then: Prints success message and exits with 0
        """
        from validate_framework_references import main

        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        (yaml_dir / "frameworks.yaml").write_text(
            """
frameworks:
  - id: test
    name: Test
    fullName: Test
    description: Test
    baseUri: https://example.com
    applicableTo:
      - controls
"""
        )
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")
        (yaml_dir / "personas.yaml").write_text("personas: []")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["script.py", "-f"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0

    def test_failure_message_and_exit_code(self, monkeypatch, tmp_path):
        """
        Test failure message and exit code together.

        Given: Validation fails
        When: main() exits
        Then: Prints failure message and exits with 1
        """
        from validate_framework_references import main

        yaml_dir = tmp_path / "risk-map" / "yaml"
        yaml_dir.mkdir(parents=True)
        # Invalid framework missing required fields
        (yaml_dir / "frameworks.yaml").write_text("frameworks:\n  - id: test\n")
        (yaml_dir / "risks.yaml").write_text("risks: []")
        (yaml_dir / "controls.yaml").write_text("controls: []")
        (yaml_dir / "personas.yaml").write_text("personas: []")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["script.py", "-f"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
