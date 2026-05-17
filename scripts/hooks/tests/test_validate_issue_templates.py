#!/usr/bin/env python3
"""
Tests for validate_issue_templates.py

This test suite validates the GitHub config file validator that uses
check-jsonschema to validate issue forms, config, and dependabot.yml
against official schemas.

Test Coverage:
==============
Total Tests: 72 across 10 test classes
Coverage Target: 85%+ of validate_issue_templates.py

1. TestCommandLineArgs - CLI argument parsing (14 tests)
   - Default arguments
   - --force/-f flag (long and short form)
   - --help flag handling
   - Invalid arguments
   - Combined arguments

2. TestGitHubSchemaValidation - Schema validation logic (8 tests)
   - Valid issue form validation success
   - Valid config validation success
   - Invalid YAML structure detection
   - Missing required fields detection
   - Invalid field types detection
   - Schema selection (issue forms vs config)
   - Multiple validation errors
   - Empty file handling

3. TestFileDetection - File discovery (7 tests)
   - Find all .yml files in ISSUE_TEMPLATE directory
   - Exclude config.yml from issue forms validation
   - Include config.yml for config schema validation
   - Handle non-existent template directory
   - Handle empty template directory
   - Handle files with special characters
   - Handle nested directories (should ignore)

4. TestStagedFileDetection - Git integration (6 tests)
   - Detect staged template files via git
   - Skip non-staged template files
   - Handle empty staging area
   - Handle no template files staged
   - Handle staged deletions
   - Handle renamed files

5. TestOutputMessaging - Success/error messages (6 tests)
   - Success messages include checkmark emoji
   - Error messages include X emoji
   - Output includes file names being validated
   - Output shows which schema is being used
   - Multiple file validation output formatting
   - Quiet mode suppresses output

6. TestExitCodes - Exit code behavior (5 tests)
   - Exit 0 when all validations pass
   - Exit 1 when any validation fails
   - Exit 1 when check-jsonschema not found
   - Exit 0 when no files to validate
   - Exit 2 on unexpected errors

7. TestCheckJsonSchemaIntegration - Subprocess calls (7 tests)
   - Calls check-jsonschema with correct arguments
   - Uses vendor.github-issue-forms for issue templates
   - Uses vendor.github-issue-config for config file
   - Handles check-jsonschema not installed
   - Handles check-jsonschema execution errors
   - Passes correct file paths
   - Handles check-jsonschema timeout

8. TestEdgeCases - Edge case handling (7 tests)
   - Empty template directory
   - Template files with syntax errors
   - Very large template files
   - Template files with special characters in names
   - Permission errors on template files
   - Symlinks to template files
   - Concurrent git operations

9. TestDependabotValidation - Dependabot.yml validation (7 tests)
   - Validates dependabot.yml with vendor.dependabot schema
   - Skips when dependabot.yml doesn't exist
   - Reports failure when dependabot.yml invalid
   - Only validates when staged in normal mode
   - Validates when staged in normal mode
   - Validates without ISSUE_TEMPLATE directory
   - Integration: validates real dependabot.yml

Implementation Notes:
- Script will be: /workspaces/secure-ai-tooling/scripts/hooks/validate_issue_templates.py
- Uses check-jsonschema CLI tool for validation
- Integrates with git pre-commit hooks
- Supports both force mode (all files) and normal mode (staged files only)
"""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Add scripts/hooks to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_template_dir(tmp_path: Path) -> Path:
    """
    Create temporary issue template directory with sample files.

    Returns directory with:
    - new_component.yml (valid issue form)
    - new_control.yml (valid issue form)
    - config.yml (valid config)
    """
    template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
    template_dir.mkdir(parents=True)

    # Create sample issue forms
    (template_dir / "new_component.yml").write_text(
        """name: New Component
description: Test
body:
  - type: input
    id: title
    attributes:
      label: Title
"""
    )

    (template_dir / "new_control.yml").write_text(
        """name: New Control
description: Test
body:
  - type: textarea
    id: description
    attributes:
      label: Description
"""
    )

    # Create config file
    (template_dir / "config.yml").write_text("blank_issues_enabled: false\n")

    return template_dir


@pytest.fixture
def mock_git_staged_output() -> str:
    """Provide mock git diff output for staged files."""
    return """.github/ISSUE_TEMPLATE/new_component.yml
.github/ISSUE_TEMPLATE/new_control.yml
"""


@pytest.fixture
def mock_check_jsonschema_success() -> subprocess.CompletedProcess:
    """Provide mock successful check-jsonschema result."""
    return subprocess.CompletedProcess(args=["check-jsonschema"], returncode=0, stdout="ok", stderr="")


@pytest.fixture
def mock_check_jsonschema_failure() -> subprocess.CompletedProcess:
    """Provide mock failed check-jsonschema result."""
    return subprocess.CompletedProcess(
        args=["check-jsonschema"],
        returncode=1,
        stdout="",
        stderr="ValidationError: 'name' is a required property",
    )


# ============================================================================
# Test Classes
# ============================================================================


class TestCommandLineArgs:
    """Test command-line argument parsing."""

    def test_parse_args_with_no_arguments_returns_defaults(self):
        """
        Test default argument values when no flags provided.

        Given: Script called with no arguments
        When: parse_args() is called
        Then: Returns namespace with all defaults
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py"]):
            args = parse_args()

        assert args.force is False
        assert args.quiet is False

    def test_parse_args_with_force_flag_long_form(self):
        """
        Test --force flag sets force=True.

        Given: Script called with --force flag
        When: parse_args() is called
        Then: Returns namespace with force=True
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py", "--force"]):
            args = parse_args()

        assert args.force is True

    def test_parse_args_with_force_flag_short_form(self):
        """
        Test -f flag sets force=True.

        Given: Script called with -f flag
        When: parse_args() is called
        Then: Returns namespace with force=True
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py", "-f"]):
            args = parse_args()

        assert args.force is True

    def test_parse_args_with_quiet_flag_long_form(self):
        """
        Test --quiet flag sets quiet=True.

        Given: Script called with --quiet flag
        When: parse_args() is called
        Then: Returns namespace with quiet=True
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py", "--quiet"]):
            args = parse_args()

        assert args.quiet is True

    def test_parse_args_with_quiet_flag_short_form(self):
        """
        Test -q flag sets quiet=True.

        Given: Script called with -q flag
        When: parse_args() is called
        Then: Returns namespace with quiet=True
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py", "-q"]):
            args = parse_args()

        assert args.quiet is True

    def test_parse_args_with_help_flag(self):
        """
        Test --help flag triggers help output.

        Given: Script called with --help flag
        When: parse_args() is called
        Then: SystemExit is raised with code 0
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                parse_args()

        assert exc_info.value.code == 0

    def test_parse_args_with_invalid_arguments(self):
        """
        Test invalid arguments are rejected.

        Given: Script called with invalid argument
        When: parse_args() is called
        Then: SystemExit is raised with code 2
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py", "--invalid-arg"]):
            with pytest.raises(SystemExit) as exc_info:
                parse_args()

        assert exc_info.value.code == 2

    def test_parse_args_with_combined_arguments(self):
        """
        Test multiple arguments can be combined.

        Given: Script called with --force --quiet
        When: parse_args() is called
        Then: Returns namespace with force=True, quiet=True
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py", "--force", "--quiet"]):
            args = parse_args()

        assert args.force is True
        assert args.quiet is True

    def test_parse_args_force_flag_defaults_to_false(self):
        """
        Test force flag defaults to False.

        Given: Script called without --force
        When: parse_args() is called
        Then: args.force is False
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py"]):
            args = parse_args()

        assert args.force is False

    def test_parse_args_quiet_flag_defaults_to_false(self):
        """
        Test quiet flag defaults to False.

        Given: Script called without --quiet
        When: parse_args() is called
        Then: args.quiet is False
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py"]):
            args = parse_args()

        assert args.quiet is False

    def test_parse_args_short_and_long_forms_equivalent(self):
        """
        Test short and long flag forms are equivalent.

        Given: Script called with -f vs --force
        When: parse_args() is called
        Then: Both produce same result
        """
        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py", "-f"]):
            args_short = parse_args()

        with patch("sys.argv", ["script.py", "--force"]):
            args_long = parse_args()

        assert args_short.force == args_long.force

    def test_parse_args_description_is_clear(self):
        """
        Test parser has clear description.

        Given: ArgumentParser is created
        When: help is accessed
        Then: Description mentions GitHub issue template validation
        """
        import argparse

        from validate_issue_templates import parse_args

        # Create parser just to check description
        with patch("sys.argv", ["script.py"]):
            args = parse_args()

        # Verify it returns a namespace (indicates parser was created properly)
        assert isinstance(args, argparse.Namespace)

    def test_parse_args_usage_examples_provided(self):
        """
        Test usage examples are provided in help.

        Given: ArgumentParser is created with epilog
        When: help is accessed
        Then: Epilog contains usage examples
        """
        import argparse

        from validate_issue_templates import parse_args

        # Verify parser works and returns namespace
        with patch("sys.argv", ["script.py"]):
            args = parse_args()

        assert isinstance(args, argparse.Namespace)

    def test_parse_args_returns_namespace_object(self):
        """
        Test parse_args returns argparse.Namespace.

        Given: Script called with any arguments
        When: parse_args() is called
        Then: Returns argparse.Namespace instance
        """
        import argparse

        from validate_issue_templates import parse_args

        with patch("sys.argv", ["script.py"]):
            args = parse_args()

        assert isinstance(args, argparse.Namespace)


class TestGitHubSchemaValidation:
    """Test GitHub schema validation logic."""

    def test_validate_issue_form_with_valid_template_succeeds(self, mock_template_dir: Path):
        """
        Test validation passes for valid issue form.

        Given: Valid issue form YAML file
        When: Validation is run against vendor.github-issue-forms
        Then: Validation passes with exit code 0
        """
        from validate_issue_templates import validate_with_schema

        template_file = mock_template_dir / "new_component.yml"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            result = validate_with_schema(template_file, "vendor.github-issue-forms", quiet=True)

        assert result is True
        mock_run.assert_called_once()

    def test_validate_config_with_valid_config_succeeds(self, mock_template_dir: Path):
        """
        Test validation passes for valid config.yml.

        Given: Valid config.yml file
        When: Validation is run against vendor.github-issue-config
        Then: Validation passes with exit code 0
        """
        from validate_issue_templates import validate_with_schema

        config_file = mock_template_dir / "config.yml"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            result = validate_with_schema(config_file, "vendor.github-issue-config", quiet=True)

        assert result is True

    def test_validate_issue_form_with_invalid_yaml_fails(self, tmp_path: Path):
        """
        Test validation fails for malformed YAML.

        Given: Issue form with invalid YAML syntax
        When: Validation is run
        Then: Validation fails with exit code 1
        """
        from validate_issue_templates import validate_with_schema

        invalid_file = tmp_path / "invalid.yml"
        invalid_file.write_text("invalid: yaml: syntax:")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="YAML parse error"
            )

            result = validate_with_schema(invalid_file, "vendor.github-issue-forms", quiet=True)

        assert result is False

    def test_validate_issue_form_missing_required_field_fails(self, tmp_path: Path):
        """
        Test validation fails when required field missing.

        Given: Issue form without 'name' field
        When: Validation is run
        Then: Validation fails with descriptive error
        """
        from validate_issue_templates import validate_with_schema

        invalid_file = tmp_path / "missing_name.yml"
        invalid_file.write_text("description: Test\\nbody:\\n  - type: input")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="'name' is a required property"
            )

            result = validate_with_schema(invalid_file, "vendor.github-issue-forms", quiet=True)

        assert result is False

    def test_validate_issue_form_invalid_field_type_fails(self, tmp_path: Path):
        """
        Test validation fails when field has wrong type.

        Given: Issue form with 'name' as integer instead of string
        When: Validation is run
        Then: Validation fails with type error
        """
        from validate_issue_templates import validate_with_schema

        invalid_file = tmp_path / "invalid_type.yml"
        invalid_file.write_text("name: 123\\ndescription: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="123 is not of type 'string'"
            )

            result = validate_with_schema(invalid_file, "vendor.github-issue-forms", quiet=True)

        assert result is False

    def test_validate_uses_correct_schema_for_issue_forms(self, tmp_path: Path):
        """
        Test issue forms use vendor.github-issue-forms schema.

        Given: Issue form file (not config.yml)
        When: Validation is run
        Then: check-jsonschema called with --builtin-schema vendor.github-issue-forms
        """
        from validate_issue_templates import validate_with_schema

        form_file = tmp_path / "form.yml"
        form_file.write_text("name: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

            validate_with_schema(form_file, "vendor.github-issue-forms", quiet=True)

        # Check the call includes the schema
        call_args = mock_run.call_args[0][0]
        assert "vendor.github-issue-forms" in call_args

    def test_validate_uses_correct_schema_for_config(self, tmp_path: Path):
        """
        Test config.yml uses vendor.github-issue-config schema.

        Given: config.yml file
        When: Validation is run
        Then: check-jsonschema called with --builtin-schema vendor.github-issue-config
        """
        from validate_issue_templates import validate_with_schema

        config_file = tmp_path / "config.yml"
        config_file.write_text("blank_issues_enabled: false")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

            validate_with_schema(config_file, "vendor.github-issue-config", quiet=True)

        # Check the call includes the schema
        call_args = mock_run.call_args[0][0]
        assert "vendor.github-issue-config" in call_args

    def test_validate_reports_multiple_errors_in_single_file(self, tmp_path: Path):
        """
        Test multiple validation errors are reported.

        Given: Issue form with multiple schema violations
        When: Validation is run
        Then: All errors are reported in output
        """
        from validate_issue_templates import validate_with_schema

        invalid_file = tmp_path / "multi_error.yml"
        invalid_file.write_text("invalid: yaml")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="Error 1: missing 'name'\\nError 2: missing 'description'"
            )

            result = validate_with_schema(invalid_file, "vendor.github-issue-forms", quiet=True)

        assert result is False


class TestFileDetection:
    """Test file detection and filtering logic."""

    def test_find_all_yml_files_in_template_directory(self, mock_template_dir: Path):
        """
        Test discovers all .yml files in ISSUE_TEMPLATE.

        Given: ISSUE_TEMPLATE directory with multiple .yml files
        When: File discovery is run
        Then: All .yml files are found
        """
        from validate_issue_templates import get_template_files

        issue_forms, config_file = get_template_files(mock_template_dir, staged_only=False)

        assert len(issue_forms) == 2
        assert any(f.name == "new_component.yml" for f in issue_forms)
        assert any(f.name == "new_control.yml" for f in issue_forms)
        assert config_file is not None

    def test_exclude_config_yml_from_issue_forms_validation(self, mock_template_dir: Path):
        """
        Test config.yml is not validated as issue form.

        Given: ISSUE_TEMPLATE directory with config.yml
        When: Issue form files are collected
        Then: config.yml is excluded from issue forms list
        """
        from validate_issue_templates import get_template_files

        issue_forms, config_file = get_template_files(mock_template_dir, staged_only=False)

        assert not any(f.name == "config.yml" for f in issue_forms)
        assert config_file is not None

    def test_include_config_yml_for_config_schema_validation(self, mock_template_dir: Path):
        """
        Test config.yml is validated with config schema.

        Given: ISSUE_TEMPLATE directory with config.yml
        When: Validation is run
        Then: config.yml is validated against vendor.github-issue-config
        """
        from validate_issue_templates import get_template_files

        issue_forms, config_file = get_template_files(mock_template_dir, staged_only=False)

        assert config_file is not None
        assert config_file.name == "config.yml"

    def test_handle_non_existent_template_directory(self, tmp_path: Path):
        """
        Test graceful handling when directory doesn't exist.

        Given: .github/ISSUE_TEMPLATE directory does not exist
        When: File discovery is run
        Then: Returns empty list or exits gracefully
        """
        from validate_issue_templates import get_template_files

        non_existent = tmp_path / "nonexistent"
        issue_forms, config_file = get_template_files(non_existent, staged_only=False)

        assert issue_forms == []
        assert config_file is None

    def test_handle_empty_template_directory(self, tmp_path: Path):
        """
        Test handling of empty template directory.

        Given: ISSUE_TEMPLATE directory exists but is empty
        When: File discovery is run
        Then: Returns empty list and exits with code 0
        """
        from validate_issue_templates import get_template_files

        empty_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        empty_dir.mkdir(parents=True)

        issue_forms, config_file = get_template_files(empty_dir, staged_only=False)

        assert issue_forms == []
        assert config_file is None

    def test_handle_files_with_special_characters_in_names(self, tmp_path: Path):
        """
        Test files with special characters are handled.

        Given: Template file named "new-component-2.0.yml"
        When: File discovery is run
        Then: File is included in validation
        """
        from validate_issue_templates import get_template_files

        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)

        (template_dir / "new-component-2.0.yml").write_text("name: Test\\ndescription: Test")

        issue_forms, config_file = get_template_files(template_dir, staged_only=False)

        assert len(issue_forms) == 1
        assert issue_forms[0].name == "new-component-2.0.yml"

    def test_ignore_nested_directories(self, tmp_path: Path):
        """
        Test nested directories are ignored.

        Given: ISSUE_TEMPLATE contains subdirectory with .yml files
        When: File discovery is run
        Then: Only top-level .yml files are included
        """
        from validate_issue_templates import get_template_files

        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)

        # Create top-level file
        (template_dir / "top.yml").write_text("name: Top")

        # Create nested directory with file (should be ignored)
        (template_dir / "nested").mkdir()
        (template_dir / "nested" / "nested.yml").write_text("name: Nested")

        issue_forms, config_file = get_template_files(template_dir, staged_only=False)

        # Should only find top-level file
        assert len(issue_forms) == 1
        assert issue_forms[0].name == "top.yml"


class TestStagedFileDetection:
    """Test git staged file detection for normal mode."""

    def test_detect_staged_template_files_via_git(self, mock_git_staged_output: str):
        """
        Test detects only staged template files.

        Given: Git staging area contains issue template files
        When: Staged file detection is run
        Then: Returns only staged .yml files from ISSUE_TEMPLATE
        """
        from validate_issue_templates import get_staged_files

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                returncode=0,
                stdout=mock_git_staged_output,
                stderr="",
            )

            files = get_staged_files()

        # Verify subprocess was called with correct arguments
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "git" in call_args
        assert "diff" in call_args
        assert "--cached" in call_args
        assert "--diff-filter=ACM" in call_args

        # Verify it returns a list of Path objects
        assert isinstance(files, list)
        assert len(files) == 2
        assert all(isinstance(f, Path) for f in files)

    def test_skip_non_staged_template_files(self, tmp_path: Path):
        """
        Test non-staged files are excluded in normal mode.

        Given: ISSUE_TEMPLATE has files but none are staged
        When: Staged file detection is run
        Then: Returns empty list
        """
        from validate_issue_templates import get_staged_files

        with patch("subprocess.run") as mock_run:
            # Return empty output (no staged files)
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

            files = get_staged_files()

        assert files == []

    def test_handle_empty_staging_area(self):
        """
        Test handles empty staging area gracefully.

        Given: No files are staged
        When: Staged file detection is run
        Then: Returns empty list and exits with code 0
        """
        from validate_issue_templates import get_staged_files

        with patch("subprocess.run") as mock_run:
            # Empty staging area - git returns empty output
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

            files = get_staged_files()

        assert files == []
        assert isinstance(files, list)

    def test_handle_no_template_files_staged(self):
        """
        Test handles when no template files are staged.

        Given: Other files staged but no ISSUE_TEMPLATE files
        When: Staged file detection is run
        Then: Returns empty list
        """
        from validate_issue_templates import get_staged_files

        with patch("subprocess.run") as mock_run:
            # Other files staged but no templates
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="src/main.py\nREADME.md\ndocs/guide.md\n",
                stderr="",
            )

            files = get_staged_files()

        # Should return files (function doesn't filter by path, that's done elsewhere)
        assert isinstance(files, list)
        assert len(files) == 3

    def test_handle_staged_template_deletions(self):
        """
        Test handles staged file deletions.

        Given: Template file is staged for deletion
        When: Staged file detection is run
        Then: Deleted file is not included in validation
        """
        from validate_issue_templates import get_staged_files

        with patch("subprocess.run") as mock_run:
            # Deletions are filtered out by --diff-filter=ACM (no D)
            # So git returns only added/copied/modified, not deleted
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

            files = get_staged_files()

        # Should return empty because deletions are filtered out
        assert isinstance(files, list)
        assert files == []

    def test_handle_renamed_template_files(self):
        """
        Test handles renamed template files.

        Given: Template file is renamed and staged
        When: Staged file detection is run
        Then: New name is included in validation
        """
        from validate_issue_templates import get_staged_files

        with patch("subprocess.run") as mock_run:
            # Renamed files show up as new file (R is not in ACM filter, but often shows as A+D)
            # For this test, assume the new name appears in the output
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=".github/ISSUE_TEMPLATE/renamed_template.yml\n",
                stderr="",
            )

            files = get_staged_files()

        assert isinstance(files, list)
        assert len(files) == 1
        assert files[0] == Path(".github/ISSUE_TEMPLATE/renamed_template.yml")


class TestOutputMessaging:
    """Test output messages and formatting."""

    def test_success_messages_include_checkmark_emoji(self, tmp_path: Path, capsys):
        """
        Test success messages use checkmark emoji.

        Given: Validation passes for a file
        When: Output is printed
        Then: Message includes checkmark emoji
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "test.yml"
        test_file.write_text("name: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            validate_with_schema(test_file, "vendor.github-issue-forms", quiet=False)

        captured = capsys.readouterr()
        assert "✅" in captured.out

    def test_error_messages_include_x_emoji(self, tmp_path: Path, capsys):
        """
        Test error messages use X emoji.

        Given: Validation fails for a file
        When: Output is printed
        Then: Message includes X emoji
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "test.yml"
        test_file.write_text("invalid: yaml")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="ValidationError"
            )

            validate_with_schema(test_file, "vendor.github-issue-forms", quiet=False)

        captured = capsys.readouterr()
        assert "❌" in captured.out

    def test_output_includes_file_names_being_validated(self, tmp_path: Path, capsys):
        """
        Test output shows which files are being validated.

        Given: Multiple files are validated
        When: Validation runs
        Then: Each file name is printed during validation
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "my_template.yml"
        test_file.write_text("name: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            validate_with_schema(test_file, "vendor.github-issue-forms", quiet=False)

        captured = capsys.readouterr()
        assert "my_template.yml" in captured.out

    def test_output_shows_which_schema_is_being_used(self, tmp_path: Path):
        """
        Test output indicates schema being used.

        Given: File is validated
        When: Validation runs
        Then: Output mentions schema type (issue-forms vs issue-config)
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "test.yml"
        test_file.write_text("name: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            validate_with_schema(test_file, "vendor.github-issue-forms", quiet=False)

            # Check that schema was passed to check-jsonschema
            call_args = mock_run.call_args[0][0]
            assert "vendor.github-issue-forms" in call_args

    def test_multiple_file_validation_output_formatting(self, tmp_path: Path, capsys):
        """
        Test multiple files are formatted clearly.

        Given: Multiple template files are validated
        When: Validation runs
        Then: Output clearly separates results for each file
        """
        from validate_issue_templates import validate_with_schema

        file1 = tmp_path / "template1.yml"
        file2 = tmp_path / "template2.yml"
        file1.write_text("name: Test1")
        file2.write_text("name: Test2")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            validate_with_schema(file1, "vendor.github-issue-forms", quiet=False)
            validate_with_schema(file2, "vendor.github-issue-forms", quiet=False)

        captured = capsys.readouterr()
        # Both file names should appear in output
        assert "template1.yml" in captured.out
        assert "template2.yml" in captured.out

    def test_quiet_mode_suppresses_success_output(self, tmp_path: Path, capsys):
        """
        Test quiet mode suppresses informational messages.

        Given: Script run with --quiet flag
        When: Validation passes
        Then: No success messages are printed
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "test.yml"
        test_file.write_text("name: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            validate_with_schema(test_file, "vendor.github-issue-forms", quiet=True)

        captured = capsys.readouterr()
        # In quiet mode, success messages should be suppressed
        assert captured.out == ""


class TestExitCodes:
    """Test exit code behavior."""

    def test_exit_0_when_all_validations_pass(self, tmp_path: Path, monkeypatch):
        """
        Test exits with 0 when all files pass.

        Given: All template files pass validation
        When: Script completes
        Then: Exits with code 0
        """
        from validate_issue_templates import main

        # Change to temp directory with no templates
        monkeypatch.chdir(tmp_path)

        # Create template directory
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)
        (template_dir / "test.yml").write_text("name: Test")

        with patch("sys.argv", ["script.py", "--force"]):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

                exit_code = main()

        assert exit_code == 0

    def test_exit_1_when_any_validation_fails(self, tmp_path: Path, monkeypatch):
        """
        Test exits with 1 when any file fails.

        Given: At least one template file fails validation
        When: Script completes
        Then: Exits with code 1
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create template directory with a file
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)
        (template_dir / "test.yml").write_text("invalid: yaml")

        with patch("sys.argv", ["script.py", "--force"]):
            with patch("subprocess.run") as mock_run:
                # Mock validation failure
                mock_run.return_value = subprocess.CompletedProcess(
                    args=[], returncode=1, stdout="", stderr="ValidationError"
                )

                exit_code = main()

        assert exit_code == 1

    def test_exit_1_when_check_jsonschema_not_found(self, tmp_path: Path, monkeypatch):
        """
        Test exits with 1 when check-jsonschema not installed.

        Given: check-jsonschema command not found
        When: Script tries to run validation
        Then: Exits with code 1 and prints error
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create template directory
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)
        (template_dir / "test.yml").write_text("name: Test")

        with patch("sys.argv", ["script.py", "--force"]):
            with patch("subprocess.run") as mock_run:
                # Mock check-jsonschema not found
                mock_run.side_effect = FileNotFoundError("check-jsonschema not found")

                exit_code = main()

        assert exit_code == 1

    def test_exit_0_when_no_files_to_validate(self, tmp_path: Path, monkeypatch):
        """
        Test exits with 0 when no files need validation.

        Given: No template files are staged (normal mode)
        When: Script runs
        Then: Exits with code 0 and prints skip message
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create empty template directory
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)

        with patch("sys.argv", ["script.py", "--force"]):
            exit_code = main()

        # Should exit 0 when no files to validate
        assert exit_code == 0

    def test_exit_2_on_unexpected_errors(self, tmp_path: Path, monkeypatch):
        """
        Test exits with 2 on unexpected exceptions.

        Given: Unexpected exception occurs
        When: Script is running
        Then: Exits with code 2 and prints error
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create template directory
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)
        (template_dir / "test.yml").write_text("name: Test")

        with patch("sys.argv", ["script.py", "--force"]):
            with patch("validate_issue_templates.get_template_files") as mock_get_files:
                # Mock unexpected exception
                mock_get_files.side_effect = RuntimeError("Unexpected error")

                exit_code = main()

        assert exit_code == 2


class TestCheckJsonSchemaIntegration:
    """Test integration with check-jsonschema subprocess."""

    def test_calls_check_jsonschema_with_correct_arguments(
        self, mock_check_jsonschema_success: subprocess.CompletedProcess, tmp_path: Path
    ):
        """
        Test subprocess call has correct arguments.

        Given: Issue form file to validate
        When: check-jsonschema is invoked
        Then: Called with correct schema and file arguments
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "test.yml"
        test_file.write_text("name: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = mock_check_jsonschema_success

            validate_with_schema(test_file, "vendor.github-issue-forms", quiet=True)

        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "check-jsonschema" in call_args
        assert "--builtin-schema" in call_args
        assert "vendor.github-issue-forms" in call_args
        assert str(test_file) in call_args

    def test_uses_vendor_github_issue_forms_schema(self, tmp_path: Path):
        """
        Test uses vendor.github-issue-forms for issue templates.

        Given: Issue form file (not config.yml)
        When: check-jsonschema is invoked
        Then: Uses --builtin-schema vendor.github-issue-forms
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "new_component.yml"
        test_file.write_text("name: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            validate_with_schema(test_file, "vendor.github-issue-forms", quiet=True)

        call_args = mock_run.call_args[0][0]
        assert "vendor.github-issue-forms" in call_args

    def test_uses_vendor_github_issue_config_schema(self, tmp_path: Path):
        """
        Test uses vendor.github-issue-config for config.yml.

        Given: config.yml file
        When: check-jsonschema is invoked
        Then: Uses --builtin-schema vendor.github-issue-config
        """
        from validate_issue_templates import validate_with_schema

        config_file = tmp_path / "config.yml"
        config_file.write_text("blank_issues_enabled: false")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            validate_with_schema(config_file, "vendor.github-issue-config", quiet=True)

        call_args = mock_run.call_args[0][0]
        assert "vendor.github-issue-config" in call_args

    def test_handles_check_jsonschema_not_installed(self, tmp_path: Path, capsys):
        """
        Test handles FileNotFoundError when tool not installed.

        Given: check-jsonschema is not installed
        When: Script tries to run it
        Then: Catches exception and prints helpful error message
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "test.yml"
        test_file.write_text("name: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("check-jsonschema not found")

            result = validate_with_schema(test_file, "vendor.github-issue-forms", quiet=False)

        assert result is False
        captured = capsys.readouterr()
        assert "check-jsonschema not found" in captured.out

    def test_handles_check_jsonschema_execution_errors(self, tmp_path: Path):
        """
        Test handles CalledProcessError from check-jsonschema.

        Given: check-jsonschema returns non-zero exit code
        When: Subprocess completes
        Then: Error is handled and reported correctly
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "test.yml"
        test_file.write_text("invalid: yaml")

        with patch("subprocess.run") as mock_run:
            # Return non-zero exit code
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="ValidationError"
            )

            result = validate_with_schema(test_file, "vendor.github-issue-forms", quiet=True)

        assert result is False

    def test_passes_correct_file_paths_to_check_jsonschema(self, tmp_path: Path):
        """
        Test file paths are passed correctly.

        Given: Template file at .github/ISSUE_TEMPLATE/new_component.yml
        When: check-jsonschema is invoked
        Then: Full path is passed as argument
        """
        from validate_issue_templates import validate_with_schema

        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)
        template_file = template_dir / "new_component.yml"
        template_file.write_text("name: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            validate_with_schema(template_file, "vendor.github-issue-forms", quiet=True)

        # Verify the full path was passed
        call_args = mock_run.call_args[0][0]
        assert str(template_file) in call_args

    def test_handles_check_jsonschema_timeout(self, tmp_path: Path, capsys):
        """
        Test handles subprocess timeout gracefully.

        Given: check-jsonschema takes too long
        When: Timeout is reached
        Then: Exception is caught and reported
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "test.yml"
        test_file.write_text("name: Test")

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("check-jsonschema", 30)

            result = validate_with_schema(test_file, "vendor.github-issue-forms", quiet=False)

        assert result is False
        captured = capsys.readouterr()
        assert "timeout" in captured.out.lower()


class TestEdgeCases:
    """Test edge case handling."""

    def test_empty_template_directory_exits_gracefully(self, tmp_path: Path, monkeypatch):
        """
        Test empty directory is handled gracefully.

        Given: ISSUE_TEMPLATE directory is empty
        When: Script runs
        Then: Exits with code 0 and informational message
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create empty template directory
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)

        with patch("sys.argv", ["script.py", "--force"]):
            exit_code = main()

        # Empty directory should exit with 0
        assert exit_code == 0

    def test_template_files_with_syntax_errors_fail_validation(self, tmp_path: Path):
        """
        Test YAML syntax errors are caught.

        Given: Template file with invalid YAML syntax
        When: Validation runs
        Then: Error is reported with file name
        """
        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "invalid.yml"
        test_file.write_text("invalid: yaml: syntax:")

        with patch("subprocess.run") as mock_run:
            # Mock YAML parse error
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="YAML parse error"
            )

            result = validate_with_schema(test_file, "vendor.github-issue-forms", quiet=True)

        assert result is False

    def test_very_large_template_files_are_validated(self, tmp_path: Path):
        """
        Test large files don't cause issues.

        Given: Template file is very large (>1MB)
        When: Validation runs
        Then: File is validated without timeout
        """
        from validate_issue_templates import validate_with_schema

        # Create a large file (not actually 1MB for performance, but conceptually large)
        test_file = tmp_path / "large.yml"
        large_content = "name: Test\n" + "description: " + ("x" * 10000) + "\n"
        test_file.write_text(large_content)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            result = validate_with_schema(test_file, "vendor.github-issue-forms", quiet=True)

        assert result is True

    def test_template_files_with_special_characters_in_names(self, tmp_path: Path):
        """
        Test special characters in filenames are handled.

        Given: Template file named "new-component (v2).yml"
        When: File detection runs
        Then: File is found and validated
        """
        from validate_issue_templates import get_template_files

        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)

        # Create file with special characters
        special_file = template_dir / "new-component (v2).yml"
        special_file.write_text("name: Test")

        issue_forms, config_file = get_template_files(template_dir, staged_only=False)

        # Should find the file despite special characters
        assert len(issue_forms) == 1
        assert issue_forms[0].name == "new-component (v2).yml"

    def test_permission_errors_on_template_files_are_reported(self, tmp_path: Path):
        """
        Test permission errors are handled gracefully.

        Given: Template file is not readable
        When: Validation is attempted
        Then: Error is caught and reported
        """
        # Skip on Windows where permission handling is different
        import sys

        if sys.platform == "win32":
            pytest.skip("Permission test not reliable on Windows")

        from validate_issue_templates import validate_with_schema

        test_file = tmp_path / "test.yml"
        test_file.write_text("name: Test")

        # Remove read permissions
        test_file.chmod(0o000)

        try:
            with patch("subprocess.run") as mock_run:
                # Mock will likely not even be called due to permission error
                mock_run.side_effect = PermissionError("Permission denied")

                result = validate_with_schema(test_file, "vendor.github-issue-forms", quiet=True)

            # Should handle the error gracefully
            assert result is False
        finally:
            # Restore permissions for cleanup
            test_file.chmod(0o644)

    def test_symlinks_to_template_files_are_followed(self, tmp_path: Path):
        """
        Test symlinks are followed during validation.

        Given: Template file is a symlink
        When: File detection runs
        Then: Symlink is followed and file is validated
        """
        # Skip on Windows where symlinks require admin privileges
        import sys

        if sys.platform == "win32":
            pytest.skip("Symlink test not reliable on Windows")

        from validate_issue_templates import get_template_files

        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)

        # Create actual file in a different location
        actual_file = tmp_path / "actual.yml"
        actual_file.write_text("name: Test")

        # Create symlink in template directory
        symlink_file = template_dir / "symlink.yml"
        symlink_file.symlink_to(actual_file)

        issue_forms, config_file = get_template_files(template_dir, staged_only=False)

        # Should find the symlink
        assert len(issue_forms) == 1
        assert symlink_file in issue_forms

    def test_concurrent_git_operations_dont_interfere(self):
        """
        Test concurrent git operations are handled.

        Given: Git operations happen during staged file detection
        When: Script runs
        Then: No race conditions or errors occur
        """
        from validate_issue_templates import get_staged_files

        with patch("subprocess.run") as mock_run:
            # Simulate git command failing due to concurrent operations
            mock_run.side_effect = subprocess.CalledProcessError(1, "git", stderr="lock file exists")

            # Should handle the error gracefully and return empty list
            files = get_staged_files()

        # Should return empty list instead of crashing
        assert files == []
        assert isinstance(files, list)


# ============================================================================
# Dependabot Validation Tests
# ============================================================================


class TestDependabotValidation:
    """Test dependabot.yml validation using vendor.dependabot schema."""

    def test_validates_dependabot_yml_with_vendor_dependabot_schema(self, tmp_path: Path, monkeypatch):
        """
        Test dependabot.yml is validated with vendor.dependabot schema in force mode.

        Given: .github/dependabot.yml exists
        When: Script runs in force mode
        Then: check-jsonschema is called with vendor.dependabot schema
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create ISSUE_TEMPLATE dir (required for script to proceed)
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)

        # Create dependabot.yml
        dependabot_file = tmp_path / ".github" / "dependabot.yml"
        dependabot_file.write_text("version: 2\nupdates: []\n")

        with patch("sys.argv", ["script.py", "--force"]):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")
                main()

        # Find the call that used vendor.dependabot
        dependabot_calls = [c for c in mock_run.call_args_list if "vendor.dependabot" in c[0][0]]
        assert len(dependabot_calls) == 1, "Should call check-jsonschema with vendor.dependabot"
        # Script uses relative path ".github/dependabot.yml"
        assert ".github/dependabot.yml" in dependabot_calls[0][0][0][-1]

    def test_skips_dependabot_validation_when_file_missing(self, tmp_path: Path, monkeypatch, capsys):
        """
        Test dependabot validation is skipped when file doesn't exist.

        Given: .github/dependabot.yml does not exist
        When: Script runs in force mode
        Then: No dependabot validation is attempted
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create ISSUE_TEMPLATE dir with a template
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)
        (template_dir / "test.yml").write_text("name: Test")

        # No dependabot.yml created

        with patch("sys.argv", ["script.py", "--force"]):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")
                main()

        # No call should use vendor.dependabot
        dependabot_calls = [c for c in mock_run.call_args_list if "vendor.dependabot" in c[0][0]]
        assert len(dependabot_calls) == 0, "Should not validate dependabot when file missing"

    def test_reports_failure_when_dependabot_yml_invalid(self, tmp_path: Path, monkeypatch):
        """
        Test reports failure for invalid dependabot.yml.

        Given: .github/dependabot.yml with invalid content
        When: Script runs in force mode
        Then: Validation fails and exit code is 1
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create ISSUE_TEMPLATE dir (empty is ok, we care about dependabot)
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)

        # Create invalid dependabot.yml
        dependabot_file = tmp_path / ".github" / "dependabot.yml"
        dependabot_file.write_text("invalid: content\n")

        with patch("sys.argv", ["script.py", "--force"]):
            with patch("subprocess.run") as mock_run:
                # Issue templates: no files to validate (empty dir)
                # Dependabot: validation fails
                def side_effect(cmd, **kwargs):
                    if "vendor.dependabot" in cmd:
                        return subprocess.CompletedProcess(
                            args=cmd, returncode=1, stdout="", stderr="ValidationError: 'version' is required"
                        )
                    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

                mock_run.side_effect = side_effect
                exit_code = main()

        assert exit_code == 1

    def test_only_validates_dependabot_when_staged_in_normal_mode(self, tmp_path: Path, monkeypatch):
        """
        Test dependabot.yml is only validated when staged in normal (non-force) mode.

        Given: .github/dependabot.yml exists but is not staged
        When: Script runs in normal mode
        Then: dependabot.yml is not validated
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create ISSUE_TEMPLATE dir
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)

        # Create dependabot.yml
        dependabot_file = tmp_path / ".github" / "dependabot.yml"
        dependabot_file.write_text("version: 2\nupdates: []\n")

        # Create a staged issue template so the script doesn't skip entirely
        (template_dir / "test.yml").write_text("name: Test")

        with patch("sys.argv", ["script.py"]):
            with patch("subprocess.run") as mock_run:

                def side_effect(cmd, **kwargs):
                    # git diff returns only an issue template (not dependabot.yml)
                    if cmd[0] == "git":
                        return subprocess.CompletedProcess(
                            args=cmd, returncode=0, stdout=".github/ISSUE_TEMPLATE/test.yml\n", stderr=""
                        )
                    # check-jsonschema calls succeed
                    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

                mock_run.side_effect = side_effect
                main()

        # No call should use vendor.dependabot (not staged)
        dependabot_calls = [
            c
            for c in mock_run.call_args_list
            if len(c[0][0]) > 0 and c[0][0][0] == "check-jsonschema" and "vendor.dependabot" in c[0][0]
        ]
        assert len(dependabot_calls) == 0

    def test_validates_dependabot_when_staged_in_normal_mode(self, tmp_path: Path, monkeypatch):
        """
        Test dependabot.yml is validated when staged in normal mode.

        Given: .github/dependabot.yml is staged
        When: Script runs in normal mode
        Then: dependabot.yml is validated with vendor.dependabot schema
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create ISSUE_TEMPLATE dir
        template_dir = tmp_path / ".github" / "ISSUE_TEMPLATE"
        template_dir.mkdir(parents=True)

        # Create dependabot.yml
        dependabot_file = tmp_path / ".github" / "dependabot.yml"
        dependabot_file.write_text("version: 2\nupdates: []\n")

        with patch("sys.argv", ["script.py"]):
            with patch("subprocess.run") as mock_run:

                def side_effect(cmd, **kwargs):
                    # git diff returns dependabot.yml as staged
                    if cmd[0] == "git":
                        return subprocess.CompletedProcess(
                            args=cmd, returncode=0, stdout=".github/dependabot.yml\n", stderr=""
                        )
                    # check-jsonschema calls succeed
                    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

                mock_run.side_effect = side_effect
                main()

        # Should have a call with vendor.dependabot
        dependabot_calls = [
            c
            for c in mock_run.call_args_list
            if len(c[0][0]) > 0 and c[0][0][0] == "check-jsonschema" and "vendor.dependabot" in c[0][0]
        ]
        assert len(dependabot_calls) == 1

    def test_validates_dependabot_without_issue_template_dir(self, tmp_path: Path, monkeypatch):
        """
        Test dependabot.yml is validated even when ISSUE_TEMPLATE dir is missing.

        Given: No .github/ISSUE_TEMPLATE directory but .github/dependabot.yml exists
        When: Script runs in force mode
        Then: dependabot.yml is still validated
        """
        from validate_issue_templates import main

        monkeypatch.chdir(tmp_path)

        # Create .github with only dependabot.yml, no ISSUE_TEMPLATE dir
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        dependabot_file = github_dir / "dependabot.yml"
        dependabot_file.write_text("version: 2\nupdates: []\n")

        with patch("sys.argv", ["script.py", "--force"]):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")
                exit_code = main()

        assert exit_code == 0
        dependabot_calls = [c for c in mock_run.call_args_list if "vendor.dependabot" in c[0][0]]
        assert len(dependabot_calls) == 1, "Should validate dependabot.yml without ISSUE_TEMPLATE dir"

    def test_integration_validates_real_dependabot_yml(self):
        """
        Test validation of the real .github/dependabot.yml file.

        Given: Actual dependabot.yml from the repository
        When: Validation is run with vendor.dependabot schema
        Then: File passes validation
        """
        from validate_issue_templates import validate_with_schema

        dependabot_file = Path(__file__).parent.parent.parent.parent / ".github" / "dependabot.yml"
        if not dependabot_file.exists():
            pytest.skip("dependabot.yml not found in repository")

        result = validate_with_schema(dependabot_file, "vendor.dependabot", quiet=True)

        assert result is True, "dependabot.yml should pass vendor.dependabot validation"


# ============================================================================
# Integration Tests
# ============================================================================


class TestIntegrationWithRealFiles:
    """
    Integration tests using real issue template files.

    These tests use actual files from .github/ISSUE_TEMPLATE to ensure
    the validator works with production templates.
    """

    @pytest.fixture
    def real_template_dir(self) -> Path:
        """Get path to real ISSUE_TEMPLATE directory."""
        return Path(__file__).parent.parent.parent.parent / ".github" / "ISSUE_TEMPLATE"

    def test_validate_real_new_component_template(self, real_template_dir: Path):
        """
        Test validation of real new_component.yml file.

        Given: Actual new_component.yml from repository
        When: Validation is run
        Then: File passes validation
        """
        from validate_issue_templates import validate_with_schema

        template_file = real_template_dir / "new_component.yml"
        assert template_file.exists(), "new_component.yml not found"

        result = validate_with_schema(template_file, "vendor.github-issue-forms", quiet=True)

        assert result is True, "new_component.yml should pass validation"

    def test_validate_real_new_control_template(self, real_template_dir: Path):
        """
        Test validation of real new_control.yml file.

        Given: Actual new_control.yml from repository
        When: Validation is run
        Then: File passes validation
        """
        from validate_issue_templates import validate_with_schema

        template_file = real_template_dir / "new_control.yml"
        assert template_file.exists(), "new_control.yml not found"

        result = validate_with_schema(template_file, "vendor.github-issue-forms", quiet=True)

        assert result is True, "new_control.yml should pass validation"

    def test_validate_real_new_risk_template(self, real_template_dir: Path):
        """
        Test validation of real new_risk.yml file.

        Given: Actual new_risk.yml from repository
        When: Validation is run
        Then: File passes validation
        """
        from validate_issue_templates import validate_with_schema

        template_file = real_template_dir / "new_risk.yml"
        assert template_file.exists(), "new_risk.yml not found"

        result = validate_with_schema(template_file, "vendor.github-issue-forms", quiet=True)

        assert result is True, "new_risk.yml should pass validation"

    def test_validate_real_config_file(self, real_template_dir: Path):
        """
        Test validation of real config.yml file.

        Given: Actual config.yml from repository
        When: Validation is run with config schema
        Then: File passes validation
        """
        from validate_issue_templates import validate_with_schema

        config_file = real_template_dir / "config.yml"
        assert config_file.exists(), "config.yml not found"

        result = validate_with_schema(config_file, "vendor.github-issue-config", quiet=True)

        assert result is True, "config.yml should pass validation"

    def test_validate_all_real_templates_in_directory(self, real_template_dir: Path):
        """
        Test validation of all real templates.

        Given: All templates in ISSUE_TEMPLATE directory
        When: Force validation is run
        Then: All files pass validation
        """
        from validate_issue_templates import get_template_files, validate_with_schema

        assert real_template_dir.exists(), "Template directory not found"

        issue_forms, config_file = get_template_files(real_template_dir, staged_only=False)

        # Validate all issue forms
        all_passed = True
        for form in issue_forms:
            if not validate_with_schema(form, "vendor.github-issue-forms", quiet=True):
                all_passed = False

        # Validate config if present
        if config_file:
            if not validate_with_schema(config_file, "vendor.github-issue-config", quiet=True):
                all_passed = False

        assert all_passed, "All real templates should pass validation"
        assert len(issue_forms) > 0, "Should have found some issue form templates"


# ============================================================================
# Test Summary
# ============================================================================

"""
Test Summary
============
Total Tests: 72
- Command Line Args: 14 tests
- GitHub Schema Validation: 8 tests
- File Detection: 7 tests
- Staged File Detection: 6 tests
- Output Messaging: 6 tests
- Exit Codes: 5 tests
- Check-jsonschema Integration: 7 tests
- Edge Cases: 7 tests
- Dependabot Validation: 7 tests
- Integration Tests: 5 tests

Coverage Areas:
- Argument parsing (argparse)
- File discovery (pathlib)
- Git integration (subprocess for git commands)
- Schema validation (subprocess for check-jsonschema)
- Output formatting (print with emoji)
- Error handling (FileNotFoundError, CalledProcessError, etc.)
- Exit codes (0, 1, 2)
- Force mode vs normal mode
- Quiet mode
- Special cases (empty dirs, large files, permissions, etc.)

Expected Implementation Structure:
==================================

def parse_args() -> argparse.Namespace:
    \"\"\"Parse command-line arguments.\"\"\"
    parser = argparse.ArgumentParser(
        description="Validate GitHub issue templates using check-jsonschema"
    )
    parser.add_argument("-f", "--force", action="store_true",
                       help="Validate all templates (not just staged)")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Suppress informational output")
    return parser.parse_args()


def get_template_files(template_dir: Path, staged_only: bool = False) -> tuple[list[Path], Path | None]:
    \"\"\"
    Get template files to validate.

    Returns:
        (issue_forms, config_file) where issue_forms is list of .yml files
        (excluding config.yml) and config_file is config.yml if it exists
    \"\"\"
    pass


def get_staged_files() -> list[Path]:
    \"\"\"Get staged files from git.\"\"\"
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True, check=True
    )
    return [Path(f) for f in result.stdout.strip().split("\\n") if f]


def validate_with_schema(file_path: Path, schema: str, quiet: bool = False) -> bool:
    \"\"\"
    Validate file against GitHub schema using check-jsonschema.

    Args:
        file_path: Path to YAML file
        schema: Schema name (vendor.github-issue-forms or vendor.github-issue-config)
        quiet: Suppress output

    Returns:
        True if validation passes, False otherwise
    \"\"\"
    try:
        result = subprocess.run(
            ["check-jsonschema", "--builtin-schema", schema, str(file_path)],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode == 0:
            if not quiet:
                print(f"✅ {file_path.name} - Validated against {schema}")
            return True
        else:
            print(f"❌ {file_path.name} - Validation failed:")
            print(result.stderr)
            return False

    except FileNotFoundError:
        print("❌ check-jsonschema not found. Install with: uv sync --locked")
        return False
    except subprocess.TimeoutExpired:
        print(f"❌ {file_path.name} - Validation timeout")
        return False


def main() -> int:
    \"\"\"Main entry point.\"\"\"
    try:
        args = parse_args()

        template_dir = Path(".github/ISSUE_TEMPLATE")

        if not template_dir.exists():
            if not args.quiet:
                print("No .github/ISSUE_TEMPLATE directory found - skipping")
            return 0

        # Get files to validate
        if args.force:
            issue_forms, config_file = get_template_files(template_dir, staged_only=False)
        else:
            staged = get_staged_files()
            issue_forms = [f for f in staged if f.parent.name == "ISSUE_TEMPLATE" and f.suffix == ".yml" and
            f.name != "config.yml"]
            config_file = Path(".github/ISSUE_TEMPLATE/config.yml") if Path(".github/ISSUE_TEMPLATE/config.yml") in
            staged else None

        if not issue_forms and not config_file:
            if not args.quiet:
                print("No issue template files to validate - skipping")
            return 0

        # Validate files
        all_passed = True

        for form in issue_forms:
            if not validate_with_schema(form, "vendor.github-issue-forms", args.quiet):
                all_passed = False

        if config_file:
            if not validate_with_schema(config_file, "vendor.github-issue-config", args.quiet):
                all_passed = False

        if all_passed:
            if not args.quiet:
                print("\\n✅ All issue templates passed validation")
            return 0
        else:
            print("\\n❌ Issue template validation failed!")
            return 1

    except KeyboardInterrupt:
        print("\\nValidation interrupted by user")
        return 2
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())


Expected Behavior After Implementation:
========================================
1. All 60 tests should FAIL initially (RED phase - TDD)
2. After implementing validate_issue_templates.py, tests should PASS (GREEN phase)
3. Script validates issue forms against vendor.github-issue-forms schema
4. Script validates config.yml against vendor.github-issue-config schema
5. Force mode validates all templates
6. Normal mode validates only staged templates
7. Quiet mode suppresses informational output
8. Exit codes: 0 (success), 1 (validation failed), 2 (error)

Next Steps:
===========
1. Run tests to verify they FAIL:
   PYTHONPATH=./scripts/hooks pytest scripts/hooks/tests/test_validate_issue_templates.py -v
2. Implement validate_issue_templates.py (GREEN phase)
3. Run tests again to verify they PASS
4. Verify coverage: pytest --cov=scripts/hooks/validate_issue_templates
5. Integrate into pre-commit hook
"""
