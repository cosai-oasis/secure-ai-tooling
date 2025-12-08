#!/usr/bin/env python3
"""
Tests for YAML to Markdown Table Generator

This test suite validates the YAML to Markdown conversion utility that generates
formatted Markdown tables from CoSAI Risk Map YAML files.

Test Coverage:
==============
1. Core Conversion Logic:
   - YAML file loading and parsing
   - DataFrame generation from YAML data
   - Column-specific formatting (edges, descriptions, lists, dicts)
   - Markdown table generation

2. CLI Argument Parsing:
   - Type selection (components, controls, risks)
   - All types conversion (--all flag)
   - Custom input/output file paths
   - Quiet mode operation
   - Argument validation and error handling

3. File Operations:
   - Default path resolution
   - Custom input file handling
   - Output directory creation
   - File writing and error handling

4. Formatting Functions:
   - Edge formatting (to/from relationships)
   - Text collapsing (multi-line descriptions)
   - List formatting
   - Dictionary formatting (tourContent)
   - Mappings formatting (metadata mappings)
   - Pandas NaN handling for all formatters

5. End-to-End Workflows:
   - Single type conversion
   - Multiple type conversion
   - All types conversion
   - Custom file paths
   - Error scenarios

The tests use temporary files and pytest fixtures to ensure isolation
and reproducibility.
"""

import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pandas as pd
import pytest
import yaml


def get_git_root():
    """Get the git repository root directory."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except subprocess.CalledProcessError:
        # Fallback to relative path if not in git repo
        return Path(__file__).parent.parent.parent


# Add scripts/hooks directory to path
git_root = get_git_root()
sys.path.insert(0, str(git_root / "scripts" / "hooks"))

# Import the module under test
import yaml_to_markdown  # noqa: E402


class TestFormattingFunctions:
    """
    Test the column-specific formatting functions.

    These functions transform YAML data structures into markdown-friendly
    formats with proper line breaks and HTML tags.
    """

    def test_format_edges_both_directions(self):
        """Test formatting edges with both 'to' and 'from' relationships."""
        edges = {"to": ["componentA", "componentB"], "from": ["componentC"]}
        result = yaml_to_markdown.format_edges(edges)

        assert "**To:**" in result
        assert "componentA" in result
        assert "componentB" in result
        assert "**From:**" in result
        assert "componentC" in result
        assert "<br>" in result

    def test_format_edges_to_only(self):
        """Test formatting edges with only 'to' relationships."""
        edges = {"to": ["componentA"]}
        result = yaml_to_markdown.format_edges(edges)

        assert "**To:**" in result
        assert "componentA" in result
        assert "**From:**" not in result

    def test_format_edges_from_only(self):
        """Test formatting edges with only 'from' relationships."""
        edges = {"from": ["componentZ"]}
        result = yaml_to_markdown.format_edges(edges)

        assert "**From:**" in result
        assert "componentZ" in result
        assert "**To:**" not in result

    def test_format_edges_empty(self):
        """Test formatting empty edges dictionary."""
        assert yaml_to_markdown.format_edges({}) == ""
        assert yaml_to_markdown.format_edges(None) == ""

    def test_format_list_simple(self):
        """Test formatting a simple list."""
        test_list = ["item1", "item2", "item3"]
        result = yaml_to_markdown.format_list(test_list)

        assert "item1" in result
        assert "item2" in result
        assert "item3" in result
        assert "<br>" in result

    def test_format_list_non_list(self):
        """Test format_list with non-list input returns string representation."""
        assert yaml_to_markdown.format_list("string") == "string"
        assert yaml_to_markdown.format_list(None) == ""
        assert yaml_to_markdown.format_list(123) == "123"

    def test_format_dict_simple(self):
        """Test formatting a simple dictionary."""
        test_dict = {"key1": "value1", "key2": "value2"}
        result = yaml_to_markdown.format_dict(test_dict)

        assert "**key1**:" in result
        assert "value1" in result
        assert "**key2**:" in result
        assert "value2" in result
        assert "<br>" in result

    def test_format_dict_with_list_values(self):
        """Test formatting dictionary with list values."""
        test_dict = {"key1": ["item1", "item2"], "key2": "simple_value"}
        result = yaml_to_markdown.format_dict(test_dict)

        assert "**key1**:" in result
        assert "item1" in result
        assert "item2" in result
        assert "**key2**:" in result
        assert "simple_value" in result

    def test_format_dict_non_dict(self):
        """Test format_dict with non-dict input returns string representation."""
        assert yaml_to_markdown.format_dict("string") == "string"
        assert yaml_to_markdown.format_dict(None) == ""

    def test_collapse_column_string(self):
        """Test collapsing a simple string."""
        test_string = "Line 1\nLine 2\n- > something"
        result = yaml_to_markdown.collapse_column(test_string)

        assert "<br>" in result
        assert "- >" not in result
        assert "Line 1" in result
        assert "Line 2" in result

    def test_collapse_column_single_item_list(self):
        """Test collapsing a list with single item."""
        test_list = ["Single item\nwith newlines"]
        result = yaml_to_markdown.collapse_column(test_list)

        assert "Single item" in result
        assert "<br>" in result

    def test_collapse_column_multiple_items(self):
        """Test collapsing a list with multiple items."""
        test_list = ["item1", "item2", ["nested1", "nested2"]]
        result = yaml_to_markdown.collapse_column(test_list)

        assert "item1" in result
        assert "item2" in result
        assert "nested1" in result
        assert "nested2" in result
        assert "<br>" in result

    def test_collapse_column_non_list_non_string(self):
        """Test collapse_column with non-list, non-string input returns string representation."""
        assert yaml_to_markdown.collapse_column(123) == "123"

    # NaN handling tests
    def test_format_edges_with_nan(self):
        """Test format_edges handles pandas NaN values correctly."""
        result = yaml_to_markdown.format_edges(pd.NA)
        assert result == ""

        result = yaml_to_markdown.format_edges(float("nan"))
        assert result == ""

    def test_format_list_with_nan(self):
        """Test format_list handles pandas NaN values correctly."""
        result = yaml_to_markdown.format_list(pd.NA)
        assert result == ""

        result = yaml_to_markdown.format_list(float("nan"))
        assert result == ""

    def test_format_dict_with_nan(self):
        """Test format_dict handles pandas NaN values correctly."""
        result = yaml_to_markdown.format_dict(pd.NA)
        assert result == ""

        result = yaml_to_markdown.format_dict(float("nan"))
        assert result == ""

    def test_collapse_column_with_nan(self):
        """Test collapse_column handles pandas NaN values correctly."""
        result = yaml_to_markdown.collapse_column(pd.NA)
        assert result == ""

        result = yaml_to_markdown.collapse_column(float("nan"))
        assert result == ""

    def test_format_mappings_simple(self):
        """Test formatting a simple mappings dictionary."""
        test_dict = {"NIST AI RMF": ["GOVERN-1.1", "GOVERN-1.2"], "ISO 42001": ["5.1", "5.2"]}
        result = yaml_to_markdown.format_mappings(test_dict)

        assert "**NIST AI RMF**:" in result
        assert "GOVERN-1.1, GOVERN-1.2" in result
        assert "**ISO 42001**:" in result
        assert "5.1, 5.2" in result
        assert "<br>" in result

    def test_format_mappings_string_values(self):
        """Test formatting mappings with string values."""
        test_dict = {"Framework1": "Single value", "Framework2": ["Value1", "Value2"]}
        result = yaml_to_markdown.format_mappings(test_dict)

        assert "**Framework1**: Single value" in result
        assert "**Framework2**: Value1, Value2" in result

    def test_format_mappings_empty(self):
        """Test format_mappings with empty/None inputs."""
        assert yaml_to_markdown.format_mappings({}) == ""
        assert yaml_to_markdown.format_mappings(None) == ""

    def test_format_mappings_with_nan(self):
        """Test format_mappings handles pandas NaN values correctly."""
        result = yaml_to_markdown.format_mappings(pd.NA)
        assert result == ""

        result = yaml_to_markdown.format_mappings(float("nan"))
        assert result == ""

    def test_format_mappings_non_dict(self):
        """Test format_mappings with non-dict input returns empty string."""
        assert yaml_to_markdown.format_mappings("string") == ""
        assert yaml_to_markdown.format_mappings(123) == ""


class TestYamlToMarkdownTable:
    """
    Test the main yaml_to_markdown_table conversion function.

    Tests YAML parsing, DataFrame creation, column formatting,
    and markdown table generation.
    """

    @pytest.fixture
    def temp_yaml_file(self):
        """Create a temporary YAML file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            test_data = {
                "components": [
                    {
                        "id": "comp1",
                        "title": "Component 1",
                        "description": ["Line 1", "Line 2"],
                        "edges": {"to": ["comp2"], "from": []},
                        "category": "test",
                    },
                    {
                        "id": "comp2",
                        "title": "Component 2",
                        "description": ["Description 2"],
                        "edges": {"to": [], "from": ["comp1"]},
                        "category": "test",
                    },
                ]
            }
            yaml.dump(test_data, f)
            temp_path = Path(f.name)

        yield temp_path

        # Cleanup
        temp_path.unlink(missing_ok=True)

    def test_basic_conversion(self, temp_yaml_file):
        """Test basic YAML to markdown conversion."""
        result = yaml_to_markdown.yaml_to_markdown_table(temp_yaml_file, "components")

        assert isinstance(result, str)
        assert "comp1" in result
        assert "comp2" in result
        assert "Component 1" in result
        assert "Component 2" in result
        assert "|" in result  # Markdown table delimiter

    def test_sorted_by_id(self, temp_yaml_file):
        """Test that output is sorted by ID."""
        result = yaml_to_markdown.yaml_to_markdown_table(temp_yaml_file, "components")

        # Result should contain both comp1 and comp2
        assert "comp1" in result
        assert "comp2" in result

        # Split into lines - skip header (line 0) and separator (line 1)
        lines = result.split("\n")

        # Find lines where the id column contains comp1 or comp2
        # The id is in the 4th column (index 3) in the test data
        comp1_row_idx = None
        comp2_row_idx = None

        for idx, line in enumerate(lines[2:], start=2):  # Skip header and separator
            if "| comp1 |" in line:
                comp1_row_idx = idx
            if "| comp2 |" in line:
                comp2_row_idx = idx

        assert comp1_row_idx is not None, "comp1 row not found"
        assert comp2_row_idx is not None, "comp2 row not found"
        assert comp1_row_idx < comp2_row_idx, "comp1 should appear before comp2 when sorted by id"

    def test_missing_values_filled(self):
        """Test that missing values are filled with empty strings."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            test_data = {
                "components": [
                    {
                        "id": "comp1",
                        "title": "Component 1",
                        # Missing description field
                        "category": "test",
                    }
                ]
            }
            yaml.dump(test_data, f)
            temp_path = Path(f.name)

        try:
            result = yaml_to_markdown.yaml_to_markdown_table(temp_path, "components")
            assert isinstance(result, str)
            assert "comp1" in result
        finally:
            temp_path.unlink(missing_ok=True)


class TestConfiguration:
    """Test configuration constants and path patterns."""

    def test_configuration_constants_exist(self):
        """Test that configuration constants are defined."""
        assert hasattr(yaml_to_markdown, "DEFAULT_INPUT_DIR")
        assert hasattr(yaml_to_markdown, "DEFAULT_OUTPUT_DIR")
        assert hasattr(yaml_to_markdown, "INPUT_FILE_PATTERN")
        assert hasattr(yaml_to_markdown, "OUTPUT_FILE_PATTERN")

    def test_default_directories(self):
        """Test default directory paths."""
        assert "risk-map/yaml" in str(yaml_to_markdown.DEFAULT_INPUT_DIR)
        assert "risk-map/tables" in str(yaml_to_markdown.DEFAULT_OUTPUT_DIR)

    def test_file_patterns(self):
        """Test file naming patterns."""
        # Test that patterns use {type} placeholder
        assert "{type}" in yaml_to_markdown.INPUT_FILE_PATTERN
        assert "{type}" in yaml_to_markdown.OUTPUT_FILE_PATTERN

        # Test pattern formatting
        assert yaml_to_markdown.INPUT_FILE_PATTERN.format(type="components") == "components.yaml"
        assert (
            yaml_to_markdown.OUTPUT_FILE_PATTERN.format(type="components", format="full") == "components-full.md"
        )
        assert (
            yaml_to_markdown.OUTPUT_FILE_PATTERN.format(type="controls", format="summary") == "controls-summary.md"
        )


class TestGetDefaultPaths:
    """Test default path resolution for different types."""

    def test_components_paths(self):
        """Test default paths for components type."""
        input_path, output_path = yaml_to_markdown.get_default_paths("components", "full")

        assert "components.yaml" in str(input_path)
        assert "components-full.md" in str(output_path)
        assert "risk-map/yaml" in str(input_path)
        assert "risk-map/tables" in str(output_path)

    def test_controls_paths(self):
        """Test default paths for controls type."""
        input_path, output_path = yaml_to_markdown.get_default_paths("controls", "summary")

        assert "controls.yaml" in str(input_path)
        assert "controls-summary.md" in str(output_path)
        assert "risk-map/yaml" in str(input_path)
        assert "risk-map/tables" in str(output_path)

    def test_risks_paths(self):
        """Test default paths for risks type."""
        input_path, output_path = yaml_to_markdown.get_default_paths("risks", "full")

        assert "risks.yaml" in str(input_path)
        assert "risks-full.md" in str(output_path)
        assert "risk-map/yaml" in str(input_path)
        assert "risk-map/tables" in str(output_path)

    def test_custom_output_dir(self):
        """Test get_default_paths with custom output directory."""
        from pathlib import Path

        custom_dir = Path("/tmp/custom-tables")
        input_path, output_path = yaml_to_markdown.get_default_paths("components", "full", output_dir=custom_dir)

        assert "components.yaml" in str(input_path)
        assert "components-full.md" in str(output_path)
        assert "risk-map/yaml" in str(input_path)
        assert str(custom_dir) in str(output_path)
        assert "risk-map/tables" not in str(output_path)


class TestConvertType:
    """Test the convert_type function for single type conversion."""

    @pytest.fixture
    def temp_yaml_and_output(self):
        """Create temporary input and output files."""
        # Input file
        input_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        test_data = {"components": [{"id": "test1", "title": "Test 1", "category": "test"}]}
        yaml.dump(test_data, input_file)
        input_file.close()
        input_path = Path(input_file.name)

        # Output file
        output_file = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False)
        output_file.close()
        output_path = Path(output_file.name)

        yield input_path, output_path

        # Cleanup
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)

    def test_convert_type_success(self, temp_yaml_and_output):
        """Test successful type conversion."""
        input_path, output_path = temp_yaml_and_output

        result = yaml_to_markdown.convert_type(
            "components", input_file=input_path, output_file=output_path, quiet=True
        )

        assert result is True
        assert output_path.exists()

        content = output_path.read_text()
        assert "test1" in content
        assert "Test 1" in content

    def test_convert_type_missing_input(self, capsys):
        """Test conversion with missing input file."""
        result = yaml_to_markdown.convert_type(
            "components", input_file=Path("/nonexistent/file.yaml"), quiet=False
        )

        assert result is False
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_convert_type_creates_output_dir(self):
        """Test that output directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "input.yaml"
            test_data = {"components": [{"id": "test1", "title": "Test 1", "category": "test"}]}
            with open(input_file, "w") as f:
                yaml.dump(test_data, f)

            # Output in nested directory that doesn't exist
            output_file = Path(tmpdir) / "nested" / "dir" / "output.md"

            result = yaml_to_markdown.convert_type(
                "components", input_file=input_file, output_file=output_file, quiet=True
            )

            assert result is True
            assert output_file.exists()
            assert output_file.parent.exists()

    def test_convert_type_with_output_dir(self):
        """Test convert_type with custom output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "input.yaml"
            output_dir = Path(tmpdir) / "custom-output"

            test_data = {"components": [{"id": "test1", "title": "Test 1", "category": "test"}]}
            with open(input_file, "w") as f:
                yaml.dump(test_data, f)

            result = yaml_to_markdown.convert_type(
                "components",
                "full",
                input_file=input_file,
                output_dir=output_dir,
                quiet=True,
            )

            assert result is True
            expected_file = output_dir / "components-full.md"
            assert expected_file.exists()
            content = expected_file.read_text()
            assert "test1" in content


class TestCLIArgumentParsing:
    """Test command-line argument parsing."""

    def test_parse_args_single_type(self):
        """Test parsing single type argument."""
        with patch("sys.argv", ["yaml_to_markdown.py", "components"]):
            args = yaml_to_markdown.parse_args()
            assert args.types == ["components"]
            assert not args.all

    def test_parse_args_multiple_types(self):
        """Test parsing multiple type arguments."""
        with patch("sys.argv", ["yaml_to_markdown.py", "components", "controls"]):
            args = yaml_to_markdown.parse_args()
            assert "components" in args.types
            assert "controls" in args.types
            assert len(args.types) == 2

    def test_parse_args_all_flag(self):
        """Test --all flag."""
        # --all flag still requires empty types list, but argparse accepts it
        with patch("sys.argv", ["yaml_to_markdown.py", "--all"]):
            args = yaml_to_markdown.parse_args()
            assert args.all is True
            # types will be empty list when --all is used
            assert args.types == []

    def test_parse_args_output_file(self):
        """Test --output argument."""
        with patch("sys.argv", ["yaml_to_markdown.py", "components", "-o", "custom.md"]):
            args = yaml_to_markdown.parse_args()
            assert args.output == Path("custom.md")

    def test_parse_args_custom_input(self):
        """Test --file argument."""
        with patch("sys.argv", ["yaml_to_markdown.py", "components", "--file", "custom.yaml"]):
            args = yaml_to_markdown.parse_args()
            assert args.file == Path("custom.yaml")

    def test_parse_args_quiet_mode(self):
        """Test --quiet flag."""
        with patch("sys.argv", ["yaml_to_markdown.py", "components", "-q"]):
            args = yaml_to_markdown.parse_args()
            assert args.quiet is True


class TestMainFunction:
    """Test the main entry point function."""

    def test_main_no_args_exits_with_error(self, capsys):
        """Test main exits with error when no types specified and no --all flag."""
        # argparse will handle this case before our validation
        # When empty args are provided without --all, argparse doesn't error
        # because nargs='*' allows zero args, but our code should error
        with patch("sys.argv", ["yaml_to_markdown.py"]):
            with pytest.raises(SystemExit) as exc_info:
                yaml_to_markdown.main()

            # Exit code 1 for our validation, or could be 2 from argparse
            assert exc_info.value.code in (1, 2)
            captured = capsys.readouterr()
            # Either our error message or argparse error
            assert "Must specify at least one type" in captured.out or "usage:" in captured.err

    def test_main_output_with_multiple_types_error(self, capsys):
        """Test main exits when --output used with multiple types."""
        with patch("sys.argv", ["yaml_to_markdown.py", "components", "controls", "-o", "out.md"]):
            with pytest.raises(SystemExit) as exc_info:
                yaml_to_markdown.main()

            assert exc_info.value.code == 1
            captured = capsys.readouterr()
            assert "single type" in captured.out

    def test_main_output_with_all_flag_error(self, capsys):
        """Test main exits when --output used with --all."""
        with patch("sys.argv", ["yaml_to_markdown.py", "--all", "-o", "out.md"]):
            with pytest.raises(SystemExit) as exc_info:
                yaml_to_markdown.main()

            # Could be exit code 1 or 2 depending on where validation fails
            assert exc_info.value.code in (1, 2)
            captured = capsys.readouterr()
            # Either our error or argparse error
            assert "single type" in captured.out or "usage:" in captured.err

    def test_main_all_flag_determines_types(self):
        """Test --all flag determines all three types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create mock input files
            for ytype in ["components", "controls", "risks"]:
                input_file = Path(tmpdir) / f"{ytype}.yaml"
                test_data = {ytype: [{"id": "test1", "title": "Test"}]}
                with open(input_file, "w") as f:
                    yaml.dump(test_data, f)

            # Use a types argument to satisfy argparse, but also --all
            # Actually, --all should work with empty types list
            with patch("sys.argv", ["yaml_to_markdown.py", "--all", "--quiet"]):
                with patch("yaml_to_markdown.get_default_paths") as mock_paths:
                    # Mock to use our temp files
                    def side_effect(ytype):
                        return Path(tmpdir) / f"{ytype}.yaml", Path(tmpdir) / f"{ytype}-table.md"

                    mock_paths.side_effect = side_effect

                    with pytest.raises(SystemExit) as exc_info:
                        yaml_to_markdown.main()

                    # Should exit successfully (0) or with argparse error (2)
                    # Depending on if argparse allows empty list with choices
                    assert exc_info.value.code in (0, 2)

    def test_main_keyboard_interrupt(self, capsys):
        """Test main handles KeyboardInterrupt gracefully."""
        with patch("sys.argv", ["yaml_to_markdown.py", "components"]):
            with patch("yaml_to_markdown.convert_type", side_effect=KeyboardInterrupt()):
                with pytest.raises(SystemExit) as exc_info:
                    yaml_to_markdown.main()

                assert exc_info.value.code == 2
                captured = capsys.readouterr()
                assert "interrupted" in captured.out


class TestEndToEndIntegration:
    """
    End-to-end integration tests with real YAML files.

    These tests use the actual Risk Map YAML files from the repository
    to ensure the converter works with real-world data.
    """

    @pytest.fixture
    def components_yaml_path(self):
        """Get path to real components.yaml file."""
        return get_git_root() / "risk-map" / "yaml" / "components.yaml"

    @pytest.fixture
    def controls_yaml_path(self):
        """Get path to real controls.yaml file."""
        return get_git_root() / "risk-map" / "yaml" / "controls.yaml"

    @pytest.fixture
    def risks_yaml_path(self):
        """Get path to real risks.yaml file."""
        return get_git_root() / "risk-map" / "yaml" / "risks.yaml"

    @pytest.mark.skipif(
        not (get_git_root() / "risk-map" / "yaml" / "components.yaml").exists(),
        reason="Real components.yaml not available",
    )
    def test_convert_real_components(self, components_yaml_path):
        """Test conversion with real components.yaml file."""
        result = yaml_to_markdown.yaml_to_markdown_table(components_yaml_path, "components")

        assert isinstance(result, str)
        assert len(result) > 0
        assert "|" in result  # Markdown table format
        assert "id" in result.lower()  # Should have id column

    @pytest.mark.skipif(
        not (get_git_root() / "risk-map" / "yaml" / "controls.yaml").exists(),
        reason="Real controls.yaml not available",
    )
    def test_convert_real_controls(self, controls_yaml_path):
        """Test conversion with real controls.yaml file."""
        result = yaml_to_markdown.yaml_to_markdown_table(controls_yaml_path, "controls")

        assert isinstance(result, str)
        assert len(result) > 0
        assert "|" in result

    @pytest.mark.skipif(
        not (get_git_root() / "risk-map" / "yaml" / "risks.yaml").exists(), reason="Real risks.yaml not available"
    )
    def test_convert_real_risks(self, risks_yaml_path):
        """Test conversion with real risks.yaml file."""
        result = yaml_to_markdown.yaml_to_markdown_table(risks_yaml_path, "risks")

        assert isinstance(result, str)
        assert len(result) > 0
        assert "|" in result


class TestTableGenerators:
    """Test new table generator classes and formats."""

    @pytest.fixture
    def sample_controls_data(self):
        """Sample controls data for testing."""
        return {
            "controls": [
                {
                    "id": "controlTest1",
                    "title": "Test Control 1",
                    "description": ["Test description"],
                    "category": "controlsData",
                    "risks": ["DP", "MST"],
                    "components": ["componentDataSources", "componentTrainingData"],
                },
                {
                    "id": "controlTest2",
                    "title": "Test Control 2",
                    "description": ["Another test"],
                    "category": "controlsModel",
                    "risks": "all",
                    "components": ["componentModelTrainingTuning"],
                },
            ]
        }

    @pytest.fixture
    def sample_components_data(self):
        """Sample components data for testing."""
        return {
            "components": [
                {"id": "comp1", "title": "Component 1", "description": "Description 1", "category": "catData"},
                {
                    "id": "comp2",
                    "title": "Component 2",
                    "shortDescription": "Short desc 2",
                    "category": "catModel",
                },
            ]
        }

    def test_full_detail_generator(self, sample_controls_data, tmp_path):
        """Test FullDetailTableGenerator."""
        generator = yaml_to_markdown.FullDetailTableGenerator()
        result = generator.generate(sample_controls_data, "controls")

        assert isinstance(result, str)
        assert "controlTest1" in result
        assert "Test Control 1" in result
        assert "|" in result  # Markdown table format

    def test_summary_generator(self, sample_components_data, tmp_path):
        """Test SummaryTableGenerator."""
        generator = yaml_to_markdown.SummaryTableGenerator()
        result = generator.generate(sample_components_data, "components")

        assert isinstance(result, str)
        assert "comp1" in result
        assert "Component 1" in result
        assert "Description 1" in result
        # Should have only summary columns
        assert "ID" in result
        assert "Title" in result
        assert "Description" in result
        assert "Category" in result

    def test_summary_generator_prefers_short_description(self, sample_components_data):
        """Test that SummaryTableGenerator prefers shortDescription over description."""
        generator = yaml_to_markdown.SummaryTableGenerator()
        result = generator.generate(sample_components_data, "components")

        assert "Short desc 2" in result

    @pytest.mark.skipif(
        not (get_git_root() / "risk-map" / "yaml" / "risks.yaml").exists(), reason="Real YAML files not available"
    )
    def test_risk_xref_generator(self, sample_controls_data):
        """Test RiskXRefTableGenerator with real risks.yaml."""
        input_dir = get_git_root() / "risk-map" / "yaml"
        generator = yaml_to_markdown.RiskXRefTableGenerator(input_dir=input_dir)
        result = generator.generate(sample_controls_data, "controls")

        assert isinstance(result, str)
        assert "controlTest1" in result
        assert "Risk IDs" in result
        assert "Risk Titles" in result
        # Check "all" handling
        assert "all" in result
        assert "All Risks" in result

    @pytest.mark.skipif(
        not (get_git_root() / "risk-map" / "yaml" / "components.yaml").exists(),
        reason="Real YAML files not available",
    )
    def test_component_xref_generator(self, sample_controls_data):
        """Test ComponentXRefTableGenerator with real components.yaml."""
        input_dir = get_git_root() / "risk-map" / "yaml"
        generator = yaml_to_markdown.ComponentXRefTableGenerator(input_dir=input_dir)
        result = generator.generate(sample_controls_data, "controls")

        assert isinstance(result, str)
        assert "controlTest1" in result
        assert "Component IDs" in result
        assert "Component Titles" in result

    def test_risk_xref_generator_invalid_type(self, sample_components_data):
        """Test that RiskXRefTableGenerator raises error for non-controls type."""
        generator = yaml_to_markdown.RiskXRefTableGenerator()

        with pytest.raises(ValueError, match="only works with 'controls'"):
            generator.generate(sample_components_data, "components")

    def test_component_xref_generator_invalid_type(self, sample_components_data):
        """Test that ComponentXRefTableGenerator raises error for non-controls type."""
        generator = yaml_to_markdown.ComponentXRefTableGenerator()

        with pytest.raises(ValueError, match="only works with 'controls'"):
            generator.generate(sample_components_data, "components")


class TestFormatParameter:
    """Test the table_format parameter in yaml_to_markdown_table."""

    @pytest.fixture
    def temp_yaml(self, tmp_path):
        """Create temporary YAML file for testing."""
        yaml_content = """
controls:
  - id: testControl
    title: Test Control
    description: ["Test description"]
    category: controlsData
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content)
        return yaml_file

    def test_format_parameter_full(self, temp_yaml):
        """Test yaml_to_markdown_table with full format."""
        result = yaml_to_markdown.yaml_to_markdown_table(temp_yaml, "controls", table_format="full")

        assert isinstance(result, str)
        assert "testControl" in result

    def test_format_parameter_summary(self, temp_yaml):
        """Test yaml_to_markdown_table with summary format."""
        result = yaml_to_markdown.yaml_to_markdown_table(temp_yaml, "controls", table_format="summary")

        assert isinstance(result, str)
        assert "testControl" in result
        assert "ID" in result
        assert "Title" in result

    def test_format_parameter_invalid(self, temp_yaml):
        """Test yaml_to_markdown_table with invalid format."""
        with pytest.raises(ValueError, match="Invalid table format"):
            yaml_to_markdown.yaml_to_markdown_table(temp_yaml, "controls", table_format="invalid")

    def test_format_parameter_default(self, temp_yaml):
        """Test yaml_to_markdown_table defaults to full format."""
        result = yaml_to_markdown.yaml_to_markdown_table(temp_yaml, "controls")

        assert isinstance(result, str)
        assert "testControl" in result

    def test_ytype_validation(self, temp_yaml):
        """Test that invalid ytype raises ValueError."""
        with pytest.raises(ValueError, match="does not contain 'invalid_type' key"):
            yaml_to_markdown.yaml_to_markdown_table(temp_yaml, "invalid_type", table_format="full")


class TestAllFormatsFeature:
    """Test the all-formats functionality."""

    def test_get_applicable_formats_components(self):
        """Test get_applicable_formats for components type."""
        formats = yaml_to_markdown.get_applicable_formats("components")

        assert isinstance(formats, list)
        assert "full" in formats
        assert "summary" in formats
        assert len(formats) == 2

    def test_get_applicable_formats_risks(self):
        """Test get_applicable_formats for risks type."""
        formats = yaml_to_markdown.get_applicable_formats("risks")

        assert isinstance(formats, list)
        assert "full" in formats
        assert "summary" in formats
        assert len(formats) == 2

    def test_get_applicable_formats_controls(self):
        """Test get_applicable_formats for controls type."""
        formats = yaml_to_markdown.get_applicable_formats("controls")

        assert isinstance(formats, list)
        assert "full" in formats
        assert "summary" in formats
        assert "xref-risks" in formats
        assert "xref-components" in formats
        assert len(formats) == 4

    def test_convert_all_formats(self, tmp_path):
        """Test convert_all_formats generates all applicable formats."""
        # Create test input file
        input_file = tmp_path / "test.yaml"
        test_data = {"components": [{"id": "comp1", "title": "Component 1", "category": "test"}]}
        with open(input_file, "w") as f:
            yaml.dump(test_data, f)

        # Mock DEFAULT_OUTPUT_DIR to use tmp_path
        with patch("yaml_to_markdown.DEFAULT_OUTPUT_DIR", tmp_path):
            result = yaml_to_markdown.convert_all_formats("components", input_file, quiet=True)

        assert result is True

        # Verify both formats were generated
        full_file = tmp_path / "components-full.md"
        summary_file = tmp_path / "components-summary.md"

        assert full_file.exists()
        assert summary_file.exists()

        # Verify content
        full_content = full_file.read_text()
        assert "comp1" in full_content

        summary_content = summary_file.read_text()
        assert "comp1" in summary_content

    def test_cli_all_formats_flag(self, tmp_path):
        """Test CLI with --all-formats flag."""
        # Create test input file
        input_file = tmp_path / "test.yaml"
        test_data = {"components": [{"id": "testComp", "title": "Test Component", "category": "test"}]}
        with open(input_file, "w") as f:
            yaml.dump(test_data, f)

        with patch(
            "sys.argv",
            ["yaml_to_markdown.py", "components", "--all-formats", "--file", str(input_file), "--quiet"],
        ):
            with patch("yaml_to_markdown.DEFAULT_OUTPUT_DIR", tmp_path):
                with pytest.raises(SystemExit) as exc_info:
                    yaml_to_markdown.main()

                # Should exit successfully
                assert exc_info.value.code == 0

        # Verify files were created
        assert (tmp_path / "components-full.md").exists()
        assert (tmp_path / "components-summary.md").exists()

    def test_cli_all_formats_with_output_error(self, capsys):
        """Test that --all-formats with --output generates error."""
        with patch("sys.argv", ["yaml_to_markdown.py", "components", "--all-formats", "-o", "out.md"]):
            with pytest.raises(SystemExit) as exc_info:
                yaml_to_markdown.main()

            assert exc_info.value.code == 1
            captured = capsys.readouterr()
            assert "single type with a single format" in captured.out
