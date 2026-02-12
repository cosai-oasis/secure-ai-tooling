"""
Tests for SchemaParser class.

This module tests the SchemaParser functionality for extracting enum values
and required fields from JSON schemas used in the CoSAI Risk Map framework.
The SchemaParser is the foundation for the IssueTemplateGenerator system.

Test Coverage:
- Schema initialization and loading
- Enum value extraction (simple and nested)
- Required field extraction
- All-enum extraction
- Integration with production schemas
- Error handling and edge cases
"""

import json
from pathlib import Path
from typing import Any

import pytest

# SchemaParser import - PYTHONPATH is set to ./scripts/hooks in GitHub Actions
from issue_template_generator.schema_parser import SchemaParser

# ============================================================================
# Pytest Fixtures
# ============================================================================


@pytest.fixture
def production_schema_dir(risk_map_schemas_dir: Path) -> Path:
    """
    Provide path to production schema directory.

    Uses the risk_map_schemas_dir fixture from conftest.py for
    environment-agnostic path resolution.
    """
    return risk_map_schemas_dir


@pytest.fixture
def sample_controls_schema_data() -> dict[str, Any]:
    """Provide sample controls schema data for testing."""
    return {
        "$id": "controls.schema.json",
        "definitions": {
            "category": {
                "properties": {
                    "id": {"type": "string", "enum": ["controlsData", "controlsInfrastructure", "controlsModel"]}
                },
                "required": ["id", "title"],
            },
            "control": {
                "properties": {
                    "id": {"type": "string", "enum": ["control1", "control2"]},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "category": {"$ref": "#/definitions/category/properties/id"},
                },
                "required": ["title", "description", "category"],
            },
        },
    }


@pytest.fixture
def sample_frameworks_schema_data() -> dict[str, Any]:
    """Provide sample frameworks schema data for testing."""
    return {
        "$id": "frameworks.schema.json",
        "definitions": {
            "framework": {
                "properties": {
                    "id": {"type": "string", "enum": ["mitre-atlas", "nist-ai-rmf"]},
                    "applicableTo": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["controls", "risks", "components"]},
                    },
                },
                "required": ["id", "name", "applicableTo"],
            }
        },
    }


# ============================================================================
# Test Classes
# ============================================================================


class TestSchemaParserInit:
    """Test SchemaParser initialization."""

    def test_init_with_valid_directory(self, tmp_path: Path) -> None:
        """
        Test SchemaParser initialization with valid directory.

        Given: A valid directory path
        When: SchemaParser is initialized
        Then: Instance is created successfully with correct schema_dir
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()

        parser = SchemaParser(schema_dir)

        assert parser.schema_dir == schema_dir
        assert isinstance(parser.schema_dir, Path)

    def test_init_with_nonexistent_directory(self, tmp_path: Path) -> None:
        """
        Test SchemaParser initialization with non-existent directory.

        Given: A directory path that doesn't exist
        When: SchemaParser is initialized
        Then: Should raise FileNotFoundError with clear message
        """
        nonexistent_dir = tmp_path / "does_not_exist"

        with pytest.raises(FileNotFoundError, match="Schema directory.*does not exist"):
            SchemaParser(nonexistent_dir)

    def test_init_with_file_instead_of_directory(self, tmp_path: Path) -> None:
        """
        Test SchemaParser initialization with file path instead of directory.

        Given: A file path instead of directory path
        When: SchemaParser is initialized
        Then: Should raise NotADirectoryError with clear message
        """
        file_path = tmp_path / "schema.json"
        file_path.write_text("{}")

        with pytest.raises(NotADirectoryError, match=".*is not a directory"):
            SchemaParser(file_path)

    def test_init_with_production_schema_directory(self, production_schema_dir: Path) -> None:
        """
        Test SchemaParser initialization with production schema directory.

        Given: The actual production schema directory
        When: SchemaParser is initialized
        Then: Instance is created successfully
        """
        schema_dir = production_schema_dir

        parser = SchemaParser(schema_dir)

        assert parser.schema_dir == schema_dir
        assert parser.schema_dir.exists()


class TestLoadSchema:
    """Test load_schema() method."""

    def test_load_existing_schema(self, tmp_path: Path) -> None:
        """
        Test loading an existing schema file.

        Given: A valid schema file exists
        When: load_schema() is called with the schema name
        Then: Returns dict with schema data
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "test.schema.json"
        schema_data = {"$id": "test.schema.json", "type": "object"}
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.load_schema("test.schema.json")

        assert result == schema_data
        assert isinstance(result, dict)

    def test_load_schema_with_nested_definitions(self, tmp_path: Path) -> None:
        """
        Test loading schema with nested definitions.

        Given: A schema file with nested definitions
        When: load_schema() is called
        Then: Returns complete dict including definitions
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "nested.schema.json"
        schema_data = {
            "$id": "nested.schema.json",
            "definitions": {
                "control": {"type": "object", "properties": {"id": {"type": "string", "enum": ["id1", "id2"]}}}
            },
        }
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.load_schema("nested.schema.json")

        assert "definitions" in result
        assert "control" in result["definitions"]
        assert result["definitions"]["control"]["properties"]["id"]["enum"] == ["id1", "id2"]

    def test_load_schema_with_refs(self, tmp_path: Path) -> None:
        """
        Test loading schema with $ref references.

        Given: A schema file with $ref references
        When: load_schema() is called
        Then: Returns dict preserving $ref structures
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "refs.schema.json"
        schema_data = {
            "$id": "refs.schema.json",
            "properties": {"category": {"$ref": "#/definitions/category"}},
            "definitions": {"category": {"type": "string", "enum": ["cat1", "cat2"]}},
        }
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.load_schema("refs.schema.json")

        assert "$ref" in result["properties"]["category"]
        assert result["properties"]["category"]["$ref"] == "#/definitions/category"

    def test_load_nonexistent_schema_file(self, tmp_path: Path) -> None:
        """
        Test loading non-existent schema file.

        Given: A schema file that doesn't exist
        When: load_schema() is called
        Then: Raises FileNotFoundError with helpful message
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()

        parser = SchemaParser(schema_dir)

        with pytest.raises(FileNotFoundError, match="Schema file.*not found"):
            parser.load_schema("nonexistent.schema.json")

    def test_load_malformed_json(self, tmp_path: Path) -> None:
        """
        Test loading file with invalid JSON syntax.

        Given: A file with malformed JSON
        When: load_schema() is called
        Then: Raises JSONDecodeError with clear message
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "bad.schema.json"
        schema_file.write_text("{invalid json content")

        parser = SchemaParser(schema_dir)

        with pytest.raises(json.JSONDecodeError):
            parser.load_schema("bad.schema.json")

    def test_load_empty_file(self, tmp_path: Path) -> None:
        """
        Test loading empty schema file.

        Given: An empty file
        When: load_schema() is called
        Then: Raises JSONDecodeError
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "empty.schema.json"
        schema_file.write_text("")

        parser = SchemaParser(schema_dir)

        with pytest.raises(json.JSONDecodeError):
            parser.load_schema("empty.schema.json")

    def test_load_non_json_file(self, tmp_path: Path) -> None:
        """
        Test loading file that's not JSON.

        Given: A file with non-JSON content
        When: load_schema() is called
        Then: Raises JSONDecodeError
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "text.schema.json"
        schema_file.write_text("This is plain text, not JSON")

        parser = SchemaParser(schema_dir)

        with pytest.raises(json.JSONDecodeError):
            parser.load_schema("text.schema.json")

    def test_load_schema_with_no_definitions(self, tmp_path: Path) -> None:
        """
        Test loading schema without definitions section.

        Given: A schema file without definitions
        When: load_schema() is called
        Then: Returns dict without definitions key
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "simple.schema.json"
        schema_data = {"$id": "simple.schema.json", "type": "object", "properties": {"name": {"type": "string"}}}
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.load_schema("simple.schema.json")

        assert "definitions" not in result
        assert result["properties"]["name"]["type"] == "string"

    def test_load_schema_with_empty_definitions(self, tmp_path: Path) -> None:
        """
        Test loading schema with empty definitions.

        Given: A schema with definitions: {}
        When: load_schema() is called
        Then: Returns dict with empty definitions dict
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "empty_defs.schema.json"
        schema_data = {"$id": "empty_defs.schema.json", "definitions": {}}
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.load_schema("empty_defs.schema.json")

        assert "definitions" in result
        assert result["definitions"] == {}

    def test_load_very_large_schema(self, tmp_path: Path) -> None:
        """
        Test loading large schema file.

        Given: A large schema file with many enum values
        When: load_schema() is called
        Then: Loads successfully within reasonable time
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "large.schema.json"

        # Create schema with 1000 enum values
        large_enum = [f"value_{i}" for i in range(1000)]
        schema_data = {"$id": "large.schema.json", "properties": {"id": {"type": "string", "enum": large_enum}}}
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.load_schema("large.schema.json")

        assert len(result["properties"]["id"]["enum"]) == 1000

    def test_load_schema_with_special_characters_in_filename(self, tmp_path: Path) -> None:
        """
        Test loading schema with special characters in filename.

        Given: A schema file with hyphens in name
        When: load_schema() is called
        Then: Loads successfully
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "lifecycle-stage.schema.json"
        schema_data = {"$id": "lifecycle-stage.schema.json", "type": "object"}
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.load_schema("lifecycle-stage.schema.json")

        assert result["$id"] == "lifecycle-stage.schema.json"


class TestExtractEnumValues:
    """Test extract_enum_values() method."""

    def test_extract_enum_from_top_level_property(self, tmp_path: Path) -> None:
        """
        Test extracting enum from top-level property.

        Given: Schema with enum at properties.id
        When: extract_enum_values() is called with path "properties.id"
        Then: Returns list of enum values
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"id": {"type": "string", "enum": ["val1", "val2", "val3"]}}}

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "properties.id")

        assert result == ["val1", "val2", "val3"]

    def test_extract_enum_from_nested_definition(self, tmp_path: Path) -> None:
        """
        Test extracting enum from nested definition.

        Given: Schema with enum at definitions.control.properties.category
        When: extract_enum_values() is called with nested path
        Then: Returns list of enum values
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {
            "definitions": {
                "control": {"properties": {"category": {"type": "string", "enum": ["cat1", "cat2", "cat3"]}}}
            }
        }

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "definitions.control.properties.category")

        assert result == ["cat1", "cat2", "cat3"]

    def test_extract_enum_from_deeply_nested_path(self, tmp_path: Path) -> None:
        """
        Test extracting enum from deeply nested path.

        Given: Schema with deeply nested enum
        When: extract_enum_values() is called with deep path
        Then: Returns list of enum values
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {
            "definitions": {
                "level1": {
                    "properties": {"level2": {"items": {"properties": {"level3": {"enum": ["deep1", "deep2"]}}}}}
                }
            }
        }

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(
            schema_data, "definitions.level1.properties.level2.items.properties.level3"
        )

        assert result == ["deep1", "deep2"]

    def test_extract_enum_with_mixed_case_values(self, tmp_path: Path) -> None:
        """
        Test extracting enum with mixed case values.

        Given: Schema with enum containing mixed case strings
        When: extract_enum_values() is called
        Then: Returns values preserving case
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"status": {"enum": ["Active", "INACTIVE", "pending", "Completed"]}}}

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "properties.status")

        assert result == ["Active", "INACTIVE", "pending", "Completed"]

    def test_extract_enum_with_hyphenated_values(self, tmp_path: Path) -> None:
        """
        Test extracting enum with hyphenated values.

        Given: Schema with enum containing hyphenated strings
        When: extract_enum_values() is called
        Then: Returns hyphenated values correctly
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"id": {"enum": ["lifecycle-stage", "impact-type", "actor-access"]}}}

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "properties.id")

        assert result == ["lifecycle-stage", "impact-type", "actor-access"]

    def test_extract_enum_with_special_characters(self, tmp_path: Path) -> None:
        """
        Test extracting enum with special characters.

        Given: Schema with enum containing special characters
        When: extract_enum_values() is called
        Then: Returns values with special characters preserved
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"special": {"enum": ["val_1", "val-2", "val.3", "val@4"]}}}

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "properties.special")

        assert result == ["val_1", "val-2", "val.3", "val@4"]

    def test_extract_enum_nonexistent_field_path(self, tmp_path: Path) -> None:
        """
        Test extracting enum from non-existent field path.

        Given: Schema without the specified field path
        When: extract_enum_values() is called with non-existent path
        Then: Raises KeyError with helpful message
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"name": {"type": "string"}}}

        parser = SchemaParser(schema_dir)

        with pytest.raises(KeyError, match="Field path.*not found"):
            parser.extract_enum_values(schema_data, "properties.nonexistent")

    def test_extract_enum_field_exists_but_no_enum(self, tmp_path: Path) -> None:
        """
        Test extracting enum from field that exists but has no enum.

        Given: Schema with field that has no enum property
        When: extract_enum_values() is called
        Then: Raises KeyError indicating no enum found
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"name": {"type": "string", "minLength": 1}}}

        parser = SchemaParser(schema_dir)

        with pytest.raises(KeyError, match="No enum found"):
            parser.extract_enum_values(schema_data, "properties.name")

    def test_extract_enum_empty_field_path(self, tmp_path: Path) -> None:
        """
        Test extracting enum with empty field path.

        Given: Empty field path string
        When: extract_enum_values() is called
        Then: Raises ValueError with clear message
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"id": {"enum": ["val1"]}}}

        parser = SchemaParser(schema_dir)

        with pytest.raises(ValueError, match="Field path cannot be empty"):
            parser.extract_enum_values(schema_data, "")

    def test_extract_enum_malformed_field_path(self, tmp_path: Path) -> None:
        """
        Test extracting enum with malformed field path.

        Given: Field path with invalid format (e.g., leading/trailing dots, empty components)
        When: extract_enum_values() is called
        Then: Raises ValueError with clear message about invalid path format
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"id": {"enum": ["val1"]}}}

        parser = SchemaParser(schema_dir)

        # Leading dot - ValueError for malformed path
        with pytest.raises(ValueError, match="Invalid field path|empty|leading"):
            parser.extract_enum_values(schema_data, ".properties.id")

        # Trailing dot - ValueError for malformed path
        with pytest.raises(ValueError, match="Invalid field path|empty|trailing"):
            parser.extract_enum_values(schema_data, "properties.id.")

        # Empty path component (double dots) - ValueError for malformed path
        with pytest.raises(ValueError, match="Invalid field path|empty"):
            parser.extract_enum_values(schema_data, "properties..id")

        # Empty path - ValueError for malformed path
        with pytest.raises(ValueError, match="Field path cannot be empty|Invalid"):
            parser.extract_enum_values(schema_data, "")

    def test_extract_empty_enum_array(self, tmp_path: Path) -> None:
        """
        Test extracting empty enum array.

        Given: Schema with enum: []
        When: extract_enum_values() is called
        Then: Returns empty list
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"id": {"type": "string", "enum": []}}}

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "properties.id")

        assert result == []

    def test_extract_enum_with_one_value(self, tmp_path: Path) -> None:
        """
        Test extracting enum with single value.

        Given: Schema with enum containing one value
        When: extract_enum_values() is called
        Then: Returns list with one value
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"id": {"enum": ["onlyValue"]}}}

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "properties.id")

        assert result == ["onlyValue"]

    def test_extract_enum_with_duplicate_values(self, tmp_path: Path) -> None:
        """
        Test extracting enum with duplicate values.

        Given: Schema with enum containing duplicates
        When: extract_enum_values() is called
        Then: Returns values as-is (including duplicates)
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"id": {"enum": ["val1", "val2", "val1", "val3"]}}}

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "properties.id")

        # Should preserve duplicates as found in schema
        assert result == ["val1", "val2", "val1", "val3"]

    def test_extract_enum_does_not_follow_ref_pointers(self, tmp_path: Path) -> None:
        """
        Test that extract_enum_values does NOT automatically follow $ref pointers.

        Given: Schema where target field uses $ref to point to enum definition
        When: extract_enum_values() is called on the field with $ref
        Then: Raises KeyError indicating no direct enum found (callers must resolve $ref first)

        Design Decision:
        - extract_enum_values() extracts enums from the exact path specified
        - It does NOT automatically resolve $ref pointers (keeps implementation simple)
        - Callers can use separate logic to resolve $ref if needed
        - This matches JSON Schema validator behavior (refs are resolved by validators)
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {
            "definitions": {
                "category": {"properties": {"id": {"enum": ["cat1", "cat2"]}}},
                "control": {"properties": {"category": {"$ref": "#/definitions/category/properties/id"}}},
            }
        }

        parser = SchemaParser(schema_dir)

        # Attempting to extract from a $ref field should raise KeyError
        with pytest.raises(KeyError, match="No enum found|'enum'"):
            parser.extract_enum_values(schema_data, "definitions.control.properties.category")

        # However, extracting from the actual definition works
        result = parser.extract_enum_values(schema_data, "definitions.category.properties.id")
        assert result == ["cat1", "cat2"]

    def test_extract_enum_from_array_items(self, tmp_path: Path) -> None:
        """
        Test extracting enum from array items definition.

        Given: Schema with enum inside items definition (for array-type fields)
        When: extract_enum_values() is called with path ending in .items
        Then: Returns enum values from items definition

        This pattern is used in frameworks.schema.json for applicableTo:
        "applicableTo": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": ["controls", "risks", "components", "personas"]
          }
        }
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {
            "properties": {
                "tags": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["tag1", "tag2", "tag3"]},
                }
            }
        }

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "properties.tags.items")

        assert result == ["tag1", "tag2", "tag3"]

    def test_extract_enum_from_deeply_nested_array_items(self, tmp_path: Path) -> None:
        """
        Test extracting enum from array items in nested definitions.

        Given: Schema with enum in items within definitions
        When: extract_enum_values() is called with full path including .items
        Then: Returns enum values correctly

        Real-world example from frameworks.schema.json:
        definitions.framework.properties.applicableTo.items
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {
            "definitions": {
                "framework": {
                    "properties": {
                        "applicableTo": {
                            "type": "array",
                            "items": {"enum": ["controls", "risks", "components", "personas"]},
                        }
                    }
                }
            }
        }

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "definitions.framework.properties.applicableTo.items")

        assert result == ["controls", "risks", "components", "personas"]


class TestGetRequiredFields:
    """Test get_required_fields() method."""

    def test_get_required_fields_from_simple_schema(self, tmp_path: Path) -> None:
        """
        Test extracting required fields from simple schema.

        Given: Schema with top-level required array
        When: get_required_fields() is called
        Then: Returns list of required field names
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {
            "type": "object",
            "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
            "required": ["name", "age"],
        }

        parser = SchemaParser(schema_dir)
        result = parser.get_required_fields(schema_data)

        assert result == ["name", "age"]

    def test_get_required_fields_from_definitions(self, tmp_path: Path) -> None:
        """
        Test extracting required fields from schema definitions.

        Given: Schema with required fields in definitions
        When: get_required_fields() is called with definition path
        Then: Returns list of required fields from that definition
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {
            "definitions": {
                "control": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    "required": ["id", "title", "description"],
                }
            }
        }

        parser = SchemaParser(schema_dir)
        result = parser.get_required_fields(schema_data["definitions"]["control"])

        assert result == ["id", "title", "description"]

    def test_get_required_fields_partial_required(self, tmp_path: Path) -> None:
        """
        Test extracting required fields when some are optional.

        Given: Schema with more properties than required fields
        When: get_required_fields() is called
        Then: Returns only the required fields
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "description": {"type": "string"},
                "optional": {"type": "string"},
            },
            "required": ["id", "name"],
        }

        parser = SchemaParser(schema_dir)
        result = parser.get_required_fields(schema_data)

        assert result == ["id", "name"]
        assert "description" not in result
        assert "optional" not in result

    def test_get_required_fields_no_required_key(self, tmp_path: Path) -> None:
        """
        Test extracting required fields when schema has no required key.

        Given: Schema without required key
        When: get_required_fields() is called
        Then: Returns empty list
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"type": "object", "properties": {"name": {"type": "string"}}}

        parser = SchemaParser(schema_dir)
        result = parser.get_required_fields(schema_data)

        assert result == []

    def test_get_required_fields_required_is_null(self, tmp_path: Path) -> None:
        """
        Test extracting required fields when required is null.

        Given: Schema with required: null
        When: get_required_fields() is called
        Then: Raises TypeError or returns empty list
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"type": "object", "properties": {"name": {"type": "string"}}, "required": None}

        parser = SchemaParser(schema_dir)

        # Should handle null gracefully
        with pytest.raises(TypeError, match="Required field must be a list"):
            parser.get_required_fields(schema_data)

    def test_get_required_fields_required_is_not_array(self, tmp_path: Path) -> None:
        """
        Test extracting required fields when required is not an array.

        Given: Schema with required as string instead of array
        When: get_required_fields() is called
        Then: Raises TypeError with clear message
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": "name",  # Should be array
        }

        parser = SchemaParser(schema_dir)

        with pytest.raises(TypeError, match="Required field must be a list"):
            parser.get_required_fields(schema_data)

    def test_get_required_fields_empty_required_array(self, tmp_path: Path) -> None:
        """
        Test extracting required fields from empty required array.

        Given: Schema with required: []
        When: get_required_fields() is called
        Then: Returns empty list
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"type": "object", "properties": {"name": {"type": "string"}}, "required": []}

        parser = SchemaParser(schema_dir)
        result = parser.get_required_fields(schema_data)

        assert result == []

    def test_get_required_fields_nonexistent_property(self, tmp_path: Path) -> None:
        """
        Test required field references non-existent property.

        Given: Schema where required field doesn't exist in properties
        When: get_required_fields() is called
        Then: Returns the required field anyway (schema may be invalid)
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name", "nonexistent"],
        }

        parser = SchemaParser(schema_dir)
        result = parser.get_required_fields(schema_data)

        # Should return what schema says, even if inconsistent
        assert "name" in result
        assert "nonexistent" in result


class TestExtractAllEnums:
    """Test extract_all_enums() method."""

    def test_extract_all_enums_from_controls_schema(self, tmp_path: Path) -> None:
        """
        Test extracting all enums from controls-like schema.

        Given: Schema similar to controls.schema.json with multiple enums
        When: extract_all_enums() is called
        Then: Returns dict mapping field paths to enum values
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "controls.schema.json"
        schema_data = {
            "$id": "controls.schema.json",
            "definitions": {
                "category": {"properties": {"id": {"type": "string", "enum": ["cat1", "cat2", "cat3"]}}},
                "control": {
                    "properties": {
                        "id": {"type": "string", "enum": ["ctrl1", "ctrl2"]},
                        "category": {"$ref": "#/definitions/category/properties/id"},
                    }
                },
            },
        }
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.extract_all_enums("controls.schema.json")

        assert isinstance(result, dict)
        assert "definitions.category.properties.id" in result
        assert "definitions.control.properties.id" in result
        assert result["definitions.category.properties.id"] == ["cat1", "cat2", "cat3"]
        assert result["definitions.control.properties.id"] == ["ctrl1", "ctrl2"]

    def test_extract_all_enums_from_frameworks_schema(self, tmp_path: Path) -> None:
        """
        Test extracting all enums from frameworks-like schema.

        Given: Schema similar to frameworks.schema.json
        When: extract_all_enums() is called
        Then: Returns dict with framework id and applicableTo enums
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "frameworks.schema.json"
        schema_data = {
            "$id": "frameworks.schema.json",
            "definitions": {
                "framework": {
                    "properties": {
                        "id": {"type": "string", "enum": ["fw1", "fw2", "fw3"]},
                        "applicableTo": {
                            "type": "array",
                            "items": {"type": "string", "enum": ["controls", "risks", "components"]},
                        },
                    }
                }
            },
        }
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.extract_all_enums("frameworks.schema.json")

        assert "definitions.framework.properties.id" in result
        assert "definitions.framework.properties.applicableTo.items" in result
        assert result["definitions.framework.properties.id"] == ["fw1", "fw2", "fw3"]
        assert result["definitions.framework.properties.applicableTo.items"] == ["controls", "risks", "components"]

    def test_extract_all_enums_from_schema_with_no_enums(self, tmp_path: Path) -> None:
        """
        Test extracting all enums from schema with no enums.

        Given: Schema with no enum fields
        When: extract_all_enums() is called
        Then: Returns empty dict
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "noenums.schema.json"
        schema_data = {
            "$id": "noenums.schema.json",
            "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
        }
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.extract_all_enums("noenums.schema.json")

        assert result == {}

    def test_extract_all_enums_from_schema_with_nested_enums(self, tmp_path: Path) -> None:
        """
        Test extracting all enums from schema with different nesting levels.

        Given: Schema with enums at multiple nesting levels
        When: extract_all_enums() is called
        Then: Returns all enums with correct paths
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "nested.schema.json"
        schema_data = {
            "$id": "nested.schema.json",
            "properties": {"topLevel": {"enum": ["top1", "top2"]}},
            "definitions": {
                "level1": {"properties": {"level2": {"properties": {"deepEnum": {"enum": ["deep1", "deep2"]}}}}}
            },
        }
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.extract_all_enums("nested.schema.json")

        assert "properties.topLevel" in result
        assert "definitions.level1.properties.level2.properties.deepEnum" in result
        assert result["properties.topLevel"] == ["top1", "top2"]

    def test_extract_all_enums_nonexistent_schema(self, tmp_path: Path) -> None:
        """
        Test extracting all enums from non-existent schema.

        Given: Schema file that doesn't exist
        When: extract_all_enums() is called
        Then: Raises FileNotFoundError
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()

        parser = SchemaParser(schema_dir)

        with pytest.raises(FileNotFoundError):
            parser.extract_all_enums("nonexistent.schema.json")

    def test_extract_all_enums_schema_with_syntax_error(self, tmp_path: Path) -> None:
        """
        Test extracting all enums from schema with syntax errors.

        Given: Schema file with JSON syntax errors
        When: extract_all_enums() is called
        Then: Raises JSONDecodeError
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "bad.schema.json"
        schema_file.write_text("{invalid json")

        parser = SchemaParser(schema_dir)

        with pytest.raises(json.JSONDecodeError):
            parser.extract_all_enums("bad.schema.json")

    def test_extract_all_enums_with_only_one_enum(self, tmp_path: Path) -> None:
        """
        Test extracting all enums when schema has only one enum.

        Given: Schema with single enum field
        When: extract_all_enums() is called
        Then: Returns dict with one entry
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "single.schema.json"
        schema_data = {"$id": "single.schema.json", "properties": {"status": {"enum": ["active", "inactive"]}}}
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)
        result = parser.extract_all_enums("single.schema.json")

        assert len(result) == 1
        assert "properties.status" in result
        assert result["properties.status"] == ["active", "inactive"]


class TestSchemaParserIntegration:
    """Test SchemaParser with real production schemas."""

    def test_load_production_controls_schema(self, production_schema_dir: Path) -> None:
        """
        Test loading actual production controls.schema.json.

        Given: Production controls.schema.json file
        When: load_schema() is called
        Then: Successfully loads with expected structure
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)

        result = parser.load_schema("controls.schema.json")

        assert result["$id"] == "controls.schema.json"
        assert "definitions" in result
        assert "control" in result["definitions"]
        assert "category" in result["definitions"]

    def test_extract_control_category_enum(self, production_schema_dir: Path) -> None:
        """
        Test extracting control category enum from production schema.

        Given: Production controls.schema.json
        When: extract_enum_values() is called for category
        Then: Returns expected category values
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)
        schema_data = parser.load_schema("controls.schema.json")

        result = parser.extract_enum_values(schema_data, "definitions.category.properties.id")

        expected_categories = [
            "controlsData",
            "controlsInfrastructure",
            "controlsModel",
            "controlsApplication",
            "controlsAssurance",
            "controlsGovernance",
        ]
        assert result == expected_categories

    def test_extract_control_id_enum(self, production_schema_dir: Path) -> None:
        """
        Test extracting control ID enum from production schema.

        Given: Production controls.schema.json
        When: extract_enum_values() is called for control.id
        Then: Returns all control IDs
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)
        schema_data = parser.load_schema("controls.schema.json")

        result = parser.extract_enum_values(schema_data, "definitions.control.properties.id")

        # Verify we got control IDs
        assert len(result) > 0
        assert all(id.startswith("control") for id in result)
        # Check a few known control IDs
        assert "controlAdversarialTrainingAndTesting" in result
        assert "controlModelAndDataAccessControls" in result

    def test_extract_control_required_fields(self, production_schema_dir: Path) -> None:
        """
        Test extracting required fields from control definition.

        Given: Production controls.schema.json
        When: get_required_fields() is called on control definition
        Then: Returns expected required fields
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)
        schema_data = parser.load_schema("controls.schema.json")

        result = parser.get_required_fields(schema_data["definitions"]["control"])

        expected_required = ["title", "description", "category", "personas", "components", "risks"]
        assert all(field in result for field in expected_required)

    def test_load_production_frameworks_schema(self, production_schema_dir: Path) -> None:
        """
        Test loading actual production frameworks.schema.json.

        Given: Production frameworks.schema.json file
        When: load_schema() is called
        Then: Successfully loads with expected structure
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)

        result = parser.load_schema("frameworks.schema.json")

        assert result["$id"] == "frameworks.schema.json"
        assert "definitions" in result
        assert "framework" in result["definitions"]

    def test_extract_framework_id_enum(self, production_schema_dir: Path) -> None:
        """
        Test extracting framework ID enum from production schema.

        Given: Production frameworks.schema.json
        When: extract_enum_values() is called for framework.id
        Then: Returns expected framework IDs
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)
        schema_data = parser.load_schema("frameworks.schema.json")

        result = parser.extract_enum_values(schema_data, "definitions.framework.properties.id")

        # Updated after removing test framework IDs from schema enum
        expected_frameworks = ["mitre-atlas", "nist-ai-rmf", "stride", "owasp-top10-llm"]
        assert result == expected_frameworks

    def test_extract_framework_applicable_to_enum(self, production_schema_dir: Path) -> None:
        """
        Test extracting applicableTo enum from frameworks schema.

        Given: Production frameworks.schema.json
        When: extract_enum_values() is called for applicableTo items
        Then: Returns expected entity types
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)
        schema_data = parser.load_schema("frameworks.schema.json")

        result = parser.extract_enum_values(schema_data, "definitions.framework.properties.applicableTo.items")

        expected_applicable = ["controls", "risks", "components", "personas"]
        assert result == expected_applicable

    def test_load_production_lifecycle_stage_schema(self, production_schema_dir: Path) -> None:
        """
        Test loading actual production lifecycle-stage.schema.json.

        Given: Production lifecycle-stage.schema.json file
        When: load_schema() is called
        Then: Successfully loads with expected structure
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)

        result = parser.load_schema("lifecycle-stage.schema.json")

        assert result["$id"] == "lifecycle-stage.schema.json"
        assert "definitions" in result
        assert "lifecycleStage" in result["definitions"]

    def test_extract_lifecycle_stage_enum(self, production_schema_dir: Path) -> None:
        """
        Test extracting lifecycle stage enum from production schema.

        Given: Production lifecycle-stage.schema.json
        When: extract_enum_values() is called
        Then: Returns expected lifecycle stages
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)
        schema_data = parser.load_schema("lifecycle-stage.schema.json")

        result = parser.extract_enum_values(schema_data, "definitions.lifecycleStage.properties.id")

        expected_stages = [
            "planning",
            "data-preparation",
            "model-training",
            "development",
            "evaluation",
            "deployment",
            "runtime",
            "maintenance",
        ]
        assert result == expected_stages

    def test_extract_all_enums_from_production_controls(self, production_schema_dir: Path) -> None:
        """
        Test extracting all enums from production controls schema.

        Given: Production controls.schema.json
        When: extract_all_enums() is called
        Then: Returns all enum fields with correct values
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)

        result = parser.extract_all_enums("controls.schema.json")

        # Should find category enum
        assert "definitions.category.properties.id" in result
        # Should find control id enum
        assert "definitions.control.properties.id" in result
        # Verify some values
        assert "controlsData" in result["definitions.category.properties.id"]

    def test_extract_all_enums_from_production_frameworks(self, production_schema_dir: Path) -> None:
        """
        Test extracting all enums from production frameworks schema.

        Given: Production frameworks.schema.json
        When: extract_all_enums() is called
        Then: Returns framework enums
        """
        schema_dir = production_schema_dir
        parser = SchemaParser(schema_dir)

        result = parser.extract_all_enums("frameworks.schema.json")

        assert "definitions.framework.properties.id" in result
        assert "definitions.framework.properties.applicableTo.items" in result
        assert "mitre-atlas" in result["definitions.framework.properties.id"]


class TestSchemaParserErrorHandling:
    """Test SchemaParser error handling."""

    def test_graceful_file_not_found_error(self, tmp_path: Path) -> None:
        """
        Test graceful handling of FileNotFoundError.

        Given: Non-existent schema file
        When: load_schema() is called
        Then: Raises FileNotFoundError with clear, helpful message
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        parser = SchemaParser(schema_dir)

        with pytest.raises(FileNotFoundError) as exc_info:
            parser.load_schema("missing.schema.json")

        error_msg = str(exc_info.value)
        assert "missing.schema.json" in error_msg
        assert "not found" in error_msg.lower()

    def test_graceful_json_decode_error(self, tmp_path: Path) -> None:
        """
        Test graceful handling of JSONDecodeError.

        Given: Schema file with invalid JSON
        When: load_schema() is called
        Then: Raises JSONDecodeError with helpful context
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "invalid.schema.json"
        schema_file.write_text("{'bad': json}")

        parser = SchemaParser(schema_dir)

        with pytest.raises(json.JSONDecodeError):
            parser.load_schema("invalid.schema.json")

    def test_graceful_key_error_handling(self, tmp_path: Path) -> None:
        """
        Test graceful handling of missing keys (KeyError).

        Given: Schema missing expected keys
        When: extract_enum_values() is called with invalid path
        Then: Raises KeyError with clear message about path
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"properties": {"name": {"type": "string"}}}

        parser = SchemaParser(schema_dir)

        with pytest.raises(KeyError) as exc_info:
            parser.extract_enum_values(schema_data, "properties.missing.enum")

        error_msg = str(exc_info.value)
        assert "properties.missing.enum" in error_msg or "not found" in error_msg.lower()

    def test_graceful_type_error_handling(self, tmp_path: Path) -> None:
        """
        Test graceful handling of wrong types (TypeError).

        Given: Schema with required field as wrong type
        When: get_required_fields() is called
        Then: Raises TypeError with clear message
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"required": "should_be_array"}

        parser = SchemaParser(schema_dir)

        with pytest.raises(TypeError) as exc_info:
            parser.get_required_fields(schema_data)

        error_msg = str(exc_info.value)
        assert "list" in error_msg.lower() or "array" in error_msg.lower()

    def test_clear_error_message_for_debugging(self, tmp_path: Path) -> None:
        """
        Test that error messages are clear and helpful for debugging.

        Given: Various error conditions
        When: Operations fail
        Then: Error messages include relevant context
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        parser = SchemaParser(schema_dir)

        # Test missing file error includes filename
        try:
            parser.load_schema("debug_test.schema.json")
        except FileNotFoundError as e:
            assert "debug_test.schema.json" in str(e)

        # Test missing path error includes path
        try:
            parser.extract_enum_values({}, "missing.path.to.enum")
        except (KeyError, ValueError) as e:
            assert "path" in str(e).lower() or "missing" in str(e).lower()


class TestSchemaParserPathResolution:
    """Test path resolution in SchemaParser."""

    def test_field_path_with_dots(self, tmp_path: Path) -> None:
        """
        Test field path with dot notation.

        Given: Schema with nested structure
        When: field_path uses dots (e.g., "definitions.control.properties.id")
        Then: Correctly navigates nested structure
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"definitions": {"control": {"properties": {"id": {"enum": ["val1", "val2"]}}}}}

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "definitions.control.properties.id")

        assert result == ["val1", "val2"]

    def test_field_path_with_multiple_levels(self, tmp_path: Path) -> None:
        """
        Test field path with many nesting levels.

        Given: Deeply nested schema structure
        When: field_path has 5+ levels
        Then: Successfully navigates deep structure
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_data = {"a": {"b": {"c": {"d": {"e": {"enum": ["deep"]}}}}}}

        parser = SchemaParser(schema_dir)
        result = parser.extract_enum_values(schema_data, "a.b.c.d.e")

        assert result == ["deep"]

    def test_absolute_vs_relative_schema_directory(self, tmp_path: Path) -> None:
        """
        Test SchemaParser with absolute vs relative paths.

        Given: Schema directory specified as absolute path
        When: SchemaParser is initialized
        Then: Works correctly with absolute path
        """
        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "test.schema.json"
        schema_file.write_text(json.dumps({"type": "object"}))

        # Test with absolute path
        parser_abs = SchemaParser(schema_dir.absolute())
        result = parser_abs.load_schema("test.schema.json")
        assert result["type"] == "object"


class TestSchemaParserPerformance:
    """Test SchemaParser performance characteristics (optional)."""

    def test_load_large_schema_performance(self, tmp_path: Path) -> None:
        """
        Test loading large schema completes quickly.

        Given: A large schema file (1000+ enum values)
        When: load_schema() is called
        Then: Completes in under 100ms
        """
        import time

        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "large.schema.json"

        # Create large schema
        large_enum = [f"value_{i}" for i in range(1000)]
        schema_data = {"properties": {"id": {"enum": large_enum}}}
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)

        start = time.time()
        result = parser.load_schema("large.schema.json")
        elapsed = time.time() - start

        assert elapsed < 0.1  # Should complete in under 100ms
        assert len(result["properties"]["id"]["enum"]) == 1000

    def test_extract_all_enums_efficient(self, tmp_path: Path) -> None:
        """
        Test extracting all enums is efficient.

        Given: Schema with many enum fields
        When: extract_all_enums() is called
        Then: Completes efficiently
        """
        import time

        schema_dir = tmp_path / "schemas"
        schema_dir.mkdir()
        schema_file = schema_dir / "many_enums.schema.json"

        # Create schema with multiple enums
        schema_data = {
            "definitions": {
                f"def_{i}": {"properties": {"id": {"enum": [f"val_{j}" for j in range(10)]}}} for i in range(20)
            }
        }
        schema_file.write_text(json.dumps(schema_data))

        parser = SchemaParser(schema_dir)

        start = time.time()
        result = parser.extract_all_enums("many_enums.schema.json")
        elapsed = time.time() - start

        assert elapsed < 0.5  # Should be reasonably fast
        assert len(result) == 20  # Found all enums
