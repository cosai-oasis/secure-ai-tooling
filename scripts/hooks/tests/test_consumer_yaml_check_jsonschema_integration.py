#!/usr/bin/env python3
"""
Integration tests for check-jsonschema acceptance across the consumer YAML corpus.

The load-bearing acceptance criterion for the additive schema work is that
all current YAML files continue to pass check-jsonschema. These tests shell
out to check-jsonschema (the same tool used by the pre-commit hook) to give
end-to-end coverage from the file layer.

This complements the unit-level behavioral tests in the individual schema
test modules (test_consumer_external_references_refs.py,
test_components_mappings_field.py, test_consumer_mappings_per_framework_wiring.py,
test_lifecycle_stage_order_range.py, test_riskmap_prose_strict.py,
test_persona_site_data_prose_items.py).

Coverage:
- risks.yaml passes risks.schema.json.
- controls.yaml passes controls.schema.json.
- components.yaml passes components.schema.json.
- personas.yaml passes personas.schema.json.
- lifecycle-stage.yaml passes lifecycle-stage.schema.json.

Note: riskmap.schema.json and persona-site-data.schema.json are not paired
with a standalone YAML file in the repo (riskmap.schema.json is a shared
utility; persona-site-data.schema.json validates generated JSON). Those
schemas are validated structurally in their respective unit test modules.
"""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# Module-level constants
# ============================================================================

# Each tuple: (schema filename, yaml filename).
YAML_SCHEMA_PAIRS: list[tuple[str, str]] = [
    ("risks.schema.json", "risks.yaml"),
    ("controls.schema.json", "controls.yaml"),
    ("components.schema.json", "components.yaml"),
    ("personas.schema.json", "personas.yaml"),
    ("lifecycle-stage.schema.json", "lifecycle-stage.yaml"),
]


# ============================================================================
# Fixtures
# ============================================================================


def _run_check_jsonschema(schema_path: Path, yaml_path: Path, base_uri: str) -> subprocess.CompletedProcess:
    """
    Invoke check-jsonschema for one (schema, yaml) pair.

    Uses list-form invocation (no shell=True) and captures output.
    """
    return subprocess.run(
        [
            "check-jsonschema",
            "--base-uri",
            base_uri,
            "--schemafile",
            str(schema_path),
            str(yaml_path),
        ],
        capture_output=True,
        text=True,
    )


# ============================================================================
# Integration checks — all YAML files remain valid
# ============================================================================


class TestAllConsumerYamlFilesPassCheckJsonschema:
    """
    All five consumer YAML files must pass check-jsonschema. This is the
    machine-readable form of the additive-edit acceptance criterion:
    additive schema changes must not break existing content.
    """

    @pytest.mark.parametrize(
        "schema_file,yaml_file",
        YAML_SCHEMA_PAIRS,
        ids=[pair[1] for pair in YAML_SCHEMA_PAIRS],
    )
    def test_yaml_passes_check_jsonschema(
        self,
        risk_map_schemas_dir: Path,
        risk_map_yaml_dir: Path,
        schema_file: str,
        yaml_file: str,
    ):
        """
        Test that each consumer YAML passes check-jsonschema.

        Given: The current YAML file on disk and its consumer schema
        When: check-jsonschema --base-uri --schemafile is invoked
        Then: Exit code is 0 (additive edits must not break existing content)
        """
        schema_path = risk_map_schemas_dir / schema_file
        yaml_path = risk_map_yaml_dir / yaml_file
        base_uri = f"file://{risk_map_schemas_dir}/"

        result = _run_check_jsonschema(schema_path, yaml_path, base_uri)
        assert result.returncode == 0, (
            f"{yaml_file} must pass {schema_file}:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ============================================================================
# Sanity — check-jsonschema is available
# ============================================================================


class TestCheckJsonschemaAvailable:
    """check-jsonschema must be installed for the integration tests to be meaningful."""

    def test_check_jsonschema_is_on_path(self):
        """
        Test that check-jsonschema is available in the environment.

        Given: The test execution environment
        When: check-jsonschema --version is run
        Then: Exit code is 0 and some version string is output

        If this test fails the integration tests above will also fail with a
        FileNotFoundError rather than an assertion error, which is confusing.
        This check makes that dependency explicit.
        """
        result = subprocess.run(
            ["check-jsonschema", "--version"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            "check-jsonschema is not installed or not on PATH; install with: uv sync --locked"
        )


# ============================================================================
# Test summary
# ============================================================================
"""
Test Summary
============
Test classes: 2

- TestAllConsumerYamlFilesPassCheckJsonschema — parametrized: 5 (schema, yaml)
                                                pairs; each must return
                                                check-jsonschema exit=0
- TestCheckJsonschemaAvailable (1)            — sanity: tool present and
                                                executable

Coverage areas:
- Acceptance criterion: all current YAML remains valid against its consumer schema
- Schemas covered: risks, controls, components, personas, lifecycle-stage
- End-to-end: uses check-jsonschema (same as pre-commit hook) rather than
  Python jsonschema, giving real cross-$ref resolution and file-URI handling
"""
