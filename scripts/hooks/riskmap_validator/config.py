"""
Configuration constants for the risk map validator.

Contains default file paths and configuration values used throughout
the validation and graph generation system.
"""

from pathlib import Path

# Central location for all default file paths and other constants
DEFAULT_COMPONENTS_FILE = Path("risk-map/yaml/components.yaml")
DEFAULT_MERMAID_CONFIG_FILE = Path("risk-map/yaml/mermaid-styles.yaml")
DEFAULT_COMPONENTS_SCHEMA_FILE = Path("risk-map/schemas/components.schema.json")
