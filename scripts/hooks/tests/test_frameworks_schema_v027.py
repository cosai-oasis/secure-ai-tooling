#!/usr/bin/env python3
"""
Tests for the ADR-027 schema additions to risk-map/schemas/frameworks.schema.json.

Scope (additive, non-breaking):
  - New optional registry fields on definitions/framework: versionId, supersedes,
    priorVersions (D2a, D2c).
  - New parallel definitions block definitions/framework-mapping-patterns-pinned
    with version-anchored per-framework value patterns and the ISO 22989
    closed controlled-vocabulary enum (D3a, D6, D7, D8).

The existing definitions/framework-mapping-patterns block (ADR-022 D5b) is
tested here as a regression guard — it must stay byte-stable. The pinned block
is a sibling, not a replacement; consumer-schema $ref swaps happen in #343.

Authoritative spec: docs/adr/027-framework-versioning-and-mapping-convention.md
D-section citations in each docstring trace the test's "why" to the ADR.

TestExistingEntriesStillValidate and TestExistingFrameworkMappingPatternsBlockUnchanged
assert backward compatibility — the additions must not disturb the entries or the
legacy pattern block that validated before them.
"""

import json
import re
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry

sys.path.insert(0, str(Path(__file__).parent.parent))

# Pull in the legacy-block constants for the regression guard (TestExistingFrameworkMappingPatternsBlockUnchanged).
# These are the exact ADR-022 D5b pattern strings the implementation must not touch.
from test_framework_mapping_patterns import EXPECTED_FRAMEWORK_KEYS, FRAMEWORK_PATTERN_TABLE  # noqa: E402

# ============================================================================
# Module-level tables — pinned valid/invalid examples per framework (D3a, D6)
# ============================================================================

# The 6 current framework ids that must appear as keys in the pinned block.
# Drift-detection test (TestNewBlockStructure) compares this against
# definitions/framework/properties/id/enum at runtime.
PINNED_BLOCK_EXPECTED_KEYS = {
    "mitre-atlas",
    "nist-ai-rmf",
    "stride",
    "owasp-top10-llm",
    "iso-22989",
    "eu-ai-act",
}

# The charset pattern the versionId field (and supersedes/priorVersions members)
# must enforce per D2a.
VERSION_ID_CHARSET_PATTERN = r"^[a-z0-9.@-]+$"

# ISO 22989 2022 closed-vocabulary enum members, version-pinned (D8).
ISO_22989_2022_ENUM = [
    "AI Producer@2022",
    "AI Customer (application builder)@2022",
    "AI Customer (end user)@2022",
    "AI Partner (data supplier)@2022",
    "AI Partner (infrastructure provider)@2022",
    "AI Partner (tooling provider)@2022",
]

# Per-framework pinned valid/invalid example table (D3a, D6, D7).
# Keys equal the 4 ID-bearing versioned frameworks; stride and iso-22989 have
# dedicated test classes (TestStridePinnedEntry, TestIso22989PinnedEntry) so
# they are excluded from the parametrized ID-bearing tests.
PINNED_PATTERN_TABLE: dict[str, dict] = {
    "mitre-atlas": {
        # D3a: spec-native base + @<version> token; version anchored to 5.0.1.
        # D6: spec-native AML.(T|M)NNNN(.NNN)? canonical base form.
        "pattern_contains": "@(5\\.0\\.1)",  # the version alternation must appear
        "valid": [
            "AML.T0020@5.0.1",  # technique, bare
            "AML.M0007@5.0.1",  # mitigation, bare
            "AML.T0020.001@5.0.1",  # technique with sub-technique
        ],
        "invalid": [
            "AML.T0020",  # un-pinned legacy form (no version token)
            "AML.T0020@9.9.9",  # unknown version
            "AML.T0020@5.0.0",  # close-but-wrong version
            "aml.t0020@5.0.1",  # wrong case
            "AML.T0020 @5.0.1",  # whitespace before @
        ],
    },
    "nist-ai-rmf": {
        # D3a: GOVERN/MAP/MEASURE/MANAGE-N(.N)* + @1.0 token.
        # D6: canonical long-form prefix (not legacy GV-/MS-/etc. abbreviations).
        "pattern_contains": "@(1\\.0)",
        "valid": [
            "GOVERN-6.2@1.0",  # function-subcategory with decimal, @version
            "MAP-2.3@1.0",  # MAP function
            "MEASURE-1@1.0",  # MEASURE, whole number sub-id
            "MANAGE-4.5.1@1.0",  # multi-level sub-id
        ],
        "invalid": [
            "GV-6.2@1.0",  # legacy short prefix (not canonical base per D6)
            "GOVERN-6.2",  # un-pinned (no @version token)
            "GOVERN-6.2@2.0",  # unknown version
            "GOVERN_6.2@1.0",  # underscore delimiter
            # D2b float-coercion guard: YAML parses version key `1.0` as float 1.0,
            # which serialises back to `1` (losing the trailing zero). Only @(1\.0)
            # is valid; @1 (the float-coerced form) must be rejected.
            "GOVERN-6.2@1",  # float-coerced version (1.0 -> 1 per D2b warning)
        ],
    },
    "owasp-top10-llm": {
        # D6: OWASP retains :YYYY token (already version-bearing, the prototype).
        # Pattern anchors to :2025 (the current version in frameworks.yaml).
        "pattern_contains": ":2025",
        "valid": [
            "LLM01:2025",
            "LLM05:2025",
            "LLM10:2025",
        ],
        "invalid": [
            "LLM04",  # un-pinned legacy form
            "LLM01:2024",  # unknown version (OWASP 2025 is current)
            "LLM01:2023",  # unknown version
            "llm01:2025",  # wrong case
            "LLM1:2025",  # single digit (must be two digits)
            "LLM01@2025",  # wrong delimiter (should be colon, not @)
        ],
    },
    "eu-ai-act": {
        # D3a: Article N(n) + @2024 token (current version 2024 per frameworks.yaml).
        "pattern_contains": "@(2024)",
        "valid": [
            "Article 50@2024",
            "Article 5@2024",
            "Article 6(2)@2024",
        ],
        "invalid": [
            "Article 50",  # un-pinned (no version token)
            "Article 50@2021",  # unknown version
            "Article 50@2025",  # unknown version (not in registry)
            "Article 50 @2024",  # whitespace before @
        ],
    },
}

# STRIDE valid/invalid (D6: unversioned — no token; frozen by enum).
STRIDE_VALID = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "InformationDisclosure",
    "DenialOfService",
    "ElevationOfPrivilege",
]
STRIDE_INVALID = [
    "spoofing",  # lowercase
    "information-disclosure",  # hyphenated legacy form
    "dos",  # abbreviation
    "ElevationPrivilege",  # truncated
    "Stride",  # framework name, not a category
]

# ISO 22989 valid (pinned) and invalid (un-pinned or wrong version or spelling).
ISO_22989_VALID = ISO_22989_2022_ENUM  # all 6 @2022 forms

ISO_22989_INVALID = [
    "AI Producer",  # un-pinned bare string
    "AI Partner (data supplier)",  # un-pinned bare string
    "AI Producer@2023",  # unknown version
    "AI Part (Data supplier)@2022",  # spelling variant (outside enum)
    "AI Producer @2022",  # whitespace before @
    "ai producer@2022",  # wrong case
]

# versionId field valid/invalid examples (D2a charset ^[a-z0-9.@-]+$).
VERSION_ID_VALID = [
    "mitre-atlas@5.0.1",
    "nist-ai-rmf@1.0",
    "stride",  # unversioned: bare concept id, no @
    "owasp-top10-llm@2025",
    "eu-ai-act@2024",
    "iso-22989@2022",
]
VERSION_ID_INVALID = [
    "Mitre-ATLAS@5.0.1",  # uppercase letters
    "mitre atlas@5.0.1",  # whitespace
    "mitre/atlas@5.0.1",  # slash character
    "",  # empty string (fails pattern)
]


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def frameworks_schema(frameworks_schema_path: Path) -> dict:
    """Parsed frameworks.schema.json contents."""
    if not frameworks_schema_path.is_file():
        pytest.fail(
            f"frameworks.schema.json not found at {frameworks_schema_path}; "
            "this is a baseline file that should already exist"
        )
    with open(frameworks_schema_path) as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def framework_definition(frameworks_schema: dict) -> dict:
    """The definitions/framework object definition."""
    defs = frameworks_schema.get("definitions", {})
    if "framework" not in defs:
        pytest.fail("definitions/framework missing from frameworks.schema.json")
    return defs["framework"]


@pytest.fixture(scope="module")
def framework_properties(framework_definition: dict) -> dict:
    """Properties dict of definitions/framework."""
    props = framework_definition.get("properties", {})
    if not props:
        pytest.fail("definitions/framework.properties is empty or missing")
    return props


@pytest.fixture(scope="module")
def legacy_mapping_patterns(frameworks_schema: dict) -> dict:
    """The existing definitions/framework-mapping-patterns block (ADR-022 D5b)."""
    defs = frameworks_schema.get("definitions", {})
    if "framework-mapping-patterns" not in defs:
        pytest.fail(
            "definitions/framework-mapping-patterns missing from frameworks.schema.json; "
            "this block must exist per ADR-022 D5b"
        )
    return defs["framework-mapping-patterns"]


@pytest.fixture(scope="module")
def pinned_mapping_patterns(frameworks_schema: dict) -> dict:
    """
    The new definitions/framework-mapping-patterns-pinned block (ADR-027).

    Fails with a clear message if the block is absent — the block must be added
    without touching the existing framework-mapping-patterns block.
    """
    defs = frameworks_schema.get("definitions", {})
    if "framework-mapping-patterns-pinned" not in defs:
        pytest.fail(
            "definitions/framework-mapping-patterns-pinned missing from frameworks.schema.json; "
            "this block must be added per ADR-027 (additive, does not modify "
            "the existing framework-mapping-patterns block)."
        )
    return defs["framework-mapping-patterns-pinned"]


@pytest.fixture(scope="module")
def frameworks_yaml_data(frameworks_yaml_path: Path) -> dict:
    """Parsed frameworks.yaml contents."""
    if not frameworks_yaml_path.is_file():
        pytest.fail(f"frameworks.yaml not found at {frameworks_yaml_path}")
    with open(frameworks_yaml_path) as fh:
        return yaml.safe_load(fh)


# ============================================================================
# TestNewBlockPresence
# ============================================================================


class TestNewBlockPresence:
    """
    The new framework-mapping-patterns-pinned block must be present as an
    additive sibling of the existing framework-mapping-patterns block.

    The existing block's presence and key-set must remain byte-stable so
    that the ADR-022 D5b consumer-schema $refs and the existing test file
    continue to work unchanged.

    D-sections: ADR-027 additive scope, D3a, D7 ("additive, non-breaking").
    """

    def test_pinned_block_is_present(self, frameworks_schema: dict):
        """
        Test that the new pinned block has been added to definitions.

        Given: frameworks.schema.json after the schema additions
        When: definitions/framework-mapping-patterns-pinned is looked up
        Then: The key exists (ADR-027 additive requirement)
        """
        assert "framework-mapping-patterns-pinned" in frameworks_schema.get("definitions", {}), (
            "definitions/framework-mapping-patterns-pinned must be added per ADR-027"
        )

    def test_legacy_block_still_present(self, frameworks_schema: dict):
        """
        Test that the existing ADR-022 D5b block has NOT been removed or renamed.

        Given: frameworks.schema.json after the schema additions
        When: definitions/framework-mapping-patterns is looked up
        Then: The key still exists (consumer $refs point at it; must not be disturbed)
        """
        assert "framework-mapping-patterns" in frameworks_schema.get("definitions", {}), (
            "definitions/framework-mapping-patterns must NOT be removed or renamed; "
            "consumer schemas ($ref in risks/controls/personas) still point at it"
        )

    def test_legacy_block_has_six_keys(self, legacy_mapping_patterns: dict):
        """
        Test that the legacy block retains exactly 6 keys.

        Given: definitions/framework-mapping-patterns
        When: Its properties keys are examined
        Then: They are the 6 keys from ADR-022 D5b — no additions, no removals
        """
        actual_keys = set(legacy_mapping_patterns.get("properties", {}).keys())
        assert actual_keys == EXPECTED_FRAMEWORK_KEYS, (
            f"Legacy framework-mapping-patterns keys must equal {EXPECTED_FRAMEWORK_KEYS}; got {actual_keys}"
        )

    @pytest.mark.parametrize("framework_key", sorted(FRAMEWORK_PATTERN_TABLE.keys()))
    def test_legacy_block_patterns_are_byte_stable(self, legacy_mapping_patterns: dict, framework_key: str):
        """
        Test that each ADR-022 D5b pattern string is unchanged.

        Given: The legacy framework-mapping-patterns block
        When: Each framework entry's 'pattern' is read
        Then: It equals the string committed in ADR-022 D5b verbatim

        The pattern strings are load-bearing; tightening them would break
        existing content that is still in the legacy (un-pinned) form.
        ADR-027 explicitly requires the legacy block to stay byte-stable
        until #343 migrates values and flips consumer $refs to the pinned block.

        D-sections: D7 ("existing block stays as-is"), #343 ordering invariant.
        """
        entry = legacy_mapping_patterns["properties"].get(framework_key)
        assert entry is not None, f"Legacy block missing entry for {framework_key!r}"
        if "pattern" in FRAMEWORK_PATTERN_TABLE[framework_key]:
            expected_pattern = FRAMEWORK_PATTERN_TABLE[framework_key]["pattern"]
            actual_pattern = entry.get("pattern")
            assert actual_pattern == expected_pattern, (
                f"Legacy pattern for {framework_key!r} has drifted from ADR-022 D5b:\n"
                f"  expected: {expected_pattern!r}\n"
                f"  actual:   {actual_pattern!r}"
            )


# ============================================================================
# TestNewBlockStructure
# ============================================================================


class TestNewBlockStructure:
    """
    The new framework-mapping-patterns-pinned block must have the same outer
    shape as the legacy block: type:object, additionalProperties:false, 6 keys
    matching the framework.id enum.

    D-sections: D3a, D7 ("same outer shape as the legacy block").
    """

    def test_pinned_block_is_object_type(self, pinned_mapping_patterns: dict):
        """
        Test that the pinned block declares type: object.

        Given: definitions/framework-mapping-patterns-pinned
        When: Its 'type' is examined
        Then: It is 'object' (mirrors the legacy block's outer shape per D7)
        """
        assert pinned_mapping_patterns.get("type") == "object", (
            "framework-mapping-patterns-pinned must be type:object"
        )

    def test_pinned_block_uses_additional_properties_false(self, pinned_mapping_patterns: dict):
        """
        Test that the pinned block is a closed schema.

        Given: definitions/framework-mapping-patterns-pinned
        When: 'additionalProperties' is examined
        Then: It is False (closed schema, mirrors the legacy block per D7)
        """
        assert pinned_mapping_patterns.get("additionalProperties") is False, (
            "framework-mapping-patterns-pinned must set additionalProperties: false"
        )

    def test_pinned_block_has_six_keys(self, pinned_mapping_patterns: dict):
        """
        Test that the pinned block has exactly 6 framework keys.

        Given: definitions/framework-mapping-patterns-pinned
        When: Its 'properties' keys are examined
        Then: They equal the 6-framework set: mitre-atlas, nist-ai-rmf, stride,
              owasp-top10-llm, iso-22989, eu-ai-act

        D-sections: D3a ("same outer shape"), D7 (6 keys equal framework.id enum).
        """
        properties = pinned_mapping_patterns.get("properties", {})
        actual_keys = set(properties.keys())
        assert actual_keys == PINNED_BLOCK_EXPECTED_KEYS, (
            f"framework-mapping-patterns-pinned must have keys {PINNED_BLOCK_EXPECTED_KEYS}; "
            f"missing={PINNED_BLOCK_EXPECTED_KEYS - actual_keys}, "
            f"extra={actual_keys - PINNED_BLOCK_EXPECTED_KEYS}"
        )

    def test_pinned_block_keys_align_with_framework_id_enum(
        self, frameworks_schema: dict, pinned_mapping_patterns: dict
    ):
        """
        Test that the pinned block's keys equal the framework.id enum (drift detection).

        Given: definitions/framework-mapping-patterns-pinned keys
        When: They are compared against definitions/framework/properties/id/enum
        Then: The sets are identical (a key added to the id enum must also appear
              in the pinned block, and vice versa)

        D-sections: D7 ("keys equal the framework.id enum"), same as the legacy block.
        """
        framework_id_enum = set(frameworks_schema["definitions"]["framework"]["properties"]["id"]["enum"])
        pinned_keys = set(pinned_mapping_patterns.get("properties", {}).keys())
        assert pinned_keys == framework_id_enum, (
            "Pinned block keys must equal framework.id enum to prevent drift; "
            f"pinned_keys - id_enum = {pinned_keys - framework_id_enum}, "
            f"id_enum - pinned_keys = {framework_id_enum - pinned_keys}"
        )

    def test_pinned_block_passes_draft07_metaschema(self, pinned_mapping_patterns: dict):
        """
        Test that the pinned block is a valid Draft-07 schema fragment.

        Given: definitions/framework-mapping-patterns-pinned
        When: It is checked against the Draft-07 meta-schema
        Then: No SchemaError is raised

        D-sections: D3a (schema anchored to known versions), D7.
        """
        try:
            Draft7Validator.check_schema(pinned_mapping_patterns)
        except SchemaError as exc:
            pytest.fail(f"framework-mapping-patterns-pinned is not valid Draft-07: {exc.message}")


# ============================================================================
# TestPerFrameworkPinnedPatternCommitments
# ============================================================================


class TestPerFrameworkPinnedPatternCommitments:
    """
    Each ID-bearing versioned framework (mitre-atlas, nist-ai-rmf, owasp-top10-llm,
    eu-ai-act) must declare a 'pattern' whose regex contains the version alternation
    anchored to the current framework version, and must accept/reject the examples
    in PINNED_PATTERN_TABLE.

    STRIDE and ISO 22989 have dedicated test classes (TestStridePinnedEntry,
    TestIso22989PinnedEntry) because their pinning mechanisms differ (frozen enum
    and closed controlled-vocabulary enum respectively).

    D-sections: D3a (version-token grammar), D6 (spec-native canonical forms),
    D7 (value patterns grow a version dimension).
    """

    ID_BEARING_FRAMEWORKS = ["mitre-atlas", "nist-ai-rmf", "owasp-top10-llm", "eu-ai-act"]

    @pytest.mark.parametrize("framework_key", ID_BEARING_FRAMEWORKS)
    def test_entry_declares_pattern(self, pinned_mapping_patterns: dict, framework_key: str):
        """
        Test that each ID-bearing framework entry is type:string with a 'pattern'.

        Given: A pinned-block entry for an ID-bearing framework
        When: Its sub-schema is examined
        Then: It declares type:string and a 'pattern' field

        D-sections: D3a (anchored alternation in the schema's sub-pattern).
        """
        props = pinned_mapping_patterns.get("properties", {})
        entry = props.get(framework_key)
        assert entry is not None, f"Pinned block is missing entry for {framework_key!r}"
        assert entry.get("type") == "string", f"Pinned entry for {framework_key!r} must be type:string"
        assert "pattern" in entry, (
            f"Pinned entry for {framework_key!r} must declare a 'pattern' field "
            "(version-anchored alternation per D3a)"
        )

    @pytest.mark.parametrize("framework_key", ID_BEARING_FRAMEWORKS)
    def test_pattern_contains_version_alternation(self, pinned_mapping_patterns: dict, framework_key: str):
        """
        Test that each pinned pattern contains the expected version alternation token.

        Given: A pinned-block entry for an ID-bearing framework
        When: Its 'pattern' is read
        Then: The pattern contains the version alternation from PINNED_PATTERN_TABLE

        D-sections: D3a ("alternation over current version plus priorVersions"),
        D6 (version token is @<version> for all except OWASP which uses :<year>).
        """
        entry = pinned_mapping_patterns["properties"][framework_key]
        actual_pattern = entry["pattern"]
        expected_fragment = PINNED_PATTERN_TABLE[framework_key]["pattern_contains"]
        assert expected_fragment in actual_pattern, (
            f"Pinned pattern for {framework_key!r} must contain version alternation "
            f"{expected_fragment!r}; actual pattern: {actual_pattern!r}\n"
            f"(D3a: the alternation is anchored to the framework's recognized version set)"
        )

    @pytest.mark.parametrize("framework_key", ID_BEARING_FRAMEWORKS)
    def test_pattern_compiles_as_python_regex(self, pinned_mapping_patterns: dict, framework_key: str):
        """
        Test that each pinned pattern compiles as a Python regex.

        Given: A pinned-block entry's 'pattern' string
        When: re.compile() is called on it
        Then: No re.error is raised

        D-sections: D3a.
        """
        entry = pinned_mapping_patterns["properties"][framework_key]
        pattern = entry["pattern"]
        try:
            re.compile(pattern)
        except re.error as exc:
            pytest.fail(f"Pinned pattern for {framework_key!r} does not compile: {exc} ({pattern!r})")

    @pytest.mark.parametrize(
        ("framework_key", "valid_value"),
        [(fw, v) for fw, info in PINNED_PATTERN_TABLE.items() for v in info["valid"]],
    )
    def test_pinned_pattern_accepts_valid_example(
        self, pinned_mapping_patterns: dict, framework_key: str, valid_value: str
    ):
        """
        Test that each pinned pattern accepts representative valid pinned values.

        Given: A pinned-block entry and a valid version-pinned mapping value
        When: The value is validated against the entry sub-schema
        Then: Draft7Validator reports no errors

        D-sections: D3a (pinned value = spec-native base + version token).
        """
        entry = pinned_mapping_patterns["properties"][framework_key]
        validator = Draft7Validator(entry)
        errors = list(validator.iter_errors(valid_value))
        assert not errors, (
            f"Pinned pattern for {framework_key!r} must accept {valid_value!r}; "
            f"errors: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize(
        ("framework_key", "invalid_value"),
        [(fw, v) for fw, info in PINNED_PATTERN_TABLE.items() for v in info["invalid"]],
    )
    def test_pinned_pattern_rejects_invalid_example(
        self, pinned_mapping_patterns: dict, framework_key: str, invalid_value: str
    ):
        """
        Test that each pinned pattern rejects un-pinned and wrong-version values.

        Given: A pinned-block entry and a malformed or un-pinned value
        When: The value is validated against the entry sub-schema
        Then: Draft7Validator reports at least one error

        Key rejections (D3a, D6):
        - Un-pinned legacy form (no version token) — the whole point of the block.
        - Unknown version token — D3a "alternation anchored to the known version set".
        - Wrong case or whitespace — spec-native canonical form.

        D-sections: D3a, D6, D7.
        """
        entry = pinned_mapping_patterns["properties"][framework_key]
        validator = Draft7Validator(entry)
        errors = list(validator.iter_errors(invalid_value))
        assert errors, (
            f"Pinned pattern for {framework_key!r} must reject {invalid_value!r}; "
            f"the value was unexpectedly accepted"
        )


# ============================================================================
# TestStridePinnedEntry
# ============================================================================


class TestStridePinnedEntry:
    """
    STRIDE is unversioned (version: null in frameworks.yaml) so its pinned
    block entry carries no version token. Its integrity comes entirely from a
    frozen closed enum of the 6 PascalCase categories; the enum IS the pin.

    The pinned block's STRIDE entry must be identical to the legacy block's
    STRIDE entry — same pattern, same shape — because STRIDE does not re-version
    and the pinning mechanism is the frozen membership set, not a @token.

    This is a dedicated test class (not merged with TestPerFrameworkPinnedPatternCommitments)
    so the "unversioned exception" is explicitly documented alongside the D6 rationale.

    D-sections: D6 ("STRIDE is pinned by enum rather than by token"),
    D3 ("no version token; version: null, no token").
    """

    EXPECTED_STRIDE_PATTERN = (
        r"^(Spoofing|Tampering|Repudiation|InformationDisclosure|"
        r"DenialOfService|ElevationOfPrivilege)$"
    )

    def test_stride_pinned_entry_present(self, pinned_mapping_patterns: dict):
        """
        Test that the stride key is present in the pinned block.

        Given: definitions/framework-mapping-patterns-pinned
        When: 'stride' key is looked up
        Then: It exists

        D-sections: D6, D7 (6 keys equal framework.id enum).
        """
        assert "stride" in pinned_mapping_patterns.get("properties", {}), (
            "Pinned block must include a 'stride' entry"
        )

    def test_stride_pinned_entry_has_pattern(self, pinned_mapping_patterns: dict):
        """
        Test that the stride pinned entry declares a pattern.

        Given: The stride pinned entry
        When: Its sub-schema is examined
        Then: It is type:string with a 'pattern' field

        D-sections: D6 (frozen membership set enforced at schema layer).
        """
        entry = pinned_mapping_patterns["properties"]["stride"]
        assert entry.get("type") == "string", "Stride pinned entry must be type:string"
        assert "pattern" in entry, (
            "Stride pinned entry must declare a 'pattern' (the frozen enum-as-pattern "
            "enforced by the schema — D6: STRIDE is pinned by enum, not by token)"
        )

    def test_stride_pinned_pattern_equals_canonical_form(self, pinned_mapping_patterns: dict):
        """
        Test that the stride pinned pattern equals the canonical PascalCase form.

        Given: The stride pinned entry
        When: Its 'pattern' is read
        Then: It equals the canonical STRIDE pattern (same as the legacy block)

        STRIDE is unversioned, so the pinned form is identical to the legacy form.
        The pinned block for STRIDE is present because all 6 framework ids must
        appear as keys (drift-detection), not because the pattern changes.

        D-sections: D6 (STRIDE canonical PascalCase enum-as-pattern, unchanged).
        """
        actual = pinned_mapping_patterns["properties"]["stride"]["pattern"]
        assert actual == self.EXPECTED_STRIDE_PATTERN, (
            f"Stride pinned pattern must equal the canonical D6 form:\n"
            f"  expected: {self.EXPECTED_STRIDE_PATTERN!r}\n"
            f"  actual:   {actual!r}"
        )

    def test_stride_pinned_pattern_equals_legacy_pattern(
        self, pinned_mapping_patterns: dict, legacy_mapping_patterns: dict
    ):
        """
        Test that the pinned-block STRIDE entry's pattern equals the legacy-block
        STRIDE entry's pattern exactly (cross-block byte-stability).

        Given: The STRIDE entry from the pinned block and from the legacy block
        When: Their 'pattern' strings are compared directly
        Then: They are identical

        STRIDE is unversioned (version: null in frameworks.yaml), so the pinned
        form is identical to the legacy form by spec. No version token is added;
        pinning is achieved via the frozen enum membership set, not a @token.
        Both blocks must carry the same byte-identical pattern string.

        D-sections: D6 ("STRIDE is pinned by enum rather than by token; the pinned
        form is identical to the legacy form").
        """
        pinned_pattern = pinned_mapping_patterns["properties"]["stride"]["pattern"]
        legacy_pattern = legacy_mapping_patterns["properties"]["stride"]["pattern"]
        assert pinned_pattern == legacy_pattern, (
            "STRIDE pinned-block pattern must equal the legacy-block pattern byte-for-byte "
            "(D6: STRIDE is unversioned; the pinned form is identical to the legacy form):\n"
            f"  pinned:  {pinned_pattern!r}\n"
            f"  legacy:  {legacy_pattern!r}"
        )

    @pytest.mark.parametrize("valid_value", STRIDE_VALID)
    def test_stride_pinned_accepts_canonical_values(self, pinned_mapping_patterns: dict, valid_value: str):
        """
        Test that the stride pinned entry accepts all 6 canonical PascalCase values.

        Given: The stride pinned entry
        When: Each canonical STRIDE category name is validated
        Then: Draft7Validator reports no errors

        D-sections: D6 (frozen PascalCase membership set).
        """
        entry = pinned_mapping_patterns["properties"]["stride"]
        validator = Draft7Validator(entry)
        errors = list(validator.iter_errors(valid_value))
        assert not errors, (
            f"Stride pinned entry must accept {valid_value!r}; errors: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("invalid_value", STRIDE_INVALID)
    def test_stride_pinned_rejects_non_canonical_values(self, pinned_mapping_patterns: dict, invalid_value: str):
        """
        Test that the stride pinned entry rejects lowercase, abbreviated, and hyphenated forms.

        Given: The stride pinned entry
        When: A non-canonical STRIDE value is validated
        Then: Draft7Validator reports at least one error

        The migration target form is PascalCase (D6); legacy lowercase-kebab values
        (e.g., 'tampering', 'information-disclosure') must fail the pinned block.

        D-sections: D6 ("STRIDE values migrate form" to the frozen set's canonical spelling).
        """
        entry = pinned_mapping_patterns["properties"]["stride"]
        validator = Draft7Validator(entry)
        errors = list(validator.iter_errors(invalid_value))
        assert errors, f"Stride pinned entry must reject {invalid_value!r}; the value was unexpectedly accepted"


# ============================================================================
# TestIso22989PinnedEntry
# ============================================================================


class TestIso22989PinnedEntry:
    """
    ISO 22989 is a non-ID-bearing framework: its mapping values are role
    descriptors, not canonical catalog IDs. ADR-027 D8 replaces the legacy
    bare-string carve-out ({"type": "string"}) with a closed, version-pinned
    controlled vocabulary encoded as an inline enum.

    The binding encoding per D7: a oneOf/anyOf over enum-bearing sub-schemas
    (one arm per edition), each arm carrying its version-suffixed members.
    For a single 2022 edition, a flat closed enum is equivalent, but
    the SHAPE must be oneOf-over-enums to leave a clean extension point for
    future editions.

    A structural test asserts "type:string with an enum, or oneOf over
    enum-bearing sub-schemas" so the implementation does not ship a tightened pattern.

    D-sections: D7 (binding encoding for non-ID frameworks), D8 (ISO 22989
    controlled-vocabulary carve-out), D3 (@2022 version token).
    """

    def test_iso22989_pinned_entry_present(self, pinned_mapping_patterns: dict):
        """
        Test that the iso-22989 key is present in the pinned block.

        Given: definitions/framework-mapping-patterns-pinned
        When: 'iso-22989' key is looked up
        Then: It exists

        D-sections: D7, D8.
        """
        assert "iso-22989" in pinned_mapping_patterns.get("properties", {}), (
            "Pinned block must include an 'iso-22989' entry"
        )

    def test_iso22989_pinned_entry_is_not_bare_string(self, pinned_mapping_patterns: dict):
        """
        Test that the iso-22989 pinned entry is NOT a bare {"type": "string"}.

        Given: The iso-22989 pinned entry
        When: Its sub-schema is examined
        Then: It does NOT have a bare string shape (i.e., must have an enum or oneOf)

        ADR-027 D8 explicitly replaces the legacy bare-string carve-out with a
        closed controlled-vocabulary enum. A bare string is wrong for a standard
        because it admits spelling variants silently.

        D-sections: D8 ("free string is not acceptable for a standard").
        """
        entry = pinned_mapping_patterns["properties"]["iso-22989"]
        is_bare_string = entry.get("type") == "string" and "enum" not in entry and "oneOf" not in entry
        assert not is_bare_string, (
            "iso-22989 pinned entry must NOT be a bare string; "
            "ADR-027 D8 requires a closed controlled-vocabulary enum, not {'type': 'string'}"
        )

    def test_iso22989_pinned_entry_has_enum_or_oneof_shape(self, pinned_mapping_patterns: dict):
        """
        Test that the iso-22989 pinned entry uses an enum or oneOf-over-enums shape.

        Given: The iso-22989 pinned entry
        When: Its sub-schema is examined
        Then: It is either:
              (a) type:string with an 'enum' field (flat closed enum for a single edition), or
              (b) a 'oneOf' over sub-schemas each of which has type:string + enum

        The binding encoding per D7 is (b) — oneOf/anyOf over per-edition enums —
        so that a second ISO edition can be added as a new arm without restructuring.
        A single 2022 edition may use (a) or (b); the test accepts both
        but a structural comment documents the preferred (b) shape.

        D-sections: D7 ("binding encoding: oneOf/anyOf over enum-bearing sub-schemas"),
        D8 ("per-framework-version: a new edition gets its own enumerated set").
        """
        entry = pinned_mapping_patterns["properties"]["iso-22989"]
        has_flat_enum = entry.get("type") == "string" and "enum" in entry
        has_oneof = "oneOf" in entry or "anyOf" in entry
        assert has_flat_enum or has_oneof, (
            "iso-22989 pinned entry must use either a flat enum (type:string + enum) "
            "or a oneOf/anyOf over enum-bearing sub-schemas per D7 binding encoding; "
            f"actual entry keys: {list(entry.keys())}"
        )

    def test_iso22989_pinned_entry_oneof_arms_have_enums(self, pinned_mapping_patterns: dict):
        """
        Test that if the entry uses oneOf/anyOf, each arm declares a string enum.

        Given: The iso-22989 pinned entry using oneOf or anyOf shape
        When: Each arm is examined
        Then: Each arm declares type:string and an 'enum' list

        D-sections: D7 ("each enum carrying its version-suffixed members").
        """
        entry = pinned_mapping_patterns["properties"]["iso-22989"]
        combiner_key = "oneOf" if "oneOf" in entry else ("anyOf" if "anyOf" in entry else None)
        if combiner_key is None:
            # Flat enum shape — this structural test only applies to oneOf/anyOf shape.
            return
        arms = entry[combiner_key]
        assert isinstance(arms, list) and len(arms) >= 1, (
            f"iso-22989 {combiner_key} must be a non-empty list of sub-schemas"
        )
        for i, arm in enumerate(arms):
            assert arm.get("type") == "string", f"iso-22989 {combiner_key}[{i}] must declare type:string"
            assert "enum" in arm, (
                f"iso-22989 {combiner_key}[{i}] must declare an 'enum' list (per D7 binding encoding)"
            )

    @pytest.mark.parametrize("valid_value", ISO_22989_VALID)
    def test_iso22989_pinned_accepts_version_pinned_enum_members(
        self, pinned_mapping_patterns: dict, valid_value: str
    ):
        """
        Test that the iso-22989 pinned entry accepts all 6 @2022 version-pinned enum members.

        Given: The iso-22989 pinned entry
        When: Each of the 6 ISO/IEC 22989:2022 role+version strings is validated
        Then: Draft7Validator reports no errors

        The 6 roles sourced from ISO/IEC 22989:2022 role taxonomy, each bearing
        the @2022 version token per D3 and D8.

        D-sections: D8 (the closed set keyed to the 2022 edition),
        D3 (version token @2022 pinned inside the value).
        """
        entry = pinned_mapping_patterns["properties"]["iso-22989"]
        validator = Draft7Validator(entry)
        errors = list(validator.iter_errors(valid_value))
        assert not errors, (
            f"iso-22989 pinned entry must accept {valid_value!r}; errors: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("invalid_value", ISO_22989_INVALID)
    def test_iso22989_pinned_rejects_invalid_values(self, pinned_mapping_patterns: dict, invalid_value: str):
        """
        Test that the iso-22989 pinned entry rejects un-pinned, wrong-version,
        and spelling-variant values.

        Given: The iso-22989 pinned entry
        When: An invalid value is validated
        Then: Draft7Validator reports at least one error

        Key rejections (D8):
        - Bare un-pinned strings (e.g., "AI Producer") — no version token.
        - Wrong version (e.g., @2023) — unknown edition.
        - Spelling variants (e.g., "AI Part (Data supplier)@2022") — outside closed set.
        - Whitespace variants — outside closed set.
        - Wrong case — outside closed set.

        D-sections: D8 ("a value outside the closed set is rejected"),
        D5 Tier 1 (controlled-vocabulary membership check).
        """
        entry = pinned_mapping_patterns["properties"]["iso-22989"]
        validator = Draft7Validator(entry)
        errors = list(validator.iter_errors(invalid_value))
        assert errors, f"iso-22989 pinned entry must reject {invalid_value!r}; the value was unexpectedly accepted"

    def test_iso22989_pinned_enum_covers_all_2022_roles(self, pinned_mapping_patterns: dict):
        """
        Test that the iso-22989 pinned entry covers all 6 known 2022-edition roles.

        Given: The iso-22989 pinned entry
        When: All valid @2022 values are validated
        Then: None are rejected

        This is a completeness guard: if the implementation omits one of the 6 roles,
        a legitimate mapping value would be rejected at schema-validation time.

        D-sections: D8 (the closed set is sourced from the standard's own role taxonomy).
        """
        entry = pinned_mapping_patterns["properties"]["iso-22989"]
        validator = Draft7Validator(entry)
        for role in ISO_22989_2022_ENUM:
            errors = list(validator.iter_errors(role))
            assert not errors, (
                f"iso-22989 pinned entry must cover all 2022 roles; "
                f"rejected {role!r}: {[e.message for e in errors]}"
            )


# ============================================================================
# TestVersionIdField
# ============================================================================


class TestVersionIdField:
    """
    The versionId field must be added to definitions/framework/properties as an
    optional string with the D2a charset pattern ^[a-z0-9.@-]+$.

    It is optional: the generator materializes it at pre-commit (D2b);
    the schema only declares the field shape. The 'required' list must NOT include
    'versionId'.

    D-sections: D2a (shape and charset), D2b (generated, not authored — optional
    in schema so legacy entries without it still validate).
    """

    def test_versionid_field_present(self, framework_properties: dict):
        """
        Test that versionId is declared in definitions/framework/properties.

        Given: definitions/framework/properties
        When: 'versionId' key is looked up
        Then: It exists

        D-sections: D2a.
        """
        assert "versionId" in framework_properties, (
            "definitions/framework/properties/versionId must be declared per ADR-027 D2a"
        )

    def test_versionid_is_string_type(self, framework_properties: dict):
        """
        Test that versionId declares type:string.

        Given: definitions/framework/properties/versionId
        When: Its 'type' is read
        Then: It is 'string'

        D-sections: D2a ("versionId is a string").
        """
        entry = framework_properties["versionId"]
        assert entry.get("type") == "string", "versionId must be type:string per D2a"

    def test_versionid_has_charset_pattern(self, framework_properties: dict):
        """
        Test that versionId declares the D2a charset pattern.

        Given: definitions/framework/properties/versionId
        When: Its 'pattern' is read
        Then: It equals ^[a-z0-9.@-]+$

        D2a: "versionId = <id>@<version>; the generator asserts each composed
        versionId matches a conservative charset ([a-z0-9.@-], no whitespace)."

        D-sections: D2a.
        """
        entry = framework_properties["versionId"]
        actual_pattern = entry.get("pattern")
        assert actual_pattern == VERSION_ID_CHARSET_PATTERN, (
            f"versionId pattern must be {VERSION_ID_CHARSET_PATTERN!r} per D2a; actual: {actual_pattern!r}"
        )

    def test_versionid_is_not_required(self, framework_definition: dict):
        """
        Test that versionId is NOT in the framework 'required' list.

        Given: definitions/framework
        When: Its 'required' list is examined
        Then: 'versionId' is absent (the schema leaves it optional;
              generator materialization (D2b) makes it present)

        D-sections: D2b ("materializing it at pre-commit").
        """
        required = framework_definition.get("required", [])
        assert "versionId" not in required, (
            "versionId must NOT be in required[]; the generator "
            "materializes it and the schema only declares the field shape (D2b)"
        )

    @pytest.mark.parametrize("valid_value", VERSION_ID_VALID)
    def test_versionid_accepts_valid_charset_values(self, framework_properties: dict, valid_value: str):
        """
        Test that the versionId sub-schema accepts values within the D2a charset.

        Given: definitions/framework/properties/versionId
        When: A charset-valid versionId string is validated
        Then: Draft7Validator reports no errors

        D-sections: D2a (versionId shape: <id>@<version> or bare <id> for unversioned).
        """
        entry = framework_properties["versionId"]
        validator = Draft7Validator(entry)
        errors = list(validator.iter_errors(valid_value))
        assert not errors, f"versionId must accept {valid_value!r}; errors: {[e.message for e in errors]}"

    @pytest.mark.parametrize("invalid_value", VERSION_ID_INVALID)
    def test_versionid_rejects_invalid_charset_values(self, framework_properties: dict, invalid_value: str):
        """
        Test that the versionId sub-schema rejects values violating the D2a charset.

        Given: definitions/framework/properties/versionId
        When: A charset-violating versionId string is validated
        Then: Draft7Validator reports at least one error

        D-sections: D2a (charset [a-z0-9.@-], no uppercase, no whitespace, no slash).
        """
        entry = framework_properties["versionId"]
        validator = Draft7Validator(entry)
        errors = list(validator.iter_errors(invalid_value))
        assert errors, f"versionId must reject {invalid_value!r}; the value was unexpectedly accepted"


# ============================================================================
# TestSupersedesField
# ============================================================================


class TestSupersedesField:
    """
    The 'supersedes' field records the prior versionId this entry replaces.
    It is optional (absent on first registration per D2c) and must satisfy the
    D2a versionId charset.

    Note on what JSON Schema CAN and CANNOT enforce here:
    - Schema-level family-consistency (that 'nist-ai-rmf@1.0' belongs to the
      'nist-ai-rmf' family, not 'mitre-atlas') is NOT enforceable in pure JSON
      Schema without per-instance logic. That invariant lives in the
      purity validator (D2b/D4c) and the drift-detection validator (D5), not
      in the schema. Tests here assert only what the schema can enforce:
      charset, type, and optionality.

    D-sections: D2c (supersession lineage), D2a (charset applies to lineage fields).
    """

    def test_supersedes_field_present(self, framework_properties: dict):
        """
        Test that 'supersedes' is declared in definitions/framework/properties.

        Given: definitions/framework/properties
        When: 'supersedes' key is looked up
        Then: It exists

        D-sections: D2c.
        """
        assert "supersedes" in framework_properties, (
            "definitions/framework/properties/supersedes must be declared per ADR-027 D2c"
        )

    def test_supersedes_is_string_type(self, framework_properties: dict):
        """
        Test that 'supersedes' is a single string (not an array).

        Given: definitions/framework/properties/supersedes
        When: Its 'type' is read
        Then: It is 'string' (not 'array')

        D2c: "supersedes — the prior versionId this version replaces."
        This is a single predecessor, not a list.

        D-sections: D2c.
        """
        entry = framework_properties["supersedes"]
        assert entry.get("type") == "string", (
            "supersedes must be type:string (single predecessor) per D2c; "
            "priorVersions is the array field for the full lineage history"
        )

    def test_supersedes_has_charset_pattern(self, framework_properties: dict):
        """
        Test that 'supersedes' enforces the D2a versionId charset.

        Given: definitions/framework/properties/supersedes
        When: Its 'pattern' is read
        Then: It equals ^[a-z0-9.@-]+$

        D2c introduces the supersedes field (supersession lineage). D2a defines
        the charset ([a-z0-9.@-], no whitespace or uppercase) that applies to
        every versionId string, including the value of supersedes.

        D-sections: D2c (field introduction), D2a (charset constraint).
        """
        entry = framework_properties["supersedes"]
        actual_pattern = entry.get("pattern")
        assert actual_pattern == VERSION_ID_CHARSET_PATTERN, (
            f"supersedes pattern must be {VERSION_ID_CHARSET_PATTERN!r} per D2a; actual: {actual_pattern!r}"
        )

    def test_supersedes_is_not_required(self, framework_definition: dict):
        """
        Test that 'supersedes' is NOT in the framework 'required' list.

        Given: definitions/framework
        When: Its 'required' list is examined
        Then: 'supersedes' is absent (optional; absent on first registration per D2c)

        D-sections: D2c ("optional; absent on first registration").
        """
        required = framework_definition.get("required", [])
        assert "supersedes" not in required, (
            "supersedes must be optional (not in required[]); it is absent on first framework registration per D2c"
        )


# ============================================================================
# TestPriorVersionsField
# ============================================================================


class TestPriorVersionsField:
    """
    The 'priorVersions' field is an optional array of versionId strings, each
    satisfying the D2a charset, with uniqueItems:true.

    Membership in priorVersions marks a pin as 'valid-but-superseded' (D5a) —
    a valid pin target that the drift validator reports informationally rather
    than flagging as invalid.

    Note: family-consistency (each member must belong to the same concept-id
    family as the carrier entry) is NOT enforceable in pure JSON Schema; it
    lives in the versionId purity validator. Tests here assert charset, uniqueness,
    type, and optionality — what the schema CAN enforce.

    D-sections: D2c (priorVersions semantics), D2a (charset), D5a (three-state
    taxonomy: current / valid-but-superseded / invalid).
    """

    def test_prior_versions_field_present(self, framework_properties: dict):
        """
        Test that 'priorVersions' is declared in definitions/framework/properties.

        Given: definitions/framework/properties
        When: 'priorVersions' key is looked up
        Then: It exists

        D-sections: D2c.
        """
        assert "priorVersions" in framework_properties, (
            "definitions/framework/properties/priorVersions must be declared per ADR-027 D2c"
        )

    def test_prior_versions_is_array_type(self, framework_properties: dict):
        """
        Test that 'priorVersions' declares type:array.

        Given: definitions/framework/properties/priorVersions
        When: Its 'type' is read
        Then: It is 'array'

        D-sections: D2c ("priorVersions — an optional ordered list of retired versionIds").
        """
        entry = framework_properties["priorVersions"]
        assert entry.get("type") == "array", "priorVersions must be type:array per D2c"

    def test_prior_versions_items_are_strings(self, framework_properties: dict):
        """
        Test that priorVersions items are strings.

        Given: definitions/framework/properties/priorVersions
        When: Its 'items' sub-schema is read
        Then: items.type == 'string'

        D-sections: D2c (each member is a versionId string).
        """
        entry = framework_properties["priorVersions"]
        items = entry.get("items", {})
        assert items.get("type") == "string", (
            "priorVersions items must be type:string (each member is a versionId)"
        )

    def test_prior_versions_items_have_charset_pattern(self, framework_properties: dict):
        """
        Test that priorVersions items enforce the D2a versionId charset.

        Given: definitions/framework/properties/priorVersions items sub-schema
        When: Its 'pattern' is read
        Then: It equals ^[a-z0-9.@-]+$

        D2c introduces priorVersions as an ordered list of retired versionIds.
        D2a defines the charset ([a-z0-9.@-]) that applies to every versionId
        string, including each member of priorVersions.

        D-sections: D2c (field introduction), D2a (charset constraint).
        """
        entry = framework_properties["priorVersions"]
        items = entry.get("items", {})
        actual_pattern = items.get("pattern")
        assert actual_pattern == VERSION_ID_CHARSET_PATTERN, (
            f"priorVersions items pattern must be {VERSION_ID_CHARSET_PATTERN!r} per D2a; "
            f"actual: {actual_pattern!r}"
        )

    def test_prior_versions_has_unique_items(self, framework_properties: dict):
        """
        Test that priorVersions declares uniqueItems:true.

        Given: definitions/framework/properties/priorVersions
        When: 'uniqueItems' is read
        Then: It is True

        D2b: "the set of versionIds across the registry is unique — two entries
        minting the same versionId is a registry error." The same uniqueness
        invariant applies within a single entry's priorVersions list.

        D-sections: D2b.
        """
        entry = framework_properties["priorVersions"]
        assert entry.get("uniqueItems") is True, (
            "priorVersions must set uniqueItems:true per D2b uniqueness invariant"
        )

    def test_prior_versions_is_not_required(self, framework_definition: dict):
        """
        Test that 'priorVersions' is NOT in the framework 'required' list.

        Given: definitions/framework
        When: Its 'required' list is examined
        Then: 'priorVersions' is absent (optional; absent on first registration per D2c)

        D-sections: D2c ("optional").
        """
        required = framework_definition.get("required", [])
        assert "priorVersions" not in required, (
            "priorVersions must be optional (not in required[]); "
            "it is absent on first framework registration per D2c"
        )

    def test_prior_versions_rejects_duplicate_entries(self, frameworks_schema: dict, schema_registry: Registry):
        """
        Test that a framework entry with duplicate priorVersions fails validation.

        Given: A synthetic framework entry with two identical strings in priorVersions
        When: It is validated against definitions/framework
        Then: Draft7Validator reports a uniqueItems violation

        D-sections: D2b (uniqueness invariant).
        """
        framework_schema = frameworks_schema["definitions"]["framework"]
        # Build a minimal valid entry that sets priorVersions to a duplicate list.
        entry = {
            "id": "mitre-atlas",
            "name": "MITRE ATLAS",
            "fullName": "Adversarial Threat Landscape for AI Systems",
            "description": "Test entry for duplicate priorVersions check",
            "baseUri": "https://atlas.mitre.org",
            "applicableTo": ["controls"],
            "priorVersions": ["mitre-atlas@4.0.0", "mitre-atlas@4.0.0"],  # duplicate
        }
        validator = Draft7Validator(framework_schema, registry=schema_registry)
        errors = list(validator.iter_errors(entry))
        error_messages = [e.message for e in errors]
        assert any(
            "uniqueItems" in msg or "non-unique" in msg.lower() or "unique" in msg.lower()
            for msg in error_messages
        ), f"priorVersions with duplicate entries must fail uniqueItems validation; errors were: {error_messages}"


# ============================================================================
# TestExistingEntriesStillValidate
# ============================================================================


class TestExistingEntriesStillValidate:
    """
    All 6 existing frameworks.yaml entries must still pass validation against
    the updated definitions/framework schema (additive, non-breaking guard).

    This test class must keep passing after the new optional fields are added —
    fields — if any existing entry fails validation, the additions
    broke backward compatibility.

    D-sections: D7 ("additive, NON-breaking"), additive scope ("additive, optional").
    """

    @pytest.fixture(scope="class")
    @classmethod
    def framework_entries(cls, frameworks_yaml_data: dict) -> list:
        """Individual framework entries from frameworks.yaml."""
        entries = frameworks_yaml_data.get("frameworks", [])
        if not entries:
            pytest.fail("frameworks.yaml has no 'frameworks' entries")
        return entries

    def test_all_six_entries_present_in_yaml(self, framework_entries: list):
        """
        Sanity check: frameworks.yaml has exactly 6 entries.

        Given: frameworks.yaml
        When: 'frameworks' list is read
        Then: It has 6 entries (the current registry)
        """
        assert len(framework_entries) == 6, (
            "Expected 6 framework entries (scope guard); "
            "etsi-en-304-223 and nist-ai-rmf-actor-tasks are #329/#319 execution, not #347"
        )

    @pytest.mark.parametrize(
        "framework_id",
        [
            "mitre-atlas",
            "nist-ai-rmf",
            "stride",
            "owasp-top10-llm",
            "iso-22989",
            "eu-ai-act",
        ],
    )
    def test_existing_entry_validates_against_updated_schema(
        self,
        framework_id: str,
        framework_entries: list,
        frameworks_schema: dict,
        schema_registry: Registry,
    ):
        """
        Test that each existing frameworks.yaml entry validates against the
        updated definitions/framework schema.

        Given: An existing frameworks.yaml entry (unmodified — no versionId,
               supersedes, or priorVersions fields yet)
        When: It is validated against definitions/framework using Draft7Validator
        Then: No validation errors are reported

        The new optional fields must not break existing entries that omit them.
        The schema_registry fixture resolves cross-file $refs.

        D-sections: D7 ("additive, non-breaking"), additive scope.
        """
        # Find the entry for this framework_id.
        entry = next((e for e in framework_entries if e.get("id") == framework_id), None)
        assert entry is not None, f"No entry with id={framework_id!r} found in frameworks.yaml"

        framework_schema = frameworks_schema["definitions"]["framework"]
        validator = Draft7Validator(framework_schema, registry=schema_registry)
        errors = list(validator.iter_errors(entry))
        assert not errors, (
            f"Existing frameworks.yaml entry for {framework_id!r} must still validate "
            f"after the schema additions; errors: {[e.message for e in errors]}"
        )


# ============================================================================
# TestNewOptionalFieldsTogether
# ============================================================================


class TestNewOptionalFieldsTogether:
    """
    Positive test: a framework entry carrying ALL THREE new optional fields
    (versionId, supersedes, priorVersions) must validate against definitions/framework.

    This guards against any interaction between the three fields that could
    produce an unexpected error (e.g., additionalProperties:false wrongly applied,
    or a combined validation side-effect).

    D-sections: D2a (versionId + charset), D2c (supersedes + priorVersions semantics).
    """

    def test_framework_entry_with_all_new_optional_fields_validates(
        self, frameworks_schema: dict, schema_registry: Registry
    ):
        """
        Test that a synthetic framework entry carrying all three new optional
        fields validates against definitions/framework with no errors.

        Given: A synthetic entry with required fields plus versionId, supersedes,
               and priorVersions all populated with valid values
        When: It is validated against definitions/framework via Draft7Validator
        Then: No validation errors are reported

        The three new fields are all optional and additive; together they must not
        trigger any schema-level rejection on a well-formed entry.

        D-sections: D2a (charset constraint on versionId, supersedes, and
        priorVersions members), D2c (supersedes = prior versionId this entry
        replaces; priorVersions = ordered list of retired versionIds).
        """
        entry = {
            "id": "mitre-atlas",
            "name": "MITRE ATLAS",
            "fullName": "Adversarial Threat Landscape for AI Systems",
            "description": "Synthetic entry with all three new optional fields",
            "baseUri": "https://atlas.mitre.org",
            "applicableTo": ["controls"],
            # All three new optional fields together.
            "versionId": "mitre-atlas@5.0.1",
            "supersedes": "mitre-atlas@5.0.0",
            "priorVersions": ["mitre-atlas@5.0.0", "mitre-atlas@4.5.0"],
        }
        framework_schema = frameworks_schema["definitions"]["framework"]
        validator = Draft7Validator(framework_schema, registry=schema_registry)
        errors = list(validator.iter_errors(entry))
        assert not errors, (
            "A framework entry with versionId, supersedes, and priorVersions must validate "
            "against definitions/framework with no errors (D2a/D2c — all three fields are "
            f"additive and optional); errors: {[e.message for e in errors]}"
        )


# ============================================================================
# TestExistingFrameworkMappingPatternsBlockUnchanged
# ============================================================================


class TestExistingFrameworkMappingPatternsBlockUnchanged:
    """
    Explicit regression guard for the ADR-022 D5b legacy block.

    The existing definitions/framework-mapping-patterns block must remain
    byte-stable across the schema additions. Consumer-schema $refs (in
    risks.schema.json, controls.schema.json, personas.schema.json) still
    point at this block; tightening it in place would reject existing legacy
    content values and break those tests.

    This class is intentionally redundant with TestNewBlockPresence's
    test_legacy_block_patterns_are_byte_stable — the redundancy is deliberate
    as an explicit regression net with a clear failure message that names the
    ADR-022 D5b source of truth.

    D-sections: D7 ("do NOT remove the consumer-schema catch-all", "additive,
    NON-breaking"), ADR-022 D5b (the legacy block's patterns are load-bearing).
    """

    def test_legacy_block_additionalproperties_false_unchanged(self, legacy_mapping_patterns: dict):
        """
        Test that the legacy block's additionalProperties is still False.

        Given: definitions/framework-mapping-patterns
        When: 'additionalProperties' is read
        Then: It is False (unchanged from ADR-022 D5b commitment)
        """
        assert legacy_mapping_patterns.get("additionalProperties") is False, (
            "Legacy framework-mapping-patterns additionalProperties must remain False; "
            "this block must not be modified (ADR-027 D7)"
        )

    def test_legacy_block_type_unchanged(self, legacy_mapping_patterns: dict):
        """
        Test that the legacy block's type is still 'object'.

        Given: definitions/framework-mapping-patterns
        When: 'type' is read
        Then: It is 'object' (unchanged)
        """
        assert legacy_mapping_patterns.get("type") == "object", (
            "Legacy framework-mapping-patterns type must remain 'object'"
        )

    @pytest.mark.parametrize("framework_key", sorted(FRAMEWORK_PATTERN_TABLE.keys()))
    def test_legacy_pattern_exact_string_match(self, legacy_mapping_patterns: dict, framework_key: str):
        """
        Test that each ADR-022 D5b legacy pattern exactly matches the committed string.

        Given: The legacy framework-mapping-patterns block
        When: Each framework entry's 'pattern' is read
        Then: It equals the string in FRAMEWORK_PATTERN_TABLE verbatim

        This is the byte-level regression guard: even a single-character change
        to an existing pattern breaks consumers using legacy-form values.

        D-sections: ADR-022 D5b (load-bearing committed patterns),
        ADR-027 D7 (existing block stays as-is).
        """
        entry = legacy_mapping_patterns["properties"].get(framework_key)
        assert entry is not None, f"Legacy block entry for {framework_key!r} must not be removed"
        expected_pattern = FRAMEWORK_PATTERN_TABLE[framework_key]["pattern"]
        actual_pattern = entry.get("pattern")
        assert actual_pattern == expected_pattern, (
            f"Legacy pattern for {framework_key!r} drifted from ADR-022 D5b — "
            f"this block must NOT be modified per ADR-027 D7:\n"
            f"  expected: {expected_pattern!r}\n"
            f"  actual:   {actual_pattern!r}"
        )

    def test_legacy_iso22989_is_still_bare_string(self, legacy_mapping_patterns: dict):
        """
        Test that the legacy iso-22989 entry remains a bare string.

        Given: definitions/framework-mapping-patterns / iso-22989 entry
        When: Its sub-schema is examined
        Then: It is still type:string with no 'pattern', 'enum', or 'oneOf'

        The legacy block is the deliberate catch-all for pre-migration content.
        The iso-22989 entry in the NEW pinned block gets the closed controlled-
        vocabulary enum (TestIso22989PinnedEntry), but the LEGACY entry must stay
        as the bare string it is today.

        D-sections: ADR-022 D5b ("ISO 22989 is the deliberate exception"),
        ADR-027 D7 ("do NOT remove the consumer-schema catch-all").
        """
        entry = legacy_mapping_patterns["properties"].get("iso-22989")
        assert entry is not None, "Legacy block must still have an iso-22989 entry"
        assert entry.get("type") == "string", (
            "Legacy iso-22989 entry must remain type:string (bare string catch-all)"
        )
        assert "pattern" not in entry, (
            "Legacy iso-22989 entry must NOT have a pattern (deliberate exception per ADR-022 D5b)"
        )
        assert "enum" not in entry, (
            "Legacy iso-22989 entry must NOT have an enum; "
            "the closed vocabulary is in the new pinned block, not the legacy block"
        )
        assert "oneOf" not in entry, (
            "Legacy iso-22989 entry must NOT have oneOf; "
            "the controlled vocabulary shape is in the new pinned block only"
        )


# ============================================================================
# TestSchemaMetaValidity
# ============================================================================


class TestSchemaMetaValidity:
    """
    The new pinned block and its per-framework entries must be valid Draft-07
    schema fragments, and each pinned regex must compile as a Python regex.

    D-sections: D3a (anchored alternation must be a valid regex), D7.
    """

    def test_pinned_block_passes_draft07_metaschema(self, pinned_mapping_patterns: dict):
        """
        Test that the pinned block is a valid Draft-07 schema fragment.

        Given: definitions/framework-mapping-patterns-pinned
        When: Draft7Validator.check_schema() is called
        Then: No SchemaError is raised

        D-sections: D3a, D7.
        """
        try:
            Draft7Validator.check_schema(pinned_mapping_patterns)
        except SchemaError as exc:
            pytest.fail(f"framework-mapping-patterns-pinned is not valid Draft-07: {exc.message}")

    @pytest.mark.parametrize("framework_key", sorted(PINNED_PATTERN_TABLE.keys()))
    def test_pinned_pattern_compiles_as_python_regex(self, pinned_mapping_patterns: dict, framework_key: str):
        """
        Test that each versioned-framework pinned pattern compiles as a Python regex.

        Given: A pinned-block entry's 'pattern' string
        When: re.compile() is called on it
        Then: No re.error is raised

        Catches stray escapes or invalid groups before they reach the validator.

        D-sections: D3a.
        """
        entry = pinned_mapping_patterns["properties"].get(framework_key, {})
        pattern = entry.get("pattern")
        if pattern is None:
            # Entries without a pattern (e.g., iso-22989 uses enum) are skipped here.
            return
        try:
            re.compile(pattern)
        except re.error as exc:
            pytest.fail(
                f"Pinned pattern for {framework_key!r} does not compile as Python regex: {exc} ({pattern!r})"
            )

    def test_versionid_charset_pattern_compiles(self):
        """
        Test that the D2a versionId charset pattern compiles as a Python regex.

        Given: VERSION_ID_CHARSET_PATTERN constant
        When: re.compile() is called on it
        Then: No re.error is raised

        D-sections: D2a.
        """
        try:
            re.compile(VERSION_ID_CHARSET_PATTERN)
        except re.error as exc:
            pytest.fail(f"VERSION_ID_CHARSET_PATTERN does not compile: {exc} ({VERSION_ID_CHARSET_PATTERN!r})")

    def test_full_frameworks_schema_passes_draft07_metaschema(self, frameworks_schema: dict):
        """
        Test that the entire frameworks.schema.json passes the Draft-07 meta-schema.

        Given: The full frameworks.schema.json after the schema additions
        When: Draft7Validator.check_schema() is called on the entire document
        Then: No SchemaError is raised

        D-sections: D7 (schema additions are confined to frameworks.schema.json).
        """
        try:
            Draft7Validator.check_schema(frameworks_schema)
        except SchemaError as exc:
            pytest.fail(
                f"Full frameworks.schema.json is not valid Draft-07 after the schema additions: {exc.message}"
            )


# ============================================================================
# Test summary
# ============================================================================
# ============================================================================
# TestIso22989OneOfSeamTripwire
# ============================================================================


class TestIso22989OneOfSeamTripwire:
    """
    Tripwire: the iso-22989 pinned subschema must retain its `oneOf` key.

    ADR-027 D7: "the entry becomes a oneOf/anyOf over enums, each enum carrying
    its version-suffixed members, and a new edition gets its own enumerated set
    keyed to its version token." The single-member `oneOf` is the deliberate
    multi-edition extension seam — NOT a redundancy to clean up.

    This class adds a lightweight tripwire so a future refactor that flattens
    the `oneOf` into a bare enum trips this test, prompting a conscious ADR
    review before the extension seam is removed.

    The fix for item 4 ADDS a `description` field to the iso-22989 subschema.
    No behavior change. These tests assert structural invariants only (not the
    exact description text, which would be brittle).
    """

    def test_iso22989_pinned_subschema_has_oneof(self, pinned_mapping_patterns: dict):
        """
        Given: definitions/framework-mapping-patterns-pinned/properties/iso-22989
        When:  the subschema is examined
        Then:  it contains a 'oneOf' key

        D7: the `oneOf` is the multi-edition extension seam. Removing it would
        collapse the architecture to a flat enum and close the extension point
        for future ISO 22989 editions.

        If this test fails after a cleanup, check ADR-027 D7 before proceeding.
        """
        entry = pinned_mapping_patterns.get("properties", {}).get("iso-22989")
        assert entry is not None, "iso-22989 must be present in the pinned block"
        assert "oneOf" in entry, (
            "iso-22989 pinned subschema must retain the 'oneOf' key (D7 multi-edition "
            "extension seam). Do not flatten to a bare enum without an ADR-027 amendment."
        )

    def test_iso22989_oneof_single_member_enum_accepts_ai_producer_at_2022(self, pinned_mapping_patterns: dict):
        """
        Given: the single oneOf arm in the iso-22989 pinned subschema
        When:  its enum is examined
        Then:  'AI Producer@2022' is in the enum
               'AI Part (Data supplier)@2022' (typo) is NOT in the enum

        D8: the closed controlled-vocabulary enum admits the six canonical
        ISO 22989:2022 roles and rejects spelling variants. This is the
        behavioral contract for the seam's single current arm.

        Note: 'AI Part (Data supplier)@2022' uses 'Part' not 'Partner' and
        uppercase 'D' — both outside the closed set. This test is NOT brittle
        to the exact description text added by the fix (item 4).
        """
        from jsonschema import Draft7Validator

        entry = pinned_mapping_patterns.get("properties", {}).get("iso-22989")
        assert entry is not None
        arms = entry.get("oneOf", [])
        assert len(arms) >= 1, "iso-22989 oneOf must have at least one arm"

        # Validate accepted value against the whole subschema.
        validator = Draft7Validator(entry)
        accepted_errors = list(validator.iter_errors("AI Producer@2022"))
        assert not accepted_errors, (
            f"iso-22989 pinned subschema must accept 'AI Producer@2022'; "
            f"errors: {[e.message for e in accepted_errors]}"
        )

        # Validate rejected value (spelling variant) against the whole subschema.
        rejected_errors = list(validator.iter_errors("AI Part (Data supplier)@2022"))
        assert rejected_errors, (
            "iso-22989 pinned subschema must reject 'AI Part (Data supplier)@2022' "
            "(typo: 'Part' not 'Partner', uppercase 'D') — D8 closed enum."
        )


"""
Test Summary
============
Test classes: 11 + 1 (TestIso22989OneOfSeamTripwire) = 12
Total tests (approximate): ~90 + 2 = ~92

Test classes and their key assertion:

| Class                                          | Key assertion                          |
|------------------------------------------------|----------------------------------------|
| TestNewBlockPresence                           | pinned block present alongside legacy   |
| TestNewBlockStructure                          | pinned block outer shape               |
| TestPerFrameworkPinnedPatternCommitments       | per-framework pinned patterns          |
| TestStridePinnedEntry                          | STRIDE frozen enum, no token           |
| TestIso22989PinnedEntry                        | ISO 22989 closed controlled-vocab enum |
| TestVersionIdField                             | versionId field shape + charset        |
| TestSupersedesField                            | supersedes field shape + charset       |
| TestPriorVersionsField                         | priorVersions field shape + charset    |
| TestExistingEntriesStillValidate               | existing entries validate as-is        |
| TestExistingFrameworkMappingPatternsBlockUnch. | legacy block byte-stable               |
| TestSchemaMetaValidity                         | full schema is valid Draft-07          |

Coverage areas:
- New block presence (additive sibling, not a replacement)
- Legacy block byte-stability (pattern strings match ADR-022 D5b verbatim)
- Pinned block outer shape (type, additionalProperties, 6 keys, id-enum drift)
- Per-framework pinned pattern commitments (ID-bearing: ATLAS, NIST, OWASP, EU AI Act)
- STRIDE pinned entry (unversioned exception: frozen enum, no token)
- ISO 22989 pinned entry (closed controlled-vocabulary enum, oneOf/enum shape)
- versionId field (type, charset, not required)
- supersedes field (type:string, charset, not required)
- priorVersions field (type:array, items charset, uniqueItems, not required)
- Existing entries backward-compatibility (additive, non-breaking)
- Draft-07 meta-validity and Python regex compile for all new patterns
"""
