#!/usr/bin/env python3
"""
Tests for the persona-site-data.schema.json prose extension.

Per ADR-016 D5, persona-site-data.schema.json definitions/prose accepts the
old array<string | array<string>> shape AND two new structured prose-item
shapes that the site builder emits after sentinel expansion:

- { "type": "ref", "id": <string>, "title": <string> }
  Intra-document sentinel resolution: {{idRiskFoo}} → a typed reference to a
  risk/control/persona/component ID.

- { "type": "link", "title": <string>, "url": <string> }
  External sentinel resolution: {{ref:identifier}} → a URL from a matching
  externalReferences entry.

Additionally, an optional externalReferences property is declared on the
per-persona, per-risk, and per-control array items. Those objects use
additionalProperties: false, so the new field MUST be explicitly declared in
their properties blocks to be accepted.

The current builder emits the old all-strings shape; that shape must continue
to validate after the extension (forward compatibility).

Coverage:
- definitions/prose accepts string items (old shape preserved).
- definitions/prose accepts nested string-array items (old shape preserved).
- definitions/prose accepts ref-type objects.
- definitions/prose accepts link-type objects.
- definitions/prose accepts mixed arrays (strings + structured items).
- Ref-type object missing required field is rejected.
- Link-type object with non-https url is rejected.
- personas[], risks[], controls[] items declare externalReferences in properties.
- externalReferences is NOT in the required array of those items.
- A valid externalReferences value is accepted by the extended schema.
- persona-site-data.schema.json passes Draft-07 meta-schema check.
"""

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# Module-level constants
# ============================================================================

SCHEMA_FILE = "persona-site-data.schema.json"

# Old-shape prose values that must continue to pass (forward compatibility).
OLD_SHAPE_VALID: list = [
    ["A plain string"],
    ["First", "Second", "Third"],
    [["bullet one", "bullet two"]],
    ["Paragraph", ["bullet a", "bullet b"]],
    [],  # The existing prose definition has no outer minItems, so [] is valid.
]

# New ref-type structured item shapes per ADR-016 D5.
VALID_REF_ITEMS: list[dict] = [
    {"type": "ref", "id": "riskDataPoisoning", "title": "Data Poisoning"},
    {"type": "ref", "id": "controlInputValidation", "title": "Input Validation"},
    {"type": "ref", "id": "personaModelCreator", "title": "Model Creator"},
]

# New link-type structured item shapes per ADR-016 D5.
VALID_LINK_ITEMS: list[dict] = [
    {"type": "link", "title": "MITRE ATLAS", "url": "https://atlas.mitre.org"},
    {"type": "link", "title": "NIST AI RMF", "url": "https://airc.nist.gov/Home"},
    {"type": "link", "title": "OWASP", "url": "https://owasp.org"},
]

# Prose arrays mixing strings and new structured items.
VALID_MIXED_PROSE: list[list] = [
    ["Plain text intro", {"type": "ref", "id": "riskFoo", "title": "Risk Foo"}],
    [{"type": "link", "title": "Source", "url": "https://example.com"}, "Additional text"],
]

# A valid externalReferences value per external-references.schema.json.
VALID_EXTERNAL_REFERENCES = [
    {
        "type": "paper",
        "id": "smith-2024-example",
        "title": "A Sample Paper",
        "url": "https://example.com/paper",
    }
]

# Top-level array property names that must gain the externalReferences field.
TOP_LEVEL_ARRAYS = ["personas", "risks", "controls"]


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def persona_site_schema(risk_map_schemas_dir: Path) -> dict:
    """Parsed persona-site-data.schema.json."""
    path = risk_map_schemas_dir / SCHEMA_FILE
    if not path.is_file():
        pytest.fail(f"Schema not found: {path}")
    with open(path) as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def prose_schema(persona_site_schema: dict) -> dict:
    """The definitions/prose sub-schema."""
    prose = persona_site_schema.get("definitions", {}).get("prose")
    if prose is None:
        pytest.fail(f"definitions/prose not found in {SCHEMA_FILE}")
    return prose


@pytest.fixture(scope="module")
def prose_validator(prose_schema: dict) -> Draft7Validator:
    """Draft-07 validator over definitions/prose."""
    return Draft7Validator(prose_schema)


@pytest.fixture(scope="module")
def registry(risk_map_schemas_dir: Path) -> Registry:
    """
    referencing.Registry that resolves bare-filename $refs against the
    schemas directory. Replaces the deprecated jsonschema.RefResolver.
    """

    def retrieve(uri: str):
        # The validator hands us the URI portion of a $ref; for our refs the
        # URI is a bare schema filename relative to risk_map_schemas_dir.
        name = uri.rsplit("/", 1)[-1]
        path = risk_map_schemas_dir / name
        with open(path) as fh:
            return Resource.from_contents(json.load(fh), default_specification=DRAFT7)

    return Registry(retrieve=retrieve)


# ============================================================================
# Schema meta-validity
# ============================================================================


class TestSchemaMetaValidity:
    """persona-site-data.schema.json must be valid Draft-07."""

    def test_schema_passes_draft07_metaschema(self, persona_site_schema: dict):
        """
        Test that persona-site-data.schema.json is a valid Draft-07 schema.

        Given: persona-site-data.schema.json loaded
        When: Draft7Validator.check_schema() is called
        Then: No SchemaError is raised
        """
        try:
            Draft7Validator.check_schema(persona_site_schema)
        except SchemaError as exc:
            pytest.fail(f"{SCHEMA_FILE} is not valid Draft-07: {exc.message}")


# ============================================================================
# Forward compatibility — old all-strings shape still validates
# ============================================================================


class TestOldShapeStillValid:
    """
    The current site builder emits all-strings prose. That shape must continue
    to validate (extension is additive).
    """

    @pytest.mark.parametrize("value", OLD_SHAPE_VALID)
    def test_old_prose_shape_accepted(self, prose_validator: Draft7Validator, value: list):
        """
        Test that old-shape prose arrays continue to pass.

        Given: The extended definitions/prose schema
        When: An old-shape prose value (strings and nested string arrays) is validated
        Then: No errors are raised (backward compatible)
        """
        errors = list(prose_validator.iter_errors(value))
        assert not errors, f"Old-shape prose {value!r} must still be accepted; got: {[e.message for e in errors]}"


# ============================================================================
# New ref-type items accepted
# ============================================================================


class TestRefTypeItemsAccepted:
    """
    definitions/prose must accept ref-type objects as items.
    """

    @pytest.mark.parametrize("ref_item", VALID_REF_ITEMS)
    def test_ref_type_item_accepted_in_prose(self, prose_validator: Draft7Validator, ref_item: dict):
        """
        Test that a ref-type prose item is accepted.

        Given: A prose array containing one ref-type structured item
        When: It is validated against definitions/prose
        Then: No errors are raised

        The ref shape is { type: "ref", id: <string>, title: <string> },
        emitted by the site builder when {{idRiskFoo}} sentinels are resolved
        (ADR-016 D5).
        """
        errors = list(prose_validator.iter_errors([ref_item]))
        assert not errors, (
            f"ref-type item {ref_item!r} must be accepted in prose; got: {[e.message for e in errors]}"
        )

    def test_ref_item_missing_id_rejected(self, prose_validator: Draft7Validator):
        """
        Test that a ref-type item missing the required 'id' field is rejected.

        Given: A ref-type object without 'id'
        When: It is validated as a prose item
        Then: ValidationError is raised
        """
        bad_ref = {"type": "ref", "title": "Missing Id"}
        errors = list(prose_validator.iter_errors([bad_ref]))
        assert errors, "ref-type item missing 'id' must be rejected"

    def test_ref_item_missing_title_rejected(self, prose_validator: Draft7Validator):
        """
        Test that a ref-type item missing the required 'title' field is rejected.

        Given: A ref-type object without 'title'
        When: It is validated as a prose item
        Then: ValidationError is raised
        """
        bad_ref = {"type": "ref", "id": "riskFoo"}
        errors = list(prose_validator.iter_errors([bad_ref]))
        assert errors, "ref-type item missing 'title' must be rejected"


# ============================================================================
# New link-type items accepted
# ============================================================================


class TestLinkTypeItemsAccepted:
    """
    definitions/prose must accept link-type objects as items.
    """

    @pytest.mark.parametrize("link_item", VALID_LINK_ITEMS)
    def test_link_type_item_accepted_in_prose(self, prose_validator: Draft7Validator, link_item: dict):
        """
        Test that a link-type prose item is accepted.

        Given: A prose array containing one link-type structured item
        When: It is validated against definitions/prose
        Then: No errors are raised

        The link shape is { type: "link", title: <string>, url: <string> },
        emitted by the site builder when {{ref:identifier}} sentinels are
        resolved (ADR-016 D5).
        """
        errors = list(prose_validator.iter_errors([link_item]))
        assert not errors, (
            f"link-type item {link_item!r} must be accepted in prose; got: {[e.message for e in errors]}"
        )

    def test_link_item_non_https_url_rejected(self, prose_validator: Draft7Validator):
        """
        Test that a link-type item with a non-https URL is rejected.

        Given: A link-type object with url='http://example.com' (non-https)
        When: It is validated as a prose item
        Then: ValidationError is raised (url must be https)
        """
        bad_link = {"type": "link", "title": "Bad URL", "url": "http://example.com"}
        errors = list(prose_validator.iter_errors([bad_link]))
        assert errors, "link-type item with http:// url must be rejected"

    def test_link_item_missing_url_rejected(self, prose_validator: Draft7Validator):
        """
        Test that a link-type item missing the required 'url' field is rejected.

        Given: A link-type object without 'url'
        When: It is validated as a prose item
        Then: ValidationError is raised
        """
        bad_link = {"type": "link", "title": "No URL"}
        errors = list(prose_validator.iter_errors([bad_link]))
        assert errors, "link-type item missing 'url' must be rejected"

    def test_link_item_missing_title_rejected(self, prose_validator: Draft7Validator):
        """
        Test that a link-type item missing the required 'title' field is rejected.

        Given: A link-type object without 'title'
        When: It is validated as a prose item
        Then: ValidationError is raised
        """
        bad_link = {"type": "link", "url": "https://example.com"}
        errors = list(prose_validator.iter_errors([bad_link]))
        assert errors, "link-type item missing 'title' must be rejected"


# ============================================================================
# Mixed-content prose arrays accepted
# ============================================================================


class TestMixedContentProseAccepted:
    """
    Heterogeneous prose arrays mixing strings, nested string arrays, and
    structured items (ref/link) must all be accepted by the extended schema.
    """

    @pytest.mark.parametrize("value", VALID_MIXED_PROSE)
    def test_mixed_prose_array_accepted(self, prose_validator: Draft7Validator, value: list):
        """
        Test that mixed-content prose arrays are accepted.

        Given: A prose array containing both plain strings and structured items
        When: It is validated against the extended definitions/prose
        Then: No errors are raised
        """
        errors = list(prose_validator.iter_errors(value))
        assert not errors, f"Mixed prose array {value!r} must be accepted; got: {[e.message for e in errors]}"


# ============================================================================
# externalReferences property added to personas/risks/controls item objects
# ============================================================================


class TestExternalReferencesOnTopLevelItems:
    """
    The per-persona, per-risk, and per-control item objects must each declare
    an optional externalReferences property in their properties block. Because
    those objects use additionalProperties: false, the field must be explicitly
    present in properties to be accepted.
    """

    @pytest.mark.parametrize("array_key", TOP_LEVEL_ARRAYS)
    def test_external_references_declared_in_item_properties(self, persona_site_schema: dict, array_key: str):
        """
        Test that externalReferences is declared in each top-level item's properties.

        Given: The per-item object schema for personas/risks/controls in
               persona-site-data.schema.json
        When: Its properties block is inspected
        Then: 'externalReferences' is present
        """
        item_schema = persona_site_schema.get("properties", {}).get(array_key, {}).get("items", {})
        item_props = item_schema.get("properties", {})
        assert "externalReferences" in item_props, (
            f"persona-site-data.schema.json {array_key}[].properties must declare "
            f"'externalReferences' (additionalProperties: false requires "
            f"explicit declaration)"
        )

    @pytest.mark.parametrize("array_key", TOP_LEVEL_ARRAYS)
    def test_external_references_not_in_required(self, persona_site_schema: dict, array_key: str):
        """
        Test that externalReferences is not in the required array of item objects.

        Given: The per-item object schema for personas/risks/controls
        When: Its required array is inspected
        Then: 'externalReferences' is absent (field is optional)
        """
        item_schema = persona_site_schema.get("properties", {}).get(array_key, {}).get("items", {})
        required = item_schema.get("required", [])
        assert "externalReferences" not in required, (
            f"{array_key}[] item schema must NOT require externalReferences "
            "(optional passthrough field per ADR-016 D5)"
        )

    @pytest.mark.parametrize("array_key", TOP_LEVEL_ARRAYS)
    def test_valid_external_references_accepted_by_item(
        self,
        persona_site_schema: dict,
        registry: Registry,
        array_key: str,
    ):
        """
        Test that a valid externalReferences value is accepted for each item type.

        Given: The externalReferences property entry in a top-level item schema
        When: A valid externalReferences array is validated against the $ref'd schema
        Then: No errors are raised
        """
        item_schema = persona_site_schema.get("properties", {}).get(array_key, {}).get("items", {})
        ext_ref_entry = item_schema.get("properties", {}).get("externalReferences")
        assert ext_ref_entry is not None, f"externalReferences not in {array_key}[] item properties yet"
        ref_target = ext_ref_entry.get("$ref")
        assert ref_target, f"externalReferences in {array_key}[] must use $ref"

        resolved_schema = registry.resolver(base_uri="").lookup(ref_target).contents
        validator = Draft7Validator(resolved_schema, registry=registry)
        errors = list(validator.iter_errors(VALID_EXTERNAL_REFERENCES))
        assert not errors, (
            f"Valid externalReferences must be accepted for {array_key}[] item; got: {[e.message for e in errors]}"
        )

    @pytest.mark.parametrize("array_key", TOP_LEVEL_ARRAYS)
    def test_additional_properties_still_false_on_item(self, persona_site_schema: dict, array_key: str):
        """
        Test that additionalProperties: false is still set on each item schema.

        Given: The per-item object schema for personas/risks/controls
        When: Its additionalProperties is examined
        Then: It is still False (unchanged; the new field is declared in properties)
        """
        item_schema = persona_site_schema.get("properties", {}).get(array_key, {}).get("items", {})
        assert item_schema.get("additionalProperties") is False, (
            f"{array_key}[] item must retain additionalProperties: false "
            "(externalReferences was added to properties, not as a relaxation)"
        )


# ============================================================================
# Test summary
# ============================================================================
"""
Test Summary
============
Test classes: 7

- TestSchemaMetaValidity (1)                  — schema valid Draft-07
- TestOldShapeStillValid                       — parametrized: 5 old-shape prose
                                                 values still accepted
- TestRefTypeItemsAccepted (3)                 — 2 parametrized valid ref items
                                                 accepted; missing-id + missing-title
                                                 rejected
- TestLinkTypeItemsAccepted (4)                — 3 parametrized valid link items
                                                 accepted; non-https url + missing-url
                                                 + missing-title rejected
- TestMixedContentProseAccepted (2)            — parametrized: 2 mixed arrays accepted
- TestExternalReferencesOnTopLevelItems        — parametrized × 3 arrays:
                                                 declared in properties, not in
                                                 required, valid value accepted,
                                                 additionalProperties:false retained
                                                 (12 cases)

Coverage areas:
- prose extension: ref/link items, mixed content
- Forward compatibility: old all-strings shape still valid
- externalReferences on personas/risks/controls items (declared, optional)
- additionalProperties: false unchanged on item objects
- Structured item validation: missing fields rejected, non-https url rejected
- guidance on the controls item (declared as prose, optional; controls only)
"""


# ============================================================================
# guidance property on the controls item object
# ============================================================================


class TestGuidanceOnControlsItem:
    """
    The per-control item object declares an optional ``guidance`` property
    using the shared ``#/definitions/prose`` shape (ADR-020 D9 amendment;
    design record control-description-and-guidance.md). The item object uses
    additionalProperties: false, so the builder's emitted ``guidance`` is only
    accepted if it is declared here.
    """

    @staticmethod
    def _controls_item_schema(persona_site_schema: dict) -> dict:
        return persona_site_schema.get("properties", {}).get("controls", {}).get("items", {})

    def test_guidance_declared_as_prose_ref(self, persona_site_schema: dict):
        """
        Test that controls[].properties.guidance $refs #/definitions/prose.

        Given: The controls item schema in persona-site-data.schema.json
        When: Its properties block is inspected
        Then: 'guidance' is present and equals {"$ref": "#/definitions/prose"}
        """
        props = self._controls_item_schema(persona_site_schema).get("properties", {})
        assert "guidance" in props, (
            "persona-site-data.schema.json controls[].properties must declare 'guidance' "
            "(additionalProperties: false requires explicit declaration)"
        )
        assert props["guidance"].get("$ref") == "#/definitions/prose", (
            f"controls[].properties.guidance must $ref '#/definitions/prose'; got {props['guidance']!r}"
        )

    def test_guidance_not_required(self, persona_site_schema: dict):
        """
        Test that guidance is optional on the controls item.

        Given: The controls item schema
        When: Its required array is inspected
        Then: 'guidance' is absent (the builder omits the key when the control has none)
        """
        required = self._controls_item_schema(persona_site_schema).get("required", [])
        assert "guidance" not in required, "controls[] item schema must NOT require guidance"

    def test_controls_item_with_guidance_accepted_by_full_schema(
        self, persona_site_schema: dict, registry: Registry
    ):
        """
        Test that a site-data document whose control carries guidance validates end to end.

        Given: A minimal site-data document with one control whose guidance mixes a
               string, a nested string array, and an expanded ref item
        When: It is validated against the full persona-site-data.schema.json
        Then: No errors are raised
        """
        document = {
            "personas": [],
            "questions": [],
            "manualFallbackPersonaIds": [],
            "riskCategories": [],
            "controlCategories": [],
            "risks": [],
            "controls": [
                {
                    "id": "controlGuided",
                    "title": "Guided",
                    "category": "controlsTest",
                    "description": ["What the control is."],
                    "guidance": [
                        "Lead paragraph.",
                        ["Sub A.", "Sub B."],
                        ["See ", {"type": "ref", "id": "riskExample", "title": "Example"}, "."],
                    ],
                    "personaIds": [],
                    "riskIds": [],
                }
            ],
        }
        validator = Draft7Validator(persona_site_schema, registry=registry)
        errors = [e.message for e in validator.iter_errors(document)]
        assert not errors, f"controls item with guidance must validate; got: {errors}"

    @pytest.mark.parametrize("array_key", ["personas", "risks"])
    def test_guidance_not_declared_on_other_items(self, persona_site_schema: dict, array_key: str):
        """
        Test that guidance is scoped to controls only.

        Given: The personas and risks item schemas
        When: Their properties blocks are inspected
        Then: 'guidance' is absent (risks keep shortDescription/longDescription by design)
        """
        item_schema = persona_site_schema.get("properties", {}).get(array_key, {}).get("items", {})
        item_props = item_schema.get("properties", {})
        assert "guidance" not in item_props, f"{array_key}[] must not declare guidance (controls-only field)"
