#!/usr/bin/env python3
"""
Tests for Decision 2 (C1-schema-tightenings): `additionalProperties: false`
on every `definitions/<entity>` block across the eight target schemas, per
ADRs 018-022 D-sections.

Plan task 2.2.6: every top-level definitions/<entity> in the 8 content +
supporting schemas closes the schema against unknown keys. Sites tested here
(12 new edits + 1 pre-existing that must be preserved):

  risks.schema.json:         definitions/risk
  controls.schema.json:      definitions/category, definitions/control
  components.schema.json:    definitions/category, definitions/subcategory,
                             definitions/component, definitions/edges
  personas.schema.json:      definitions/persona
  frameworks.schema.json:    definitions/framework
  actor-access.schema.json:  definitions/actorAccessLevel
  impact-type.schema.json:   definitions/impactType
  lifecycle-stage.schema.json: definitions/lifecycleStage

Pre-existing (must remain):
  frameworks.schema.json:    definitions/framework-mapping-patterns (ADR-022 D5b)

Out of scope:
  file-root additionalProperties — plan task 2.2.6 targets definitions/<entity>
  blocks only.
  self-assessment.schema.json#/definitions/selfAssessment — handled by the C3
  sibling PR (archive self-assessment), not this PR.

Coverage:
- Each of the 12 new sites declares additionalProperties:false.
- Each entity definition rejects a synthetic entry carrying a stray field.
- The pre-existing framework-mapping-patterns additionalProperties:false
  is preserved.
- Phase-2 (#343 ADR-027 D3a): mappings.additionalProperties is the BOOLEAN FALSE
  for all four consumer schemas (risks/controls/components/personas). The former
  loose catch-all schema object was removed by the Phase-2 schema flip (#343).
- The live risks.yaml corpus validates clean against definitions/risk under
  the combined D1+D2 state — ordering guard so D1 lands before D2.
"""

import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft7Validator

sys.path.insert(0, str(Path(__file__).parent.parent))

from conftest import _load_schema, _make_registry

# ============================================================================
# Module-level constants
# ============================================================================

# All 11 entity definition sites that must gain additionalProperties:false.
# Tuple layout: (schema_filename, definitions_key)
# 10 new edits; framework-mapping-patterns is the 11th site but pre-existing —
# listed separately in ALREADY_STRICT_SITES for the preservation guard.
NEW_STRICT_SITES: list[tuple[str, str]] = [
    ("risks.schema.json", "risk"),
    ("controls.schema.json", "category"),
    ("controls.schema.json", "control"),
    ("components.schema.json", "category"),
    ("components.schema.json", "subcategory"),
    ("components.schema.json", "component"),
    ("components.schema.json", "edges"),
    ("personas.schema.json", "persona"),
    ("frameworks.schema.json", "framework"),
    ("actor-access.schema.json", "actorAccessLevel"),
    ("impact-type.schema.json", "impactType"),
    ("lifecycle-stage.schema.json", "lifecycleStage"),
]

# Strict site established by ADR-022 D5b; preserved through C1.
ALREADY_STRICT_SITES: list[tuple[str, str]] = [
    ("frameworks.schema.json", "framework-mapping-patterns"),
]

# Stray field used in all synthetic rejection tests.
_STRAY_FIELD = "unknownXyzField"

# ============================================================================
# Minimal valid synthetic entries per entity — used in rejection tests.
# Fields satisfy the required[] array for each entity; enum values are corpus-valid.
# ============================================================================

# risks.schema.json / definitions/risk — required: id, title, shortDescription,
# longDescription, category, personas, controls
_MINIMAL_RISK: dict = {
    "id": "riskDataPoisoning",
    "title": "Data Poisoning",
    "shortDescription": ["Short description."],
    "longDescription": ["Long description."],
    "category": "risksSupplyChainAndDevelopment",
    "personas": ["personaModelProvider"],
    "controls": ["controlTrainingDataSanitization"],
}

# controls.schema.json / definitions/category — required: id, title
_MINIMAL_CONTROLS_CATEGORY: dict = {
    "id": "controlsData",
    "title": "Data Controls",
}

# controls.schema.json / definitions/control — required: title, description, category,
# personas, components, risks
_MINIMAL_CONTROL: dict = {
    "title": "Training Data Management",
    "description": ["Manage training data."],
    "category": "controlsData",
    "personas": ["personaModelProvider"],
    "components": ["componentDataSources"],
    "risks": ["riskDataPoisoning"],
}

# components.schema.json / definitions/category — required: id, title
_MINIMAL_COMPONENTS_CATEGORY: dict = {
    "id": "componentsInfrastructure",
    "title": "Infrastructure",
}

# components.schema.json / definitions/subcategory — required: id, title
_MINIMAL_SUBCATEGORY: dict = {
    "id": "componentsData",
    "title": "Data",
}

# components.schema.json / definitions/component — required: id, title, category, edges
_MINIMAL_COMPONENT: dict = {
    "id": "componentDataSources",
    "title": "Data Sources",
    "category": "componentsInfrastructure",
    "edges": {"to": ["componentTheModel"]},
}

# components.schema.json / definitions/edges — anyOf: [{required: ["to"]},{required: ["from"]}]
_MINIMAL_EDGES: dict = {
    "to": ["componentTheModel"],
}

# personas.schema.json / definitions/persona — required: id, title, description.
# Non-deprecated personas also require identificationQuestions (ADR-021 D8
# if/then constraint), so an active minimal persona must carry the block.
_MINIMAL_PERSONA: dict = {
    "id": "personaModelProvider",
    "title": "Model Provider",
    "description": ["A model provider persona."],
    "identificationQuestions": ["Do you supply or license AI models to other organizations?"],
}

# frameworks.schema.json / definitions/framework — required: id, name, fullName,
# description, baseUri, applicableTo
_MINIMAL_FRAMEWORK: dict = {
    "id": "mitre-atlas",
    "name": "MITRE ATLAS",
    "fullName": "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)",
    "description": "Framework for AI threat modeling.",
    "baseUri": "https://atlas.mitre.org",
    "applicableTo": ["risks"],
}

# actor-access.schema.json / definitions/actorAccessLevel — required: id, title, description
_MINIMAL_ACTOR_ACCESS: dict = {
    "id": "external",
    "title": "External",
    "description": "External actor with no system access.",
}

# impact-type.schema.json / definitions/impactType — required: id, title, description
_MINIMAL_IMPACT_TYPE: dict = {
    "id": "confidentiality",
    "title": "Confidentiality",
    "description": "Data confidentiality impact.",
}

# lifecycle-stage.schema.json / definitions/lifecycleStage — required: id, title, description
_MINIMAL_LIFECYCLE_STAGE: dict = {
    "id": "planning",
    "title": "Planning",
    "description": "Initial planning phase.",
}

# Maps (schema_file, entity_key) to a minimal valid entry for that entity.
_MINIMAL_ENTRIES: dict[tuple[str, str], dict] = {
    ("risks.schema.json", "risk"): _MINIMAL_RISK,
    ("controls.schema.json", "category"): _MINIMAL_CONTROLS_CATEGORY,
    ("controls.schema.json", "control"): _MINIMAL_CONTROL,
    ("components.schema.json", "category"): _MINIMAL_COMPONENTS_CATEGORY,
    ("components.schema.json", "subcategory"): _MINIMAL_SUBCATEGORY,
    ("components.schema.json", "component"): _MINIMAL_COMPONENT,
    ("components.schema.json", "edges"): _MINIMAL_EDGES,
    ("personas.schema.json", "persona"): _MINIMAL_PERSONA,
    ("frameworks.schema.json", "framework"): _MINIMAL_FRAMEWORK,
    ("actor-access.schema.json", "actorAccessLevel"): _MINIMAL_ACTOR_ACCESS,
    ("impact-type.schema.json", "impactType"): _MINIMAL_IMPACT_TYPE,
    ("lifecycle-stage.schema.json", "lifecycleStage"): _MINIMAL_LIFECYCLE_STAGE,
}


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def schemas_dir(risk_map_schemas_dir: Path) -> Path:
    """Alias for concise test signatures."""
    return risk_map_schemas_dir


# ============================================================================
# Helper — build a validator for a specific entity definition
# ============================================================================


def _entity_validator(schemas_dir: Path, schema_file: str, entity_key: str) -> Draft7Validator:
    """
    Build a Draft-07 validator targeting definitions/<entity_key> in schema_file.

    Uses the full parent schema as the root so that internal $refs (e.g.,
    '#/definitions/component/properties/id' inside definitions/edges) resolve
    correctly against the full definitions map, not just the entity sub-object.
    Cross-file $refs are resolved via _make_registry.

    The wrapper schema routes validation through a $ref to the entity definition
    inside the parent schema, which is registered in the registry under schema_file.
    """
    registry = _make_registry(schemas_dir)
    # Validate via a $ref wrapper: the full schema is accessible in the registry
    # under its $id (e.g., 'controls.schema.json'), so internal #/definitions/...
    # refs resolve against the full schema root.
    wrapper = {"$ref": f"{schema_file}#/definitions/{entity_key}"}
    return Draft7Validator(wrapper, registry=registry)


# ============================================================================
# Decision 2 — each site declares additionalProperties:false
# ============================================================================


class TestEntityDefinitionsHaveAdditionalPropertiesFalse:
    """
    Every definitions/<entity> block in the 8 target schemas declares
    additionalProperties:false per ADRs 018-022 D-sections.

    self-assessment.schema.json#/definitions/selfAssessment is explicitly
    out of C1 scope (handled by the C3 sibling PR — archive self-assessment).
    """

    @pytest.mark.parametrize(
        "schema_file,entity_key",
        NEW_STRICT_SITES,
        ids=[f"{s}/{e}" for s, e in NEW_STRICT_SITES],
    )
    def test_entity_definition_has_additional_properties_false(
        self,
        schemas_dir: Path,
        schema_file: str,
        entity_key: str,
    ):
        """
        Test that definitions/<entity_key> declares additionalProperties:false.

        Given: A target schema file and entity definition key
        When: definitions/<entity_key> is inspected for additionalProperties
        Then: The value is exactly false (boolean), not missing or a schema object

        Per ADRs 018-022: all definitions/<entity> blocks must be closed schemas.
        """
        schema = _load_schema(schemas_dir, schema_file)
        entity_defn = schema.get("definitions", {}).get(entity_key, {})
        ap = entity_defn.get("additionalProperties", "<MISSING>")
        assert ap is False, (
            f"{schema_file} definitions/{entity_key} must declare "
            f"additionalProperties:false (got: {ap!r}); "
            "per ADRs 018-022 D-sections — all entity definitions must be closed schemas"
        )


# ============================================================================
# Decision 2 — each entity definition rejects synthetic stray-field entries
# ============================================================================


class TestEntityDefinitionsRejectAdditionalProperties:
    """
    A synthetic entry carrying a stray field (e.g., a typo like 'descripton')
    raises ValidationError against any of the 12 closed entity definitions.
    """

    @pytest.mark.parametrize(
        "schema_file,entity_key",
        NEW_STRICT_SITES,
        ids=[f"{s}/{e}" for s, e in NEW_STRICT_SITES],
    )
    def test_stray_field_raises_validation_error(
        self,
        schemas_dir: Path,
        schema_file: str,
        entity_key: str,
    ):
        """
        Test that a synthetic entity entry with a stray field is rejected.

        Given: A minimal valid entity entry augmented with an unrecognized field
        When: It is validated against definitions/<entity_key>
        Then: ValidationError is raised (additionalProperties:false)

        The stray field 'unknownXyzField' simulates a typo or unsupported key
        that authors might accidentally include.
        """
        base = _MINIMAL_ENTRIES.get((schema_file, entity_key))
        if base is None:
            pytest.fail(f"No minimal entry defined for ({schema_file}, {entity_key})")
        entry = dict(base)
        entry[_STRAY_FIELD] = "unexpected value"

        validator = _entity_validator(schemas_dir, schema_file, entity_key)
        errors = list(validator.iter_errors(entry))
        assert errors, (
            f"{schema_file} definitions/{entity_key} must reject entry with stray field "
            f"'{_STRAY_FIELD}' (additionalProperties:false on the entity definition)"
        )

    @pytest.mark.parametrize(
        "schema_file,entity_key",
        NEW_STRICT_SITES,
        ids=[f"{s}/{e}" for s, e in NEW_STRICT_SITES],
    )
    def test_minimal_valid_entry_passes(
        self,
        schemas_dir: Path,
        schema_file: str,
        entity_key: str,
    ):
        """
        Test that the minimal valid entry passes validation (baseline health check).

        Given: A minimal entity entry with all required fields and no stray properties
        When: It is validated against definitions/<entity_key>
        Then: No errors are raised

        Baseline sentinel: the stray-field rejection tests above need a clean
        positive control. If this fails, the minimal entry or schema required
        fields need updating.
        """
        base = _MINIMAL_ENTRIES.get((schema_file, entity_key))
        if base is None:
            pytest.fail(f"No minimal entry defined for ({schema_file}, {entity_key})")
        validator = _entity_validator(schemas_dir, schema_file, entity_key)
        errors = list(validator.iter_errors(base))
        assert not errors, (
            f"Minimal valid entry for {schema_file} definitions/{entity_key} must pass; "
            f"errors: {[e.message for e in errors]}"
        )


# ============================================================================
# Preservation guard — framework-mapping-patterns additionalProperties:false retained
# ============================================================================


class TestFrameworkMappingPatternsPreservesAdditionalPropertiesFalse:
    """
    frameworks.schema.json definitions/framework-mapping-patterns has carried
    additionalProperties:false since ADR-022 D5b. This guard confirms the C1
    edits never accidentally revert it.
    """

    @pytest.mark.parametrize(
        "schema_file,entity_key",
        ALREADY_STRICT_SITES,
        ids=[f"{s}/{e}" for s, e in ALREADY_STRICT_SITES],
    )
    def test_pre_existing_additional_properties_false_preserved(
        self,
        schemas_dir: Path,
        schema_file: str,
        entity_key: str,
    ):
        """
        Test that additionalProperties:false on framework-mapping-patterns is
        present (preserved through C1).

        Given: frameworks.schema.json definitions/framework-mapping-patterns
        When: additionalProperties is inspected
        Then: It is false (ADR-022 D5b shape preserved)
        """
        schema = _load_schema(schemas_dir, schema_file)
        entity_defn = schema.get("definitions", {}).get(entity_key, {})
        ap = entity_defn.get("additionalProperties", "<MISSING>")
        assert ap is False, (
            f"{schema_file} definitions/{entity_key} must declare "
            f"additionalProperties:false (preserved from ADR-022 D5b); got: {ap!r}"
        )


# ============================================================================
# Phase-2 strict flip — mappings.additionalProperties is false for all four consumers
# ============================================================================


class TestMappingsAdditionalPropertiesIsFalse:
    """
    After the Phase-2 strict flip (#343 ADR-027 D3a), the mappings field inside
    all four consumer entities (risk, control, component, persona) must have:

        additionalProperties: false

    The loose schema-object catch-all
        additionalProperties: {type: array, items: {type: string}}
    that previously allowed stride/nist-ai-rmf/owasp-top10-llm legacy forms
    to pass through is REMOVED. All frameworks are now explicitly wired via
    per-property entries pointing at framework-mapping-patterns-pinned.

    This class replaces the former TestMappingsAdditionalPropertiesIsNotBoolean
    which asserted the opposite invariant (catch-all present). That invariant is
    gone after Phase 2.

    These tests assert the strict ADR-027 D3a wiring now enforced by the schema (#343).
    """

    # All four consumer schemas that host a mappings field.
    _MAPPINGS_HOSTS: list[tuple[str, str]] = [
        ("risks.schema.json", "risk"),
        ("controls.schema.json", "control"),
        ("components.schema.json", "component"),
        ("personas.schema.json", "persona"),
    ]

    @pytest.mark.parametrize(
        "schema_file,entity_key",
        _MAPPINGS_HOSTS,
        ids=[f"{s}/{e}" for s, e in _MAPPINGS_HOSTS],
    )
    def test_mappings_additional_properties_is_false(
        self,
        schemas_dir: Path,
        schema_file: str,
        entity_key: str,
    ):
        """
        Test that mappings.additionalProperties is exactly the boolean false.

        Given: definitions/<entity>/properties/mappings in a consumer schema (#343)
        When: Its additionalProperties value is inspected
        Then: It is the boolean false — NOT a schema-object catch-all

        ADR-027 D3a: the loose catch-all for stride/nist-ai-rmf/owasp-top10-llm
        was removed after content migration; additionalProperties: false is now
        set on all four consumer mappings blocks.

        Formerly this test class (then named TestMappingsAdditionalPropertiesIsNotBoolean)
        asserted the opposite — that the catch-all was a schema object, not false.
        That invariant was removed by the Phase-2 schema flip (#343).
        """
        schema = _load_schema(schemas_dir, schema_file)
        entity_defn = schema.get("definitions", {}).get(entity_key, {})
        mappings = entity_defn.get("properties", {}).get("mappings")
        if mappings is None:
            pytest.skip(f"{schema_file} definitions/{entity_key} has no mappings property")
        ap = mappings.get("additionalProperties", "<MISSING>")
        assert ap is False, (
            f"{schema_file} definitions/{entity_key}/properties/mappings/additionalProperties "
            f"must be the boolean false (strict schema, #343 ADR-027 D3a); "
            f"got: {ap!r}. The loose catch-all schema object must be replaced with false."
        )


# ============================================================================
# Decision 2 ordering guard — risks.yaml validates clean after D1+D2 combined
# ============================================================================


class TestRisksYamlValidatesCleanPostTightening:
    """
    The live risks.yaml corpus validates clean against definitions/risk under
    the combined D1+D2 state (relevantQuestions removed + additionalProperties
    closed). This pins the Risk R10 ordering invariant: D1 must land before D2
    so the corpus never hits a state where the still-present relevantQuestions
    field collides with a just-closed schema.

    A failure here means either (a) a corpus risk entry uses a field not
    declared in definitions/risk, or (b) Decision 1 content removal regressed
    (relevantQuestions reintroduced to YAML).
    """

    def test_risks_yaml_corpus_validates_against_definitions_risk(
        self,
        schemas_dir: Path,
        risk_map_yaml_dir: Path,
    ):
        """
        Test that every risk entry in risks.yaml passes definitions/risk validation.

        Given: The full risks.yaml corpus and the definitions/risk validator
        When: Each risk entry is validated
        Then: No ValidationError is raised for any entry

        Risk R10 ordering guard: a failure here surfaces either a corpus
        regression or a D1-before-D2 ordering violation.
        """
        risks_path = risk_map_yaml_dir / "risks.yaml"
        if not risks_path.is_file():
            pytest.fail(f"risks.yaml not found at {risks_path}")
        with open(risks_path) as fh:
            data = yaml.safe_load(fh)

        risks_schema = _load_schema(schemas_dir, "risks.schema.json")
        registry = _make_registry(schemas_dir)
        risk_defn = risks_schema.get("definitions", {}).get("risk")
        if risk_defn is None:
            pytest.fail("definitions/risk not found in risks.schema.json")

        validator = Draft7Validator(risk_defn, registry=registry)
        failures: list[str] = []
        for risk in data.get("risks", []):
            errors = list(validator.iter_errors(risk))
            if errors:
                rid = risk.get("id", "<unknown>")
                failures.append(f"  {rid}: {[e.message for e in errors]}")

        assert not failures, (
            "risks.yaml corpus has validation failures against definitions/risk "
            "(D1+D2 ordering guard):\n" + "\n".join(failures)
        )


# ============================================================================
# Test summary
# ============================================================================
"""
Test Summary
============
Parametrized sites: 12 new entity definitions + 1 pre-existing
  (framework-mapping-patterns) + 4 mappings-host entities
Standalone test methods: 1 (corpus ordering guard)
Test classes: 5

- TestEntityDefinitionsHaveAdditionalPropertiesFalse (12 parametrized) —
  every entity definition declares additionalProperties:false.
- TestEntityDefinitionsRejectAdditionalProperties (12+12 parametrized) —
  stray-field entries rejected; minimal valid entries accepted (baseline).
- TestFrameworkMappingPatternsPreservesAdditionalPropertiesFalse (1) —
  pre-existing additionalProperties:false (ADR-022 D5b) preserved.
- TestMappingsAdditionalPropertiesIsFalse (4) — Phase-2 (#343 ADR-027 D3a):
  mappings.additionalProperties is the boolean false for all four consumer
  schemas (strict schema now active).
  (Replaced former TestMappingsAdditionalPropertiesIsNotBoolean which
  asserted the loose catch-all schema object was NOT false — that invariant
  was removed by the Phase-2 schema flip.)
- TestRisksYamlValidatesCleanPostTightening (1) — risks.yaml validates
  clean under combined D1+D2 (Risk R10 ordering invariant).

Coverage areas:
- Structural: additionalProperties:false declared on all 12 new sites
- Behavioral: stray fields rejected, valid entries accepted
- Preservation: framework-mapping-patterns intact
- Phase-2 strict flip: mappings.additionalProperties is false (not a catch-all)
- Ordering guard: corpus clean under combined D1+D2
"""
