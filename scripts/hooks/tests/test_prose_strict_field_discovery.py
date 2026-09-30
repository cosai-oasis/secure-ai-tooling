#!/usr/bin/env python3
"""
Regression tests for prose-field discovery after the utils/text → utils/prose-strict
migration in the four content schemas (risks, controls, components, personas).

Background
----------
``find_prose_fields()`` in ``precommit/_prose_fields.py`` identifies prose fields
by matching the ``$ref`` value in the schema against a known prose-ref string.
After the content schemas were migrated to reference
``riskmap.schema.json#/definitions/utils/prose-strict``, the discovery module
still only recognised the old ``utils/text`` ref, causing zero ProseFields to be
discovered for all four content YAML files.

The fix must make ``find_prose_fields`` recognise BOTH refs:
  - ``riskmap.schema.json#/definitions/utils/prose-strict``  (content schemas)
  - ``riskmap.schema.json#/definitions/utils/text``          (supporting schemas)

These tests are structured to be RED until that fix lands and GREEN afterwards.

Test categories
---------------
1. Real-corpus non-zero discovery — the core regression guard.
   Each content YAML must yield >0 ProseFields.

2. prose-strict ref recognised via synthetic fixture — unit-level assertion
   that a schema using utils/prose-strict causes find_prose_fields to discover
   the field.

3. utils/text still recognised — additive guard ensuring the fix does not swap
   one ref for another; supporting schemas must still work.
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# sys.path injection — same idiom as sibling tests (test_validate_yaml_prose_subset.py,
# test_prose_field_shape_coverage.py)
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent / "precommit"))

try:
    from precommit._prose_fields import find_prose_fields  # noqa: E402

    _IMPORT_ERROR: Exception | None = None
except ImportError as _e:
    _IMPORT_ERROR = _e
    find_prose_fields = None  # type: ignore[assignment]


@pytest.fixture(autouse=True)
def _require_module():
    """Fail every test with ImportError when _prose_fields cannot be imported."""
    if _IMPORT_ERROR is not None:
        raise _IMPORT_ERROR


# ---------------------------------------------------------------------------
# Helpers — synthetic fixture builders
#
# The schema helpers follow the exact same pattern used in
# test_prose_field_shape_coverage.py: a minimal schema whose
# stem name matches the YAML file name so _infer_schema_name resolves it
# without needing the full real schema tree.
# ---------------------------------------------------------------------------

_UTILS_TEXT_REF = "riskmap.schema.json#/definitions/utils/text"
_UTILS_PROSE_STRICT_REF = "riskmap.schema.json#/definitions/utils/prose-strict"


def _write_schema_with_ref(schema_dir: Path, stem: str, prose_ref: str) -> Path:
    """Write a minimal ``<stem>.schema.json`` with one prose field using the given $ref.

    The schema declares a single ``description`` prose field on the entity definition,
    using the provided ``prose_ref`` value. Uses the same structure as
    ``_write_mock_schema`` in test_prose_field_shape_coverage.py.

    Args:
        schema_dir: Directory to write the schema file into.
        stem:       Schema filename stem (``<stem>.schema.json``); must match the YAML stem.
        prose_ref:  The ``$ref`` value to use for the description field.

    Returns:
        Path to the written schema file.
    """
    schema = {
        "$id": f"mock_{stem}.schema.json",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            f"{stem}s": {
                "type": "array",
                "items": {"$ref": f"#/definitions/{stem}"},
            }
        },
        "definitions": {
            stem: {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "description": {"$ref": prose_ref},
                },
            }
        },
    }
    path = schema_dir / f"{stem}.schema.json"
    path.write_text(json.dumps(schema))
    return path


def _build_synthetic_corpus(
    tmp_path: Path, stem: str, prose_ref: str, description_value: object
) -> tuple[Path, Path]:
    """Build a minimal schema + YAML pair for one entity using the given prose $ref.

    Args:
        tmp_path:           Per-test temporary directory.
        stem:               YAML/schema stem name (e.g. ``"risks"``).
        prose_ref:          The ``$ref`` string to place on the ``description`` field.
        description_value:  Value to write for the prose field.

    Returns:
        ``(yaml_path, schema_dir)`` ready to pass to ``find_prose_fields``.
    """
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    _write_schema_with_ref(schema_dir, stem, prose_ref)

    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    data = {f"{stem}s": [{"id": f"{stem}Alpha", "description": description_value}]}
    yaml_path = yaml_dir / f"{stem}.yaml"
    yaml_path.write_text(yaml.dump(data))
    return yaml_path, schema_dir


# ---------------------------------------------------------------------------
# Section 1 — Real-corpus non-zero discovery
#
# These tests are the core regression guard. They call find_prose_fields against
# the actual YAML and schema files in the repository. Each must yield at least one
# ProseField after the fix lands.
#
# Today (before the fix), all four yield 0 because the content schemas reference
# utils/prose-strict but _prose_fields.py only recognises utils/text.
# ---------------------------------------------------------------------------


# Repo root relative to this file: scripts/hooks/tests/ -> ../../../
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_REAL_YAML_DIR = _REPO_ROOT / "risk-map" / "yaml"
_REAL_SCHEMA_DIR = _REPO_ROOT / "risk-map" / "schemas"

_CONTENT_YAML_FILES = [
    "risks.yaml",
    "controls.yaml",
    "components.yaml",
    "personas.yaml",
]


@pytest.mark.parametrize("yaml_filename", _CONTENT_YAML_FILES, ids=_CONTENT_YAML_FILES)
def test_content_yaml_find_prose_fields_yields_nonzero(yaml_filename):
    """
    Asserts that find_prose_fields discovers at least one ProseField for each
    content YAML file when run against the real repository schemas.

    Given: A content YAML file and its companion schema (which uses utils/prose-strict
           for all description fields per the prose-strict schema migration (ADR-017/ADR-019))
    When:  find_prose_fields(yaml_path, schema_dir) is called
    Then:  At least one ProseField is yielded

    Before the fix: yields 0 (utils/prose-strict not recognised).
    After the fix:  yields >0 (both utils/prose-strict and utils/text recognised).
    """
    yaml_path = _REAL_YAML_DIR / yaml_filename
    if not yaml_path.is_file():
        pytest.fail(f"Real corpus file not found: {yaml_path}")

    fields = list(find_prose_fields(yaml_path, _REAL_SCHEMA_DIR))

    assert len(fields) > 0, (
        f"find_prose_fields() returned 0 ProseFields for {yaml_filename}. "
        f"The schema for this file uses utils/prose-strict $refs, which are not "
        f"recognised by the current _PROSE_REF constant in _prose_fields.py. "
        f"Fix: extend _is_prose_ref (or _PROSE_REFS) to recognise both "
        f"utils/prose-strict and utils/text."
    )


# ---------------------------------------------------------------------------
# Section 2 — prose-strict ref recognised at the unit level
#
# These tests use synthetic schema+yaml fixtures so they isolate exactly the
# ref-recognition logic without depending on the real corpus content.
#
# The assertion is against the public find_prose_fields interface. The private
# _is_prose_ref/_PROSE_REF symbols are not imported here because the SWE may
# rename them to _is_prose_ref/_PROSE_REFS during the fix. If a test that
# exercises the private predicate directly is later needed, it should be added
# with a comment noting the symbol may be renamed.
# ---------------------------------------------------------------------------


def test_prose_strict_ref_causes_field_to_be_discovered(tmp_path):
    """
    Asserts that a schema field whose $ref is utils/prose-strict is discovered
    by find_prose_fields.

    Given: A synthetic schema where description uses utils/prose-strict, and a
           matching YAML entry with a non-empty description
    When:  find_prose_fields(yaml_path, schema_dir) is called
    Then:  At least one ProseField is yielded — the description value is
           discovered as a prose field

    Before the fix: yields 0 (utils/prose-strict not in the recognised-ref set).
    After the fix:  yields >0.
    """
    yaml_path, schema_dir = _build_synthetic_corpus(
        tmp_path,
        stem="risks",
        prose_ref=_UTILS_PROSE_STRICT_REF,
        description_value=["A sentence about this risk."],
    )

    fields = list(find_prose_fields(yaml_path, schema_dir))

    assert len(fields) > 0, (
        f"find_prose_fields() returned 0 ProseFields for a schema that uses "
        f"utils/prose-strict. The $ref '{_UTILS_PROSE_STRICT_REF}' is not "
        f"recognised by _is_prose_ref in _prose_fields.py. "
        f"Fix: add this ref to the recognised set alongside utils/text."
    )


def test_prose_strict_ref_discovered_field_has_correct_raw_text(tmp_path):
    """
    Asserts that the ProseField discovered via utils/prose-strict carries the
    correct raw_text value from the YAML entry.

    Given: A synthetic schema with utils/prose-strict and a YAML entry with
           description: ["Expected text."]
    When:  find_prose_fields is called
    Then:  The single ProseField has raw_text == "Expected text."
    """
    expected_text = "Expected text."
    yaml_path, schema_dir = _build_synthetic_corpus(
        tmp_path,
        stem="controls",
        prose_ref=_UTILS_PROSE_STRICT_REF,
        description_value=[expected_text],
    )

    fields = list(find_prose_fields(yaml_path, schema_dir))

    # one entity, one description field, one list item -> exactly one ProseField
    assert len(fields) == 1, f"Expected exactly one ProseField from a single-entry description; got {len(fields)}"
    assert fields[0].raw_text == expected_text, (
        f"ProseField.raw_text mismatch: expected {expected_text!r}, got {fields[0].raw_text!r}"
    )


# ---------------------------------------------------------------------------
# Section 3 — utils/text still recognised (no-regression on supporting schemas)
#
# These tests confirm that the fix is additive: the utils/text ref must continue
# to be discovered so supporting schemas (frameworks, actor-access, impact-type,
# lifecycle-stage) are not broken by the fix.
# ---------------------------------------------------------------------------


def test_utils_text_ref_causes_field_to_be_discovered_synthetic(tmp_path):
    """
    Asserts that a schema field whose $ref is utils/text is still discovered by
    find_prose_fields after the fix.

    Given: A synthetic schema where description uses utils/text
    When:  find_prose_fields is called
    Then:  At least one ProseField is yielded

    This is a no-regression guard: the fix must extend the recognised-ref set,
    not swap utils/text for utils/prose-strict.
    """
    yaml_path, schema_dir = _build_synthetic_corpus(
        tmp_path,
        stem="risks",
        prose_ref=_UTILS_TEXT_REF,
        description_value=["A sentence."],
    )

    fields = list(find_prose_fields(yaml_path, schema_dir))

    assert len(fields) > 0, (
        "find_prose_fields() returned 0 ProseFields for a schema using utils/text. "
        "The utils/text $ref must remain recognised after the fix. "
        "Fix must be additive (both refs recognised), not a swap."
    )


def test_utils_text_ref_real_supporting_schema_yields_nonzero():
    """
    Asserts that find_prose_fields yields at least one ProseField for a real
    supporting schema that uses utils/text.

    Given: frameworks.yaml and its companion schema (which uses utils/text)
    When:  find_prose_fields is called
    Then:  At least one ProseField is yielded

    This guards against a regression where the fix accidentally stops recognising
    utils/text, breaking discovery for supporting schemas.
    """
    yaml_path = _REAL_YAML_DIR / "frameworks.yaml"
    if not yaml_path.is_file():
        pytest.skip(f"frameworks.yaml not found at {yaml_path}; skipping real-corpus guard")

    fields = list(find_prose_fields(yaml_path, _REAL_SCHEMA_DIR))

    assert len(fields) > 0, (
        "find_prose_fields() returned 0 ProseFields for frameworks.yaml. "
        "The frameworks schema uses utils/text, which must remain recognised "
        "after the fix. The fix must extend the recognised-ref set, not swap it."
    )


def test_both_refs_discovered_when_each_used_in_separate_schemas(tmp_path):
    """
    Asserts that two schemas in the same schema_dir — one using utils/prose-strict
    and one using utils/text — each cause find_prose_fields to discover a field.

    Given: Two minimal schemas in the same schema_dir, one referencing
           utils/prose-strict and one utils/text; two matching YAML files
    When:  find_prose_fields is called on each YAML file
    Then:  Both calls yield at least one ProseField

    This confirms the fix is additive: both refs are in the recognised set
    simultaneously.
    """
    # Schema/YAML pair for utils/prose-strict (content schema shape)
    # Use singular stems ("risk", "framework") so _write_schema_with_ref produces
    # array-property keys "risks" / "frameworks" that match the YAML top-level keys.
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    _write_schema_with_ref(schema_dir, "risk", _UTILS_PROSE_STRICT_REF)
    _write_schema_with_ref(schema_dir, "framework", _UTILS_TEXT_REF)

    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()

    # YAML top-level keys must match the schema's array-property keys (f"{stem}s").
    risks_yaml = yaml_dir / "risk.yaml"
    risks_yaml.write_text(yaml.dump({"risks": [{"id": "riskAlpha", "description": ["Risk prose."]}]}))

    frameworks_yaml = yaml_dir / "framework.yaml"
    frameworks_yaml.write_text(yaml.dump({"frameworks": [{"id": "fwAlpha", "description": ["Framework prose."]}]}))

    prose_strict_fields = list(find_prose_fields(risks_yaml, schema_dir))
    utils_text_fields = list(find_prose_fields(frameworks_yaml, schema_dir))

    assert len(prose_strict_fields) > 0, (
        "utils/prose-strict schema yielded 0 ProseFields in a two-schema schema_dir. "
        "The fix must recognise utils/prose-strict alongside utils/text."
    )
    assert len(utils_text_fields) > 0, (
        "utils/text schema yielded 0 ProseFields in a two-schema schema_dir. "
        "The fix must retain utils/text recognition (additive, not a swap)."
    )


"""
Test Summary
============
Total Tests: 9

Section 1 — Real-corpus non-zero discovery (4 parametrized):
  test_content_yaml_find_prose_fields_yields_nonzero[risks.yaml]
  test_content_yaml_find_prose_fields_yields_nonzero[controls.yaml]
  test_content_yaml_find_prose_fields_yields_nonzero[components.yaml]
  test_content_yaml_find_prose_fields_yields_nonzero[personas.yaml]

Section 2 — prose-strict ref recognised (2):
  test_prose_strict_ref_causes_field_to_be_discovered
  test_prose_strict_ref_discovered_field_has_correct_raw_text

Section 3 — utils/text still recognised (3):
  test_utils_text_ref_causes_field_to_be_discovered_synthetic
  test_utils_text_ref_real_supporting_schema_yields_nonzero
  test_both_refs_discovered_when_each_used_in_separate_schemas

Coverage areas:
  - Real-corpus regression guard: content schemas post-migration yield >0 fields
  - utils/prose-strict synthetic: schema using prose-strict ref is discovered
  - utils/text no-regression: utils/text remains recognised after the fix
  - Additive fix validation: both refs work simultaneously in one schema_dir

Section 4 — per-control guidance discovered from the real controls schema (3):
  test_real_controls_schema_discovers_guidance_field
  test_real_controls_schema_guidance_nested_list_carries_nested_index
  test_real_controls_schema_control_without_guidance_yields_no_guidance_field
"""


# ---------------------------------------------------------------------------
# Section 4 — per-control guidance discovered from the real controls schema
#
# The optional ``guidance`` property (ADR-020 D9 amendment; design record
# control-description-and-guidance.md) shares the description prose shape.
# Both prose linters discover fields from the schema, so declaring the property
# is what makes ``guidance`` lint-visible. These tests run against the REAL
# risk-map/schemas/ directory with a synthetic controls.yaml.
#
# The YAML basename is pinned to ``controls.yaml`` so ``_infer_schema_name``
# resolves controls.schema.json by stem; any other basename can fall back to
# array-key matching against a different schema and pass vacuously.
# ---------------------------------------------------------------------------


def _write_synthetic_controls_yaml(tmp_path: Path, control: dict) -> Path:
    """Write ``<tmp_path>/controls.yaml`` holding a single control entry."""
    yaml_path = tmp_path / "controls.yaml"
    yaml_path.write_text(yaml.dump({"controls": [control]}))
    return yaml_path


def test_real_controls_schema_discovers_guidance_field(tmp_path):
    """
    Given: The real risk-map/schemas/ dir and a controls.yaml whose one control
           carries guidance: ["How to meet the objective."]
    When:  find_prose_fields(yaml_path, real_schema_dir) is called
    Then:  Exactly one ProseField has field_name == "guidance", with the entry id
           and raw text of that control
    """
    guidance_text = "How to meet the objective."
    yaml_path = _write_synthetic_controls_yaml(
        tmp_path,
        {
            "id": "controlAlpha",
            "title": "Alpha",
            "description": ["What the control is."],
            "guidance": [guidance_text],
        },
    )

    fields = [f for f in find_prose_fields(yaml_path, _REAL_SCHEMA_DIR) if f.field_name == "guidance"]

    assert len(fields) == 1, (
        "controls.schema.json must declare definitions/control/properties/guidance with the "
        f"prose-strict $ref so the linters discover it; got guidance fields: {fields!r}"
    )
    assert fields[0].entry_id == "controlAlpha"
    assert fields[0].raw_text == guidance_text
    assert fields[0].index == 0
    assert fields[0].nested_index is None


def test_real_controls_schema_guidance_nested_list_carries_nested_index(tmp_path):
    """
    Given: A control whose guidance is ["Lead.", ["Bullet a.", "Bullet b."]]
    When:  find_prose_fields is called against the real schema dir
    Then:  Three guidance ProseFields are yielded with (index, nested_index)
           == {(0, None), (1, 0), (1, 1)} — the same nesting contract as description
    """
    yaml_path = _write_synthetic_controls_yaml(
        tmp_path,
        {
            "id": "controlAlpha",
            "title": "Alpha",
            "description": ["What the control is."],
            "guidance": ["Lead.", ["Bullet a.", "Bullet b."]],
        },
    )

    guidance_fields = [f for f in find_prose_fields(yaml_path, _REAL_SCHEMA_DIR) if f.field_name == "guidance"]
    positions = {(f.index, f.nested_index) for f in guidance_fields}

    assert positions == {(0, None), (1, 0), (1, 1)}, f"unexpected guidance positions: {positions!r}"


def test_real_controls_schema_control_without_guidance_yields_no_guidance_field(tmp_path):
    """
    Given: A control with a description and no guidance key
    When:  find_prose_fields is called against the real schema dir
    Then:  The description is discovered and no ProseField has field_name "guidance"
           (the optional field is silently absent, not an error)
    """
    yaml_path = _write_synthetic_controls_yaml(
        tmp_path,
        {"id": "controlAlpha", "title": "Alpha", "description": ["What the control is."]},
    )

    fields = list(find_prose_fields(yaml_path, _REAL_SCHEMA_DIR))

    assert any(f.field_name == "description" for f in fields), "description must still be discovered"
    assert not any(f.field_name == "guidance" for f in fields), "absent guidance must not yield a ProseField"
