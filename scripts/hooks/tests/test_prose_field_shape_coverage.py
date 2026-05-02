#!/usr/bin/env python3
r"""
Empirical coverage probe for ``find_prose_fields()`` across YAML prose-field shapes.

Both prose linters (``validate_yaml_prose_subset`` and ``validate_prose_references``)
expose ``find_prose_fields(yaml_path, schema_dir)`` with the same documented shape.
The schema's ``utils/text`` definition is::

    {type: array, items: {oneOf: [
        {type: string},
        {type: array, items: {type: string}, minItems: 1}
    ]}}

That definition admits five item-level shapes per prose field:

    Shape 1 — null / field omitted
    Shape 2 — empty list
    Shape 3 — flat array of strings
    Shape 4 — pure nested array (every outer item is a list)
    Shape 5 — mixed strings + nested arrays at the outer level

This file is a BEHAVIORAL test: it asserts the post-Phase-2 contract of
``find_prose_fields()`` for every shape.  Tests will go RED until the SWE
lands the shared helper at ``scripts/hooks/precommit/_prose_fields.py`` plus
the ``nested_index`` field on ``ProseField``.

Phase-2 contract encoded here:
    - Pure nested arrays yield one ProseField per inner string.
    - Mixed shape yields outer strings AND inner-list strings.
    - Inner-list ProseFields carry ``nested_index = inner_idx`` and outer
      ``index = outer_idx``; flat-array and bare-string ProseFields keep
      ``nested_index = None``.
    - Top-level ``description`` keyed directly under the YAML document
      root (sibling to the entity array) yields ProseFields with
      ``entry_id = <yaml-file-stem>``.

The tests do not call ``check_prose_field`` or ``check_references``; the
coverage probe sits at the ``find_prose_fields`` boundary only.

Helpers ``_write_mock_schema`` and ``_write_yaml`` mirror the conventions in
``test_validate_yaml_prose_subset.py`` and ``test_validate_prose_references.py``
(stem-matched schema, ``$ref`` to ``riskmap.schema.json#/definitions/utils/text``,
single prose field named ``longDescription``).
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# sys.path injection — mirrors A5/A3 sibling-test pattern
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent / "precommit"))

# Deferred import: keep collection green even when one module fails to import.
try:
    import validate_prose_references as references_module  # noqa: E402
    import validate_yaml_prose_subset as subset_module  # noqa: E402

    _IMPORT_ERROR: Exception | None = None
except ImportError as _e:
    _IMPORT_ERROR = _e
    subset_module = None  # type: ignore[assignment]
    references_module = None  # type: ignore[assignment]


@pytest.fixture(autouse=True)
def _require_modules_under_test():
    """Fail every test with ImportError when either linter module is absent."""
    if _IMPORT_ERROR is not None:
        raise _IMPORT_ERROR


# ---------------------------------------------------------------------------
# Linter-module parametrisation
#
# Every shape-probe test is parametrised over both linters so test IDs make
# linter coverage obvious in pytest output (e.g. ``[subset]`` / ``[references]``).
# ---------------------------------------------------------------------------

_LINTER_PARAMS = [
    pytest.param(lambda: subset_module, id="subset"),
    pytest.param(lambda: references_module, id="references"),
]


# ---------------------------------------------------------------------------
# Fixture builders — mirror sibling helpers (_write_mock_schema, _write_yaml).
#
# We use a single prose field named ``longDescription`` on a ``risk`` entity so
# the schema's stem-name match (``risks.schema.json`` ↔ ``risks.yaml``) drives
# discovery without exercising the secondary array-key fallback.
# ---------------------------------------------------------------------------

# The single prose field exercised in this file.
_FIELD_NAME = "longDescription"


def _write_mock_schema(tmp_path: Path) -> Path:
    r"""Write a minimal ``risks.schema.json`` with one prose field.

    The schema declares ``longDescription`` as
    ``$ref: riskmap.schema.json#/definitions/utils/text`` so that
    ``find_prose_fields`` discovers it via introspection.  Stem-name matching
    (``risks.yaml`` ↔ ``risks.schema.json``) is sufficient — no copy of the
    ``utils/text`` definition is needed because both linters resolve the prose
    field by string-equality on the ``$ref`` value, not by following it.

    Args:
        tmp_path: Directory to write the schema file into.

    Returns:
        Path to the written ``risks.schema.json`` file.
    """
    prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
    schema = {
        "$id": "mock_risks.schema.json",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {"risks": {"type": "array", "items": {"$ref": "#/definitions/risk"}}},
        "definitions": {
            "risk": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    _FIELD_NAME: prose_ref,
                },
            }
        },
    }
    path = tmp_path / "risks.schema.json"
    path.write_text(json.dumps(schema))
    return path


def _write_wrapper_mock_schema(tmp_path: Path, schema_stem: str = "risks") -> Path:
    r"""Write a schema where the prose field is keyed at the document root.

    Used to exercise the file-level wrapper gap: the YAML document has a
    top-level ``description`` sibling to (and not nested inside) the entity
    array.  The schema declares ``description`` as a ``$ref`` to
    ``riskmap.schema.json#/definitions/utils/text`` directly under the root
    object's ``properties`` map.

    Args:
        tmp_path:    Directory to write the schema file into.
        schema_stem: Schema filename stem; matches the YAML file stem so
                     ``find_prose_fields``'s stem-name matching succeeds.

    Returns:
        Path to the written ``<stem>.schema.json`` file.
    """
    prose_ref = {"$ref": "riskmap.schema.json#/definitions/utils/text"}
    schema = {
        "$id": f"mock_{schema_stem}_wrapper.schema.json",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        # ``description`` keyed at root level, sibling-eligible to any entity
        # array.  No entity array is required for the wrapper-only case.
        "properties": {"description": prose_ref},
    }
    path = tmp_path / f"{schema_stem}.schema.json"
    path.write_text(json.dumps(schema))
    return path


def _build_wrapper_corpus(
    tmp_path: Path,
    description_value: object,
    *,
    yaml_stem: str = "risks",
) -> tuple[Path, Path]:
    r"""Write a wrapper schema + a YAML file with a top-level ``description``.

    Args:
        tmp_path:          Per-test temporary directory.
        description_value: Value to assign to the top-level ``description``
                           key (flat list, mixed list, etc.).
        yaml_stem:         Stem used for both the YAML file and schema file
                           so stem-name matching resolves the schema.

    Returns:
        ``(yaml_path, schema_dir)`` ready to pass to ``find_prose_fields``.
    """
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    _write_wrapper_mock_schema(schema_dir, schema_stem=yaml_stem)

    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    # Top-level ``description`` sibling to (no) entity array — the wrapper
    # gap under test.  No ``risks:`` key written.
    p = yaml_dir / f"{yaml_stem}.yaml"
    p.write_text(yaml.dump({"description": description_value}))
    return p, schema_dir


def _write_yaml(tmp_path: Path, content: dict) -> Path:
    r"""Write ``risks.yaml`` from a dict and return the path."""
    p = tmp_path / "risks.yaml"
    p.write_text(yaml.dump(content))
    return p


def _build_corpus(tmp_path: Path, field_value: object, *, omit_field: bool = False) -> tuple[Path, Path]:
    r"""Write a schema + a one-entry YAML for the requested shape.

    Args:
        tmp_path:    Per-test temporary directory.
        field_value: The value to assign to the prose field.  Ignored when
                     ``omit_field`` is True.
        omit_field:  When True, the prose field key is not written at all
                     (Shape 1 omitted-key variant).

    Returns:
        ``(yaml_path, schema_dir)`` ready to pass to ``find_prose_fields``.
    """
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    _write_mock_schema(schema_dir)

    entry: dict = {"id": "riskAlpha", "title": "Title for riskAlpha"}
    if not omit_field:
        entry[_FIELD_NAME] = field_value
    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    yaml_path = _write_yaml(yaml_dir, {"risks": [entry]})
    return yaml_path, schema_dir


# Canonical shape values exercised by the suite.  Shape 1 is split into two
# variants (omitted vs. explicit-null) and tested independently.
_SHAPE_FLAT = ["p0", "p1"]
_SHAPE_EMPTY: list = []
_SHAPE_PURE_NESTED = [["a", "b"], ["c", "d"]]
_SHAPE_MIXED = ["intro", ["a", "b"], "outro"]


# ---------------------------------------------------------------------------
# Shape 1 — missing or null field
# ---------------------------------------------------------------------------


class TestShapeMissingOrNull:
    r"""Shape 1: prose field absent or explicitly null yields zero ProseField records."""

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_missing_field_yields_zero_prose_fields(self, tmp_path, linter_factory):
        r"""
        Given: a YAML entry that omits the prose field key entirely
        When:  find_prose_fields() walks the file
        Then:  no ProseField records are yielded
        """
        linter = linter_factory()
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=None, omit_field=True)
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        assert fields == []

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_explicit_null_field_yields_zero_prose_fields(self, tmp_path, linter_factory):
        r"""
        Given: a YAML entry whose prose field is present with value ``null``
        When:  find_prose_fields() walks the file
        Then:  no ProseField records are yielded
        """
        linter = linter_factory()
        # PyYAML serialises Python ``None`` as the YAML scalar ``null``.
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=None)
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        assert fields == []


# ---------------------------------------------------------------------------
# Shape 2 — empty list
# ---------------------------------------------------------------------------


class TestShapeEmptyList:
    r"""Shape 2: prose field set to an empty list yields zero ProseField records."""

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_empty_list_yields_zero_prose_fields(self, tmp_path, linter_factory):
        r"""
        Given: a YAML entry whose prose field is an empty list ``[]``
        When:  find_prose_fields() walks the file
        Then:  no ProseField records are yielded
        """
        linter = linter_factory()
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=_SHAPE_EMPTY)
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        assert fields == []


# ---------------------------------------------------------------------------
# Shape 3 — flat array of strings
# ---------------------------------------------------------------------------


class TestShapeFlatArray:
    r"""Shape 3: a flat string list yields one ProseField per outer string."""

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_flat_array_yields_one_prose_field_per_string(self, tmp_path, linter_factory):
        r"""
        Given: a YAML entry whose prose field is ``["p0", "p1"]``
        When:  find_prose_fields() walks the file
        Then:  exactly two ProseField records are yielded
        """
        linter = linter_factory()
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=list(_SHAPE_FLAT))
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        assert len(fields) == len(_SHAPE_FLAT)

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_flat_array_indices_match_array_position(self, tmp_path, linter_factory):
        r"""
        Given: a YAML entry whose prose field is ``["p0", "p1"]``
        When:  find_prose_fields() walks the file
        Then:  the yielded ProseField indices are 0 and 1, in order, with
               raw_text matching the source strings positionally and
               ``nested_index is None`` on every record (flat-array contract).
        """
        linter = linter_factory()
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=list(_SHAPE_FLAT))
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        # Lock the (index, raw_text) pairs to the flat-array positions.
        assert [(f.index, f.raw_text) for f in fields] == [
            (0, "p0"),
            (1, "p1"),
        ]
        # Flat-array contract: no inner-list source, so nested_index is None.
        assert all(f.nested_index is None for f in fields)


# ---------------------------------------------------------------------------
# Shape 4 — pure nested array
# ---------------------------------------------------------------------------


class TestShapePureNestedArray:
    r"""Shape 4: every outer item is a list — Phase-2 yields one field per inner string."""

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_pure_nested_array_yields_one_prose_field_per_inner_string(self, tmp_path, linter_factory):
        r"""
        Given: a YAML prose field of pure nested arrays ``[["a","b"],["c","d"]]``
        When:  find_prose_fields() walks the file
        Then:  exactly four ProseField records are yielded, one per inner
               string; raw_text values are the set ``{"a","b","c","d"}``.
        """
        linter = linter_factory()
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=[list(x) for x in _SHAPE_PURE_NESTED])
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        assert len(fields) == 4
        # Order across nested lists may not be stable; compare by set membership.
        assert {f.raw_text for f in fields} == {"a", "b", "c", "d"}

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_pure_nested_array_inner_strings_yield_with_nested_index(self, tmp_path, linter_factory):
        r"""
        Given: a YAML prose field of pure nested arrays ``[["a","b"],["c","d"]]``
        When:  find_prose_fields() walks the file
        Then:  every yielded ProseField has ``nested_index is not None``; the
               (index, nested_index, raw_text) tuple set is exactly
               ``{(0,0,"a"),(0,1,"b"),(1,0,"c"),(1,1,"d")}``.
        """
        linter = linter_factory()
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=[list(x) for x in _SHAPE_PURE_NESTED])
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        # Every inner-list ProseField must carry a non-None nested_index.
        assert all(f.nested_index is not None for f in fields)
        observed = {(f.index, f.nested_index, f.raw_text) for f in fields}
        assert observed == {
            (0, 0, "a"),
            (0, 1, "b"),
            (1, 0, "c"),
            (1, 1, "d"),
        }


# ---------------------------------------------------------------------------
# Shape 5 — mixed outer strings and nested arrays
# ---------------------------------------------------------------------------


class TestShapeMixedStringAndNestedArray:
    r"""Shape 5: outer strings AND inner-list strings both yield ProseFields under Phase-2."""

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_mixed_shape_yields_outer_strings_and_inner_strings(self, tmp_path, linter_factory):
        r"""
        Given: a YAML prose field of ``["intro", ["a","b"], "outro"]``
        When:  find_prose_fields() walks the file
        Then:  exactly four ProseField records are yielded; the
               (index, nested_index, raw_text) tuple set is exactly
               ``{(0,None,"intro"),(1,0,"a"),(1,1,"b"),(2,None,"outro")}``.
        """
        linter = linter_factory()
        # Deep-copy the literal so PyYAML does not pick up shared aliases.
        mixed = ["intro", ["a", "b"], "outro"]
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=mixed)
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        assert len(fields) == 4
        observed = {(f.index, f.nested_index, f.raw_text) for f in fields}
        assert observed == {
            (0, None, "intro"),
            (1, 0, "a"),
            (1, 1, "b"),
            (2, None, "outro"),
        }

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_mixed_shape_inner_strings_carry_nested_index(self, tmp_path, linter_factory):
        r"""
        Given: a YAML prose field of ``["intro", ["a","b"], "outro"]``
        When:  find_prose_fields() walks the file
        Then:  ProseFields whose raw_text is in ``{"a","b"}`` carry a
               non-None ``nested_index``; ProseFields whose raw_text is in
               ``{"intro","outro"}`` carry ``nested_index is None``.
        """
        linter = linter_factory()
        mixed = ["intro", ["a", "b"], "outro"]
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=mixed)
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        for f in fields:
            if f.raw_text in {"a", "b"}:
                assert f.nested_index is not None, f"inner-list string {f.raw_text!r} must carry a nested_index"
            elif f.raw_text in {"intro", "outro"}:
                assert f.nested_index is None, f"outer string {f.raw_text!r} must have nested_index=None"

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_mixed_shape_outer_indices_preserved(self, tmp_path, linter_factory):
        r"""
        Given: a YAML prose field of ``["intro", ["a","b"], "outro"]``
        When:  find_prose_fields() walks the file
        Then:  the outer string at array position 2 yields a ProseField with
               ``index == 2`` and ``nested_index is None``; the nested-list
               item at array position 1 yields ProseFields with ``index == 1``
               and ``nested_index in {0,1}``.
        """
        linter = linter_factory()
        mixed = ["intro", ["a", "b"], "outro"]
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=mixed)
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))

        outro_fields = [f for f in fields if f.raw_text == "outro"]
        assert len(outro_fields) == 1
        assert outro_fields[0].index == 2
        assert outro_fields[0].nested_index is None

        nested_fields = [f for f in fields if f.raw_text in {"a", "b"}]
        assert len(nested_fields) == 2
        for f in nested_fields:
            assert f.index == 1, f"nested ProseField for {f.raw_text!r} must have index=1"
            assert f.nested_index in {0, 1}


# ---------------------------------------------------------------------------
# Over-deep nesting — schema-illegal triple-nesting probe
#
# riskmap.schema.json#/definitions/utils/text permits exactly one level of
# nested array (oneOf: [string, array<string>]).  Triple-nested input like
# ``[[["x"]]]`` is schema-illegal but reachable if a contributor edits YAML
# without running check-jsonschema.  This test pins the iteration contract:
# the helper does not recurse past depth 1, so the depth-1 item (a list) is
# silently dropped and zero ProseFields are yielded.
# ---------------------------------------------------------------------------


class TestShapeOverDeepNesting:
    r"""Defensive: triple-nested input yields nothing — schema permits only one nesting level."""

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_triple_nested_input_yields_zero_prose_fields(self, tmp_path, linter_factory):
        r"""
        Given: a schema-illegal prose field ``[[["x"]]]`` (depth-2 nesting)
        When:  find_prose_fields() walks the file
        Then:  zero ProseField records are yielded — the depth-1 item is itself
               a list (not a string), so the helper drops it without recursing
               into the depth-2 strings; no recursion path beyond the single
               nested level the schema admits.
        """
        linter = linter_factory()
        yaml_path, schema_dir = _build_corpus(tmp_path, field_value=[[["x"]]])
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        assert fields == []


# ---------------------------------------------------------------------------
# Wrapper-description gap — top-level prose keyed at the YAML document root
# ---------------------------------------------------------------------------


class TestShapeWrapperDescription:
    r"""File-level wrapper: top-level ``description`` keyed sibling to entity arrays.

    Phase-2 contract: a top-level prose field discovered at the document root
    (no enclosing entity array) yields ProseFields whose ``entry_id`` is the
    YAML file stem (e.g., ``risks.yaml`` → ``"risks"``).
    """

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_wrapper_description_flat_array_yields_one_field_per_string(self, tmp_path, linter_factory):
        r"""
        Given: a YAML file whose document root has ``description: ["a","b","c"]``
               keyed directly at the root (no entity array required), and a
               schema declaring ``description`` as ``$ref: utils/text``
        When:  find_prose_fields(yaml_path, schema_dir) runs
        Then:  three ProseFields are yielded; each has ``entry_id`` equal to
               the YAML file stem, ``field_name == "description"``,
               ``nested_index is None``, and indices ``{0, 1, 2}``.
        """
        linter = linter_factory()
        yaml_path, schema_dir = _build_wrapper_corpus(tmp_path, ["a", "b", "c"])
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        assert len(fields) == 3

        expected_entry_id = yaml_path.stem  # e.g., "risks"
        for f in fields:
            assert f.entry_id == expected_entry_id, (
                f"wrapper-description ProseField must use file-stem entry_id; "
                f"expected {expected_entry_id!r}, got {f.entry_id!r}"
            )
            assert f.field_name == "description"
            assert f.nested_index is None

        assert {f.index for f in fields} == {0, 1, 2}

    @pytest.mark.parametrize("linter_factory", _LINTER_PARAMS)
    def test_wrapper_description_mixed_shape_yields_outer_and_inner(self, tmp_path, linter_factory):
        r"""
        Given: a YAML file whose document root has
               ``description: ["intro", ["nested-a","nested-b"], "outro"]``
        When:  find_prose_fields(yaml_path, schema_dir) runs
        Then:  four ProseFields are yielded.  Each has ``entry_id`` equal to
               the YAML file stem and ``field_name == "description"``.  The
               (index, nested_index, raw_text) tuple set is exactly
               ``{(0,None,"intro"),(1,0,"nested-a"),(1,1,"nested-b"),(2,None,"outro")}``.
        """
        linter = linter_factory()
        yaml_path, schema_dir = _build_wrapper_corpus(
            tmp_path,
            ["intro", ["nested-a", "nested-b"], "outro"],
        )
        fields = list(linter.find_prose_fields(yaml_path, schema_dir))
        assert len(fields) == 4

        expected_entry_id = yaml_path.stem
        for f in fields:
            assert f.entry_id == expected_entry_id
            assert f.field_name == "description"

        observed = {(f.index, f.nested_index, f.raw_text) for f in fields}
        assert observed == {
            (0, None, "intro"),
            (1, 0, "nested-a"),
            (1, 1, "nested-b"),
            (2, None, "outro"),
        }


# ---------------------------------------------------------------------------
# Linter symmetry — both linters share find_prose_fields via shared helper
# ---------------------------------------------------------------------------


class TestLinterSymmetry:
    r"""Both linters re-export the same find_prose_fields helper from _prose_fields."""

    def test_linters_share_find_prose_fields_helper(self):
        r"""
        Given: validate_yaml_prose_subset.py and validate_prose_references.py
               both ``from ._prose_fields import find_prose_fields``
        When:  the two module-level attributes are compared by identity
        Then:  they refer to the same function object — symmetry is structural,
               not behavioral.  Any future re-duplication of the helper into
               either wrapper module would flip ``is`` to ``False`` and fail
               this test immediately.
        """
        assert subset_module.find_prose_fields is references_module.find_prose_fields
