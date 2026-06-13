#!/usr/bin/env python3
"""
Shared library for ADR-027 framework-mapping composition and splitting.

Implements the core logic for D3/D3a/D4/D4a/D4b/D6/D8:
  - compose_pinned_value:    generate a pinned value from structured inputs
  - split_pinned_value:      recover (base_ref, version) from a pinned value
  - derive_mapping_id:       deterministic SHA-256 handle (non-stored, D4b)
  - load_registry:           parse frameworks.yaml into a keyed dict
  - load_pinned_patterns:    extract the framework-mapping-patterns-pinned block
  - known_versions:          recognized version set for a framework (D3a)
  - migrate_legacy_value:    map a legacy value to its pinned form (#343)
  - LEGACY_NIST_PREFIX_MAP:  GV/MS/MP/MG → GOVERN/MEASURE/MAP/MANAGE (#343)
  - LEGACY_STRIDE_KEBAB_MAP: kebab → PascalCase STRIDE enum members (#343)

The SINGLE SOURCE OF TRUTH for per-framework delimiters and controlled
vocabularies is the `framework-mapping-patterns-pinned` block in
frameworks.schema.json (D3a / D7).  No parallel delimiter dict is
maintained here; the schema is consulted directly.

The mapping-value purity validator (D4c, validate_mapping_purity.py) and the
Tier-1 drift validator (D5, validate_mapping_drift.py) import this module —
keep the public API stable.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import jsonschema
import yaml
from jsonschema import ValidationError as JSONSchemaValidationError

# ---------------------------------------------------------------------------
# Repo-relative default paths (resolved from this file's location)
# ---------------------------------------------------------------------------

# This file lives at scripts/hooks/precommit/framework_mapping.py.
# Walk up three levels to reach the repo root.
_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parent.parent.parent.parent

DEFAULT_FRAMEWORKS_PATH: Path = _REPO_ROOT / "risk-map" / "yaml" / "frameworks.yaml"
DEFAULT_SCHEMA_PATH: Path = _REPO_ROOT / "risk-map" / "schemas" / "frameworks.schema.json"

# ---------------------------------------------------------------------------
# Exception hierarchy (D4a: validation failures surface as typed errors)
# ---------------------------------------------------------------------------


class FrameworkMappingError(Exception):
    """Base exception for all framework-mapping errors."""


class UnknownFrameworkError(FrameworkMappingError):
    """Raised when the framework id is not found in the registry."""


class UnknownVersionError(FrameworkMappingError):
    """Raised when a version is not in the framework's recognized version set."""


class InvalidRefError(FrameworkMappingError):
    """
    Raised when the framework-specific ref fails schema validation.

    Covers both out-of-vocab controlled-vocabulary refs (D8) and
    malformed ID-bearing refs that don't match the spec-native pattern.
    """


# ---------------------------------------------------------------------------
# Registry and schema loading
# ---------------------------------------------------------------------------


def load_registry(frameworks_yaml_path: Path) -> dict[str, dict]:
    """
    Parse frameworks.yaml and return a dict keyed by framework id.

    Each entry keeps at minimum `version`, `priorVersions` (defaulting to
    an empty list when absent), and all other fields from the source file.

    Args:
        frameworks_yaml_path: Path to frameworks.yaml.

    Returns:
        Dict mapping framework id to its entry dict.

    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the file cannot be parsed.
        ValueError: If the file lacks a `frameworks:` array.
    """
    if not frameworks_yaml_path.is_file():
        raise FileNotFoundError(f"frameworks.yaml not found at {frameworks_yaml_path}")

    with open(frameworks_yaml_path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict) or not isinstance(data.get("frameworks"), list):
        raise ValueError(f"{frameworks_yaml_path} has no `frameworks:` array")

    registry: dict[str, dict] = {}
    for entry in data["frameworks"]:
        fw_id = entry.get("id")
        if not isinstance(fw_id, str):
            continue
        # Ensure priorVersions defaults to an empty list if absent.
        if "priorVersions" not in entry:
            entry = dict(entry)
            entry["priorVersions"] = []
        registry[fw_id] = entry

    return registry


def load_pinned_patterns(schema_path: Path) -> dict[str, dict]:
    """
    Extract the framework-mapping-patterns-pinned block from the schema.

    Returns the `properties` sub-dict keyed by framework id, i.e. the
    per-framework subschema that pinned values must validate against.

    Args:
        schema_path: Path to frameworks.schema.json.

    Returns:
        Dict mapping framework id to its JSON subschema dict.

    Raises:
        FileNotFoundError: If the schema file does not exist.
        KeyError: If the expected block is absent from the schema.
    """
    if not schema_path.is_file():
        raise FileNotFoundError(f"Schema not found at {schema_path}")

    with open(schema_path, encoding="utf-8") as fh:
        schema: dict[str, Any] = json.loads(fh.read())

    return schema["definitions"]["framework-mapping-patterns-pinned"]["properties"]


# ---------------------------------------------------------------------------
# known_versions
# ---------------------------------------------------------------------------


def known_versions(framework_id: str, registry: dict[str, dict]) -> set[str]:
    """
    Return the recognized version set for a framework (D3a).

    The set is `{current version}` ∪ `{version token of each priorVersions entry}`.
    For unversioned frameworks (version == None, e.g. STRIDE) the set is empty.

    priorVersions entries are versionIds of the form `<id>@<version>`; the
    version token is the part after the last `@`.

    Args:
        framework_id: Framework concept id.
        registry:     Registry dict from load_registry().

    Returns:
        Set of recognized version strings; empty for unversioned frameworks.

    Raises:
        UnknownFrameworkError: If framework_id is not in the registry.
    """
    if framework_id not in registry:
        raise UnknownFrameworkError(
            f"Framework {framework_id!r} not found in registry. Known frameworks: {sorted(registry.keys())}"
        )

    entry = registry[framework_id]
    version = entry.get("version")

    # Unversioned framework (D6: STRIDE carries no version token).
    if version is None:
        return set()

    versions: set[str] = {version}

    # Extract version tokens from priorVersions entries ("mitre-atlas@5.0.1" → "5.0.1").
    for prior in entry.get("priorVersions", []):
        if isinstance(prior, str) and "@" in prior:
            versions.add(prior.rsplit("@", 1)[1])

    return versions


# ---------------------------------------------------------------------------
# compose_pinned_value
# ---------------------------------------------------------------------------


def compose_pinned_value(
    framework_id: str,
    version: str | None,
    ref: str,
    *,
    registry: dict[str, dict],
    pinned_patterns: dict[str, dict],
) -> str:
    """
    Compose a pinned mapping value from structured inputs (D4a steps 1-4).

    Steps:
      1. Validate framework_id against the registry.
      2. Determine versioned-ness from the registry entry.
      3. For versioned frameworks: validate version against known_versions().
      4. Compose candidate(s) using the schema-determined delimiter (D3a/D6):
         try `@` then `:`, accept the first that validates against the schema.
         For unversioned, the candidate is the bare ref.
      5. Validate final candidate against the framework's pinned subschema.
         Raises InvalidRefError if nothing validates (out-of-vocab or malformed).

    The schema is the sole authority for both delimiter choice and controlled
    vocabulary — no parallel delimiter dict is maintained here (D3a / D7).

    Args:
        framework_id: Framework concept id from frameworks.yaml.
        version:      Version string (e.g. '5.0.1') or None for unversioned.
        ref:          Spec-native canonical reference (e.g. 'AML.T0043').
        registry:     Registry dict from load_registry().
        pinned_patterns: Pinned subschemas from load_pinned_patterns().

    Returns:
        The composed, schema-validated pinned value string.

    Raises:
        UnknownFrameworkError: If framework_id not in registry.
        UnknownVersionError:   If version not in the known version set.
        InvalidRefError:       If the ref/value fails schema validation.
    """
    # Step 1: validate framework id.
    if framework_id not in registry:
        raise UnknownFrameworkError(
            f"Framework {framework_id!r} not found in registry. Known frameworks: {sorted(registry.keys())}"
        )

    entry = registry[framework_id]
    fw_version = entry.get("version")
    is_versioned = fw_version is not None

    # Step 3: validate version for versioned frameworks.
    if is_versioned:
        recognized = known_versions(framework_id, registry)
        if version not in recognized:
            raise UnknownVersionError(
                f"Version {version!r} not recognized for framework {framework_id!r}. "
                f"Known versions: {sorted(recognized)}"
            )

    sub_schema = pinned_patterns.get(framework_id)

    # Step 4: compose candidate.
    if not is_versioned:
        # D6: warn when a caller supplies a version for an unversioned framework.
        # The return is still the bare ref — observability only; the framework
        # is version: null so no version token exists to include.
        if version is not None:
            print(
                f"warning: framework {framework_id!r} is unversioned; supplied version {version!r} ignored (D6).",
                file=sys.stderr,
            )
        candidate = ref
    else:
        # Try delimiters in order: @ first, then :.
        # The schema is the authority — the first candidate that validates wins.
        candidate = _try_delimiters(ref, version, sub_schema)
        if candidate is None:
            # Neither delimiter validated; will be caught in step 5.
            candidate = f"{ref}@{version}"

    # Step 5: final schema validation.
    if sub_schema is not None:
        try:
            jsonschema.validate(instance=candidate, schema=sub_schema)
        except JSONSchemaValidationError:
            raise InvalidRefError(
                f"Framework {framework_id!r}: ref {ref!r} (version {version!r}) "
                f"produced candidate {candidate!r} which does not validate against "
                "the pinned subschema. Check that the ref is in the correct form "
                "and the version is recognized."
            )

    return candidate


def _try_delimiters(ref: str, version: str, sub_schema: dict[str, Any] | None) -> str | None:
    """
    Try `@` then `:` delimiter; return the first candidate that validates.

    Returns None if neither candidate validates, or if sub_schema is None
    (no pinned subschema to validate against — same guard split_pinned_value
    applies; compose then returns the unvalidated default candidate, matching
    its step-5 None-sub_schema handling rather than raising TypeError on a
    framework declared in the registry but absent from the pinned block).
    This is the schema-anchored delimiter resolution (D3a / D6 / M1).
    """
    if sub_schema is None:
        return None
    for delim in ("@", ":"):
        candidate = f"{ref}{delim}{version}"
        try:
            jsonschema.validate(instance=candidate, schema=sub_schema)
            return candidate
        except JSONSchemaValidationError:
            continue
    return None


# ---------------------------------------------------------------------------
# split_pinned_value
# ---------------------------------------------------------------------------


def split_pinned_value(
    framework_id: str,
    value: str,
    *,
    registry: dict[str, dict],
    pinned_patterns: dict[str, dict],
) -> tuple[str, str | None]:
    """
    Recover (base_ref, version) from a pinned value (inverse of compose).

    For unversioned frameworks (version == None) returns (value, None).

    For versioned frameworks, splits on the last `@` or on `:` (for OWASP)
    and validates that the right side is a known version.  The correct split
    is the one whose recomposition validates against the schema (D3a / D6 / M1).

    Args:
        framework_id:    Framework concept id.
        value:           A pinned value string (e.g. 'AML.T0043@5.0.1').
        registry:        Registry dict from load_registry().
        pinned_patterns: Pinned subschemas from load_pinned_patterns().

    Returns:
        Tuple of (base_ref, version_string_or_None).

    Raises:
        UnknownFrameworkError: If framework_id not in registry.
        InvalidRefError:       If no split produces a known-version right side.
    """
    if framework_id not in registry:
        raise UnknownFrameworkError(f"Framework {framework_id!r} not found in registry.")

    entry = registry[framework_id]
    fw_version = entry.get("version")

    # Unversioned: bare ref, no token (D6 / STRIDE).
    if fw_version is None:
        return (value, None)

    recognized = known_versions(framework_id, registry)
    sub_schema = pinned_patterns.get(framework_id)

    # Try each delimiter; accept the split whose recomposition validates.
    # Trying `@` (rsplit on last) first, then `:`.
    # rsplit on `@` handles `AI Partner (data supplier)@2022` correctly because
    # the H3 invariant guarantees `@` doesn't appear in the base ref (D3a).
    for delim in ("@", ":"):
        if delim not in value:
            continue
        base_ref, ver_token = value.rsplit(delim, 1)
        if ver_token not in recognized:
            continue
        # Belt-and-suspenders: validate the recomposition against the schema.
        if sub_schema is not None:
            try:
                jsonschema.validate(instance=value, schema=sub_schema)
            except JSONSchemaValidationError:
                continue
        return (base_ref, ver_token)

    raise InvalidRefError(
        f"Framework {framework_id!r}: cannot split {value!r} into a known "
        f"(base_ref, version) pair. Recognized versions: {sorted(recognized)}"
    )


# ---------------------------------------------------------------------------
# derive_mapping_id
# ---------------------------------------------------------------------------


def derive_mapping_id(cosai_id: str, framework_id: str, pinned_value: str) -> str:
    """
    Derive a deterministic, token-safe mapping handle (D4b).

    Canonical string: `<cosai-id>|<framework-id>|<pinned-value>`.
    Returns the SHA-256 hex digest of that string encoded as UTF-8.

    The `|` separator is reserved (not present in any component) per D3a / D4b.
    The hex digest is token-safe regardless of spaces/parens/@/: in the value.
    The mappingId is NEVER written to YAML (D4b binding decision).

    Args:
        cosai_id:     CoSAI entity id (e.g. 'controlFoo').
        framework_id: Framework concept id (e.g. 'mitre-atlas').
        pinned_value: Pinned mapping value (e.g. 'AML.T0043@5.0.1').

    Returns:
        Lowercase hex SHA-256 digest string.
    """
    canonical = f"{cosai_id}|{framework_id}|{pinned_value}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Legacy migration — lookup tables and migrate_legacy_value (#343)
# ---------------------------------------------------------------------------

# NIST AI RMF legacy 2-letter prefix → canonical GOVERN/MEASURE/MAP/MANAGE.
# Sourced from the four NIST AI RMF core functions used in the live corpus.
# An unknown prefix must raise InvalidRefError (fail-loud — never silent-skip).
LEGACY_NIST_PREFIX_MAP: dict[str, str] = {
    "GV": "GOVERN",
    "MS": "MEASURE",
    "MP": "MAP",
    "MG": "MANAGE",
}

# STRIDE legacy kebab-case form → canonical PascalCase enum member.
# These are the six STRIDE threat categories used in the live corpus.
# An unknown kebab form must raise InvalidRefError (fail-loud).
LEGACY_STRIDE_KEBAB_MAP: dict[str, str] = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information-disclosure": "InformationDisclosure",
    "denial-of-service": "DenialOfService",
    "elevation-of-privilege": "ElevationOfPrivilege",
}


def migrate_legacy_value(
    framework_id: str,
    value: str,
    *,
    registry: dict[str, dict],
    pinned_patterns: dict[str, dict],
) -> tuple[str, bool]:
    """
    Map a legacy mapping value to its ADR-027 pinned form.

    Idempotency first: if value already validates against the framework's
    pinned subschema, return (value, False) unchanged. This makes a second
    migrate pass a no-op on an already-migrated corpus.

    Otherwise respell the base-ref per framework-specific rules and call
    compose_pinned_value() to produce the canonical pinned value. Never
    hand-spells the output.

    NIST AI RMF: split on the first '-'; look up the prefix in
    LEGACY_NIST_PREFIX_MAP. Raises InvalidRefError if the prefix is unknown.

    STRIDE: look up the kebab form in LEGACY_STRIDE_KEBAB_MAP. Raises
    InvalidRefError if the form is not in the map. Already-pinned PascalCase
    values are caught by the idempotency check above and never reach this path.

    All other frameworks (mitre-atlas, owasp-top10-llm, iso-22989, eu-ai-act):
    use the value as the base_ref directly (identity). compose_pinned_value()
    handles version-token appending and schema validation.

    Args:
        framework_id:    Framework concept id from frameworks.yaml.
        value:           Current (possibly legacy) mapping value.
        registry:        Registry dict from load_registry().
        pinned_patterns: Pinned subschemas from load_pinned_patterns().

    Returns:
        Tuple (pinned_value, changed) where changed is True if the value was
        rewritten, False if it was already in pinned form (idempotent).

    Raises:
        UnknownFrameworkError: If framework_id is not in the registry.
        InvalidRefError:       If the value cannot be mapped to a valid pinned form.
    """
    # Fail loud immediately for unknown frameworks — before any respell attempt.
    if framework_id not in registry:
        raise UnknownFrameworkError(
            f"Framework {framework_id!r} not found in registry. Known frameworks: {sorted(registry.keys())}"
        )

    # Idempotency check: if value already validates against the pinned subschema,
    # return unchanged. A missing/None subschema means no pinned validation exists
    # for this framework, so we treat it as "not yet pinned" and proceed.
    sub_schema = pinned_patterns.get(framework_id)
    if sub_schema is not None:
        try:
            jsonschema.validate(instance=value, schema=sub_schema)
            # Value already validates against the pinned subschema — idempotent.
            return (value, False)
        except JSONSchemaValidationError:
            pass  # Not yet pinned; fall through to respell logic.

    # Respell the base_ref per framework.
    if framework_id == "nist-ai-rmf":
        # Split on the FIRST '-' only. 'GV-6.2' → prefix='GV', rest='6.2'.
        # A value with no '-' will produce empty sep and fail the check below.
        prefix, sep, rest = value.partition("-")
        if not sep or prefix not in LEGACY_NIST_PREFIX_MAP:
            known = sorted(LEGACY_NIST_PREFIX_MAP.keys())
            raise InvalidRefError(
                f"Framework 'nist-ai-rmf': cannot respell {value!r}. "
                f"Expected '<PREFIX>-<sub-id>' where PREFIX is one of {known}; "
                f"got prefix {prefix!r}."
            )
        base_ref = f"{LEGACY_NIST_PREFIX_MAP[prefix]}-{rest}"

    elif framework_id == "stride":
        # STRIDE: kebab → PascalCase. Already-pinned PascalCase is caught above.
        if value not in LEGACY_STRIDE_KEBAB_MAP:
            known = sorted(LEGACY_STRIDE_KEBAB_MAP.keys())
            raise InvalidRefError(
                f"Framework 'stride': cannot respell {value!r}. Expected one of the known kebab forms: {known}."
            )
        base_ref = LEGACY_STRIDE_KEBAB_MAP[value]

    else:
        # All other frameworks: the value is used as-is for the base_ref.
        # compose_pinned_value() appends the version token and validates.
        base_ref = value

    # Look up the current version for this framework (None for unversioned).
    version = registry[framework_id].get("version")

    new_value = compose_pinned_value(
        framework_id,
        version,
        base_ref,
        registry=registry,
        pinned_patterns=pinned_patterns,
    )
    return (new_value, new_value != value)
