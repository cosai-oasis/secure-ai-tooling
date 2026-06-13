#!/bin/bash
# =============================================================================
# validate-all.sh - Run every risk-map validator with --force
# =============================================================================
# Replacement for the prior `pre-commit.sh --force` workflow. Runs each
# validator against the full tree (regardless of git staging) and, by
# default, does not regenerate graphs, tables, or SVGs. Use this while
# iterating on content to catch issues before you stage for commit.
#
# Usage:
#   ./scripts/tools/validate-all.sh                    # run all validators
#   ./scripts/tools/validate-all.sh --quiet            # suppress per-validator banners
#   ./scripts/tools/validate-all.sh --check-generation # also verify generated tables
#   ./scripts/tools/validate-all.sh --help             # show this help
#
# --check-generation regenerates tables into a temporary directory and compares
# them with risk-map/tables. It does not write tracked files or change the git
# index. The temporary directory is cleaned up on success, failure, INT, and TERM.
#
# Exit codes:
#   0  All validators passed
#   1  One or more validators failed (see output for details)
#   2  Bad arguments
# =============================================================================

# set -u catches unset variables; we deliberately do not set -e because each
# validator must run even if a prior one fails (failures are counted, not
# fatal). Any new statement added to check_generated_tables that can return
# non-zero must therefore be explicitly checked (e.g. wrapped in `if !`).
set -u

QUIET=false
CHECK_GENERATION=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --check-generation)
            CHECK_GENERATION=true
            shift
            ;;
        --help|-h)
            sed -n '2,23p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "See --help for usage." >&2
            exit 2
            ;;
    esac
done

# Resolve repo root from this script's location so the command works from
# any cwd. This script lives at scripts/tools/validate-all.sh so the repo
# root is two parents up.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
cd "$REPO_ROOT"

# ANSI colors (match install-deps.sh / verify-deps.sh conventions)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    RESET='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; RESET=''
fi

banner() {
    if [[ "$QUIET" != "true" ]]; then
        echo -e "${YELLOW}─── $1 ───${RESET}"
    fi
}

pass_msg() { echo -e "${GREEN}[PASS]${RESET} $1"; }
fail_msg() { echo -e "${RED}[FAIL]${RESET} $1"; }

FAILURES=0
GEN_TMPDIR=""

cleanup_generation_tmp() {
    if [[ -n "${GEN_TMPDIR:-}" && -d "$GEN_TMPDIR" ]]; then
        rm -rf "$GEN_TMPDIR"
    fi
}

handle_generation_signal() {
    # exit 130 re-fires the EXIT trap, which runs cleanup_generation_tmp a
    # second time; the `-d "$GEN_TMPDIR"` guard in that function makes the
    # second call a no-op, so net behavior is one cleanup.
    cleanup_generation_tmp
    trap - INT TERM
    exit 130
}

check_generated_tables() {
    # Without this guard an empty GEN_TMPDIR turns "$GEN_TMPDIR/tables"
    # into "/tables", writing outside the repo.
    if ! GEN_TMPDIR="$(mktemp -d)"; then
        fail_msg "Could not create temporary directory for generation check"
        return 1
    fi
    # check_generated_tables owns the EXIT trap for the remainder of the
    # script. The function is the last validator invoked, so this is safe;
    # any future code added after the CHECK_GENERATION block needs to either
    # chain into this trap or move it out of the function.
    trap cleanup_generation_tmp EXIT
    trap handle_generation_signal INT TERM

    local generated_table_dir="$GEN_TMPDIR/tables"
    local drift_report="$GEN_TMPDIR/table-drift.txt"

    mkdir -p "$generated_table_dir"

    if ! python3 scripts/hooks/yaml_to_markdown.py --all --all-formats --output-dir "$generated_table_dir" --quiet; then
        fail_msg "Markdown table generation check failed"
        return 1
    fi

    if ! diff -r -q risk-map/tables "$generated_table_dir" > "$drift_report"; then
        fail_msg "Generated markdown tables are out of sync"
        echo "Table drift detected:" >&2
        cat "$drift_report" >&2
        return 1
    fi

    pass_msg "Generated markdown tables match risk-map/tables"
    return 0
}

# Each validator accepts --force to run against the full tree. Output is
# routed straight to the user's terminal so error messages retain their
# original formatting. The order below matches the framework config's
# validator ordering for consistency with commit-time feedback.

banner "Schema meta-validation"
if check-jsonschema --check-metaschema risk-map/schemas/*.schema.json; then
    pass_msg "Schema files are structurally valid JSON Schema"
else
    fail_msg "One or more schema files are invalid JSON Schema"
    FAILURES=$((FAILURES + 1))
fi

# Content schema validation — validate each consumer YAML against its schema,
# mirroring the per-file `schema: <X>.yaml` check-jsonschema hooks in
# .pre-commit-config.yaml (same --schemafile / --base-uri invocation). The
# meta-validation above only checks that the schema FILES are valid JSON Schema;
# it never validates the content. Post-#343 the strict consumer schemas make
# framework-mapping pinning mandatory, so this is where the full-tree sweep
# enforces the same mandatory-pin gate as pre-commit and CI. Without it the sweep
# gives a false all-clear on an unpinned value. One explicit block per consumer
# (matching this script's unrolled per-validator style) so the conformance is
# greppable and a dropped file cannot hide behind a loop variable.
banner "Content schema validation"
if check-jsonschema --schemafile risk-map/schemas/risks.schema.json \
    --base-uri file://./risk-map/schemas/ risk-map/yaml/risks.yaml; then
    pass_msg "Content schema: risks.yaml"
else
    fail_msg "Content schema validation failed for risks.yaml"
    FAILURES=$((FAILURES + 1))
fi

if check-jsonschema --schemafile risk-map/schemas/controls.schema.json \
    --base-uri file://./risk-map/schemas/ risk-map/yaml/controls.yaml; then
    pass_msg "Content schema: controls.yaml"
else
    fail_msg "Content schema validation failed for controls.yaml"
    FAILURES=$((FAILURES + 1))
fi

if check-jsonschema --schemafile risk-map/schemas/components.schema.json \
    --base-uri file://./risk-map/schemas/ risk-map/yaml/components.yaml; then
    pass_msg "Content schema: components.yaml"
else
    fail_msg "Content schema validation failed for components.yaml"
    FAILURES=$((FAILURES + 1))
fi

if check-jsonschema --schemafile risk-map/schemas/personas.schema.json \
    --base-uri file://./risk-map/schemas/ risk-map/yaml/personas.yaml; then
    pass_msg "Content schema: personas.yaml"
else
    fail_msg "Content schema validation failed for personas.yaml"
    FAILURES=$((FAILURES + 1))
fi

banner "Component edge validation"
if python3 scripts/hooks/validate_riskmap.py --force; then
    pass_msg "Component edges"
else
    fail_msg "Component edge validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

banner "Control-to-risk reference validation"
if python3 scripts/hooks/validate_control_risk_references.py --force; then
    pass_msg "Control-to-risk references"
else
    fail_msg "Control-to-risk reference validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

banner "Framework reference validation"
if python3 scripts/hooks/validate_framework_references.py --force; then
    pass_msg "Framework references"
else
    fail_msg "Framework reference validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

banner "Issue template validation"
if python3 scripts/hooks/validate_issue_templates.py --force; then
    pass_msg "Issue templates"
else
    fail_msg "Issue template validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

# ADR-027 framework-mapping validators (D2b/D4c/D5). The pre-commit hooks run
# these on staged files; the full-tree sweep invokes them with explicit paths
# so the same conformance is checked regardless of git staging. versionId
# purity reads frameworks.yaml; mapping purity and drift read the four
# consumer YAMLs.
banner "Framework versionId purity validation"
if python3 scripts/hooks/precommit/validate_versionid_purity.py --path risk-map/yaml/frameworks.yaml; then
    pass_msg "Framework versionId purity"
else
    fail_msg "Framework versionId purity validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

banner "Framework mapping-value purity validation"
if python3 scripts/hooks/precommit/validate_mapping_purity.py \
    risk-map/yaml/risks.yaml \
    risk-map/yaml/controls.yaml \
    risk-map/yaml/components.yaml \
    risk-map/yaml/personas.yaml; then
    pass_msg "Framework mapping-value purity"
else
    fail_msg "Framework mapping-value purity validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

banner "Framework mapping-value drift validation"
if python3 scripts/hooks/precommit/validate_mapping_drift.py \
    risk-map/yaml/risks.yaml \
    risk-map/yaml/controls.yaml \
    risk-map/yaml/components.yaml \
    risk-map/yaml/personas.yaml; then
    pass_msg "Framework mapping-value drift"
else
    fail_msg "Framework mapping-value drift validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

if [[ "$CHECK_GENERATION" == "true" ]]; then
    banner "Generated table parity"
    if ! check_generated_tables; then
        FAILURES=$((FAILURES + 1))
    fi
fi

echo
if [[ "$FAILURES" -eq 0 ]]; then
    pass_msg "All validators passed"
    exit 0
else
    fail_msg "$FAILURES validator(s) reported errors"
    exit 1
fi
