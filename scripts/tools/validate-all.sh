#!/bin/bash
# =============================================================================
# validate-all.sh - Run every risk-map validator with --force
# =============================================================================
# Replacement for the prior `pre-commit.sh --force` workflow. Runs each
# validator against the full tree (regardless of git staging) without
# regenerating graphs, tables, or SVGs. Use this while iterating on content
# to catch issues before you stage for commit.
#
# Usage:
#   ./scripts/tools/validate-all.sh          # run all validators
#   ./scripts/tools/validate-all.sh --quiet  # suppress per-validator banners
#   ./scripts/tools/validate-all.sh --help   # show this help
#
# Exit codes:
#   0  All validators passed
#   1  One or more validators failed (see output for details)
#   2  Bad arguments
# =============================================================================

set -u

QUIET=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --help|-h)
            sed -n '2,19p' "$0"
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

if ! command -v uv &>/dev/null; then
    fail_msg "uv not found; run ./scripts/tools/install-deps.sh first"
    exit 1
fi

# Each validator accepts --force to run against the full tree. Output is
# routed straight to the user's terminal so error messages retain their
# original formatting. The order below matches the framework config's
# validator ordering for consistency with commit-time feedback.

banner "Schema meta-validation"
if uv run --locked --no-sync check-jsonschema --check-metaschema risk-map/schemas/*.schema.json; then
    pass_msg "Schema files are structurally valid JSON Schema"
else
    fail_msg "One or more schema files are invalid JSON Schema"
    FAILURES=$((FAILURES + 1))
fi

banner "Component edge validation"
if uv run --locked --no-sync python scripts/hooks/validate_riskmap.py --force; then
    pass_msg "Component edges"
else
    fail_msg "Component edge validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

banner "Control-to-risk reference validation"
if uv run --locked --no-sync python scripts/hooks/validate_control_risk_references.py --force; then
    pass_msg "Control-to-risk references"
else
    fail_msg "Control-to-risk reference validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

banner "Framework reference validation"
if uv run --locked --no-sync python scripts/hooks/validate_framework_references.py --force; then
    pass_msg "Framework references"
else
    fail_msg "Framework reference validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

banner "Issue template validation"
if uv run --locked --no-sync python scripts/hooks/validate_issue_templates.py --force; then
    pass_msg "Issue templates"
else
    fail_msg "Issue template validation reported errors"
    FAILURES=$((FAILURES + 1))
fi

echo
if [[ "$FAILURES" -eq 0 ]]; then
    pass_msg "All validators passed"
    exit 0
else
    fail_msg "$FAILURES validator(s) reported errors"
    exit 1
fi
