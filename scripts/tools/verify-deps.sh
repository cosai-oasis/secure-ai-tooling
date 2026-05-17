#!/bin/bash
# verify-deps.sh - Verify development environment dependencies
# Checks for required tools and their versions needed for CoSAI Risk Map development

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
RESET='\033[0m'

# Parse command line flags
QUIET=false
if [[ "$1" == "--quiet" ]]; then
    QUIET=true
fi

# Failure counter
FAILURES=0

# Resolve repo root relative to this script. verify-deps.sh checks the uv
# project environment in the repository, not whichever Python happens to be
# globally active.
_script_source="${BASH_SOURCE[0]}"
if [[ "$_script_source" == */* ]]; then
    SCRIPT_DIR="$(cd "${_script_source%/*}" && pwd)"
else
    SCRIPT_DIR="$(pwd)"
fi
REPO_ROOT="${VERIFY_DEPS_REPO_ROOT:-$SCRIPT_DIR/../..}"

# Output functions
pass_msg() {
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${GREEN}[PASS]${RESET} $1"
    fi
}

fail_msg() {
    echo -e "${RED}[FAIL]${RESET} $1"
    ((FAILURES++))
}

warn_msg() {
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${YELLOW}[WARN]${RESET} $1"
    fi
}

# extract_version: extract version string from text using bash builtins only
extract_version() {
    local text="$1"
    local result=""
    local in_version=false
    local i char

    for (( i=0; i<${#text}; i++ )); do
        char="${text:$i:1}"
        if [[ "$char" =~ [0-9] ]]; then
            in_version=true
            result+="$char"
        elif [[ "$char" == "." && "$in_version" == "true" && -n "$result" ]]; then
            result+="$char"
        elif [[ "$in_version" == "true" ]]; then
            break
        fi
    done

    result="${result%.}"
    echo "$result"
}

extract_major() {
    echo "${1%%.*}"
}

extract_minor() {
    local without_major="${1#*.}"
    echo "${without_major%%.*}"
}

PROJECT_PYTHON="$REPO_ROOT/.venv/bin/python"
if [[ ! -x "$PROJECT_PYTHON" && -x "$REPO_ROOT/.venv/Scripts/python.exe" ]]; then
    PROJECT_PYTHON="$REPO_ROOT/.venv/Scripts/python.exe"
fi

# Check 1: Python >= 3.14. Prefer the uv-managed project interpreter because
# repository Python commands run through `.venv`, not whichever python3 appears
# first on PATH.
PYTHON_CHECK_CMD=""
PYTHON_CHECK_LABEL=""
if [[ -x "$PROJECT_PYTHON" ]]; then
    PYTHON_CHECK_CMD="$PROJECT_PYTHON"
    PYTHON_CHECK_LABEL="Project Python"
elif command -v python3 &>/dev/null; then
    PYTHON_CHECK_CMD="$(command -v python3)"
    PYTHON_CHECK_LABEL="Python"
fi

if [[ -n "$PYTHON_CHECK_CMD" ]]; then
    PYTHON_RAW=$("$PYTHON_CHECK_CMD" --version 2>&1)
    PYTHON_VERSION=$(extract_version "$PYTHON_RAW")
    if [[ -n "$PYTHON_VERSION" ]]; then
        PYTHON_MAJOR=$(extract_major "$PYTHON_VERSION")
        PYTHON_MINOR=$(extract_minor "$PYTHON_VERSION")
        if [[ "$PYTHON_MAJOR" -gt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -ge 14 ]]; then
            pass_msg "$PYTHON_CHECK_LABEL $PYTHON_VERSION (>= 3.14 required)"
        else
            fail_msg "$PYTHON_CHECK_LABEL $PYTHON_VERSION (>= 3.14 required)"
        fi
    else
        fail_msg "Python version detection failed"
    fi
else
    fail_msg "Project .venv Python not found at $REPO_ROOT/.venv and python3 not found"
fi

# Check 2: Node.js >= 22
if command -v node &>/dev/null; then
    NODE_RAW=$(node --version 2>&1)
    NODE_VERSION=$(extract_version "$NODE_RAW")
    if [[ -n "$NODE_VERSION" ]]; then
        NODE_MAJOR=$(extract_major "$NODE_VERSION")
        if [[ "$NODE_MAJOR" -ge 22 ]]; then
            pass_msg "Node.js $NODE_VERSION (>= 22 required)"
        else
            fail_msg "Node.js $NODE_VERSION (>= 22 required)"
        fi
    else
        fail_msg "Node.js version detection failed"
    fi
else
    fail_msg "node not found"
fi

# Check 3: npm
if command -v npm &>/dev/null; then
    pass_msg "npm found"
else
    fail_msg "npm not found"
fi

# Check 4: git
if command -v git &>/dev/null; then
    pass_msg "git found"
else
    fail_msg "git not found"
fi

# Check 5: uv
if command -v uv &>/dev/null; then
    pass_msg "uv found"
else
    fail_msg "uv not found"
fi

# Check 6: uv-managed Python packages in the project .venv
UV_PACKAGES=(
    "check-jsonschema"
    "jsonschema"
    "pre-commit"
    "pytest"
    "pytest-cov"
    "pytest-timeout"
    "PyYAML"
    "ruff"
    "pandas"
    "tabulate"
)

if command -v uv &>/dev/null && [[ -x "$PROJECT_PYTHON" ]]; then
    for package in "${UV_PACKAGES[@]}"; do
        if uv pip show --python "$PROJECT_PYTHON" "$package" &>/dev/null; then
            pass_msg "uv package: $package"
        else
            fail_msg "uv package: $package (not installed in .venv)"
        fi
    done
else
    if ! command -v uv &>/dev/null; then
        warn_msg "Skipping uv package checks because uv is not available"
    else
        fail_msg "Project .venv Python not found at $REPO_ROOT/.venv"
    fi
fi

# Check 7: npx prettier
if npx prettier --version &>/dev/null; then
    pass_msg "npx prettier found"
else
    fail_msg "npx prettier not found"
fi

# Check 8: npx mmdc (mermaid-cli)
if npx mmdc --version &>/dev/null; then
    pass_msg "npx mmdc found"
else
    fail_msg "npx mmdc not found"
fi

# Check 9: ruff through uv-managed environment
if command -v uv &>/dev/null && (cd "$REPO_ROOT" && uv run --locked --no-sync ruff version) &>/dev/null; then
    pass_msg "ruff found via uv"
else
    fail_msg "ruff not found via uv"
fi

# Check 10: check-jsonschema through uv-managed environment
if command -v uv &>/dev/null && (cd "$REPO_ROOT" && uv run --locked --no-sync check-jsonschema --version) &>/dev/null; then
    pass_msg "check-jsonschema found via uv"
else
    fail_msg "check-jsonschema not found via uv"
fi

# Check 11: Chromium
CHROMIUM_FOUND=false
CHROMIUM_PATH=""

# Check Playwright cache first
PLAYWRIGHT_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
if [[ -d "$PLAYWRIGHT_PATH" ]]; then
    # Search for headless_shell or chrome binaries
    while IFS= read -r -d '' chromium_file; do
        CHROMIUM_FOUND=true
        CHROMIUM_PATH="$chromium_file"
        break
    done < <(find "$PLAYWRIGHT_PATH" -type f \( -name "headless_shell" -o -name "chrome" \) -print0 2>/dev/null)
fi

# Check system paths if not found in Playwright cache
if [[ "$CHROMIUM_FOUND" == "false" ]]; then
    SYSTEM_PATHS=(
        "/usr/bin/chromium"
        "/usr/bin/chromium-browser"
        "/usr/bin/google-chrome"
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    )
    for path in "${SYSTEM_PATHS[@]}"; do
        if [[ -f "$path" ]]; then
            CHROMIUM_FOUND=true
            CHROMIUM_PATH="$path"
            break
        fi
    done
fi

if [[ "$CHROMIUM_FOUND" == "true" ]]; then
    pass_msg "Chromium found at $CHROMIUM_PATH"
else
    fail_msg "Chromium not found (checked Playwright cache and system paths)"
fi

# Check 12: act
if command -v act &>/dev/null || act --version &>/dev/null 2>&1; then
    pass_msg "act found"
else
    fail_msg "act not found"
fi

# Exit with appropriate code
if [[ "$FAILURES" -eq 0 ]]; then
    exit 0
else
    exit 1
fi
