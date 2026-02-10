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

# Check 1: Python >= 3.14
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [[ -n "$PYTHON_VERSION" ]]; then
        PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
        PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
        if [[ "$PYTHON_MAJOR" -gt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -ge 14 ]]; then
            pass_msg "Python $PYTHON_VERSION (>= 3.14 required)"
        else
            fail_msg "Python $PYTHON_VERSION (>= 3.14 required)"
        fi
    else
        fail_msg "Python version detection failed"
    fi
else
    fail_msg "python3 not found"
fi

# Check 2: Node.js >= 22
if command -v node &>/dev/null; then
    NODE_VERSION=$(node --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [[ -n "$NODE_VERSION" ]]; then
        NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
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

# Check 5: pip packages (all 8 from requirements.txt)
PIP_PACKAGES=("check-jsonschema" "pytest" "pytest-cov" "pytest-timeout" "PyYAML" "ruff" "pandas" "tabulate")
for package in "${PIP_PACKAGES[@]}"; do
    if python3 -m pip show "$package" &>/dev/null; then
        pass_msg "pip package: $package"
    else
        fail_msg "pip package: $package (not installed)"
    fi
done

# Check 6: npx prettier
if npx prettier --version &>/dev/null; then
    pass_msg "npx prettier found"
else
    fail_msg "npx prettier not found"
fi

# Check 7: npx mmdc (mermaid-cli)
if npx mmdc --version &>/dev/null; then
    pass_msg "npx mmdc found"
else
    fail_msg "npx mmdc not found"
fi

# Check 8: ruff command-line
if command -v ruff &>/dev/null || ruff version &>/dev/null 2>&1; then
    pass_msg "ruff found"
else
    fail_msg "ruff not found"
fi

# Check 9: check-jsonschema command-line
if command -v check-jsonschema &>/dev/null; then
    pass_msg "check-jsonschema found"
else
    fail_msg "check-jsonschema not found"
fi

# Check 10: Chromium
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

# Check 11: act
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
