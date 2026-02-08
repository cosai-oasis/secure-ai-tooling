#!/bin/bash
# install-deps.sh - Install development environment dependencies
# Installs required tools for CoSAI Risk Map development in dependency order.
# Idempotent: pre-checks each tool and skips if already present.
#
# Uses only bash builtins for parsing (no grep/sed/cut/tr/find) to work
# in restricted PATH environments like test stubs.

# Color codes for output (match verify-deps.sh conventions)
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
RESET='\033[0m'

# Script directory and repo root detection using bash builtins only
# ${BASH_SOURCE[0]%/*} is the bash-builtin equivalent of dirname
_script_source="${BASH_SOURCE[0]}"
if [[ "$_script_source" == */* ]]; then
    SCRIPT_DIR="$(cd "${_script_source%/*}" && pwd)"
else
    SCRIPT_DIR="$(pwd)"
fi
REPO_ROOT="${INSTALL_DEPS_REPO_ROOT:-$SCRIPT_DIR/../..}"

# Flags
QUIET=false
DRY_RUN=false

# Failure counter - no set -e, manual error checking
FAILURES=0

# Total number of install steps (for progress banners)
TOTAL_STEPS=9

# Make all mise commands non-interactive (trust, install, etc.)
# Prevents stdin hangs during container builds
export MISE_YES=1

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quiet)
            QUIET=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help)
            echo "Usage: install-deps.sh [OPTIONS]"
            echo ""
            echo "Install development environment dependencies for CoSAI Risk Map."
            echo ""
            echo "Options:"
            echo "  --quiet    Suppress non-error output ([PASS], [SKIP], [INFO])"
            echo "  --dry-run  Print what would be done without executing"
            echo "  --help     Show this help message and exit"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

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

skip_msg() {
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${GREEN}[SKIP]${RESET} $1"
    fi
}

info_msg() {
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${YELLOW}[INFO]${RESET} $1"
    fi
}

dry_run_msg() {
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${YELLOW}[DRY-RUN]${RESET} $1"
    fi
}

step_msg() {
    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "  [$1/$TOTAL_STEPS] $2"
    echo "══════════════════════════════════════════════════════════════"
}

# extract_version: extract version string from text using bash builtins only
# Extracts the first occurrence of a dotted version number (e.g., "3.14.0")
# Usage: extract_version "Python 3.14.0"
# Returns version string via stdout, empty if not found
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
            # End of version string; stop at first complete version
            break
        fi
    done
    # Remove trailing dot if present
    result="${result%.}"
    echo "$result"
}

# extract_major: get major version number from a dotted version string
# Usage: extract_major "3.14.0" -> "3"
extract_major() {
    echo "${1%%.*}"
}

# extract_minor: get minor version number from a dotted version string
# Usage: extract_minor "3.14.0" -> "14"
extract_minor() {
    local without_major="${1#*.}"
    echo "${without_major%%.*}"
}

# find_chromium_recursive: search for chrome/headless_shell in a directory tree
# Uses bash builtins only (globstar) instead of find command.
# Sets CHROMIUM_FOUND=true if found.
find_chromium_recursive() {
    local base_dir="$1"
    # Enable globstar for recursive globbing
    local prev_globstar
    prev_globstar="$(shopt -p globstar 2>/dev/null || true)"
    shopt -s globstar 2>/dev/null || true

    for f in "$base_dir"/**/*; do
        if [[ -f "$f" ]]; then
            local basename="${f##*/}"
            if [[ "$basename" == "chrome" || "$basename" == "headless_shell" ]]; then
                CHROMIUM_FOUND=true
                eval "$prev_globstar" 2>/dev/null || true
                return 0
            fi
        fi
    done

    eval "$prev_globstar" 2>/dev/null || true
    return 1
}

# strip_version_specifiers: remove version specifiers from a package line
# Handles ==, >=, <=, ~=, !=, >, < and strips whitespace using bash only
# Usage: strip_version_specifiers "PyYAML>=6.0.2" -> "PyYAML"
strip_version_specifiers() {
    local line="$1"
    # Remove everything from the first version specifier char onward
    local package="${line%%[>=<~!]*}"
    # Trim leading/trailing whitespace using bash parameter expansion
    package="${package#"${package%%[![:space:]]*}"}"
    package="${package%"${package##*[![:space:]]}"}"
    echo "$package"
}

# =============================================================================
# Step 1: mise
# =============================================================================
step_msg 1 "mise"
info_msg "Checking mise..."
if command -v mise &>/dev/null; then
    skip_msg "mise already installed"
else
    info_msg "Installing mise..."
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run_msg "Would run: curl https://mise.run | sh"
    else
        curl -fsSL https://mise.run | sh
        if [[ $? -ne 0 ]]; then
            fail_msg "mise installation failed"
        else
            # Add mise to PATH for subsequent steps
            export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"
            if command -v mise &>/dev/null; then
                pass_msg "mise installed"
            else
                fail_msg "mise installation completed but mise not found on PATH"
            fi
        fi
    fi
fi

# Add mise paths to PATH regardless (in case mise was already installed there)
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"

# Persist mise shims in ~/.bashrc so interactive shells find tools on PATH.
# Idempotent: only appends if the marker is not already present.
BASHRC="$HOME/.bashrc"
MISE_PATH_MARKER="mise/shims"
ALREADY_PRESENT=false
if [[ -f "$BASHRC" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == *"$MISE_PATH_MARKER"* ]]; then
            ALREADY_PRESENT=true
            break
        fi
    done < "$BASHRC"
fi

if [[ "$ALREADY_PRESENT" == "false" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run_msg "Would append mise shims PATH to $BASHRC"
    else
        echo '' >> "$BASHRC"
        echo '# mise shims PATH (added by install-deps.sh)' >> "$BASHRC"
        echo 'export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"' >> "$BASHRC"
        pass_msg "mise shims PATH persisted in $BASHRC"
    fi
else
    skip_msg "mise shims PATH already in $BASHRC"
fi

# Trust .mise.toml so mise reads tool versions from config
MISE_CONFIG="$REPO_ROOT/.mise.toml"
if command -v mise &>/dev/null && [[ -f "$MISE_CONFIG" ]]; then
    info_msg "Trusting $MISE_CONFIG..."
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run_msg "Would run: mise trust $MISE_CONFIG"
    else
        mise trust "$MISE_CONFIG"
        if [[ $? -ne 0 ]]; then
            fail_msg "mise trust $MISE_CONFIG failed"
        else
            pass_msg ".mise.toml trusted"
        fi
    fi
elif command -v mise &>/dev/null && [[ ! -f "$MISE_CONFIG" ]]; then
    info_msg ".mise.toml not found at $MISE_CONFIG, skipping mise trust"
fi

# Install all tools declared in .mise.toml (ensures tools are activated, not just installed)
if command -v mise &>/dev/null && [[ -f "$MISE_CONFIG" ]]; then
    info_msg "Installing tools from .mise.toml..."
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run_msg "Would run: mise install"
    else
        mise install
        if [[ $? -ne 0 ]]; then
            fail_msg "mise install (from .mise.toml) failed"
        else
            pass_msg "Tools installed from .mise.toml"
            mise reshim 2>/dev/null || true
        fi
    fi
fi

# =============================================================================
# Step 2: Python >= 3.14
# =============================================================================
step_msg 2 "Python"
info_msg "Checking Python..."
PYTHON_INSTALLED=false
if command -v python3 &>/dev/null; then
    PYTHON_RAW=$(python3 --version 2>&1)
    PYTHON_VERSION=$(extract_version "$PYTHON_RAW")
    if [[ -n "$PYTHON_VERSION" ]]; then
        PYTHON_MAJOR=$(extract_major "$PYTHON_VERSION")
        PYTHON_MINOR=$(extract_minor "$PYTHON_VERSION")
        if [[ "$PYTHON_MAJOR" -gt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -ge 14 ]]; then
            skip_msg "Python $PYTHON_VERSION already installed (>= 3.14)"
            PYTHON_INSTALLED=true
        fi
    fi
fi

if [[ "$PYTHON_INSTALLED" == "false" ]]; then
    if command -v mise &>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            dry_run_msg "Would run: mise install python@3.14"
        else
            mise install python@3.14
            if [[ $? -ne 0 ]]; then
                fail_msg "Python 3.14 installation via mise failed"
            else
                pass_msg "Python 3.14 installed via mise"
            fi
        fi
    else
        fail_msg "Cannot install Python 3.14: mise is not available"
    fi
fi

# =============================================================================
# Step 3: Node.js >= 22
# =============================================================================
step_msg 3 "Node.js"
info_msg "Checking Node.js..."
NODE_INSTALLED=false
if command -v node &>/dev/null; then
    NODE_RAW=$(node --version 2>&1)
    NODE_VERSION=$(extract_version "$NODE_RAW")
    if [[ -n "$NODE_VERSION" ]]; then
        NODE_MAJOR=$(extract_major "$NODE_VERSION")
        if [[ "$NODE_MAJOR" -ge 22 ]]; then
            skip_msg "Node.js $NODE_VERSION already installed (>= 22)"
            NODE_INSTALLED=true
        fi
    fi
fi

if [[ "$NODE_INSTALLED" == "false" ]]; then
    if command -v mise &>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            dry_run_msg "Would run: mise install node@22"
        else
            mise install node@22
            if [[ $? -ne 0 ]]; then
                fail_msg "Node.js 22 installation via mise failed"
            else
                pass_msg "Node.js 22 installed via mise"
            fi
        fi
    else
        fail_msg "Cannot install Node.js 22: mise is not available"
    fi
fi

# =============================================================================
# Step 4: pip packages
# =============================================================================
step_msg 4 "pip packages"
info_msg "Checking pip packages..."
PIP_NEEDS_INSTALL=false

if command -v python3 &>/dev/null && [[ -f "$REPO_ROOT/requirements.txt" ]]; then
    # Check if any package from requirements.txt is missing
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip version specifiers and whitespace using bash builtins
        package=$(strip_version_specifiers "$line")
        # Skip empty lines and comments
        if [[ -z "$package" || "$package" == \#* ]]; then
            continue
        fi
        if ! python3 -m pip show "$package" &>/dev/null; then
            PIP_NEEDS_INSTALL=true
            break
        fi
    done < "$REPO_ROOT/requirements.txt"

    if [[ "$PIP_NEEDS_INSTALL" == "true" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            dry_run_msg "Would run: pip install -r $REPO_ROOT/requirements.txt"
        else
            python3 -m pip install --no-input -r "$REPO_ROOT/requirements.txt" < /dev/null
            if [[ $? -ne 0 ]]; then
                fail_msg "pip install -r requirements.txt failed"
            else
                pass_msg "pip packages installed"
                # Regenerate mise shims so pip-installed binaries (ruff, check-jsonschema) are available
                if command -v mise &>/dev/null; then
                    mise reshim 2>/dev/null || true
                fi
            fi
        fi
    else
        skip_msg "pip packages already installed"
    fi
else
    if ! command -v python3 &>/dev/null; then
        fail_msg "Cannot install pip packages: python3 not available"
    elif [[ ! -f "$REPO_ROOT/requirements.txt" ]]; then
        fail_msg "Cannot install pip packages: requirements.txt not found at $REPO_ROOT/requirements.txt"
    fi
fi

# =============================================================================
# Step 5: npm packages
# =============================================================================
step_msg 5 "npm packages"
info_msg "Checking npm packages..."
NPM_NEEDS_INSTALL=false

if command -v npm &>/dev/null && [[ -f "$REPO_ROOT/package.json" ]]; then
    # Check if npm packages are installed by running npm ls
    if ! npm ls --prefix "$REPO_ROOT" &>/dev/null 2>&1; then
        NPM_NEEDS_INSTALL=true
    fi

    if [[ "$NPM_NEEDS_INSTALL" == "true" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            dry_run_msg "Would run: npm install (in $REPO_ROOT)"
        else
            cd "$REPO_ROOT" && npm install --no-audit --no-fund < /dev/null
            if [[ $? -ne 0 ]]; then
                fail_msg "npm install failed"
            else
                pass_msg "npm packages installed"
            fi
        fi
    else
        skip_msg "npm packages already installed"
    fi
else
    if ! command -v npm &>/dev/null; then
        fail_msg "Cannot install npm packages: npm not available"
    elif [[ ! -f "$REPO_ROOT/package.json" ]]; then
        fail_msg "Cannot install npm packages: package.json not found at $REPO_ROOT/package.json"
    fi
fi

# =============================================================================
# Step 6: act
# =============================================================================
step_msg 6 "act"
info_msg "Checking act..."
if command -v act &>/dev/null; then
    skip_msg "act already installed"
else
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run_msg "Would run: curl nektos/act install script"
    else
        curl -fsSL https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo -n bash -s -- -b /usr/local/bin
        if [[ $? -ne 0 ]]; then
            fail_msg "act installation failed"
        else
            if command -v act &>/dev/null; then
                pass_msg "act installed"
            else
                fail_msg "act installation completed but act not found on PATH"
            fi
        fi
    fi
fi

# =============================================================================
# Step 7: Playwright Chromium
# =============================================================================
step_msg 7 "Playwright Chromium"
info_msg "Checking Playwright Chromium..."
PLAYWRIGHT_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
CHROMIUM_FOUND=false

if [[ -d "$PLAYWRIGHT_PATH" ]]; then
    # Search for chrome or headless_shell binaries using bash globstar
    find_chromium_recursive "$PLAYWRIGHT_PATH"
fi

if [[ "$CHROMIUM_FOUND" == "true" ]]; then
    skip_msg "Playwright Chromium already installed"
else
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run_msg "Would run: npx playwright install chromium"
    else
        npx playwright install chromium < /dev/null
        if [[ $? -ne 0 ]]; then
            fail_msg "Playwright Chromium installation failed"
        else
            pass_msg "Playwright Chromium installed"
        fi
    fi
fi

# =============================================================================
# Step 8: Pre-commit hooks
# =============================================================================
step_msg 8 "Pre-commit hooks"
info_msg "Installing pre-commit hooks..."
PRECOMMIT_SCRIPT="$REPO_ROOT/scripts/install-precommit-hook.sh"

# install-precommit-hook.sh uses 'git rev-parse --show-toplevel' which fails
# in devcontainers where the workspace is mounted with different ownership.
# Mark the repo as safe so git commands work for the current user.
if command -v git &>/dev/null; then
    RESOLVED_ROOT="$(cd "$REPO_ROOT" && pwd -P)"
    git config --global --add safe.directory "$RESOLVED_ROOT" 2>/dev/null || true
fi

if [[ -x "$PRECOMMIT_SCRIPT" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run_msg "Would run: $PRECOMMIT_SCRIPT --force --auto --install-playwright"
    else
        bash "$PRECOMMIT_SCRIPT" --force --auto --install-playwright
        if [[ $? -ne 0 ]]; then
            fail_msg "Pre-commit hook installation failed"
        else
            pass_msg "Pre-commit hooks installed"
        fi
    fi
else
    fail_msg "install-precommit-hook.sh not found or not executable at $PRECOMMIT_SCRIPT"
fi

# =============================================================================
# Step 9: Verification
# =============================================================================
step_msg 9 "Verification"
if [[ "$DRY_RUN" == "true" ]]; then
    info_msg "Skipping verification in dry-run mode"
else
    info_msg "Running verification..."
    VERIFY_SCRIPT="$REPO_ROOT/scripts/tools/verify-deps.sh"
    if [[ -x "$VERIFY_SCRIPT" ]]; then
        "$VERIFY_SCRIPT"
        VERIFY_EXIT=$?
        if [[ $VERIFY_EXIT -ne 0 ]]; then
            fail_msg "Verification failed (verify-deps.sh exited with $VERIFY_EXIT)"
        else
            pass_msg "Verification passed"
        fi
    else
        fail_msg "verify-deps.sh not found or not executable at $VERIFY_SCRIPT"
    fi
fi

# =============================================================================
# Final exit
# =============================================================================
if [[ "$FAILURES" -eq 0 ]]; then
    info_msg "All dependencies installed successfully"
    exit 0
else
    info_msg "$FAILURES failure(s) detected"
    exit 1
fi
