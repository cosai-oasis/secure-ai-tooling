#!/bin/bash
# Simple git hook installer
# Copies scripts/hooks/pre-commit to .git/hooks/pre-commit
# Copies scripts/hooks/validate_riskmap.py to .git/hooks/validate_riskmap.py
# Copies scripts/hooks/riskmap_validator/* to .git/hooks/riskmap_validator/*
# Copies scripts/hooks/validate_control_risk_references.py to .git/hooks/validate_control_risk_references.py
# Usage: ./install-precommit-hook.sh [--force]

set -e

# =============================================================================
# Platform Detection and Chrome Configuration
# =============================================================================

# Detect platform for Chrome/Chromium configuration
detect_platform() {
    local os=$(uname -s)
    local arch=$(uname -m)

    case "$os" in
        Darwin*) PLATFORM="mac" ;;
        MINGW*|CYGWIN*|MSYS*) PLATFORM="windows" ;;
        Linux*)
            case "$arch" in
                aarch64|arm64) PLATFORM="linux-arm64" ;;
                *) PLATFORM="linux-x64" ;;
            esac ;;
        *) PLATFORM="unknown" ;;
    esac

    echo "🔍 Detected platform: $PLATFORM"
}

# Configure Chrome/Chromium path based on platform and user preference
configure_chromium_path() {
    local chromium_path=""

    case "$PLATFORM" in
        "mac"|"windows"|"linux-x64")
            echo ""
            echo "🌐 Chrome Configuration"
            echo "For most users, mermaid-cli can use its bundled Chrome automatically."
            echo ""
            echo "Options:"
            echo "  1) Use automatic Chrome detection (recommended)"
            echo "  2) Specify custom Chrome/Chromium path"
            echo ""
            read -p "Choose option (1-2) [1]: " chrome_choice
            chrome_choice=${chrome_choice:-1}

            case "$chrome_choice" in
                1)
                    echo "✅ Using automatic Chrome detection"
                    chromium_path=""
                    ;;
                2)
                    echo ""
                    read -p "Enter full path to Chrome/Chromium executable: " custom_path
                    if [[ -x "$custom_path" ]]; then
                        chromium_path="$custom_path"
                        echo "✅ Using custom Chrome at: $custom_path"
                    else
                        echo "⚠️  Warning: Path '$custom_path' not found or not executable"
                        echo "   Falling back to automatic detection"
                        chromium_path=""
                    fi
                    ;;
                *)
                    echo "Invalid choice. Using automatic detection."
                    chromium_path=""
                    ;;
            esac
            ;;

        "linux-arm64")
            echo ""
            echo "🚨 ARM64 Linux Detected"
            echo "Chrome/Chrome-for-testing are not available for ARM64 Linux from Google."
            echo "You need to provide an alternative Chromium installation."
            echo ""
            echo "Options:"
            echo "  1) Use Playwright's Chromium (recommended)"
            echo "  2) Use system-installed Chromium"
            echo "  3) Specify custom Chromium path"
            echo ""
            read -p "Choose option (1-3) [1]: " arm_choice
            arm_choice=${arm_choice:-1}

            case "$arm_choice" in
                1)
                    echo "📦 Checking for Playwright Chromium..."
                    if ! npx  --version &>/dev/null; then
                        echo "❌ npx not found. Please install Node.js first."
                        exit 1
                    fi

                    if ! npx playwright -V &> /dev/null and [[ "$INSTALL_PLAYWRIGHT" == "true" ]]; then
                        echo "   Playwright Chromium not found. Installing..."
                        if ! $(npx playwright install chromium --with-deps); then
                            echo "❌ Failed to install Playwright Chromium"
                            echo "   Exiting..."
                            exit 1
                        fi
                        echo "✅ Playwright Chromium installed ..."
                    fi

                    # Check if playwright chromium is already installed
                    local BROWSER_PATHS="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"

                    local CHROME_EXEC=$(find "$BROWSER_PATHS" -name "headless_shell" -type f 2>/dev/null | head -1)

                    if [ -z "$CHROME_EXEC" ]; then
                      CHROME_EXEC=$(find "$BROWSER_PATHS" -name "chrome" -type f 2>/dev/null | head -1)
                    fi

                    local playwright_path=$CHROME_EXEC

                    if [[ -n "$playwright_path" && -x "$playwright_path" ]]; then
                        chromium_path="$playwright_path"
                        echo "✅ Found existing Playwright Chromium at: $playwright_path"
                    else
                        echo "   Playwright Chromium not found."
                        echo "   Please install Playwright manually or run:"
                        echo "   $0 --install-playwright"
                        chromium_path=""
                    fi
                    ;;
                2)
                    # Try common system chromium locations
                    local system_paths=(
                        "/usr/bin/chromium"
                        "/usr/bin/chromium-browser"
                        "/snap/bin/chromium"
                        "/usr/bin/google-chrome"
                    )

                    for path in "${system_paths[@]}"; do
                        if [[ -x "$path" ]]; then
                            chromium_path="$path"
                            echo "✅ Found system Chromium at: $path"
                            break
                        fi
                    done

                    if [[ -z "$chromium_path" ]]; then
                        echo "⚠️  No system Chromium found in standard locations"
                        echo "   You may need to install chromium: sudo apt install chromium-browser"
                        chromium_path=""
                    fi
                    ;;
                3)
                    echo ""
                    read -p "Enter full path to Chromium executable: " custom_path
                    if [[ -x "$custom_path" ]]; then
                        chromium_path="$custom_path"
                        echo "✅ Using custom Chromium at: $custom_path"
                    else
                        echo "❌ Error: Path '$custom_path' not found or not executable"
                        echo "   SVG generation will likely fail without a valid Chromium path"
                        chromium_path="$custom_path"  # Keep it anyway, user might fix later
                    fi
                    ;;
                *)
                    echo "Invalid choice. Using Playwright Chromium option."
                    chromium_path=""
                    ;;
            esac
            ;;

        "unknown")
            echo "⚠️  Unknown platform. Chrome configuration may not work correctly."
            echo "   You may need to manually configure CHROMIUM_PATH in the pre-commit hook."
            chromium_path=""
            ;;
    esac

    CHROMIUM_PATH="$chromium_path"
}

# Parse command line arguments
FORCE=false
INSTALL_PLAYWRIGHT=false
PRECOMMIT_SRC="scripts/hooks/pre-commit"
VALIDATOR_SRC="scripts/hooks/validate_riskmap.py"
VALIDATOR_MODULE_SRC="scripts/hooks/riskmap_validator"
REF_VALIDATOR_SRC="scripts/hooks/validate_control_risk_references.py"

while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE=true
            shift
            ;;
        --install-playwright)
            INSTALL_PLAYWRIGHT=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--force] [--install-playwright]"
            echo "  --force, -f              Overwrite existing hooks"
            echo "  --install-playwright     Automatically install Playwright Chromium for ARM64 Linux"
            echo "  --help, -h               Show this help message"
            echo ""
            echo "This script installs:"
            echo "  - Pre-commit hook (YAML schema validation, SVG generation)"
            echo "  - Component edge validator (edge consistency validation)"
            echo "  - Control-to-risk reference validator (reference consistency validation)"
            echo ""
            echo "Chrome/Chromium configuration:"
            echo "  - On most platforms: automatic Chrome detection (recommended)"
            echo "  - On ARM64 Linux: requires manual Chromium installation or --install-playwright"
            exit 0
            ;;
        *)
            echo "❌ Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"
TARGET_HOOK="$REPO_ROOT/.git/hooks/pre-commit"
TARGET_VALIDATOR="$REPO_ROOT/.git/hooks/validate_riskmap.py"
TARGET_VALIDATOR_MODULE="$REPO_ROOT/.git/hooks/riskmap_validator"
TARGET_REF_VALIDATOR="$REPO_ROOT/.git/hooks/validate_control_risk_references.py"

echo "Installing git hooks..."

# Detect platform and configure Chromium path
detect_platform
configure_chromium_path

echo ""
echo "🔧 Chrome/Chromium configuration:"
if [[ -n "$CHROMIUM_PATH" ]]; then
    echo "   Path: $CHROMIUM_PATH"
else
    echo "   Using automatic detection"
fi

# Check if source files exist
if [[ ! -f "$REPO_ROOT/${PRECOMMIT_SRC}" ]]; then
    echo "❌ Error: ${PRECOMMIT_SRC} not found"
    exit 1
fi

if [[ ! -f "$REPO_ROOT/${VALIDATOR_SRC}" ]]; then
    echo "❌ Error: ${VALIDATOR_SRC} not found"
    exit 1
fi

if [[ ! -f "$REPO_ROOT/${REF_VALIDATOR_SRC}" ]]; then
    echo "❌ Error: ${REF_VALIDATOR_SRC} not found"
    exit 1
fi

# Check if target files already exist
EXISTING_HOOK=false
EXISTING_VALIDATOR=false
EXISTING_REF_VALIDATOR=false

if [[ -f "$TARGET_HOOK" ]]; then
    EXISTING_HOOK=true
fi

# Only tests for the main script -> assumes the module directory will exist if the script does...
if [[ -f "$TARGET_VALIDATOR" ]]; then
    EXISTING_VALIDATOR=true
fi

if [[ -f "$TARGET_REF_VALIDATOR" ]]; then
    EXISTING_REF_VALIDATOR=true
fi

if [[ ($EXISTING_HOOK == true || $EXISTING_VALIDATOR == true || $EXISTING_REF_VALIDATOR == true) && "$FORCE" != "true" ]]; then
    echo "❌ Error: One or more hooks already exist:"
    [[ $EXISTING_HOOK == true ]] && echo "   - pre-commit hook exists at $TARGET_HOOK"
    [[ $EXISTING_VALIDATOR == true ]] && echo "   - component validator exists at $TARGET_VALIDATOR"
    [[ $EXISTING_REF_VALIDATOR == true ]] && echo "   - control-to-risk reference validator exists at $TARGET_REF_VALIDATOR"
    echo ""
    echo "💡 Use --force to overwrite, or remove the existing hooks manually"
    echo "   Example: $0 --force"
    exit 1
fi

# Create .git/hooks directory if it doesn't exist
mkdir -p "$REPO_ROOT/.git/hooks"

# Install pre-commit hook
echo "📋 Installing pre-commit hook..."
cp "$REPO_ROOT/${PRECOMMIT_SRC}" "$TARGET_HOOK"

# Configure CHROMIUM_PATH in the pre-commit hook
if [[ -n "$CHROMIUM_PATH" ]]; then
    # Replace CHROMIUM_PATH=MUST_BE_SET with the actual path
    sed -i.bak "s|^CHROMIUM_PATH=.*|CHROMIUM_PATH=\"$CHROMIUM_PATH\"|" "$TARGET_HOOK"
    echo "   ✅ Set CHROMIUM_PATH to: $CHROMIUM_PATH"
else
    # Set empty path for automatic detection
    sed -i.bak "s|^CHROMIUM_PATH=.*|CHROMIUM_PATH=\"\"|" "$TARGET_HOOK"
    echo "   ✅ Configured for automatic Chrome detection"
fi

# Remove backup file created by sed
rm -f "${TARGET_HOOK}.bak"

chmod +x "$TARGET_HOOK"

# Install component edge validator
echo "🔗 Installing component edge validator..."
mkdir -p "${TARGET_VALIDATOR_MODULE}"
cp "${REPO_ROOT}/${VALIDATOR_SRC}" "${TARGET_VALIDATOR}"
cp -r ${REPO_ROOT}/${VALIDATOR_MODULE_SRC}/* "${TARGET_VALIDATOR_MODULE}/"
chmod +x "$TARGET_VALIDATOR"

# Install control-to-risk reference validator
echo "🔗 Installing control-to-risk reference validator..."
cp "$REPO_ROOT/${REF_VALIDATOR_SRC}" "$TARGET_REF_VALIDATOR"
chmod +x "$TARGET_REF_VALIDATOR"

# Success message
if [[ "$FORCE" == "true" ]]; then
    echo ""
    echo "✅ Git hooks installed successfully! (overwritten existing hooks)"
else
    echo ""
    echo "✅ Git hooks installed successfully!"
fi

echo ""
echo "📝 Installed hooks:"
echo "   - Pre-commit hook: $TARGET_HOOK"
echo "   - Edge validator: $TARGET_VALIDATOR"
echo "   - Control-to-risk validator: $TARGET_REF_VALIDATOR"
echo ""
echo "🔍 These hooks will now run automatically before each commit to validate:"
echo "   ✅ YAML schema compliance"
echo "   ✅ Component edge consistency"
echo "   ✅ Control-to-risk reference consistency"
echo "   ✅ Generate SVG files from Mermaid diagrams"
echo ""
echo "💡 To bypass hooks temporarily: git commit --no-verify"