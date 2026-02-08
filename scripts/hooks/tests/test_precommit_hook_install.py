#!/usr/bin/env python3
"""
Tests for install-precommit-hook.sh --auto flag.

Static analysis tests that read the script source and validate that the
--auto flag is properly implemented to skip interactive prompts during
non-interactive execution (e.g., devcontainer onCreateCommand).

Test Coverage:
==============
Total Test Classes: 3
Total Test Methods: 6

Group 1 -- Auto Flag Existence (1 class, 2 methods):
1. TestAutoFlagExists - Script accepts --auto in argument parsing

Group 2 -- Auto Mode Prompt Skipping (1 class, 2 methods):
2. TestAutoModeSkipsInteractivePrompts - AUTO_MODE check before read prompts

Group 3 -- Auto Mode Defaults (1 class, 2 methods):
3. TestAutoModeDefaults - Sensible defaults for non-interactive execution
"""

from pathlib import Path

# Path to the script under test
REPO_ROOT = Path(__file__).parent.parent.parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "install-precommit-hook.sh"


class TestAutoFlagExists:
    """
    Test that install-precommit-hook.sh accepts the --auto flag.

    The --auto flag enables non-interactive execution by skipping
    all read prompts and using sensible defaults.
    """

    def test_script_accepts_auto_flag(self):
        """
        Script source contains --auto in argument parsing case statement.

        Given: The install-precommit-hook.sh source code
        When: Examining the argument parsing block
        Then: --auto appears as a case pattern
        """
        content = SCRIPT_PATH.read_text()
        assert "--auto)" in content or "--auto )" in content, (
            "Script should contain '--auto)' in argument parsing case statement."
        )

    def test_auto_flag_sets_auto_mode(self):
        """
        Script sets AUTO_MODE=true when --auto is passed.

        Given: The install-precommit-hook.sh source code
        When: Examining the --auto handler
        Then: AUTO_MODE=true is set
        """
        content = SCRIPT_PATH.read_text()
        assert "AUTO_MODE=true" in content, (
            "Script should set AUTO_MODE=true when --auto flag is passed."
        )


class TestAutoModeSkipsInteractivePrompts:
    """
    Test that AUTO_MODE bypasses interactive read prompts.

    In the configure_chromium_path function, AUTO_MODE should be checked
    before any read -p calls to prevent stdin hangs.
    """

    def test_auto_mode_skips_read_on_mac_x64(self):
        """
        In the mac/windows/linux-x64 branch, AUTO_MODE check appears before read.

        Given: The install-precommit-hook.sh source code
        When: Examining the configure_chromium_path mac/x64 branch
        Then: AUTO_MODE check appears in that branch
        """
        content = SCRIPT_PATH.read_text()
        # Find the mac/windows/linux-x64 case block
        # Look for AUTO_MODE in the context of the non-arm64 platform handling
        lines = content.splitlines()
        in_mac_block = False
        found_auto_check = False
        for line in lines:
            stripped = line.strip()
            if '"mac"|"windows"|"linux-x64")' in stripped:
                in_mac_block = True
                found_auto_check = False
                continue
            if in_mac_block:
                if "AUTO_MODE" in stripped:
                    found_auto_check = True
                if stripped.startswith(";;"):
                    break
        assert found_auto_check, (
            "The mac/windows/linux-x64 branch should check AUTO_MODE "
            "before any interactive prompt."
        )

    def test_auto_mode_skips_read_on_arm64(self):
        """
        In the linux-arm64 branch, AUTO_MODE check appears before read.

        Given: The install-precommit-hook.sh source code
        When: Examining the configure_chromium_path arm64 branch
        Then: AUTO_MODE check appears in that branch
        """
        content = SCRIPT_PATH.read_text()
        lines = content.splitlines()
        in_arm_block = False
        found_auto_check = False
        for line in lines:
            stripped = line.strip()
            if '"linux-arm64")' in stripped:
                in_arm_block = True
                found_auto_check = False
                continue
            if in_arm_block:
                if "AUTO_MODE" in stripped:
                    found_auto_check = True
                # End of case block
                if stripped.startswith(";;"):
                    break
        assert found_auto_check, (
            "The linux-arm64 branch should check AUTO_MODE "
            "before any interactive prompt."
        )


class TestAutoModeDefaults:
    """
    Test that auto mode uses sensible defaults for each platform.

    - mac/windows/linux-x64: empty chromium_path (auto-detection)
    - linux-arm64: uses Playwright Chromium finder
    """

    def test_auto_mode_uses_auto_detection_on_non_arm(self):
        """
        For mac/x64, auto mode sets empty chromium_path (auto-detection).

        Given: The install-precommit-hook.sh source code
        When: Examining the mac/x64 AUTO_MODE block
        Then: chromium_path is set to empty string (auto-detection)
        """
        content = SCRIPT_PATH.read_text()
        lines = content.splitlines()
        in_mac_block = False
        in_auto_block = False
        found_empty_path = False
        for line in lines:
            stripped = line.strip()
            if '"mac"|"windows"|"linux-x64")' in stripped:
                in_mac_block = True
                continue
            if in_mac_block:
                if "AUTO_MODE" in stripped and "true" in stripped:
                    in_auto_block = True
                    continue
                if in_auto_block:
                    if 'chromium_path=""' in stripped:
                        found_empty_path = True
                        break
                    # Stop if we hit else/fi/;; without finding it
                    if stripped in ("else", "fi", ";;"):
                        break
                if stripped.startswith(";;"):
                    break
        assert found_empty_path, (
            "In auto mode for mac/x64, chromium_path should be set to empty "
            "string for automatic Chrome detection."
        )

    def test_auto_mode_uses_playwright_on_arm64(self):
        """
        For ARM64, auto mode uses the Playwright Chromium finder.

        Given: The install-precommit-hook.sh source code
        When: Examining the linux-arm64 AUTO_MODE block
        Then: The block references Playwright browser path or CHROMIUM_PATH
        """
        content = SCRIPT_PATH.read_text()
        lines = content.splitlines()
        in_arm_block = False
        in_auto_block = False
        found_playwright_ref = False
        for line in lines:
            stripped = line.strip()
            if '"linux-arm64")' in stripped:
                in_arm_block = True
                continue
            if in_arm_block:
                if "AUTO_MODE" in stripped and "true" in stripped:
                    in_auto_block = True
                    continue
                if in_auto_block:
                    if "playwright" in stripped.lower() or "PLAYWRIGHT" in stripped:
                        found_playwright_ref = True
                        break
                    # Stop if we hit else/fi/;; without finding it
                    if stripped in ("else", "fi", ";;"):
                        break
                if stripped.startswith(";;"):
                    break
        assert found_playwright_ref, (
            "In auto mode for ARM64, the block should reference Playwright "
            "for Chromium detection."
        )


"""
Test Summary
============
Total Test Classes: 3
Total Test Methods: 6

Group 1 -- Auto Flag Existence (1 class, 2 methods):
- TestAutoFlagExists (2): --auto in case statement, AUTO_MODE=true set

Group 2 -- Auto Mode Prompt Skipping (1 class, 2 methods):
- TestAutoModeSkipsInteractivePrompts (2): AUTO_MODE check in mac/x64, ARM64

Group 3 -- Auto Mode Defaults (1 class, 2 methods):
- TestAutoModeDefaults (2): empty path on mac/x64, Playwright on ARM64
"""
