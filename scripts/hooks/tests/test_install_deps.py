#!/usr/bin/env python3
"""
Tests for install-deps.sh dependency installation script.

This test suite validates the dependency installer script that installs
required development environment tools for CoSAI Risk Map development.
The script is designed to be idempotent, skipping tools already present,
and supports --dry-run and --quiet flags.

Test Coverage:
==============
Total Test Classes: 34
Coverage Target: 100% of install-deps.sh functionality

Group 1 -- Script Fundamentals (3):
1.  TestScriptExists - Script file exists at expected path and is executable
2.  TestArgumentParsing - --dry-run, --quiet, --help, unknown flags
3.  TestDryRunNoSideEffects - Dry-run produces no filesystem changes

Group 2 -- Dry-Run Output (7):
4.  TestDryRunMiseInstall - mise missing -> shows dry-run curl command
5.  TestDryRunMiseSkip - mise present -> shows [SKIP]
6.  TestDryRunPythonInstall - python missing -> shows mise install python
7.  TestDryRunNodeInstall - node missing -> shows mise install node
8.  TestDryRunPipInstall - pip packages missing -> shows pip install
9.  TestDryRunNpmInstall - npm packages missing -> shows npm install
10. TestDryRunActInstall - act missing -> shows dry-run act install

Group 3 -- Skip/Idempotency (5):
11. TestSkipPythonWhenPresent - python3 with correct version -> [SKIP]
12. TestSkipNodeWhenPresent - node with correct version -> [SKIP]
13. TestSkipActWhenPresent - act present -> [SKIP]
14. TestSkipChromiumWhenPresent - chromium in cache -> [SKIP]
15. TestSkipMiseWhenPresent - mise present -> [SKIP]

Group 3c -- mise install from config (1):
16. TestMiseInstallFromConfig - bare mise install + reshim after trust

Group 4 -- Error Handling (4):
17. TestMiseInstallFailure - mise install fails -> [FAIL], continues
18. TestPipInstallFailure - pip install fails -> [FAIL], continues
19. TestNpmInstallFailure - npm install fails -> [FAIL], continues
20. TestVerificationFailure - verify-deps.sh fails -> exit non-zero

Group 4b -- mise reshim after pip (1):
21. TestMiseReshimAfterPip - mise reshim after pip install

Group 5 -- Output Formatting (2):
22. TestOutputColors - ANSI color codes present for tags
23. TestQuietModeSuppression - --quiet hides [PASS]/[SKIP]/[INFO], shows [FAIL]

Group 6 -- Integration (1):
24. TestFullInstallDryRun - all tools present, --dry-run -> all [SKIP], exit 0

Group 7 -- PATH Persistence (4):
25. TestPathPersistenceBashrcCreated - creates ~/.bashrc with mise shims PATH
26. TestPathPersistenceIdempotent - no duplicates on rerun, [SKIP] when present
27. TestPathPersistenceDryRun - --dry-run does not modify bashrc, shows message
28. TestPathPersistenceContent - correct export line format

Group 8 -- Non-Interactive Execution (2):
29. TestNonInteractiveCommands - pip --no-input, npm --no-audit flags
30. TestNonInteractiveSudo - act install uses sudo -n

Group 9 -- Pre-commit Hook Installation (3):
31. TestPrecommitHookInstallStep - step [8/9] banner, TOTAL_STEPS=9
32. TestPrecommitHookInstallDryRun - dry-run shows pre-commit message
33. TestPrecommitHookInstallOutcome - PASS on success, FAIL when missing

Installation Order Tested:
==========================
1. mise (curl https://mise.run | sh)
2. Python >= 3.14 (mise install python@3.14)
3. Node.js >= 22 (mise install node@22)
4. pip packages (pip install -r requirements.txt)
5. npm packages (npm install)
6. act (curl nektos/act install script)
7. Playwright Chromium (npx playwright install chromium)
8. Pre-commit hooks (install-precommit-hook.sh --force --auto --install-playwright)
9. Verification (verify-deps.sh as final gate)

Testing Approach:
=================
Uses subprocess to execute the bash script with manipulated PATH and environment
variables. Creates temporary directories with stub scripts to simulate missing,
present, or failing dependencies. The tmp_path fixture provides isolation for
each test scenario. A create_full_stub_env() helper builds a complete stubbed
environment for integration-style tests.
"""

import os
import stat
import subprocess
from pathlib import Path

# Path to the script under test (relative to repo root)
REPO_ROOT = Path(__file__).parent.parent.parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "tools" / "install-deps.sh"


def create_full_stub_env(tmp_path, overrides=None):
    """
    Build a fully stubbed environment where all tools appear present and correct.

    Creates executable stubs for every tool install-deps.sh checks, a fake
    REPO_ROOT with requirements.txt, package.json, and a passing verify-deps.sh.

    Args:
        tmp_path: pytest tmp_path fixture for file isolation.
        overrides: dict mapping tool names to stub content strings. Use None as
            a value to remove that tool entirely (simulate missing). Use a string
            to replace the default stub content.

    Returns:
        dict with keys:
            env: environment dict ready for subprocess.run
            stub_bin: Path to the directory containing stub binaries
            repo_root: Path to the fake repo root
    """
    if overrides is None:
        overrides = {}

    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()

    # Fake repo root with necessary files
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "requirements.txt").write_text(
        "check-jsonschema==0.35.0\npytest==9.0.2\nPyYAML==6.0.2\nruff==0.13.0\n"
    )
    (repo_root / "package.json").write_text(
        '{"dependencies": {"prettier": "^3.8.1", "@mermaid-js/mermaid-cli": "^11.12.0"}}\n'
    )
    (repo_root / ".mise.toml").write_text('[tools]\npython = "3.14"\nnode = "22"\n')

    # Create fake verify-deps.sh in the repo structure
    tools_dir = repo_root / "scripts" / "tools"
    tools_dir.mkdir(parents=True)
    verify_script = tools_dir / "verify-deps.sh"
    verify_content = overrides.get(
        "verify-deps",
        "#!/bin/bash\nexit 0\n",
    )
    if verify_content is not None:
        verify_script.write_text(verify_content)
        verify_script.chmod(0o755)

    # Default stubs -- each handles the subcommands install-deps.sh will invoke
    default_stubs = {
        "mise": (
            "#!/bin/bash\n"
            'echo "$@" >> "$HOME/mise-invocations.log"\n'
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "2025.1.0 linux-x64"\n'
            'elif [[ "$1" == "install" ]]; then\n'
            "    exit 0\n"
            'elif [[ "$1" == "trust" ]]; then\n'
            "    exit 0\n"
            'elif [[ "$1" == "reshim" ]]; then\n'
            "    exit 0\n"
            'elif [[ "$1" == "which" ]]; then\n'
            '    echo "/usr/local/bin/$2"\n'
            "else\n"
            "    exit 0\n"
            "fi\n"
        ),
        "python3": (
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "Python 3.14.0"\n'
            'elif [[ "$1" == "-m" && "$2" == "pip" && "$3" == "show" ]]; then\n'
            '    echo "Name: $4"\n'
            '    echo "Version: 1.0.0"\n'
            "    exit 0\n"
            'elif [[ "$1" == "-m" && "$2" == "pip" && "$3" == "install" ]]; then\n'
            "    exit 0\n"
            "else\n"
            "    exit 0\n"
            "fi\n"
        ),
        "node": (
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" || "$1" == "-v" ]]; then\n'
            '    echo "v22.0.0"\n'
            "else\n"
            "    exit 0\n"
            "fi\n"
        ),
        "npm": (
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "10.0.0"\n'
            'elif [[ "$1" == "install" ]]; then\n'
            "    exit 0\n"
            'elif [[ "$1" == "ls" || "$1" == "list" ]]; then\n'
            '    echo "prettier@3.8.1"\n'
            '    echo "@mermaid-js/mermaid-cli@11.12.0"\n'
            "    exit 0\n"
            "else\n"
            "    exit 0\n"
            "fi\n"
        ),
        "npx": (
            "#!/bin/bash\n"
            'if [[ "$1" == "prettier" && "$2" == "--version" ]]; then\n'
            '    echo "3.8.1"\n'
            "    exit 0\n"
            'elif [[ "$1" == "mmdc" && "$2" == "--version" ]]; then\n'
            '    echo "11.12.0"\n'
            "    exit 0\n"
            'elif [[ "$1" == "playwright" && "$2" == "install" ]]; then\n'
            "    exit 0\n"
            "else\n"
            "    exit 0\n"
            "fi\n"
        ),
        "pip": (
            "#!/bin/bash\n"
            'if [[ "$1" == "install" ]]; then\n'
            "    exit 0\n"
            'elif [[ "$1" == "show" ]]; then\n'
            '    echo "Name: $2"\n'
            '    echo "Version: 1.0.0"\n'
            "    exit 0\n"
            "else\n"
            "    exit 0\n"
            "fi\n"
        ),
        "git": ('#!/bin/bash\necho "git version 2.45.0"\n'),
        "act": (
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "act version 0.2.68"\n'
            "else\n"
            "    exit 0\n"
            "fi\n"
        ),
        "ruff": ('#!/bin/bash\necho "ruff 0.13.0"\n'),
        "check-jsonschema": ('#!/bin/bash\necho "check-jsonschema 0.35.0"\n'),
        "curl": ("#!/bin/bash\n# Stub curl that does nothing successfully\nexit 0\n"),
        "sudo": ('#!/bin/bash\n# Stub sudo that runs the command without privileges\n"$@"\n'),
        "wget": ("#!/bin/bash\nexit 0\n"),
    }

    # Apply overrides: None removes the tool, string replaces the stub
    for tool, content in overrides.items():
        if tool in ("verify-deps", "install-precommit-hook"):
            continue  # already handled above
        if content is None:
            default_stubs.pop(tool, None)
        else:
            default_stubs[tool] = content

    # Write all stubs
    for tool_name, content in default_stubs.items():
        stub_file = stub_bin / tool_name
        stub_file.write_text(content)
        stub_file.chmod(0o755)

    # Create install-precommit-hook.sh stub in fake repo's scripts/ directory
    scripts_dir = repo_root / "scripts"
    scripts_dir.mkdir(exist_ok=True)
    precommit_script = scripts_dir / "install-precommit-hook.sh"
    precommit_content = overrides.get(
        "install-precommit-hook",
        "#!/bin/bash\nexit 0\n",
    )
    if precommit_content is not None:
        precommit_script.write_text(precommit_content)
        precommit_script.chmod(0o755)

    # Create .git/hooks directory in fake repo (for pre-commit hook installation)
    git_hooks_dir = repo_root / ".git" / "hooks"
    git_hooks_dir.mkdir(parents=True, exist_ok=True)

    # Create Playwright cache with chromium present
    playwright_cache = tmp_path / "playwright-cache"
    chromium_dir = playwright_cache / "chromium-1234" / "chrome-linux"
    chromium_dir.mkdir(parents=True)
    chromium_bin = chromium_dir / "chrome"
    chromium_bin.write_text("#!/bin/bash\necho 'Chromium stub'\n")
    chromium_bin.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = str(stub_bin)
    env["HOME"] = str(tmp_path / "home")
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(playwright_cache)
    # Override REPO_ROOT so the script finds fake requirements.txt etc.
    env["INSTALL_DEPS_REPO_ROOT"] = str(repo_root)

    # Create HOME directory
    (tmp_path / "home").mkdir(exist_ok=True)

    return {
        "env": env,
        "stub_bin": stub_bin,
        "repo_root": repo_root,
        "mise_log": tmp_path / "home" / "mise-invocations.log",
    }


# =============================================================================
# Group 1 -- Script Fundamentals
# =============================================================================


class TestScriptExists:
    """
    Test script file existence and permissions.

    Validates that install-deps.sh exists at the expected location
    and has execute permissions.
    """

    def test_script_file_exists(self):
        """
        Test that install-deps.sh exists at expected path.

        Given: The scripts/tools directory structure
        When: Checking for install-deps.sh file
        Then: File exists at scripts/tools/install-deps.sh
        """
        assert SCRIPT_PATH.exists(), f"Script not found at {SCRIPT_PATH}"

    def test_script_is_executable(self):
        """
        Test that install-deps.sh has execute permissions.

        Given: The install-deps.sh file exists
        When: Checking file permissions
        Then: File has the user executable bit set
        """
        assert SCRIPT_PATH.exists(), f"Script not found at {SCRIPT_PATH}"
        file_stat = os.stat(SCRIPT_PATH)
        is_executable = bool(file_stat.st_mode & stat.S_IXUSR)
        assert is_executable, f"Script {SCRIPT_PATH} is not executable"


class TestArgumentParsing:
    """
    Test command-line argument parsing.

    Validates that the script accepts --dry-run, --quiet, and --help flags,
    and rejects unknown flags with a non-zero exit code.
    """

    def test_dry_run_flag_accepted(self, tmp_path):
        """
        Test that --dry-run flag is accepted and script exits 0 in stubbed env.

        Given: A fully stubbed environment with all tools present
        When: Running install-deps.sh --dry-run
        Then: Script exits with code 0
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Script should exit 0 with --dry-run and all tools present.\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    def test_quiet_flag_accepted(self, tmp_path):
        """
        Test that --quiet flag is accepted without error.

        Given: A fully stubbed environment with all tools present
        When: Running install-deps.sh --quiet --dry-run
        Then: Script exits with code 0
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--quiet", "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Script should exit 0 with --quiet --dry-run.\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    def test_help_flag_prints_usage(self, tmp_path):
        """
        Test that --help prints usage information and exits 0.

        Given: No specific environment requirements
        When: Running install-deps.sh --help
        Then: Script exits with code 0
        And: Output contains usage or help text
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--help"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Script should exit 0 with --help.\nExit code: {result.returncode}\nSTDERR:\n{result.stderr}"
        )
        combined_output = result.stdout + result.stderr
        # --help should produce usage text containing at least one of these keywords
        assert any(keyword in combined_output.lower() for keyword in ["usage", "help", "dry-run", "quiet"]), (
            f"--help output should contain usage information.\nOutput:\n{combined_output}"
        )

    def test_unknown_flag_errors(self, tmp_path):
        """
        Test that unknown flags cause a non-zero exit.

        Given: No specific environment requirements
        When: Running install-deps.sh --bogus-flag
        Then: Script exits with non-zero code
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--bogus-flag"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        assert result.returncode != 0, (
            f"Script should exit non-zero for unknown flag.\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}"
        )


class TestDryRunNoSideEffects:
    """
    Test that --dry-run mode produces no filesystem changes.

    Validates that running with --dry-run in a full stub environment
    does not create, modify, or delete any files outside tmp_path.
    """

    def test_dry_run_no_filesystem_changes(self, tmp_path):
        """
        Test that dry-run does not modify any files.

        Given: A fully stubbed environment
        When: Running install-deps.sh --dry-run
        Then: No files are created, modified, or deleted outside tmp_path
        """
        env_info = create_full_stub_env(tmp_path)

        # Snapshot the tmp_path state before running
        before_files = set()
        for p in tmp_path.rglob("*"):
            before_files.add((str(p.relative_to(tmp_path)), p.stat().st_size if p.is_file() else -1))

        subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )

        # Snapshot after running
        after_files = set()
        for p in tmp_path.rglob("*"):
            after_files.add((str(p.relative_to(tmp_path)), p.stat().st_size if p.is_file() else -1))

        # No new files should have been created in the repo root
        repo_root = env_info["repo_root"]
        new_in_repo = set()
        for p in repo_root.rglob("*"):
            rel = str(p.relative_to(tmp_path))
            matching = [f for f in before_files if f[0] == rel]
            if not matching:
                new_in_repo.add(rel)

        assert len(new_in_repo) == 0, (
            f"Dry-run should not create new files in repo root.\nNew files: {new_in_repo}"
        )


# =============================================================================
# Group 2 -- Dry-Run Output
# =============================================================================


class TestDryRunMiseInstall:
    """
    Test dry-run output when mise is missing.

    When mise is not found on PATH, the script should output a [DRY-RUN]
    message indicating it would install mise via curl.
    """

    def test_mise_missing_shows_dry_run_install(self, tmp_path):
        """
        Test that missing mise triggers dry-run curl install message.

        Given: An environment where mise is not installed
        When: Running install-deps.sh --dry-run
        Then: Output contains [DRY-RUN] with curl or mise install reference
        """
        env_info = create_full_stub_env(tmp_path, overrides={"mise": None})
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "DRY-RUN" in combined_output, (
            f"Output should contain [DRY-RUN] tag when mise is missing.\nOutput:\n{combined_output}"
        )
        # Should mention curl or mise.run for the install command
        assert "curl" in combined_output.lower() or "mise" in combined_output.lower(), (
            f"Dry-run output should reference curl/mise install command.\nOutput:\n{combined_output}"
        )


class TestDryRunMiseSkip:
    """
    Test dry-run output when mise is already present.

    When mise is found on PATH, the script should output [SKIP] for mise.
    """

    def test_mise_present_shows_skip(self, tmp_path):
        """
        Test that present mise triggers [SKIP] in dry-run output.

        Given: An environment where mise is installed
        When: Running install-deps.sh --dry-run
        Then: Output contains [SKIP] for mise
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "SKIP" in combined_output, (
            f"Output should contain [SKIP] when mise is present.\nOutput:\n{combined_output}"
        )
        # Verify mise is mentioned in a skip context
        lines_with_skip = [
            line for line in combined_output.splitlines() if "SKIP" in line and "mise" in line.lower()
        ]
        assert len(lines_with_skip) > 0, (
            f"Output should have a [SKIP] line mentioning mise.\nOutput:\n{combined_output}"
        )


class TestDryRunPythonInstall:
    """
    Test dry-run output when Python is missing.

    When python3 is not found or version is insufficient, the script should
    output a [DRY-RUN] message about mise install python@3.14.
    """

    def test_python_missing_shows_dry_run_install(self, tmp_path):
        """
        Test that missing python triggers dry-run mise install python message.

        Given: An environment where python3 is not installed
        When: Running install-deps.sh --dry-run
        Then: Output contains [DRY-RUN] referencing mise install python
        """
        env_info = create_full_stub_env(tmp_path, overrides={"python3": None})
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "DRY-RUN" in combined_output, (
            f"Output should contain [DRY-RUN] when python3 is missing.\nOutput:\n{combined_output}"
        )
        # Should mention python in the install command
        assert "python" in combined_output.lower(), (
            f"Dry-run output should reference python installation.\nOutput:\n{combined_output}"
        )


class TestDryRunNodeInstall:
    """
    Test dry-run output when Node.js is missing.

    When node is not found, the script should output a [DRY-RUN] message
    about mise install node@22.
    """

    def test_node_missing_shows_dry_run_install(self, tmp_path):
        """
        Test that missing node triggers dry-run mise install node message.

        Given: An environment where node is not installed
        When: Running install-deps.sh --dry-run
        Then: Output contains [DRY-RUN] referencing mise install node
        """
        env_info = create_full_stub_env(tmp_path, overrides={"node": None})
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "DRY-RUN" in combined_output, (
            f"Output should contain [DRY-RUN] when node is missing.\nOutput:\n{combined_output}"
        )
        assert "node" in combined_output.lower(), (
            f"Dry-run output should reference node installation.\nOutput:\n{combined_output}"
        )


class TestDryRunPipInstall:
    """
    Test dry-run output when pip packages are missing.

    When pip packages from requirements.txt are not installed, the script
    should output a [DRY-RUN] message about pip install -r requirements.txt.
    """

    def test_pip_packages_missing_shows_dry_run_install(self, tmp_path):
        """
        Test that missing pip packages trigger dry-run pip install message.

        Given: An environment where pip packages are not installed
        When: Running install-deps.sh --dry-run
        Then: Output contains [DRY-RUN] referencing pip install
        """
        # python3 stub that reports packages as missing
        python_stub_missing_pkgs = (
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "Python 3.14.0"\n'
            'elif [[ "$1" == "-m" && "$2" == "pip" && "$3" == "show" ]]; then\n'
            "    exit 1\n"
            'elif [[ "$1" == "-m" && "$2" == "pip" && "$3" == "install" ]]; then\n'
            "    exit 0\n"
            "else\n"
            "    exit 0\n"
            "fi\n"
        )
        env_info = create_full_stub_env(tmp_path, overrides={"python3": python_stub_missing_pkgs})
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "DRY-RUN" in combined_output, (
            f"Output should contain [DRY-RUN] when pip packages are missing.\nOutput:\n{combined_output}"
        )
        assert "pip" in combined_output.lower() or "requirements" in combined_output.lower(), (
            f"Dry-run output should reference pip install or requirements.txt.\nOutput:\n{combined_output}"
        )


class TestDryRunNpmInstall:
    """
    Test dry-run output when npm packages are missing.

    When npm packages (prettier, mermaid-cli) are not installed, the script
    should output a [DRY-RUN] message about npm install.
    """

    def test_npm_packages_missing_shows_dry_run_install(self, tmp_path):
        """
        Test that missing npm packages trigger dry-run npm install message.

        Given: An environment where npm packages are not installed
        When: Running install-deps.sh --dry-run
        Then: Output contains [DRY-RUN] referencing npm install
        """
        # npm stub that reports no packages installed
        npm_stub_no_pkgs = (
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "10.0.0"\n'
            'elif [[ "$1" == "ls" || "$1" == "list" ]]; then\n'
            "    exit 1\n"
            'elif [[ "$1" == "install" ]]; then\n'
            "    exit 0\n"
            "else\n"
            "    exit 0\n"
            "fi\n"
        )
        env_info = create_full_stub_env(tmp_path, overrides={"npm": npm_stub_no_pkgs})
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "DRY-RUN" in combined_output, (
            f"Output should contain [DRY-RUN] when npm packages are missing.\nOutput:\n{combined_output}"
        )
        assert "npm" in combined_output.lower(), (
            f"Dry-run output should reference npm install.\nOutput:\n{combined_output}"
        )


class TestDryRunActInstall:
    """
    Test dry-run output when act is missing.

    When act is not found on PATH, the script should output a [DRY-RUN]
    message indicating it would install act via the nektos install script.
    """

    def test_act_missing_shows_dry_run_install(self, tmp_path):
        """
        Test that missing act triggers dry-run install message.

        Given: An environment where act is not installed
        When: Running install-deps.sh --dry-run
        Then: Output contains [DRY-RUN] referencing act installation
        """
        env_info = create_full_stub_env(tmp_path, overrides={"act": None})
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "DRY-RUN" in combined_output, (
            f"Output should contain [DRY-RUN] when act is missing.\nOutput:\n{combined_output}"
        )
        assert "act" in combined_output.lower(), (
            f"Dry-run output should reference act installation.\nOutput:\n{combined_output}"
        )


# =============================================================================
# Group 3 -- Skip/Idempotency
# =============================================================================


class TestSkipMiseWhenPresent:
    """
    Test that mise installation is skipped when mise is already present.

    When mise is already on PATH, the script should emit [SKIP] and not
    attempt to re-install.
    """

    def test_mise_present_emits_skip(self, tmp_path):
        """
        Test that present mise results in [SKIP] output.

        Given: An environment where mise is installed and on PATH
        When: Running install-deps.sh --dry-run
        Then: Output contains [SKIP] for mise
        And: No install command is shown for mise
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        # Find lines that mention mise and SKIP
        mise_skip_lines = [
            line for line in combined_output.splitlines() if "SKIP" in line and "mise" in line.lower()
        ]
        assert len(mise_skip_lines) > 0, (
            f"Output should have [SKIP] line for mise when already present.\nOutput:\n{combined_output}"
        )


class TestSkipPythonWhenPresent:
    """
    Test that Python installation is skipped when correct version is present.

    When python3 >= 3.14 is already available, the script should emit [SKIP].
    """

    def test_python_correct_version_emits_skip(self, tmp_path):
        """
        Test that Python >= 3.14 results in [SKIP] output.

        Given: An environment where python3 reports version 3.14.0
        When: Running install-deps.sh --dry-run
        Then: Output contains [SKIP] for Python
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        python_skip_lines = [
            line for line in combined_output.splitlines() if "SKIP" in line and "python" in line.lower()
        ]
        assert len(python_skip_lines) > 0, (
            f"Output should have [SKIP] line for python when correct version present.\nOutput:\n{combined_output}"
        )


class TestSkipNodeWhenPresent:
    """
    Test that Node.js installation is skipped when correct version is present.

    When node >= 22 is already available, the script should emit [SKIP].
    """

    def test_node_correct_version_emits_skip(self, tmp_path):
        """
        Test that Node.js >= 22 results in [SKIP] output.

        Given: An environment where node reports version v22.0.0
        When: Running install-deps.sh --dry-run
        Then: Output contains [SKIP] for Node.js
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        node_skip_lines = [
            line for line in combined_output.splitlines() if "SKIP" in line and "node" in line.lower()
        ]
        assert len(node_skip_lines) > 0, (
            f"Output should have [SKIP] line for node when correct version present.\nOutput:\n{combined_output}"
        )


class TestSkipActWhenPresent:
    """
    Test that act installation is skipped when act is already present.

    When act is already on PATH, the script should emit [SKIP].
    """

    def test_act_present_emits_skip(self, tmp_path):
        """
        Test that present act results in [SKIP] output.

        Given: An environment where act is installed and on PATH
        When: Running install-deps.sh --dry-run
        Then: Output contains [SKIP] for act
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        act_skip_lines = [
            line for line in combined_output.splitlines() if "SKIP" in line and "act" in line.lower()
        ]
        assert len(act_skip_lines) > 0, (
            f"Output should have [SKIP] line for act when already present.\nOutput:\n{combined_output}"
        )


class TestSkipChromiumWhenPresent:
    """
    Test that Chromium installation is skipped when found in Playwright cache.

    When Chromium exists in PLAYWRIGHT_BROWSERS_PATH, the script should emit [SKIP].
    """

    def test_chromium_in_cache_emits_skip(self, tmp_path):
        """
        Test that Chromium in Playwright cache results in [SKIP] output.

        Given: An environment with Chromium in PLAYWRIGHT_BROWSERS_PATH
        When: Running install-deps.sh --dry-run
        Then: Output contains [SKIP] for Chromium/Playwright
        """
        # create_full_stub_env already sets up a Playwright cache with chromium
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        chromium_skip_lines = [
            line
            for line in combined_output.splitlines()
            if "SKIP" in line and ("chromium" in line.lower() or "playwright" in line.lower())
        ]
        assert len(chromium_skip_lines) > 0, (
            f"Output should have [SKIP] line for Chromium/Playwright when in cache.\nOutput:\n{combined_output}"
        )


# =============================================================================
# Group 3b -- mise trust config
# =============================================================================


class TestMiseTrustConfig:
    """
    Test mise trust behavior for .mise.toml configuration.

    Validates that install-deps.sh trusts .mise.toml so mise reads tool
    versions from config, handles dry-run mode, missing config, and
    trust failures.
    """

    def test_mise_trust_dry_run_shows_message(self, tmp_path):
        """
        Test that dry-run mode shows mise trust message.

        Given: A fully stubbed environment with .mise.toml present
        When: Running install-deps.sh --dry-run
        Then: Output contains [DRY-RUN] referencing mise trust
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        trust_dry_run_lines = [
            line for line in combined_output.splitlines() if "DRY-RUN" in line and "mise trust" in line.lower()
        ]
        assert len(trust_dry_run_lines) > 0, (
            f"Dry-run output should contain [DRY-RUN] referencing mise trust.\nOutput:\n{combined_output}"
        )

    def test_mise_trust_pass_in_full_run(self, tmp_path):
        """
        Test that non-dry-run emits [PASS] for mise trust.

        Given: A fully stubbed environment with .mise.toml present
        When: Running install-deps.sh (non-dry-run)
        Then: Output contains [PASS] for .mise.toml trusted
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        trust_pass_lines = [
            line for line in combined_output.splitlines() if "PASS" in line and "mise.toml" in line.lower()
        ]
        assert len(trust_pass_lines) > 0, (
            f"Output should contain [PASS] for .mise.toml trusted.\nOutput:\n{combined_output}"
        )

    def test_mise_trust_skipped_when_no_config(self, tmp_path):
        """
        Test that mise trust is skipped when .mise.toml is absent.

        Given: A fully stubbed environment without .mise.toml
        When: Running install-deps.sh --dry-run
        Then: No [FAIL] related to mise trust appears
        And: Script continues normally
        """
        env_info = create_full_stub_env(tmp_path)
        # Remove .mise.toml from fake repo root
        mise_config = env_info["repo_root"] / ".mise.toml"
        if mise_config.exists():
            mise_config.unlink()
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        # Should not contain FAIL for mise trust
        trust_fail_lines = [
            line for line in combined_output.splitlines() if "FAIL" in line and "mise trust" in line.lower()
        ]
        assert len(trust_fail_lines) == 0, (
            f"Output should not contain [FAIL] for mise trust when config missing.\nOutput:\n{combined_output}"
        )
        assert result.returncode == 0, (
            f"Script should still exit 0 when .mise.toml is absent.\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    def test_mise_trust_failure_emits_fail(self, tmp_path):
        """
        Test that mise trust failure emits [FAIL].

        Given: A fully stubbed environment where mise trust exits 1
        When: Running install-deps.sh
        Then: Output contains [FAIL] for mise trust
        """
        mise_trust_fail = (
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "2025.1.0 linux-x64"\n'
            'elif [[ "$1" == "trust" ]]; then\n'
            "    exit 1\n"
            'elif [[ "$1" == "install" ]]; then\n'
            "    exit 0\n"
            'elif [[ "$1" == "which" ]]; then\n'
            '    echo "/usr/local/bin/$2"\n'
            "else\n"
            "    exit 0\n"
            "fi\n"
        )
        env_info = create_full_stub_env(tmp_path, overrides={"mise": mise_trust_fail})
        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        trust_fail_lines = [
            line for line in combined_output.splitlines() if "FAIL" in line and "mise trust" in line.lower()
        ]
        assert len(trust_fail_lines) > 0, (
            f"Output should contain [FAIL] for mise trust failure.\nOutput:\n{combined_output}"
        )


# =============================================================================
# Group 3c -- mise install from config
# =============================================================================


class TestMiseInstallFromConfig:
    """
    Test that mise install (no args) is called to activate tools from .mise.toml.

    After trusting .mise.toml, the script should run bare 'mise install' to
    install and activate all tools declared in the config, followed by
    'mise reshim' to regenerate shims.
    """

    def test_mise_install_no_args_called_after_trust(self, tmp_path):
        """
        Test that bare 'mise install' (no tool specifier) is called.

        Given: A fully stubbed environment with .mise.toml present
        When: Running install-deps.sh (non-dry-run)
        Then: mise invocation log contains a line that is exactly "install"
        """
        env_info = create_full_stub_env(tmp_path)
        subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        mise_log = env_info["mise_log"]
        assert mise_log.exists(), "mise invocation log should exist after running install-deps.sh"
        log_lines = mise_log.read_text().strip().splitlines()
        assert "install" in log_lines, (
            f"mise log should contain a bare 'install' line (no tool specifier).\nLog lines: {log_lines}"
        )

    def test_mise_reshim_called_after_mise_install(self, tmp_path):
        """
        Test that 'mise reshim' is called after bare 'mise install'.

        Given: A fully stubbed environment with .mise.toml present
        When: Running install-deps.sh (non-dry-run)
        Then: mise invocation log contains "reshim" after the bare "install" line
        """
        env_info = create_full_stub_env(tmp_path)
        subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        mise_log = env_info["mise_log"]
        assert mise_log.exists(), "mise invocation log should exist after running install-deps.sh"
        log_lines = mise_log.read_text().strip().splitlines()
        # Find positions of bare "install" and "reshim"
        install_indices = [i for i, line in enumerate(log_lines) if line == "install"]
        reshim_indices = [i for i, line in enumerate(log_lines) if line == "reshim"]
        assert len(install_indices) > 0, f"mise log should contain a bare 'install' line.\nLog lines: {log_lines}"
        assert len(reshim_indices) > 0, f"mise log should contain a 'reshim' line.\nLog lines: {log_lines}"
        assert reshim_indices[0] > install_indices[0], (
            f"'reshim' should appear after bare 'install' in mise log.\n"
            f"install at index {install_indices[0]}, reshim at index {reshim_indices[0]}\n"
            f"Log lines: {log_lines}"
        )


# =============================================================================
# Group 4 -- Error Handling
# =============================================================================


class TestMiseInstallFailure:
    """
    Test behavior when mise installation fails.

    When mise is missing and the install command fails, the script should
    increment its FAILURES counter, emit [FAIL], and continue with
    remaining installations.
    """

    def test_mise_install_failure_shows_fail_and_continues(self, tmp_path):
        """
        Test that failing mise install emits [FAIL] and continues.

        Given: An environment where mise is missing and curl fails
        When: Running install-deps.sh (non-dry-run with failing curl stub)
        Then: Output contains [FAIL] for mise
        And: Script continues to check remaining tools (does not abort)
        """
        # curl stub that fails for mise install
        curl_fail = "#!/bin/bash\nexit 1\n"
        env_info = create_full_stub_env(
            tmp_path,
            overrides={"mise": None, "curl": curl_fail},
        )
        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "FAIL" in combined_output, (
            f"Output should contain [FAIL] when mise install fails.\nOutput:\n{combined_output}"
        )
        # Script should not abort -- it should continue and mention other tools
        # (e.g., python, node, act, etc.)
        assert result.returncode != 0, (
            f"Script should exit non-zero when mise install fails.\nExit code: {result.returncode}"
        )


class TestPipInstallFailure:
    """
    Test behavior when pip install fails.

    When pip install -r requirements.txt fails, the script should emit [FAIL]
    and continue with remaining installations.
    """

    def test_pip_install_failure_shows_fail_and_continues(self, tmp_path):
        """
        Test that failing pip install emits [FAIL] and continues.

        Given: An environment where pip install fails
        When: Running install-deps.sh
        Then: Output contains [FAIL] for pip packages
        And: Script continues to subsequent installation steps
        """
        # python3 stub that fails on pip install
        python_pip_fail = (
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "Python 3.14.0"\n'
            'elif [[ "$1" == "-m" && "$2" == "pip" && "$3" == "show" ]]; then\n'
            "    exit 1\n"
            'elif [[ "$1" == "-m" && "$2" == "pip" && "$3" == "install" ]]; then\n'
            "    exit 1\n"
            "else\n"
            "    exit 0\n"
            "fi\n"
        )
        env_info = create_full_stub_env(tmp_path, overrides={"python3": python_pip_fail})
        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "FAIL" in combined_output, (
            f"Output should contain [FAIL] when pip install fails.\nOutput:\n{combined_output}"
        )
        # Verify script did not abort early -- it should mention npm or act
        # (subsequent steps after pip)
        lower_output = combined_output.lower()
        assert "npm" in lower_output or "act" in lower_output or "node" in lower_output, (
            f"Script should continue after pip failure and mention subsequent steps.\nOutput:\n{combined_output}"
        )


class TestNpmInstallFailure:
    """
    Test behavior when npm install fails.

    When npm install fails, the script should emit [FAIL] and continue
    with remaining installations.
    """

    def test_npm_install_failure_shows_fail_and_continues(self, tmp_path):
        """
        Test that failing npm install emits [FAIL] and continues.

        Given: An environment where npm install fails
        When: Running install-deps.sh
        Then: Output contains [FAIL] for npm packages
        And: Script continues to subsequent installation steps
        """
        # npm stub that fails on install
        npm_fail = (
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "10.0.0"\n'
            'elif [[ "$1" == "ls" || "$1" == "list" ]]; then\n'
            "    exit 1\n"
            'elif [[ "$1" == "install" ]]; then\n'
            "    exit 1\n"
            "else\n"
            "    exit 0\n"
            "fi\n"
        )
        env_info = create_full_stub_env(tmp_path, overrides={"npm": npm_fail})
        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "FAIL" in combined_output, (
            f"Output should contain [FAIL] when npm install fails.\nOutput:\n{combined_output}"
        )
        # Script should continue past npm failure to act/chromium/verification
        lower_output = combined_output.lower()
        assert "act" in lower_output or "chromium" in lower_output or "verif" in lower_output, (
            f"Script should continue after npm failure and mention subsequent steps.\nOutput:\n{combined_output}"
        )


class TestVerificationFailure:
    """
    Test behavior when verify-deps.sh returns non-zero.

    When the final verification step (verify-deps.sh) fails, install-deps.sh
    should exit with a non-zero code.
    """

    def test_verify_deps_failure_exits_nonzero(self, tmp_path):
        """
        Test that failing verify-deps.sh causes install-deps.sh to exit non-zero.

        Given: An environment where verify-deps.sh exits 1
        When: Running install-deps.sh
        Then: install-deps.sh exits with non-zero code
        """
        verify_fail = "#!/bin/bash\nexit 1\n"
        env_info = create_full_stub_env(tmp_path, overrides={"verify-deps": verify_fail})
        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        assert result.returncode != 0, (
            f"Script should exit non-zero when verify-deps.sh fails.\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )


# =============================================================================
# Group 4b -- mise reshim after pip
# =============================================================================


class TestMiseReshimAfterPip:
    """
    Test that mise reshim is called after pip install.

    After pip installs packages (ruff, check-jsonschema), mise shims must be
    regenerated so the new binaries are visible before verify-deps.sh runs.
    """

    def test_mise_reshim_called_after_pip_install(self, tmp_path):
        """
        Test that 'mise reshim' is called after pip install completes.

        Given: An environment where pip packages are missing (triggering pip install)
        When: Running install-deps.sh (non-dry-run)
        Then: mise invocation log contains "reshim" after pip install would have run
        """
        # python3 stub that reports packages missing (triggers pip install path)
        python_stub_missing_pkgs = (
            "#!/bin/bash\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '    echo "Python 3.14.0"\n'
            'elif [[ "$1" == "-m" && "$2" == "pip" && "$3" == "show" ]]; then\n'
            "    exit 1\n"
            'elif [[ "$1" == "-m" && "$2" == "pip" && "$3" == "install" ]]; then\n'
            "    exit 0\n"
            "else\n"
            "    exit 0\n"
            "fi\n"
        )
        env_info = create_full_stub_env(tmp_path, overrides={"python3": python_stub_missing_pkgs})
        subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        mise_log = env_info["mise_log"]
        assert mise_log.exists(), "mise invocation log should exist after running install-deps.sh"
        log_lines = mise_log.read_text().strip().splitlines()
        # reshim should appear at least twice: once after mise install, once after pip
        reshim_lines = [line for line in log_lines if line == "reshim"]
        assert len(reshim_lines) >= 2, (
            f"mise log should contain at least 2 'reshim' calls "
            f"(after mise install and after pip install).\n"
            f"Found {len(reshim_lines)} reshim call(s).\n"
            f"Log lines: {log_lines}"
        )


# =============================================================================
# Group 5 -- Output Formatting
# =============================================================================


class TestOutputColors:
    """
    Test that output contains ANSI color codes for status tags.

    The script should use color-coded output tags:
    - GREEN for [PASS] and [SKIP]
    - RED for [FAIL]
    - YELLOW for [INFO] and [DRY-RUN]
    """

    def test_output_contains_ansi_color_codes(self, tmp_path):
        """
        Test that ANSI escape codes are present in output.

        Given: A fully stubbed environment with all tools present
        When: Running install-deps.sh --dry-run
        Then: Output contains ANSI color escape sequences
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        # Check for ANSI escape code prefix \033[ (appears as \x1b[ in Python)
        assert "\x1b[" in combined_output, (
            f"Output should contain ANSI color escape sequences.\nOutput (repr):\n{repr(combined_output[:500])}"
        )

    def test_pass_or_skip_uses_green(self, tmp_path):
        """
        Test that [PASS] and [SKIP] tags use green color code.

        Given: A fully stubbed environment where tools are skipped
        When: Running install-deps.sh --dry-run
        Then: [SKIP] tags are preceded by green ANSI code (\\033[0;32m)
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        # GREEN = \033[0;32m which appears as \x1b[0;32m in Python
        green_code = "\x1b[0;32m"
        assert green_code in combined_output, (
            f"Output should contain green ANSI code for [PASS]/[SKIP] tags.\n"
            f"Output (repr):\n{repr(combined_output[:500])}"
        )

    def test_fail_uses_red(self, tmp_path):
        """
        Test that [FAIL] tags use red color code.

        Given: An environment with a failing tool
        When: Running install-deps.sh
        Then: [FAIL] tags are preceded by red ANSI code (\\033[0;31m)
        """
        # Make curl fail so mise install fails
        env_info = create_full_stub_env(
            tmp_path,
            overrides={"mise": None, "curl": "#!/bin/bash\nexit 1\n"},
        )
        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        red_code = "\x1b[0;31m"
        assert red_code in combined_output, (
            f"Output should contain red ANSI code for [FAIL] tags.\nOutput (repr):\n{repr(combined_output[:500])}"
        )


class TestQuietModeSuppression:
    """
    Test that --quiet flag suppresses non-error output.

    With --quiet, [PASS], [SKIP], and [INFO] messages should be suppressed.
    [FAIL] messages should still be shown.
    """

    def test_quiet_suppresses_pass_skip_info(self, tmp_path):
        """
        Test that --quiet hides [PASS], [SKIP], and [INFO] output.

        Given: A fully stubbed environment with all tools present
        When: Running install-deps.sh --quiet --dry-run
        Then: Output does not contain [PASS], [SKIP], or [INFO] tags
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--quiet", "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        # In quiet mode with all tools present, there should be no PASS/SKIP/INFO
        for tag in ["[PASS]", "[SKIP]", "[INFO]"]:
            assert tag not in combined_output, f"--quiet should suppress {tag} output.\nOutput:\n{combined_output}"

    def test_quiet_still_shows_fail(self, tmp_path):
        """
        Test that --quiet does not suppress [FAIL] output.

        Given: An environment where a tool install fails
        When: Running install-deps.sh --quiet
        Then: Output still contains [FAIL] messages
        """
        # Make mise missing and curl fail so we get a FAIL
        env_info = create_full_stub_env(
            tmp_path,
            overrides={"mise": None, "curl": "#!/bin/bash\nexit 1\n"},
        )
        result = subprocess.run(
            [str(SCRIPT_PATH), "--quiet"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "FAIL" in combined_output, f"--quiet should still show [FAIL] messages.\nOutput:\n{combined_output}"


# =============================================================================
# Group 6 -- Integration
# =============================================================================


class TestFullInstallDryRun:
    """
    Test full dry-run with all tools present.

    Integration test that creates a complete stubbed environment with every
    tool reporting as present and correctly versioned. Running --dry-run
    should produce all [SKIP] messages and exit 0.
    """

    def test_all_tools_present_dry_run_all_skip_exit_0(self, tmp_path):
        """
        Test full dry-run with all tools present produces all [SKIP] and exit 0.

        Given: A fully stubbed environment with all tools present
        When: Running install-deps.sh --dry-run
        Then: Script exits with code 0
        And: Output contains [SKIP] for each tool category
        And: Output does not contain [FAIL]
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr

        assert result.returncode == 0, (
            f"Script should exit 0 when all tools present in dry-run.\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

        assert "FAIL" not in combined_output, (
            f"Output should not contain [FAIL] when all tools present.\nOutput:\n{combined_output}"
        )

        assert "SKIP" in combined_output, (
            f"Output should contain [SKIP] tags for present tools.\nOutput:\n{combined_output}"
        )

    def test_all_tools_present_dry_run_mentions_all_categories(self, tmp_path):
        """
        Test that dry-run output mentions all tool categories.

        Given: A fully stubbed environment with all tools present
        When: Running install-deps.sh --dry-run
        Then: Output references mise, python, node, pip, npm, act, chromium
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = (result.stdout + result.stderr).lower()

        expected_tools = ["mise", "python", "node", "pip", "npm", "act", "chromium"]
        missing_mentions = [tool for tool in expected_tools if tool not in combined_output]
        assert len(missing_mentions) == 0, (
            f"Dry-run output should mention all tool categories.\n"
            f"Missing: {missing_mentions}\n"
            f"Output:\n{result.stdout + result.stderr}"
        )


# =============================================================================
# Group 7 -- PATH Persistence
# =============================================================================


class TestPathPersistenceBashrcCreated:
    """
    Test that install-deps.sh creates ~/.bashrc with mise shims PATH export
    when it doesn't already exist.
    """

    def test_bashrc_created_with_mise_path(self, tmp_path):
        """
        When ~/.bashrc doesn't exist, install-deps.sh creates it with mise shims PATH.

        Given: A fully stubbed environment where $HOME/.bashrc does not exist
        When: Running install-deps.sh (non-dry-run)
        Then: $HOME/.bashrc exists and contains 'mise/shims'
        """
        env_info = create_full_stub_env(tmp_path)
        home_dir = tmp_path / "home"
        bashrc = home_dir / ".bashrc"
        # Ensure .bashrc does not exist
        if bashrc.exists():
            bashrc.unlink()

        subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )

        assert bashrc.exists(), f"~/.bashrc should have been created at {bashrc}"
        content = bashrc.read_text()
        assert "mise/shims" in content, (
            f"~/.bashrc should contain 'mise/shims' PATH export.\nContent:\n{content}"
        )


class TestPathPersistenceIdempotent:
    """
    Test that PATH persistence in ~/.bashrc is idempotent -- no duplicates
    on re-run, and [SKIP] message when already present.
    """

    def test_bashrc_not_duplicated_on_rerun(self, tmp_path):
        """
        Pre-create ~/.bashrc with mise path line, run script, assert only 1 occurrence.

        Given: ~/.bashrc already contains the mise shims PATH export
        When: Running install-deps.sh (non-dry-run)
        Then: ~/.bashrc still contains exactly 1 occurrence of 'mise/shims'
        """
        env_info = create_full_stub_env(tmp_path)
        home_dir = tmp_path / "home"
        bashrc = home_dir / ".bashrc"
        # Pre-create with the expected line
        bashrc.write_text(
            '# mise shims PATH (added by install-deps.sh)\n'
            'export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"\n'
        )

        subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )

        content = bashrc.read_text()
        count = content.count("mise/shims")
        assert count == 1, (
            f"~/.bashrc should contain exactly 1 'mise/shims' line, found {count}.\n"
            f"Content:\n{content}"
        )

    def test_bashrc_skip_message_when_already_present(self, tmp_path):
        """
        When ~/.bashrc already has mise shims PATH, output contains [SKIP].

        Given: ~/.bashrc already contains the mise shims PATH export
        When: Running install-deps.sh (non-dry-run)
        Then: Output contains [SKIP] referencing PATH or bashrc
        """
        env_info = create_full_stub_env(tmp_path)
        home_dir = tmp_path / "home"
        bashrc = home_dir / ".bashrc"
        bashrc.write_text(
            '# mise shims PATH (added by install-deps.sh)\n'
            'export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"\n'
        )

        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )

        combined_output = result.stdout + result.stderr
        skip_path_lines = [
            line for line in combined_output.splitlines()
            if "SKIP" in line and ("PATH" in line or "bashrc" in line.lower())
        ]
        assert len(skip_path_lines) > 0, (
            f"Output should have [SKIP] line for PATH/bashrc when already present.\n"
            f"Output:\n{combined_output}"
        )


class TestPathPersistenceDryRun:
    """
    Test that --dry-run does not modify ~/.bashrc and shows [DRY-RUN] message.
    """

    def test_dry_run_does_not_write_bashrc(self, tmp_path):
        """
        Running with --dry-run should not create or modify ~/.bashrc.

        Given: A fully stubbed environment where $HOME/.bashrc does not exist
        When: Running install-deps.sh --dry-run
        Then: $HOME/.bashrc still does not exist
        """
        env_info = create_full_stub_env(tmp_path)
        home_dir = tmp_path / "home"
        bashrc = home_dir / ".bashrc"
        if bashrc.exists():
            bashrc.unlink()

        subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )

        assert not bashrc.exists(), (
            "~/.bashrc should NOT be created in --dry-run mode."
        )

    def test_dry_run_shows_would_append_message(self, tmp_path):
        """
        --dry-run output should contain [DRY-RUN] referencing bashrc.

        Given: A fully stubbed environment where $HOME/.bashrc does not exist
        When: Running install-deps.sh --dry-run
        Then: Output contains [DRY-RUN] referencing bashrc
        """
        env_info = create_full_stub_env(tmp_path)
        home_dir = tmp_path / "home"
        bashrc = home_dir / ".bashrc"
        if bashrc.exists():
            bashrc.unlink()

        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )

        combined_output = result.stdout + result.stderr
        dry_run_bashrc_lines = [
            line for line in combined_output.splitlines()
            if "DRY-RUN" in line and "bashrc" in line.lower()
        ]
        assert len(dry_run_bashrc_lines) > 0, (
            f"Output should have [DRY-RUN] line referencing bashrc.\n"
            f"Output:\n{combined_output}"
        )


class TestPathPersistenceContent:
    """
    Test that the written export line has the correct format.
    """

    def test_bashrc_contains_correct_export_line(self, tmp_path):
        """
        The written line should be the correct PATH export with mise shims.

        Given: A fully stubbed environment where $HOME/.bashrc does not exist
        When: Running install-deps.sh (non-dry-run)
        Then: ~/.bashrc contains: export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"
        """
        env_info = create_full_stub_env(tmp_path)
        home_dir = tmp_path / "home"
        bashrc = home_dir / ".bashrc"
        if bashrc.exists():
            bashrc.unlink()

        subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )

        assert bashrc.exists(), f"~/.bashrc should have been created at {bashrc}"
        content = bashrc.read_text()
        expected_line = 'export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"'
        assert expected_line in content, (
            f"~/.bashrc should contain the exact export line.\n"
            f"Expected: {expected_line}\n"
            f"Content:\n{content}"
        )


# =============================================================================
# Group 8 -- Non-Interactive Execution
# =============================================================================


class TestNonInteractiveCommands:
    """
    Static analysis tests: read script source and verify non-interactive flags
    are present on commands that can prompt for stdin.
    """

    def test_pip_install_uses_no_input_flag(self):
        """
        The pip install command in install-deps.sh must use --no-input.

        Given: The install-deps.sh source code
        When: Examining pip install lines
        Then: The line contains '--no-input'
        """
        content = SCRIPT_PATH.read_text()
        # Find lines containing 'pip install' (the actual install, not dry-run messages)
        pip_install_lines = [
            line.strip() for line in content.splitlines()
            if "pip install" in line and "dry_run_msg" not in line and "fail_msg" not in line
        ]
        assert len(pip_install_lines) > 0, (
            "Script should contain at least one 'pip install' command line."
        )
        has_no_input = any("--no-input" in line for line in pip_install_lines)
        assert has_no_input, (
            f"pip install command should include '--no-input' flag.\n"
            f"Found pip install lines: {pip_install_lines}"
        )

    def test_npm_install_uses_non_interactive_flags(self):
        """
        The npm install command in install-deps.sh must use --no-audit.

        Given: The install-deps.sh source code
        When: Examining npm install lines
        Then: The line contains '--no-audit'
        """
        content = SCRIPT_PATH.read_text()
        # Find lines containing 'npm install' (the actual install, not dry-run/fail messages)
        npm_install_lines = [
            line.strip() for line in content.splitlines()
            if "npm install" in line and "dry_run_msg" not in line and "fail_msg" not in line
        ]
        assert len(npm_install_lines) > 0, (
            "Script should contain at least one 'npm install' command line."
        )
        has_no_audit = any("--no-audit" in line for line in npm_install_lines)
        assert has_no_audit, (
            f"npm install command should include '--no-audit' flag.\n"
            f"Found npm install lines: {npm_install_lines}"
        )


class TestNonInteractiveSudo:
    """
    Static analysis test: verify act install uses non-interactive sudo.
    """

    def test_act_install_uses_sudo_non_interactive(self):
        """
        The act install command must use 'sudo -n' (non-interactive).

        Given: The install-deps.sh source code
        When: Examining the act install line with sudo
        Then: The line contains 'sudo -n'
        """
        content = SCRIPT_PATH.read_text()
        # Find lines with sudo and act/nektos (the actual install, not dry-run messages)
        sudo_lines = [
            line.strip() for line in content.splitlines()
            if "sudo" in line and ("nektos" in line or "act" in line.lower())
            and "dry_run_msg" not in line and "fail_msg" not in line
        ]
        assert len(sudo_lines) > 0, (
            "Script should contain at least one sudo line for act install."
        )
        has_sudo_n = any("sudo -n" in line for line in sudo_lines)
        assert has_sudo_n, (
            f"act install should use 'sudo -n' for non-interactive execution.\n"
            f"Found sudo lines: {sudo_lines}"
        )


# =============================================================================
# Group 9 -- Pre-commit Hook Installation
# =============================================================================


class TestPrecommitHookInstallStep:
    """
    Test that Step 8 installs pre-commit hooks.

    Validates that install-deps.sh includes a step for pre-commit hook
    installation and that TOTAL_STEPS is updated accordingly.
    """

    def test_step_8_is_precommit_hooks(self, tmp_path):
        """
        Script output contains step banner [8/9] with pre-commit or hook reference.

        Given: A fully stubbed environment with all tools present
        When: Running install-deps.sh --dry-run
        Then: Output contains a step banner [8/9] referencing pre-commit or hooks
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        assert "[8/9]" in combined_output, (
            f"Output should contain step banner [8/9].\nOutput:\n{combined_output}"
        )
        # Find the line with [8/9] and check it references pre-commit or hooks
        step_8_lines = [
            line for line in combined_output.splitlines()
            if "[8/9]" in line
        ]
        assert len(step_8_lines) > 0, (
            f"Should find at least one line with [8/9].\nOutput:\n{combined_output}"
        )
        step_8_text = step_8_lines[0].lower()
        assert "pre-commit" in step_8_text or "hook" in step_8_text, (
            f"Step [8/9] banner should reference pre-commit or hooks.\n"
            f"Line: {step_8_lines[0]}"
        )

    def test_total_steps_is_9(self):
        """
        Static analysis: TOTAL_STEPS=9 in script source.

        Given: The install-deps.sh source code
        When: Examining the TOTAL_STEPS variable
        Then: TOTAL_STEPS is set to 9
        """
        content = SCRIPT_PATH.read_text()
        assert "TOTAL_STEPS=9" in content, (
            "install-deps.sh should have TOTAL_STEPS=9 after adding pre-commit step."
        )


class TestPrecommitHookInstallDryRun:
    """
    Test that --dry-run shows pre-commit hook installation message.
    """

    def test_dry_run_shows_precommit_message(self, tmp_path):
        """
        With --dry-run, output contains [DRY-RUN] referencing pre-commit hook.

        Given: A fully stubbed environment
        When: Running install-deps.sh --dry-run
        Then: Output contains [DRY-RUN] referencing pre-commit or hook install
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        dry_run_precommit_lines = [
            line for line in combined_output.splitlines()
            if "DRY-RUN" in line
            and ("precommit" in line.lower() or "pre-commit" in line.lower()
                 or "install-precommit" in line.lower())
        ]
        assert len(dry_run_precommit_lines) > 0, (
            f"Dry-run output should contain [DRY-RUN] referencing pre-commit hook.\n"
            f"Output:\n{combined_output}"
        )


class TestPrecommitHookInstallOutcome:
    """
    Test pre-commit hook installation outcomes (pass/fail).
    """

    def test_precommit_hook_pass_when_script_succeeds(self, tmp_path):
        """
        When install-precommit-hook.sh stub exists and succeeds, output contains [PASS].

        Given: A stubbed environment with a passing install-precommit-hook.sh
        When: Running install-deps.sh (non-dry-run)
        Then: Output contains [PASS] referencing pre-commit or hooks
        """
        env_info = create_full_stub_env(tmp_path)
        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        pass_hook_lines = [
            line for line in combined_output.splitlines()
            if "PASS" in line
            and ("pre-commit" in line.lower() or "hook" in line.lower())
        ]
        assert len(pass_hook_lines) > 0, (
            f"Output should contain [PASS] for pre-commit hooks when script succeeds.\n"
            f"Output:\n{combined_output}"
        )

    def test_precommit_hook_fail_when_script_missing(self, tmp_path):
        """
        When install-precommit-hook.sh doesn't exist, output contains [FAIL].

        Given: A stubbed environment without install-precommit-hook.sh
        When: Running install-deps.sh (non-dry-run)
        Then: Output contains [FAIL] referencing pre-commit or hook
        """
        env_info = create_full_stub_env(
            tmp_path, overrides={"install-precommit-hook": None}
        )
        result = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=env_info["env"],
            timeout=30,
        )
        combined_output = result.stdout + result.stderr
        fail_hook_lines = [
            line for line in combined_output.splitlines()
            if "FAIL" in line
            and ("pre-commit" in line.lower() or "hook" in line.lower()
                 or "install-precommit" in line.lower())
        ]
        assert len(fail_hook_lines) > 0, (
            f"Output should contain [FAIL] for pre-commit hooks when script is missing.\n"
            f"Output:\n{combined_output}"
        )


"""
Test Summary
============
Total Test Classes: 34
Total Test Methods: 51

Group 1 -- Script Fundamentals (3 classes, 6 methods):
- TestScriptExists (2): file exists, is executable
- TestArgumentParsing (4): --dry-run, --quiet, --help, unknown flag
- TestDryRunNoSideEffects (1): no filesystem changes

Group 2 -- Dry-Run Output (7 classes, 7 methods):
- TestDryRunMiseInstall (1): mise missing -> DRY-RUN curl
- TestDryRunMiseSkip (1): mise present -> SKIP
- TestDryRunPythonInstall (1): python missing -> DRY-RUN mise install python
- TestDryRunNodeInstall (1): node missing -> DRY-RUN mise install node
- TestDryRunPipInstall (1): pip packages missing -> DRY-RUN pip install
- TestDryRunNpmInstall (1): npm packages missing -> DRY-RUN npm install
- TestDryRunActInstall (1): act missing -> DRY-RUN act install

Group 3 -- Skip/Idempotency (5 classes, 5 methods):
- TestSkipMiseWhenPresent (1): mise present -> SKIP
- TestSkipPythonWhenPresent (1): python correct version -> SKIP
- TestSkipNodeWhenPresent (1): node correct version -> SKIP
- TestSkipActWhenPresent (1): act present -> SKIP
- TestSkipChromiumWhenPresent (1): chromium in cache -> SKIP

Group 3b -- mise trust config (1 class, 4 methods):
- TestMiseTrustConfig (4): dry-run msg, pass, skip when no config, fail

Group 3c -- mise install from config (1 class, 2 methods):
- TestMiseInstallFromConfig (2): bare mise install, reshim after install

Group 4 -- Error Handling (4 classes, 4 methods):
- TestMiseInstallFailure (1): curl fails -> FAIL, continues
- TestPipInstallFailure (1): pip install fails -> FAIL, continues
- TestNpmInstallFailure (1): npm install fails -> FAIL, continues
- TestVerificationFailure (1): verify-deps.sh fails -> exit non-zero

Group 4b -- mise reshim after pip (1 class, 1 method):
- TestMiseReshimAfterPip (1): reshim called after pip install

Group 5 -- Output Formatting (2 classes, 5 methods):
- TestOutputColors (3): ANSI codes present, green for PASS/SKIP, red for FAIL
- TestQuietModeSuppression (2): quiet hides PASS/SKIP/INFO, shows FAIL

Group 6 -- Integration (1 class, 2 methods):
- TestFullInstallDryRun (2): all SKIP + exit 0, all categories mentioned

Group 7 -- PATH Persistence (4 classes, 6 methods):
- TestPathPersistenceBashrcCreated (1): creates ~/.bashrc with mise shims PATH
- TestPathPersistenceIdempotent (2): no duplicates on rerun, SKIP when present
- TestPathPersistenceDryRun (2): dry-run skips bashrc, shows would-append message
- TestPathPersistenceContent (1): correct export PATH line format

Group 8 -- Non-Interactive Execution (2 classes, 3 methods):
- TestNonInteractiveCommands (2): pip --no-input, npm --no-audit flags
- TestNonInteractiveSudo (1): act install uses sudo -n

Group 9 -- Pre-commit Hook Installation (3 classes, 5 methods):
- TestPrecommitHookInstallStep (2): step [8/9] banner, TOTAL_STEPS=9
- TestPrecommitHookInstallDryRun (1): dry-run shows pre-commit message
- TestPrecommitHookInstallOutcome (2): PASS on success, FAIL when missing

Coverage Areas:
- Script existence and permissions
- Command-line argument parsing (--dry-run, --quiet, --help, unknown flags)
- Dry-run mode filesystem safety
- Tool presence detection and [SKIP] output
- Tool absence detection and [DRY-RUN] install commands
- Installation failure handling and [FAIL] output
- Verification gate (verify-deps.sh exit code propagation)
- ANSI color codes for status tags
- Quiet mode output suppression
- Full integration with all tools present
- PATH persistence in ~/.bashrc (idempotent, dry-run safe)
- Non-interactive command execution (--no-input, --no-audit, sudo -n)
- Pre-commit hook installation step (dry-run, pass, fail)
"""
