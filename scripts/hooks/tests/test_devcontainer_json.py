#!/usr/bin/env python3
"""
Tests for .devcontainer/devcontainer.json structure.

Static analysis tests that read devcontainer.json and validate its structure.
These tests validate the Phase 4 devcontainer refactor, which moves tool
installation from devcontainer features to install-deps.sh with mise.

Test Coverage:
==============
Total Test Classes: 7
Total Test Methods: 33

1. TestDevcontainerJsonExists (2): file exists, parses as valid JSON
2. TestDevcontainerJsonFeatures (11): no Python feature, no Node feature,
   Docker-in-Docker feature present, common-utils feature present,
   common-utils username vscode, common-utils automatic uid,
   common-utils automatic gid, common-utils no zsh,
   Git feature present, Git latest version, Git PPA enabled
3. TestDevcontainerJsonCommands (4): onCreateCommand exists,
   onCreateCommand references install-deps.sh, no direct pip/npm in
   onCreateCommand, no postCreateCommand
4. TestDevcontainerJsonPythonConfig (5): interpreter path exists, uses mise
   install path, uses absolute path, does not use mise shims, does not use
   /usr/local/python/current
5. TestDevcontainerJsonVscodeExtensions (2): extensions array exists,
   required extensions present (including ms-python.python)
6. TestDevcontainerJsonBuildConfig (4): remoteUser is vscode,
   build.args contains WORKSPACE and WORKSPACE_REPO, build.context is "..",
   build.dockerfile is "Dockerfile"
7. TestDevcontainerJsonRemoteEnv (5): remoteEnv exists, PATH includes
   mise shims, PATH includes .local/bin, PATH preserves existing PATH,
   PATH does not use ${containerEnv:HOME}

Testing Approach:
=================
Reads .devcontainer/devcontainer.json, strips JSONC comments (// and /* */),
parses as JSON, and validates structure. Uses module-level fixture to load
file once per session.
"""

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent.parent
DEVCONTAINER_JSON_PATH = REPO_ROOT / ".devcontainer" / "devcontainer.json"


def strip_jsonc_comments(content: str) -> str:
    """
    Strip JSONC comments from content.

    Removes:
    - // line comments
    - /* block comments */

    Does NOT handle comments inside strings (but devcontainer.json doesn't
    contain such cases, so this simple approach is sufficient).
    """
    # Remove block comments /* ... */
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    # Remove line comments //
    lines = content.splitlines()
    cleaned_lines = []
    for line in lines:
        # Find // outside of quoted strings (simple heuristic)
        comment_idx = line.find("//")
        if comment_idx != -1:
            line = line[:comment_idx]
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


@pytest.fixture(scope="module")
def devcontainer_json():
    """Load and parse devcontainer.json once per test module."""
    assert DEVCONTAINER_JSON_PATH.exists(), f"devcontainer.json not found at {DEVCONTAINER_JSON_PATH}"
    content = DEVCONTAINER_JSON_PATH.read_text()
    # Strip JSONC comments before parsing
    cleaned = strip_jsonc_comments(content)
    return json.loads(cleaned)


# =============================================================================
# TestDevcontainerJsonExists
# =============================================================================


class TestDevcontainerJsonExists:
    """
    Validate devcontainer.json existence and JSON parsability.
    """

    def test_devcontainer_json_exists(self):
        """
        Given: The .devcontainer directory structure
        When: Checking for devcontainer.json
        Then: File exists at .devcontainer/devcontainer.json
        """
        assert DEVCONTAINER_JSON_PATH.exists(), f"devcontainer.json not found at {DEVCONTAINER_JSON_PATH}"

    def test_devcontainer_json_parses_as_valid_json(self):
        """
        Given: The devcontainer.json file exists
        When: Parsing with comment stripping and json.loads
        Then: File parses without errors and returns a dict
        """
        assert DEVCONTAINER_JSON_PATH.exists(), f"devcontainer.json not found at {DEVCONTAINER_JSON_PATH}"
        content = DEVCONTAINER_JSON_PATH.read_text()
        cleaned = strip_jsonc_comments(content)
        config = json.loads(cleaned)
        assert isinstance(config, dict), "devcontainer.json did not parse to a dict"


# =============================================================================
# TestDevcontainerJsonFeatures
# =============================================================================


class TestDevcontainerJsonFeatures:
    """
    Validate devcontainer features configuration.

    After refactor:
    - No Python feature (ghcr.io/devcontainers/features/python)
    - No Node feature (ghcr.io/devcontainers/features/node)
    - Git feature is present with latest version and PPA enabled
    - Docker-in-Docker feature is still present
    """

    def test_no_python_feature(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking for Python devcontainer feature
        Then: No feature key contains "features/python"

        Python is now installed via mise in install-deps.sh, not as a
        devcontainer feature.
        """
        features = devcontainer_json.get("features", {})
        for feature_key in features.keys():
            assert "features/python" not in feature_key.lower(), (
                f"devcontainer.json should not use Python feature, found: {feature_key}"
            )

    def test_no_node_feature(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking for Node devcontainer feature
        Then: No feature key contains "features/node"

        Node.js is now installed via mise in install-deps.sh, not as a
        devcontainer feature.
        """
        features = devcontainer_json.get("features", {})
        for feature_key in features.keys():
            assert "features/node" not in feature_key.lower(), (
                f"devcontainer.json should not use Node feature, found: {feature_key}"
            )

    def test_docker_in_docker_feature_present(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking for Docker-in-Docker feature
        Then: Feature key contains "features/docker-in-docker"

        Docker-in-Docker is still needed for running act (GitHub Actions
        locally), so this feature should remain.
        """
        features = devcontainer_json.get("features", {})
        found_docker = any("docker-in-docker" in key.lower() for key in features.keys())
        assert found_docker, "devcontainer.json should include Docker-in-Docker feature"

    def test_git_feature_present(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking for Git devcontainer feature
        Then: Feature key is exactly ghcr.io/devcontainers/features/git:1

        Git is installed through the official devcontainer feature so the
        container gets the current stable Git without relying on Ubuntu
        Noble's frozen apt package.
        """
        features = devcontainer_json.get("features", {})
        assert "ghcr.io/devcontainers/features/git:1" in features, (
            "devcontainer.json should include ghcr.io/devcontainers/features/git:1"
        )

    def test_git_feature_version_latest(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking Git feature options
        Then: version is set to "latest"
        """
        features = devcontainer_json.get("features", {})
        git_config = features.get("ghcr.io/devcontainers/features/git:1", {})
        assert git_config.get("version") == "latest", (
            f"git feature version should be 'latest', got: {git_config.get('version')}"
        )

    def test_git_feature_ppa_enabled(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking Git feature options
        Then: ppa is true

        The Git feature uses the git-core PPA on Ubuntu when this option is
        enabled, which avoids the distro-frozen Git version.
        """
        features = devcontainer_json.get("features", {})
        git_config = features.get("ghcr.io/devcontainers/features/git:1", {})
        assert git_config.get("ppa") is True, f"git feature ppa should be true, got: {git_config.get('ppa')}"

    def test_common_utils_feature_present(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking for common-utils feature
        Then: Feature key contains "common-utils"

        common-utils handles user creation with automatic UID/GID detection,
        replacing manual groupadd/useradd in the Dockerfile.
        """
        features = devcontainer_json.get("features", {})
        found_common_utils = any("common-utils" in key.lower() for key in features.keys())
        assert found_common_utils, "devcontainer.json should include common-utils feature"

    def test_common_utils_username_vscode(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking common-utils feature username setting
        Then: username is set to "vscode"

        This replaces the old ARG USERNAME=vscode in the Dockerfile.
        The common-utils feature creates this user at feature-install time.
        """
        features = devcontainer_json.get("features", {})
        common_utils_config = None
        for key, config in features.items():
            if "common-utils" in key.lower():
                common_utils_config = config
                break
        assert common_utils_config is not None, "common-utils feature not found"
        assert common_utils_config.get("username") == "vscode", (
            f"common-utils username should be 'vscode', got: {common_utils_config.get('username')}"
        )

    def test_common_utils_automatic_uid(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking common-utils feature uid setting
        Then: uid is set to "automatic"

        Automatic UID detection resolves Mac Docker Desktop UID/GID
        mismatches by detecting the host UID from the workspace mount.
        """
        features = devcontainer_json.get("features", {})
        common_utils_config = None
        for key, config in features.items():
            if "common-utils" in key.lower():
                common_utils_config = config
                break
        assert common_utils_config is not None, "common-utils feature not found"
        assert common_utils_config.get("uid") == "automatic", (
            f"common-utils uid should be 'automatic', got: {common_utils_config.get('uid')}"
        )

    def test_common_utils_automatic_gid(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking common-utils feature gid setting
        Then: gid is set to "automatic"

        Automatic GID detection resolves Mac Docker Desktop UID/GID
        mismatches by detecting the host GID from the workspace mount.
        """
        features = devcontainer_json.get("features", {})
        common_utils_config = None
        for key, config in features.items():
            if "common-utils" in key.lower():
                common_utils_config = config
                break
        assert common_utils_config is not None, "common-utils feature not found"
        assert common_utils_config.get("gid") == "automatic", (
            f"common-utils gid should be 'automatic', got: {common_utils_config.get('gid')}"
        )

    def test_common_utils_no_zsh(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking common-utils feature zsh settings
        Then: installZsh and installOhMyZsh are both false

        The project uses bash. Disabling Zsh/Oh My Zsh avoids unnecessary
        image bloat from the common-utils defaults.
        """
        features = devcontainer_json.get("features", {})
        common_utils_config = None
        for key, config in features.items():
            if "common-utils" in key.lower():
                common_utils_config = config
                break
        assert common_utils_config is not None, "common-utils feature not found"
        assert common_utils_config.get("installZsh") is False, (
            f"common-utils installZsh should be false, got: {common_utils_config.get('installZsh')}"
        )
        assert common_utils_config.get("installOhMyZsh") is False, (
            f"common-utils installOhMyZsh should be false, got: {common_utils_config.get('installOhMyZsh')}"
        )


# =============================================================================
# TestDevcontainerJsonCommands
# =============================================================================


class TestDevcontainerJsonCommands:
    """
    Validate devcontainer lifecycle commands.

    After refactor:
    - onCreateCommand should exist and reference install-deps.sh
    - onCreateCommand should not contain direct pip/npm install commands
    - postCreateCommand should be absent (replaced by onCreateCommand)
    """

    def test_oncreate_command_exists(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking for onCreateCommand
        Then: onCreateCommand key exists and is non-empty

        onCreateCommand runs install-deps.sh to set up the environment.
        This runs earlier in the lifecycle than postCreateCommand, before
        the workspace is fully ready, which is appropriate since install-deps.sh
        only needs the repo files (available via the widened build context).
        """
        on_create = devcontainer_json.get("onCreateCommand")
        assert on_create is not None, "devcontainer.json should have an onCreateCommand"
        assert on_create != "", "devcontainer.json onCreateCommand should be non-empty"

    def test_oncreate_command_references_install_deps(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking onCreateCommand content
        Then: Command references install-deps.sh (not old setup-script)

        The refactor moves environment setup from .devcontainer/setup-script
        to scripts/tools/install-deps.sh.
        """
        on_create = devcontainer_json.get("onCreateCommand", "")
        on_create_str = json.dumps(on_create).lower()
        assert "install-deps.sh" in on_create_str, (
            "devcontainer.json onCreateCommand should reference install-deps.sh"
        )
        assert "setup-script" not in on_create_str, (
            "devcontainer.json onCreateCommand should not reference old setup-script"
        )

    def test_no_oncreate_command_pip_npm(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking onCreateCommand content
        Then: onCreateCommand does not contain direct pip install or npm install

        pip and npm installs are handled inside install-deps.sh, not as
        raw commands in onCreateCommand.
        """
        on_create = devcontainer_json.get("onCreateCommand", "")
        on_create_str = json.dumps(on_create).lower()
        assert "pip install" not in on_create_str, (
            "devcontainer.json onCreateCommand should not run pip install directly"
        )
        assert "npm install" not in on_create_str, (
            "devcontainer.json onCreateCommand should not run npm install directly"
        )

    def test_no_postcreate_command(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking for postCreateCommand
        Then: postCreateCommand key is absent

        install-deps.sh has been moved from postCreateCommand to
        onCreateCommand. postCreateCommand should no longer exist.
        """
        assert "postCreateCommand" not in devcontainer_json, (
            "devcontainer.json should not have postCreateCommand (replaced by onCreateCommand)"
        )


# =============================================================================
# TestDevcontainerJsonPythonConfig
# =============================================================================


class TestDevcontainerJsonPythonConfig:
    """
    Validate VSCode Python interpreter configuration.

    After refactor:
    - python.defaultInterpreterPath should use the real mise-installed binary
      (via the "latest" symlink), NOT the shim — the Python extension can't
      resolve shims because they're symlinks to the mise binary itself
    - Should NOT use /usr/local/python/current
    """

    def test_python_interpreter_path_exists(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking for python.defaultInterpreterPath in vscode settings
        Then: Setting exists

        VSCode needs to know where to find the Python interpreter.
        """
        vscode_settings = devcontainer_json.get("customizations", {}).get("vscode", {}).get("settings", {})
        assert "python.defaultInterpreterPath" in vscode_settings, (
            "devcontainer.json vscode settings should include python.defaultInterpreterPath"
        )

    def test_python_interpreter_uses_mise_install(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking python.defaultInterpreterPath value
        Then: Path references the real mise-installed Python binary

        Points to the actual binary via mise's "latest" symlink rather than
        the shim. Shims are symlinks to the mise binary itself, which the
        VS Code Python extension cannot resolve as a valid interpreter.
        """
        vscode_settings = devcontainer_json.get("customizations", {}).get("vscode", {}).get("settings", {})
        interpreter_path = vscode_settings.get("python.defaultInterpreterPath", "")
        assert "mise/installs/python" in interpreter_path, (
            f"python.defaultInterpreterPath should reference mise-installed Python binary, got: {interpreter_path}"
        )

    def test_python_interpreter_not_mise_shim(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking python.defaultInterpreterPath value
        Then: Path does NOT use mise shims

        Shims are symlinks to the mise binary. The VS Code Python extension
        tries to validate the interpreter and fails because it's not a real
        Python binary, producing a "could not be resolved" warning on startup.
        """
        vscode_settings = devcontainer_json.get("customizations", {}).get("vscode", {}).get("settings", {})
        interpreter_path = vscode_settings.get("python.defaultInterpreterPath", "")
        assert "mise/shims" not in interpreter_path, (
            f"python.defaultInterpreterPath should not use mise shims "
            f"(VS Code Python extension can't resolve them), got: {interpreter_path}"
        )

    def test_python_interpreter_uses_absolute_path(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking python.defaultInterpreterPath value
        Then: Path is absolute, not using tilde (~) expansion

        HOME is set dynamically by common-utils at runtime, not as a Docker
        ENV. Tilde expansion fails when the Python extension activates before
        HOME is available, producing a "could not be resolved" warning.
        """
        vscode_settings = devcontainer_json.get("customizations", {}).get("vscode", {}).get("settings", {})
        interpreter_path = vscode_settings.get("python.defaultInterpreterPath", "")
        assert interpreter_path.startswith("/"), (
            f"python.defaultInterpreterPath must be an absolute path (no ~ expansion), got: {interpreter_path}"
        )

    def test_python_interpreter_not_usr_local(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking python.defaultInterpreterPath value
        Then: Path does NOT reference /usr/local/python/current

        The old devcontainer Python feature installed to /usr/local/python/current.
        The refactor uses mise instead.
        """
        vscode_settings = devcontainer_json.get("customizations", {}).get("vscode", {}).get("settings", {})
        interpreter_path = vscode_settings.get("python.defaultInterpreterPath", "")
        assert "/usr/local/python/current" not in interpreter_path, (
            f"python.defaultInterpreterPath should not use "
            f"/usr/local/python/current (old devcontainer feature path), "
            f"got: {interpreter_path}"
        )


# =============================================================================
# TestDevcontainerJsonVscodeExtensions
# =============================================================================


class TestDevcontainerJsonVscodeExtensions:
    """
    Validate VSCode extensions configuration.

    Required extensions:
    - ms-python.python (explicit install for reliable activation timing)
    - bierner.markdown-mermaid
    - charliermarsh.ruff
    - redhat.vscode-yaml
    """

    def test_extensions_array_exists(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking for vscode extensions array
        Then: Extensions array exists and is non-empty

        The devcontainer should specify required extensions for the project.
        """
        extensions = devcontainer_json.get("customizations", {}).get("vscode", {}).get("extensions", [])
        assert isinstance(extensions, list), "devcontainer.json vscode extensions should be a list"
        assert len(extensions) > 0, "devcontainer.json vscode extensions should be non-empty"

    def test_required_extensions_present(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking vscode extensions list
        Then: Required extensions are present

        Required for CoSAI Risk Map development:
        - ms-python.python (interpreter discovery, test runner)
        - bierner.markdown-mermaid (Mermaid diagram preview)
        - charliermarsh.ruff (Python linting/formatting)
        - redhat.vscode-yaml (YAML validation)

        ms-python.python is installed explicitly (rather than as a transitive
        dependency of ruff) so its activation timing is controlled by the
        devcontainer lifecycle.
        """
        extensions = devcontainer_json.get("customizations", {}).get("vscode", {}).get("extensions", [])
        required = [
            "ms-python.python",
            "bierner.markdown-mermaid",
            "charliermarsh.ruff",
            "redhat.vscode-yaml",
        ]
        for ext in required:
            assert ext in extensions, f"devcontainer.json vscode extensions should include {ext}"


# =============================================================================
# TestDevcontainerJsonBuildConfig
# =============================================================================


class TestDevcontainerJsonBuildConfig:
    """
    Validate devcontainer build configuration.

    Checks:
    - remoteUser is "vscode"
    - build.args contains WORKSPACE and WORKSPACE_REPO
    - build.context is ".." (repo root, not .devcontainer/)
    - build.dockerfile is "Dockerfile"
    """

    def test_remote_user_is_vscode(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking remoteUser setting
        Then: remoteUser is "vscode"

        The common-utils feature creates a vscode user, and the devcontainer
        should run as that user.
        """
        remote_user = devcontainer_json.get("remoteUser", "")
        assert remote_user == "vscode", f"devcontainer.json remoteUser should be 'vscode', got: {remote_user}"

    def test_build_args_contain_workspace(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking build.args
        Then: WORKSPACE and WORKSPACE_REPO args are present

        The Dockerfile expects these ARGs to configure the workspace path
        structure.
        """
        build_args = devcontainer_json.get("build", {}).get("args", {})
        assert "WORKSPACE" in build_args, "devcontainer.json build.args should include WORKSPACE"
        assert "WORKSPACE_REPO" in build_args, "devcontainer.json build.args should include WORKSPACE_REPO"

    def test_build_context_is_parent(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking build.context
        Then: build.context is ".." (repo root)

        The build context is widened to the repo root so the Dockerfile
        can COPY .mise.toml and install mise during the build.
        """
        build_context = devcontainer_json.get("build", {}).get("context")
        assert build_context == "..", f"devcontainer.json build.context should be '..', got: {build_context}"

    def test_build_dockerfile_path(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking build.dockerfile
        Then: build.dockerfile is "Dockerfile"

        With a widened build context, the dockerfile path is specified
        explicitly via the build.dockerfile key (not the top-level
        dockerFile key).
        """
        build_dockerfile = devcontainer_json.get("build", {}).get("dockerfile")
        assert build_dockerfile == "Dockerfile", (
            f"devcontainer.json build.dockerfile should be 'Dockerfile', got: {build_dockerfile}"
        )


# =============================================================================
# TestDevcontainerJsonRemoteEnv
# =============================================================================


class TestDevcontainerJsonRemoteEnv:
    """
    Validate remoteEnv configuration for VS Code Server process environment.

    The VS Code Server starts before onCreateCommand runs, capturing the
    container's initial environment. Without remoteEnv, the server's PATH
    lacks mise shims, causing the Python extension to fail interpreter
    validation until a manual "Reload Window".

    remoteEnv injects environment variables directly into the VS Code Server
    process, independent of ~/.bashrc.
    """

    def test_remote_env_exists(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking for remoteEnv
        Then: remoteEnv key exists and is a dict

        remoteEnv is required to inject mise shim paths into the VS Code
        Server process environment so extensions can find tools without
        requiring a manual "Reload Window" after container build.
        """
        remote_env = devcontainer_json.get("remoteEnv")
        assert remote_env is not None, (
            "devcontainer.json should have remoteEnv to inject mise paths into VS Code Server environment"
        )
        assert isinstance(remote_env, dict), (
            f"devcontainer.json remoteEnv should be a dict, got: {type(remote_env)}"
        )

    def test_remote_env_path_includes_mise_shims(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking remoteEnv PATH value
        Then: PATH includes mise shims directory

        The mise shims directory contains symlinks for python, node, etc.
        It must be on the VS Code Server's PATH so extensions (especially
        the Python extension) can resolve tools from any working directory.
        """
        remote_env = devcontainer_json.get("remoteEnv", {})
        path_value = remote_env.get("PATH", "")
        assert "mise/shims" in path_value, f"remoteEnv PATH should include mise shims directory, got: {path_value}"

    def test_remote_env_path_includes_mise_bin(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking remoteEnv PATH value
        Then: PATH includes .local/bin (where mise binary lives for user installs)

        The .local/bin directory contains the mise binary itself when
        installed per-user. Including it ensures mise commands work in
        VS Code terminals without sourcing ~/.bashrc.
        """
        remote_env = devcontainer_json.get("remoteEnv", {})
        path_value = remote_env.get("PATH", "")
        assert ".local/bin" in path_value, f"remoteEnv PATH should include .local/bin directory, got: {path_value}"

    def test_remote_env_path_no_containerenv_home(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking remoteEnv PATH for ${containerEnv:HOME} usage
        Then: PATH does NOT use ${containerEnv:HOME}

        ${containerEnv:HOME} resolves to an empty string because HOME is not
        set as a Docker ENV at the time remoteEnv is evaluated (it is set
        dynamically by common-utils at runtime). This produces broken paths
        like /.local/share/mise/shims instead of /home/vscode/.local/share/
        mise/shims. Hardcoded /home/vscode is used instead, which is safe
        because remoteUser is already set to vscode.
        """
        remote_env = devcontainer_json.get("remoteEnv", {})
        path_value = remote_env.get("PATH", "")
        assert "${containerEnv:HOME}" not in path_value, (
            f"remoteEnv PATH should not use ${{containerEnv:HOME}} (resolves to "
            f"empty string), use hardcoded /home/vscode instead. Got: {path_value}"
        )

    def test_remote_env_path_preserves_existing(self, devcontainer_json):
        """
        Given: The devcontainer.json config
        When: Checking remoteEnv PATH value
        Then: PATH references containerEnv:PATH to preserve existing PATH entries

        remoteEnv PATH must append to (not replace) the container's existing
        PATH, otherwise system tools like git, curl, etc. would be lost.
        """
        remote_env = devcontainer_json.get("remoteEnv", {})
        path_value = remote_env.get("PATH", "")
        assert "${containerEnv:PATH}" in path_value, (
            f"remoteEnv PATH should reference ${{containerEnv:PATH}} to preserve existing PATH, got: {path_value}"
        )


"""
Test Summary
============
Total Test Classes: 7
Total Test Methods: 33

1. TestDevcontainerJsonExists (2): file exists, parses as valid JSON
2. TestDevcontainerJsonFeatures (11): no Python feature, no Node feature,
   Docker-in-Docker present, Git feature present with latest version and PPA
   enabled, common-utils present, username vscode, automatic uid,
   automatic gid, no zsh
3. TestDevcontainerJsonCommands (4): onCreateCommand exists,
   onCreateCommand references install-deps.sh, no direct pip/npm,
   no postCreateCommand
4. TestDevcontainerJsonPythonConfig (5): interpreter path exists, uses mise
   install path, uses absolute path, does not use mise shims, not
   /usr/local/python/current
5. TestDevcontainerJsonVscodeExtensions (2): extensions array exists,
   required extensions present (including ms-python.python)
6. TestDevcontainerJsonBuildConfig (4): remoteUser is vscode,
   build.args has WORKSPACE/WORKSPACE_REPO, build.context is "..",
   build.dockerfile is "Dockerfile"
7. TestDevcontainerJsonRemoteEnv (5): remoteEnv exists, PATH includes
   mise shims, PATH includes .local/bin, no ${containerEnv:HOME},
   PATH preserves existing PATH

Coverage Areas:
- File existence and JSON validity
- Feature configuration (Python/Node removed, Git added, Docker-in-Docker kept, common-utils added)
- Lifecycle commands (onCreateCommand uses install-deps.sh, postCreateCommand absent)
- Python interpreter configuration (mise install path, not the shim)
- VSCode extensions (ms-python.python, markdown-mermaid, ruff, yaml)
- Build configuration (remoteUser, build.args, context, dockerfile)
- Remote environment (hardcoded /home/vscode paths, no broken ${containerEnv:HOME})
"""
