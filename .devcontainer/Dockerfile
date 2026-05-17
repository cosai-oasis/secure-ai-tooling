FROM ubuntu:noble

ARG WORKSPACE=/workspaces
ARG WORKSPACE_REPO=secure-ai-tooling

# Install system packages: core utilities + Playwright Chromium system dependencies
# Core: build-essential, bash-completion, vim, curl, wget, git, ca-certificates
# Note: sudo is provided by the common-utils devcontainer feature, not installed here
# Playwright deps: 31 packages needed by Chromium on Ubuntu Noble (with t64 suffixes)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    bash-completion \
    vim \
    curl \
    wget \
    git \
    ca-certificates \
    libasound2t64 \
    libatk-bridge2.0-0t64 \
    libatk1.0-0t64 \
    libatspi2.0-0t64 \
    libcairo2 \
    libcups2t64 \
    libdbus-1-3 \
    libdrm2 \
    libegl1 \
    libgbm1 \
    libglib2.0-0t64 \
    libgtk-3-0t64 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xvfb \
    fonts-noto-color-emoji \
    fonts-unifont \
    libfontconfig1 \
    libfreetype6 \
    libharfbuzz0b \
    && rm -rf /var/lib/apt/lists/*

# Install mise binary system-wide (cached in Docker layer).
# Binary is used both here (build-time tool install) and by install-deps.sh.
RUN curl -fsSL https://mise.run | MISE_INSTALL_PATH=/usr/local/bin/mise sh

# Create workspace directory (user creation handled by common-utils feature)
RUN mkdir -p ${WORKSPACE}/${WORKSPACE_REPO}

# Copy .mise.toml so mise can read tool versions during onCreateCommand
# (overwritten by workspace mount, but available during build)
COPY .mise.toml ${WORKSPACE}/${WORKSPACE_REPO}/.mise.toml

WORKDIR ${WORKSPACE}/${WORKSPACE_REPO}

# Create vscode user for build-time tool installation.
# common-utils feature re-creates/configures this user at runtime;
# the || true makes this idempotent with that later creation.
ARG USERNAME=vscode
RUN useradd -m -d /home/${USERNAME} -s /bin/bash ${USERNAME} 2>/dev/null || true

# Install Python, Node.js, and uv via mise during Docker build so binaries and
# shims exist when the container starts. This eliminates the race condition
# where VS Code's Python extension activates before onCreateCommand installs
# Python via install-deps.sh.
USER ${USERNAME}
ENV HOME=/home/${USERNAME}
# Versions are derived from .mise.toml via `mise current` after install,
# keeping .mise.toml as the single source of truth for tool versions.
RUN mise trust .mise.toml && \
    mise install && \
    mise reshim && \
    mise use -g python@$(mise current python | cut -d. -f1-2) && \
    mise use -g node@$(mise current node | cut -d. -f1) && \
    mise use -g uv@$(mise current uv)
USER root
