# Multi-stage build matching upstream ASH v3 beta Dockerfile
# Based on: https://github.com/awslabs/automated-security-helper/blob/beta/Dockerfile
ARG BASE_IMAGE=public.ecr.aws/docker/library/python:3.12-bullseye

# First stage: Build poetry requirements
FROM ${BASE_IMAGE} AS poetry-reqs

ENV PYTHONDONTWRITEBYTECODE=1
RUN apt-get clean && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3-venv git tree && \
    rm -rf /var/lib/apt/lists/*

# Clone the real ASH v3 beta source
ARG INSTALL_ASH_REVISION="beta"
ARG ASH_REPO_CLONE_URL="https://github.com/awslabs/automated-security-helper.git"
ENV INSTALL_ASH_REVISION=${INSTALL_ASH_REVISION}
ENV ASH_REPO_CLONE_URL=${ASH_REPO_CLONE_URL}
RUN python3 -m pip install -U pip poetry

WORKDIR /src
# Always clone the real ASH source for a working installation
RUN git clone \
        --branch ${INSTALL_ASH_REVISION} \
        ${ASH_REPO_CLONE_URL} \
        .

# Build the real ASH wheel
RUN tree .
RUN git status --short || true
RUN poetry build
RUN python -m pip install poetry-plugin-export
RUN poetry export --without-hashes --format=requirements.txt > requirements.txt

# Second stage: Core ASH image
FROM ${BASE_IMAGE} AS core
SHELL ["/bin/bash", "-c"]
ARG BUILD_DATE_EPOCH="-1"
ARG OFFLINE="NO"
ARG OFFLINE_SEMGREP_RULESETS="p/ci"
ARG ASH_BIN_PATH="/.ash/bin"

ARG INSTALL_ASH_REVISION="LOCAL"
ENV INSTALL_ASH_REVISION=${INSTALL_ASH_REVISION}

ENV ASH_BIN_PATH="${ASH_BIN_PATH}"
ENV BUILD_DATE_EPOCH="${BUILD_DATE_EPOCH}"
ENV OFFLINE="${OFFLINE}"
ENV OFFLINE_AT_BUILD_TIME="${OFFLINE}"
ENV ASH_OFFLINE="${OFFLINE}"
ENV ASH_OFFLINE_AT_BUILD_TIME="${OFFLINE}"
ENV OFFLINE_SEMGREP_RULESETS="${OFFLINE_SEMGREP_RULESETS}"
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# General / shared component installation
WORKDIR /deps

# Add GitHub's public fingerprints to known_hosts to prevent fingerprint confirmation requests
RUN mkdir -p ${HOME}/.ssh && \
    echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" >> ${HOME}/.ssh/known_hosts && \
    echo "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=" >> ${HOME}/.ssh/known_hosts && \
    echo "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=" >> ${HOME}/.ssh/known_hosts

# Base dependency installation
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
      curl \
      python3-venv \
      git \
      ripgrep \
      ruby-dev \
      tree && \
    rm -rf /var/lib/apt/lists/*

# Install nodejs@20 using latest recommended method
RUN set -uex; \
    apt-get update; \
    apt-get install -y ca-certificates curl gnupg; \
    mkdir -p /etc/apt/keyrings; \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; \
    NODE_MAJOR=20; \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" > /etc/apt/sources.list.d/nodesource.list; \
    apt-get -qy update; \
    apt-get -qy install nodejs;

# Python (no-op other than updating pip --- Python deps managed via Poetry @ pyproject.toml)
RUN wget https://bootstrap.pypa.io/get-pip.py && python3 get-pip.py
RUN python3 -m pip install --no-cache-dir --upgrade pip

# cfn-nag
RUN echo "gem: --no-document" >> /etc/gemrc && \
    gem install cfn-nag

# JavaScript:
RUN npm install -g npm pnpm yarn

# Grype/Syft/Semgrep - Also sets default location env vars for root user for CI compat
ENV GRYPE_DB_CACHE_DIR="/deps/.grype"
ENV SEMGREP_RULES_CACHE_DIR="/deps/.semgrep"
RUN mkdir -p ${GRYPE_DB_CACHE_DIR} ${SEMGREP_RULES_CACHE_DIR}
ENV PATH="/usr/local/bin:$PATH"

RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
    sh -s -- -b /usr/local/bin
RUN syft --version

RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
    sh -s -- -b /usr/local/bin
RUN grype --version

RUN set -uex; if [[ "${OFFLINE}" == "YES" ]]; then \
        grype db update && \
        mkdir -p ${SEMGREP_RULES_CACHE_DIR} && \
        for i in $OFFLINE_SEMGREP_RULESETS; do curl "https://semgrep.dev/c/${i}" -o "${SEMGREP_RULES_CACHE_DIR}/$(basename "${i}").yml"; done \
    fi

# Setting default WORKDIR to /src
WORKDIR /src

# Make sure the default dirs are initialized
RUN mkdir -p /src && \
    mkdir -p /out && \
    mkdir -p /ash/utils && \
    mkdir -p ${ASH_BIN_PATH}

# Limit memory size available for Node to prevent segmentation faults during npm install
ENV NODE_OPTIONS=--max_old_space_size=512

# COPY ASH source to /ash instead of / to isolate
COPY --from=poetry-reqs /src/dist/*.whl .
COPY --from=poetry-reqs /src/requirements.txt .
RUN python -m pip install -r requirements.txt && \
    python -m pip install *.whl --no-deps && \
    rm -rf *.whl requirements.txt

# Make sure the ash script is executable
RUN chmod -R 755 /ash && chmod -R 777 /src /out /deps ${ASH_BIN_PATH}

# Flag ASH as local execution mode since we are running in a container already
ENV _ASH_EXEC_MODE="local"

# Install dependencies via ASH CLI
RUN ash dependencies install --bin-path "${ASH_BIN_PATH}"
ENV PATH="${ASH_BIN_PATH}:$PATH"

# Flag ASH as running in container to prevent ProgressBar panel from showing (causes output blocking)
ENV ASH_IN_CONTAINER="YES"

# CI stage -- any customizations specific to CI platform compatibility should be added
# in this stage if it is not applicable to ASH outside of CI usage
FROM core AS ci

ENV ASH_TARGET=ci

# GitHub Actions stage - Add GitHub Actions specific dependencies and integration
FROM ci AS github-actions

# Install GitHub Actions specific dependencies (minimal set)
RUN apt-get update && apt-get install -y \
    jq \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies for GitHub Actions integration (updated versions)
RUN pip3 install --no-cache-dir \
    jinja2==3.1.4 \
    requests==2.32.3 \
    pyyaml==6.0.2

# Copy action source code
COPY src/ /action/src/
COPY scripts/ /action/scripts/

# Make scripts executable
RUN chmod +x /action/scripts/entrypoint.sh

# Set working directory and entrypoint
WORKDIR /action
ENTRYPOINT ["/action/scripts/entrypoint.sh"]
