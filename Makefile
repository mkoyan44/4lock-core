# 4lock-core Makefile (same approach as 4lock-api: nerdctl, TARGET_ARCH, docker/ layout)

PROJECT_NAME := $(shell git rev-parse --show-toplevel | awk -F/ '{print $$NF}')
BRANCH_NAME := $(shell git rev-parse --abbrev-ref HEAD)
REPO_ROOT := $(shell git rev-parse --show-toplevel)
CODE_BASE_PATH ?= ${REPO_ROOT}
NAMESPACE ?= ${PROJECT_NAME}

.NOTPARALLEL:
SHELL := /bin/bash
.EXPORT_ALL_VARIABLES:

# .env optional; used for GH_OWNER/GH_TOKEN (push) and to override TARGET_ARCH
ENV_FILE := ${REPO_ROOT}/.env
ifneq (,$(wildcard $(ENV_FILE)))
  ifeq ($(shell test -s $(ENV_FILE) && echo non-empty || echo empty), non-empty)
    include $(ENV_FILE)
    export $(shell sed 's/=.*//' $(ENV_FILE))
  endif
endif

# TARGET_ARCH: from .env, or auto-detect from host (uname -m)
# aarch64/arm64 -> arm64, x86_64/amd64 -> amd64
HOST_ARCH := $(shell uname -m)
TARGET_ARCH ?= $(if $(filter aarch64 arm64,$(HOST_ARCH)),arm64,amd64)

ifeq ($(filter $(TARGET_ARCH),arm64 amd64),)
	$(error "TARGET_ARCH must be arm64 or amd64. Got: $(TARGET_ARCH) (HOST_ARCH=$(HOST_ARCH)). Set in .env to override.")
endif
export TARGET_ARCH

REGISTRY_FQDN := ghcr.io
COMPOSED_BUILD_ARGS := --build-arg TARGET_ARCH=$(TARGET_ARCH)
IMAGE_TAG := $(if $(VERSION),$(VERSION),latest)

# Registry image for push; local image for build/run when GH_OWNER not set
IMAGE_NAME := $(if $(GH_OWNER),${REGISTRY_FQDN}/${GH_OWNER}/4lock-core-${TARGET_ARCH},4lock-core)

# -----------------------------------------------------------------------------
# Default: build then run (so "make" with no target does this)
# -----------------------------------------------------------------------------
default: from-scratch

# -----------------------------------------------------------------------------
# Build and push
# -----------------------------------------------------------------------------
nerdctl-build:
	nerdctl build -f docker/dockerfiles/Dockerfile.core $(COMPOSED_BUILD_ARGS) -t ${IMAGE_NAME}:${IMAGE_TAG} .

nerdctl-push:
	@test -n "$(GH_OWNER)" || (echo "GH_OWNER and GH_TOKEN required for push. Set in .env."; exit 1)
	@test -n "$(GH_TOKEN)" || (echo "GH_TOKEN required for push. Set in .env."; exit 1)
	nerdctl push ${IMAGE_NAME}:${IMAGE_TAG}

sudo-build:
	sudo nerdctl build -f docker/dockerfiles/Dockerfile.core $(COMPOSED_BUILD_ARGS) -t ${IMAGE_NAME}:${IMAGE_TAG} .

sudo-push:
	@test -n "$(GH_OWNER)" || (echo "GH_OWNER and GH_TOKEN required for push. Set in .env."; exit 1)
	@test -n "$(GH_TOKEN)" || (echo "GH_TOKEN required for push. Set in .env."; exit 1)
	sudo nerdctl push ${IMAGE_NAME}:${IMAGE_TAG}

build: nerdctl-build
push: nerdctl-push
all: build push

# Dev profile: fast recompile when changing src/ (cache mounts + dev-fast profile). Tag :dev.
nerdctl-build-dev:
	nerdctl build -f docker/dockerfiles/Dockerfile.core $(COMPOSED_BUILD_ARGS) --build-arg BUILD_PROFILE=dev -t ${IMAGE_NAME}:dev .
build-dev: nerdctl-build-dev

# Container name for run/run-dev so we can stop it on Ctrl+C
RUN_NAME := 4lock-core-run

# Run the built image. Detached + logs -f so Ctrl+C stops the container and exits.
# nerdctl does not allow -d and --rm together; we remove the container explicitly after stop.
# --privileged required for network/user namespaces (pasta, rootless containers).
run:
	@-nerdctl rm -f $(RUN_NAME) 2>/dev/null || true
	nerdctl run -d --name $(RUN_NAME) --privileged -v /tmp/vappc:/tmp ${IMAGE_NAME}:${IMAGE_TAG}
	@trap 'nerdctl stop $(RUN_NAME) 2>/dev/null; nerdctl rm -f $(RUN_NAME) 2>/dev/null' INT TERM; nerdctl logs -f $(RUN_NAME); nerdctl stop $(RUN_NAME) 2>/dev/null || true; nerdctl rm -f $(RUN_NAME) 2>/dev/null || true

run-dev:
	@-nerdctl rm -f $(RUN_NAME) 2>/dev/null || true
	nerdctl run -d --name $(RUN_NAME) --privileged -v /tmp/vappc:/tmp ${IMAGE_NAME}:dev
	@trap 'nerdctl stop $(RUN_NAME) 2>/dev/null; nerdctl rm -f $(RUN_NAME) 2>/dev/null' INT TERM; nerdctl logs -f $(RUN_NAME); nerdctl stop $(RUN_NAME) 2>/dev/null || true; nerdctl rm -f $(RUN_NAME) 2>/dev/null || true

# From scratch: build then run (release image).
from-scratch: build
	$(MAKE) run
