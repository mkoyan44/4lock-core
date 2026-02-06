# 4lock-core Makefile (same approach as 4lock-api: nerdctl, TARGET_ARCH, docker/ layout)

PROJECT_NAME := $(shell git rev-parse --show-toplevel | awk -F/ '{print $$NF}')
BRANCH_NAME := $(shell git rev-parse --abbrev-ref HEAD)
REPO_ROOT := $(shell git rev-parse --show-toplevel)
CODE_BASE_PATH ?= ${REPO_ROOT}
NAMESPACE ?= ${PROJECT_NAME}

.NOTPARALLEL:
SHELL := /bin/bash
.EXPORT_ALL_VARIABLES:

# Check if .env file exists and is not empty (required for push; used for build context)
ENV_FILE := ${REPO_ROOT}/.env

ifeq (,$(wildcard $(ENV_FILE)))
	$(error ".env file not found at $(ENV_FILE). Copy .env.example to .env and set GH_TOKEN, GH_OWNER, TARGET_ARCH.")
endif

ifeq ($(shell test -s $(ENV_FILE) && echo non-empty || echo empty), empty)
	$(error ".env file is empty at $(ENV_FILE)")
endif

include $(ENV_FILE)
export $(shell sed 's/=.*//' $(ENV_FILE))

CRITICAL_VARS := GH_TOKEN GH_OWNER

$(foreach var,$(CRITICAL_VARS),\
	$(if $(filter undefined,$(origin $(var))),\
		$(error "Critical variable $(var) is not set in .env")),))
$(foreach var,$(CRITICAL_VARS),\
	$(if $(shell [ -z "$($(var))" ] && echo empty),\
		$(error "Critical variable $(var) is empty in .env")),))

ifeq ($(filter $(TARGET_ARCH),arm64 amd64),)
	$(error "Invalid TARGET_ARCH value: $(TARGET_ARCH). Must be one of arm64,amd64. Set in .env.")
endif
export TARGET_ARCH

REGISTRY_FQDN := ghcr.io
COMPOSED_BUILD_ARGS := --build-arg TARGET_ARCH=$(TARGET_ARCH)

IMAGE_NAME := ${REGISTRY_FQDN}/${GH_OWNER}/4lock-core-${TARGET_ARCH}
IMAGE_TAG := $(if $(VERSION),$(VERSION),latest)

# -----------------------------------------------------------------------------
# Build and push
# -----------------------------------------------------------------------------
nerdctl-build:
	nerdctl build -f docker/dockerfiles/Dockerfile.core $(COMPOSED_BUILD_ARGS) -t ${IMAGE_NAME}:${IMAGE_TAG} .

nerdctl-push:
	nerdctl push ${IMAGE_NAME}:${IMAGE_TAG}

sudo-build:
	sudo nerdctl build -f docker/dockerfiles/Dockerfile.core $(COMPOSED_BUILD_ARGS) -t ${IMAGE_NAME}:${IMAGE_TAG} .

sudo-push:
	sudo nerdctl push ${IMAGE_NAME}:${IMAGE_TAG}

build: nerdctl-build
push: nerdctl-push
all: build push

# Run the built image (interactive; mount socket dir to access /tmp/vappc.sock on host)
run:
	nerdctl run --rm -it -v /tmp/vappc:/tmp ${IMAGE_NAME}:${IMAGE_TAG}
