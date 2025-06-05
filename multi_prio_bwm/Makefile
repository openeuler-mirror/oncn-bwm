.DEFAULT_GOAL := all

## all: make everything
.PHONY: all
all: generate bin image update-yaml

GIT_COMMIT := $(shell git rev-parse --short HEAD)
IMAGE_NAME := bwm

TARGET = bwmctl bwm-cni bwm-daemon alg-daemon

BIN_DIR = bin
PKG_DIR = pkg

CTL_DIR = cmd/cmdctl
CNI_DIR = cmd/cni-plugin
DAEMON_DIR = cmd/daemon
ALG_DAEMON_DIR = cmd/alg-daemon

K8S_YAML_FILE = install/kubernetes/oncn-bwm.yaml

define USAGE_OPTIONS

Options:
  PLATFORMS        The multiple platforms to build. Default is depend on your os's arch.
                   Example: make PLATFORMS="amd64" or make PLATFORMS="arm64"
  CUSTOM           Company-customized compiling options
                   Example: make CUSTOM="DAHUA"
endef
export USAGE_OPTIONS

ifeq ($(shell uname -m),x86_64)
	PLATFORMS ?= amd64
else ifeq ($(shell uname -m),aarch64)
	PLATFORMS ?= arm64
endif

CUSTOM ?= ""

## bwmctl: Build source code for bwmctl cli tool binary.
.PHONY: bwmctl
bwmctl:
		GOOS=linux GOARCH=$(PLATFORMS) go build -mod=vendor -tags=$(CUSTOM) -o $(CURDIR)/bin/$@ $(CURDIR)/$(CTL_DIR)/main.go

## bwm-cni: Build source code for bwm-cni binary.
.PHONY: bwm-cni
bwm-cni:
		GOOS=linux GOARCH=$(PLATFORMS) go build -mod=vendor -tags=$(CUSTOM) -o $(CURDIR)/bin/$@ -ldflags "-X 'main.Gitversion=$(GIT_COMMIT)'" $(CURDIR)/$(CNI_DIR)/main.go

## bwm-daemon: Build source code for bwm-daemon daemonproc binary.
.PHONY: bwm-daemon
bwm-daemon:
		GOOS=linux GOARCH=$(PLATFORMS) go build -mod=vendor -tags=$(CUSTOM) -o $(CURDIR)/bin/$@ $(CURDIR)/$(DAEMON_DIR)/main.go

## bwm-daemon: Build source code for bwm-daemon daemonproc binary.
.PHONY: alg-daemon
alg-daemon:
		GOOS=linux GOARCH=$(PLATFORMS) go build -mod=vendor -tags=$(CUSTOM) -o $(CURDIR)/bin/$@ -ldflags "-X 'oncn-bwm/pkg/tc.Custom=$(CUSTOM)'" $(CURDIR)/$(ALG_DAEMON_DIR)/main.go

## image: Build image for oncn-bwm.
.PHONY: image
image: $(TARGET)
		docker build --build-arg TARGETARCH=$(PLATFORMS) -t $(IMAGE_NAME):$(GIT_COMMIT) . -f=build/Dockerfile

## bin: Build all binary.
.PHONY: bin
bin: $(TARGET)

## generate: auto generate code for project.
.PHONY: generate
generate:
		@if [ "$(CUSTOM)" = "DAHUA" ]; then \
			sed -i '/^#define CUSTOM_MARK_SKB\b/ s/.*/#define CUSTOM_MARK_SKB 1/' $(CURDIR)/pkg/bpfgo/bpf/include/tc_edt.h; \
		else \
			sed -i '/^#define CUSTOM_MARK_SKB\b/ s/.*/#define CUSTOM_MARK_SKB 0/' $(CURDIR)/pkg/bpfgo/bpf/include/tc_edt.h; \
		fi
		-mv vendor vendor-bak
		go generate pkg/bpfgo/gen.go
		mv vendor-bak vendor

## update-yaml: update install/kubernetes/oncn-bwm.yaml.
.PHONY: update-yaml
update-yaml:
		sed -i 's|image: ".*"|image: "$(IMAGE_NAME):$(GIT_COMMIT)"|' $(K8S_YAML_FILE)

## clean: Remove all files that are created by building.
.PHONY: clean
clean:
		@-rm -vrf $(BIN_DIR)

## help: Show this help info.
.PHONY: help
help: Makefile
	@printf "\nUsage: make <TARGETS> <OPTIONS> ...\n\nTargets:\n"
	@sed -n 's/^##//p' $< | column -t -s ':' | sed -e 's/^/ /'
	@echo "$$USAGE_OPTIONS"
