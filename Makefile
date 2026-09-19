BINARY  := sshsignhost
DIST    := dist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"
OS      ?= $(shell go env GOOS)
ARCH    ?= $(shell go env GOARCH)

.PHONY: all build test lint fmt pre-commit clean install completions rpm rpm-package patch minor major _tag

all: build

build:
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build $(GOFLAGS) -o $(DIST)/$(BINARY) .

test:
	go test -v -race ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

pre-commit:
	pre-commit run --all-files

clean:
	rm -rf $(DIST) $(BINARY)

install:
	go install $(GOFLAGS) .

completions: build
	@mkdir -p $(DIST)/completions
	$(DIST)/$(BINARY) completion bash > $(DIST)/completions/$(BINARY).bash
	$(DIST)/$(BINARY) completion zsh  > $(DIST)/completions/_$(BINARY)
	$(DIST)/$(BINARY) completion fish > $(DIST)/completions/$(BINARY).fish

rpm: build rpm-package

rpm-package:
	./scripts/build-rpm.sh $(VERSION)

# Bump helpers -- read the latest semver tag and create the next one.
_LATEST := $(shell git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -1)
_BASE   := $(if $(_LATEST),$(_LATEST),v0.0.0)
_MAJ    := $(shell echo $(_BASE) | sed 's/^v//' | cut -d. -f1)
_MIN    := $(shell echo $(_BASE) | sed 's/^v//' | cut -d. -f2)
_PAT    := $(shell echo $(_BASE) | sed 's/^v//' | cut -d. -f3)

patch:
	@NEW=v$(_MAJ).$(_MIN).$(shell expr $(_PAT) + 1); \
	git tag $$NEW && echo "Tagged $$NEW" && $(MAKE) _tag TAG=$$NEW

minor:
	@NEW=v$(_MAJ).$(shell expr $(_MIN) + 1).0; \
	git tag $$NEW && echo "Tagged $$NEW" && $(MAKE) _tag TAG=$$NEW

major:
	@NEW=v$(shell expr $(_MAJ) + 1).0.0; \
	git tag $$NEW && echo "Tagged $$NEW" && $(MAKE) _tag TAG=$$NEW

_tag:
	git push origin $(TAG)
