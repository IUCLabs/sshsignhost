BINARY  := sshsignhost
DIST    := dist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"
OS      ?= $(shell go env GOOS)
ARCH    ?= $(shell go env GOARCH)

.PHONY: all build test lint fmt pre-commit clean install integration-test snapshot release-check patch minor major

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
	rm -rf $(DIST) completions $(BINARY)

install:
	go install $(GOFLAGS) .

# Signs a host key against a throwaway dev-mode Vault; needs docker or podman.
integration-test:
	./scripts/integration-test.sh

# Binaries, the RPM and the release assets all come out of goreleaser.
snapshot:
	goreleaser release --snapshot --clean

release-check:
	goreleaser check

DEFAULT_BRANCH ?= main

# Draft the release with generated notes, then push the tag; the release
# workflow attaches assets to the draft and publishes it.
patch minor major:
	@git fetch --quiet --tags origin $(DEFAULT_BRANCH)
	@test "$$(git branch --show-current)" = "$(DEFAULT_BRANCH)" || { echo "ERROR: not on $(DEFAULT_BRANCH)"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "ERROR: working tree not clean"; exit 1; }
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/$(DEFAULT_BRANCH))" || { echo "ERROR: HEAD is not origin/$(DEFAULT_BRANCH)"; exit 1; }
	@LATEST=$$(git tag --list 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -1); \
	NEW=$$(echo "$${LATEST:-v0.0.0}" | sed 's/^v//' | awk -F. -v b=$@ '{ \
		if (b == "major") print "v" ($$1+1) ".0.0"; \
		else if (b == "minor") print "v" $$1 "." ($$2+1) ".0"; \
		else print "v" $$1 "." $$2 "." ($$3+1) }'); \
	SHA=$$(git rev-parse HEAD); \
	gh release create "$$NEW" --draft --target "$$SHA" --generate-notes --title "$$NEW" || exit 1; \
	git push origin "$$SHA:refs/tags/$$NEW" || { gh release delete "$$NEW" --yes; exit 1; }
