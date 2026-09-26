SHELL := /bin/bash
GO ?= go
GOFMT = $(shell $(GO) env GOROOT)/bin/gofmt
DIST ?= dist
GOVULNCHECK ?= golang.org/x/vuln/cmd/govulncheck@v1.8.0
ARCH ?= $(shell $(GO) env GOARCH)
PACKAGED = $(DIST)/linux-$(ARCH)/seagull-agent

# Every gate verifies the module graph go.mod pins, never a local workspace
# that points at sibling checkouts.
export GOWORK := off

.PHONY: help fmt fmt-check vet mod-check lint test test-race build package native-gate vulncheck clean verify

help:
	@echo "fmt         format the module"
	@echo "fmt-check   fail when the module is not formatted"
	@echo "vet         run go vet"
	@echo "mod-check   verify the dependency graph and checksums"
	@echo "lint        fmt-check and vet"
	@echo "test        run the unit, architecture and compatibility suites"
	@echo "test-race   run the same suites under the race detector"
	@echo "build       build the agent into $(DIST)"
	@echo "package     build the Debian package of the commit checked out into $(DIST)/deb"
	@echo "native-gate install that package on THIS host, as root, and run it as a service: use a disposable host"
	@echo "vulncheck   scan reachable dependencies"
	@echo "verify      the full gate: lint, mod-check, tests and build"

fmt:
	$(GO) fmt ./...

fmt-check:
	@out="$$($(GOFMT) -l .)"; \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

mod-check:
	$(GO) mod verify
	$(GO) mod tidy -diff

lint: fmt-check vet

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

build:
	@mkdir -p $(DIST)
	$(GO) build -trimpath -o $(DIST)/seagull-agent ./cmd/seagull-agent

package:
	@mkdir -p $(dir $(PACKAGED))
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -trimpath -o $(PACKAGED) ./cmd/seagull-agent
	rm -rf $(DIST)/deb
	$(GO) run ./packaging -binary $(PACKAGED) -out $(DIST)/deb

native-gate:
	@test "$(words $(wildcard $(DIST)/deb/*.deb))" = 1 || { echo "$(DIST)/deb holds no single package: make package first" >&2; exit 1; }
	$(GO) test -c -o $(DIST)/native.test ./tests/native
	sudo $(DIST)/native.test -test.v -test.count=1 -test.timeout=15m -package "$(abspath $(wildcard $(DIST)/deb/*.deb))"

vulncheck:
	$(GO) run $(GOVULNCHECK) ./...

clean:
	rm -rf $(DIST)

verify: lint mod-check test test-race build
