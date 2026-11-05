SHELL := /bin/bash
GO ?= go
GOFMT = $(shell $(GO) env GOROOT)/bin/gofmt
DIST ?= dist
GOVULNCHECK ?= golang.org/x/vuln/cmd/govulncheck@v1.9.0
GOSEC ?= github.com/securego/gosec/v2/cmd/gosec@v2.30.0
REPOSITORY ?= dynasmon/Seagull-agent-v2
PLATFORM ?= github.com/dynasmon/Seagull-backend-v2
BACKEND ?=
ANSWERS = tests/e2e/testdata/agent/protocol-1
HELD = tests/compatibility/testdata/backend-$(shell printf %.7s "$(BACKEND)")
FUZZTIME ?= 10s
SOAK ?= 4h
EVIDENCE ?=
ARCH ?= $(shell $(GO) env GOARCH)
PACKAGED = $(DIST)/linux-$(ARCH)/seagull-agent
AHEAD = v1.999.0-gate

# Every gate verifies the module graph go.mod pins, never a local workspace
# that points at sibling checkouts.
export GOWORK := off

.PHONY: help fmt fmt-check vet mod-check lint test test-race fuzz build package ahead native-gate chaos footprint soak vulncheck gosec verify-tag check-protection platform-answers clean verify

help:
	@echo "fmt         format the module"
	@echo "fmt-check   fail when the module is not formatted"
	@echo "vet         run go vet"
	@echo "mod-check   verify the dependency graph and checksums"
	@echo "lint        fmt-check and vet"
	@echo "test        run the unit, architecture and compatibility suites"
	@echo "test-race   run the same suites under the race detector"
	@echo "fuzz        run every fuzz target for FUZZTIME ($(FUZZTIME)); an input that fails is kept under the package's testdata/fuzz"
	@echo "build       build the agent into $(DIST)"
	@echo "package     build the Debian package of the commit checked out, and its SPDX bill of materials, into $(DIST)/deb"
	@echo "ahead       package the same commit as release $(AHEAD) into $(DIST)/ahead, which the native gate updates the agent to"
	@echo "native-gate install that package on THIS host, as root, and run it as a service: use a disposable host"
	@echo "chaos       install that package on THIS host, as root, and fail what the service depends on: use a disposable host"
	@echo "footprint   install that package on THIS host, as root, and measure what the service spends against its budgets: use a disposable host"
	@echo "soak        install that package on THIS host, as root, and run it for SOAK ($(SOAK)) with every module: use a disposable host"
	@echo "            EVIDENCE=DIR has native-gate, footprint and soak write what they recorded under DIR"
	@echo "vulncheck   refuse a known vulnerability in any package this module links"
	@echo "gosec       refuse what the static security rules find"
	@echo "verify-tag  refuse TAG unless a signer main names signed it"
	@echo "check-protection  compare the rules GitHub enforces on main with the ones declared here"
	@echo "platform-answers  copy every answer the backend commit BACKEND recorded for an agent into tests/compatibility/testdata"
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

fuzz:
	@failed=""; said=$$(mktemp); \
	for package in $$($(GO) list ./...); do \
		directory=$$($(GO) list -f '{{.Dir}}' $$package); \
		for target in $$($(GO) test -list '^Fuzz' $$package | grep '^Fuzz'); do \
			echo "fuzz $$target of $$package for $(FUZZTIME)"; \
			kept=$$(ls $$directory/testdata/fuzz/$$target 2>/dev/null | wc -l); \
			$(GO) test -run '^$$' -fuzz "^$$target\$$" -fuzztime $(FUZZTIME) $$package > $$said 2>&1; ended=$$?; cat $$said; \
			if [ $$ended -ne 0 ]; then \
				if grep -q 'context deadline exceeded' $$said && [ "$$(ls $$directory/testdata/fuzz/$$target 2>/dev/null | wc -l)" = "$$kept" ]; then \
					echo "$$target ran out of time as a worker was busy, and kept no input that fails"; \
				else \
					failed="$$failed $$package.$$target"; \
				fi; \
			fi; \
		done; \
	done; \
	rm -f $$said; \
	if [ -n "$$failed" ]; then echo "fuzzing found inputs that fail, kept under testdata/fuzz:$$failed" >&2; exit 1; fi

build:
	@mkdir -p $(DIST)
	$(GO) build -trimpath -o $(DIST)/seagull-agent ./cmd/seagull-agent

package:
	@mkdir -p $(dir $(PACKAGED))
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -trimpath -ldflags='-s -w' -o $(PACKAGED) ./cmd/seagull-agent
	rm -rf $(DIST)/deb
	$(GO) run ./packaging -binary $(PACKAGED) -out $(DIST)/deb

ahead:
	rm -rf $(DIST)/ahead
	git clone --quiet --no-local . $(DIST)/ahead/source
	git -C $(DIST)/ahead/source tag $(AHEAD)
	$(MAKE) -C $(DIST)/ahead/source package DIST=$(abspath $(DIST)/ahead)
	rm -rf $(DIST)/ahead/source

RUN_native-gate = ^TestTheDebianPackageRunsTheAgentAsAServiceFromInstallationToPurge$$
RUN_chaos = ^TestTheInstalledAgentAccountsForEveryEventThroughFailures$$
RUN_footprint = ^TestTheInstalledAgentSpendsWithinItsBudgets$$
RUN_soak = ^TestTheInstalledAgentLastsWithoutGrowing$$
TIMEOUT_native-gate = 25m
TIMEOUT_chaos = 45m
TIMEOUT_footprint = 45m
TIMEOUT_soak = 0

native-gate chaos footprint soak:
	@test "$(words $(wildcard $(DIST)/deb/*.deb))" = 1 || { echo "$(DIST)/deb holds no single package: make package first" >&2; exit 1; }
	@$(if $(filter native-gate chaos,$@),test "$(words $(wildcard $(DIST)/ahead/deb/*.deb))" = 1 || { echo "$(DIST)/ahead/deb holds no single package: make ahead first" >&2; exit 1; },true)
	$(GO) test -c -o $(DIST)/native.test ./tests/native
	sudo $(DIST)/native.test -test.v -test.count=1 -test.timeout=$(TIMEOUT_$@) -test.run '$(RUN_$@)' \
		-package "$(abspath $(wildcard $(DIST)/deb/*.deb))" $(if $(filter native-gate chaos,$@),-ahead "$(abspath $(wildcard $(DIST)/ahead/deb/*.deb))") \
		$(if $(filter soak,$@),-soak $(SOAK)) $(if $(EVIDENCE),-evidence "$(abspath $(EVIDENCE))")

vulncheck:
	$(GO) run $(GOVULNCHECK) -scan package ./...

gosec:
	$(GO) run $(GOSEC) -quiet -conf .gosec.json -exclude=G104,G115 ./...

verify-tag:
	@test -n "$(TAG)" || { echo "name the tag: make verify-tag TAG=v1.2.3"; exit 1; }
	@mkdir -p $(DIST)
	@git show origin/main:.github/allowed_signers > $(DIST)/allowed_signers
	@git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=$(DIST)/allowed_signers -c gpg.minTrustLevel=fully \
	  verify-tag "$(TAG)"

check-protection:
	@summary='{rules: (map(.type) | unique), checks: ([.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[].context] | sort)}'; \
	declared="$$(jq -c ".rules | $$summary" .github/rulesets/main.json)"; \
	enforced="$$(gh api repos/$(REPOSITORY)/rules/branches/main | jq -c "$$summary")"; \
	if [ "$$declared" != "$$enforced" ]; then \
	  echo "main is declared as $$declared"; echo "and enforced as   $$enforced"; exit 1; \
	fi; echo "main is enforced as declared"

platform-answers:
	@[[ "$(BACKEND)" =~ ^[0-9a-f]{40}$$ ]] || { echo "name the backend commit whole: make platform-answers BACKEND=<40 hexadecimal digits>" >&2; exit 1; }
	@test ! -e $(HELD)/protocol-1 || { echo "$(HELD)/protocol-1 holds a copy already" >&2; exit 1; }
	git init --quiet $(DIST)/platform
	git -C $(DIST)/platform fetch --quiet --depth 1 https://$(PLATFORM) $(BACKEND)
	test "$$(git -C $(DIST)/platform rev-parse FETCH_HEAD)" = "$(BACKEND)"
	mkdir -p $(HELD)
	git -C $(DIST)/platform archive FETCH_HEAD $(ANSWERS) | tar -x --strip-components=4 -C $(HELD)
	jq -n --arg repository $(PLATFORM) --arg commit $(BACKEND) --arg path $(ANSWERS) \
	  '{repository: $$repository, commit: $$commit, path: $$path}' > $(HELD)/platform.json

clean:
	rm -rf $(DIST)

verify: lint mod-check test test-race build
