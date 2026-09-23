SHELL := /bin/bash
GO ?= go
BIN := bin/trestle

# `sed 's/^v//'` is not cosmetic (PRINCIPLES §4). `git describe` returns the
# tag as written — `v0.14.0` — and that string is what /healthz would then
# report, while the image label carries the BARE `0.14.0` that
# metadata-action stamps. Switchyard compares the two with strict equality,
# so a "v" here is a permanent `claimed_not_confirmed` row. Stripping it
# locally keeps the form identical everywhere the version is produced, which
# is the only way that comparison stays honest.
#
# Only a checkout sitting exactly on a semver tag claims a version. Anything
# else — untagged, past a tag, no git — passes an EMPTY value, which the
# binary reports as `dev`: `--always` would hand it a bare short sha, and a
# plausible-looking non-version is worse than an honest `dev`.
VERSION ?= $(shell git describe --tags --exact-match --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null | sed 's/^v//')
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT)
IMAGE ?= ghcr.io/einlanzerous/trestle

.PHONY: all build run test vet fmt tidy lint verify image clean help

all: build

build: ## Build the static binary into bin/trestle
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/trestle

run: build ## Run the HTTP server
	$(BIN) serve

test: ## Run unit tests (temp dir + httptest, no external services)
	$(GO) test -race ./... -count=1

vet: ## go vet
	$(GO) vet ./...

fmt: ## gofmt -w
	gofmt -w .

tidy: ## go mod tidy
	$(GO) mod tidy

lint: ## golangci-lint (falls back to go vet)
	@which golangci-lint >/dev/null 2>&1 && golangci-lint run || $(GO) vet ./...

verify: ## gofmt check + vet + lint + test -race — the full local gate, same list CI runs
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi
	$(MAKE) vet
	$(MAKE) lint
	$(MAKE) test

image: ## Build the production image
	docker build -f deploy/Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg GIT_SHA=$(COMMIT) \
		-t $(IMAGE):latest .

clean: ## Remove build artifacts
	rm -rf bin

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
