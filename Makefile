BINARY  := threatdiff
PKG     := github.com/ggeorgeazevedo/threatdiff
# firstword guards against a git that prints a diagnostic to stdout in a
# repository with no commits, which would otherwise inject a stray argument
# into -ldflags.
VERSION ?= $(firstword $(shell git describe --tags --always --dirty 2>/dev/null) dev)
COMMIT  ?= $(firstword $(shell git rev-parse --quiet --verify HEAD 2>/dev/null) unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build ./bin/threatdiff
	@CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/$(BINARY)
	@echo "built bin/$(BINARY) $(VERSION)"

.PHONY: install
install: ## Install into GOBIN
	@go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/$(BINARY)

.PHONY: test
test: ## Run the test suite
	@go test ./...

.PHONY: cover
cover: ## Run tests with coverage and print the summary
	@go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

.PHONY: check
check: ## vet + gofmt + tests, the same set CI runs
	@go vet ./...
	@test -z "$$(gofmt -l .)" || { echo "needs gofmt:"; gofmt -l .; exit 1; }
	@go test ./...

.PHONY: docs
docs: build ## Regenerate docs/rules.md from the builtin packs
	@./bin/$(BINARY) rules docs --out docs/rules.md
	@echo "regenerated docs/rules.md"

.PHONY: demo
demo: build ## Run against the bundled example pull request
	@./bin/$(BINARY) scan --diff examples/pull-request.patch

.PHONY: dogfood
dogfood: build ## Run threatdiff against your own working tree
	@./bin/$(BINARY) scan

.PHONY: rename
rename: ## Re-point the module path: make rename OWNER=your-org
	@test -n "$(OWNER)" || { echo "usage: make rename OWNER=your-org"; exit 1; }
	@go mod edit -module github.com/$(OWNER)/threatdiff
	@grep -rl 'github.com/ggeorgeazevedo/threatdiff' --include='*.go' --include='*.yml' --include='*.yaml' --include='*.md' . \
		| xargs sed -i.bak 's|github.com/ggeorgeazevedo/threatdiff|github.com/$(OWNER)/threatdiff|g'
	@find . -name '*.bak' -delete
	@go build ./... && echo "module is now github.com/$(OWNER)/threatdiff"

.PHONY: clean
clean:
	@rm -rf bin dist coverage.out

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
