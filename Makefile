PKG    = github.com/majewsky/wirewrap
PREFIX = /usr

GO            = GOPATH=$(CURDIR)/.gopath GOBIN=$(CURDIR)/build go
GO_BUILDFLAGS =
GO_LDFLAGS    = -s -w

PKGS := $(shell go list ./... | grep -vw vendor)
# which packages to test with `go test`?
TESTPKGS := $(shell go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' $(PKG)/pkg/...)
# which packages to measure coverage for?
COVERPKGS := $(shell go list $(PKG)/pkg/... | grep -vw vendor)

all: FORCE
	$(GO) install $(GO_BUILDFLAGS) -ldflags '$(GO_LDFLAGS)' '$(PKG)'

install: FORCE all
	install -D -m 0755 build/wirewrap "$(DESTDIR)$(PREFIX)/bin/wirewrap"

check: golint govet gofmt gotest FORCE

govet:
	@echo "+ go vet"
	@go vet $(PKGS)

gofmt:
	@echo "+ gofmt"
	@test -z "$$(gofmt -s -l . 2>&1 | grep -vw vendor | tee /dev/stderr)" || \
		(echo >&2 "+ please format Go code with 'gofmt -s'" && false)

GOLINT=$(shell which golint || echo '')
golint:
	@echo "+ golint"
	$(if $(GOLINT), , \
		$(error Please install golint: `go get -u github.com/golang/lint/golint`))
	@test -z "$$($(GOLINT) ./... 2>&1 | grep -vw vendor | tee /dev/stderr)"

gotest:
	@echo "+ go test"
	@go test -coverprofile=build/cover.out -covermode=count -coverpkg=$(subst $(space),$(comma),$(COVERPKGS)) $(TESTPKGS)
	@echo "+ render build/cover.html"
	@go tool cover -html build/cover.out -o build/cover.html

vendor: FORCE
	@# vendoring by https://github.com/holocm/golangvend
	golangvend

.PHONY: FORCE
