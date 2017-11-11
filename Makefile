PKG    = github.com/majewsky/wirewrap
PREFIX = /usr

GO            = GOPATH=$(CURDIR)/.gopath GOBIN=$(CURDIR)/build go
GO_BUILDFLAGS =
GO_LDFLAGS    = -s -w

all: FORCE
	$(GO) install $(GO_BUILDFLAGS) -ldflags '$(GO_LDFLAGS)' '$(PKG)'

install: FORCE all
	install -D -m 0755 build/wirewrap "$(DESTDIR)$(PREFIX)/bin/wirewrap"

vendor: FORCE
	@# vendoring by https://github.com/holocm/golangvend
	golangvend

.PHONY: FORCE
