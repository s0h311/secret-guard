BIN := secret-guard

.PHONY: help build install test lint hook unhook clean matrix sbx
.DEFAULT_GOAL := help

help:
	@echo "secret-guard"
	@echo "  make build    build ./$(BIN)"
	@echo "  make install  install the binary into \$$(go env GOBIN) or GOPATH/bin"
	@echo "  make test     run the test suite"
	@echo "  make lint     go vet"
	@echo "  make hook     install git hooks globally (uses the built binary)"
	@echo "  make unhook   remove the global git hooks"

build:
	@go build -o $(BIN) .

# go install honours GOBIN when it is set, so resolve the same way it does.
BINDIR := $(shell go env GOBIN)
ifeq ($(strip $(BINDIR)),)
BINDIR := $(shell go env GOPATH)/bin
endif

install:
	@go install .
	@echo "installed $(BIN) to $(BINDIR)"

test:
	@go test ./...

lint:
	@go vet ./...

hook: install
	@$(BINDIR)/$(BIN) hook install --global

unhook:
	@$(BINDIR)/$(BIN) hook uninstall --global

clean:
	@rm -f $(BIN)

matrix:
	@node ../matrix/src/index.ts

sbx:
	@sbx run --name matrix-secret-guard
