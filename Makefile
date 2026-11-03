.PHONY: help matrix sbx
.DEFAULT_GOAL := help

help:
	@echo "Usage: make [matrix|sbx]"

matrix:
	@node ../matrix/src/index.ts

sbx:
	@sbx run --name matrix-secret-guard
