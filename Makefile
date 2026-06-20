# auth - Zig Library Makefile
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2025 CodePros

.PHONY: all build test test-unit test-integration clean check fmt help dev ci example
.PHONY: test-release test-release-safe test-release-fast test-release-small test-all-optimizations
.PHONY: fuzz pre-commit-install pre-commit pre-commit-run
.PHONY: test-fips test-dual

# Default target: build and run tests
all: build test-unit
	@echo "✅ All builds and tests completed successfully!"

# Build the library (full compile + link).
# Note: CI's "build" job runs `zig build check` (compile-only, no codegen);
# `make build` here runs a full `zig build` including linking and output.
build:
	@echo "🔨 Building auth..."
	@zig build

# Run all tests
test: test-unit test-integration
	@echo "✅ All tests completed"

# Run unit tests only
test-unit:
	@echo "🧪 Running unit tests..."
	@zig build test --summary all

# Run integration tests only
test-integration:
	@echo "🔗 Running integration tests..."
	@zig build test-integration --summary all

# FIPS-mode tests (requires `make deps` from the fips package + OpenSSL).
test-fips:
	@echo "🔐 Running FIPS-mode tests..."
	@zig build test -Dfips=true -Dopenssl_path=$(or $(OPENSSL_PREFIX),/usr/local/ssl) --summary all
	@zig build test-integration -Dfips=true -Dopenssl_path=$(or $(OPENSSL_PREFIX),/usr/local/ssl) --summary all

# Dual-mode gate: std shim AND OpenSSL FIPS backend must both be green.
test-dual: test test-fips
	@echo "✅ Dual-mode (-Dfips off + on) tests passed"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf zig-cache zig-out .zig-cache

# Check for compilation errors (fast, no codegen)
check:
	@echo "🔍 Checking for compilation errors..."
	@zig build check

# Build and run the basic example
example: ## Build and run the basic example
	@echo "📖 Running basic example..."
	@zig build example

# Format source code
fmt:
	@echo "📝 Formatting code..."
	@zig fmt src/ tests/ examples/ build.zig

# Quick development iteration loop
dev: fmt check test-unit
	@echo "✅ Development checks passed"

# Run the CI fuzz job locally
fuzz: ## Run the CI fuzz job locally
	@echo "🔬 Running fuzz tests (60s timeout)..."
	@timeout 60 zig build test --fuzz; rc=$$?; if [ $$rc -ne 0 ] && [ $$rc -ne 124 ]; then exit $$rc; fi

# Release-mode test matrix (mirrors CI)
test-release: ## Release-mode test matrix (mirrors CI)
	@echo "🧪 Running release-mode test matrix..."
	@zig build test -Doptimize=ReleaseSafe && \
	 zig build test -Doptimize=ReleaseFast && \
	 zig build test-integration -Doptimize=ReleaseSafe
	@echo "✅ Release-mode tests passed"

# Full CI pipeline (clean slate, mirrors pipeline more closely)
ci: clean check test test-release
	@echo "✅ CI pipeline passed"

# Release optimization level tests
test-release-safe:
	@echo "🧪 Testing with ReleaseSafe..."
	@zig build test -Doptimize=ReleaseSafe --summary all

test-release-fast:
	@echo "🧪 Testing with ReleaseFast..."
	@zig build test -Doptimize=ReleaseFast --summary all

test-release-small:
	@echo "🧪 Testing with ReleaseSmall..."
	@zig build test -Doptimize=ReleaseSmall --summary all

test-all-optimizations: test-unit test-release-safe test-release-fast test-release-small
	@echo "✅ All optimization levels passed"

# Pre-commit hook management
pre-commit-install:
	@echo "📦 Installing pre-commit hooks..."
	@pre-commit install
	@pre-commit install --hook-type commit-msg
	@pre-commit install --hook-type pre-push

pre-commit:
	@echo "🔍 Running pre-commit checks..."
	@pre-commit run --all-files

pre-commit-run: pre-commit

# Display help
help:
	@echo "auth - Zig Library"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development:"
	@echo "  all                  Build and run tests (default)"
	@echo "  build                Build the library"
	@echo "  example              Build and run the basic example"
	@echo "  dev                  Quick iteration: fmt + check + test"
	@echo "  ci                   Full CI: clean + check + test + test-release"
	@echo ""
	@echo "Testing:"
	@echo "  test                 Run all tests"
	@echo "  test-unit            Run unit tests only"
	@echo "  test-integration     Run integration tests only"
	@echo "  test-fips            Run FIPS-mode tests (-Dfips=true; needs OpenSSL FIPS provider)"
	@echo "  test-dual            Dual-mode gate: -Dfips off AND on must both pass"
	@echo "  test-release         Release-mode test matrix (mirrors CI)"
	@echo "  test-release-safe    Test with ReleaseSafe"
	@echo "  test-release-fast    Test with ReleaseFast"
	@echo "  test-release-small   Test with ReleaseSmall"
	@echo "  test-all-optimizations  Test all optimization levels"
	@echo "  fuzz                 Run the CI fuzz job locally"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt                  Format source code"
	@echo "  check                Compile-check all code (mirrors CI build job)"
	@echo "  pre-commit           Run pre-commit hooks"
	@echo "  pre-commit-install   Install pre-commit hooks"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean                Remove build artifacts"
	@echo "  help                 Show this help message"
