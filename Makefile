# Makefile for mini-btmon-rs development

.PHONY: help fmt check clippy test build examples install-hooks clean

help:
	@echo "mini-btmon-rs development commands:"
	@echo "  make fmt           - Format code with rustfmt"
	@echo "  make check         - Quick compilation check"
	@echo "  make clippy        - Run clippy linter"
	@echo "  make test          - Run tests"
	@echo "  make build         - Build library and examples"
	@echo "  make examples      - Build examples with capabilities"
	@echo "  make install-hooks - Install git pre-commit hooks"
	@echo "  make clean         - Clean build artifacts"

fmt:
	cargo fmt

check:
	cargo check --all-targets

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --lib

build:
	cargo build --all-targets

examples: build
	@echo "Building examples..."
	@cargo build --examples
	@echo ""
	@echo "To run examples, you need CAP_NET_RAW capability:"
	@echo "  sudo setcap 'cap_net_raw+ep' target/debug/examples/basic"
	@echo "  sudo setcap 'cap_net_raw+ep' target/debug/examples/att_filter"
	@echo "  sudo setcap 'cap_net_raw+ep' target/debug/examples/integrated"

install-hooks:
	@echo "Installing git hooks..."
	@chmod +x .git/hooks/pre-commit
	@echo "✅ Pre-commit hook installed"

clean:
	cargo clean

# CI commands
ci: fmt check clippy test
	@echo "✅ All CI checks passed"
