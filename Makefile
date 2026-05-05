CARGO ?= cargo
CARGO_DENY ?= cargo-deny

# Toolchain targets for static release builds (Linux musl)
RELEASE_TARGET_X86 ?= x86_64-unknown-linux-musl
RELEASE_TARGET_ARM ?= aarch64-unknown-linux-musl
# macOS release targets — best-effort per design D11 (no static-musl equivalent).
RELEASE_TARGET_MACOS_X86 ?= x86_64-apple-darwin
RELEASE_TARGET_MACOS_ARM ?= aarch64-apple-darwin
RELEASE_OUT_DIR          ?= target/release-static

.DEFAULT_GOAL := help

.PHONY: help build verify lint test integration-test license-audit \
        release release-x86 release-arm release-macos-x86 release-macos-arm clean

help: ## Show this help
	@awk 'BEGIN{FS=":.*##"; printf "Usage: make <target>\n\nTargets:\n"} \
	     /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Compile workspace + all test targets (debug)
	$(CARGO) build --workspace --all-targets

verify: lint test license-audit ## Run lint + test + license-audit (CI gate)

lint: ## rustfmt --check + clippy -D warnings
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test: ## cargo test (unit + non-integration)
	$(CARGO) test --workspace --all-targets

integration-test: ## Docker-backed integration tests (Linux only)
	$(CARGO) test --workspace --all-targets --features integration -- --ignored --test-threads=1

license-audit: ## cargo-deny check licenses (needs cargo-deny installed)
	@command -v $(CARGO_DENY) >/dev/null 2>&1 || { \
		echo "cargo-deny not found. Install with: cargo install --locked cargo-deny"; \
		exit 1; \
	}
	$(CARGO_DENY) check licenses

release: release-x86 release-arm ## Build static musl binaries for x86_64 + aarch64

release-x86: ## Build x86_64-unknown-linux-musl static binary
	$(CARGO) build --release --target $(RELEASE_TARGET_X86)
	mkdir -p $(RELEASE_OUT_DIR)
	cp target/$(RELEASE_TARGET_X86)/release/snmptrap-rs $(RELEASE_OUT_DIR)/snmptrap-rs-$(RELEASE_TARGET_X86)

release-arm: ## Build aarch64-unknown-linux-musl static binary
	$(CARGO) build --release --target $(RELEASE_TARGET_ARM)
	mkdir -p $(RELEASE_OUT_DIR)
	cp target/$(RELEASE_TARGET_ARM)/release/snmptrap-rs $(RELEASE_OUT_DIR)/snmptrap-rs-$(RELEASE_TARGET_ARM)

release-macos-x86: ## Build x86_64-apple-darwin binary (best-effort)
	$(CARGO) build --release --target $(RELEASE_TARGET_MACOS_X86)
	mkdir -p $(RELEASE_OUT_DIR)
	cp target/$(RELEASE_TARGET_MACOS_X86)/release/snmptrap-rs $(RELEASE_OUT_DIR)/snmptrap-rs-$(RELEASE_TARGET_MACOS_X86)

release-macos-arm: ## Build aarch64-apple-darwin binary (best-effort)
	$(CARGO) build --release --target $(RELEASE_TARGET_MACOS_ARM)
	mkdir -p $(RELEASE_OUT_DIR)
	cp target/$(RELEASE_TARGET_MACOS_ARM)/release/snmptrap-rs $(RELEASE_OUT_DIR)/snmptrap-rs-$(RELEASE_TARGET_MACOS_ARM)

clean: ## cargo clean + remove release-static artifacts
	$(CARGO) clean
	rm -rf $(RELEASE_OUT_DIR)
