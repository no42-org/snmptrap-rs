CARGO ?= cargo
CARGO_DENY ?= cargo-deny

# Toolchain targets for static release builds (Linux musl)
RELEASE_TARGET_X86 ?= x86_64-unknown-linux-musl
RELEASE_TARGET_ARM ?= aarch64-unknown-linux-musl
# macOS release targets — best-effort per design D11 (no static-musl equivalent).
RELEASE_TARGET_MACOS_X86 ?= x86_64-apple-darwin
RELEASE_TARGET_MACOS_ARM ?= aarch64-apple-darwin
RELEASE_OUT_DIR          ?= target/release-static

.PHONY: build verify lint test integration-test license-audit \
        release release-x86 release-arm release-macos-x86 release-macos-arm clean

build:
	$(CARGO) build --workspace --all-targets

verify: lint test license-audit

lint:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test:
	$(CARGO) test --workspace --all-targets

integration-test:
	$(CARGO) test --workspace --all-targets --features integration -- --ignored --test-threads=1

license-audit:
	@command -v $(CARGO_DENY) >/dev/null 2>&1 || { \
		echo "cargo-deny not found. Install with: cargo install --locked cargo-deny"; \
		exit 1; \
	}
	$(CARGO_DENY) check licenses

release: release-x86 release-arm

release-x86:
	$(CARGO) build --release --target $(RELEASE_TARGET_X86)
	mkdir -p $(RELEASE_OUT_DIR)
	cp target/$(RELEASE_TARGET_X86)/release/snmptrap-rs $(RELEASE_OUT_DIR)/snmptrap-rs-$(RELEASE_TARGET_X86)

release-arm:
	$(CARGO) build --release --target $(RELEASE_TARGET_ARM)
	mkdir -p $(RELEASE_OUT_DIR)
	cp target/$(RELEASE_TARGET_ARM)/release/snmptrap-rs $(RELEASE_OUT_DIR)/snmptrap-rs-$(RELEASE_TARGET_ARM)

release-macos-x86:
	$(CARGO) build --release --target $(RELEASE_TARGET_MACOS_X86)
	mkdir -p $(RELEASE_OUT_DIR)
	cp target/$(RELEASE_TARGET_MACOS_X86)/release/snmptrap-rs $(RELEASE_OUT_DIR)/snmptrap-rs-$(RELEASE_TARGET_MACOS_X86)

release-macos-arm:
	$(CARGO) build --release --target $(RELEASE_TARGET_MACOS_ARM)
	mkdir -p $(RELEASE_OUT_DIR)
	cp target/$(RELEASE_TARGET_MACOS_ARM)/release/snmptrap-rs $(RELEASE_OUT_DIR)/snmptrap-rs-$(RELEASE_TARGET_MACOS_ARM)

clean:
	$(CARGO) clean
	rm -rf $(RELEASE_OUT_DIR)
