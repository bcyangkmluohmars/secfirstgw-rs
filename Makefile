# secfirstgw-rs build targets
#
# Usage:
#   make build           — debug build (native)
#   make release         — release build (native)
#   make aarch64         — static musl release for ARM routers (UDM Pro, etc.)
#   make x86_64          — static musl release for x86 appliances
#   make all-targets     — build both architectures
#   make web             — build frontend only
#   make clean           — remove build artifacts
#   make dist            — create distributable tarballs for both arches

VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
BINARY := sfgw
WEB_DIR := web
DIST_DIR := dist

.PHONY: build release aarch64 x86_64 all-targets web clean dist check test fmt clippy

# --- Development ---

build:
	cargo build --workspace

release:
	cargo build --release --bin $(BINARY)

check:
	cargo check --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all
	cd $(WEB_DIR) && npx prettier --write src/

clippy:
	cargo clippy --workspace -- -D warnings

# --- Frontend ---

web:
	cd $(WEB_DIR) && npm ci && npm run build

# --- Cross-compilation (static musl binaries) ---

aarch64: web
	cargo build --release --bin $(BINARY) --target aarch64-unknown-linux-musl

x86_64: web
	cargo build --release --bin $(BINARY) --target x86_64-unknown-linux-musl

all-targets: aarch64 x86_64

# --- Distribution tarballs ---

dist: all-targets
	mkdir -p $(DIST_DIR)
	# aarch64
	tar -czf $(DIST_DIR)/secfirstgw-$(VERSION)-aarch64-linux.tar.gz \
		-C target/aarch64-unknown-linux-musl/release $(BINARY) \
		-C $(CURDIR)/$(WEB_DIR) dist \
		-C $(CURDIR) scripts/clean-and-install.sh
	# x86_64
	tar -czf $(DIST_DIR)/secfirstgw-$(VERSION)-x86_64-linux.tar.gz \
		-C target/x86_64-unknown-linux-musl/release $(BINARY) \
		-C $(CURDIR)/$(WEB_DIR) dist \
		-C $(CURDIR) scripts/clean-and-install.sh
	@echo "Built: $(DIST_DIR)/secfirstgw-$(VERSION)-aarch64-linux.tar.gz"
	@echo "Built: $(DIST_DIR)/secfirstgw-$(VERSION)-x86_64-linux.tar.gz"

# --- Cleanup ---

clean:
	cargo clean
	rm -rf $(WEB_DIR)/dist $(WEB_DIR)/node_modules $(DIST_DIR)
