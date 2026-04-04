.PHONY: coverage test check format clippy build

# Run all tests
test:
	cargo test --workspace

# Run code coverage with cargo-tarpaulin
coverage:
	cargo tarpaulin --workspace --out Html --output-dir coverage/

# Format code
format:
	cargo fmt --all

# Run clippy
clippy:
	cargo clippy --all -- -D warnings

# Build release
build:
	cargo build --release
