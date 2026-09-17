$ErrorActionPreference = "Stop"

cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo clippy --workspace --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test --workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --workspace --no-deps
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo package -p centralcore
exit $LASTEXITCODE
