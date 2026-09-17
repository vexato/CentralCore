# Contributing

CentralCore is a from-scratch implementation. Do not copy, translate, or adapt
code from Selvania Launcher, the former CentralCorp Launcher, or
`minecraft-java-core-azbetter`.

Keep modules focused and public APIs documented. Before proposing a change,
run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Network behavior must have deterministic fixture or mock coverage so the test
suite does not require Internet access.
