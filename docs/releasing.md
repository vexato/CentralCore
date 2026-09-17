# Release checklist

- [ ] Confirm the intended crate version and update `CHANGELOG.md`.
- [ ] Review public API diff and SemVer impact.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run workspace Clippy, all targets/features, with warnings denied.
- [ ] Run the full workspace test suite on Windows, Linux and macOS.
- [ ] Build rustdoc with warnings denied and check links.
- [ ] Check the Rust 1.88 MSRV job.
- [ ] Re-run direct and transitive dependency/license audit.
- [ ] Review `docs/security/review-1.0.md` and unresolved advisories.
- [ ] Run `cargo package -p centralcore` and inspect package contents/size.
- [ ] Run `cargo publish -p centralcore --dry-run` when registry access exists.
- [ ] Verify no fixture cache, downloaded game, credential, token or private key
  appears in the package or Git history.
- [ ] Exercise the signed-provider and detached-process smoke scenarios.
- [ ] Obtain human approval before `cargo publish`, Git tag or GitHub release.
- [ ] After publication, create the annotated tag and release notes from the
  changelog; never automate these steps from an ordinary validation run.
