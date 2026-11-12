// Host-side contract checks; not a substitute for executing GitHub Actions.
#[test]
fn source_native_gate_covers_actor_scope_changes() {
    let native = include_str!("../.github/workflows/borrow-mir-rust-exact-head.yml");
    for path in [
        "src/lib.rs",
        "src/mir_v1.rs",
        "src/actor_state_guard_v1.rs",
        "src/actor_state_runtime_v1.rs",
        "tests/actor_state_guard_v1.rs",
        "tests/actor_state_runtime_v1.rs",
        ".github/workflows/rust-actor-exact-ephemeral.yml",
    ] {
        assert!(native.contains(&format!("- \"{path}\"")), "missing native CI path: {path}");
    }
}

#[test]
fn generic_rust_ci_checks_original_pr_head_and_forbids_persisted_checkout_token() {
    let yml = include_str!("../.github/workflows/rust-v0.yml");
    assert!(yml.contains("ref: ${{ github.event.pull_request.head.sha || github.sha }}"));
    assert!(yml.contains("test \"$(git rev-parse HEAD)\" = \"$EXPECTED_HEAD\""));
    assert!(yml.contains("persist-credentials: false"));
}

#[test]
fn manual_source_local_runner_cannot_be_pr_triggered_or_unreviewed() {
    let yml = include_str!("../.github/workflows/rust-actor-exact-ephemeral.yml");
    assert!(yml.contains("  workflow_dispatch:"));
    assert!(!yml.contains("  pull_request:"));
    for required in [
        "atto-rust-ephemeral-v1",
        "refs/heads/main",
        "branches/main",
        "SOURCE_TREE",
        "github.repository ==",
        "APPROVED",
        "SOURCE_SHA",
        "persist-credentials: false",
        "cargo test --all-targets --locked",
    ] {
        assert!(yml.contains(required), "missing trusted-runner gate: {required}");
    }
}
