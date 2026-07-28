//! Black-box HTTP conformance suite for the C2SP tlog-witness checklist in
//! `docs/spec-conformance.md` §1–§6, plus the test-anchored threat-model
//! invariants of `docs/threat-model.md` §4.
//!
//! Every test cites the checklist row(s) it covers (`// covers XX-nn`), as
//! the checklist preamble promises. Tests drive the full T4 layer stack via
//! `server::router` (the same wiring `tests/server.rs` and
//! `tests/monitoring.rs` use); the socket-level rows that `Router::oneshot`
//! cannot reach — GI-03 keep-alive, ST-11 stderr evidence, the I3 startup
//! banner — spawn the real binary over loopback TCP.
//!
//! Coverage is deliberately layered with the parser unit tests in
//! `src/witness/tests.rs` and the integration tests in
//! `tests/{witness,server,monitoring}.rs`: where a row is already pinned at
//! the same black-box level, the test here says so in a cross-reference
//! comment instead of re-asserting every detail.

mod ac;
mod cs;
mod gi;
mod i3;
mod mp;
mod sm;
mod st;
mod support;
