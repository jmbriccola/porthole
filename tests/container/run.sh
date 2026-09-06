#!/usr/bin/env bash
# Convenience wrapper for the container integration tests.
#
# `cargo test` alone never runs these: they need podman, they are slow (each
# spins up one or more containers), and they must not run with any other
# `cargo test` in flight (see the `--test-threads=1` below, and the module
# docs on crates/porthole-cli/tests/container.rs for why). So they are gated
# on PORTHOLE_CONTAINER_TESTS and skip loudly without it -- this script is
# the one place that actually sets it and runs them.
#
# Usage: tests/container/run.sh [extra libtest args, e.g. a test name filter]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# static-pie, debug: `--session` and PORTHOLE_STATE_FILE are both gated on
# cfg!(debug_assertions), and the tests need both. A release build would not
# start on Fedora anyway if it were glibc-linked, since Fedora 44's glibc is
# newer than Debian 13's -- musl sidesteps the whole question.
cargo build --target x86_64-unknown-linux-musl --bins

PORTHOLE_CONTAINER_TESTS=1 exec cargo test --test container -- --test-threads=1 --nocapture "$@"
