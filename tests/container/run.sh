#!/usr/bin/env bash
# Convenience wrapper for the container integration tests.
#
# `cargo test` alone never runs these: they need podman, they are slow (each
# spins up one or more containers), and they must not run with any other
# `cargo test` in flight (see the `--test-threads=1` below, and the module
# docs on crates/porthole-cli/tests/container.rs for why). So every test
# there is `#[ignore]`d -- a plain `cargo test` names them as ignored rather
# than counting them passed -- and this script is the one place that asks for
# them with `--ignored`, sets PORTHOLE_CONTAINER_TESTS=1, and builds what
# they need first.
#
# Usage: tests/container/run.sh [extra libtest args, e.g. a test name filter]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Bound how many rustc processes the two cargo calls below run at once.
#
# Measured on the 22-core host that develops porthole: clean target
# directory, peak anonymous memory of the build's own cgroup, mean of three
# runs. The first block is the heaviest host build there is here, which is
# not this script's; the second is the musl build on the next line.
#
#   cargo test --workspace --exclude porthole-gui --no-run
#     -j22 (cargo's default)  1.40 GiB   17.3 s
#     -j8                     1.09 GiB   19.3 s
#     -j4                     0.71 GiB   24.7 s
#
#   cargo build --target x86_64-unknown-linux-musl --bins
#     -j22 (cargo's default)  1.35 GiB   16.6 s
#     -j8                     1.21 GiB   17.3 s
#
# So the musl build gains little from a cap -- four binaries never fan out
# far enough for job count to matter much. The export is here because the
# `cargo test` below compiles the rest of the workspace, and because a
# developer running this script should not have to think about which of its
# two cargo calls is the expensive one.
#
# Concurrent rustc is the whole of it: the largest single rustc here peaks
# at 0.64 GiB, and the linker never passed 4 MiB, so there is no link-time
# or debug-info component to bound instead. 0.64 GiB is also the floor --
# no job count gets below one rustc.
#
# min(nproc, 8) rather than a flat 8, because cargo does not clamp `jobs`
# to the core count: `jobs = 8` really does start 8 rustc processes on a
# 4-core machine. CI runs this script on a 4-core ubuntu-24.04 runner, and
# a flat 8 would double that runner's compile parallelism rather than leave
# it alone. With min(), any machine of 8 cores or fewer gets exactly what
# it gets today.
#
# CARGO_BUILD_JOBS already in the environment wins over this default, and
# an explicit `cargo -j N` wins over the environment.
porthole_nproc=$(nproc 2>/dev/null || echo 1)
: "${CARGO_BUILD_JOBS:=$(( porthole_nproc < 8 ? porthole_nproc : 8 ))}"
export CARGO_BUILD_JOBS
unset porthole_nproc

# static-pie, debug: `--session` and PORTHOLE_STATE_FILE are both gated on
# cfg!(debug_assertions), and the tests need both. A release build would not
# start on Fedora anyway if it were glibc-linked, since Fedora 44's glibc is
# newer than Debian 13's -- musl sidesteps the whole question.
cargo build --target x86_64-unknown-linux-musl --bins

PORTHOLE_CONTAINER_TESTS=1 exec cargo test --test container -- \
    --ignored --test-threads=1 --nocapture "$@"
