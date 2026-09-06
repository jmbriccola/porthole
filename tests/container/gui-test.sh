#!/usr/bin/env bash
# Runs porthole-gui's tests inside tests/container/Containerfile.gui.
#
# porthole-gui sits outside every host-side gate (root Cargo.toml excludes
# it from `default-members`, and every host `--workspace` command carries
# `--exclude porthole-gui`, since GTK4 is not installed on the host). This
# script is therefore the *only* place `-D warnings` is ever checked against
# this crate at all -- so the clippy run below is not optional polish, it is
# the one and only enforcement of a binding constraint of this milestone for
# this crate. It runs before the tests so a lint failure stops the script
# before spending time on Xvfb/dbus.
#
# Xvfb stands in for a real display; GTK_A11Y=none silences the missing
# org.a11y.Bus; GSK_RENDERER=cairo because there is no GPU in the container;
# dbus-run-session because adw::Application needs a session bus to own its
# application id. `libEGL warning: DRI3 error` on stderr is the software
# renderer announcing itself, not a failure.
#
# Usage: tests/container/gui-test.sh [extra cargo-test args, e.g. a filter]
set -e
# rust-version = "1.87" (the workspace's own Cargo.toml) is a binding floor
# on porthole-gui too, and nothing else ever checks the crate against it --
# the plain `cargo` below is Fedora's own current stable, always newer than
# 1.87. The explicit path and RUSTUP_HOME/CARGO_HOME reach the rustup-managed
# 1.87 toolchain Containerfile.gui installs off to the side (see that file's
# own comment for why: pointing rustup at the default `~/.cargo` breaks dnf's
# own `cargo clippy`, since Cargo's subcommand search always checks
# `$CARGO_HOME/bin` regardless of `PATH`). Only this one command gets those
# variables -- clippy and the tests below run with the ordinary environment,
# untouched. Runs before clippy for the same reason clippy runs before the
# tests: fail the cheapest check first.
RUSTUP_HOME=/opt/rustup-1.87/home CARGO_HOME=/opt/rustup-1.87/cargo \
  /opt/rustup-1.87/cargo/bin/cargo +1.87 check -p porthole-gui --all-targets
cargo clippy -p porthole-gui --all-targets -- -D warnings
Xvfb :99 -screen 0 1024x768x24 >/dev/null 2>&1 &
sleep 2
export DISPLAY=:99 GTK_A11Y=none GSK_RENDERER=cairo
exec dbus-run-session -- cargo test -p porthole-gui "$@"
