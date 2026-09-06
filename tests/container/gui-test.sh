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
cargo clippy -p porthole-gui --all-targets -- -D warnings
Xvfb :99 -screen 0 1024x768x24 >/dev/null 2>&1 &
sleep 2
export DISPLAY=:99 GTK_A11Y=none GSK_RENDERER=cairo
exec dbus-run-session -- cargo test -p porthole-gui "$@"
