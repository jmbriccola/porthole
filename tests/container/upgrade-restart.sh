#!/usr/bin/env bash
# Does an upgrade end the previous version's helper process?
#
# porthole-helper runs as root, holds the firewall, and has no idle timeout
# while a rule is open. An upgrade that ends no process therefore leaves the
# *previous* version's root daemon serving the new version's clients, out of a
# binary that is no longer on disk -- and porthole's D-Bus wire format has
# already changed incompatibly once, so what that produces is not an error but
# a component that goes quiet. Each packaging answers it in its own terms:
#
#   Debian  debian/rules: dh_installsystemd --no-start --restart-after-upgrade,
#           which puts `deb-systemd-invoke try-restart` in postinst behind
#           dpkg's "was there a previous version" test
#   Arch    packaging/aur/porthole.install: post_upgrade(), daemon-reload then
#           `systemctl try-restart`
#
# That those lines exist is not the claim. **The claim is that the helper's PID
# changes across the upgrade**, and this script is what measures it: it builds
# the package from `git archive HEAD`, installs it in a disposable container
# running systemd as PID 1, lets the bus activate the helper, records
# MainPID, installs a newer package, and records MainPID again.
#
# Every measurement here is paired with a negative control -- the same
# measurement with the mechanism removed -- because a scriptlet that runs and
# does nothing is this project's most-repeated defect, and a PID that changed
# proves nothing until a PID that did not change has been seen on the same
# rig. The controls are:
#
#   deb    the shipped package upgraded on a machine that has
#          /usr/sbin/policy-rc.d returning 101. deb-systemd-invoke honours it,
#          so the postinst runs and every service action inside it is inert.
#          This is also the exact trap the test image removes: see
#          tests/container/Containerfile.deb-upgrade.
#   deb    a package built with --restart-after-upgrade deleted from
#          debian/rules.
#   arch   a package built with post_upgrade() deleted from
#          packaging/aur/porthole.install.
#
# Usage:  tests/container/upgrade-restart.sh [debian|arch|all]
#
# Not part of `cargo test` and not part of tests/container/run.sh: it builds
# two distribution packages from source and takes minutes, and it needs
# rootless podman with network access. It measures HEAD, not the working
# tree -- see the refusal below.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
readonly REPO="$PWD"

WHICH="${1:-all}"
case "$WHICH" in
    debian | arch | all) ;;
    *)
        echo "usage: ${BASH_SOURCE[0]} [debian|arch|all]" >&2
        exit 2
        ;;
esac

# What is measured is `git archive HEAD`, which is also what every real build
# of these packages starts from (.copr/Makefile and both CI package jobs use
# it). An uncommitted edit to debian/rules or porthole.install is therefore
# invisible to this script, and a run that silently measured the previous
# commit would be worse than no run: it is the shape of the green check that
# executed nothing. So it refuses rather than warns.
if [ -n "$(git status --porcelain)" ] && [ "${PORTHOLE_UPGRADE_ALLOW_DIRTY:-0}" != 1 ]; then
    cat >&2 <<'DIRTY'
upgrade-restart.sh: the working tree has uncommitted changes.

This script builds the packages from `git archive HEAD`, so anything not
committed is not in what it measures. Commit first, or set
PORTHOLE_UPGRADE_ALLOW_DIRTY=1 if you have read that sentence and mean it.
DIRTY
    exit 2
fi

# Bounded for the same reason tests/container/run.sh and the Makefile bound
# it: cargo does not clamp `jobs` to the core count, and two of these builds
# can be in flight beside a host build. The packages' own builds honour
# CARGO_BUILD_JOBS from the environment (the Makefile takes it with `?=`).
readonly JOBS="${PORTHOLE_UPGRADE_JOBS:-4}"

readonly DEBIAN_IMAGE=localhost/porthole-upgrade-debian
readonly ARCH_IMAGE=localhost/porthole-upgrade-arch

# The versions the two packages are built at. The first is this tree's own;
# the second exists only to be newer than it, and is never committed anywhere.
VERSION="$(sed -n '/^\[workspace\.package\]/,/^\[/ s/^version = "\(.*\)"$/\1/p' Cargo.toml)"
PKGVER="$(sed -n 's/^pkgver=//p' packaging/aur/PKGBUILD)"
test -n "$VERSION" || { echo "no version in Cargo.toml's [workspace.package]" >&2; exit 1; }
test -n "$PKGVER" || { echo "no pkgver= in packaging/aur/PKGBUILD" >&2; exit 1; }
# One digit past this tree's version, on the last component. Only ever used as
# a package version, so it needs to be greater and nothing else.
NEXT="${VERSION%.*}.$(( ${VERSION##*.} + 1 ))"
NEXT_PKG="${PKGVER%.*}.$(( ${PKGVER##*.} + 1 ))"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
readonly WORK

# Podman needs these for systemd as PID 1 in a rootless container, and polkit
# needs the SYS_ADMIN among them: without it polkit fails 217/USER and a
# measurement taken there runs with no authorizer at all. The same set
# crates/porthole-cli/tests/container.rs passes for its systemd images.
# shellcheck disable=SC2054 # the commas inside --cap-add= are podman's own
# syntax for one option's value, not array element separators.
readonly SYSTEMD_ARGS=(
    --systemd=always
    --cap-add=NET_ADMIN,NET_RAW,SYS_ADMIN,SYS_PTRACE,MKNOD,AUDIT_WRITE,SYS_CHROOT,SETFCAP,DAC_OVERRIDE
    --security-opt seccomp=unconfined
    --security-opt label=disable
)

# Every line the two measurements produce, printed again at the end so the
# verdict is not something a reader has to reconstruct from scrollback.
RESULTS=()
FAILURES=0

note() { printf '\n=== %s ===\n' "$*"; }

# Build, or reuse from podman's cache, one of the two images this script
# needs. The script that needs an image is the script that builds it -- the
# same shape crates/porthole-cli/tests/container.rs uses -- so that running
# this on a machine that has never built them is not a precondition somebody
# has to have been told about.
ensure_image() {
    local tag="$1" containerfile="$2"
    podman build -q -t "$tag" -f "tests/container/$containerfile" tests/container >/dev/null
}

record() { # label before after expectation verdict
    RESULTS+=("$(printf '%-34s before=%-8s after=%-8s %-28s %s' "$1" "$2" "$3" "$4" "$5")")
    [ "$5" = ok ] || FAILURES=$((FAILURES + 1))
}

# A disposable container of $1 running systemd, with $WORK/out mounted at /out.
start_systemd_container() {
    local name="$1" image="$2"
    podman rm -f "$name" >/dev/null 2>&1 || true
    podman run -d --name "$name" "${SYSTEMD_ARGS[@]}" \
        -v "$WORK/out:/out:ro,Z" "$image" /sbin/init >/dev/null
    for _ in $(seq 1 120); do
        case "$(podman exec "$name" systemctl is-system-running 2>&1 || true)" in
            running | degraded | maintenance) return 0 ;;
        esac
        sleep 0.5
    done
    echo "systemd never finished starting in $name" >&2
    podman logs "$name" >&2 || true
    return 1
}

# The helper's PID as systemd itself reports it. 0 means "no such process":
# systemd prints MainPID=0 for a unit that is not running.
helper_pid() { podman exec "$1" systemctl show -p MainPID --value porthole-helper.service | tr -d '\r\n'; }

# Bring the helper up the way a user does: by asking it something. The unit is
# Type=dbus with no [Install], so nothing starts it at install time and
# `systemctl start` would not be the production path. ProtocolVersion is the
# one method with no polkit check in front of it, so what this exercises is
# activation and nothing else.
activate_helper() {
    podman exec "$1" busctl --system call com.jacopobriccola.Porthole \
        /com/jacopobriccola/Porthole com.jacopobriccola.Porthole1 ProtocolVersion
}

# ---------------------------------------------------------------------------
# Debian
# ---------------------------------------------------------------------------

build_debian() {
    note "deb: building $VERSION, $NEXT, and the $NEXT with --restart-after-upgrade removed"
    mkdir -p "$WORK/out/deb"/{a,b,nc}
    git archive --format=tar.gz --prefix="porthole-$VERSION/" -o "$WORK/deb-src.tar.gz" HEAD
    podman run --rm \
        -v "$WORK/deb-src.tar.gz:/src.tar.gz:ro,Z" \
        -v "$WORK/out/deb:/out:Z" \
        -e "CARGO_BUILD_JOBS=$JOBS" \
        -e "NEXT=$NEXT" \
        "$DEBIAN_IMAGE" bash -euo pipefail -c '
mkdir -p /build && cd /build
tar -xf /src.tar.gz
cd porthole-*/
export DEB_BUILD_PROFILES=pkg.porthole.nogui

# 1. The package this tree builds.
dpkg-buildpackage -b -us -uc
mv ../*.deb /out/a/
# Printed, not filed. $WORK is removed when this script exits, so a result
# written there and nowhere else is a check whose output nobody ever reads.
echo "--- lintian, on the package this tree builds ---"
lintian_rc=0
lintian --no-tag-display-limit /out/a/porthole_*.deb || lintian_rc=$?
echo "lintian exit: $lintian_rc"

# 2. The same source under a newer package version. Only debian/changelog
#    moves: the .deb version comes from there, and nothing about the
#    maintainer scripts depends on the number.
{
  printf "porthole (%s-1) unstable; urgency=medium\n\n" "$NEXT"
  printf "  * Not a release. Built by tests/container/upgrade-restart.sh to be\n"
  printf "    newer than the version under test, so that an upgrade happens.\n\n"
  printf " -- upgrade-restart.sh <nobody@example.invalid>  %s\n\n" "$(date -R)"
  cat debian/changelog
} > /tmp/changelog && mv /tmp/changelog debian/changelog
dpkg-buildpackage -b -us -uc
mv ../*.deb /out/b/

# 3. The negative control: the same newer package with the flag deleted.
sed -i "s/ --restart-after-upgrade//" debian/rules
if grep -q -- "--restart-after-upgrade" debian/rules; then
  echo "the control did not remove the flag from debian/rules" >&2; exit 1
fi
dpkg-buildpackage -b -us -uc
mv ../*.deb /out/nc/
'
    echo "deb packages built:"
    ls -1 "$WORK/out/deb"/{a,b,nc}/porthole_*.deb
    # What the maintainer scripts actually became, read out of the built
    # packages rather than inferred from the flags that generated them.
    #
    # Read *inside the image*. This ran on the host once and printed "(none)"
    # for all three packages, because the host develops porthole on Fedora and
    # has no dpkg-deb: a check reporting nothing rather than failing, which is
    # the exact shape this script exists to catch elsewhere.
    podman run --rm -v "$WORK/out/deb:/d:ro,Z" "$DEBIAN_IMAGE" bash -c '
for x in a b nc; do
  echo "--- $x postinst ---"
  dpkg-deb -I /d/$x/porthole_*.deb postinst \
    | grep -nE "try-restart|deb-systemd-invoke" || echo "(no service action in postinst)"
  echo "--- $x preinst ---"
  dpkg-deb -I /d/$x/porthole_*.deb preinst 2>/dev/null \
    | grep -nE "stop|try-restart" || echo "(no preinst, or no service action in it)"
done'
}

measure_debian() {
    local label="$1" newdir="$2" restore_policy_rc="$3" expectation="$4"
    local name=porthole-upgrade-deb
    note "deb: $label"
    start_systemd_container "$name" "$DEBIAN_IMAGE"
    podman exec "$name" systemctl is-active dbus.service
    podman exec "$name" bash -euo pipefail -c \
        'apt-get update -qq && apt-get install -y -qq /out/deb/a/porthole_*.deb'
    if [ "$restore_policy_rc" = yes ]; then
        podman exec "$name" bash -euo pipefail -c \
            'printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d; chmod 0755 /usr/sbin/policy-rc.d'
        echo "(policy-rc.d returning 101 restored before the upgrade)"
    fi
    activate_helper "$name"
    local before after
    before="$(helper_pid "$name")"
    echo "helper MainPID after activation: $before"
    podman exec "$name" bash -c "readlink /proc/$before/exe" || true
    podman exec "$name" bash -euo pipefail -c \
        "apt-get install -y -qq /out/deb/$newdir/porthole_*.deb"
    after="$(helper_pid "$name")"
    echo "helper MainPID after the upgrade: $after"
    [ "$after" = 0 ] || podman exec "$name" bash -c "readlink /proc/$after/exe" || true
    podman exec "$name" journalctl -u porthole-helper.service --no-pager -o short-precise | tail -20 || true
    podman rm -f "$name" >/dev/null

    local verdict=failed
    case "$expectation" in
        restarted)
            if [ "$before" != 0 ] && [ "$after" != 0 ] && [ "$after" != "$before" ]; then verdict=ok; fi ;;
        unchanged)
            if [ "$before" != 0 ] && [ "$after" = "$before" ]; then verdict=ok; fi ;;
        not-a-new-helper)
            if [ "$before" != 0 ] && { [ "$after" = 0 ] || [ "$after" = "$before" ]; }; then verdict=ok; fi ;;
    esac
    record "deb: $label" "$before" "$after" "expected: $expectation" "$verdict"
}

# ---------------------------------------------------------------------------
# Arch
# ---------------------------------------------------------------------------

build_arch() {
    note "arch: building $PKGVER, $NEXT_PKG, and the $NEXT_PKG with post_upgrade() removed"
    mkdir -p "$WORK/out/arch"/{a,b,nc}
    git archive --format=tar.gz --prefix="porthole-$PKGVER/" -o "$WORK/arch-src.tar.gz" HEAD
    git archive --format=tar.gz --prefix="porthole-$NEXT_PKG/" -o "$WORK/arch-src-next.tar.gz" HEAD
    podman run --rm \
        -v "$WORK/arch-src.tar.gz:/src.tar.gz:ro,Z" \
        -v "$WORK/arch-src-next.tar.gz:/src-next.tar.gz:ro,Z" \
        -v "$REPO/packaging/aur:/pkg:ro,Z" \
        -v "$WORK/out/arch:/out:Z" \
        -e "CARGO_BUILD_JOBS=$JOBS" \
        -e "PKGVER=$PKGVER" -e "NEXT_PKG=$NEXT_PKG" \
        "$ARCH_IMAGE" bash -euo pipefail -c '
install -d -o builder -g builder /home/builder/build
install -m0644 -o builder -g builder /pkg/PKGBUILD /pkg/porthole.install /home/builder/build/
install -m0644 -o builder -g builder /src.tar.gz "/home/builder/build/porthole-$PKGVER.tar.gz"
install -m0644 -o builder -g builder /src-next.tar.gz "/home/builder/build/porthole-$NEXT_PKG.tar.gz"
cd /home/builder/build

# 1. The package this tree builds, check() and all. --nodeps because the
#    image already carries what the PKGBUILD declares; --syncdeps would only
#    re-resolve it.
su builder -c "cd /home/builder/build && makepkg --noconfirm --nodeps"
mv ./*.pkg.tar.zst /out/a/

# 2. The same source under a newer pkgver. --nocheck, and the reason is worth
#    stating: check() runs the workspace version guard
#    (crates/porthole-core/tests/packaged_version.rs), which compares this
#    PKGBUILD against Cargo.toml, the spec, debian/changelog, .SRCINFO and the
#    AppStream file -- so a PKGBUILD bumped on its own is exactly what that
#    guard refuses. It refused this one; the real build above ran it in full.
sed -i "s/^pkgver=.*/pkgver=$NEXT_PKG/" PKGBUILD
su builder -c "cd /home/builder/build && makepkg --noconfirm --nodeps --nocheck"
mv ./*.pkg.tar.zst /out/b/

# 3. The negative control: the same built tree, repackaged with post_upgrade()
#    deleted from the scriptlet. --repackage runs package() again over the
#    $srcdir that is already there, so the binaries in it are the same bytes
#    as the ones in (2) and the scriptlet is the only difference.
sed -i "/^post_upgrade() {$/,/^}$/d" porthole.install
if grep -q "^post_upgrade" porthole.install; then
  echo "the control did not remove post_upgrade() from porthole.install" >&2; exit 1
fi
if ! grep -q "^pre_remove" porthole.install; then
  echo "the control removed more than post_upgrade() from porthole.install" >&2; exit 1
fi
su builder -c "cd /home/builder/build && makepkg --noconfirm --nodeps --nocheck --repackage"
mv ./*.pkg.tar.zst /out/nc/
'
    echo "arch packages built:"
    ls -1 "$WORK/out/arch"/{a,b,nc}/porthole-[0-9]*.pkg.tar.zst
    # Inside the image, for the reason build_debian gives about dpkg-deb: a
    # Fedora host has no bsdtar either, and this printed "(no .INSTALL)" for
    # all three packages when it ran there.
    podman run --rm -v "$WORK/out/arch:/d:ro,Z" "$ARCH_IMAGE" bash -c '
for x in a b nc; do
  echo "--- $x .INSTALL: the functions it defines ---"
  bsdtar -xOf /d/$x/porthole-[0-9]*.pkg.tar.zst .INSTALL \
    | grep -E "^[a-z_]+\(\) \{" || echo "(no .INSTALL, or it defines nothing)"
done'
}

measure_arch() {
    local label="$1" newdir="$2" expectation="$3"
    local name=porthole-upgrade-arch
    note "arch: $label"
    start_systemd_container "$name" "$ARCH_IMAGE"
    podman exec "$name" systemctl is-active dbus.service
    podman exec "$name" bash -euo pipefail -c \
        'pacman -U --noconfirm /out/arch/a/porthole-[0-9]*.pkg.tar.zst'
    activate_helper "$name"
    local before after
    before="$(helper_pid "$name")"
    echo "helper MainPID after activation: $before"
    podman exec "$name" bash -c "readlink /proc/$before/exe" || true
    podman exec "$name" bash -euo pipefail -c \
        "pacman -U --noconfirm /out/arch/$newdir/porthole-[0-9]*.pkg.tar.zst"
    after="$(helper_pid "$name")"
    echo "helper MainPID after the upgrade: $after"
    [ "$after" = 0 ] || podman exec "$name" bash -c "readlink /proc/$after/exe" || true
    podman exec "$name" journalctl -u porthole-helper.service --no-pager -o short-precise | tail -20 || true
    podman rm -f "$name" >/dev/null

    local verdict=failed
    case "$expectation" in
        restarted)
            if [ "$before" != 0 ] && [ "$after" != 0 ] && [ "$after" != "$before" ]; then verdict=ok; fi ;;
        unchanged)
            if [ "$before" != 0 ] && [ "$after" = "$before" ]; then verdict=ok; fi ;;
    esac
    record "arch: $label" "$before" "$after" "expected: $expectation" "$verdict"
}

# ---------------------------------------------------------------------------

if [ "$WHICH" = debian ] || [ "$WHICH" = all ]; then
    build_debian
    measure_debian "the shipped package" b no restarted
    measure_debian "control: policy-rc.d 101" b yes unchanged
    measure_debian "control: no --restart-after-upgrade" nc no not-a-new-helper
fi

if [ "$WHICH" = arch ] || [ "$WHICH" = all ]; then
    build_arch
    measure_arch "the shipped package" b restarted
    measure_arch "control: no post_upgrade()" nc unchanged
fi

note "what the PIDs did"
printf '%s\n' "${RESULTS[@]}"
if [ "$FAILURES" -ne 0 ]; then
    echo
    echo "$FAILURES measurement(s) did not do what the packaging claims." >&2
    exit 1
fi
echo
echo "Every measurement matched what the packaging claims, and every control did not."
