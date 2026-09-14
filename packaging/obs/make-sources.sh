#!/usr/bin/env bash
# The files the OBS package home:jmbriccola:porthole/porthole is built from,
# for one tagged release, written to one directory ready to upload.
#
# OBS builders have no network, so everything cargo would fetch has to arrive
# as a source file: the crates, vendored once from the release's own
# Cargo.lock and handed to both packagings -- to the RPM spec as Source1 (its
# `--with vendor` switch, which packaging/obs/prjconf turns on), and to the
# Debian source package as a second orig tarball, which dpkg-source unpacks
# into vendor/ and debian/rules then points cargo at.
#
# What comes out, for version V and Debian revision R:
#   porthole.spec                    this tree's spec
#   porthole-V.tar.gz                the tarball GitHub serves for tag vV
#   porthole-V-vendor.tar.xz         the crates: the spec's Source1
#   porthole_V.orig.tar.gz           the same GitHub tarball, under Debian's name
#   porthole_V.orig-vendor.tar.xz    the same crates, under Debian's name
#   porthole_V-R.debian.tar.xz       this tree's debian/
#   porthole_V-R.dsc                 what OBS reads to build the Debian ones
#
# The upstream tarball is checked against the sha256 pinned in
# packaging/aur/PKGBUILD whenever that PKGBUILD is for the same version, so
# all three packagings are provably built from one file.
#
# Needs curl, cargo and network (to vendor), git (the tag's date), and podman
# (dpkg-source runs in a debian:13 container).
#
# Usage: packaging/obs/make-sources.sh <version> [outdir]
set -euo pipefail

version=${1:?usage: packaging/obs/make-sources.sh <version> [outdir]}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
out=${2:-$repo/build/obs/$version}
url="https://github.com/jmbriccola/porthole/archive/refs/tags/v$version.tar.gz"

# Never clean a directory that is not ours to clean: an existing, non-empty
# outdir is a mistake in the arguments, not something to delete.
if [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
    echo "$out is not empty; give an empty or new directory" >&2
    exit 1
fi
mkdir -p "$out"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "== upstream tarball for v$version"
curl -fsSL "$url" -o "$out/porthole-$version.tar.gz"
sum=$(sha256sum "$out/porthole-$version.tar.gz" | cut -d' ' -f1)
pinned_version=$(sed -n 's/^pkgver=//p' "$repo/packaging/aur/PKGBUILD")
pinned=$(sed -n "s/^sha256sums=('\([0-9a-f]\{64\}\)')$/\1/p" "$repo/packaging/aur/PKGBUILD")
if [ "$pinned_version" != "$version" ]; then
    echo "   packaging/aur/PKGBUILD is for $pinned_version, not $version: not cross-checked" >&2
elif [ -z "$pinned" ]; then
    # The tag's own PKGBUILD still carries sha256sums=('SKIP'): the checksum
    # of the tarball GitHub serves for a tag cannot be inside that tarball,
    # so it is pinned in a commit after the tag. Running right after the tag,
    # which is what the release workflow does, is that moment.
    echo "   packaging/aur/PKGBUILD carries SKIP: nothing to cross-check yet" >&2
elif [ "$sum" != "$pinned" ]; then
    echo "sha256 $sum does not match the $pinned in packaging/aur/PKGBUILD" >&2
    exit 1
else
    echo "   sha256 matches packaging/aur/PKGBUILD"
fi
cp "$out/porthole-$version.tar.gz" "$out/porthole_$version.orig.tar.gz"

echo "== crates, vendored from the release's own Cargo.lock"
tar -C "$work" -xzf "$out/porthole-$version.tar.gz"
src="$work/porthole-$version"
cargo vendor --locked --manifest-path "$src/Cargo.toml" "$work/vendor" >/dev/null
# The tag's commit time rather than now, so one release always yields the
# same tarball.
epoch=$(git -C "$repo" log -1 --format=%ct "v$version")
tar -C "$work" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    -cJf "$out/porthole-$version-vendor.tar.xz" vendor
cp "$out/porthole-$version-vendor.tar.xz" "$out/porthole_$version.orig-vendor.tar.xz"

cp "$repo/packaging/rpm/porthole.spec" "$out/porthole.spec"

echo "== Debian source package"
# What dpkg-source builds from: the upstream tree as shipped, the crates under
# vendor/, and this tree's debian/ in place of the one the tag carries.
mv "$work/vendor" "$src/vendor"
rm -rf "$src/debian"
cp -a "$repo/debian" "$src/debian"
cp "$out/porthole_$version.orig.tar.gz" "$out/porthole_$version.orig-vendor.tar.xz" "$work/"
if command -v dpkg-source >/dev/null && command -v dpkg-parsechangelog >/dev/null; then
    echo "   dpkg-source: this machine's own"
    ( cd "$work"
      upstream=$(dpkg-parsechangelog -l "porthole-$version/debian/changelog" -S Version | sed "s/-[^-]*$//")
      if [ "$upstream" != "$version" ]; then
          echo "debian/changelog is for $upstream, not $version" >&2
          exit 1
      fi
      dpkg-source -b "porthole-$version" )
else
    echo "   dpkg-source: in a debian:13 container"
    podman run --rm --security-opt label=disable -v "$work:/w" -w /w debian:13 bash -c '
        set -euo pipefail
        apt-get -o Acquire::http::Timeout=20 -o Acquire::Retries=2 update -qq >/dev/null
        apt-get install -y -qq --no-install-recommends dpkg-dev >/dev/null
        upstream=$(dpkg-parsechangelog -l "porthole-$0/debian/changelog" -S Version | sed "s/-[^-]*$//")
        if [ "$upstream" != "$0" ]; then
            echo "debian/changelog is for $upstream, not $0" >&2
            exit 1
        fi
        dpkg-source -b "porthole-$0"
    ' "$version"
fi
cp "$work"/porthole_"$version"-*.debian.tar.xz "$work"/porthole_"$version"-*.dsc "$out/"

echo "== obs-sources.tar, the release's one attachment"
# The same seven files in one file, so the _service on OBS can name a single
# attachment that never changes with the version. Reproducible like the
# vendor tarball above: one release in, the same bytes out.
( cd "$out" && tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    -cf obs-sources.tar porthole.spec "porthole-$version.tar.gz" \
    "porthole-$version-vendor.tar.xz" "porthole_$version.orig.tar.gz" \
    "porthole_$version.orig-vendor.tar.xz" porthole_"$version"-*.debian.tar.xz \
    porthole_"$version"-*.dsc )

echo "== $out"
ls -l "$out"
