# Building on the openSUSE Build Service

porthole's Fedora, Debian and Ubuntu packages are built on build.opensuse.org,
in the project `home:jmbriccola:porthole`, package `porthole`. People install
them from the repositories that project publishes, and get updates the way
they get every other update on their system.

OBS builds with no network. Everything cargo would download therefore has to
arrive as a source file, and every build here was checked that way, with the
network switched off, before anything was uploaded.

## The project

| Repository      | Paths, in this order                             |
| --------------- | ------------------------------------------------ |
| `Fedora_44`     | `Fedora:44/standard`                             |
| `Fedora_43`     | `Fedora:43/standard`                             |
| `xUbuntu_26.04` | `Ubuntu:26.04/universe`                          |
| `Debian_13`     | `Debian:13/backports`, then `Debian:13/standard` |

**The order of Debian_13's two paths matters.** OBS takes a package from the
first path that carries it, whatever its version. Debian 13's own rustc is
1.85, this workspace needs 1.87, and trixie-backports carries a newer one: with
`standard` first, the build would get 1.85. `standard` also has to be the last
path, because the last one is the one OBS expands into the rest of the
distribution.

The project config is [`prjconf`](prjconf), pasted into the Project Config
tab. It turns on the spec's `--with vendor`. The Debian packages need nothing
there: `debian/rules` goes offline by itself when the source carries
`vendor/`.

## A release

Once the tag exists at GitHub, and after `packaging/aur/PKGBUILD` has its
checksum (step 3 of [docs/releasing.md](../../docs/releasing.md)):

    packaging/obs/make-sources.sh <version>

writes seven files to `build/obs/<version>/`:

| File                               | Used by                                   |
| ---------------------------------- | ----------------------------------------- |
| `porthole.spec`                    | Fedora                                    |
| `porthole-<v>.tar.gz`              | Fedora: the tag's tarball, `Source0`      |
| `porthole-<v>-vendor.tar.xz`       | Fedora: the crates, `Source1`             |
| `porthole_<v>.orig.tar.gz`         | Debian, Ubuntu: the same tarball          |
| `porthole_<v>.orig-vendor.tar.xz`  | Debian, Ubuntu: the same crates           |
| `porthole_<v>-<r>.debian.tar.xz`   | Debian, Ubuntu: this tree's `debian/`     |
| `porthole_<v>-<r>.dsc`             | Debian, Ubuntu: what OBS reads to build   |

The crates are vendored once, from the tag's own `Cargo.lock`, and the same
tarball goes to both packagings under the two names they each expect. The
script checks the upstream tarball against the checksum in the PKGBUILD, so
all three packagings are provably built from one file. It refuses an output
directory that is not empty rather than clearing it.

Upload the seven files to the package, and delete the previous version's
tarballs and `.dsc` from it. OBS rebuilds every repository on its own.

## How this was checked

On 2026-09-11, for 1.0.1, before the first upload:

- `make-sources.sh` run twice gave seven byte-identical files each time.
- Each distribution built in a container started with `--network none`, with
  a connection attempt that had to fail before the build was allowed to
  count. Fedora 44: `rpmbuild -ba --with vendor`, `%check` 688 passed and 0
  failed, six RPMs. Debian 13 with trixie-backports (rustc 1.94.1) and Ubuntu
  26.04 (rustc 1.93.1): `dpkg-buildpackage -b`, exit 0.
- The first Debian-family run failed, and the reason is written down in
  `debian/rules` beside the fix: `dh_clean` deletes `*.orig`, and every
  vendored crate carries a `Cargo.toml.orig` its checksums name.

What that does not cover is OBS itself: its resolver choosing the backports
rustc, and its own build environment. The first build on OBS is where that
gets checked.
