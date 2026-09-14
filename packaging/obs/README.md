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

## A release, once this is set up

Tagging is all of it. `.github/workflows/ci.yml` runs for a tag as it does
for a branch, and its last job -- `obs`, which lists every other job in its
`needs` and refuses to run for anything but a tag -- does three things:

1. runs `packaging/obs/make-sources.sh <version>`, which writes the seven
   files to `build/obs/<version>/` and packs them into `obs-sources.tar`;
2. creates the GitHub release for the tag with that one attachment;
3. asks OBS to run the services of this package, with a token whose only
   permission is exactly that.

OBS then reads [`_service`](_service): `download_url` takes
`releases/latest/download/obs-sources.tar`, `extract_file` unpacks the seven
files beside it, and every repository rebuilds. Nothing in `_service` names a
version, so no release edits it.

The checksum in `packaging/aur/PKGBUILD` cannot be cross-checked at that
moment -- the sum of the tarball GitHub serves for a tag is pinned in a
commit *after* the tag -- so `make-sources.sh` says so and goes on. Run it
again later, after that commit, and it checks.

**What the seven files are:**

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
script refuses an output directory that is not empty rather than clearing it,
and the same tag always produces the same bytes.

**By hand**, when the automatic path is not wanted or not yet set up: run
`packaging/obs/make-sources.sh <version>` and upload the seven files to the
package, replacing the previous version's. That is how 1.0.1 was published.

## Setting it up once

1. **A token on OBS**, bound to this package and allowed one operation:

       osc token --create --operation runservice home:jmbriccola:porthole porthole

   or the same thing from the web interface, under the account's Tokens.
   Anyone holding it can ask OBS to re-read the files this project publishes,
   and nothing else: it cannot upload, change or release anything.

2. **The token in GitHub**, as the repository secret `OBS_RUNSERVICE_TOKEN`.
   Without it the release is still made and the job says so instead of
   failing; OBS then has to be asked by hand.

3. **`_service` in the package**, in place of the seven uploaded files.
   Delete those first: with both present, OBS would keep building the ones
   that no longer move.

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

On 2026-09-14, for the automatic path, on OBS itself:

- A package `porthole-test` in the same project, publishing disabled, holding
  nothing but `_service`. Its first run failed with `404`, because the release
  did not exist yet; its second with `service error: No matching archive
  found`, which is how the prefix in the archive's name was found. With the
  glob, the services succeeded and the expanded sources showed the downloaded
  tar and the seven extracted files at the sizes they have here.
- All six builds of that package succeeded from those sources: Debian 13,
  Ubuntu 26.04, and Fedora 43 and 44 on x86_64 and aarch64. Debian was the
  one in doubt, since its `.dsc` names tarballs that arrive under prefixed
  names.

What none of this covers is the release job itself: it can only run for a
tag, so the first tag after this is where it gets checked.
