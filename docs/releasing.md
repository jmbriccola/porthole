# Cutting a release

porthole's version is written by hand in **ten places across six files**, and
three packagings build from them. This is the order to move them in and the
checks that have to pass before a tag exists.

Steps 1 to 3 are a person's: the version, the checks, and the tag. Step 4 is
not, since this workflow publishes to the build service on a tag of its own
accord. Nothing here pushes a commit or a tag, and the AUR submission stays
the maintainer's own.

## 1. The version, in the ten places that carry it

| File | What carries the version |
| --- | --- |
| `Cargo.toml` | `version = "…"` in `[workspace.package]` |
| `Cargo.lock` | the five workspace crates' own `version =` lines |
| `packaging/rpm/porthole.spec` | the `Version:` tag |
| `packaging/rpm/porthole.spec` | the newest `%changelog` entry |
| `packaging/aur/PKGBUILD` | `pkgver=` |
| `packaging/aur/.SRCINFO` | `pkgver =` |
| `packaging/aur/.SRCINFO` | the tarball name in `source =` |
| `packaging/aur/.SRCINFO` | the **git tag** `v<version>` in `source =`'s URL |
| `packaging/aur/.SRCINFO` | `porthole-gui`'s `depends = porthole=<version>-<pkgrel>` |
| `debian/changelog` | the newest entry's `porthole (<version>-<revision>)` |
| `data/com.jacopobriccola.Porthole.metainfo.xml` | a **new** `<release version=… date=…>` |

Notes on the four that are not just a number:

- **`Cargo.lock`.** `cargo update --workspace` after editing `Cargo.toml`.
  Every packaged build runs `cargo build --locked`, which fails on a lockfile
  that does not already satisfy the manifest — so a forgotten lockfile is a
  broken package build rather than a wrong number.
- **The three changelogs** (`debian/changelog`, the spec's `%changelog`, the
  AppStream `<releases>`) are *histories*: add an entry, never edit the
  previous one. AppStream is newest-first, and the guard below checks that it
  stayed that way.
- **`.SRCINFO` is generated**, and is also what the AUR serves to everything
  that lists or resolves the package — the PKGBUILD beside it is only read by
  whoever builds it. Regenerate rather than hand-edit:

      podman run --rm -v "$PWD/packaging/aur:/pkg:ro,Z" archlinux:latest bash -c \
        'useradd -m b; install -d -o b /tmp/b; install -m0644 -o b /pkg/PKGBUILD /pkg/porthole.install /tmp/b/; \
         su b -c "cd /tmp/b && makepkg --printsrcinfo"' > packaging/aur/.SRCINFO

- **The packaging revisions are not the version** and do not move with it:
  `debian/changelog`'s `-1`, the spec's `Release:`, `.SRCINFO`'s `pkgrel`.
  Each is its own packaging system's counter, for when the packaging changes
  and upstream does not.

`crates/porthole-core/tests/packaged_version.rs` compares all ten and fails
naming every file and what it read, so the check for this step is `cargo test`
— and it runs inside two of the three package builds as well (the RPM's
`%check` and the AUR's `check()`).

Documentation that names the old version in an example moves too. What does
*not* move: a line where the old version is deliberately illustrative of a
past state, and `selinux/porthole.te`'s `policy_module(porthole, 0.1.0)`,
which is that module's own version and not porthole's.

## 2. The checks

Run from a clean tree. Every one of these is a gate, not a formality.

**Run the container-based ones one at a time.** They bind-mount this working
tree into containers with SELinux `:Z`, which relabels the mounted files with
a category private to that one container. Two containers holding overlapping
`:Z` mounts of this tree therefore relabel each other's files, and a binary
that was executable a moment ago fails with `Permission denied` and exit 126.
Measured here on 2026-09-11: the RPM build below mounts the whole repository,
`tests/container/run.sh` mounts the musl binaries under `target/`, and running
the two together failed
`a_subnet_the_machine_left_is_announced_along_with_the_rules_it_closed` on a
tree where nothing was wrong. Neither check was at fault and neither is flaky.
A failure of that shape means they overlapped, and the answer is to re-run the
suite on its own rather than to look for the bug in porthole.

    cargo fmt --all --check
    cargo clippy --workspace --exclude porthole-gui --all-targets -- -D warnings
    cargo test --workspace --exclude porthole-gui
    cargo test --release --workspace --exclude porthole-gui

`--release` is not redundant: the tests that reach the binary through
`PORTHOLE_STATE_FILE`, `PORTHOLE_DEVICES_FILE` or `porthole-helper --session`
are `#[cfg_attr(not(debug_assertions), ignore = …)]`, so a release run reports
them as ignored by name rather than failing.

The GUI crate is outside every host command above (GTK4 headers are not
installed on the development host), so its lint and its tests happen in a
container, and that is the only place `-D warnings` is ever applied to it:

    podman build -t porthole-gui-test -f tests/container/Containerfile.gui tests/container
    podman run --rm -v .:/src:z -w /src porthole-gui-test bash tests/container/gui-test.sh

Read that command's **exit code**. Piping it through `grep -c` reports 1 when
it finds nothing, which turns a clean run into an apparent failure.

The container integration suite drives the three backends, Docker and the
helper's idle exit against real firewalls, and takes about eleven minutes:

    PORTHOLE_CONTAINER_TESTS=1 tests/container/run.sh

The upgrade measurement is separate because it builds two distribution
packages from `git archive HEAD`:

    tests/container/upgrade-restart.sh

It proves the thing an upgrade has to do — that the previous version's **root**
helper process ends — by recording the helper's PID either side of an upgrade
inside a container running systemd as PID 1, on Debian and on Arch, each
against a negative control with the mechanism removed. Its own header says
what the controls are.

Finally, the packaging, built the way the real builders build it — an
unprivileged user, a clean `fedora:44`, `%check` enabled:

    make -f .copr/Makefile srpm outdir=/tmp/porthole-srpm
    dnf builddep -y packaging/rpm/porthole.spec
    rpmbuild --rebuild /tmp/porthole-srpm/porthole-<version>-1.*.src.rpm

`%check` refuses to run as root and says why: six of the suite's tests cannot
run there at all. mock and COPR build unprivileged, so this refusal never
fires for them.

## 3. The tag, and what depends on it

`packaging/aur/.SRCINFO`'s `source =` URL names `v<version>`, and
`packaging/rpm/porthole.spec`'s `Source0` names the same tag. Neither is
fetched by any check above — the RPM build uses a `git archive` of the working
commit, and the AUR PKGBUILD carries `sha256sums=('SKIP')` — so **the tag is
the one thing in this list that nothing in this repository can verify for
you.**

After the tag exists at the remote:

- `updpkgsums` in `packaging/aur/`, which replaces `SKIP` with the real
  checksum of the tarball GitHub then serves, and regenerate `.SRCINFO`
  afterwards, because the checksum lives in it too.
- The AUR submission is a push to a separate `ssh://aur@aur.archlinux.org/`
  repository holding just `PKGBUILD`, `.SRCINFO` and `porthole.install`. It is
  not this repository, and nothing here pushes to it.

## 4. The build service

Pushing the tag is what publishes the Fedora, Debian and Ubuntu packages.
This workflow runs for the tag like it does for a branch, and its last job --
`obs`, gated on every other job of that same run -- prepares the seven files,
attaches them to the tag's GitHub release as `obs-sources.tar`, and asks
build.opensuse.org to fetch them. The one credential this needs is a token
that can do nothing but that, and nothing to any other package.

So nothing here is a step for a person, unless something failed:

    packaging/obs/make-sources.sh <version>

writes the same seven files to `build/obs/<version>/` for uploading by hand.
[packaging/obs/README.md](../packaging/obs/README.md) says how the project is
set up, what the seven files are, and why Debian 13's repository paths are in
the order they are.

## 5. What is deliberately not in this procedure

- **No version-bumping script.** Six files in four syntaxes, three of them
  histories that need a sentence written by a person. A script would need the
  sentence anyway, and the guard in step 1 already makes a forgotten file a
  red test rather than a shipped mistake.
- **Nothing uploads to COPR, to Debian or to the AUR.** The build service is
  the one exception, and only through the workflow: on a tag it attaches the
  seven files to that tag's GitHub release and asks OBS to fetch them, with a
  token that can ask for nothing else. `make-sources.sh` on its own downloads
  the tag's tarball and the crates it needs, writes the seven files, and
  stops there.
