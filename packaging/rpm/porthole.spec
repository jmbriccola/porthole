# porthole -- RPM spec.
#
# The file list is not written here. `make install` at the repository root is
# the one place the install layout is recorded, and `%%install` below reads
# back what it put down: two `find` passes either side of `make install-gui`,
# split into a base list and a `-gui` list. A row added to the Makefile
# reaches this package without anyone editing this file, and a row that moves
# moves here too. Retyping the list is how three packaging formats end up
# shipping three different subsets of the same project.
#
# Build-time switches:
#   --without gui     leave out the porthole-gui subpackage (no GTK4 headers
#                     needed; `make install WITH_GUI=0`).
#   --without check   skip %%check.
#   --with vendor     build from a vendored crate tree (Source1) with no
#                     network access. Without it cargo fetches from
#                     crates.io, which COPR's builders allow and Koji's do
#                     not.

%bcond_without gui
%bcond_without check
%bcond_with    vendor

Name:           porthole
Version:        1.0.1
Release:        1%{?dist}
Summary:        Open a port to your local network, temporarily and on purpose

License:        GPL-3.0-or-later
URL:            https://github.com/jmbriccola/porthole
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
%if %{with vendor}
Source1:        %{name}-%{version}-vendor.tar.xz
%endif

BuildRequires:  make
BuildRequires:  gcc
# The workspace's rust-version is 1.87. That floor is a security decision --
# holding lower would mean pinning zbus and its dependants, and zbus is the
# D-Bus library of a privileged helper -- so it is expressed as a hard
# BuildRequires rather than a comment.
BuildRequires:  cargo >= 1.87
BuildRequires:  rust >= 1.87
BuildRequires:  rust-srpm-macros
BuildRequires:  systemd-rpm-macros
BuildRequires:  desktop-file-utils
BuildRequires:  libappstream-glib
# What %%check's `cargo test` runs, declared rather than left to whatever the
# build root happens to drag in. Every one of these is executed by the suite
# and named by the test that executes it; a build root without them does not
# fail with a clear message, it reports a pass on a test that ran nothing,
# which is the failure mode this list exists to prevent.
#
# The firewall itself is deliberately *not* on this list. The tests that need
# one carry their own: crates/porthole-cli/tests/cli.rs, its helper_e2e.rs and
# crates/porthole-helper/tests/{forward_gate,reconciled_signal}.rs each write
# a `firewall-cmd` and an `ip` of their own into a temporary directory and put
# it in front of `PATH`, because every command porthole issues to those two on
# the paths under test is a read of a handful of fixed shapes. Requiring
# firewalld here would be worse than useless: no build root runs a firewalld
# *daemon*, and an installed-but-stopped firewalld is what made
# crates/porthole-helper/tests/signals.rs stop skipping and start failing.
#
#   dbus-run-session  one private bus for the whole run; see %%check below
#   dbus-daemon       crates/porthole-helper/tests/signals.rs starts one on the
#                     shipped data/com.jacopobriccola.Porthole.conf and checks
#                     what a real bus daemon makes of it. dbus-broker cannot
#                     stand in, and those two tests are the only place that
#                     file is ever parsed.
#   busctl            crates/porthole-cli/tests/helper_e2e.rs waits for the
#                     helper's bus name to appear before driving it
#   nftables          two of crates/porthole-helper/tests/service.rs need a
#                     backend to be *present* (so `close` reaches RuleNotFound
#                     rather than "no firewall found"), and
#                     a_forget_announces_no_close_because_nothing_was_closed in
#                     its signals.rs needs `backend::detect` to succeed before
#                     `close_by_id` can reach `forget_rule` at all. nft is the
#                     cheapest of the three to satisfy that with, and this is
#                     the same alternation the Requires: below offers.
#   iptables          reading Docker's chain must fail as a typed CommandFailed
#                     rather than as a missing file
#
# Nothing here is run privileged and nothing here writes a rule.
#
# The first three are named by package rather than by path because the build
# service could not resolve the paths: the first upload to OBS came back
# "nothing provides /usr/bin/dbus-run-session, nothing provides
# /usr/bin/dbus-daemon, nothing provides /usr/bin/busctl" on Fedora 43 and 44
# alike (2026-09-11). `dnf repoquery --whatprovides` on Fedora 44 answers
# dbus-daemon for the first two and systemd for busctl.
BuildRequires:  dbus-daemon
BuildRequires:  systemd
BuildRequires:  nftables
BuildRequires:  /usr/sbin/iptables
%if %{with gui}
BuildRequires:  pkgconfig(gtk4)
BuildRequires:  pkgconfig(libadwaita-1)
%endif

# Three backends, chosen at runtime by porthole_core::backend::detect in that
# order: firewalld, then ufw, then nftables. Requiring firewalld by name would
# be wrong -- porthole drives whichever of the three the machine already has,
# and installs none of them.
Requires:       (firewalld or ufw or nftables)
# `ip -j route show default`, `ip -4 neigh show`, `ip -j -4 addr show`.
Requires:       iproute
# /usr/share/polkit-1/actions, and the authority the helper asks.
Requires:       polkit
# /usr/share/dbus-1/system.d and /usr/share/dbus-1/system-services belong to
# dbus-common; the bus that reads them, and the only route a client has to
# the helper, is dbus's.
Requires:       dbus-common
Requires:       dbus
# /usr/share/icons/hicolor/{scalable,symbolic}/apps.
Requires:       hicolor-icon-theme
# `iptables -t nat -S DOCKER`: how porthole notices a published container port
# that bypasses the host firewall. Without it that check reports a generic
# caveat instead of naming the ports, and nothing else changes.
Recommends:     iptables-nft
%{?systemd_requires}
# `timeout`, in %%preun: the close it bounds runs while the package is being
# erased, so the dependency is on the scriptlet rather than on the package.
Requires(preun): coreutils

%description
porthole opens one firewall port towards the network you are on right now,
for a bounded time, and closes it again by itself. Opening towards your own
subnet authenticates once per session; opening towards everything the machine
can reach asks every time. Nothing it opens survives a reboot, and no timed
opening lasts longer than eight hours.

It drives firewalld, ufw or nftables -- whichever is already installed -- and
adds no permanent rules to any of them. It is not a firewall manager: no
zones, no services, no NAT, no port forwarding.

This package contains the porthole command, the privileged D-Bus helper it
talks to, and the desktop notification agent that says when a port closed.

The agent starts at the next login, not at install time: neither of its two
start files -- a systemd user unit and an XDG autostart entry -- runs in a
session that is already open. An announced close is the only signal a timed
port has gone, so a port opened in the session that installed this package
closes with nothing said. `systemctl --user start porthole-agent.service`
starts one for the session you are in.

%if %{with gui}
%package gui
Summary:        GTK4 desktop application for porthole
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description gui
The GTK4/libadwaita window for porthole: what is open now, what is listening
on this machine, and a dialog to open a port.

Separate from the base package because it is the only part that links GTK4
and libadwaita. A headless server wants porthole's command and helper without
dragging a desktop toolkit onto the machine; the icons stay in the base
package, because the notification agent's autostart entry names the same
icon.
%endif

%prep
%autosetup -n %{name}-%{version}
%if %{with vendor}
tar -xf %{SOURCE1}
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF
%endif

%build
export RUSTFLAGS="%{?build_rustflags}"
%if %{with vendor}
export CARGO_NET_OFFLINE=true
%endif

# `build` is the workspace's default members: the CLI, the helper and the
# agent. crates/porthole-cli/build.rs renders the eleven man pages and the
# three completion files during it.
%make_build build
%if %{with gui}
%make_build build-gui
%endif

%install
# Every directory the Makefile can place a file in, pinned to this
# distribution's macro for it. The defaults already agree with Fedora's
# layout for all of them; naming them is what keeps that true if either side
# moves.
staged_install() {
    make "$@" \
        DESTDIR=%{buildroot} \
        PREFIX=%{_prefix} \
        BINDIR=%{_bindir} \
        LIBEXECDIR=%{_libexecdir} \
        DATADIR=%{_datadir} \
        MANDIR=%{_mandir} \
        SYSCONFDIR=%{_sysconfdir} \
        UNITDIR=%{_unitdir} \
        USERUNITDIR=%{_userunitdir} \
        METAINFODIR=%{_metainfodir} \
        INSTALL="install -p"
}

list_buildroot() {
    ( cd %{buildroot} && find . \( -type f -o -type l \) | sed 's|^\.||' ) \
        | LC_ALL=C sort
}

# Base first, GUI after, so the difference between the two listings is the
# -gui subpackage's file list and nobody has to write it down.
staged_install install WITH_GUI=0
list_buildroot > %{_builddir}/%{name}.files.base
%if %{with gui}
staged_install install-gui
list_buildroot > %{_builddir}/%{name}.files.all
LC_ALL=C comm -13 %{_builddir}/%{name}.files.base %{_builddir}/%{name}.files.all \
    > %{_builddir}/%{name}.files.gui
%endif

# brp-compress runs between %%install and %%files and renames the man pages to
# .1.gz, so the listing taken above names files that no longer exist by the
# time %%files is read. The trailing glob covers both spellings.
sed -i 's|^\(%{_mandir}/.*\)$|\1*|' %{_builddir}/%{name}.files.base

# Whatever the Makefile put under the distribution's sysconfdir is
# configuration, and an upgrade must not overwrite an edited copy of it.
# Written as a rule over that directory rather than as a named file, for the
# same reason the lists above are generated: the Makefile decides what lands
# there.
sed -i 's|^\(%{_sysconfdir}/.*\)$|%%config(noreplace) \1|' \
    %{_builddir}/%{name}.files.base

%check
desktop-file-validate \
    %{buildroot}%{_sysconfdir}/xdg/autostart/porthole-agent.desktop
%if %{with gui}
desktop-file-validate \
    %{buildroot}%{_datadir}/applications/com.jacopobriccola.Porthole.desktop
appstream-util validate-relax --nonet \
    %{buildroot}%{_metainfodir}/com.jacopobriccola.Porthole.metainfo.xml
%endif

# The helper's activation file and its systemd unit both name
# /usr/libexec/porthole-helper as a literal string, and the bus and systemd
# read the path out of the installed copy. `make install-helper` refuses when
# LIBEXECDIR disagrees with them; this asserts the third leg -- that the
# binary this package ships is at the path those two files name.
test -x %{buildroot}%{_libexecdir}/porthole-helper
grep -qx 'Exec=%{_libexecdir}/porthole-helper' \
    %{buildroot}%{_datadir}/dbus-1/system-services/com.jacopobriccola.Porthole.service
grep -qx 'ExecStart=%{_libexecdir}/porthole-helper' \
    %{buildroot}%{_unitdir}/porthole-helper.service
# The agent's unit is the one the Makefile rewrites; the rewrite must land on
# this package's bindir and must not have touched Restart=.
grep -qx 'ExecStart=%{_bindir}/porthole-agent' \
    %{buildroot}%{_userunitdir}/porthole-agent.service
grep -qx 'Restart=on-failure' \
    %{buildroot}%{_userunitdir}/porthole-agent.service

%if %{with check}
# %%check runs as whoever invoked rpmbuild, and as root this suite cannot run.
# Not "runs and is a bit weaker" -- cannot run, and used to report a pass
# saying so:
#
#   - porthole_core::cli_path::resolve_cli offers a *root* helper only
#     /usr/bin/porthole and /usr/local/bin/porthole, never the CLI built
#     beside it, because that path is a root-execution target for the expiry
#     timer. In a build root porthole is not installed yet, so every helper
#     crates/porthole-cli/tests/helper_e2e.rs starts exits before serving:
#     four of its five tests. They used to print `skipped:` and be counted
#     `ok`; they assert now, which is why this refusal has to come first.
#   - a_dry_run_works_without_a_writable_state_directory and
#     status_works_without_a_writable_state_directory in its cli.rs are about
#     a directory an unprivileged process cannot create. As root there is no
#     such directory, so they assert nothing -- and they say so themselves,
#     loudly, which is how a root build first surfaced as two failures.
#
# mock and COPR both build as an unprivileged user, so this refusal never
# fires there; it fires on a bare `rpmbuild -ba` run as root, which is the one
# case where six of this suite's tests cannot run. Refusing beats letting them
# through: a build that quietly ran a fraction of its own tests is exactly the
# green check that executed nothing this project keeps finding, and six
# failures that all mean "you are root" is a worse way to learn it than one
# sentence that says so.
if [ "$(id -u)" -eq 0 ] ; then
    cat >&2 <<-'REFUSAL'
	porthole: %%check must not run as root.
	porthole: `porthole-helper --session` refuses a CLI that is not installed
	porthole: at /usr/bin/porthole when it is root, and two more tests are
	porthole: about a directory an unprivileged process cannot create. Six
	porthole: tests therefore cannot run at all as root; they say so rather
	porthole: than pass, and this says it once instead of six times.
	porthole: Build as an unprivileged user, which is what mock and COPR do:
	porthole:     rpmbuild --rebuild <the .src.rpm>   # as an ordinary user
	porthole: or, to build a package without running its tests at all:
	porthole:     rpmbuild -ba --without check packaging/rpm/porthole.spec
	REFUSAL
    exit 1
fi

# `cargo test`, and with %%build's RUSTFLAGS dropped rather than reused. Those
# carry -Copt-level=3, and rustc leaves cfg!(debug_assertions) off above
# opt-level 0 whichever cargo profile asked -- measured on this spec: with
# them exported, four tests in crates/porthole-cli/tests/cli.rs fail and no
# others do. What those four reach the binary through --
# PORTHOLE_STATE_FILE, PORTHOLE_DEVICES_FILE, `porthole-helper --session` --
# is honoured only where debug_assertions holds, because a release helper
# runs privileged and must not take its state location, its address book or
# its bus from the environment.
unset RUSTFLAGS

# One private bus, standing in for both, in a chroot that has neither.
# crates/porthole-agent/tests/session.rs spawns its own session bus per test,
# crates/porthole-cli/tests/cli.rs gives every porthole process it starts a
# private one of its own, and its helper_e2e.rs starts one for the
# `porthole-helper --session` it drives -- that last so the helper cannot
# land on a session bus where something already owns its name, which on a
# developer's machine is any session with porthole-gui open. None of the
# three depends on this bus; what is left needing one is the helper's own
# service, signal and round-trip tests. The system-bus address is exported
# alongside so nothing that asks for a system bus in this chroot finds none.
#
# No firewall daemon is needed and none is started: every test that needs a
# firewall to answer writes one of its own onto `PATH` -- see the
# BuildRequires block above for which files do it and why requiring firewalld
# here would make things worse rather than better.
#
# porthole-gui is excluded: its test targets open a GTK display.
dbus-run-session -- sh -c '
    DBUS_SYSTEM_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS
    export DBUS_SYSTEM_BUS_ADDRESS
    cargo test --locked --workspace --exclude porthole-gui
'
%endif

%post
%systemd_post porthole-helper.service
# Applies the preset, which on Fedora leaves this unit disabled: the enable
# exceptions for user units live in fedora-release's own
# /usr/lib/systemd/user-preset/90-default-user.preset, not in the package
# that owns the unit, and /usr/lib/systemd/user-preset/99-default-disable.preset
# is `disable *`. That is not what decides whether notifications work right
# now, and the notice below says what does: this macro runs
# `systemctl --no-reload preset --global`, which only settles whether a
# symlink exists under /etc/systemd/user and starts nothing in a session that
# is already running. Enabled or disabled, this install announces nothing
# until the next login.
%systemd_user_post porthole-agent.service
# The bus reads /usr/share/dbus-1/system.d and
# /usr/share/dbus-1/system-services at start-up and on reload. `|| :` because
# there is no bus to reload in a chroot or an image build.
systemctl reload dbus.service >/dev/null 2>&1 || :
# $1 is 1 on a first install and 2 or more on an upgrade. Said on the first
# install only: an upgrade does not change which session the user is in, and
# a notice repeated on every version bump is one nobody reads on the day it
# matters. Same wording as debian/porthole.postinst and
# packaging/aur/porthole.install, which say it at the same moment for the
# same reason.
if [ $1 -eq 1 ] ; then
    cat >&2 <<-NOTICE
	porthole: Desktop notifications start at your next login.
	porthole: A port porthole closes by itself -- on expiry, or on a network
	porthole: change -- is announced only while porthole-agent is running, and
	porthole: neither of its start files runs in a session that is already
	porthole: open. For the session you are in, without logging out:
	porthole:     systemctl --user start porthole-agent.service
	NOTICE
fi

%preun
# $1 is 0 on an erase and 1 on an upgrade, and that is the whole distinction
# the block below turns on: an erase must close every port porthole has open,
# while an upgrade must leave them alone -- taking away access the user
# arranged, silently, as the price of a version bump, would be its own bad
# surprise. The two %%systemd_* macros branch on the same $1 themselves.
if [ $1 -eq 0 ] ; then
    # Removal has to close what porthole opened, because nothing else will.
    # Every other way a porthole rule ends needs porthole to still be
    # installed: the expiry timer re-executes %{_bindir}/porthole, `close`
    # and the network-change monitor go through the helper, and
    # reconciliation runs inside an operation. Erasing the package ends all
    # of them at once and leaves the firewall rule enforced, with the state
    # file that names it on a tmpfs and nothing left that can act on it. So
    # the close happens here, while the binaries are still on disk -- and before
    # %%systemd_preun below stops the helper, since stopping first would
    # leave the close to D-Bus-activate it again.
    #
    # `porthole close --all` rather than any shell that guesses at rules: the
    # helper owns the firewall and holds the record of what it opened, and it
    # also cancels each opening's transient expiry timer as it closes -- a
    # timer that would otherwise fire, after this erase, into a
    # %{_bindir}/porthole that is no longer there.
    #
    # Never fatal. An un-erasable package is a worse failure than a port left
    # open, and this call can fail for reasons that have nothing to do with
    # the firewall: no system bus (a container, an image build), polkit not
    # running, a helper left broken by an earlier failed upgrade. On any of
    # those the erase continues and the warning below is what the user gets.
    # Closing is not authenticated -- the polkit action
    # com.jacopobriccola.Porthole.close is `yes` for allow_any, allow_active
    # and allow_inactive -- so there is nothing here for a non-interactive
    # erase to be prompted by.
    #
    # The timeout is a bound on how long an erase can sit here: the call
    # reaches a root D-Bus service that drives the firewall, and a bus that
    # never answers must not hang rpm indefinitely.
    if [ -d /run/systemd/system ] && [ -x %{_bindir}/porthole ] ; then
        echo 'porthole: closing every port porthole still has open, before removing it.' >&2
        rc=0
        timeout 60 %{_bindir}/porthole close --all >&2 || rc=$?
        if [ "$rc" -ne 0 ] ; then
            cat >&2 <<-WARNING
	porthole: WARNING: \`porthole close --all\` failed (exit $rc).
	porthole: Any port porthole had open is still open, and removing this
	porthole: package leaves nothing behind that would close it. Check with
	porthole: \`firewall-cmd --list-rich-rules\`, \`ufw status numbered\` or
	porthole: \`nft list ruleset\` and remove what is left by hand.
	WARNING
        fi
    fi
fi
%systemd_preun porthole-helper.service
%systemd_user_preun porthole-agent.service

%postun
# try-restart, so an upgrade does not leave the previous helper binary serving
# the bus name. The state file survives it: porthole-helper.service sets
# RuntimeDirectoryPreserve=yes, and an opened port's automatic close is a
# separate systemd transient timer outside this process.
%systemd_postun_with_restart porthole-helper.service
%systemd_user_postun_with_restart porthole-agent.service
systemctl reload dbus.service >/dev/null 2>&1 || :

%files -f %{_builddir}/%{name}.files.base
%license LICENSE
%doc README.md docs/backends.md docs/installing.md docs/json-schema.md

%if %{with gui}
%files gui -f %{_builddir}/%{name}.files.gui
%endif

%changelog
* Fri Sep 11 2026 Jacopo Maria Briccola <jmbriccola@gmail.com> - 1.0.1-1
- Where firewalld refuses an unprivileged caller, firewall-cmd --state
  exits 253, and porthole read that as firewalld not running: doctor told
  the user no rule was being enforced, and open --dry-run refused on that
  premise. Only exit 252 now means stopped; any other failure is reported
  as unconfirmed.

* Fri Sep 11 2026 Jacopo Maria Briccola <jmbriccola@gmail.com> - 1.0.0-1
- First release.
- The 0.1.0 below was never published anywhere; this is the version the
  first tag carries.

* Sun Sep 06 2026 Jacopo Maria Briccola <jmbriccola@gmail.com> - 0.1.0-1
- First packaged release.
