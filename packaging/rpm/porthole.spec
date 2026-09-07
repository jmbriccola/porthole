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
Version:        0.1.0
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
# %%check runs the workspace's own suite, which drives the helper and the CLI
# against the real tools rather than stubs. crates/porthole-agent/tests/session.rs
# spawns each agent under a private session bus; two of
# crates/porthole-helper/tests/service.rs need a backend to be *present* (so
# `close` reaches RuleNotFound rather than "no firewall found") and `iptables`
# to be *present* (so reading Docker's chain fails as a typed CommandFailed
# rather than as a missing file). Neither is run privileged, and neither
# writes a rule.
BuildRequires:  /usr/bin/dbus-run-session
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

# One private bus, standing in for both. crates/porthole-agent/tests/session.rs
# spawns its own session bus per test and does not need this; what this adds
# is a system-bus address for `porthole doctor` to reach, so its helper check
# reports a bus on which nothing owns the name -- which is the state
# crates/porthole-cli/tests/cli.rs asserts the remedy for. Without it that one
# test sees no bus at all and fails.
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
%systemd_user_post porthole-agent.service
# The bus reads /usr/share/dbus-1/system.d and
# /usr/share/dbus-1/system-services at start-up and on reload. `|| :` because
# there is no bus to reload in a chroot or an image build.
systemctl reload dbus.service >/dev/null 2>&1 || :

%preun
# $1 is 0 on an erase and 1 on an upgrade, and both macros below branch on
# that themselves. Nothing here acts on ports the helper has open.
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
* Sun Sep 06 2026 Jacopo Maria Briccola <jmbriccola@gmail.com> - 0.1.0-1
- First packaged release.
