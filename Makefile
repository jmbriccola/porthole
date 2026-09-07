# The install layout. Every packaging format calls `make install` and lists
# no files of its own: three copies of this table would drift, and the way
# drift shows up is a package that ships the helper without its polkit
# policy, which fails looking like a porthole bug.
#
#   make                      build everything this host can build
#   make install DESTDIR=... PREFIX=/usr
#   make check-install        install into a throwaway DESTDIR and list it
#   make uninstall            remove what `install` put down
#
# DESTDIR is honoured by every rule. Nothing here needs root; staging into a
# DESTDIR and packaging that is the intended use.

CARGO   ?= cargo
PROFILE ?= release
TARGETDIR ?= target

# Where the built binaries are read from, and where build.rs leaves the man
# pages and completions. Overridable together for an out-of-tree build.
BINSRC    ?= $(TARGETDIR)/$(PROFILE)
ASSETSDIR ?= $(TARGETDIR)/$(PROFILE)/assets

# porthole-gui links GTK4/libadwaita. WITH_GUI=0 installs the CLI, the helper
# and the agent without it -- a headless machine, or a build host with no
# GTK4 development headers. It skips exactly the GUI binary, the desktop
# entry that launches it and the AppStream metainfo that describes it; the
# icons stay, because the agent's autostart entry names the same icon.
WITH_GUI ?= 1

# /usr, not /usr/local: data/com.jacopobriccola.Porthole.service and
# data/porthole-helper.service both name /usr/libexec/porthole-helper
# literally, and the D-Bus daemon reads that path out of the installed file
# rather than from anything this Makefile can tell it. The check further down
# refuses an install whose LIBEXECDIR disagrees with those two files -- while
# this Makefile is being read, before any recipe runs -- so a PREFIX=/usr/local
# install needs LIBEXECDIR=/usr/libexec passed with it.
PREFIX  ?= /usr
DESTDIR ?=

BINDIR     ?= $(PREFIX)/bin
LIBEXECDIR ?= $(PREFIX)/libexec
DATADIR    ?= $(PREFIX)/share
MANDIR     ?= $(DATADIR)/man
SYSCONFDIR ?= /etc

# `$(PREFIX)/lib/systemd`, not `/lib/systemd`: systemd reads unit files from
# /usr/local/lib/systemd/{system,user} as well as /usr/lib/systemd, so
# PREFIX=/usr/local still lands somewhere systemd looks. It reads no other
# prefix -- PREFIX=/opt/porthole writes units systemd never looks at.
UNITDIR     ?= $(PREFIX)/lib/systemd/system
USERUNITDIR ?= $(PREFIX)/lib/systemd/user

POLKITDIR      ?= $(DATADIR)/polkit-1/actions
DBUSCONFDIR    ?= $(DATADIR)/dbus-1/system.d
DBUSSERVICEDIR ?= $(DATADIR)/dbus-1/system-services
APPDIR         ?= $(DATADIR)/applications
METAINFODIR    ?= $(DATADIR)/metainfo
ICONDIR        ?= $(DATADIR)/icons/hicolor
AUTOSTARTDIR   ?= $(SYSCONFDIR)/xdg/autostart

# Completion directories differ between distributions; each is overridable on
# its own. Debian, for one, prefers zsh/vendor-completions over site-functions.
BASHCOMPDIR ?= $(DATADIR)/bash-completion/completions
ZSHCOMPDIR  ?= $(DATADIR)/zsh/site-functions
FISHCOMPDIR ?= $(DATADIR)/fish/vendor_completions.d

# One page per node of the command tree, all rendered by
# crates/porthole-cli/build.rs from the same clap definition `porthole --help`
# prints. Every page's SUBCOMMANDS section cross-references its children by
# name, so a subset of this list ships broken references. Named rather than
# globbed: an empty glob installs nothing without saying so, and this list
# failing loudly is what catches a generation step that stopped running.
MAN1 = porthole.1 \
       porthole-open.1 \
       porthole-close.1 \
       porthole-list.1 \
       porthole-status.1 \
       porthole-doctor.1 \
       porthole-listen.1 \
       porthole-devices.1 \
       porthole-devices-list.1 \
       porthole-devices-add.1 \
       porthole-devices-rm.1

INSTALL         = install
INSTALL_PROGRAM = $(INSTALL) -Dm755
INSTALL_DATA    = $(INSTALL) -Dm644

GENDIR   = $(TARGETDIR)/generated
CHECKDIR ?= $(TARGETDIR)/install-check

.PHONY: all build build-gui install install-cli install-helper install-agent \
        install-gui install-icons install-man install-completions \
        uninstall check-install clean help

all: build

# The workspace's own default-members leave porthole-gui out, so this builds
# the CLI, the helper and the agent. build.rs renders the man pages and the
# completions into $(ASSETSDIR) as part of it.
build:
	$(CARGO) build --$(PROFILE) --locked

build-gui:
	$(CARGO) build --$(PROFILE) --locked -p porthole-gui

ifeq ($(WITH_GUI),1)
install: install-cli install-helper install-agent install-gui install-icons
else
install: install-cli install-helper install-agent install-icons
endif

install-cli: install-man install-completions
	$(INSTALL_PROGRAM) $(BINSRC)/porthole $(DESTDIR)$(BINDIR)/porthole

# The two files below name /usr/libexec/porthole-helper literally, and the
# D-Bus daemon and systemd read the path out of them rather than from this
# Makefile. Installing the binary somewhere they do not name produces an
# activation that fails at the moment someone first opens a port.
#
# Checked here rather than inside install-helper's recipe, because a recipe
# runs after its prerequisites: install-helper is `install`'s second one, and
# a check there exits with the CLI, the man pages and the completions already
# on disk -- a root-owned CLI with no helper, no polkit policy and no D-Bus
# files. $(error) is raised while this file is being read, so a disagreeing
# LIBEXECDIR stops make with nothing installed at all.
#
# Only for the goals that reach install-helper. `install-cli` and the rest
# read no path out of these files, and `make clean PREFIX=/opt` has no reason
# to fail. `check-install` recurses with `install` on the sub-make's command
# line, so that sub-make is checked here in its turn.
ifneq (,$(filter install install-helper,$(MAKECMDGOALS)))
ifneq (ok,$(shell grep -qx 'Exec=$(LIBEXECDIR)/porthole-helper' \
                    data/com.jacopobriccola.Porthole.service && echo ok))
$(error LIBEXECDIR=$(LIBEXECDIR) does not match the Exec= line in \
        data/com.jacopobriccola.Porthole.service. Pass LIBEXECDIR=/usr/libexec, \
        or change that file. Nothing has been installed)
endif
ifneq (ok,$(shell grep -qx 'ExecStart=$(LIBEXECDIR)/porthole-helper' \
                    data/porthole-helper.service && echo ok))
$(error LIBEXECDIR=$(LIBEXECDIR) does not match the ExecStart= line in \
        data/porthole-helper.service. Pass LIBEXECDIR=/usr/libexec, or change \
        that file. Nothing has been installed)
endif
endif

install-helper:
	$(INSTALL_PROGRAM) $(BINSRC)/porthole-helper \
	  $(DESTDIR)$(LIBEXECDIR)/porthole-helper
	$(INSTALL_DATA) data/com.jacopobriccola.Porthole.policy \
	  $(DESTDIR)$(POLKITDIR)/com.jacopobriccola.Porthole.policy
	$(INSTALL_DATA) data/com.jacopobriccola.Porthole.conf \
	  $(DESTDIR)$(DBUSCONFDIR)/com.jacopobriccola.Porthole.conf
	$(INSTALL_DATA) data/com.jacopobriccola.Porthole.service \
	  $(DESTDIR)$(DBUSSERVICEDIR)/com.jacopobriccola.Porthole.service
	$(INSTALL_DATA) data/porthole-helper.service \
	  $(DESTDIR)$(UNITDIR)/porthole-helper.service

# data/porthole-agent.service ships the by-hand install's
# /usr/local/bin/porthole-agent, because a systemd unit's ExecStart= is an
# absolute path and nothing looks it up on $$PATH. The rewrite below makes
# the installed copy name $(BINDIR); the grep after it fails the build if the
# substitution matched nothing. The autostart entry beside it needs no such
# treatment -- a desktop entry's Exec= is looked up on $$PATH.
$(GENDIR)/porthole-agent.service: data/porthole-agent.service
	@mkdir -p $(GENDIR)
	sed 's|^ExecStart=.*/porthole-agent$$|ExecStart=$(BINDIR)/porthole-agent|' \
	  $< > $@
	@grep -qx 'ExecStart=$(BINDIR)/porthole-agent' $@ || { \
	  echo 'make: the ExecStart= rewrite left no ExecStart=$(BINDIR)/porthole-agent'; \
	  echo '      in $@. data/porthole-agent.service has changed shape.'; \
	  exit 1; }

install-agent: $(GENDIR)/porthole-agent.service
	$(INSTALL_PROGRAM) $(BINSRC)/porthole-agent \
	  $(DESTDIR)$(BINDIR)/porthole-agent
	$(INSTALL_DATA) $(GENDIR)/porthole-agent.service \
	  $(DESTDIR)$(USERUNITDIR)/porthole-agent.service
	$(INSTALL_DATA) data/porthole-agent.desktop \
	  $(DESTDIR)$(AUTOSTARTDIR)/porthole-agent.desktop

install-gui:
	$(INSTALL_PROGRAM) $(BINSRC)/porthole-gui $(DESTDIR)$(BINDIR)/porthole-gui
	$(INSTALL_DATA) data/com.jacopobriccola.Porthole.desktop \
	  $(DESTDIR)$(APPDIR)/com.jacopobriccola.Porthole.desktop
	$(INSTALL_DATA) data/com.jacopobriccola.Porthole.metainfo.xml \
	  $(DESTDIR)$(METAINFODIR)/com.jacopobriccola.Porthole.metainfo.xml

install-icons:
	$(INSTALL_DATA) data/icons/hicolor/scalable/apps/com.jacopobriccola.Porthole.svg \
	  $(DESTDIR)$(ICONDIR)/scalable/apps/com.jacopobriccola.Porthole.svg
	$(INSTALL_DATA) data/icons/hicolor/symbolic/apps/com.jacopobriccola.Porthole-symbolic.svg \
	  $(DESTDIR)$(ICONDIR)/symbolic/apps/com.jacopobriccola.Porthole-symbolic.svg

install-man:
	@for page in $(MAN1); do \
	  test -f $(ASSETSDIR)/man/$$page || { \
	    echo "make: $(ASSETSDIR)/man/$$page is missing."; \
	    echo '      crates/porthole-cli/build.rs renders it during'; \
	    echo '      `make build`. Run that first, or set ASSETSDIR.'; \
	    exit 1; }; \
	done
	@for page in $(MAN1); do \
	  echo "$(INSTALL_DATA) $(ASSETSDIR)/man/$$page $(DESTDIR)$(MANDIR)/man1/$$page"; \
	  $(INSTALL_DATA) $(ASSETSDIR)/man/$$page $(DESTDIR)$(MANDIR)/man1/$$page; \
	done

install-completions:
	$(INSTALL_DATA) $(ASSETSDIR)/completions/porthole.bash \
	  $(DESTDIR)$(BASHCOMPDIR)/porthole
	$(INSTALL_DATA) $(ASSETSDIR)/completions/_porthole \
	  $(DESTDIR)$(ZSHCOMPDIR)/_porthole
	$(INSTALL_DATA) $(ASSETSDIR)/completions/porthole.fish \
	  $(DESTDIR)$(FISHCOMPDIR)/porthole.fish

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/porthole
	rm -f $(DESTDIR)$(BINDIR)/porthole-gui
	rm -f $(DESTDIR)$(BINDIR)/porthole-agent
	rm -f $(DESTDIR)$(LIBEXECDIR)/porthole-helper
	rm -f $(DESTDIR)$(POLKITDIR)/com.jacopobriccola.Porthole.policy
	rm -f $(DESTDIR)$(DBUSCONFDIR)/com.jacopobriccola.Porthole.conf
	rm -f $(DESTDIR)$(DBUSSERVICEDIR)/com.jacopobriccola.Porthole.service
	rm -f $(DESTDIR)$(UNITDIR)/porthole-helper.service
	rm -f $(DESTDIR)$(USERUNITDIR)/porthole-agent.service
	rm -f $(DESTDIR)$(AUTOSTARTDIR)/porthole-agent.desktop
	rm -f $(DESTDIR)$(APPDIR)/com.jacopobriccola.Porthole.desktop
	rm -f $(DESTDIR)$(METAINFODIR)/com.jacopobriccola.Porthole.metainfo.xml
	rm -f $(DESTDIR)$(ICONDIR)/scalable/apps/com.jacopobriccola.Porthole.svg
	rm -f $(DESTDIR)$(ICONDIR)/symbolic/apps/com.jacopobriccola.Porthole-symbolic.svg
	rm -f $(DESTDIR)$(BASHCOMPDIR)/porthole
	rm -f $(DESTDIR)$(ZSHCOMPDIR)/_porthole
	rm -f $(DESTDIR)$(FISHCOMPDIR)/porthole.fish
	for page in $(MAN1); do rm -f $(DESTDIR)$(MANDIR)/man1/$$page; done

# Stages the whole layout into a throwaway directory and prints it. What a
# packager should run before writing a spec file, and what
# crates/porthole-cli/tests/install_layout.rs runs on its own DESTDIR.
check-install:
	rm -rf $(CHECKDIR)
	$(MAKE) install DESTDIR=$(abspath $(CHECKDIR)) PREFIX=/usr
	@echo
	@echo 'installed under $(CHECKDIR):'
	@cd $(CHECKDIR) && find . -type f | sed 's|^\.||' | sort

clean:
	$(CARGO) clean
	rm -rf $(GENDIR) $(CHECKDIR)

help:
	@sed -n '1,12p' Makefile
