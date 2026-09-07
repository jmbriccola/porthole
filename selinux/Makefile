# The SELinux policy module.
#
#   make -C selinux                 build porthole.pp
#   make -C selinux install DESTDIR=... PREFIX=/usr
#   make -C selinux clean
#
# Deliberately not reachable from the root Makefile's `install`. That
# Makefile is the install layout every packaging format reads back, and a
# .pp added to it would land in the base package on every distribution --
# including the ones with no SELinux policy store to load it into, and
# without the %post/%postun scriptlets that are the only thing which makes a
# shipped .pp take effect. A module that is installed but never loaded is
# not confinement; it is a file. Ship it from a subpackage whose scriptlets
# load it, and leave the base layout alone.
#
# Building needs the reference policy headers and macros --
# selinux-policy-devel on Fedora, which puts them under
# /usr/share/selinux/devel. Nothing here loads anything.

MODULE = porthole

DEVEL_MAKEFILE ?= /usr/share/selinux/devel/Makefile

DESTDIR ?=
PREFIX  ?= /usr
DATADIR ?= $(PREFIX)/share

# Where Fedora's %selinux_modules_install expects to find a module to load.
PACKAGEDIR ?= $(DATADIR)/selinux/packages

INSTALL_DATA = install -Dm644

.PHONY: all install clean

all: $(MODULE).pp

# The reference policy's own Makefile does the whole build: m4 over the
# interface headers, then checkmodule, then semodule_package. It writes the
# .pp and loads nothing.
$(MODULE).pp: $(MODULE).te $(MODULE).fc $(MODULE).if
	@test -f $(DEVEL_MAKEFILE) || { \
	  echo 'make: $(DEVEL_MAKEFILE) is missing.'; \
	  echo '      Install selinux-policy-devel (Fedora) or the equivalent'; \
	  echo '      reference-policy headers for this distribution.'; \
	  exit 1; }
	$(MAKE) -f $(DEVEL_MAKEFILE) $@

install: $(MODULE).pp
	$(INSTALL_DATA) $(MODULE).pp $(DESTDIR)$(PACKAGEDIR)/$(MODULE).pp

clean:
	rm -rf tmp $(MODULE).pp
