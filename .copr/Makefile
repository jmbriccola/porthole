# COPR configuration.
#
# COPR's "Make SRPM" source method clones this repository and runs
#
#     make -f .copr/Makefile srpm outdir=<a directory it made>
#
# in the clone, then builds whatever source RPM it finds in `outdir`. That is
# the whole interface: one target, one variable. The spec file itself lives in
# packaging/rpm/porthole.spec and is what a `rpmbuild -ba` on a release
# tarball would use as well; this file only wraps it up for COPR.
#
# By hand, from a clean checkout:
#
#     make -f .copr/Makefile srpm outdir=/tmp/porthole-srpm
#
# The tarball comes from `git archive HEAD`, so it contains what is committed
# and nothing else -- no target/, no editor leftovers, and no uncommitted
# work. `Version:` is read out of the spec rather than repeated here.

outdir ?= $(CURDIR)/build/srpm
spec   := packaging/rpm/porthole.spec
topdir := $(CURDIR)/build/rpm
version = $(shell sed -n 's/^Version:[[:space:]]*//p' $(spec))

.PHONY: srpm
srpm:
	@test -n "$(version)" || { \
	  echo 'no Version: line in $(spec)'; exit 1; }
	# COPR's SRPM environment is a minimal container: it has dnf and little
	# else, and installing into it affects nothing outside that container.
	dnf -y install rpm-build git
	# The clone COPR made belongs to a different uid than the one this runs
	# as, which git refuses to read from without being told it is expected.
	git config --global --add safe.directory $(CURDIR)
	rm -rf $(topdir)
	mkdir -p $(topdir)/SOURCES $(outdir)
	git archive --format=tar.gz --prefix=porthole-$(version)/ \
	  -o $(topdir)/SOURCES/porthole-$(version).tar.gz HEAD
	rpmbuild -bs $(spec) \
	  --define "_topdir $(topdir)" \
	  --define "_sourcedir $(topdir)/SOURCES" \
	  --define "_srcrpmdir $(outdir)"
