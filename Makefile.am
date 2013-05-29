
# Where we keep m4 files for aclocal
ACLOCAL_AMFLAGS = -I m4

# Subdirectories to recurse into
SUBDIRS = src

EXTRA_DIST = NEWS t/pktgen.pl

# Some junk autotools doesn't seem to clean on its own
DISTCLEANFILES = config.h.in~ configure.ac~

# kill distfiles and coverage junk on maintainer-clean
MAINTAINERCLEANFILES = vhtcpd-*.tar.*

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck 

all-local: libtool

install-exec-hook:
	$(MKDIR_P) "$(DESTDIR)$(VHTCPD_SYSRUNDIR)";
	@id vhtcpd >/dev/null 2>&1; if test $$? -ne 0; then \
		echo; \
		echo === READ ME ===; \
		echo The default user \"vhtcpd\" \(for privdrop when executed as root\) does not seem to exist yet!; \
		echo; \
	fi
