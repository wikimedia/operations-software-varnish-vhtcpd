
EXTRA_DIST = libdmn/ http-parser/ libdmn/README
AM_CPPFLAGS = -DVHTCPD_SYSRUNDIR=\"$(VHTCPD_SYSRUNDIR)\"

LIBDMN_SRC = libdmn/dmn_daemon.c libdmn/dmn_log.c libdmn/dmn_secure.c libdmn/dmn_net.c libdmn/dmn.h

# How to build gdnsd
sbin_PROGRAMS = vhtcpd
vhtcpd_SOURCES = main.c strq.c strq.h receiver.c receiver.h purger.c purger.h stats.c stats.h http-parser/http_parser.c http-parser/http_parser.h $(LIBDMN_SRC)
vhtcpd_LDADD = -lev

TESTS = test_strq
check_PROGRAMS = test_strq
test_strq_SOURCES = test_strq.c strq.c strq.h stats.c stats.h $(LIBDMN_SRC)
test_strq_LDADD = -lev
