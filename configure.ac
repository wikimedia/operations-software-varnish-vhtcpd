AC_PREREQ([2.68])
AC_INIT([vhtcpd],[0.1.2],[bblack@wikimedia.org],[vhtcpd],[https://gerrit.wikimedia.org/r/gitweb?p=operations/software/varnish/vhtcpd.git])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_AUX_DIR([acaux])
AM_INIT_AUTOMAKE([1.11.3 subdir-objects dist-xz no-dist-gzip foreign tar-ustar -Wall])
AC_CONFIG_MACRO_DIR([m4])

dnl TODO: when/if a new autoconf release has a C11 macro,
dnl    prefer that and fall back to requiring C99.
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = xno; then
    AC_MSG_ERROR([Your compiler lacks sufficient C99 support])
fi
dnl AC_PROG_CC_C99 has to come before this or we don't get a C99 CPP
AC_USE_SYSTEM_EXTENSIONS

dnl This is explcitly checked by CC_C99 above for now, but
dnl   the C11 standard reversed course and made this an optional
dnl   feature, so we may as well double-check here for future-proofing
AC_C_VARARRAYS
if test "x$ac_cv_c_vararrays" = xno; then
    AC_MSG_ERROR([Your compiler lacks support for variable arrays])
fi

dnl Apparently libtool+automake need this now...
AM_PROG_AR
LT_INIT
LT_PREREQ([2.4.2])

dnl include libdmn configure stuff (only sets some config.h stuff)
m4_include([src/libdmn/libdmn.m4])

dnl libev, libpcre, libjemalloc
AC_CHECK_DECLS([EVBREAK_ALL],,AC_MSG_ERROR([libev 4.x headers not found!]),[
    #include <ev.h>
])
AC_CHECK_DECLS([pcre_compile],,AC_MSG_ERROR([libpcre headers not found!]),[
    #include <pcre.h>
])
AC_CHECK_DECLS([malloc_conf],,AC_MSG_ERROR([libjemalloc headers not found!]),[
    #include <jemalloc/jemalloc.h>
])
AC_CHECK_LIB([ev],[ev_break],,AC_MSG_ERROR([libev 4.x library not found!]))
AC_CHECK_LIB([pcre],[pcre_compile],,AC_MSG_ERROR([libpcre library not found!]))
AC_CHECK_LIB([jemalloc],[malloc_stats_print],,AC_MSG_ERROR([libjemalloc library not found!]))

dnl Check for --enable-developer
developer=no
AC_ARG_ENABLE([developer],
    [  --enable-developer      Turn on gcc developer warnings, debugging, etc (default=no)],
    [if test "x$enable_developer" = xyes; then developer=yes; fi])

dnl normal builds set -DNDEBUG because we make very very heavy
dnl   use of assertions that really slow stuff down, and also
dnl   adds "-Wall -W" to CFLAGS if the compiler is gcc.
dnl --enable-developer sets liburcu debug stuff and doesn't set -DNDEBUG,
dnl   and also sets "-g" for debug if the compiler supports it,
dnl   and sets a ton of gcc 4.x extra warnings flags.
GCC_WARNFLAGS="-Wall -W -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wshadow -Wredundant-decls -Wwrite-strings -Wformat=2"
GCC_DEV_WARNFLAGS="${GCC_WARNFLAGS} -Wpointer-arith -Wfloat-equal -Wcast-align"
if test "x$developer" != xno; then
  if test "x$ac_cv_c_compiler_gnu" = xyes; then
    CFLAGS="${CFLAGS} -g ${GCC_DEV_WARNFLAGS}"
  elif test "x$ac_cv_prog_cc_g" = xyes; then
    CFLAGS="${CFLAGS} -g"
  fi
else
  if test "x$ac_cv_c_compiler_gnu" = xyes; then
    CFLAGS="${CFLAGS} ${GCC_WARNFLAGS}"
  fi
  CPPFLAGS="-DNDEBUG ${CPPFLAGS}"
fi

dnl Allow specifying an alternate rundir (default $localstatedir/run) for distros
dnl   that prefer e.g. /run to /var/run
rundir_fail="The --with-rundir= option must specify an absolute pathname if used";
AC_ARG_WITH([rundir],[
AS_HELP_STRING([--with-rundir=LOCALSTATEDIR/run],[Specify alternate ditro-specific rundir, e.g. /run, for non-chroot cases])
],[
  echo "$with_rundir" | $GREP '^/' >/dev/null || AC_MSG_ERROR($rundir_fail)
  VHTCPD_SYSRUNDIR="$with_rundir"
],[
  VHTCPD_SYSRUNDIR="${localstatedir}/run"
])
AC_SUBST([VHTCPD_SYSRUNDIR])

dnl Output generation
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
