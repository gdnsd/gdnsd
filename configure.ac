AC_PREREQ([2.63])
AC_INIT([gdnsd],[2.4.0],[https://github.com/gdnsd/gdnsd/issues])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_AUX_DIR([acaux])
AM_INIT_AUTOMAKE([1.11.1 dist-xz no-dist-gzip foreign tar-ustar subdir-objects -Wall])
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

## Autoconf-2.63-Compat
# Future reference: both of the below could be addressed by bumping our
# AC_PREREQ() to 2.64.  It's just a question of at what point in the future
# the 2.63-using distros are old enough that it's reasonable to do so.
#---
# We're compatible to autoconf 2.63, which doesn't have PACKAGE_URL
#   as a final arg to AC_INIT.  We can't define it ourselves here
#   with the same name as this causes compiler warnings that matter
#   during other parts of ./configure.  So, pick a new name for now.
AC_DEFINE([PKG_URL],["http://gdnsd.org"],[Package URL])
#---
# This hack makes PKG_CHECK_VARS from m4/pkg.m4 work on autoconf 2.63
# ( courtesy of sunnybear in https://github.com/gdnsd/gdnsd/issues/85 )
m4_ifndef([AS_VAR_COPY],
[m4_define([AS_VAR_COPY],
[AS_LITERAL_IF([$1[]$2], [$1=$$2], [eval $1=\$$2])])])
## End Autoconf-2.63-Compat

# TODO: when/if a new autoconf release has a C11 macro,
#    prefer that and fall back to requiring C99.
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = xno; then
    AC_MSG_ERROR([Your compiler lacks sufficient C99 support])
fi
# AC_PROG_CC_C99 has to come before this or we don't get a C99 CPP
AC_USE_SYSTEM_EXTENSIONS

# This is explcitly checked by CC_C99 above for now, but
#   the C11 standard reversed course and made this an optional
#   feature, so we may as well double-check here for future-proofing
AC_C_VARARRAYS
if test "x$ac_cv_c_vararrays" = xno; then
    AC_MSG_ERROR([Your compiler lacks support for variable arrays])
fi

AM_PROG_CC_C_O

# POSIX threads stuff
AX_PTHREAD(,AC_MSG_ERROR([POSIX threads support is required]))
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

AC_MSG_CHECKING([if compiling with clang])
AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([], [[
#ifndef __clang__
       not clang
#endif
]])],
[CLANG=yes], [CLANG=no])
AC_MSG_RESULT([$CLANG])

# need to know endian-ness
AC_C_BIGENDIAN

# pointer width...
AC_CHECK_SIZEOF(uintptr_t)

# Apparently libtool+automake need this now, in newer versions
#   which have it at all
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# The libtool macros in 2.2.6b - 2.4.2 have a bug that causes
#  them to accidentally add LIBADD_DLOPEN to LIBS permanently,
#  so we workaround that by saving and restoring LIBS
XLIBS=$LIBS
AC_DISABLE_STATIC
LT_INIT([dlopen])
LT_PREREQ([2.2.6])
LT_LIB_DLLOAD
AC_SUBST([LIBTOOL_DEPS])
AC_SUBST([LIBADD_DLOPEN])
LIBS=$XLIBS

# Check for --enable-developer
developer=no
AC_ARG_ENABLE([developer],
    [  --enable-developer      Turn on gcc developer warnings, debugging, etc (default=no)],
    [if test "x$enable_developer" = xyes; then developer=yes; fi])

# normal builds set -DNDEBUG because we make very very heavy
#   use of assertions that really slow stuff down.
# --enable-developer sets liburcu debug stuff and doesn't set -DNDEBUG,
if test "x$developer" != xno; then
    AC_DEFINE([DEBUG_RCU], 1, [liburcu verification checks])
    AC_DEFINE([RCU_DEBUG], 1, [liburcu verification checks])
    TRY_DEBUG_CFLAGS=-g
else
    CPPFLAGS="-DNDEBUG ${CPPFLAGS}"
    TRY_DEBUG_CFLAGS=
fi

# These are only for urcu header stuff currently
AC_DEFINE([_LGPL_SOURCE], 1, [LGPL-compatible source])
AC_DEFINE([GDNSD_SOURCE_TREE], 1, [Identifies local source vs 3rd party])

harden=1
AC_ARG_WITH([hardening],[AS_HELP_STRING([--without-hardening],
    [Disable compiler/linker flags for security hardening])],[
    if test "x$withval" = xno; then
        harden=0
    fi
])
HARDEN_COMPILER=
HARDEN_LINKER=
CFLAGS_PIE=
LDFLAGS_PIE=
if test $harden = 1; then
    AS_CASE([$CFLAGS], [*-O[[1-6]]*], [CPPFLAGS="-D_FORTIFY_SOURCE=2 ${CPPFLAGS}"])
    HARDEN_COMPILER="-fstack-protector-all -ftrapv"
    HARDEN_LINKER="-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"
    AX_APPEND_COMPILE_FLAGS([-fPIE],[CFLAGS_PIE],[])
    AX_APPEND_LINK_FLAGS([-pie],[LDFLAGS_PIE],[])
fi
AC_SUBST([CFLAGS_PIE])
AC_SUBST([LDFLAGS_PIE])

# clang does not fail on some unsupported options without this,
#  but it screws up some of our warnflag tests on gcc as well.
CLANG_WERROR=
if test $CLANG = yes; then
   CLANG_WERROR="-Werror"
fi

AX_APPEND_LINK_FLAGS([\
    $HARDEN_LINKER \
    -Wl,--as-needed \
    -Wl,--gc-sections \
],[LDFLAGS],[$CLANG_WERROR])

AX_APPEND_COMPILE_FLAGS([\
    $TRY_DEBUG_CFLAGS \
    $HARDEN_COMPILER \
    -fvisibility=hidden \
    -ffunction-sections \
    -fdata-sections \
    -fno-common \
    -pipe \
    -Wall \
    -Wextra \
    -Warray-bounds=2 \
    -Wbad-function-cast \
    -Wcast-align \
    -Wcast-qual \
    -Wduplicated-cond \
    -Wendif-labels \
    -Wfloat-equal \
    -Wfloat-conversion \
    -Wformat=2 \
    -Wformat-signedness \
    -Winit-self \
    -Wjump-misses-init \
    -Wlogical-op \
    -Wloop-analysis \
    -Wmissing-declarations \
    -Wmissing-include-dirs \
    -Wmissing-prototypes \
    -Wnull-dereference \
    -Wold-style-definition \
    -Wpointer-arith \
    -Wredundant-decls \
    -Wshadow \
    -Wsign-conversion \
    -Wshift-overflow=2 \
    -Wstrict-overflow=5 \
    -Wstrict-prototypes \
    -Wswitch-default \
    -Wswitch-enum \
    -Wtrampolines \
    -Wundef \
    -Wunused \
    -Wwrite-strings \
    -Wthis-does-not-exist \
],[CFLAGS],[$CLANG_WERROR])

# include libdmn configure stuff
m4_include([libgdnsd/libdmn.m4])

# include libgdmaps configure stuff
m4_include([libgdmaps/libgdmaps.m4])

# explicit check on math lib.  libev also does this, but
#  might not in the future, and we need it directly
XLIBS=$LIBS
LIBS=""
AC_CHECK_LIB(m,atan2)
MATH_LIB=$LIBS
LIBS=$XLIBS
AC_SUBST([MATH_LIB])

# posix_madvise to readahead on zonefiles
AC_CHECK_FUNCS([posix_madvise])

# high-precision mtime from struct stat
AC_CHECK_MEMBERS([struct stat.st_mtim.tv_nsec])
AC_CHECK_MEMBERS([struct stat.st_mtimespec.tv_nsec])
AC_CHECK_MEMBERS([struct stat.st_mtimensec])

# *mmsg for Linux
HAS_SENDMMSG=1
AC_CHECK_DECLS([sendmmsg, recvmmsg],,[HAS_SENDMMSG=0],[[#include <sys/socket.h>]])
AC_CHECK_FUNCS([sendmmsg recvmmsg],,[HAS_SENDMMSG=0])
if test $HAS_SENDMMSG -eq 1; then
    AC_DEFINE([USE_SENDMMSG],1,[Linux sendmmsg is usable])
fi

# Network Stuff
AC_DEFINE([__APPLE_USE_RFC_3542],1,[Force MacOS Lion and higher to use RFC3542 IPv6 stuff])

# liburcu-qsbr
KILL_QSBR=0
AC_ARG_WITH([urcu],[AS_HELP_STRING([--without-urcu],
    [Explicitly disable userspace-rcu detection])],[
    if test "x$withval" = xno; then
        KILL_QSBR=1
    fi
])

GDNSD_B_QSBR=0
QSBRLIBS=
if test $KILL_QSBR -eq 0; then
    AC_CHECK_HEADER(urcu-qsbr.h,[
        XLIBS=$LIBS
        LIBS=""
        AC_CHECK_LIB([urcu-qsbr],[perror],[
            GDNSD_B_QSBR=1
            QSBRLIBS="-lurcu-qsbr"
        ])
        LIBS=$XLIBS
    ])
fi
AC_DEFINE_UNQUOTED([GDNSD_B_QSBR], [$GDNSD_B_QSBR], [Use liburcu-qsbr])
AC_SUBST([GDNSD_B_QSBR])
AC_SUBST([QSBRLIBS])

# systemd unit dir for "make install" of gdnsd.service
PKG_CHECK_VAR([SYSD_UNITDIR], [systemd], [systemdsystemunitdir])
AC_MSG_CHECKING([for systemd system unit installdir])
AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
        if test x"$with_systemdsystemunitdir" = xno; then
            with_systemdsystemunitdir=""
        fi,
        [with_systemdsystemunitdir="$SYSD_UNITDIR"]
)
if test -n "$with_systemdsystemunitdir"; then
    AC_MSG_RESULT([$with_systemdsystemunitdir])
else
    AC_MSG_RESULT([none])
fi
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL(DO_SYSD_UNITFILE, [test -n "$with_systemdsystemunitdir"])

# libev (which shouldn't use pkg-config anyways, but has
#   to on Fedora because they munge the header path the author intended...)
PKG_CHECK_MODULES([LIBEV],[libev >= 4.0],
    CPPFLAGS="${CPPFLAGS} ${LIBEV_CFLAGS}"
,
    # try manually...
    XLIBS=$LIBS
    LIBS=""
    AC_CHECK_LIB([ev],[ev_break],,AC_MSG_ERROR([libev 4.x library not found!]))
    AC_CHECK_DECLS([EVBREAK_ALL],,AC_MSG_ERROR([libev 4.x headers not found!]),[
        #include <ev.h>
    ])
    LIBEV_LIBS=$LIBS
    LIBS=$XLIBS
)
AC_SUBST([LIBEV_LIBS])

#---------------------------------------------
# pthread setname (4 non-portable variants...)
#---------------------------------------------
AC_CHECK_HEADERS([pthread_np.h])
define(pthread_np_preamble,[
  #include <pthread.h>
  #if HAVE_PTHREAD_NP_H
  #  include <pthread_np.h>
  #endif
])
# 2-arg setname (e.g. Linux/glibc, QNX, IBM)
AC_MSG_CHECKING([for 2-arg pthread_setname_np])
AC_LINK_IFELSE([AC_LANG_PROGRAM(pthread_np_preamble, [
    pthread_setname_np(pthread_self(), "foo")
])], [
  AC_DEFINE(HAVE_PTHREAD_SETNAME_NP_2, 1, [2-arg pthread_setname_np])
  AC_MSG_RESULT([yes])
], [
  AC_MSG_RESULT([no])

  # 2-arg set_name (e.g. FreeBSD, OpenBSD)
  AC_MSG_CHECKING([for 2-arg pthread_set_name_np])
  AC_LINK_IFELSE([AC_LANG_PROGRAM(pthread_np_preamble, [
      return pthread_set_name_np(pthread_self(), "foo");
  ])], [
    AC_DEFINE(HAVE_PTHREAD_SET_NAME_NP_2, 1, [2-arg pthread_set_name_np])
    AC_MSG_RESULT([yes])
  ], [
    AC_MSG_RESULT([no])

    # 1-arg setname (e.g. Darwin)
    AC_MSG_CHECKING([for 1-arg pthread_setname_np])
    AC_LINK_IFELSE([AC_LANG_PROGRAM(pthread_np_preamble, [
        return pthread_setname_np("foo");
    ])], [
      AC_DEFINE(HAVE_PTHREAD_SETNAME_NP_1, 1, [1-arg pthread_setname_np])
      AC_MSG_RESULT([yes])
    ], [
      AC_MSG_RESULT([no])

      # 3-arg setname (e.g. NetBSD)
      AC_MSG_CHECKING([for 3-arg pthread_setname_np])
      AC_LINK_IFELSE([AC_LANG_PROGRAM(pthread_np_preamble, [
          return pthread_setname_np(pthread_self(), "foo", NULL);
      ])], [
        AC_DEFINE(HAVE_PTHREAD_SETNAME_NP_3, 1, [3-arg pthread_setname_np])
        AC_MSG_RESULT([yes])
      ], [
        AC_MSG_RESULT([no])
      ])
    ])
  ])
])
#---------------------------------------------
# end pthread_setname stuff
#---------------------------------------------

# == inotify stuff ==
# inotify_init1() is Linux 2.6.27+ and glibc 2.9
# We also use Linux 2.6.36+ / glibc 2.13 IN_EXCL_UNLINK, but we
#   fix that with a manual ifndef for the define and a runtime
#   kernel version check for the support
USE_INOTIFY=1
AC_CHECK_FUNCS([inotify_init1],,[USE_INOTIFY=0])
if test $USE_INOTIFY -eq 1; then
    AC_DEFINE([USE_INOTIFY], 1, [Linux 2.6.36+ inotify support])
fi

# Basic perl 5.10.1+
AC_ARG_VAR([PERL],[path to Perl 5.10.1 or higher])
if test "x$ac_cv_env_PERL_set" != "xset"; then
    AC_PATH_PROG([PERL],[perl],[missing])
fi
if test x"$PERL" = xmissing; then
    AC_MSG_ERROR([Cannot find required perl binary])
fi
AX_PROG_PERL_VERSION([5.10.1],,[AC_MSG_ERROR([Perl 5.10.1 or higher required])])

# pod2man
AC_ARG_VAR([POD2MAN],[path to the Perl "pod2man" command])
if test "x$ac_cv_env_POD2MAN_set" != "xset"; then
    AC_PATH_PROG([POD2MAN],[pod2man],[missing])
fi
if test x"$POD2MAN" = xmissing; then
    AC_MSG_ERROR([Cannot find required pod2man binary (perl podlater)])
fi

# prove for test harness (optional)
AC_ARG_VAR([PROVE], [path to the Perl Test::Harness "prove" command])
if test "x$ac_cv_env_PROVE_set" != "xset"; then
    AC_PATH_PROG([PROVE],[prove],[missing])
fi
if test x"$PROVE" = xmissing; then
    AC_MSG_WARN([Cannot "make check" without the Perl Test::Harness "prove" command])
fi

# various perl modules for the testsuites (optional)
HAVE_TESTSUITE_MODULES=0
AX_PROG_PERL_MODULES(
    [Test::More JSON::PP Socket6 IO::Socket::INET6 HTTP::Daemon LWP],
    [HAVE_TESTSUITE_MODULES=1],
    AC_MSG_WARN([[Cannot "make check" without Perl modules Test::More, JSON::PP, Socket6, IO::Socket::INET6, HTTP::Daemon, and LWP (aka libwww-perl)]])
)
AC_SUBST([HAVE_TESTSUITE_MODULES])

# Find ragel
AC_ARG_VAR([RAGEL],[path to ragel version 6.x])
if test "x$ac_cv_env_RAGEL_set" != "xset"; then
    AC_PATH_PROG([RAGEL],[ragel],[missing])
fi
if test "x$RAGEL" = xmissing; then
    AC_MSG_ERROR([Ragel not found])
else
    $RAGEL --version|$EGREP 'Ragel State Machine Compiler version 6\.' >/dev/null \
        || AC_MSG_ERROR([Ragel is not version 6.x])
fi

# Discover CPUs for testsuite parallelism, allowing user to override via env var.
# I'd much rather either:
#  (a) steal the user-supplied -jN argument from make inside of Makefile.am,
#      but there doesn't seem to be a really good way to do that reliably, especially with
#      recursive make.  or...
#  (b) Set -jN based on TEST_CPUS (and rename it BUILD_CPUS), but there doesn't seem
#      to be any clean way to do that either without disabling direct user override
#      of that in MAKEFLAGS at make invocation time...
# As things stand with this commit, user-supplied -jN controls build parallelism
#  and is not auto-detected, while TEST_CPUS controls testsuite parallelism, and
#  is auto-detected but can be overridden at configure time.
AC_ARG_VAR([TEST_CPUS],[number of CPUs to assume when parallelizing the testsuite])
AC_MSG_CHECKING([number of CPUs available for testing])
if test "x$ac_cv_env_TEST_CPUS_set" = "xset"; then
    AC_MSG_RESULT([$TEST_CPUS (user-specified)])
else
    # These two methods should work for the *BSDs, MacOS, and Linux
    TEST_CPUS=$(sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
    AC_MSG_RESULT([$TEST_CPUS])
fi

# Decompressor for compressed test data from git submodule
AC_ARG_VAR([XZ],[path to xz compression utility])
if test "x$ac_cv_env_XZ_set" != "xset"; then
    AC_PATH_PROG([XZ], [xz], [missing])
fi
AM_CONDITIONAL(HAS_XZ, [test x$XZ != xmissing])

# Allow user to override the port range we use for testing
AC_ARG_WITH([testport],[AS_HELP_STRING([--with-testport=N],
    [The testsuite needs ~300 IP port numbers to use, starting at "N", that it can bind to on "127.0.0.1" and "::1".  If the default value of "12345" does not work for you, change it here.])],
    [],
    [with_testport=12345]
)

TESTPORT_START=$with_testport
AC_SUBST([TESTPORT_START])

AC_CHECK_HEADERS([valgrind/memcheck.h])

# Allow specifying an alternate rundir (default $localstatedir/run) for distros
#   that prefer e.g. /run to /var/run
rundir_fail="The --with-rundir= option must specify an absolute pathname if used";
AC_ARG_WITH([rundir],[AS_HELP_STRING([--with-rundir=LOCALSTATEDIR/run],
    [Specify alternate ditro-specific rundir, e.g. /run])],[
  echo "$with_rundir" | $GREP '^/' >/dev/null || AC_MSG_ERROR($rundir_fail)
  GDNSD_DEFPATH_RUN="${with_rundir}/${PACKAGE_NAME}"
],[
  GDNSD_DEFPATH_RUN="${localstatedir}/run/${PACKAGE_NAME}"
])
GDNSD_DEFPATH_CONFIG="${sysconfdir}/${PACKAGE_NAME}"
GDNSD_DEFPATH_STATE="${localstatedir}/lib/${PACKAGE_NAME}"
GDNSD_DEFPATH_LIB="${libdir}/${PACKAGE_NAME}"
GDNSD_DEFPATH_LIBEXEC="${libexecdir}/${PACKAGE_NAME}"
AC_SUBST([GDNSD_DEFPATH_RUN])
AC_SUBST([GDNSD_DEFPATH_CONFIG])
AC_SUBST([GDNSD_DEFPATH_STATE])
AC_SUBST([GDNSD_DEFPATH_LIB])
AC_SUBST([GDNSD_DEFPATH_LIBEXEC])

# clump up all of the libgdnsd libdeps for re-use in LDADD for
#   binaries that link libgdnsd on platforms where libtool's
#   automatic dep resolution is disabled
LIBGDNSD_LIBS="$MATH_LIB $QSBRLIBS $LIBEV_LIBS $LIBADD_DLOPEN $LIBUNWIND_LIBS"
AC_SUBST([LIBGDNSD_LIBS])

# BUILD_FEATURES for cmdline output
B_FEAT="prod"
if test "x$developer" != xno;    then B_FEAT="dev";             fi
if test "x$HAS_SENDMMSG" = x1;   then B_FEAT="$B_FEAT mmsg";    fi
if test "x$USE_INOTIFY" = x1;    then B_FEAT="$B_FEAT inotify"; fi
if test "x$HAVE_LIBUNWIND" = x1; then B_FEAT="$B_FEAT unwind";  fi
if test "x$HAVE_GEOIP2" = x1;    then B_FEAT="$B_FEAT geoip2";  fi
if test "x$GDNSD_B_QSBR" = x1;   then B_FEAT="$B_FEAT urcu";    fi
AC_DEFINE_UNQUOTED([BUILD_FEATURES], ["$B_FEAT"], [Build Features])

# BUILD_INFO for cmdline output
B_INFO=non-git
if test -d ${srcdir}/${GIT_DIR:-.git} -o -f ${srcdir}/.git; then
    [B_INFO=`cd ${srcdir}; git describe --match 'v[0-9]*' --always --dirty`]
fi
AC_DEFINE_UNQUOTED([BUILD_INFO],["$B_INFO"],[Build Info])

# Output generation
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  t/Makefile
  t/libtap/Makefile
  t/libgdmaps/Makefile
])
AC_CONFIG_COMMANDS([mkdirs],[$MKDIR_P sysd; $MKDIR_P docs])
AC_OUTPUT

echo "========================================================================"
echo "| Build Info: $B_INFO"
echo "| Build Features: $B_FEAT"
echo "| CC: $CC"
echo "| CPPFLAGS: $CPPFLAGS"
echo "| CFLAGS: $CFLAGS $CFLAGS_PIE"
echo "| LDFLAGS: $LDFLAGS $LDFLAGS_PIE"
echo "========================================================================"
