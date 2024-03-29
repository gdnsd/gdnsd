m4_define([PKG_V_MAJOR],[3])
m4_define([PKG_V_MINOR],[8])
m4_define([PKG_V_PATCH],[2])
m4_define([PKG_V_EXTRA],[])
m4_define([PVER],[PKG_V_MAJOR().PKG_V_MINOR().PKG_V_PATCH()PKG_V_EXTRA()])

AC_PREREQ([2.64])
AC_INIT([gdnsd],[PVER],[https://github.com/gdnsd/gdnsd/issues],[gdnsd],[https://gdnsd.org])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_AUX_DIR([acaux])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([1.13 dist-xz no-dist-gzip foreign tar-ustar subdir-objects -Wall])
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

# Guard against version components that are out of range for the positive half
# of a signed byte value.  Really we could use unsigned values too, but it
# seems safer to be more-restrictive by default here so that we don't ever have
# to worry about some integer conversion rule.  The major constraint here is
# that our control socket protocol communicates these as unsigned byte values.
AS_IF([test PKG_V_MAJOR -gt 127 -o PKG_V_MINOR -gt 127 -o PKG_V_PATCH -gt 127],
    [AC_MSG_ERROR([Package version components must be <= 127])]
)

# Make the three numeric components available directly to code
AC_DEFINE_UNQUOTED([PACKAGE_V_MAJOR], [PKG_V_MAJOR], [Major version])
AC_DEFINE_UNQUOTED([PACKAGE_V_MINOR], [PKG_V_MINOR], [Minor version])
AC_DEFINE_UNQUOTED([PACKAGE_V_PATCH], [PKG_V_PATCH], [Patch version])

AC_USE_SYSTEM_EXTENSIONS
# We're hoping for C11, but anything C99 or higher will work
AC_PROG_CC_STDC
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

# Various type widths
AC_CHECK_SIZEOF(uintptr_t)
AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned long long)

# Some tooling we need in our makefiles or here:
AM_PROG_AR
AC_PROG_RANLIB
AC_PROG_LN_S

# Check for --enable-developer
developer=no
AC_ARG_ENABLE([developer],
    [  --enable-developer      Turn on gcc developer warnings, debugging, etc (default=no)],
    [if test "x$enable_developer" = xyes; then developer=yes; fi])

extrawarn=no
AC_ARG_ENABLE([extrawarn],
    [  --enable-extrawarn      Turn on excessive compiler warning flags (default=no, implied by --enable-developer)],
    [if test "x$enable_extrawarn" = xyes; then extrawarn=yes; fi])

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

# clang does not fail on some unsupported options without this,
#  but it screws up some of our warnflag tests on gcc as well.
CLANG_WERROR=
if test $CLANG = yes; then
   CLANG_WERROR="-Werror"
fi

harden=1
AC_ARG_WITH([hardening],[AS_HELP_STRING([--without-hardening],
    [Disable compiler/linker flags for security hardening])],[
    if test "x$withval" = xno; then
        harden=0
    fi
])
if test $harden = 1; then
    AS_CASE([$CFLAGS], [*-O[[1-6]]*], [CPPFLAGS="-D_FORTIFY_SOURCE=2 ${CPPFLAGS}"])
    AX_APPEND_COMPILE_FLAGS([-fPIE -fstack-protector-strong -fstack-clash-protection -fexceptions -ftrapv],[CFLAGS],[$CLANG_WERROR])
    if test $CLANG != yes; then
        # We'll only turn this on by default for real GCC-8 for now, because at
        # least clang-7 seems to cause all binutils (ranlib, ar, ld) to emit
        # strange errors on Linux with fcf-protection (yet linking succeeds
        # anyways, which is odd in itself).  The errors look like:
        # /usr/bin/ld: error: src/src_gdnsd-main.o: <corrupt x86 feature size: 0x8>
        AX_APPEND_COMPILE_FLAGS([-mshstk -fcf-protection=full],[CFLAGS],[])
    fi
    AX_APPEND_LINK_FLAGS([-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack],[LDFLAGS],[$CLANG_WERROR])
fi

AX_APPEND_COMPILE_FLAGS([\
    $TRY_DEBUG_CFLAGS \
    -fno-common \
    -pipe \
    -Wall \
    -Wno-pragmas \
],[CFLAGS],[$CLANG_WERROR])

if test $developer = yes -o $extrawarn = yes; then
    AX_APPEND_COMPILE_FLAGS([\
        -Wmost \
        -Wextra \
        -Waggregate-return \
        -Walloca \
        -Walloc-zero \
        -Warray-bounds=2 \
        -Wbad-function-cast \
        -Wcast-align \
        -Wcast-align=strict \
        -Wcast-qual \
        -Wdate-time \
        -Wdouble-promotion \
        -Wduplicated-branches \
        -Wduplicated-cond \
        -Werror=vla \
        -Wfloat-equal \
        -Wfloat-conversion \
        -Wformat=2 \
        -Wformat-signedness \
        -Winit-self \
        -Wjump-misses-init \
        -Wlogical-op \
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
        -Wstringop-overflow=3 \
        -Wswitch-default \
        -Wswitch-enum \
        -Wtrampolines \
        -Wtautological-compare \
        -Wundef \
        -Wunused \
        -Wwrite-strings \
        -Wthis-does-not-exist \
    ],[CFLAGS],[$CLANG_WERROR])
fi

# Note "-Wno-pragmas" above is because our only use of pragmas is to suppress
# warnings, and sometimes this in turn causes a warning on older GCC versions
# that don't support the warning we're trying to suppress...

# include libgdnsd configure stuff
m4_include([libgdnsd/libgdnsd.m4])

# include libgdmaps configure stuff
m4_include([libgdmaps/libgdmaps.m4])

# Linux, FreeBSD, and NetBSD all have this these days
USE_MMSG=1
AC_CHECK_DECLS([sendmmsg, recvmmsg, MSG_WAITFORONE],,[USE_MMSG=0],[[#include <sys/socket.h>]])
AC_CHECK_FUNCS([sendmmsg recvmmsg],,[USE_MMSG=0])
if test $USE_MMSG -eq 1; then
    AC_DEFINE([USE_MMSG],1,[recvmmsg and sendmmsg look usable])
fi

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

#---------------------------------------------
# pthread setname (3 non-portable variants...)
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
      pthread_set_name_np(pthread_self(), "foo");
  ])], [
    AC_DEFINE(HAVE_PTHREAD_SET_NAME_NP_2, 1, [2-arg pthread_set_name_np])
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
#---------------------------------------------
# end pthread_setname stuff
#---------------------------------------------

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
    [Test::More JSON::PP Socket6 IO::Socket::INET6 HTTP::Daemon Net::DNS=1.03],
    [HAVE_TESTSUITE_MODULES=1],
    AC_MSG_WARN([[Cannot "make check" without Perl modules Test::More, JSON::PP, Socket6, IO::Socket::INET6, HTTP::Daemon, and Net::DNS 1.03+]])
)
AC_SUBST([HAVE_TESTSUITE_MODULES])

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
    # These two methods should work for the *BSDs and Linux
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
GDNSD_DEFPATH_LIBEXEC="${libexecdir}/${PACKAGE_NAME}"
AC_SUBST([GDNSD_DEFPATH_RUN])
AC_SUBST([GDNSD_DEFPATH_CONFIG])
AC_SUBST([GDNSD_DEFPATH_STATE])
AC_SUBST([GDNSD_DEFPATH_LIBEXEC])

# BUILD_FEATURES for cmdline output
B_FEAT="prod"
if test "x$developer" != xno;    then B_FEAT="dev";             fi
if test "x$HAS_SENDMMSG" = x1;   then B_FEAT="$B_FEAT mmsg";    fi
if test "x$HAVE_LIBUNWIND" = x1; then B_FEAT="$B_FEAT unwind";  fi
if test "x$HAVE_GEOIP2" = x1;    then B_FEAT="$B_FEAT geoip2";  fi
AC_DEFINE_UNQUOTED([BUILD_FEATURES], ["$B_FEAT"], [Build Features])

# BUILD_INFO for cmdline output
B_INFO=non-git
AC_ARG_WITH([buildinfo],[AS_HELP_STRING([--with-buildinfo=v1.2.3-4],
    [Overrides the "Build Info" string which is output by CLI tools and normally contains version info derived directly from a git checkout])],
    [B_INFO=$with_buildinfo],
    [if test -d ${srcdir}/${GIT_DIR:-.git} -o -f ${srcdir}/.git; then
        [B_INFO=`cd ${srcdir}; git describe --match 'v[0-9]*' --always --dirty`]
    fi]
)
AC_DEFINE_UNQUOTED([BUILD_INFO],["$B_INFO"],[Build Info])

werror=0
AC_ARG_WITH([werror],[AS_HELP_STRING([--with-werror],
    [Turn on -Werror in CFLAGS after other autoconf tests are done])],[
    if test "x$withval" = xyes; then
        werror=1
    fi
])
if test $werror = 1; then
    CFLAGS="${CFLAGS} -Werror"
fi

# Output generation
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  t/Makefile
  t/libtap/Makefile
  t/libgdmaps/Makefile
])
AC_CONFIG_COMMANDS([mkdirs],[$MKDIR_P init; $MKDIR_P docs])
AC_OUTPUT

echo "========================================================================"
echo "| Build Info: $B_INFO"
echo "| Build Features: $B_FEAT"
echo "| CC: $CC"
echo "| CPPFLAGS: $CPPFLAGS"
echo "| CFLAGS: $CFLAGS $CFLAGS_PIE"
echo "| LDFLAGS: $LDFLAGS $LDFLAGS_PIE"
echo "========================================================================"
