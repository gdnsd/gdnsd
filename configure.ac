AC_PREREQ([2.63])
AC_INIT([gdnsd],[2.1.0],[blblack@gmail.com],[gdnsd])
AC_CONFIG_SRCDIR([gdnsd/main.c])
AC_CONFIG_AUX_DIR([acaux])
AM_INIT_AUTOMAKE([1.11.1 dist-xz no-dist-gzip foreign tar-ustar -Wall])
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

# We're compatible to autoconf 2.63, which doesn't have PACKAGE_URL
#   as a final arg to AC_INIT.  We can't define it ourselves here
#   with the same name as this causes compiler warnings that matter
#   during other parts of ./configure.  So, pick a new name for now.
AC_DEFINE([PKG_URL],["https://github.com/gdnsd/gdnsd/"],[Package URL])

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
AX_APPEND_LINK_FLAGS([$HARDEN_LINKER -Wl,--as-needed],[LDFLAGS],[])
AX_APPEND_COMPILE_FLAGS([\
    $TRY_DEBUG_CFLAGS \
    $HARDEN_COMPILER \
    -fno-common \
    -pipe \
    -Wall \
    -Wextra \
    -Wbad-function-cast \
    -Wcast-align \
    -Wclobbered \
    -Wempty-body \
    -Wendif-labels \
    -Wfloat-equal \
    -Wformat=2 \
    -Wformat-nonliteral \
    -Wformat-security \
    -Wignored-qualifiers \
    -Winit-self \
    -Wlogical-op \
    -Wmissing-declarations \
    -Wmissing-field-initializers \
    -Wmissing-include-dirs \
    -Wmissing-parameter-type \
    -Wmissing-prototypes \
    -Wold-style-declaration \
    -Wold-style-definition \
    -Woverride-init \
    -Wpointer-arith \
    -Wredundant-decls \
    -Wshadow \
    -Wsign-compare \
    -Wstack-protector \
    -Wstrict-aliasing=3 \
    -Wstrict-overflow=5 \
    -Wstrict-prototypes \
    -Wtype-limits \
    -Wundef \
    -Wuninitialized \
    -Wunused \
    -Wwrite-strings \
],[CFLAGS],[-Werror])

# include libdmn configure stuff
m4_include([gdnsd/libgdnsd/libdmn/libdmn.m4])

# explicit check on math lib.  libev also does this, but
#  might not in the future, and we need it directly
XLIBS=$LIBS
LIBS=""
AC_CHECK_LIB(m,ceil)
MATH_LIB=$LIBS
LIBS=$XLIBS
AC_SUBST([MATH_LIB])

# posix_fadvise to readahead on zonefiles
AC_CHECK_FUNCS([posix_fadvise])

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

# ======== Begin Network Stuff ==========
AC_DEFINE([__APPLE_USE_RFC_3542],1,[Force MacOS Lion to use RFC3542 IPv6 stuff])

# Find out if -lsocket -lnsl is needed, and put them
#  in $NETLIBS if so, and use them for these network-related
#  feature checks...
XLIBS=$LIBS
LIBS=""
AC_SEARCH_LIBS([gethostent],[nsl],[],[],[])
AC_SEARCH_LIBS([setsockopt],[socket],[],[],[])
NETLIBS=$LIBS
AC_SUBST([NETLIBS])

# sockaddr<->string mapping
AC_CHECK_FUNCS([inet_pton getifaddrs getaddrinfo getnameinfo],,AC_MSG_ERROR([required network library calls missing]))
AC_CHECK_DECLS([NI_NUMERICHOST, NI_NUMERICSERV],,AC_MSG_ERROR([NI_NUMERIC* decls missing]),[
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
])
AC_CHECK_DECLS([AF_INET6, PF_INET6, AF_INET, PF_INET, AF_UNSPEC],,AC_MSG_ERROR([AF_*/PF_* decls missing]),[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
])

# The IPv4 UDP source-addr fixup stuff is optional.  If not present, gdnsd
#  will abort at startup if configured to listen on 0.0.0.0.
AC_CHECK_DECLS([IP_PKTINFO, IP_RECVDSTADDR, IP_SENDSRCADDR],,,[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
])

# Whereas the equivalent IPv6 source-addr/flow/interface stuff is absolutely
#  required even for specific listen-adddreses, because we have to at minimum
#  copy the sending hosts' flow labels.  We allow IPV6_RECVPKTINFO to be optional,
#  but not the corresponding IPV6_PKTINFO (for the MacOS quirk of
#  re-using IPV6_PKTINFO as IPV6_RECVPKTINFO prior to Lion, where we #define
#  the latter to the former).
AC_CHECK_DECLS([IPV6_PKTINFO],,AC_MSG_ERROR([IPV6_PKTINFO is required]),[
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
])
AC_CHECK_DECLS([IPV6_RECVPKTINFO],,,[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
])

# restore original LIBS, from before NETLIBS
LIBS=$XLIBS

# ======== End Network Stuff ==========

# liburcu-qsbr
KILL_QSBR=0
AC_ARG_WITH([urcu],[AS_HELP_STRING([--without-urcu],
    [Explicitly disable userspace-rcu detection])],[
    if test "x$withval" = xno; then
        KILL_QSBR=1
    fi
])

HAVE_QSBR=0
QSBRLIBS=
if test $KILL_QSBR -eq 0; then
    AC_CHECK_HEADER(urcu-qsbr.h,[
        XLIBS=$LIBS
        LIBS=""
        AC_CHECK_LIB([urcu-qsbr],[perror],[
            HAVE_QSBR=1
            AC_DEFINE([HAVE_QSBR], 1, [Use liburcu-qsbr])
            QSBRLIBS="-lurcu-qsbr"
        ])
        LIBS=$XLIBS
    ])
fi
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

# Basic perl 5.8.1+ and pod2man for doc generation
AC_PATH_PROG([PERL],[perl],[missing])
if test x"$PERL" = xmissing; then
    AC_MSG_ERROR([Cannot find required perl binary])
fi
AX_PROG_PERL_VERSION([5.8.1],,[AC_MSG_ERROR([Perl 5.8.1 or higher required])])
AC_PATH_PROG([POD2MAN],[pod2man],[missing])
if test x"$POD2MAN" = xmissing; then
    AC_MSG_ERROR([Cannot find required pod2man binary (perl podlater)])
fi

# Various perl modules for the testsuite (optional)
HAVE_TESTSUITE_MODULES=0
AX_PROG_PERL_MODULES([Test::More LWP=5.805 Socket6 IO::Socket::INET6 HTTP::Daemon],[HAVE_TESTSUITE_MODULES=1], AC_MSG_WARN([[Cannot "make check" without Perl modules Test::More (aka Test-Simple for some package managers), LWP (aka libwww-perl) 5.805+, Socket6, IO::Socket::INET6, and HTTP::Daemon]]))
AC_SUBST([HAVE_TESTSUITE_MODULES])

# Find ragel
AC_REQUIRE_AUX_FILE([noragel])
AC_MSG_CHECKING([for Ragel v6.x]);
AC_PATH_PROGS_FEATURE_CHECK([RAGEL], [ragel],
  [[$ac_path_RAGEL --version |$EGREP 'Ragel State Machine Compiler version 6\.' >/dev/null && ac_cv_path_RAGEL=$ac_path_RAGEL ac_path_RAGEL_found=:]],
  [ac_cv_path_RAGEL=$am_aux_dir/noragel])
AC_SUBST([RAGEL], [$ac_cv_path_RAGEL])
AC_MSG_RESULT([$ac_cv_path_RAGEL])

# download/unpack for GeoLite data for plugin_geoip tests
AC_CHECK_PROGS(GEOLITE_DECOMP, [xz], [none])
AC_CHECK_PROGS(GEOLITE_DL, [wget curl], [none])

# Allow user to override the port range we use for testing
AC_ARG_WITH([testport],[AS_HELP_STRING([--with-testport=N],
    [The testsuite needs a set of 3 IP port numbers to use, starting at "N", that it can bind to on "127.0.0.1".  If the default value of "12345" does not work for you, change it here.])],
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
LIBGDNSD_LIBS="$QSBRLIBS $LIBEV_LIBS $NETLIBS $LIBADD_DLOPEN"
AC_SUBST([LIBGDNSD_LIBS])

# Output generation
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  gdnsd/Makefile
  gdnsd/libgdnsd/Makefile
  gdnsd/libgdnsd/libdmn/Makefile
  sysd/Makefile
  t/Makefile
  docs/Makefile
  plugins/Makefile
  plugins/extfile/Makefile
  plugins/extmon/Makefile
  plugins/meta/Makefile
  plugins/meta/libgdmaps/Makefile
  plugins/meta/libgdmaps/t/Makefile
  plugins/weighted/Makefile
  plugins/trivial/Makefile
])
AC_OUTPUT

# Summary output for the user

if test "x$developer" != xno; then CFSUM_DEV=Yes; else CFSUM_DEV=No; fi
if test "x$HAS_SENDMMSG" = x1; then CFSUM_SENDMMSG=Yes; else CFSUM_SENDMMSG=No; fi
if test "x$USE_INOTIFY" = x1; then CFSUM_INOTIFY=Yes; else CFSUM_INOTIFY=No; fi
if test "x$HAVE_QSBR" = x1; then
    CFSUM_QSBR=Yes
else
    if test "x$KILL_QSBR" = x1; then
        CFSUM_QSBR=Disabled
    else
        CFSUM_QSBR=No
    fi
fi
CFSUM_TP=$TESTPORT_START
echo "======================================="
echo "CPPFLAGS: $CPPFLAGS"
echo "CFLAGS: $CFLAGS $CFLAGS_PIE"
echo "LDFLAGS: $LDFLAGS $LDFLAGS_PIE"
echo "======================================="
echo "| Configuration Summary:"
echo "| Developer Build:            $CFSUM_DEV"
echo "| Userspace-rcu support:      $CFSUM_QSBR"
echo "| Linux sendmmsg support:     $CFSUM_SENDMMSG"
echo "| Linux inotify support:      $CFSUM_INOTIFY"
echo "| Test Port Start:            $CFSUM_TP"
echo "======================================="
