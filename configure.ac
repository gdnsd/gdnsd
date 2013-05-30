AC_PREREQ([2.68])
AC_INIT([gdnsd],[1.8.3],[blblack@gmail.com],[gdnsd],[https://github.com/blblack/gdnsd])
AC_CONFIG_SRCDIR([gdnsd/main.c])
AC_CONFIG_AUX_DIR([acaux])
AM_INIT_AUTOMAKE([1.11.3 dist-xz no-dist-gzip foreign tar-ustar -Wall])
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

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

dnl POSIX threads stuff
AX_PTHREAD(,AC_MSG_ERROR([POSIX threads support is required]))
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

dnl need to know endian-ness
AC_C_BIGENDIAN

dnl Apparently libtool+automake need this now...
AM_PROG_AR

dnl The libtool macros in 2.2.6b - 2.4.2 have a bug that causes
dnl  them to accidentally add LIBADD_DLOPEN to LIBS permanently,
dnl  so we workaround that by saving and restoring LIBS
XLIBS=$LIBS
AC_DISABLE_STATIC
LT_INIT([dlopen])
LT_PREREQ([2.4.2])
LT_LIB_DLLOAD
AC_SUBST([LIBTOOL_DEPS])
AC_SUBST([LIBADD_DLOPEN])
LIBS=$XLIBS

dnl include libdmn configure stuff (only sets some config.h stuff)
m4_include([gdnsd/libgdnsd/libdmn/libdmn.m4])

dnl explicit check on math lib.  libev also does this, but
dnl  might not in the future, and we need it directly
XLIBS=$LIBS
LIBS=""
AC_CHECK_LIB(m,ceil)
MATH_LIB=$LIBS
LIBS=$XLIBS
AC_SUBST([MATH_LIB])

dnl posix_fadvise to readahead on zonefiles
AC_CHECK_FUNCS([posix_fadvise])

dnl high-precision mtime from struct stat
AC_CHECK_MEMBERS([struct stat.st_mtim.tv_nsec])
AC_CHECK_MEMBERS([struct stat.st_mtimespec.tv_nsec])
AC_CHECK_MEMBERS([struct stat.st_mtimensec])

dnl *mmsg for Linux
HAS_SENDMMSG=1
AC_CHECK_DECLS([sendmmsg, recvmmsg],,[HAS_SENDMMSG=0],[[#include <sys/socket.h>]])
AC_CHECK_FUNCS([sendmmsg recvmmsg],,[HAS_SENDMMSG=0])
if test $HAS_SENDMMSG -eq 1; then
    AC_DEFINE([USE_SENDMMSG],[1],[Linux sendmmsg is usable])
fi

dnl ======== Begin Network Stuff ==========
AC_DEFINE([__APPLE_USE_RFC_3542],1,[Force MacOS Lion to use RFC3542 IPv6 stuff])

dnl Find out if -lsocket -lnsl is needed, and put them
dnl  in $NETLIBS if so, and use them for these network-related
dnl  feature checks...
XLIBS=$LIBS
LIBS=""
AC_SEARCH_LIBS([gethostent],[nsl],[],[],[])
AC_SEARCH_LIBS([setsockopt],[socket],[],[],[])
NETLIBS=$LIBS
AC_SUBST([NETLIBS])

dnl sockaddr<->string mapping
AC_CHECK_FUNCS([inet_pton getifaddrs getaddrinfo getnameinfo],,AC_MSG_ERROR([required network library calls missing]))
AC_CHECK_DECLS([NI_MAXHOST, NI_MAXSERV, NI_NUMERICHOST, NI_NUMERICSERV],,AC_MSG_ERROR([NI_* decls missing]),[
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

dnl The IPv4 UDP source-addr fixup stuff is optional.  If not present, gdnsd
dnl  will abort at startup if configured to listen on 0.0.0.0.
AC_CHECK_DECLS([IP_PKTINFO, IP_RECVDSTADDR, IP_SENDSRCADDR],,,[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
])

dnl Whereas the equivalent IPv6 source-addr/flow/interface stuff is absolutely
dnl  required even for specific listen-adddreses, because we have to at minimum
dnl  copy the sending hosts' flow labels.  We allow IPV6_RECVPKTINFO to be optional,
dnl  but not the corresponding IPV6_PKTINFO (for the MacOS quirk of
dnl  re-using IPV6_PKTINFO as IPV6_RECVPKTINFO prior to Lion, where we #define
dnl  the latter to the former).
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

dnl restore original LIBS, from before NETLIBS
LIBS=$XLIBS

dnl ======== End Network Stuff ==========

dnl liburcu-qsbr
KILL_QSBR=0
AC_ARG_WITH([urcu],[
AS_HELP_STRING([--without-urcu],[Explicitly disable userspace-rcu detection])
],[
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
            AC_DEFINE_UNQUOTED([HAVE_QSBR], $HAVE_QSBR, [Use liburcu-qsbr])
            QSBRLIBS="-lurcu-qsbr"
        ])
        LIBS=$XLIBS
    ])
fi
AC_SUBST([QSBRLIBS])

dnl libev
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


dnl ======== Begin Capabilities Stuff ==========

dnl Check libcap on Linux, plus the prctl support for surviving setuid,
dnl   then use it to check for all the caps bits we need.  If the required
dnl   bits are not present, and this is a Linux host, fail unless an explicit
dnl   --without-libcap was specified.

IS_LINUX=0
case $host_os in
    *linux*)
        IS_LINUX=1
    ;;
esac

KILL_LIBCAP=0
if test $IS_LINUX -eq 0; then KILL_LIBCAP=1; fi

AC_ARG_WITH([libcap],[
AS_HELP_STRING([--without-libcap],[Explicitly disable libcap support on Linux])
],[
    if test "x$withval" = xno; then
        KILL_LIBCAP=1
    fi
])

XLIBS=$LIBS
LIBS=""
CAP_FUNCS=0
CAP_DECLS=0

if test $KILL_LIBCAP -eq 0; then
    AC_SEARCH_LIBS([cap_set_flag], [cap], [], [])
    AC_CHECK_FUNCS([cap_init cap_free cap_set_flag cap_set_proc prctl],[CAP_FUNCS=1],[])
    AC_CHECK_DECLS([CAP_NET_BIND_SERVICE, CAP_PERMITTED, CAP_EFFECTIVE, CAP_SET, CAP_SYS_CHROOT, CAP_SETGID, CAP_SETUID, PR_SET_KEEPCAPS],[CAP_DECLS=1],[],[
    #include <sys/types.h>
    #include <sys/capability.h>
    #include <sys/prctl.h>
    ])
fi

USE_LINUX_CAPS=0
CAPLIBS=
if test $CAP_FUNCS -eq 1 -a $CAP_DECLS -eq 1; then
    USE_LINUX_CAPS=1
    CAPLIBS=$LIBS
    AC_DEFINE([USE_LINUX_CAPS], [1], [Linux libcap2+prctl Capabilities])
else
    if test $KILL_LIBCAP -eq 0 -a $IS_LINUX -eq 1; then
      AC_MSG_ERROR([Linux libcap support not found, you may need to install the libcap-devel or libcap-dev package, or explicitly specify --without-libcap (not recommended)])
    fi
fi

AC_SUBST([CAPLIBS])

dnl restore original LIBS, from before CAPLIBS
LIBS=$XLIBS

dnl ======== End Capabilities Stuff ==========

dnl == inotify stuff ==
dnl inotify_init1() is Linux 2.6.27+ and glibc 2.9
dnl We also use Linux 2.6.36+ / glibc 2.13 IN_EXCL_UNLINK, but we
dnl   fix that with a manual ifndef for the define and a runtime
dnl   kernel version check for the support
USE_INOTIFY=1
AC_CHECK_FUNCS([inotify_init1],,[USE_INOTIFY=0])
if test $USE_INOTIFY -eq 1; then
    AC_DEFINE([USE_INOTIFY], [1], [Linux 2.6.36+ inotify support])
fi

dnl Check for perl stuff for doc generation and core regression testsuite
HAVE_TESTSUITE_MODULES=0
AC_REQUIRE_AUX_FILE([noperl])
AC_PATH_PROG([PERL],[perl],[$am_aux_dir/noperl])
AC_PATH_PROG([POD2MAN],[pod2man],[$am_aux_dir/noperl])
AC_PATH_PROG([POD2TEXT],[pod2text],[$am_aux_dir/noperl])
AX_PROG_PERL_VERSION([5.8.1],[
    AX_PROG_PERL_MODULES([Test::More LWP=5.805 Socket6 IO::Socket::INET6 HTTP::Daemon],[HAVE_TESTSUITE_MODULES=1], AC_MSG_WARN([[Cannot "make check" without Perl modules Test::More (aka Test-Simple for some package managers), LWP (aka libwww-perl) 5.805+, Socket6, IO::Socket::INET6, and HTTP::Daemon]]))
],[
    AC_MSG_WARN([Cannot "make check" or (re-)generate documentation without perl 5.8.1+ (neither of which are strictly necessary to build and install from a tarball)])
])
AC_SUBST([HAVE_TESTSUITE_MODULES])

dnl Find ragel
AC_REQUIRE_AUX_FILE([noragel])
AC_MSG_CHECKING([for Ragel v6.x]);
AC_PATH_PROGS_FEATURE_CHECK([RAGEL], [ragel],
  [[$ac_path_RAGEL --version |$EGREP 'Ragel State Machine Compiler version 6\.' >/dev/null && ac_cv_path_RAGEL=$ac_path_RAGEL ac_path_RAGEL_found=:]],
  [ac_cv_path_RAGEL=$am_aux_dir/noragel])
AC_SUBST([RAGEL], [$ac_cv_path_RAGEL])
AC_MSG_RESULT([$ac_cv_path_RAGEL])

dnl download/unpack for GeoLite data for plugin_geoip tests
AC_CHECK_PROGS(GEOLITE_DECOMP, [xz], [none])
AC_CHECK_PROGS(GEOLITE_DL, [wget curl], [none])

dnl Allow user to override the port range we use for testing
AC_ARG_WITH([testport],[
  --with-testport=N       The testsuite needs a set of 3 IP port numbers
                          to use, starting at "N", that it can bind to
                          on "127.0.0.1".  If the default value of "12345"
                          does not work for you, change it here.],
    [],
    [with_testport=12345]
)

TESTPORT_START=$with_testport
AC_SUBST([TESTPORT_START])

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
  AC_DEFINE([DEBUG_RCU], 1, [liburcu verification checks])
  AC_DEFINE([RCU_DEBUG], 1, [liburcu verification checks])
else
  if test "x$ac_cv_c_compiler_gnu" = xyes; then
    CFLAGS="${CFLAGS} ${GCC_WARNFLAGS}"
  fi
  CPPFLAGS="-DNDEBUG ${CPPFLAGS}"
fi

AC_CHECK_HEADERS([valgrind/memcheck.h])

dnl A default build of gdnsd uses system paths as specified
dnl   via the standard --prefix, --sysconfdir, --localstatedir, etc
dnl   (as well as --with-rundir for e.g. /run).
dnl The default build *can* be used for chroot operation if gdnsd
dnl   is supplied a "-d /some/path" argument on every invocation,
dnl   e.g. by a custom initscript.
dnl Specifying --with-rootdir=/some/path enables the chroot mode
dnl   of operation by default with no daemon arguments, using
dnl   the specified path as the default chroot location.
rootdir_fail="The --with-rootdir= option must specify an absolute pathname if used";
AC_ARG_WITH([rootdir],[
AS_HELP_STRING([--with-rootdir=/some/path],[Enables default chroot operation using the default chroot path specified])
],[
  echo "$with_rootdir" | $GREP '^/' >/dev/null || AC_MSG_ERROR($rootdir_fail)
],[
  with_rootdir="system"
])
GDNSD_DEF_ROOTDIR=$with_rootdir
AC_SUBST([GDNSD_DEF_ROOTDIR])
AM_CONDITIONAL([HAS_DEF_ROOTDIR], [test "x$GDNSD_DEF_ROOTDIR" = xsystem])

dnl Allow specifying an alternate rundir (default $localstatedir/run) for distros
dnl   that prefer e.g. /run to /var/run
rundir_fail="The --with-rundir= option must specify an absolute pathname if used";
AC_ARG_WITH([rundir],[
AS_HELP_STRING([--with-rundir=LOCALSTATEDIR/run],[Specify alternate ditro-specific rundir, e.g. /run, for non-chroot cases])
],[
  echo "$with_rundir" | $GREP '^/' >/dev/null || AC_MSG_ERROR($rundir_fail)
  GDNSD_SYSRUNDIR="$with_rundir"
],[
  GDNSD_SYSRUNDIR="${localstatedir}/run"
])
AC_SUBST([GDNSD_SYSRUNDIR])

dnl clump up all of the libgdnsd libdeps for re-use in LDADD for
dnl   binaries that link libgdnsd on platforms where libtool's
dnl   automatic dep resolution is disabled
LIBGDNSD_LIBS="$QSBRLIBS $MATH_LIB $LIBEV_LIBS $NETLIBS $LIBADD_DLOPEN"
AC_SUBST([LIBGDNSD_LIBS])

dnl Output generation
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  gdnsd/Makefile
  gdnsd/libgdnsd/Makefile
  t/Makefile
  docs/Makefile
  plugins/Makefile
  plugins/trivial/Makefile
  plugins/weighted/Makefile
  plugins/meta/Makefile
  plugins/meta/libgdmaps/Makefile
  plugins/meta/libgdmaps/t/Makefile
  plugins/extmon/Makefile
])
AC_OUTPUT

dnl Summary output for the user

if test "x$developer" != xno; then CFSUM_DEV=Yes; else CFSUM_DEV=No; fi
if test "x$USE_LINUX_CAPS" = x1; then CFSUM_CAP=Yes; else CFSUM_CAP=No; fi
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
echo "| Configuration Summary:"
echo "| Developer Build?        $CFSUM_DEV"
echo "| Userspace-rcu support:  $CFSUM_QSBR"
echo "| Linux libcap support:   $CFSUM_CAP"
echo "| Linux sendmmsg support: $CFSUM_SENDMMSG"
echo "| Linux inotify support:  $CFSUM_INOTIFY"
echo "| Test Port Start:        $CFSUM_TP"
echo "======================================="

if test $IS_LINUX -eq 1 -a $KILL_LIBCAP -eq 1; then
    AC_MSG_WARN([You have explicitly disabled Linux libcap support for Linux.  The "late_bind_secs" feature will not work in many common scenarios.])
fi
