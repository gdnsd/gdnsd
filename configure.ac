AC_INIT([gdnsd],[1.6.7],[blblack@gmail.com],[gdnsd],[http://gdnsd.googlecode.com])
AC_PREREQ([2.69])
AC_CONFIG_AUX_DIR([acaux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.12 dist-xz foreign tar-ustar -Wall])
AM_SILENT_RULES([yes])

dnl These lines pretty much *have* to be in this order, and before
dnl  anything else that might invoke CC/CPP.  This ensures that
dnl  we get a C99 CC, a C99 CPP, and a set of #defines to turn
dnl  on "extended" interfaces in various OS's.
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = xno; then
    AC_MSG_ERROR([Your compiler lacks sufficient C99 support])
fi
AC_USE_SYSTEM_EXTENSIONS

dnl POSIX threads stuff
AX_PTHREAD(,AC_MSG_ERROR([POSIX threads support is required]))
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

dnl need to know endian-ness
AC_C_BIGENDIAN

dnl figure out whether and how to use TLS
AX_TLS

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

dnl include libev configure stuff
XLIBS=$LIBS
LIBS=""
m4_include([gdnsd/libgdnsd/libev/libev.m4])
EVLIBS=$LIBS
LIBS=$XLIBS
AC_SUBST([EVLIBS])

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

dnl *mmsg for Linux
HAS_SENDMMSG=0
AC_CHECK_FUNCS([sendmmsg],[HAS_SENDMMSG=1])

dnl ======== Begin Network Stuff ==========
AC_DEFINE_UNQUOTED([__APPLE_USE_RFC_3542],1,[Force MacOS Lion to use RFC3452 IPv6 stuff])

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

dnl Network stuff
AC_CHECK_FUNCS([accept4])
AC_CHECK_DECLS([SOCK_NONBLOCK],,,[[#include <sys/socket.h>]])

dnl restore original LIBS, from before NETLIBS
LIBS=$XLIBS

dnl ======== End Network Stuff ==========

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

if test $CAP_FUNCS -eq 1 -a $CAP_DECLS -eq 1; then
    USE_LINUX_CAPS=1
    CAPLIBS=$LIBS
else
    if test $KILL_LIBCAP -eq 0 -a $IS_LINUX -eq 1; then
      AC_MSG_ERROR([Linux libcap support not found, you may need to install the libcap-devel or libcap-dev package, or explicitly specify --without-libcap (not recommended)])
    fi
    USE_LINUX_CAPS=0
    CAPLIBS=
fi

AC_SUBST([CAPLIBS])
AC_DEFINE_UNQUOTED([USE_LINUX_CAPS], $USE_LINUX_CAPS, [Use Linux libcap2+prctl Capabilities])

dnl restore original LIBS, from before CAPLIBS
LIBS=$XLIBS

dnl ======== End Capabilities Stuff ==========

dnl --enable-lowmem reduces memory waste for tiny environments where it matters
LOWMEM=0
AC_ARG_ENABLE([lowmem], [
  --enable-lowmem        Reduce memory consumption (for embedded systems)],
  [if test "x$enable_lowmem" = xyes; then LOWMEM=1; fi])
AC_DEFINE_UNQUOTED([LOWMEM], $LOWMEM, [Waste less memory for embedded systems])
AM_CONDITIONAL([LOWMEM], [test x$LOWMEM = x1])

dnl Check for perl stuff for doc generation and core regression testsuite
HAVE_TESTSUITE_MODULES=0
HAVE_WIKI_MODULE=0
AC_REQUIRE_AUX_FILE([noperl])
AC_PATH_PROG([PERL],[perl],[$am_aux_dir/noperl])
AC_PATH_PROG([POD2MAN],[pod2man],[$am_aux_dir/noperl])
AC_PATH_PROG([POD2TEXT],[pod2text],[$am_aux_dir/noperl])
AC_PATH_PROG([POD2WIKI],[pod2wiki],[$am_aux_dir/noperl])
AX_PROG_PERL_VERSION([5.8.1],[
    AX_PROG_PERL_MODULES([Test::More Net::DNS=0.63 LWP=5.805 Socket6 IO::Socket::INET6],[HAVE_TESTSUITE_MODULES=1], AC_MSG_WARN([[Cannot "make check" without Perl modules Test::More (aka Test-Simple for some package managers), Net::DNS 0.63+, LWP (aka libwww-perl) 5.805+, Socket6, and IO::Socket::INET6]]))
    AX_PROG_PERL_MODULES([Pod::Simple::Wiki::Googlecode],[HAVE_WIKI_MODULE=1])
],[
    AC_MSG_WARN([Cannot "make check" or (re-)generate documentation without perl 5.8.1+ (neither of which are strictly necessary to build and install from a tarball)])
])
AC_SUBST([HAVE_TESTSUITE_MODULES])
AC_SUBST([HAVE_WIKI_MODULE])

dnl Find ragel
AC_REQUIRE_AUX_FILE([noragel])
AC_MSG_CHECKING([for Ragel v6.6 or v6.7]);
AC_PATH_PROGS_FEATURE_CHECK([RAGEL], [ragel],
  [[$ac_path_RAGEL --version |$EGREP 'Ragel State Machine Compiler version 6\.(6 Dec 2009|7 May 2011)' >/dev/null && ac_cv_path_RAGEL=$ac_path_RAGEL ac_path_RAGEL_found=:]],
  [ac_cv_path_RAGEL=$am_aux_dir/noragel])
AC_SUBST([RAGEL], [$ac_cv_path_RAGEL])
AC_MSG_RESULT([$ac_cv_path_RAGEL])

dnl download/unpack for GeoLite data for plugin_geoip tests
AC_CHECK_PROGS(GEOLITE_DECOMP, [xz gzip], [none])
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

dnl If developer, set -g and a ton of warnings.  Otherwise, set -DNDEBUG
dnl Other -Wflags that are interesting to check sometimes, w/ latest gcc:
dnl    -Wfloat-equal -Wpointer-arith -Wwrite-strings -Wlogical-op -Waddress
if test "x$developer" != xno; then
  if test x"$ac_cv_prog_cc_g" = xyes; then
    CFLAGS="${CFLAGS} -g -Wall -W -Wshadow"
  fi
  AC_DEFINE_UNQUOTED([EV_VERIFY], 3, [libev verification checks])
else
  CPPFLAGS="-DNDEBUG ${CPPFLAGS}"
  AC_DEFINE_UNQUOTED([EV_VERIFY], 0, [libev verification checks])
fi

AC_CHECK_HEADERS([valgrind/memcheck.h])

dnl doublecheck user-supplied srcdir argument
AC_CONFIG_SRCDIR([gdnsd/main.c])

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
])
AC_OUTPUT

dnl Summary output for the user

if test "x$developer" != xno; then CFSUM_DEV=Yes; else CFSUM_DEV=No; fi
if test "x$LOWMEM" = x1; then CFSUM_LM=Yes; else CFSUM_LM=No; fi
if test "x$USE_LINUX_CAPS" = x1; then CFSUM_CAP=Yes; else CFSUM_CAP=No; fi
if test "x$HAS_SENDMMSG" = x1; then CFSUM_SENDMMSG=Yes; else CFSUM_SENDMMSG=No; fi
CFSUM_TP=$TESTPORT_START

echo "======================================="
echo "| Configuration Summary:"
echo "| Developer Build?        $CFSUM_DEV"
echo "| Low Memory Build?       $CFSUM_LM"
echo "| Linux libcap support:   $CFSUM_CAP"
echo "| Linux sendmmsg support: $CFSUM_SENDMMSG"
echo "| Test Port Start:        $CFSUM_TP"
echo "======================================="

if test $IS_LINUX -eq 1 -a $KILL_LIBCAP -eq 1; then
    AC_MSG_WARN([You have explicitly disabled Linux libcap support for Linux.  The "late_bind_secs" feature will not work in many common scenarios.])
fi
