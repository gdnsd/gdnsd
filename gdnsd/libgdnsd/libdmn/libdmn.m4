
# Find out which strerror_r we have
AC_FUNC_STRERROR_R

# Check on fputs_unlocked
AC_CHECK_DECLS([fputs_unlocked],,,[#include <stdio.h>])

# Check on fflush_unlocked
AC_CHECK_DECLS([fflush_unlocked],,,[#include <stdio.h>])

# systemd must be enabled explicitly!

USE_SYSTEMD=0
USE_SYSTEMD_HAX=0

AC_ARG_WITH([systemd],[
    AS_HELP_STRING([--with-systemd],[Enable systemd usage])
],[
    if test "x$withval" = xyes; then
        USE_SYSTEMD=1
        AC_DEFINE([USE_SYSTEMD],[1],[Use systemd])
    fi
])

AC_ARG_WITH([systemd-hax],[
    AS_HELP_STRING([--with-systemd-hax],[Enable systemd hacks for fast-restart via systemctl reload])
],[
    if test "x$withval" = xyes; then
        USE_SYSTEMD_HAX=1
        USE_SYSTEMD=1
        AC_DEFINE([USE_SYSTEMD_HAX],[1],[Use systemd hacks for fast-restart via systemctl reload])
    fi
])

PKG_PROG_PKG_CONFIG()
if test x"$USE_SYSTEMD" = x1; then
    PKG_CHECK_MODULES([SYSD_DAEMON],[libsystemd-daemon])
    PKG_CHECK_MODULES([SYSD_JOURNAL],[libsystemd-journal])
fi
if test x"$USE_SYSTEMD_HAX" = x1; then
    PKG_CHECK_MODULES([SYSD_LOGIN],[libsystemd-login])
fi

AC_SUBST([SYSD_DAEMON_CFLAGS])
AC_SUBST([SYSD_DAEMON_LIBS])
AC_SUBST([SYSD_JOURNAL_CFLAGS])
AC_SUBST([SYSD_JOURNAL_LIBS])
AC_SUBST([SYSD_LOGIN_CFLAGS])
AC_SUBST([SYSD_LOGIN_LIBS])
