
dnl Find out which strerror_r we have
AC_FUNC_STRERROR_R

dnl Check on fputs_unlocked
AC_CHECK_DECLS([fputs_unlocked],,,[#include <stdio.h>])

dnl Check on fflush_unlocked
AC_CHECK_DECLS([fflush_unlocked],,,[#include <stdio.h>])

dnl systemd must be enabled explicitly!
AC_ARG_WITH([systemd],[
    AS_HELP_STRING([--with-systemd],[Enable systemd usage])
],[
    if test "x$withval" = xyes; then
        USE_SYSTEMD=1
        AC_DEFINE([USE_SYSTEMD],[1],[Use systemd])
        PKG_CHECK_MODULES([SYSD_DAEMON],[libsystemd-daemon])
        PKG_CHECK_MODULES([SYSD_LOGIN],[libsystemd-login])
        AC_SUBST([SYSD_DAEMON_CFLAGS])
        AC_SUBST([SYSD_DAEMON_LIBS])
        AC_SUBST([SYSD_LOGIN_CFLAGS])
        AC_SUBST([SYSD_LOGIN_LIBS])
    fi
])
