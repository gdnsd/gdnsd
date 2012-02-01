
dnl Find out which strerror_r we have
AC_FUNC_STRERROR_R

dnl Check on fputs_unlocked
AC_CHECK_DECLS([fputs_unlocked],,,[#include <stdio.h>])

dnl Check on fflush_unlocked
AC_CHECK_DECLS([fflush_unlocked],,,[#include <stdio.h>])

