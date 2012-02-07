dnl this file is part of libev, do not make local modifications
dnl http://software.schmorp.de/pkg/libev

dnl libev support 
AC_CHECK_HEADERS(sys/inotify.h sys/epoll.h sys/event.h port.h poll.h sys/select.h sys/eventfd.h sys/signalfd.h) 
 
AC_CHECK_FUNCS(inotify_init epoll_ctl kqueue port_create poll select eventfd signalfd)
 
AC_CHECK_FUNCS(clock_gettime, [], [ 
   dnl XXX gdnsd uses pthreads and prefers not to use the syscall wrapper,
   dnl    but there doesn't appear to be any easier way to disable it...
   dnl on linux, try syscall wrapper first
   dnl if test $(uname) = Linux; then
   dnl    AC_MSG_CHECKING(for clock_gettime syscall)
   dnl    AC_LINK_IFELSE([AC_LANG_PROGRAM(
   dnl                    [#include <unistd.h>
   dnl                     #include <sys/syscall.h>
   dnl                     #include <time.h>],
   dnl                    [struct timespec ts; int status = syscall (SYS_clock_gettime, CLOCK_REALTIME, &ts)])],
   dnl                   [ac_have_clock_syscall=1
   dnl                    AC_DEFINE(HAVE_CLOCK_SYSCALL, 1, Define to 1 to use the syscall interface for clock_gettime)
   dnl                    AC_MSG_RESULT(yes)],
   dnl                   [AC_MSG_RESULT(no)])
   dnl fi
   if test -z "$LIBEV_M4_AVOID_LIBRT" && test -z "$ac_have_clock_syscall"; then
      AC_CHECK_LIB(rt, clock_gettime) 
      unset ac_cv_func_clock_gettime
      AC_CHECK_FUNCS(clock_gettime)
   fi
])

AC_CHECK_FUNCS(nanosleep, [], [ 
   if test -z "$LIBEV_M4_AVOID_LIBRT"; then
      AC_CHECK_LIB(rt, nanosleep) 
      unset ac_cv_func_nanosleep
      AC_CHECK_FUNCS(nanosleep)
   fi
])

if test -z "$LIBEV_M4_AVOID_LIBM"; then
   LIBM=m
fi
AC_SEARCH_LIBS(floor, $LIBM, [AC_DEFINE(HAVE_FLOOR, 1, Define to 1 if the floor function is available)])

