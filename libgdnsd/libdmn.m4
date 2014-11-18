# Find out which strerror_r we have
AC_FUNC_STRERROR_R

# Check on fputs_unlocked
AC_CHECK_DECLS([fputs_unlocked],,,[#include <stdio.h>])

# Check on fflush_unlocked
AC_CHECK_DECLS([fflush_unlocked],,,[#include <stdio.h>])

HAVE_LIBUNWIND=0
LIBUNWIND_LIBS=
AC_CHECK_HEADER([libunwind.h],[
    XLIBS=$LIBS
    LIBS=""
    AC_CHECK_LIB([unwind],[perror],[
        HAVE_LIBUNWIND=1
        AC_DEFINE([HAVE_LIBUNWIND], 1, [libunwind])
        LIBUNWIND_LIBS="-lunwind"
    ])
    LIBS=$XLIBS
])
AC_SUBST([LIBUNWIND_LIBS])
