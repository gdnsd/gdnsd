HAVE_GEOIP2=0
GEOIP2_LIBS=
AC_CHECK_HEADER([maxminddb.h],[
    AC_CHECK_MEMBER([MMDB_search_node_s.left_record_type],
        [AC_DEFINE([MMDB_GTE_120], 1, [libmaxminddb >= 1.2.0])],
        [], [[#include <maxminddb.h>]])
    XLIBS=$LIBS
    LIBS=""
    AC_CHECK_LIB([maxminddb],[MMDB_open],[
        HAVE_GEOIP2=1
        AC_DEFINE([HAVE_GEOIP2], 1, [libmaxminddb])
        GEOIP2_LIBS="-lmaxminddb"
    ])
    LIBS=$XLIBS
])
AC_SUBST([GEOIP2_LIBS])
