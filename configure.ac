AC_INIT([dhcp-helper], [2.0], [], [dhcp-helper])
AC_PREREQ([2.59])
AC_CONFIG_HEADERS([src/include/config.h])

# check if the source folder is available
AC_CONFIG_SRCDIR([src/dhcp-helper.c])

# check for C++ preprocessor and compiler
AC_PROG_CPP
AC_PROG_CC

AM_INIT_AUTOMAKE([1.10 foreign -Wall no-define])

# use the C++ compiler for the following checks
AC_LANG([C])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/select.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([sys/stat.h])
AC_CHECK_HEADERS([limits.h])
AC_CHECK_HEADERS([net/if.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([stdio.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([time.h])
AC_CHECK_HEADERS([errno.h])
AC_CHECK_HEADERS([pwd.h])
AC_CHECK_HEADERS([grp.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([linux/types.h])
AC_CHECK_HEADERS([linux/capability.h])

AC_CHECK_HEADERS([sys/prctl.h])
AC_CHECK_HEADERS([net/if_arp.h])

AC_CHECK_HEADERS([linux/netlink.h])
PKG_CHECK_MODULES([LIBNL], [libnl-3.0 libnl-genl-3.0 libnl-route-3.0])

PKG_CHECK_MODULES([JANSSON], [jansson])

AC_CHECK_HEADER([ev.h],
    [AC_CHECK_LIB([ev], [ev_loop_new],
        [],
	[AC_MSG_ERROR("libev not found")] )],
    [AC_MSG_ERROR("ev.h not found")]
)

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# distribute additional compiler and linker flags among Makefiles
# --> set and change these variables instead of CXXFLAGS or LDFLAGS (for user only)
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_SUBST([CFLAGS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
