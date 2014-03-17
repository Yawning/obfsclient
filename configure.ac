#
# obfsclient configure.ac
# Yawning Angel (yawning at schwanenlied dot me)
#

AC_INIT([obfsclient],
	[0.0.1],
	[yawning at schwanenlied dot me],
	[obfsclient],
	[https://github.com/Yawning/obfsclient])
AC_PREREQ([2.69])
AM_INIT_AUTOMAKE([1.10 no-define foreign -Wall])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST
AC_PROG_CXX

# Host specific compiler stuff
case "$host_os" in
  freebsd8* | freebsd9.0*)
    # FreeBSD < 9.1 does not have the appropriate goo in sys/cdefs.h to expose
    # the C99 limits when using a C++11 compiler.
    CXXFLAGS="$CXXFLAGS -D__STDC_LIMIT_MACROS -D__LONG_LONG_SUPPORTED"
    ;;
  darwin*)
    # Ignore deprecation warnings on Darwin because the system OpenSSL is
    # deprecated in OSX >= 10.7.
    CXXFLAGS="$CXXFLAGS -Wno-deprecated-declarations"
    ;;
esac

AC_ARG_ENABLE(scramblesuit_iat,
              AS_HELP_STRING([--enable-scramblesuit-iat],
                             [Enable ScrambleSuit IAT obfuscation]),
[if test x$enableval = xyes; then
  AC_DEFINE(ENABLE_SCRAMBLESUIT_IAT, 1, [Enable ScrambleSuit IAT obfuscation])
fi])

# Include a bunch of macros
m4_include([m4/ax_pthread.m4])
m4_include([m4/ax_check_openssl.m4])
m4_include([m4/ax_cxx_compile_stdcxx_11.m4])

# Find common packages
#  - Sigh, none of the fucking BSDs ship openssl.pc
AX_PTHREAD(, AC_MSG_ERROR(Can not find pthreads.  This is required.))
AX_CHECK_OPENSSL(, AC_MSG_ERROR(Can not find OpenSSL.  This is required.))
PKG_CHECK_MODULES([libevent], [libevent >= 2.0.2])
PKG_CHECK_MODULES([liballium], [liballium-1.0 >= 0.0.1])

# Ensure that pkg-config (or the user) actually found/specified the correct
# paths for the dependencies instead of taking PKG_CHECK_MODULE's word for it.
oldCPPFLAGS=$CPPFLAGS
oldLDFLAGS=$LDFLAGS
CPPFLAGS="$CPPFLAGS $liballium_CFLAGS $libevent_CFLAGS"
LDFLAGS="$LDFLAGS $liballium_LIBS $libevent_LIBS"
AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <allium/allium.h>],
                                [(void)allium_ptcfg_init();])],
               [],
               [AC_MSG_ERROR([liballium headers or library missing.])])
AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <event2/event.h>],
                                [(void)event_base_dispatch(NULL);])],
               [],
               [AC_MSG_ERROR([libevent2 headers or libraries missing.])])
CPPFLAGS=$oldCPPFLAGS
LDFLAGS=$oldLDFLAGS

# Ensure that the barest minimum of stuff works
#  - Not going to bother checking for the crap that gtest want
AX_CXX_COMPILE_STDCXX_11(noext,mandatory)
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Maybe they want documentation?
AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
  then AC_MSG_WARN([Doxygen not found - No documentation can be generated])
fi
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([Doxyfile])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
