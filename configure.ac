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
AM_INIT_AUTOMAKE([no-define foreign -Wall])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CXX

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
