#
# obfsclient Makefile.am
# Yawning Angel (yawning at schwanenlied dot me)
#

AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CXXFLAGS = -Wall -Werror -fno-exceptions -fno-rtti ${PTHREAD_CFLAGS}

common_sources = src/schwanenlied/crypto/base32.cc \
	src/schwanenlied/crypto/hkdf_sha256.cc \
	src/schwanenlied/crypto/hmac_sha256.cc \
	src/schwanenlied/crypto/sha256.cc \
	src/schwanenlied/crypto/uniform_dh.cc \
	src/schwanenlied/crypto/utils.cc \
	src/schwanenlied/pt/obfs2/client.cc \
	src/schwanenlied/pt/obfs3/client.cc \
	src/schwanenlied/pt/scramblesuit/client.cc \
        src/schwanenlied/pt/scramblesuit/session_ticket_handshake.cc \
	src/schwanenlied/pt/scramblesuit/uniform_dh_handshake.cc \
        src/schwanenlied/pt/scramblesuit/prob_dist.cc \
	src/schwanenlied/socks5_server.cc

# obfsclient
bin_PROGRAMS = obfsclient
obfsclient_CPPFLAGS = -I$(srcdir)/src
obfsclient_CXXFLAGS = ${AM_CXXFLAGS} ${libevent_CFLAGS} ${liballium_CFLAGS} ${OPENSSL_INCLUDES}
obfsclient_LDADD = ${libevent_LIBS} ${liballium_LIBS} ${OPENSSL_LIBS} ${OPENSSL_LDFLAGS} ${PTHREAD_LIBS}
obfsclient_SOURCES = ${common_sources} \
	src/main.cc 

# Tests
TESTS = obfsclient_test

check_PROGRAMS = obfsclient_test

obfsclient_test_CPPFLAGS = -I$(srcdir)/src
obfsclient_test_CXXFLAGS = ${AM_CXXFLAGS} ${libevent_CFLAGS} ${liballium_CFLAGS} ${OPENSSL_INCLUDES}
obfsclient_test_LDADD = ${libevent_LIBS} ${liballium_LIBS} ${OPENSSL_LIBS} ${OPENSSL_LDFLAGS} ${PTHREAD_LIBS}
obfsclient_test_SOURCES = ${common_sources} \
	src/schwanenlied/crypto/aes_test.cc \
	src/schwanenlied/crypto/base32_test.cc \
	src/schwanenlied/crypto/hkdf_sha256_test.cc \
	src/schwanenlied/crypto/hmac_sha256_test.cc \
	src/schwanenlied/crypto/sha256_test.cc \
	src/schwanenlied/crypto/uniform_dh_test.cc \
	src/schwanenlied/crypto/utils_test.cc \
        src/schwanenlied/well512_test.cc \
	src/gtest/gtest-all.cc \
	src/gtest/gtest_main.cc

# Documentation
if HAVE_DOXYGEN
docs:
	mkdir -p ${top_builddir}/docs/
	$(DOXYGEN) Doxyfile
endif 

dist_noinst_SCRIPTS = autogen.sh
