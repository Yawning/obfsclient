include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

set(obfsclient_SRCS
  schwanenlied/crypto/base32.cc
  schwanenlied/crypto/hkdf_sha256.cc
  schwanenlied/crypto/hmac_sha256.cc
  schwanenlied/crypto/sha256.cc
  schwanenlied/crypto/uniform_dh.cc
  schwanenlied/crypto/utils.cc
  schwanenlied/pt/obfs2/client.cc
  schwanenlied/pt/obfs3/client.cc
  schwanenlied/socks5_server.cc
)

# Unit tests
add_library(gtest gtest/gtest-all.cc)
add_library(gtest_main gtest/gtest_main.cc)

set(obfsclient_test_SRCS
  schwanenlied/crypto/aes_test.cc
  schwanenlied/crypto/base32_test.cc
  schwanenlied/crypto/hkdf_sha256_test.cc
  schwanenlied/crypto/hmac_sha256_test.cc
  schwanenlied/crypto/sha256_test.cc
  schwanenlied/crypto/uniform_dh_test.cc
  schwanenlied/crypto/utils_test.cc
)

add_executable(obfsclient_test ${obfsclient_test_SRCS})
target_link_libraries(obfsclient_test
  obfsclient_lib
  ${CMAKE_THREAD_LIBS_INIT}
  ${OPENSSL_LIBRARIES}
  gtest
  gtest_main
)
add_test(obfsclient_test obfsclient_test)

add_library(obfsclient_lib ${obfsclient_SRCS})
add_executable(obfsclient main.cc)
target_link_libraries(obfsclient
  obfsclient_lib
  ${CMAKE_THREAD_LIBS_INIT}
  ${OPENSSL_LIBRARIES}
  libevent
  liballium
)
