cmake_minimum_required(VERSION 2.8.0)
project(obfsclient)

# Default to debug builds
if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type selected, defaulting to Debug")
  set(CMAKE_BUILD_TYPE "Debug")
endif()

# Tweak the compiler flags
add_definitions(-Wall -Werror -O2)
#add_definitions(-Wall -Werror)
#add_definitions(-Wall -Weffc++)
set(CMAKE_CXX_FLAGS "-std=c++11 -fno-exceptions -fno-rtti")

# Need some external libraries
find_package(Threads)
find_package(OpenSSL)

# Need some "custom" external libraries
set(LIBALLIUM_PATH /opt/liballium)
add_library(liballium STATIC IMPORTED)
set_target_properties(liballium
  PROPERTIES IMPORTED_LOCATION "${LIBALLIUM_PATH}/lib/liballium.a"
)
include_directories("${LIBALLIUM_PATH}/include")

set(LIBEVENT_PATH /usr)
add_library(libevent SHARED IMPORTED)
set_target_properties(libevent
  PROPERTIES IMPORTED_LOCATION "${LIBEVENT_PATH}/lib/libevent_core.so"
)
include_directories("${LIBEVENT_PATH}/include")

# Enable ctest support
enable_testing()

# Add subdirectories
add_subdirectory(src)
add_subdirectory(doc)
