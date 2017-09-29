# Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE.
cmake_minimum_required(VERSION 2.8)


project(lsquic)

# We prefer clang
IF(NOT ("${CMAKE_C_COMPILER}" MATCHES "ccc-analyzer" OR
        "${CMAKE_C_COMPILER}" MATCHES "gcc"          OR
        "${CMAKE_C_COMPILER}" MATCHES "afl-gcc"))
    FIND_PROGRAM(CLANG "clang")
    IF(CLANG)
        SET(CMAKE_C_COMPILER "${CLANG}")
    ENDIF()
ENDIF()

# By default, we compile in development mode.  To compile production code,
# pass -DDEVEL_MODE=0 to cmake (before that, `make clean' and remove any
# cmake cache files).
#
IF(NOT DEFINED DEVEL_MODE)
    SET(DEVEL_MODE 1)
ENDIF()


MESSAGE(STATUS "DEVEL_MODE: ${DEVEL_MODE}")

SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Wall -Wextra -Wno-unused-parameter")
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fno-omit-frame-pointer")

IF(CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9.3)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Wno-missing-field-initializers")
ENDIF()
IF(DEVEL_MODE EQUAL 1)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -O0 -g3")
    # -Werror is used to force us to fix warnings early.
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Werror")
    IF(CMAKE_C_COMPILER MATCHES "clang")
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fsanitize=address")
    ENDIF()
    # Uncomment to enable fault injection testing via libfiu:
    #SET (MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DFIU_ENABLE=1")
    #SET (FIULIB "fiu")
ELSE()
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -O3 -g0")
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DNDEBUG")
    # Comment out the following line to compile out debug messages:
    #SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_LOWEST_LOG_LEVEL=LSQ_LOG_INFO")
ENDIF()

IF(LSQUIC_PROFILE EQUAL 1)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -g -pg")
ENDIF()

IF(MY_CMAKE_FLAGS MATCHES "fsanitize=address")
    MESSAGE(STATUS "AddressSanitizer is ON")
ELSE()
    MESSAGE(STATUS "AddressSanitizer is OFF")
ENDIF()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  ${MY_CMAKE_FLAGS} $ENV{EXTRA_CFLAGS}")

MESSAGE(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")

IF(NOT DEFINED BORINGSSL_INCLUDE)
    SET(BORINGSSL_INCLUDE /usr/local/include)
ENDIF()
IF(NOT DEFINED BORINGSSL_LIB)
    SET(BORINGSSL_LIB /usr/local/lib)
ENDIF()

include_directories( ${BORINGSSL_INCLUDE} )
link_directories( ${BORINGSSL_LIB} )

SET(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories( include )

IF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    # Find libevent on FreeBSD:
    include_directories( /usr/local/include )
    link_directories( /usr/local/lib )
ENDIF()

add_executable(http_client test/http_client.c test/prog.c test/test_common.c test/test_cert.c)

target_link_libraries(http_client lsquic event pthread libssl.a libcrypto.a ${FIULIB} z m)

add_subdirectory(src)

IF(DEVEL_MODE EQUAL 1)
    # Our test framework relies on assertions, only compile if assertions are
    # enabled.
    #
    add_subdirectory(test)
    enable_testing()
ENDIF()


ADD_CUSTOM_TARGET(docs doxygen dox.cfg)
