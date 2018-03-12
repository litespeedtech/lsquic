# Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE.
cmake_minimum_required(VERSION 2.8)


project(lsquic)

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
# We prefer clang
IF(NOT ("${CMAKE_C_COMPILER}" MATCHES "ccc-analyzer" OR
        "${CMAKE_C_COMPILER}" MATCHES "gcc"          OR
        "${CMAKE_C_COMPILER}" MATCHES "afl-gcc"))
    FIND_PROGRAM(CLANG "clang")
    IF(CLANG)
        SET(CMAKE_C_COMPILER "${CLANG}")
    ENDIF()
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

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))

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

#MSVC
ELSE()
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -W4 -WX -Zi -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS -I${CMAKE_CURRENT_SOURCE_DIR}/wincompat")
IF(DEVEL_MODE EQUAL 1)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Od ")
    #SET (MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DFIU_ENABLE=1")
    #SET (FIULIB "fiu")
ELSE()
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -OX")
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DNDEBUG")
    # Comment out the following line to compile out debug messages:
    #SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_LOWEST_LOG_LEVEL=LSQ_LOG_INFO")
ENDIF()

SET (BORINGSSL_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../boringssl/include)
SET (VCPKG_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../vcpkg/installed/x64-windows-static/include )

IF(CMAKE_BUILD_TYPE MATCHES "Debug")
SET (BORINGSSL_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../boringssl/build/ssl ${CMAKE_CURRENT_SOURCE_DIR}/../boringssl/build/x64/debug)
SET (VCPKG_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../vcpkg/installed/x64-windows-static/lib)
SET (ZLIB_NAME "zlibd")
ELSE()
SET (BORINGSSL_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../boringssl/build/ssl ${CMAKE_CURRENT_SOURCE_DIR}/../boringssl/build/x64)
SET (VCPKG_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../vcpkg/installed/x64-windows-static/debug/lib)
SET (ZLIB_NAME zlibd)
ENDIF()


ENDIF() #MSVC

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  ${MY_CMAKE_FLAGS} $ENV{EXTRA_CFLAGS}")

MESSAGE(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")

IF(NOT DEFINED BORINGSSL_INCLUDE)
    SET(BORINGSSL_INCLUDE /usr/local/include)
ENDIF()
IF(NOT DEFINED BORINGSSL_LIB)
    SET(BORINGSSL_LIB /usr/local/lib)
ENDIF()


include_directories(${BORINGSSL_INCLUDE} ${VCPKG_INCLUDE} )
link_directories( ${BORINGSSL_LIB} ${VCPKG_LIB} )

SET(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories( include )

IF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    # Find libevent on FreeBSD:
    include_directories( /usr/local/include )
    link_directories( /usr/local/lib )
ENDIF()

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
add_executable(http_client
    test/http_client.c
    test/prog.c
    test/test_common.c
)
target_link_libraries(http_client lsquic event pthread libssl.a libcrypto.a ${FIULIB} z m)
ELSE()
add_executable(http_client
    test/http_client.c
    test/prog.c
    wincompat/test_common_win.c
    wincompat/getopt.c
    wincompat/getopt1.c
)

target_link_libraries(http_client lsquic event ssl crypto ${FIULIB} ${ZLIB_NAME} ws2_32)

ENDIF()



add_subdirectory(src)

add_subdirectory(test)

IF(DEVEL_MODE EQUAL 1)
    # Our test framework relies on assertions, only compile if assertions are
    # enabled.
    #
    enable_testing()
ENDIF()


ADD_CUSTOM_TARGET(docs doxygen dox.cfg)
