# Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE.
cmake_minimum_required(VERSION 2.8)


project(lsquic)

IF (NOT MSVC)
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

IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # If using older glibc, need to link with -lrt.  See clock_getres(2).
    EXECUTE_PROCESS(
        COMMAND ${PROJECT_SOURCE_DIR}/print-glibc-version.sh ${CMAKE_C_COMPILER}
        OUTPUT_VARIABLE GLIBC_VERSION)
    IF(NOT GLIBC_VERSION EQUAL "" AND GLIBC_VERSION VERSION_LESS 2.17)
        SET(LIBS ${LIBS} rt)
    ENDIF()
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF()


MESSAGE(STATUS "Build type: ${CMAKE_BUILD_TYPE}")


IF (NOT MSVC)

SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Wall -Wextra -Wno-unused-parameter")
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fno-omit-frame-pointer")

IF(CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9.3)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Wno-missing-field-initializers")
ENDIF()
IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -O0 -g3")
    IF(CMAKE_C_COMPILER MATCHES "clang" AND
                        NOT "$ENV{TRAVIS}" MATCHES "^true$")
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fsanitize=address")
    ENDIF()
    # Uncomment to enable fault injection testing via libfiu:
    #SET (MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DFIU_ENABLE=1")
    #SET(LIBS ${LIBS} fiu)
ELSE()
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -O3 -g0")
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DNDEBUG")
    # Comment out the following line to compile out debug messages:
    #SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_LOWEST_LOG_LEVEL=LSQ_LOG_INFO")
ENDIF()

IF(LSQUIC_PROFILE EQUAL 1)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -g -pg")
ENDIF()

IF(LSQUIC_COVERAGE EQUAL 1)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fprofile-arcs -ftest-coverage")
ENDIF()

IF(MY_CMAKE_FLAGS MATCHES "fsanitize=address")
    MESSAGE(STATUS "AddressSanitizer is ON")
ELSE()
    MESSAGE(STATUS "AddressSanitizer is OFF")
ENDIF()

#MSVC
ELSE()
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4214")	# nonstandard extension used: bit field types other than int
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -W4 -WX -Zi -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS -I${CMAKE_CURRENT_SOURCE_DIR}/wincompat")
IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Od")
    #SET (MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DFIU_ENABLE=1")
    #SET(LIBS ${LIBS} fiu)
ELSE()
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Ox")
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DNDEBUG")
    # Comment out the following line to compile out debug messages:
    #SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_LOWEST_LOG_LEVEL=LSQ_LOG_INFO")
ENDIF()

# SET (VCPKG_BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../vcpkg/installed/x64-windows-static)

ENDIF() #MSVC

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  ${MY_CMAKE_FLAGS} $ENV{EXTRA_CFLAGS}")

MESSAGE(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")

IF(NOT DEFINED BORINGSSL_INCLUDE)
    SET(BORINGSSL_INCLUDE /usr/local/include)
ENDIF()
IF(NOT DEFINED BORINGSSL_LIB)
    SET(BORINGSSL_LIB /usr/local/lib)
ENDIF()


include_directories(${BORINGSSL_INCLUDE} ${VCPKG_INCLUDE})
link_directories( ${BORINGSSL_LIB}  )

SET(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories( include src/lshpack)
IF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    # Find libevent on FreeBSD:
    include_directories( /usr/local/include )
    link_directories( /usr/local/lib )
ENDIF()


IF (NOT MSVC)
add_executable(http_client
    test/http_client.c
    test/prog.c
    test/test_common.c
)
target_link_libraries(http_client lsquic event pthread libssl.a libcrypto.a ${LIBS} z m)

#MSVC
ELSE()
add_executable(http_client
    test/http_client.c
    test/prog.c
    test/test_common.c
    wincompat/getopt.c
    wincompat/getopt1.c
)

target_link_libraries(http_client
		debug  $(SolutionDir)src/liblsquic/debug/lsquic.lib
		debug  ${VCPKG_BASE_DIR}/event.lib
		debug  ${VCPKG_BASE_DIR}/zlib.lib
		debug  ${BORINGSSL_LIB}/ssl.lib
		debug  ${BORINGSSL_LIB}/crypto.lib
		ws2_32
		${LIBS} )

ENDIF()

#target_link_libraries(http_client lsquic event pthread libssl.a libcrypto.a ${LIBS} z m)

add_subdirectory(src)

add_subdirectory(test)

IF(NOT (CMAKE_C_FLAGS MATCHES "-DNDEBUG"))
    # Our test framework relies on assertions, only compile if assertions are
    # enabled.
    #
    enable_testing()
ENDIF()


ADD_CUSTOM_TARGET(docs doxygen dox.cfg)
