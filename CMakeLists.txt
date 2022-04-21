# Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE.
cmake_minimum_required(VERSION 3.1...3.23)

project(lsquic C)

option(LSQUIC_FIU "Use Fault Injection in Userspace (FIU)" OFF)
option(LSQUIC_BIN "Compile example binaries that use the library" ON)
option(LSQUIC_TESTS "Compile library unit tests" ON)
option(LSQUIC_DEVEL "Compile in development mode" OFF)
option(LSQUIC_DEBUG_NEXT_ADV_TICK "Define LSQUIC_DEBUG_NEXT_ADV_TICK to 1" ON)
option(LSQUIC_CONN_STATS "Track and print some connection stats" ON)
option(LSQUIC_ENABLE_HANDSHAKE_DISABLE "Disable crypto (plaintext only)" OFF)
option(LSQUIC_COMPILE_OUT_DEBUG_MESSAGES "Disable debug messages" OFF)
option(LSQUIC_SANITIZER "Enable address sanitizer" OFF)
option(BUILD_SHARED_LIBS "Compile as shared library" OFF)

include(GNUInstallDirs)

message(STATUS "CMake v${CMAKE_VERSION}")

set(NEED_LIBRT_FOR_clock_getres OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # If using older glibc, need to link with -lrt.  See clock_getres(2).
    include(CheckSymbolExists)
    check_symbol_exists(clock_getres "time.h" HAS_clock_getres_WITHOUT_LIBRT)

    if(NOT HAS_clock_getres_WITHOUT_LIBRT)
        find_library(RT_LIBRARY rt)
        set(NEED_LIBRT_FOR_clock_getres ON)
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
    # for android-ndk >= r19b
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY "BOTH")
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE "BOTH")
    set(CMAKE_FIND_ROOT_PATH_MODE_PATH "BOTH")
endif()

if(NOT MSVC)
    include(CheckCCompilerFlag)
    check_c_compiler_flag(-Wno-implicit-fallthrough HAS_NO_IMPLICIT_FALLTHROUGH)

    set(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Wall -Wextra -Wno-unused-parameter")

    if(CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS
                                   4.9.3)
        set(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Wno-missing-field-initializers")
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -O0 -g3")
    else()
        set(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -O3 -g0")
    endif()

    if(LSQUIC_SANITIZER)
        message(STATUS "AddressSanitizer is ON")
    else()
        message(STATUS "AddressSanitizer is OFF")
    endif()

endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  ${MY_CMAKE_FLAGS} $ENV{EXTRA_CFLAGS}")

message(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")

find_package(Perl)
if(NOT PERL_FOUND)
    message(FATAL_ERROR "Perl not found -- need it to generate source code")
endif()

if(BUILD_SHARED_LIBS)
    if(MSVC)
        set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS
            YES
            CACHE BOOL "Export all symbols")
        set(LIB_SUFFIX ${CMAKE_IMPORT_LIBRARY_SUFFIX})
    else()
        set(LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
    endif()
else()
    set(LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()

if(NOT DEFINED BORINGSSL_INCLUDE AND DEFINED BORINGSSL_DIR)
    find_path(
        BORINGSSL_INCLUDE
        NAMES openssl/ssl.h
        PATHS ${BORINGSSL_DIR}/include
        NO_DEFAULT_PATH)
endif()
# This must be done before adding other include directories to take precedence
# over header files from other SSL installs.

if(BORINGSSL_INCLUDE)
    message(STATUS "BoringSSL include directory ${BORINGSSL_INCLUDE}")
    include_directories(${BORINGSSL_INCLUDE})
else()
    message(FATAL_ERROR "BoringSSL headers not found")
endif()

foreach(LIB_NAME ssl crypto decrepit)
    find_library(
        BORINGSSL_LIB_${LIB_NAME}
        NAMES ${LIB_NAME} lib${LIB_NAME}
        PATHS ${BORINGSSL_DIR}/${LIB_NAME} ${BORINGSSL_LIB}
        PATH_SUFFIXES Debug Release MinSizeRel RelWithDebInfo
        NO_DEFAULT_PATH)
    if(BORINGSSL_LIB_${LIB_NAME})
        message(
            STATUS "Found ${LIB_NAME} library: ${BORINGSSL_LIB_${LIB_NAME}}")
    else()
        message(STATUS "${LIB_NAME} library not found")
    endif()
endforeach()

set(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories(include)
if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # Find libevent on FreeBSD:
    include_directories(/usr/local/include)
    link_directories(/usr/local/lib)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    find_path(GETOPT_INCLUDE_DIR NAMES getopt.h)
    if(GETOPT_INCLUDE_DIR)
        include_directories(${GETOPT_INCLUDE_DIR})
    else()
        message(FATAL_ERROR "getopt.h was not found")
    endif()
    find_library(GETOPT_LIB getopt)
    if(GETOPT_LIB)
        message(STATUS "Found getopt: ${GETOPT_LIB}")
    else()
        message(STATUS "getopt not found")
    endif()
endif()

# Find zlib and libevent header files and library files TODO: libevent is not
# strictly necessary to build the library.
find_package(ZLIB REQUIRED)

set(LIBS lsquic ${BORINGSSL_LIB_ssl} ${BORINGSSL_LIB_crypto} ${ZLIB_LIB})

if(LSQUIC_BIN)
    find_path(EVENT_INCLUDE_DIR NAMES event2/event.h)
    if(NOT EVENT_INCLUDE_DIR)
        message(WARNING "event2/event.h was not found: binaries won't be built")
        set(LSQUIC_BIN OFF)
    endif()
endif()

if(LSQUIC_BIN)
    find_library(EVENT_LIB NAMES event libevent)
    if(EVENT_LIB)
        message(STATUS "Found event: ${EVENT_LIB}")
    else()
        message(WARNING "libevent not found: binaries won't be built")
        set(LSQUIC_BIN OFF)
    endif()
endif()
find_package(Threads REQUIRED)

if(NOT MSVC)
    list(APPEND LIBS m)
else()
    list(APPEND LIBS ws2_32)
endif()

if(LSQUIC_BIN)
    add_subdirectory(bin)
endif()

add_subdirectory(src)

if(LSQUIC_TESTS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Our test framework relies on assertions, only compile if assertions are
    # enabled.
    #
    enable_testing()
    add_subdirectory(tests)
endif()

find_program(SPHINX NAMES sphinx-build)
if(SPHINX)
    add_custom_target(docs ${SPHINX} -b html docs docs/_build)
else()
    message(STATUS "sphinx-build not found: docs won't be made")
endif()

install(FILES include/lsquic.h include/lsquic_types.h include/lsxpack_header.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/lsquic)
