# Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE.
INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(sendmmsg HAVE_SENDMMSG)
CHECK_FUNCTION_EXISTS(recvmmsg HAVE_RECVMMSG)
CHECK_FUNCTION_EXISTS(open_memstream HAVE_OPEN_MEMSTREAM)


INCLUDE(CheckSymbolExists)

CHECK_SYMBOL_EXISTS(
    IP_MTU_DISCOVER
    "netinet/in.h"
    HAVE_IP_MTU_DISCOVER
)

CHECK_SYMBOL_EXISTS(
    IP_DONTFRAG
    "netinet/in.h"
    HAVE_IP_DONTFRAG
)

INCLUDE(CheckIncludeFiles)

CHECK_INCLUDE_FILES(regex.h HAVE_REGEX)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/test_config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/test_config.h)

IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Our test framework relies on assertions, only compile if assertions are
    # enabled.
    #
    add_subdirectory(unittests)
    enable_testing()
ENDIF()
