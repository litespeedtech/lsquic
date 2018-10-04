# Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE.

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


IF(DEVEL_MODE EQUAL 1)
    # Our test framework relies on assertions, only compile if assertions are
    # enabled.
    #
    add_subdirectory(ietf)
    add_subdirectory(unittests)
    enable_testing()
ENDIF()
