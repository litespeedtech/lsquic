# Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE.

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


IF(NOT (CMAKE_C_FLAGS MATCHES "-DNDEBUG"))
    # Our test framework relies on assertions, only compile if assertions are
    # enabled.
    #
    add_subdirectory(unittests)
    enable_testing()
ENDIF()
