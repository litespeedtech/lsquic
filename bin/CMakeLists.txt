# Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE.
LIST(APPEND LIBS ${EVENT_LIB})

# not working in appveyor-windows; odl cmake and vcpkg?
INCLUDE(CheckIncludeFile)

CHECK_INCLUDE_FILE(regex.h HAVE_REGEX)
IF(NOT HAVE_REGEX)

  #CHECK_INCLUDE_FILE(pcre2posix.h HAVE_PCRE2)

  MESSAGE(STATUS "Checking ${VCPKG_INSTALLED_DIR_TRIPLET}/include")

  FIND_PATH(PCRE2_INCLUDE_DIR NAMES pcre2posix.h HINTS "${VCPKG_INSTALLED_DIR_TRIPLET}/include")

  IF (PCRE2_INCLUDE_DIR)
      INCLUDE_DIRECTORIES(${PCRE2_INCLUDE_DIR})
      SET(HAVE_PCRE2 1)
  ENDIF()


  IF(HAVE_PCRE2)
    MESSAGE(STATUS "Found pcre2posix.h")
    FIND_LIBRARY(PCRE_LIB NAMES pcre2-32 pcre2-32-static)
    IF(PCRE_LIB)
        MESSAGE(STATUS "Found pcre2-32: ${PCRE_LIB}")
        LIST(APPEND LIBS ${PCRE_LIB})
    ELSE()
        MESSAGE(STATUS "pcre2-32 not found: http_server won't work")
    ENDIF()

    FIND_LIBRARY(PCREPOSIX_LIB NAMES pcre2-posix pcre2-posix-static)
    IF(PCREPOSIX_LIB)
        MESSAGE(STATUS "Found pcre2-posix: ${PCREPOSIX_LIB}")
        LIST(APPEND LIBS ${PCREPOSIX_LIB})
    ELSE()
        MESSAGE(STATUS "pcre2-posix not found: http_server won't work")
    ENDIF()
    
    IF(MSVC AND NOT VCPKG_TARGET_TRIPLET MATCHES "-static$")
      FIND_PATH(PCRE_DLL "pcre2-32.dll" HINTS "${VCPKG_INSTALLED_DIR_X64_WINDOWS}/bin" REQUIRED)
      FIND_PATH(PCREPOSIX_DLL "pcre2-posix.dll" HINTS "${VCPKG_INSTALLED_DIR_X64_WINDOWS}/bin" REQUIRED)
      SET(PCRE_DLL "${PCRE_DLL}/pcre2-32.dll")
      SET(PCREPOSIX_DLL "${PCREPOSIX_DLL}/pcre2-posix.dll")
      MESSAGE(STATUS "Found pcre2-32.dll: ${PCRE_DLL}")
      MESSAGE(STATUS "Found pcre2-posix.dll: ${PCREPOSIX_DLL}")
    ENDIF()
  ELSE()
    MESSAGE(STATUS "pcre2posix.h not found.")
    # NOT HAVE_PCRE2
    #CHECK_INCLUDE_FILE(pcreposix.h HAVE_PCRE)
    FIND_PATH(PCRE_INCLUDE_DIR NAMES pcreposix.h HINTS "${VCPKG_INSTALLED_DIR_TRIPLET}/include")

    IF (PCRE_INCLUDE_DIR)
        INCLUDE_DIRECTORIES(${PCRE_INCLUDE_DIR})
        SET(HAVE_PCRE 1)
    ENDIF()
    IF(NOT HAVE_PCRE)
      MESSAGE(FATAL_ERROR "no supported regex library found (regex, pcre, pcre2)")
    ENDIF()
    MESSAGE(STATUS "Found pcreposix.h")
    FIND_LIBRARY(PCRE_LIB pcre)
    IF(PCRE_LIB)
        MESSAGE(STATUS "Found pcre: ${PCRE_LIB}")
        LIST(APPEND LIBS ${PCRE_LIB})
    ELSE()
        MESSAGE(STATUS "pcre not found: http_server won't work")
    ENDIF()

    FIND_LIBRARY(PCREPOSIX_LIB pcreposix)
    IF(PCREPOSIX_LIB)
        MESSAGE(STATUS "Found pcreposix: ${PCREPOSIX_LIB}")
        LIST(APPEND LIBS ${PCREPOSIX_LIB})
    ELSE()
        MESSAGE(STATUS "pcreposix not found: http_server won't work")
    ENDIF()

    IF(MSVC AND NOT VCPKG_TARGET_TRIPLET MATCHES "-static$")
      FIND_PATH(PCRE_DLL "pcre.dll" HINTS "${VCPKG_INSTALLED_DIR_X64_WINDOWS}/bin" REQUIRED)
      FIND_PATH(PCREPOSIX_DLL "pcreposix.dll" HINTS "${VCPKG_INSTALLED_DIR_X64_WINDOWS}/bin" REQUIRED)
      SET(PCRE_DLL "${PCRE_DLL}/pcre.dll")
      SET(PCREPOSIX_DLL "${PCRE_DLL}/pcreposix.dll")
      MESSAGE(STATUS "Found pcre.dll: ${PCRE_DLL}")
      MESSAGE(STATUS "Found pcreposix.dll: ${PCREPOSIX_DLL}")
    ENDIF()
  ENDIF()

  IF (HAVE_PCRE OR HAVE_PCRE2)
    SET(HAVE_REGEX 1)
  ENDIF()
ENDIF()

IF(MSVC)
    LIST(APPEND LIBS ws2_32)
    LIST(APPEND LIBS iphlpapi)
    LIST(APPEND LIBS ${GETOPT_LIB})
ENDIF()

list(APPEND bin_targets http_client)
list(APPEND bin_targets http_server)
list(APPEND bin_targets echo_server)
list(APPEND bin_targets echo_client)
list(APPEND bin_targets duck_server)
list(APPEND bin_targets duck_client)
list(APPEND bin_targets perf_client)
list(APPEND bin_targets perf_server)
IF(NOT MSVC)
list(APPEND bin_targets md5_server)
list(APPEND bin_targets md5_client)
ENDIF()

#MESSAGE(STATUS "bin_targets: ${bin_targets}")
#MESSAGE(STATUS "bin_targets LIBS: ${LIBS}")

FOREACH(bin_target IN LISTS bin_targets)
    add_executable(${bin_target} ${bin_target}.c prog.c test_common.c test_cert.c)
    TARGET_LINK_LIBRARIES(${bin_target} ${LIBS})
ENDFOREACH()

IF(MSVC)
  FOREACH(bin_target IN LISTS bin_targets)
    # copy any dependencies local to the targets
    ADD_CUSTOM_COMMAND(TARGET ${bin_target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy \"$<TARGET_FILE:lsquic>\" \"$<TARGET_FILE_DIR:${bin_target}>\"
      COMMAND_EXPAND_LISTS
    )
    ADD_CUSTOM_COMMAND(TARGET ${bin_target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy \"${VCPKG_INSTALLED_DIR_X64_WINDOWS}/bin/getopt.dll\" \"$<TARGET_FILE_DIR:${bin_target}>\"
      COMMAND_EXPAND_LISTS
    )
    IF(EXISTS ${BORINGSSL_DLL_crypto})
        ADD_CUSTOM_COMMAND(TARGET ${bin_target} POST_BUILD
          COMMAND ${CMAKE_COMMAND} -E copy \"${BORINGSSL_DLL_crypto}\" \"$<TARGET_FILE_DIR:${bin_target}>\"
          COMMAND_EXPAND_LISTS
        )
    ENDIF()
    IF(EXISTS ${BORINGSSL_DLL_ssl})
        ADD_CUSTOM_COMMAND(TARGET ${bin_target} POST_BUILD
          COMMAND ${CMAKE_COMMAND} -E copy \"${BORINGSSL_DLL_ssl}\" \"$<TARGET_FILE_DIR:${bin_target}>\"
          COMMAND_EXPAND_LISTS
        )
    ENDIF()
    IF(EXISTS ${PCRE_DLL})
        ADD_CUSTOM_COMMAND(TARGET ${bin_target} POST_BUILD
          COMMAND ${CMAKE_COMMAND} -E copy \"${PCRE_DLL}\" \"$<TARGET_FILE_DIR:${bin_target}>\"
          COMMAND_EXPAND_LISTS
        )
    ENDIF()
  ENDFOREACH()
ENDIF()


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

CHECK_SYMBOL_EXISTS(
    preadv
    "sys/uio.h"
    HAVE_PREADV
)

IF (MSVC)
  FIND_PATH(EVENT_INCLUDE_DIR NAMES event2/event.h)
  IF (EVENT_INCLUDE_DIR)
      MESSAGE(STATUS "found event2/event.h")
  ELSE()
      MESSAGE(FATAL_ERROR "event2/event.h was not found")
  ENDIF()
ENDIF()

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/test_config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/test_config.h)
