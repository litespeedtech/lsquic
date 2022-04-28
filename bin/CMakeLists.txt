# Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE.

include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_library(example_common_objects STATIC prog.c test_common.c test_cert.c)
target_link_libraries(example_common_objects PUBLIC ${LIBS} ${EVENT_LIB} Threads::Threads)
target_include_directories(example_common_objects PUBLIC ${EVENT_INCLUDE_DIR})

if(MSVC)
    find_library(PCRE_LIB pcre)
    if(PCRE_LIB)
        message(STATUS "Found pcre: ${PCRE_LIB}")
    else()
        message(STATUS "pcre not found: http_server won't work")
    endif()
    find_library(PCREPOSIX_LIB pcreposix)
    if(PCREPOSIX_LIB)
        message(STATUS "Found pcreposix: ${PCREPOSIX_LIB}")
    else()
        message(STATUS "pcreposix not found: http_server won't work")
    endif()
    target_link_libraries(example_common_objects PUBLIC ws2_32 iphlpapi
                                                        ${GETOPT_LIB})
endif()

add_executable(http_client http_client.c)
target_link_libraries(http_client PRIVATE example_common_objects)

if(NOT MSVC OR (PCRE_LIB AND PCREPOSIX_LIB))
    add_executable(http_server http_server.c)
    target_link_libraries(http_server PRIVATE example_common_objects)
    if(MSVC)
        target_link_libraries(http_server PRIVATE ${PCRE_LIB} ${PCREPOSIX_LIB})
    endif()
endif()

if(NOT MSVC) # TODO: port MD5 server and client to Windows
    add_executable(md5_server md5_server.c)
    target_link_libraries(md5_server PRIVATE example_common_objects)

    add_executable(md5_client md5_client.c)
    target_link_libraries(md5_client PRIVATE example_common_objects)
endif()

add_executable(echo_server echo_server.c)
target_link_libraries(echo_server PRIVATE example_common_objects)

add_executable(echo_client echo_client.c)
target_link_libraries(echo_client PRIVATE example_common_objects)

add_executable(duck_server duck_server.c)
target_link_libraries(duck_server PRIVATE example_common_objects)

add_executable(duck_client duck_client.c)
target_link_libraries(duck_client PRIVATE example_common_objects)

add_executable(perf_client perf_client.c)
target_link_libraries(perf_client PRIVATE example_common_objects)

add_executable(perf_server perf_server.c)
target_link_libraries(perf_server PRIVATE example_common_objects)

include(CheckFunctionExists)
check_function_exists(sendmmsg HAVE_SENDMMSG)
check_function_exists(recvmmsg HAVE_RECVMMSG)
check_function_exists(open_memstream HAVE_OPEN_MEMSTREAM)

include(CheckSymbolExists)

check_symbol_exists(IP_MTU_DISCOVER "netinet/in.h" HAVE_IP_MTU_DISCOVER)

check_symbol_exists(IP_DONTFRAG "netinet/in.h" HAVE_IP_DONTFRAG)

check_symbol_exists(preadv "sys/uio.h" HAVE_PREADV)

include(CheckIncludeFiles)

if(MSVC AND PCRE_LIB)
    find_path(EVENT_INCLUDE_DIR NAMES pcreposix.h)
    if(EVENT_INCLUDE_DIR)
        message(STATUS "found pcreposix.h")
        set(HAVE_REGEX 1)
    else()
        message(FATAL_ERROR "event2/event.h was not found")
    endif()
else()
    check_include_files(regex.h HAVE_REGEX)
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test_config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/test_config.h)
