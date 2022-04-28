# Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE.
include_directories(../src/liblsquic)

enable_testing()

add_definitions(-DLSQUIC_TEST=1)
set(_warning_disable_options)
if(MSVC)
    set(LIB_FLAGS "-FORCE:MULTIPLE")
else()
    string(APPEND CMAKE_C_FLAGS " -Wno-unused-value")
    if(CMAKE_C_COMPILER_ID STREQUAL GNU)
        string(APPEND CMAKE_C_FLAGS " -Wno-override-init")
    endif()
    if(CMAKE_C_COMPILER_ID STREQUAL Clang)
        string(APPEND CMAKE_C_FLAGS " -Wno-initializer-overrides")
    endif()
endif()

include_directories(../src/liblsquic/ls-qpack)
include_directories(../src/lshpack)

set(TESTS
    ack
    ackgen_gquic_be
    ackparse_gquic_be
    ackparse_ietf
    alarmset
    alt_svc_ver
    arr
    attq
    blocked_gquic_be
    bw_sampler
    conn_close_gquic_be
    crypto_gen
    cubic
    dec
    di_nocopy
    elision
    engine_ctor
    export_key
    frame_chop
    frame_reader
    frame_writer
    goaway_gquic_be
    hkdf
    hpi
    lsquic_hash
    packet_out
    packet_resize
    packno_len
    parse_packet_in
    purga
    qlog
    quic_be_floats
    reg_pkt_headergen
    rst_stream_gquic_be
    rtt
    send_headers
    senhist
    set
    sfcw
    shi
    spi
    stop_waiting_gquic_be
    streamgen
    streamparse
    tokgen
    trapa
    varint
    ver_nego
    wuf_gquic_be)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Linux has fmemopen
    list(APPEND TESTS frame_rw)
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")

    list(
        APPEND
        TESTS
        # No regexes on Windows
        ack_merge
        # No open_memstream() on Windows
        hcsi_reader
        # Takes forever on Windows, for whatever reason.  Or maybe it's the MS C
        # compilers.  Something to investigate... later.
        h3_framing)
endif()

foreach(TEST_NAME ${TESTS})
    add_executable(test_${TEST_NAME} test_${TEST_NAME}.c ${ADDL_SOURCES})
    if(NOT MSVC)
        target_link_libraries(test_${TEST_NAME} ${LIBS} ${LIB_FLAGS})
    else()
        target_link_libraries(test_${TEST_NAME} ${LIBS} ${GETOPT_LIB}
                              ${LIB_FLAGS})
        # copy any dependencies local to the tests IF (${CMAKE_VERSION}
        # VERSION_LESS "3.21.0")
        add_custom_command(
            TARGET test_${TEST_NAME}
            POST_BUILD
            COMMAND
                ${CMAKE_COMMAND} -E copy
                \"$ENV{VCPKG_ROOT}/installed/x64-windows$<$<CONFIG:Debug>:/debug>/bin/getopt.dll\"
                \"$<TARGET_FILE_DIR:test_${TEST_NAME}>\"
            COMMAND_EXPAND_LISTS)
        # ELSE() ADD_CUSTOM_COMMAND(TARGET test_${TEST_NAME} POST_BUILD COMMAND
        # if not \"\"=="$<TARGET_RUNTIME_DLLS:test_${TEST_NAME}>"
        # ${CMAKE_COMMAND} -E copy $<TARGET_RUNTIME_DLLS:test_${TEST_NAME}>
        # $<TARGET_FILE_DIR:test_${TEST_NAME}> COMMAND_EXPAND_LISTS ) ENDIF()
    endif()
    add_test(${TEST_NAME} test_${TEST_NAME})
endforeach()

add_executable(test_stream test_stream.c ${ADDL_SOURCES})
target_link_libraries(test_stream ${LIBS} ${LIB_FLAGS})
if(MSVC)
    target_link_libraries(test_stream ${GETOPT_LIB})
endif()
add_test(stream test_stream)
add_test(stream_hash test_stream -h)
add_test(stream_A test_stream -A)
add_test(stream_hash_A test_stream -A -h)

if(NOT MSVC)
    add_executable(graph_cubic graph_cubic.c ${ADDL_SOURCES})
    target_link_libraries(graph_cubic ${LIBS})

    add_executable(mini_parse mini_parse.c ${ADDL_SOURCES})
    target_link_libraries(mini_parse ${LIBS})
endif()

add_executable(test_min_heap test_min_heap.c ../src/liblsquic/lsquic_min_heap.c)
add_test(min_heap test_min_heap)

set(MALO_SRC test_malo.c ../src/liblsquic/lsquic_malo.c)
add_executable(test_malo_pooled ${MALO_SRC})
if(MSVC)
    target_link_libraries(test_malo_pooled ${GETOPT_LIB})
endif()
target_compile_definitions(test_malo_pooled PRIVATE LSQUIC_USE_POOLS=2)
add_test(malo_pooled test_malo_pooled)

add_executable(test_malo_nopool ${MALO_SRC})
if(MSVC)
    target_link_libraries(test_malo_nopool ${GETOPT_LIB})
endif()
target_compile_definitions(test_malo_nopool PRIVATE LSQUIC_USE_POOLS=0)
add_test(malo_nopool test_malo_nopool)

add_executable(test_minmax test_minmax.c ../src/liblsquic/lsquic_minmax.c)
if(MSVC)
    target_link_libraries(test_minmax ${GETOPT_LIB})
endif()
add_test(minmax test_minmax)

add_executable(test_rechist test_rechist.c ../src/liblsquic/lsquic_rechist.c)
add_test(rechist test_rechist)

add_executable(test_trechist test_trechist.c ../src/liblsquic/lsquic_trechist.c)
add_test(trechist test_trechist)
