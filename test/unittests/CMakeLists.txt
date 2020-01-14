# Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE.
INCLUDE_DIRECTORIES(../../src/liblsquic)

ENABLE_TESTING()

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLSQUIC_TEST=1")

IF (MSVC)
    SET(ADDL_SOURCES ../../wincompat/getopt.c ../../wincompat/getopt1.c)
    SET(LIB_FLAGS "-FORCE:MULTIPLE")
ELSE()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-value")
    IF (CMAKE_C_COMPILER_ID STREQUAL GNU)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-override-init")
    ENDIF()
    IF (CMAKE_C_COMPILER_ID STREQUAL Clang)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-initializer-overrides")
    ENDIF()
ENDIF()

include_directories(../../src/liblsquic/ls-qpack)

SET(TESTS
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
    h3_framing
    hcsi_reader
    hkdf
    lsquic_hash
    packet_out
    packno_len
    parse_packet_in
    purga
    qlog
    quic_be_floats
    rechist
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
    trapa
    varint
    ver_nego
    wuf_gquic_be
)

IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Linux has fmemopen
    SET(TESTS ${TESTS} frame_rw)
ENDIF()

IF (NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # No regexes on Windows
    SET(TESTS ${TESTS} ack_merge)
ENDIF()


FOREACH(TEST_NAME ${TESTS})
    ADD_EXECUTABLE(test_${TEST_NAME} test_${TEST_NAME}.c ${ADDL_SOURCES})
    TARGET_LINK_LIBRARIES(test_${TEST_NAME} ${LIBS} ${LIB_FLAGS})
    ADD_TEST(${TEST_NAME} test_${TEST_NAME})
ENDFOREACH()

ADD_EXECUTABLE(test_stream test_stream.c ${ADDL_SOURCES})
TARGET_LINK_LIBRARIES(test_stream ${LIBS} ${LIB_FLAGS})
ADD_TEST(stream test_stream)
ADD_TEST(stream_hash test_stream -h)
ADD_TEST(stream_A test_stream -A)
ADD_TEST(stream_hash_A test_stream -A -h)

ADD_EXECUTABLE(graph_cubic graph_cubic.c ${ADDL_SOURCES})
TARGET_LINK_LIBRARIES(graph_cubic ${LIBS})

ADD_EXECUTABLE(mini_parse mini_parse.c ${ADDL_SOURCES})
TARGET_LINK_LIBRARIES(mini_parse ${LIBS})

ADD_EXECUTABLE(test_min_heap test_min_heap.c ../../src/liblsquic/lsquic_min_heap.c)
ADD_TEST(min_heap test_min_heap)

ADD_EXECUTABLE(test_malo_pooled test_malo.c ../../src/liblsquic/lsquic_malo.c)
SET_TARGET_PROPERTIES(test_malo_pooled
    PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS} -DLSQUIC_USE_POOLS=1")
ADD_TEST(malo_pooled test_malo_pooled)

ADD_EXECUTABLE(test_malo_nopool test_malo.c ../../src/liblsquic/lsquic_malo.c)
SET_TARGET_PROPERTIES(test_malo_nopool
    PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS} -DLSQUIC_USE_POOLS=0")
ADD_TEST(malo_nopool test_malo_nopool)

ADD_EXECUTABLE(test_minmax test_minmax.c ../../src/liblsquic/lsquic_minmax.c)
ADD_TEST(minmax test_minmax)
