# Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE.
INCLUDE_DIRECTORIES(../src/liblsquic)

ENABLE_TESTING()

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLSQUIC_TEST=1")

IF (MSVC)
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

include_directories(../src/liblsquic/ls-qpack)
INCLUDE_DIRECTORIES(../src/lshpack)

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
    wuf_gquic_be
)

IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Linux has fmemopen
    SET(TESTS ${TESTS} frame_rw)
ENDIF()

IF (NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # No regexes on Windows
    SET(TESTS ${TESTS} ack_merge)
    # No open_memstream() on Windows
    SET(TESTS ${TESTS} hcsi_reader)
    # Takes forever on Windows, for whatever reason.  Or maybe it's the
    # MS C compilers.  Something to investigate... later.
    LIST(APPEND TESTS h3_framing)
ENDIF()


FOREACH(TEST_NAME ${TESTS})
    ADD_EXECUTABLE(test_${TEST_NAME} test_${TEST_NAME}.c ${ADDL_SOURCES})
    IF(NOT MSVC)
        TARGET_LINK_LIBRARIES(test_${TEST_NAME} ${LIBS} ${LIB_FLAGS})
    ELSE()
        TARGET_LINK_LIBRARIES(test_${TEST_NAME} ${LIBS} ${GETOPT_LIB} ${LIB_FLAGS})
        # copy any dependencies local to the tests
      #IF (${CMAKE_VERSION} VERSION_LESS "3.21.0")
        ADD_CUSTOM_COMMAND(TARGET test_${TEST_NAME} POST_BUILD
          COMMAND ${CMAKE_COMMAND} -E copy \"$ENV{VCPKG_ROOT}/installed/x64-windows$<$<CONFIG:Debug>:/debug>/bin/getopt.dll\" \"$<TARGET_FILE_DIR:test_${TEST_NAME}>\"
          COMMAND_EXPAND_LISTS
        )
      #ELSE()
      #  ADD_CUSTOM_COMMAND(TARGET test_${TEST_NAME} POST_BUILD
      #    COMMAND if not \"\"=="$<TARGET_RUNTIME_DLLS:test_${TEST_NAME}>" ${CMAKE_COMMAND} -E copy $<TARGET_RUNTIME_DLLS:test_${TEST_NAME}> $<TARGET_FILE_DIR:test_${TEST_NAME}>
      #    COMMAND_EXPAND_LISTS
      #  )
      #ENDIF()
    ENDIF()
    ADD_TEST(${TEST_NAME} test_${TEST_NAME})
ENDFOREACH()

ADD_EXECUTABLE(test_stream test_stream.c ${ADDL_SOURCES})
TARGET_LINK_LIBRARIES(test_stream ${LIBS} ${LIB_FLAGS})
IF(MSVC)
    TARGET_LINK_LIBRARIES(test_stream ${GETOPT_LIB})
ENDIF()
ADD_TEST(stream test_stream)
ADD_TEST(stream_hash test_stream -h)
ADD_TEST(stream_A test_stream -A)
ADD_TEST(stream_hash_A test_stream -A -h)

IF(NOT MSVC)
ADD_EXECUTABLE(graph_cubic graph_cubic.c ${ADDL_SOURCES})
TARGET_LINK_LIBRARIES(graph_cubic ${LIBS})

ADD_EXECUTABLE(mini_parse mini_parse.c ${ADDL_SOURCES})
TARGET_LINK_LIBRARIES(mini_parse ${LIBS})
ENDIF()

ADD_EXECUTABLE(test_min_heap test_min_heap.c ../src/liblsquic/lsquic_min_heap.c)
ADD_TEST(min_heap test_min_heap)

SET(MALO_SRC test_malo.c ../src/liblsquic/lsquic_malo.c)
ADD_EXECUTABLE(test_malo_pooled ${MALO_SRC})
IF(MSVC)
    TARGET_LINK_LIBRARIES(test_malo_pooled ${GETOPT_LIB})
ENDIF()
SET_TARGET_PROPERTIES(test_malo_pooled
    PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS} -DLSQUIC_USE_POOLS=1")
ADD_TEST(malo_pooled test_malo_pooled)

ADD_EXECUTABLE(test_malo_nopool ${MALO_SRC})
IF(MSVC)
    TARGET_LINK_LIBRARIES(test_malo_nopool ${GETOPT_LIB})
ENDIF()
SET_TARGET_PROPERTIES(test_malo_nopool
    PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS} -DLSQUIC_USE_POOLS=0")
ADD_TEST(malo_nopool test_malo_nopool)

ADD_EXECUTABLE(test_minmax test_minmax.c ../src/liblsquic/lsquic_minmax.c)
IF(MSVC)
    TARGET_LINK_LIBRARIES(test_minmax ${GETOPT_LIB})
ENDIF()
ADD_TEST(minmax test_minmax)

ADD_EXECUTABLE(test_rechist test_rechist.c ../src/liblsquic/lsquic_rechist.c)
ADD_TEST(rechist test_rechist)

ADD_EXECUTABLE(test_trechist test_trechist.c ../src/liblsquic/lsquic_trechist.c)
ADD_TEST(trechist test_trechist)
