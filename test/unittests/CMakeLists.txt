# Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE.
include_directories( BEFORE ../../ssl/include )
include_directories( ../../include )
include_directories( ../../src/liblsquic )

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-value")
set(MIN_LIBS_LIST "m ${FIULIB}")
set(LIBS_LIST "pthread libssl.a libcrypto.a z ${MIN_LIBS_LIST}")
ELSE()
set(MIN_LIBS_LIST ${FIULIB} ws2_32)
set(LIBS_LIST ssl crypto ${ZLIB_NAME} ${MIN_LIBS_LIST})
ENDIF()

enable_testing()


add_executable(test_rechist test_rechist.c)
target_link_libraries(test_rechist lsquic ${LIBS_LIST})
add_test(rechist test_rechist)

add_executable(test_senhist test_senhist.c)
target_link_libraries(test_senhist lsquic ${LIBS_LIST})
add_test(senhist test_senhist)

add_executable(test_rtt test_rtt.c)
target_link_libraries(test_rtt lsquic ${MIN_LIBS_LIST})
add_test(rtt test_rtt)

add_executable(test_set test_set.c)
target_link_libraries(test_set lsquic ${MIN_LIBS_LIST})
add_test(set test_set)


add_executable(test_engine_ctor test_engine_ctor.c)
target_link_libraries(test_engine_ctor lsquic ${LIBS_LIST})
add_test(engine_ctor test_engine_ctor)

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
add_executable(test_stream test_stream.c)
target_link_libraries(test_stream lsquic ${LIBS_LIST})
ELSE()
add_executable(test_stream test_stream.c ../../wincompat/getopt.c ../../wincompat/getopt1.c)
target_link_libraries(test_stream lsquic ${LIBS_LIST} -FORCE:multiple)
ENDIF()

add_test(stream test_stream)
add_test(stream_hash test_stream -h)
add_test(stream_A test_stream -A)
add_test(stream_hash_A test_stream -A -h)

add_executable(test_spi test_spi.c)
target_link_libraries(test_spi lsquic ${LIBS_LIST})
add_test(spi test_spi)

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
add_executable(test_malo test_malo.c)
ELSE()
add_executable(test_malo test_malo.c ../../wincompat/getopt.c ../../wincompat/getopt1.c)
ENDIF()
target_link_libraries(test_malo lsquic ${MIN_LIBS_LIST})
add_test(malo test_malo)

add_executable(test_conn_hash test_conn_hash.c)
target_link_libraries(test_conn_hash lsquic ${MIN_LIBS_LIST})
add_test(conn_hash test_conn_hash)

add_executable(test_lsquic_hash test_lsquic_hash.c)
target_link_libraries(test_lsquic_hash lsquic ${MIN_LIBS_LIST})
add_test(lsquic_hash test_lsquic_hash)

add_executable(test_blocked_gquic_le test_blocked_gquic_le.c)
target_link_libraries(test_blocked_gquic_le lsquic ${LIBS_LIST})
add_test(blocked_gquic_le test_blocked_gquic_le)

add_executable(test_blocked_gquic_be test_blocked_gquic_be.c)
target_link_libraries(test_blocked_gquic_be lsquic ${LIBS_LIST})
add_test(blocked_gquic_be test_blocked_gquic_be)

add_executable(test_rst_stream_gquic_le test_rst_stream_gquic_le.c)
target_link_libraries(test_rst_stream_gquic_le lsquic ${LIBS_LIST})
add_test(rst_stream_gquic_le test_rst_stream_gquic_le)

add_executable(test_rst_stream_gquic_be test_rst_stream_gquic_be.c)
target_link_libraries(test_rst_stream_gquic_be lsquic ${LIBS_LIST})
add_test(rst_stream_gquic_be test_rst_stream_gquic_be)

add_executable(test_rst_stream_ietf test_rst_stream_ietf.c)
target_link_libraries(test_rst_stream_ietf lsquic ${LIBS_LIST})
add_test(rst_stream_ietf test_rst_stream_ietf)

add_executable(test_conn_close_gquic_le test_conn_close_gquic_le.c)
target_link_libraries(test_conn_close_gquic_le lsquic ${LIBS_LIST})
add_test(conn_close_gquic_le test_conn_close_gquic_le)

add_executable(test_conn_close_gquic_be test_conn_close_gquic_be.c)
target_link_libraries(test_conn_close_gquic_be lsquic ${LIBS_LIST})
add_test(conn_close_gquic_be test_conn_close_gquic_be)

add_executable(test_goaway_gquic_le test_goaway_gquic_le.c)
target_link_libraries(test_goaway_gquic_le lsquic ${LIBS_LIST})
add_test(goaway_gquic_le test_goaway_gquic_le)

add_executable(test_goaway_gquic_be test_goaway_gquic_be.c)
target_link_libraries(test_goaway_gquic_be lsquic ${LIBS_LIST})
add_test(goaway_gquic_be test_goaway_gquic_be)

add_executable(test_wuf_gquic_le test_wuf_gquic_le.c)
target_link_libraries(test_wuf_gquic_le lsquic ${LIBS_LIST})
add_test(wuf_gquic_le test_wuf_gquic_le)

add_executable(test_wuf_gquic_be test_wuf_gquic_be.c)
target_link_libraries(test_wuf_gquic_be lsquic ${LIBS_LIST})
add_test(wuf_gquic_be test_wuf_gquic_be)

add_executable(test_ackparse_gquic_le test_ackparse_gquic_le.c)
target_link_libraries(test_ackparse_gquic_le lsquic ${LIBS_LIST})
add_test(ackparse_gquic_le test_ackparse_gquic_le)

add_executable(test_ackparse_gquic_be test_ackparse_gquic_be.c)
target_link_libraries(test_ackparse_gquic_be lsquic ${LIBS_LIST})
add_test(ackparse_gquic_be test_ackparse_gquic_be)

add_executable(test_ackparse_gquic_ietf test_ackparse_gquic_ietf.c)
target_link_libraries(test_ackparse_gquic_ietf lsquic ${LIBS_LIST})
add_test(ackparse_gquic_ietf test_ackparse_gquic_ietf)

add_executable(test_ackgen_gquic_le test_ackgen_gquic_le.c)
target_link_libraries(test_ackgen_gquic_le lsquic ${LIBS_LIST})
add_test(ackgen_gquic_le test_ackgen_gquic_le)

add_executable(test_ackgen_gquic_be test_ackgen_gquic_be.c)
target_link_libraries(test_ackgen_gquic_be lsquic ${LIBS_LIST})
add_test(ackgen_gquic_be test_ackgen_gquic_be)

add_executable(test_ackgen_gquic_ietf test_ackgen_gquic_ietf.c)
target_link_libraries(test_ackgen_gquic_ietf lsquic ${LIBS_LIST})
add_test(ackgen_gquic_ietf test_ackgen_gquic_ietf)

add_executable(test_sfcw test_sfcw.c)
target_link_libraries(test_sfcw lsquic ${LIBS_LIST})
add_test(sfcw test_sfcw)

add_executable(test_alarmset test_alarmset.c)
target_link_libraries(test_alarmset lsquic ${MIN_LIBS_LIST})
add_test(alarmset test_alarmset)

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
add_executable(graph_cubic graph_cubic.c)
ELSE()
add_executable(graph_cubic graph_cubic.c ../../wincompat/getopt.c ../../wincompat/getopt1.c)
ENDIF()
target_link_libraries(graph_cubic lsquic ${MIN_LIBS_LIST})


add_executable(test_streamparse test_streamparse.c)
target_link_libraries(test_streamparse lsquic ${LIBS_LIST})
add_test(streamparse test_streamparse)

add_executable(test_packet_out test_packet_out.c)
target_link_libraries(test_packet_out lsquic ${LIBS_LIST})
add_test(packet_out test_packet_out)

add_executable(test_reg_pkt_headergen test_reg_pkt_headergen.c)
target_link_libraries(test_reg_pkt_headergen lsquic ${LIBS_LIST})
add_test(reg_pkt_headergen test_reg_pkt_headergen)

add_executable(test_ver_nego test_ver_nego.c)
target_link_libraries(test_ver_nego lsquic ${LIBS_LIST})
add_test(ver_nego test_ver_nego)

add_executable(test_packno_len test_packno_len.c)
target_link_libraries(test_packno_len lsquic ${LIBS_LIST})
add_test(packno_len test_packno_len)


add_executable(test_streamgen test_streamgen.c)
target_link_libraries(test_streamgen lsquic ${LIBS_LIST})
add_test(streamgen test_streamgen)

add_executable(test_some_packets test_some_packets.c)
target_link_libraries(test_some_packets lsquic ${LIBS_LIST})
add_test(some_packets test_some_packets)


add_executable(test_elision test_elision.c)
IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
target_link_libraries(test_elision lsquic ${LIBS_LIST})
ELSE()
target_link_libraries(test_elision lsquic ${LIBS_LIST} -FORCE:multiple)
ENDIF()
add_test(elision test_elision)

add_executable(test_stop_waiting_gquic_le test_stop_waiting_gquic_le.c)
target_link_libraries(test_stop_waiting_gquic_le lsquic ${LIBS_LIST})
add_test(stop_waiting_gquic_le test_stop_waiting_gquic_le)

add_executable(test_stop_waiting_gquic_be test_stop_waiting_gquic_be.c)
target_link_libraries(test_stop_waiting_gquic_be lsquic ${LIBS_LIST})
add_test(stop_waiting_gquic_be test_stop_waiting_gquic_be)

add_executable(test_parse_packet_in test_parse_packet_in.c)
target_link_libraries(test_parse_packet_in lsquic ${LIBS_LIST})
add_test(parse_packet_in test_parse_packet_in)

add_executable(test_quic_le_floats test_quic_le_floats.c)
target_link_libraries(test_quic_le_floats lsquic ${LIBS_LIST})
add_test(quic_le_floats test_quic_le_floats)

add_executable(test_quic_be_floats test_quic_be_floats.c)
target_link_libraries(test_quic_be_floats lsquic ${LIBS_LIST})
add_test(quic_be_floats test_quic_be_floats)

add_executable(test_export_key test_export_key.c)
target_link_libraries(test_export_key lsquic ${LIBS_LIST})
add_test(export_key test_export_key)

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
add_executable(test_frame_reader test_frame_reader.c)
ELSE()
add_executable(test_frame_reader test_frame_reader.c ../../wincompat/getopt.c ../../wincompat/getopt1.c)
ENDIF()
target_link_libraries(test_frame_reader lsquic ${LIBS_LIST})
add_test(frame_reader test_frame_reader)

add_executable(test_frame_writer test_frame_writer.c)
target_link_libraries(test_frame_writer lsquic ${LIBS_LIST})
add_test(frame_writer test_frame_writer)

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
add_executable(test_frame_chop test_frame_chop.c)
ELSE()
add_executable(test_frame_chop test_frame_chop.c ../../wincompat/getopt.c ../../wincompat/getopt1.c)
ENDIF()
target_link_libraries(test_frame_chop lsquic ${LIBS_LIST})
add_test(frame_chop test_frame_chop)

IF (NOT ( (${CMAKE_SYSTEM_NAME} MATCHES "Darwin") OR  (CMAKE_C_COMPILER MATCHES "MSVC")) )
    add_executable(test_frame_rw test_frame_rw.c)
    target_link_libraries(test_frame_rw lsquic ${LIBS_LIST})
    add_test(frame_rw test_frame_rw)
ENDIF()

add_executable(test_hpack test_hpack.c)
target_link_libraries(test_hpack lsquic ${MIN_LIBS_LIST})
add_test(hpack test_hpack)

add_executable(test_hkdf test_hkdf.c)
target_link_libraries(test_hkdf lsquic ${LIBS_LIST})
add_test(hkdf test_hkdf)



add_executable(test_attq test_attq.c)
target_link_libraries(test_attq lsquic ${LIBS_LIST})
add_test(attq test_attq)

add_executable(test_arr test_arr.c)
target_link_libraries(test_arr lsquic ${LIBS_LIST})
add_test(arr test_arr)

add_executable(test_buf test_buf.c)
target_link_libraries(test_buf lsquic ${LIBS_LIST})
add_test(buf test_buf)

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
add_executable(test_cubic test_cubic.c)
ELSE()
add_executable(test_cubic test_cubic.c ../../wincompat/getopt.c ../../wincompat/getopt1.c)
ENDIF()
target_link_libraries(test_cubic lsquic ${LIBS_LIST})
add_test(cubic test_cubic)

IF (NOT (CMAKE_C_COMPILER MATCHES "MSVC"))
add_executable(test_dec test_dec.c)
ELSE()
add_executable(test_dec test_dec.c ../../wincompat/getopt.c ../../wincompat/getopt1.c)
ENDIF()

target_link_libraries(test_dec ${LIBS_LIST})
