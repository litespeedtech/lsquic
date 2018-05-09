# Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE.
SET(lsquic_STAT_SRCS
    lsquic_alarmset.c
    lsquic_conn.c
    lsquic_full_conn.c
    lsquic_chsk_stream.c
    lsquic_engine.c
    lsquic_parse_gquic_common.c
    lsquic_parse_gquic_le.c
    lsquic_parse_gquic_be.c
    lsquic_packet_in.c
    lsquic_packet_out.c
    lsquic_crypto.c
    lsquic_handshake.c
    lsquic_logger.c
    lsquic_malo.c
    lsquic_mm.c
    lsquic_rechist.c
    lsquic_rtt.c
    lsquic_send_ctl.c
    lsquic_senhist.c
    lsquic_cfcw.c
    lsquic_sfcw.c
    lsquic_stream.c
    lsquic_util.c
    lsquic_cubic.c
    lsquic_set.c
    lsquic_headers_stream.c
    lsquic_frame_reader.c
    lsquic_frame_writer.c
    lsquic_crt_compress.c
    lsquic_conn_hash.c
    lsquic_eng_hist.c
    lsquic_spi.c
    lsquic_di_nocopy.c
    lsquic_di_hash.c
    lsquic_di_error.c
    lsquic_global.c
    lsquic_packet_common.c
    lsquic_ev_log.c
    lsquic_frame_common.c
    lsquic_packints.c
    lsquic_version.c
    lsquic_pacer.c
    lsquic_attq.c
    lsquic_str.c
    lsquic_arr.c
    lsquic_hash.c
    lsquic_xxhash.c
    lsquic_buf.c
    lsquic_min_heap.c
    lshpack.c
    )



SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DXXH_HEADER_NAME=\\\"lsquic_xxhash.h\\\"")

add_library(lsquic STATIC ${lsquic_STAT_SRCS} )

link_directories(${PROJECT_SOURCE_DIR}/ssl/ /usr/local/lib)
