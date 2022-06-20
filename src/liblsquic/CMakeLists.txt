# Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE.
SET(lsquic_STAT_SRCS
    ls-qpack/lsqpack.c
    lsquic_adaptive_cc.c
    lsquic_alarmset.c
    lsquic_arr.c
    lsquic_attq.c
    lsquic_bbr.c
    lsquic_bw_sampler.c
    lsquic_cfcw.c
    lsquic_chsk_stream.c
    lsquic_conn.c
    lsquic_crand.c
    lsquic_crt_compress.c
    lsquic_crypto.c
    lsquic_cubic.c
    lsquic_di_error.c
    lsquic_di_hash.c
    lsquic_di_nocopy.c
    lsquic_enc_sess_common.c
    lsquic_enc_sess_ietf.c
    lsquic_eng_hist.c
    lsquic_engine.c
    lsquic_ev_log.c
    lsquic_frab_list.c
    lsquic_frame_common.c
    lsquic_frame_reader.c
    lsquic_frame_writer.c
    lsquic_full_conn.c
    lsquic_full_conn_ietf.c
    lsquic_global.c
    lsquic_handshake.c
    lsquic_hash.c
    lsquic_hcsi_reader.c
    lsquic_hcso_writer.c
    lsquic_headers_stream.c
    lsquic_hkdf.c
    lsquic_hpi.c
    lsquic_hspack_valid.c
    lsquic_http.c
    lsquic_http1x_if.c
    lsquic_logger.c
    lsquic_malo.c
    lsquic_min_heap.c
    lsquic_mini_conn.c
    lsquic_mini_conn_ietf.c
    lsquic_minmax.c
    lsquic_mm.c
    lsquic_pacer.c
    lsquic_packet_common.c
    lsquic_packet_gquic.c
    lsquic_packet_in.c
    lsquic_packet_out.c
    lsquic_packet_resize.c
    lsquic_parse_Q046.c
    lsquic_parse_Q050.c
    lsquic_parse_common.c
    lsquic_parse_gquic_be.c
    lsquic_parse_gquic_common.c
    lsquic_parse_ietf_v1.c
    lsquic_parse_iquic_common.c
    lsquic_pr_queue.c
    lsquic_purga.c
    lsquic_qdec_hdl.c
    lsquic_qenc_hdl.c
    lsquic_qlog.c
    lsquic_qpack_exp.c
    lsquic_rechist.c
    lsquic_rtt.c
    lsquic_send_ctl.c
    lsquic_senhist.c
    lsquic_set.c
    lsquic_sfcw.c
    lsquic_shsk_stream.c
    lsquic_spi.c
    lsquic_stock_shi.c
    lsquic_str.c
    lsquic_stream.c
    lsquic_tokgen.c
    lsquic_trans_params.c
    lsquic_trechist.c
    lsquic_util.c
    lsquic_varint.c
    lsquic_version.c
)

IF(NOT MSVC)
    SET(QPACK_FLAGS "-Wno-uninitialized")
    INCLUDE(CheckCCompilerFlag)
    CHECK_C_COMPILER_FLAG(-Wno-implicit-fallthrough HAS_NO_IMPLICIT_FALLTHROUGH)
    IF (HAS_NO_IMPLICIT_FALLTHROUGH)
        SET(QPACK_FLAGS "${QPACK_FLAGS} -Wno-implicit-fallthrough")
    ENDIF()
set_source_files_properties(ls-qpack/lsqpack.c PROPERTIES COMPILE_FLAGS ${QPACK_FLAGS})
ENDIF()

include_directories(ls-qpack)

IF(PROJECT_NAME STREQUAL "openlitespeed")
    INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/spdy)
ELSE()
    INCLUDE_DIRECTORIES(../lshpack)
    SET(lsquic_STAT_SRCS ${lsquic_STAT_SRCS}
        lsquic_xxhash.c
        ../lshpack/lshpack.c
    )
ENDIF()

ADD_CUSTOM_COMMAND(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lsquic_versions_to_string.c
    COMMAND ${PERL_EXECUTABLE}
    ARGS ${CMAKE_CURRENT_SOURCE_DIR}/gen-verstrs.pl ${CMAKE_CURRENT_SOURCE_DIR}/../../include/lsquic.h ${CMAKE_CURRENT_BINARY_DIR}/lsquic_versions_to_string.c
    DEPENDS ./gen-verstrs.pl ${CMAKE_CURRENT_SOURCE_DIR}/../../include/lsquic.h
)
SET(lsquic_STAT_SRCS ${lsquic_STAT_SRCS} ${CMAKE_CURRENT_BINARY_DIR}/lsquic_versions_to_string.c)
SET(lsquic_STAT_SRCS ${lsquic_STAT_SRCS} ls-sfparser.c)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DXXH_HEADER_NAME=\\\"lsquic_xxhash.h\\\"")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLSQPACK_ENC_LOGGER_HEADER=\\\"lsquic_qpack_enc_logger.h\\\"")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLSQPACK_DEC_LOGGER_HEADER=\\\"lsquic_qpack_dec_logger.h\\\"")

if(NEED_LIBRT_FOR_clock_getres)
    target_link_libraries(lsquic PRIVATE ${RT_LIBRARY})
endif()

IF(LSQUIC_SHARED_LIB)
  add_library(lsquic SHARED ${lsquic_STAT_SRCS})
  TARGET_LINK_LIBRARIES(lsquic PRIVATE ${BORINGSSL_LIB_ssl} ${BORINGSSL_LIB_crypto} ${ZLIB_LIB})
  IF(MSVC)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLSQUIC_EXPORTS")
  TARGET_LINK_LIBRARIES(lsquic PRIVATE ws2_32.lib)
  ENDIF()
ELSE()
  add_library(lsquic STATIC ${lsquic_STAT_SRCS})
ENDIF()

target_include_directories(
    lsquic PUBLIC $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/lsquic>)

install(TARGETS lsquic
    EXPORT lsquic-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    lsquic-config.cmake ${CMAKE_CURRENT_BINARY_DIR}/lsquic-config.cmake
    INSTALL_DESTINATION share/lsquic
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
    PATH_VARS CMAKE_INSTALL_INCLUDEDIR)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/lsquic-config.cmake
    DESTINATION share/lsquic)

install(
    EXPORT lsquic-targets
    DESTINATION share/lsquic
    NAMESPACE lsquic::
    FILE lsquic-targets.cmake)

