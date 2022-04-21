# Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE.
set(lsquic_EXTRA_SRCS)

if(NOT (PROJECT_NAME STREQUAL "openlitespeed"))
    list(APPEND lsquic_EXTRA_SRCS lsquic_xxhash.c ../lshpack/lshpack.c)
endif()

# library type controlled by BUILD_SHARED_LIBS if STATIC or SHARED not
# explicitly specified
add_library(
    lsquic
    ${lsquic_EXTRA_SRCS}
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
    ls-sfparser.c
    ${CMAKE_CURRENT_BINARY_DIR}/lsquic_versions_to_string.c)
target_link_libraries(lsquic PRIVATE ${BORINGSSL_LIB_ssl}
                                     ${BORINGSSL_LIB_crypto} ZLIB::ZLIB)
target_compile_definitions(
    lsquic
    PRIVATE "LSQPACK_DEC_LOGGER_HEADER=\"lsquic_qpack_dec_logger.h\""
            "LSQPACK_ENC_LOGGER_HEADER=\"lsquic_qpack_enc_logger.h\""
            "XXH_HEADER_NAME=\"lsquic_xxhash.h\"")
target_include_directories(lsquic PRIVATE ls-qpack)

if(PROJECT_NAME STREQUAL "openlitespeed")
    target_include_directories(lsquic PRIVATE ${PROJECT_SOURCE_DIR}/src/spdy)
else()
    target_include_directories(lsquic PRIVATE ../lshpack)
endif()
if(MSVC)
    target_compile_definitions(lsquic PRIVATE LSQUIC_EXPORTS)
    target_link_libraries(lsquic PRIVATE ws2_32)
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lsquic_versions_to_string.c
    COMMAND
        ${PERL} ARGS ${CMAKE_CURRENT_SOURCE_DIR}/gen-verstrs.pl
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include/lsquic.h
        ${CMAKE_CURRENT_BINARY_DIR}/lsquic_versions_to_string.c
    DEPENDS ./gen-verstrs.pl ${CMAKE_CURRENT_SOURCE_DIR}/../../include/lsquic.h)

if(WIN32)
    target_compile_definitions(lsquic PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()
if(MSVC)
    target_compile_options(lsquic PRIVATE -W4 -WX -Zi
                                          $<IF:$<CONFIG:Debug>,-Od,-Ox>)
    target_include_directories(
        lsquic
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../wincompat
        PUBLIC $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/lsquic/wincompat>
    )
    target_compile_definitions(lsquic PRIVATE _CRT_SECURE_NO_WARNINGS)

    if(BUILD_SHARED_LIBS)
        target_compile_definitions(lsquic PRIVATE LSQUIC_SHARED_LIB)
    endif()
    target_compile_options(lsquic PUBLIC /wd4100) # unreferenced formal
                                                  # parameter
    target_compile_options(lsquic PUBLIC /wd4115) # unnamed type definition in
                                                  # parentheses
    target_compile_options(lsquic PUBLIC /wd4116) # named type definition in
                                                  # parentheses
    target_compile_options(
        lsquic PUBLIC /wd4146) # unary minus operator applied to unsigned type,
                               # result still unsigned
    target_compile_options(lsquic PUBLIC /wd4132) # const initialization
    target_compile_options(lsquic PUBLIC /wd4200) # zero-sized array
    target_compile_options(lsquic PUBLIC /wd4204) # non-constant aggregate
                                                  # initializer
    target_compile_options(lsquic PUBLIC /wd4244) # integer conversion
    target_compile_options(
        lsquic PUBLIC /wd4245) # conversion from 'int' to 'unsigned int',
                               # signed/unsigned mismatch
    target_compile_options(lsquic PUBLIC /wd4267) # integer conversion
    target_compile_options(
        lsquic PUBLIC /wd4214) # nonstandard extension used: bit field types
                               # other than int
    target_compile_options(
        lsquic PUBLIC /wd4295) # array is too small to include a terminating
                               # null character
    target_compile_options(
        lsquic PUBLIC /wd4334) # result of 32-bit shift implicitly converted to
                               # 64 bits (was 64-bit shift intended?)
    target_compile_options(lsquic PUBLIC /wd4456) # hide previous local
                                                  # declaration
    target_compile_options(lsquic PUBLIC /wd4459) # hide global declaration
    target_compile_options(lsquic PUBLIC /wd4706) # assignment within
                                                  # conditional expression
    target_compile_options(lsquic PUBLIC /wd4090) # different 'const' qualifier
                                                  # (TODO: debug ls-sfparser.c)
    target_compile_options(lsquic PUBLIC /wd4305) # truncation from double to
                                                  # float
else()
    # configure flags for lsqpack.c
    set(QPACK_FLAGS "-Wno-uninitialized")
    if(HAS_NO_IMPLICIT_FALLTHROUGH)
        string(APPEND QPACK_FLAGS " -Wno-implicit-fallthrough")
    endif()
    set_source_files_properties(ls-qpack/lsqpack.c PROPERTIES COMPILE_FLAGS
                                                              ${QPACK_FLAGS})

    # flags for the whole library
    target_compile_options(lsquic PRIVATE -fno-omit-frame-pointer)

    if(LSQUIC_SANITIZER)
        target_compile_options(lsquic PRIVATE $<DEBUG:-fsanitize=address>)
        # This command is introduced in CMake 3.13, so 3.13 is required for
        # ASan.
        target_link_options(lsquic PRIVATE $<DEBUG:-fsanitize=address>)
    endif()

    if(LSQUIC_PROFILE)
        target_compile_options(lsquic PRIVATE -g -pg)
    endif()

    if(LSQUIC_COVERAGE)
        target_compile_options(lsquic PUBLIC -fprofile-arcs -ftest-coverage)
    endif()
endif()

if(LSQUIC_FIU)
    target_compile_definitions(lsquic PRIVATE FIU_ENABLE=1)
    target_link_libraries(lsquic PRIVATE fiu)
endif()
if(NEED_LIBRT_FOR_clock_getres AND RT_LIBRARY)
    target_link_libraries(lsquic PRIVATE ${RT_LIBRARY})
endif()

if(LSQUIC_DEBUG_NEXT_ADV_TICK)
    target_compile_definitions(lsquic PRIVATE LSQUIC_DEBUG_NEXT_ADV_TICK=1)
else()
    target_compile_definitions(lsquic PRIVATE LSQUIC_DEBUG_NEXT_ADV_TICK=0)
endif()
if(LSQUIC_CONN_STATS)
    target_compile_definitions(lsquic PRIVATE LSQUIC_CONN_STATS=1)
else()
    target_compile_definitions(lsquic PRIVATE LSQUIC_CONN_STATS=0)
endif()
if(LSQUIC_ENABLE_HANDSHAKE_DISABLE)
    target_compile_definitions(lsquic PRIVATE LSQUIC_ENABLE_HANDSHAKE_DISABLE=1)
endif()
if(LSQUIC_COMPILE_OUT_DEBUG_MESSAGES)
    target_compile_definitions(lsquic
                               PRIVATE LSQUIC_LOWEST_LOG_LEVEL=LSQ_LOG_WARN)
endif()
if(LSQUIC_DEVEL)
    target_compile_definitions(lsquic PRIVATE LSQUIC_DEVEL=1)
endif()

install(
    TARGETS lsquic
    EXPORT lsquic-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

target_include_directories(
    lsquic PUBLIC $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/lsquic>)

configure_file(lsquic-config.cmake
               ${CMAKE_CURRENT_BINARY_DIR}/lsquic-config.cmake @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lsquic-config.cmake
        DESTINATION share/lsquic)

install(
    EXPORT lsquic-targets
    DESTINATION share/lsquic
    NAMESPACE lsquic::
    FILE lsquic-targets.cmake)
