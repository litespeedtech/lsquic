noinst_LIBRARIES = liblsquic.a

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/src/lsr -I$(top_srcdir)/src/liblsquic/ls-qpack -I$(top_srcdir)/src/spdy/


liblsquic_a_METASOURCES = AUTO

liblsquic_a_SOURCES = \
	ls-qpack/lsqpack.c \
	lsquic_adaptive_cc.c \
	lsquic_alarmset.c \
	lsquic_arr.c \
	lsquic_attq.c \
	lsquic_bbr.c \
	lsquic_bw_sampler.c \
	lsquic_cfcw.c \
	lsquic_chsk_stream.c \
	lsquic_conn.c \
	lsquic_crand.c \
	lsquic_crt_compress.c \
	lsquic_crypto.c \
	lsquic_cubic.c \
	lsquic_di_error.c \
	lsquic_di_hash.c \
	lsquic_di_nocopy.c \
	lsquic_enc_sess_common.c \
	lsquic_enc_sess_ietf.c \
	lsquic_eng_hist.c \
	lsquic_engine.c \
	lsquic_ev_log.c \
	lsquic_frab_list.c \
	lsquic_frame_common.c \
	lsquic_frame_reader.c \
	lsquic_frame_writer.c \
	lsquic_full_conn.c \
	lsquic_full_conn_ietf.c \
	lsquic_global.c \
	lsquic_handshake.c \
	lsquic_hash.c \
	lsquic_hcsi_reader.c \
	lsquic_hcso_writer.c \
	lsquic_headers_stream.c \
	lsquic_hkdf.c \
	lsquic_hpi.c \
	lsquic_hspack_valid.c \
	lsquic_http.c \
	lsquic_http1x_if.c \
	lsquic_logger.c \
	lsquic_malo.c \
	lsquic_min_heap.c \
	lsquic_mini_conn.c \
	lsquic_mini_conn_ietf.c \
	lsquic_minmax.c \
	lsquic_mm.c \
	lsquic_pacer.c \
	lsquic_packet_common.c \
	lsquic_packet_gquic.c \
	lsquic_packet_in.c \
	lsquic_packet_out.c \
	lsquic_packet_resize.c \
	lsquic_parse_Q046.c \
	lsquic_parse_Q050.c \
	lsquic_parse_common.c \
	lsquic_parse_gquic_be.c \
	lsquic_parse_gquic_common.c \
	lsquic_parse_ietf_v1.c \
	lsquic_parse_iquic_common.c \
	lsquic_pr_queue.c \
	lsquic_purga.c \
	lsquic_qdec_hdl.c \
	lsquic_qenc_hdl.c \
	lsquic_qlog.c \
	lsquic_qpack_exp.c \
	lsquic_rechist.c \
	lsquic_rtt.c \
	lsquic_send_ctl.c \
	lsquic_senhist.c \
	lsquic_set.c \
	lsquic_sfcw.c \
	lsquic_shsk_stream.c \
	lsquic_spi.c \
	lsquic_stock_shi.c \
	lsquic_str.c \
	lsquic_stream.c \
	lsquic_tokgen.c \
	lsquic_trans_params.c \
	lsquic_trechist.c \
	lsquic_util.c \
	lsquic_varint.c \
	lsquic_version.c \
	lsquic_xxhash.c \
	lsquic_versions_to_string.c \
	ls-sfparser.c

lsquic_versions_to_string.c: gen-verstrs.pl
	$(top_srcdir)/src/liblsquic/gen-verstrs.pl $(top_srcdir)/include/lsquic.h lsquic_versions_to_string.c
