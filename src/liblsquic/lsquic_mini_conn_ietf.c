/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_mini_conn_ietf.c -- Mini connection used by the IETF QUIC
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#include <stdlib.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_mm.h"
#include "lsquic_malo.h"
#include "lsquic_engine_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_rtt.h"
#include "lsquic_util.h"
#include "lsquic_enc_sess.h"
#include "lsquic_trechist.h"
#include "lsquic_mini_conn_ietf.h"
#include "lsquic_ev_log.h"
#include "lsquic_trans_params.h"
#include "lsquic_ietf.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_attq.h"
#include "lsquic_alarmset.h"
#include "lsquic_crand.h"

#define LSQUIC_LOGGER_MODULE LSQLM_MINI_CONN
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(&conn->imc_conn)
#include "lsquic_logger.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static const struct conn_iface mini_conn_ietf_iface;

static unsigned highest_bit_set (unsigned long long);

static int
imico_can_send (const struct ietf_mini_conn *, size_t);

static void
ietf_mini_conn_ci_abort_error (struct lsquic_conn *lconn, int is_app,
                                unsigned error_code, const char *fmt, ...);

static const enum header_type el2hety[] =
{
    [ENC_LEV_INIT]  = HETY_HANDSHAKE,
    [ENC_LEV_CLEAR] = HETY_INITIAL,
    [ENC_LEV_FORW]  = HETY_NOT_SET,
    [ENC_LEV_EARLY] = 0,    /* Invalid */
};


static void
imico_destroy_packet (struct ietf_mini_conn *conn,
                                        struct lsquic_packet_out *packet_out)
{
    lsquic_packet_out_destroy(packet_out, conn->imc_enpub,
                                                conn->imc_path.np_peer_ctx);
}


int
lsquic_mini_conn_ietf_ecn_ok (const struct ietf_mini_conn *conn)
{
    packno_set_t acked;

    /* First flight has only Initial and Handshake packets */
    acked = conn->imc_acked_packnos[PNS_INIT]
          | conn->imc_acked_packnos[PNS_HSK]
          ;
    return 0 != (conn->imc_ecn_packnos & acked);
}


#define imico_ecn_ok lsquic_mini_conn_ietf_ecn_ok


static enum ecn
imico_get_ecn (struct ietf_mini_conn *conn)
{
    if (!conn->imc_enpub->enp_settings.es_ecn)
        return ECN_NOT_ECT;
    else if (!conn->imc_sent_packnos /* We set ECT0 in first flight */
                                                    || imico_ecn_ok(conn))
        return ECN_ECT0;
    else
        return ECN_NOT_ECT;
}


static struct lsquic_packet_out *
imico_get_packet_out (struct ietf_mini_conn *conn,
                                    enum header_type header_type, size_t need)
{
    struct lsquic_packet_out *packet_out;
    enum ecn ecn;

    if (need)
        TAILQ_FOREACH(packet_out, &conn->imc_packets_out, po_next)
            if (!(packet_out->po_flags & PO_SENT)
                    && packet_out->po_header_type == header_type
                    && lsquic_packet_out_avail(packet_out) >= need)
                return packet_out;

    if (conn->imc_next_packno >= MAX_PACKETS)
    {
        LSQ_DEBUG("ran out of outgoing packet numbers, won't allocate packet");
        return NULL;
    }

    packet_out = lsquic_packet_out_new(&conn->imc_enpub->enp_mm, NULL, 1,
            &conn->imc_conn, IQUIC_PACKNO_LEN_1, NULL, NULL, &conn->imc_path,
            header_type);
    if (!packet_out)
    {
        LSQ_WARN("could not allocate packet: %s", strerror(errno));
        return NULL;
    }

    packet_out->po_header_type = header_type;
    packet_out->po_packno = conn->imc_next_packno++;
    packet_out->po_flags |= PO_MINI;
    lsquic_packet_out_set_pns(packet_out, lsquic_hety2pns[header_type]);
    ecn = imico_get_ecn(conn);
    packet_out->po_lflags |= ecn << POECN_SHIFT;
    TAILQ_INSERT_TAIL(&conn->imc_packets_out, packet_out, po_next);
    packet_out->po_loss_chain = packet_out;
    return packet_out;
}


static struct ietf_mini_conn *
cryst_get_conn (const struct mini_crypto_stream *cryst)
{
    return (void *)
        ((unsigned char *) (cryst - cryst->mcs_enc_level)
                        - offsetof(struct ietf_mini_conn, imc_streams));
}


struct msg_ctx
{
    const unsigned char       *buf;
    const unsigned char *const end;
};


static size_t
read_from_msg_ctx (void *ctx, void *buf, size_t len, int *fin)
{
    struct msg_ctx *msg_ctx = ctx;
    if (len > (uintptr_t) (msg_ctx->end - msg_ctx->buf))
        len = msg_ctx->end - msg_ctx->buf;
    memcpy(buf, msg_ctx->buf, len);
    msg_ctx->buf += len;
    return len;
}


static int
imico_chlo_has_been_consumed (const struct ietf_mini_conn *conn)
{
    return conn->imc_streams[ENC_LEV_CLEAR].mcs_read_off > 3
        && conn->imc_streams[ENC_LEV_CLEAR].mcs_read_off >= conn->imc_ch_len;
}


static int
imico_maybe_process_params (struct ietf_mini_conn *conn)
{
    const struct transport_params *params;

    if (imico_chlo_has_been_consumed(conn)
        && (conn->imc_flags & (IMC_ENC_SESS_INITED|IMC_HAVE_TP))
                                                    == IMC_ENC_SESS_INITED)
    {
        params = conn->imc_conn.cn_esf.i->esfi_get_peer_transport_params(
                                                conn->imc_conn.cn_enc_session);
        if (params)
        {
            conn->imc_flags |= IMC_HAVE_TP;
            conn->imc_ack_exp = params->tp_ack_delay_exponent;
            if (params->tp_set & (1 << TPI_MAX_UDP_PAYLOAD_SIZE))
            {
                if (params->tp_numerics[TPI_MAX_UDP_PAYLOAD_SIZE]
                                                < conn->imc_path.np_pack_size)
                    conn->imc_path.np_pack_size =
                                params->tp_numerics[TPI_MAX_UDP_PAYLOAD_SIZE];
            }
            LSQ_DEBUG("read transport params, packet size is set to %hu bytes",
                                                conn->imc_path.np_pack_size);
        }
        else
        {
            conn->imc_flags |= IMC_BAD_TRANS_PARAMS;
            return -1;
        }
    }

    return 0;
}


static ssize_t
imico_stream_write (void *stream, const void *bufp, size_t bufsz)
{
    struct mini_crypto_stream *const cryst = stream;
    struct ietf_mini_conn *const conn = cryst_get_conn(cryst);
    struct lsquic_conn *const lconn = &conn->imc_conn;
    const struct parse_funcs *const pf = lconn->cn_pf;
    struct msg_ctx msg_ctx = { bufp, (unsigned char *) bufp + bufsz, };
    struct lsquic_packet_out *packet_out;
    size_t header_sz, need;
    const unsigned char *p;
    int len;

    if (0 != imico_maybe_process_params(conn))
        return -1;

    if (PNS_INIT == lsquic_enclev2pns[ cryst->mcs_enc_level ]
                                        && (conn->imc_flags & IMC_IGNORE_INIT))
    {
        LSQ_WARN("trying to write at the ignored Initial level");
        return bufsz;
    }

    while (msg_ctx.buf < msg_ctx.end)
    {
        header_sz = lconn->cn_pf->pf_calc_crypto_frame_header_sz(
                            cryst->mcs_write_off, msg_ctx.end - msg_ctx.buf);
        need = header_sz + 1;
        packet_out = imico_get_packet_out(conn,
                                        el2hety[ cryst->mcs_enc_level ], need);
        if (!packet_out)
            return -1;

        p = msg_ctx.buf;
        len = pf->pf_gen_crypto_frame(packet_out->po_data + packet_out->po_data_sz,
                    lsquic_packet_out_avail(packet_out), 0, cryst->mcs_write_off, 0,
                    msg_ctx.end - msg_ctx.buf, read_from_msg_ctx, &msg_ctx);
        if (len < 0)
            return len;
        EV_LOG_GENERATED_CRYPTO_FRAME(LSQUIC_LOG_CONN_ID, pf,
                                packet_out->po_data + packet_out->po_data_sz, len);
        packet_out->po_data_sz += len;
        packet_out->po_frame_types |= 1 << QUIC_FRAME_CRYPTO;
        packet_out->po_flags |= PO_HELLO;
        cryst->mcs_write_off += msg_ctx.buf - p;
    }

    assert(msg_ctx.buf == msg_ctx.end);
    return bufsz;
}


static int
imico_stream_flush (void *stream)
{
    return 0;
}


static struct stream_frame *
imico_find_stream_frame (const struct ietf_mini_conn *conn,
                                enum enc_level enc_level, unsigned read_off)
{
    struct stream_frame *frame;

    if (conn->imc_last_in.frame && enc_level == conn->imc_last_in.enc_level
            && read_off == DF_ROFF(conn->imc_last_in.frame))
        return conn->imc_last_in.frame;

    TAILQ_FOREACH(frame, &conn->imc_crypto_frames, next_frame)
        if (enc_level == frame->stream_id && read_off == DF_ROFF(frame))
            return frame;

    return NULL;
}


static void
imico_read_chlo_size (struct ietf_mini_conn *conn, const unsigned char *buf,
                                                                    size_t sz)
{
    const unsigned char *const end = buf + sz;

    assert(conn->imc_streams[ENC_LEV_CLEAR].mcs_read_off < 4);
    switch (conn->imc_streams[ENC_LEV_CLEAR].mcs_read_off)
    {
    case 0:
        if (buf == end)
            return;
        if (*buf != 1)
        {
            LSQ_DEBUG("Does not begin with ClientHello");
            conn->imc_flags |= IMC_ERROR;
            return;
        }
        ++buf;
        /* fall-through */
    case 1:
        if (buf == end)
            return;
        if (*buf != 0)
        {
            LSQ_DEBUG("ClientHello larger than 16K");
            conn->imc_flags |= IMC_ERROR;
            return;
        }
        ++buf;
        /* fall-through */
    case 2:
        if (buf == end)
            return;
        conn->imc_ch_len = *buf << 8;
        ++buf;
        /* fall-through */
    default:
        if (buf == end)
            return;
        conn->imc_ch_len |= *buf;
    }
}


static ssize_t
imico_stream_readf (void *stream,
        size_t (*readf)(void *, const unsigned char *, size_t, int), void *ctx)
{
    struct mini_crypto_stream *const cryst = stream;
    struct ietf_mini_conn *const conn = cryst_get_conn(cryst);
    struct stream_frame *frame;
    const unsigned char *buf;
    size_t nread, total_read;
    unsigned avail;

    total_read = 0;
    while ((frame = imico_find_stream_frame(conn, cryst->mcs_enc_level,
                                                        cryst->mcs_read_off)))
    {
        avail = DF_SIZE(frame) - frame->data_frame.df_read_off;
        buf = frame->data_frame.df_data + frame->data_frame.df_read_off;
        nread = readf(ctx, buf, avail, DF_FIN(frame));
        if (cryst->mcs_enc_level == ENC_LEV_CLEAR && cryst->mcs_read_off < 4)
            imico_read_chlo_size(conn, buf, nread);
        total_read += nread;
        cryst->mcs_read_off += nread;
        frame->data_frame.df_read_off += nread;
        LSQ_DEBUG("read %zu bytes at offset %"PRIu64" on enc level %u", nread,
            DF_ROFF(frame), cryst->mcs_enc_level);
        if (DF_END(frame) == DF_ROFF(frame))
        {
            if (frame == conn->imc_last_in.frame)
                conn->imc_last_in.frame = NULL;
            else
            {
                TAILQ_REMOVE(&conn->imc_crypto_frames, frame, next_frame);
                --conn->imc_n_crypto_frames;
                conn->imc_crypto_frames_sz -= DF_SIZE(frame);
                lsquic_packet_in_put(&conn->imc_enpub->enp_mm,
                                                            frame->packet_in);
                lsquic_malo_put(frame);
            }
        }
        if (nread < avail)
            break;
    }

    if (total_read > 0)
        return total_read;
    else
    {
        /* CRYPTO streams never end, so zero bytes read always means
         * EWOULDBLOCK
         */
        errno = EWOULDBLOCK;
        return -1;
    }
}


static int
imico_stream_wantX (struct mini_crypto_stream *cryst, int bit, int is_want)
{
    int old;

    old = (cryst->mcs_flags & (1 << bit)) > 0;
    cryst->mcs_flags &= ~(1 << bit);
    cryst->mcs_flags |= !!is_want << bit;
    return old;
}


static int
imico_stream_wantwrite (void *stream, int is_want)
{
    return imico_stream_wantX(stream, MCSBIT_WANTWRITE, is_want);
}


static int
imico_stream_wantread (void *stream, int is_want)
{
    return imico_stream_wantX(stream, MCSBIT_WANTREAD, is_want);
}


static enum enc_level
imico_stream_enc_level (void *stream)
{
    struct mini_crypto_stream *const cryst = stream;
    return cryst->mcs_enc_level;
}


static const struct crypto_stream_if crypto_stream_if =
{
    .csi_write      = imico_stream_write,
    .csi_flush      = imico_stream_flush,
    .csi_readf      = imico_stream_readf,
    .csi_wantwrite  = imico_stream_wantwrite,
    .csi_wantread   = imico_stream_wantread,
    .csi_enc_level  = imico_stream_enc_level,
};


static int
is_first_packet_ok (const struct lsquic_packet_in *packet_in,
                                                    size_t udp_payload_size)
{
    if (udp_payload_size < IQUIC_MIN_INIT_PACKET_SZ)
    {
        /* [draft-ietf-quic-transport-24] Section 14 */
        LSQ_LOG1(LSQ_LOG_DEBUG, "incoming UDP payload too small: %zu bytes",
                                                            udp_payload_size);
        return 0;
    }
    /* TODO: Move decryption of the first packet into this function? */
    return 1;   /* TODO */
}


static void
imico_peer_addr_validated (struct ietf_mini_conn *conn, const char *how)
{
    if (!(conn->imc_flags & IMC_ADDR_VALIDATED))
    {
        conn->imc_flags |= IMC_ADDR_VALIDATED;
        LSQ_DEBUG("peer address validated (%s)", how);
    }
}


struct lsquic_conn *
lsquic_mini_conn_ietf_new (struct lsquic_engine_public *enpub,
               const struct lsquic_packet_in *packet_in,
           enum lsquic_version version, int is_ipv4, const lsquic_cid_t *odcid,
           size_t udp_payload_size)
{
    struct ietf_mini_conn *conn;
    enc_session_t *enc_sess;
    enum enc_level i;
    const struct enc_session_funcs_iquic *esfi;
    unsigned char rand_nybble;

    if (!is_first_packet_ok(packet_in, udp_payload_size))
        return NULL;

    conn = lsquic_malo_get(enpub->enp_mm.malo.mini_conn_ietf);
    if (!conn)
    {
        LSQ_LOG1(LSQ_LOG_WARN, "cannot allocate mini connection: %s",
                                                            strerror(errno));
        return NULL;
    }
    memset(conn, 0, sizeof(*conn));
    conn->imc_conn.cn_if = &mini_conn_ietf_iface;
    conn->imc_conn.cn_cces = conn->imc_cces;
    conn->imc_conn.cn_n_cces = sizeof(conn->imc_cces)
                                                / sizeof(conn->imc_cces[0]);
    conn->imc_cces[0].cce_cid = packet_in->pi_dcid;
    conn->imc_cces[0].cce_flags = CCE_USED;
    conn->imc_conn.cn_cces_mask = 1;
    lsquic_scid_from_packet_in(packet_in, &conn->imc_path.np_dcid);
    LSQ_DEBUGC("recv SCID from client %"CID_FMT, CID_BITS(&conn->imc_cces[0].cce_cid));
    LSQ_DEBUGC("recv DCID from client %"CID_FMT, CID_BITS(&conn->imc_path.np_dcid));

    /* Generate new SCID. Since is not the original SCID, it is given
     * a sequence number (0) and therefore can be retired by the client.
     */
    enpub->enp_generate_scid(enpub->enp_gen_scid_ctx, &conn->imc_conn,
        &conn->imc_conn.cn_cces[1].cce_cid, enpub->enp_settings.es_scid_len);

    LSQ_DEBUGC("generated SCID %"CID_FMT" at index %u, switching to it",
                CID_BITS(&conn->imc_conn.cn_cces[1].cce_cid), 1);
    conn->imc_conn.cn_cces[1].cce_flags = CCE_SEQNO | CCE_USED;
    conn->imc_conn.cn_cces_mask |= 1u << 1;
    conn->imc_conn.cn_cur_cce_idx = 1;

    conn->imc_conn.cn_flags = LSCONN_MINI|LSCONN_IETF|LSCONN_SERVER;
    conn->imc_conn.cn_version = version;

    for (i = 0; i < N_ENC_LEVS; ++i)
    {
        conn->imc_streams[i].mcs_enc_level = i;
        conn->imc_stream_ps[i] = &conn->imc_streams[i];
    }

    rand_nybble = lsquic_crand_get_nybble(enpub->enp_crand);
    if (rand_nybble == 0)
    {
        /* Use trechist for about one out of every sixteen connections so
         * that the code does not grow stale.
         */
        LSQ_DEBUG("using trechist");
        conn->imc_flags |= IMC_TRECHIST;
        conn->imc_recvd_packnos.trechist.hist_elems
                                    = malloc(TRECHIST_SIZE * IMICO_N_PNS);
        if (!conn->imc_recvd_packnos.trechist.hist_elems)
        {
            LSQ_WARN("cannot allocate trechist elems");
            return NULL;
        }
    }

    esfi = select_esf_iquic_by_ver(version);
    enc_sess = esfi->esfi_create_server(enpub, &conn->imc_conn,
                &packet_in->pi_dcid, conn->imc_stream_ps, &crypto_stream_if,
                &conn->imc_cces[0].cce_cid, &conn->imc_path.np_dcid);
    if (!enc_sess)
    {
        lsquic_malo_put(conn);
        return NULL;
    }

    conn->imc_enpub = enpub;
    conn->imc_created = packet_in->pi_received;
    if (enpub->enp_settings.es_base_plpmtu)
        conn->imc_path.np_pack_size = enpub->enp_settings.es_base_plpmtu;
    else if (is_ipv4)
        conn->imc_path.np_pack_size = IQUIC_MAX_IPv4_PACKET_SZ;
    else
        conn->imc_path.np_pack_size = IQUIC_MAX_IPv6_PACKET_SZ;
    conn->imc_conn.cn_pf = select_pf_by_ver(version);
    conn->imc_conn.cn_esf.i = esfi;
    conn->imc_conn.cn_enc_session = enc_sess;
    conn->imc_conn.cn_esf_c = select_esf_common_by_ver(version);
    TAILQ_INIT(&conn->imc_packets_out);
    TAILQ_INIT(&conn->imc_app_packets);
    TAILQ_INIT(&conn->imc_crypto_frames);
    if (odcid)
        imico_peer_addr_validated(conn, "odcid");
#if LSQUIC_DEVEL
    {
        const char *const s = getenv("LSQUIC_LOSE_0RTT");
        if (s && atoi(s))
        {
            LSQ_DEBUG("will lose 0-RTT packets (via env variable)");
            conn->imc_delayed_packets_count = UCHAR_MAX;
        }
    }
#endif

    LSQ_DEBUG("created mini connection object %p; max packet size=%hu",
                                                conn, conn->imc_path.np_pack_size);
    return &conn->imc_conn;
}


static void
ietf_mini_conn_ci_client_call_on_new (struct lsquic_conn *lconn)
{
    assert(0);
}


static void
ietf_mini_conn_ci_destroy (struct lsquic_conn *lconn)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    struct lsquic_packet_out *packet_out;
    struct lsquic_packet_in *packet_in;
    struct stream_frame *frame;

    while ((packet_out = TAILQ_FIRST(&conn->imc_packets_out)))
    {
        TAILQ_REMOVE(&conn->imc_packets_out, packet_out, po_next);
        imico_destroy_packet(conn, packet_out);
    }
    while ((packet_in = TAILQ_FIRST(&conn->imc_app_packets)))
    {
        TAILQ_REMOVE(&conn->imc_app_packets, packet_in, pi_next);
        lsquic_packet_in_put(&conn->imc_enpub->enp_mm, packet_in);
    }
    while ((frame = TAILQ_FIRST(&conn->imc_crypto_frames)))
    {
        TAILQ_REMOVE(&conn->imc_crypto_frames, frame, next_frame);
        lsquic_packet_in_put(&conn->imc_enpub->enp_mm, frame->packet_in);
        lsquic_malo_put(frame);
    }
    if (lconn->cn_enc_session)
        lconn->cn_esf.i->esfi_destroy(lconn->cn_enc_session);
    LSQ_DEBUG("ietf_mini_conn_ci_destroyed");
    if (conn->imc_flags & IMC_TRECHIST)
        free(conn->imc_recvd_packnos.trechist.hist_elems);
    lsquic_malo_put(conn);
}


static struct lsquic_engine *
ietf_mini_conn_ci_get_engine (struct lsquic_conn *lconn)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    return conn->imc_enpub->enp_engine;
}


static void
ietf_mini_conn_ci_hsk_done (struct lsquic_conn *lconn,
                                                enum lsquic_hsk_status status)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;

    switch (status)
    {
    case LSQ_HSK_OK:
    case LSQ_HSK_RESUMED_OK:
        conn->imc_flags |= IMC_HSK_OK;
        conn->imc_conn.cn_flags |= LSCONN_HANDSHAKE_DONE;
        LSQ_DEBUG("handshake OK");
        break;
    default:
        assert(0);
        /* fall-through */
    case LSQ_HSK_FAIL:
        conn->imc_flags |= IMC_HSK_FAILED|IMC_ERROR;
        LSQ_INFO("handshake failed");
        break;
    }
}


static void
ietf_mini_conn_ci_tls_alert (struct lsquic_conn *lconn, uint8_t alert)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    LSQ_DEBUG("got TLS alert %"PRIu8, alert);
    conn->imc_flags |= IMC_ERROR|IMC_TLS_ALERT;
    conn->imc_tls_alert = alert;
}


/* A mini connection is only tickable if it has unsent packets.  This can
 * occur when packet sending is delayed.
 *
 * Otherwise, a mini connection is not tickable:  Either there are incoming
 * packets, in which case, the connection is going to be ticked, or there is
 * an alarm pending, in which case it will be handled via the attq.
 */
static int
ietf_mini_conn_ci_is_tickable (struct lsquic_conn *lconn)
{
    struct ietf_mini_conn *const conn = (struct ietf_mini_conn *) lconn;
    const struct lsquic_packet_out *packet_out;
    size_t packet_size;

    if (conn->imc_enpub->enp_flags & ENPUB_CAN_SEND)
        TAILQ_FOREACH(packet_out, &conn->imc_packets_out, po_next)
            if (!(packet_out->po_flags & PO_SENT))
            {
                packet_size = lsquic_packet_out_total_sz(lconn, packet_out);
                return imico_can_send(conn, packet_size);
            }

    return 0;
}


static int
imico_can_send (const struct ietf_mini_conn *conn, size_t size)
{
    return (conn->imc_flags & IMC_ADDR_VALIDATED)
        || conn->imc_bytes_in * 3 >= conn->imc_bytes_out + size
        ;
}


static void
imico_zero_pad (struct lsquic_packet_out *packet_out)
{
    size_t pad_size;

    pad_size = lsquic_packet_out_avail(packet_out);
    memset(packet_out->po_data + packet_out->po_data_sz, 0, pad_size);
    packet_out->po_data_sz += pad_size;
    packet_out->po_frame_types |= QUIC_FTBIT_PADDING;
}


static struct lsquic_packet_out *
ietf_mini_conn_ci_next_packet_to_send (struct lsquic_conn *lconn,
                                            const struct to_coal *to_coal)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    struct lsquic_packet_out *packet_out;
    size_t packet_size;

    TAILQ_FOREACH(packet_out, &conn->imc_packets_out, po_next)
    {
        if (packet_out->po_flags & PO_SENT)
            continue;
        /* [draft-ietf-quic-transport-32] Section 14.1:
         " a server MUST expand the payload of all UDP datagrams carrying
         " ack-eliciting Initial packets to at least the smallest allowed
         " maximum datagram size of 1200 bytes.
         */
        if (packet_out->po_header_type == HETY_INITIAL
                && !(packet_out->po_frame_types & (1 << QUIC_FRAME_PADDING))
                && (packet_out->po_frame_types & IQUIC_FRAME_ACKABLE_MASK)
                && lsquic_packet_out_avail(packet_out) > 0)
            imico_zero_pad(packet_out);
        packet_size = lsquic_packet_out_total_sz(lconn, packet_out);
        if (!(to_coal
            && (packet_size + to_coal->prev_sz_sum
                                            > conn->imc_path.np_pack_size
            || !lsquic_packet_out_equal_dcids(to_coal->prev_packet, packet_out))
            ))
        {
            if (!imico_can_send(conn, packet_size))
            {
                LSQ_DEBUG("cannot send packet %"PRIu64" of size %zu: client "
                    "address has not been validated", packet_out->po_packno,
                    packet_size);
                return NULL;
            }
            packet_out->po_flags |= PO_SENT;
            conn->imc_bytes_out += packet_size;
            if (!to_coal)
                LSQ_DEBUG("packet_to_send: %"PRIu64, packet_out->po_packno);
            else
                LSQ_DEBUG("packet_to_send: %"PRIu64" (coalesced)",
                                                    packet_out->po_packno);
            return packet_out;
        }
        else
            return NULL;
    }

    return NULL;
}


static int
imico_calc_retx_timeout (const struct ietf_mini_conn *conn)
{
    lsquic_time_t to;
    to = lsquic_rtt_stats_get_srtt(&conn->imc_rtt_stats);
    if (to)
    {
        to += to / 2;
        if (to < 10000)
            to = 10000;
    }
    else
        to = 300000;
    return to << conn->imc_hsk_count;
}


static lsquic_time_t
ietf_mini_conn_ci_next_tick_time (struct lsquic_conn *lconn, unsigned *why)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    const struct lsquic_packet_out *packet_out;
    lsquic_time_t exp_time, retx_time;

    exp_time = conn->imc_created +
                        conn->imc_enpub->enp_settings.es_handshake_to;

    TAILQ_FOREACH(packet_out, &conn->imc_packets_out, po_next)
        if (packet_out->po_flags & PO_SENT)
        {
            retx_time = packet_out->po_sent + imico_calc_retx_timeout(conn);
            if (retx_time < exp_time)
            {
                *why = N_AEWS + AL_RETX_HSK;
                return retx_time;
            }
            else
            {
                *why = AEW_MINI_EXPIRE;
                return exp_time;
            }
        }

    *why = AEW_MINI_EXPIRE;
    return exp_time;
}


#define IMICO_PROC_FRAME_ARGS                                           \
    struct ietf_mini_conn *conn, struct lsquic_packet_in *packet_in,    \
    const unsigned char *p, size_t len


static void
imico_dispatch_stream_events (struct ietf_mini_conn *conn)
{
    enum enc_level i;

    for (i = 0; i < N_ENC_LEVS; ++i)
        if ((conn->imc_streams[i].mcs_flags & (MCS_CREATED|MCS_WANTREAD))
                                                == (MCS_CREATED|MCS_WANTREAD))
        {
            LSQ_DEBUG("dispatch read events on level #%u", i);
            lsquic_mini_cry_sm_if.on_read((void *) &conn->imc_streams[i],
                                            conn->imc_conn.cn_enc_session);
        }

    for (i = 0; i < N_ENC_LEVS; ++i)
        if ((conn->imc_streams[i].mcs_flags & (MCS_CREATED|MCS_WANTWRITE))
                                                == (MCS_CREATED|MCS_WANTWRITE))
        {
            LSQ_DEBUG("dispatch write events on level #%u", i);
            lsquic_mini_cry_sm_if.on_write((void *) &conn->imc_streams[i],
                                            conn->imc_conn.cn_enc_session);
        }
}


static int
imico_stash_stream_frame (struct ietf_mini_conn *conn,
        enum enc_level enc_level, struct lsquic_packet_in *packet_in,
        const struct stream_frame *frame)
{
    struct stream_frame *copy;

    if (conn->imc_n_crypto_frames >= IMICO_MAX_STASHED_FRAMES)
    {
        LSQ_INFO("cannot stash more CRYPTO frames, at %hhu already, while max "
            "is %u", conn->imc_n_crypto_frames, IMICO_MAX_STASHED_FRAMES);
        return -1;
    }

    if (conn->imc_crypto_frames_sz + DF_SIZE(frame) > IMICO_MAX_BUFFERED_CRYPTO)
    {
        LSQ_INFO("cannot stash more than %u bytes of CRYPTO frames",
            IMICO_MAX_BUFFERED_CRYPTO);
        return -1;
    }

    copy = lsquic_malo_get(conn->imc_enpub->enp_mm.malo.stream_frame);
    if (!copy)
    {
        LSQ_INFO("could not allocate stream frame for stashing");
        return -1;
    }

    *copy = *frame;
    copy->packet_in = lsquic_packet_in_get(packet_in);
    copy->stream_id = enc_level;
    TAILQ_INSERT_TAIL(&conn->imc_crypto_frames, copy, next_frame);
    ++conn->imc_n_crypto_frames;
    conn->imc_crypto_frames_sz += DF_SIZE(frame);
    return 0;
}


static unsigned
imico_process_crypto_frame (IMICO_PROC_FRAME_ARGS)
{
    int parsed_len;
    enum enc_level enc_level, i;
    struct stream_frame stream_frame;

    parsed_len = conn->imc_conn.cn_pf->pf_parse_crypto_frame(p, len,
                                                                &stream_frame);
    if (parsed_len < 0)
    {
        conn->imc_flags |= IMC_PARSE_FAILED;
        return 0;
    }

    enc_level = lsquic_packet_in_enc_level(packet_in);
    EV_LOG_CRYPTO_FRAME_IN(LSQUIC_LOG_CONN_ID, &stream_frame, enc_level);

    if (conn->imc_streams[enc_level].mcs_read_off >= DF_OFF(&stream_frame)
        && conn->imc_streams[enc_level].mcs_read_off < DF_END(&stream_frame))
        LSQ_DEBUG("Got CRYPTO frame for enc level #%u", enc_level);
    else if (conn->imc_streams[enc_level].mcs_read_off < DF_OFF(&stream_frame))
    {
        LSQ_DEBUG("Can't read CRYPTO frame on enc level #%u at offset %"PRIu64
            " yet -- stash", enc_level, DF_OFF(&stream_frame));
        if (0 == imico_stash_stream_frame(conn, enc_level, packet_in,
                                                                &stream_frame))
            return parsed_len;
        else
            return 0;
    }
    else
    {
        LSQ_DEBUG("Got duplicate CRYPTO frame for enc level #%u -- ignore",
                                                                    enc_level);
        return parsed_len;
    }

    if (!(conn->imc_flags & IMC_ENC_SESS_INITED))
    {
        if (0 != conn->imc_conn.cn_esf.i->esfi_init_server(
                                            conn->imc_conn.cn_enc_session))
            return 0;
        conn->imc_flags |= IMC_ENC_SESS_INITED;
    }

    if (!(conn->imc_streams[enc_level].mcs_flags & MCS_CREATED))
    {
        LSQ_DEBUG("creating stream on level #%u", enc_level);
        conn->imc_streams[enc_level].mcs_flags |= MCS_CREATED;
        lsquic_mini_cry_sm_if.on_new_stream(conn->imc_conn.cn_enc_session,
                                    (void *) &conn->imc_streams[enc_level]);
    }

    /* Assume that receiving a CRYPTO frame at a higher level means that we
     * no longer want to read from a lower level.
     */
    for (i = 0; i < enc_level; ++i)
        conn->imc_streams[i].mcs_flags &= ~MCS_WANTREAD;

    conn->imc_last_in.frame = &stream_frame;
    conn->imc_last_in.enc_level = enc_level;
    imico_dispatch_stream_events(conn);
    conn->imc_last_in.frame = NULL;

    if (DF_ROFF(&stream_frame) < DF_END(&stream_frame))
    {
        /* This is an odd condition, but let's handle it just in case */
        LSQ_DEBUG("New CRYPTO frame on enc level #%u not fully read -- stash",
            enc_level);
        if (0 != imico_stash_stream_frame(conn, enc_level, packet_in,
                                                                &stream_frame))
            return 0;
    }


    return parsed_len;
}


static ptrdiff_t
imico_count_zero_bytes (const unsigned char *p, size_t len)
{
    const unsigned char *const end = p + len;
    while (p < end && 0 == *p)
        ++p;
    return len - (end - p);
}


static unsigned
imico_process_padding_frame (IMICO_PROC_FRAME_ARGS)
{
    len = (size_t) imico_count_zero_bytes(p, len);
    EV_LOG_PADDING_FRAME_IN(LSQUIC_LOG_CONN_ID, len);
    return len;
}


static void
imico_take_rtt_sample (struct ietf_mini_conn *conn,
                            const struct lsquic_packet_out *packet_out,
                            lsquic_time_t now, lsquic_time_t lack_delta)
{
    assert(packet_out->po_sent);
    lsquic_time_t measured_rtt = now - packet_out->po_sent;
    if (lack_delta < measured_rtt)
    {
        lsquic_rtt_stats_update(&conn->imc_rtt_stats, measured_rtt, lack_delta);
        LSQ_DEBUG("srtt: %"PRIu64" usec, var: %"PRIu64,
                        lsquic_rtt_stats_get_srtt(&conn->imc_rtt_stats),
                        lsquic_rtt_stats_get_rttvar(&conn->imc_rtt_stats));
    }
}


static unsigned
imico_process_ack_frame (IMICO_PROC_FRAME_ARGS)
{
    int parsed_len;
    unsigned n;
    lsquic_packet_out_t *packet_out, *next;
    struct ack_info *acki;
    lsquic_packno_t packno;
    lsquic_time_t warn_time;
    packno_set_t acked;
    enum packnum_space pns;
    uint8_t ack_exp;

    if (conn->imc_flags & IMC_HAVE_TP)
        ack_exp = conn->imc_ack_exp;
    else
        ack_exp = TP_DEF_ACK_DELAY_EXP; /* Odd: no transport params yet? */
    acki = conn->imc_enpub->enp_mm.acki;
    parsed_len = conn->imc_conn.cn_pf->pf_parse_ack_frame(p, len, acki,
                                                                    ack_exp);
    if (parsed_len < 0)
    {
        conn->imc_flags |= IMC_PARSE_FAILED;
        return 0;
    }

    pns = lsquic_hety2pns[ packet_in->pi_header_type ];
    acked = 0;

    for (n = 0; n < acki->n_ranges; ++n)
    {
        if (acki->ranges[n].high <= MAX_PACKETS)
        {
            acked |= (1ULL << acki->ranges[n].high)
                                        | ((1ULL << acki->ranges[n].high) - 1);
            acked &= ~((1ULL << acki->ranges[n].low) - 1);
        }
        else
        {
            packno = acki->ranges[n].high;
            goto err_never_sent;
        }
    }
    if (acked & ~conn->imc_sent_packnos)
    {
        packno = highest_bit_set(acked & ~conn->imc_sent_packnos);
        goto err_never_sent;
    }

    EV_LOG_ACK_FRAME_IN(LSQUIC_LOG_CONN_ID, acki);
    for (packet_out = TAILQ_FIRST(&conn->imc_packets_out); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if ((1ULL << packet_out->po_packno) & acked)
        {
            assert(lsquic_packet_out_pns(packet_out) == pns);
            LSQ_DEBUG("Got ACK for packet %"PRIu64, packet_out->po_packno);
            if (packet_out->po_packno == largest_acked(acki))
                imico_take_rtt_sample(conn, packet_out,
                                    packet_in->pi_received, acki->lack_delta);
            TAILQ_REMOVE(&conn->imc_packets_out, packet_out, po_next);
            imico_destroy_packet(conn, packet_out);
        }
    }

    if (conn->imc_sent_packnos & ~conn->imc_acked_packnos[pns] & acked)
    {
        LSQ_DEBUG("Newly acked packets, reset handshake count");
        conn->imc_hsk_count = 0;
    }

    conn->imc_acked_packnos[pns] |= acked;

    return parsed_len;

  err_never_sent:
    warn_time = lsquic_time_now();
    if (0 == conn->imc_enpub->enp_last_warning[WT_ACKPARSE_MINI]
        || conn->imc_enpub->enp_last_warning[WT_ACKPARSE_MINI]
                + WARNING_INTERVAL < warn_time)
    {
        conn->imc_enpub->enp_last_warning[WT_ACKPARSE_MINI] = warn_time;
        LSQ_WARN("packet %"PRIu64" (pns: %u) was never sent", packno, pns);
    }
    else
        LSQ_DEBUG("packet %"PRIu64" (pns: %u) was never sent", packno, pns);
    return 0;
}


static unsigned
imico_process_ping_frame (IMICO_PROC_FRAME_ARGS)
{
    LSQ_DEBUG("got a PING frame, do nothing");
    return 1;
}


static unsigned
imico_process_connection_close_frame (IMICO_PROC_FRAME_ARGS)
{
    struct lsquic_packet_out *packet_out;
    uint64_t error_code;
    uint16_t reason_len;
    uint8_t reason_off;
    int parsed_len, app_error;

    while ((packet_out = TAILQ_FIRST(&conn->imc_packets_out)))
    {
        TAILQ_REMOVE(&conn->imc_packets_out, packet_out, po_next);
        imico_destroy_packet(conn, packet_out);
    }
    conn->imc_flags |= IMC_CLOSE_RECVD;
    parsed_len = conn->imc_conn.cn_pf->pf_parse_connect_close_frame(p, len,
                            &app_error, &error_code, &reason_len, &reason_off);
    if (parsed_len < 0)
    {
        conn->imc_flags |= IMC_PARSE_FAILED;
        return 0;
    }
    EV_LOG_CONNECTION_CLOSE_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code,
                            (int) reason_len, (const char *) p + reason_off);
    LSQ_INFO("Received CONNECTION_CLOSE frame (%s-level code: %"PRIu64"; "
            "reason: %.*s)", app_error ? "application" : "transport",
                error_code, (int) reason_len, (const char *) p + reason_off);
    return 0;   /* This shuts down the connection */
}


static unsigned
imico_process_invalid_frame (IMICO_PROC_FRAME_ARGS)
{
    LSQ_DEBUG("invalid frame %u (%s)", p[0],
        frame_type_2_str[ conn->imc_conn.cn_pf->pf_parse_frame_type(p, len) ]);
    return 0;
}


static unsigned (*const imico_process_frames[N_QUIC_FRAMES])
                                                (IMICO_PROC_FRAME_ARGS) =
{
    [QUIC_FRAME_PADDING]            =  imico_process_padding_frame,
    [QUIC_FRAME_CRYPTO]             =  imico_process_crypto_frame,
    [QUIC_FRAME_ACK]                =  imico_process_ack_frame,
    [QUIC_FRAME_PING]               =  imico_process_ping_frame,
    [QUIC_FRAME_CONNECTION_CLOSE]   =  imico_process_connection_close_frame,
    /* Some of them are invalid, while others are unexpected.  We treat
     * them the same: handshake cannot proceed.
     */
    [QUIC_FRAME_RST_STREAM]         =  imico_process_invalid_frame,
    [QUIC_FRAME_MAX_DATA]           =  imico_process_invalid_frame,
    [QUIC_FRAME_MAX_STREAM_DATA]    =  imico_process_invalid_frame,
    [QUIC_FRAME_MAX_STREAMS]        =  imico_process_invalid_frame,
    [QUIC_FRAME_BLOCKED]            =  imico_process_invalid_frame,
    [QUIC_FRAME_STREAM_BLOCKED]     =  imico_process_invalid_frame,
    [QUIC_FRAME_STREAMS_BLOCKED]    =  imico_process_invalid_frame,
    [QUIC_FRAME_NEW_CONNECTION_ID]  =  imico_process_invalid_frame,
    [QUIC_FRAME_STOP_SENDING]       =  imico_process_invalid_frame,
    [QUIC_FRAME_PATH_CHALLENGE]     =  imico_process_invalid_frame,
    [QUIC_FRAME_PATH_RESPONSE]      =  imico_process_invalid_frame,
    /* STREAM frame can only come in the App PNS and we delay those packets: */
    [QUIC_FRAME_STREAM]             =  imico_process_invalid_frame,
    [QUIC_FRAME_HANDSHAKE_DONE]     =  imico_process_invalid_frame,
    [QUIC_FRAME_ACK_FREQUENCY]      =  imico_process_invalid_frame,
    [QUIC_FRAME_TIMESTAMP]          =  imico_process_invalid_frame,
};


static unsigned
imico_process_packet_frame (struct ietf_mini_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    enum enc_level enc_level;
    enum quic_frame_type type;

    enc_level = lsquic_packet_in_enc_level(packet_in);
    type = conn->imc_conn.cn_pf->pf_parse_frame_type(p, len);
    if (lsquic_legal_frames_by_level[conn->imc_conn.cn_version][enc_level]
                                                                & (1 << type))
    {
        packet_in->pi_frame_types |= 1 << type;
        return imico_process_frames[type](conn, packet_in, p, len);
    }
    else
    {
        LSQ_DEBUG("invalid frame %u at encryption level %s", type,
                                                lsquic_enclev2str[enc_level]);
        return 0;
    }
}


static int
imico_parse_regular_packet (struct ietf_mini_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    const unsigned char *p, *pend;
    unsigned len;

    p = packet_in->pi_data + packet_in->pi_header_sz;
    pend = packet_in->pi_data + packet_in->pi_data_sz;

    while (p < pend)
    {
        len = imico_process_packet_frame(conn, packet_in, p, pend - p);
        if (len > 0)
            p += len;
        else
            return -1;
    }

    return 0;
}


static unsigned
highest_bit_set (unsigned long long sz)
{
#if __GNUC__
    unsigned clz = __builtin_clzll(sz);
    return 63 - clz;
#else
    unsigned long y;
    unsigned n;
    n = 64;
    y = sz >> 32;     if (y) { n -= 32; sz = y; }
    y = sz >> 16;     if (y) { n -= 16; sz = y; }
    y = sz >>  8;     if (y) { n -=  8; sz = y; }
    y = sz >>  4;     if (y) { n -=  4; sz = y; }
    y = sz >>  2;     if (y) { n -=  2; sz = y; }
    y = sz >>  1;     if (y) return 63 - n + 2;
    return 63 - n + sz;
#endif
}


static void
ignore_init (struct ietf_mini_conn *conn)
{
    struct lsquic_packet_out *packet_out, *next;
    unsigned count;

    conn->imc_flags |= IMC_IGNORE_INIT;
    conn->imc_flags &= ~(IMC_QUEUED_ACK_INIT << PNS_INIT);

    count = 0;
    for (packet_out = TAILQ_FIRST(&conn->imc_packets_out); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (PNS_INIT == lsquic_packet_out_pns(packet_out))
        {
            TAILQ_REMOVE(&conn->imc_packets_out, packet_out, po_next);
            imico_destroy_packet(conn, packet_out);
            ++count;
        }
    }

    LSQ_DEBUG("henceforth, no Initial packets shall be sent or received; "
        "destroyed %u packet%.*s", count, count != 1, "s");
}


static void
imico_maybe_delay_processing (struct ietf_mini_conn *conn,
                                            struct lsquic_packet_in *packet_in)
{
    unsigned max_delayed;

    if (conn->imc_flags & IMC_ADDR_VALIDATED)
        max_delayed = IMICO_MAX_DELAYED_PACKETS_VALIDATED;
    else
        max_delayed = IMICO_MAX_DELAYED_PACKETS_UNVALIDATED;

    if (conn->imc_delayed_packets_count < max_delayed)
    {
        ++conn->imc_delayed_packets_count;
        lsquic_packet_in_upref(packet_in);
        TAILQ_INSERT_TAIL(&conn->imc_app_packets, packet_in, pi_next);
        LSQ_DEBUG("delay processing of packet (now delayed %hhu)",
            conn->imc_delayed_packets_count);
    }
    else
        LSQ_DEBUG("drop packet, already delayed %hhu packets",
                                            conn->imc_delayed_packets_count);
}


/* [draft-ietf-quic-transport-30] Section 8.1:
 " Additionally, a server MAY consider the client address validated if
 " the client uses a connection ID chosen by the server and the
 " connection ID contains at least 64 bits of entropy.
 *
 * We use RAND_bytes() to generate SCIDs, so it's all entropy.
 */
static void
imico_maybe_validate_by_dcid (struct ietf_mini_conn *conn,
                                                    const lsquic_cid_t *dcid)
{
    unsigned i;

    if (dcid->len >= 8)
        /* Generic code with unnecessary loop as future-proofing */
        for (i = 0; i < conn->imc_conn.cn_n_cces; ++i)
            if ((conn->imc_conn.cn_cces_mask & (1 << i))
                && (conn->imc_conn.cn_cces[i].cce_flags & CCE_SEQNO)
                && LSQUIC_CIDS_EQ(&conn->imc_conn.cn_cces[i].cce_cid, dcid))
            {
                imico_peer_addr_validated(conn, "dcid/scid + entropy");
                return;
            }
}


static int
imico_received_packet_is_dup (struct ietf_mini_conn *conn,
                                enum packnum_space pns, lsquic_packno_t packno)
{
    if (conn->imc_flags & IMC_TRECHIST)
        return lsquic_trechist_contains(
            conn->imc_recvd_packnos.trechist.hist_masks[pns],
            conn->imc_recvd_packnos.trechist.hist_elems
                                        + TRECHIST_MAX_RANGES * pns, packno);
    else
        return !!(conn->imc_recvd_packnos.bitmasks[pns] & (1ULL << packno));
}


static int
imico_packno_is_largest (struct ietf_mini_conn *conn,
                                enum packnum_space pns, lsquic_packno_t packno)
{
    if (conn->imc_flags & IMC_TRECHIST)
        return 0 == conn->imc_recvd_packnos.trechist.hist_masks[pns]
            || packno > lsquic_trechist_max(
                        conn->imc_recvd_packnos.trechist.hist_masks[pns],
                        conn->imc_recvd_packnos.trechist.hist_elems
                                            + TRECHIST_MAX_RANGES * pns);
    else
        return 0 == conn->imc_recvd_packnos.bitmasks[pns]
            || packno > highest_bit_set(conn->imc_recvd_packnos.bitmasks[pns]);
}


static void
imico_record_recvd_packno (struct ietf_mini_conn *conn,
                                enum packnum_space pns, lsquic_packno_t packno)
{
    if (conn->imc_flags & IMC_TRECHIST)
    {
        if (0 != lsquic_trechist_insert(
                    &conn->imc_recvd_packnos.trechist.hist_masks[pns],
                    conn->imc_recvd_packnos.trechist.hist_elems
                                        + TRECHIST_MAX_RANGES * pns, packno))
        {
            LSQ_INFO("too many ranges for trechist to hold or range too wide");
            conn->imc_flags |= IMC_ERROR;
        }
    }
    else
        conn->imc_recvd_packnos.bitmasks[pns] |= 1ULL << packno;
}


static int
imico_switch_to_trechist (struct ietf_mini_conn *conn)
{
    uint32_t masks[IMICO_N_PNS];
    enum packnum_space pns;
    struct trechist_elem *elems;
    struct ietf_mini_rechist iter;

    elems = malloc(TRECHIST_SIZE * N_PNS);
    if (!elems)
    {
        LSQ_WARN("cannot allocate trechist elems");
        return -1;
    }

    for (pns = 0; pns < IMICO_N_PNS; ++pns)
        if (conn->imc_recvd_packnos.bitmasks[pns])
        {
            lsquic_imico_rechist_init(&iter, conn, pns);
            lsquic_trechist_copy_ranges(&masks[pns],
                                elems + TRECHIST_MAX_RANGES * pns, &iter,
                                lsquic_imico_rechist_first,
                                lsquic_imico_rechist_next);
        }
        else
            masks[pns] = 0;

    memcpy(conn->imc_recvd_packnos.trechist.hist_masks, masks, sizeof(masks));
    conn->imc_recvd_packnos.trechist.hist_elems = elems;
    conn->imc_flags |= IMC_TRECHIST;
    LSQ_DEBUG("switched to trechist");
    return 0;
}


/* Only a single packet is supported */
static void
ietf_mini_conn_ci_packet_in (struct lsquic_conn *lconn,
                        struct lsquic_packet_in *packet_in)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    enum dec_packin dec_packin;
    enum packnum_space pns;

    /* Update "bytes in" count as early as possible.  From
     * [draft-ietf-quic-transport-28] Section 8.1:
     "                                                 For the purposes of
     " avoiding amplification prior to address validation, servers MUST
     " count all of the payload bytes received in datagrams that are
     " uniquely attributed to a single connection.  This includes datagrams
     " that contain packets that are successfully processed and datagrams
     " that contain packets that are all discarded.
     */
    conn->imc_bytes_in += packet_in->pi_data_sz;

    if (conn->imc_flags & IMC_ERROR)
    {
        LSQ_DEBUG("ignore incoming packet: connection is in error state");
        return;
    }

    if (!(conn->imc_flags & IMC_ADDR_VALIDATED))
        imico_maybe_validate_by_dcid(conn, &packet_in->pi_dcid);

    pns = lsquic_hety2pns[ packet_in->pi_header_type ];
    if (pns == PNS_INIT && (conn->imc_flags & IMC_IGNORE_INIT))
    {
        LSQ_DEBUG("ignore init packet");    /* Don't bother decrypting */
        return;
    }

    dec_packin = lconn->cn_esf_c->esf_decrypt_packet(lconn->cn_enc_session,
                                conn->imc_enpub, &conn->imc_conn, packet_in);
    switch (dec_packin)
    {
    case DECPI_OK:
        break;
    case DECPI_VIOLATION:
        ietf_mini_conn_ci_abort_error(lconn, 0, TEC_PROTOCOL_VIOLATION,
                    "protocol violation detected while decrypting packet");
        return;
    case DECPI_NOT_YET:
        imico_maybe_delay_processing(conn, packet_in);
        return;
    default:
        LSQ_DEBUG("could not decrypt packet");
        return;
    }

    EV_LOG_PACKET_IN(LSQUIC_LOG_CONN_ID, packet_in);

    if (pns == PNS_APP)
    {
        imico_maybe_delay_processing(conn, packet_in);
        return;
    }
    else if (pns == PNS_HSK)
        imico_peer_addr_validated(conn, "handshake PNS");

    if (((conn->imc_flags >> IMCBIT_PNS_BIT_SHIFT) & 3) < pns)
    {
        conn->imc_flags &= ~(3 << IMCBIT_PNS_BIT_SHIFT);
        conn->imc_flags |= pns << IMCBIT_PNS_BIT_SHIFT;
    }

    if (pns == PNS_HSK && !(conn->imc_flags & IMC_IGNORE_INIT))
        ignore_init(conn);

    if (packet_in->pi_packno > MAX_PACKETS
                                    && !(conn->imc_flags & IMC_TRECHIST))
    {
        if (0 != imico_switch_to_trechist(conn))
            return;
    }

    if (imico_received_packet_is_dup(conn, pns, packet_in->pi_packno))
    {
        LSQ_DEBUG("duplicate packet %"PRIu64, packet_in->pi_packno);
        return;
    }

    /* Update receive history before processing the packet: if there is an
     * error, the connection is terminated and recording this packet number
     * is helpful when it is printed along with other diagnostics in dtor.
     */
    if (imico_packno_is_largest(conn, pns, packet_in->pi_packno))
        conn->imc_largest_recvd[pns] = packet_in->pi_received;
    imico_record_recvd_packno(conn, pns, packet_in->pi_packno);

    if (0 != imico_parse_regular_packet(conn, packet_in))
    {
        LSQ_DEBUG("connection is now in error state");
        conn->imc_flags |= IMC_ERROR;
        return;
    }

    if (!(conn->imc_flags & (IMC_QUEUED_ACK_INIT << pns)))
        LSQ_DEBUG("queued ACK in %s", lsquic_pns2str[pns]);
    conn->imc_flags |= IMC_QUEUED_ACK_INIT << pns;
    ++conn->imc_ecn_counts_in[pns][ lsquic_packet_in_ecn(packet_in) ];
    conn->imc_incoming_ecn <<= 1;
    conn->imc_incoming_ecn |= lsquic_packet_in_ecn(packet_in) != ECN_NOT_ECT;
}


static void
ietf_mini_conn_ci_packet_sent (struct lsquic_conn *lconn,
                              struct lsquic_packet_out *packet_out)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    conn->imc_sent_packnos |= 1ULL << packet_out->po_packno;
    conn->imc_ecn_packnos |= !!lsquic_packet_out_ecn(packet_out)
                                                    << packet_out->po_packno;
#if 0
    if (packet_out->po_frame_types & (1 << QUIC_FRAME_ACK))
    {
        assert(mc->mc_flags & MC_UNSENT_ACK);
        mc->mc_flags &= ~MC_UNSENT_ACK;
    }
#endif
    if (packet_out->po_header_type == HETY_HANDSHAKE)
        conn->imc_flags |= IMC_HSK_PACKET_SENT;
    LSQ_DEBUG("%s: packet %"PRIu64" sent", __func__, packet_out->po_packno);
}


static void
ietf_mini_conn_ci_packet_not_sent (struct lsquic_conn *lconn,
                              struct lsquic_packet_out *packet_out)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    size_t packet_size;

    packet_out->po_flags &= ~PO_SENT;
    packet_size = lsquic_packet_out_total_sz(lconn, packet_out);
    conn->imc_bytes_out -= packet_size;
    LSQ_DEBUG("%s: packet %"PRIu64" not sent", __func__, packet_out->po_packno);
}


static void
imico_return_enc_data (struct ietf_mini_conn *conn,
                                        struct lsquic_packet_out *packet_out)
{
    conn->imc_enpub->enp_pmi->pmi_return(conn->imc_enpub->enp_pmi_ctx,
        conn->imc_path.np_peer_ctx, packet_out->po_enc_data,
        lsquic_packet_out_ipv6(packet_out));
    packet_out->po_flags &= ~PO_ENCRYPTED;
    packet_out->po_enc_data = NULL;
}


static int
imico_repackage_packet (struct ietf_mini_conn *conn,
                                        struct lsquic_packet_out *packet_out)
{
    const lsquic_packno_t oldno = packet_out->po_packno;
    const lsquic_packno_t packno = conn->imc_next_packno++;
    if (packno > MAX_PACKETS)
        return -1;

    LSQ_DEBUG("Packet %"PRIu64" repackaged for resending as packet %"PRIu64,
                                                        oldno, packno);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "packet %"PRIu64" repackaged for "
        "resending as packet %"PRIu64, oldno, packno);
    packet_out->po_packno = packno;
    packet_out->po_flags &= ~PO_SENT;
    lsquic_packet_out_set_ecn(packet_out, imico_get_ecn(conn));
    if (packet_out->po_flags & PO_ENCRYPTED)
        imico_return_enc_data(conn, packet_out);
    TAILQ_INSERT_TAIL(&conn->imc_packets_out, packet_out, po_next);
    return 0;
}


static int
imico_handle_losses_and_have_unsent (struct ietf_mini_conn *conn,
                                                            lsquic_time_t now)
{
    TAILQ_HEAD(, lsquic_packet_out) lost_packets =
                                    TAILQ_HEAD_INITIALIZER(lost_packets);
    const struct lsquic_conn *const lconn = &conn->imc_conn;
    lsquic_packet_out_t *packet_out, *next;
    lsquic_time_t retx_to = 0;
    unsigned n_to_send = 0;
    size_t packet_size;

    for (packet_out = TAILQ_FIRST(&conn->imc_packets_out); packet_out;
                                                        packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (packet_out->po_flags & PO_SENT)
        {
            if (0 == retx_to)
                retx_to = imico_calc_retx_timeout(conn);
            if (packet_out->po_sent + retx_to < now)
            {
                LSQ_DEBUG("packet %"PRIu64" has been lost (rto: %"PRIu64")",
                                                packet_out->po_packno, retx_to);
                TAILQ_REMOVE(&conn->imc_packets_out, packet_out, po_next);
                TAILQ_INSERT_TAIL(&lost_packets, packet_out, po_next);
            }
        }
        else if (packet_size = lsquic_packet_out_total_sz(lconn, packet_out),
                                                imico_can_send(conn, packet_size))
            ++n_to_send;
        else
            break;
    }

    conn->imc_hsk_count += !TAILQ_EMPTY(&lost_packets);

    while ((packet_out = TAILQ_FIRST(&lost_packets)))
    {
        TAILQ_REMOVE(&lost_packets, packet_out, po_next);
        if ((packet_out->po_frame_types & IQUIC_FRAME_RETX_MASK)
                            && 0 == imico_repackage_packet(conn, packet_out))
        {
            packet_size = lsquic_packet_out_total_sz(lconn, packet_out);
            if (imico_can_send(conn, packet_size))
                ++n_to_send;
        }
        else
            imico_destroy_packet(conn, packet_out);
    }

    return n_to_send > 0;
}


static int
imico_have_packets_to_send (struct ietf_mini_conn *conn, lsquic_time_t now)
{
    return imico_handle_losses_and_have_unsent(conn, now);
}


void
lsquic_imico_rechist_init (struct ietf_mini_rechist *rechist,
                    const struct ietf_mini_conn *conn, enum packnum_space pns)
{
    assert(pns < IMICO_N_PNS);
    rechist->conn = conn;
    rechist->pns  = pns;
    if (conn->imc_flags & IMC_TRECHIST)
        lsquic_trechist_iter(&rechist->u.trechist_iter,
            conn->imc_recvd_packnos.trechist.hist_masks[pns],
            conn->imc_recvd_packnos.trechist.hist_elems + TRECHIST_MAX_RANGES * pns);
    else
    {
        rechist->u.bitmask.cur_set = 0;
        rechist->u.bitmask.cur_idx = 0;
    }
}


static lsquic_time_t
imico_rechist_largest_recv (void *rechist_ctx)
{
    struct ietf_mini_rechist *rechist = rechist_ctx;
    return rechist->conn->imc_largest_recvd[ rechist->pns ];
}


static const struct lsquic_packno_range *
imico_bitmask_rechist_next (struct ietf_mini_rechist *rechist)
{
    const struct ietf_mini_conn *conn = rechist->conn;
    packno_set_t packnos;
    int i;

    packnos = rechist->u.bitmask.cur_set;
    if (0 == packnos)
        return NULL;

    /* There may be a faster way to do this, but for now, we just want
     * correctness.
     */
    for (i = rechist->u.bitmask.cur_idx; i >= 0; --i)
        if (packnos & (1ULL << i))
        {
            rechist->u.bitmask.range.low  = i;
            rechist->u.bitmask.range.high = i;
            break;
        }
    assert(i >= 0); /* We must have hit at least one bit */
    --i;
    for ( ; i >= 0 && (packnos & (1ULL << i)); --i)
        rechist->u.bitmask.range.low = i;
    if (i >= 0)
    {
        rechist->u.bitmask.cur_set = packnos & ((1ULL << i) - 1);
        rechist->u.bitmask.cur_idx = i;
    }
    else
        rechist->u.bitmask.cur_set = 0;
    LSQ_DEBUG("%s: return [%"PRIu64", %"PRIu64"]", __func__,
                rechist->u.bitmask.range.low, rechist->u.bitmask.range.high);
    return &rechist->u.bitmask.range;
}


const struct lsquic_packno_range *
lsquic_imico_rechist_next (void *rechist_ctx)
{
    struct ietf_mini_rechist *rechist = rechist_ctx;

    if (rechist->conn->imc_flags & IMC_TRECHIST)
        return lsquic_trechist_next(&rechist->u.trechist_iter);
    else
        return imico_bitmask_rechist_next(rechist);
}


const struct lsquic_packno_range *
lsquic_imico_rechist_first (void *rechist_ctx)
{
    struct ietf_mini_rechist *rechist = rechist_ctx;

    if (rechist->conn->imc_flags & IMC_TRECHIST)
        return lsquic_trechist_first(&rechist->u.trechist_iter);
    else
    {
        rechist->u.bitmask.cur_set
                = rechist->conn->imc_recvd_packnos.bitmasks[ rechist->pns ];
        rechist->u.bitmask.cur_idx
                = highest_bit_set(rechist->u.bitmask.cur_set);
        return lsquic_imico_rechist_next(rechist_ctx);
    }
}


static const enum header_type pns2hety[] =
{
    [PNS_INIT]  = HETY_INITIAL,
    [PNS_HSK]   = HETY_HANDSHAKE,
    [PNS_APP]   = HETY_NOT_SET,
};


static int
imico_generate_ack (struct ietf_mini_conn *conn, enum packnum_space pns,
                                                            lsquic_time_t now)
{
    struct lsquic_packet_out *packet_out;
    enum header_type header_type;
    struct ietf_mini_rechist rechist;
    int not_used_has_missing, len;
    uint64_t ecn_counts_buf[4];
    const uint64_t *ecn_counts;

    header_type = pns2hety[pns];

    if (conn->imc_incoming_ecn)
    {
        ecn_counts_buf[0]   = conn->imc_ecn_counts_in[pns][0];
        ecn_counts_buf[1]   = conn->imc_ecn_counts_in[pns][1];
        ecn_counts_buf[2]   = conn->imc_ecn_counts_in[pns][2];
        ecn_counts_buf[3]   = conn->imc_ecn_counts_in[pns][3];
        ecn_counts = ecn_counts_buf;
    }
    else
        ecn_counts = NULL;

    packet_out = imico_get_packet_out(conn, header_type, 0);
    if (!packet_out)
        return -1;

    /* Generate ACK frame */
    lsquic_imico_rechist_init(&rechist, conn, pns);
    len = conn->imc_conn.cn_pf->pf_gen_ack_frame(
                packet_out->po_data + packet_out->po_data_sz,
                lsquic_packet_out_avail(packet_out), lsquic_imico_rechist_first,
                lsquic_imico_rechist_next, imico_rechist_largest_recv, &rechist,
                now, &not_used_has_missing, &packet_out->po_ack2ed, ecn_counts);
    if (len < 0)
    {
        LSQ_WARN("could not generate ACK frame");
        return -1;
    }
    EV_LOG_GENERATED_ACK_FRAME(LSQUIC_LOG_CONN_ID, conn->imc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, len);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_ACK;
    packet_out->po_data_sz += len;
    packet_out->po_regen_sz += len;
    conn->imc_flags &= ~(IMC_QUEUED_ACK_INIT << pns);
    LSQ_DEBUG("wrote ACK frame of size %d in %s", len, lsquic_pns2str[pns]);
    return 0;
}


static int
imico_generate_acks (struct ietf_mini_conn *conn, lsquic_time_t now)
{
    enum packnum_space pns;

    for (pns = PNS_INIT; pns < IMICO_N_PNS; ++pns)
        if (conn->imc_flags & (IMC_QUEUED_ACK_INIT << pns)
                && !(pns == PNS_INIT && (conn->imc_flags & IMC_IGNORE_INIT)))
            if (0 != imico_generate_ack(conn, pns, now))
                return -1;

    return 0;
}


static void
imico_generate_conn_close (struct ietf_mini_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    enum header_type header_type;
    enum packnum_space pns, pns_max;
    unsigned error_code;
    const char *reason;
    size_t need;
    int sz, rlen, is_app;
    char reason_buf[0x20];

    if (conn->imc_flags & IMC_ABORT_ERROR)
    {
        is_app = !!(conn->imc_flags & IMC_ABORT_ISAPP);
        error_code = conn->imc_error_code;
        reason = NULL;
        rlen = 0;
    }
    else if (conn->imc_flags & IMC_TLS_ALERT)
    {
        is_app = 0;
        error_code = 0x100 + conn->imc_tls_alert;
        if (ALERT_NO_APPLICATION_PROTOCOL == conn->imc_tls_alert)
            reason = "no suitable application protocol";
        else
        {
            snprintf(reason_buf, sizeof(reason_buf), "TLS alert %"PRIu8,
                                                        conn->imc_tls_alert);
            reason = reason_buf;
        }
        rlen = strlen(reason);
    }
    else if (conn->imc_flags & IMC_BAD_TRANS_PARAMS)
    {
        is_app = 0;
        error_code = TEC_TRANSPORT_PARAMETER_ERROR;
        reason = "bad transport parameters";
        rlen = 24;
    }
    else if (conn->imc_flags & IMC_HSK_FAILED)
    {
        is_app = 0;
        error_code = TEC_NO_ERROR;
        reason = "handshake failed";
        rlen = 16;
    }
    else if (conn->imc_flags & IMC_PARSE_FAILED)
    {
        is_app = 0;
        error_code = TEC_FRAME_ENCODING_ERROR;
        reason = "cannot decode frame";
        rlen = 19;
    }
    else
    {
        is_app = 0;
        error_code = TEC_INTERNAL_ERROR;
        reason = NULL;
        rlen = 0;
    }


/* [draft-ietf-quic-transport-28] Section 10.3.1:
 *
 " A client will always know whether the server has Handshake keys (see
 " Section 17.2.2.1), but it is possible that a server does not know
 " whether the client has Handshake keys.  Under these circumstances, a
 " server SHOULD send a CONNECTION_CLOSE frame in both Handshake and
 " Initial packets to ensure that at least one of them is processable by
 " the client.
--- 8< ---
 " Sending a CONNECTION_CLOSE of type 0x1d in an Initial or Handshake
 " packet could expose application state or be used to alter application
 " state.  A CONNECTION_CLOSE of type 0x1d MUST be replaced by a
 " CONNECTION_CLOSE of type 0x1c when sending the frame in Initial or
 " Handshake packets.  Otherwise, information about the application
 " state might be revealed.  Endpoints MUST clear the value of the
 " Reason Phrase field and SHOULD use the APPLICATION_ERROR code when
 " converting to a CONNECTION_CLOSE of type 0x1c.
 */
    LSQ_DEBUG("sending CONNECTION_CLOSE, is_app: %d, error code: %u, "
        "reason: %.*s", is_app, error_code, rlen, reason);
    if (is_app && conn->imc_conn.cn_version > LSQVER_ID27)
    {
        LSQ_DEBUG("convert to 0x1C, replace code and reason");
        is_app = 0;
        error_code = TEC_APPLICATION_ERROR;
        rlen = 0;
    }

    pns = (conn->imc_flags >> IMCBIT_PNS_BIT_SHIFT) & 3;
    switch ((!!(conn->imc_flags & IMC_HSK_PACKET_SENT) << 1)
                | (pns == PNS_HSK) /* Handshake packet received */)
    {
    case (0 << 1) | 0:
        pns = PNS_INIT;
        pns_max = PNS_INIT;
        break;
    case (1 << 1) | 0:
        pns = PNS_INIT;
        pns_max = PNS_HSK;
        break;
    default:
        pns = PNS_HSK;
        pns_max = PNS_HSK;
        break;
    }

    need = conn->imc_conn.cn_pf->pf_connect_close_frame_size(is_app,
                                                        error_code, 0, rlen);
    LSQ_DEBUG("will generate %u CONNECTION_CLOSE frame%.*s",
        pns_max - pns + 1, pns_max > pns, "s");
    do
    {
        header_type = pns2hety[pns];
        packet_out = imico_get_packet_out(conn, header_type, need);
        if (!packet_out)
            return;
        sz = conn->imc_conn.cn_pf->pf_gen_connect_close_frame(
                 packet_out->po_data + packet_out->po_data_sz,
                 lsquic_packet_out_avail(packet_out), is_app, error_code, reason,
                 rlen);
        if (sz >= 0)
        {
            packet_out->po_frame_types |= 1 << QUIC_FRAME_CONNECTION_CLOSE;
            packet_out->po_data_sz += sz;
            LSQ_DEBUG("generated CONNECTION_CLOSE frame");
        }
        else
            LSQ_WARN("could not generate CONNECTION_CLOSE frame");
        ++pns;
    }
    while (pns <= pns_max);
}


static int
imico_generate_handshake_done (struct ietf_mini_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    unsigned need;
    int sz;

    need = conn->imc_conn.cn_pf->pf_handshake_done_frame_size();
    packet_out = imico_get_packet_out(conn, HETY_NOT_SET, need);
    if (!packet_out)
        return -1;
    sz = conn->imc_conn.cn_pf->pf_gen_handshake_done_frame(
                 packet_out->po_data + packet_out->po_data_sz,
                 lsquic_packet_out_avail(packet_out));
    if (sz < 0)
    {
        LSQ_WARN("could not generate HANDSHAKE_DONE frame");
        return -1;
    }

    packet_out->po_frame_types |= 1 << QUIC_FRAME_HANDSHAKE_DONE;
    packet_out->po_data_sz += sz;
    LSQ_DEBUG("generated HANDSHAKE_DONE frame");
    conn->imc_flags |= IMC_HSK_DONE_SENT;

    return 0;
}


static enum tick_st
ietf_mini_conn_ci_tick (struct lsquic_conn *lconn, lsquic_time_t now)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    enum tick_st tick;

    if (conn->imc_created + conn->imc_enpub->enp_settings.es_handshake_to < now)
    {
        LSQ_DEBUG("connection expired: closing");
        return TICK_CLOSE;
    }


    if (conn->imc_flags & (IMC_QUEUED_ACK_INIT|IMC_QUEUED_ACK_HSK))
    {
        if (0 != imico_generate_acks(conn, now))
        {
            conn->imc_flags |= IMC_ERROR;
            return TICK_CLOSE;
        }
    }


    tick = 0;

    if (conn->imc_flags & IMC_ERROR)
    {
  close_on_error:
        if (!(conn->imc_flags & IMC_CLOSE_RECVD))
            imico_generate_conn_close(conn);
        tick |= TICK_CLOSE;
    }
    else if (conn->imc_flags & IMC_HSK_OK)
    {
        if (lconn->cn_esf.i->esfi_in_init(lconn->cn_enc_session))
            LSQ_DEBUG("still in init, defer HANDSHAKE_DONE");
        else if (0 != imico_generate_handshake_done(conn))
            goto close_on_error;
        tick |= TICK_PROMOTE;
    }

    if (imico_have_packets_to_send(conn, now))
        tick |= TICK_SEND;
    else
        tick |= TICK_QUIET;

    LSQ_DEBUG("Return TICK %d", tick);
    return tick;
}


static void
ietf_mini_conn_ci_internal_error (struct lsquic_conn *lconn,
                                                    const char *format, ...)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    LSQ_INFO("internal error reported");
    conn->imc_flags |= IMC_ERROR;
}


static void
ietf_mini_conn_ci_abort_error (struct lsquic_conn *lconn, int is_app,
                                unsigned error_code, const char *fmt, ...)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    va_list ap;
    const char *err_str, *percent;
    char err_buf[0x100];

    percent = strchr(fmt, '%');
    if (percent)
    {
        va_start(ap, fmt);
        vsnprintf(err_buf, sizeof(err_buf), fmt, ap);
        va_end(ap);
        err_str = err_buf;
    }
    else
        err_str = fmt;
    LSQ_INFO("abort error: is_app: %d; error code: %u; error str: %s",
        is_app, error_code, err_str);
    conn->imc_flags |= IMC_ERROR|IMC_ABORT_ERROR;
    if (is_app)
        conn->imc_flags |= IMC_ABORT_ISAPP;
    conn->imc_error_code = error_code;
}


static struct network_path *
ietf_mini_conn_ci_get_path (struct lsquic_conn *lconn,
                                                    const struct sockaddr *sa)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;

    return &conn->imc_path;
}


static const lsquic_cid_t *
ietf_mini_conn_ci_get_log_cid (const struct lsquic_conn *lconn)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;

    if (conn->imc_path.np_dcid.len)
        return &conn->imc_path.np_dcid;
    else
        return CN_SCID(lconn);
}


static unsigned char
ietf_mini_conn_ci_record_addrs (struct lsquic_conn *lconn, void *peer_ctx,
            const struct sockaddr *local_sa, const struct sockaddr *peer_sa)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;
    const struct sockaddr *orig_peer_sa;
    struct lsquic_packet_out *packet_out;
    size_t len;
    char path_str[4][INET6_ADDRSTRLEN + sizeof(":65535")];

    if (NP_IS_IPv6(&conn->imc_path) != (AF_INET6 == peer_sa->sa_family))
        TAILQ_FOREACH(packet_out, &conn->imc_packets_out, po_next)
            if ((packet_out->po_flags & (PO_SENT|PO_ENCRYPTED)) == PO_ENCRYPTED)
                imico_return_enc_data(conn, packet_out);

    orig_peer_sa = NP_PEER_SA(&conn->imc_path);
    if (orig_peer_sa->sa_family == 0)
        LSQ_DEBUG("connection to %s from %s", SA2STR(local_sa, path_str[0]),
                                                SA2STR(peer_sa, path_str[1]));
    else if (!(lsquic_sockaddr_eq(NP_PEER_SA(&conn->imc_path), peer_sa)
              && lsquic_sockaddr_eq(NP_LOCAL_SA(&conn->imc_path), local_sa)))
    {
        LSQ_DEBUG("path changed from (%s - %s) to (%s - %s)",
            SA2STR(NP_LOCAL_SA(&conn->imc_path), path_str[0]),
            SA2STR(NP_PEER_SA(&conn->imc_path), path_str[1]),
            SA2STR(local_sa, path_str[2]),
            SA2STR(peer_sa, path_str[3]));
        conn->imc_flags |= IMC_PATH_CHANGED;
    }

    len = local_sa->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                                : sizeof(struct sockaddr_in6);

    memcpy(conn->imc_path.np_peer_addr, peer_sa, len);
    memcpy(conn->imc_path.np_local_addr, local_sa, len);
    conn->imc_path.np_peer_ctx = peer_ctx;
    return 0;
}


void
ietf_mini_conn_ci_count_garbage (struct lsquic_conn *lconn, size_t garbage_sz)
{
    struct ietf_mini_conn *conn = (struct ietf_mini_conn *) lconn;

    conn->imc_bytes_in += garbage_sz;
    LSQ_DEBUG("count %zd bytes of garbage, new value: %u bytes", garbage_sz,
        conn->imc_bytes_in);
}


static const struct conn_iface mini_conn_ietf_iface = {
    .ci_abort_error          =  ietf_mini_conn_ci_abort_error,
    .ci_client_call_on_new   =  ietf_mini_conn_ci_client_call_on_new,
    .ci_count_garbage        =  ietf_mini_conn_ci_count_garbage,
    .ci_destroy              =  ietf_mini_conn_ci_destroy,
    .ci_get_engine           =  ietf_mini_conn_ci_get_engine,
    .ci_get_log_cid          =  ietf_mini_conn_ci_get_log_cid,
    .ci_get_path             =  ietf_mini_conn_ci_get_path,
    .ci_hsk_done             =  ietf_mini_conn_ci_hsk_done,
    .ci_internal_error       =  ietf_mini_conn_ci_internal_error,
    .ci_is_tickable          =  ietf_mini_conn_ci_is_tickable,
    .ci_next_packet_to_send  =  ietf_mini_conn_ci_next_packet_to_send,
    .ci_next_tick_time       =  ietf_mini_conn_ci_next_tick_time,
    .ci_packet_in            =  ietf_mini_conn_ci_packet_in,
    .ci_packet_not_sent      =  ietf_mini_conn_ci_packet_not_sent,
    .ci_packet_sent          =  ietf_mini_conn_ci_packet_sent,
    .ci_record_addrs         =  ietf_mini_conn_ci_record_addrs,
    .ci_tick                 =  ietf_mini_conn_ci_tick,
    .ci_tls_alert            =  ietf_mini_conn_ci_tls_alert,
};
