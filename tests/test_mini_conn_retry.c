/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Test that a mini connection does not Retry a ClientHello in progress */

#undef LSQUIC_TEST

#include <assert.h>
#include <string.h>
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_mm.h"
#include "lsquic_hash.h"
#include "lsquic_engine_public.h"
#include "lsquic_trechist.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_packet_common.h"
#include "lsquic_rtt.h"
#include "lsquic_mini_conn_ietf.h"
#include "lsquic_crand.h"
#include "lsquic_ev_log.h"
#include "lsquic_packet_in.h"
#include "lsquic_version.h"


#define RECEIVED 1234567890


struct test_ctx
{
    struct lsquic_engine_public  tc_enpub;
    struct crand                 tc_crand;
    unsigned char                tc_data[1200];
};


static void
generate_scid (void *UNUSED_ctx, struct lsquic_conn *UNUSED_conn,
                                            uint8_t *scid, unsigned len)
{
    memset(scid, 0xCC, len);
}


/* A server mini connection created by a tokenless Initial packet: its
 * peer's address is not validated.
 */
static struct ietf_mini_conn *
new_mini_conn (struct test_ctx *ctx)
{
    lsquic_cid_t dcid = { .len = 8, .idbuf = { 1, 2, 3, 4, 5, 6, 7, 8, }, };
    struct lsquic_packet_in *packet_in;
    struct lsquic_conn *conn;
    struct ietf_mini_conn *mini_conn;

    memset(ctx, 0, sizeof(*ctx));
    lsquic_mm_init(&ctx->tc_enpub.enp_mm);
    lsquic_engine_init_settings(&ctx->tc_enpub.enp_settings, LSENG_SERVER);
    ctx->tc_enpub.enp_settings.es_ecn = 0;
    ctx->tc_enpub.enp_generate_scid = generate_scid;
    ctx->tc_enpub.enp_crand = &ctx->tc_crand;

    packet_in = lsquic_mm_get_packet_in(&ctx->tc_enpub.enp_mm);
    packet_in->pi_data = ctx->tc_data;
    packet_in->pi_data_sz = sizeof(ctx->tc_data);
    packet_in->pi_header_type = HETY_INITIAL;
    packet_in->pi_dcid = dcid;
    packet_in->pi_received = RECEIVED;

    conn = lsquic_mini_conn_ietf_new(&ctx->tc_enpub, packet_in, LSQVER_I001,
                                    1, NULL, sizeof(ctx->tc_data));
    assert(conn);
    lsquic_mm_put_packet_in(&ctx->tc_enpub.enp_mm, packet_in);
    mini_conn = (struct ietf_mini_conn *) conn;
    assert(!(mini_conn->imc_flags & IMC_ADDR_VALIDATED));

    /* Model the pending ACK for the first received Initial packet. */
    if (mini_conn->imc_flags & IMC_TRECHIST)
        assert(0 == lsquic_trechist_insert(
                    &mini_conn->imc_recvd_packnos.trechist.hist_masks[PNS_INIT],
                    mini_conn->imc_recvd_packnos.trechist.hist_elems, 0));
    else
        mini_conn->imc_recvd_packnos.bitmasks[PNS_INIT] = 1;
    mini_conn->imc_flags |= IMC_QUEUED_ACK_INIT;
    mini_conn->imc_largest_recvd[PNS_INIT] = RECEIVED;
    mini_conn->imc_bytes_in = sizeof(ctx->tc_data);
    return mini_conn;
}


static enum tick_st
tick (struct ietf_mini_conn *conn)
{
    return conn->imc_conn.cn_if->ci_tick(&conn->imc_conn, RECEIVED + 1000);
}


static void
destroy (struct test_ctx *ctx, struct ietf_mini_conn *conn)
{
    conn->imc_conn.cn_if->ci_destroy(&conn->imc_conn);
    lsquic_mm_cleanup(&ctx->tc_enpub.enp_mm);
}


/* No ClientHello has arrived: Retry, as before */
static void
test_no_chlo (void)
{
    struct test_ctx ctx;
    struct ietf_mini_conn *conn;

    conn = new_mini_conn(&ctx);
    assert(tick(conn) & TICK_RETRY);
    destroy(&ctx, conn);
}


/* The first of the ClientHello's packets has been read, and we know from
 * its length that more is due: wait for it, and send nothing meanwhile.
 */
static void
test_chlo_partly_read (int srej)
{
    static const unsigned read_offsets[] = { 1100, 1700, 1701, 1702, 1703, };
    struct test_ctx ctx;
    struct ietf_mini_conn *conn;
    enum tick_st tick_st;
    unsigned i;

    conn = new_mini_conn(&ctx);
    ctx.tc_enpub.enp_settings.es_support_srej = srej;
    conn->imc_ch_len = 1700;
    for (i = 0; i < sizeof(read_offsets) / sizeof(read_offsets[0]); ++i)
    {
        conn->imc_streams[ENC_LEV_INIT].mcs_read_off = read_offsets[i];
        tick_st = tick(conn);
        assert(!(tick_st & (TICK_RETRY|TICK_CLOSE|TICK_SEND)));
        assert(conn->imc_flags & IMC_QUEUED_ACK_INIT);
        assert(TAILQ_EMPTY(&conn->imc_packets_out));
    }

    /* The remaining bytes and transport parameters arrive on a later tick. */
    conn->imc_streams[ENC_LEV_INIT].mcs_read_off = 1704;
    conn->imc_flags |= IMC_HAVE_TP;
    tick_st = tick(conn);
    assert(tick_st & TICK_SEND);
    assert(!(tick_st & (TICK_RETRY|TICK_CLOSE)));
    assert(!(conn->imc_flags & IMC_QUEUED_ACK_INIT));
    destroy(&ctx, conn);
}


/* A later piece of the ClientHello arrived first and is stashed: wait */
static void
test_chlo_stashed (int srej)
{
    struct test_ctx ctx;
    struct ietf_mini_conn *conn;
    struct stream_frame frame;
    enum tick_st tick_st;

    conn = new_mini_conn(&ctx);
    ctx.tc_enpub.enp_settings.es_support_srej = srej;
    memset(&frame, 0, sizeof(frame));
    TAILQ_INSERT_TAIL(&conn->imc_crypto_frames, &frame, next_frame);
    tick_st = tick(conn);
    assert(!(tick_st & (TICK_RETRY|TICK_CLOSE|TICK_SEND)));
    assert(conn->imc_flags & IMC_QUEUED_ACK_INIT);
    assert(TAILQ_EMPTY(&conn->imc_packets_out));
    TAILQ_REMOVE(&conn->imc_crypto_frames, &frame, next_frame);

    conn->imc_ch_len = 1700;
    conn->imc_streams[ENC_LEV_INIT].mcs_read_off = 1704;
    conn->imc_flags |= IMC_HAVE_TP;
    tick_st = tick(conn);
    assert(tick_st & TICK_SEND);
    assert(!(tick_st & (TICK_RETRY|TICK_CLOSE)));
    destroy(&ctx, conn);
}


/* With stateless retries off, there is no Retry in any case */
static void
test_srej_off (void)
{
    struct test_ctx ctx;
    struct ietf_mini_conn *conn;
    enum tick_st tick_st;

    conn = new_mini_conn(&ctx);
    ctx.tc_enpub.enp_settings.es_support_srej = 0;
    tick_st = tick(conn);
    assert(tick_st & TICK_SEND);
    assert(!(tick_st & (TICK_RETRY|TICK_CLOSE)));
    destroy(&ctx, conn);
}


int
main (void)
{
    int srej;

    test_no_chlo();
    for (srej = 0; srej <= 1; ++srej)
    {
        test_chlo_partly_read(srej);
        test_chlo_stashed(srej);
    }
    test_srej_off();
    return 0;
}
