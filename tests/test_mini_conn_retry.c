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
    assert(!(((struct ietf_mini_conn *) conn)->imc_flags & IMC_ADDR_VALIDATED));
    return (struct ietf_mini_conn *) conn;
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
test_chlo_partly_read (void)
{
    struct test_ctx ctx;
    struct ietf_mini_conn *conn;
    enum tick_st tick_st;

    conn = new_mini_conn(&ctx);
    conn->imc_streams[ENC_LEV_INIT].mcs_read_off = 1100;
    conn->imc_ch_len = 1700;
    tick_st = tick(conn);
    assert(!(tick_st & (TICK_RETRY|TICK_CLOSE|TICK_SEND)));
    destroy(&ctx, conn);
}


/* Only the end of the ClientHello is missing: wait.  imc_ch_len does not
 * count the four-byte handshake header.
 */
static void
test_chlo_end_missing (void)
{
    struct test_ctx ctx;
    struct ietf_mini_conn *conn;
    enum tick_st tick_st;
    unsigned missing;

    for (missing = 1; missing <= 4; ++missing)
    {
        conn = new_mini_conn(&ctx);
        conn->imc_streams[ENC_LEV_INIT].mcs_read_off = 1704 - missing;
        conn->imc_ch_len = 1700;
        tick_st = tick(conn);
        assert(!(tick_st & (TICK_RETRY|TICK_CLOSE|TICK_SEND)));
        destroy(&ctx, conn);
    }

    /* All of it read, but no transport parameters: Retry, as before */
    conn = new_mini_conn(&ctx);
    conn->imc_streams[ENC_LEV_INIT].mcs_read_off = 1704;
    conn->imc_ch_len = 1700;
    assert(tick(conn) & TICK_RETRY);
    destroy(&ctx, conn);
}


/* A later piece of the ClientHello arrived first and is stashed: wait */
static void
test_chlo_stashed (void)
{
    struct test_ctx ctx;
    struct ietf_mini_conn *conn;
    struct stream_frame frame;
    enum tick_st tick_st;

    conn = new_mini_conn(&ctx);
    memset(&frame, 0, sizeof(frame));
    TAILQ_INSERT_TAIL(&conn->imc_crypto_frames, &frame, next_frame);
    tick_st = tick(conn);
    assert(!(tick_st & (TICK_RETRY|TICK_CLOSE|TICK_SEND)));
    TAILQ_REMOVE(&conn->imc_crypto_frames, &frame, next_frame);
    destroy(&ctx, conn);
}


/* With stateless retries off, there is no Retry in any case */
static void
test_srej_off (void)
{
    struct test_ctx ctx;
    struct ietf_mini_conn *conn;

    conn = new_mini_conn(&ctx);
    ctx.tc_enpub.enp_settings.es_support_srej = 0;
    assert(!(tick(conn) & TICK_RETRY));
    destroy(&ctx, conn);
}


int
main (void)
{
    test_no_chlo();
    test_chlo_partly_read();
    test_chlo_end_missing();
    test_chlo_stashed();
    test_srej_off();
    return 0;
}
