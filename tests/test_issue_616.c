/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_hash.h"
#include "lsquic_mm.h"
#include "lsquic_conn.h"
#include "lsquic_crand.h"
#include "lsquic_engine_public.h"
#include "lsquic_full_conn.h"
#include "lsquic_ietf.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_types.h"
#include "lsquic_util.h"


static lsquic_conn_ctx_t *
on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    (void) stream_if_ctx;
    (void) conn;
    return NULL;
}


static void
on_conn_closed (lsquic_conn_t *conn)
{
    (void) conn;
}


static const struct lsquic_stream_if stream_if = {
    .on_new_conn    = on_new_conn,
    .on_conn_closed = on_conn_closed,
};

static void *
pmi_allocate (void *ctx, void *peer_ctx, lsquic_conn_ctx_t *conn_ctx,
                                            unsigned short sz, char is_ipv6)
{
    (void) ctx;
    (void) peer_ctx;
    (void) conn_ctx;
    (void) is_ipv6;
    return malloc(sz);
}


static void
pmi_release (void *ctx, void *peer_ctx, void *buf, char is_ipv6)
{
    (void) ctx;
    (void) peer_ctx;
    (void) is_ipv6;
    free(buf);
}


static void
pmi_return (void *ctx, void *peer_ctx, void *buf, char is_ipv6)
{
    (void) ctx;
    (void) peer_ctx;
    (void) is_ipv6;
    free(buf);
}


static const struct lsquic_packout_mem_if packout_mem_if = {
    .pmi_allocate = pmi_allocate,
    .pmi_release  = pmi_release,
    .pmi_return   = pmi_return,
};


static void
gen_scid (void *ctx, struct lsquic_conn *conn, uint8_t *scid, unsigned len)
{
    (void) ctx;
    (void) conn;
    memset(scid, 0xAB, len);
}


static int
extract_close_code (uint64_t *close_code)
{
    struct lsquic_engine_public enpub;
    struct crand crand;
    static unsigned char alpn[] = "\x02h3";
    struct lsquic_conn *conn;
    struct lsquic_packet_out *packet_out;
    int app_error;
    uint16_t reason_len;
    uint8_t reason_off;
    int parsed, i;
    int rv = -1;

    memset(&enpub, 0, sizeof(enpub));
    memset(&crand, 0, sizeof(crand));

    lsquic_mm_init(&enpub.enp_mm);
    lsquic_engine_init_settings(&enpub.enp_settings, 0);
    enpub.enp_crand = &crand;
    enpub.enp_stream_if = &stream_if;
    enpub.enp_generate_scid = gen_scid;
    enpub.enp_pmi = &packout_mem_if;
    enpub.enp_flags = ENPUB_PROC;  /* Disable engine queue operations. */
    enpub.enp_settings.es_scid_len = 8;
    enpub.enp_settings.es_silent_close = 0;
    enpub.enp_alpn = alpn;

    /* Use server flag to bypass client version-negotiation early return in
     * immediate_close(), so we can inspect the generated close code directly.
     */
    conn = lsquic_ietf_full_conn_client_new(&enpub, 1u << LSQVER_I001,
        LSENG_SERVER,
        "localhost", 0, 1, NULL, 0, NULL, 0, NULL);
    if (!conn)
    {
        fprintf(stderr, "cannot create full IETF conn\n");
        goto cleanup;
    }
    /* Trigger handshake_ok() while peer TPs are unavailable.  This hits the
     * same close-code mapping used for TP decode failures.
     */
    conn->cn_if->ci_hsk_done(conn, LSQ_HSK_OK);

    packet_out = NULL;
    for (i = 0; i < 4 && !packet_out; ++i)
    {
        (void) conn->cn_if->ci_tick(conn, lsquic_time_now());
        packet_out = conn->cn_if->ci_next_packet_to_send(conn, NULL);
    }

    if (!packet_out)
    {
        fprintf(stderr, "no packet generated after handshake failure\n");
        goto destroy;
    }

    if (!(packet_out->po_frame_types & (1 << QUIC_FRAME_CONNECTION_CLOSE)))
    {
        fprintf(stderr, "expected CONNECTION_CLOSE frame, frame bits: 0x%X\n",
            packet_out->po_frame_types);
        goto destroy;
    }

    parsed = conn->cn_pf->pf_parse_connect_close_frame(packet_out->po_data,
        packet_out->po_data_sz, &app_error, close_code, &reason_len,
        &reason_off);
    if (parsed <= 0)
    {
        fprintf(stderr, "cannot parse generated CONNECTION_CLOSE frame\n");
        goto destroy;
    }

    rv = 0;

destroy:
    conn->cn_if->ci_destroy(conn);
cleanup:
    lsquic_mm_cleanup(&enpub.enp_mm);
    return rv;
}


int
main (void)
{
    uint64_t close_code;

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT))
    {
        fprintf(stderr, "lsquic_global_init failed\n");
        return 1;
    }
    if (0 != extract_close_code(&close_code))
    {
        lsquic_global_cleanup();
        return 1;
    }

    printf("close_code=%"PRIu64"\n", close_code);
    if (close_code != TEC_TRANSPORT_PARAMETER_ERROR)
    {
        fprintf(stderr, "expected close code %"PRIu64", got %"PRIu64"\n",
            (uint64_t) TEC_TRANSPORT_PARAMETER_ERROR, close_code);
        lsquic_global_cleanup();
        return 2;
    }

    lsquic_global_cleanup();
    return 0;
}
