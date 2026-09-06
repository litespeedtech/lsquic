/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"


static void
test_gquic_no_peer_cert (enum lsquic_version version, int server)
{
    struct lsquic_engine_public enpub;
    struct lsquic_conn conn;
    lsquic_cid_t cid;

    memset(&enpub, 0, sizeof(enpub));
    lsquic_engine_init_settings(&enpub.enp_settings, server);
    memset(&conn, 0, sizeof(conn));
    conn.cn_cces = conn.cn_cces_buf;
    conn.cn_version = version;
    conn.cn_esf_c = select_esf_common_by_ver(version);
    memset(&cid, 0, sizeof(cid));

    assert(NULL == lsquic_conn_get_full_peer_cert_chain(&conn));

    if (server)
        conn.cn_enc_session = lsquic_enc_session_gquic_gquic_1
                                    .esf_create_server(&conn, cid, &enpub);
    else
        conn.cn_enc_session = lsquic_enc_session_gquic_gquic_1
                    .esf_create_client(&conn, "example.com", cid, &enpub,
                                                                    NULL, 0);
    assert(conn.cn_enc_session);
    /* A server has no client certificate; a fresh client has no peer chain
     * yet.  Exercise both gQUIC tables through the public API.
     */
    assert(NULL == lsquic_conn_get_full_peer_cert_chain(&conn));
    lsquic_enc_session_gquic_gquic_1.esf_destroy(conn.cn_enc_session);
}


int
main (void)
{
    assert(0 == lsquic_global_init(LSQUIC_GLOBAL_CLIENT|LSQUIC_GLOBAL_SERVER));
    test_gquic_no_peer_cert(LSQVER_046, 0);
    test_gquic_no_peer_cert(LSQVER_046, LSENG_SERVER);
    test_gquic_no_peer_cert(LSQVER_050, 0);
    test_gquic_no_peer_cert(LSQVER_050, LSENG_SERVER);
    lsquic_global_cleanup();
    return 0;
}
