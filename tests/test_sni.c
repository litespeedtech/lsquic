/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <netinet/in.h>
#include <sys/uio.h>
#else
#include "vc_compat.h"
#endif
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include "lsquic.h"


struct lookup_ctx
{
    const char *lc_hostname;
    unsigned lc_calls;
    SSL_CTX *lc_cert_ctx;
};


struct packet
{
    struct packet *pa_next;
    size_t pa_size;
    unsigned char pa_data[65536];
};


static int
save_packets (void *ctx, const struct lsquic_out_spec *specs, unsigned count)
{
    struct packet **tail = ctx, *packet;
    unsigned i;
    size_t j;

    while (*tail)
        tail = &(*tail)->pa_next;
    for (i = 0; i < count; ++i)
    {
        packet = calloc(1, sizeof(*packet));
        assert(packet);
        for (j = 0; j < specs[i].iovlen; ++j)
        {
            assert(packet->pa_size + specs[i].iov[j].iov_len
                                                <= sizeof(packet->pa_data));
            memcpy(packet->pa_data + packet->pa_size, specs[i].iov[j].iov_base,
                                                    specs[i].iov[j].iov_len);
            packet->pa_size += specs[i].iov[j].iov_len;
        }
        *tail = packet;
        tail = &packet->pa_next;
    }
    return count;
}


struct handshake_ctx
{
    unsigned hc_connections, hc_closed, hc_verified;
    int hc_done;
    enum lsquic_hsk_status hc_status;
    X509 *hc_cert;
};


static lsquic_conn_ctx_t *
on_new_conn (void *ctx, lsquic_conn_t *UNUSED_conn)
{
    struct handshake_ctx *hctx = ctx;
    ++hctx->hc_connections;
    return ctx;
}


static void
on_conn_closed (lsquic_conn_t *conn)
{
    struct handshake_ctx *hctx = (void *) lsquic_conn_get_ctx(conn);
    ++hctx->hc_closed;
    lsquic_conn_set_ctx(conn, NULL);
}


static void
on_hsk_done (lsquic_conn_t *conn, enum lsquic_hsk_status status)
{
    struct handshake_ctx *hctx = (void *) lsquic_conn_get_ctx(conn);
    hctx->hc_done = 1;
    hctx->hc_status = status;
}


static int
verify_cert (void *ctx, STACK_OF(X509) *chain)
{
    struct handshake_ctx *hctx = ctx;
    ++hctx->hc_verified;
    if (sk_X509_num(chain) == 1
        && X509_cmp(sk_X509_value(chain, 0), hctx->hc_cert) == 0)
        return 0;
    else
        return -1;
}


static const struct lsquic_stream_if stream_if = {
    .on_new_conn = on_new_conn,
    .on_conn_closed = on_conn_closed,
    .on_hsk_done = on_hsk_done,
};


static int
select_alpn (SSL *UNUSED_ssl, const unsigned char **out, unsigned char *outlen,
             const unsigned char *in, unsigned inlen, void *ctx)
{
    const unsigned char *protocols = ctx;

    if (SSL_select_next_proto((unsigned char **) out, outlen, protocols,
                strlen((const char *) protocols), in, inlen)
                                                    == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    else
        return SSL_TLSEXT_ERR_ALERT_FATAL;
}


static void
make_certificate (EVP_PKEY **key, X509 **cert)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    assert(ctx);
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
                                            NID_X9_62_prime256v1) == 1);
    assert(EVP_PKEY_keygen(ctx, key) == 1);
    EVP_PKEY_CTX_free(ctx);
    *cert = X509_new();
    assert(*cert);
    assert(X509_set_version(*cert, 2));
    assert(ASN1_INTEGER_set(X509_get_serialNumber(*cert), 1));
    assert(X509_gmtime_adj(X509_get_notBefore(*cert), -60));
    assert(X509_gmtime_adj(X509_get_notAfter(*cert), 3600));
    assert(X509_set_pubkey(*cert, *key));
    assert(X509_sign(*cert, *key, EVP_sha256()));
}


static void
deliver_packets (struct packet **packets, lsquic_engine_t *engine,
                 const struct sockaddr_in *local,
                 const struct sockaddr_in *peer, void *peer_ctx)
{
    struct packet *packet;

    while ((packet = *packets))
    {
        *packets = packet->pa_next;
        assert(0 <= lsquic_engine_packet_in(engine, packet->pa_data,
            packet->pa_size, (const struct sockaddr *) local,
            (const struct sockaddr *) peer, peer_ctx, 0));
        free(packet);
    }
}


static SSL_CTX *
get_ssl_ctx (void *ctx, const struct sockaddr *UNUSED_local)
{
    return ctx;
}


static SSL_CTX *
lookup_cert (void *ctx, const struct sockaddr *UNUSED_local, const char *hostname)
{
    struct lookup_ctx *lookup = ctx;

    ++lookup->lc_calls;
    if (lookup->lc_hostname)
        assert(hostname && 0 == strcmp(hostname, lookup->lc_hostname));
    else
        assert(!hostname);
    return lookup->lc_cert_ctx;
}


static void
test_handshake (enum lsquic_version version, unsigned http, int allow_no_sni,
                const char *hostname, int reject, EVP_PKEY *key, X509 *cert)
{
    struct lsquic_engine_settings settings;
    struct lsquic_engine_api api;
    struct sockaddr_in client_addr, server_addr;
    struct lookup_ctx lookup = { hostname, 0, NULL };
    struct handshake_ctx client_hsk = { 0 }, server_hsk = { 0 };
    struct packet *to_server = NULL, *to_client = NULL;
    const unsigned expected_lookup = !!(hostname || !http || allow_no_sni);
    const int expected_success = expected_lookup && !reject;
    unsigned rounds;
    lsquic_engine_t *client, *server;
    SSL_CTX *ssl_ctx, *cert_ctx;

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    client_addr.sin_port = htons(12345);
    server_addr = client_addr;
    server_addr.sin_port = htons(443);
    ssl_ctx = SSL_CTX_new(TLS_method());
    assert(ssl_ctx);
    assert(SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION));
    assert(SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION));
    SSL_CTX_set_alpn_select_cb(ssl_ctx, select_alpn, http ? "\2h3" : "\4test");
    /* Only the lookup context has a certificate, proving it was selected. */
    cert_ctx = SSL_CTX_new(TLS_method());
    assert(cert_ctx);
    assert(SSL_CTX_use_certificate(cert_ctx, cert));
    assert(SSL_CTX_use_PrivateKey(cert_ctx, key));
    SSL_CTX_set_alpn_select_cb(cert_ctx, select_alpn, http ? "\2h3" : "\4test");
    if (!reject)
        lookup.lc_cert_ctx = cert_ctx;
    client_hsk.hc_cert = cert;

    memset(&api, 0, sizeof(api));
    api.ea_stream_if = &stream_if;
    api.ea_packets_out = save_packets;
    api.ea_packets_out_ctx = &to_server;
    api.ea_stream_if_ctx = &client_hsk;
    api.ea_verify_cert = verify_cert;
    api.ea_verify_ctx = &client_hsk;
    api.ea_alpn = "test";
    client = lsquic_engine_new(http, &api);
    assert(client);

    lsquic_engine_init_settings(&settings, LSENG_SERVER | http);
    settings.es_allow_no_sni = allow_no_sni;
    api.ea_settings = &settings;
    api.ea_packets_out_ctx = &to_client;
    api.ea_stream_if_ctx = &server_hsk;
    api.ea_verify_cert = NULL;
    api.ea_verify_ctx = NULL;
    api.ea_get_ssl_ctx = get_ssl_ctx;
    api.ea_lookup_cert = lookup_cert;
    api.ea_cert_lu_ctx = &lookup;
    server = lsquic_engine_new(LSENG_SERVER | http, &api);
    assert(server);
    assert(lsquic_engine_connect(client, version,
        (const struct sockaddr *) &client_addr,
        (const struct sockaddr *) &server_addr, NULL, NULL, hostname,
        0, NULL, 0, NULL, 0));
    for (rounds = 0; rounds < 100; ++rounds)
    {
        lsquic_engine_process_conns(client);
        deliver_packets(&to_server, server, &server_addr, &client_addr, ssl_ctx);
        lsquic_engine_process_conns(server);
        deliver_packets(&to_client, client, &client_addr, &server_addr, NULL);
        if (client_hsk.hc_closed
            || (client_hsk.hc_done && server_hsk.hc_connections))
            break;
    }
    assert(rounds < 100);
    assert(lookup.lc_calls == expected_lookup);
    if (expected_success)
    {
        assert(client_hsk.hc_done && client_hsk.hc_status == LSQ_HSK_OK);
        assert(client_hsk.hc_verified == 1);
        assert(server_hsk.hc_connections == 1);
        assert(!client_hsk.hc_closed && !server_hsk.hc_closed);
    }
    else
    {
        assert(client_hsk.hc_closed);
        assert(!client_hsk.hc_done || client_hsk.hc_status == LSQ_HSK_FAIL);
        assert(!client_hsk.hc_verified && !server_hsk.hc_connections);
    }
    lsquic_engine_destroy(client);
    lsquic_engine_destroy(server);
    SSL_CTX_free(ssl_ctx);
    SSL_CTX_free(cert_ctx);
    assert(!to_server && !to_client);
}


int
main (void)
{
    const enum lsquic_version versions[] = { LSQVER_I001, LSQVER_I002 };
    unsigned i, http;
    int allow, reject;
    EVP_PKEY *key = NULL;
    X509 *cert;

    assert(0 == lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER));
    make_certificate(&key, &cert);
    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); ++i)
        for (http = 0; http <= LSENG_HTTP; http += LSENG_HTTP)
            for (allow = 0; allow <= 1; ++allow)
                for (reject = 0; reject <= 1; ++reject)
                {
                    test_handshake(versions[i], http, allow, NULL,
                                   reject, key, cert);
                    test_handshake(versions[i], http, allow, "example.com",
                                   reject, key, cert);
                }
    X509_free(cert);
    EVP_PKEY_free(key);
    lsquic_global_cleanup();
    return 0;
}
