/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include "lsquic_types.h"
#include "lsquic.h"
#include "../src/liblsquic/lsquic_logger.h"
#include "../src/liblsquic/lsquic_hash.h"

#include "test_cert.h"


static char s_alpn[0x100];

int
add_alpn (const char *alpn)
{
    size_t alpn_len, all_len;

    alpn_len = strlen(alpn);
    if (alpn_len > 255)
        return -1;

    all_len = strlen(s_alpn);
    if (all_len + 1 + alpn_len + 1 > sizeof(s_alpn))
        return -1;

    s_alpn[all_len] = alpn_len;
    memcpy(&s_alpn[all_len + 1], alpn, alpn_len);
    s_alpn[all_len + 1 + alpn_len] = '\0';
    return 0;
}


static int
select_alpn (SSL *ssl, const unsigned char **out, unsigned char *outlen,
                    const unsigned char *in, unsigned int inlen, void *arg)
{
    int r;

    r = SSL_select_next_proto((unsigned char **) out, outlen, in, inlen,
                                    (unsigned char *) s_alpn, strlen(s_alpn));
    if (r == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    else
    {
        LSQ_WARN("no supported protocol can be selected from %.*s",
                                                    (int) inlen, (char *) in);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}



int
load_cert (struct lsquic_hash *certs, const char *optarg)
{
    int rv = -1;
    char *sni, *cert_file, *key_file;
    struct server_cert *cert = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *f = NULL;

    sni = strdup(optarg);
    cert_file = strchr(sni, ',');
    if (!cert_file)
        goto end;
    *cert_file = '\0';
    ++cert_file;
    key_file = strchr(cert_file, ',');
    if (!key_file)
        goto end;
    *key_file = '\0';
    ++key_file;

    cert = calloc(1, sizeof(*cert));
    cert->ce_sni = strdup(sni);

    cert->ce_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!cert->ce_ssl_ctx)
    {
        LSQ_ERROR("SSL_CTX_new failed");
        goto end;
    }
    SSL_CTX_set_min_proto_version(cert->ce_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(cert->ce_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(cert->ce_ssl_ctx);
    SSL_CTX_set_alpn_select_cb(cert->ce_ssl_ctx, select_alpn, NULL);
    {
        const char *const s = getenv("LSQUIC_ENABLE_EARLY_DATA");
        if (!s || atoi(s))
            SSL_CTX_set_early_data_enabled(cert->ce_ssl_ctx, 1);    /* XXX */
    }
    if (1 != SSL_CTX_use_certificate_chain_file(cert->ce_ssl_ctx, cert_file))
    {
        LSQ_ERROR("SSL_CTX_use_certificate_chain_file failed: %s", cert_file);
        goto end;
    }

    if (strstr(key_file, ".pkcs8"))
    {
        f = fopen(key_file, "r");
        if (!f)
        {
            LSQ_ERROR("fopen(%s) failed: %s", cert_file, strerror(errno));
            goto end;
        }
        pkey = d2i_PrivateKey_fp(f, NULL);
        fclose(f);
        f = NULL;
        if (!pkey)
        {
            LSQ_ERROR("Reading private key from %s failed", key_file);
            goto end;
        }
        if (!SSL_CTX_use_PrivateKey(cert->ce_ssl_ctx, pkey))
        {
            LSQ_ERROR("SSL_CTX_use_PrivateKey failed");
            goto end;
        }
    }
    else if (1 != SSL_CTX_use_PrivateKey_file(cert->ce_ssl_ctx, key_file,
                                                            SSL_FILETYPE_PEM))
    {
        LSQ_ERROR("SSL_CTX_use_PrivateKey_file failed");
        goto end;
    }

    const int was = SSL_CTX_set_session_cache_mode(cert->ce_ssl_ctx, 1);
    LSQ_DEBUG("set SSL session cache mode to 1 (was: %d)", was);

    if (lsquic_hash_insert(certs, cert->ce_sni, strlen(cert->ce_sni), cert,
                                                            &cert->ce_hash_el))
        rv = 0;
    else
        LSQ_WARN("cannot insert cert for %s into hash table", cert->ce_sni);

  end:
    free(sni);
    if (rv != 0)
    {   /* Error: free cert and its components */
        if (cert)
        {
            free(cert->ce_sni);
            free(cert);
        }
    }
    return rv;
}

struct ssl_ctx_st *
lookup_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED,
             const char *sni)
{
    struct lsquic_hash_elem *el;
    struct server_cert *server_cert;

    if (!cert_lu_ctx)
        return NULL;

    if (sni)
        el = lsquic_hash_find(cert_lu_ctx, sni, strlen(sni));
    else
    {
        LSQ_INFO("SNI is not set");
        el = lsquic_hash_first(cert_lu_ctx);
    }

    if (el)
    {
        server_cert = lsquic_hashelem_getdata(el);
        if (server_cert)
            return server_cert->ce_ssl_ctx;
    }

    return NULL;
}


void
delete_certs (struct lsquic_hash *certs)
{
    struct lsquic_hash_elem *el;
    struct server_cert *cert;

    for (el = lsquic_hash_first(certs); el; el = lsquic_hash_next(certs))
    {
        cert = lsquic_hashelem_getdata(el);
        SSL_CTX_free(cert->ce_ssl_ctx);
        free(cert->ce_sni);
        free(cert);
    }
    lsquic_hash_destroy(certs);
}
