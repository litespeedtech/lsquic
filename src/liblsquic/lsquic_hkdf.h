/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HKDF_H
#define LSQUIC_HKDF_H 1

/* [draft-ietf-quic-tls-23] Section 5.2 */
#define HSK_SALT_BUF "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7" \
                     "\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02"
#define HSK_SALT_PRE29 ((unsigned char *) HSK_SALT_BUF)
/* [draft-ietf-quic-tls-29] Section 5.2 */
#define HSK_SALT ((unsigned char *) \
                     "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97" \
                     "\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99")
#define HSK_SALT_SZ (sizeof(HSK_SALT_BUF) - 1)

#define CLIENT_LABEL "client in"
#define CLIENT_LABEL_SZ (sizeof(CLIENT_LABEL) - 1)
#define SERVER_LABEL "server in"
#define SERVER_LABEL_SZ (sizeof(SERVER_LABEL) - 1)

void
lsquic_qhkdf_expand (const struct env_md_st *, const unsigned char *secret,
            unsigned secret_len, const char *label, uint8_t label_len,
            unsigned char *out, uint16_t out_len);

#endif
