/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HKDF_H
#define LSQUIC_HKDF_H 1

/* [draft-ietf-quic-tls-22] Section 5.2 */
#define HSK_SALT_BUF "\x7f\xbc\xdb\x0e\x7c\x66\xbb\xe9\x19\x3a" \
                     "\x96\xcd\x21\x51\x9e\xbd\x7a\x02\x64\x4a"
#define HSK_SALT ((unsigned char *) HSK_SALT_BUF)
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
