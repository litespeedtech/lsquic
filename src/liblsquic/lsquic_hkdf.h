/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HKDF_H
#define LSQUIC_HKDF_H 1

/* [draft-ietf-quic-tls-11] Section 5.3.2 */
#define HSK_SALT_BUF "\x9c\x10\x8f\x98\x52\x0a\x5c\x5c\x32\x96" \
                     "\x8e\x95\x0e\x8a\x2c\x5f\xe0\x6d\x6c\x38"
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
