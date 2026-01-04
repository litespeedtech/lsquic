/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HKDF_H
#define LSQUIC_HKDF_H 1

/* [RFC 9001] Section 5.2 (Initial Secrets) - draft-23 for backward compatibility */
#define HSK_SALT_BUF "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7" \
                     "\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02"
#define HSK_SALT_PRE29 ((unsigned char *) HSK_SALT_BUF)
/* [RFC 9001] Section 5.2 (Initial Secrets) - draft-29 for backward compatibility */
#define HSK_SALT_PRE33 ((unsigned char *) \
                     "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97" \
                     "\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99")
/* [RFC 9001] Section 5.2 (Initial Secrets) */
#define HSK_SALT ((unsigned char *) \
                     "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17" \
                     "\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a")
/* [RFC 9369] Section 3.2 (QUIC Version 2 Initial Salt) */
#define HSK_SALT_V2 ((unsigned char *) \
                     "\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93" \
                     "\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9")
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
