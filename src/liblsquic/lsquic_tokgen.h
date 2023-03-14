/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_TOKEN_H
#define LSQUIC_TOKEN_H 1

struct lsquic_engine_public;
struct sockaddr;
struct lsquic_packet_in;
struct lsquic_cid;

enum token_type { TOKEN_RETRY, TOKEN_RESUME, N_TOKEN_TYPES, };

struct token_generator;

struct token_generator *
lsquic_tg_new (struct lsquic_engine_public *);

void
lsquic_tg_destroy (struct token_generator *);

/* `reset_token' must be IQUIC_SRESET_TOKEN_SZ bytes in length */
void
lsquic_tg_generate_sreset (struct token_generator *,
        const struct lsquic_cid *cid, unsigned char *reset_token);


/* Retry and Resume tokens have identical sizes.  Use *RETRY* macros
 * for both.
 */
#define RETRY_TAG_LEN 16

/* Type is encoded in the nonce */
#define RETRY_NONCE_LEN 12

#define MAX_RETRY_TOKEN_LEN (RETRY_NONCE_LEN + 1 /* version */ + \
    sizeof(time_t) /* time */ + 1 /* IPv4 or IPv6 */ + \
    16 /* IPv6 or IPv4 address */ + 2 /* Port number */ + MAX_CID_LEN + \
    RETRY_TAG_LEN)

/* Need this to make sure we have enough bytes for Bloom filter functions */
#define MIN_RESUME_TOKEN_LEN (RETRY_NONCE_LEN + 1 /* version */ + \
    sizeof(time_t) /* time */ + 1 /* IPv4 or IPv6 */ + \
    4 /* IPv4 address */ + 0 /* No port number */ + 0 /* No CID */ + \
    RETRY_TAG_LEN)

ssize_t
lsquic_tg_generate_retry (struct token_generator *,
        unsigned char *buf, size_t bufsz,
        const unsigned char *scid_buf, size_t scid_len,
        const struct sockaddr *sa_peer, const struct lsquic_cid *odcid);

ssize_t
lsquic_tg_generate_resume (struct token_generator *,
        unsigned char *buf, size_t bufsz,
        const struct sockaddr *sa_peer);

int
lsquic_tg_validate_token (struct token_generator *,
        const struct lsquic_packet_in *, const struct sockaddr *,
        struct lsquic_cid *);

size_t
lsquic_tg_token_size (const struct token_generator *tokgen,
                enum token_type token_type, const struct sockaddr *sa_peer);

#endif
