/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_TOKEN_H
#define LSQUIC_TOKEN_H 1

struct lsquic_engine_public;
struct sockaddr;
struct lsquic_packet_in;
struct lsquic_cid;

struct token_generator;

struct token_generator *
lsquic_tg_new (struct lsquic_engine_public *);

void
lsquic_tg_destroy (struct token_generator *);

/* `reset_token' must be IQUIC_SRESET_TOKEN_SZ bytes in length */
void
lsquic_tg_generate_sreset (struct token_generator *,
        const struct lsquic_cid *cid, unsigned char *reset_token);

#endif
