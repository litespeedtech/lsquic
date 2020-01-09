/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef __LSQUIC_CRT_COMPRESS_H__
#define __LSQUIC_CRT_COMPRESS_H__

#include <stdint.h>

struct lsquic_str;

#ifdef __cplusplus
extern "C" {
#endif


enum entry_type {
    END_OF_LIST = 0,
    ENTRY_COMPRESSED = 1,
    ENTRY_CACHED = 2,
    ENTRY_COMMON = 3,
};

typedef struct cert_entry_st {
    enum entry_type type;
    uint32_t index;
    uint64_t hash;
    uint64_t set_hash;
} cert_entry_t;


typedef struct common_cert_st
{
    size_t num_certs;
    const unsigned char* const* certs;
    const size_t* lens;
    uint64_t hash;
} common_cert_t;

struct lsquic_str * get_common_certs_hash();


int get_common_cert(uint64_t hash, uint32_t index, struct lsquic_str *buf);
int match_common_cert(struct lsquic_str * cert, struct lsquic_str * common_set_hashes,
                      uint64_t* out_hash, uint32_t* out_index);

int compress_certs(struct lsquic_str **certs, size_t certs_count,
                   struct lsquic_str *client_common_set_hashes,
                   struct lsquic_str *client_cached_cert_hashes,
                   struct lsquic_str *result);

int get_certs_count(struct lsquic_str *compressed_crt_buf);
int decompress_certs(const unsigned char *in, const unsigned char *in_end,
                     struct lsquic_str *cached_certs, size_t cached_certs_count,
                     struct lsquic_str **out_certs, 
                     size_t *out_certs_count);

void
lsquic_crt_cleanup (void);


#ifdef __cplusplus
}
#endif


#endif //__LSQUIC_CRT_COMPRESS_H__
