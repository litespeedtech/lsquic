/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Global state
 */

#include <stdlib.h>
#include <sys/queue.h>

#include <openssl/rand.h>

#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic.h"
#include "lsquic_hash.h"
#include "lsquic_str.h"
#include "lsquic_enc_sess.h"
#include "lsquic_util.h"


int
lsquic_global_init (int flags)
{
    uint64_t seed;

    lsquic_init_timers();
    (void) /* BoringSSL's RAND_bytes does not fail */
    RAND_bytes((void *) &seed, sizeof(seed));
    lsquic_hash_set_global_seed(seed);
    srand(seed);
    if (0 != lsquic_enc_session_common_gquic_1.esf_global_init(flags))
        return -1;
    if (0 != lsquic_enc_session_common_ietf_v1.esf_global_init(flags))
        return -1;
    return 0;
}


void
lsquic_global_cleanup (void)
{
    lsquic_enc_session_common_gquic_1.esf_global_cleanup();
    lsquic_enc_session_common_ietf_v1.esf_global_cleanup();
}
