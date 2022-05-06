/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_senhist.h -- History sent packets.
 *
 * We need to keep track of packet numbers in order to verify ACKs.  To
 * speed up processing, we make sure that there is never a gap in the
 * packet number sequence we generate.
 */

#ifndef LSQUIC_SENHIST_H
#define LSQUIC_SENHIST_H 1

#ifndef LSQUIC_SENHIST_FATAL
#   define LSQUIC_SENHIST_FATAL 0
#endif

typedef struct lsquic_senhist {
    lsquic_packno_t             sh_last_sent;
    lsquic_packno_t             sh_warn_thresh;
    enum {
#if !LSQUIC_SENHIST_FATAL
        SH_WARNED   = 1 << 0,   /* Warn once */
#endif
        SH_GAP_OK   = 1 << 1,   /* Before connection is just about to close or
                                 * during mini/full packet handoff.
                                 */
    }                           sh_flags;
} lsquic_senhist_t;

#define lsquic_senhist_init(hist, is_ietf) do {                         \
    if (is_ietf)                                                        \
        (hist)->sh_last_sent = ~0ull;                                   \
    else                                                                \
        (hist)->sh_last_sent = 0;                                       \
} while (0)

#define lsquic_senhist_cleanup(hist)

#if LSQUIC_SENHIST_FATAL
#define lsquic_senhist_add(hist, packno) do {                           \
    if (!((hist)->sh_flags & SH_GAP_OK)                                 \
                        && (packno) > (hist)->sh_warn_thresh)           \
        assert((hist)->sh_last_sent == packno - 1);                     \
    if ((int64_t) (packno) > (int64_t) (hist)->sh_last_sent)            \
        (hist)->sh_last_sent = packno;                                  \
} while (0)
#else
#define lsquic_senhist_add(hist, packno) do {                           \
    if ((hist)->sh_last_sent != packno - 1)                             \
    {                                                                   \
        if (!((hist)->sh_flags & (SH_WARNED|SH_GAP_OK))                 \
                        && (packno) > (hist)->sh_warn_thresh)           \
        {                                                               \
            LSQ_WARN("send history gap %"PRIu64" - %"PRIu64,            \
                (hist)->sh_last_sent, packno);                          \
            (hist)->sh_flags |= SH_WARNED;                              \
        }                                                               \
    }                                                                   \
    if ((int64_t) (packno) > (int64_t) (hist)->sh_last_sent)            \
        (hist)->sh_last_sent = packno;                                  \
} while (0)
#endif

/* Returns 0 if no packets have been sent yet */
#define lsquic_senhist_largest(hist) (+(hist)->sh_last_sent)

void
lsquic_senhist_tostr (lsquic_senhist_t *hist, char *buf, size_t bufsz);

#define lsquic_senhist_mem_used(hist) (sizeof(*(hist)))

#endif
