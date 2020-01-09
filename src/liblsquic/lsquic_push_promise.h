/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PUSH_PROMISE_H
#define LSQUIC_PUSH_PROMISE_H 1

struct lsquic_hash_elem;
struct lsquic_stream;


enum push_promise_key_type {
    PPKT_ID,
    PPKT_CONTENT,
};


struct push_promise
{
    /* A push promise is associated with a single stream, while a stream can
     * have several push promises it depends on.  These push promises are
     * stored on a list.  A push promise is destroyed when the dependent
     * stream is destroyed.  This bounds the amount of time when DUPLICATE_PUSH
     * frames can be sent out.
     */
    SLIST_ENTRY(push_promise)   pp_next;
    /* Push promises are stored in the same hash and can be searched either
     * by ID or by content.  To differentiate the two keys, the key type is
     * appended at the end PPKT_ID or PPKT_CONTENT.
     */
    struct lsquic_hash_elem     pp_hash_id,
                                pp_hash_content;
    union {
        uint64_t        id;
        unsigned char   buf[9];
    }                           pp_u_id;
#define pp_id   pp_u_id.id
    struct lsquic_stream       *pp_pushed_stream;
    /* This does not include the last key-type byte: */
    size_t                      pp_content_len;
    /* Number of streams holding a reference to this push promise.  When this
     * value becomes zero, the push promise is destroyed.  See lsquic_pp_put().
     *
     * The stream on which PUSH_PROMISE frame is sent has a reference in its
     * sm_promises list.  The push streams themselves have a reference in
     * sm_promise.
     */
    unsigned                    pp_refcnt;
    /* State for the promise reader.  If the state is not PPWS_NONE, we are
     * in the process of writing the first push promise on sm_promises list
     * (that's the last promise received).
     */
    enum {
        PPWS_ID0,       /* Write first byte of Push ID */
        PPWS_ID1,       /* Write second byte of Push ID */
        PPWS_ID2,       /* Write third byte of Push ID */
        PPWS_ID3,       /* Write fourth byte of Push ID */
        PPWS_ID4,       /* Write fifth byte of Push ID */
        PPWS_ID5,       /* Write sixth byte of Push ID */
        PPWS_ID6,       /* Write seventh byte of Push ID */
        PPWS_ID7,       /* Write eighth byte of Push ID */
        PPWS_PFX0,      /* Write first NUL byte of the Header Block Prefix */
        PPWS_PFX1,      /* Write second NUL byte of the Header Block Prefix */
        PPWS_HBLOCK,    /* Write header block -- use sm_push_hblock_off */
        PPWS_DONE,
    }                           pp_write_state;
    unsigned                    pp_write_off;
    unsigned char               pp_encoded_push_id[8];
    /* The content buffer is the header block: it does not include Header
     * Block Prefix.  It is followed by one-byte key type PPKT_CONTENT.
     */
    unsigned char               pp_content_buf[0];
};


#define lsquic_pp_put(promise_, all_promises_) do {                         \
    if ((promise_)->pp_refcnt > 0) {                                        \
        --(promise_)->pp_refcnt;                                            \
        if (0 == (promise_)->pp_refcnt) {                                   \
            LSQ_DEBUG("destroy push promise %"PRIu64, (promise_)->pp_id);   \
            if ((promise_)->pp_hash_id.qhe_flags & QHE_HASHED)              \
                lsquic_hash_erase(all_promises_, &(promise_)->pp_hash_id);  \
            if ((promise_)->pp_hash_content.qhe_flags & QHE_HASHED)         \
                lsquic_hash_erase(all_promises_,                            \
                                            &(promise_)->pp_hash_content);  \
            free(promise);                                                  \
        }                                                                   \
    }                                                                       \
    else                                                                    \
        assert(0);                                                          \
} while (0)

#endif
