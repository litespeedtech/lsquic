/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_engine_public.h -- Engine's "public interface"
 *
 */

#ifndef LSQUIC_ENGINE_PUBLIC_H
#define LSQUIC_ENGINE_PUBLIC_H 1

struct lsquic_conn;
struct lsquic_engine;

struct lsquic_engine_public {
    struct lsquic_mm                enp_mm;
    struct lsquic_engine_settings   enp_settings;
    const struct lsquic_packout_mem_if
                                   *enp_pmi;
    void                           *enp_pmi_ctx;
    struct lsquic_engine           *enp_engine;
    enum {
        ENPUB_PROC  = (1 << 0), /* Being processed by one of the user-facing
                                 * functions.
                                 */
    }                               enp_flags;
    unsigned char                   enp_ver_tags_buf[ sizeof(lsquic_ver_tag_t) * N_LSQVER ];
    unsigned                        enp_ver_tags_len;
};

/* These values are printable ASCII characters for ease of printing the
 * whole history in a single line of a log message.  If connection was
 * processed as result of being put onto the queue, the letter is converted
 * to uppercase.
 *
 * The letters are assigned by first letter of the verb for most obvious
 * and important actions, like "read" and "write" and other letters of
 * the verb or some other letters for other actions.
 *
 * Each reason is either expected to produce user read from the stream
 * or putting stream data into packet for sending out.  This is documented
 * in a separate comment column below.
 */
enum rw_reason
{
    RW_REASON_EMPTY         =  '\0',    /* No init required */

                                        /* Expected action: */
    RW_REASON_USER_WRITE    =  'w',     /* write */
    RW_REASON_USER_WRITEV   =  'v',     /* write */
    RW_REASON_USER_READ     =  'r',     /* write (WINDOW_UPDATE frame) */
    RW_REASON_FLUSH         =  'f',     /* write */
    RW_REASON_STREAM_CLOSE  =  'c',     /* write */
    RW_REASON_RST_IN        =  'n',     /* read */
    RW_REASON_STREAM_IN     =  'd',     /* read */
    RW_REASON_RESET_EXT     =  'e',     /* write */
    RW_REASON_WANTREAD      =  'a',     /* read */
    RW_REASON_SHUTDOWN      =  'u',     /* write */
    RW_REASON_WRITEFILE     =  't',     /* write */
    RW_REASON_SENDFILE      =  's',     /* write */
};

/* Put connection onto Pending RW Queue if it is not already on it.  If
 * connection is being destroyed, this is a no-op.
 * XXX Is the bit about "being destroyed" still true?
 */
void
lsquic_engine_add_conn_to_pend_rw (struct lsquic_engine_public *enpub,
                                        lsquic_conn_t *conn, enum rw_reason);

/* Put connection onto Advisory Tick Time  Queue if it is not already on it.
 */
void
lsquic_engine_add_conn_to_attq (struct lsquic_engine_public *enpub,
                                            lsquic_conn_t *, lsquic_time_t);

#endif
