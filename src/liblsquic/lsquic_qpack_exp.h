/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/* QPACK Experiment record */

#ifndef LSQUIC_QPACK_EXP_H
#define LSQUIC_QPACK_EXP_H

struct qpack_exp_record
{
    enum {
        QER_SERVER       = 1 << 0,      /* Client or server */
        QER_ENCODER      = 1 << 1,      /* If not set, this is decoder */
    }               qer_flags;

    /* Timestamp of the first request */
    lsquic_time_t   qer_first_req;

    /* Timestamp of the last request */
    lsquic_time_t   qer_last_req;

    /* Number of header blocks passed through the encoder or the decoder */
    unsigned        qer_hblock_count;

    /* Cumulative size of all header blocks processed */
    unsigned        qer_hblock_size;

    /* For encoder, the "peer max size" is the maximum size advertised by
     * the peer and the "used max size" is the maximum size that our
     * encoder ends up using (the value selected by experiment).
     *
     * For decoder, the "used max size" is the maximum size we advertize
     * (selecte by experiment), while the "peer max size" is the size the
     * encoder uses as given by the value of the last TSU instruction.
     */
    unsigned        qer_peer_max_size;
    unsigned        qer_used_max_size;

    /* For encoder, the "peer max blocked" is the maximum number of blocked
     * streams advertised by the peer, while the "used max blocked" is the
     * self-imposed limit (selected by experiment).
     *
     * For decoder, the "used max blocked" is the maximum number of blocked
     * streams that we advertised (selected by experiment) and the "peer max
     * blocked" is the total number of times a header was blocked.  Note
     * that the latter does not count the duration of blockage and it may be
     * insignificant.  For example, a single packet may have header block
     * packaged before the required encoder stream update, in which case the
     * header block will be blocked and then unblocked immediately.
     */
    unsigned        qer_peer_max_blocked;
    unsigned        qer_used_max_blocked;

    /* The compression ratio is taken when experiment concludes via
     * lsqpack_enc_ratio() or lsqpack_dec_ratio().
     */
    float           qer_comp_ratio;

    /* Either 'Server:' or 'User-Agent:' */
    char           *qer_user_agent;
};

struct qpack_exp_record *
lsquic_qpack_exp_new (void);

void
lsquic_qpack_exp_destroy (struct qpack_exp_record *);

/* Returns same as snprintf(3) */
int
lsquic_qpack_exp_to_xml (const struct qpack_exp_record *, char *, size_t);

#endif
