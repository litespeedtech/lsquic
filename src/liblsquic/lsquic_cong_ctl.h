/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_cong_ctl.h -- congestion control interface
 */

#ifndef LSQUIC_CONG_CTL_H
#define LSQUIC_CONG_CTL_H


struct cong_ctl_if
{
    void
    (*cci_init) (void *cong_ctl, const lsquic_cid_t *);

    void
    (*cci_ack) (void *cong_ctl, lsquic_time_t now,
               lsquic_time_t rtt, int app_limited, unsigned n_bytes);

    void
    (*cci_loss) (void *cong_ctl);

    void
    (*cci_timeout) (void *cong_ctl);

    void
    (*cci_was_quiet) (void *cong_ctl, lsquic_time_t now);

    unsigned long
    (*cci_get_cwnd) (void *cong_ctl);

    int
    (*cci_in_slow_start) (void *cong_ctl);

    void
    (*cci_cleanup) (void *cong_ctl);
};

#endif
