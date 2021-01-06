/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_VER_NEG_H
#define LSQUIC_VER_NEG_H

/* Client engages in version negotiation, going from highest supported
 * version to lowest.
 */
struct ver_neg {
    unsigned            vn_supp;    /* Remaining options, including `vn_ver' */
    enum lsquic_version vn_ver;     /* If client, current version sent to server
                                     * (sess_resume version or highest supported);
                                     * if server, this is set to negotiated version.
                                     */
    enum ver_neg_state {
        VN_START,                   /* Have not received ver-nego packet */
        VN_IN_PROGRESS,             /* Received ver-nego packet */
        VN_END,                     /* Received packet using supported version */
    }                   vn_state;
    lsquic_ver_tag_t    vn_buf;     /* Buffer to store version tag */
    lsquic_ver_tag_t   *vn_tag;     /* Pointer to version tag.  Set to NULL if
                                     * version negotiation is done in the client;
                                     * always set to NULL in server.
                                     */
};

#endif
