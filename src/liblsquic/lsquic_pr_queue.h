/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_pr_queue.h -- a queue of packet requests
 *
 * Some packets need to be replied to outside of context of existing
 * mini or full connections:
 *
 *  1. A version negotiation packet needs to be sent when a packet
 *     arrives that specifies QUIC version that we do not support.
 *  2. A public reset packet needs to be sent when we receive a
 *     packet that does not belong to a known QUIC connection.
 *
 * The replies cannot be sent immediately.  They share outgoing
 * socket with existing connections and must be scheduled according
 * to prioritization rules.
 *
 * The information needed to generate reply packet  -- connection ID,
 * connection context, and the peer address -- is saved in the Packet
 * Request Queue.
 *
 * When it is time to send packets, the connection iterator knows to
 * call prq_next_conn() when appropriate.  What is returned is an
 * evanescent connection object that disappears as soon as the reply
 * packet is successfully sent out.
 *
 * There are two limits associated with Packet Request Queue:
 *  1. Maximum number of packet requests that are allowed to be
 *     pending at any one time.  This is simply to prevent memory
 *     blowout.
 *  2. Maximum verneg connection objects to be allocated at any one
 *     time.  This number is the same as the maximum batch size in
 *     the engine, because the packet (and, therefore, the connection)
 *     is returned to the Packet Request Queue when it could not be
 *     sent.
 *
 * We call this a "request" queue because it describes what we do with
 * QUIC packets whose version we do not support or those packets that
 * do not belong to an existing connection: we send a reply for each of
 * these packets, which effectively makes them "requests."
 */

#ifndef LSQUIC_PR_QUEUE_H
#define LSQUIC_PR_QUEUE_H 1

struct lsquic_conn;
struct lsquic_packet_in;
struct lsquic_engine_settings;
struct pr_queue;
struct sockaddr;

enum packet_req_type {
    PACKET_REQ_VERNEG,
    PACKET_REQ_PUBRES,
    N_PREQ_TYPES,
};

extern const char *const lsquic_preqt2str[N_PREQ_TYPES];

struct pr_queue *
lsquic_prq_create (unsigned max_elems, unsigned max_conns,
                const struct lsquic_engine_public *);

void
lsquic_prq_destroy (struct pr_queue *);

int
lsquic_prq_new_req (struct pr_queue *, enum packet_req_type,
             const struct lsquic_packet_in *, void *conn_ctx,
             const struct sockaddr *local_addr,
             const struct sockaddr *peer_addr);

struct lsquic_conn *
lsquic_prq_next_conn (struct pr_queue *);

int
lsquic_prq_have_pending (const struct pr_queue *);

void
lsquic_prq_drop (struct lsquic_conn *);

#endif
