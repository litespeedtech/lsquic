/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_H3_PRIO_H
#define LSQUIC_H3_PRIO_H 1

#define H3_PRIO_MAX_ELEMS ((1 << 16) - 1)

struct h3_prio_tree;
struct lsquic_conn;
struct lsquic_stream;

/* Same deal as with GQUIC priorities: lower value means higher priority */
typedef uint8_t h3_weight_t;

/* This corresponds to 16: */
#define H3_DEFAULT_WEIGHT 240

enum h3_elem_type
{
    H3ET_ROOT,
    H3ET_REQ_STREAM,
    H3ET_PUSH_STREAM,
    H3ET_PLACEHOLDER,
};

struct h3_prio_tree *
lsquic_prio_tree_new (const struct lsquic_conn *, unsigned);

void
lsquic_prio_tree_set_ph (struct h3_prio_tree *, unsigned);

void
lsquic_prio_tree_destroy (struct h3_prio_tree *);

/* Call for PRIORITY frames arriving on request stream */
int
lsquic_prio_tree_add_stream (struct h3_prio_tree *, struct lsquic_stream *,
    enum h3_elem_type parent_type, uint64_t parent_id, h3_weight_t);

/* Call for PRIORITY frames on the control stream */
int
lsquic_prio_tree_set_rel (struct h3_prio_tree *,
    enum h3_elem_type child_type, uint64_t child_id, h3_weight_t child_weight,
    enum h3_elem_type parent_type, uint64_t parent_id);

int
lsquic_prio_tree_remove_stream (struct h3_prio_tree *, struct lsquic_stream *,
                                    lsquic_time_t now);

void
lsquic_prio_tree_prune (struct h3_prio_tree *, lsquic_time_t cutoff);

/* To begin to use the iterator, reset it first */
void
lsquic_prio_tree_iter_reset (struct h3_prio_tree *tree, const char *);

/* Then, add one or more stream objects */
int
lsquic_prio_tree_iter_add (struct h3_prio_tree *tree, struct lsquic_stream *);

struct lsquic_stream *
lsquic_prio_tree_highest_non_crit (struct h3_prio_tree *);

/* Then, call next() until NULL is returned.  It is OK to abandon the iterator
 * at any time.
 */
struct lsquic_stream *
lsquic_prio_tree_iter_next (struct h3_prio_tree *tree);

size_t
lsquic_prio_tree_to_str (const struct h3_prio_tree *tree, char *, size_t);

#endif
