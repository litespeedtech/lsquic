/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_h3_prio.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"


static struct conn_cid_elem cces[1] = {{ .cce_cid = { .len = 8, }, }};
static struct lsquic_conn s_conn = { .cn_cces = cces, .cn_cces_mask = 1, };

static struct lsquic_stream s_streams[20];
static struct lsquic_stream *s_next_stream;

struct set_rel_args
{
    enum h3_elem_type   parent_type;
    uint64_t            parent_id;
    enum h3_elem_type   child_type;
    uint64_t            child_id;
    h3_weight_t         child_weight;
};

#define EXP_ARGS(ra) (ra)->child_type, (ra)->child_id, (ra)->child_weight, \
                            (ra)->parent_type, (ra)->parent_id

struct add_stream_args
{
    enum h3_elem_type   parent_type;
    uint64_t            parent_id;
    h3_weight_t         weight;
};

#define EXP_ADD_STREAM_ARGS(a) stream, (a)->parent_type, (a)->parent_id, \
                                                                (a)->weight

struct remove_stream_args
{
    struct lsquic_stream *stream;
    lsquic_time_t         now;
};

#define EXP_REMOVE_STREAM_ARGS(a) stream, (a)->now

struct prune_args
{
    lsquic_time_t         cutoff;
};

#define EXP_PRUNE_ARGS(a) (a)->cutoff

enum tree_test_id {
    TEST_ID_UNSPECIFIED,
    TEST_ID_RFC7540_EXAMPLE,
    TEST_ID_PRE_PRUNE,
    TEST_ID_SIMPLE_TREE_1,
    TEST_ID_PRUNE,
    TEST_ID_TOP_LEVEL_PLACEHOLDERS,
};

struct step
{
    enum {
        LAST_STEP = 0,
        REPLAY_TEST,
        CALL_SET_REL,
        CALL_ADD_STREAM,
        CALL_REMOVE_STREAM,
        CALL_PRUNE,
    }                    call;
    int                  retval;
    union {
        struct set_rel_args         set_rel;
        struct add_stream_args      add_stream;
        struct remove_stream_args   remove_stream;
        struct prune_args           prune;
        enum tree_test_id                test_id;
    }                    args;
    union {
        struct {
            lsquic_stream_id_t  stream_id;
        }                           add_stream;
        struct {
            lsquic_stream_id_t  stream_id;
        }                           remove_stream;
    }                    ctx;
    const char          *result;    /* Optional */
};

struct tree_test
{
    int                 lineno;
    enum tree_test_id        test_id;
    unsigned            n_placeholders;
    struct step         steps[20];
    const char         *result;     /* Optional */
};

static const struct tree_test tree_tests[] =
{
    {
        .lineno     = __LINE__,
        .result     = "(t: R; id: 0; w: 0)",
    },

    {
        .lineno     = __LINE__,
        .test_id    = TEST_ID_SIMPLE_TREE_1,
        .n_placeholders = 20,
        .steps      = {
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_ROOT, 0, H3ET_REQ_STREAM, 1, 22, },
                .result = "(t: R; id: 0; w: 0; c: [(t: Q; id: 1; w: 22)])",
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .parent_type = H3ET_ROOT, .parent_id = 0, .weight = 77, },
                .ctx.add_stream.stream_id = 1,
                .result = "(t: R; id: 0; w: 0; c: [(t: Q; id: 1; w: 22)])",
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .parent_type = H3ET_ROOT, .parent_id = 0, .weight = 77, },
                .ctx.add_stream.stream_id = 1,
                .retval = -1,
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_ROOT, 0, H3ET_REQ_STREAM, 1, 23, },
                .result = "(t: R; id: 0; w: 0; c: [(t: Q; id: 1; w: 23)])",
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_PLACEHOLDER, 0, H3ET_REQ_STREAM, 1, 23, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: H; id: 0; w: 240; c: ["
                                    "(t: Q; id: 1; w: 23)"
                                "])"
                            "])",
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .parent_type = H3ET_PLACEHOLDER, .parent_id = 0, .weight = 77, },
                .ctx.add_stream.stream_id = 2,
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: H; id: 0; w: 240; c: ["
                                    "(t: P; id: 2; w: 77),"
                                    "(t: Q; id: 1; w: 23)"
                                "])"
                            "])",
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_REQ_STREAM, 1, H3ET_PUSH_STREAM, 2, 77, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: H; id: 0; w: 240; c: ["
                                    "(t: Q; id: 1; w: 23; c: ["
                                        "(t: P; id: 2; w: 77)"
                                    "])"
                                "])"
                            "])",
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_REQ_STREAM, 1, H3ET_PLACEHOLDER, 2, 77, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: H; id: 0; w: 240; c: ["
                                    "(t: Q; id: 1; w: 23; c: ["
                                        "(t: H; id: 2; w: 77),"
                                        "(t: P; id: 2; w: 77)"
                                    "])"
                                "])"
                            "])",
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_PLACEHOLDER, 0, H3ET_PUSH_STREAM, 3, 100, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: H; id: 0; w: 240; c: ["
                                    "(t: P; id: 3; w: 100),"
                                    "(t: Q; id: 1; w: 23; c: ["
                                        "(t: H; id: 2; w: 77),"
                                        "(t: P; id: 2; w: 77)"
                                    "])"
                                "])"
                            "])",
            },
        },
    },

    {
        .lineno     = __LINE__,
        .n_placeholders = 20,
        .steps      = {
            {
                .call   = REPLAY_TEST,
                .args.test_id = TEST_ID_SIMPLE_TREE_1,
            },
            {
                .call   = CALL_REMOVE_STREAM,
                .args.remove_stream = { .now = 100, },
                .ctx.remove_stream.stream_id = 2,
            },
            {
                .call   = CALL_REMOVE_STREAM,
                .args.remove_stream = { .now = 100, },
                .ctx.remove_stream.stream_id = 2,
                .retval = -1,
            },
            {
                .call   = CALL_PRUNE,
                .args.prune = { .cutoff = 101, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: H; id: 0; w: 240; c: ["
                                    "(t: P; id: 3; w: 100),"
                                    "(t: Q; id: 1; w: 23; c: ["
                                        "(t: H; id: 2; w: 77)"
                                    "])"
                                "])"
                            "])",
            },
        },
    },

/* From RFC 7540, Section 5.3.3:
 *
 * If a stream is made dependent on one of its own dependencies, the
 * formerly dependent stream is first moved to be dependent on the
 * reprioritized stream's previous parent.  The moved dependency retains
 * its weight.
 *
 * For example, consider an original dependency tree where B and C
 * depend on A, D and E depend on C, and F depends on D.  If A is made
 * dependent on D, then D takes the place of A.  All other dependency
 * relationships stay the same, except for F, which becomes dependent on
 * A if the reprioritization is exclusive.
 *
 *     x                x                x                 x
 *     |               / \               |                 |
 *     A              D   A              D                 D
 *    / \            /   / \            / \                |
 *   B   C     ==>  F   B   C   ==>    F   A       OR      A
 *      / \                 |             / \             /|\
 *     D   E                E            B   C           B C F
 *     |                                     |             |
 *     F                                     E             E
 *                (intermediate)   (non-exclusive)    (exclusive)
 *
 *              Figure 5: Example of Dependency Reordering
 */
    {
        .lineno     = __LINE__,
        .test_id    = TEST_ID_RFC7540_EXAMPLE,
        .steps      = {
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_ROOT, 0, H3ET_REQ_STREAM, 'A', 0, },
                .result = "(t: R; id: 0; w: 0; c: [(t: Q; id: 65; w: 0)])",
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_REQ_STREAM, 'A', H3ET_PUSH_STREAM, 'C', 0, },
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_REQ_STREAM, 'A', H3ET_PUSH_STREAM, 'B', 0, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: Q; id: 65; w: 0; c: ["
                                    "(t: P; id: 66; w: 0),"
                                    "(t: P; id: 67; w: 0)"
                                "])"
                          "])",
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_PUSH_STREAM, 'C', H3ET_REQ_STREAM, 'E', 0, },
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_PUSH_STREAM, 'C', H3ET_REQ_STREAM, 'D', 0, },
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_REQ_STREAM, 'D', H3ET_PUSH_STREAM, 'F', 0, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: Q; id: 65; w: 0; c: ["
                                    "(t: P; id: 66; w: 0),"
                                    "(t: P; id: 67; w: 0; c: ["
                                        "(t: Q; id: 68; w: 0; c: ["
                                            "(t: P; id: 70; w: 0)"
                                        "]),"
                                        "(t: Q; id: 69; w: 0)"
                                    "])"
                                "])"
                          "])",
            },
            /*
             * Now that the state corresponds to the picture on the left,
             * flip A and D.  We want to have same structure as picture #3
             * (non-exclusive).  The order of A and F is flipped, however,
             * as new elements are inserted at the head of the child list.
             */
            {
                .call   = CALL_SET_REL,
                .args.set_rel   = { H3ET_REQ_STREAM, 'D', H3ET_REQ_STREAM, 'A', 0, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: Q; id: 68; w: 0; c: ["             /* D */
                                    "(t: Q; id: 65; w: 0; c: ["         /* A */
                                        "(t: P; id: 66; w: 0),"         /* B */
                                        "(t: P; id: 67; w: 0; c: ["     /* C */
                                            "(t: Q; id: 69; w: 0)"      /* E */
                                        "])"
                                    "]),"
                                    "(t: P; id: 70; w: 0)"              /* F */
                                "])"
                          "])",
            },
        },
    },

    {
        .lineno     = __LINE__,
        .test_id    = TEST_ID_PRE_PRUNE,
        .steps      = {
            {
                .call   = REPLAY_TEST,
                .args.test_id = TEST_ID_RFC7540_EXAMPLE,
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: Q; id: 68; w: 0; c: ["             /* D */
                                    "(t: Q; id: 65; w: 0; c: ["         /* A */
                                        "(t: P; id: 66; w: 0),"         /* B */
                                        "(t: P; id: 67; w: 0; c: ["     /* C */
                                            "(t: Q; id: 69; w: 0)"      /* E */
                                        "])"
                                    "]),"
                                    "(t: P; id: 70; w: 0)"              /* F */
                                "])"
                          "])",
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .parent_type = H3ET_ROOT, .parent_id = 0, .weight = 123, },
                .ctx.add_stream.stream_id = 71,
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: P; id: 71; w: 123),"
                                "(t: Q; id: 68; w: 0; c: ["             /* D */
                                    "(t: Q; id: 65; w: 0; c: ["         /* A */
                                        "(t: P; id: 66; w: 0),"         /* B */
                                        "(t: P; id: 67; w: 0; c: ["     /* C */
                                            "(t: Q; id: 69; w: 0)"      /* E */
                                        "])"
                                    "]),"
                                    "(t: P; id: 70; w: 0)"              /* F */
                                "])"
                          "])",
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .parent_type = H3ET_REQ_STREAM, .parent_id = 65, .weight = 29, },
                .ctx.add_stream.stream_id = 72,
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .parent_type = H3ET_REQ_STREAM, .parent_id = 68, .weight = 6, },
                .ctx.add_stream.stream_id = 73,
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: P; id: 71; w: 123),"
                                "(t: Q; id: 68; w: 0; c: ["             /* D */
                                    "(t: Q; id: 73; w: 6),"
                                    "(t: Q; id: 65; w: 0; c: ["         /* A */
                                        "(t: Q; id: 72; w: 29),"
                                        "(t: P; id: 66; w: 0),"         /* B */
                                        "(t: P; id: 67; w: 0; c: ["     /* C */
                                            "(t: Q; id: 69; w: 0)"      /* E */
                                        "])"
                                    "]),"
                                    "(t: P; id: 70; w: 0)"              /* F */
                                "])"
                          "])",
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .weight = 123, },
                .ctx.add_stream.stream_id = 65,
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .weight = 123, },
                .ctx.add_stream.stream_id = 66,
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .weight = 123, },
                .ctx.add_stream.stream_id = 67,
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .weight = 123, },
                .ctx.add_stream.stream_id = 68,
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .weight = 123, },
                .ctx.add_stream.stream_id = 69,
            },
            {
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .weight = 123, },
                .ctx.add_stream.stream_id = 70,
            },
        },
    },

    {
        .lineno     = __LINE__,
        .test_id    = TEST_ID_PRUNE,
        .steps      = {
            {
                .call   = REPLAY_TEST,
                .args.test_id = TEST_ID_PRE_PRUNE,
            },
            {
                .call   = CALL_REMOVE_STREAM,
                .args.remove_stream = { .now = 100, },
                .ctx.remove_stream.stream_id = 65,
            },
            {
                .call   = CALL_PRUNE,
                .args.prune = { .cutoff = 101, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: P; id: 71; w: 123),"
                                "(t: Q; id: 68; w: 0; c: ["
                                    "(t: Q; id: 73; w: 6),"
                                    "(t: Q; id: 72; w: 29),"
                                    "(t: P; id: 66; w: 0),"
                                    "(t: P; id: 67; w: 0; c: ["
                                        "(t: Q; id: 69; w: 0)"
                                    "]),"
                                    "(t: P; id: 70; w: 0)"
                                "])"
                          "])",
            },
            {
                .call   = CALL_REMOVE_STREAM,
                .args.remove_stream = { .now = 200, },
                .ctx.remove_stream.stream_id = 66,
            },
            {
                .call   = CALL_REMOVE_STREAM,
                .args.remove_stream = { .now = 210, },
                .ctx.remove_stream.stream_id = 67,
            },
            {
                .call   = CALL_REMOVE_STREAM,
                .args.remove_stream = { .now = 220, },
                .ctx.remove_stream.stream_id = 73,
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: P; id: 71; w: 123),"
                                "(t: Q; id: 68; w: 0; c: ["
                                    "(t: Q; id: 73; w: 6),"
                                    "(t: Q; id: 72; w: 29),"
                                    "(t: P; id: 66; w: 0),"
                                    "(t: P; id: 67; w: 0; c: ["
                                        "(t: Q; id: 69; w: 0)"
                                    "]),"
                                    "(t: P; id: 70; w: 0)"
                                "])"
                          "])",
            },
            {
                .call   = CALL_PRUNE,
                .args.prune = { .cutoff = 201, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: P; id: 71; w: 123),"
                                "(t: Q; id: 68; w: 0; c: ["
                                    "(t: Q; id: 73; w: 6),"
                                    "(t: Q; id: 72; w: 29),"
                                    "(t: P; id: 67; w: 0; c: ["
                                        "(t: Q; id: 69; w: 0)"
                                    "]),"
                                    "(t: P; id: 70; w: 0)"
                                "])"
                          "])",
            },
            {
                .call   = CALL_PRUNE,
                .args.prune = { .cutoff = 211, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: P; id: 71; w: 123),"
                                "(t: Q; id: 68; w: 0; c: ["
                                    "(t: Q; id: 73; w: 6),"
                                    "(t: Q; id: 72; w: 29),"
                                    "(t: Q; id: 69; w: 0),"
                                    "(t: P; id: 70; w: 0)"
                                "])"
                          "])",
            },
            {
                .call   = CALL_PRUNE,
                .args.prune = { .cutoff = 225, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: P; id: 71; w: 123),"
                                "(t: Q; id: 68; w: 0; c: ["
                                    "(t: Q; id: 72; w: 29),"
                                    "(t: Q; id: 69; w: 0),"
                                    "(t: P; id: 70; w: 0)"
                                "])"
                          "])",
            },
            {
                .call   = CALL_REMOVE_STREAM,
                .args.remove_stream = { .now = 230, },
                .ctx.remove_stream.stream_id = 71,
            },
            {
                .call   = CALL_PRUNE,
                .args.prune = { .cutoff = 235, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: Q; id: 68; w: 0; c: ["
                                    "(t: Q; id: 72; w: 29),"
                                    "(t: Q; id: 69; w: 0),"
                                    "(t: P; id: 70; w: 0)"
                                "])"
                          "])",
            },
            {
                .call   = CALL_REMOVE_STREAM,
                .args.remove_stream = { .now = 240, },
                .ctx.remove_stream.stream_id = 68,
            },
            {
                .call   = CALL_PRUNE,
                .args.prune = { .cutoff = 245, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: Q; id: 72; w: 29),"
                                "(t: Q; id: 69; w: 0),"
                                "(t: P; id: 70; w: 0)"
                          "])",
            },
        },
    },

    {
        .lineno     = __LINE__,
        .n_placeholders = 20,
        .steps      = {
            {
                .call   = REPLAY_TEST,
                .args.test_id = TEST_ID_RFC7540_EXAMPLE,
            },
            {
                /* Test adding stream that depends on an non-existent
                 * placeholder
                 */
                .call   = CALL_ADD_STREAM,
                .args.add_stream = { .parent_type = H3ET_PLACEHOLDER, .parent_id = 9, .weight = 33, },
                .ctx.add_stream.stream_id = 71,
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: H; id: 9; w: 240; c: ["
                                    "(t: P; id: 71; w: 33)"
                                "]),"
                                "(t: Q; id: 68; w: 0; c: ["             /* D */
                                    "(t: Q; id: 65; w: 0; c: ["         /* A */
                                        "(t: P; id: 66; w: 0),"         /* B */
                                        "(t: P; id: 67; w: 0; c: ["     /* C */
                                            "(t: Q; id: 69; w: 0)"      /* E */
                                        "])"
                                    "]),"
                                    "(t: P; id: 70; w: 0)"              /* F */
                                "])"
                          "])",
            },
        },
    },

    {
        .lineno     = __LINE__,
        .n_placeholders = 20,
        .test_id    = TEST_ID_TOP_LEVEL_PLACEHOLDERS,
        .steps      = {
            {
                .call   = REPLAY_TEST,
                .args.test_id = TEST_ID_RFC7540_EXAMPLE,
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel = { H3ET_PLACEHOLDER, 1, H3ET_REQ_STREAM, 68, 0, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: H; id: 1; w: 240; c: ["
                                    "(t: Q; id: 68; w: 0; c: ["             /* D */
                                        "(t: Q; id: 65; w: 0; c: ["         /* A */
                                            "(t: P; id: 66; w: 0),"         /* B */
                                            "(t: P; id: 67; w: 0; c: ["     /* C */
                                                "(t: Q; id: 69; w: 0)"      /* E */
                                            "])"
                                        "]),"
                                        "(t: P; id: 70; w: 0)"              /* F */
                                    "])"
                                "])"
                          "])",
            },
            {
                .call   = CALL_SET_REL,
                .args.set_rel = { H3ET_PLACEHOLDER, 2, H3ET_PUSH_STREAM, 70, 0, },
                .result = "(t: R; id: 0; w: 0; c: ["
                                "(t: H; id: 2; w: 240; c: ["
                                    "(t: P; id: 70; w: 0)"                  /* F */
                                "]),"
                                "(t: H; id: 1; w: 240; c: ["
                                    "(t: Q; id: 68; w: 0; c: ["             /* D */
                                        "(t: Q; id: 65; w: 0; c: ["         /* A */
                                            "(t: P; id: 66; w: 0),"         /* B */
                                            "(t: P; id: 67; w: 0; c: ["     /* C */
                                                "(t: Q; id: 69; w: 0)"      /* E */
                                            "])"
                                        "])"
                                    "])"
                                "])"
                          "])",
            },
        },
    },
};

struct iter_test
{
    int                 lineno;
    enum tree_test_id   tree_test_id;
    unsigned            n_streams;
    lsquic_stream_id_t  in[20], out[20];
};

static const struct iter_test iter_tests[] =
{

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_RFC7540_EXAMPLE,
        .n_streams = 1,
        .in = { 70, },
        .out = { 70, },
    },

    /* 65 and 70 have the same parent and weight: so the iterator should
     * return them in the order in which they were added to the iterator.
     */
    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_RFC7540_EXAMPLE,
        .n_streams = 2,
        .in = { 70, 65, },
        .out = { 70, 65, },
    },

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_RFC7540_EXAMPLE,
        .n_streams = 2,
        .in = { 65, 70, },
        .out = { 65, 70, },
    },

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_RFC7540_EXAMPLE,
        .n_streams = 6,
        .in = { 65, 66, 67, 68, 69, 70, },
        .out = { 68, 65, 70, 66, 67, 69, },
    },

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_RFC7540_EXAMPLE,
        .n_streams = 2,
        .in = { 69, 68, },
        .out = { 68, 69, },
    },

    /* Streams 1 and 3 are on the same level, but have different weight.
     * Order of interator insertion should not matter.
     */
    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_SIMPLE_TREE_1,
        .n_streams = 3,
        .in = { 1, 2, 3, },
        .out = { 1, 3, 2, },
    },

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_SIMPLE_TREE_1,
        .n_streams = 3,
        .in = { 3, 2, 1, },
        .out = { 1, 3, 2, },
    },

};

struct crit_test
{
    int                 lineno;
    enum tree_test_id   tree_test_id;
    lsquic_stream_id_t  add_streams[10];    /* 0 means last */
    lsquic_stream_id_t  expected;
};

static const struct crit_test crit_tests[] =
{

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_RFC7540_EXAMPLE,
        .add_streams = { 65, 66, 67, 68, 69, 70, },
        .expected    = 68,
    },

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_PRUNE,
        .expected    = 69,
    },

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_TOP_LEVEL_PLACEHOLDERS,
        .expected    = ~0ull,
    },

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_TOP_LEVEL_PLACEHOLDERS,
        .add_streams = { 69, },
        .expected    = 69,
    },

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_TOP_LEVEL_PLACEHOLDERS,
        .add_streams = { 69, 70, },
        .expected    = 70,
    },

    {
        .lineno = __LINE__,
        .tree_test_id = TEST_ID_TOP_LEVEL_PLACEHOLDERS,
        .add_streams = { 69, 68, },
        .expected    = 68,
    },

};

enum run_step_flags
{
    RUN_STEP_CHECK_RES    = 1 << 0,
};

static void
replay_test (struct h3_prio_tree *tree, enum tree_test_id test_id);

static void
run_step (struct h3_prio_tree *tree, const struct step *step,
                                                    enum run_step_flags flags)
{
    int s;
    struct lsquic_stream *stream;
    char buf[0x1000];

    switch (step->call)
    {
    case CALL_SET_REL:
        s = lsquic_prio_tree_set_rel(tree, EXP_ARGS(&step->args.set_rel));
        break;
    case CALL_ADD_STREAM:
        stream = s_next_stream++;
        assert(stream < s_streams + sizeof(s_streams) / sizeof(s_streams[0]));
        memset(stream, 0, sizeof(*stream));
        stream->id = step->ctx.add_stream.stream_id;
        s = lsquic_prio_tree_add_stream(tree,
                    EXP_ADD_STREAM_ARGS(&step->args.add_stream));
        break;
    case CALL_REMOVE_STREAM:
        for (stream = s_streams; stream < s_next_stream; ++stream)
            if (stream->id == step->ctx.remove_stream.stream_id)
                break;
        assert(stream);
        s = lsquic_prio_tree_remove_stream(tree,
                    EXP_REMOVE_STREAM_ARGS(&step->args.remove_stream));
        break;
    case CALL_PRUNE:
        lsquic_prio_tree_prune(tree, EXP_PRUNE_ARGS(&step->args.prune));
        s = 0;  /* prune is a void function call */
        break;
    case REPLAY_TEST:
        replay_test(tree, step->args.test_id);
        s = 0;
        break;
    default:
        assert(0);
        break;
    }
    assert(step->retval == s);
    if ((flags & RUN_STEP_CHECK_RES) && step->result)
    {
        memset(buf, 0, sizeof(buf));
        (void) lsquic_prio_tree_to_str(tree, buf, sizeof(buf));
        assert(0 == strcmp(step->result, buf));
    }
}


static void
replay_test (struct h3_prio_tree *tree, enum tree_test_id test_id)
{
    const struct tree_test *test;
    const struct step *step;

    for (test = tree_tests; test < tree_tests + sizeof(tree_tests) / sizeof(tree_tests[0]); ++test)
        if (test->test_id == test_id)
            break;

    assert(test);

    for (step = test->steps; step->call != LAST_STEP; ++step)
        run_step(tree, step, 0);
}


static void
run_test (const struct tree_test *test)
{
    struct h3_prio_tree *tree;
    const struct step *step;
    s_next_stream = s_streams;
    char buf[0x1000];

    tree = lsquic_prio_tree_new(&s_conn, test->n_placeholders);

    for (step = test->steps; step->call != LAST_STEP; ++step)
        run_step(tree, step, RUN_STEP_CHECK_RES);

    if (test->result)
    {
        memset(buf, 0, sizeof(buf));
        (void) lsquic_prio_tree_to_str(tree, buf, sizeof(buf));
        assert(0 == strcmp(test->result, buf));
    }

    lsquic_prio_tree_destroy(tree);
}


static void
run_iter_test (const struct iter_test *test)
{
    struct h3_prio_tree *tree;
    const struct tree_test *tree_test;
    const struct step *step;
    struct lsquic_stream *stream;
    unsigned n;
    int s;

    for (tree_test = tree_tests; tree_test < tree_tests + sizeof(tree_tests)
                                        / sizeof(tree_tests[0]); ++tree_test)
        if (tree_test->test_id == test->tree_test_id)
            break;

    assert(tree_test);

    s_next_stream = s_streams;
    tree = lsquic_prio_tree_new(&s_conn, tree_test->n_placeholders);
    for (step = tree_test->steps; step->call != LAST_STEP; ++step)
        run_step(tree, step, RUN_STEP_CHECK_RES);

    lsquic_prio_tree_iter_reset(tree, "test");
    for (n = 0; n < test->n_streams; ++n)
    {
        for (stream = s_streams; stream < s_next_stream; ++stream)
            if (stream->id == test->in[n])
                break;
        if (stream >= s_next_stream)
        {
            stream = s_next_stream++;
            memset(stream, 0, sizeof(*stream));
            stream->id = test->in[n];
            /* We assume the relationship is already in there */
            s = lsquic_prio_tree_add_stream(tree, stream, 0, 0, 0);
            assert(0 == s);
        }
        lsquic_prio_tree_iter_add(tree, stream);
    }

    for (n = 0; n < test->n_streams; ++n)
    {
        stream = lsquic_prio_tree_iter_next(tree);
        assert(stream);
        assert(stream->id == test->out[n]);
    }
    stream = lsquic_prio_tree_iter_next(tree);
    assert(NULL == stream);

    lsquic_prio_tree_destroy(tree);
}


static void
run_crit_test (const struct crit_test *test)
{
    struct h3_prio_tree *tree;
    const struct tree_test *tree_test;
    const struct step *step;
    struct lsquic_stream *stream;
    const lsquic_stream_id_t *stream_id;
    int s;

    for (tree_test = tree_tests; tree_test < tree_tests + sizeof(tree_tests)
                                        / sizeof(tree_tests[0]); ++tree_test)
        if (tree_test->test_id == test->tree_test_id)
            break;

    assert(tree_test);

    s_next_stream = s_streams;
    tree = lsquic_prio_tree_new(&s_conn, tree_test->n_placeholders);
    for (step = tree_test->steps; step->call != LAST_STEP; ++step)
        run_step(tree, step, RUN_STEP_CHECK_RES);

    for (stream_id = test->add_streams; *stream_id; ++stream_id)
    {
        stream = s_next_stream++;
        memset(stream, 0, sizeof(*stream));
        stream->id = *stream_id;
        /* We assume the relationship is already in there */
        s = lsquic_prio_tree_add_stream(tree, stream, 0, 0, 0);
        assert(0 == s);
    }

    stream = lsquic_prio_tree_highest_non_crit(tree);
    if (test->expected != ~0ull)
        assert(stream->id == test->expected);
    else
        assert(!stream);

    lsquic_prio_tree_destroy(tree);
}


int
main (void)
{
    const struct tree_test *tree_test;
    const struct iter_test *iter_test;
    const struct crit_test *crit_test;

    for (tree_test = tree_tests; tree_test < tree_tests + sizeof(tree_tests)
                                        / sizeof(tree_tests[0]); ++tree_test)
        run_test(tree_test);
    for (iter_test = iter_tests; iter_test < iter_tests + sizeof(iter_tests)
                                        / sizeof(iter_tests[0]); ++iter_test)
        run_iter_test(iter_test);
    for (crit_test = crit_tests; crit_test < crit_tests + sizeof(crit_tests)
                                        / sizeof(crit_tests[0]); ++crit_test)
        run_crit_test(crit_test);

    return 0;
}
