/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/types.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_h3_prio.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PRIO
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(tree->h3pt_conn)
#include "lsquic_logger.h"

/* The tree supports up to 2^16 - 1 elements, which should suffice.
 * Zero is not a valid value (thus -1 elements).
 */
typedef unsigned short elem_idx_t;

/* Because stream IDs are 62-bit integers and we the HTTP/3 element type
 * only has four values (enum h3_elem_type), we can combine the two into
 * a single value.  h3_id_t's lower 62 bits contain the ID, while the
 * high 2 bits contain element type.  This makes searching faster.
 */
typedef uint64_t h3_id_t;

typedef unsigned char active_mark_t;

#define H3_EL_ID(type, id) ((((uint64_t) (type)) << 62) | id)

#define ROOT_IDX 1

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct h3_prio_elem
{
    h3_id_t                 h3pe_id;
    struct lsquic_stream   *h3pe_stream;

    /* Time at which stream was closed: */
    lsquic_time_t           h3pe_closed_at;

    /* Tree neighbors: */
    elem_idx_t              h3pe_parent,
                            h3pe_first_child,
                            h3pe_left,
                            h3pe_right;

    /* Closed streams are kept on a separate queue for efficient pruning: */
    elem_idx_t              h3pe_next_closed;

    /* Used as tiebreaker between elements with the same weight: streams
     * added earlier to the iterator have higher priority.
     */
    elem_idx_t              h3pe_iter_order;
#define h3pe_taken h3pe_iter_order

    enum {
        H3PE_FLAG_CLOSED    = 1 << 0,
    }                       h3pe_flags:8;
    h3_weight_t             h3pe_weight;

    /* These marks are part of the iterator state */
    active_mark_t           h3pe_active_self;
    active_mark_t           h3pe_active_path;
};

#define EL_TYPE(el) ((enum h3_elem_type)((el)->h3pe_id >> 62))
#define EL_ID(el) ((uint64_t)((el)->h3pe_id & ((1ull << 62) - 1)))

#define CALC_EL_IDX(tree, el) (+((el) - (tree)->h3pt_els))

/* The weight and the iterator order are combined into a single value to
 * reduce the number of branches.
 */
typedef uint32_t iter_prio_t;
#define EL_ITER_PRIO(el) (((uint32_t) ((el)->h3pe_weight << 16)) | \
                                                        (el)->h3pe_iter_order)
#define MAX_ITER_PRIO ((1u << 24) - 1)

#define MAX_CRIT_STREAMS (4 /* crypto streams */    \
                        + 3 /* outgoing control, encoder, and decoder */ \
                        + 3 /* incoming control, encoder, and decoder */)

struct h3_iter
{
    const char             *h3it_log_id;
    elem_idx_t              h3it_cursor;
    elem_idx_t              h3it_count;
    active_mark_t           h3it_active;

    /* Critical streams do not participate in the regular HTTP/3 priority
     * mechanism.  They have an implicit priority which is higher than
     * that of the regular request or push streams.  The iterator holds
     * references to them only for the duration of the iteration.
     */
    unsigned                h3it_crit_off;
    unsigned                h3it_crit_count;
    struct lsquic_stream   *h3it_crit_streams[MAX_CRIT_STREAMS];
};

struct h3_prio_tree
{
    const struct lsquic_conn    *h3pt_conn;     /* Used for logging */

    /* Element 0 does not contain a valid value.  Its only use is to store
     * the linear search sentinel.
     */
    struct h3_prio_elem         *h3pt_els;

    struct h3_iter               h3pt_iter;

    unsigned                     h3pt_nalloc;   /* Including element 0 */
    unsigned                     h3pt_nelem;    /* Including element 0 */
    unsigned                     h3pt_max_ph;   /* Maximum placeholder ID */

    /* STAILQ analog: first element is the oldest, newly closed stream
     * elements are inserted at the end.
     */
    elem_idx_t                   h3pt_closed_first,
                                 h3pt_closed_last;
};


struct h3_prio_tree *
lsquic_prio_tree_new (const struct lsquic_conn *conn, unsigned n_placeholders)
{
    struct h3_prio_tree *tree;
    struct h3_prio_elem *els;
    unsigned nalloc, nelem;

    tree = calloc(1, sizeof(*tree));
    if (!tree)
        return NULL;

    nelem = 1 /* element 0 */ + 1 /* root */;
    nalloc = nelem + 4;
    els = malloc(nalloc * sizeof(els[0]));
    if (!els)
    {
        free(tree);
        return NULL;
    }

    els[ROOT_IDX] = (struct h3_prio_elem) { .h3pe_id = H3_EL_ID(H3ET_ROOT, 0) };

    tree->h3pt_conn   = conn;
    tree->h3pt_els    = els;
    tree->h3pt_nalloc = nalloc;
    tree->h3pt_nelem  = nelem;
    tree->h3pt_max_ph = n_placeholders;
    LSQ_DEBUG("create tree with maximum %u placeholders", n_placeholders);
    return tree;
}


static struct h3_prio_elem *
prio_tree_find_by_h3_id (struct h3_prio_tree *tree, h3_id_t h3_id)
{
    struct h3_prio_elem *el;

    tree->h3pt_els[0].h3pe_id = h3_id;
    for (el = &tree->h3pt_els[tree->h3pt_nelem - 1]; el->h3pe_id != h3_id; --el)
        ;

    if (el > tree->h3pt_els)
        return el;
    else
        return NULL;
}


static struct h3_prio_elem *
prio_tree_find (struct h3_prio_tree *tree, enum h3_elem_type type, uint64_t id)
{
    if (type == H3ET_ROOT)
        return &tree->h3pt_els[ROOT_IDX];
    else
        return prio_tree_find_by_h3_id(tree, H3_EL_ID(type, id));
}


static struct h3_prio_elem *
prio_tree_alloc_elem (struct h3_prio_tree *tree)
{
    struct h3_prio_elem *els;
    unsigned nalloc;

    if (tree->h3pt_nalloc > tree->h3pt_nelem)
        return &tree->h3pt_els[ tree->h3pt_nelem++ ];

    nalloc = MIN(H3_PRIO_MAX_ELEMS + 1, tree->h3pt_nalloc * 2);
    if (nalloc <= tree->h3pt_nelem)
    {
        LSQ_ERROR("number of elements reached maximum");
        return NULL;
    }

    els = realloc(tree->h3pt_els, nalloc * sizeof(tree->h3pt_els[0]));
    if (!els)
    {
        LSQ_WARN("memory allocation failure");
        return NULL;
    }

    tree->h3pt_els = els;
    tree->h3pt_nalloc = nalloc;
    return &tree->h3pt_els[ tree->h3pt_nelem++ ];
}


static struct h3_prio_elem *
prio_tree_create_elem (struct h3_prio_tree *tree, enum h3_elem_type type,
                                                                uint64_t id)
{
    struct h3_prio_elem *el, *root;

    assert(type != H3ET_ROOT);
    if (type == H3ET_PLACEHOLDER && id >= tree->h3pt_max_ph)
    {
        LSQ_INFO("invalid placeholder id %"PRIu64" is invalid (maximum "
            "is %u placeholders", id, tree->h3pt_max_ph);
        return NULL;
    }

    el = prio_tree_alloc_elem(tree);
    if (el)
    {
        root = &tree->h3pt_els[ROOT_IDX];
        *el = (struct h3_prio_elem) { .h3pe_id     = H3_EL_ID(type, id),
                                      .h3pe_parent = ROOT_IDX,
                                      .h3pe_right  = root->h3pe_first_child,
                                      .h3pe_weight = H3_DEFAULT_WEIGHT, };
        if (root->h3pe_first_child)
            tree->h3pt_els[ root->h3pe_first_child ].h3pe_left
                                                        = el - tree->h3pt_els;
        root->h3pe_first_child = el - tree->h3pt_els;
    }

    return el;
}


static void
prio_tree_reparent (struct h3_prio_tree *tree,
                                            struct h3_prio_elem *const child,
                                            struct h3_prio_elem *const parent)
{
    struct h3_prio_elem *orig_parent;
    elem_idx_t child_idx;

    child_idx = CALC_EL_IDX(tree, child);
    orig_parent = &tree->h3pt_els[child->h3pe_parent];

    if (orig_parent->h3pe_first_child == child_idx)
        orig_parent->h3pe_first_child = child->h3pe_right;
    else
        tree->h3pt_els[child->h3pe_left].h3pe_right = child->h3pe_right;
    if (child->h3pe_right)
        tree->h3pt_els[child->h3pe_right].h3pe_left = child->h3pe_left;

    child->h3pe_left = 0;
    child->h3pe_right = parent->h3pe_first_child;
    if (child->h3pe_right)
        tree->h3pt_els[child->h3pe_right].h3pe_left = child_idx;
    parent->h3pe_first_child = child_idx;
    child->h3pe_parent = CALC_EL_IDX(tree, parent);
}


static int
prio_tree_is_parent (struct h3_prio_tree *tree,
         const struct h3_prio_elem *parent, const struct h3_prio_elem *child)
{
    elem_idx_t idx;

    assert(parent != child);
    tree->h3pt_els[0].h3pe_id = parent->h3pe_id;
    idx = child->h3pe_parent;
    while (tree->h3pt_els[idx].h3pe_id != parent->h3pe_id)
        idx = tree->h3pt_els[idx].h3pe_parent;
    return idx > 0;
}


static const char el_type2char[] =
{
    [H3ET_ROOT]        = 'R',
    [H3ET_REQ_STREAM]  = 'Q',
    [H3ET_PUSH_STREAM] = 'P',
    [H3ET_PLACEHOLDER] = 'H',
};


int
lsquic_prio_tree_set_rel (struct h3_prio_tree *tree,
    enum h3_elem_type child_type, uint64_t child_id, h3_weight_t child_weight,
    enum h3_elem_type parent_type, uint64_t parent_id)
{
    struct h3_prio_elem *parent, *child;

    parent = prio_tree_find(tree, parent_type, parent_id);
    if (!parent)
    {
        parent = prio_tree_create_elem(tree, parent_type, parent_id);
        if (!parent)
            return -1;
    }
    const elem_idx_t parent_idx = CALC_EL_IDX(tree, parent);

    child = prio_tree_find(tree, child_type, child_id);
    if (!child)
    {
        child = prio_tree_create_elem(tree, child_type, child_id);
        if (!child)
            return -1;
        /* create() above may have realloced */
        parent = &tree->h3pt_els[ parent_idx ];
    }

    if (child->h3pe_parent != parent_idx)
    {
        if (prio_tree_is_parent(tree, child, parent))
            prio_tree_reparent(tree, parent,
                                        &tree->h3pt_els[child->h3pe_parent]);
        prio_tree_reparent(tree, child, parent);
    }
    else if (child == parent)
        return -1;  /* This is unlikely, so check for it last */

    child->h3pe_weight = child_weight;

    LSQ_DEBUG("add rel to %c:%"PRIu64" -> %c:%"PRIu64" with w=%u",
            el_type2char[ child_type ], child_id,
            el_type2char[ parent_type ], parent_id, child_weight);

    return 0;
}


/* Assume that unidirectional streams are push streams */
static enum h3_elem_type
stream_id_2_elem_type (lsquic_stream_id_t stream_id)
{
    enum stream_dir dir;

    dir = 1 & (stream_id >> SD_SHIFT);
    if (dir == SD_BIDI)
        return H3ET_REQ_STREAM;
    else
        return H3ET_PUSH_STREAM;
}


int
lsquic_prio_tree_add_stream (struct h3_prio_tree *tree,
            struct lsquic_stream *stream, enum h3_elem_type parent_type,
            uint64_t parent_id, h3_weight_t weight)
{
    struct h3_prio_elem *parent, *child;
    enum h3_elem_type type;
    elem_idx_t child_idx;

    assert(!lsquic_stream_is_critical(stream));

    type = stream_id_2_elem_type(stream->id);
    child = prio_tree_find(tree, type, stream->id);
    if (child)
    {
        /* Prioritization information already exists: set the pointer
         * and ignore PRIORITY frame information on the request stream.
         */
        if (!child->h3pe_stream)
        {
            child_idx = CALC_EL_IDX(tree, child);
            LSQ_DEBUG("reference stream %c:%"PRIu64" in prio element",
                    el_type2char[ type ], stream->id);
            goto link;
        }
        LSQ_WARN("stream %"PRIu64" is already referenced", stream->id);
        return -1;
    }

    child = prio_tree_create_elem(tree, type, stream->id);
    if (!child)
        return -1;
    child_idx = CALC_EL_IDX(tree, child);

    parent = prio_tree_find(tree, parent_type, parent_id);
    if (!parent)
    {
        parent = prio_tree_create_elem(tree, parent_type, parent_id);
        if (!parent)
            return -1;
        /* create() above may have realloced */
        child = &tree->h3pt_els[ child_idx ];
    }

    prio_tree_reparent(tree, child, parent);
    child->h3pe_weight = weight;
    LSQ_DEBUG("add stream %c:%"PRIu64" -> %c:%"PRIu64" with w=%u",
            el_type2char[ type ], stream->id,
            el_type2char[ parent_type ], parent_id, weight);
  link:
    child->h3pe_stream = stream;
    stream->sm_h3_prio_idx = child_idx;
    return 0;
}


int
lsquic_prio_tree_remove_stream (struct h3_prio_tree *tree,
                                struct lsquic_stream *stream, lsquic_time_t now)
{
    struct h3_prio_elem *el;

    el = &tree->h3pt_els[ stream->sm_h3_prio_idx ];

    if (stream->sm_h3_prio_idx > 0
        && stream->sm_h3_prio_idx < tree->h3pt_nelem
        && el->h3pe_stream == stream
        && !(el->h3pe_flags & H3PE_FLAG_CLOSED))
    {
        assert(el->h3pe_stream == stream);
        if (tree->h3pt_closed_first)
        {
            tree->h3pt_els[ tree->h3pt_closed_last ].h3pe_next_closed
                                    = stream->sm_h3_prio_idx;
            tree->h3pt_closed_last = stream->sm_h3_prio_idx;
        }
        else
        {
            tree->h3pt_closed_first = stream->sm_h3_prio_idx;
            tree->h3pt_closed_last = stream->sm_h3_prio_idx;
        }
        el->h3pe_stream = NULL;
        el->h3pe_closed_at = now;
        el->h3pe_flags |= H3PE_FLAG_CLOSED;
        stream->sm_h3_prio_idx = 0;
        LSQ_DEBUG("removed reference to stream %"PRIu64, stream->id);
        return 0;
    }
    else
    {
        LSQ_WARN("cannot remove stream %"PRIu64, stream->id);
        return -1;
    }
}


void
lsquic_prio_tree_drop_el (struct h3_prio_tree *tree, struct h3_prio_elem *el)
{
    const elem_idx_t
        right   = el->h3pe_right,
        left    = el->h3pe_left,
        parent  = el->h3pe_parent,
        el_idx  = CALC_EL_IDX(tree, el);
    elem_idx_t idx, last;

    /* Update links around the element: */
    idx = el->h3pe_first_child;
    if (idx == 0)
    {
        if (left)
            tree->h3pt_els[ left ].h3pe_right = right;
        else
            tree->h3pt_els[ parent ].h3pe_first_child = right;

        if (right)
            tree->h3pt_els[ right ].h3pe_left = left;
    }
    else
    {
        if (left)
        {
            tree->h3pt_els[ left ].h3pe_right = idx;
            tree->h3pt_els[ idx ].h3pe_left = left;
        }
        else
            tree->h3pt_els[ parent ].h3pe_first_child = idx;

        do
        {
            last = idx;
            tree->h3pt_els[ idx ].h3pe_parent = parent;
            idx = tree->h3pt_els[ idx ].h3pe_right;
        }
        while (idx);

        if (right)
        {
            tree->h3pt_els[ right ].h3pe_left = last;
            tree->h3pt_els[ last ].h3pe_right = right;
        }
    }

    /* Move last element into its spot */
    if (--tree->h3pt_nelem > el_idx)
    {
        el = &tree->h3pt_els[ el_idx ];
        *el = tree->h3pt_els[ tree->h3pt_nelem ];
        for (idx = el->h3pe_first_child; idx;
                                idx = tree->h3pt_els[ idx ].h3pe_right)
            tree->h3pt_els[ idx ].h3pe_parent = el_idx;
        if (el->h3pe_left)
            tree->h3pt_els[ el->h3pe_left ].h3pe_right = el_idx;
        if (el->h3pe_right)
            tree->h3pt_els[ el->h3pe_right ].h3pe_left = el_idx;
        if (tree->h3pt_els[ el->h3pe_parent ].h3pe_first_child
                                                        == tree->h3pt_nelem)
            tree->h3pt_els[ el->h3pe_parent ].h3pe_first_child = el_idx;
        if (el->h3pe_stream)
            el->h3pe_stream->sm_h3_prio_idx = el_idx;
    }
}


void
lsquic_prio_tree_prune (struct h3_prio_tree *tree, lsquic_time_t cutoff)
{
    struct h3_prio_elem *el;
    unsigned count = 0;

    while (tree->h3pt_closed_first
        && tree->h3pt_els[ tree->h3pt_closed_first ].h3pe_closed_at < cutoff)
    {
        el = &tree->h3pt_els[ tree->h3pt_closed_first ];
        tree->h3pt_closed_first = el->h3pe_next_closed;
        if (tree->h3pt_closed_first == 0)
            tree->h3pt_closed_last = 0;
        ++count;
        lsquic_prio_tree_drop_el(tree, el);
    }

    LSQ_DEBUG("pruned %u element%.*s from the tree", count, count != 1, "s");
}


void
lsquic_prio_tree_destroy (struct h3_prio_tree *tree)
{
    LSQ_DEBUG("destroyed");
    free(tree->h3pt_els);
    free(tree);
}


void
lsquic_prio_tree_iter_reset (struct h3_prio_tree *tree, const char *log_id)
{
    struct h3_iter *const iter = &tree->h3pt_iter;
    unsigned i;

    iter->h3it_log_id = log_id;
    iter->h3it_count = 0;
    iter->h3it_crit_count = 0;
    iter->h3it_crit_off = 0;
    iter->h3it_cursor = ROOT_IDX;
    iter->h3it_active++;
    if (0 == iter->h3it_active)
    {
        for (i = 0; i < tree->h3pt_nelem; ++i)
        {
            tree->h3pt_els[i].h3pe_active_self = 0;
            tree->h3pt_els[i].h3pe_active_path = 0;
        }
        iter->h3it_active++;
    }

    LSQ_DEBUG("reset iterator; log id: `%s'; active mark: %u", log_id,
                                                        iter->h3it_active);
}


static int
prio_tree_iter_add_critical (struct h3_prio_tree *tree,
                                            struct lsquic_stream *stream)
{
    struct h3_iter *const iter = &tree->h3pt_iter;

    if (iter->h3it_crit_count < sizeof(iter->h3it_crit_streams)
                                    / sizeof(iter->h3it_crit_streams[0]))
    {
        iter->h3it_crit_streams[ iter->h3it_crit_count++ ] = stream;
        LSQ_DEBUG("%s: add critical stream %"PRIu64" at position %u",
            iter->h3it_log_id, stream->id, iter->h3it_crit_count - 1);
        return 0;
    }
    else
    {
        LSQ_WARN("could not add critical stream %"PRIu64" to the iterator: "
            "no room", stream->id);
        return -1;
    }
}


static int
prio_tree_iter_add_regular (struct h3_prio_tree *tree,
                                            struct lsquic_stream *stream)
{
    struct h3_iter *const iter = &tree->h3pt_iter;
    struct h3_prio_elem *el;

    if (stream->sm_h3_prio_idx > 0
            && stream->sm_h3_prio_idx < tree->h3pt_nelem)
    {
        el = &tree->h3pt_els[stream->sm_h3_prio_idx];
        assert(el->h3pe_stream == stream);
        el->h3pe_active_self = iter->h3it_active;
        el->h3pe_iter_order = iter->h3it_count++;
        while (el->h3pe_parent)
        {
            el = &tree->h3pt_els[ el->h3pe_parent ];
            el->h3pe_active_path = iter->h3it_active;
        }
        LSQ_DEBUG("%s: added stream %"PRIu64" to the iterator",
                                                iter->h3it_log_id, stream->id);
        return 0;
    }
    else
    {
        LSQ_WARN("%s: stream %"PRIu64" has invalid priority index value: %u",
                        iter->h3it_log_id, stream->id, stream->sm_h3_prio_idx);
        assert(0);
        return -1;
    }
}


int
lsquic_prio_tree_iter_add (struct h3_prio_tree *tree,
                                            struct lsquic_stream *stream)
{
    if (lsquic_stream_is_critical(stream))
        return prio_tree_iter_add_critical(tree, stream);
    else
        return prio_tree_iter_add_regular(tree, stream);
}


struct lsquic_stream *
lsquic_prio_tree_iter_next (struct h3_prio_tree *tree)
{
    struct h3_iter *const iter = &tree->h3pt_iter;
    struct h3_prio_elem *el_self, *el_path;
    iter_prio_t prio_self, prio_path;
    elem_idx_t idx;

    if (iter->h3it_crit_off < iter->h3it_crit_count)
    {
        LSQ_DEBUG("%s: return critical stream %"PRIu64" at position %u",
            iter->h3it_log_id, iter->h3it_crit_streams[iter->h3it_crit_off]->id,
            iter->h3it_crit_off);
        return iter->h3it_crit_streams[ iter->h3it_crit_off++ ];
    }

  top0:
    if (!iter->h3it_cursor)
    {
        LSQ_DEBUG("%s: out of streams", iter->h3it_log_id);
        return NULL;
    }

  top1:
    el_self = NULL, el_path = NULL;
    prio_self = MAX_ITER_PRIO + 1;
    prio_path = MAX_ITER_PRIO + 1;
    for (idx = tree->h3pt_els[ iter->h3it_cursor ].h3pe_first_child;
            idx;
                idx = tree->h3pt_els[ idx ].h3pe_right)
    {
        if (tree->h3pt_els[ idx ].h3pe_active_self == iter->h3it_active
                && EL_ITER_PRIO(&tree->h3pt_els[ idx ]) < prio_self)
        {
            el_self = &tree->h3pt_els[ idx ];
            prio_self = EL_ITER_PRIO(el_self);
        }
        if (tree->h3pt_els[ idx ].h3pe_active_path == iter->h3it_active
                && EL_ITER_PRIO(&tree->h3pt_els[ idx ]) < prio_path)
        {
            el_path = &tree->h3pt_els[ idx ];
            prio_path = EL_ITER_PRIO(el_path);
        }
    }

    if (el_self)
    {
        el_self->h3pe_active_self = 0;
        LSQ_DEBUG("%s: return %c stream %"PRIu64, iter->h3it_log_id,
                        el_type2char[ EL_TYPE(el_self) ], EL_ID(el_self));
        return el_self->h3pe_stream;
    }
    else if (el_path)
    {
        iter->h3it_cursor = CALC_EL_IDX(tree, el_path);
        LSQ_DEBUG("%s: step down to %c:%"PRIu64, iter->h3it_log_id,
                        el_type2char[ EL_TYPE(el_path) ], EL_ID(el_path));
        goto top1;
    }
    else
    {
        tree->h3pt_els[ iter->h3it_cursor ].h3pe_active_path = 0;
        iter->h3it_cursor = tree->h3pt_els[ iter->h3it_cursor ].h3pe_parent;
        LSQ_DEBUG("%s: step up to %c:%"PRIu64, iter->h3it_log_id,
                el_type2char[ EL_TYPE(&tree->h3pt_els[ iter->h3it_cursor ]) ],
                EL_ID(&tree->h3pt_els[ iter->h3it_cursor ]));
        goto top0;
    }
}


struct lsquic_stream *
lsquic_prio_tree_highest_non_crit (struct h3_prio_tree *tree)
{
    elem_idx_t idx, parent;
    struct h3_prio_elem *el;
    unsigned weight;

    parent = ROOT_IDX;

  new_level:
    /* Look for the stream */
    weight = 1u << sizeof(h3_weight_t) * 8;
    el = NULL;
    for (idx = tree->h3pt_els[ parent ].h3pe_first_child;
            idx;
                idx = tree->h3pt_els[ idx ].h3pe_right)
        if (tree->h3pt_els[ idx ].h3pe_stream
                && tree->h3pt_els[ idx ].h3pe_weight < weight)
        {
            el = &tree->h3pt_els[ idx ];
            weight = el->h3pe_weight;
        }
        else
            /* Clear new level of crumbs */
            tree->h3pt_els[ idx ].h3pe_taken = 0;

    if (el)
        return el->h3pe_stream;

  old_level:
    /* Look for paths not taken */
    weight = 1u << sizeof(h3_weight_t) * 8;
    el = NULL;
    for (idx = tree->h3pt_els[ parent ].h3pe_first_child;
            idx;
                idx = tree->h3pt_els[ idx ].h3pe_right)
        if (tree->h3pt_els[ idx ].h3pe_first_child
                && !tree->h3pt_els[ idx ].h3pe_taken
                && tree->h3pt_els[ idx ].h3pe_weight < weight)
        {
            el = &tree->h3pt_els[ idx ];
            weight = el->h3pe_weight;
        }

    if (el)
    {
        parent = CALC_EL_IDX(tree, el);
        goto new_level;
    }

    tree->h3pt_els[ parent ].h3pe_taken = 1;
    parent = tree->h3pt_els[ parent ].h3pe_parent;
    if (parent)
        goto old_level;

    return NULL;
}


static size_t
prio_tree_node_to_str (const struct h3_prio_tree *tree,
            const struct h3_prio_elem *el, char *const buf, char *const end)
{
    elem_idx_t next_idx;
    char *p;
    int sz, comma;

    if (buf >= end)
        return 0;

    p = buf;
    sz = snprintf(p, end - p, "(t: %c; id: %"PRIu64"; w: %u",
                        el_type2char[EL_TYPE(el)], EL_ID(el), el->h3pe_weight);
    if (sz > end - p)
        return end - buf;
    p += sz;

    if (el->h3pe_first_child)
    {
        sz = snprintf(p, end - p, "; c: [");
        if (sz > end - p)
            return end - buf;
        p += sz;
        next_idx = el->h3pe_first_child;
        comma = 0;
        do
        {
            if (comma)
            {
                sz = snprintf(p, end - p, ",");
                if (sz > end - p)
                    return end - buf;
                p += sz;
            }
            else
                ++comma;
            el = &tree->h3pt_els[ next_idx ];
            p += prio_tree_node_to_str(tree, el, p, end);
            if (p >= end)
                return end - buf;
        }
        while ((next_idx = el->h3pe_right));
        sz = snprintf(p, end - p, "])");
        if (sz > end - p)
            return end - buf;
        p += sz;
    }
    else
    {
        sz = snprintf(p, end - p, ")");
        if (sz > end - p)
            return end - buf;
        p += sz;
    }

    return p - buf;
}


size_t
lsquic_prio_tree_to_str (const struct h3_prio_tree *tree, char *buf,
                                                                size_t buf_sz)
{
    return prio_tree_node_to_str(tree, &tree->h3pt_els[ROOT_IDX], buf,
                                                                buf + buf_sz);
}


void
lsquic_prio_tree_set_ph (struct h3_prio_tree *tree, unsigned ph)
{
    LSQ_DEBUG("set max placeholders to %u", ph);
    tree->h3pt_max_ph = ph;
}
