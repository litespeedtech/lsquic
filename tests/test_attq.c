/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_attq.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"


static char curiosity[] =
    "Dogs say cats love too much, are irresponsible,"
    "are changeable, marry too many wives,"
    "desert their children, chill all dinner tables"
    "with tales of their nine lives."
    "Well, they are lucky. Let them be"
    "nine-lived and contradictory,"
    "curious enough to change, prepared to pay"
    "the cat price, which is to die"
    "and die again and again,"
    "each time with no less pain."
    "A cat minority of one"
    "is all that can be counted on"
    "to tell the truth. And what cats have to tell"
    "on each return from hell"
    "is this: that dying is what the living do,"
    "that dying is what the loving do,"
    "and that dead dogs are those who do not know"
    "that dying is what, to live, each has to do."
    ;


static int
cmp_chars_asc (const void *ap, const void *bp)
{
    char a = * (char *) ap;
    char b = * (char *) bp;
    return (a > b) - (b > a);
}


static int
cmp_chars_desc (const void *ap, const void *bp)
{
    char a = * (char *) ap;
    char b = * (char *) bp;
    return (a < b) - (b < a);
}


enum sort_action { SORT_NONE, SORT_ASC, SORT_DESC, };

static void
test_attq_ordering (enum sort_action sa)
{
    struct attq *q;
    struct lsquic_conn *conns, *conn;
    const struct attq_elem *next_attq;
    lsquic_time_t prev;
    lsquic_time_t t;
    unsigned i;
    int s;

    switch (sa)
    {
    case SORT_NONE:
        break;
    case SORT_ASC:
        qsort(curiosity, sizeof(curiosity) *
            sizeof(curiosity[0]), sizeof(curiosity[0]), cmp_chars_asc);
        break;
    case SORT_DESC:
        qsort(curiosity, sizeof(curiosity) *
            sizeof(curiosity[0]), sizeof(curiosity[0]), cmp_chars_desc);
        break;
    }

    q = lsquic_attq_create();

    for (i = 0; i < sizeof(curiosity); ++i)
    {
        unsigned count_before = lsquic_attq_count_before(q, curiosity[i]);
        assert(count_before == 0);
    }

    conns = calloc(sizeof(curiosity), sizeof(conns[0]));
    for (i = 0; i < sizeof(curiosity); ++i)
    {
        s = lsquic_attq_add(q, &conns[i], (lsquic_time_t) curiosity[i], 0);
        assert(s == 0);
    }

    for (i = 0; i < sizeof(curiosity); ++i)
        assert(conns[i].cn_attq_elem);

    if (sa == SORT_ASC)
    {
        unsigned counts[ sizeof(curiosity) ];
        unsigned count_before;
        counts[0] = 0;
        for (i = 1; i < sizeof(curiosity); ++i)
        {
            if (curiosity[i - 1] == curiosity[i])
                counts[i] = counts[i - 1];
            else
                counts[i] = i;
        }
        for (i = 1; i < sizeof(curiosity); ++i)
        {
            count_before = lsquic_attq_count_before(q, curiosity[i]);
            assert(count_before == counts[i]);
        }
    }

#ifdef _MSC_VER
    prev = 0;
#endif
    for (i = 0; i < sizeof(curiosity); ++i)
    {
        next_attq = lsquic_attq_next(q);
        assert(next_attq);
        t = next_attq->ae_adv_time;
        if (i > 0)
            assert(t >= prev);
        prev = t;
        conn = lsquic_attq_pop(q, ~0ULL);
        assert(conn);
    }

    next_attq = lsquic_attq_next(q);
    assert(!next_attq);
    conn = lsquic_attq_pop(q, ~0ULL);
    assert(!conn);

    free(conns);
    lsquic_attq_destroy(q);
}


/* Filter up */
static void
test_attq_removal_1 (void)
{
    struct attq *q;
    struct lsquic_conn *conns;

    q = lsquic_attq_create();
    conns = calloc(6, sizeof(conns[0]));

    lsquic_attq_add(q, &conns[0], 1, 0);
    lsquic_attq_add(q, &conns[1], 4, 0);
    lsquic_attq_add(q, &conns[2], 2, 0);
    lsquic_attq_add(q, &conns[3], 5, 0);
    lsquic_attq_add(q, &conns[4], 6, 0);
    lsquic_attq_add(q, &conns[5], 3, 0);

    lsquic_attq_remove(q, &conns[3]);

    free(conns);
    lsquic_attq_destroy(q);
}


/* Filter down */
static void
test_attq_removal_2 (void)
{
    struct attq *q;
    struct lsquic_conn *conns;

    q = lsquic_attq_create();
    conns = calloc(9, sizeof(conns[0]));

    lsquic_attq_add(q, &conns[0], 1, 0);
    lsquic_attq_add(q, &conns[1], 5, 0);
    lsquic_attq_add(q, &conns[2], 6, 0);
    lsquic_attq_add(q, &conns[3], 9, 0);
    lsquic_attq_add(q, &conns[4], 11, 0);
    lsquic_attq_add(q, &conns[5], 8, 0);
    lsquic_attq_add(q, &conns[6], 15, 0);
    lsquic_attq_add(q, &conns[7], 17, 0);
    lsquic_attq_add(q, &conns[8], 21, 0);

    lsquic_attq_remove(q, &conns[1]);

    free(conns);
    lsquic_attq_destroy(q);
}


/* Filter up */
static void
test_attq_removal_3 (void)
{
    struct attq *q;
    struct lsquic_conn *conns;

    q = lsquic_attq_create();
    conns = calloc(9, sizeof(conns[0]));

    lsquic_attq_add(q, &conns[0], 1, 0);
    lsquic_attq_add(q, &conns[1], 9, 0);
    lsquic_attq_add(q, &conns[2], 22, 0);
    lsquic_attq_add(q, &conns[3], 17, 0);
    lsquic_attq_add(q, &conns[4], 11, 0);
    lsquic_attq_add(q, &conns[5], 33, 0);
    lsquic_attq_add(q, &conns[6], 27, 0);
    lsquic_attq_add(q, &conns[7], 21, 0);
    lsquic_attq_add(q, &conns[8], 19, 0);

    lsquic_attq_remove(q, &conns[1]);

    free(conns);
    lsquic_attq_destroy(q);
}


int
main (void)
{
    test_attq_ordering(SORT_NONE);
    test_attq_ordering(SORT_ASC);
    test_attq_ordering(SORT_DESC);
    test_attq_removal_1();
    test_attq_removal_2();
    test_attq_removal_3();
    return 0;
}
