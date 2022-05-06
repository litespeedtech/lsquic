/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * http_server.c -- A simple HTTP/QUIC server
 *
 * It serves up files from the filesystem.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>

#ifndef WIN32
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#else
#include "vc_compat.h"
#include "getopt.h"
#endif

#include <event2/event.h>

#include <openssl/md5.h>

#include "lsquic.h"
#include "../src/liblsquic/lsquic_hash.h"
#include "lsxpack_header.h"
#include "test_config.h"
#include "test_common.h"
#include "test_cert.h"
#include "prog.h"

#if HAVE_REGEX
#ifndef WIN32
#include <regex.h>
#else
#include <pcreposix.h>
#endif
#endif

#include "../src/liblsquic/lsquic_logger.h"
#include "../src/liblsquic/lsquic_int_types.h"
#include "../src/liblsquic/lsquic_util.h"

#if HAVE_REGEX
static const char on_being_idle[] =
"ON BEING IDLE.\n"
"\n"
"Now, this is a subject on which I flatter myself I really am _au fait_.\n"
"The gentleman who, when I was young, bathed me at wisdom's font for nine\n"
"guineas a term--no extras--used to say he never knew a boy who could\n"
"do less work in more time; and I remember my poor grandmother once\n"
"incidentally observing, in the course of an instruction upon the use\n"
"of the Prayer-book, that it was highly improbable that I should ever do\n"
"much that I ought not to do, but that she felt convinced beyond a doubt\n"
"that I should leave undone pretty well everything that I ought to do.\n"
"\n"
"I am afraid I have somewhat belied half the dear old lady's prophecy.\n"
"Heaven help me! I have done a good many things that I ought not to have\n"
"done, in spite of my laziness. But I have fully confirmed the accuracy\n"
"of her judgment so far as neglecting much that I ought not to have\n"
"neglected is concerned. Idling always has been my strong point. I take\n"
"no credit to myself in the matter--it is a gift. Few possess it. There\n"
"are plenty of lazy people and plenty of slow-coaches, but a genuine\n"
"idler is a rarity. He is not a man who slouches about with his hands in\n"
"his pockets. On the contrary, his most startling characteristic is that\n"
"he is always intensely busy.\n"
"\n"
"It is impossible to enjoy idling thoroughly unless one has plenty of\n"
"work to do. There is no fun in doing nothing when you have nothing to\n"
"do. Wasting time is merely an occupation then, and a most exhausting\n"
"one. Idleness, like kisses, to be sweet must be stolen.\n"
"\n"
"Many years ago, when I was a young man, I was taken very ill--I never\n"
"could see myself that much was the matter with me, except that I had\n"
"a beastly cold. But I suppose it was something very serious, for the\n"
"doctor said that I ought to have come to him a month before, and that\n"
"if it (whatever it was) had gone on for another week he would not have\n"
"answered for the consequences. It is an extraordinary thing, but I\n"
"never knew a doctor called into any case yet but what it transpired\n"
"that another day's delay would have rendered cure hopeless. Our medical\n"
"guide, philosopher, and friend is like the hero in a melodrama--he\n"
"always comes upon the scene just, and only just, in the nick of time. It\n"
"is Providence, that is what it is.\n"
"\n"
"Well, as I was saying, I was very ill and was ordered to Buxton for a\n"
"month, with strict injunctions to do nothing whatever all the while\n"
"that I was there. \"Rest is what you require,\" said the doctor, \"perfect\n"
"rest.\"\n"
"\n"
"It seemed a delightful prospect. \"This man evidently understands my\n"
"complaint,\" said I, and I pictured to myself a glorious time--a four\n"
"weeks' _dolce far niente_ with a dash of illness in it. Not too much\n"
"illness, but just illness enough--just sufficient to give it the flavor\n"
"of suffering and make it poetical. I should get up late, sip chocolate,\n"
"and have my breakfast in slippers and a dressing-gown. I should lie out\n"
"in the garden in a hammock and read sentimental novels with a melancholy\n"
"ending, until the books should fall from my listless hand, and I should\n"
"recline there, dreamily gazing into the deep blue of the firmament,\n"
"watching the fleecy clouds floating like white-sailed ships across\n"
"its depths, and listening to the joyous song of the birds and the low\n"
"rustling of the trees. Or, on becoming too weak to go out of doors,\n"
"I should sit propped up with pillows at the open window of the\n"
"ground-floor front, and look wasted and interesting, so that all the\n"
"pretty girls would sigh as they passed by.\n"
"\n"
"And twice a day I should go down in a Bath chair to the Colonnade to\n"
"drink the waters. Oh, those waters! I knew nothing about them then,\n"
"and was rather taken with the idea. \"Drinking the waters\" sounded\n"
"fashionable and Queen Anne-fied, and I thought I should like them. But,\n"
"ugh! after the first three or four mornings! Sam Weller's description of\n"
"them as \"having a taste of warm flat-irons\" conveys only a faint idea of\n"
"their hideous nauseousness. If anything could make a sick man get well\n"
"quickly, it would be the knowledge that he must drink a glassful of them\n"
"every day until he was recovered. I drank them neat for six consecutive\n"
"days, and they nearly killed me; but after then I adopted the plan of\n"
"taking a stiff glass of brandy-and-water immediately on the top of them,\n"
"and found much relief thereby. I have been informed since, by various\n"
"eminent medical gentlemen, that the alcohol must have entirely\n"
"counteracted the effects of the chalybeate properties contained in the\n"
"water. I am glad I was lucky enough to hit upon the right thing.\n"
"\n"
"But \"drinking the waters\" was only a small portion of the torture I\n"
"experienced during that memorable month--a month which was, without\n"
"exception, the most miserable I have ever spent. During the best part of\n"
"it I religiously followed the doctor's mandate and did nothing whatever,\n"
"except moon about the house and garden and go out for two hours a day in\n"
"a Bath chair. That did break the monotony to a certain extent. There is\n"
"more excitement about Bath-chairing--especially if you are not used to\n"
"the exhilarating exercise--than might appear to the casual observer. A\n"
"sense of danger, such as a mere outsider might not understand, is ever\n"
"present to the mind of the occupant. He feels convinced every minute\n"
"that the whole concern is going over, a conviction which becomes\n"
"especially lively whenever a ditch or a stretch of newly macadamized\n"
"road comes in sight. Every vehicle that passes he expects is going to\n"
"run into him; and he never finds himself ascending or descending a\n"
"hill without immediately beginning to speculate upon his chances,\n"
"supposing--as seems extremely probable--that the weak-kneed controller\n"
"of his destiny should let go.\n"
"\n"
"But even this diversion failed to enliven after awhile, and the _ennui_\n"
"became perfectly unbearable. I felt my mind giving way under it. It is\n"
"not a strong mind, and I thought it would be unwise to tax it too far.\n"
"So somewhere about the twentieth morning I got up early, had a good\n"
"breakfast, and walked straight off to Hayfield, at the foot of the\n"
"Kinder Scout--a pleasant, busy little town, reached through a lovely\n"
"valley, and with two sweetly pretty women in it. At least they were\n"
"sweetly pretty then; one passed me on the bridge and, I think, smiled;\n"
"and the other was standing at an open door, making an unremunerative\n"
"investment of kisses upon a red-faced baby. But it is years ago, and I\n"
"dare say they have both grown stout and snappish since that time.\n"
"Coming back, I saw an old man breaking stones, and it roused such strong\n"
"longing in me to use my arms that I offered him a drink to let me take\n"
"his place. He was a kindly old man and he humored me. I went for those\n"
"stones with the accumulated energy of three weeks, and did more work in\n"
"half an hour than he had done all day. But it did not make him jealous.\n"
"\n"
"Having taken the plunge, I went further and further into dissipation,\n"
"going out for a long walk every morning and listening to the band in\n"
"the pavilion every evening. But the days still passed slowly\n"
"notwithstanding, and I was heartily glad when the last one came and I\n"
"was being whirled away from gouty, consumptive Buxton to London with its\n"
"stern work and life. I looked out of the carriage as we rushed through\n"
"Hendon in the evening. The lurid glare overhanging the mighty city\n"
"seemed to warm my heart, and when, later on, my cab rattled out of St.\n"
"Pancras' station, the old familiar roar that came swelling up around me\n"
"sounded the sweetest music I had heard for many a long day.\n"
"\n"
"I certainly did not enjoy that month's idling. I like idling when I\n"
"ought not to be idling; not when it is the only thing I have to do. That\n"
"is my pig-headed nature. The time when I like best to stand with my\n"
"back to the fire, calculating how much I owe, is when my desk is heaped\n"
"highest with letters that must be answered by the next post. When I like\n"
"to dawdle longest over my dinner is when I have a heavy evening's work\n"
"before me. And if, for some urgent reason, I ought to be up particularly\n"
"early in the morning, it is then, more than at any other time, that I\n"
"love to lie an extra half-hour in bed.\n"
"\n"
"Ah! how delicious it is to turn over and go to sleep again: \"just for\n"
"five minutes.\" Is there any human being, I wonder, besides the hero of\n"
"a Sunday-school \"tale for boys,\" who ever gets up willingly? There\n"
"are some men to whom getting up at the proper time is an utter\n"
"impossibility. If eight o'clock happens to be the time that they should\n"
"turn out, then they lie till half-past. If circumstances change and\n"
"half-past eight becomes early enough for them, then it is nine before\n"
"they can rise. They are like the statesman of whom it was said that he\n"
"was always punctually half an hour late. They try all manner of schemes.\n"
"They buy alarm-clocks (artful contrivances that go off at the wrong time\n"
"and alarm the wrong people). They tell Sarah Jane to knock at the door\n"
"and call them, and Sarah Jane does knock at the door and does call them,\n"
"and they grunt back \"awri\" and then go comfortably to sleep again. I\n"
"knew one man who would actually get out and have a cold bath; and even\n"
"that was of no use, for afterward he would jump into bed again to warm\n"
"himself.\n"
"\n"
"I think myself that I could keep out of bed all right if I once got\n"
"out. It is the wrenching away of the head from the pillow that I find so\n"
"hard, and no amount of over-night determination makes it easier. I say\n"
"to myself, after having wasted the whole evening, \"Well, I won't do\n"
"any more work to-night; I'll get up early to-morrow morning;\" and I am\n"
"thoroughly resolved to do so--then. In the morning, however, I feel less\n"
"enthusiastic about the idea, and reflect that it would have been much\n"
"better if I had stopped up last night. And then there is the trouble of\n"
"dressing, and the more one thinks about that the more one wants to put\n"
"it off.\n"
"\n"
"It is a strange thing this bed, this mimic grave, where we stretch our\n"
"tired limbs and sink away so quietly into the silence and rest. \"O bed,\n"
"O bed, delicious bed, that heaven on earth to the weary head,\" as sang\n"
"poor Hood, you are a kind old nurse to us fretful boys and girls. Clever\n"
"and foolish, naughty and good, you take us all in your motherly lap and\n"
"hush our wayward crying. The strong man full of care--the sick man\n"
"full of pain--the little maiden sobbing for her faithless lover--like\n"
"children we lay our aching heads on your white bosom, and you gently\n"
"soothe us off to by-by.\n"
"\n"
"Our trouble is sore indeed when you turn away and will not comfort us.\n"
"How long the dawn seems coming when we cannot sleep! Oh! those hideous\n"
"nights when we toss and turn in fever and pain, when we lie, like living\n"
"men among the dead, staring out into the dark hours that drift so slowly\n"
"between us and the light. And oh! those still more hideous nights when\n"
"we sit by another in pain, when the low fire startles us every now and\n"
"then with a falling cinder, and the tick of the clock seems a hammer\n"
"beating out the life that we are watching.\n"
"\n"
"But enough of beds and bedrooms. I have kept to them too long, even for\n"
"an idle fellow. Let us come out and have a smoke. That wastes time just\n"
"as well and does not look so bad. Tobacco has been a blessing to us\n"
"idlers. What the civil-service clerk before Sir Walter's time found\n"
"to occupy their minds with it is hard to imagine. I attribute the\n"
"quarrelsome nature of the Middle Ages young men entirely to the want of\n"
"the soothing weed. They had no work to do and could not smoke, and\n"
"the consequence was they were forever fighting and rowing. If, by any\n"
"extraordinary chance, there was no war going, then they got up a deadly\n"
"family feud with the next-door neighbor, and if, in spite of this, they\n"
"still had a few spare moments on their hands, they occupied them with\n"
"discussions as to whose sweetheart was the best looking, the arguments\n"
"employed on both sides being battle-axes, clubs, etc. Questions of taste\n"
"were soon decided in those days. When a twelfth-century youth fell in\n"
"love he did not take three paces backward, gaze into her eyes, and tell\n"
"her she was too beautiful to live. He said he would step outside and see\n"
"about it. And if, when he got out, he met a man and broke his head--the\n"
"other man's head, I mean--then that proved that his--the first\n"
"fellow's--girl was a pretty girl. But if the other fellow broke _his_\n"
"head--not his own, you know, but the other fellow's--the other fellow\n"
"to the second fellow, that is, because of course the other fellow would\n"
"only be the other fellow to him, not the first fellow who--well, if he\n"
"broke his head, then _his_ girl--not the other fellow's, but the fellow\n"
"who _was_ the--Look here, if A broke B's head, then A's girl was a\n"
"pretty girl; but if B broke A's head, then A's girl wasn't a pretty\n"
"girl, but B's girl was. That was their method of conducting art\n"
"criticism.\n"
"\n"
"Nowadays we light a pipe and let the girls fight it out among\n"
"themselves.\n"
"\n"
"They do it very well. They are getting to do all our work. They are\n"
"doctors, and barristers, and artists. They manage theaters, and promote\n"
"swindles, and edit newspapers. I am looking forward to the time when we\n"
"men shall have nothing to do but lie in bed till twelve, read two novels\n"
"a day, have nice little five-o'clock teas all to ourselves, and tax\n"
"our brains with nothing more trying than discussions upon the latest\n"
"patterns in trousers and arguments as to what Mr. Jones' coat was\n"
"made of and whether it fitted him. It is a glorious prospect--for idle\n"
"fellows.\n"
"\n\n\n"
;
static const size_t IDLE_SIZE = sizeof(on_being_idle) - 1;
#endif

/* This is the "LSWS" mode: first write is performed immediately, outside
 * of the on_write() callback.  This makes it possible to play with buffered
 * packet queues.
 */
static int s_immediate_write;

/* Use preadv(2) in conjuction with lsquic_stream_pwritev() to reduce
 * number of system calls required to read from disk.  The actual value
 * specifies maximum write size.  A negative value indicates always to use
 * the remaining file size.
 */
static ssize_t s_pwritev;

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define V(v) (v), strlen(v)

struct lsquic_conn_ctx;

static void interop_server_hset_destroy (void *);


struct server_ctx {
    struct lsquic_conn_ctx  *conn_h;
    lsquic_engine_t             *engine;
    const char                  *document_root;
    const char                  *push_path;
    struct sport_head            sports;
    struct prog                 *prog;
    unsigned                     max_conn;
    unsigned                     n_conn;
    unsigned                     n_current_conns;
    unsigned                     delay_resp_sec;
};

struct lsquic_conn_ctx {
    lsquic_conn_t       *conn;
    struct server_ctx   *server_ctx;
    enum {
        RECEIVED_GOAWAY = 1 << 0,
    }                    flags;
};


static lsquic_conn_ctx_t *
http_server_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct server_ctx *server_ctx = stream_if_ctx;
    const char *sni;

    sni = lsquic_conn_get_sni(conn);
    LSQ_DEBUG("new connection, SNI: %s", sni ? sni : "<not set>");

    lsquic_conn_ctx_t *conn_h = malloc(sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->server_ctx = server_ctx;
    server_ctx->conn_h = conn_h;
    ++server_ctx->n_current_conns;
    return conn_h;
}


static void
http_server_on_goaway (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    conn_h->flags |= RECEIVED_GOAWAY;
    LSQ_INFO("received GOAWAY");
}


static void
http_server_on_conn_closed (lsquic_conn_t *conn)
{
    static int stopped;
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    LSQ_INFO("Connection closed");
    --conn_h->server_ctx->n_current_conns;
    if ((conn_h->server_ctx->prog->prog_flags & PROG_FLAG_COOLDOWN)
                                && 0 == conn_h->server_ctx->n_current_conns)
    {
        if (!stopped)
        {
            stopped = 1;
            prog_stop(conn_h->server_ctx->prog);
        }
    }
    if (conn_h->server_ctx->max_conn > 0)
    {
        ++conn_h->server_ctx->n_conn;
        LSQ_NOTICE("Connection closed, remaining: %d",
                   conn_h->server_ctx->max_conn - conn_h->server_ctx->n_conn);
        if (conn_h->server_ctx->n_conn >= conn_h->server_ctx->max_conn)
        {
            if (!stopped)
            {
                stopped = 1;
                prog_stop(conn_h->server_ctx->prog);
            }
        }
    }
    /* No provision is made to stop HTTP server */
    free(conn_h);
}


struct resp
{
    const char      *buf;
    size_t           sz;
    size_t           off;
};


struct index_html_ctx
{
    struct resp resp;
};


struct ver_head_ctx
{
    struct resp resp;
    unsigned char   *req_body;
    size_t           req_sz;    /* Expect it to be the same as qif_sz */
};


struct md5sum_ctx
{
    char        resp_buf[0x100];
    MD5_CTX     md5ctx;
    struct resp resp;
    int         done;
};


struct req
{
    enum method {
        UNSET, GET, POST, UNSUPPORTED,
    }            method;
    enum {
        HAVE_XHDR   = 1 << 0,
    }            flags;
    enum {
        PH_AUTHORITY    = 1 << 0,
        PH_METHOD       = 1 << 1,
        PH_PATH         = 1 << 2,
    }            pseudo_headers;
    char        *path;
    char        *method_str;
    char        *authority_str;
    char        *qif_str;
    size_t       qif_sz;
    struct lsxpack_header
                 xhdr;
    size_t       decode_off;
    char         decode_buf[MIN(LSXPACK_MAX_STRLEN + 1, 64 * 1024)];
};


struct interop_push_path
{
    STAILQ_ENTRY(interop_push_path)     next;
    char                                path[0];
};


struct gen_file_ctx
{
    STAILQ_HEAD(, interop_push_path)    push_paths;
    size_t      remain;
    unsigned    idle_off;
};


struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct server_ctx   *server_ctx;
    FILE                *req_fh;
    char                *req_buf;
    char                *req_filename;
    char                *req_path;
    size_t               req_sz;
    enum {
        SH_HEADERS_SENT = (1 << 0),
        SH_DELAYED      = (1 << 1),
        SH_HEADERS_READ = (1 << 2),
    }                    flags;
    struct lsquic_reader reader;
    int                  file_fd;   /* Used by pwritev */

    /* Fields below are used by interop callbacks: */
    enum interop_handler {
        IOH_ERROR,
        IOH_INDEX_HTML,
        IOH_MD5SUM,
        IOH_VER_HEAD,
        IOH_GEN_FILE,
        IOH_ECHO,
    }                    interop_handler;
    struct req          *req;
    const char          *resp_status;
    union {
        struct index_html_ctx   ihc;
        struct ver_head_ctx     vhc;
        struct md5sum_ctx       md5c;
        struct gen_file_ctx     gfc;
        struct {
            char buf[0x100];
            struct resp resp;
        }                       err;
    }                    interop_u;
    struct event        *resume_resp;
    size_t               written;
    size_t               file_size; /* Used by pwritev */
};


static lsquic_stream_ctx_t *
http_server_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    lsquic_stream_ctx_t *st_h = calloc(1, sizeof(*st_h));
    st_h->stream = stream;
    st_h->server_ctx = stream_if_ctx;
    lsquic_stream_wantread(stream, 1);
    return st_h;
}


static int
ends_with (const char *filename, const char *ext)
{
    const char *where;

    where = strstr(filename, ext);
    return where
        && strlen(where) == strlen(ext);
}


static const char *
select_content_type (lsquic_stream_ctx_t *st_h)
{
    if (     ends_with(st_h->req_filename, ".html"))
        return "text/html";
    else if (ends_with(st_h->req_filename, ".png"))
        return "image/png";
    else if (ends_with(st_h->req_filename, ".css"))
        return "text/css";
    else if (ends_with(st_h->req_filename, ".gif"))
        return "image/gif";
    else if (ends_with(st_h->req_filename, ".txt"))
        return "text/plain";
    else
        return "application/octet-stream";
}


static int
send_headers (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
    const char *content_type;
    struct header_buf hbuf;

    content_type = select_content_type(st_h);
    struct lsxpack_header headers_arr[2];

    hbuf.off = 0;
    header_set_ptr(&headers_arr[0], &hbuf, ":status", 7, "200", 3);
    header_set_ptr(&headers_arr[1], &hbuf, "content-type", 12,
                                        content_type, strlen(content_type));
    lsquic_http_headers_t headers = {
        .count = sizeof(headers_arr) / sizeof(headers_arr[0]),
        .headers = headers_arr,
    };
    if (0 != lsquic_stream_send_headers(stream, &headers, 0))
    {
        LSQ_ERROR("cannot send headers: %s", strerror(errno));
        return -1;
    }

    st_h->flags |= SH_HEADERS_SENT;
    return 0;
}


static void
resume_response (evutil_socket_t fd, short what, void *arg)
{
    struct lsquic_stream_ctx *const st_h = arg;

    lsquic_stream_wantwrite(st_h->stream, 1);
    event_del(st_h->resume_resp);
    event_free(st_h->resume_resp);
    st_h->resume_resp = NULL;

    LSQ_NOTICE("resume response to stream %"PRIu64,
                                                lsquic_stream_id(st_h->stream));
    prog_process_conns(st_h->server_ctx->prog);
}


static size_t
bytes_left (lsquic_stream_ctx_t *st_h)
{
    if (s_pwritev)
        return st_h->file_size - st_h->written;
    else
        return test_reader_size(st_h->reader.lsqr_ctx);
}


static ssize_t
my_preadv (void *user_data, const struct iovec *iov, int iovcnt)
{
#if HAVE_PREADV
    lsquic_stream_ctx_t *const st_h = user_data;
    ssize_t nread = preadv(st_h->file_fd, iov, iovcnt, st_h->written);
    LSQ_DEBUG("%s: wrote %zd bytes", __func__, (size_t) nread);
    return nread;
#else
    return -1;
#endif
}


static size_t
pwritev_fallback_read (void *lsqr_ctx, void *buf, size_t count)
{
    lsquic_stream_ctx_t *const st_h = lsqr_ctx;
    struct iovec iov;
    size_t ntoread;

    ntoread = st_h->file_size - st_h->written;
    if (ntoread > count)
        count = ntoread;
    iov.iov_base = buf;
    iov.iov_len = count;
    return my_preadv(lsqr_ctx, &iov, 1);
}


static size_t
pwritev_fallback_size (void *lsqr_ctx)
{
    lsquic_stream_ctx_t *const st_h = lsqr_ctx;
    return st_h->file_size - st_h->written;
}


static void
http_server_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    if (st_h->flags & SH_HEADERS_SENT)
    {
        ssize_t nw;
        if (bytes_left(st_h) > 0)
        {
            if (st_h->server_ctx->delay_resp_sec
                    && !(st_h->flags & SH_DELAYED)
                        && st_h->written > 10000000)
            {
                struct timeval delay = {
                                .tv_sec = st_h->server_ctx->delay_resp_sec, };
                st_h->resume_resp = event_new(st_h->server_ctx->prog->prog_eb,
                            -1, EV_TIMEOUT, resume_response, st_h);
                if (st_h->resume_resp)
                {
                    event_add(st_h->resume_resp, &delay);
                    lsquic_stream_wantwrite(stream, 0);
                    st_h->flags |= SH_DELAYED;
                    LSQ_NOTICE("delay response of stream %"PRIu64" for %u seconds",
                        lsquic_stream_id(stream), st_h->server_ctx->delay_resp_sec);
                    return;
                }
                else
                    LSQ_ERROR("cannot allocate event");
            }
            if (s_pwritev)
            {
                size_t to_write = bytes_left(st_h);
                if (s_pwritev > 0 && (size_t) s_pwritev < to_write)
                    to_write = s_pwritev;
                nw = lsquic_stream_pwritev(stream, my_preadv, st_h, to_write);
                if (nw == 0)
                {
                    struct lsquic_reader reader = {
                        .lsqr_read = pwritev_fallback_read,
                        .lsqr_size = pwritev_fallback_size,
                        .lsqr_ctx = st_h,
                    };
                    nw = lsquic_stream_writef(stream, &reader);
                }
            }
            else
            {
                nw = lsquic_stream_writef(stream, &st_h->reader);
            }
            if (nw < 0)
            {
                struct lsquic_conn *conn = lsquic_stream_conn(stream);
                lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
                if (conn_h->flags & RECEIVED_GOAWAY)
                {
                    LSQ_NOTICE("cannot write: goaway received");
                    lsquic_stream_close(stream);
                }
                else
                {
                    LSQ_ERROR("write error: %s", strerror(errno));
                    exit(1);
                }
            }
            if (bytes_left(st_h) > 0)
            {
                st_h->written += (size_t) nw;
                lsquic_stream_wantwrite(stream, 1);
            }
            else
            {
                lsquic_stream_shutdown(stream, 1);
                lsquic_stream_wantread(stream, 1);
            }
        }
        else
        {
            lsquic_stream_shutdown(stream, 1);
            lsquic_stream_wantread(stream, 1);
        }
    }
    else
    {
        if (0 != send_headers(stream, st_h))
            exit(1);
    }
}


struct capped_reader_ctx
{
    struct lsquic_reader *inner_reader;
    size_t                nread;
};


static size_t
capped_reader_size (void *void_ctx)
{
    struct capped_reader_ctx *const capped_reader_ctx = void_ctx;
    struct lsquic_reader *const inner_reader = capped_reader_ctx->inner_reader;
    size_t size;

    size = inner_reader->lsqr_size(inner_reader->lsqr_ctx);
    return MIN((size_t) (s_immediate_write - capped_reader_ctx->nread), size);
}


static size_t
capped_reader_read (void *void_ctx, void *buf, size_t count)
{
    struct capped_reader_ctx *const capped_reader_ctx = void_ctx;
    struct lsquic_reader *const inner_reader = capped_reader_ctx->inner_reader;
    size_t size;

    count = MIN(count, (size_t) (s_immediate_write - capped_reader_ctx->nread));
    size = inner_reader->lsqr_read(inner_reader->lsqr_ctx, buf, count);
    capped_reader_ctx->nread += size;
    return size;
}


#if HAVE_OPEN_MEMSTREAM
static void
parse_request (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
    char *filename;
    int s;
    regex_t re;
    regmatch_t matches[2];

    s = regcomp(&re, "GET (.*) HTTP/1.[01]\r\n", REG_EXTENDED);
    if (0 != s)
    {
        perror("regcomp");
        exit(3);
    }

    s = regexec(&re, st_h->req_buf, 2, matches, 0);
    if (0 != s)
    {
        LSQ_WARN("GET request could not be parsed: `%s'", st_h->req_buf);
        regfree(&re);
        return;
    }

    regfree(&re);

    filename = malloc(strlen(st_h->server_ctx->document_root) + 1 +
                                matches[1].rm_eo - matches[1].rm_so + 1);
    strcpy(filename, st_h->server_ctx->document_root);
    strcat(filename, "/");
    strncat(filename, st_h->req_buf + matches[1].rm_so,
                                        matches[1].rm_eo - matches[1].rm_so);

    LSQ_INFO("filename to fetch: %s", filename);

    st_h->req_filename = filename;
    st_h->req_path     = strdup(filename);
}


static void
process_request (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
    struct stat st;

    if (s_pwritev)
    {
        st_h->file_fd = open(st_h->req_path, O_RDONLY);
        if (st_h->file_fd < 0)
        {
            LSQ_ERROR("cannot open %s for reading: %s", st_h->req_path,
                                                            strerror(errno));
            exit(1);
        }
        if (fstat(st_h->file_fd, &st) < 0)
        {
            LSQ_ERROR("fstat: %s", strerror(errno));
            exit(1);
        }
        st_h->file_size = st.st_size;
    }
    else
    {
        st_h->reader.lsqr_read = test_reader_read;
        st_h->reader.lsqr_size = test_reader_size;
        st_h->reader.lsqr_ctx = create_lsquic_reader_ctx(st_h->req_path);
        if (!st_h->reader.lsqr_ctx)
            exit(1);
    }

    if (s_immediate_write)
    {
        if (0 != send_headers(stream, st_h))
            exit(1);

        if (test_reader_size(st_h->reader.lsqr_ctx) > 0)
        {
            struct capped_reader_ctx capped_reader_ctx =
            {
                .inner_reader = &st_h->reader,
            };
            struct lsquic_reader capped_reader =
            {
                .lsqr_read  = capped_reader_read,
                .lsqr_size  = capped_reader_size,
                .lsqr_ctx   = &capped_reader_ctx,
            };
            ssize_t nw;
            nw = lsquic_stream_writef(stream, &capped_reader);
            if (nw < 0)
            {
                LSQ_ERROR("write error: %s", strerror(errno));
                exit(1);
            }
        }

        if (test_reader_size(st_h->reader.lsqr_ctx) > 0)
        {
            lsquic_stream_flush(stream);
            lsquic_stream_wantwrite(stream, 1);
        }
        else
        {
            lsquic_stream_shutdown(stream, 1);
            lsquic_stream_wantread(stream, 1);
        }
    }
    else
        lsquic_stream_wantwrite(st_h->stream, 1);
}


static struct hset_fm      /* FM stands for Filesystem Mode */
{
    unsigned    id;
    char       *path;
} *
new_hset_fm (const char *path)
{
    static unsigned hfm_id;
    struct hset_fm *const hfm = malloc(sizeof(*hfm));
    char *const str = strdup(path);
    if (hfm && path)
    {
        hfm->id = hfm_id++;
        hfm->path = str;
        return hfm;
    }
    else
    {
        free(str);
        free(hfm);
        return NULL;
    }
}


static void
destroy_hset_fm (struct hset_fm *hfm)
{
    free(hfm->path);
    free(hfm);
}


static int
push_promise (lsquic_stream_ctx_t *st_h, lsquic_stream_t *stream)
{
    lsquic_conn_t *conn;
    int s;
    regex_t re;
    regmatch_t matches[2];
    struct hset_fm *hfm;
    struct header_buf hbuf;

    s = regcomp(&re, "\r\nHost: *([[:alnum:].][[:alnum:].]*)\r\n",
                                                    REG_EXTENDED|REG_ICASE);
    if (0 != s)
    {
        perror("regcomp");
        exit(3);
    }

    s = regexec(&re, st_h->req_buf, 2, matches, 0);
    if (0 != s)
    {
        LSQ_WARN("Could not find host header in request `%s'", st_h->req_buf);
        regfree(&re);
        return -1;
    }
    regfree(&re);

    hfm = new_hset_fm(st_h->server_ctx->push_path);
    if (!hfm)
    {
        LSQ_WARN("Could not allocate hfm");
        return -1;
    }

#define V(v) (v), strlen(v)
    hbuf.off = 0;
    struct lsxpack_header headers_arr[6];
    header_set_ptr(&headers_arr[0], &hbuf, V(":method"), V("GET"));
    header_set_ptr(&headers_arr[1], &hbuf, V(":path"),
                                            V(st_h->server_ctx->push_path));
    header_set_ptr(&headers_arr[2], &hbuf, V(":authority"),
        st_h->req_buf + matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);
    header_set_ptr(&headers_arr[3], &hbuf, V(":scheme"), V("https"));
    header_set_ptr(&headers_arr[4], &hbuf, V("x-some-header"),
                                                        V("x-some-value"));
    header_set_ptr(&headers_arr[5], &hbuf, V("x-kenny-status"),
                        V("Oh my God!  They killed Kenny!!!  You bastards!"));
    lsquic_http_headers_t headers = {
        .count = sizeof(headers_arr) / sizeof(headers_arr[0]),
        .headers = headers_arr,
    };

    conn = lsquic_stream_conn(stream);
    s = lsquic_conn_push_stream(conn, hfm, stream, &headers);
    if (0 == s)
        LSQ_NOTICE("pushed stream successfully");
    else
    {
        destroy_hset_fm(hfm);
        LSQ_ERROR("could not push stream: %s", strerror(errno));
    }

    return 0;
}


static void
http_server_on_read_pushed (struct lsquic_stream *stream,
                                                    lsquic_stream_ctx_t *st_h)
{
    struct hset_fm *hfm;

    hfm = lsquic_stream_get_hset(stream);
    if (!hfm)
    {
        LSQ_ERROR("%s: error fetching hset: %s", __func__, strerror(errno));
        lsquic_stream_close(stream);
        return;
    }

    LSQ_INFO("got push request #%u for %s", hfm->id, hfm->path);
    st_h->req_path = malloc(strlen(st_h->server_ctx->document_root) + 1 +
                                strlen(hfm->path) + 1);
    strcpy(st_h->req_path, st_h->server_ctx->document_root);
    strcat(st_h->req_path, "/");
    strcat(st_h->req_path, hfm->path);
    st_h->req_filename = strdup(st_h->req_path);  /* XXX Only used for ends_with: drop it? */

    process_request(stream, st_h);
    free(st_h->req_buf);
    lsquic_stream_shutdown(stream, 0);
    destroy_hset_fm(hfm);
}


static void
http_server_on_read_regular (struct lsquic_stream *stream,
                                                    lsquic_stream_ctx_t *st_h)
{
    unsigned char buf[0x400];
    ssize_t nread;
    int s;

    if (!st_h->req_fh)
        st_h->req_fh = open_memstream(&st_h->req_buf, &st_h->req_sz);

    nread = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nread > 0)
        fwrite(buf, 1, nread, st_h->req_fh);
    else if (0 == nread)
    {
        fwrite("", 1, 1, st_h->req_fh);  /* NUL-terminate so that we can regex the string */
        fclose(st_h->req_fh);
        LSQ_INFO("got request: `%.*s'", (int) st_h->req_sz, st_h->req_buf);
        parse_request(stream, st_h);
        if (st_h->server_ctx->push_path &&
                0 != strcmp(st_h->req_path, st_h->server_ctx->push_path))
        {
            s = push_promise(st_h, stream);
            if (s != 0)
                exit(1);
        }
        process_request(stream, st_h);
        free(st_h->req_buf);
        lsquic_stream_shutdown(stream, 0);
    }
    else
    {
        LSQ_ERROR("error reading: %s", strerror(errno));
        lsquic_stream_close(stream);
    }
}
#endif


static void
http_server_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
#if HAVE_OPEN_MEMSTREAM
    if (lsquic_stream_is_pushed(stream))
        http_server_on_read_pushed(stream, st_h);
    else
        http_server_on_read_regular(stream, st_h);
#else
    LSQ_ERROR("%s: open_memstream not supported\n", __func__);
    exit(1);
#endif
}


static void
http_server_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    free(st_h->req_filename);
    free(st_h->req_path);
    if (st_h->reader.lsqr_ctx)
        destroy_lsquic_reader_ctx(st_h->reader.lsqr_ctx);
#if HAVE_PREADV
    if (s_pwritev)
        close(st_h->file_fd);
#endif
    if (st_h->req)
        interop_server_hset_destroy(st_h->req);
    free(st_h);
    LSQ_INFO("%s called, has unacked data: %d", __func__,
                                lsquic_stream_has_unacked_data(stream));
}


const struct lsquic_stream_if http_server_if = {
    .on_new_conn            = http_server_on_new_conn,
    .on_conn_closed         = http_server_on_conn_closed,
    .on_new_stream          = http_server_on_new_stream,
    .on_read                = http_server_on_read,
    .on_write               = http_server_on_write,
    .on_close               = http_server_on_close,
    .on_goaway_received     = http_server_on_goaway,
};


#if HAVE_OPEN_MEMSTREAM
static void
hq_server_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
    char tbuf[0x100], *buf;
    ssize_t nread;
    char *path, *end, *filename;

    if (!st_h->req_fh)
        st_h->req_fh = open_memstream(&st_h->req_buf, &st_h->req_sz);

    nread = lsquic_stream_read(stream, tbuf, sizeof(tbuf));
    if (nread > 0)
    {
        fwrite(tbuf, 1, nread, st_h->req_fh);
        return;
    }

    if (nread < 0)
    {
        LSQ_WARN("error reading request from stream: %s", strerror(errno));
        lsquic_stream_close(stream);
        return;
    }

    fwrite("", 1, 1, st_h->req_fh);
    fclose(st_h->req_fh);
    LSQ_INFO("got request: `%.*s'", (int) st_h->req_sz, st_h->req_buf);

    buf = st_h->req_buf;
    path = strchr(buf, ' ');
    if (!path)
    {
        LSQ_WARN("invalid request (no space character): `%s'", buf);
        lsquic_stream_close(stream);
        return;
    }
    if (!(path - buf == 3 && 0 == strncasecmp(buf, "GET", 3)))
    {
        LSQ_NOTICE("unsupported method `%.*s'", (int) (path - buf), buf);
        lsquic_stream_close(stream);
        return;
    }
    ++path;
    for (end = buf + st_h->req_sz - 1; end > path
                && (*end == '\0' || *end == '\r' || *end == '\n'); --end)
        *end = '\0';
    LSQ_NOTICE("parsed out request path: %s", path);

    filename = malloc(strlen(st_h->server_ctx->document_root) + 1 + strlen(path) + 1);
    strcpy(filename, st_h->server_ctx->document_root);
    strcat(filename, "/");
    strcat(filename, path);
    LSQ_NOTICE("file to fetch: %s", filename);
    /* XXX This copy pasta is getting a bit annoying now: two mallocs of the
     * same thing?
     */
    st_h->req_filename = filename;
    st_h->req_path = strdup(filename);
    st_h->reader.lsqr_read = test_reader_read;
    st_h->reader.lsqr_size = test_reader_size;
    st_h->reader.lsqr_ctx = create_lsquic_reader_ctx(st_h->req_path);
    if (!st_h->reader.lsqr_ctx)
    {
        lsquic_stream_close(stream);
        return;
    }
    lsquic_stream_shutdown(stream, 0);
    lsquic_stream_wantwrite(stream, 1);
}


static void
hq_server_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
    ssize_t nw;

    nw = lsquic_stream_writef(stream, &st_h->reader);
    if (nw < 0)
    {
        struct lsquic_conn *conn = lsquic_stream_conn(stream);
        lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
        if (conn_h->flags & RECEIVED_GOAWAY)
        {
            LSQ_NOTICE("cannot write: goaway received");
            lsquic_stream_close(stream);
        }
        else
        {
            LSQ_ERROR("write error: %s", strerror(errno));
            lsquic_stream_close(stream);
        }
    }
    else if (bytes_left(st_h) > 0)
    {
        st_h->written += (size_t) nw;
        lsquic_stream_wantwrite(stream, 1);
    }
    else
    {
        lsquic_stream_shutdown(stream, 1);
        lsquic_stream_wantread(stream, 1);
    }
}


const struct lsquic_stream_if hq_server_if = {
    .on_new_conn            = http_server_on_new_conn,
    .on_conn_closed         = http_server_on_conn_closed,
    .on_new_stream          = http_server_on_new_stream,
    .on_read                = hq_server_on_read,
    .on_write               = hq_server_on_write,
    .on_close               = http_server_on_close,
};
#endif


#if HAVE_REGEX
struct req_map
{
    enum method             method;
    const char             *path;
    enum interop_handler    handler;
    const char             *status;
    enum {
        RM_WANTBODY     = 1 << 0,
        RM_REGEX        = 1 << 1,
        RM_COMPILED     = 1 << 2,
    }                       flags;
    regex_t                 re;
};


static struct req_map req_maps[] =
{
    { .method = GET, .path = "/", .handler = IOH_INDEX_HTML, .status = "200", .flags = 0, },
    { .method = GET, .path = "/index.html", .handler = IOH_INDEX_HTML, .status = "200", .flags = 0, },
    { .method = POST, .path = "/cgi-bin/md5sum.cgi", .handler = IOH_MD5SUM, .status = "200", .flags = RM_WANTBODY, },
    { .method = POST, .path = "/cgi-bin/verify-headers.cgi", .handler = IOH_VER_HEAD, .status = "200", .flags = RM_WANTBODY, },
    { .method = GET, .path = "^/([0-9][0-9]*)([KMG]?)$", .handler = IOH_GEN_FILE, .status = "200", .flags = RM_REGEX, },
    { .method = GET, .path = "^/([0-9][0-9]*)([KMG]?)\\?push=([^&]*)$", .handler = IOH_GEN_FILE, .status = "200", .flags = RM_REGEX, },
    { .method = GET, .path = "^/([0-9][0-9]*)([KMG]?)\\?push=([^&]*)&push=([^&]*)$", .handler = IOH_GEN_FILE, .status = "200", .flags = RM_REGEX, },
    { .method = GET, .path = "^/([0-9][0-9]*)([KMG]?)\\?push=([^&]*)&push=([^&]*)&push=([^&]*)$", .handler = IOH_GEN_FILE, .status = "200", .flags = RM_REGEX, },
    { .method = GET, .path = "^/file-([0-9][0-9]*)([KMG]?)$", .handler = IOH_GEN_FILE, .status = "200", .flags = RM_REGEX, },
    { .method = GET, .path = "^/file-([0-9][0-9]*)([KMG]?)\\?push=([^&]*)$", .handler = IOH_GEN_FILE, .status = "200", .flags = RM_REGEX, },
    { .method = GET, .path = "^/file-([0-9][0-9]*)([KMG]?)\\?push=([^&]*)&push=([^&]*)$", .handler = IOH_GEN_FILE, .status = "200", .flags = RM_REGEX, },
    { .method = GET, .path = "^/file-([0-9][0-9]*)([KMG]?)\\?push=([^&]*)&push=([^&]*)&push=([^&]*)$", .handler = IOH_GEN_FILE, .status = "200", .flags = RM_REGEX, },
};


#define MAX_MATCHES 5


static void
init_map_regexes (void)
{
    struct req_map *map;

    for (map = req_maps; map < req_maps + sizeof(req_maps)
                                            / sizeof(req_maps[0]); ++map)
        if (map->flags & RM_REGEX)
        {
#ifndef NDEBUG
            int s;
            s =
#endif
            regcomp(&map->re, map->path, REG_EXTENDED|REG_ICASE);
            assert(0 == s);
            map->flags |= RM_COMPILED;
        }
}


static void
free_map_regexes (void)
{
    struct req_map *map;

    for (map = req_maps; map < req_maps + sizeof(req_maps)
                                            / sizeof(req_maps[0]); ++map)
        if (map->flags & RM_COMPILED)
        {
            regfree(&map->re);
            map->flags &= ~RM_COMPILED;
        }
}


static const struct req_map *
find_handler (enum method method, const char *path, regmatch_t *matches)
{
    const struct req_map *map;

    for (map = req_maps; map < req_maps + sizeof(req_maps)
                                            / sizeof(req_maps[0]); ++map)
        if (map->flags & RM_COMPILED)
        {
            if (0 == regexec(&map->re, path, MAX_MATCHES + 1, matches, 0))
                return map;
        }
        else if (0 == strcasecmp(path, map->path))
            return map;

    return NULL;
}


static const char INDEX_HTML[] =
"<html>\n"
"   <head>\n"
"       <title>LiteSpeed IETF QUIC Server Index Page</title>\n"
"   </head>\n"
"   <body>\n"
"       <h1>LiteSpeed IETF QUIC Server Index Page</h1>\n"
"       <p>Hello!  Welcome to the interop.  Available services:\n"
"       <ul>\n"
"           <li><b>POST to /cgi-bin/md5sum.cgi</b>.  This will return\n"
"                   MD5 checksum of the request body.\n"
"           <li><b>GET /123K</b> or <b>GET /file-123K</b>.  This will return\n"
"                   requested number of payload in the form of repeating text\n"
"                   by Jerome K. Jerome.  The size specification must match\n"
"                   (\\d+)[KMG]? and the total size request must not exceed\n"
"                   2 gigabytes.  Then, you will get back that many bytes\n"
"                   of the <a\n"
"                       href=http://www.gutenberg.org/cache/epub/849/pg849.txt\n"
"                                                       >beloved classic</a>.\n"
"       </ul>\n"
"   </body>\n"
"</html>\n"
;


static size_t
read_md5 (void *ctx, const unsigned char *buf, size_t sz, int fin)
{
    struct lsquic_stream_ctx *st_h = ctx;

    if (sz)
        MD5_Update(&st_h->interop_u.md5c.md5ctx, buf, sz);

    if (fin)
        st_h->interop_u.md5c.done = 1;

    return sz;
}


static void
http_server_interop_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
#define ERROR_RESP(code, ...) do {  \
    LSQ_WARN(__VA_ARGS__);                                     \
    st_h->interop_handler = IOH_ERROR; \
    st_h->resp_status = #code;  \
    st_h->interop_u.err.resp.sz = snprintf(st_h->interop_u.err.buf, \
                            sizeof(st_h->interop_u.err.buf), __VA_ARGS__);  \
    if (st_h->interop_u.err.resp.sz >= sizeof(st_h->interop_u.err.buf))     \
        st_h->interop_u.err.resp.sz = sizeof(st_h->interop_u.err.buf) - 1;  \
    st_h->interop_u.err.resp.buf = st_h->interop_u.err.buf;                 \
    st_h->interop_u.err.resp.off = 0;                                       \
    goto err;                                                               \
} while (0)

    const struct req_map *map;
    ssize_t nw;
    size_t need;
    unsigned len, i;
    struct interop_push_path *push_path;
    regmatch_t matches[MAX_MATCHES + 1];
    unsigned char md5sum[MD5_DIGEST_LENGTH];
    char md5str[ sizeof(md5sum) * 2 + 1 ];
    char byte[1];

    if (!(st_h->flags & SH_HEADERS_READ))
    {
        st_h->flags |= SH_HEADERS_READ;
        st_h->req = lsquic_stream_get_hset(stream);
        if (!st_h->req)
            ERROR_RESP(500, "Internal error: cannot fetch header set from stream");
        else if (st_h->req->method == UNSET)
            ERROR_RESP(400, "Method is not specified");
        else if (!st_h->req->path)
            ERROR_RESP(400, "Path is not specified");
        else if (st_h->req->method == UNSUPPORTED)
            ERROR_RESP(501, "Method %s is not supported", st_h->req->method_str);
        else if (!(map = find_handler(st_h->req->method, st_h->req->path, matches)))
            ERROR_RESP(404, "No handler found for method: %s; path: %s",
                st_h->req->method_str, st_h->req->path);
        else
        {
            LSQ_INFO("found handler for %s %s", st_h->req->method_str, st_h->req->path);
            st_h->resp_status = map->status;
            st_h->interop_handler = map->handler;
            switch (map->handler)
            {
            case IOH_INDEX_HTML:
                st_h->interop_u.ihc.resp = (struct resp) { INDEX_HTML, sizeof(INDEX_HTML) - 1, 0, };
                break;
            case IOH_VER_HEAD:
                st_h->interop_u.vhc.resp = (struct resp) {
                        st_h->req->qif_str, st_h->req->qif_sz, 0, };
                break;
            case IOH_MD5SUM:
                MD5_Init(&st_h->interop_u.md5c.md5ctx);
                st_h->interop_u.md5c.done = 0;
                break;
            case IOH_GEN_FILE:
                STAILQ_INIT(&st_h->interop_u.gfc.push_paths);
                st_h->interop_u.gfc.remain = strtol(st_h->req->path + matches[1].rm_so, NULL, 10);
                if (matches[2].rm_so >= 0
                        && matches[2].rm_so < matches[2].rm_eo)
                {
                    switch (st_h->req->path[ matches[2].rm_so ])
                    {
                    case 'G':
                    case 'g':
                        st_h->interop_u.gfc.remain <<= 30;
                        break;
                    case 'M':
                    case 'm':
                        st_h->interop_u.gfc.remain <<= 20;
                        break;
                    case 'K':
                    case 'k':
                        st_h->interop_u.gfc.remain <<= 10;
                        break;
                    }
                }
                if (st_h->interop_u.gfc.remain > 2 * (1u << 30))
                    ERROR_RESP(406, "Response of %zd bytes is too long to generate",
                        st_h->interop_u.gfc.remain);
                st_h->interop_u.gfc.idle_off = 0;
                for (i = 3; i <= MAX_MATCHES; ++i)
                    if (matches[i].rm_so >= 0)
                    {
                        len = matches[i].rm_eo - matches[i].rm_so;
                        push_path = malloc(sizeof(*push_path) + len + 1);
                        memcpy(push_path->path, st_h->req->path
                            + matches[i].rm_so, len);
                        push_path->path[len] ='\0';
                        STAILQ_INSERT_TAIL(&st_h->interop_u.gfc.push_paths,
                                                                push_path, next);
                    }
                    else
                        break;
                break;
            default:
                /* TODO: implement this */
                assert(0);
                break;
            }
        }

        if (!(map->flags & RM_WANTBODY))
        {
  err:
            lsquic_stream_shutdown(stream, 0);
            lsquic_stream_wantwrite(stream, 1);
        }
    }
    else
    {
        switch (st_h->interop_handler)
        {
        case IOH_MD5SUM:
            assert(!st_h->interop_u.md5c.done);
            nw = lsquic_stream_readf(stream, read_md5, st_h);
            if (nw < 0)
            {
                LSQ_ERROR("could not read from stream for MD5: %s", strerror(errno));
                exit(1);
            }
            if (nw == 0)
                st_h->interop_u.md5c.done = 1;
            if (st_h->interop_u.md5c.done)
            {
                MD5_Final(md5sum, &st_h->interop_u.md5c.md5ctx);
                lsquic_hexstr(md5sum, sizeof(md5sum), md5str, sizeof(md5str));
                snprintf(st_h->interop_u.md5c.resp_buf, sizeof(st_h->interop_u.md5c.resp_buf),
                    "<html><head><title>MD5 Checksum Result</title></head>\n"
                    "<body><h1>MD5 Checksum Result</h1>\n<p>"
                    "MD5 Checksum: <tt>%s</tt>\n</body></html>\n",
                    md5str);
                st_h->interop_u.md5c.resp.buf = st_h->interop_u.md5c.resp_buf;
                st_h->interop_u.md5c.resp.sz = strlen(st_h->interop_u.md5c.resp_buf);
                st_h->interop_u.md5c.resp.off = 0;
                lsquic_stream_shutdown(stream, 0);
                lsquic_stream_wantwrite(stream, 1);
            }
            break;
        case IOH_VER_HEAD:
            if (!st_h->interop_u.vhc.req_body)
            {
                st_h->interop_u.vhc.req_body = malloc(st_h->req->qif_sz);
                if (!st_h->interop_u.vhc.req_body)
                {
                    perror("malloc");
                    exit(1);
                }
            }
            need = st_h->req->qif_sz - st_h->interop_u.vhc.req_sz;
            if (need > 0)
            {
                nw = lsquic_stream_read(stream,
                        st_h->interop_u.vhc.req_body
                                        + st_h->interop_u.vhc.req_sz, need);
                if (nw > 0)
                    st_h->interop_u.vhc.req_sz += need;
                else if (nw == 0)
                {
                    LSQ_WARN("request body too short (does not match headers)");
                    lsquic_stream_shutdown(stream, 0);
                    lsquic_stream_wantwrite(stream, 1);
                }
                else
                {
                    LSQ_ERROR("error reading from stream");
                    exit(1);
                }
            }
            else
            {
                nw = lsquic_stream_read(stream, byte, sizeof(byte));
                if (nw == 0)
                {
                    if (0 == memcmp(st_h->req->qif_str,
                            st_h->interop_u.vhc.req_body, st_h->req->qif_sz))
                        LSQ_INFO("request headers and payload check out");
                    else
                        LSQ_WARN("request headers and payload are different");
                }
                else
                    LSQ_WARN("request body too long (does not match headers)");
                lsquic_stream_shutdown(stream, 0);
                lsquic_stream_wantwrite(stream, 1);
            }
            break;
        default:
            assert(0);
        }
    }
}


static int
send_headers2 (struct lsquic_stream *stream, struct lsquic_stream_ctx *st_h,
                    size_t content_len)
{
    char clbuf[0x20];
    struct header_buf hbuf;

    snprintf(clbuf, sizeof(clbuf), "%zd", content_len);

    hbuf.off = 0;
    struct lsxpack_header  headers_arr[4];
    header_set_ptr(&headers_arr[0], &hbuf, V(":status"), V(st_h->resp_status));
    header_set_ptr(&headers_arr[1], &hbuf, V("server"), V(LITESPEED_ID));
    header_set_ptr(&headers_arr[2], &hbuf, V("content-type"), V("text/html"));
    header_set_ptr(&headers_arr[3], &hbuf, V("content-length"), V(clbuf));
    lsquic_http_headers_t headers = {
        .count = sizeof(headers_arr) / sizeof(headers_arr[0]),
        .headers = headers_arr,
    };

    return lsquic_stream_send_headers(st_h->stream, &headers, 0);
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static size_t
idle_read (void *lsqr_ctx, void *buf, size_t count)
{
    struct gen_file_ctx *const gfc = lsqr_ctx;
    unsigned char *p = buf;
    unsigned char *const end = p + count;
    size_t towrite;

    while (p < end && gfc->remain > 0)
    {
        towrite = MIN((unsigned) (end - p), IDLE_SIZE - gfc->idle_off);
        if (towrite > gfc->remain)
            towrite = gfc->remain;
        memcpy(p, on_being_idle + gfc->idle_off, towrite);
        gfc->idle_off += towrite;
        if (gfc->idle_off == IDLE_SIZE)
            gfc->idle_off = 0;
        p += towrite;
        gfc->remain -= towrite;
    }

    return p - (unsigned char *) buf;
}


static size_t
idle_size (void *lsqr_ctx)
{
    struct gen_file_ctx *const gfc = lsqr_ctx;

    return gfc->remain;
}


static struct req *
new_req (enum method method, const char *path, const char *authority)
{
    struct req *req;

    req = malloc(sizeof(*req));
    if (!req)
        return NULL;

    memset(req, 0, offsetof(struct req, decode_buf));
    req->method = method;
    req->path = strdup(path);
    req->authority_str = strdup(authority);
    if (!(req->path && req->authority_str))
    {
        free(req->path);
        free(req->authority_str);
        free(req);
        return NULL;
    }

    return req;
}


static ssize_t
my_interop_preadv (void *user_data, const struct iovec *iov, int iovcnt)
{
    struct gen_file_ctx *const gfc = user_data;
    size_t nread, nr;
    int i;

    nread = 0;
    for (i = 0; i < iovcnt; ++i)
    {
        nr = idle_read(gfc, iov[i].iov_base, iov[i].iov_len);
        nread += nr;
    }

    return (ssize_t) nread;
}


static void
idle_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct gen_file_ctx *const gfc = &st_h->interop_u.gfc;
    struct interop_push_path *push_path;
    struct lsxpack_header header_arr[4];
    struct lsquic_http_headers headers;
    struct req *req;
    ssize_t nw;
    struct header_buf hbuf;
    struct lsquic_reader reader;

    if (st_h->flags & SH_HEADERS_SENT)
    {
        if (s_pwritev)
        {
            nw = lsquic_stream_pwritev(stream, my_interop_preadv, gfc,
                                                            gfc->remain);
            if (nw == 0)
                goto with_reader;
        }
        else
        {
  with_reader:
            reader.lsqr_read = idle_read,
            reader.lsqr_size = idle_size,
            reader.lsqr_ctx = gfc,
            nw = lsquic_stream_writef(stream, &reader);
        }
        if (nw < 0)
        {
            LSQ_ERROR("error writing idle thoughts: %s", strerror(errno));
            exit(1);
        }
        if (gfc->remain == 0)
            lsquic_stream_shutdown(stream, 1);
    }
    else
    {
        if (st_h->req->authority_str)
            while ((push_path = STAILQ_FIRST(&gfc->push_paths)))
            {
                STAILQ_REMOVE_HEAD(&gfc->push_paths, next);
                LSQ_DEBUG("pushing promise for %s", push_path->path);
                hbuf.off = 0;
                header_set_ptr(&header_arr[0], &hbuf, V(":method"), V("GET"));
                header_set_ptr(&header_arr[1], &hbuf, V(":path"), V(push_path->path));
                header_set_ptr(&header_arr[2], &hbuf, V(":authority"), V(st_h->req->authority_str));
                header_set_ptr(&header_arr[3], &hbuf, V(":scheme"), V("https"));
                headers.headers = header_arr;
                headers.count = sizeof(header_arr) / sizeof(header_arr[0]);
                req = new_req(GET, push_path->path, st_h->req->authority_str);
                if (req)
                {
                    if (0 != lsquic_conn_push_stream(lsquic_stream_conn(stream),
                                                            req, stream, &headers))
                    {
                        LSQ_WARN("stream push failed");
                        interop_server_hset_destroy(req);
                    }
                }
                else
                    LSQ_WARN("cannot allocate req for push");
                free(push_path);
            }
        if (0 == send_headers2(stream, st_h, gfc->remain))
            st_h->flags |= SH_HEADERS_SENT;
        else
        {
            LSQ_ERROR("cannot send headers: %s", strerror(errno));
            lsquic_stream_close(stream);
        }
    }
}


static void
http_server_interop_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct resp *resp;
    ssize_t nw;

    switch (st_h->interop_handler)
    {
    case IOH_ERROR:
        resp = &st_h->interop_u.err.resp;
        goto reply;
    case IOH_INDEX_HTML:
        resp = &st_h->interop_u.ihc.resp;
        goto reply;
    case IOH_VER_HEAD:
        resp = &st_h->interop_u.vhc.resp;
        goto reply;
    case IOH_MD5SUM:
        resp = &st_h->interop_u.md5c.resp;
        goto reply;
    case IOH_GEN_FILE:
        idle_on_write(stream, st_h);
        return;
    default:
        assert(0);
        return;
    }

  reply:
    assert(resp->sz);   /* We always need to send body */
    if (!(st_h->flags & SH_HEADERS_SENT))
    {
        send_headers2(stream, st_h, resp->sz);
        st_h->flags |= SH_HEADERS_SENT;
        return;
    }

    nw = lsquic_stream_write(stream, resp->buf + resp->off, resp->sz - resp->off);
    if (nw < 0)
    {
        LSQ_ERROR("error writing to stream: %s", strerror(errno));
        lsquic_conn_abort(lsquic_stream_conn(stream));
        return;
    }

    resp->off += nw;
    lsquic_stream_flush(stream);
    if (resp->off == resp->sz)
        lsquic_stream_shutdown(stream, 1);
}


const struct lsquic_stream_if interop_http_server_if = {
    .on_new_conn            = http_server_on_new_conn,
    .on_conn_closed         = http_server_on_conn_closed,
    .on_new_stream          = http_server_on_new_stream,
    .on_read                = http_server_interop_on_read,
    .on_write               = http_server_interop_on_write,
    .on_close               = http_server_on_close,
};
#endif /* HAVE_REGEX */


static void
usage (const char *prog)
{
    const char *const slash = strrchr(prog, '/');
    if (slash)
        prog = slash + 1;
    printf(
"Usage: %s [opts]\n"
"\n"
"Options:\n"
"   -r ROOT     Document root\n"
"   -p FILE     Push request with this path\n"
"   -w SIZE     Write immediately (LSWS mode).  Argument specifies maximum\n"
"                 size of the immediate write.\n"
#if HAVE_PREADV
"   -P SIZE     Use preadv(2) to read from disk and lsquic_stream_pwritev() to\n"
"                 write to stream.  Positive SIZE indicate maximum value per\n"
"                 write; negative means always use remaining file size.\n"
"                 Incompatible with -w.\n"
#endif
"   -y DELAY    Delay response for this many seconds -- use for debugging\n"
"   -Q ALPN     Use hq mode; ALPN could be \"hq-29\", for example.\n"
            , prog);
}


static void *
interop_server_hset_create (void *hsi_ctx, lsquic_stream_t *stream,
                            int is_push_promise)
{
    struct req *req;

    req = malloc(sizeof(struct req));
    memset(req, 0, offsetof(struct req, decode_buf));

    return req;
}


static struct lsxpack_header *
interop_server_hset_prepare_decode (void *hset_p, struct lsxpack_header *xhdr,
                                                                size_t req_space)
{
    struct req *req = hset_p;

    if (xhdr)
    {
        LSQ_WARN("we don't reallocate headers: can't give more");
        return NULL;
    }

    if (req->flags & HAVE_XHDR)
    {
        if (req->decode_off + lsxpack_header_get_dec_size(&req->xhdr)
                                                    >= sizeof(req->decode_buf))
        {
            LSQ_WARN("Not enough room in header");
            return NULL;
        }
        req->decode_off += lsxpack_header_get_dec_size(&req->xhdr);
    }
    else
        req->flags |= HAVE_XHDR;

    lsxpack_header_prepare_decode(&req->xhdr, req->decode_buf,
                req->decode_off, sizeof(req->decode_buf) - req->decode_off);
    return &req->xhdr;
}


static int
interop_server_hset_add_header (void *hset_p, struct lsxpack_header *xhdr)
{
    struct req *req = hset_p;
    const char *name, *value;
    unsigned name_len, value_len;

    if (!xhdr)
    {
        if (req->pseudo_headers == (PH_AUTHORITY|PH_METHOD|PH_PATH))
            return 0;
        else
        {
            LSQ_INFO("%s: missing some pseudo-headers: 0x%X", __func__,
                req->pseudo_headers);
            return 1;
        }
    }

    name = lsxpack_header_get_name(xhdr);
    value = lsxpack_header_get_value(xhdr);
    name_len = xhdr->name_len;
    value_len = xhdr->val_len;

    req->qif_str = realloc(req->qif_str,
                        req->qif_sz + name_len + value_len + 2);
    if (!req->qif_str)
    {
        LSQ_ERROR("malloc failed");
        return -1;
    }
    memcpy(req->qif_str + req->qif_sz, name, name_len);
    req->qif_str[req->qif_sz + name_len] = '\t';
    memcpy(req->qif_str + req->qif_sz + name_len + 1, value, value_len);
    req->qif_str[req->qif_sz + name_len + 1 + value_len] = '\n';
    req->qif_sz += name_len + value_len + 2;

    if (5 == name_len && 0 == strncmp(name, ":path", 5))
    {
        if (req->path)
            return 1;
        req->path = strndup(value, value_len);
        if (!req->path)
            return -1;
        req->pseudo_headers |= PH_PATH;
        return 0;
    }

    if (7 == name_len && 0 == strncmp(name, ":method", 7))
    {
        if (req->method != UNSET)
            return 1;
        req->method_str = strndup(value, value_len);
        if (!req->method_str)
            return -1;
        if (0 == strcmp(req->method_str, "GET"))
            req->method = GET;
        else if (0 == strcmp(req->method_str, "POST"))
            req->method = POST;
        else
            req->method = UNSUPPORTED;
        req->pseudo_headers |= PH_METHOD;
        return 0;
    }

    if (10 == name_len && 0 == strncmp(name, ":authority", 10))
    {
        req->authority_str = strndup(value, value_len);
        if (!req->authority_str)
            return -1;
        req->pseudo_headers |= PH_AUTHORITY;
        return 0;
    }

    return 0;
}


static void
interop_server_hset_destroy (void *hset_p)
{
    struct req *req = hset_p;
    free(req->qif_str);
    free(req->path);
    free(req->method_str);
    free(req->authority_str);
    free(req);
}


static const struct lsquic_hset_if header_bypass_api =
{
    .hsi_create_header_set  = interop_server_hset_create,
    .hsi_prepare_decode     = interop_server_hset_prepare_decode,
    .hsi_process_header     = interop_server_hset_add_header,
    .hsi_discard_header_set = interop_server_hset_destroy,
};


int
main (int argc, char **argv) 
{
    int opt, s;
    struct stat st;
    struct server_ctx server_ctx;
    struct prog prog;
    const char *const *alpn;

#if !(HAVE_OPEN_MEMSTREAM || HAVE_REGEX)
    fprintf(stderr, "cannot run server without regex or open_memstream\n");
    return 1;
#endif

    memset(&server_ctx, 0, sizeof(server_ctx));
    TAILQ_INIT(&server_ctx.sports);
    server_ctx.prog = &prog;

    prog_init(&prog, LSENG_SERVER|LSENG_HTTP, &server_ctx.sports,
                                            &http_server_if, &server_ctx);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "y:Y:n:p:r:w:P:h"
#if HAVE_OPEN_MEMSTREAM
                                                    "Q:"
#endif
                                                                        )))
    {
        switch (opt) {
        case 'n':
            server_ctx.max_conn = atoi(optarg);
            break;
        case 'p':
            server_ctx.push_path = optarg;
            break;
        case 'r':
            if (-1 == stat(optarg, &st))
            {
                perror("stat");
                exit(2);
            }
#ifndef WIN32
            if (!S_ISDIR(st.st_mode))
            {
                fprintf(stderr, "`%s' is not a directory\n", optarg);
                exit(2);
            }
#endif
            server_ctx.document_root = optarg;
            break;
        case 'w':
            s_immediate_write = atoi(optarg);
            break;
        case 'P':
#if HAVE_PREADV
            s_pwritev = strtoull(optarg, NULL, 10);
            break;
#else
            fprintf(stderr, "preadv is not supported on this platform, "
                                                        "cannot use -P\n");
            exit(EXIT_FAILURE);
#endif
        case 'y':
            server_ctx.delay_resp_sec = atoi(optarg);
            break;
        case 'h':
            usage(argv[0]);
            prog_print_common_options(&prog, stdout);
            exit(0);
#if HAVE_OPEN_MEMSTREAM
        case 'Q':
            /* XXX A bit hacky, as `prog' has already been initialized... */
            prog.prog_engine_flags &= ~LSENG_HTTP;
            prog.prog_api.ea_stream_if = &hq_server_if;
            add_alpn(optarg);
            break;
#endif
        default:
            if (0 != prog_set_opt(&prog, opt, optarg))
                exit(1);
        }
    }

    if (!server_ctx.document_root)
    {
#if HAVE_REGEX
        LSQ_NOTICE("Document root is not set: start in Interop Mode");
        init_map_regexes();
        prog.prog_api.ea_stream_if = &interop_http_server_if;
        prog.prog_api.ea_hsi_if = &header_bypass_api;
        prog.prog_api.ea_hsi_ctx = NULL;
#else
        LSQ_ERROR("Document root is not set: use -r option");
        exit(EXIT_FAILURE);
#endif
    }

    if (s_immediate_write && s_pwritev)
    {
        LSQ_ERROR("-w and -P are incompatible options");
        exit(EXIT_FAILURE);
    }

    alpn = lsquic_get_h3_alpns(prog.prog_settings.es_versions);
    while (*alpn)
    {
        if (0 == add_alpn(*alpn))
            ++alpn;
        else
        {
            LSQ_ERROR("cannot add ALPN %s", *alpn);
            exit(EXIT_FAILURE);
        }
    }

    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    LSQ_DEBUG("entering event loop");

    s = prog_run(&prog);
    prog_cleanup(&prog);

#if HAVE_REGEX
    if (!server_ctx.document_root)
        free_map_regexes();
#endif

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
