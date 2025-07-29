#include <sys/queue.h>
#include <time.h>
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_minmax.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_bbr.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_spi.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_pacer.h"
#include "lsquic_senhist.h"
#include "lsquic_cubic.h"
#include "lsquic_bbr.h"
#include "lsquic_adaptive_cc.h"
#include "lsquic_send_ctl.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_util.h"

#include <string.h>

#include "lsquic_cctk.h"

const struct cctk_frame cctk_zero_frame = {
    .version = 0x02,
    ._key_stmp = {'S', 'T', 'M', 'P'},
    .stmp = 0,
    ._key_slst = {'S', 'L', 'S', 'T'},
    .slst = 0,
    ._key_ntyp = {'N', 'T', 'Y', 'P'},
    .ntyp = 0,
    ._key_cip = {'C', 'I', 'P', '\0'},
    .cip = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    ._key_srtt = {'S', 'R', 'T', 'T'},
    .srtt = 0,
    ._key_mrtt = {'M', 'R', 'T', 'T'},
    .mrtt = 0,
    ._key_rttv = {'R', 'T', 'T', 'V'},
    .rttv = 0,
    ._key_mcwd = {'M', 'C', 'W', 'D'},
    .mcwd = 0,
    ._key_mflg = {'M', 'F', 'L', 'G'},
    .mflg = 0,
    ._key_bw = {'B', 'W', '\0', '\0'},
    .bw = 0,
    ._key_mbw = {'M', 'B', 'W', '\0'},
    .mbw = 0,
    ._key_thpt = {'T', 'H', 'P', 'T'},
    .thpt = 0,
    ._key_plr = {'P', 'L', 'R', '\0'},
    .plr = 0,
    ._key_srat = {'S', 'R', 'A', 'T'},
    .srat = 0,
    ._key_rrat = {'R', 'R', 'A', 'T'},
    .rrat = 0,
    ._key_irat = {'I', 'R', 'A', 'T'},
    .irat = 0,
    ._key_blen = {'B', 'L', 'E', 'N'},
    .blen = 0
};  

int cctk_fill_frame(const struct cctk_data *data, struct cctk_frame *frame) {
    memcpy(frame, &cctk_zero_frame, sizeof(struct cctk_frame));
    frame->version = data->version;
    frame->stmp = data->stmp;
    frame->slst = data->slst;
    frame->ntyp = data->ntyp;
    memcpy(frame->cip, data->cip, sizeof(data->cip));
    frame->srtt = data->srtt;
    frame->mrtt = data->mrtt;
    frame->rttv = data->rttv;
    frame->mcwd = data->mcwd;
    frame->mflg = data->mflg;
    frame->bw = data->bw;
    frame->mbw = data->mbw;
    frame->thpt = data->thpt;
    frame->plr = data->plr;
    frame->srat = data->srat;
    frame->rrat = data->rrat;
    frame->irat = data->irat;
    frame->blen = data->blen;
    return sizeof(sizeof(struct cctk_frame));
}

enum CC_ALGS {
    CC_ALG_CUBIC = 1,
    CC_ALG_BBR = 2,
    CC_ALG_ADAPTIVE = 3,
};

void * get_cc_ctx(char cc_type, lsquic_send_ctl_t *send_ctl) {
    struct lsquic_engine_public *enpub = send_ctl->sc_enpub;
    switch (cc_type)
    {
    case CC_ALG_CUBIC:
        if(enpub->enp_settings.es_cc_algo != CC_ALG_BBR)
            return &send_ctl->sc_adaptive_cc.acc_cubic;
        else
            return NULL;
    case CC_ALG_BBR:
        if(enpub->enp_settings.es_cc_algo != CC_ALG_CUBIC)
            return &send_ctl->sc_adaptive_cc.acc_bbr;
        else
            return NULL;
    case CC_ALG_ADAPTIVE:
    default:
        return &send_ctl->sc_adaptive_cc;
    }
    return NULL;
}

void sockaddr_to_16(const struct sockaddr *sa, unsigned char *cip /*must point to char[16]*/) {
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        memcpy(cip, &sin->sin_addr.s_addr, 4);
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        memcpy(cip, sin6->sin6_addr.s6_addr, 16);
    } else {
        memset(cip, 0, 16); // Unknown family, zero out cip
    }
}

unsigned int 
lsquic_conn_buffered_sum(const struct lsquic_conn_public *conn_pub)
{
    unsigned int sum = 0;
    
    struct lsquic_hash *all_streams = conn_pub->all_streams;

    for (struct lsquic_hash_elem *el = lsquic_hash_first(all_streams); el;
                                     el = lsquic_hash_next(all_streams))
    {
        const lsquic_stream_t *stream = lsquic_hashelem_getdata(el);
        sum += stream->sm_n_buffered;
    }
    return sum;
}

unsigned int 
lsquic_conn_written_sum(const struct lsquic_conn_public *conn_pub)
{
    unsigned int sum = 0;
    
    struct lsquic_hash *all_streams = conn_pub->all_streams;

    for (struct lsquic_hash_elem *el = lsquic_hash_first(all_streams); el;
                                     el = lsquic_hash_next(all_streams))
    {
        const lsquic_stream_t *stream = lsquic_hashelem_getdata(el);
        sum += stream->tosend_off;
    }
    return sum;
}

int
lsquic_write_cctk_frame_payload (unsigned char *buf, size_t buf_len, struct cctk_ctx *cctk_ctx, lsquic_send_ctl_t * send_ctl)
{
    if( buf_len < sizeof(cctk_zero_frame) )
        return -1;
    
    struct cctk_data cctk = {0};
    struct lsquic_conn_public *conn_pub = send_ctl->sc_conn_pub;

    struct sockaddr *local, *remote;
    lsquic_conn_get_sockaddr(conn_pub->lconn, (const struct sockaddr **)&local, (const struct sockaddr **)&remote);
    sockaddr_to_16(remote, cctk.cip);

    // STMP - timestamp
    cctk.version = 2;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    cctk.stmp = (unsigned long) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;

    // NTYP - network type
    cctk.ntyp = cctk_ctx->net_type;

    // MFLG - max in flight bytes
    unsigned int in_flight = send_ctl->sc_bytes_unacked_all;
    if( in_flight > cctk_ctx->max_in_flight ) {
        cctk_ctx->max_in_flight = in_flight;
    }

    // SRTT
    cctk.srtt = (unsigned int)conn_pub->rtt_stats.srtt;
    // MRTT
    cctk.mrtt = (unsigned int)conn_pub->rtt_stats.min_rtt;
    // RTTV
    cctk.rttv = (unsigned int)conn_pub->rtt_stats.rttvar;
    // MCWD - max congestion window
    unsigned long cwd = send_ctl->sc_ci->cci_get_cwnd(send_ctl->sc_cong_ctl);
    if( cwd > cctk_ctx->max_cwnd ) {
        cctk_ctx->max_cwnd = cwd;
    }
    cctk.mcwd = cctk_ctx->max_cwnd;

    // BW
    cctk.bw = send_ctl->sc_ci->cci_pacing_rate(send_ctl->sc_cong_ctl, 1);
    // MBW - max bandwidth
    if( cctk.bw > cctk_ctx->max_bw ) {
        cctk_ctx->max_bw = cctk.bw;
    }
    cctk.mbw = cctk_ctx->max_bw;

    // THPT - throughput
    cctk.thpt = cctk.bw; // FIXME: for now assuming throughput is same as current bandwidth

    // PLR percentage of lost packets
    #if LSQUIC_SEND_STATS
    if(send_ctl->sc_stats.n_total_sent > 0) {
        cctk.plr = send_ctl->sc_loss_count * 100 / send_ctl->sc_stats.n_total_sent;
    }
    #endif

    struct lsquic_bbr *bbr = get_cc_ctx(CC_ALG_BBR, send_ctl);
    struct lsquic_cubic *cubic = get_cc_ctx(CC_ALG_CUBIC, send_ctl);
    
    // SLST - slow start
    if (bbr)
        cctk.slst = (bbr->bbr_mode == BBR_MODE_STARTUP) ? 1 : 0;
    else
        cctk.slst = (cubic->cu_cwnd < cubic->cu_ssthresh) ? 1 : 0;

    // BLEN - buffer length in connection level
    cctk.blen = lsquic_conn_buffered_sum(conn_pub);

    #if LSQUIC_CONN_STATS
    
    const struct conn_stats *conn_stats = conn_pub->conn_stats;

    double retx_rate = (double) conn_stats->out.retx_packets / (double) conn_stats->out.packets;
    cctk.thpt = (unsigned long)((double)cctk.thpt * (1.0 - retx_rate));
    unsigned long written_total = 0;
    unsigned long time_diff = cctk.stmp - cctk_ctx->last_ts;
    if( time_diff > 0 && cctk_ctx->last_ts > 0 ) {
        unsigned long bytes_diff_in = conn_stats->in.bytes - cctk_ctx->last_bytes_in;
        unsigned long bytes_diff_out = conn_stats->out.bytes - cctk_ctx->last_bytes_out;
        cctk.srat = 1000000 * bytes_diff_out / time_diff; 
        cctk.rrat = 1000000 * bytes_diff_in / time_diff;
        written_total = lsquic_conn_written_sum(conn_pub);
        unsigned long written_diff = written_total - cctk_ctx->last_written;
        cctk.irat = 1000000 * written_diff / time_diff;
    }
    cctk_ctx->last_ts = cctk.stmp;
    cctk_ctx->last_bytes_in = conn_stats->in.bytes;
    cctk_ctx->last_bytes_out = conn_stats->out.bytes;
    cctk_ctx->last_written = written_total;

    #endif

    return cctk_fill_frame(&cctk, (struct cctk_frame *)buf);
}
