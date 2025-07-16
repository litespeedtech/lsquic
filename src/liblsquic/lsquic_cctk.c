#include <sys/queue.h>

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
#include "lsquic_util.h"

#include <string.h>

#include "lsquic_cctk.h"

const struct cctk_frame cctk_zero_frame = {
    .version = 0x01,
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
    .plr = 0
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
    return sizeof(sizeof(struct cctk_frame));
}

int
lsquic_gquic_be_gen_cctk_frame (unsigned char *buf, size_t buf_len, lsquic_send_ctl_t * send_ctl)
{
    if( buf_len < sizeof(cctk_zero_frame) )
        return -1;
    
    struct cctk_data cctk = {0};
    
    //struct sockaddr *local, *remote;
    //lsquic_conn_get_sockaddr(conn, (const struct sockaddr **)&local, (const struct sockaddr **)&remote);

    cctk.stmp = (unsigned long) lsquic_time_now();
    struct lsquic_conn_public *conn = send_ctl->sc_conn_pub;
    cctk.srtt = (unsigned int)conn->rtt_stats.srtt;
    cctk.mrtt = (unsigned int)conn->rtt_stats.min_rtt;
    cctk.rttv = (unsigned int)conn->rtt_stats.rttvar;
    unsigned long cwd = send_ctl->sc_ci->cci_get_cwnd(send_ctl->sc_cong_ctl);
    if( cwd > cctk.mcwd ) {
        cctk.mcwd = cwd;
    }

    return cctk_fill_frame(&cctk, (struct cctk_frame *)buf);
}
