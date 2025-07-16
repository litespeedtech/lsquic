#ifndef LSQUIC_CCTK_H
#define LSQUIC_CCTK_H

typedef struct lsquic_send_ctl lsquic_send_ctl_t;

int
lsquic_gquic_be_gen_cctk_frame (unsigned char *buf, size_t buf_len, lsquic_send_ctl_t * send_ctl);

struct cctk_data {
    char version;
    unsigned long stmp;          // timestamp in seconds since epoch
    unsigned char slst;          // slow start 1 or not - 0
    unsigned char ntyp;          // Client network type
    unsigned char cip[16];       // Client IP
    unsigned int srtt;           //Smoothed RTT microseconds
    unsigned int mrtt;           //Minimum RTT microseconds
    unsigned int rttv;           //The variance of RTT, defined in RFC9002
    unsigned int mcwd;           //Maximum congestion window bytes
    unsigned int mflg;           //Max in flight bytes
    unsigned long bw;             //bandwidth in bytes per second
    unsigned long mbw;           //Max bandwidth in bytes per second
    unsigned long thpt;           //throughput in bytes per second, retransmitted data excluded.
    unsigned char plr;            // The Packet Loss Rate
};

#pragma pack(1)
struct cctk_frame {
    char version;
    char _key_stmp[4];
    unsigned long stmp;          // timestamp in seconds since epoch
    char _key_slst[4];
    unsigned char slst;          // slow start 1 or not - 0
    char _key_ntyp[4];
    unsigned char ntyp;          // Client network type
    char _key_cip[4];
    unsigned char cip[16];       // Client IP
    char _key_srtt[4];
    unsigned int srtt;           //Smoothed RTT microseconds
    char _key_mrtt[4];
    unsigned int mrtt;           //Minimum RTT microseconds
    char _key_rttv[4]; 
    unsigned int rttv;           //The variance of RTT, defined in RFC9002
    char _key_mcwd[4];
    unsigned int mcwd;           //Maximum congestion window bytes
    char _key_mflg[4];
    unsigned int mflg;           //Max in flight bytes
    char _key_bw[4];
    unsigned long bw;             //bandwidth in bytes per second
    char _key_mbw[4];
    unsigned long mbw;           //Max bandwidth in bytes per second
    char _key_thpt[4];
    unsigned long thpt;           //throughput in bytes per second, retransmitted data excluded.
    char _key_plr[4];
    unsigned char plr;            // The Packet Loss Rate
};
#pragma pack()
#endif