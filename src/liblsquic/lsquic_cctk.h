#ifndef LSQUIC_CCTK_H
#define LSQUIC_CCTK_H

#include <stddef.h>

typedef struct lsquic_send_ctl lsquic_send_ctl_t;

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
    unsigned long thpt;          //throughput in bytes per second, retransmitted data excluded.
    unsigned char plr;           // The Packet Loss Rate
    unsigned long srat;          // Send bit rate in bytes per second  
    unsigned long rrat;          // Receive bit rate in bytes per second
    unsigned long irat;          // receive bitrate last second from application
    unsigned int blen;           // Buffer length in connection level   
};

struct cctk_ctx {
        unsigned char version; // Version of the CCTK protocol
        unsigned init_time;
        unsigned send_period;
        unsigned char net_type;
        unsigned int max_in_flight;
        unsigned long max_bw;
        unsigned long max_cwnd; // Maximum congestion window bytes
        unsigned long last_ts;
        unsigned long last_bytes_acked;
        unsigned long last_bytes_out;
        unsigned long last_written;
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
    char _key_srat[4];
    unsigned long srat;          // Send bit rate in bytes per second
    char _key_rrat[4];
    unsigned long rrat;          // Receive bit rate in bytes per second
    char _key_irat[4];
    unsigned long irat;         // Input bit rate in bytes per second
    char _key_blen[4];
    unsigned int blen;          // Buffer length in connection level
};
#pragma pack()

#define CCTK_SIZE_V1 (offsetof(struct cctk_frame, _key_srat))
#define CCTK_SIZE_V2 (sizeof(struct cctk_frame))

size_t
lsquic_cctk_frame_size(const struct cctk_ctx *cctk_ctx);

int
lsquic_write_cctk_frame_payload (unsigned char *buf, size_t buf_len,  struct cctk_ctx *cctk_ctx, lsquic_send_ctl_t *send_ctl);

#endif
