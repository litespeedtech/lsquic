/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * LSQUIC Logger implementation.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif
#include <time.h>

#define LSQUIC_LOGGER_MODULE LSQLM_LOGGER /* Quis custodiet ipsos custodes? */
#include "lsquic.h"
#include "lsquic_logger.h"

#define MAX_LINE_LEN 8192
/* Expanded TRUNC_FMT should not exceed TRUNC_SZ bytes.  At the same time,
 * TRUNC_SZ should be significantly smaller than MAX_LINE_LEN.
 */
#define TRUNC_FMT "<truncated, need %d bytes>"
#define TRUNC_SZ 40
#define FORMAT_PROBLEM(lb, len, max) ((lb < 0) || (lb + len >= max))

/* TODO: display GQUIC CIDs in Chrome-compatible format */

static enum lsquic_logger_timestamp_style g_llts = LLTS_NONE;

static int
null_log_buf (void *ctx, const char *buf, size_t len)
{
    return 0;
}

static int
file_log_buf (void *ctx, const char *buf, size_t len)
{
    return (int)fwrite(buf, sizeof(char), len, (FILE *) ctx);
}

static const struct lsquic_logger_if file_logger_if = {
    .log_buf    = file_log_buf,
};

static const struct lsquic_logger_if null_logger_if = {
    .log_buf    = null_log_buf,
};

static void *logger_ctx = NULL;
static const struct lsquic_logger_if *logger_if = &null_logger_if;

enum lsq_log_level lsq_log_levels[N_LSQUIC_LOGGER_MODULES] = {
    [LSQLM_NOMODULE]    = LSQ_LOG_WARN,
    [LSQLM_LOGGER]      = LSQ_LOG_WARN,
    [LSQLM_EVENT]       = LSQ_LOG_WARN,
    [LSQLM_ENGINE]      = LSQ_LOG_WARN,
    [LSQLM_CONN]        = LSQ_LOG_WARN,
    [LSQLM_STREAM]      = LSQ_LOG_WARN,
    [LSQLM_PARSE]       = LSQ_LOG_WARN,
    [LSQLM_CFCW]        = LSQ_LOG_WARN,
    [LSQLM_SFCW]        = LSQ_LOG_WARN,
    [LSQLM_SENDCTL]     = LSQ_LOG_WARN,
    [LSQLM_ALARMSET]    = LSQ_LOG_WARN,
    [LSQLM_CRYPTO]      = LSQ_LOG_WARN,
    [LSQLM_HANDSHAKE]   = LSQ_LOG_WARN,
    [LSQLM_HSK_ADAPTER] = LSQ_LOG_WARN,
    [LSQLM_BBR]         = LSQ_LOG_WARN,
    [LSQLM_CUBIC]       = LSQ_LOG_WARN,
    [LSQLM_ADAPTIVE_CC] = LSQ_LOG_WARN,
    [LSQLM_HEADERS]     = LSQ_LOG_WARN,
    [LSQLM_FRAME_READER]= LSQ_LOG_WARN,
    [LSQLM_FRAME_WRITER]= LSQ_LOG_WARN,
    [LSQLM_MINI_CONN]   = LSQ_LOG_WARN,
    [LSQLM_TOKGEN]      = LSQ_LOG_WARN,
    [LSQLM_ENG_HIST]    = LSQ_LOG_WARN,
    [LSQLM_SPI]         = LSQ_LOG_WARN,
    [LSQLM_HPI]         = LSQ_LOG_WARN,
    [LSQLM_DI]          = LSQ_LOG_WARN,
    [LSQLM_PRQ]         = LSQ_LOG_WARN,
    [LSQLM_PACER]       = LSQ_LOG_WARN,
    [LSQLM_HTTP1X]      = LSQ_LOG_WARN,
    [LSQLM_QLOG]        = LSQ_LOG_WARN,
    [LSQLM_TRAPA]       = LSQ_LOG_WARN,
    [LSQLM_PURGA]       = LSQ_LOG_WARN,
    [LSQLM_HCSI_READER] = LSQ_LOG_WARN,
    [LSQLM_HCSO_WRITER] = LSQ_LOG_WARN,
    [LSQLM_QENC_HDL]    = LSQ_LOG_WARN,
    [LSQLM_QDEC_HDL]    = LSQ_LOG_WARN,
    [LSQLM_QPACK_ENC]    = LSQ_LOG_WARN,
    [LSQLM_QPACK_DEC]    = LSQ_LOG_WARN,
    [LSQLM_PRIO]        = LSQ_LOG_WARN,
    [LSQLM_BW_SAMPLER]  = LSQ_LOG_WARN,
    [LSQLM_PACKET_RESIZE] = LSQ_LOG_WARN,
    [LSQLM_CONN_STATS]  = LSQ_LOG_WARN,
};

const char *const lsqlm_to_str[N_LSQUIC_LOGGER_MODULES] = {
    [LSQLM_NOMODULE]    = "",
    [LSQLM_LOGGER]      = "logger",
    [LSQLM_EVENT]       = "event",
    [LSQLM_ENGINE]      = "engine",
    [LSQLM_CONN]        = "conn",
    [LSQLM_STREAM]      = "stream",
    [LSQLM_PARSE]       = "parse",
    [LSQLM_CFCW]        = "cfcw",
    [LSQLM_SFCW]        = "sfcw",
    [LSQLM_SENDCTL]     = "sendctl",
    [LSQLM_ALARMSET]    = "alarmset",
    [LSQLM_CRYPTO]      = "crypto",
    [LSQLM_HANDSHAKE]   = "handshake",
    [LSQLM_HSK_ADAPTER] = "hsk-adapter",
    [LSQLM_BBR]         = "bbr",
    [LSQLM_CUBIC]       = "cubic",
    [LSQLM_ADAPTIVE_CC] = "adaptive-cc",
    [LSQLM_HEADERS]     = "headers",
    [LSQLM_FRAME_READER]= "frame-reader",
    [LSQLM_FRAME_WRITER]= "frame-writer",
    [LSQLM_MINI_CONN]   = "mini-conn",
    [LSQLM_TOKGEN]      = "tokgen",
    [LSQLM_ENG_HIST]    = "eng-hist",
    [LSQLM_SPI]         = "spi",
    [LSQLM_HPI]         = "hpi",
    [LSQLM_DI]          = "di",
    [LSQLM_PRQ]         = "prq",
    [LSQLM_PACER]       = "pacer",
    [LSQLM_HTTP1X]      = "http1x",
    [LSQLM_QLOG]        = "qlog",
    [LSQLM_TRAPA]       = "trapa",
    [LSQLM_PURGA]       = "purga",
    [LSQLM_HCSI_READER] = "hcsi-reader",
    [LSQLM_HCSO_WRITER] = "hcso-writer",
    [LSQLM_QENC_HDL]    = "qenc-hdl",
    [LSQLM_QDEC_HDL]    = "qdec-hdl",
    [LSQLM_QPACK_ENC]    = "qpack-enc",
    [LSQLM_QPACK_DEC]    = "qpack-dec",
    [LSQLM_PRIO]        = "prio",
    [LSQLM_BW_SAMPLER]  = "bw-sampler",
    [LSQLM_PACKET_RESIZE] = "packet-resize",
    [LSQLM_CONN_STATS]  = "conn-stats",
};

const char *const lsq_loglevel2str[N_LSQUIC_LOG_LEVELS] = {
    [LSQ_LOG_ALERT]   =  "ALERT",
    [LSQ_LOG_CRIT]    =  "CRIT",
    [LSQ_LOG_DEBUG]   =  "DEBUG",
    [LSQ_LOG_EMERG]   =  "EMERG",
    [LSQ_LOG_ERROR]   =  "ERROR",
    [LSQ_LOG_INFO]    =  "INFO",
    [LSQ_LOG_NOTICE]  =  "NOTICE",
    [LSQ_LOG_WARN]    =  "WARN",
};


#ifdef WIN32
#define DELTA_EPOCH_IN_TICKS  116444736000000000Ui64
struct timezone
{
    time_t tz_minuteswest;         /* minutes W of Greenwich */
    time_t tz_dsttime;             /* type of dst correction */
};

static int
gettimeofday (struct timeval *tv, struct timezone *tz)
{
    FILETIME ft;
    uint64_t tmpres;
    static int tzflag;

    if (NULL != tv)
    {
        GetSystemTimeAsFileTime(&ft);

        tmpres = ((uint64_t) ft.dwHighDateTime << 32)
               | (ft.dwLowDateTime);

        tmpres -= DELTA_EPOCH_IN_TICKS;
        tv->tv_sec = tmpres / 10000000;
        tv->tv_usec = tmpres % 1000000;
    }

    if (NULL != tz)
    {
        if (!tzflag)
        {
            _tzset();
            tzflag++;
        }
        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
    }

    return 0;
}
#endif


static size_t
print_timestamp (char *buf, size_t max)
{
    struct tm tm;
    struct timeval tv;
    size_t len = 0;

    gettimeofday(&tv, NULL);
#ifdef WIN32
    {
        time_t t = tv.tv_sec;
#ifndef NDEBUG
        errno_t e =
#endif
	localtime_s(&tm, &t);
	assert(!e);
    }
#else    
    localtime_r(&tv.tv_sec, &tm);
#endif    
    if (g_llts == LLTS_YYYYMMDD_HHMMSSUS)
        len = snprintf(buf, max, "%04d-%02d-%02d %02d:%02d:%02d.%06d ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, (int) (tv.tv_usec));
    else if (g_llts == LLTS_YYYYMMDD_HHMMSSMS)
        len = snprintf(buf, max, "%04d-%02d-%02d %02d:%02d:%02d.%03d ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, (int) (tv.tv_usec / 1000));
    else if (g_llts == LLTS_HHMMSSMS)
        len = snprintf(buf, max, "%02d:%02d:%02d.%03d ",
            tm.tm_hour, tm.tm_min, tm.tm_sec, (int) (tv.tv_usec / 1000));
    else if (g_llts == LLTS_HHMMSSUS)
        len = snprintf(buf, max, "%02d:%02d:%02d.%06d ",
            tm.tm_hour, tm.tm_min, tm.tm_sec, (int) tv.tv_usec);
    else if (g_llts == LLTS_CHROMELIKE)
        len = snprintf(buf, max, "%02d%02d/%02d%02d%02d.%06d ",
            tm.tm_mon + 1, tm.tm_mday,tm.tm_hour, tm.tm_min,
            tm.tm_sec, (int) tv.tv_usec);
    return len;
}


void
lsquic_logger_log3 (enum lsq_log_level log_level,
                    enum lsquic_logger_module module,
                    const lsquic_cid_t *conn_id, lsquic_stream_id_t stream_id,
                    const char *fmt, ...)
{
    const int saved_errno = errno;
    char cidbuf_[MAX_CID_LEN * 2 + 1];
    size_t len = 0;
    int lb;
    size_t max = MAX_LINE_LEN;
    char buf[MAX_LINE_LEN];

    if (g_llts != LLTS_NONE)
    {
        lb = print_timestamp(buf, max);
        if (FORMAT_PROBLEM(lb, len, max))
            goto end;
        len += lb;
    }
    lb = snprintf(buf + len, max - len, "[%s] [QUIC:%"CID_FMT"-%"PRIu64"] %s: ",
        lsq_loglevel2str[log_level], CID_BITS(conn_id),
        stream_id, lsqlm_to_str[module]);
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    va_list ap;
    va_start(ap, fmt);
    lb = vsnprintf(buf + len, max - len, fmt, ap);
    va_end(ap);
    if (lb > 0 && (size_t) lb >= max - len && max - len >= TRUNC_SZ)
    {
        len = max - TRUNC_SZ;
        lb = snprintf(buf + max - TRUNC_SZ, TRUNC_SZ, TRUNC_FMT, lb);
    }
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    lb = snprintf(buf + len, max - len, "\n");
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    logger_if->log_buf(logger_ctx, buf, len);
end:
    errno = saved_errno;
}


void
lsquic_logger_log2 (enum lsq_log_level log_level,
                    enum lsquic_logger_module module,
                    const struct lsquic_cid *conn_id, const char *fmt, ...)
{
    const int saved_errno = errno;
    char cidbuf_[MAX_CID_LEN * 2 + 1];
    size_t len = 0;
    int lb;
    size_t max = MAX_LINE_LEN;
    char buf[MAX_LINE_LEN];

    if (g_llts != LLTS_NONE)
    {
        lb = print_timestamp(buf, max);
        if (FORMAT_PROBLEM(lb, len, max))
            goto end;
        len += lb;
    }

    lb = snprintf(buf + len, max - len, "[%s] [QUIC:%"CID_FMT"] %s: ",
        lsq_loglevel2str[log_level], CID_BITS(conn_id), lsqlm_to_str[module]);
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    va_list ap;
    va_start(ap, fmt);
    lb = vsnprintf(buf + len, max - len, fmt, ap);
    va_end(ap);
    if (lb > 0 && (size_t) lb >= max - len && max - len >= TRUNC_SZ)
    {
        len = max - TRUNC_SZ;
        lb = snprintf(buf + max - TRUNC_SZ, TRUNC_SZ, TRUNC_FMT, lb);
    }
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    lb = snprintf(buf + len, max - len, "\n");
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    logger_if->log_buf(logger_ctx, buf, len);
end:
    errno = saved_errno;
}


void
lsquic_logger_log1 (enum lsq_log_level log_level,
                    enum lsquic_logger_module module,
                    const char *fmt, ...)
{
    const int saved_errno = errno;
    size_t len = 0;
    int lb;
    size_t max = MAX_LINE_LEN;
    char buf[MAX_LINE_LEN];

    if (g_llts != LLTS_NONE)
    {
        lb = print_timestamp(buf, max);
        if (FORMAT_PROBLEM(lb, len, max))
            goto end;
        len += lb;
    }
    lb = snprintf(buf + len, max - len, "[%s] %s: ", lsq_loglevel2str[log_level],
                                                lsqlm_to_str[module]);
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    va_list ap;
    va_start(ap, fmt);
    lb = vsnprintf(buf + len, max - len, fmt, ap);
    va_end(ap);
    if (lb > 0 && (size_t) lb >= max - len && max - len >= TRUNC_SZ)
    {
        len = max - TRUNC_SZ;
        lb = snprintf(buf + max - TRUNC_SZ, TRUNC_SZ, TRUNC_FMT, lb);
    }
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    lb = snprintf(buf + len, max - len, "\n");
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    logger_if->log_buf(logger_ctx, buf, len);
end:
    errno = saved_errno;
}


void
lsquic_logger_log0 (enum lsq_log_level log_level, const char *fmt, ...)
{
    const int saved_errno = errno;
    size_t len = 0;
    int lb;
    size_t max = MAX_LINE_LEN;
    char buf[MAX_LINE_LEN];

    if (g_llts != LLTS_NONE)
    {
        lb = print_timestamp(buf, max);
        if (FORMAT_PROBLEM(lb, len, max))
            goto end;
        len += lb;
    }

    lb = snprintf(buf + len, max - len, "[%s] ", lsq_loglevel2str[log_level]);
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    va_list ap;
    va_start(ap, fmt);
    lb = vsnprintf(buf + len, max - len, fmt, ap);
    va_end(ap);
    if (lb > 0 && (size_t) lb >= max - len && max - len >= TRUNC_SZ)
    {
        len = max - TRUNC_SZ;
        lb = snprintf(buf + max - TRUNC_SZ, TRUNC_SZ, TRUNC_FMT, lb);
    }
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    lb = snprintf(buf + len, max - len, "\n");
    if (FORMAT_PROBLEM(lb, len, max))
        goto end;
    len += lb;
    logger_if->log_buf(logger_ctx, buf, len);
end:
    errno = saved_errno;
}


void
lsquic_logger_init (const struct lsquic_logger_if *lif, void *lctx,
                    unsigned llts)
{
    logger_if  = lif;
    logger_ctx = lctx;
    if (llts < N_LLTS)
        g_llts = llts;
    LSQ_DEBUG("%s called", __func__);
}


enum lsquic_logger_module
lsquic_str_to_logger_module (const char *str)
{
    enum lsquic_logger_module i;
    for (i = 0; i < sizeof(lsqlm_to_str) / sizeof(lsqlm_to_str[0]); ++i)
        if (0 == strcasecmp(lsqlm_to_str[i], str))
            return i;
    return -1;
}


enum lsq_log_level
lsquic_str_to_log_level (const char *str)
{
    if (0 == strcasecmp(str, "emerg"))
        return LSQ_LOG_EMERG;
    if (0 == strcasecmp(str, "alert"))
        return LSQ_LOG_ALERT;
    if (0 == strcasecmp(str, "crit"))
        return LSQ_LOG_CRIT;
    if (0 == strcasecmp(str, "error"))
        return LSQ_LOG_ERROR;
    if (0 == strcasecmp(str, "warn"))
        return LSQ_LOG_WARN;
    if (0 == strcasecmp(str, "notice"))
        return LSQ_LOG_NOTICE;
    if (0 == strcasecmp(str, "info"))
        return LSQ_LOG_INFO;
    if (0 == strcasecmp(str, "debug"))
        return LSQ_LOG_DEBUG;
    return -1;
}


void
lsquic_log_to_fstream (FILE *file, unsigned llts)
{
    lsquic_logger_init(&file_logger_if, file, llts);
}


int
lsquic_logger_lopt (const char *optarg_orig)
{
    char *const optarg = strdup(optarg_orig);
    char *mod_str;
    int i;
    for (i = 0; (mod_str = strtok(i ? NULL : optarg, ",")); ++i) {
        char *level_str = strchr(mod_str, '=');
        if (!level_str) {
            fprintf(stderr, "Invalid module specification `%s'\n", mod_str);
            break;
        }
        *level_str = '\0';
        ++level_str;
        enum lsquic_logger_module mod = lsquic_str_to_logger_module(mod_str);
        if (-1 == (int) mod) {
            fprintf(stderr, "`%s' is not a valid module name\n", mod_str);
            break;
        }
        enum lsq_log_level level = lsquic_str_to_log_level(level_str);
        if (-1 == (int) level) {
            fprintf(stderr, "`%s' is not a valid level\n", level_str);
            break;
        }
        lsq_log_levels[mod] = level;
        LSQ_INFO("set %s to %s", mod_str, level_str);
    }
    free(optarg);
    return mod_str == NULL ? 0 : -1;
}


int
lsquic_set_log_level (const char *level_str)
{
    enum lsq_log_level level;
    unsigned i;

    level = lsquic_str_to_log_level(level_str);
    if ((int) level >= 0)
    {
        for (i = 0; i < sizeof(lsq_log_levels) / sizeof(lsq_log_levels[0]); ++i)
            lsq_log_levels[i] = level;
        return 0;
    }
    else
        return -1;
}


/* `out' must be at least MAX_CID_LEN * 2 + 1 characters long */
void
lsquic_cid2str (const lsquic_cid_t *cid, char *out)
{
    static const char hex[] = "0123456789ABCDEF";
    int i;

    for (i = 0; i < (int) cid->len; ++i)
    {
        *out++ = hex[ cid->idbuf[i] >> 4 ];
        *out++ = hex[ cid->idbuf[i] & 0xF ];
    }
    *out = '\0';
}
