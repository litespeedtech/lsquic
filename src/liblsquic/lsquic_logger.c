/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include "lsquic_logger.h"
#include "lsquic.h"

static enum lsquic_logger_timestamp_style g_llts = LLTS_NONE;

static int
null_vprintf (void *ctx, const char *fmt, va_list ap)
{
    return 0;
}


static int
file_vprintf (void *ctx, const char *fmt, va_list ap)
{
    return vfprintf((FILE *) ctx, fmt, ap);
}


static const struct lsquic_logger_if file_logger_if = {
    .vprintf    = file_vprintf,
};

static const struct lsquic_logger_if null_logger_if = {
    .vprintf    = null_vprintf,
};

static void *logger_ctx = NULL;
static const struct lsquic_logger_if *logger_if = &null_logger_if;

enum lsq_log_level lsq_log_levels[N_LSQUIC_LOGGER_MODULES] = {
    [LSQLM_NOMODULE]    = LSQ_LOG_WARN,
    [LSQLM_LOGGER]      = LSQ_LOG_WARN,
    [LSQLM_EVENT]       = LSQ_LOG_WARN,
    [LSQLM_ENGINE]      = LSQ_LOG_WARN,
    [LSQLM_CONN]        = LSQ_LOG_WARN,
    [LSQLM_RECHIST]     = LSQ_LOG_WARN,
    [LSQLM_STREAM]      = LSQ_LOG_WARN,
    [LSQLM_PARSE]       = LSQ_LOG_WARN,
    [LSQLM_CFCW]        = LSQ_LOG_WARN,
    [LSQLM_SFCW]        = LSQ_LOG_WARN,
    [LSQLM_SENDCTL]     = LSQ_LOG_WARN,
    [LSQLM_ALARMSET]    = LSQ_LOG_WARN,
    [LSQLM_CRYPTO]      = LSQ_LOG_WARN,
    [LSQLM_HANDSHAKE]   = LSQ_LOG_WARN,
    [LSQLM_HSK_ADAPTER] = LSQ_LOG_WARN,
    [LSQLM_CUBIC]       = LSQ_LOG_WARN,
    [LSQLM_HEADERS]     = LSQ_LOG_WARN,
    [LSQLM_FRAME_READER]= LSQ_LOG_WARN,
    [LSQLM_FRAME_WRITER]= LSQ_LOG_WARN,
    [LSQLM_CONN_HASH]   = LSQ_LOG_WARN,
    [LSQLM_ENG_HIST]    = LSQ_LOG_WARN,
    [LSQLM_SPI]         = LSQ_LOG_WARN,
    [LSQLM_DI]          = LSQ_LOG_WARN,
    [LSQLM_PACER]       = LSQ_LOG_WARN,
    [LSQLM_MIN_HEAP]    = LSQ_LOG_WARN,
};

const char *const lsqlm_to_str[N_LSQUIC_LOGGER_MODULES] = {
    [LSQLM_NOMODULE]    = "",
    [LSQLM_LOGGER]      = "logger",
    [LSQLM_EVENT]       = "event",
    [LSQLM_ENGINE]      = "engine",
    [LSQLM_CONN]        = "conn",
    [LSQLM_RECHIST]     = "rechist",
    [LSQLM_STREAM]      = "stream",
    [LSQLM_PARSE]       = "parse",
    [LSQLM_CFCW]        = "cfcw",
    [LSQLM_SFCW]        = "sfcw",
    [LSQLM_SENDCTL]     = "sendctl",
    [LSQLM_ALARMSET]    = "alarmset",
    [LSQLM_CRYPTO]      = "crypto",
    [LSQLM_HANDSHAKE]   = "handshake",
    [LSQLM_HSK_ADAPTER] = "hsk-adapter",
    [LSQLM_CUBIC]       = "cubic",
    [LSQLM_HEADERS]     = "headers",
    [LSQLM_FRAME_READER]= "frame-reader",
    [LSQLM_FRAME_WRITER]= "frame-writer",
    [LSQLM_CONN_HASH]   = "conn-hash",
    [LSQLM_ENG_HIST]    = "eng-hist",
    [LSQLM_SPI]         = "spi",
    [LSQLM_DI]          = "di",
    [LSQLM_PACER]       = "pacer",
    [LSQLM_MIN_HEAP]    = "min-heap",
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


static void
lsquic_printf (const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    logger_if->vprintf(logger_ctx, fmt, ap);
    va_end(ap);
}


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


static void
print_timestamp (void)
{
    struct tm tm;
    struct timeval tv;
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
        lsquic_printf("%04d-%02d-%02d %02d:%02d:%02d.%06d ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, (int) (tv.tv_usec));
    else if (g_llts == LLTS_YYYYMMDD_HHMMSSMS)
        lsquic_printf("%04d-%02d-%02d %02d:%02d:%02d.%03d ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, (int) (tv.tv_usec / 1000));
    else if (g_llts == LLTS_HHMMSSMS)
        lsquic_printf("%02d:%02d:%02d.%03d ", tm.tm_hour, tm.tm_min,
                                    tm.tm_sec, (int) (tv.tv_usec / 1000));
    else if (g_llts == LLTS_HHMMSSUS)
        lsquic_printf("%02d:%02d:%02d.%06d ", tm.tm_hour, tm.tm_min,
                                    tm.tm_sec, (int) tv.tv_usec);
    else if (g_llts == LLTS_CHROMELIKE)
        lsquic_printf("%02d%02d/%02d%02d%02d.%06d ", tm.tm_mon + 1,
            tm.tm_mday,tm.tm_hour, tm.tm_min, tm.tm_sec, (int) tv.tv_usec);
}


void
lsquic_logger_log3 (enum lsq_log_level log_level,
                    enum lsquic_logger_module module,
                    uint64_t conn_id, uint32_t stream_id, const char *fmt, ...)
{
    const int saved_errno = errno;

    if (g_llts != LLTS_NONE)
        print_timestamp();

    lsquic_printf("[%s] [QUIC:%"PRIu64"-%"PRIu32"] %s: ",
        lsq_loglevel2str[log_level], conn_id, stream_id, lsqlm_to_str[module]);
    va_list ap;
    va_start(ap, fmt);
    logger_if->vprintf(logger_ctx, fmt, ap);
    va_end(ap);
    lsquic_printf("\n");
    errno = saved_errno;
}


void
lsquic_logger_log2 (enum lsq_log_level log_level,
                    enum lsquic_logger_module module,
                    uint64_t conn_id, const char *fmt, ...)
{
    const int saved_errno = errno;

    if (g_llts != LLTS_NONE)
        print_timestamp();

    lsquic_printf("[%s] [QUIC:%"PRIu64"] %s: ",
        lsq_loglevel2str[log_level], conn_id, lsqlm_to_str[module]);
    va_list ap;
    va_start(ap, fmt);
    logger_if->vprintf(logger_ctx, fmt, ap);
    va_end(ap);
    lsquic_printf("\n");
    errno = saved_errno;
}


void
lsquic_logger_log1 (enum lsq_log_level log_level,
                    enum lsquic_logger_module module,
                    const char *fmt, ...)
{
    const int saved_errno = errno;

    if (g_llts != LLTS_NONE)
        print_timestamp();

    lsquic_printf("[%s] %s: ", lsq_loglevel2str[log_level],
                                                lsqlm_to_str[module]);
    va_list ap;
    va_start(ap, fmt);
    logger_if->vprintf(logger_ctx, fmt, ap);
    va_end(ap);
    lsquic_printf("\n");
    errno = saved_errno;
}


void
lsquic_logger_log0 (enum lsq_log_level log_level, const char *fmt, ...)
{
    const int saved_errno = errno;

    if (g_llts != LLTS_NONE)
        print_timestamp();

    lsquic_printf("[%s] ", lsq_loglevel2str[log_level]);
    va_list ap;
    va_start(ap, fmt);
    logger_if->vprintf(logger_ctx, fmt, ap);
    va_end(ap);
    lsquic_printf("\n");
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
