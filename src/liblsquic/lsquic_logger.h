/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_logger.h -- logging functions and macros.
 *
 * Usage (this assumes MY_MODULE) is a part of enum lsquic_logger_module):
 *   #define LSQUIC_LOGGER_MODULE MY_MODULE
 *   #include "lsquic_logger.h"
 *   LSQ_INFO("info message");
 *
 * If you want log messages from your module to contain connection ID, #define
 * LSQUIC_LOG_CONN_ID so that it evaluates to connection ID.  If, in addition,
 * you want stream ID to be logged, #define LSQUIC_LOG_STREAM_ID similarly.
 * See existing code for examples.
 *
 * To add a module:
 *   1. Add entry to enum lsquic_logger_module.
 *   2. Update lsqlm_to_str.
 *   3. Update lsq_log_levels.
 */

#ifndef LSQUIC_LOGGER_H
#define LSQUIC_LOGGER_H

#include <stdint.h>
#include <stdio.h>

#include "lsquic_shared_support.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#ifndef LSQUIC_LOWEST_LOG_LEVEL
#   define LSQUIC_LOWEST_LOG_LEVEL LSQ_LOG_DEBUG
#endif

/* Same levels as in sys/syslog.h: */
enum lsq_log_level {
    LSQ_LOG_EMERG,
    LSQ_LOG_ALERT,
    LSQ_LOG_CRIT,
    LSQ_LOG_ERROR,
    LSQ_LOG_WARN,
    LSQ_LOG_NOTICE,
    LSQ_LOG_INFO,
    LSQ_LOG_DEBUG,
    N_LSQUIC_LOG_LEVELS
};

enum lsquic_logger_module {
    LSQLM_NOMODULE,
    LSQLM_LOGGER,
    LSQLM_EVENT,
    LSQLM_ENGINE,
    LSQLM_CONN,
    LSQLM_STREAM,
    LSQLM_PARSE,
    LSQLM_CFCW,
    LSQLM_SFCW,
    LSQLM_SENDCTL,
    LSQLM_ALARMSET,
    LSQLM_CRYPTO,
    LSQLM_HANDSHAKE,
    LSQLM_HSK_ADAPTER,
    LSQLM_BBR,
    LSQLM_CUBIC,
    LSQLM_ADAPTIVE_CC,
    LSQLM_HEADERS,
    LSQLM_FRAME_WRITER,
    LSQLM_FRAME_READER,
    LSQLM_MINI_CONN,
    LSQLM_TOKGEN,
    LSQLM_ENG_HIST,
    LSQLM_SPI,
    LSQLM_HPI,
    LSQLM_DI,
    LSQLM_PRQ,
    LSQLM_PACER,
    LSQLM_HTTP1X,
    LSQLM_QLOG,
    LSQLM_TRAPA,
    LSQLM_PURGA,
    LSQLM_HCSI_READER,
    LSQLM_HCSO_WRITER,
    LSQLM_QENC_HDL,
    LSQLM_QDEC_HDL,
    LSQLM_QPACK_ENC,
    LSQLM_QPACK_DEC,
    LSQLM_PRIO,
    LSQLM_BW_SAMPLER,
    LSQLM_PACKET_RESIZE,
    LSQLM_CONN_STATS,
    N_LSQUIC_LOGGER_MODULES
};

/* Each module has its own log level.
 */

LSQUIC_EXTERN enum lsq_log_level lsq_log_levels[N_LSQUIC_LOGGER_MODULES];

extern const char *const lsqlm_to_str[N_LSQUIC_LOGGER_MODULES];

extern const char *const lsq_loglevel2str[N_LSQUIC_LOG_LEVELS];

#define LSQ_LOG_ENABLED_EXT(level, module) (                            \
    level <= LSQUIC_LOWEST_LOG_LEVEL && level <= lsq_log_levels[module])

#define LSQ_LOG_ENABLED(level) LSQ_LOG_ENABLED_EXT(level, LSQUIC_LOGGER_MODULE)

struct lsquic_cid;

/* The functions that perform actual logging are void.  This is an
 * optimization.  In majority of cases the calls will succeed; even if
 * they fail, there is nothing (at least, nothing simple) to be done to
 * handle logging failure.
 */

/* There are four levels of log functions, depending on whether they take
 * the following arguments:
 *  1. Logger module
 *  2. Connection ID
 *  3. Stream ID
 *
 * Each level of logging function supports one additional argument, as seen
 * below.  LSQ_LOG is set to one of LSQ_LOG0, LSQ_LOG1, LSQ_LOG2, or LSQ_LOG3.
 * You can still use LSQ_LOG{0..3} directly.
 */

void
lsquic_logger_log3 (enum lsq_log_level, enum lsquic_logger_module,
                    const struct lsquic_cid *conn_id,
                    lsquic_stream_id_t stream_id, const char *format, ...)
#if __GNUC__
            __attribute__((format(printf, 5, 6)))
#endif
;
#   define LSQ_LOG3(level, ...) do {                                         \
        if (LSQ_LOG_ENABLED(level))                                          \
            lsquic_logger_log3(level, LSQUIC_LOGGER_MODULE,                  \
                    LSQUIC_LOG_CONN_ID, LSQUIC_LOG_STREAM_ID, __VA_ARGS__);  \
    } while (0)


void
lsquic_logger_log2 (enum lsq_log_level, enum lsquic_logger_module,
                    const struct lsquic_cid *conn_id, const char *format, ...)
#if __GNUC__
            __attribute__((format(printf, 4, 5)))
#endif
;
#   define LSQ_LOG2(level, ...) do {                                         \
        if (LSQ_LOG_ENABLED(level))                                          \
            lsquic_logger_log2(level, LSQUIC_LOGGER_MODULE,                  \
                                       LSQUIC_LOG_CONN_ID, __VA_ARGS__);     \
    } while (0)
#   define LSQ_LOG2C(level, ...) do {                                        \
        if (LSQ_LOG_ENABLED(level))                                          \
        {                                                                    \
            char cidbuf_[MAX_CID_LEN * 2 + 1];                               \
            lsquic_logger_log2(level, LSQUIC_LOGGER_MODULE,                  \
                                       LSQUIC_LOG_CONN_ID, __VA_ARGS__);     \
        }                                                                    \
    } while (0)

void
lsquic_logger_log1 (enum lsq_log_level, enum lsquic_logger_module,
                    const char *format, ...)
#if __GNUC__
            __attribute__((format(printf, 3, 4)))
#endif
;
#   define LSQ_LOG1(level, ...) do {                                         \
        if (LSQ_LOG_ENABLED(level))                                          \
            lsquic_logger_log1(level, LSQUIC_LOGGER_MODULE, __VA_ARGS__);    \
    } while (0)
#   define LSQ_LOG1C(level, ...) do {                                        \
        if (LSQ_LOG_ENABLED(level))                                          \
        {                                                                    \
            char cidbuf_[MAX_CID_LEN * 2 + 1];                               \
            lsquic_logger_log1(level, LSQUIC_LOGGER_MODULE, __VA_ARGS__);    \
        }                                                                    \
    } while (0)

void
lsquic_logger_log0 (enum lsq_log_level, const char *format, ...)
#if __GNUC__
            __attribute__((format(printf, 2, 3)))
#endif
;
#   define LSQ_LOG0(level, ...) do {                                         \
        if (LSQ_LOG_ENABLED(level))                                          \
            lsquic_logger_log0(level, __VA_ARGS__);                          \
    } while (0)
#   define LSQ_LOG0C(level, ...) do {                                        \
        if (LSQ_LOG_ENABLED(level))                                          \
        {                                                                    \
            char cidbuf_[MAX_CID_LEN * 2 + 1];                               \
            lsquic_logger_log0(level, __VA_ARGS__);                          \
        }                                                                    \
    } while (0)

#if defined(LSQUIC_LOGGER_MODULE)
#if defined(LSQUIC_LOG_CONN_ID)
#if defined(LSQUIC_LOG_STREAM_ID)
#       define LSQ_LOG LSQ_LOG3
#else
#       define LSQ_LOG LSQ_LOG2
#       define LSQ_LOGC LSQ_LOG2C
#endif
#else
#       define LSQ_LOG LSQ_LOG1
#       define LSQ_LOGC LSQ_LOG1C
#endif
#else
#       define LSQ_LOG LSQ_LOG0
#       define LSQ_LOGC LSQ_LOG0C
#       define LSQUIC_LOGGER_MODULE LSQLM_NOMODULE
#endif

#define LSQ_DEBUG(...)   LSQ_LOG(LSQ_LOG_DEBUG,  __VA_ARGS__)
#define LSQ_WARN(...)    LSQ_LOG(LSQ_LOG_WARN,   __VA_ARGS__)
#define LSQ_ALERT(...)   LSQ_LOG(LSQ_LOG_ALERT,  __VA_ARGS__)
#define LSQ_CRIT(...)    LSQ_LOG(LSQ_LOG_CRIT,   __VA_ARGS__)
#define LSQ_ERROR(...)   LSQ_LOG(LSQ_LOG_ERROR,  __VA_ARGS__)
#define LSQ_NOTICE(...)  LSQ_LOG(LSQ_LOG_NOTICE, __VA_ARGS__)
#define LSQ_INFO(...)    LSQ_LOG(LSQ_LOG_INFO,   __VA_ARGS__)
#define LSQ_EMERG(...)   LSQ_LOG(LSQ_LOG_EMERG,  __VA_ARGS__)

#define LSQ_DEBUGC(...)   LSQ_LOGC(LSQ_LOG_DEBUG,  __VA_ARGS__)
#define LSQ_WARNC(...)    LSQ_LOGC(LSQ_LOG_WARN,   __VA_ARGS__)
#define LSQ_ALERTC(...)   LSQ_LOGC(LSQ_LOG_ALERT,  __VA_ARGS__)
#define LSQ_CRITC(...)    LSQ_LOGC(LSQ_LOG_CRIT,   __VA_ARGS__)
#define LSQ_ERRORC(...)   LSQ_LOGC(LSQ_LOG_ERROR,  __VA_ARGS__)
#define LSQ_NOTICEC(...)  LSQ_LOGC(LSQ_LOG_NOTICE, __VA_ARGS__)
#define LSQ_INFOC(...)    LSQ_LOGC(LSQ_LOG_INFO,   __VA_ARGS__)
#define LSQ_EMERGC(...)   LSQ_LOGC(LSQ_LOG_EMERG,  __VA_ARGS__)

/* Shorthand for printing to file streams using internal lsquic_logger_if
 */
void
lsquic_log_to_fstream (FILE *, unsigned llts);

enum lsquic_logger_module
lsquic_str_to_logger_module (const char *);

enum lsq_log_level
lsquic_str_to_log_level (const char *);

/* Parse and set log levels passed via -l flag.  If an error is encountered,
 * an error message is printed to stderr and negative value is returned.
 */
int
lsquic_logger_lopt (const char *optarg);

#define CID_FMT ".*s"

#define CID_BITS_B(cid, b) 2 * (int) (cid)->len, \
                                    (lsquic_cid2str(cid, b), b)

#define CID_BITS(cid) CID_BITS_B(cid, cidbuf_)

void
lsquic_cid2str (const struct lsquic_cid *, char *out);

const struct lsquic_cid *
lsquic_conn_log_cid (const struct lsquic_conn *);

#ifdef __cplusplus
}
#endif

#endif
