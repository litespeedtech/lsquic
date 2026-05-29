#ifndef BIN_TOOL_LOG_H
#define BIN_TOOL_LOG_H

#ifndef TOOL_LOG_PREFIX
#define TOOL_LOG_PREFIX "tool"
#endif

#include <stdarg.h>
#include <stdio.h>

#include "../src/liblsquic/lsquic_logger.h"


static inline void
tool_log_prefixed (enum lsq_log_level level, const char *fmt, ...)
{
    char prefixed_fmt[2048];
    int off;
    va_list ap;

    off = snprintf(prefixed_fmt, sizeof(prefixed_fmt), "%s: ", TOOL_LOG_PREFIX);
    if (off < 0 || (size_t) off >= sizeof(prefixed_fmt))
        off = 0;

    if ((size_t) off < sizeof(prefixed_fmt))
        snprintf(prefixed_fmt + off, sizeof(prefixed_fmt) - (size_t) off,
                                                        "%s", fmt);

    va_start(ap, fmt);
    lsquic_logger_log0v(level, prefixed_fmt, ap);
    va_end(ap);
}


#define TOOL_LOG(level, ...) do {                                          \
    if (LSQ_LOG_ENABLED_EXT(level, LSQLM_NOMODULE))                        \
        tool_log_prefixed(level, __VA_ARGS__);                             \
} while (0)

#undef LSQ_DEBUG
#undef LSQ_INFO
#undef LSQ_NOTICE
#undef LSQ_WARN
#undef LSQ_ERROR
#undef LSQ_ALERT
#undef LSQ_CRIT
#undef LSQ_EMERG

#define LSQ_DEBUG(...)   TOOL_LOG(LSQ_LOG_DEBUG, __VA_ARGS__)
#define LSQ_INFO(...)    TOOL_LOG(LSQ_LOG_INFO, __VA_ARGS__)
#define LSQ_NOTICE(...)  TOOL_LOG(LSQ_LOG_NOTICE, __VA_ARGS__)
#define LSQ_WARN(...)    TOOL_LOG(LSQ_LOG_WARN, __VA_ARGS__)
#define LSQ_ERROR(...)   TOOL_LOG(LSQ_LOG_ERROR, __VA_ARGS__)
#define LSQ_ALERT(...)   TOOL_LOG(LSQ_LOG_ALERT, __VA_ARGS__)
#define LSQ_CRIT(...)    TOOL_LOG(LSQ_LOG_CRIT, __VA_ARGS__)
#define LSQ_EMERG(...)   TOOL_LOG(LSQ_LOG_EMERG, __VA_ARGS__)

#endif
