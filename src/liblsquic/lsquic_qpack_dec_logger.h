/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/* This header file is included into lsqpack.c */

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"

#undef LSQUIC_LOGGER_MODULE
#undef LSQUIC_LOG_CONN_ID

#define LSQUIC_LOGGER_MODULE LSQLM_QPACK_DEC
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(dec->qpd_logger_ctx)
#include "lsquic_logger.h"

#define D_DEBUG LSQ_DEBUG
#define D_INFO LSQ_INFO
#define D_WARN LSQ_WARN
#define D_ERROR LSQ_ERROR
