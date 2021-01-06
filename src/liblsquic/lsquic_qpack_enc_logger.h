/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/* This header file is included into lsqpack.c */

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"

#define LSQUIC_LOGGER_MODULE LSQLM_QPACK_ENC
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(enc->qpe_logger_ctx)
#include "lsquic_logger.h"

#define E_DEBUG LSQ_DEBUG
#define E_INFO LSQ_INFO
#define E_WARN LSQ_WARN
#define E_ERROR LSQ_ERROR
