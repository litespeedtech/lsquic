#ifndef WT_FUZZ_RUNTIME_H
#define WT_FUZZ_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

enum wt_fuzz_mode
{
    WT_FUZZ_MODE_AUTO = -1,
    WT_FUZZ_MODE_CORE = 0,
    WT_FUZZ_MODE_BATON = 1,
};

enum wt_fuzz_opcode
{
    WT_FUZZ_OP_END = 0,
    WT_FUZZ_OP_NEGOTIATE = 1,
    WT_FUZZ_OP_UNI = 2,
    WT_FUZZ_OP_DGRAM_IN = 3,
    WT_FUZZ_OP_DGRAM_OUT = 4,
    WT_FUZZ_OP_REMOTE_CLOSE = 5,
    WT_FUZZ_OP_LOCAL_CLOSE = 6,
    WT_FUZZ_OP_CONTROL_RESET = 7,
    WT_FUZZ_OP_QUEUE = 8,
    WT_FUZZ_OP_DISPATCH_RESET = 9,
    WT_FUZZ_OP_STREAM_ERRORS = 10,
    WT_FUZZ_OP_BATON_CONFIG = 11,
    WT_FUZZ_OP_BATON_STREAM = 12,
    WT_FUZZ_OP_BATON_DGRAM = 13,
};

enum wt_fuzz_accept_flag
{
    WT_FUZZ_ACCEPT_SETTINGS = 1u << 0,
    WT_FUZZ_ACCEPT_WT = 1u << 1,
    WT_FUZZ_ACCEPT_CONNECT_PROTOCOL = 1u << 2,
};

enum wt_fuzz_oracle
{
    WT_FUZZ_ORACLE_REOPEN_AFTER_TERMINAL = 1u << 0,
    WT_FUZZ_ORACLE_DATAGRAM_AFTER_CLOSE = 1u << 1,
    WT_FUZZ_ORACLE_BATON_AFTER_CLOSE = 1u << 2,
    WT_FUZZ_ORACLE_BATON_MALFORMED_NOT_CLOSED = 1u << 3,
    WT_FUZZ_ORACLE_TRAILING_BATON_BYTES = 1u << 4,
    WT_FUZZ_ORACLE_REJECT_AFTER_OPEN = 1u << 5,
    WT_FUZZ_ORACLE_INVALID_REJECT_STATUS = 1u << 6,
    WT_FUZZ_ORACLE_MISSING_TERMINAL_CALLBACK = 1u << 7,
};

enum wt_fuzz_state
{
    WT_FUZZ_STATE_PENDING = 1u << 0,
    WT_FUZZ_STATE_OPENED = 1u << 1,
    WT_FUZZ_STATE_REJECTED = 1u << 2,
    WT_FUZZ_STATE_CLOSED = 1u << 3,
    WT_FUZZ_STATE_BATON = 1u << 4,
};

struct wt_fuzz_result
{
    unsigned mode;
    unsigned state_mask;
    unsigned helper_mask;
    unsigned oracle_mask;
    unsigned session_opened;
    unsigned session_rejected;
    unsigned session_closed;
    unsigned datagram_reads;
    unsigned datagram_writes;
    unsigned baton_messages;
    unsigned baton_errors;
    unsigned accept_status;
    uint64_t sink;
};

int
wt_fuzz_run_trace (const unsigned char *data, size_t size, int forced_mode,
                   struct wt_fuzz_result *result);

unsigned
wt_fuzz_bug_oracle_mask (const struct wt_fuzz_result *result);

size_t
wt_fuzz_build_baton_message (unsigned char *buf, size_t bufsz,
                             unsigned padding_len, unsigned baton,
                             int add_trailing);

#endif
