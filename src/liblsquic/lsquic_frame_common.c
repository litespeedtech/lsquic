/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <stdint.h>

#include "lsquic_frame_common.h"


const char *
lsquic_http_setting_id2str (enum settings_param id)
{
    switch (id)
    {
    case SETTINGS_HEADER_TABLE_SIZE:
        return "SETTINGS_HEADER_TABLE_SIZE";
    case SETTINGS_ENABLE_PUSH:
        return "SETTINGS_ENABLE_PUSH";
    case SETTINGS_MAX_CONCURRENT_STREAMS:
        return "SETTINGS_MAX_CONCURRENT_STREAMS";
    case SETTINGS_INITIAL_WINDOW_SIZE:
        return "SETTINGS_INITIAL_WINDOW_SIZE";
    case SETTINGS_MAX_FRAME_SIZE:
        return "SETTINGS_MAX_FRAME_SIZE";
    case SETTINGS_MAX_HEADER_LIST_SIZE:
        return "SETTINGS_MAX_HEADER_LIST_SIZE";
    }
    return "<unknown>";
}
