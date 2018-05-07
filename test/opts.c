/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <stdlib.h>
#include <string.h>

#include "lsquic.h"


int
set_engine_option (struct lsquic_engine_settings *settings,
                   int *version_cleared, const char *name)
{
    int len;
    const char *val = strchr(name, '=');
    if (!val)
        return -1;
    len = val - name;
    ++val;

    switch (len)
    {
    case 2:
        if (0 == strncmp(name, "ua", 2))
        {
            settings->es_ua = val;
            return 0;
        }
        break;
    case 4:
        if (0 == strncmp(name, "cfcw", 4))
        {
            settings->es_cfcw = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "sfcw", 4))
        {
            settings->es_sfcw = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "srej", 4))
        {
            settings->es_support_srej = atoi(val);
            return 0;
        }
        break;
    case 7:
        if (0 == strncmp(name, "version", 7))
        {
            if (!*version_cleared)
            {
                *version_cleared = 1;
                settings->es_versions = 0;
            }
            const enum lsquic_version ver = lsquic_str2ver(val, strlen(val));
            if (ver < N_LSQVER)
            {
                settings->es_versions |= 1 << ver;
                return 0;
            }
        }
        else if (0 == strncmp(name, "rw_once", 7))
        {
            settings->es_rw_once = atoi(val);
            return 0;
        }
        break;
    case 8:
        if (0 == strncmp(name, "max_cfcw", 8))
        {
            settings->es_max_cfcw = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "max_sfcw", 8))
        {
            settings->es_max_sfcw = atoi(val);
            return 0;
        }
        break;
    case 10:
        if (0 == strncmp(name, "honor_prst", 10))
        {
            settings->es_honor_prst = atoi(val);
            return 0;
        }
        break;
    case 12:
        if (0 == strncmp(name, "idle_conn_to", 12))
        {
            settings->es_idle_conn_to = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "silent_close", 12))
        {
            settings->es_silent_close = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "support_nstp", 12))
        {
            settings->es_support_nstp = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "pace_packets", 12))
        {
            settings->es_pace_packets = atoi(val);
            return 0;
        }
        break;
    case 13:
        if (0 == strncmp(name, "support_tcid0", 13))
        {
            settings->es_support_tcid0 = atoi(val);
            return 0;
        }
        break;
    case 14:
        if (0 == strncmp(name, "max_streams_in", 14))
        {
            settings->es_max_streams_in = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "progress_check", 14))
        {
            settings->es_progress_check = atoi(val);
            return 0;
        }
        break;
    case 16:
        if (0 == strncmp(name, "proc_time_thresh", 16))
        {
            settings->es_proc_time_thresh = atoi(val);
            return 0;
        }
        break;
    case 20:
        if (0 == strncmp(name, "max_header_list_size", 20))
        {
            settings->es_max_header_list_size = atoi(val);
            return 0;
        }
        break;
    }

    return -1;
}


