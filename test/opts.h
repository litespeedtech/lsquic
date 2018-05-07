/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef TEST_OPTS_H
#define TEST_OPTS_H 1

int
set_engine_option (struct lsquic_engine_settings *,
                   int *version_cleared, const char *name_value);

#endif
