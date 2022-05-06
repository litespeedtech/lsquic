/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/* Copyright (c) 2015 The Chromium Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.chrome file.
 */

/* This file contains common certificates. It's designed to be #included in
 * another file, in a namespace. */

/* Updated for C style, David Shue */
/*
 * Replace "kDERCert"  to "der_cert2_"
 * 
 */

#include <stdint.h>

#include "common_cert_set_2a.inc"
#include "common_cert_set_2b.inc"

#define common_certs2_num 54
static const unsigned char * const common_certs2[common_certs2_num] = {
  der_cert2_0,
  der_cert2_1,
  der_cert2_2,
  der_cert2_3,
  der_cert2_4,
  der_cert2_5,
  der_cert2_6,
  der_cert2_7,
  der_cert2_8,
  der_cert2_9,
  der_cert2_10,
  der_cert2_11,
  der_cert2_12,
  der_cert2_13,
  der_cert2_14,
  der_cert2_15,
  der_cert2_16,
  der_cert2_17,
  der_cert2_18,
  der_cert2_19,
  der_cert2_20,
  der_cert2_21,
  der_cert2_22,
  der_cert2_23,
  der_cert2_24,
  der_cert2_25,
  der_cert2_26,
  der_cert2_27,
  der_cert2_28,
  der_cert2_29,
  der_cert2_30,
  der_cert2_31,
  der_cert2_32,
  der_cert2_33,
  der_cert2_34,
  der_cert2_35,
  der_cert2_36,
  der_cert2_37,
  der_cert2_38,
  der_cert2_39,
  der_cert2_40,
  der_cert2_41,
  der_cert2_42,
  der_cert2_43,
  der_cert2_44,
  der_cert2_45,
  der_cert2_46,
  der_cert2_47,
  der_cert2_48,
  der_cert2_49,
  der_cert2_50,
  der_cert2_51,
  der_cert2_52,
  der_cert2_53,
};

static const size_t common_certs2_lens[common_certs2_num] = {
  897,
  911,
  985,
  1012,
  1049,
  1062,
  1065,
  1071,
  1084,
  1096,
  1097,
  1105,
  1107,
  1117,
  1127,
  1133,
  1136,
  1138,
  1153,
  1171,
  1172,
  1176,
  1182,
  1188,
  1194,
  1203,
  1205,
  1206,
  1210,
  1222,
  1226,
  1236,
  1236,
  1236,
  1238,
  1256,
  1270,
  1280,
  1283,
  1284,
  1287,
  1315,
  1327,
  1340,
  1418,
  1447,
  1509,
  1520,
  1570,
  1581,
  1592,
  1628,
  1632,
  1770,
};

#define common_certs2_hash UINT64_C(0xe81a92926081e801)
