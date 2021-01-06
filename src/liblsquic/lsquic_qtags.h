/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_QTAGS_H
#define LSQUIC_QTAGS_H 1

#define TAG(a, b, c, d) ((uint32_t)(((unsigned) d << 24) + \
                ((unsigned) c << 16) + ((unsigned) b << 8) + (unsigned) a))

#define QTAG_AEAD TAG('A', 'E', 'A', 'D')
#define QTAG_AESG TAG('A', 'E', 'S', 'G')
#define QTAG_C255 TAG('C', '2', '5', '5')
#define QTAG_CCRT TAG('C', 'C', 'R', 'T')
#define QTAG_CCS  TAG('C', 'C', 'S',  0 )
#define QTAG_CFCW TAG('C', 'F', 'C', 'W')
#define QTAG_CHLO TAG('C', 'H', 'L', 'O')
#define QTAG_COPT TAG('C', 'O', 'P', 'T')
#define QTAG_CSCT TAG('C', 'S', 'C', 'T')
#define QTAG_EXPY TAG('E', 'X', 'P', 'Y')
#define QTAG_ICSL TAG('I', 'C', 'S', 'L')
#define QTAG_IRTT TAG('I', 'R', 'T', 'T')
#define QTAG_KEXS TAG('K', 'E', 'X', 'S')
#define QTAG_MIDS TAG('M', 'I', 'D', 'S')
#define QTAG_NONC TAG('N', 'O', 'N', 'C')
#define QTAG_ORBT TAG('O', 'B', 'I', 'T')
#define QTAG_PAD  TAG('P', 'A', 'D',  0 )
#define QTAG_PDMD TAG('P', 'D', 'M', 'D')
#define QTAG_PROF TAG('P', 'R', 'O', 'F')
#define QTAG_PUBS TAG('P', 'U', 'B', 'S')
#define QTAG_RCID TAG('R', 'C', 'I', 'D')
#define QTAG_REJ  TAG('R', 'E', 'J',  0 )
#define QTAG_RREJ TAG('R', 'R', 'E', 'J')
#define QTAG_SCFG TAG('S', 'C', 'F', 'G')
#define QTAG_SCID TAG('S', 'C', 'I', 'D')
#define QTAG_SCLS TAG('S', 'C', 'L', 'S')
#define QTAG_SFCW TAG('S', 'F', 'C', 'W')
#define QTAG_SHLO TAG('S', 'H', 'L', 'O')
#define QTAG_SNI  TAG('S', 'N', 'I',  0 )
#define QTAG_SREJ TAG('S', 'R', 'E', 'J')
#define QTAG_STTL TAG('S', 'T', 'T', 'L')
#define QTAG_TCID TAG('T', 'C', 'I', 'D')
#define QTAG_UAID TAG('U', 'A', 'I', 'D')
#define QTAG_VER  TAG('V', 'E', 'R',  0 )
#define QTAG_X509 TAG('X', '5', '0', '9')
#define QTAG_XLCT TAG('X', 'L', 'C', 'T')
#define QTAG_STK  TAG('S', 'T', 'K', '\0')
#define QTAG_SNO  TAG('S', 'N', 'O', '\0')
#define QTAG_CRT  TAG('C', 'R', 'T', '\xFF')

/* SMHL: Support SETTINGS_MAX_HEADER_LIST_SIZE.  Based on comments in
 * Chrome code, this setting frame will be supported by default in
 * Q037.
 */
#define QTAG_SMHL TAG('S', 'M', 'H', 'L')

/* Supported in Q037 and later.  If this option is specified in the
 * handshake, do not send or process STOP_WINDOW frames.
 */
#define QTAG_NSTP TAG('N', 'S', 'T', 'P')

/* Stateless reset token.  Used in Q044 and later. */
#define QTAG_SRST TAG('S', 'R', 'S', 'T')

#endif
