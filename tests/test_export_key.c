/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

#include "lsquic_crypto.h"

#ifdef WIN32
#pragma warning(disable:4295 4245) //4295: array is too small to include a terminating null character, 4245:initializing': conversion from 'int' to 'unsigned char', signed/unsigned mismatch
#endif

struct export_key_test
{
    /* Line number for easy verification: */
    int                 ekt_lineno;
    /* Input: */
    size_t              ekt_ikm_sz,
                        ekt_salt_sz,
                        ekt_context_sz;
    unsigned char       ekt_ikm[0x20],
                        ekt_salt[0x60],
                        ekt_context[0x1000];
    size_t              ekt_server_key_sz,
                        ekt_server_iv_sz,
                        ekt_client_key_sz,
                        ekt_client_iv_sz;
    /* Output: */
    unsigned char       ekt_server_key[32],
                        ekt_client_key[32],
                        ekt_server_iv[4],
                        ekt_client_iv[4];
};


static const struct export_key_test tests[] = {

#define BUF_PAIR(name, buf) .ekt_##name = buf, .ekt_##name##_sz = sizeof(buf) - 1

/* Convert using
 *  sed '/^0x/{s/0x....: /"/; s~  .*~"~; s/ /\\x/g}'
 */

/*
[0112/144512.438811:VERBOSE4:hkdf.cc(87)] secret:
0x0000:  73 65 63 72 65 74                                secret

[0112/144512.438876:VERBOSE4:hkdf.cc(88)] salt:
0x0000:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0x0010:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

[0112/144512.438916:VERBOSE4:hkdf.cc(89)] info:
0x0000:  51 55 49 43 20 73 6f 75 72 63 65 20 61 64 64 72  QUIC.source.addr
0x0010:  65 73 73 20 74 6f 6b 65 6e 20 6b 65 79           ess.token.key

[0112/144512.438983:VERBOSE4:hkdf.cc(103)] PRK:
0x0000:  18 10 e8 d3 41 b9 e6 1e 88 89 5f ba 0b 1a a2 bd  ....A....._.....
0x0010:  03 cb 6c 8f ff 2b 36 8e 66 6e f8 ef de f5 b4 fb  ..l..+6.fn......

[0112/144512.439042:VERBOSE4:hkdf.cc(149)] client key:
0x0000:  59 58 f5 06 ac 1f f9 e6 2d 0b f9 77 df 05 c9 35  YX......-..w...5

[0112/144512.439076:VERBOSE4:hkdf.cc(156)] server key:
0x0000:  45 ca 99 4a 40 bc e3 3b 32 16 59 51 98 36 d4 21  E..J@..;2.YQ.6.!
 */
    {
        .ekt_lineno         = __LINE__,
        .ekt_ikm            = "secret",
        .ekt_ikm_sz         = 6,
        BUF_PAIR(salt,
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
        BUF_PAIR(context, "QUIC source address token key"),
        BUF_PAIR(client_key,
            "\x59\x58\xf5\x06\xac\x1f\xf9\xe6\x2d\x0b\xf9\x77\xdf\x05\xc9\x35"
            ),
        BUF_PAIR(server_key,
            "\x45\xca\x99\x4a\x40\xbc\xe3\x3b\x32\x16\x59\x51\x98\x36\xd4\x21"
            ),
    },

/*
[0112/144522.376235:VERBOSE4:hkdf.cc(87)] secret:
0x0000:  ab 62 c8 e1 03 63 b5 4e b9 c5 e4 f1 d9 47 ed 60  .b...c.N.....G.`
0x0010:  43 2f 3b c2 27 c3 2c 51 e7 7f e7 4b 5e a4 08 29  C/;.'.,Q...K^..)

[0112/144522.376323:VERBOSE4:hkdf.cc(88)] salt:
0x0000:  58 77 dc d2 a5 d0 b3 7f 65 c3 cd 6b 03 a7 34 53  Xw......e..k..4S
0x0010:  d7 8b 6e 56 3c a0 22 a2 ab 7a 1e 4c 40 e9 cf d6  ..nV<."..z.L@...
0x0020:  02 2e ef d3 08 bc d1 be cb 70 f1 92 8e ec 27 7b  .........p....'{
0x0030:  b6 b5 27 ce ea 43 7d c2 34 b7 be 44 a3 89 70 9a  ..'..C}.4..D..p.
0x0040:  62 65 46 fa e5 86 44 04 fb 66 22 2d 7c 07 b8 b8  beF...D..f"-|...

[0112/144522.376423:VERBOSE4:hkdf.cc(89)] info:
0x0000:  51 55 49 43 20 6b 65 79 20 65 78 70 61 6e 73 69  QUIC.key.expansi
0x0010:  6f 6e 00 a8 9f 60 a0 05 e6 1a 02 43 48 4c 4f 18  on...`.....CHLO.
0x0020:  00 00 00 50 41 44 00 01 02 00 00 53 4e 49 00 10  ...PAD.....SNI..
0x0030:  02 00 00 53 54 4b 00 44 02 00 00 53 4e 4f 00 74  ...STK.D...SNO.t
0x0040:  02 00 00 56 45 52 00 78 02 00 00 43 43 53 00 88  ...VER.x...CCS..
0x0050:  02 00 00 4e 4f 4e 43 a8 02 00 00 4d 53 50 43 ac  ...NONC....MSPC.
0x0060:  02 00 00 41 45 41 44 b0 02 00 00 53 43 49 44 c0  ...AEAD....SCID.
0x0070:  02 00 00 50 44 4d 44 c4 02 00 00 53 4d 48 4c c8  ...PDMD....SMHL.
0x0080:  02 00 00 49 43 53 4c cc 02 00 00 43 54 49 4d d4  ...ICSL....CTIM.
0x0090:  02 00 00 4e 4f 4e 50 f4 02 00 00 50 55 42 53 14  ...NONP....PUBS.
0x00a0:  03 00 00 4d 49 44 53 18 03 00 00 53 43 4c 53 1c  ...MIDS....SCLS.
0x00b0:  03 00 00 4b 45 58 53 20 03 00 00 58 4c 43 54 28  ...KEXS....XLCT(
0x00c0:  03 00 00 43 53 43 54 28 03 00 00 43 43 52 54 30  ...CSCT(...CCRT0
0x00d0:  03 00 00 43 46 43 57 34 03 00 00 53 46 43 57 38  ...CFCW4...SFCW8
0x00e0:  03 00 00 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ...-------------
0x00f0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0100:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0110:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0120:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0130:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0140:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0150:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0160:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0170:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0180:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0190:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x01a0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x01b0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x01c0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x01d0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x01e0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x01f0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0200:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0210:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0220:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0230:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0240:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0250:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0260:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0270:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0280:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x0290:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x02a0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x02b0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x02c0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x02d0:  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  ----------------
0x02e0:  2d 2d 2d 2d 77 77 77 2e 65 78 61 6d 70 6c 65 2e  ----www.example.
0x02f0:  6f 72 67 2f 22 e6 5d e0 f8 78 94 5a 23 2d ba b4  org/".]..x.Z#-..
0x0300:  d7 e8 aa 1a 46 21 20 20 94 7f 0d 7a 5e 2e 41 98  ....F!.....z^.A.
0x0310:  66 0e 44 88 eb f3 41 c5 b1 e2 65 a7 38 01 3c 2c  f.D...A...e.8.<,
0x0320:  0d eb 00 2b 73 48 da 02 2e ef d3 08 bc d1 be cb  ...+sH..........
0x0330:  70 f1 92 8e ec 27 7b b6 b5 27 ce ea 43 7d c2 34  p....'{..'..C}.4
0x0340:  b7 be 44 a3 89 70 9a 62 65 46 fa e5 86 44 04 fb  ..D..p.beF...D..
0x0350:  66 22 2d 7c 07 b8 b8 51 30 33 37 01 e8 81 60 92  f"-|...Q037...`.
0x0360:  92 1a e8 7e ed 80 86 a2 15 82 91 58 77 dc d2 a5  ...~.......Xw...
0x0370:  d0 b3 7f 65 c3 cd 6b 03 a7 34 53 d7 8b 6e 56 3c  ...e..k..4S..nV<
0x0380:  a0 22 a2 ab 7a 1e 4c 40 e9 cf d6 64 00 00 00 43  ."..z.L@...d...C
0x0390:  43 32 30 08 68 02 10 36 fa fb 68 b3 8a aa a4 e7  C20.h..6..h.....
0x03a0:  96 41 ca 58 35 30 39 01 00 00 00 58 02 00 00 d2  .A.X509....X....
0x03b0:  dc 77 58 00 00 00 00 2d c8 07 0e 2a 4b 39 15 ae  .wX....-...*K9..
0x03c0:  98 1f 5c b1 6f ac 77 0e f7 ea dd 57 93 8b 38 f2  ..\.o.w....W..8.
0x03d0:  8a 45 f5 d3 01 c1 9b a5 79 21 45 36 4f c6 f6 83  .E......y!E6O...
0x03e0:  bc ba 1d e5 06 c1 8e 69 4c b6 e2 99 35 17 a1 ca  .......iL...5...
0x03f0:  f0 d2 82 d9 a5 b0 3e 64 00 00 00 01 00 00 00 43  ......>d.......C
0x0400:  32 35 35 b4 e2 9f fc ab 17 f2 4a b4 e2 9f fc ab  255.......J.....
0x0410:  17 f2 4a 00 00 f0 00 00 00 60 00 53 43 46 47 06  ..J......`.SCFG.
0x0420:  00 00 00 41 45 41 44 08 00 00 00 53 43 49 44 18  ...AEAD....SCID.
0x0430:  00 00 00 50 55 42 53 3b 00 00 00 4b 45 58 53 3f  ...PUBS;...KEXS?
0x0440:  00 00 00 4f 42 49 54 47 00 00 00 45 58 50 59 4f  ...OBITG...EXPYO
0x0450:  00 00 00 41 45 53 47 43 43 32 30 08 68 02 10 36  ...AESGCC20.h..6
0x0460:  fa fb 68 b3 8a aa a4 e7 96 41 ca 20 00 00 f6 00  ..h......A......
0x0470:  dd 9e 3e 30 4f d9 fb 26 77 4e ce 35 79 6d 98 6d  ..>0O..&wN.5ym.m
0x0480:  9a e6 a5 19 c0 b8 72 66 cd 46 b1 b6 90 4a 43 32  ......rf.F...JC2
0x0490:  35 35 a5 d0 b3 7f 65 c3 cd 6b c8 2a 65 59 00 00  55....e..k.*eY..
0x04a0:  00 00 30 82 03 b4 30 82 02 9c a0 03 02 01 02 02  ..0...0.........
0x04b0:  01 01 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05  ..0...*.H.......
0x04c0:  00 30 1e 31 1c 30 1a 06 03 55 04 03 0c 13 51 55  .0.1.0...U....QU
0x04d0:  49 43 20 53 65 72 76 65 72 20 52 6f 6f 74 20 43  IC.Server.Root.C
0x04e0:  41 30 1e 17 0d 31 36 31 32 32 32 32 31 32 39 30  A0...16122221290
0x04f0:  34 5a 17 0d 31 36 31 32 32 35 32 31 32 39 30 34  4Z..161225212904
0x0500:  5a 30 64 31 0b 30 09 06 03 55 04 06 13 02 55 53  Z0d1.0...U....US
0x0510:  31 13 30 11 06 03 55 04 08 0c 0a 43 61 6c 69 66  1.0...U....Calif
0x0520:  6f 72 6e 69 61 31 16 30 14 06 03 55 04 07 0c 0d  ornia1.0...U....
0x0530:  4d 6f 75 6e 74 61 69 6e 20 56 69 65 77 31 14 30  Mountain.View1.0
0x0540:  12 06 03 55 04 0a 0c 0b 51 55 49 43 20 53 65 72  ...U....QUIC.Ser
0x0550:  76 65 72 31 12 30 10 06 03 55 04 03 0c 09 31 32  ver1.0...U....12
0x0560:  37 2e 30 2e 30 2e 31 30 82 01 22 30 0d 06 09 2a  7.0.0.10.."0...*
0x0570:  86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30  .H.............0
0x0580:  82 01 0a 02 82 01 01 00 f0 55 bf b6 81 96 69 f3  .........U....i.
0x0590:  7a 06 f7 68 89 af fe 9c 30 e9 bb e7 0d 9b 37 c1  z..h....0.....7.
0x05a0:  f6 a0 b8 28 72 bc 53 8e 8c 2c 99 a0 63 fe 7e 84  ...(r.S..,..c.~.
0x05b0:  cb 35 11 96 24 98 20 ee 22 59 53 61 47 aa bc 66  .5..$..."YSaG..f
0x05c0:  8f 05 4f ec b6 a7 9c 3c fb de a7 24 3f d8 fd 97  ..O....<...$?...
0x05d0:  a8 79 50 80 86 11 3a a8 a4 1e fa 7b 1e cf 4b 5c  .yP...:....{..K\
0x05e0:  7e 1c 23 5b b2 e1 d4 d7 ca 32 6e 4c 74 01 42 f0  ~.#[.....2nLt.B.
0x05f0:  36 14 09 f8 c7 22 6f 13 69 4a 32 9d e1 33 36 1b  6...."o.iJ2..36.
0x0600:  e6 4d 74 6c b8 fa 49 f0 9a 0d 81 9f c6 b8 88 79  .Mtl..I........y
0x0610:  70 6c 0c 1c fb f9 70 27 e8 c1 c7 dd ba d0 97 f9  pl....p'........
0x0620:  ca 1a 1f 24 64 3b f7 3d 4c 67 b1 e2 87 07 f9 a2  ...$d;.=Lg......
0x0630:  b8 d5 82 06 80 cd 1f 97 ca 4b 39 87 4f 0a b7 a7  .........K9.O...
0x0640:  36 cf f2 fe 08 7b 46 7d 25 61 f5 ec 18 13 f5 e1  6....{F}%a......
0x0650:  4b a9 eb ec a8 53 7f ad 66 19 fb 22 70 cc fa df  K....S..f.."p...
0x0660:  64 da f4 b1 07 17 3d b0 0f d7 0d df fe e8 9b 3a  d.....=........:
0x0670:  86 fc a0 85 d1 03 a3 4d 89 9c cc de c6 c6 de 9a  .......M........
0x0680:  d0 f3 7f 6d 1d 0a 8e 27 02 03 01 00 01 a3 81 b6  ...m...'........
0x0690:  30 81 b3 30 0c 06 03 55 1d 13 01 01 ff 04 02 30  0..0...U.......0
0x06a0:  00 30 1d 06 03 55 1d 0e 04 16 04 14 1a 79 b5 96  .0...U.......y..
0x06b0:  b0 18 f3 1a 21 fd 8c 82 30 b9 af 94 60 d1 62 fe  ....!...0...`.b.
0x06c0:  30 1f 06 03 55 1d 23 04 18 30 16 80 14 f2 38 71  0...U.#..0....8q
0x06d0:  39 4b 66 26 ac 8c 4b 3e cc 03 88 d7 55 1f aa 5d  9Kf&..K>....U..]
0x06e0:  92 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06  .0...U.%..0...+.
0x06f0:  01 05 05 07 03 01 06 08 2b 06 01 05 05 07 03 02  ........+.......
0x0700:  30 44 06 03 55 1d 11 04 3d 30 3b 82 0f 77 77 77  0D..U...=0;..www
0x0710:  2e 65 78 61 6d 70 6c 65 2e 6f 72 67 82 10 6d 61  .example.org..ma
0x0720:  69 6c 2e 65 78 61 6d 70 6c 65 2e 6f 72 67 82 10  il.example.org..
0x0730:  6d 61 69 6c 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d  mail.example.com
0x0740:  87 04 7f 00 00 01 30 0d 06 09 2a 86 48 86 f7 0d  ......0...*.H...
0x0750:  01 01 0b 05 00 03 82 01 01 00 68 24 9a 07 f7 b8  ..........h$....
0x0760:  7d 96 ef fd e5 0c 7c 2c 31 a8 95 e2 fa 05 a7 3e  }.....|,1......>
0x0770:  98 3b 77 3c 0a e1 a2 16 51 7f 58 43 82 6c c4 66  .;w<....Q.XC.l.f
0x0780:  f3 88 26 17 bd e5 d3 b1 84 2a b7 cf e1 d1 b2 85  ..&......*......
0x0790:  3b fc 20 1a df 1d 24 f5 dc 58 b7 ef 36 72 9f d7  ;.....$..X..6r..
0x07a0:  da c5 f4 46 08 4b 17 64 99 1a b1 1e de 68 00 74  ...F.K.d.....h.t
0x07b0:  4c 1a 7c 55 b9 7f c3 2d fa 58 3b 6b 93 5a 0a 43  L.|U...-.X;k.Z.C
0x07c0:  e3 41 4e 4e 5c 2c a6 0c cf 17 c4 86 ea 58 37 a2  .ANN\,.......X7.
0x07d0:  40 de 22 eb ad 07 77 05 cb 57 df 49 56 96 f7 d4  @."...w..W.IV...
0x07e0:  a6 9a ac 65 c9 2e 0e dc 53 14 6c 1d 41 68 22 8d  ...e....S.l.Ah".
0x07f0:  1f 40 49 6d b2 a7 6c 26 a5 60 52 a7 aa 8a 57 0c  .@Im..l&.`R...W.
0x0800:  d6 45 54 5b 18 75 00 c2 cb 64 ae 66 45 0d 96 67  .ET[.u...d.fE..g
0x0810:  0b 6d 11 c6 51 b5 2b e3 e8 68 2d 60 91 b0 bc 3c  .m..Q.+..h-`...<
0x0820:  03 69 99 06 9f 16 e4 a8 b9 8c ac 04 9f 1f e9 0a  .i..............
0x0830:  81 eb 60 ae 27 6d 87 f7 0b cf 9c bb 1a db 15 8a  ..`.'m..........
0x0840:  92 08 28 5a ac 9d 37 2c 35 f2 c1 bb e6 01 4a f6  ..(Z..7,5.....J.
0x0850:  4b 67 f5 ec 1f 1f a7 04 9b 21                    Kg.......!

[0112/144522.378102:VERBOSE4:hkdf.cc(103)] PRK:
0x0000:  76 54 6a 15 79 39 65 66 5c 63 0d a9 85 d9 f8 89  vTj.y9ef\c......
0x0010:  a7 a5 c5 41 62 e0 6c 26 fb 42 32 30 3d 0a 32 80  ...Ab.l&.B20=.2.

[0112/144522.378351:VERBOSE4:hkdf.cc(149)] client key:
0x0000:  52 79 c1 44 f0 8d 83 99 6b f3 b6 83 11 ff 31 25  Ry.D....k.....1%
0x0010:  86 79 d6 af 62 bc b3 71 1d 7e fa 71 35 9f f2 aa  .y..b..q.~.q5...

[0112/144522.378422:VERBOSE4:hkdf.cc(156)] server key:
0x0000:  bf 3d 5e 92 6e 8f 09 15 3f 0b f3 0b 91 e8 84 50  .=^.n...?......P
0x0010:  73 33 81 86 be 9c 32 56 d7 b2 6a 57 67 80 46 fd  s3....2V..jWg.F.

[0112/144522.378489:VERBOSE4:hkdf.cc(163)] client IV:
0x0000:  a1 c0 66 60                                      ..f`

[0112/144522.378549:VERBOSE4:hkdf.cc(170)] server IV:
0x0000:  fa 93 8b 39                                      ...9

[0112/144522.378594:VERBOSE4:hkdf.cc(176)] subkey secret:
0x0000:  55 3a eb 1e 23 82 a7 6b a6 22 a9 c8 23 7d c7 11  U:..#..k."..#}..
0x0010:  7e 35 ca c8 c8 26 8c 36 cb 75 78 18 58 c5 d3 3a  ~5...&.6.ux.X..:
*/
    {
        .ekt_lineno         = __LINE__,
        BUF_PAIR(ikm,
            "\xab\x62\xc8\xe1\x03\x63\xb5\x4e\xb9\xc5\xe4\xf1\xd9\x47\xed\x60"
            "\x43\x2f\x3b\xc2\x27\xc3\x2c\x51\xe7\x7f\xe7\x4b\x5e\xa4\x08\x29"
            ),
        BUF_PAIR(salt,
            "\x58\x77\xdc\xd2\xa5\xd0\xb3\x7f\x65\xc3\xcd\x6b\x03\xa7\x34\x53"
            "\xd7\x8b\x6e\x56\x3c\xa0\x22\xa2\xab\x7a\x1e\x4c\x40\xe9\xcf\xd6"
            "\x02\x2e\xef\xd3\x08\xbc\xd1\xbe\xcb\x70\xf1\x92\x8e\xec\x27\x7b"
            "\xb6\xb5\x27\xce\xea\x43\x7d\xc2\x34\xb7\xbe\x44\xa3\x89\x70\x9a"
            "\x62\x65\x46\xfa\xe5\x86\x44\x04\xfb\x66\x22\x2d\x7c\x07\xb8\xb8"
            ),
        BUF_PAIR(context,
            "\x51\x55\x49\x43\x20\x6b\x65\x79\x20\x65\x78\x70\x61\x6e\x73\x69"
            "\x6f\x6e\x00\xa8\x9f\x60\xa0\x05\xe6\x1a\x02\x43\x48\x4c\x4f\x18"
            "\x00\x00\x00\x50\x41\x44\x00\x01\x02\x00\x00\x53\x4e\x49\x00\x10"
            "\x02\x00\x00\x53\x54\x4b\x00\x44\x02\x00\x00\x53\x4e\x4f\x00\x74"
            "\x02\x00\x00\x56\x45\x52\x00\x78\x02\x00\x00\x43\x43\x53\x00\x88"
            "\x02\x00\x00\x4e\x4f\x4e\x43\xa8\x02\x00\x00\x4d\x53\x50\x43\xac"
            "\x02\x00\x00\x41\x45\x41\x44\xb0\x02\x00\x00\x53\x43\x49\x44\xc0"
            "\x02\x00\x00\x50\x44\x4d\x44\xc4\x02\x00\x00\x53\x4d\x48\x4c\xc8"
            "\x02\x00\x00\x49\x43\x53\x4c\xcc\x02\x00\x00\x43\x54\x49\x4d\xd4"
            "\x02\x00\x00\x4e\x4f\x4e\x50\xf4\x02\x00\x00\x50\x55\x42\x53\x14"
            "\x03\x00\x00\x4d\x49\x44\x53\x18\x03\x00\x00\x53\x43\x4c\x53\x1c"
            "\x03\x00\x00\x4b\x45\x58\x53\x20\x03\x00\x00\x58\x4c\x43\x54\x28"
            "\x03\x00\x00\x43\x53\x43\x54\x28\x03\x00\x00\x43\x43\x52\x54\x30"
            "\x03\x00\x00\x43\x46\x43\x57\x34\x03\x00\x00\x53\x46\x43\x57\x38"
            "\x03\x00\x00\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d"
            "\x2d\x2d\x2d\x2d\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e"
            "\x6f\x72\x67\x2f\x22\xe6\x5d\xe0\xf8\x78\x94\x5a\x23\x2d\xba\xb4"
            "\xd7\xe8\xaa\x1a\x46\x21\x20\x20\x94\x7f\x0d\x7a\x5e\x2e\x41\x98"
            "\x66\x0e\x44\x88\xeb\xf3\x41\xc5\xb1\xe2\x65\xa7\x38\x01\x3c\x2c"
            "\x0d\xeb\x00\x2b\x73\x48\xda\x02\x2e\xef\xd3\x08\xbc\xd1\xbe\xcb"
            "\x70\xf1\x92\x8e\xec\x27\x7b\xb6\xb5\x27\xce\xea\x43\x7d\xc2\x34"
            "\xb7\xbe\x44\xa3\x89\x70\x9a\x62\x65\x46\xfa\xe5\x86\x44\x04\xfb"
            "\x66\x22\x2d\x7c\x07\xb8\xb8\x51\x30\x33\x37\x01\xe8\x81\x60\x92"
            "\x92\x1a\xe8\x7e\xed\x80\x86\xa2\x15\x82\x91\x58\x77\xdc\xd2\xa5"
            "\xd0\xb3\x7f\x65\xc3\xcd\x6b\x03\xa7\x34\x53\xd7\x8b\x6e\x56\x3c"
            "\xa0\x22\xa2\xab\x7a\x1e\x4c\x40\xe9\xcf\xd6\x64\x00\x00\x00\x43"
            "\x43\x32\x30\x08\x68\x02\x10\x36\xfa\xfb\x68\xb3\x8a\xaa\xa4\xe7"
            "\x96\x41\xca\x58\x35\x30\x39\x01\x00\x00\x00\x58\x02\x00\x00\xd2"
            "\xdc\x77\x58\x00\x00\x00\x00\x2d\xc8\x07\x0e\x2a\x4b\x39\x15\xae"
            "\x98\x1f\x5c\xb1\x6f\xac\x77\x0e\xf7\xea\xdd\x57\x93\x8b\x38\xf2"
            "\x8a\x45\xf5\xd3\x01\xc1\x9b\xa5\x79\x21\x45\x36\x4f\xc6\xf6\x83"
            "\xbc\xba\x1d\xe5\x06\xc1\x8e\x69\x4c\xb6\xe2\x99\x35\x17\xa1\xca"
            "\xf0\xd2\x82\xd9\xa5\xb0\x3e\x64\x00\x00\x00\x01\x00\x00\x00\x43"
            "\x32\x35\x35\xb4\xe2\x9f\xfc\xab\x17\xf2\x4a\xb4\xe2\x9f\xfc\xab"
            "\x17\xf2\x4a\x00\x00\xf0\x00\x00\x00\x60\x00\x53\x43\x46\x47\x06"
            "\x00\x00\x00\x41\x45\x41\x44\x08\x00\x00\x00\x53\x43\x49\x44\x18"
            "\x00\x00\x00\x50\x55\x42\x53\x3b\x00\x00\x00\x4b\x45\x58\x53\x3f"
            "\x00\x00\x00\x4f\x42\x49\x54\x47\x00\x00\x00\x45\x58\x50\x59\x4f"
            "\x00\x00\x00\x41\x45\x53\x47\x43\x43\x32\x30\x08\x68\x02\x10\x36"
            "\xfa\xfb\x68\xb3\x8a\xaa\xa4\xe7\x96\x41\xca\x20\x00\x00\xf6\x00"
            "\xdd\x9e\x3e\x30\x4f\xd9\xfb\x26\x77\x4e\xce\x35\x79\x6d\x98\x6d"
            "\x9a\xe6\xa5\x19\xc0\xb8\x72\x66\xcd\x46\xb1\xb6\x90\x4a\x43\x32"
            "\x35\x35\xa5\xd0\xb3\x7f\x65\xc3\xcd\x6b\xc8\x2a\x65\x59\x00\x00"
            "\x00\x00\x30\x82\x03\xb4\x30\x82\x02\x9c\xa0\x03\x02\x01\x02\x02"
            "\x01\x01\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05"
            "\x00\x30\x1e\x31\x1c\x30\x1a\x06\x03\x55\x04\x03\x0c\x13\x51\x55"
            "\x49\x43\x20\x53\x65\x72\x76\x65\x72\x20\x52\x6f\x6f\x74\x20\x43"
            "\x41\x30\x1e\x17\x0d\x31\x36\x31\x32\x32\x32\x32\x31\x32\x39\x30"
            "\x34\x5a\x17\x0d\x31\x36\x31\x32\x32\x35\x32\x31\x32\x39\x30\x34"
            "\x5a\x30\x64\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53"
            "\x31\x13\x30\x11\x06\x03\x55\x04\x08\x0c\x0a\x43\x61\x6c\x69\x66"
            "\x6f\x72\x6e\x69\x61\x31\x16\x30\x14\x06\x03\x55\x04\x07\x0c\x0d"
            "\x4d\x6f\x75\x6e\x74\x61\x69\x6e\x20\x56\x69\x65\x77\x31\x14\x30"
            "\x12\x06\x03\x55\x04\x0a\x0c\x0b\x51\x55\x49\x43\x20\x53\x65\x72"
            "\x76\x65\x72\x31\x12\x30\x10\x06\x03\x55\x04\x03\x0c\x09\x31\x32"
            "\x37\x2e\x30\x2e\x30\x2e\x31\x30\x82\x01\x22\x30\x0d\x06\x09\x2a"
            "\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x00\x30"
            "\x82\x01\x0a\x02\x82\x01\x01\x00\xf0\x55\xbf\xb6\x81\x96\x69\xf3"
            "\x7a\x06\xf7\x68\x89\xaf\xfe\x9c\x30\xe9\xbb\xe7\x0d\x9b\x37\xc1"
            "\xf6\xa0\xb8\x28\x72\xbc\x53\x8e\x8c\x2c\x99\xa0\x63\xfe\x7e\x84"
            "\xcb\x35\x11\x96\x24\x98\x20\xee\x22\x59\x53\x61\x47\xaa\xbc\x66"
            "\x8f\x05\x4f\xec\xb6\xa7\x9c\x3c\xfb\xde\xa7\x24\x3f\xd8\xfd\x97"
            "\xa8\x79\x50\x80\x86\x11\x3a\xa8\xa4\x1e\xfa\x7b\x1e\xcf\x4b\x5c"
            "\x7e\x1c\x23\x5b\xb2\xe1\xd4\xd7\xca\x32\x6e\x4c\x74\x01\x42\xf0"
            "\x36\x14\x09\xf8\xc7\x22\x6f\x13\x69\x4a\x32\x9d\xe1\x33\x36\x1b"
            "\xe6\x4d\x74\x6c\xb8\xfa\x49\xf0\x9a\x0d\x81\x9f\xc6\xb8\x88\x79"
            "\x70\x6c\x0c\x1c\xfb\xf9\x70\x27\xe8\xc1\xc7\xdd\xba\xd0\x97\xf9"
            "\xca\x1a\x1f\x24\x64\x3b\xf7\x3d\x4c\x67\xb1\xe2\x87\x07\xf9\xa2"
            "\xb8\xd5\x82\x06\x80\xcd\x1f\x97\xca\x4b\x39\x87\x4f\x0a\xb7\xa7"
            "\x36\xcf\xf2\xfe\x08\x7b\x46\x7d\x25\x61\xf5\xec\x18\x13\xf5\xe1"
            "\x4b\xa9\xeb\xec\xa8\x53\x7f\xad\x66\x19\xfb\x22\x70\xcc\xfa\xdf"
            "\x64\xda\xf4\xb1\x07\x17\x3d\xb0\x0f\xd7\x0d\xdf\xfe\xe8\x9b\x3a"
            "\x86\xfc\xa0\x85\xd1\x03\xa3\x4d\x89\x9c\xcc\xde\xc6\xc6\xde\x9a"
            "\xd0\xf3\x7f\x6d\x1d\x0a\x8e\x27\x02\x03\x01\x00\x01\xa3\x81\xb6"
            "\x30\x81\xb3\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30"
            "\x00\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\x1a\x79\xb5\x96"
            "\xb0\x18\xf3\x1a\x21\xfd\x8c\x82\x30\xb9\xaf\x94\x60\xd1\x62\xfe"
            "\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30\x16\x80\x14\xf2\x38\x71"
            "\x39\x4b\x66\x26\xac\x8c\x4b\x3e\xcc\x03\x88\xd7\x55\x1f\xaa\x5d"
            "\x92\x30\x1d\x06\x03\x55\x1d\x25\x04\x16\x30\x14\x06\x08\x2b\x06"
            "\x01\x05\x05\x07\x03\x01\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02"
            "\x30\x44\x06\x03\x55\x1d\x11\x04\x3d\x30\x3b\x82\x0f\x77\x77\x77"
            "\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x82\x10\x6d\x61"
            "\x69\x6c\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x82\x10"
            "\x6d\x61\x69\x6c\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d"
            "\x87\x04\x7f\x00\x00\x01\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d"
            "\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x68\x24\x9a\x07\xf7\xb8"
            "\x7d\x96\xef\xfd\xe5\x0c\x7c\x2c\x31\xa8\x95\xe2\xfa\x05\xa7\x3e"
            "\x98\x3b\x77\x3c\x0a\xe1\xa2\x16\x51\x7f\x58\x43\x82\x6c\xc4\x66"
            "\xf3\x88\x26\x17\xbd\xe5\xd3\xb1\x84\x2a\xb7\xcf\xe1\xd1\xb2\x85"
            "\x3b\xfc\x20\x1a\xdf\x1d\x24\xf5\xdc\x58\xb7\xef\x36\x72\x9f\xd7"
            "\xda\xc5\xf4\x46\x08\x4b\x17\x64\x99\x1a\xb1\x1e\xde\x68\x00\x74"
            "\x4c\x1a\x7c\x55\xb9\x7f\xc3\x2d\xfa\x58\x3b\x6b\x93\x5a\x0a\x43"
            "\xe3\x41\x4e\x4e\x5c\x2c\xa6\x0c\xcf\x17\xc4\x86\xea\x58\x37\xa2"
            "\x40\xde\x22\xeb\xad\x07\x77\x05\xcb\x57\xdf\x49\x56\x96\xf7\xd4"
            "\xa6\x9a\xac\x65\xc9\x2e\x0e\xdc\x53\x14\x6c\x1d\x41\x68\x22\x8d"
            "\x1f\x40\x49\x6d\xb2\xa7\x6c\x26\xa5\x60\x52\xa7\xaa\x8a\x57\x0c"
            "\xd6\x45\x54\x5b\x18\x75\x00\xc2\xcb\x64\xae\x66\x45\x0d\x96\x67"
            "\x0b\x6d\x11\xc6\x51\xb5\x2b\xe3\xe8\x68\x2d\x60\x91\xb0\xbc\x3c"
            "\x03\x69\x99\x06\x9f\x16\xe4\xa8\xb9\x8c\xac\x04\x9f\x1f\xe9\x0a"
            "\x81\xeb\x60\xae\x27\x6d\x87\xf7\x0b\xcf\x9c\xbb\x1a\xdb\x15\x8a"
            "\x92\x08\x28\x5a\xac\x9d\x37\x2c\x35\xf2\xc1\xbb\xe6\x01\x4a\xf6"
            "\x4b\x67\xf5\xec\x1f\x1f\xa7\x04\x9b\x21"
            ),
        BUF_PAIR(client_key,
            "\x52\x79\xc1\x44\xf0\x8d\x83\x99\x6b\xf3\xb6\x83\x11\xff\x31\x25"
            "\x86\x79\xd6\xaf\x62\xbc\xb3\x71\x1d\x7e\xfa\x71\x35\x9f\xf2\xaa"
            ),
        BUF_PAIR(server_key,
            "\xbf\x3d\x5e\x92\x6e\x8f\x09\x15\x3f\x0b\xf3\x0b\x91\xe8\x84\x50"
            "\x73\x33\x81\x86\xbe\x9c\x32\x56\xd7\xb2\x6a\x57\x67\x80\x46\xfd"
            ),
        BUF_PAIR(client_iv, "\xa1\xc0\x66\x60"),
        BUF_PAIR(server_iv, "\xfa\x93\x8b\x39"),
/*
[0112/144522.378594:VERBOSE4:hkdf.cc(176)] subkey secret:
"\x55\x3a\xeb\x1e\x23\x82\xa7\x6b\xa6\x22\xa9\xc8\x23\x7d\xc7\x11"
"\x7e\x35\xca\xc8\xc8\x26\x8c\x36\xcb\x75\x78\x18\x58\xc5\xd3\x3a"
*/
    },


};


static void
run_ekt_test (const struct export_key_test *test)
{
    int s, i;

    unsigned char   client_key[0x100],
                    server_key[0x100],
                    client_iv[0x100],
                    server_iv[0x100];

    unsigned char   sub_key[32];
    unsigned char   c_hp[16], s_hp[16];

    /* Sanity check the test itself: */
    assert(test->ekt_client_key_sz < sizeof(client_key));
    assert(test->ekt_server_key_sz < sizeof(server_key));
    assert(test->ekt_server_iv_sz < sizeof(server_iv));
    assert(test->ekt_client_iv_sz < sizeof(client_iv));

    for (i = 0; i < 2; ++i)
    {
        if (i && !(test->ekt_ikm_sz == 32 && test->ekt_client_key_sz == 16 && test->ekt_server_key_sz == 16))
            continue;
        s = lsquic_export_key_material(test->ekt_ikm,       (uint32_t)test->ekt_ikm_sz,
                                test->ekt_salt,             (int)test->ekt_salt_sz,
                                test->ekt_context,          (uint32_t)test->ekt_context_sz,
                                (uint16_t)test->ekt_client_key_sz,    client_key,
                                (uint16_t)test->ekt_server_key_sz,    server_key,
                                (uint16_t)test->ekt_client_iv_sz,     client_iv,
                                (uint16_t)test->ekt_server_iv_sz,     server_iv,
                                sub_key,
                                /* Keys should not change because HP pointers are given */
                                i ? c_hp : NULL,
                                i ? s_hp : NULL
                                );
        assert(0 == s);     /* This function always returns zero */
        if (test->ekt_client_key_sz)
            assert(0 == memcmp(client_key, test->ekt_client_key,
                                                        test->ekt_client_key_sz));
        if (test->ekt_server_key_sz)
            assert(0 == memcmp(server_key, test->ekt_server_key,
                                                        test->ekt_server_key_sz));
    }
}


int
main (void)
{
    unsigned n;
    for (n = 0; n < sizeof(tests) / sizeof(tests[0]); ++n)
        run_ekt_test(&tests[n]);
    return 0;
}
