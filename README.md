[![Build Status](https://travis-ci.org/litespeedtech/lsquic-client.svg?branch=master)](https://travis-ci.org/litespeedtech/lsquic-client)

LiteSpeed QUIC (LSQUIC) Client Library README
=============================================

Description
-----------

LiteSpeed QUIC (LSQUIC) Client Library is an open-source implementation
of QUIC functionality for clients.  It is released in the hope to speed
the adoption of QUIC.  Most of the code in this distribution is used in
our own products: LiteSpeed Web Server and ADC.  We think it is free of
major problems.  Nevertheless, do not hesitate to report bugs back to us.
Even better, send us fixes and improvements!

Currently supported QUIC versions are Q035, Q039, Q043, and Q044.  Support
for newer versions will be added soon after they are released.  The
version(s) specified by IETF QUIC WG will be added once the IETF version
of the protocol settles down a little.

Documentation
-------------

The documentation for this module is admittedly sparse.  The API is
documented in include/lsquic.h.  If you have doxygen, you can run
`doxygen dox.cfg` or `make docs`.  The example program is
test/http_client.c: a bare-bones, but working, QUIC client.  Have a look
in EXAMPLES.txt to see how it can be used.

Requirements
------------

To build LSQUIC, you need CMake, zlib, and BoringSSL.  The example program
uses libevent to provide the event loop.

Building BoringSSL
------------------

BoringSSL is not packaged; you have to build it yourself.  The process is
straightforward.  You will need `go` installed.

1. Clone BoringSSL by issuing the following command:

```
git clone https://boringssl.googlesource.com/boringssl
cd boringssl
```

2. Compile the library

```
cmake . &&  make
```

If you want to turn on optimizations, do

```
cmake -DCMAKE_BUILD_TYPE=Release . && make
```

4. Install the library

This is the manual step.  You will need to copy library files manually.
LSQUIC client library needs two: `ssl/libssl.a` and `crypto/libcrypto.a`.
To install these in `/usr/local/lib`, you should do the following:

```
BORINGSSL_SOURCE=$PWD
cd /usr/local/lib
sudo cp $BORINGSSL_SOURCE/ssl/libssl.a .
sudo cp $BORINGSSL_SOURCE/crypto/libcrypto.a .
```

If you do not want to install the library (or do not have root), you
can do this instead:

```
BORINGSSL_SOURCE=$PWD
mkdir -p $HOME/tmp/boringssl-libs
cd $HOME/tmp/boringssl-libs
ln -s $BORINGSSL_SOURCE/ssl/libssl.a
ln -s $BORINGSSL_SOURCE/crypto/libcrypto.a
```

Building LSQUIC Client Library
------------------------------

LSQUIC's `http_client` and the tests link BoringSSL libraries statically.
Following previous section, you can build LSQUIC as follows:

1. Get the source code

```
git clone https://github.com/litespeedtech/lsquic-client.git
cd lsquic-client
```

2. Compile the library


```
cmake -DBORINGSSL_INCLUDE=$BORINGSSL_SOURCE/include \
                                -DBORINGSSL_LIB=$HOME/tmp/boringssl-libs .
make
```

3. Run tests

```
make test
```

Building with Docker
---------
The library and http_client example can be built with Docker.
```
docker build -t lsquic-client .
```

Then you can use the http_client example from the command line.
```
docker run -it --rm lsquic-client http_client -H www.google.com -s 74.125.22.106:443 -p /
```

Platforms
---------

The client library has been tested on the following platforms:
- Linux
  - i386
  - x86_64
  - ARM (Raspberry Pi 3)
- FreeBSD
  - i386
- Windows
  - x86_64
- MacOS
  - x86_64

Have fun,

LiteSpeed QUIC Team.

Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc
