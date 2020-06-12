[![Build Status](https://travis-ci.org/litespeedtech/lsquic.svg?branch=master)](https://travis-ci.org/litespeedtech/lsquic)
[![Build Status](https://api.cirrus-ci.com/github/litespeedtech/lsquic.svg)](https://cirrus-ci.com/github/litespeedtech/lsquic)
[![Build status](https://ci.appveyor.com/api/projects/status/ij4n3vy343pkgm1j?svg=true)](https://ci.appveyor.com/project/litespeedtech/lsquic)

LiteSpeed QUIC (LSQUIC) Library README
=============================================

Description
-----------

LiteSpeed QUIC (LSQUIC) Library is an open-source implementation of QUIC
and HTTP/3 functionality for servers and clients.  Most of the code in this
distribution is used in our own products: LiteSpeed Web Server, LiteSpeed ADC,
and OpenLiteSpeed.  We think it is free of major problems.  Nevertheless, do
not hesitate to report bugs back to us.  Even better, send us fixes and
improvements!

Currently supported QUIC versions are Q043, Q046, Q050, ID-27, and ID-28.
Support for newer versions will be added soon after they are released.

Documentation
-------------

Documentation is available at https://lsquic.readthedocs.io/en/latest/.

In addition, see example programs for API usage and EXAMPLES.txt for
some compilation and run-time options.

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

You may need to install pre-requisites like zlib and libevent.

2. Use specific BoringSSL version

```
git checkout 251b5169fd44345f455438312ec4e18ae07fd58c
```

3. Compile the library

```
cmake . &&  make
```

Remember where BoringSSL sources are:
```
BORINGSSL=$PWD
```

If you want to turn on optimizations, do

```
cmake -DCMAKE_BUILD_TYPE=Release . && make
```

Building LSQUIC Library
-----------------------

LSQUIC's `http_client`, `http_server`, and the tests link BoringSSL
libraries statically.  Following previous section, you can build LSQUIC
as follows:

1. Get the source code

```
git clone https://github.com/litespeedtech/lsquic.git
cd lsquic
git submodule init
git submodule update
```

2. Compile the library


```
# $BORINGSSL is the top-level BoringSSL directory from the previous step
cmake -DBORINGSSL_DIR=$BORINGSSL .
make
```

3. Run tests

```
make test
```

Building with Docker
---------
The library and the example client and server can be built with Docker.

Initialize Git submodules:
```
cd lsquic
git submodule init
git submodule update
```

Build the Docker image:
```
docker build -t lsquic .
```

Then you can use the examples from the command line.  For example:
```
sudo docker run -it --rm lsquic http_client -s www.google.com  -p / -o version=Q046
sudo docker run -p 12345:12345/udp -v /path/to/certs:/mnt/certs -it --rm lsquic http_server -c www.example.com,/mnt/certs/chain,/mnt/certs/key
```

Platforms
---------

The library has been tested on the following platforms:
- Linux
  - i386
  - x86_64
  - ARM (Raspberry Pi 3)
- FreeBSD
  - i386
- MacOS
  - x86_64
- Android
  - ARM
- Windows
  - x86_64

Have fun,

LiteSpeed QUIC Team.

Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc
