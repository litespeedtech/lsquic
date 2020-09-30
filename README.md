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
and OpenLiteSpeed.  Do not hesitate to report bugs back to us.  Even better,
send us fixes and improvements!

Currently supported QUIC versions are Q043, Q046, Q050, ID-27, ID-28, ID-29,
ID-30, and ID-31.  Support for newer versions will be added soon after they
are released.

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
straightforward, but we provide a helper in "./tools/build_boringssl".  You will need `go` installed.

1. You may need to install pre-requisites like zlib and libevent.

2. Run the CMake configure step (instructions assume to be run from the root of this repository):

```
cmake -DCMAKE_INSTALL_PREFIX=tools/build_boringssl/install -Btools/build_boringssl/build -Stools/build_boringssl
```

_Note that with older versions of CMake (e.g. on Ubuntu 18.04), `-S` may be `-H.`._

If you want to turn on optimizations, use `-DCMAKE_BUILD_TYPE=Release`, too.

3. Run the CMake build step to build and install BoringSSL:

```
cmake --build tools/build_boringssl/build
```

After this succeeds, using this installed BoringSSL when building LSQUIC is a matter of adding `-DCMAKE_PREFIX_PATH=tools/build_boringssl/install` in the LSQUIC configure step.

Building LSQUIC Library
-----------------------

LSQUIC's `http_client`, `http_server`, and the tests link BoringSSL
libraries statically.  Following previous section, you can build LSQUIC
as follows:

1. Compile the library

```
cmake -DCMAKE_PREFIX_PATH=tools/build_boringssl/install -Bbuild -S.
cmake --build build
```

2. Run tests

```
cmake --build build --target test
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
