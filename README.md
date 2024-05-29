[![Linux and MacOS build status](https://ci.appveyor.com/api/projects/status/x790ve5msewmva2b/branch/master?svg=true)](https://ci.appveyor.com/project/litespeedtech/lsquic-linux/branch/master)
[![Windows build status](https://ci.appveyor.com/api/projects/status/ij4n3vy343pkgm1j/branch/master?svg=true)](https://ci.appveyor.com/project/litespeedtech/lsquic-windows/branch/master)
[![FreeBSD build status](https://api.cirrus-ci.com/github/litespeedtech/lsquic.svg)](https://cirrus-ci.com/github/litespeedtech/lsquic)
[![Documentation Status](https://readthedocs.org/projects/lsquic/badge/?version=latest)](https://lsquic.readthedocs.io/en/latest/?badge=latest)

LiteSpeed QUIC (LSQUIC) Library README
=============================================

Description
-----------

LiteSpeed QUIC (LSQUIC) Library is an open-source implementation of QUIC
and HTTP/3 functionality for servers and clients.  Most of the code in this
distribution is used in our own products: LiteSpeed Web Server, LiteSpeed ADC,
and OpenLiteSpeed.

Currently supported QUIC versions are v1, v2, Internet-Draft versions 29, and 27;
and the older "Google" QUIC versions Q043, Q046, an Q050.

Standard Compliance
-------------------

LiteSpeed QUIC is mostly compliant to the follow RFCs:

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) QUIC: A UDP-Based Multiplexed and Secure Transport
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) Using TLS to Secure QUIC
- [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) QUIC Loss Detection and Congestion Control
- [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) HTTP/3
- [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) QPACK: Field Compression for HTTP/3

QUIC protocol extensions
------------------------

The following QUIC protocol extensions are implemented:

- [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368) Compatible Version Negotiation for QUIC
- [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) QUIC Version 2
- [RFC 9218](https://www.rfc-editor.org/rfc/rfc9218) Extensible Prioritization Scheme for HTTP
- [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) An Unreliable Datagram Extension to QUIC
- [RFC 9287](https://www.rfc-editor.org/rfc/rfc9287) Greasing the QUIC Bit
- [ACK Frequency](https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/)

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
git checkout 9fc1c33e9c21439ce5f87855a6591a9324e569fd
```
Or, just try the latest master branch.

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

If you want to build as a library, (necessary to build lsquic itself
as as shared library) do:

```
cmake -DBUILD_SHARED_LIBS=1 . && make
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
git submodule update --init
```

2. Compile the library

Statically:


```
# $BORINGSSL is the top-level BoringSSL directory from the previous step
cmake -DBORINGSSL_DIR=$BORINGSSL .
make
```

As a dynamic library:

```
cmake -DLSQUIC_SHARED_LIB=1 -DBORINGSSL_DIR=$BORINGSSL .
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
git submodule update --init
```

Build the Docker image:
```
docker build -t lsquic .
```

Then you can use the examples from the command line.  For example:
```
sudo docker run -it --rm lsquic http_client -s www.google.com  -p / -o version=h3
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
- iOS
  - ARM
- Android
  - ARM
- Windows
  - x86_64

Get Involved
------------

Do not hesitate to report bugs back to us.  Even better, send us fixes
and improvements!

Have fun,

LiteSpeed QUIC Team.

Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc
