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

Currently supported QUIC versions are Q035, Q037, Q038, Q039, and Q040.
Support for newer versions will be added soon after they are released.
The version(s) specified by IETF QUIC WG will be added once the IETF
version of the protocol settles down a little.

Documentation
-------------

The documentation for this module is admittedly sparse.  The API is
documented in include/lsquic.h.  If you have doxygen, you can run
`doxygen dox.cfg' or `make docs'.  The example program is
test/http_client.c: a bare-bones, but working, QUIC client.  Have a look
in EXAMPLES.txt to see how it can be used.

Building
--------

To build LSQUIC, you need CMake and BoringSSL.  The example program
uses libevent to provide the event loop.  In short:

  cmake -DBORINGSSL_INCLUDE=/some/dir -DBORINGSSL_LIB=/some/other/dir .

Have fun,

LiteSpeed QUIC Team.

Copyright (c) 2017 LiteSpeed Technologies Inc
