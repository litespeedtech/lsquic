LSQUIC Documentation
====================

This is the documentation for LSQUIC_ |release|, last updated |today|.

LiteSpeed QUIC (LSQUIC) Library is an open-source implementation of QUIC
and HTTP/3 functionality for servers and clients.  LSQUIC is:

- fast;

- flexible; and

- production-ready.

Most of the code in this distribution has been  used in our own products
-- `LiteSpeed Web Server`_, `LiteSpeed Web ADC`_, and OpenLiteSpeed_ --
since 2017.

Currently supported QUIC versions are v1 (disabled by default until the
QUIC RFC is released); Internet-Draft versions 34, 29, and 27;
and the older "Google" QUIC versions Q043, Q046, an Q050.

LSQUIC is licensed under the `MIT License`_; see LICENSE in the source
distribution for details.

Features
--------

LSQUIC supports nearly all QUIC and HTTP/3 features, including

- DPLPMTUD
- ECN
- Spin bits (allowing network observer to calculate a connection's RTT)
- Path migration
- NAT rebinding
- Push promises
- TLS Key updates
- Extensions:

 - :ref:`extensible-http-priorities`
 - :ref:`apiref-datagrams`
 - Loss bits extension (allowing network observer to locate source of packet loss)
 - Timestamps extension (allowing for one-way delay calculation, improving performance of some congestion controllers)
 - Delayed ACKs (this reduces number of ACK frames sent and processed, improving throughput)
 - QUIC grease bit to reduce ossification opportunities

Architecture
------------

The LSQUIC library does not use sockets to receive and send packets; that is handled by the user-supplied callbacks.  The library also does not mandate the use of any particular event loop.  Instead, it has functions to help the user schedule events.  (Thus, using an event loop is not even strictly necessary.)  The various callbacks and settings are supplied to the engine constructor.
LSQUIC keeps QUIC connections in several data structures in order to process them efficiently.  Connections that need processing are kept in two priority queues: one holds connections that are ready to be processed (or "ticked") and the other orders connections by their next timer value.  As a result, no connection is processed needlessly.

.. _LSQUIC: https://github.com/litespeedtech/lsquic
.. _`MIT License`: http://www.opensource.org/licenses/mit-license.php
.. _`LiteSpeed Web Server`: https://www.litespeedtech.com/products/litespeed-web-server/
.. _`LiteSpeed Web ADC`: https://www.litespeedtech.com/products/litespeed-web-adc/
.. _OpenLiteSpeed: https://openlitespeed.org/

Contents
--------

.. toctree::
   :maxdepth: 2

   gettingstarted
   tutorial
   apiref
   internals
   devel
   faq

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
