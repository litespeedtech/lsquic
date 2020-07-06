********
Tutorial
********

.. highlight:: c

Introduction
============

The LSQUIC library provides facilities for operating a QUIC (Google QUIC
or IETF QUIC) server or client with optional HTTP (or HTTP/3) functionality.
To do that, it specifies an application programming interface (API) and
exposes several basic object types to operate upon:

- engine;
- connection; and
- stream.

An engine manages connections, processes incoming packets, and schedules
outgoing packets.  An engine operates in one of two modes: client or server.

The LSQUIC library does not use sockets to receive and send packets; that is
handled by the user-supplied callbacks.  The library also does not mandate
the use of any particular event loop.  Instead, it has functions to help the
user schedule events.  (Thus, using an event loop is not even strictly
necessary.)  The various callbacks and settings are supplied to the engine
constructor.

A connection carries one or more streams, ensures reliable data delivery,
and handles the protocol details.

A stream usually corresponds to a request/response pair: a client sends
its request over a single stream and a server sends its response back
using the same stream.  This is the Google QUIC and HTTP/3 use case.
Nevertheless, the library does not limit one to this scenario.  Any
application protocol can be implemented using LSQUIC -- as long as it
can be implemented using the QUIC transport protocol.  The library provides
hooks for stream events: when a stream is created or closed, when it has
data to read or when it can be written to, and so on.

In the following sections, we will describe how to:

- initialize the library;
- configure and instantiate an engine object;
- send and receive packets; and
- work with connections and streams.

Include Files
-------------

A single include file, :file:`lsquic.h`, contains all the necessary
LSQUIC declarations:

::

    #include <lsquic.h>

Library Initialization
======================

Before the first engine object is instantiate, the library must be
initialized using :func:`lsquic_global_init()`:

::

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT|LSQUIC_GLOBAL_SERVER))
    {
        exit(EXIT_FAILURE);
    }
    /* OK, do something useful */

If you plan to instantiate engines only in a single mode, client or server,
you can omit the appropriate flag.

After all engines have been destroyed and the LSQUIC library is no longer
going to be used, the global initialization can be undone:

::

    lsquic_global_cleanup();
    exit(EXIT_SUCCESS);

Engine Instantiation
====================

Engine instantiation is performed by :func:`lsquic_engine_new()`:

::

    /* Create an engine in server mode with HTTP behavior: */
    lsquic_engine_t *engine
        = lsquic_engine_new(LSENG_SERVER|LSENG_HTTP, &engine_api);

The engine mode is selected by using the :macro:`LSENG_SERVER` flag.
If present, the engine will be in server mode; if not, the engine will
be in client mode.  If you need both server and client functionality
in your program, instantiate two engines (or as many as you like).

Using the :macro:`LSENG_HTTP` flag enables the HTTP behavior:  The library
hides the interaction between the HTTP application layer and the QUIC
transport layer and presents a simple, unified (between Google QUIC and
HTTP/3) way of sending and receiving HTTP messages.  Behind the scenes,
the library will compress and uncompress HTTP headers, add and remove
HTTP/3 stream framing, and operate the necessary control streams.

Engine Configuration
--------------------

The second argument to :func:`lsquic_engine_new()` is a pointer to
a struct of type :type:`lsquic_engine_api`.  This structure lists
several user-specified function pointers that the engine is to use
to perform various functions.  Mandatory among these are:

- function to set packets out, :member:`lsquic_engine_api.ea_packets_out`;
- functions linked to connection and stream events,
  :member:`lsquic_engine_api.ea_stream_if`;
- function to look up certificate to use, :member:`lsquic_engine_api.ea_lookup_cert` (in server mode); and
- function to fetch SSL context, :member:`lsquic_engine_api.ea_get_ssl_ctx` (in server mode).

The minimal structure for a client will look like this:

::

    lsquic_engine_api engine_api = {
        .ea_packets_out     = send_packets_out,
        .ea_packets_out_ctx = (void *) sockfd,  /* For example */
        .ea_stream_if       = &stream_callbacks,
        .ea_stream_if_ctx   = &some_context,
    };

Engine Settings
---------------

Engine settings can be changed by specifying
:member:`lsquic_engine_api.ea_settings`.  There are **many** parameters
to tweak: supported QUIC versions, amount of memory dedicated to connections
and streams, various timeout values, and so on.  See
:ref:`apiref-engine-settings` for full details.  If ``ea_settings`` is set
to ``NULL``, the engine will use the defaults, which should be OK.

Sending Packets
===============

The :member:`lsquic_engine_api.ea_packets_out` is the function that gets
called when an engine instance has packets to send.  It could look like
this:

::

    /* Return number of packets sent or -1 on error */
    static int
    send_packets_out (void *ctx, const struct lsquic_out_spec *specs,
                                                    unsigned n_specs)
    {
        struct msghdr msg;
        int sockfd;
        unsigned n;

        memset(&msg, 0, sizeof(msg));
        sockfd = (int) (uintptr_t) ctx;

        for (n = 0; n < n_specs; ++n)
        {
            msg.msg_name       = (void *) specs[n].dest_sa;
            msg.msg_namelen    = sizeof(struct sockaddr_in);
            msg.msg_iov        = specs[n].iov;
            msg.msg_iovlen     = specs[n].iovlen;
            if (sendmsg(sockfd, &msg, 0) < 0)
                break;
        }

        return (int) n;
    }

Note that the version above is very simple.  :type:`lsquic_out_spec`
also specifies local address as well as ECN value.  These are set
using ancillary data in a platform-dependent way.

Receiving Packets
=================

The user reads packets and provides them to an engine instance using
:func:`lsquic_engine_packet_in()`.

*TODO*

Running Connections
===================

A connection needs to be processed once in a while.  It needs to be
processed when one of the following is true:

- There are incoming packets;
- A stream is both readable by the user code and the user code wants
  to read from it;
- A stream is both writeable by the user code and the user code wants
  to write to it;
- User has written to stream outside of on_write() callbacks (that is
  allowed) and now there are packets ready to be sent;
- A timer (pacer, retransmission, idle, etc) has expired;
- A control frame needs to be sent out;
- A stream needs to be serviced or created.

Each of these use cases is handled by a single function,
:func:`lsquic_engine_process_conns()`.

The connections to which the conditions above apply are processed (or
"ticked") in the least recently ticked order.  After calling this function,
you can see when is the next time a connection needs to be processed using
:func:`lsquic_engine_earliest_adv_tick()`.

Based on this value, next event can be scheduled (in the event loop of
your choice).

::


Stream Reading and Writing
==========================

Reading from (or writing to) a stream is best down when that stream is
readable (or writeable).  To register an interest in an event,
