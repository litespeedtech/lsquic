************
WebTransport
************

.. highlight:: c

This document describes how to use LSQUIC's WebTransport support as an
application guide.  It focuses on the control flow and lifecycle of a
WebTransport session.  For low-level HTTP Datagram details, see
:ref:`apiref-http-datagrams`.  For engine settings, see
:ref:`apiref-engine-settings`.

Current Status
==============

WebTransport support is usable today, with the following
important limits:

- HTTP/3 only.
- One WebTransport session per QUIC connection.
- Per-session WebTransport flow control is deferred.
- Compatibility mode may accept some draft-14 peers and some partial
  draft-15 peers.

If your application needs WebTransport datagrams, enable both
WebTransport and HTTP Datagrams in engine settings.

Required Includes
=================

Include both headers:

::

    #include "lsquic.h"
    #include "lsquic_wt.h"

Recommended Engine Settings
===========================

At minimum, enable WebTransport itself:

::

    settings.es_webtransport = 1;

Applications using WebTransport must also use:

::

    settings.es_http_datagrams = 1;
    settings.es_reset_stream_at = 1;
    settings.es_max_webtransport_sessions = 1;

``es_http_datagrams`` is required for WebTransport datagrams.
``es_reset_stream_at`` is required by the current WebTransport support.
``es_max_webtransport_sessions`` must be set to 1.

WebTransport Model In LSQUIC
============================

LSQUIC treats a WebTransport session as something that takes over an HTTP/3
Extended CONNECT stream.

The important points are:

- Your application first sees the CONNECT stream as a normal HTTP stream.
- Your application either rejects the request using ``lsquic_wt_reject()``
  or hands the stream to WebTransport using ``lsquic_wt_accept()``.
- Once ``lsquic_wt_accept()`` returns 0, the CONNECT stream belongs to the
  WebTransport layer.  Application code must stop using that stream for
  normal I/O or readiness management.
- ``lsquic_wt_accept()`` does not return a session handle.  Instead, it
  transfers ownership of the CONNECT stream to WebTransport.
- The session becomes usable in ``wti_on_session_open()``.
- If acceptance later fails, ``wti_on_session_rejected()`` is called.
- If a usable session later ends, ``wti_on_session_close()`` is called.

This matters because peer HTTP/3 SETTINGS may not be known yet when the
CONNECT request arrives.  LSQUIC handles that internally.  Your application
does not need to retry acceptance later.

The WebTransport Callback Table
===============================

WebTransport uses a separate callback table:

::

    static const struct lsquic_webtransport_if wt_if = {
        .wti_on_session_open      = on_wt_session_open,
        .wti_on_session_rejected  = on_wt_session_rejected,
        .wti_on_session_close     = on_wt_session_close,
        .wti_on_uni_stream        = on_wt_uni_stream,
        .wti_on_bidi_stream       = on_wt_bidi_stream,
        .wti_on_stream_read       = on_wt_stream_read,
        .wti_on_stream_write      = on_wt_stream_write,
        .wti_on_stream_close      = on_wt_stream_close,
        .wti_on_stream_ss_code    = on_wt_stream_ss_code,
        .wti_on_datagram_read     = on_wt_datagram_read,
        .wti_on_datagram_write    = on_wt_datagram_write,
        .wti_on_stream_fin        = on_wt_stream_fin,
        .wti_on_stream_reset      = on_wt_stream_reset,
        .wti_on_stop_sending      = on_wt_stop_sending,
    };

Most applications will use only a subset at first:

- session open / rejected / close;
- unidirectional and bidirectional stream creation;
- stream read / write / close; and
- datagram read / write if datagrams are needed.

Server-Side Flow
================

The server starts with a normal HTTP/3 CONNECT request.

1. Parse the request headers.
2. Apply application policy.
3. If the request is not acceptable, call ``lsquic_wt_reject()``.
4. If the request is acceptable, fill ``struct lsquic_wt_accept_params`` and
   call ``lsquic_wt_accept()``.
5. Stop touching the CONNECT stream after successful acceptance.
6. Wait for ``wti_on_session_open()``.

A minimal acceptance flow looks like this:

::

    static int
    handle_wt_connect(lsquic_stream_t *stream,
                      const struct lsquic_wt_connect_info *info)
    {
        struct lsquic_wt_accept_params params;

        if (!path_is_allowed(info->wtci_path))
        {
            lsquic_wt_reject(stream, 404,
                             "no handler for this path",
                             sizeof("no handler for this path") - 1);
            lsquic_stream_close(stream);
            return -1;
        }

        memset(&params, 0, sizeof(params));
        params.wtap_status = 200;
        params.wtap_wt_if = &wt_if;
        params.wtap_wt_if_ctx = &app_ctx;
        params.wtap_connect_info = info;

        if (0 != lsquic_wt_accept(stream, &params))
            return -1;

        return 0;
    }

A few notes:

- ``wtap_wt_if`` points to the WebTransport callback table.
- ``wtap_wt_if_ctx`` is passed to ``wti_on_session_open()`` and
  ``wti_on_session_rejected()``.
- ``wtap_connect_info`` lets the WebTransport layer keep request metadata.
- ``wtap_status`` defaults to 200 when zero; setting it explicitly makes the
  code easier to read.
- ``wtap_extra_resp_headers`` can add extra response headers to the CONNECT
  2xx response.
- ``wtap_sess_ctx`` can supply a fixed session context if the application
  does not want to allocate one in ``wti_on_session_open()``.

``struct lsquic_wt_accept_params`` also lets the application set per-session
WT datagram queue limits, default queue-full policy, and default datagram
send mode.

Request Validation
------------------

Application code is still responsible for request validation before calling
``lsquic_wt_accept()``.  In practice this means checking:

- ``:method`` is ``CONNECT``;
- ``:protocol`` is a supported WebTransport protocol token;
- ``:scheme`` is ``https``;
- ``:authority`` and ``:path`` are present;
- any application-specific path or protocol constraints; and
- ``Origin`` policy, if you use one.

Origin validation is intentionally application-owned.

Client-Side Flow
================

The client also starts with a normal HTTP/3 stream.

1. Create a stream.
2. Send Extended CONNECT headers.
3. Read the response headers.
4. If the response is not successful, treat it as a CONNECT failure.
5. If the response is successful, fill ``struct lsquic_wt_accept_params`` and
   call ``lsquic_wt_accept()`` on the control stream.
6. Wait for ``wti_on_session_open()``.

A minimal client-side CONNECT request includes:

- ``:method = CONNECT``
- ``:protocol = webtransport``
- ``:scheme = https``
- ``:authority = ...``
- ``:path = ...``

After the response is accepted, the client hands the control stream to the
WT layer exactly like the server does.

The important symmetry is this: once the CONNECT response is successful,
both peers use the same WebTransport session callbacks.

Session Open, Rejection, and Close
==================================

There are three distinct application-visible outcomes:

Session opened
--------------

``wti_on_session_open()`` is called when the session becomes usable.
Return a session context pointer from this callback if you want one
associated with the session.

A typical callback looks like this:

::

    static lsquic_wt_session_ctx_t *
    on_wt_session_open(void *ctx, lsquic_wt_session_t *sess,
                       const struct lsquic_wt_connect_info *info)
    {
        struct my_wt_session *s;

        s = calloc(1, sizeof(*s));
        if (!s)
            return NULL;

        s->sess = sess;
        s->path = info->wtci_path;
        return (lsquic_wt_session_ctx_t *) s;
    }

Session rejected
----------------

``wti_on_session_rejected()`` is called when LSQUIC took ownership of the
CONNECT stream but the session never became usable.

This includes deferred-accept failure cases, for example when peer HTTP/3
capabilities are resolved later and WebTransport cannot be enabled.

The callback receives:

- the application context passed via ``wtap_wt_if_ctx``;
- request metadata via ``wtci_*`` fields; and
- an HTTP status code, or 0 if no response was sent.

Session closed
--------------

``wti_on_session_close()`` is called only for sessions that opened.

Call ``lsquic_wt_close()`` to close a live session with an application error
code and optional reason bytes:

::

    lsquic_wt_close(sess, 0, NULL, 0);

or:

::

    lsquic_wt_close(sess, MY_APP_ERR_BAD_STATE,
                    reason_buf, reason_len);

The close callback runs when the session is actually finished, not when close
starts.

Working With WT Streams
=======================

Open outgoing WT streams using:

- ``lsquic_wt_open_uni()``
- ``lsquic_wt_open_bidi()``

Incoming peer-initiated streams are delivered using:

- ``wti_on_uni_stream()``
- ``wti_on_bidi_stream()``

These callbacks should allocate and return the usual ``lsquic_stream_ctx_t``
for the new WT data stream.

After that, ordinary stream callbacks apply:

- ``wti_on_stream_read()``
- ``wti_on_stream_write()``
- ``wti_on_stream_close()``

Optional stream lifecycle callbacks are also available:

- ``wti_on_stream_fin()``
- ``wti_on_stream_reset()``
- ``wti_on_stop_sending()``

WT stream metadata helpers are available when the application needs them:

- ``lsquic_wt_session_from_stream()``
- ``lsquic_wt_stream_get_ctx()``
- ``lsquic_wt_stream_dir()``
- ``lsquic_wt_stream_initiator()``
- ``lsquic_stream_is_webtransport_session()``
- ``lsquic_stream_is_webtransport_client_bidi_stream()``
- ``lsquic_stream_get_webtransport_session_stream_id()``

If your application needs to terminate a WT data stream explicitly, use:

- ``lsquic_wt_stream_reset()``
- ``lsquic_wt_stream_stop_sending()``

Working With WT Datagrams
=========================

WT datagrams are session-scoped and use the HTTP Datagram machinery
internally.  That means ``es_http_datagrams`` must be enabled.

The simplest send path is:

::

    if (0 > lsquic_wt_send_datagram(sess, buf, len))
        ; /* queue full, session closing, or datagrams unavailable */

If the application wants callback-driven sending, enable datagram write
interest:

::

    lsquic_wt_want_datagram_write(sess, 1);

That causes ``wti_on_datagram_write()`` to be called when the session should
try to send.  The callback receives the current maximum datagram size.

Incoming datagrams arrive in ``wti_on_datagram_read()``.

If the application needs explicit queue-full policy or send mode, use
``lsquic_wt_send_datagram_ex()``.  Otherwise, ``lsquic_wt_send_datagram()``
uses the session defaults.

The default send mode is ``LSQUIC_HTTP_DG_SEND_DEFAULT``.  In that mode,
LSQUIC may send via QUIC DATAGRAM frames or fall back to Capsules, depending
on negotiated capability and payload size.  See :ref:`apiref-http-datagrams`
for transport details.

Capability Queries
==================

LSQUIC exposes a few connection-level helpers:

- ``lsquic_wt_peer_settings_received()``
- ``lsquic_wt_peer_supports()``
- ``lsquic_wt_peer_draft()``
- ``lsquic_wt_peer_connect_protocol()``

These are useful for diagnostics and policy, but a typical accept path does
not need to pre-check them before calling ``lsquic_wt_accept()``.

If you want notification when effective HTTP capabilities become known, use
the ordinary stream callback table's ``on_http_caps`` callback.  The
``LSQUIC_HTTP_CAP_WEBTRANSPORT`` bit is best-effort on this branch and may be
set in compatibility mode.

Practical Rules
===============

Do not:

- keep using the CONNECT stream after ``lsquic_wt_accept()`` returns 0;
- assume that ``lsquic_wt_accept()`` means the session is already open;
- assume WT datagrams require QUIC DATAGRAM support, because Capsule fallback
  may be used; or
- assume more than one WT session can be active on a connection.

Do:

- validate request policy before accepting on the server;
- treat ``wti_on_session_open()`` as the point where the session becomes
  usable;
- handle ``wti_on_session_rejected()`` separately from
  ``wti_on_session_close()``; and
- enable HTTP Datagrams if you plan to use WT datagrams.

Worked Example
==============

The Devious Baton example in the ``bin`` directory is the best in-tree WT
example today:

- ``bin/http_server.c`` shows CONNECT request handling.
- ``bin/devious_baton.c`` shows both server-side and client-side WT handoff,
  stream callbacks, datagram callbacks, and session close handling.
- ``bin/baton_client.c`` exercises the client path.

Use those files as the concrete companion to this guide.
