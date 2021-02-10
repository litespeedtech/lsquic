API Reference
=============

.. highlight:: c

Preliminaries
-------------

All declarations are in :file:`lsquic.h`, so it is enough to

::

    #include <lsquic.h>

in each source file.


Library Version
---------------

LSQUIC follows the following versioning model.  The version number
has the form MAJOR.MINOR.PATCH, where

- MAJOR changes when a large redesign occurs;
- MINOR changes when an API change or another significant change occurs; and
- PATCH changes when a bug is fixed or another small, API-compatible change occurs.

QUIC Versions
-------------

LSQUIC supports two types of QUIC protocol: Google QUIC and IETF QUIC.  The
former will at some point become obsolete, while the latter is still being
developed by the IETF.  Both types are included in a single enum:

.. type:: enum lsquic_version

    .. member:: LSQVER_043

        Google QUIC version Q043

    .. member:: LSQVER_046

        Google QUIC version Q046

    .. member:: LSQVER_050

        Google QUIC version Q050

    .. member:: LSQVER_ID27

        IETF QUIC version ID (Internet-Draft) 27; this version is deprecated.

    .. member:: LSQVER_ID29

        IETF QUIC version ID 29

    .. member:: LSQVER_ID34

        IETF QUIC version ID 34

    .. member:: LSQVER_I001

        IETF QUIC version 1.  (This version is disabled by default until
        the QUIC RFC is released).

    .. member:: N_LSQVER

        Special value indicating the number of versions in the enum.  It
        may be used as argument to :func:`lsquic_engine_connect()`.

Several version lists (as bitmasks) are defined in :file:`lsquic.h`:

.. macro:: LSQUIC_SUPPORTED_VERSIONS

List of all supported versions.

.. macro:: LSQUIC_FORCED_TCID0_VERSIONS

List of versions in which the server never includes CID in short packets.

.. macro:: LSQUIC_EXPERIMENTAL_VERSIONS

Experimental versions.

.. macro:: LSQUIC_DEPRECATED_VERSIONS

Deprecated versions.

.. macro:: LSQUIC_GQUIC_HEADER_VERSIONS

Versions that have Google QUIC-like headers.  Only Q043 remains in this
list.

.. macro:: LSQUIC_IETF_VERSIONS

IETF QUIC versions.

.. macro:: LSQUIC_IETF_DRAFT_VERSIONS

IETF QUIC *draft* versions.  When IETF QUIC v1 is released, it will not
be included in this list.

LSQUIC Types
------------

LSQUIC declares several types used by many of its public functions.  They are:

.. type:: lsquic_engine_t

    Instance of LSQUIC engine.

.. type:: lsquic_conn_t

    QUIC connection.

.. type:: lsquic_stream_t

    QUIC stream.

.. type:: lsquic_stream_id_t

    Stream ID.

.. type:: lsquic_conn_ctx_t

    Connection context.  This is the return value of :member:`lsquic_stream_if.on_new_conn`.
    To LSQUIC, this is just an opaque pointer.  User code is expected to
    use it for its own purposes.

.. type:: lsquic_stream_ctx_t

    Stream context.  This is the return value of :func:`on_new_stream()`.
    To LSQUIC, this is just an opaque pointer.  User code is expected to
    use it for its own purposes.

.. type:: lsquic_http_headers_t

    HTTP headers

Library Initialization
----------------------

Before using the library, internal structures must be initialized using
the global initialization function:

::

    if (0 == lsquic_global_init(LSQUIC_GLOBAL_CLIENT|LSQUIC_GLOBAL_SERVER))
        /* OK, do something useful */
        ;

This call only needs to be made once.  Afterwards, any number of LSQUIC
engines may be instantiated.

After a process is done using LSQUIC, it should clean up:

::

    lsquic_global_cleanup();

Logging
-------

.. type:: struct lsquic_logger_if

    .. member:: int     (*log_buf)(void *logger_ctx, const char *buf, size_t len)

.. function:: void lsquic_logger_init (const struct lsquic_logger_if *logger_if, void *logger_ctx, enum lsquic_logger_timestamp_style)

    Call this if you want to do something with LSQUIC log messages, as they are thrown out by default.

.. function:: int lsquic_set_log_level (const char *log_level)

    Set log level for all LSQUIC modules.

    :param log_level: Acceptable values are debug, info, notice, warning, error, alert, emerg, crit (case-insensitive).
    :return: 0 on success or -1 on failure (invalid log level).

.. function:: int lsquic_logger_lopt (const char *log_specs)

    Set log level for a particular module or several modules.

    :param log_specs:

        One or more "module=level" specifications serapated by comma.
        For example, "event=debug,engine=info".  See `List of Log Modules`_

Engine Instantiation and Destruction
------------------------------------

To use the library, an instance of the ``struct lsquic_engine`` needs to be
created:

.. function:: lsquic_engine_t *lsquic_engine_new (unsigned flags, const struct lsquic_engine_api *api)

    Create a new engine.

    :param flags: This is is a bitmask of :macro:`LSENG_SERVER` and
                :macro:`LSENG_HTTP`.
    :param api: Pointer to an initialized :type:`lsquic_engine_api`.

    The engine can be instantiated either in server mode (when ``LSENG_SERVER``
    is set) or client mode.  If you need both server and client in your program,
    create two engines (or as many as you'd like).

    Specifying ``LSENG_HTTP`` flag enables the HTTP functionality: HTTP/2-like
    for Google QUIC connections and HTTP/3 functionality for IETF QUIC
    connections.

.. macro:: LSENG_SERVER

    One of possible bitmask values passed as first argument to
    :type:`lsquic_engine_new`.  When set, the engine instance
    will be in the server mode.

.. macro:: LSENG_HTTP

    One of possible bitmask values passed as first argument to
    :type:`lsquic_engine_new`.  When set, the engine instance
    will enable HTTP functionality.

.. function:: void lsquic_engine_cooldown (lsquic_engine_t *engine)

    This function closes all mini connections and marks all full connections
    as going away.  In server mode, this also causes the engine to stop
    creating new connections.

.. function:: void lsquic_engine_destroy (lsquic_engine_t *engine)

    Destroy engine and all its resources.

Engine Callbacks
----------------

``struct lsquic_engine_api`` contains a few mandatory members and several
optional members.

.. type:: struct lsquic_engine_api

    .. member:: const struct lsquic_stream_if       *ea_stream_if
    .. member:: void                                *ea_stream_if_ctx

        ``ea_stream_if`` is mandatory.  This structure contains pointers
        to callbacks that handle connections and stream events.

    .. member:: lsquic_packets_out_f                 ea_packets_out
    .. member:: void                                *ea_packets_out_ctx

        ``ea_packets_out`` is used by the engine to send packets.

    .. member:: const struct lsquic_engine_settings *ea_settings

        If ``ea_settings`` is set to NULL, the engine uses default settings
        (see :func:`lsquic_engine_init_settings()`)

    .. member:: lsquic_lookup_cert_f                 ea_lookup_cert
    .. member:: void                                *ea_cert_lu_ctx

        Look up certificate.  Mandatory in server mode.

    .. member:: struct ssl_ctx_st *                (*ea_get_ssl_ctx)(void *peer_ctx, const struct sockaddr *local)

        Get SSL_CTX associated with a peer context.  Mandatory in server
        mode.  This is used for default values for SSL instantiation.

    .. member:: const struct lsquic_hset_if         *ea_hsi_if
    .. member:: void                                *ea_hsi_ctx

        Optional header set interface.  If not specified, the incoming headers
        are converted to HTTP/1.x format and are read from stream and have to
        be parsed again.

    .. member:: const struct lsquic_shared_hash_if  *ea_shi
    .. member:: void                                *ea_shi_ctx

        Shared hash interface can be used to share state between several
        processes of a single QUIC server.

    .. member:: const struct lsquic_packout_mem_if  *ea_pmi
    .. member:: void                                *ea_pmi_ctx

        Optional set of functions to manage memory allocation for outgoing
        packets.

    .. member:: lsquic_cids_update_f                 ea_new_scids
    .. member:: lsquic_cids_update_f                 ea_live_scids
    .. member:: lsquic_cids_update_f                 ea_old_scids
    .. member:: void                                *ea_cids_update_ctx

        In a multi-process setup, it may be useful to observe the CID
        lifecycle.  This optional set of callbacks makes it possible.

    .. member:: const char                          *ea_alpn

        The optional ALPN string is used by the client if :macro:`LSENG_HTTP`
        is not set.

    .. member::                               void (*ea_generate_scid)(lsquic_conn_t *, lsquic_cid_t *, unsigned)

        Optional interface to control the creation of connection IDs.

.. _apiref-engine-settings:

Engine Settings
---------------

Engine behavior can be controlled by several settings specified in the
settings structure:

.. type:: struct lsquic_engine_settings

    .. member:: unsigned        es_versions

        This is a bit mask wherein each bit corresponds to a value in
        :type:`lsquic_version`.  Client starts negotiating with the highest
        version and goes down.  Server supports either of the versions
        specified here.  This setting applies to both Google and IETF QUIC.

        The default value is :macro:`LSQUIC_DF_VERSIONS`.

    .. member:: unsigned        es_cfcw

       Initial default connection flow control window.

       In server mode, per-connection values may be set lower than
       this if resources are scarce.

       Do not set es_cfcw and es_sfcw lower than :macro:`LSQUIC_MIN_FCW`.

    .. member:: unsigned        es_sfcw

       Initial default stream flow control window.

       In server mode, per-connection values may be set lower than
       this if resources are scarce.

       Do not set es_cfcw and es_sfcw lower than :macro:`LSQUIC_MIN_FCW`.

    .. member:: unsigned        es_max_cfcw

       This value is used to specify maximum allowed value CFCW is allowed
       to reach due to window auto-tuning.  By default, this value is zero,
       which means that CFCW is not allowed to increase from its initial
       value.

       This setting is applicable to both gQUIC and IETF QUIC.

       See :member:`lsquic_engine_settings.es_cfcw`,
       :member:`lsquic_engine_settings.es_init_max_data`.

    .. member:: unsigned        es_max_sfcw

       This value is used to specify the maximum value stream flow control
       window is allowed to reach due to auto-tuning.  By default, this
       value is zero, meaning that auto-tuning is turned off.

       This setting is applicable to both gQUIC and IETF QUIC.

       See :member:`lsquic_engine_settings.es_sfcw`,
       :member:`lsquic_engine_settings.es_init_max_stream_data_bidi_local`,
       :member:`lsquic_engine_settings.es_init_max_stream_data_bidi_remote`.

    .. member:: unsigned        es_max_streams_in

        Maximum incoming streams, a.k.a. MIDS.

        Google QUIC only.

    .. member:: unsigned long   es_handshake_to

       Handshake timeout in microseconds.

       For client, this can be set to an arbitrary value (zero turns the
       timeout off).

       For server, this value is limited to about 16 seconds.  Do not set
       it to zero.

       Defaults to :macro:`LSQUIC_DF_HANDSHAKE_TO`.

    .. member:: unsigned long   es_idle_conn_to

        Idle connection timeout, a.k.a ICSL, in microseconds; GQUIC only.

        Defaults to :macro:`LSQUIC_DF_IDLE_CONN_TO`

    .. member:: int             es_silent_close

        When true, ``CONNECTION_CLOSE`` is not sent when connection times out.
        The server will also not send a reply to client's ``CONNECTION_CLOSE``.

        Corresponds to SCLS (silent close) gQUIC option.

    .. member:: unsigned        es_max_header_list_size

       This corresponds to SETTINGS_MAX_HEADER_LIST_SIZE
       (:rfc:`7540#section-6.5.2`).  0 means no limit.  Defaults
       to :func:`LSQUIC_DF_MAX_HEADER_LIST_SIZE`.

    .. member:: const char     *es_ua

        UAID -- User-Agent ID.  Defaults to :macro:`LSQUIC_DF_UA`.

        Google QUIC only.


       More parameters for server

    .. member:: unsigned        es_max_inchoate

        Maximum number of incoming connections in inchoate state.  (In
        other words, maximum number of mini connections.)

        This is only applicable in server mode.

        Defaults to :macro:`LSQUIC_DF_MAX_INCHOATE`.

    .. member:: int             es_support_push

       Setting this value to 0 means that

       For client:

       1. we send a SETTINGS frame to indicate that we do not support server
          push; and
       2. all incoming pushed streams get reset immediately.

       (For maximum effect, set es_max_streams_in to 0.)

       For server:

       1. :func:`lsquic_conn_push_stream()` will return -1.

    .. member:: int             es_support_tcid0

       If set to true value, the server will not include connection ID in
       outgoing packets if client's CHLO specifies TCID=0.

       For client, this means including TCID=0 into CHLO message.  Note that
       in this case, the engine tracks connections by the
       (source-addr, dest-addr) tuple, thereby making it necessary to create
       a socket for each connection.

       This option has no effect in Q046 and Q050, as the server never includes
       CIDs in the short packets.

       This setting is applicable to gQUIC only.

       The default is :func:`LSQUIC_DF_SUPPORT_TCID0`.

    .. member:: int             es_support_nstp

       Q037 and higher support "No STOP_WAITING frame" mode.  When set, the
       client will send NSTP option in its Client Hello message and will not
       sent STOP_WAITING frames, while ignoring incoming STOP_WAITING frames,
       if any.  Note that if the version negotiation happens to downgrade the
       client below Q037, this mode will *not* be used.

       This option does not affect the server, as it must support NSTP mode
       if it was specified by the client.

        Defaults to :macro:`LSQUIC_DF_SUPPORT_NSTP`.

    .. member:: int             es_honor_prst

       If set to true value, the library will drop connections when it
       receives corresponding Public Reset packet.  The default is to
       ignore these packets.

       The default is :macro:`LSQUIC_DF_HONOR_PRST`.

    .. member:: int             es_send_prst

       If set to true value, the library will send Public Reset packets
       in response to incoming packets with unknown Connection IDs.

       The default is :macro:`LSQUIC_DF_SEND_PRST`.

    .. member:: unsigned        es_progress_check

       A non-zero value enables internal checks that identify suspected
       infinite loops in user `on_read` and `on_write` callbacks
       and break them.  An infinite loop may occur if user code keeps
       on performing the same operation without checking status, e.g.
       reading from a closed stream etc.

       The value of this parameter is as follows: should a callback return
       this number of times in a row without making progress (that is,
       reading, writing, or changing stream state), loop break will occur.

       The defaut value is :macro:`LSQUIC_DF_PROGRESS_CHECK`.

    .. member:: int             es_rw_once

       A non-zero value make stream dispatch its read-write events once
       per call.

       When zero, read and write events are dispatched until the stream
       is no longer readable or writeable, respectively, or until the
       user signals unwillingness to read or write using
       :func:`lsquic_stream_wantread()` or :func:`lsquic_stream_wantwrite()`
       or shuts down the stream.

       The default value is :macro:`LSQUIC_DF_RW_ONCE`.

    .. member:: unsigned        es_proc_time_thresh

       If set, this value specifies the number of microseconds that
       :func:`lsquic_engine_process_conns()` and
       :func:`lsquic_engine_send_unsent_packets()` are allowed to spend
       before returning.

       This is not an exact science and the connections must make
       progress, so the deadline is checked after all connections get
       a chance to tick (in the case of :func:`lsquic_engine_process_conns())`
       and at least one batch of packets is sent out.

       When processing function runs out of its time slice, immediate
       calls to :func:`lsquic_engine_has_unsent_packets()` return false.

       The default value is :func:`LSQUIC_DF_PROC_TIME_THRESH`.

    .. member:: int             es_pace_packets

       If set to true, packet pacing is implemented per connection.

       The default value is :func:`LSQUIC_DF_PACE_PACKETS`.

    .. member:: unsigned        es_clock_granularity

       Clock granularity information is used by the pacer.  The value
       is in microseconds; default is :func:`LSQUIC_DF_CLOCK_GRANULARITY`.

    .. member:: unsigned        es_init_max_data

       Initial max data.

       This is a transport parameter.

       Depending on the engine mode, the default value is either
       :macro:`LSQUIC_DF_INIT_MAX_DATA_CLIENT` or
       :macro:`LSQUIC_DF_INIT_MAX_DATA_SERVER`.

       IETF QUIC only.

    .. member:: unsigned        es_init_max_stream_data_bidi_remote

       Initial max stream data.

       This is a transport parameter.

       Depending on the engine mode, the default value is either
       :macro:`LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT` or
       :macro:`LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER`.

       IETF QUIC only.

    .. member:: unsigned        es_init_max_stream_data_bidi_local

       Initial max stream data.

       This is a transport parameter.

       Depending on the engine mode, the default value is either
       :macro:`LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT` or
       :macro:`LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER`.

       IETF QUIC only.

    .. member:: unsigned        es_init_max_stream_data_uni

       Initial max stream data for unidirectional streams initiated
       by remote endpoint.

       This is a transport parameter.

       Depending on the engine mode, the default value is either
       :macro:`LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_CLIENT` or
       :macro:`LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_SERVER`.

       IETF QUIC only.

    .. member:: unsigned        es_init_max_streams_bidi

       Maximum initial number of bidirectional stream.

       This is a transport parameter.

       Default value is :macro:`LSQUIC_DF_INIT_MAX_STREAMS_BIDI`.

       IETF QUIC only.

    .. member:: unsigned        es_init_max_streams_uni

       Maximum initial number of unidirectional stream.

       This is a transport parameter.

       Default value is :macro:`LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT` or
       :macro:`LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_SERVER`.

       IETF QUIC only.

    .. member:: unsigned        es_idle_timeout

       Idle connection timeout.

       This is a transport parameter.

       (Note: `es_idle_conn_to` is not reused because it is in microseconds,
       which, I now realize, was not a good choice.  Since it will be
       obsoleted some time after the switchover to IETF QUIC, we do not
       have to keep on using strange units.)

       Default value is :macro:`LSQUIC_DF_IDLE_TIMEOUT`.

       Maximum value is 600 seconds.

       IETF QUIC only.

    .. member:: unsigned        es_ping_period

       Ping period.  If set to non-zero value, the connection will generate and
       send PING frames in the absence of other activity.

       By default, the server does not send PINGs and the period is set to zero.
       The client's defaut value is :macro:`LSQUIC_DF_PING_PERIOD`.

       IETF QUIC only.

    .. member:: unsigned        es_scid_len

       Source Connection ID length.  Valid values are 0 through 20, inclusive.

       Default value is :macro:`LSQUIC_DF_SCID_LEN`.

       IETF QUIC only.

    .. member:: unsigned        es_scid_iss_rate

       Source Connection ID issuance rate.  This field is measured in CIDs
       per minute.  Using value 0 indicates that there is no rate limit for
       CID issuance.

       Default value is :macro:`LSQUIC_DF_SCID_ISS_RATE`.

       IETF QUIC only.

    .. member:: unsigned        es_qpack_dec_max_size

       Maximum size of the QPACK dynamic table that the QPACK decoder will
       use.

       The default is :macro:`LSQUIC_DF_QPACK_DEC_MAX_SIZE`.

       IETF QUIC only.

    .. member:: unsigned        es_qpack_dec_max_blocked

       Maximum number of blocked streams that the QPACK decoder is willing
       to tolerate.

       The default is :macro:`LSQUIC_DF_QPACK_DEC_MAX_BLOCKED`.

       IETF QUIC only.

    .. member:: unsigned        es_qpack_enc_max_size

       Maximum size of the dynamic table that the encoder is willing to use.
       The actual size of the dynamic table will not exceed the minimum of
       this value and the value advertized by peer.

       The default is :macro:`LSQUIC_DF_QPACK_ENC_MAX_SIZE`.

       IETF QUIC only.

    .. member:: unsigned        es_qpack_enc_max_blocked

       Maximum number of blocked streams that the QPACK encoder is willing
       to risk.  The actual number of blocked streams will not exceed the
       minimum of this value and the value advertized by peer.

       The default is :macro:`LSQUIC_DF_QPACK_ENC_MAX_BLOCKED`.

       IETF QUIC only.

    .. member:: int             es_ecn

       Enable ECN support.

       The default is :macro:`LSQUIC_DF_ECN`

       IETF QUIC only.

    .. member:: int             es_allow_migration

       Allow peer to migrate connection.

       The default is :macro:`LSQUIC_DF_ALLOW_MIGRATION`

       IETF QUIC only.

    .. member:: unsigned        es_cc_algo

       Congestion control algorithm to use.

       - 0:  Use default (:macro:`LSQUIC_DF_CC_ALGO`)
       - 1:  Cubic
       - 2:  BBRv1
       - 3:  Adaptive congestion control.

       Adaptive congestion control adapts to the environment.  It figures
       out whether to use Cubic or BBRv1 based on the RTT.

    .. member:: unsigned        es_cc_rtt_thresh

       Congestion controller RTT threshold in microseconds.

       Adaptive congestion control uses BBRv1 until RTT is determined.  At
       that point a permanent choice of congestion controller is made.  If
       RTT is smaller than or equal to
       :member:`lsquic_engine_settings.es_cc_rtt_thresh`, congestion
       controller is switched to Cubic; otherwise, BBRv1 is picked.

       The default value is :macro:`LSQUIC_DF_CC_RTT_THRESH`

    .. member:: int             es_ql_bits

       Use QL loss bits.  Allowed values are:

       - 0:  Do not use loss bits
       - 1:  Allow loss bits
       - 2:  Allow and send loss bits

       Default value is :macro:`LSQUIC_DF_QL_BITS`

    .. member:: int             es_spin

       Enable spin bit.  Allowed values are 0 and 1.

       Default value is :macro:`LSQUIC_DF_SPIN`

    .. member:: int             es_delayed_acks

       Enable delayed ACKs extension.  Allowed values are 0 and 1.

       Default value is :macro:`LSQUIC_DF_DELAYED_ACKS`

    .. member:: int             es_timestamps

       Enable timestamps extension.  Allowed values are 0 and 1.

       Default value is @ref LSQUIC_DF_TIMESTAMPS

    .. member:: unsigned short  es_max_udp_payload_size_rx

       Maximum packet size we are willing to receive.  This is sent to
       peer in transport parameters: the library does not enforce this
       limit for incoming packets.

       If set to zero, limit is not set.

       Default value is :macro:`LSQUIC_DF_MAX_UDP_PAYLOAD_SIZE_RX`

    .. member:: int es_dplpmtud

       If set to true value, enable DPLPMTUD -- Datagram Packetization
       Layer Path MTU Discovery.

       Default value is :macro:`LSQUIC_DF_DPLPMTUD`

    .. member:: unsigned short  es_base_plpmtu

        PLPMTU size expected to work for most paths.

        If set to zero, this value is calculated based on QUIC and IP versions.

        Default value is :macro:`LSQUIC_DF_BASE_PLPMTU`

    .. member:: unsigned short  es_max_plpmtu

        Largest PLPMTU size the engine will try.

        If set to zero, picking this value is left to the engine.

        Default value is :macro:`LSQUIC_DF_MAX_PLPMTU`

    .. member:: unsigned        es_mtu_probe_timer

        This value specifies how long the DPLPMTUD probe timer is, in
        milliseconds.  :rfc:`8899` says:

            PROBE_TIMER:  The PROBE_TIMER is configured to expire after a period
            longer than the maximum time to receive an acknowledgment to a
            probe packet.  This value MUST NOT be smaller than 1 second, and
            SHOULD be larger than 15 seconds.  Guidance on selection of the
            timer value are provided in section 3.1.1 of the UDP Usage
            Guidelines :rfc:`8085#section-3.1`.

        If set to zero, the default is used.

        Default value is :macro:`LSQUIC_DF_MTU_PROBE_TIMER`

    .. member:: unsigned        es_noprogress_timeout

       No progress timeout.

       If connection does not make progress for this number of seconds, the
       connection is dropped.  Here, progress is defined as user streams
       being written to or read from.

       If this value is zero, this timeout is disabled.

       Default value is :macro:`LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER` in server
       mode and :macro:`LSQUIC_DF_NOPROGRESS_TIMEOUT_CLIENT` in client mode.

    .. member:: int             es_grease_quic_bit

       Enable the "QUIC bit grease" extension.  When set to a true value,
       lsquic will grease the QUIC bit on the outgoing QUIC packets if
       the peer sent the "grease_quic_bit" transport parameter.

       Default value is :macro:`LSQUIC_DF_GREASE_QUIC_BIT`

    .. member:: int             es_datagrams

       Enable datagrams extension.  Allowed values are 0 and 1.

       Default value is :macro:`LSQUIC_DF_DATAGRAMS`

    .. member:: int             es_optimistic_nat

       If set to true, changes in peer port are assumed to be due to a
       benign NAT rebinding and path characteristics -- MTU, RTT, and
       CC state -- are not reset.

       Default value is :macro:`LSQUIC_DF_OPTIMISTIC_NAT`

    .. member:: int             es_ext_http_prio

       If set to true, Extensible HTTP Priorities are enabled.  This
       is HTTP/3-only setting.

       Default value is :macro:`LSQUIC_DF_EXT_HTTP_PRIO`

    .. member:: int             es_qpack_experiment

       If set to 1, QPACK statistics are logged per connection.

       If set to 2, QPACK experiments are run.  In this mode, encoder
       and decoder setting values are randomly selected (from the range
       [0, whatever is specified in es_qpack_(enc|dec)_*]) and these
       values along with compression ratio and user agent are logged at
       NOTICE level when connection is destroyed.  The purpose of these
       experiments is to use compression performance statistics to figure
       out a good set of default values.

       Default value is :macro:`LSQUIC_DF_QPACK_EXPERIMENT`

    .. member:: int             es_delay_onclose

       When set to true, :member:`lsquic_stream_if.on_close` will be delayed until the
       peer acknowledges all data sent on the stream.  (Or until the connection
       is destroyed in some manner -- either explicitly closed by the user or
       as a result of an engine shutdown.)  To find out whether all data written
       to peer has been acknowledged, use `lsquic_stream_has_unacked_data()`.

       Default value is :macro:`LSQUIC_DF_DELAY_ONCLOSE`

    .. member:: int             es_max_batch_size

       If set to a non-zero value, specifies maximum batch size.  (The
       batch of packets passed to :member:`lsquic_engine_api.ea_packets_out`).
       Must be no larger than 1024.

       Default value is :macro:`LSQUIC_DF_MAX_BATCH_SIZE`

    .. member:: int             es_check_tp_sanity

       When true, sanity checks are performed on peer's transport parameter
       values.  If some limits are set suspiciously low, the connection won't
       be established.

       Default value is :macro:`LSQUIC_DF_CHECK_TP_SANITY`

To initialize the settings structure to library defaults, use the following
convenience function:

.. function:: lsquic_engine_init_settings (struct lsquic_engine_settings *, unsigned flags)

    ``flags`` is a bitmask of ``LSENG_SERVER`` and ``LSENG_HTTP``

After doing this, change just the settings you'd like.  To check whether
the values are correct, another convenience function is provided:

.. function:: lsquic_engine_check_settings (const struct lsquic_engine_settings *, unsigned flags, char *err_buf, size_t err_buf_sz)

    Check settings for errors.  Return 0 if settings are OK, -1 otherwise.

    If `err_buf` and `err_buf_sz` are set, an error string is written to the
    buffers.

The following macros in :file:`lsquic.h` specify default values:

*Note that, despite our best efforts, documentation may accidentally get
out of date.  Please check your :file:`lsquic.h` for actual values.*

.. macro::      LSQUIC_MIN_FCW

    Minimum flow control window is set to 16 KB for both client and server.
    This means we can send up to this amount of data before handshake gets
    completed.

.. macro:: LSQUIC_DF_VERSIONS

    By default, deprecated and experimental versions are not included.

.. macro:: LSQUIC_DF_CFCW_SERVER
.. macro:: LSQUIC_DF_CFCW_CLIENT
.. macro:: LSQUIC_DF_SFCW_SERVER
.. macro:: LSQUIC_DF_SFCW_CLIENT
.. macro:: LSQUIC_DF_MAX_STREAMS_IN

.. macro:: LSQUIC_DF_INIT_MAX_DATA_SERVER
.. macro:: LSQUIC_DF_INIT_MAX_DATA_CLIENT
.. macro:: LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER
.. macro:: LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER
.. macro:: LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT
.. macro:: LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT
.. macro:: LSQUIC_DF_INIT_MAX_STREAMS_BIDI
.. macro:: LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT
.. macro:: LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER
.. macro:: LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_CLIENT
.. macro:: LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_SERVER

.. macro:: LSQUIC_DF_IDLE_TIMEOUT

    Default idle connection timeout is 30 seconds.

.. macro:: LSQUIC_DF_PING_PERIOD

    Default ping period is 15 seconds.

.. macro:: LSQUIC_DF_HANDSHAKE_TO

    Default handshake timeout is 10,000,000 microseconds (10 seconds).

.. macro:: LSQUIC_DF_IDLE_CONN_TO

    Default idle connection timeout is 30,000,000 microseconds.

.. macro:: LSQUIC_DF_SILENT_CLOSE

    By default, connections are closed silenty when they time out (no
    ``CONNECTION_CLOSE`` frame is sent) and the server does not reply with
    own ``CONNECTION_CLOSE`` after it receives one.

.. macro:: LSQUIC_DF_MAX_HEADER_LIST_SIZE

    Default value of maximum header list size.  If set to non-zero value,
    SETTINGS_MAX_HEADER_LIST_SIZE will be sent to peer after handshake is
    completed (assuming the peer supports this setting frame type).

.. macro:: LSQUIC_DF_UA

    Default value of UAID (user-agent ID).

.. macro:: LSQUIC_DF_MAX_INCHOATE

    Default is 1,000,000.

.. macro:: LSQUIC_DF_SUPPORT_NSTP

    NSTP is not used by default.

.. macro:: LSQUIC_DF_SUPPORT_PUSH

    Push promises are supported by default.

.. macro:: LSQUIC_DF_SUPPORT_TCID0

    Support for TCID=0 is enabled by default.

.. macro:: LSQUIC_DF_HONOR_PRST

    By default, LSQUIC ignores Public Reset packets.

.. macro:: LSQUIC_DF_SEND_PRST

    By default, LSQUIC will not send Public Reset packets in response to
    packets that specify unknown connections.

.. macro:: LSQUIC_DF_PROGRESS_CHECK

    By default, infinite loop checks are turned on.

.. macro:: LSQUIC_DF_RW_ONCE

    By default, read/write events are dispatched in a loop.

.. macro:: LSQUIC_DF_PROC_TIME_THRESH

    By default, the threshold is not enabled.

.. macro:: LSQUIC_DF_PACE_PACKETS

    By default, packets are paced

.. macro:: LSQUIC_DF_CLOCK_GRANULARITY

    Default clock granularity is 1000 microseconds.

.. macro:: LSQUIC_DF_SCID_LEN

    The default value is 8 for simplicity and speed.

.. macro:: LSQUIC_DF_SCID_ISS_RATE

    The default value is 60 CIDs per minute.

.. macro:: LSQUIC_DF_QPACK_DEC_MAX_BLOCKED

    Default value is 100.

.. macro:: LSQUIC_DF_QPACK_DEC_MAX_SIZE

    Default value is 4,096 bytes.

.. macro:: LSQUIC_DF_QPACK_ENC_MAX_BLOCKED

    Default value is 100.

.. macro:: LSQUIC_DF_QPACK_ENC_MAX_SIZE

    Default value is 4,096 bytes.

.. macro:: LSQUIC_DF_ECN

    ECN is disabled by default.

.. macro:: LSQUIC_DF_ALLOW_MIGRATION

    Allow migration by default.

.. macro:: LSQUIC_DF_QL_BITS

    Use QL loss bits by default.

.. macro:: LSQUIC_DF_SPIN

    Turn spin bit on by default.

.. macro:: LSQUIC_DF_CC_ALGO

    Use Adaptive Congestion Controller by default.

.. macro:: LSQUIC_DF_CC_RTT_THRESH

    Default value of the CC RTT threshold is 1500 microseconds

.. macro:: LSQUIC_DF_DELAYED_ACKS

    The Delayed ACKs extension is on by default.

.. macro:: LSQUIC_DF_MAX_UDP_PAYLOAD_SIZE_RX

    By default, incoming packet size is not limited.

.. macro:: LSQUIC_DF_DPLPMTUD

    By default, DPLPMTUD is enabled

.. macro:: LSQUIC_DF_BASE_PLPMTU

    By default, this value is left up to the engine.

.. macro:: LSQUIC_DF_MAX_PLPMTU

    By default, this value is left up to the engine.

.. macro:: LSQUIC_DF_MTU_PROBE_TIMER

    By default, we use the minimum timer of 1000 milliseconds.

.. macro:: LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER

    By default, drop no-progress connections after 60 seconds on the server.

.. macro:: LSQUIC_DF_NOPROGRESS_TIMEOUT_CLIENT

    By default, do not use no-progress timeout on the client.

.. macro:: LSQUIC_DF_GREASE_QUIC_BIT

    By default, greasing the QUIC bit is enabled (if peer sent
    the "grease_quic_bit" transport parameter).

.. macro:: LSQUIC_DF_TIMESTAMPS

    Timestamps are on by default.

.. macro:: LSQUIC_DF_DATAGRAMS

    Datagrams are off by default.

.. macro:: LSQUIC_DF_OPTIMISTIC_NAT

    Assume optimistic NAT by default.

.. macro:: LSQUIC_DF_EXT_HTTP_PRIO

    Turn on Extensible HTTP Priorities by default.

.. macro:: LSQUIC_DF_QPACK_EXPERIMENT

    By default, QPACK experiments are turned off.

.. macro:: LSQUIC_DF_DELAY_ONCLOSE

    By default, calling :member:`lsquic_stream_if.on_close()` is not delayed.

.. macro:: LSQUIC_DF_MAX_BATCH_SIZE

    By default, maximum batch size is not specified, leaving it up to the
    library.

.. macro:: LSQUIC_DF_CHECK_TP_SANITY

    Transport parameter sanity checks are performed by default.

Receiving Packets
-----------------

Incoming packets are supplied to the engine using :func:`lsquic_engine_packet_in()`.
It is up to the engine to decide what do to with the packet.  It can find an existing
connection and dispatch the packet there, create a new connection (in server mode), or
schedule a version negotiation or stateless reset packet.

.. function:: int lsquic_engine_packet_in (lsquic_engine_t *engine, const unsigned char *data, size_t size, const struct sockaddr *local, const struct sockaddr *peer, void *peer_ctx, int ecn)

    Pass incoming packet to the QUIC engine.  This function can be called
    more than once in a row.  After you add one or more packets, call
    :func:`lsquic_engine_process_conns()` to schedule outgoing packets, if any.

    :param engine: Engine instance.
    :param data: Pointer to UDP datagram payload.
    :param size: Size of UDP datagram.
    :param local: Local address.
    :param peer: Peer address.
    :param peer_ctx: Peer context.
    :param ecn: ECN marking associated with this UDP datagram.

    :return:

        - ``0``: Packet was processed by a real connection.
        - ``1``: Packet was handled successfully, but not by a connection.
          This may happen with version negotiation and public reset
          packets as well as some packets that may be ignored.
        - ``-1``: Some error occurred.  Possible reasons are invalid packet
          size or failure to allocate memory.

.. function:: int lsquic_engine_earliest_adv_tick (lsquic_engine_t *engine, int *diff)

    Returns true if there are connections to be processed, false otherwise.

    :param engine:

        Engine instance.

    :param diff:

        If the function returns a true value, the pointed to integer is set to the
        difference between the earliest advisory tick time and now.
        If the former is in the past, this difference is negative.

    :return:

        True if there are connections to be processed, false otherwise.

Sending Packets
---------------

User specifies a callback :type:`lsquic_packets_out_f` in :type:`lsquic_engine_api`
that the library uses to send packets.

.. type:: struct lsquic_out_spec

    This structure describes an outgoing packet.

    .. member:: struct iovec          *iov

        A vector with payload.

    .. member:: size_t                 iovlen

        Vector length.

    .. member:: const struct sockaddr *local_sa

        Local address.

    .. member:: const struct sockaddr *dest_sa

        Destination address.

    .. member:: void                  *peer_ctx

        Peer context associated with the local address.

    .. member:: int                    ecn

        ECN: Valid values are 0 - 3. See :rfc:`3168`.

        ECN may be set by IETF QUIC connections if ``es_ecn`` is set.

.. type:: typedef int (*lsquic_packets_out_f)(void *packets_out_ctx, const struct lsquic_out_spec  *out_spec, unsigned n_packets_out)

    Returns number of packets successfully sent out or -1 on error.  -1 should
    only be returned if no packets were sent out.  If -1 is returned or if the
    return value is smaller than ``n_packets_out``, this indicates that sending
    of packets is not possible.

    If not all packets could be sent out, then:

        - errno is examined.  If it is not EAGAIN or EWOULDBLOCK, the connection
          whose packet caused the error is closed forthwith.
        - No packets are attempted to be sent out until :func:`lsquic_engine_send_unsent_packets()`
          is called.

.. function:: void lsquic_engine_process_conns (lsquic_engine_t *engine)

    Process tickable connections.  This function must be called often enough so
    that packets and connections do not expire.  The preferred method of doing
    so is by using :func:`lsquic_engine_earliest_adv_tick()`.

.. function:: int lsquic_engine_has_unsent_packets (lsquic_engine_t *engine)

    Returns true if engine has some unsent packets.  This happens if
    :member:`lsquic_engine_api.ea_packets_out` could not send everything out
    or if processing deadline was exceeded (see
    :member:`lsquic_engine_settings.es_proc_time_thresh`).

.. function:: void lsquic_engine_send_unsent_packets (lsquic_engine_t *engine)

    Send out as many unsent packets as possibe: until we are out of unsent
    packets or until ``ea_packets_out()`` fails.

    If ``ea_packets_out()`` cannot send all packets, this function must be
    called to signify that sending of packets is possible again.

Stream Callback Interface
-------------------------

The stream callback interface structure lists the callbacks used by
the engine to communicate with the user code:

.. type:: struct lsquic_stream_if

    .. member:: lsquic_conn_ctx_t *(*on_new_conn)(void *stream_if_ctx, lsquic_conn_t *)

        Called when a new connection has been created.  In server mode,
        this means that the handshake has been successful.  In client mode,
        on the other hand, this callback is called as soon as connection
        object is created inside the engine, but before the handshake is
        done.

        The return value is the connection context associated with this
        connection.  Use :func:`lsquic_conn_get_ctx()` to get back this
        context.  It is OK for this function to return NULL.

        This callback is mandatory.

    .. member:: void (*on_conn_closed)(lsquic_conn_t *)

        Connection is closed.

        This callback is mandatory.

    .. member:: lsquic_stream_ctx_t * (*on_new_stream)(void *stream_if_ctx, lsquic_stream_t *)

        If you need to initiate a connection, call lsquic_conn_make_stream().
        This will cause `on_new_stream` callback to be called when appropriate
        (this operation is delayed when maximum number of outgoing streams is
        reached).

        If connection is going away, this callback may be called with the
        second parameter set to NULL.

        The return value is the stream context associated with the stream.
        A pointer to it is passed to `on_read()`, `on_write()`, and `on_close()`
        callbacks.  It is OK for this function to return NULL.

        This callback is mandatory.

    .. member:: void (*on_read)     (lsquic_stream_t *s, lsquic_stream_ctx_t *h)

        Stream is readable: either there are bytes to be read or an error
        is ready to be collected.

        This callback is mandatory.

    .. member:: void (*on_write)    (lsquic_stream_t *s, lsquic_stream_ctx_t *h)

        Stream is writeable.

        This callback is mandatory.

    .. member:: void (*on_close)    (lsquic_stream_t *s, lsquic_stream_ctx_t *h)

        After this callback returns, the stream is no longer accessible.  This is
        a good time to clean up the stream context.

        This callback is mandatory.

    .. member:: void (*on_reset)    (lsquic_stream_t *s, lsquic_stream_ctx_t *h, int how)

        This callback is called as soon as the peer resets a stream.
        The argument `how` is either 0, 1, or 2, meaning "read", "write", and
        "read and write", respectively (just like in ``shutdown(2)``).  This
        signals the user to stop reading, writing, or both.

        Note that resets differ in gQUIC and IETF QUIC.  In gQUIC, `how` is
        always 2; in IETF QUIC, `how` is either 0 or 1 because one can reset
        just one direction in IETF QUIC.

        This callback is optional.  The reset error can still be collected
        during next "on read" or "on write" event.

    .. member:: void (*on_hsk_done)(lsquic_conn_t *c, enum lsquic_hsk_status s)

        When handshake is completed, this callback is called.

        This callback is optional.

    .. member:: void (*on_goaway_received)(lsquic_conn_t *)

        This is called when our side received GOAWAY frame.  After this,
        new streams should not be created.

        This callback is optional.

    .. member:: void (*on_new_token)(lsquic_conn_t *c, const unsigned char *token, size_t token_size)

        When client receives a token in NEW_TOKEN frame, this callback is called.

        This callback is optional.

    .. member:: void (*on_sess_resume_info)(lsquic_conn_t *c, const unsigned char *, size_t)

        This callback lets client record information needed to
        perform session resumption next time around.

        For IETF QUIC, this is called only if :member:`lsquic_engine_api.ea_get_ssl_ctx_st`
        is *not* set, in which case the library creates its own SSL_CTX.

        Note: this callback will be deprecated when gQUIC support is removed.

        This callback is optional.

    .. member:: ssize_t (*on_dg_write)(lsquic_conn_t *c, void *buf, size_t buf_sz)

        Called when datagram is ready to be written.  Write at most
        ``buf_sz`` bytes to ``buf`` and  return number of bytes
        written.

    .. member:: void (*on_datagram)(lsquic_conn_t *c, const void *buf, size_t sz)

        Called when datagram is read from a packet.  This callback is
        required when :member:`lsquic_engine_settings.es_datagrams` is true.
        Take care to process it quickly, as this is called during
        :func:`lsquic_engine_packet_in()`.

Creating Connections
--------------------

In server mode, the connections are created by the library based on incoming
packets.  After handshake is completed, the library calls :member:`lsquic_stream_if.on_new_conn`
callback.

In client mode, a new connection is created by

.. function:: lsquic_conn_t * lsquic_engine_connect (lsquic_engine_t *engine, enum lsquic_version version, const struct sockaddr *local_sa, const struct sockaddr *peer_sa, void *peer_ctx, lsquic_conn_ctx_t *conn_ctx, const char *sni, unsigned short base_plpmtu, const unsigned char *sess_resume, size_t sess_resume_len, const unsigned char *token, size_t token_sz)

    :param engine: Engine to use.

    :param version:

        To let the engine specify QUIC version, use N_LSQVER.  If session resumption
        information is supplied, version is picked from there instead.

    :param local_sa:

        Local address.

    :param peer_sa:

        Address of the server.

    :param peer_ctx:

        Context associated with the peer.  This is what gets passed to TODO.

    :param conn_ctx:

        Connection context can be set early using this parameter.  Useful if
        you need the connection context to be available in `on_conn_new()`.
        Note that that callback's return value replaces the connection
        context set here.

    :param sni:

        The SNI is required for Google QUIC connections; it is optional for
        IETF QUIC and may be set to NULL.

    :param base_plpmtu:

        Base PLPMTU.  If set to zero, it is selected based on the
        engine settings (see
        :member:`lsquic_engine_settings.es_base_plpmtu`),
        QUIC version, and IP version.

    :param sess_resume:

        Pointer to previously saved session resumption data needed for
        TLS resumption.  May be NULL.

    :param sess_resume_len:

        Size of session resumption data.

    :param token:

        Pointer to previously received token to include in the Initial
        packet.  Tokens are used by IETF QUIC to pre-validate client
        connections, potentially avoiding a retry.

        See :member:`lsquic_stream_if.on_new_token` callback.

        May be NULL.

    :param token_sz:

        Size of data pointed to by ``token``.

Closing Connections
-------------------

.. function:: void lsquic_conn_going_away (lsquic_conn_t *conn)

    Mark connection as going away: send GOAWAY frame and do not accept
    any more incoming streams, nor generate streams of our own.

    Only applicable to HTTP/3 and GQUIC connections.  Otherwise a no-op.

.. function:: void lsquic_conn_close (lsquic_conn_t *conn)

    This closes the connection.  :member:`lsquic_stream_if.on_conn_closed`
    and :member:`lsquic_stream_if.on_close` callbacks will be called.

.. function:: void lsquic_conn_abort (lsquic_conn_t *conn)

    This aborts the connection.  The connection and all associated objects
    will be destroyed (with necessary callbacks called) during the next time
    :func:`lsquic_engine_process_conns()` is invoked.

Creating Streams
----------------

Similar to connections, streams are created by the library in server mode; they
correspond to requests.  In client mode, a new stream is created by

.. function:: void lsquic_conn_make_stream (lsquic_conn_t *)

    Create a new request stream.  This causes :member:`on_new_stream()` callback
    to be called.  If creating more requests is not permitted at the moment
    (due to number of concurrent streams limit), stream creation is registered
    as "pending" and the stream is created later when number of streams dips
    under the limit again.  Any number of pending streams can be created.
    Use :func:`lsquic_conn_n_pending_streams()` and
    :func:`lsquic_conn_cancel_pending_streams()` to manage pending streams.

    If connection is going away, :func:`on_new_stream()` is called with the
    stream parameter set to NULL.

Stream Events
-------------

To register or unregister an interest in a read or write event, use the
following functions:

.. function:: int lsquic_stream_wantread (lsquic_stream_t *stream, int want)

    :param stream: Stream to read from.
    :param want: Boolean value indicating whether the caller wants to read
                 from stream.
    :return: Previous value of ``want`` or ``-1`` if the stream has already
             been closed for reading.

    A stream becomes readable if there is was an error: for example, the
    peer may have reset the stream.  In this case, reading from the stream
    will return an error.

.. function:: int lsquic_stream_wantwrite (lsquic_stream_t *stream, int want)

    :param stream: Stream to write to.
    :param want: Boolean value indicating whether the caller wants to write
                 to stream.
    :return: Previous value of ``want`` or ``-1`` if the stream has already
             been closed for writing.

Reading From Streams
--------------------

.. function:: ssize_t lsquic_stream_read (lsquic_stream_t *stream, unsigned char *buf, size_t sz)

    :param stream: Stream to read from.
    :param buf: Buffer to copy data to.
    :param sz: Size of the buffer.
    :return: Number of bytes read, zero if EOS has been reached, or -1 on error.

    Read up to ``sz`` bytes from ``stream`` into buffer ``buf``.

    ``-1`` is returned on error, in which case ``errno`` is set:

    - ``EBADF``: The stream is closed.
    - ``ECONNRESET``: The stream has been reset.
    - ``EWOULDBLOCK``: There is no data to be read.

.. function:: ssize_t lsquic_stream_readv (lsquic_stream_t *stream, const struct iovec *vec, int iovcnt)

    :param stream: Stream to read from.
    :param vec: Array of ``iovec`` structures.
    :param iovcnt: Number of elements in ``vec``.
    :return: Number of bytes read, zero if EOS has been reached, or -1 on error.

    Similar to :func:`lsquic_stream_read()`, but reads data into a vector.

.. function:: ssize_t lsquic_stream_readf (lsquic_stream_t *stream, size_t (*readf)(void *ctx, const unsigned char *buf, size_t len, int fin), void *ctx)

    :param stream: Stream to read from.

    :param readf:

        The callback takes four parameters:

        - Pointer to user-supplied context;
        - Pointer to the data;
        - Data size (can be zero); and
        - Indicator whether the FIN follows the data.

        The callback returns number of bytes processed.  If this number is zero
        or is smaller than ``len``, reading from stream stops.

    :param ctx: Context pointer passed to ``readf``.

    This function allows user-supplied callback to read the stream contents.
    It is meant to be used for zero-copy stream processing.

    Return value and errors are same as in :func:`lsquic_stream_read()`.

Writing To Streams
------------------

.. function:: ssize_t lsquic_stream_write (lsquic_stream_t *stream, const void *buf, size_t len)

    :param stream: Stream to write to.
    :param buf: Buffer to copy data from.
    :param len: Number of bytes to copy.
    :return: Number of bytes written -- which may be smaller than ``len`` -- or a negative
             value when an error occurs.

    Write ``len`` bytes to the stream.  Returns number of bytes written, which
    may be smaller that ``len``.

    A negative return value indicates a serious error (the library is likely
    to have aborted the connection because of it).

.. function:: ssize_t lsquic_stream_writev (lsquic_stream_t *s, const struct iovec *vec, int count)

    Like :func:`lsquic_stream_write()`, but read data from a vector.

.. type:: struct lsquic_reader

    Used as argument to :func:`lsquic_stream_writef()`.

    .. member:: size_t (*lsqr_read) (void *lsqr_ctx, void *buf, size_t count)

        :param lsqr_ctx: Pointer to user-specified context.
        :param buf: Memory location to write to.
        :param count: Size of available memory pointed to by ``buf``.
        :return:

            Number of bytes written.  This is not a ``ssize_t`` because
            the read function is not supposed to return an error.  If an error
            occurs in the read function (for example, when reading from a file
            fails), it is supposed to deal with the error itself.

    .. member:: size_t (*lsqr_size) (void *lsqr_ctx)

        Return number of bytes remaining in the reader.

    .. member:: void    *lsqr_ctx

        Context pointer passed both to ``lsqr_read()`` and to ``lsqr_size()``.

.. function:: ssize_t lsquic_stream_writef (lsquic_stream_t *stream, struct lsquic_reader *reader)

    :param stream: Stream to write to.
    :param reader: Reader to read from.
    :return: Number of bytes written or -1 on error.

    Write to stream using :type:`lsquic_reader`.  This is the most generic of
    the write functions -- :func:`lsquic_stream_write()` and
    :func:`lsquic_stream_writev()` utilize the same mechanism.

.. function:: ssize_t lsquic_stream_pwritev (struct lsquic_stream *stream, ssize_t (*preadv)(void *user_data, const struct iovec *iov, int iovcnt), void *user_data, size_t n_to_write)

    :param stream: Stream to write to.
    :param preadv: Pointer to a custom ``preadv(2)``-like function.
    :param user_data: Data to pass to ``preadv`` function.
    :param n_to_write: Number of bytes to write.
    :return: Number of bytes written or -1 on error.

    Write to stream using user-supplied ``preadv()`` function.
    The stream allocates one or more packets and calls ``preadv()``,
    which then fills the array of buffers.  This is a good way to
    minimize the number of ``read(2)`` system calls; the user can call
    ``preadv(2)`` instead.

    The number of bytes available in the ``iov`` vector passed back to
    the user callback may be smaller than ``n_to_write``.  The expected
    use pattern is to pass the number of bytes remaining in the file
    and keep on calling ``preadv(2)``.

    Note that, unlike other stream-writing functions above,
    ``lsquic_stream_pwritev()`` does *not* buffer bytes inside the
    stream; it only writes to packets.  That means the caller must be
    prepared for this function to return 0 even inside the "on write"
    stream callback.  In that case, the caller should fall back to using
    another write function.

    It is OK for the ``preadv`` callback to write fewer bytes that
    ``n_to_write``.  (This can happen if the underlying data source
    is truncated.)

::

    /*
     * For example, the return value of zero can be handled as follows:
     */
    nw = lsquic_stream_pwritev(stream, my_readv, some_ctx, n_to_write);
    if (nw == 0)
        nw = lsquic_stream_write(stream, rem_bytes_buf, rem_bytes_len);

.. function:: int lsquic_stream_flush (lsquic_stream_t *stream)

    :param stream: Stream to flush.
    :return: 0 on success and -1 on failure.

    Flush any buffered data.  This triggers packetizing even a single byte
    into a separate frame.  Flushing a closed stream is an error.

Closing Streams
---------------

Streams can be closed for reading, writing, or both.
``on_close()`` callback is called at some point after a stream is closed
for both reading and writing,

.. function:: int lsquic_stream_shutdown (lsquic_stream_t *stream, int how)

    :param stream: Stream to shut down.
    :param how:

        This parameter specifies what do to.  Allowed values are:

        - 0: Stop reading.
        - 1: Stop writing.
        - 2: Stop both reading and writing.

    :return: 0 on success or -1 on failure.

.. function:: int lsquic_stream_close (lsquic_stream_t *stream)

    :param stream: Stream to close.
    :return: 0 on success or -1 on failure.

Sending HTTP Headers
--------------------

.. type:: struct lsxpack_header

This type is defined in _lsxpack_header.h_.  See that header file for
more information.

    .. member:: char             *buf

        the buffer for headers

    .. member:: uint32_t          name_hash

        hash value for name

    .. member:: uint32_t          nameval_hash

        hash value for name + value

    .. member:: lsxpack_strlen_t  name_offset

        the offset for name in the buffer

    .. member:: lsxpack_strlen_t  name_len

        the length of name

    .. member:: lsxpack_strlen_t  val_offset

        the offset for value in the buffer

    .. member:: lsxpack_strlen_t  val_len

        the length of value

    .. member:: uint16_t          chain_next_idx

        mainly for cookie value chain

    .. member:: uint8_t           hpack_index

        HPACK static table index

    .. member:: uint8_t           qpack_index

        QPACK static table index

    .. member:: uint8_t           app_index

        APP header index

    .. member:: enum lsxpack_flag flags:8

        combination of lsxpack_flag

    .. member:: uint8_t           indexed_type

        control to disable index or not

    .. member:: uint8_t           dec_overhead

        num of extra bytes written to decoded buffer

.. type:: lsquic_http_headers_t

    .. member::     int   count

        Number of headers in ``headers``.

    .. member::     struct lsxpack_header   *headers

        Pointer to an array of HTTP headers.

    HTTP header list structure.  Contains a list of HTTP headers.

.. function:: int lsquic_stream_send_headers (lsquic_stream_t *stream, const lsquic_http_headers_t *headers, int eos)

    :param stream:

        Stream to send headers on.

    :param headers:

        Headers to send.

    :param eos:

        Boolean value to indicate whether these headers constitute the whole
        HTTP message.

    :return:

        0 on success or -1 on error.

Receiving HTTP Headers
----------------------

If ``ea_hsi_if`` is not set in :type:`lsquic_engine_api`, the library will translate
HPACK- and QPACK-encoded headers into HTTP/1.x-like headers and prepend them to the
stream.  To the stream-reading function, it will look as if a standard HTTP/1.x
message.

Alternatively, you can specify header-processing set of functions and manage header
fields yourself.  In that case, the header set must be "read" from the stream via
:func:`lsquic_stream_get_hset()`.

.. type:: struct lsquic_hset_if

    .. member::  void * (*hsi_create_header_set)(void *hsi_ctx, lsquic_stream_t *stream, int is_push_promise)

        :param hsi_ctx: User context.  This is the pointer specifed in ``ea_hsi_ctx``.
        :param stream: Stream with which the header set is associated.  May be set
                       to NULL in server mode.
        :param is_push_promise: Boolean value indicating whether this header set is
                                for a push promise.
        :return: Pointer to user-defined header set object.

        Create a new header set.  This object is (and must be) fetched from a
        stream by calling :func:`lsquic_stream_get_hset()` before the stream can
        be read.

    .. member:: struct lsxpack_header * (*hsi_prepare_decode)(void *hdr_set, struct lsxpack_header *hdr, size_t space)

        Return a header set prepared for decoding.  If ``hdr`` is NULL, this
        means return a new structure with at least ``space`` bytes available
        in the decoder buffer.  On success, a newly prepared header is
        returned.

        If ``hdr`` is not NULL, it means there was not enough decoder buffer
        and it must be increased to at least ``space`` bytes.  ``buf``, ``val_len``,
        and ``name_offset`` member of the ``hdr`` structure may change.  On
        success, the return value is the same as ``hdr``.

        If NULL is returned, the space cannot be allocated.

    .. member:: int (*hsi_process_header)(void *hdr_set, struct lsxpack_header *hdr)

        Process new header.

        :param hdr_set:

            Header set to add the new header field to.  This is the object
            returned by ``hsi_create_header_set()``.

        :param hdr:

            The header returned by @ref ``hsi_prepare_decode()``.

        :return:

            Return 0 on success, a positive value if a header error occured,
            or a negative value on any other error.  A positive return value
            will result in cancellation of associated stream. A negative return
            value will result in connection being aborted.

    .. member:: void                (*hsi_discard_header_set)(void *hdr_set)

        :param hdr_set: Header set to discard.

        Discard header set.  This is called for unclaimed header sets and
        header sets that had an error.

    .. member:: enum lsquic_hsi_flag hsi_flags

        These flags specify properties of decoded headers passed to
        ``hsi_process_header()``.  This is only applicable to QPACK headers;
        HPACK library header properties are based on compilation, not
        run-time, options.

.. function:: void * lsquic_stream_get_hset (lsquic_stream_t *stream)

    :param stream: Stream to fetch header set from.

    :return: Header set associated with the stream.

    Get header set associated with the stream.  The header set is created by
    ``hsi_create_header_set()`` callback.  After this call, the ownership of
    the header set is transferred to the caller.

    This call must precede calls to :func:`lsquic_stream_read()`,
    :func:`lsquic_stream_readv()`, and :func:`lsquic_stream_readf()`.

    If the optional header set interface is not specified,
    this function returns NULL.

Push Promises
-------------

.. function:: int lsquic_conn_push_stream (lsquic_conn_t *conn, void *hdr_set, lsquic_stream_t *stream, const lsquic_http_headers_t *headers)

    :return:

        - 0: Stream pushed successfully.
        - 1: Stream push failed because it is disabled or because we hit
             stream limit or connection is going away.
        - -1: Stream push failed because of an internal error.

    A server may push a stream.  This call creates a new stream in reference
    to stream ``stream``.  It will behave as if the client made a request: it will
    trigger ``on_new_stream()`` event and it can be used as a regular client-initiated stream.

    ``hdr_set`` must be set.  It is passed as-is to :func:`lsquic_stream_get_hset()`.

.. function:: int lsquic_conn_is_push_enabled (lsquic_conn_t *conn)

    :return: Boolean value indicating whether push promises are enabled.

    Only makes sense in server mode: the client cannot push a stream and this
    function always returns false in client mode.

.. function:: int lsquic_stream_is_pushed (const lsquic_stream_t *stream)

    :return: Boolean value indicating whether this is a pushed stream.

.. function:: int lsquic_stream_refuse_push (lsquic_stream_t *stream)

    Refuse pushed stream.  Call it from ``on_new_stream()``.  No need to
    call :func:`lsquic_stream_close()` after this.  ``on_close()`` will be called.

.. function:: int lsquic_stream_push_info (const lsquic_stream_t *stream, lsquic_stream_id_t *ref_stream_id, void **hdr_set)

    Get information associated with pushed stream

    :param ref_stream_id: Stream ID in response to which push promise was sent.
    :param hdr_set: Header set. This object was passed to or generated by :func:`lsquic_conn_push_stream()`.

    :return: 0 on success and -1 if this is not a pushed stream.

Stream Priorities
-----------------

.. function:: unsigned lsquic_stream_priority (const lsquic_stream_t *stream)

    Return current priority of the stream.

.. function:: int lsquic_stream_set_priority (lsquic_stream_t *stream, unsigned priority)

    Set stream priority.  Valid priority values are 1 through 256, inclusive.
    Lower value means higher priority.

    :return: 0 on success of -1 on failure (this happens if priority value is invalid).

Miscellaneous Engine Functions
------------------------------

.. function:: unsigned lsquic_engine_quic_versions (const lsquic_engine_t *engine)

    Return the list of QUIC versions (as bitmask) this engine instance supports.

.. function:: unsigned lsquic_engine_count_attq (lsquic_engine_t *engine, int from_now)

    Return number of connections whose advisory tick time is before current
    time plus ``from_now`` microseconds from now.  ``from_now`` can be negative.

Miscellaneous Connection Functions
----------------------------------

.. function:: enum lsquic_version lsquic_conn_quic_version (const lsquic_conn_t *conn)

    Get QUIC version used by the connection.

    If version has not yet been negotiated (can happen in client mode), ``-1`` is
    returned.

.. function:: const lsquic_cid_t * lsquic_conn_id (const lsquic_conn_t *conn)

    Get connection ID.

.. function:: lsquic_engine_t * lsquic_conn_get_engine (lsquic_conn_t *conn)

    Get pointer to the engine.

.. function:: int lsquic_conn_get_sockaddr (lsquic_conn_t *conn, const struct sockaddr **local, const struct sockaddr **peer)

    Get current (last used) addresses associated with the current path
    used by the connection.

.. function:: struct stack_st_X509 * lsquic_conn_get_server_cert_chain (lsquic_conn_t *conn)

    Get certificate chain returned by the server.  This can be used for
    server certificate verification.

    The caller releases the stack using sk_X509_free().

.. function:: lsquic_conn_ctx_t * lsquic_conn_get_ctx (const lsquic_conn_t *conn)

    Get user-supplied context associated with the connection.

.. function:: void lsquic_conn_set_ctx (lsquic_conn_t *conn, lsquic_conn_ctx_t *ctx)

    Set user-supplied context associated with the connection.

.. function:: void * lsquic_conn_get_peer_ctx (lsquic_conn_t *conn, const struct sockaddr *local_sa)

    Get peer context associated with the connection and local address.

.. function:: const char * lsquic_conn_get_sni (lsquic_conn_t *conn)

    Get SNI sent by the client.

.. function:: enum LSQUIC_CONN_STATUS lsquic_conn_status (lsquic_conn_t *conn, char *errbuf, size_t bufsz)

    Get connection status.

Miscellaneous Stream Functions
------------------------------

.. function:: unsigned lsquic_conn_n_avail_streams (const lsquic_conn_t *conn)

    Return max allowed outbound streams less current outbound streams.

.. function:: unsigned lsquic_conn_n_pending_streams (const lsquic_conn_t *conn)

    Return number of delayed streams currently pending.

.. function:: unsigned lsquic_conn_cancel_pending_streams (lsquic_conn_t *, unsigned n)

    Cancel ``n`` pending streams.  Returns new number of pending streams.

.. function:: lsquic_conn_t * lsquic_stream_conn (const lsquic_stream_t *stream)

    Get a pointer to the connection object.  Use it with connection functions.

.. function:: int lsquic_stream_is_rejected (const lsquic_stream_t *stream)

    Returns true if this stream was rejected, false otherwise.  Use this as
    an aid to distinguish between errors.

.. function:: int lsquic_stream_has_unacked_data (const lsquic_stream_t *stream)

    Return true if peer has not ACKed all data written to the stream.  This
    includes both packetized and buffered data.

Other Functions
---------------

.. function:: lsquic_conn_t lsquic_ssl_to_conn (const SSL *)

    Get connection associated with this SSL object.

.. function:: enum lsquic_version lsquic_str2ver (const char *str, size_t len)

    Translate string QUIC version to LSQUIC QUIC version representation.

.. function:: enum lsquic_version lsquic_alpn2ver (const char *alpn, size_t len)

    Translate ALPN (e.g. "h3", "h3-23", "h3-Q046") to LSQUIC enum.

Miscellaneous Types
-------------------

.. type:: struct lsquic_shared_hash_if

    The shared hash interface is used to share data between multiple LSQUIC instances.

    .. member:: int (*shi_insert)(void *shi_ctx, void *key, unsigned key_sz, void *data, unsigned data_sz, time_t expiry)

        :param shi_ctx:

            Shared memory context pointer

        :param key:

            Key data.

        :param key_sz:

            Key size.

        :param data:

            Pointer to the data to store.

        :param data_sz:

            Data size.

        :param expiry: When this item expires.  If you want your item to never expire, set this to zero.

        :return: 0 on success, -1 on failure.

        If inserted successfully, ``free()`` will be called on ``data`` and ``key``
        pointer when the element is deleted, whether due to expiration
        or explicit deletion.

    .. member:: int (*shi_delete)(void *shi_ctx, const void *key, unsigned key_sz)

        Delete item from shared hash

        :return: 0 on success, -1 on failure.

    .. member:: int (*shi_lookup)(void *shi_ctx, const void *key, unsigned key_sz, void **data, unsigned *data_sz)

        :param shi_ctx:

            Shared memory context pointer

        :param key:

            Key data.

        :param key_sz:

            Key size.

        :param data:

            Pointer to set to the result.

        :param data_sz:

            Pointer to the data size.

        :return:

            - ``1``: found.
            - ``0``: not found.
            - ``-1``:  error (perhaps not enough room in ``data`` if copy was attempted).

         The implementation may choose to copy the object into buffer pointed
         to by ``data``, so you should have it ready.

.. type:: struct lsquic_packout_mem_if

    The packet out memory interface is used by LSQUIC to get buffers to
    which outgoing packets will be written before they are passed to
    :member:`lsquic_engine_api.ea_packets_out` callback.

    If not specified, malloc() and free() are used.

    .. member:: void *  (*pmi_allocate) (void *pmi_ctx, void *peer_ctx, lsquic_conn_get_ctx *conn_ctx, unsigned short sz, char is_ipv6)

        Allocate buffer for sending.

    .. member:: void    (*pmi_release)  (void *pmi_ctx, void *peer_ctx, void *buf, char is_ipv6)

        This function is used to release the allocated buffer after it is
        sent via ``ea_packets_out()``.

    .. member:: void    (*pmi_return)  (void *pmi_ctx, void *peer_ctx, void *buf, char is_ipv6)

        If allocated buffer is not going to be sent, return it to the
        caller using this function.

.. type:: typedef void (*lsquic_cids_update_f)(void *ctx, void **peer_ctx, const lsquic_cid_t *cids, unsigned n_cids)

    :param ctx:

        Context associated with the CID lifecycle callbacks (ea_cids_update_ctx).

    :param peer_ctx:

        Array of peer context pointers.

    :param cids:

        Array of connection IDs.

    :param n_cids:

        Number of elements in the peer context pointer and connection ID arrays.

.. type:: enum lsquic_logger_timestamp_style

    Enumerate timestamp styles supported by LSQUIC logger mechanism.

    .. member:: LLTS_NONE

        No timestamp is generated.

    .. member:: LLTS_HHMMSSMS

        The timestamp consists of 24 hours, minutes, seconds, and milliseconds.  Example: 13:43:46.671

    .. member:: LLTS_YYYYMMDD_HHMMSSMS

        Like above, plus date, e.g: 2017-03-21 13:43:46.671

    .. member:: LLTS_CHROMELIKE

        This is Chrome-like timestamp used by proto-quic.  The timestamp
        includes month, date, hours, minutes, seconds, and microseconds.

        Example: 1223/104613.946956 (instead of 12/23 10:46:13.946956).

        This is to facilitate reading two logs side-by-side.

    .. member:: LLTS_HHMMSSUS

        The timestamp consists of 24 hours, minutes, seconds, and microseconds.  Example: 13:43:46.671123

    .. member:: LLTS_YYYYMMDD_HHMMSSUS

        Date and time using microsecond resolution, e.g: 2017-03-21 13:43:46.671123

.. type:: enum LSQUIC_CONN_STATUS

    .. member:: LSCONN_ST_HSK_IN_PROGRESS
    .. member:: LSCONN_ST_CONNECTED
    .. member:: LSCONN_ST_HSK_FAILURE
    .. member:: LSCONN_ST_GOING_AWAY
    .. member:: LSCONN_ST_TIMED_OUT
    .. member:: LSCONN_ST_RESET

        If es_honor_prst is not set, the connection will never get public
        reset packets and this flag will not be set.

    .. member:: LSCONN_ST_USER_ABORTED
    .. member:: LSCONN_ST_ERROR
    .. member:: LSCONN_ST_CLOSED
    .. member:: LSCONN_ST_PEER_GOING_AWAY

.. type:: enum lsquic_hsi_flag

    These flags are ORed together to specify properties of
    :type:`lsxpack_header` passed to :member:`lsquic_hset_if.hsi_process_header`.

    .. member:: LSQUIC_HSI_HTTP1X

        Turn HTTP/1.x mode on or off.  In this mode, decoded name and value
        pair are separated by ``": "`` and ``"\r\n"`` is appended to the end
        of the string.  By default, this mode is off.

    .. member:: LSQUIC_HSI_HASH_NAME

        Include name hash into lsxpack_header.

    .. member:: LSQUIC_HSI_HASH_NAMEVAL

        Include nameval hash into lsxpack_header.

Global Variables
----------------

.. var:: const char *const lsquic_ver2str[N_LSQVER]

    Convert LSQUIC version to human-readable string

List of Log Modules
-------------------

The following log modules are defined:

- *alarmset*: Alarm processing.
- *bbr*: BBRv1 congestion controller.
- *bw-sampler*: Bandwidth sampler (used by BBR).
- *cfcw*: Connection flow control window.
- *conn*: Connection.
- *crypto*: Low-level Google QUIC cryptography tracing.
- *cubic*: Cubic congestion controller.
- *di*: "Data In" handler (storing incoming data before it is read).
- *eng-hist*: Engine history.
- *engine*: Engine.
- *event*: Cross-module significant events.
- *frame-reader*: Reader of the HEADERS stream in Google QUIC.
- *frame-writer*: Writer of the HEADERS stream in Google QUIC.
- *handshake*: Handshake and packet encryption and decryption.
- *hcsi-reader*: Reader of the HTTP/3 control stream.
- *hcso-writer*: Writer of the HTTP/3 control stream.
- *headers*: HEADERS stream (Google QUIC).
- *hsk-adapter*:
- *http1x*: Header conversion to HTTP/1.x.
- *logger*: Logger.
- *mini-conn*: Mini connection.
- *pacer*: Pacer.
- *parse*: Parsing.
- *prq*: PRQ stands for Packet Request Queue.  This logs scheduling
  and sending packets not associated with a connection: version
  negotiation and stateless resets.
- *purga*: CID purgatory.
- *qdec-hdl*: QPACK decoder stream handler.
- *qenc-hdl*: QPACK encoder stream handler.
- *qlog*: QLOG output.  At the moment, it is out of date.
- *qpack-dec*: QPACK decoder.
- *qpack-enc*: QPACK encoder.
- *sendctl*: Send controller.
- *sfcw*: Stream flow control window.
- *spi*: Stream priority iterator.
- *stream*: Stream operation.
- *tokgen*: Token generation and validation.
- *trapa*: Transport parameter processing.

.. _extensible-http-priorities:

Extensible HTTP Priorities
--------------------------

lsquic supports the
`Extensible HTTP Priorities Extension <https://tools.ietf.org/html/draft-ietf-httpbis-priority>`_.
It is enabled by default when HTTP/3 is used.  The "urgency" and "incremental"
parameters are included into a dedicated type:

.. type:: struct lsquic_ext_http_prio

    .. member::     unsigned char       urgency

        This value's range is [0, 7], where 0 is the highest and 7 is
        the lowest urgency.

    .. member::     signed char         incremental

        This is a boolean value.  The valid range is [0, 1].

Some useful macros are also available:

.. macro:: LSQUIC_MAX_HTTP_URGENCY

The maximum value of the "urgency" parameter is 7.

.. macro:: LSQUIC_DEF_HTTP_URGENCY

The default value of the "urgency" parameter is 3.

.. macro:: LSQUIC_DEF_HTTP_INCREMENTAL

The default value of the "incremental" parameter is 0.

There are two functions to
manage a stream's priority:

.. function:: int lsquic_stream_get_http_prio (lsquic_stream_t \*stream, struct lsquic_ext_http_prio \*ehp)

    Get a stream's priority information.

    :param stream:  The stream whose priority informaion we want.

    :param ehp:     Structure that is to be populated with the stream's
                    priority information.

    :return:    Returns zero on success of a negative value on failure.
                A failure occurs if this is not an HTTP/3 stream or if
                Extensible HTTP Priorities have not been enabled.
                See :member:`lsquic_engine_settings.es_ext_http_prio`.

.. function:: int lsquic_stream_set_http_prio (lsquic_stream_t \*stream, const struct lsquic_ext_http_prio \*ehp)

    Set a stream's priority information.

    :param stream:  The stream whose priority we want to set.

    :param ehp:     Structure containing the stream's new priority information.

    :return:        Returns zero on success of a negative value on failure.
                    A failure occurs if some internal error occured or if this
                    is not an HTTP/3 stream or if Extensible HTTP Priorities
                    haven't been enabled.
                    See :member:`lsquic_engine_settings.es_ext_http_prio`.

.. _apiref-datagrams:

Datagrams
---------

lsquic supports the
`Unreliable Datagram Extension <https://tools.ietf.org/html/draft-pauly-quic-datagram-05>`_.
To enable datagrams, set :member:`lsquic_engine_settings.es_datagrams` to
true and specify
:member:`lsquic_stream_if.on_datagram`
and
:member:`lsquic_stream_if.on_dg_write` callbacks.

.. function:: int lsquic_conn_want_datagram_write (lsquic_conn_t *conn, int want)

    Indicate desire (or lack thereof) to write a datagram.

    :param conn: Connection on which to send a datagram.
    :param want: Boolean value indicating whether the caller wants to write
                 a datagram.
    :return: Previous value of ``want`` or ``-1`` if the datagrams cannot be
             written.

.. function:: size_t lsquic_conn_get_min_datagram_size (lsquic_conn_t *conn)

    Get minimum datagram size.  By default, this value is zero.

.. function:: int lsquic_conn_set_min_datagram_size (lsquic_conn_t *conn, size_t sz)

    Set minimum datagram size.  This is the minumum value of the buffer
    passed to the :member:`lsquic_stream_if.on_dg_write` callback.
    Returns 0 on success and -1 on error.
