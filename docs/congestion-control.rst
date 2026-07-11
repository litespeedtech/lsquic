******************
Congestion Control
******************

LSQUIC supports several congestion controllers.  An application can select
one controller for every connection created by an engine or override the
selection for an individual connection.

Available Controllers
=====================

Cubic
-----

Cubic is a loss-based congestion controller.  Select it using
``LSQUIC_CC_CUBIC``.

BBRv1
-----

BBRv1 models bottleneck bandwidth and round-trip propagation time.  Select it
using ``LSQUIC_CC_BBR``.

Adaptive
--------

Adaptive initializes both Cubic and BBRv1, measures the connection RTT, and
then selects one of them.  The threshold is configured using
:member:`lsquic_engine_settings.es_cc_rtt_thresh`.  Select Adaptive using
``LSQUIC_CC_ADAPTIVE``.  It is the default controller.

BBR-Copilot
-----------

BBR-Copilot is a variant of BBRv1 intended for applications such as live
streaming that produce on-off traffic.  When BBR is probing for additional
bandwidth but the application has no data to send, BBR-Copilot sends padded,
ack-eliciting packets to complete the probe and obtain a useful bandwidth
sample.

This behavior can improve BBR's bandwidth estimate when application-limited
periods would otherwise interrupt active probing.  It also deliberately sends
data that the application did not request, so applications should account for
the additional network traffic.  Adaptive never selects BBR-Copilot.

Select BBR-Copilot using ``LSQUIC_CC_BBR_COPILOT``.

Selecting a Controller
======================

Engine-Wide Selection
---------------------

Set :member:`lsquic_engine_settings.es_cc_algo` before creating the engine:

.. code-block:: c

    struct lsquic_engine_settings settings;

    lsquic_engine_init_settings(&settings, 0);
    settings.es_cc_algo = LSQUIC_CC_BBR_COPILOT;

    engine_api.ea_settings = &settings;

The example programs expose this setting through ``-A``.  BBR-Copilot is
controller number 4:

.. code-block:: console

    cbr_server -A 4

Per-Connection Selection
------------------------

Use :func:`lsquic_conn_set_param()` to override the controller for one
connection, typically from the ``on_new_conn`` callback:

.. code-block:: c

    enum lsquic_cc cc = LSQUIC_CC_BBR_COPILOT;

    if (0 != lsquic_conn_set_param(conn, LSQCP_CC_ALGO,
                                   &cc, sizeof(cc)))
    {
        /* Handle invalid or unsupported parameter. */
    }

Passing ``LSQUIC_CC_DEFAULT`` selects the library default.  The current
controller can be read using :func:`lsquic_conn_get_param()`.

Reference
=========

Xu Yan, Tong Li, Bo Wu, Cheng Luo, Jiuxiang Zhu, and Laizhong Cui,
"When BBR Meets Live Streaming," *Frontiers of Networking Technologies
(CCF ChinaNet)*, pp. 11-27, 2026.
