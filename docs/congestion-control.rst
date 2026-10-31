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
using ``LSQUIC_CC_BBR``.  It is the default controller.

BBR-Copilot
-----------

BBR-Copilot is a variant of BBRv1 intended for applications such as live
streaming that produce on-off traffic.  When BBR is probing for additional
bandwidth but the application has no data to send, BBR-Copilot sends padded,
ack-eliciting packets to complete the probe and obtain a useful bandwidth
sample.

BBR-Copilot stops generating fill probes after one second without sending
application data.  Padding and keepalives do not extend this interval.

Fill probes add traffic beyond the application payload, so applications
should account for the additional network traffic.

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
controller can be read using :func:`lsquic_conn_get_param()` with
``LSQCP_CC_ALGO``.

Switching between Cubic and either BBR variant initializes fresh controller
state.  After switching from Cubic to BBR-Copilot, fill probing waits until
new application data is sent.

Trying the CBR Examples
=======================

``cbr_server`` sends a file in periodic application bursts; ``cbr_client``
receives it and can save the result.  Both use the ``cbr`` ALPN and a single
QUIC stream.  These examples report connection statistics and aggregate
transfer progress; they do not measure per-frame latency.

Build and Loopback Transfer
---------------------------

The following commands use a Unix shell, a C/C++ toolchain, CMake, Perl,
zlib, libevent, and a built QUIC-capable BoringSSL or OpenSSL library.
Initialize the HPACK/QPACK submodules as described in :doc:`gettingstarted`.
The ``openssl`` command-line tool is also needed for the temporary test
certificate.  From the repository root, build the examples in a fresh
directory, replacing the TLS library path below:

.. code-block:: sh

    cbr_build=$(mktemp -d)
    cmake -S . -B "$cbr_build" -DCMAKE_BUILD_TYPE=Debug \
        -DLIBSSL_DIR=/path/to/boringssl -DLSQUIC_BIN=ON
    cmake --build "$cbr_build" --target cbr_server cbr_client -j

Create a self-signed certificate and 1,250,000 bytes of input, corresponding
to two seconds of application data at 5 Mbps.  The example client accepts
this test certificate:

.. code-block:: sh

    cbr_tmp=$(mktemp -d)
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj /CN=localhost -keyout "$cbr_tmp/key.pem" \
        -out "$cbr_tmp/cert.pem" >"$cbr_tmp/cert.log" 2>&1
    dd if=/dev/urandom of="$cbr_tmp/input.bin" bs=62500 count=20

Run a separate server and fresh client connection for BBRv1 (``-A 2``) and
BBR-Copilot (``-A 4``).  The sender's controller is the variable of interest;
the client stays on BBRv1.  The server's ``-b`` is in bits per second and
``-I`` is in milliseconds: these settings produce 62,500-byte application
frames every 100 ms.  Choose an unused UDP port if 4433 is occupied.

.. code-block:: sh

    for algo in 2 4; do
        "$cbr_build/bin/cbr_server" -s 127.0.0.1:4433 \
            -c "localhost,$cbr_tmp/cert.pem,$cbr_tmp/key.pem" \
            -f "$cbr_tmp/input.bin" -b 5000000 -I 100 -t 1 \
            -A "$algo" -L notice -y 5 \
            >"$cbr_tmp/server-$algo.log" 2>&1 &
        cbr_pid=$!
        sleep 1
        kill -0 "$cbr_pid" || break
        "$cbr_build/bin/cbr_client" -s 127.0.0.1:4433 -H localhost \
            -O "$cbr_tmp/output-$algo.bin" -n 1 -A 2 -L notice -y 5 \
            >"$cbr_tmp/client-$algo.log" 2>&1
        cbr_status=$?
        kill "$cbr_pid"
        wait "$cbr_pid" || :
        test "$cbr_status" -eq 0 || break
        cmp "$cbr_tmp/input.bin" "$cbr_tmp/output-$algo.bin" || break
    done

``cmp`` produces no output when the files match.  Check both output files
and the logs: the client should report a stream FIN and 1,250,000 bytes
read.  The server logs application bytes accepted for sending, bandwidth
and pacing estimates, congestion window, RTT, and loss/retransmission
counters.  The client logs received application bytes and connection
counters.  For example:

.. code-block:: sh

    wc -c "$cbr_tmp"/output-*.bin
    cat "$cbr_tmp"/server-*.log "$cbr_tmp"/client-*.log

Controller Comparison Recipe
----------------------------

For a longer comparison, use the same build and commands on an already
controlled path with a 10 Mbps bottleneck, 50 ms RTT, and no injected loss.
Keep the path, queue settings, endpoints, client controller, and logging
options identical.  Replace the loopback addresses with the endpoint
addresses; retain matching certificate and SNI names.  This guide does not
configure path shaping.

Use 5 Mbps application data, 100 ms frames, and a 60-second payload:

.. code-block:: sh

    dd if=/dev/urandom of="$cbr_tmp/input.bin" bs=62500 count=600

This creates 37,500,000 bytes.  Keep ``-b 5000000 -I 100`` and omit ``-r``,
which would override the frame size.  Run five fresh connections per server
controller, alternating ``2, 4, 2, 4, 2, 4, 2, 4, 2, 4``.  Restart the
server for each run, use unique log and output filenames, omit session
resumption (``-0``), and compare every received file with the same input.
The unshaped loopback transfer above checks functionality; it supplies no
performance comparison.

Interpret the observations separately:

* Goodput counts unique application bytes received per elapsed second.
  The client's ``recv`` rate is a cumulative approximation using
  whole-second timestamps; the server's accepted-byte rate is not a
  receiver goodput measurement.
* Transfer completion time ends when the client receives the stream FIN.
  The ``-y 5`` log timestamps help locate completion.  If timing the whole
  client process externally, report that interval as including connection
  setup and teardown.  The 60-second payload is a production schedule, not
  a guarantee of completion in exactly 60 seconds.
* Bandwidth estimates are model/sampler observations, not measured
  application goodput or proof of the path's capacity.  Inspect the
  sender's periodic ``bw`` and final ``bw_est`` alongside pacing, RTT, and
  congestion window.
* Traffic overhead includes QUIC control frames, retransmissions, padding,
  and transport/network headers at the layer being counted.  State the
  direction and layer when comparing captured traffic with application
  bytes.  Do not label that difference as padding alone.

For padding inspection, add ``-G "$cbr_tmp/keys"`` to the server in both
cases and capture the connection, including its handshake, using the same
capture setup.  This writes per-connection ``.keys`` files.  Load the
appropriate file as the TLS secrets log in Wireshark to decrypt IETF QUIC
and inspect PADDING frames and padded PING packets.  Other packets,
including handshake packets, also contain padding; a padding count alone
does not identify Copilot probes.  See :doc:`tutorial` for key logging
details.  These examples provide neither per-frame send/receive timestamps
nor a per-frame latency measurement, and no performance results are
reported here.

After finishing the examples and saving any logs you need, remove the
temporary certificate, input, outputs, and build directory:

.. code-block:: sh

    rm -rf -- "$cbr_tmp" "$cbr_build"

Reference
=========

Xu Yan, Tong Li, Bo Wu, Cheng Luo, Jiuxiang Zhu, and Laizhong Cui,
"When BBR Meets Live Streaming," *Frontiers of Networking Technologies
(CCF ChinaNet)*, pp. 11-27, 2026.
