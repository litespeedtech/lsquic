# LSQUIC WebTransport Security Audit Plan

## 1. Threat model and assumptions

This is a plan, not a findings report.

- Highest expected CVE yield is in post-handshake WebTransport code, not in generic QUIC parsing. The WT implementation in `src/liblsquic/lsquic_wt.c` mixes stream wrappers, session objects, callback handoff, queued datagrams, and deferred acceptance in one ownership domain.
- Likely remote unauthenticated bugs are limited to the QUIC/HTTP3 ingress that gates WT: packet/frame parsing and stream classification in `src/liblsquic/lsquic_full_conn_ietf.c`, `src/liblsquic/lsquic_stream.c`, and related packet code.
- Likely remote authenticated/post-handshake bugs are the main target: CONNECT handling, WT session creation, WT_CLOSE capsule handling, uni/bidi stream binding, HTTP Datagram delivery, and teardown/finalization.
- Local/config/example issues matter if operators expose the sample server: `bin/http_server.c` and `bin/devious_baton.c` parse attacker-controlled WT requests and payloads.

## 2. Attack surface map

1. Unauthenticated UDP ingress: QUIC packet/frame parsing and connection promotion. Path: `lsquic_packet_in.c` -> mini/full connection parsers -> `src/liblsquic/lsquic_full_conn_ietf.c`. Review only enough to understand how DATAGRAM/STREAM input reaches WT.
2. Post-handshake capability negotiation: peer SETTINGS and transport capability synthesis. Path: `on_setting`/`on_settings_frame` -> `update_peer_wt_support` in `src/liblsquic/lsquic_full_conn_ietf.c`.
3. WT CONNECT control stream: app accepts CONNECT, then `lsquic_wt_accept` installs capsule/datagram handlers and wraps the original stream callbacks in `src/liblsquic/lsquic_wt.c`.
4. Peer-created WT streams:
- Uni: `apply_uni_stream_class` -> `lsquic_wt_uni_stream_if` -> `wt_uni_on_read`.
- Client bidi: `hq_filter_readable` -> `cp_on_hq_switch_stream` -> `wt_on_client_bidi_stream`.
5. QUIC DATAGRAM to WT datagram path: `process_datagram_frame` -> `process_http_dg_frame` -> `lsquic_wt_on_http_dg_read`.
6. Teardown path: CLOSE capsule, control stream EOF/reset, stream destroy hooks, buffered replay, and session finalization in `wt_control_on_*`, `wt_on_stream_destroy`, `wt_session_maybe_finalize`.

## 3. Prioritized hotspots

### 1. WT session lifecycle and control-stream wrapper

- Files/functions: `src/liblsquic/lsquic_wt.c` `lsquic_wt_accept`, `wt_wrap_control_stream`, `wt_control_on_read`, `wt_control_on_write`, `wt_control_on_close`, `wt_control_on_reset`, `wt_on_close_capsule`, `wt_on_stream_destroy`, `wt_session_maybe_finalize`, `wt_destroy_session`
- Why it matters: this is the ownership nexus for session object lifetime, callback redirection, close capsule state, and final teardown.
- Likely bug classes: UAF, double free, stale callback context, double-close/finalize, null deref, assertion reachable from peer-driven teardown ordering.
- Exposure: remote authenticated/post-handshake.

### 2. Pending WT streams and datagram replay

- Files/functions: `src/liblsquic/lsquic_wt.c` `wt_evaluate_accept`, `wt_buffer_or_reject_stream`, `wt_replay_pending_streams`, `wt_replay_pending_datagrams`, `wt_count_pending_streams`, `wt_close_data_streams`, `wt_in_dgq_enqueue`, `wt_dgq_enqueue`
- Why it matters: attacker-controlled ordering can create streams/datagrams before session open, then drive replay or reject/close races.
- Likely bug classes: memory/resource exhaustion, count/size underflow, queue leaks, stale `wt_uni_read_ctx` use, wrong-session binding.
- Exposure: remote authenticated/post-handshake.

### 3. WT capability negotiation and stream classification

- Files/functions: `src/liblsquic/lsquic_full_conn_ietf.c` `update_peer_wt_support`, `on_setting`, `apply_uni_stream_class`, `unicla_on_read`; `src/liblsquic/lsquic_stream.c` `hq_filter_readable`; `src/liblsquic/lsquic_wt.c` `wt_on_client_bidi_stream`
- Why it matters: this decides when arbitrary peer input is reinterpreted as WT traffic and bound to a session.
- Likely bug classes: state machine bypass, protocol desync, invalid stream/session association, assert/crash on duplicate or reordered transitions.
- Exposure: remote authenticated; limited unauthenticated relevance via malformed stream/frame delivery.

### 4. QUIC DATAGRAM and HTTP Datagram demux into WT

- Files/functions: `src/liblsquic/lsquic_full_conn_ietf.c` `process_http_dg_frame`, `process_datagram_frame`; `src/liblsquic/lsquic_wt.c` `lsquic_wt_on_http_dg_read`, `lsquic_wt_on_http_dg_write`, `wt_dgq_send_one`
- Why it matters: datagrams are attacker-sized, unordered, and mapped by qsid to stream/session state.
- Likely bug classes: parser confusion, integer truncation in qsid mapping, wrong-stream delivery, queue exhaustion, oversized datagram handling bugs.
- Exposure: remote authenticated/post-handshake.

### 5. Example/server-side WT request parsing

- Files/functions: `bin/http_server.c` `handle_connect_request`, `baton_connect_handler`; `bin/devious_baton.c` `parse_request`, `parse_path`, `parse_query`, `buf_append`, `consume_baton_data`
- Why it matters: many deployments copy example code; this code allocates and parses attacker-controlled path/query/datagram/stream data.
- Likely bug classes: heap overflow via growth math, memory leaks, request parsing confusion, excessive allocation/DoS.
- Exposure: local/configuration/example, but remotely reachable if the sample server is deployed.

## 4. Audit techniques by hotspot

### 1. Lifecycle/control wrapper

- Evidence that confirms a real vuln: ASan/UAF on control-stream close/reset after app callbacks; double free on repeated close paths; crash or callback after `wts_if`/session destroy.
- Dynamic checks: targeted harness that drives `accept -> open -> close capsule -> control FIN/reset -> stream destroy` in all permutations; inject allocation failures in `wt_copy_*`, `wt_queue_close_capsule`, `wt_wrap_control_stream`.

### 2. Pending replay and buffering

- Evidence: queued counts/bytes exceed configured limits, leaked pending streams/datagrams across reject/close, replay binds stream to wrong session, free-after-replay of `wt_uni_read_ctx`.
- Dynamic checks: harness for datagrams/uni/bidi streams arriving before accept/open; corpus cases that hit `WT_MAX_PENDING_STREAMS`, queue byte ceilings, drop-oldest/newest behavior, and close during replay.

### 3. Negotiation and classification

- Evidence: `CP_WEBTRANSPORT` becomes set without full prerequisites; malformed uni stream type or bidi switch frame crashes or binds incorrectly; duplicate SETTINGS/control streams turn into asserts instead of clean aborts.
- Dynamic checks: packet-driven tests for reordered SETTINGS, draft-14 vs draft-15, CONNECT protocol missing/present, partial varints on uni classifier, duplicate close/session advertisements.

### 4. Datagram demux

- Evidence: invalid qsid reaches wrong stream, datagram before stream existence causes unexpected object creation, oversized datagram causes overflow or stale queue state.
- Dynamic checks: fuzz `process_datagram_frame` with valid/invalid DATAGRAM frames and quarter-stream IDs; replay seeds for nonexistent stream IDs, max-size qsid, zero-length payloads, repeated bursts.

### 5. Example code

- Evidence: realloc growth overflow, unbounded memory growth, malformed path/query/datagram causing crash or persistent leak in `http_server`/`devious_baton`.
- Dynamic checks: run sample server under ASan/UBSan/LSan with malformed CONNECT headers, large query strings, fragmented baton messages, and datagram floods.

Concrete invariants/assertions to check during review:

- `CP_WEBTRANSPORT` implies `CP_H3_PEER_SETTINGS` and `CP_HTTP_DATAGRAMS`, and client mode also implies `CP_CONNECT_PROTOCOL`.
- Each live WT session is unique by `wts_stream_id`.
- `wts_n_streams` reaches zero exactly once before `wt_destroy_session`.
- No callback runs after `wts_if` is nulled in `wt_fire_session_close_cb`.
- Pending stream count never exceeds 64 and queue bytes/count never exceed configured maxima.
- A control stream sees at most one WT_CLOSE capsule and no data after it.
- A stream is never rebound from one session to another.

## 5. Fuzzing and sanitizer plan

- Sanitizers: keep existing Debug+clang ASan path from `CMakeLists.txt`, but add explicit ASan+UBSan+LSan CI jobs for WT tests. Use MSan only for isolated unit/fuzzer harnesses that do not depend on full BoringSSL paths. TSan is lower priority.
- Existing coverage gaps:
- `tests/test_wt.c` covers helper/state routines but is not packet-driven and does not exercise real ingress/classification/replay end to end.
- `tests/test_h3_framing.c` has AFL-style fuzz-driver support, but it is generic HTTP/3 framing, not WT-specific.
- Existing fuzzing under `src/liblsquic/ls-qpack/fuzz/` is QPACK-only.
- There is no dedicated WT corpus or harness for CLOSE capsules, uni-stream session IDs, HQ switch frames, or DATAGRAM demux.
- New fuzz targets:
- WT control stream harness around `lsquic_wt_accept` plus capsule parsing and close/reset interleavings.
- Uni-stream classifier harness for `HQUST_WEBTRANSPORT` plus partial/fragmented session-id varints.
- DATAGRAM harness for `process_datagram_frame` / `process_http_dg_frame` / `lsquic_wt_on_http_dg_read`.
- Negotiation harness for SETTINGS permutations feeding `on_setting` and `update_peer_wt_support`.
- Corpus seeds:
- Valid draft-14 and draft-15 handshakes with and without CONNECT protocol.
- Valid WT_CLOSE capsule, duplicate CLOSE, truncated CLOSE, oversized reason, unknown capsules.
- Valid/invalid quarter stream IDs, nonexistent stream IDs, max varint IDs.
- Streams/datagrams arriving before session open, during accept-pending, and after session close.
- Pending-stream floods that hit 63, 64, and 65 queued streams.
- AFL++ is available in this environment, so `afl-fuzz` and companion `afl-*` tools should be used for the WT-specific harnesses once they exist.

## 6. Concrete step-by-step audit schedule

1. Read `lsquic_wt.c` top-to-bottom once, but annotate only lifetime edges first: accept, wrap, close, destroy, replay, destroy-on-stream callbacks.
2. Review `lsquic_full_conn_ietf.c` only at WT-relevant ingress points: SETTINGS, WT support synthesis, uni-stream classification, DATAGRAM demux.
3. Review `lsquic_stream.c:hq_filter_readable` to confirm how switch-to-WT bidi streams can be triggered and whether partial-frame/error states can mis-sequence the handoff.
4. Build a small packet/state matrix and execute it under ASan+UBSan: `SETTINGS reorder`, `CONNECT pending`, `uni before accept`, `bidi before open`, `datagram before open`, `close/reset during replay`.
5. Fuzz the three WT-specific targets above before spending time on generic QUIC/QPACK code. WT should dominate the budget.
6. Only after WT-specific review stabilizes, spot-check related generic code for prerequisite bypasses: stream creation limits, DATAGRAM frame parsing, and hash/stream lookup ownership.
7. Audit `bin/http_server.c` and `bin/devious_baton.c` last, and only treat findings there as lower-priority unless the deployment clearly exposes those programs.
8. Any confirmed issue should immediately get a minimized regression in `tests/test_wt.c` or a new dedicated WT harness, not just a prose note.

Expected order by CVE yield: `lsquic_wt.c` lifecycle -> pending replay/queues -> SETTINGS/capability/classification -> DATAGRAM demux -> example server code.
