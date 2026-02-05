# WebTransport (WT) Devious Baton Integration Plan

## Goal
Implement WebTransport support in **lsquic** and validate the API and state machine by integrating the *Devious Baton* test application into the existing lsquic HTTP client and server example programs.

This approach deliberately avoids early integration with OpenLiteSpeed (OLS) or PHP bindings, reducing complexity and enabling faster iteration and interop testing.

---

## High-Level Design Principles

1. **WebTransport is layered on top of HTTP/3**
   - WT sessions are initiated via `CONNECT` requests with `:protocol = "webtransport"`.
   - The CONNECT request stream acts as the WT *control stream*.

2. **No special WT request callback**
   - lsquic does not introduce a dedicated `on_wt_connect_request` handler.
   - WT requests flow through the normal HTTP request path (hset or HTTP/1.x-compatible APIs).

3. **Application-driven accept / reject**
   - The application inspects the request headers as usual.
   - When the application sends a response:
     - **2xx** → lsquic *promotes* the stream to a WT session.
     - **non-2xx** → request is rejected; no WT session is created.

4. **lsquic stays out of request routing logic**
   - lsquic only detects WT *candidates* and manages protocol transitions.
   - All policy decisions live in application code.

---

## Internal lsquic Behavior

### WT Candidate Detection
When request headers are complete on an HTTP/3 stream, lsquic internally checks:
- Method == `CONNECT`
- `:protocol == "webtransport"`

If matched, the stream is marked as a **WT candidate**.

### Promotion Trigger
When the application sends final response headers:
- If status is **2xx** and the stream is a WT candidate:
  - The stream is promoted to a WT control stream.
  - A `wt_session` object is created and bound to the stream.
- If status is **non-2xx**:
  - WT candidate state is cleared; the stream completes as a normal HTTP request.

### Required API Primitives
Minimal helper APIs needed:
- `lsquic_stream_is_wt_candidate(stream)`
- `lsquic_stream_get_wt_sess(stream)` (valid only after 2xx promotion)

WT session APIs:
- Open WT bidi / uni streams
- Send WT datagrams
- WT callbacks: incoming streams, datagrams, session close

---

## TODO (Short-Term)

- Implement WT datagrams using existing HTTP Datagram support; wire
  `lsquic_wt_send_datagram()` and `lsquic_wt_max_datagram_size()`.
- Dispatch incoming WT datagrams to the application callback
  (`on_dg_datagram` / WT datagram handler).
- Update Devious Baton to exercise WT datagrams (send/receive) via the WT
  datagram callback.

---

## Devious Baton Integration (Server Example)

### Hook Point
In the existing HTTP server example:
- At request-headers-complete time:
  - If `lsquic_stream_is_wt_candidate(stream)` is true:
    - Hand off the stream to the *baton server module*.
    - Bypass normal HTTP request handling.

### Baton Server Module Responsibilities
1. Inspect request headers and apply policy.
2. Send response:
   - Accept: send `2xx`.
   - Reject: send `4xx` / `5xx` and return.
3. On acceptance:
   - Call `lsquic_stream_get_wt_sess(stream)`.
   - Register WT callbacks.
4. Implement Devious Baton behavior:
   - Handle incoming WT bidi streams.
   - Process baton payloads per the test spec.
   - Handle WT datagrams if required.
   - Clean up on WT session close.

### Ownership Model
Once baton handling begins:
- The stream switches from HTTP mode to WT mode.
- HTTP request/response logic must not touch the stream again.

---

## Devious Baton Integration (Client Example)

Add a new client mode, e.g.:
- `--devious-baton`

Client flow:
1. Send CONNECT request with `:protocol=webtransport`.
2. Read response headers:
   - If 2xx: WT session established.
   - Else: report failure and exit.
3. Execute baton test logic:
   - Open WT bidi streams.
   - Send baton data.
   - Receive and validate responses.
   - Optionally test datagrams.

This turns the existing examples into a self-contained interop test harness.

---

## Benefits of This Approach

- Fast validation of WT API design and state machine.
- No dependency on OLS, PHP, or language bindings.
- Clear separation between HTTP handling and WT runtime.
- Minimal public API surface required initially.
- Easy evolution toward OLS integration once semantics stabilize.

---

## Future Work (Out of Scope for Now)

- OpenLiteSpeed integration
- PHP or other language bindings
- Advanced routing, auth, or deployment concerns

These can be layered on once WT support is proven via Devious Baton.
