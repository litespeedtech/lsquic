RESET_STREAM_AT send-side implementation plan (options)

Decision constraints
- Feature flag in engine settings; default OFF.
- Only send RESET_STREAM_AT if peer advertised reset_stream_at transport parameter.
- Focus is WebTransport: RESET_STREAM_AT is used for WT only.
- For WT streams, we intentionally allow retraction beyond the WT header;
  reliable_size MUST be at least the WT header size, per the I-D.
  (Comment to keep in code verbatim.)

Option A: WebTransport-only, header-sized reliable_size
- Track per-WT stream header size.
- On reset of a WT data stream, send RESET_STREAM_AT with
  reliable_size = wt_header_size (and final_size = final offset).
- Non-WT streams continue using RST_STREAM.

Pros: matches WT requirement, minimal logic.
Cons: does not support partial-reliability beyond header for other protocols.

Option B: WebTransport-only, header-sized reliable_size + optional override
- Same as Option A, but allow app/API to override reliable_size
  (>= wt_header_size) for WT streams only.
- Default remains header size if no override.

Pros: still WT-focused, allows future tuning without rework.
Cons: requires API surface + app wiring.

Option C: Always send RESET_STREAM_AT when enabled (IETF only)
- If flag ON + peer TP present, use RESET_STREAM_AT for all IETF streams.
- For WT streams: reliable_size = wt_header_size.
- For non-WT streams: reliable_size = 0 (full retraction) or final_size
  (no retraction) — needs a policy choice.

Pros: simple single path in sender.
Cons: affects non-WT behavior; policy ambiguity.

Common work items (all options)
- Settings flag (default OFF) and peer-support check.
- New send flag/state to choose RESET_STREAM_AT vs RST_STREAM in frame writer.
- Store send-side final_size, reliable_size, error_code for retransmission.
- Update STOP_SENDING handling to choose RESET_STREAM_AT when enabled.
- Update ACK handling for RESET_STREAM_AT frames (clear send flag on ack).
- Tests: verify correct frame chosen, correct fields, ack clears send flag,
  and fallback to RST_STREAM when disabled or peer doesn’t support.

Open questions
- Where/how to store WT header size (stream field vs per-session map)?
- How to identify WT streams in core (flag on stream vs external hook)?
- Should we allow RESET_STREAM_AT only when WT support is compiled in?

Commit.  Then:

I like Option A best.  Who know where WT I-D will go, let's make it easy to change.

Answers to open questions:
- WT header size should be stored as uint8_t in stream.  Small integer because
  the maximum varint length will fit there.  Find a good place in struct lsquic_stream
- Flag on stream.
- WT support is always compiled in.  Instead, send RESET_STREAM_AT for WT streams only.
