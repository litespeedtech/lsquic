# Delayed ACKs / ACK_FREQUENCY State Report

## Executive Summary

LSQUIC still contains a substantial delayed-ACK implementation, but it matches the older 2020 delayed-ack draft rather than the current `draft-ietf-quic-ack-frequency` design.

As of February 28, 2026, the current published `ack-frequency` draft is `draft-ietf-quic-ack-frequency-14` (January 19, 2024). Relative to that draft, the implementation in this tree is not wire-compatible in key areas:

- It uses obsolete `min_ack_delay` transport parameter IDs.
- It encodes `ACK_FREQUENCY` using the older layout with a trailing boolean `Ignore Order`.
- It does not implement `IMMEDIATE_ACK`.
- It uses old-draft semantics where the current draft uses a numeric reordering threshold.

The feature is best described as legacy experimental support for the older delayed-ack draft, not current ACK Frequency support.

## What Exists In Tree

The implementation is functional and not just parser scaffolding:

- The feature was introduced in 2020 as experimental delayed-ACK support.
- It advertises legacy delayed-ack transport parameters.
- It parses incoming `ACK_FREQUENCY` frames and can generate outgoing `ACK_FREQUENCY` frames.
- It includes a packet-tolerance controller that adjusts the peer's ACK cadence based on observed ACKs per RTT.

Relevant source files:

- `include/lsquic.h`
- `src/liblsquic/lsquic_engine.c`
- `src/liblsquic/lsquic_enc_sess_ietf.c`
- `src/liblsquic/lsquic_full_conn_ietf.c`
- `src/liblsquic/lsquic_parse_ietf_v1.c`
- `src/liblsquic/lsquic_trans_params.c`
- `src/liblsquic/lsquic_trans_params.h`

## Where It Matches The Older Delayed-ACK Draft

### Old frame layout

The current parser and generator still use:

- frame type `0xAF`
- `Sequence Number`
- `Packet Tolerance`
- `Update Max Ack Delay`
- `Ignore Order` as a trailing one-byte boolean

That matches the older delayed-ack draft layout, not the current `ack-frequency` frame format.

### Obsolete transport parameter IDs

The implementation still recognizes and emits legacy delayed-ack transport parameter IDs:

- `0xDE1A`
- `0xFF02DE1A`

It does not emit the current `min_ack_delay` transport parameter ID used by the modern draft.

### Old terminology

The implementation and comments still use older delayed-ack terminology:

- `Packet Tolerance`
- `Ignore Order`
- `Delayed ACKs`

The current draft instead uses:

- `Ack-Eliciting Threshold`
- `Reordering Threshold`
- `ACK Frequency`

## Mismatch Against The Current Draft

### 1. Negotiation is outdated

The current draft uses a different `min_ack_delay` transport parameter ID. This implementation still uses the older IDs, so negotiation with a modern peer is likely to fail unless that peer still carries compatibility code for the older delayed-ack drafts.

### 2. `ACK_FREQUENCY` payload is outdated

The current draft uses four varints:

- `Sequence Number`
- `Ack-Eliciting Threshold`
- `Requested Max Ack Delay`
- `Reordering Threshold`

This implementation still expects the last field to be a single-byte boolean. A modern peer can therefore fail to interoperate even if frame type `0xAF` is recognized.

### 3. `IMMEDIATE_ACK` is missing

The current draft also defines `IMMEDIATE_ACK` (`0x1f`). There is no implementation support for that frame in the current tree.

### 4. Sender-side max-ack-delay requests are effectively not used

The sender negotiates `min_ack_delay`, but the code path that generates `ACK_FREQUENCY` frames reuses the peer's existing `max_ack_delay` value instead of actively requesting a new max ACK delay. In practice, the implementation mainly adjusts only the packet-count side of delayed ACKs.

### 5. Automatic sending is coupled to BBR

The packet-tolerance control loop is only initially armed when the send controller is using direct BBR. That means the automatic outgoing `ACK_FREQUENCY` path is not universally active across congestion-control choices.

## Testing State

There does not appear to be dedicated unit-test coverage under `tests/` for:

- `ACK_FREQUENCY` frame encode/decode
- delayed-ack transport parameter encode/decode
- current-draft ACK Frequency behavior

That leaves the legacy implementation with weak regression coverage and increases the cost of a spec refresh.

## Recommendation

### Short term

- Keep the legacy implementation in tree if it is still useful for experiments.
- Do not enable it by default.
- Do not advertise it as supported in user-facing docs.

### Follow-up work

To resuscitate the feature for current-spec interoperability:

- replace legacy `min_ack_delay` transport parameter IDs with the current one
- update `ACK_FREQUENCY` parsing and generation to the current four-varint format
- add `IMMEDIATE_ACK`
- rename or rework the `Ignore Order` behavior into a current-draft reordering-threshold model
- add explicit transport-parameter and frame-level tests

## Overall Verdict

The code is still present and substantial, but it is legacy delayed-ack code, not current ACK Frequency support. It should be treated as obsolete experimental functionality until it is refreshed against the modern draft.
