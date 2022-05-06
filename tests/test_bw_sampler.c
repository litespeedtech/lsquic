/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/* Test adapted from Chromium bandwidth_sampler_test.cc */
// Copyright 2016 The Chromium Authors. All rights reserved.

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_conn.h"
#include "lsquic_malo.h"


/* Convert seconds to microseconds */
#define sec(val) ((val) * 1000 * 1000)

/* Convert milliseconds to lsquic_time_t, which is microseconds */
#define ms(val) ((val) * 1000)

/* Microseconds */
#define us(val) (val)

#define kRegularPacketSize 1280

#define PacketsToBytes(count_) ((count_) * kRegularPacketSize)

#define FromKBytesPerSecond(size_) (size_ * 8000)

// Enforce divisibility for some of the tests:
//      "kRegularPacketSize has to be five times divisible by 2"
typedef char packet_size_has_to_be_five_times_divisible_by_2[
                                (kRegularPacketSize & 31) == 0 ? 1 : -1];

struct sampler_test
{
    struct bw_sampler   sampler;
    lsquic_time_t       time;
    uint64_t            bytes_in_flight;
    struct lsquic_conn  conn;
    struct malo        *malo_po;
};


static void
sampler_test_init (struct sampler_test *stest)
{
    memset(stest, 0, sizeof(*stest));
    stest->time = ms(1000);     /* Time must not be zero, or test breaks */
    LSCONN_INITIALIZE(&stest->conn);
    lsquic_bw_sampler_init(&stest->sampler, &stest->conn, QUIC_FTBIT_STREAM);
    stest->malo_po = lsquic_malo_create(sizeof(struct lsquic_packet_out));
    assert(stest->malo_po);
}


static void
sampler_test_cleanup (struct sampler_test *stest)
{
    lsquic_bw_sampler_cleanup(&stest->sampler);
    lsquic_malo_destroy(stest->malo_po);
}


static struct lsquic_packet_out *
sampler_test_send_packet (struct sampler_test *stest, lsquic_packno_t packno,
                                                                    bool retx)
{
    struct lsquic_packet_out *packet_out;

    packet_out = lsquic_malo_get(stest->malo_po);
    assert(packet_out);
    memset(packet_out, 0, sizeof(*packet_out));
    packet_out->po_packno = packno;
    packet_out->po_flags |= PO_SENT_SZ;
    packet_out->po_flags |= PO_HELLO;   /* Bypass sanity check */
    packet_out->po_sent_sz = kRegularPacketSize;
    packet_out->po_sent = stest->time;
    if (retx)
        packet_out->po_frame_types |= QUIC_FTBIT_STREAM;
    lsquic_bw_sampler_packet_sent(&stest->sampler, packet_out,
                                                    stest->bytes_in_flight);
    if (retx)
        stest->bytes_in_flight += packet_out->po_sent_sz;
    return packet_out;
}


static struct bw_sample *
sampler_test_ack_packet (struct sampler_test *stest,
                                        struct lsquic_packet_out *packet_out)
{
    if (packet_out->po_frame_types & QUIC_FTBIT_STREAM)
        stest->bytes_in_flight -= packet_out->po_sent_sz;
    return lsquic_bw_sampler_packet_acked(&stest->sampler, packet_out,
                                                                stest->time);
}


static void
sampler_test_lose_packet (struct sampler_test *stest,
                                        struct lsquic_packet_out *packet_out)
{
    if (packet_out->po_frame_types & QUIC_FTBIT_STREAM)
        stest->bytes_in_flight -= packet_out->po_sent_sz;
    lsquic_bw_sampler_packet_lost(&stest->sampler, packet_out);
}


static void
sampler_test_send_40_packets_and_ack_first_20 (struct sampler_test *stest,
        lsquic_time_t time_between_packets, struct lsquic_packet_out *packets[])
{
    struct bw_sample *sample;
    unsigned i;

    // Send 20 packets at a constant inter-packet time.
    for (i = 1; i <= 20; i++)
    {
        packets[i] = sampler_test_send_packet(stest, i, true);
        stest->time += time_between_packets;
    }

    // Ack packets 1 to 20, while sending new packets at the same rate as
    // before.
    for (i = 1; i <= 20; i++)
    {
        sample = sampler_test_ack_packet(stest, packets[i]);
        assert(sample);
        lsquic_malo_put(sample);
        packets[i + 20] = sampler_test_send_packet(stest, i + 20, true);
        stest->time += time_between_packets;
    }
}


// Test the sampler in a simple stop-and-wait sender setting.
static void
test_send_and_wait (void)
{
    struct sampler_test stest;
    lsquic_time_t time_between_packets = ms(10);
    uint64_t expected_bandwidth = kRegularPacketSize * 100 * 8;
    unsigned i;
    struct bw_sample *sample;
    struct lsquic_packet_out *packet;

    sampler_test_init(&stest);

    // Send packets at the constant bandwidth.
    for (i = 1; i < 20; ++i)
    {
        packet = sampler_test_send_packet(&stest, i, true);
        stest.time += time_between_packets;
        sample = sampler_test_ack_packet(&stest, packet);
        assert(sample);
        assert(expected_bandwidth == BW_VALUE(&sample->bandwidth));
        lsquic_malo_put(sample);
    }

    // Send packets at the exponentially decreasing bandwidth.
    for (i = 20; i < 25; i++)
    {
        time_between_packets = time_between_packets * 2;
        expected_bandwidth = expected_bandwidth / 2;
        packet = sampler_test_send_packet(&stest, i, true);
        stest.time += time_between_packets;
        sample = sampler_test_ack_packet(&stest, packet);
        assert(sample);
        assert(expected_bandwidth == BW_VALUE(&sample->bandwidth));
        lsquic_malo_put(sample);
    }

    assert(lsquic_bw_sampler_entry_count(&stest.sampler) == 0);
    assert(stest.bytes_in_flight == 0);

    sampler_test_cleanup(&stest);
}


static void
test_send_time_state (void)
{
    struct sampler_test stest;
    lsquic_time_t time_between_packets = ms(10);
    struct bw_sample *sample;
    unsigned i;
    struct lsquic_packet_out *packets[11];

    sampler_test_init(&stest);

    // Send packets 1-5.
    for (i = 1; i <= 5; i++) {
        packets[i] = sampler_test_send_packet(&stest, i, true);
        assert(PacketsToBytes(i) == stest.sampler.bws_total_sent);
        stest.time += time_between_packets;
    }

    /* The order of tests here is different.  Because the send state is
     * deleted when packet is acked, we have to check its values first.
     */
#define SEND_STATE(idx_) (&packets[idx_]->po_bwp_state->bwps_send_state)

    // Ack packet 1.
    assert(PacketsToBytes(1) == SEND_STATE(1)->total_bytes_sent);
    assert(0 == SEND_STATE(1)->total_bytes_acked);
    assert(0 == SEND_STATE(1)->total_bytes_lost);
    sample = sampler_test_ack_packet(&stest, packets[1]);
    assert(sample);
    lsquic_malo_put(sample);
    assert(PacketsToBytes(1) == stest.sampler.bws_total_acked);

    // Lose packet 2.
    assert(PacketsToBytes(2) == SEND_STATE(2)->total_bytes_sent);
    assert(0 == SEND_STATE(2)->total_bytes_acked);
    assert(0 == SEND_STATE(2)->total_bytes_lost);
    sampler_test_lose_packet(&stest, packets[2]);
    assert(PacketsToBytes(1) == stest.sampler.bws_total_lost);

    // Lose packet 3.
    assert(PacketsToBytes(3) == SEND_STATE(3)->total_bytes_sent);
    assert(0 == SEND_STATE(3)->total_bytes_acked);
    assert(0 == SEND_STATE(3)->total_bytes_lost);
    sampler_test_lose_packet(&stest, packets[3]);
    assert(PacketsToBytes(2) == stest.sampler.bws_total_lost);

    // Send packets 6-10.
    for (i = 6; i <= 10; i++)
    {
        packets[i] = sampler_test_send_packet(&stest, i, true);
        assert(PacketsToBytes(i) == stest.sampler.bws_total_sent);
        stest.time += time_between_packets;
    }

    // Ack all inflight packets.
    unsigned acked_packet_count = 1;
    assert(PacketsToBytes(acked_packet_count) ==
                                                stest.sampler.bws_total_acked);
    for (i = 4; i <= 10; i++)
    {
        assert(PacketsToBytes(i) == SEND_STATE(i)->total_bytes_sent);
        if (i <= 5)
        {
            assert(0 == SEND_STATE(i)->total_bytes_acked);
            assert(0 == SEND_STATE(i)->total_bytes_lost);
        }
        else
        {
            assert(PacketsToBytes(1) == SEND_STATE(i)->total_bytes_acked);
            assert(PacketsToBytes(2) == SEND_STATE(i)->total_bytes_lost);
        }
        sample = sampler_test_ack_packet(&stest, packets[i]);
        assert(sample);
        lsquic_malo_put(sample);
        ++acked_packet_count;
        assert(PacketsToBytes(acked_packet_count) ==
                                                stest.sampler.bws_total_acked);
        stest.time += time_between_packets;
    }

    assert(lsquic_bw_sampler_entry_count(&stest.sampler) == 0);

    sampler_test_cleanup(&stest);
}


// Test the sampler during regular windowed sender scenario with fixed
// CWND of 20.
static void
test_send_paced (void)
{
    struct sampler_test stest;
    const lsquic_time_t time_between_packets = ms(1);
    uint64_t expected_bw = FromKBytesPerSecond(kRegularPacketSize);
    unsigned i;
    struct bw_sample *sample;
    struct lsquic_packet_out *packets[41];

    sampler_test_init(&stest);
    sampler_test_send_40_packets_and_ack_first_20(&stest,
                                                time_between_packets, packets);

    // Ack the packets 21 to 40, arriving at the correct bandwidth.
    for (i = 21; i <= 40; ++i)
    {
        sample = sampler_test_ack_packet(&stest, packets[i]);
        assert(sample);
        assert(expected_bw == BW_VALUE(&sample->bandwidth));
        stest.time += time_between_packets;
        lsquic_malo_put(sample);
    }

    assert(lsquic_bw_sampler_entry_count(&stest.sampler) == 0);
    assert(stest.bytes_in_flight == 0);

    sampler_test_cleanup(&stest);
}


// Test the sampler in a scenario where 50% of packets is consistently lost.
static void
test_send_with_losses (void)
{
    struct sampler_test stest;
    const lsquic_time_t time_between_packets = ms(1);
    uint64_t expected_bw = FromKBytesPerSecond(kRegularPacketSize) / 2;
    unsigned i;
    struct bw_sample *sample;
    struct lsquic_packet_out *packets[41];

    sampler_test_init(&stest);

    // Send 20 packets, each 1 ms apart.
    for (i = 1; i <= 20; i++)
    {
        packets[i] = sampler_test_send_packet(&stest, i, true);
        stest.time += time_between_packets;
    }

    // Ack packets 1 to 20, losing every even-numbered packet, while sending new
    // packets at the same rate as before.
    for (i = 1; i <= 20; i++)
    {
        if (i % 2 == 0)
        {
            sample = sampler_test_ack_packet(&stest, packets[i]);
            assert(sample);
            lsquic_malo_put(sample);
        }
        else
            sampler_test_lose_packet(&stest, packets[i]);
        packets[i + 20] = sampler_test_send_packet(&stest, i + 20, true);
        stest.time += time_between_packets;
    }

    // Ack the packets 21 to 40 with the same loss pattern.
    for (i = 21; i <= 40; i++)
    {
        if (i % 2 == 0)
        {
            sample = sampler_test_ack_packet(&stest, packets[i]);
            assert(sample);
            assert(expected_bw == BW_VALUE(&sample->bandwidth));
            lsquic_malo_put(sample);
        }
        else
            sampler_test_lose_packet(&stest, packets[i]);
        stest.time += time_between_packets;
    }

    assert(lsquic_bw_sampler_entry_count(&stest.sampler) == 0);
    assert(stest.bytes_in_flight == 0);

    sampler_test_cleanup(&stest);
}


// Test the sampler in a scenario where the 50% of packets are not
// congestion controlled (specifically, non-retransmittable data is not
// congestion controlled).  Should be functionally consistent in behavior with
// the SendWithLosses test.
static void
test_not_congestion_controlled (void)
{
    struct sampler_test stest;
    const lsquic_time_t time_between_packets = ms(1);
    uint64_t expected_bw = FromKBytesPerSecond(kRegularPacketSize) / 2;
    unsigned i;
    struct bw_sample *sample;
    struct lsquic_packet_out *packets[41];

    sampler_test_init(&stest);

    /* Note the mismatch between the comment and the code.  This is
     * inherited from the original code.
     */
    // Send 20 packets, each 1 ms apart. Every even packet is not congestion
    // controlled.
    for (i = 1; i <= 20; i++)
    {
        packets[i] = sampler_test_send_packet(&stest, i,
                                                i % 2 == 0 ? true : false);
        stest.time += time_between_packets;
    }

    assert(lsquic_bw_sampler_entry_count(&stest.sampler) == 10);

    // Ack packets 2 to 21, ignoring every even-numbered packet, while sending new
    // packets at the same rate as before.
    for (i = 1; i <= 20; i++)
    {
        if (i % 2 == 0)
        {
            sample = sampler_test_ack_packet(&stest, packets[i]);
            assert(sample);
            lsquic_malo_put(sample);
        }
        packets[i + 20] = sampler_test_send_packet(&stest, i + 20,
                                                i % 2 == 0 ? true : false);
        stest.time += time_between_packets;
    }

    // Ack the packets 22 to 41 with the same congestion controlled pattern.
    for (i = 21; i <= 40; i++)
    {
        if (i % 2 == 0)
        {
            sample = sampler_test_ack_packet(&stest, packets[i]);
            assert(sample);
            assert(expected_bw == BW_VALUE(&sample->bandwidth));
            lsquic_malo_put(sample);
        }
        stest.time += time_between_packets;
    }

    // Since only congestion controlled packets are entered into the map, it has
    // to be empty at this point.
    assert(lsquic_bw_sampler_entry_count(&stest.sampler) == 0);
    assert(stest.bytes_in_flight == 0);

    sampler_test_cleanup(&stest);
}


// Simulate a situation where ACKs arrive in burst and earlier than usual, thus
// producing an ACK rate which is higher than the original send rate.
static void
test_compressed_ack (void)
{
    struct sampler_test stest;
    const lsquic_time_t time_between_packets = ms(1),
                        ridiculously_small_time_delta = us(20);
    uint64_t expected_bw = FromKBytesPerSecond(kRegularPacketSize);
    uint64_t bw;
    unsigned i;
    struct bw_sample *sample;
    struct lsquic_packet_out *packets[41];

    sampler_test_init(&stest);
    sampler_test_send_40_packets_and_ack_first_20(&stest,
                                                time_between_packets, packets);

    // Simulate an RTT somewhat lower than the one for 1-to-21 transmission.
    stest.time += time_between_packets * 15;

    // Ack the packets 21 to 40 almost immediately at once.
    for (i = 21; i <= 40; i++)
    {
        sample = sampler_test_ack_packet(&stest, packets[i]);
        assert(sample);
        stest.time += ridiculously_small_time_delta;
        bw = BW_VALUE(&sample->bandwidth);
        lsquic_malo_put(sample);
    }

    assert(bw == expected_bw);
    assert(lsquic_bw_sampler_entry_count(&stest.sampler) == 0);
    assert(stest.bytes_in_flight == 0);

    sampler_test_cleanup(&stest);
}


// Tests receiving ACK packets in the reverse order.
static void
test_reordered_ack (void)
{
    struct sampler_test stest;
    const lsquic_time_t time_between_packets = ms(1);
    uint64_t expected_bw = FromKBytesPerSecond(kRegularPacketSize);
    unsigned i;
    struct bw_sample *sample;
    struct lsquic_packet_out *packets[61];

    sampler_test_init(&stest);
    sampler_test_send_40_packets_and_ack_first_20(&stest,
                                                time_between_packets, packets);

    // Ack the packets 21 to 40 in the reverse order, while sending packets 41 to
    // 60.
    for (i = 0; i < 20; i++)
    {
        sample = sampler_test_ack_packet(&stest, packets[40 - i]);
        assert(sample);
        assert(expected_bw == BW_VALUE(&sample->bandwidth));
        packets[41 + i] = sampler_test_send_packet(&stest, 41 + i, true);
        stest.time += time_between_packets;
        lsquic_malo_put(sample);
    }

    // Ack the packets 41 to 60, now in the regular order.
    for (i = 41; i <= 60; i++)
    {
        sample = sampler_test_ack_packet(&stest, packets[i]);
        assert(sample);
        assert(expected_bw == BW_VALUE(&sample->bandwidth));
        stest.time += time_between_packets;
        lsquic_malo_put(sample);
    }

    assert(lsquic_bw_sampler_entry_count(&stest.sampler) == 0);
    assert(stest.bytes_in_flight == 0);

    sampler_test_cleanup(&stest);
}


// Test the app-limited logic.
static void
test_app_limited (void)
{
    struct sampler_test stest;
    const lsquic_time_t time_between_packets = ms(1);
    uint64_t expected_bw = FromKBytesPerSecond(kRegularPacketSize);
    unsigned i;
    struct bw_sample *sample;
    struct lsquic_packet_out *packets[81];

    sampler_test_init(&stest);
    sampler_test_send_40_packets_and_ack_first_20(&stest,
                                                time_between_packets, packets);

    // We are now app-limited. Ack 21 to 40 as usual, but do not send anything for
    // now.
    lsquic_bw_sampler_app_limited(&stest.sampler);
    for (i = 21; i <= 40; i++)
    {
        sample = sampler_test_ack_packet(&stest, packets[i]);
        assert(sample);
        assert(expected_bw == BW_VALUE(&sample->bandwidth));
        stest.time += time_between_packets;
        lsquic_malo_put(sample);
    }

    stest.time += sec(1);

    // Send packets 41 to 60, all of which would be marked as app-limited.
    for (i = 41; i <= 60; i++)
    {
        packets[i] = sampler_test_send_packet(&stest, i, true);
        stest.time += time_between_packets;
    }

    // Ack packets 41 to 60, while sending packets 61 to 80.  41 to 60 should be
    // app-limited and underestimate the bandwidth due to that.
    for (i = 41; i <= 60; i++)
    {
        sample = sampler_test_ack_packet(&stest, packets[i]);
        assert(sample);
        assert(sample->is_app_limited);
        assert(BW_VALUE(&sample->bandwidth) < 0.7 * expected_bw);
        packets[i + 20] = sampler_test_send_packet(&stest, i + 20, true);
        stest.time += time_between_packets;
        lsquic_malo_put(sample);
    }

    // Run out of packets, and then ack packet 61 to 80, all of which should have
    // correct non-app-limited samples.
    for (i = 61; i <= 80; i++)
    {
        sample = sampler_test_ack_packet(&stest, packets[i]);
        assert(sample);
        assert(BW_VALUE(&sample->bandwidth) == expected_bw);
        stest.time += time_between_packets;
        lsquic_malo_put(sample);
    }

    assert(lsquic_bw_sampler_entry_count(&stest.sampler) == 0);
    assert(stest.bytes_in_flight == 0);

    sampler_test_cleanup(&stest);
}


// Test the samples taken at the first flight of packets sent.
static void
test_first_round_trip (void)
{
    struct sampler_test stest;
    const lsquic_time_t time_between_packets = ms(1),
                        rtt = ms(800);
    const unsigned num_packets = 10;
    const uint64_t num_bytes = num_packets * kRegularPacketSize;
    struct bandwidth real_bandwidth = BW_FROM_BYTES_AND_DELTA(num_bytes, rtt);
    uint64_t last_bw;
    unsigned i;
    struct bw_sample *sample;
    struct lsquic_packet_out *packets[11];

    sampler_test_init(&stest);

    for (i = 1; i <= 10; i++)
    {
        packets[i] = sampler_test_send_packet(&stest, i, true);
        stest.time += time_between_packets;
    }

    stest.time += rtt - num_packets * time_between_packets;

    last_bw = 0;
    for (i = 1; i <= 10; i++)
    {
        sample = sampler_test_ack_packet(&stest, packets[i]);
        assert(sample);
        assert(BW_VALUE(&sample->bandwidth) > last_bw);
        last_bw = BW_VALUE(&sample->bandwidth);
        stest.time += time_between_packets;
        lsquic_malo_put(sample);
    }

    // The final measured sample for the first flight of sample is expected to be
    // smaller than the real bandwidth, yet it should not lose more than 10%. The
    // specific value of the error depends on the difference between the RTT and
    // the time it takes to exhaust the congestion window (i.e. in the limit when
    // all packets are sent simultaneously, last sample would indicate the real
    // bandwidth).
    assert(last_bw < real_bandwidth.value);
    assert(last_bw > 0.9f * real_bandwidth.value);

    sampler_test_cleanup(&stest);
}


int
main (void)
{
    test_send_and_wait();
    test_send_time_state();
    test_send_paced();
    test_send_with_losses();
    test_not_congestion_controlled();
    test_compressed_ack();
    test_reordered_ack();
    test_app_limited();
    test_first_round_trip();

    return 0;
}
