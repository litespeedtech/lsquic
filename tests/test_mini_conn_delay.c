/* Test for mini connection delayed packet data corruption bug */

#undef LSQUIC_TEST

#include <assert.h>
#include <string.h>
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_mm.h"
#include "lsquic_hash.h"
#include "lsquic_engine_public.h"
#include "lsquic_trechist.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_packet_common.h"
#include "lsquic_rtt.h"
#include "lsquic_mini_conn_ietf.h"
#include "lsquic_crand.h"
#include "lsquic_ev_log.h"
#include "lsquic_packet_in.h"
#include "lsquic_version.h"

static enum dec_packin mock_decrypt_packet(enc_session_t *enc_sess,
                                           struct lsquic_engine_public *enpub,
                                           const struct lsquic_conn *lconn,
                                           struct lsquic_packet_in *packet_in) {
  // Return DECPI_NOT_YET to trigger delay
  return DECPI_NOT_YET;
}

static void mock_generate_scid(void *ctx, struct lsquic_conn *conn,
                               uint8_t *scid, unsigned len) {
  memset(scid, 0xCC, len);
}

static void test_delayed_packet_corruption(void) {
  unsigned char packet_data[200];
  unsigned char app_data[200];
  lsquic_cid_t dcid = {.len = 8, .idbuf = {1, 2, 3, 4, 5, 6, 7, 8}};
  struct enc_session_funcs_common mock_esf_c;
  struct crand crand;

  struct lsquic_engine_public enpub;
  memset(&enpub, 0, sizeof(enpub));
  lsquic_mm_init(&enpub.enp_mm);
  lsquic_engine_init_settings(&enpub.enp_settings, 0);
  enpub.enp_settings.es_ecn = 0;
  enpub.enp_generate_scid = mock_generate_scid;
  memset(&crand, 0, sizeof(crand));
  enpub.enp_crand = &crand;

  // Setup initial packet
  struct lsquic_packet_in *packet_in_init =
      lsquic_mm_get_packet_in(&enpub.enp_mm);
  packet_in_init->pi_data = packet_data;
  packet_in_init->pi_data_sz = 1200;
  packet_in_init->pi_header_type = HETY_INITIAL;
  packet_in_init->pi_flags = PI_OWN_DATA;
  packet_in_init->pi_dcid = dcid;
  packet_in_init->pi_received = 1234567890;

  // Create mini connection
  struct lsquic_conn *conn = lsquic_mini_conn_ietf_new(
      &enpub, packet_in_init, LSQVER_I001, 0, &dcid, 1200);
  assert(conn);
  struct ietf_mini_conn *mini_conn = (struct ietf_mini_conn *)conn;

  // Setup mock crypto interface to force delay
  memcpy(&mock_esf_c, conn->cn_esf_c, sizeof(mock_esf_c));
  mock_esf_c.esf_decrypt_packet = mock_decrypt_packet;
  conn->cn_esf_c = &mock_esf_c;

  // Create APP packet to be delayed
  memset(app_data, 0x42, sizeof(app_data));
  struct lsquic_packet_in *packet_in_app =
      lsquic_mm_get_packet_in(&enpub.enp_mm);
  packet_in_app->pi_data = app_data;
  packet_in_app->pi_data_sz = sizeof(app_data);
  packet_in_app->pi_header_type = HETY_SHORT;
  packet_in_app->pi_flags = 0;
  packet_in_app->pi_dcid = dcid;
  packet_in_app->pi_received = 1234567891;

  // Send APP packet
  conn->cn_if->ci_packet_in(conn, packet_in_app);

  // Verify it is delayed
  assert(!TAILQ_EMPTY(&mini_conn->imc_app_packets) && "Packet was NOT delayed");
  struct lsquic_packet_in *delayed = TAILQ_FIRST(&mini_conn->imc_app_packets);
  assert(delayed == packet_in_app &&
         "Delayed packet is different from one we sent");

  // Modify buffer
  memset(app_data, 0xAC, sizeof(app_data));

  // Check delayed packet data is not corrupted
  assert(delayed->pi_data[0] == 0x42 && "Delayed data is corrupted!");

  lsquic_mm_cleanup(&enpub.enp_mm);
}

int main(void) {
  test_delayed_packet_corruption();
  return 0;
}
