/* Exercise real gossip, CRDS, peer sampling, and ping tracking with a
   simulated clock.  Transport and tile publication stay in process;
   incoming values enter at the already-verified gossip boundary. */

#include "fd_gossip.c"
#include "../../ballet/ed25519/fd_ed25519.h"

#include <stdlib.h>

#define START_NS (100L*1000L*1000L*1000L)
#define MS       (1000L*1000L)

typedef struct {
  fd_gossip_t *     gossip;
  fd_rng_t          rng[1];
  fd_sha512_t       sha[1];
  fd_stem_context_t stem[1];
  uchar            private_key[32];
  uchar            public_key[32];
  ulong            own_push_cnt;
  long             last_push_ns;
  ulong            last_push_wallclock;
  fd_ip4_port_t    last_push_addr;
  ulong            ping_cnt;
  uchar            ping_token[32];
  fd_ip4_port_t    ping_addr;
} fixture_t;

/* Replace only tile publication, not the gossip/CRDS state machines. */
void *
fd_gossip_out_get_chunk( fd_gossip_out_ctx_t * ctx ) {
  (void)ctx;
  static fd_gossip_update_message_t message;
  return &message;
}

void
fd_gossip_tx_publish_chunk( fd_gossip_out_ctx_t * ctx,
                            fd_stem_context_t *  stem,
                            ulong                sig,
                            ulong                sz,
                            long                 now ) {
  (void)ctx; (void)stem; (void)sig; (void)sz; (void)now;
}

static void
sign_message( void *        ctx,
              uchar const * data,
              ulong         sz,
              int           sign_type,
              uchar *       signature ) {
  fixture_t * f = ctx;
  FD_TEST( sign_type==FD_KEYGUARD_SIGN_TYPE_ED25519 );
  fd_ed25519_sign( signature, data, sz, f->public_key, f->private_key, f->sha );
}

static void
send_message( void *                ctx,
              fd_stem_context_t *   stem,
              uchar const *         data,
              ulong                 sz,
              fd_ip4_port_t const * addr,
              ulong                 now ) {
  (void)stem;
  fixture_t * f = ctx;
  fd_gossip_message_t message[1];
  FD_TEST( fd_gossip_message_deserialize( message, data, sz ) );
  if( message->tag==FD_GOSSIP_MESSAGE_PING ) {
    f->ping_cnt++;
    fd_memcpy( f->ping_token, message->ping->token, 32UL );
    f->ping_addr = *addr;
  }
  if( message->tag!=FD_GOSSIP_MESSAGE_PUSH ) return;
  for( ulong i=0UL; i<message->push->values_len; i++ ) {
    fd_gossip_value_t const * value = &message->push->values[i];
    if( memcmp( value->origin, f->public_key, 32UL ) ) continue;
    FD_TEST( value->tag==FD_GOSSIP_VALUE_CONTACT_INFO );
    FD_TEST( value->contact_info->shred_version==42U );
    FD_TEST( value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].port==fd_ushort_bswap( 8001U ) );
    FD_TEST( FD_ED25519_SUCCESS==fd_ed25519_verify( data+value->offset+64UL, value->length-64UL,
                                                  value->signature, f->public_key, f->sha ) );
    f->own_push_cnt++;
    f->last_push_ns        = (long)now;
    f->last_push_wallclock = value->wallclock;
    f->last_push_addr      = *addr;
  }
}

static void
ping_changed( void *        ctx,
              uchar const * peer,
              fd_ip4_port_t addr,
              long          now,
              int           change ) {
  (void)ctx; (void)peer; (void)addr; (void)now; (void)change;
}

static void
activity_changed( void *                           ctx,
                  fd_pubkey_t const *              peer,
                  fd_gossip_contact_info_t const * ci,
                  int                              change ) {
  (void)ctx; (void)peer; (void)ci; (void)change;
}

static void
fixture_init( fixture_t * f,
              ulong       own_stake ) {
  fd_memset( f, 0, sizeof(*f) );
  FD_TEST( fd_rng_join( fd_rng_new( f->rng, 0U, 0UL ) ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( f->sha ) ) );
  f->private_key[0] = 1U;
  fd_ed25519_public_from_private( f->public_key, f->private_key, f->sha );

  fd_gossip_contact_info_t ci = { .shred_version = 42U };
  ci.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4  = FD_IP4_ADDR( 127, 0, 0, 1 );
  ci.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].port = fd_ushort_bswap( 8001U );
  static fd_gossip_out_ctx_t out;
  void * mem = aligned_alloc( fd_gossip_align(), fd_gossip_footprint( 128UL, 0UL ) );
  FD_TEST( mem );
  f->gossip = fd_gossip_join( fd_gossip_new( mem, f->rng, 128UL, 0UL, NULL, f->public_key, &ci, START_NS,
                                           send_message, f, sign_message, f, ping_changed, NULL,
                                           activity_changed, NULL, &out, &out ) );
  FD_TEST( f->gossip );
  fd_stake_weight_t own_weight = { .stake = own_stake };
  fd_memcpy( own_weight.key.uc, f->public_key, 32UL );
  fd_gossip_stakes_update( f->gossip, &own_weight, 1UL );

  int busy = 0;
  fd_gossip_advance( f->gossip, START_NS, f->stem, &busy );
  FD_TEST( busy );
  FD_TEST( !f->own_push_cnt ); /* no peers, and never send to self */
  FD_TEST( f->gossip->timers.next_contact_info_refresh==START_NS+7500L*MS );
}

static fd_ip4_port_t
peer_addr( uchar peer_id ) {
  return (fd_ip4_port_t){ .addr = FD_IP4_ADDR( 127, 0, 0, 1 ), .port = fd_ushort_bswap( (ushort)(8001U+100U*peer_id) ) };
}

static void
receive_contact_info( fixture_t * f,
                      uchar       peer_id,
                      ulong       stake,
                      long        now ) {
  fd_gossip_value_t value = { .tag = FD_GOSSIP_VALUE_CONTACT_INFO, .wallclock = (ulong)(now/MS) };
  value.origin[0] = peer_id;
  value.signature[0] = peer_id;
  value.contact_info->shred_version = 42U;
  fd_ip4_port_t addr = peer_addr( peer_id );
  value.contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4  = addr.addr;
  value.contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].port = addr.port;

  fd_stake_weight_t weights[2] = { { .stake = f->gossip->identity_stake }, { .stake = stake } };
  fd_memcpy( weights[0].key.uc, f->public_key, 32UL );
  weights[1].key.uc[0] = peer_id;
  fd_gossip_stakes_update( f->gossip, weights, 2UL );

  uchar serialized[ FD_GOSSIP_VALUE_MAX_SZ ];
  long sz = fd_gossip_value_serialize( &value, serialized, sizeof(serialized) );
  FD_TEST( sz>0L );
  value.length = (ulong)sz;
  uchar failed[1] = {0};
  long results[17];
  rx_values( f->gossip, 1UL, &value, serialized, failed, f->stem, now, results );
  FD_TEST( results[0]>=0L );
}

static void
receive_pong( fixture_t * f,
              uchar       peer_id,
              long        now,
              int         valid ) {
  FD_TEST( f->ping_cnt );
  fd_gossip_pong_t pong = {0};
  pong.from[0] = peer_id;
  uchar preimage[48];
  fd_memcpy( preimage, "SOLANA_PING_PONG", 16UL );
  fd_memcpy( preimage+16UL, f->ping_token, 32UL );
  fd_sha256_hash( preimage, sizeof(preimage), pong.hash );
  if( !valid ) pong.hash[0] ^= 1U;
  rx_pong( f->gossip, &pong, f->ping_addr, now );
}

static void
advance( fixture_t * f,
         long        now ) {
  int busy = 0;
  fd_gossip_advance( f->gossip, now, f->stem, &busy );
}

static void
test_first_usable_peer( ulong own_stake,
                        ulong peer_stake ) {
  FD_LOG_NOTICE(( "test_first_usable_peer: own_stake=%lu peer_stake=%lu", own_stake, peer_stake ));
  fixture_t f[1];
  fixture_init( f, own_stake );

  /* Bucket zero was visited while empty.  Learn a peer long before
     either the next bucket visit or the 7.5s contact-info refresh. */
  receive_contact_info( f, 2U, peer_stake, START_NS+10L*MS );
  if( peer_stake<FD_GOSSIP_STAKED_THRESHOLD ) {
    advance( f, START_NS+20L*MS );
    FD_TEST( !f->own_push_cnt ); /* an unponged low-stake peer is not usable */
    FD_TEST( f->ping_cnt==1UL );
    receive_pong( f, 2U, START_NS+21L*MS, 0 );
    advance( f, START_NS+22L*MS );
    FD_TEST( !f->own_push_cnt ); /* an invalid pong cannot trigger advertisement */
    receive_pong( f, 2U, START_NS+23L*MS, 1 );
  }

  long advertised_at = START_NS+24L*MS;
  advance( f, advertised_at );
  FD_TEST( f->own_push_cnt==1UL );
  FD_TEST( f->last_push_ns==advertised_at );
  FD_TEST( f->last_push_wallclock==(ulong)(advertised_at/MS) );
  FD_TEST( f->last_push_addr.l==peer_addr( 2U ).l );
  FD_TEST( f->gossip->timers.next_contact_info_refresh==advertised_at+7500L*MS );

  /* Repeated contact info and maintenance passes must not cause a
     burst of signatures or advertisements once the bucket is seeded. */
  receive_contact_info( f, 2U, peer_stake, START_NS+10L*MS );
  for( long i=25L; i<300L; i++ ) advance( f, START_NS+i*MS );
  FD_TEST( f->own_push_cnt==1UL );
  advance( f, advertised_at+7500L*MS );
  FD_TEST( f->own_push_cnt==2UL ); /* periodic refresh remains enabled */
  free( f->gossip );
}

static void
test_pong_before_contact_info( void ) {
  FD_LOG_NOTICE(( "test_pong_before_contact_info" ));
  fixture_t f[1];
  fixture_init( f, 0UL );
  uchar peer[32] = {2U};
  fd_gossip_ping_tracker_track( f->gossip, peer, peer_addr( 2U ), START_NS+10L*MS );
  advance( f, START_NS+11L*MS );
  receive_pong( f, 2U, START_NS+12L*MS, 1 );
  advance( f, START_NS+13L*MS );
  FD_TEST( !f->own_push_cnt ); /* a pong alone does not populate CRDS */
  receive_contact_info( f, 2U, 0UL, START_NS+14L*MS );
  advance( f, START_NS+15L*MS );
  FD_TEST( f->own_push_cnt==1UL );
  FD_TEST( f->last_push_ns==START_NS+15L*MS );
  free( f->gossip );
}

static void
test_peer_becomes_usable_again( void ) {
  FD_LOG_NOTICE(( "test_peer_becomes_usable_again" ));
  fixture_t f[1];
  fixture_init( f, 0UL );
  receive_contact_info( f, 2U, 0UL, START_NS+10L*MS );
  advance( f, START_NS+11L*MS );
  receive_pong( f, 2U, START_NS+12L*MS, 1 );
  advance( f, START_NS+13L*MS );
  FD_TEST( f->own_push_cnt==1UL );

  uchar peer[32] = {2U};
  fd_ping_tracker_remove( f->gossip->ping_tracker, peer, START_NS+14L*MS );
  advance( f, START_NS+15L*MS );
  FD_TEST( f->own_push_cnt==1UL );
  fd_gossip_ping_tracker_track( f->gossip, peer, peer_addr( 2U ), START_NS+16L*MS );
  advance( f, START_NS+17L*MS );
  FD_TEST( f->ping_cnt==2UL );
  FD_TEST( f->own_push_cnt==1UL );
  receive_pong( f, 2U, START_NS+18L*MS, 1 );
  advance( f, START_NS+19L*MS );
  FD_TEST( f->own_push_cnt==2UL );
  FD_TEST( f->last_push_ns==START_NS+19L*MS );
  free( f->gossip );
}

static void
test_rotation_advertises( void ) {
  FD_LOG_NOTICE(( "test_rotation_advertises" ));
  fixture_t f[1];
  fixture_init( f, 0UL );
  receive_contact_info( f, 2U, FD_GOSSIP_STAKED_THRESHOLD, START_NS+10L*MS );
  advance( f, START_NS+11L*MS );
  FD_TEST( f->own_push_cnt==1UL );
  receive_contact_info( f, 3U, FD_GOSSIP_STAKED_THRESHOLD, START_NS+12L*MS );

  /* Normal rotations still run at 300ms.  When bucket zero gets its
     next peer, advertise without waiting for the periodic deadline. */
  for( long i=1L; i<25L; i++ ) advance( f, START_NS+i*300L*MS );
  FD_TEST( f->own_push_cnt==1UL );
  advance( f, START_NS+7500L*MS );
  FD_TEST( f->own_push_cnt==3UL ); /* one contact-info push to each peer */
  FD_TEST( f->last_push_ns==START_NS+7500L*MS );
  FD_TEST( f->last_push_addr.l==peer_addr( 3U ).l );
  advance( f, START_NS+7501L*MS );
  FD_TEST( f->own_push_cnt==3UL );
  free( f->gossip );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_first_usable_peer( 0UL, 0UL );
  test_first_usable_peer( FD_GOSSIP_STAKED_THRESHOLD, 0UL );
  test_first_usable_peer( 0UL, FD_GOSSIP_STAKED_THRESHOLD );
  test_pong_before_contact_info();
  test_peer_becomes_usable_again();
  test_rotation_advertises();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
