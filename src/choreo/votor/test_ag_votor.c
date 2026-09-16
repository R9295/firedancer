#include "ag_votor.c"
#include "test_ag_cert_builder.h"
#include "ag_cert_serde.h"
#include "ag_vote_serde.h"

#define NV                 (2UL)
#define TEST_SLOT_MAX      (64UL)
#define TEST_SHRED_VERSION ((ushort)0x5a5a)

/* Long enough for every timeout of a leader window to come due. */

#define TEST_WINDOW_ELAPSED_NS (AG_DELTA_TIMEOUT_NS + (long)(AG_SLOTS_PER_WINDOW+1UL)*AG_DELTA_BLOCK_NS)

#define FD_TEST_NO_MSG( votor ) do {           \
    ag_vote_t unused_;                         \
    FD_TEST( !try_recv( (votor), &unused_ ) ); \
  } while( 0 )

#define SCRATCH_MAX (1UL<<19) /* 512 KiB */

static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned(128)));

static fd_bls_sec_t      g_sk  [ NV ];
static ag_validator_info_t g_info[ NV ];
static ulong               g_hash_ctr = 0UL;

static void
genesis_hash( ag_block_hash_t out ) {
  fd_memset( out, 0, sizeof(ag_block_hash_t) );
}

static void
random_hash( ag_block_hash_t out ) {
  fd_memset( out, 0, sizeof(ag_block_hash_t) );
  FD_STORE( ulong, out,     0x9000UL + (++g_hash_ctr) );
  FD_STORE( ulong, out+8UL, 0xc0ffee00UL ^ g_hash_ctr );
}

static ag_block_id_t
genesis_block_id( void ) {
  ag_block_id_t b; b.slot = 0UL; genesis_hash( b.hash );
  return b;
}

static ag_block_id_t
random_block_id( ulong slot ) {
  ag_block_id_t b; b.slot = slot; random_hash( b.hash );
  return b;
}

static void
create_validators( void ) {
  for( ulong i=0UL; i<NV; i++ ) {
    fd_memset( &g_sk[i], (int)(i*7UL+1UL), FD_BLS_SEC_SZ );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    fd_bls_sec_to_pub( &g_sk[i], &g_info[i].bls_key );
  }
}

static int
contains_slot( ag_votor_t const * votor,
               ulong              slot ) {
  return slot_state_map_ele_query_const( votor->slot_states->map, &slot, NULL, votor->slot_states->pool )!=NULL;
}

static ulong
min_live_slot( ag_votor_t const * votor ) {
  slot_state_map_t const * map = votor->slot_states->map;
  slot_state_ele_t const * ele = votor->slot_states->pool;
  ulong min = ULONG_MAX;
  for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, ele );
                                   !slot_state_map_iter_done( iter, map, ele );
                             iter = slot_state_map_iter_next( iter, map, ele ) ) {
    min = fd_ulong_min( min, slot_state_map_iter_ele_const( iter, map, ele )->slot );
  }
  return min;
}

/* The Rust reference drives a second All2All instance and awaits
   messages on it.  Here the votor's outbound vote stream is drained
   instead: recv insists on a vote, try_recv does not.  Certs travel on
   their own stream now, so everything these tests await is a vote. */

static int
try_recv( ag_votor_t * votor,
          ag_vote_t *  out ) {
  ag_event_vote_t event;
  if( FD_UNLIKELY( !ag_votor_poll_vote_event( votor, &event ) ) ) return 0;
  *out = event.vote;
  return 1;
}

static ag_vote_t
recv( ag_votor_t * votor ) {
  ag_vote_t vote;
  FD_TEST( try_recv( votor, &vote ) );
  return vote;
}

/* Timeouts used to be fired in bulk by advancing the clock.  The votor
   now hands them out one at a time, so drain everything due at now. */

static void
handle_timeouts( ag_votor_t * votor,
                 long         now ) {
  ag_event_timeout_t event;
  while( ag_votor_poll_timeout_event( votor, now, &event ) ) ag_votor_handle_timeout_event( votor, &event );
}

/* The epoch info is nearly 300 KiB, too big for the stack, and only one
   is ever live, so it gets its own file static rather than a slice of
   the scratch. */

static ag_epoch_info_t   epoch_info_mem;
static ag_epoch_info_t * g_epoch_info = NULL;

/* Creates a fresh fully wired-up votor instance. */

static ag_votor_t *
setup_votor( long now ) {
  create_validators();
  FD_TEST( ag_votor_footprint( TEST_SLOT_MAX )<=sizeof(scratch) );
  ag_votor_t * votor = ag_votor_join( ag_votor_new( scratch, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( votor );
  ag_votor_init         ( votor, 0UL, now, TEST_SHRED_VERSION, sec_sign_fn, &g_sk[0] );
  ag_votor_advance_epoch( votor, 0UL, 0UL );

  g_epoch_info = &epoch_info_mem;
  ag_epoch_info( g_epoch_info, g_info, NV );
  return votor;
}

static void
teardown_votor( ag_votor_t * votor ) {
  ag_votor_delete( ag_votor_leave( votor ) );
  g_epoch_info = NULL;
}

/* Notifies the votor of a new block and returns the resulting notar
   vote. */

static ag_vote_t
send_block_and_expect_notar( ag_votor_t *          votor,
                             ulong                 slot,
                             ag_block_id_t const * parent ) {
  ag_event_block_t first_shred = { .kind = AG_EVENT_BLOCK_FIRST_SHRED, .slot = slot };
  ag_votor_handle_block_event ( votor, &first_shred );

  ag_event_replay_t block = { .kind = AG_EVENT_REPLAY_COMPLETED };
  block.slot              = slot;
  random_hash( block.block_info.hash );
  block.block_info.parent = *parent;
  ag_votor_handle_replay_event( votor, &block );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_NOTAR );
  FD_TEST( ag_vote_slot( &msg )==slot );
  return msg;
}

/* src/consensus/votor.rs::timeouts */

static void
test_timeouts( void ) {
  ag_votor_t * votor = setup_votor( 0L );

  /* should vote skip for all slots */
  handle_timeouts( votor, TEST_WINDOW_ELAPSED_NS );

  ulong skipped_slots[ AG_SLOTS_PER_WINDOW ];
  ulong skipped_cnt = 0UL;
  for( ulong s=1UL; s<AG_SLOTS_PER_WINDOW; s++ ) {
    ag_vote_t msg = recv( votor );
    FD_TEST( msg.kind==AG_VOTE_KIND_SKIP );
    skipped_slots[ skipped_cnt++ ] = ag_vote_slot( &msg );
  }
  FD_TEST( skipped_cnt==AG_SLOTS_PER_WINDOW-1UL );
  for( ulong i=0UL; i<skipped_cnt; i++ ) FD_TEST( skipped_slots[i]==i+1UL );
  FD_TEST_NO_MSG( votor );

  teardown_votor( votor );
}

/* src/consensus/votor.rs::notar_and_final */

static void
test_notar_and_final( void ) {
  ag_votor_t *  votor  = setup_votor( 0L );
  ulong         slot   = 1UL;
  ag_block_id_t parent = genesis_block_id();

  /* vote notar after seeing block */
  ag_vote_t vote = send_block_and_expect_notar( votor, slot, &parent );

  /* vote finalize after seeing branch-certified */
  ag_cert_t cert = cert_build_notar( &vote.notar, 1UL, g_epoch_info );
  ag_event_pool_t event = { .kind = AG_EVENT_POOL_CERT_CREATED, .cert_created = cert };
  ag_votor_handle_pool_event( votor, &event, 0L );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_FINAL );
  FD_TEST( ag_vote_slot( &msg )==slot );

  teardown_votor( votor );
}

/* src/consensus/votor.rs::notar_out_of_order */

static void
test_notar_out_of_order( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  ulong slot1 = 1UL;       ag_block_hash_t hash1; random_hash( hash1 );
  ulong slot2 = slot1+1UL; ag_block_hash_t hash2; random_hash( hash2 );

  /* give later block to votor first */
  ag_event_block_t first_shred = { .kind = AG_EVENT_BLOCK_FIRST_SHRED, .slot = slot2 };
  ag_votor_handle_block_event ( votor, &first_shred );

  ag_event_replay_t block = { .kind = AG_EVENT_REPLAY_COMPLETED };
  block.slot              = slot2;
  block.block_info.parent = ag_block_id( slot1, hash1 );
  memcpy( block.block_info.hash, hash2, sizeof(ag_block_hash_t) );
  ag_votor_handle_replay_event( votor, &block );

  /* should not vote yet */
  FD_TEST_NO_MSG( votor );

  /* now notify votor of earlier block */
  first_shred.slot = slot1;
  ag_votor_handle_block_event ( votor, &first_shred );

  block.slot              = slot1;
  block.block_info.parent = genesis_block_id();
  memcpy( block.block_info.hash, hash1, sizeof(ag_block_hash_t) );
  ag_votor_handle_replay_event( votor, &block );

  /* should now see notar votes */
  for( ulong i=0UL; i<2UL; i++ ) {
    ag_vote_t msg = recv( votor );
    FD_TEST( msg.kind==AG_VOTE_KIND_NOTAR );
    ulong slot = ag_vote_slot( &msg );
    FD_TEST( slot==slot1 || slot==slot2 );
  }

  teardown_votor( votor );
}

/* src/consensus/votor.rs::pending_block_not_notarized_after_skip */

static void
test_pending_block_not_notarized_after_skip( void ) {
  ag_votor_t * votor = setup_votor( 0L );

  /* first slot of the second leader window; its parent is not ready yet */
  ulong slot = AG_SLOTS_PER_WINDOW;
  FD_TEST( ag_is_start_of_window( slot ) );
  ag_block_id_t parent = { .slot = slot-1UL }; random_hash( parent.hash );

  /* block reconstructs before its parent is ready: stashed as pending, no
     vote yet (parent not in parents_ready) */
  ag_event_replay_t block = { .kind = AG_EVENT_REPLAY_COMPLETED };
  block.slot              = slot;
  random_hash( block.block_info.hash );
  block.block_info.parent = parent;
  ag_votor_handle_replay_event( votor, &block );

  /* window times out: we vote skip for every slot in the window */
  ag_event_timeout_t timeout = { .kind = AG_EVENT_TIMEOUT, .slot = slot };
  ag_votor_handle_timeout_event( votor, &timeout );

  /* parent becomes ready late: re-checks pending blocks */
  ag_event_pool_t parent_ready = { .kind = AG_EVENT_POOL_PARENT_READY };
  parent_ready.parent_ready.slot   = slot;
  parent_ready.parent_ready.parent = parent;
  ag_votor_handle_pool_event( votor, &parent_ready, 0L );

  /* collect every vote broadcast for slot */
  int                    voted_skip  = 0;
  int                    voted_notar = 0;
  ag_vote_t msg;
  while( try_recv( votor, &msg ) ) {
    if( ag_vote_slot( &msg )!=slot   ) continue;
    if( msg.kind==AG_VOTE_KIND_SKIP  ) voted_skip  = 1;
    if( msg.kind==AG_VOTE_KIND_NOTAR ) voted_notar = 1;
  }

  /* must not notarize slot, which we already voted skip for */
  FD_TEST(  voted_skip  ); /* expected a skip vote for slot */
  FD_TEST( !voted_notar ); /* slot notarized after voting skip (slashable skip-and-notarize) */

  teardown_votor( votor );
}

/* src/consensus/votor.rs::safe_to_notar */

static void
test_safe_to_notar( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  ulong        slot  = 1UL;

  /* wait for skip votes */
  handle_timeouts( votor, TEST_WINDOW_ELAPSED_NS );
  for( ulong s=1UL; s<AG_SLOTS_PER_WINDOW; s++ ) {
    ag_vote_t msg = recv( votor );
    FD_TEST( msg.kind==AG_VOTE_KIND_SKIP );
  }

  /* vote notar-fallback after safe-to-notar */
  ag_block_id_t   block = random_block_id( slot );
  ag_event_pool_t event = { .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = block };
  ag_votor_handle_pool_event( votor, &event, 0L );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_NOTAR_FALLBACK );
  FD_TEST( ag_vote_slot( &msg )==block.slot );
  FD_TEST( !memcmp( msg.notar_fallback.block_hash, block.hash, sizeof(ag_block_hash_t) ) );

  teardown_votor( votor );
}

/* src/consensus/votor.rs::safe_to_skip */

static void
test_safe_to_skip( void ) {
  ag_votor_t *  votor  = setup_votor( 0L );
  ulong         slot   = 1UL;
  ag_block_id_t parent = genesis_block_id();

  /* vote notar after seeing block */
  send_block_and_expect_notar( votor, slot, &parent );

  /* vote skip-fallback after safe-to-skip */
  ag_event_pool_t event = { .kind = AG_EVENT_POOL_SAFE_TO_SKIP, .safe_to_skip = slot };
  ag_votor_handle_pool_event( votor, &event, 0L );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_SKIP_FALLBACK );
  FD_TEST( ag_vote_slot( &msg )==slot );

  teardown_votor( votor );
}

/* src/consensus/votor.rs::prunes_to_finalized_window */

static void
test_prunes_to_finalized_window( void ) {
  ag_votor_t * votor = setup_votor( 0L );

  /* finalize a slot that is NOT first in its window and isn't in the
     genesis window */
  ulong finalized    = AG_SLOTS_PER_WINDOW + 1UL;
  ulong window_start = ag_first_slot_in_window( finalized );
  FD_TEST( window_start>0UL       );
  FD_TEST( window_start<finalized );

  /* populate per-slot state across the previous window and into the next
     one */
  ulong highest = 2UL*AG_SLOTS_PER_WINDOW;
  for( ulong i=1UL; i<=highest; i++ ) {
    ag_event_block_t event = { .kind = AG_EVENT_BLOCK_FIRST_SHRED, .slot = i };
    ag_votor_handle_block_event ( votor, &event );
  }
  for( ulong i=0UL; i<=highest; i++ ) FD_TEST( contains_slot( votor, i ) );

  /* finalizing a mid-window slot should drop only the slots before its
     window */
  ag_vote_t fv; fv = ag_vote_construct_final( sec_sign_fn, &g_sk[1], finalized, (ushort)1, TEST_SHRED_VERSION );
  ag_cert_t cert = cert_build_final( &fv.final, 1UL, g_epoch_info );
  ag_event_pool_t event = { .kind = AG_EVENT_POOL_CERT_CREATED, .cert_created = cert };
  ag_votor_handle_pool_event( votor, &event, 0L );
  FD_TEST( votor->highest_final_cert_slot==finalized );

  /* the finalized window and the reward buffer before it are kept */
  ulong kept_start = ag_first_slot_in_window( fd_ulong_sat_sub( finalized, AG_REWARD_SLOT_DELTA ) );
  FD_TEST( min_live_slot( votor )>=kept_start );
  for( ulong slot=window_start; slot<window_start+AG_SLOTS_PER_WINDOW; slot++ ) {
    FD_TEST( contains_slot( votor, slot ) );
  }

  /* earlier windows are dropped */
  for( ulong slot=0UL; slot<kept_start; slot++ ) FD_TEST( !contains_slot( votor, slot ) );
  for( ulong slot=kept_start; slot<=highest; slot++ ) FD_TEST( contains_slot( votor, slot ) );

  teardown_votor( votor );
}

/* Firedancer-only test.

   Agave extends the skip timeout by 5% per leader window since the slot
   a standstill was detected at, capped at an hour, until a later
   finalization.  timers.rs::test_calculate_timeout_multiplier and
   event_handler.rs::test_received_standstill. */

static void
test_standstill_extends_timeouts( void ) {
  ag_votor_t * votor = setup_votor( 0L );

  FD_TEST( votor->standstill_slot==ULONG_MAX );
  FD_TEST( delta_timeout( votor, 100UL*AG_SLOTS_PER_WINDOW )==AG_DELTA_TIMEOUT_NS );

  ag_event_pool_t standstill = { .kind = AG_EVENT_POOL_STANDSTILL, .standstill = 0UL };
  ag_votor_handle_pool_event( votor, &standstill, 0L );
  FD_TEST( votor->standstill_slot==0UL );
  FD_TEST_NO_MSG( votor );

  long t1 = AG_DELTA_TIMEOUT_NS*21L/20L;
  long t2 = t1*21L/20L;
  FD_TEST( delta_timeout( votor, 0UL                        )==AG_DELTA_TIMEOUT_NS );
  FD_TEST( delta_timeout( votor, AG_SLOTS_PER_WINDOW-1UL    )==AG_DELTA_TIMEOUT_NS );
  FD_TEST( delta_timeout( votor, AG_SLOTS_PER_WINDOW        )==t1                  );
  FD_TEST( delta_timeout( votor, 2UL*AG_SLOTS_PER_WINDOW    )==t2                  );
  FD_TEST( delta_timeout( votor, 1000000UL                  )==AG_TIMEOUT_MAX_NS   );
  FD_TEST( delta_timeout( votor, ULONG_MAX                  )==AG_TIMEOUT_MAX_NS   );

  /* repeated standstill signals keep the slot it was first detected at */

  standstill.standstill = AG_SLOTS_PER_WINDOW;
  ag_votor_handle_pool_event( votor, &standstill, 0L );
  FD_TEST( votor->standstill_slot==0UL );

  /* a window whose parent becomes ready now times out later than the
     genesis window, whose timeouts were set before the standstill */

  ulong slot     = 40UL*AG_SLOTS_PER_WINDOW;
  long  extended = delta_timeout( votor, slot );
  FD_TEST( extended>TEST_WINDOW_ELAPSED_NS );

  ag_event_pool_t parent_ready = { .kind = AG_EVENT_POOL_PARENT_READY };
  parent_ready.parent_ready.slot   = slot;
  parent_ready.parent_ready.parent = random_block_id( slot-1UL );
  ag_votor_handle_pool_event( votor, &parent_ready, 0L );

  handle_timeouts( votor, TEST_WINDOW_ELAPSED_NS );
  for( ulong s=1UL; s<AG_SLOTS_PER_WINDOW; s++ ) {
    ag_vote_t msg = recv( votor );
    FD_TEST( msg.kind==AG_VOTE_KIND_SKIP );
    FD_TEST( ag_vote_slot( &msg )==s );
  }
  FD_TEST_NO_MSG( votor );

  handle_timeouts( votor, extended+TEST_WINDOW_ELAPSED_NS );
  for( ulong s=slot; s<slot+AG_SLOTS_PER_WINDOW; s++ ) {
    ag_vote_t msg = recv( votor );
    FD_TEST( msg.kind==AG_VOTE_KIND_SKIP );
    FD_TEST( ag_vote_slot( &msg )==s );
  }
  FD_TEST_NO_MSG( votor );

  /* finalizing the slot standstill was detected at does not end it,
     finalizing past it does */

  ag_vote_t       fv   = ag_vote_construct_final( sec_sign_fn, &g_sk[1], 0UL, (ushort)1, TEST_SHRED_VERSION );
  ag_event_pool_t cert = { .kind = AG_EVENT_POOL_CERT_CREATED, .cert_created = cert_build_final( &fv.final, 1UL, g_epoch_info ) };
  ag_votor_handle_pool_event( votor, &cert, 0L );
  FD_TEST( votor->standstill_slot==0UL );

  fv                = ag_vote_construct_final( sec_sign_fn, &g_sk[1], 1UL, (ushort)1, TEST_SHRED_VERSION );
  cert.cert_created = cert_build_final( &fv.final, 1UL, g_epoch_info );
  ag_votor_handle_pool_event( votor, &cert, 0L );
  FD_TEST( votor->standstill_slot==ULONG_MAX );
  FD_TEST( delta_timeout( votor, slot )==AG_DELTA_TIMEOUT_NS );

  teardown_votor( votor );
}

/* Firedancer-only test.

   Votor relays a refresh batch from the pool onto its vote and cert
   streams unchanged. */

static void
test_refresh_relayed( void ) {
  ag_votor_t *  votor  = setup_votor( 0L );
  ag_block_id_t parent = genesis_block_id();

  ag_vote_t vote = send_block_and_expect_notar( votor, 1UL, &parent );
  ag_cert_t cert = cert_build_notar( &vote.notar, 1UL, g_epoch_info );

  ag_event_pool_t refresh = { .kind = AG_EVENT_POOL_REFRESH };
  refresh.refresh = (ag_refresh_t){ .slot = 0UL, .certs = &cert, .cert_cnt = 1UL, .votes = &vote, .vote_cnt = 1UL };
  ag_votor_handle_pool_event( votor, &refresh, 0L );

  uchar want[ AG_VOTE_SER_SZ( 1 ) > AG_CERT_SER_MAX ? AG_VOTE_SER_SZ( 1 ) : AG_CERT_SER_MAX ];
  uchar got [ sizeof(want) ];

  ag_vote_t msg     = recv( votor );
  ulong     want_sz = ag_vote_ser( &vote, want );
  FD_TEST( ag_vote_ser( &msg, got )==want_sz );
  FD_TEST( !memcmp( got, want, want_sz ) );
  FD_TEST_NO_MSG( votor );

  ag_event_cert_t cert_event;
  FD_TEST( ag_votor_poll_cert_event( votor, &cert_event ) );
  want_sz = ag_cert_ser( &cert, want );
  FD_TEST( ag_cert_ser( &cert_event.cert, got )==want_sz );
  FD_TEST( !memcmp( got, want, want_sz ) );
  FD_TEST( !ag_votor_poll_cert_event( votor, &cert_event ) );

  /* a refresh is not a state transition: no finalize vote for the
     refreshed notar cert */

  FD_TEST( votor->standstill_slot==ULONG_MAX );
  FD_TEST_NO_MSG( votor );

  teardown_votor( votor );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_timeouts();
  test_notar_and_final();
  test_notar_out_of_order();
  test_pending_block_not_notarized_after_skip();
  test_safe_to_notar();
  test_safe_to_skip();
  test_prunes_to_finalized_window();
  test_standstill_extends_timeouts();
  test_refresh_relayed();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
