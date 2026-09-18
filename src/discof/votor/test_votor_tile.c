#include "../../waltz/quic/fd_quic.h"
#include "../../waltz/quic/fd_quic_conn.h"

static fd_quic_conn_t *
mock_quic_connect( fd_quic_t * quic,
                   uint        dst_ip_addr,
                   ushort      dst_udp_port,
                   uint        src_ip_addr,
                   ushort      src_udp_port,
                   long        now );

static void
mock_quic_conn_close( fd_quic_conn_t * conn,
                      uint             reason );

/* Keep this test at the Votor connection-state-machine boundary.  Real QUIC
   owns connection lifetime; the mocks below let the test explicitly deliver
   conn_final after an asynchronous close. */

#define fd_quic_connect    mock_quic_connect
#define fd_quic_conn_close mock_quic_conn_close
#include "fd_votor_tile.c"
#undef fd_quic_connect
#undef fd_quic_conn_close

#define MOCK_CONN_MAX (4UL)

static fd_quic_conn_t mock_conns[ MOCK_CONN_MAX ];
static ulong          mock_connect_call_cnt;
static ulong          mock_connect_fail_cnt;
static ulong          mock_conn_cnt;
static ulong          mock_close_call_cnt;
static uint           mock_close_reason;

static fd_quic_conn_t *
mock_quic_connect( fd_quic_t * quic,
                   uint        dst_ip_addr,
                   ushort      dst_udp_port,
                   uint        src_ip_addr,
                   ushort      src_udp_port,
                   long        now ) {
  (void)quic;
  (void)dst_ip_addr;
  (void)dst_udp_port;
  (void)src_ip_addr;
  (void)src_udp_port;
  (void)now;

  mock_connect_call_cnt++;
  if( FD_UNLIKELY( mock_connect_fail_cnt ) ) {
    mock_connect_fail_cnt--;
    return NULL;
  }

  FD_TEST( mock_conn_cnt<MOCK_CONN_MAX );
  fd_quic_conn_t * conn = &mock_conns[ mock_conn_cnt ];
  fd_memset( conn, 0, sizeof(fd_quic_conn_t) );
  conn->conn_idx = (uint)mock_conn_cnt;
  conn->conn_gen = (uint)(mock_conn_cnt+1UL);
  conn->state    = FD_QUIC_CONN_STATE_HANDSHAKE;
  mock_conn_cnt++;
  return conn;
}

static void
mock_quic_conn_close( fd_quic_conn_t * conn,
                      uint             reason ) {
  FD_TEST( conn );
  mock_close_call_cnt++;
  mock_close_reason = reason;
  conn->state       = FD_QUIC_CONN_STATE_CLOSE_PENDING;
}

static void
test_client_reconnect( void ) {
  static fd_votor_tile_t ctx[ 1 ];
  static peer_t          peer_mem        [ 1UL<<PEERS_LG_SLOT_CNT        ];
  static contact_info_t  contact_info_mem[ 1UL<<CONTACT_INFOS_LG_SLOT_CNT ];

  fd_memset( ctx, 0, sizeof(fd_votor_tile_t) );
  ctx->peers         = peers_join        ( peers_new        ( peer_mem         ) );
  ctx->contact_infos = contact_infos_join( contact_infos_new( contact_info_mem ) );
  ctx->id_key.ul[ 0 ] = 1UL;

  fd_pubkey_t peer_id = { .ul = { 2UL, 0UL, 0UL, 0UL } };
  peer_t * peer = peers_insert( ctx->peers, peer_id );
  FD_TEST( peer );
  peer->prev_rank        = 0U;
  peer->curr_rank        = 0U;
  peer->next_rank        = USHORT_MAX;
  peer->tx_conn          = NULL;
  peer->rx_conn          = NULL;
  peer->ban_ts           = 0L;
  peer->connect_deadline = LONG_MAX;

  contact_info_t * ci = contact_infos_insert( ctx->contact_infos, peer_id );
  FD_TEST( ci );
  ci->ip4 = 0x0100007fU;
  ci->port = 9000U;

  mock_connect_call_cnt = 0UL;
  mock_connect_fail_cnt = 1UL;
  mock_conn_cnt         = 0UL;
  mock_close_call_cnt   = 0UL;
  mock_close_reason     = 0U;

  long const start = QUIC_BAN_TIMEOUT_NS+10L*QUIC_RECONCILE_NS;

  /* A transient synchronous fd_quic_connect failure leaves no sticky state;
     the next reconciliation attempts the peer again. */

  quic_client_reconcile( ctx, start );
  FD_TEST( mock_connect_call_cnt==1UL );
  FD_TEST( !peer->tx_conn );
  FD_TEST( peer->connect_deadline==LONG_MAX );

  quic_client_reconcile( ctx, start+QUIC_RECONCILE_NS );
  FD_TEST( mock_connect_call_cnt==2UL );
  FD_TEST( mock_conn_cnt==1UL );
  fd_quic_conn_t * first = &mock_conns[ 0 ];
  FD_TEST( peer->tx_conn==first );
  FD_TEST( peer->connect_deadline==start+QUIC_RECONCILE_NS+QUIC_HANDSHAKE_TIMEOUT_NS );

  /* A pending handshake is retained until its deadline, then closed exactly
     once.  The asynchronous close must not overlap a replacement dial. */

  long const deadline = peer->connect_deadline;
  quic_client_reconcile( ctx, deadline-1L );
  FD_TEST( mock_close_call_cnt==0UL );
  FD_TEST( mock_connect_call_cnt==2UL );

  quic_client_reconcile( ctx, deadline );
  FD_TEST( mock_close_call_cnt==1UL );
  FD_TEST( mock_close_reason==QUIC_CLOSE_CODE_HANDSHAKE_TIMEOUT );
  FD_TEST( peer->tx_conn==first );
  FD_TEST( peer->connect_deadline==LONG_MAX );
  FD_TEST( mock_connect_call_cnt==2UL );

  quic_client_reconcile( ctx, deadline+1L );
  FD_TEST( mock_close_call_cnt==1UL );
  FD_TEST( mock_connect_call_cnt==2UL );

  /* QUIC delivers conn_final before freeing the connection.  It clears the
     matching attempt; only then may the next periodic reconciliation install
     a new one. */

  ctx->next_reconcile = 123L;
  quic_client_conn_final( first, ctx );
  FD_TEST( !peer->tx_conn );
  FD_TEST( peer->connect_deadline==LONG_MAX );
  FD_TEST( ctx->next_reconcile==123L );

  quic_client_reconcile( ctx, deadline+1L );
  FD_TEST( mock_connect_call_cnt==3UL );
  FD_TEST( mock_conn_cnt==2UL );
  fd_quic_conn_t * second = &mock_conns[ 1 ];
  FD_TEST( peer->tx_conn==second );

  /* A valid handshake retires the attempt deadline. */

  static fd_quic_tls_hs_t tls_hs[ 1 ];
  fd_memset( tls_hs, 0, sizeof(fd_quic_tls_hs_t) );
  fd_memcpy( tls_hs->hs.cli.server_pubkey, peer_id.uc, sizeof(fd_pubkey_t) );
  second->tls_hs = tls_hs;
  second->state  = FD_QUIC_CONN_STATE_ACTIVE;
  quic_client_conn_hs_complete( second, ctx );
  FD_TEST( peer->connect_deadline==LONG_MAX );

  /* The timeout is only for handshakes.  An ACTIVE connection remains valid
     even after the attempt's old deadline. */

  long const second_deadline = deadline+QUIC_HANDSHAKE_TIMEOUT_NS;
  peer->connect_deadline = second_deadline;
  quic_client_reconcile( ctx, second_deadline );
  FD_TEST( peer->tx_conn==second );
  FD_TEST( mock_close_call_cnt==1UL );
  FD_TEST( mock_connect_call_cnt==3UL );

  /* A stale final callback from an older generation must not clear the live
     replacement or perturb its retry schedule. */

  ctx->next_reconcile = 456L;
  quic_client_conn_final( first, ctx );
  FD_TEST( peer->tx_conn==second );
  FD_TEST( peer->connect_deadline==second_deadline );
  FD_TEST( ctx->next_reconcile==456L );
}

/* Build an aggregate whose bytes are a function of tag, so a test can
   tell which aggregate ended up in which field of the published
   message. */

static fd_bls_agg_t
mock_agg( uchar tag ) {
  fd_bls_agg_t agg;
  fd_memset( &agg, tag, sizeof(fd_bls_agg_t) );
  return agg;
}

static fd_votor_tile_t *
join_certed_ctx( void ) {
  static fd_votor_tile_t ctx[ 1 ];

  fd_memset( ctx, 0, sizeof(fd_votor_tile_t) );
  void * publish_mem = aligned_alloc( publishes_align(), fd_ulong_align_up( publishes_footprint( 16UL ), publishes_align() ) );
  FD_TEST( publish_mem );
  ctx->publishes = publishes_join( publishes_new( publish_mem, 16UL ) );
  FD_TEST( ctx->publishes );
  for( ulong i=0UL; i<CERT_SLOT_MAX; i++ ) ctx->final_notar_join[ i ].slot = ULONG_MAX;
  return ctx;
}

static void
push_notar( fd_votor_tile_t * ctx,
            ulong             slot,
            uchar             hash_tag,
            uchar             agg_tag ) {
  ag_cert_t cert;
  fd_memset( &cert, 0, sizeof(ag_cert_t) );
  cert.kind       = AG_CERT_KIND_NOTAR;
  cert.notar.slot = slot;
  cert.notar.agg  = mock_agg( agg_tag );
  fd_memset( cert.notar.block_hash, hash_tag, sizeof(ag_block_hash_t) );
  publish_cert_created( ctx, &cert );
}

static void
push_final( fd_votor_tile_t * ctx,
            ulong             slot,
            uchar             agg_tag ) {
  ag_cert_t cert;
  fd_memset( &cert, 0, sizeof(ag_cert_t) );
  cert.kind       = AG_CERT_KIND_FINAL;
  cert.final.slot = slot;
  cert.final.agg  = mock_agg( agg_tag );
  publish_cert_created( ctx, &cert );
}

/* A slow finalization needs both a FINAL and a NOTAR for the same slot,
   and the two certificates are created independently.  Whichever
   arrives second must publish the joined message, and FINAL must never
   be published alone. */

static void
test_final_notar_join( void ) {
  fd_votor_tile_t * ctx = join_certed_ctx();

  /* NOTAR first: it publishes itself, then FINAL completes the pair. */

  push_notar( ctx, 10UL, 0xa1, 0xb1 );
  FD_TEST( publishes_cnt( ctx->publishes )==1UL );
  publish_t pub = publishes_pop( ctx->publishes );
  FD_TEST( pub.sig==FD_VOTOR_SIG_CERTED );
  FD_TEST( pub.msg.certed.kind==AG_CERT_KIND_NOTAR );
  FD_TEST( pub.msg.certed.slot==10UL );

  push_final( ctx, 10UL, 0xc1 );
  FD_TEST( publishes_cnt( ctx->publishes )==1UL );
  pub = publishes_pop( ctx->publishes );
  FD_TEST( pub.sig==FD_VOTOR_SIG_CERTED );
  FD_TEST( pub.msg.certed.kind==AG_CERT_KIND_FINAL );
  FD_TEST( pub.msg.certed.slot==10UL );
  FD_TEST( pub.msg.certed.agg.set[ 0 ]==mock_agg( 0xc1 ).set[ 0 ] );
  FD_TEST( pub.msg.certed.agg2.set[ 0 ]==mock_agg( 0xb1 ).set[ 0 ] );
  FD_TEST( pub.msg.certed.block_id.uc[ 0 ]==0xa1 );

  /* FINAL first: nothing is published until its NOTAR arrives, and then
     the NOTAR and the joined FINAL are published in that order. */

  push_final( ctx, 11UL, 0xc2 );
  FD_TEST( publishes_empty( ctx->publishes ) );

  push_notar( ctx, 11UL, 0xa2, 0xb2 );
  FD_TEST( publishes_cnt( ctx->publishes )==2UL );
  pub = publishes_pop( ctx->publishes );
  FD_TEST( pub.msg.certed.kind==AG_CERT_KIND_NOTAR );
  FD_TEST( pub.msg.certed.slot==11UL );
  FD_TEST( pub.msg.certed.agg.set[ 0 ]==mock_agg( 0xb2 ).set[ 0 ] );

  pub = publishes_pop( ctx->publishes );
  FD_TEST( pub.msg.certed.kind==AG_CERT_KIND_FINAL );
  FD_TEST( pub.msg.certed.slot==11UL );
  FD_TEST( pub.msg.certed.agg.set[ 0 ]==mock_agg( 0xc2 ).set[ 0 ] );
  FD_TEST( pub.msg.certed.agg2.set[ 0 ]==mock_agg( 0xb2 ).set[ 0 ] );
  FD_TEST( pub.msg.certed.block_id.uc[ 0 ]==0xa2 );

  /* The pair is published once.  A duplicate NOTAR does not re-join a
     FINAL that was already reported. */

  push_notar( ctx, 11UL, 0xa2, 0xb2 );
  FD_TEST( publishes_cnt( ctx->publishes )==1UL );
  pub = publishes_pop( ctx->publishes );
  FD_TEST( pub.msg.certed.kind==AG_CERT_KIND_NOTAR );

  /* Entries are keyed by slot modulo CERT_SLOT_MAX.  A slot that evicts
     a half-populated entry must not inherit its partner. */

  push_final( ctx, 12UL, 0xc3 );
  FD_TEST( publishes_empty( ctx->publishes ) );

  push_notar( ctx, 12UL+CERT_SLOT_MAX, 0xa4, 0xb4 );
  FD_TEST( publishes_cnt( ctx->publishes )==1UL );
  pub = publishes_pop( ctx->publishes );
  FD_TEST( pub.msg.certed.kind==AG_CERT_KIND_NOTAR );
  FD_TEST( pub.msg.certed.slot==12UL+CERT_SLOT_MAX );

  /* A fast finalization is self-contained and is published immediately,
     without consulting the join table. */

  ag_cert_t fast;
  fd_memset( &fast, 0, sizeof(ag_cert_t) );
  fast.kind            = AG_CERT_KIND_FAST_FINAL;
  fast.fast_final.slot = 13UL;
  fast.fast_final.agg  = mock_agg( 0xd1 );
  fd_memset( fast.fast_final.block_hash, 0xa5, sizeof(ag_block_hash_t) );
  publish_cert_created( ctx, &fast );
  FD_TEST( publishes_cnt( ctx->publishes )==1UL );
  pub = publishes_pop( ctx->publishes );
  FD_TEST( pub.msg.certed.kind==AG_CERT_KIND_FAST_FINAL );
  FD_TEST( pub.msg.certed.slot==13UL );
  FD_TEST( pub.msg.certed.agg.set[ 0 ]==mock_agg( 0xd1 ).set[ 0 ] );
  FD_TEST( pub.msg.certed.block_id.uc[ 0 ]==0xa5 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_client_reconnect();
  test_final_notar_join();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
