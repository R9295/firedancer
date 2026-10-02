#include "ag_invariant.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#define SLOT_MAX (16UL) /* a ring of 32 slots */

static uchar mem[ 1UL<<20 ] __attribute__((aligned(128)));

/* EXPECT_CRIT runs call in a child, which must abort with FD_LOG_CRIT
   logging msg.  The child inherits the invariant's state, so a test
   sets it up first and passes only the violating call.  The child logs
   to a pipe, keeping its expected CRIT out of the test's log file. */

#define EXPECT_CRIT( call, msg ) do {                                 \
    int fds[ 2 ];                                                     \
    FD_TEST( !pipe( fds ) );                                          \
    pid_t pid = fork();                                               \
    FD_TEST( pid>=0 );                                                \
    if( !pid ) {                                                      \
      child_log_to( fds[ 1 ] );                                       \
      call;                                                           \
      _exit( 0 );                                                     \
    }                                                                 \
    expect_crit( pid, fds, (msg) );                                   \
  } while(0)

static void
child_log_to( int fd ) {
  int null_fd = open( "/dev/null", O_WRONLY );
  int log_fd  = fd_log_private_logfile_fd();
  FD_TEST( null_fd>=0 );
  if( log_fd!=-1 ) FD_TEST( dup2( null_fd, log_fd )==log_fd );
  FD_TEST( dup2( fd, STDERR_FILENO )==STDERR_FILENO );
  fd_log_level_logfile_set( 5 ); /* a message below the logfile level reaches neither */
  fd_log_level_stderr_set ( 5 );
}

/* expect_crit collects the child's log until it exits, then checks it
   aborted having logged msg. */

static void
expect_crit( pid_t        pid,
             int          fds[ 2 ],
             char const * msg ) {
  FD_TEST( !close( fds[ 1 ] ) );
  static char log[ 1UL<<16 ];
  ulong       log_sz = 0UL;
  for(;;) {
    char chunk[ 4096 ];
    long n = read( fds[ 0 ], chunk, sizeof(chunk) );
    if( FD_UNLIKELY( n<0L && errno==EINTR ) ) continue;
    if( n<=0L ) break;
    ulong copy = fd_ulong_min( (ulong)n, sizeof(log)-1UL-log_sz ); /* keep draining past a full buffer */
    memcpy( log+log_sz, chunk, copy );
    log_sz += copy;
  }
  log[ log_sz ] = '\0';
  FD_TEST( !close( fds[ 0 ] ) );

  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFSIGNALED( status ) && WTERMSIG( status )==SIGABRT );
  if( FD_UNLIKELY( !strstr( log, msg ) ) ) FD_LOG_ERR(( "expected \"%s\", the child logged:\n%s", msg, log ));
}

/* block names version index of slot, as the votor scenario harness
   does.  Version 0 of slot 0 is the all-zero Alpenglow genesis. */

static ag_block_id_t
block( ulong slot,
       ulong index ) {
  ag_block_id_t id = { .slot = slot };
  FD_STORE( ulong, id.hash,     slot  );
  FD_STORE( ulong, id.hash+8UL, index );
  return id;
}

static ag_invariant_t *
fresh( void ) {
  FD_TEST( ag_invariant_footprint( SLOT_MAX ) && ag_invariant_footprint( SLOT_MAX )<=sizeof(mem) );
  ag_invariant_t * inv = ag_invariant_join( ag_invariant_new( mem, SLOT_MAX ) );
  FD_TEST( inv );
  ag_block_id_t boot = block( 0UL, 0UL );
  ag_invariant_init( inv, &boot );
  return inv;
}

static void
replay( ag_invariant_t * inv,
        ulong            slot,
        ulong            index,
        ulong            parent_slot,
        ulong            parent_index ) {
  ag_block_id_t b = block( slot,        index        );
  ag_block_id_t p = block( parent_slot, parent_index );
  ag_invariant_replay_completed( inv, &b, &p );
}

static void
dead( ag_invariant_t * inv,
      ulong            slot,
      ulong            index ) {
  ag_block_id_t b = block( slot, index );
  ag_invariant_replay_dead( inv, &b );
}

static void
notar_cert( ag_invariant_t * inv,
            ulong            slot,
            ulong            index ) {
  ag_cert_t c; memset( &c, 0, sizeof(c) );
  c.kind       = AG_CERT_KIND_NOTAR;
  c.notar.slot = slot;
  memcpy( c.notar.block_hash, block( slot, index ).hash, sizeof(ag_block_hash_t) );
  ag_invariant_cert_created( inv, &c );
}

static void
vote( ag_invariant_t * inv,
      uint             kind,
      ulong            slot,
      ulong            index ) {
  ag_vote_t v; memset( &v, 0, sizeof(v) );
  v.kind = kind;
  switch( kind ) {
  case AG_VOTE_KIND_NOTAR:          v.notar.slot          = slot; memcpy( v.notar.block_hash,          block( slot, index ).hash, sizeof(ag_block_hash_t) ); break;
  case AG_VOTE_KIND_NOTAR_FALLBACK: v.notar_fallback.slot = slot; memcpy( v.notar_fallback.block_hash, block( slot, index ).hash, sizeof(ag_block_hash_t) ); break;
  case AG_VOTE_KIND_FINAL:          v.final.slot          = slot; break;
  case AG_VOTE_KIND_SKIP:           v.skip.slot           = slot; break;
  case AG_VOTE_KIND_SKIP_FALLBACK:  v.skip_fallback.slot  = slot; break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
  ag_invariant_vote( inv, &v );
}

#define NOTAR( inv, slot, index ) vote( (inv), AG_VOTE_KIND_NOTAR, (slot), (index) )
#define FINAL( inv, slot )        vote( (inv), AG_VOTE_KIND_FINAL, (slot), 0UL     )
#define SKIP( inv, slot )         vote( (inv), AG_VOTE_KIND_SKIP,  (slot), 0UL     )

#define NONE (ULONG_MAX)

/* certs returns a slot's certs: a final cert if final, and a notar and
   fast final cert for the versions named, NONE for none. */

static ag_slot_certs_t
certs( ulong slot,
       int   final,
       ulong notar_index,
       ulong fast_final_index ) {
  ag_slot_certs_t c; memset( &c, 0, sizeof(c) );
  c.notar.slot         = ULONG_MAX;
  c.skip.slot          = ULONG_MAX;
  c.fast_finalize.slot = ULONG_MAX;
  c.finalize.slot      = final ? slot : ULONG_MAX;
  if( notar_index!=NONE ) {
    c.notar.slot = slot;
    memcpy( c.notar.block_hash, block( slot, notar_index ).hash, sizeof(ag_block_hash_t) );
  }
  if( fast_final_index!=NONE ) {
    c.fast_finalize.slot = slot;
    memcpy( c.fast_finalize.block_hash, block( slot, fast_final_index ).hash, sizeof(ag_block_hash_t) );
  }
  return c;
}

/* finalize delivers a finalization event: finalized (NULL for none)
   with its certs, and implicit_cnt implicitly finalized blocks. */

static void
finalize( ag_invariant_t *        inv,
          ag_block_id_t const *   finalized,
          ag_slot_certs_t const * c,
          ag_block_id_t *         implicit,
          ulong                   implicit_cnt ) {
  ag_finalization_event_t event = ag_finalization_event_default( implicit, NULL );
  if( finalized ) event.finalized = *finalized;
  event.implicitly_finalized_cnt = implicit_cnt;
  ag_invariant_finalization( inv, &event, c );
}

static void
test_footprint( void ) {
  FD_TEST( !ag_invariant_footprint( 0UL ) );
  FD_TEST(  ag_invariant_footprint( 1UL ) );
  FD_TEST( !ag_invariant_new( NULL, SLOT_MAX ) );
  FD_TEST( !ag_invariant_new( mem+1, SLOT_MAX ) );
  FD_TEST( !ag_invariant_new( mem, 0UL ) );
}

/* Invariants 1-5 on our own votes. */

static void
test_votes( void ) {
  ag_invariant_t * inv = fresh();

  /* A notar for a replayed block, then a final once its notar cert is
     created, and skips elsewhere.  Fallback votes are not checked. */

  replay( inv, 1UL, 0UL, 0UL, 0UL );
  NOTAR( inv, 1UL, 0UL );
  notar_cert( inv, 1UL, 0UL );
  FINAL( inv, 1UL );
  SKIP( inv, 2UL );
  SKIP( inv, 3UL );
  vote( inv, AG_VOTE_KIND_NOTAR_FALLBACK, 2UL, 5UL );
  vote( inv, AG_VOTE_KIND_SKIP_FALLBACK,  2UL, 0UL );
  vote( inv, AG_VOTE_KIND_SKIP_FALLBACK,  2UL, 0UL );

  /* 1. never notar and skip in the same slot, in either order */

  EXPECT_CRIT( SKIP( inv, 1UL ), "INVARIANT: voted notar and skip in slot 1" );
  replay( inv, 2UL, 0UL, 1UL, 0UL );
  EXPECT_CRIT( NOTAR( inv, 2UL, 0UL ), "INVARIANT: voted notar and skip in slot 2" );

  /* 2. at most one notar per slot, and 3. one skip */

  EXPECT_CRIT( NOTAR( inv, 1UL, 0UL ), "INVARIANT: voted notar twice in slot 1" );
  EXPECT_CRIT( SKIP( inv, 2UL ),       "INVARIANT: voted skip twice in slot 2" );

  /* The boot block counts as voted notar, as ag_votor_init has it */

  EXPECT_CRIT( NOTAR( inv, 0UL, 0UL ), "INVARIANT: voted notar twice in slot 0" );

  /* 4. notar only for a block whose replay completed and was not dead */

# define NOT_REPLAYED( slot ) "INVARIANT: voted notar in slot " #slot " for a block replay did not complete or found dead"
  EXPECT_CRIT( NOTAR( inv, 4UL, 0UL ), NOT_REPLAYED( 4 ) ); /* nothing replayed in slot 4 */
  replay( inv, 5UL, 0UL, 1UL, 0UL );
  EXPECT_CRIT( NOTAR( inv, 5UL, 1UL ), NOT_REPLAYED( 5 ) ); /* another version of slot 5 replayed */
  dead( inv, 6UL, 0UL );
  EXPECT_CRIT( NOTAR( inv, 6UL, 0UL ), NOT_REPLAYED( 6 ) ); /* found dead, never completed */
  replay( inv, 7UL, 0UL, 1UL, 0UL );
  dead( inv, 7UL, 0UL );
  EXPECT_CRIT( NOTAR( inv, 7UL, 0UL ), NOT_REPLAYED( 7 ) ); /* reported both completed and dead */
# undef NOT_REPLAYED
  NOTAR( inv, 5UL, 0UL );

  /* 5. final only after our notar for the block a notar cert names */

# define FINAL_WITHOUT( slot ) "INVARIANT: voted final in slot " #slot " without voting notar for the block a notar cert names"
  EXPECT_CRIT( FINAL( inv, 8UL ), FINAL_WITHOUT( 8 ) ); /* no notar vote */
  EXPECT_CRIT( FINAL( inv, 5UL ), FINAL_WITHOUT( 5 ) ); /* no notar cert */
  notar_cert( inv, 5UL, 1UL );
  EXPECT_CRIT( FINAL( inv, 5UL ), FINAL_WITHOUT( 5 ) ); /* the notar cert names another block */
  EXPECT_CRIT( FINAL( inv, 3UL ), FINAL_WITHOUT( 3 ) ); /* voted skip */

  /* With notar certs for several blocks of a slot, which one the final
     follows is unknown, but our notar is still needed. */

  replay( inv, 9UL, 0UL, 1UL, 0UL );
  NOTAR( inv, 9UL, 0UL );
  notar_cert( inv, 9UL, 1UL );
  notar_cert( inv, 9UL, 2UL );
  FINAL( inv, 9UL );
  notar_cert( inv, 10UL, 0UL );
  notar_cert( inv, 10UL, 1UL );
  EXPECT_CRIT( FINAL( inv, 10UL ), FINAL_WITHOUT( 10 ) );
# undef FINAL_WITHOUT

  /* Replay reporting a block again changes nothing */

  replay( inv, 11UL, 0UL, 1UL, 0UL );
  replay( inv, 11UL, 0UL, 1UL, 0UL );
  NOTAR( inv, 11UL, 0UL );
}

/* A record a later slot took over is unknown: checks needing it pass. */

static void
test_unknown( void ) {
  ag_invariant_t * inv = fresh();
  ulong            cnt = 2UL*SLOT_MAX;

  SKIP( inv, 3UL );
  replay( inv, 3UL+cnt, 0UL, 2UL+cnt, 0UL );
  SKIP( inv, 3UL );
  NOTAR( inv, 3UL, 0UL );
  FINAL( inv, 3UL );

  /* More versions of a slot than are recorded */

  for( ulong i=0UL; i<=AG_INVARIANT_BLOCK_MAX; i++ ) replay( inv, 4UL, i, 1UL, 0UL );
  NOTAR( inv, 4UL, AG_INVARIANT_BLOCK_MAX );
}

/* Invariant 6: a finalized block has a final and notar cert, or a fast
   final cert. */

static void
test_finalized( void ) {
  ag_invariant_t * inv = fresh();
  ag_block_id_t    b1  = block( 1UL, 0UL );
  ag_block_id_t    b2  = block( 2UL, 0UL );

  ag_slot_certs_t final_notar = certs( 1UL, 1, 0UL,  NONE );
  ag_slot_certs_t fast_final  = certs( 2UL, 0, NONE, 0UL  );
  finalize( inv, &b1, &final_notar, NULL, 0UL );
  finalize( inv, &b2, &fast_final,  NULL, 0UL );

  ag_block_id_t   b3            = block( 3UL, 0UL );
  ag_slot_certs_t final_only    = certs( 3UL, 1, NONE, NONE );
  ag_slot_certs_t notar_only    = certs( 3UL, 0, 0UL,  NONE );
  ag_slot_certs_t notar_other   = certs( 3UL, 1, 1UL,  NONE );
  ag_slot_certs_t fast_other    = certs( 3UL, 0, NONE, 1UL  );
# define NO_CERTS "INVARIANT: finalized slot 3 without a final and notar cert or a fast final cert"
  EXPECT_CRIT( finalize( inv, &b3, NULL,         NULL, 0UL ), NO_CERTS );
  EXPECT_CRIT( finalize( inv, &b3, &final_only,  NULL, 0UL ), NO_CERTS );
  EXPECT_CRIT( finalize( inv, &b3, &notar_only,  NULL, 0UL ), NO_CERTS );
  EXPECT_CRIT( finalize( inv, &b3, &notar_other, NULL, 0UL ), NO_CERTS );
  EXPECT_CRIT( finalize( inv, &b3, &fast_other,  NULL, 0UL ), NO_CERTS );
# undef NO_CERTS

  /* An event that finalizes nothing directly needs no certs */

  finalize( inv, NULL, NULL, NULL, 0UL );
}

/* Invariant 7: an implicitly finalized block has a finalized descendant
   that replay's parent links lead down to. */

static void
test_implicitly_finalized( void ) {
  ag_invariant_t * inv = fresh();

  /* 0 <- 1a <- 2a <- 4a, and a fork 0 <- 1a <- 3b */

  replay( inv, 1UL, 0UL, 0UL, 0UL );
  replay( inv, 2UL, 0UL, 1UL, 0UL );
  replay( inv, 3UL, 1UL, 1UL, 0UL );
  replay( inv, 4UL, 0UL, 2UL, 0UL );

  ag_block_id_t   b4    = block( 4UL, 0UL );
  ag_slot_certs_t c4    = certs( 4UL, 0, NONE, 0UL );
  ag_block_id_t   anc[] = { block( 2UL, 0UL ), block( 1UL, 0UL ), block( 0UL, 0UL ) };
  finalize( inv, &b4, &c4, anc, 3UL );

  ag_block_id_t off   = block( 3UL, 1UL ); /* replayed, but off 4a's chain */
  ag_block_id_t other = block( 2UL, 1UL ); /* never replayed */
  ag_block_id_t above = block( 5UL, 0UL ); /* nothing finalized above it */
# define NO_DESCENDANT( slot ) "INVARIANT: implicitly finalized slot " #slot " without a finalized descendant linked to it"
  EXPECT_CRIT( finalize( inv, NULL, NULL, &off,   1UL ), NO_DESCENDANT( 3 ) );
  EXPECT_CRIT( finalize( inv, NULL, NULL, &other, 1UL ), NO_DESCENDANT( 2 ) );
  EXPECT_CRIT( finalize( inv, NULL, NULL, &above, 1UL ), NO_DESCENDANT( 5 ) );

  /* A parent link replay reports after its child was finalized: 6a is
     finalized first, then 5a completes as its parent. */

  replay( inv, 6UL, 0UL, 5UL, 0UL );
  ag_block_id_t   b6 = block( 6UL, 0UL );
  ag_slot_certs_t c6 = certs( 6UL, 1, 0UL, NONE );
  finalize( inv, &b6, &c6, NULL, 0UL );
  replay( inv, 5UL, 0UL, 4UL, 0UL );
  ag_block_id_t b5 = block( 5UL, 0UL );
  finalize( inv, NULL, NULL, &b5, 1UL );

  /* With nothing finalized at all */

  inv = fresh();
  replay( inv, 1UL, 0UL, 0UL, 0UL );
  ag_block_id_t b1 = block( 1UL, 0UL );
  EXPECT_CRIT( finalize( inv, NULL, NULL, &b1, 1UL ), NO_DESCENDANT( 1 ) );
# undef NO_DESCENDANT

  /* A link a later slot took over is unknown */

  ulong cnt = 2UL*SLOT_MAX;
  replay( inv, 2UL, 0UL, 1UL, 0UL );
  ag_block_id_t   b2 = block( 2UL, 0UL );
  ag_slot_certs_t c2 = certs( 2UL, 0, NONE, 0UL );
  finalize( inv, &b2, &c2, NULL, 0UL );
  replay( inv, 2UL+cnt, 0UL, 1UL+cnt, 0UL );
  finalize( inv, NULL, NULL, &b1, 1UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_footprint();
  test_votes();
  test_unknown();
  test_finalized();
  test_implicitly_finalized();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
