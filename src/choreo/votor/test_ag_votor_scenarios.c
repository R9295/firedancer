/* test_ag_votor_scenarios drives a votor wired to a pool, as the votor
   tile does, through scenarios and checks its invariants.

     test_ag_votor_scenarios [--jobs N] <file|pattern>...

   Quoted patterns are expanded with glob, which avoids the shell's
   argument limit on large corpora.

   A scenario is a JSON list of actions on a block tree:

     [ { "node": "1a", "parent": "0",  "action": "NOTARIZE_CERT", "part": 0 },
       { "action": "CLOCK", "ms": 100 },
       { "node": "2b", "parent": "1a", "action": "REPLAY_COMPLETE" } ]

   NOTARIZE_CERT and SKIP_CERT parts 0, 1, 2 each deliver disjoint votes
   with 20% stake.  Without "part", an older input delivers all three
   parts in sequence, pumping events between them.

   Labels are a slot, then the block's index in letters (a, ..., z, aa).
   The canonical chain runs from the root to the leftmost deepest block
   that is not skipped.

   Scenarios run in N forked workers.  The first failure stops the
   suite: its worker logs the backtrace, then the suite prints the
   failing input and exits nonzero.

   Requires EXTRAS=no-cert-verify: direct certificate templates have
   synthetic signatures; the partial and local votes are signed. */

#include <errno.h>
#include <execinfo.h>
#include <glob.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ag_pool.c" /* reads the pool's finality tracker */
#include "ag_votor.h"
#include "test_ag_cert_builder.h"
#include "../../ballet/json/fd_jtok.h"
#include "../../util/log/fd_backtrace.h"

#if FD_HAS_COVERAGE
extern int __llvm_profile_write_file( void );
extern void __llvm_profile_set_filename( char const * filename );
#endif

#define VALIDATOR_CNT          (20UL)
#define QUORUM_SIGNERS         (11UL) /* validators 1 to 11, 63.4% of stake */
#define STRONG_QUORUM_SIGNERS  (16UL) /* validators 1 to 16, 82.4% of stake */
#define FALLBACK_NOTAR_SIGNERS (5UL)  /* of a notar fallback cert's signers, how many vote notar */
#define SHRED_VERSION          ((ushort)0x5a5a)
#define NS_PER_SLOT            (400000000L)
#define NS_EVERY_TIMEOUT       (1000000000000L)
#define CERT_PART_CNT          (3UL)
#define CERT_PART_SIGNERS      (4UL)

/* Each group has two 620k-stake and two 380k-stake validators, exactly
   20% of the 10M total.  The three disjoint groups form a 60% cert. */
static ushort const cert_part_rank[ CERT_PART_CNT ][ CERT_PART_SIGNERS ] = {
  { 1, 2, 10, 11 },
  { 3, 4, 12, 13 },
  { 5, 6, 14, 15 }
};

enum { NOTARIZE_CERT, FINALIZE_CERT, NOTAR_FALLBACK_CERT, FAST_FINALIZE_CERT, SKIP_CERT,
       REPLAY_ARRIVES, REPLAY_COMPLETE, REPLAY_DEAD, CLOCK, STANDSTILL, ACTION_KIND_CNT };

#define CERT_CNT (REPLAY_ARRIVES)

static char const * const action_kind_name[ ACTION_KIND_CNT ] = {
  "NOTARIZE_CERT", "FINALIZE_CERT", "NOTAR_FALLBACK_CERT", "FAST_FINALIZE_CERT", "SKIP_CERT",
  "REPLAY_ARRIVES", "REPLAY_COMPLETE", "REPLAY_DEAD", "CLOCK", "STANDSTILL"
};

enum { CANONICAL_NONE, CANONICAL_BLOCK, CANONICAL_SKIP };

typedef struct {
  ulong slot;
  ulong index;
} label_t;

typedef struct {
  uint    kind;
  label_t label;
  label_t parent;
  ulong   ms;
  ulong   part; /* 0, 1, 2 for a 20% notar/skip message; ULONG_MAX for legacy actions */
} action_t;

typedef struct {
  label_t       label;
  label_t       parent;
  uint          kinds;           /* bit per action kind, 0 if no action names the node */
  int           replayed;
  int           dead;
  ag_block_id_t replayed_parent;
} node_t;

typedef struct {
  int             canonical; /* CANONICAL_* */
  ag_block_id_t   canonical_block;
  int             voted_notar;
  int             voted_skip;
  int             voted_final;
  int             voted_notar_fallback;
  int             voted_skip_fallback;
  ag_block_hash_t voted_notar_hash;
  ag_block_hash_t voted_notar_fallback_hash;
} slot_t;

/* A cert offered to the pool, by name and label, deduped, for tracing */

typedef struct {
  char const * name;
  label_t      label;
  int          slot_only; /* final and skip certs name only a slot */
} cert_ref_t;

typedef struct {
  action_t * actions;
  ulong      action_cnt;
  node_t *   nodes;           /* by slot, then index */
  ulong      node_cnt;
  ulong      width;           /* highest index+1 */
  ulong      slot_cnt;        /* the root's slot to the deepest */
  ulong      vote_slot_cnt;
  slot_t *   slots;           /* vote_slot_cnt of them */
  ulong      canonical_final; /* deepest directly finalized canonical slot */
  cert_ref_t * certs;        /* certs offered to the pool, deduped */
  ulong        cert_cnt;
} scenario_t;

static ag_epoch_info_t epoch_info;
static fd_bls_sec_t    validator_sk[ VALIDATOR_CNT ];
static fd_bls_sig_t    fake_sig;
static ag_cert_t       templates[ CERT_CNT ];
static fd_bls_set_t    bad[ fd_bls_set_word_cnt ];

static void
fake_sign_fn( void *         ctx,
              fd_bls_sig_t * sig,
              uchar const *  public_key,
              uchar const *  msg,
              ulong          msg_sz ) {
  (void)ctx; (void)public_key; (void)msg; (void)msg_sz;
  *sig = fake_sig;
}

static ag_block_id_t
block_id( label_t label ) {
  ag_block_id_t id = { .slot = label.slot };
  FD_STORE( ulong, id.hash,     label.slot  );
  FD_STORE( ulong, id.hash+8UL, label.index );
  return id;
}

/* Direct certificate templates use fake_sig, so their aggregates depend
   only on their signers: each cert is its kind's template, renamed. */

static ag_cert_t
cert( uint    kind,
      label_t label ) {
  ag_cert_t     c  = templates[ kind ];
  ag_block_id_t id = block_id( label );
  switch( c.kind ) {
  case AG_CERT_KIND_FINAL:          c.final.slot          = label.slot; break;
  case AG_CERT_KIND_SKIP:           c.skip.slot           = label.slot; break;
  case AG_CERT_KIND_NOTAR:          c.notar.slot          = label.slot; memcpy( c.notar.block_hash,          id.hash, sizeof(ag_block_hash_t) ); break;
  case AG_CERT_KIND_NOTAR_FALLBACK: c.notar_fallback.slot = label.slot; memcpy( c.notar_fallback.block_hash, id.hash, sizeof(ag_block_hash_t) ); break;
  case AG_CERT_KIND_FAST_FINAL:     c.fast_final.slot     = label.slot; memcpy( c.fast_final.block_hash,     id.hash, sizeof(ag_block_hash_t) ); break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
  return c;
}

/* Keys and stakes the cluster, and builds one template per cert kind. */

static void
cluster_init( void ) {
  ag_validator_info_t info[ VALIDATOR_CNT ];
  for( ulong i=0UL; i<VALIDATOR_CNT; i++ ) {
    uchar ikm[ 32 ] = {0};
    FD_STORE( ulong, ikm, i );
    fd_bls_sec_t * sk = &validator_sk[i];
    fd_bls_sec_derive( sk, ikm, sizeof(ikm) );
    info[i].id    = i;
    info[i].stake = i<10UL ? 620000UL : 380000UL;
    bls_key_from_sec( info[i].bls_key, sk );
    if( !i ) sec_sign_fn( sk, &fake_sig, info[i].bls_key, (uchar const *)"votor", 5UL );
  }
  epoch_info_build( &epoch_info, info, VALIDATOR_CNT );
  for( ulong part=0UL; part<CERT_PART_CNT; part++ ) {
    ulong stake = 0UL;
    for( ulong i=0UL; i<CERT_PART_SIGNERS; i++ ) stake += info[ cert_part_rank[ part ][ i ] ].stake;
    FD_TEST( stake*5UL==epoch_info.total_stake );
  }

  /* Validator 0 is the votor under test and never signs */
  ulong                    slot = 1UL;
  ag_block_id_t            id   = block_id( (label_t){ .slot = slot } );
  ag_vote_final_t          final   [ QUORUM_SIGNERS ];
  ag_vote_skip_t           skip    [ QUORUM_SIGNERS ];
  ag_vote_notar_t          notar   [ STRONG_QUORUM_SIGNERS ];
  ag_vote_notar_fallback_t fallback[ QUORUM_SIGNERS-FALLBACK_NOTAR_SIGNERS ];
  for( ushort rank=1; rank<=STRONG_QUORUM_SIGNERS; rank++ ) {
    notar[ rank-1 ] = ag_vote_construct_notar( fake_sign_fn, NULL, info[rank].bls_key, slot, id.hash, rank, SHRED_VERSION ).notar;
    if( rank>QUORUM_SIGNERS ) continue;
    final[ rank-1 ] = ag_vote_construct_final( fake_sign_fn, NULL, info[rank].bls_key, slot, rank, SHRED_VERSION ).final;
    skip [ rank-1 ] = ag_vote_construct_skip ( fake_sign_fn, NULL, info[rank].bls_key, slot, rank, SHRED_VERSION ).skip;
    if( rank>FALLBACK_NOTAR_SIGNERS ) fallback[ rank-1-FALLBACK_NOTAR_SIGNERS ] = ag_vote_construct_notar_fallback( fake_sign_fn, NULL, info[rank].bls_key, slot, id.hash, rank, SHRED_VERSION ).notar_fallback;
  }
  templates[ NOTARIZE_CERT       ] = cert_build_notar         ( notar, QUORUM_SIGNERS, &epoch_info );
  templates[ FINALIZE_CERT       ] = cert_build_final         ( final, QUORUM_SIGNERS, &epoch_info );
  templates[ NOTAR_FALLBACK_CERT ] = cert_build_notar_fallback( notar, FALLBACK_NOTAR_SIGNERS, fallback, QUORUM_SIGNERS-FALLBACK_NOTAR_SIGNERS, &epoch_info );
  templates[ FAST_FINALIZE_CERT  ] = cert_build_fast_final    ( notar, STRONG_QUORUM_SIGNERS, &epoch_info );
  templates[ SKIP_CERT           ] = cert_build_skip          ( skip,  QUORUM_SIGNERS, NULL, 0UL, &epoch_info );
}

/* Parsing.  A malformed scenario is a failure. */

/* Parses "0", or a slot then letters: a is index 0, z 25, aa 26. */

static label_t
label_parse( fd_jtok_t * j ) {
  char s[ 32 ];
  fd_jtok_cstr( j, s, sizeof(s) );
  if( !strcmp( s, "0" ) ) return (label_t){ 0 };
  label_t      label = { 0 };
  char const * c     = s;
  if( *c<'1' || *c>'9' ) FD_LOG_ERR(( "bad label \"%s\"", s ));
  for( ; *c>='0' && *c<='9'; c++ ) label.slot = label.slot*10UL + (ulong)( *c-'0' );
  if( *c<'a' || *c>'z' ) FD_LOG_ERR(( "bad label \"%s\"", s ));
  for( ; *c>='a' && *c<='z'; c++ ) label.index = label.index*26UL + (ulong)( *c-'a' ) + 1UL;
  if( *c ) FD_LOG_ERR(( "bad label \"%s\"", s ));
  label.index--;
  return label;
}

static uint
action_kind_parse( fd_jtok_str_t const * s ) {
  for( uint kind=0U; kind<ACTION_KIND_CNT; kind++ ) {
    if( fd_jtok_str_eq( s, action_kind_name[ kind ] ) ) return kind;
  }
  FD_LOG_ERR(( "unknown action" ));
}

static node_t *
node_find( scenario_t const * s,
           label_t            label ) {
  if( label.slot>=s->slot_cnt || label.index>=s->width ) return NULL;
  node_t * n = &s->nodes[ label.slot*s->width+label.index ];
  return n->kinds ? n : NULL;
}

/* The node a block hash names, as block_id encodes it, or NULL. */

static node_t *
node_of_block( scenario_t const * s,
               ulong              slot,
               uchar const *      hash ) {
  if( FD_LOAD( ulong, hash )!=slot ) return NULL;
  return node_find( s, (label_t){ .slot = slot, .index = FD_LOAD( ulong, hash+8UL ) } );
}

/* Parses the JSON action list, failing on any malformed action. */

static void
actions_parse( scenario_t * s,
               uchar const * data,
               ulong         size ) {
  ulong action_max = 0UL;
  fd_jtok_t     j[1];
  fd_jtok_str_t key;
  fd_jtok_init( j, data, size );
  fd_jtok_arr_enter( j );
  while( fd_jtok_arr_next( j ) ) {
    if( s->action_cnt==action_max ) {
      action_max = fd_ulong_max( 64UL, 2UL*action_max );
      s->actions = realloc( s->actions, action_max*sizeof(action_t) );
      FD_TEST( s->actions );
    }
    action_t * a          = &s->actions[ s->action_cnt++ ];
    int        has_node   = 0;
    int        has_parent = 0;
    *a = (action_t){ .kind = UINT_MAX, .ms = ULONG_MAX, .part = ULONG_MAX };
    fd_jtok_obj_enter( j );
    while( fd_jtok_obj_next( j, &key ) ) {
      if(      fd_jtok_str_eq( &key, "node"   ) ) { a->label  = label_parse( j ); has_node   = 1; }
      else if( fd_jtok_str_eq( &key, "parent" ) ) { a->parent = label_parse( j ); has_parent = 1; }
      else if( fd_jtok_str_eq( &key, "ms"     ) ) fd_jtok_ulong( j, &a->ms );
      else if( fd_jtok_str_eq( &key, "part"   ) ) fd_jtok_ulong( j, &a->part );
      else if( fd_jtok_str_eq( &key, "action" ) ) {
        fd_jtok_str_t kind;
        fd_jtok_str( j, &kind );
        a->kind = action_kind_parse( &kind );
      }
    }
    if( fd_jtok_err( j ) ) FD_LOG_ERR(( "malformed action %lu", s->action_cnt-1UL ));
    int ok = a->kind==CLOCK      ? !has_node && !has_parent && a->ms!=ULONG_MAX && a->part==ULONG_MAX
           : a->kind==STANDSTILL ? !has_node && !has_parent && a->ms==ULONG_MAX && a->part==ULONG_MAX
           : a->kind!=UINT_MAX && has_node && has_parent && a->label.slot && a->parent.slot<a->label.slot &&
             ( (a->kind==NOTARIZE_CERT || a->kind==SKIP_CERT) ? (a->part==ULONG_MAX || a->part<CERT_PART_CNT) : a->part==ULONG_MAX );
    if( !ok ) FD_LOG_ERR(( "bad action %lu", s->action_cnt-1UL ));
  }
  if( fd_jtok_fini( j ) ) FD_LOG_ERR(( "malformed JSON" ));
}

/* Lays nodes out by slot then index, merging what each node's actions say. */

static void
nodes_build( scenario_t * s ) {
  for( ulong i=0UL; i<s->action_cnt; i++ ) {
    if( s->actions[i].kind==CLOCK || s->actions[i].kind==STANDSTILL ) continue;
    s->slot_cnt = fd_ulong_max( s->slot_cnt, s->actions[i].label.slot +1UL );
    s->width    = fd_ulong_max( s->width,    s->actions[i].label.index+1UL );
  }
  s->nodes = calloc( s->slot_cnt*s->width, sizeof(node_t) );
  FD_TEST( s->nodes );
  for( ulong i=0UL; i<s->action_cnt; i++ ) {
    action_t const * a = &s->actions[i];
    if( a->kind==CLOCK || a->kind==STANDSTILL ) continue;
    node_t * n   = &s->nodes[ a->label.slot*s->width+a->label.index ];
    s->node_cnt += !n->kinds;
    n->label     = a->label;
    n->parent    = a->parent;
    n->kinds    |= 1U<<a->kind;
  }
}

/* A canonical block is directly finalized by a notar and final cert, or
   a fast final cert.  Slots the chain jumps over are skipped. */

static void
canonical_build( scenario_t * s ) {
  node_t const * n = NULL;
  for( ulong slot=s->slot_cnt-1UL; slot && !n; slot-- ) {
    for( ulong index=0UL; index<s->width && !n; index++ ) {
      node_t const * c = node_find( s, (label_t){ .slot = slot, .index = index } );
      if( c && !( c->kinds & (1U<<SKIP_CERT) ) ) n = c;
    }
  }

  for( ; n; n = n->parent.slot ? node_find( s, n->parent ) : NULL ) {
    uint k      = n->kinds;
    int  direct = ( ( k & (1U<<NOTARIZE_CERT) ) && ( k & (1U<<FINALIZE_CERT) ) ) || ( k & (1U<<FAST_FINALIZE_CERT) );
    s->slots[ n->label.slot ].canonical       = CANONICAL_BLOCK;
    s->slots[ n->label.slot ].canonical_block = block_id( n->label );
    if( !s->canonical_final && direct ) s->canonical_final = n->label.slot;
    for( ulong slot=n->parent.slot+1UL; slot<n->label.slot; slot++ ) s->slots[ slot ].canonical = CANONICAL_SKIP;
    if( n->parent.slot && !node_find( s, n->parent ) ) FD_LOG_ERR(( "canonical block in slot %lu cites a parent with no actions", n->label.slot ));
  }
  s->slots[ 0 ].canonical = CANONICAL_BLOCK;
}

static uchar *
file_read( char const * path,
           ulong *      size ) {
  FILE * f = fopen( path, "rb" );
  if( !f ) FD_LOG_ERR(( "fopen(%s) failed", path ));
  struct stat st;
  FD_TEST( !fstat( fileno( f ), &st ) );
  if( !S_ISREG( st.st_mode ) ) FD_LOG_ERR(( "%s is not a regular file", path ));
  FD_TEST( !fseek( f, 0L, SEEK_END ) );
  long sz = ftell( f );
  FD_TEST( sz>=0L && !fseek( f, 0L, SEEK_SET ) );
  uchar * data = malloc( (ulong)sz+1UL );
  FD_TEST( data && fread( data, 1UL, (ulong)sz, f )==(ulong)sz );
  fclose( f );
  *size = (ulong)sz;
  return data;
}

/* Parses a scenario and derives its nodes, canonical chain and vote bounds. */

static void
scenario_load( scenario_t * s,
               char const * path ) {
  ulong   size;
  uchar * data = file_read( path, &size );
  memset( s, 0, sizeof(scenario_t) );
  s->slot_cnt = 1UL;
  s->width    = 1UL;
  actions_parse( s, data, size );
  free( data );
  nodes_build( s );

  /* A cert in the deepest slot, at a window's end, readies the next
     window, so votes reach the end of that window. */
  s->vote_slot_cnt = ( (s->slot_cnt-1UL)/AG_SLOTS_PER_WINDOW+2UL )*AG_SLOTS_PER_WINDOW;
  s->slots         = calloc( s->vote_slot_cnt, sizeof(slot_t) );
  FD_TEST( s->slots );
  s->slots[ 0 ].voted_notar = 1; /* the root, as ag_votor_init */
  canonical_build( s );
}

static void
scenario_free( scenario_t * s ) {
  free( s->actions );
  free( s->nodes );
  free( s->slots );
  free( s->certs );
}

/* Invariants */

/* Notar or skip at most once per slot, notar only for live replayed blocks, final only for the canonical one. */

static void
check_vote( scenario_t *            s,
            ag_event_vote_t const * event ) {
  ag_vote_t const * vote = &event->vote;
  ulong             slot = ag_vote_slot( vote );
  FD_TEST( slot<s->vote_slot_cnt );
  slot_t * st = &s->slots[ slot ];
  if( event->reason==UCHAR_MAX ) { /* standstill recovery re-broadcasts prior votes */
    int seen = 0;
    switch( vote->kind ) {
    case AG_VOTE_KIND_NOTAR:          seen = st->voted_notar && !memcmp( st->voted_notar_hash, vote->notar.block_hash, sizeof(ag_block_hash_t) ); break;
    case AG_VOTE_KIND_SKIP:           seen = st->voted_skip;           break;
    case AG_VOTE_KIND_FINAL:          seen = st->voted_final;          break;
    case AG_VOTE_KIND_NOTAR_FALLBACK: seen = st->voted_notar_fallback; break;
    case AG_VOTE_KIND_SKIP_FALLBACK:  seen = st->voted_skip_fallback;  break;
    default: break;
    }
    if( !seen ) FD_LOG_CRIT(( "INVARIANT: standstill re-broadcasted an unseen vote in slot %lu", slot ));
    return;
  }
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    if( st->voted_skip  ) FD_LOG_CRIT(( "INVARIANT: voted notar and skip in slot %lu", slot ));
    if( st->voted_notar ) FD_LOG_CRIT(( "INVARIANT: voted notar twice in slot %lu", slot ));
    node_t const * n = node_of_block( s, slot, vote->notar.block_hash );
    if( !n || !n->replayed || n->dead ) FD_LOG_CRIT(( "INVARIANT: voted notar in slot %lu for a block replay did not complete or found dead", slot ));
    st->voted_notar = 1;
    memcpy( st->voted_notar_hash, vote->notar.block_hash, sizeof(ag_block_hash_t) );
    break;
  }
  case AG_VOTE_KIND_SKIP:
    if( st->voted_notar ) FD_LOG_CRIT(( "INVARIANT: voted notar and skip in slot %lu", slot ));
    if( st->voted_skip  ) FD_LOG_CRIT(( "INVARIANT: voted skip twice in slot %lu", slot ));
    st->voted_skip = 1;
    break;
  case AG_VOTE_KIND_FINAL:
    if( st->canonical!=CANONICAL_BLOCK || !st->voted_notar ||
        memcmp( st->voted_notar_hash, st->canonical_block.hash, sizeof(ag_block_hash_t) ) ) {
      FD_LOG_CRIT(( "INVARIANT: voted final in slot %lu without voting notar for its canonical block", slot ));
    }
    st->voted_final = 1;
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    if( !st->voted_notar_fallback ) {
      st->voted_notar_fallback = 1;
      memcpy( st->voted_notar_fallback_hash, vote->notar_fallback.block_hash, sizeof(ag_block_hash_t) );
    }
    break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
    st->voted_skip_fallback = 1;
    break;
  default:
    break;
  }
}

/* Whether a block the tracker holds as finalized descends from block
   through the parent links replay gave the pool. */

static int
finalized_descendant( scenario_t const *            s,
                      ag_finality_tracker_t const * tracker,
                      ag_block_id_t const *         block ) {
  for( ulong later=block->slot+1UL; later<s->slot_cnt; later++ ) {
    ag_block_hash_t hash;
    if( ag_finality_tracker_status( tracker, later, hash )!=AG_FINALIZATION_STATUS_FINALIZED ) continue;
    ag_block_id_t id = ag_block_id( later, hash );
    while( id.slot>block->slot ) {
      node_t const * n = node_of_block( s, id.slot, id.hash );
      if( !n || !n->replayed ) break;
      id = n->replayed_parent;
    }
    if( ag_block_id_eq( &id, block ) ) return 1;
  }
  return 0;
}

/* Finalized blocks have a notar and final cert or a fast final cert; implicitly finalized ones a finalized descendant. */

static void
check_finality( scenario_t const * s,
                ag_pool_t const *  pool ) {
  ag_finality_tracker_t const * tracker = pool->finality_tracker;
  for( ulong slot=1UL; slot<s->slot_cnt; slot++ ) {
    ag_block_hash_t hash;
    switch( ag_finality_tracker_status( tracker, slot, hash ) ) {
    case AG_FINALIZATION_STATUS_FINALIZED: {
      ag_slot_state_t const * state      = ag_pool_slot_state( pool, slot );
      int                     final      = state && state->certs.finalize.slot!=ULONG_MAX;
      int                     notar      = state && state->certs.notar.slot!=ULONG_MAX         && !memcmp( state->certs.notar.block_hash,         hash, sizeof(ag_block_hash_t) );
      int                     fast_final = state && state->certs.fast_finalize.slot!=ULONG_MAX && !memcmp( state->certs.fast_finalize.block_hash, hash, sizeof(ag_block_hash_t) );
      if( !( final && notar ) && !fast_final ) FD_LOG_CRIT(( "INVARIANT: finalized slot %lu without a final and notar cert or a fast final cert", slot ));
      break;
    }
    case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED: {
      ag_block_id_t block = ag_block_id( slot, hash );
      if( !finalized_descendant( s, tracker, &block ) ) FD_LOG_CRIT(( "INVARIANT: implicitly finalized slot %lu without a finalized descendant linked to it", slot ));
      break;
    }
    default:
      break;
    }
  }
}

/* Only canonical blocks are finalized, and only slots the canonical chain skips are skipped. */

static void
check_canonical( scenario_t const * s,
                 ag_pool_t const *  pool ) {
  ag_finality_tracker_t const * tracker = pool->finality_tracker;
  for( ulong slot=1UL; slot<s->slot_cnt; slot++ ) {
    ag_block_hash_t hash;
    int             kind = s->slots[ slot ].canonical;
    switch( ag_finality_tracker_status( tracker, slot, hash ) ) {
    case AG_FINALIZATION_STATUS_FINALIZED:
    case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
      if( kind!=CANONICAL_BLOCK || memcmp( hash, s->slots[ slot ].canonical_block.hash, sizeof(ag_block_hash_t) ) ) {
        FD_LOG_CRIT(( "INVARIANT: finalized a block off the canonical chain in slot %lu", slot ));
      }
      break;
    case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
      if( kind!=CANONICAL_SKIP ) FD_LOG_CRIT(( "INVARIANT: skipped slot %lu, which the canonical chain does not skip", slot ));
      break;
    default:
      break;
    }
  }
}

/* Shuttle events between pool and votor, as the votor tile does, until
   both are quiet, then check finality. */

/* Tracing.  After each action, once pool and votor are quiet, both this
   harness and agave's write the same JSON record, so a comparator can
   diff the two implementations' state per action. */

static char const *
ag_cert_kind_name( uint kind ) {
  switch( kind ) {
  case AG_CERT_KIND_NOTAR:          return "NOTARIZE_CERT";
  case AG_CERT_KIND_FINAL:          return "FINALIZE_CERT";
  case AG_CERT_KIND_NOTAR_FALLBACK: return "NOTAR_FALLBACK_CERT";
  case AG_CERT_KIND_FAST_FINAL:     return "FAST_FINALIZE_CERT";
  case AG_CERT_KIND_SKIP:           return "SKIP_CERT";
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

static void
ag_cert_label( ag_cert_t const * c,
               label_t *        label,
               int *            slot_only ) {
  *slot_only = 0;
  switch( c->kind ) {
  case AG_CERT_KIND_FINAL:          *slot_only=1; label->slot=c->final.slot; break;
  case AG_CERT_KIND_SKIP:           *slot_only=1; label->slot=c->skip.slot; break;
  case AG_CERT_KIND_NOTAR:          label->slot=c->notar.slot; label->index=FD_LOAD( ulong, c->notar.block_hash+8UL ); break;
  case AG_CERT_KIND_NOTAR_FALLBACK: label->slot=c->notar_fallback.slot; label->index=FD_LOAD( ulong, c->notar_fallback.block_hash+8UL ); break;
  case AG_CERT_KIND_FAST_FINAL:     label->slot=c->fast_final.slot; label->index=FD_LOAD( ulong, c->fast_final.block_hash+8UL ); break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

static void
scenario_cert_add( scenario_t *     s,
                   char const *     name,
                   label_t const *  label,
                   int              slot_only ) {
  for( ulong i=0UL; i<s->cert_cnt; i++ ) {
    if( s->certs[i].slot_only!=slot_only || strcmp( s->certs[i].name, name ) ) continue;
    if(  slot_only && s->certs[i].label.slot!=label->slot ) continue;
    if( !slot_only && memcmp( &s->certs[i].label, label, sizeof(label_t) ) ) continue;
    return;
  }
  s->certs = realloc( s->certs, ( s->cert_cnt+1UL )*sizeof(cert_ref_t) );
  FD_TEST( s->certs );
  s->certs[ s->cert_cnt++ ] = (cert_ref_t){ .name=name, .label=*label, .slot_only=slot_only };
}

/* Labels render as Firedancer's harness writes them: a slot in digits,
   then the index in letters, a is 0, z 25, aa 26.  The root is "0". */

static void
label_str( label_t l,
           char *  out ) {
  if( !l.slot && !l.index ) { out[0]='0'; out[1]=0; return; }
  char letters[ 32 ];
  int  n   = 0;
  ulong v  = l.index+1UL;
  while( v ) { v--; letters[ n++ ] = (char)('a' + (int)(v%26UL)); v /= 26UL; }
  int p = sprintf( out, "%lu", l.slot );
  while( n ) out[ p++ ] = letters[ --n ];
  out[ p ] = 0;
}

static label_t
hash_label( uchar const * hash ) {
  label_t l = { 0 };
  if( FD_LIKELY( hash ) ) {
    l.slot  = FD_LOAD( ulong, hash );
    l.index = FD_LOAD( ulong, hash+8UL );
  }
  return l;
}

/* One record per action, once quiet: the votor's votes, the pool's
   finality and certs, and the pool's root.  Root here is the pool's
   finalized slot: firedancer's pool roots on finalization. */

static void
trace_record( FILE *             trace,
              scenario_t const * s,
              ag_pool_t const *  pool,
              ulong              i,
              char const *       action ) {
  if( !trace ) return;

  ulong         root_slot = ag_pool_finalized_slot( pool );
  char          root_lbl[ 64 ];
  label_t       root_l    = hash_label( ag_pool_finalized_block_hash( pool ) );
  label_str( root_l, root_lbl );

  fprintf( trace, "{\"i\":%lu,\"action\":\"%s\",\"finalized\":{\"slot\":%lu,\"hash\":\"%s\"},\"root\":{\"slot\":%lu,\"hash\":\"%s\"},\"votes\":{",
           i, action, root_slot, root_lbl, root_slot, root_lbl );
  int first = 1;
  for( ulong slot=1UL; slot<s->vote_slot_cnt; slot++ ) {
    slot_t const * st = &s->slots[ slot ];
    if( !st->voted_notar && !st->voted_skip && !st->voted_final &&
        !st->voted_notar_fallback && !st->voted_skip_fallback ) continue;
    if( !first ) fputc( ',', trace );
    first = 0;
    char nb[ 64 ];
    label_str( hash_label( st->voted_notar_hash ), nb );
    char fb[ 64 ];
    label_str( hash_label( st->voted_notar_fallback_hash ), fb );
    fprintf( trace, "\"%lu\":{", slot );
    int vf = 1;
    if( st->voted_notar )          { fprintf( trace, "\"notar\":\"%s\"", nb ); vf=0; }
    if( st->voted_final )          { fprintf( trace, "%s\"final\":true",      vf?"":"," ); vf=0; }
    if( st->voted_notar_fallback )  { fprintf( trace, "%s\"notar_fb\":\"%s\"", vf?"":",", fb ); vf=0; }
    if( st->voted_skip )            { fprintf( trace, "%s\"skip\":true",      vf?"":"," ); vf=0; }
    if( st->voted_skip_fallback )   { fprintf( trace, "%s\"skip_fb\":true",   vf?"":"," ); vf=0; }
    fprintf( trace, "}" );
  }

  fprintf( trace, "},\"finality\":{" );
  first = 1;
  for( ulong slot=1UL; slot<s->slot_cnt; slot++ ) {
    ag_block_hash_t hash;
    int status = ag_finality_tracker_status( pool->finality_tracker, slot, hash );
    char const * tag = NULL;
    switch( status ) {
    case AG_FINALIZATION_STATUS_FINALIZED:            tag = "final";  break;
    case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED: tag = "ifinal"; break;
    case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:   tag = "iskip";  break;
    default: break;
    }
    if( !tag ) continue;
    if( !first ) fputc( ',', trace );
    first = 0;
    char hb[ 64 ];
    label_str( hash_label( hash ), hb );
    fprintf( trace, "\"%lu\":\"%s%s%s\"", slot, tag, ( !strcmp(tag,"iskip") )?"":":", ( !strcmp(tag,"iskip") )?"":hb );
  }

  fprintf( trace, "},\"certs\":[" );
  for( ulong j=0UL; j<s->cert_cnt; j++ ) {
    if( j ) fputc( ',', trace );
    char cb[ 64 ];
    if( s->certs[j].slot_only ) sprintf( cb, "%lu", s->certs[j].label.slot );
    else                        label_str( s->certs[j].label, cb );
    fprintf( trace, "\"%s %s\"", s->certs[j].name, cb );
  }
  fprintf( trace, "]}\n" );
  fflush( trace );
}

static void
pump( scenario_t * s,
      ag_pool_t *  pool,
      ag_votor_t * votor,
      long         now ) {
  for( int progress=1; progress; ) {
    progress = 0;

    ag_event_pool_t pool_event;
    if( ag_pool_poll_pool_event( pool, &pool_event ) ) {
      ag_votor_handle_pool_event( votor, &pool_event, now );
      progress = 1;
    }

    ag_event_repair_t repair_event;
    if( ag_pool_poll_repair_event( pool, &repair_event ) ) progress = 1;

    ag_event_timeout_t timeout_event;
    if( ag_votor_poll_timeout_event( votor, now, &timeout_event ) ) {
      ag_votor_handle_timeout_event( votor, &timeout_event );
      progress = 1;
    }

    ag_event_vote_t vote_event;
    if( ag_votor_poll_vote_event( votor, &vote_event ) ) {
      check_vote( s, &vote_event );
      uchar quorum_reached;
      ag_pool_add_vote( pool, &vote_event.vote, bad, &quorum_reached );
      progress = 1;
    }

    ag_event_cert_t cert_event;
    if( ag_votor_poll_cert_event( votor, &cert_event ) ) {
      label_t cl = {0}; int slot_only;
      ag_cert_label( &cert_event.cert, &cl, &slot_only );
      scenario_cert_add( s, ag_cert_kind_name( cert_event.cert.kind ), &cl, slot_only );
      ag_pool_add_cert( pool, &cert_event.cert, bad );
      progress = 1;
    }
  }
  check_finality( s, pool );
  check_canonical( s, pool );
}

/* Deliver one 20% message, or all three for a legacy whole-cert action.
   Pump between legacy messages so weak-quorum events reach Votor. */
static void
add_cert_parts( scenario_t *  s,
                ag_pool_t *   pool,
                ag_votor_t *  votor,
                action_t const * a,
                long          now ) {
  ag_block_id_t id = block_id( a->label );
  ulong begin = a->part==ULONG_MAX ? 0UL           : a->part;
  ulong end   = a->part==ULONG_MAX ? CERT_PART_CNT : a->part+1UL;
  for( ulong part=begin; part<end; part++ ) {
    for( ulong i=0UL; i<CERT_PART_SIGNERS; i++ ) {
      ushort rank = cert_part_rank[ part ][ i ];
      uchar const * pubkey = epoch_info.validators[ rank ].bls_key;
      ag_vote_t vote = a->kind==NOTARIZE_CERT
        ? ag_vote_construct_notar( sec_sign_fn, &validator_sk[ rank ], pubkey, id.slot, id.hash, rank, SHRED_VERSION )
        : ag_vote_construct_skip ( sec_sign_fn, &validator_sk[ rank ], pubkey, id.slot,          rank, SHRED_VERSION );
      uchar quorum_reached;
      int err = ag_pool_add_vote( pool, &vote, bad, &quorum_reached );
      if( err==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS ) return;
      if( err!=AG_POOL_SUCCESS ) FD_LOG_CRIT(( "certificate part vote rejected in slot %lu: %d", id.slot, err ));
    }
    if( part+1UL<end ) pump( s, pool, votor, now );
  }
}

/* Mapping fresh pool and votor memory for every scenario dominates the
   run time, so a worker reuses its largest. */

static void * pool_mem;
static void * votor_mem;
static ulong  mem_slot_max;

/* Runs the actions against a fresh pool and votor, then checks the finalized slot. */

static void
scenario_run( scenario_t * s,
             FILE *        trace ) {
  /* The pool holds slots up to slot_max-AG_REWARD_SLOT_DELTA past the
     root, and its event queues hold slot_max events. */
  ulong slot_max = fd_ulong_max( s->vote_slot_cnt+AG_REWARD_SLOT_DELTA, s->node_cnt+2UL );
  if( slot_max>mem_slot_max ) {
    free( pool_mem  );
    free( votor_mem );
    pool_mem     = aligned_alloc( ag_pool_align(),  fd_ulong_align_up( ag_pool_footprint ( slot_max ), ag_pool_align()  ) );
    votor_mem    = aligned_alloc( ag_votor_align(), fd_ulong_align_up( ag_votor_footprint( slot_max ), ag_votor_align() ) );
    mem_slot_max = slot_max;
    FD_TEST( pool_mem && votor_mem );
  }

  ag_pool_t *  pool  = ag_pool_join ( ag_pool_new ( pool_mem,  slot_max, 42UL ) );
  ag_votor_t * votor = ag_votor_join( ag_votor_new( votor_mem, slot_max, 42UL ) );
  FD_TEST( pool && votor );
  ag_pool_init          ( pool, 0UL );
  ag_pool_advance_epoch ( pool, &epoch_info, 0UL, 0UL );
  ag_votor_init         ( votor, 0UL, 0L, NS_PER_SLOT, SHRED_VERSION, sec_sign_fn, &validator_sk[0] );
  ag_votor_advance_epoch( votor, NS_PER_SLOT, 0UL, 0UL, epoch_info.validators[0].bls_key );

  long now = 0L;
  for( ulong i=0UL; i<s->action_cnt; i++ ) {
    action_t const * a = &s->actions[i];
    switch( a->kind ) {
    case NOTARIZE_CERT:
    case SKIP_CERT:
      add_cert_parts( s, pool, votor, a, now );
      break;
    case FINALIZE_CERT:
    case NOTAR_FALLBACK_CERT:
    case FAST_FINALIZE_CERT: {
      ag_cert_t c = cert( a->kind, a->label );
      scenario_cert_add( s, action_kind_name[ a->kind ], &a->label, a->kind==FINALIZE_CERT || a->kind==SKIP_CERT );
      ag_pool_add_cert( pool, &c, bad );
      break;
    }
    case REPLAY_ARRIVES: {
      /* Votor now receives replayed blocks only after completion. */
      break;
    }
    case REPLAY_COMPLETE: {
      ag_block_id_t id     = block_id( a->label );
      ag_block_id_t parent = block_id( a->parent );
      if( ag_pool_add_block( pool, &id, &parent, bad )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS ) break;
      node_t * n          = node_find( s, a->label );
      n->replayed         = 1;
      n->replayed_parent  = parent;
      ag_event_replay_t completed = { .slot = id.slot, .block_info = { .parent = parent } };
      memcpy( completed.block_info.hash, id.hash, sizeof(ag_block_hash_t) );
      ag_votor_handle_replay_event( votor, &completed );
      break;
    }
    case REPLAY_DEAD: {
      /* A failed replay emits no replay event to Votor. */
      node_find( s, a->label )->dead = 1;
      break;
    }
    case CLOCK:
      now += (long)a->ms*1000000L;
      break;
    case STANDSTILL:
      ag_pool_recover_from_standstill( pool );
      break;
    }
    pump( s, pool, votor, now );
    {
      char as[ 96 ], lb[ 64 ];
      if( a->kind==CLOCK ) snprintf( as, sizeof(as), "CLOCK %lums", a->ms );
      else if( a->kind==STANDSTILL ) snprintf( as, sizeof(as), "STANDSTILL" );
      else {
        label_str( a->label, lb );
        if( a->part!=ULONG_MAX ) snprintf( as, sizeof(as), "%s %s %lu/3", action_kind_name[ a->kind ], lb, a->part+1UL );
        else                     snprintf( as, sizeof(as), "%s %s", action_kind_name[ a->kind ], lb );
      }
      trace_record( trace, s, pool, i, as );
    }
  }
  pump( s, pool, votor, now+NS_EVERY_TIMEOUT );
  trace_record( trace, s, pool, s->action_cnt, "END" );

  ulong         finalized_slot = ag_pool_finalized_slot( pool );
  uchar const * finalized_hash = ag_pool_finalized_block_hash( pool );
  if( finalized_slot!=s->canonical_final ||
      ( finalized_slot && ( !finalized_hash || memcmp( finalized_hash, s->slots[ finalized_slot ].canonical_block.hash, sizeof(ag_block_hash_t) ) ) ) ) {
    FD_LOG_CRIT(( "INVARIANT: finalized slot %lu, not canonical slot %lu", finalized_slot, s->canonical_final ));
  }

  ag_votor_delete( ag_votor_leave( votor ) );
  ag_pool_delete ( ag_pool_leave ( pool  ) );
}

/* Workers.  FD_TEST exits without a backtrace, so a worker logs one on
   exit.  It never exits on success: _exit skips atexit.  FD_LOG_CRIT
   aborts, and fd_log logs its own. */

static void
backtrace_on_exit( void ) {
  void * frames[ 128 ];
  fd_backtrace_log( frames, (ulong)backtrace( frames, 128 ) );
}

static void
worker( char **       paths,
        ulong         path_cnt,
        ulong         first,
        ulong         stride,
        ulong *       current,
        char const *  trace_dir ) {
  atexit( backtrace_on_exit );
  fd_log_level_logfile_set( 4 ); /* ERR and up, the votor warns a lot */
  fd_log_level_stderr_set ( 4 );
  for( ulong i=first; i<path_cnt; i+=stride ) {
    *current = i;
    scenario_t s;
    scenario_load( &s, paths[i] );
    FILE * trace = NULL;
    if( trace_dir ) {
      char const * base = strrchr( paths[i], '/' );
      base = base ? base+1 : paths[i];
      char path[ PATH_MAX ];
      FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s.trace", trace_dir, base ) );
      trace = fopen( path, "w" );
      FD_TEST( trace );
    }
    scenario_run( &s, trace );
    if( trace ) fclose( trace );
    scenario_free( &s );
  }
#if FD_HAS_COVERAGE
  char const * profile_file = getenv( "LLVM_PROFILE_FILE" );
  if( profile_file ) {
    char worker_profile[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( worker_profile, sizeof(worker_profile), NULL, "%s-worker-%lu", profile_file, first ) );
    __llvm_profile_set_filename( worker_profile );
  }
  FD_TEST( !__llvm_profile_write_file() );
#endif
  _exit( 0 );
}

/* Forks --jobs workers over the inputs and prints the first failing input. */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  ulong jobs = fd_env_strip_cmdline_ulong( &argc, &argv, "--jobs", NULL, (ulong)sysconf( _SC_NPROCESSORS_ONLN ) );
  char const * trace_dir = fd_env_strip_cmdline_cstr( &argc, &argv, "--trace", NULL, NULL );
  if( trace_dir ) {
    if( mkdir( trace_dir, 0777 ) && errno!=EEXIST ) FD_LOG_ERR(( "mkdir(%s) failed", trace_dir ));
  }

  glob_t g = { 0 };
  for( int i=1; i<argc; i++ ) {
    /* A directory runs every entry in it */
    char         pattern[ PATH_MAX ];
    char const * arg = argv[i];
    struct stat  st;
    if( !stat( arg, &st ) && S_ISDIR( st.st_mode ) ) {
      FD_TEST( fd_cstr_printf_check( pattern, sizeof(pattern), NULL, "%s/*", arg ) );
      arg = pattern;
    }
    if( glob( arg, i>1 ? GLOB_APPEND : 0, NULL, &g ) ) FD_LOG_ERR(( "no input matches %s", arg ));
  }
  if( !g.gl_pathc ) FD_LOG_ERR(( "usage: %s [--jobs N] <file|dir|pattern>...", argv[0] ));
  jobs = fd_ulong_max( fd_ulong_min( jobs, g.gl_pathc ), 1UL );

  cluster_init();

  ulong * current = mmap( NULL, jobs*sizeof(ulong), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0 );
  pid_t * pids    = malloc( jobs*sizeof(pid_t) );
  FD_TEST( current!=MAP_FAILED && pids );
  for( ulong w=0UL; w<jobs; w++ ) {
    pids[w] = fork();
    FD_TEST( pids[w]>=0 );
    if( !pids[w] ) worker( g.gl_pathv, g.gl_pathc, w, jobs, &current[w], trace_dir );
  }

  int failed = 0;
  for( ulong left=jobs; left && !failed; left-- ) {
    int   status;
    pid_t pid = wait( &status );
    FD_TEST( pid>0 );
    failed = !WIFEXITED( status ) || WEXITSTATUS( status );
    for( ulong w=0UL; failed && w<jobs; w++ ) {
      if( pids[w]!=pid ) { kill( pids[w], SIGKILL ); continue; }
      ulong   size;
      uchar * data = file_read( g.gl_pathv[ current[w] ], &size );
      fprintf( stderr, "\nfailing input: %s\n%.*s\n", g.gl_pathv[ current[w] ], (int)size, (char const *)data );
      free( data );
    }
  }

  if( !failed ) FD_LOG_NOTICE(( "pass: %lu scenarios", g.gl_pathc ));
  free( pids );
  globfree( &g );
  fd_halt();
  return failed;
}
