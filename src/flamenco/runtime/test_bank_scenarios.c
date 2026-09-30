/* test_bank_scenarios drives fd_banks, as the replay tile does, through
   scenarios and checks its invariants.

     test_bank_scenarios [--jobs N] <file|dir|pattern>...

   Quoted patterns are expanded with glob, which avoids the shell's
   argument limit on large corpora.

   A scenario is a JSON list of actions on a block tree:

     [ { "node": "1a", "parent": "0",  "action": "NEW_BANK", "leader": 1 },
       { "node": "1a", "parent": "0",  "action": "BLOCK_START" },
       { "node": "2a", "parent": "1a", "action": "EVICT" },
       { "action": "PRUNE" } ]

   Labels are as in test_ag_votor_scenarios: a depth, then the block's
   index in letters.  "0" is the bank fd_banks_init_bank makes.  PRUNE
   names no node, and EVICT names one only to protect it from eviction.

   The harness keeps a model of the fork tree and predicts every bank's
   state after each action.  An action whose preconditions in the model
   break the caller's contract in fd_bank.h is skipped, as replay would
   not take it.

   Scenarios run in N forked workers.  The first failure stops the
   suite: its worker logs the backtrace, then the suite prints the
   failing input and exits nonzero. */

#define _GNU_SOURCE
#include <execinfo.h>
#include <glob.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fd_bank.c" /* reads the bank pool, cost tracker pool and dead queue */
#include "../../ballet/json/fd_jtok.h"
#include "../../util/log/fd_backtrace.h"

#define BANK_MAX   (24UL)
#define FORK_WIDTH (6UL)

enum { NEW_BANK, BLOCK_START, FINALIZE, DEAD, ACQUIRE, RELEASE, ROOT, EVICT, PRUNE, ACTION_KIND_CNT };

static char const * const action_kind_name[ ACTION_KIND_CNT ] = {
  "NEW_BANK", "BLOCK_START", "FINALIZE", "DEAD", "ACQUIRE", "RELEASE", "ROOT", "EVICT", "PRUNE"
};

static char const * const state_name[] = { "INACTIVE", "INIT", "REPLAYABLE", "FROZEN", "DEAD", "PRUNABLE" };

/* allowed[ from ] is a bit per state a bank may move to from state
   from.  It is the diagram in fd_bank.h plus FROZEN -> DEAD, which
   fd_banks_mark_bank_dead allows and the diagram leaves out. */

#define BIT( state ) (1UL<<(state))
static ulong const allowed[ 6 ] = {
  [ FD_BANK_STATE_INACTIVE   ] = BIT( FD_BANK_STATE_INIT ),
  [ FD_BANK_STATE_INIT       ] = BIT( FD_BANK_STATE_REPLAYABLE ) | BIT( FD_BANK_STATE_DEAD ) | BIT( FD_BANK_STATE_PRUNABLE ) | BIT( FD_BANK_STATE_INACTIVE ),
  [ FD_BANK_STATE_REPLAYABLE ] = BIT( FD_BANK_STATE_FROZEN ) | BIT( FD_BANK_STATE_DEAD ) | BIT( FD_BANK_STATE_PRUNABLE ) | BIT( FD_BANK_STATE_INACTIVE ),
  [ FD_BANK_STATE_FROZEN     ] = BIT( FD_BANK_STATE_DEAD ) | BIT( FD_BANK_STATE_PRUNABLE ) | BIT( FD_BANK_STATE_INACTIVE ),
  [ FD_BANK_STATE_DEAD       ] = BIT( FD_BANK_STATE_INACTIVE ),
  [ FD_BANK_STATE_PRUNABLE   ] = BIT( FD_BANK_STATE_DEAD ) | BIT( FD_BANK_STATE_INACTIVE ),
};

typedef struct {
  ulong slot;
  ulong index;
} label_t;

typedef struct {
  uint    kind;
  int     has_node;
  int     leader;
  label_t label;
  label_t parent;
} action_t;

typedef struct node node_t;

struct node {
  label_t  label;
  label_t  parent_label;
  int      named;     /* an action names the node */
  int      live;      /* the node holds a bank */
  int      freed;     /* the node held a bank, since freed */
  ulong    idx;
  ulong    seq;
  ulong    state;     /* predicted */
  ulong    before;    /* state before the current action */
  ulong    refcnt;
  int      leader;
  int      cloned;    /* BLOCK_START ran, so pruning it cancels its forks */
  int      has_cost;  /* holds a cost tracker */
  node_t * parent;    /* in the model's fork tree */
  node_t * child;     /* leftmost child */
  node_t * sibling;   /* next sibling to the right */
};

typedef struct {
  action_t *   actions;
  ulong        action_cnt;
  node_t *     nodes;       /* by slot, then index */
  ulong        width;       /* highest index+1 */
  ulong        slot_cnt;    /* the root's slot to the deepest */
  node_t *     root;
  fd_banks_t * banks;
  ulong        evict_rr;    /* the eviction round robin index */
  ulong        last_seq;
} scenario_t;

/* The action being run, for failure messages, and per-worker counts of
   actions run and skipped, shared with the parent. */

static ulong   cur_action;
static ulong * run_cnt;  /* [ACTION_KIND_CNT][2]: skipped, run */

/* t=3 sequence coverage (mirrors alpenglow_seqcov): an event is an
   action refined by the transition it made, and a t-sequence is t
   distinct events in order (not necessarily adjacent) within one
   scenario.  Coverage is measured over the whole corpus.

   The alphabet is the paper model's (replay-corpus): INIT, REPLAY,
   FINALIZE, DEAD, ROOT, PRUNE.  A block only dies at INIT or in REPLAY,
   never frozen (a dead ancestor never finalized, so no frozen
   descendant), and there is no eviction, so DEAD.frozen, the EVICT
   events, ACQUIRE/RELEASE, a leader NEW, and PRUNE.prunable cannot
   occur and are not in the alphabet. */
enum { EV_NEW, EV_START, EV_FINALIZE,
       EV_DEAD_INIT, EV_DEAD_REPLAY,
       EV_ROOT,
       EV_PRUNE_DEAD, EV_CNT };
__attribute__((unused)) static char const * const ev_name[ EV_CNT ] = {
  "NEW", "START", "FINALIZE", "DEAD.init", "DEAD.replay", "ROOT", "PRUNE.dead" };
#define COV_MAXT 5
static int     g_cov;          /* coverage mode enabled */
static int     g_event;        /* event id of the current action, -1 = none */
static uchar   ev_buf[ 1<<16 ];/* per-scenario event sequence */
static ulong   ev_cnt;
static uchar * cov[ COV_MAXT+1 ]; /* cov[k] = [EV_CNT^k] this worker's covered ordered distinct k-tuples */

/* Whether the base-EV_CNT k-digit index contains digit v. */
static int
has_digit( ulong idx, int k, int v ) {
  for( int i=0; i<k; i++ ) { if( (int)( idx%EV_CNT )==v ) return 1; idx /= EV_CNT; }
  return 0;
}

/* The DEAD event by the primary node's state.  In the paper model only
   INIT and REPLAYABLE occur; anything else is left uncounted (-1). */
static int
dead_event( ulong st ) {
  switch( st ) {
  case FD_BANK_STATE_INIT:       return EV_DEAD_INIT;
  case FD_BANK_STATE_REPLAYABLE: return EV_DEAD_REPLAY;
  default:                       return -1;
  }
}

/* Fold the current scenario's event sequence into this worker's covered
   sets: every ordered distinct k-tuple it realizes, for k up to COV_MAXT.
   A running scan keeps this scenario's seen k-tuples (s[k]); a new event
   v extends each seen (k-1)-tuple that lacks v into a k-tuple. */
static void
cov_accumulate( void ) {
  ulong const E = EV_CNT;
  ulong pw[ COV_MAXT+1 ]; pw[0] = 1UL; for( int k=1; k<=COV_MAXT; k++ ) pw[k] = pw[k-1]*E;
  /* per-scenario seen k-tuples, k=1..COV_MAXT-1 */
  static uchar seen1[ EV_CNT ];
  static uchar seen2[ EV_CNT*EV_CNT ];
  static uchar seen3[ EV_CNT*EV_CNT*EV_CNT ];
  static uchar seen4[ EV_CNT*EV_CNT*EV_CNT*EV_CNT ];
  uchar * seen[ COV_MAXT ] = { NULL, seen1, seen2, seen3, seen4 };
  memset( seen1, 0, sizeof(seen1) );
  memset( seen2, 0, sizeof(seen2) );
  memset( seen3, 0, sizeof(seen3) );
  memset( seen4, 0, sizeof(seen4) );
  for( ulong n=0UL; n<ev_cnt; n++ ) {
    int v = ev_buf[ n ];
    /* Extend high k first so v is never chained with itself. */
    for( int k=COV_MAXT; k>=2; k-- ) {
      ulong lim = pw[ k-1 ];
      for( ulong i=0UL; i<lim; i++ ) {
        if( !seen[ k-1 ][ i ] || has_digit( i, k-1, v ) ) continue;
        ulong j = i*E + (ulong)v;
        cov[ k ][ j ] = 1;
        if( k<COV_MAXT ) seen[ k ][ j ] = 1;
      }
    }
    cov[ 1 ][ v ] = 1;
    seen[ 1 ][ v ] = 1;
  }
}

#define INVARIANT( c, fmt, ... ) do {                                                     \
    if( FD_UNLIKELY( !(c) ) ) FD_LOG_CRIT(( "INVARIANT (action %lu): " fmt, cur_action, ##__VA_ARGS__ )); \
  } while(0)

static char const *
label_cstr( label_t label,
            char *  buf ) {
  if( !label.slot ) return strcpy( buf, "0" );
  char  letters[ 16 ];
  ulong n     = 0UL;
  ulong index = label.index;
  for(;;) {
    letters[ n++ ] = (char)( 'a' + index%26UL );
    if( index<26UL ) break;
    index = index/26UL - 1UL;
  }
  char * p = buf + sprintf( buf, "%lu", label.slot );
  while( n ) *p++ = letters[ --n ];
  *p = '\0';
  return buf;
}

#define LABEL( n ) label_cstr( (n)->label, (char[32]){0} )

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
  /* Paper-model names for the same actions. */
  if( fd_jtok_str_eq( s, "INIT"   ) ) return NEW_BANK;
  if( fd_jtok_str_eq( s, "REPLAY" ) ) return BLOCK_START;
  FD_LOG_ERR(( "unknown action" ));
}

static node_t *
node_find( scenario_t const * s,
           label_t            label ) {
  if( label.slot>=s->slot_cnt || label.index>=s->width ) return NULL;
  node_t * n = &s->nodes[ label.slot*s->width+label.index ];
  return n->named ? n : NULL;
}

/* Parses the JSON action list, failing on any malformed action. */

static void
actions_parse( scenario_t *  s,
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
    int        has_parent = 0;
    ulong      leader     = 0UL;
    *a = (action_t){ .kind = UINT_MAX };
    fd_jtok_obj_enter( j );
    while( fd_jtok_obj_next( j, &key ) ) {
      if(      fd_jtok_str_eq( &key, "node"   ) ) { a->label  = label_parse( j ); a->has_node = 1; }
      else if( fd_jtok_str_eq( &key, "parent" ) ) { a->parent = label_parse( j ); has_parent  = 1; }
      else if( fd_jtok_str_eq( &key, "leader" ) ) fd_jtok_ulong( j, &leader );
      else if( fd_jtok_str_eq( &key, "action" ) ) {
        fd_jtok_str_t kind;
        fd_jtok_str( j, &kind );
        a->kind = action_kind_parse( &kind );
      }
    }
    if( fd_jtok_err( j ) ) FD_LOG_ERR(( "malformed action %lu", s->action_cnt-1UL ));
    a->leader = !!leader;
    int node_ok = a->has_node && has_parent && a->label.slot && a->parent.slot<a->label.slot;
    int ok = a->kind==PRUNE ? !a->has_node && !has_parent
           : a->kind==EVICT ? ( !a->has_node && !has_parent ) || node_ok
           :                  a->kind!=UINT_MAX && node_ok;
    if( !ok ) FD_LOG_ERR(( "bad action %lu", s->action_cnt-1UL ));
  }
  if( fd_jtok_fini( j ) ) FD_LOG_ERR(( "malformed JSON" ));
}

/* Lays nodes out by slot then index.  Every action naming a node must
   cite the same parent. */

static void
nodes_build( scenario_t * s ) {
  for( ulong i=0UL; i<s->action_cnt; i++ ) {
    if( !s->actions[i].has_node ) continue;
    s->slot_cnt = fd_ulong_max( s->slot_cnt, s->actions[i].label.slot +1UL );
    s->width    = fd_ulong_max( s->width,    s->actions[i].label.index+1UL );
  }
  s->nodes = calloc( s->slot_cnt*s->width, sizeof(node_t) );
  FD_TEST( s->nodes );
  s->nodes[0].named = 1; /* the root */
  for( ulong i=0UL; i<s->action_cnt; i++ ) {
    action_t const * a = &s->actions[i];
    if( !a->has_node ) continue;
    node_t * n = &s->nodes[ a->label.slot*s->width+a->label.index ];
    if( n->named && ( n->parent_label.slot!=a->parent.slot || n->parent_label.index!=a->parent.index ) ) {
      FD_LOG_ERR(( "action %lu cites another parent for node %s", i, LABEL( n ) ));
    }
    n->named        = 1;
    n->label        = a->label;
    n->parent_label = a->parent;
  }
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
}

static void
scenario_free( scenario_t * s ) {
  free( s->actions );
  free( s->nodes );
}

/* The model's fork tree */

static fd_bank_t *
bank_of( scenario_t const * s,
         node_t const *     n ) {
  return fd_banks_pool_ele( fd_banks_get_bank_pool( s->banks ), n->idx );
}

static node_t *
node_of_idx( scenario_t const * s,
             ulong              idx ) {
  for( ulong i=0UL; i<s->slot_cnt*s->width; i++ ) {
    if( s->nodes[i].live && s->nodes[i].idx==idx ) return &s->nodes[i];
  }
  return NULL;
}

static void
child_append( node_t * parent,
              node_t * n ) {
  n->parent  = parent;
  n->sibling = NULL;
  if( !parent->child ) { parent->child = n; return; }
  node_t * c = parent->child;
  while( c->sibling ) c = c->sibling;
  c->sibling = n;
}

static void
child_unlink( node_t * n ) {
  if( !n->parent ) return;
  if( n->parent->child==n ) {
    n->parent->child = n->sibling;
  } else {
    node_t * c = n->parent->child;
    while( c->sibling!=n ) c = c->sibling;
    c->sibling = n->sibling;
  }
  n->parent  = NULL;
  n->sibling = NULL;
}

/* A freed node's bank must hold no references. */

static void
node_free( node_t * n ) {
  INVARIANT( !n->refcnt, "freed bank %s with %lu references", LABEL( n ), n->refcnt );
  n->live     = 0;
  n->freed    = 1;
  n->state    = FD_BANK_STATE_INACTIVE;
  n->has_cost = 0;
}

static void
subtree_free( node_t * n ) {
  for( node_t * c = n->child; c; ) {
    node_t * next = c->sibling;
    subtree_free( c );
    c = next;
  }
  n->child = NULL;
  node_free( n );
}

static ulong
subtree_refcnt( node_t const * n ) {
  ulong cnt = n->refcnt;
  for( node_t const * c = n->child; c; c = c->sibling ) cnt += subtree_refcnt( c );
  return cnt;
}

/* Collects eviction candidates in fd_banks' DFS order: children left to
   right, then the node.  Only leaves qualify. */

static void
evictable_collect( scenario_t const * s,
                   node_t *           n,
                   node_t const *     protect,
                   node_t **          out,
                   ulong *            cnt ) {
  for( node_t * c = n->child; c; c = c->sibling ) evictable_collect( s, c, protect, out, cnt );
  if( n->child || n==s->root || n==protect || n->leader ) return;
  if( n->state==FD_BANK_STATE_DEAD || n->state==FD_BANK_STATE_PRUNABLE ) return;
  out[ (*cnt)++ ] = n;
}

/* Invariants checked after every action */

/* Bank state, links, references, leader flag and cost tracker match the
   model; so do the pool's counts, the root, the fork width and the
   pending prunable bank. */

static void
check_structure( scenario_t * s ) {
  fd_bank_t *              pool      = fd_banks_get_bank_pool( s->banks );
  fd_bank_cost_tracker_t * cost_pool = fd_banks_get_cost_tracker_pool( s->banks );
  ulong                    null_idx  = fd_banks_pool_idx_null( pool );
  ulong                    cost_null = fd_bank_cost_tracker_pool_idx_null( cost_pool );

  ulong    live_cnt = 0UL;
  ulong    leaf_cnt = 0UL;
  ulong    cost_cnt = 0UL;
  node_t * prunable = NULL;
  for( ulong i=0UL; i<s->slot_cnt*s->width; i++ ) {
    node_t * n = &s->nodes[i];
    if( n->freed && !n->live ) {
      fd_bank_t const * b = bank_of( s, n );
      INVARIANT( b->state==FD_BANK_STATE_INACTIVE || b->bank_seq!=n->seq, "freed bank %s is still %s", LABEL( n ), state_name[ b->state ] );
    }
    if( !n->live ) continue;
    fd_bank_t const * b = bank_of( s, n );
    live_cnt++;
    leaf_cnt += !n->child;
    cost_cnt += !!n->has_cost;
    INVARIANT( b->bank_seq==n->seq, "bank %s has bank_seq %lu, not %lu", LABEL( n ), b->bank_seq, n->seq );
    INVARIANT( b->state==n->state, "bank %s is %s, not %s", LABEL( n ), state_name[ b->state ], state_name[ n->state ] );
    INVARIANT( b->refcnt==n->refcnt, "bank %s has refcnt %lu, not %lu", LABEL( n ), b->refcnt, n->refcnt );
    INVARIANT( !!b->is_leader==!!n->leader, "bank %s is_leader is %u", LABEL( n ), (uint)b->is_leader );
    INVARIANT( ( b->cost_tracker_pool_idx!=cost_null )==!!n->has_cost, "bank %s %s a cost tracker", LABEL( n ), n->has_cost ? "lacks" : "holds" );
    INVARIANT( b->parent_idx==( n->parent ? n->parent->idx : null_idx ), "bank %s has the wrong parent", LABEL( n ) );

    ulong child_idx = b->child_idx;
    for( node_t const * c = n->child; c; c = c->sibling ) {
      INVARIANT( child_idx==c->idx, "bank %s's children differ from the model at %s", LABEL( n ), LABEL( c ) );
      child_idx = fd_banks_pool_ele( pool, child_idx )->sibling_idx;
    }
    INVARIANT( child_idx==null_idx, "bank %s has a child the model lacks", LABEL( n ) );

    if( n->state==FD_BANK_STATE_DEAD ) {
      for( node_t const * c = n->child; c; c = c->sibling ) {
        INVARIANT( c->state==FD_BANK_STATE_DEAD, "bank %s is %s under dead bank %s", LABEL( c ), state_name[ c->state ], LABEL( n ) );
      }
    }
    if( n->state==FD_BANK_STATE_PRUNABLE ) {
      INVARIANT( !prunable, "banks %s and %s are both prunable", LABEL( prunable ), LABEL( n ) );
      INVARIANT( !n->child, "prunable bank %s has children", LABEL( n ) );
      prunable = n;
    }
  }

  INVARIANT( fd_banks_pool_used( pool )==live_cnt, "pool holds %lu banks, model %lu", fd_banks_pool_used( pool ), live_cnt );
  INVARIANT( s->banks->root_idx==s->root->idx, "root is bank %lu, not %s", s->banks->root_idx, LABEL( s->root ) );
  INVARIANT( s->banks->curr_fork_width==leaf_cnt, "fork width is %lu with %lu leaves", s->banks->curr_fork_width, leaf_cnt );
  INVARIANT( s->banks->prunable_idx==( prunable ? prunable->idx : null_idx ), "prunable_idx is %lu", s->banks->prunable_idx );
  INVARIANT( fd_bank_cost_tracker_pool_free( cost_pool )==FORK_WIDTH-cost_cnt, "%lu cost trackers free with %lu held", fd_bank_cost_tracker_pool_free( cost_pool ), cost_cnt );
}

/* Every bank that changed state took an edge in allowed. */

static void
transitions_begin( scenario_t * s ) {
  for( ulong i=0UL; i<s->slot_cnt*s->width; i++ ) {
    node_t * n = &s->nodes[i];
    n->before = n->live ? n->state : FD_BANK_STATE_INACTIVE;
  }
}

static void
transitions_check( scenario_t * s ) {
  for( ulong i=0UL; i<s->slot_cnt*s->width; i++ ) {
    node_t * n = &s->nodes[i];
    if( !n->live && !n->freed ) continue;
    ulong after = fd_banks_pool_ele( fd_banks_get_bank_pool( s->banks ), n->idx )->state;
    if( !n->live ) after = FD_BANK_STATE_INACTIVE; /* the slot may be reused */
    if( after==n->before ) continue;
    INVARIANT( allowed[ n->before ] & BIT( after ), "bank %s went %s -> %s", LABEL( n ), state_name[ n->before ], state_name[ after ] );
  }
}

/* Actions.  Each returns whether it ran, or 0 if its preconditions fail
   in the model. */

static int
new_bank( scenario_t *     s,
          action_t const * a ) {
  node_t * n = node_find( s, a->label );
  node_t * p = node_find( s, a->parent );
  if( n->live ) return 0;
  /* A freed node may be re-created: replay re-replays an evicted slot,
     making a fresh bank (new idx and bank_seq) for the same slot.  This
     exercises the dead queue's stale-entry skip and pool index reuse. */
  if( !p || !p->live || p->state==FD_BANK_STATE_DEAD || p->state==FD_BANK_STATE_PRUNABLE ) return 0;

  ulong live_cnt = 0UL;
  ulong leaf_cnt = 0UL;
  for( ulong i=0UL; i<s->slot_cnt*s->width; i++ ) {
    live_cnt += !!s->nodes[i].live;
    leaf_cnt += s->nodes[i].live && !s->nodes[i].child;
  }
  int can = live_cnt<BANK_MAX && leaf_cnt<FORK_WIDTH;
  INVARIANT( fd_banks_can_start_bank( s->banks )==can, "can_start_bank is %d with %lu banks and %lu leaves", !can, live_cnt, leaf_cnt );
  if( !can ) return 0;

  fd_bank_t * b = fd_banks_new_bank( s->banks, p->idx, 0L, (uchar)a->leader );
  INVARIANT( b->state==FD_BANK_STATE_INIT, "new bank %s is %s", LABEL( n ), state_name[ b->state ] );
  INVARIANT( b->bank_seq>s->last_seq, "new bank %s reuses bank_seq %lu", LABEL( n ), b->bank_seq );
  b->f.slot   = n->label.slot;
  s->last_seq = b->bank_seq;
  n->live     = 1;
  n->freed    = 0;
  n->cloned   = 0;
  n->has_cost = 0;
  n->refcnt   = 0UL;
  n->child    = NULL;
  n->idx      = b->idx;
  n->seq      = b->bank_seq;
  n->state    = FD_BANK_STATE_INIT;
  n->leader   = a->leader;
  child_append( p, n );
  g_event = EV_NEW;
  return 1;
}

static int
block_start( scenario_t *     s,
             action_t const * a ) {
  node_t * n = node_find( s, a->label );
  if( !n->live || n->state!=FD_BANK_STATE_INIT || n->parent->state!=FD_BANK_STATE_FROZEN ) return 0;
  fd_bank_t * b = fd_banks_clone_from_parent( s->banks, n->idx );
  b->f.slot   = n->label.slot;
  n->state    = FD_BANK_STATE_REPLAYABLE;
  n->cloned   = 1;
  n->has_cost = 1;
  g_event = EV_START;
  return 1;
}

static int
finalize( scenario_t *     s,
          action_t const * a ) {
  node_t * n = node_find( s, a->label );
  if( !n->live || n->state!=FD_BANK_STATE_REPLAYABLE ) return 0;
  fd_banks_mark_bank_frozen( bank_of( s, n ) );
  n->state    = FD_BANK_STATE_FROZEN;
  n->has_cost = 0;
  g_event = EV_FINALIZE;
  return 1;
}

/* fd_banks_mark_bank_dead's walk: the node, then each child's subtree
   left to right, skipping subtrees already dead. */

static void
subtree_mark_dead( node_t *  n,
                   node_t ** out,
                   ulong *   cnt ) {
  if( n->state==FD_BANK_STATE_DEAD ) return;
  n->state = FD_BANK_STATE_DEAD;
  out[ (*cnt)++ ] = n;
  for( node_t * c = n->child; c; c = c->sibling ) subtree_mark_dead( c, out, cnt );
}

static int
dead( scenario_t *     s,
      action_t const * a ) {
  node_t * n = node_find( s, a->label );
  if( !n->live || n==s->root ) return 0;
  g_event = dead_event( n->state );
  node_t * expect[ BANK_MAX ];
  ulong    expect_cnt = 0UL;
  ulong    idxs[ BANK_MAX ];
  ulong    idxs_cnt   = ULONG_MAX;
  subtree_mark_dead( n, expect, &expect_cnt );
  fd_banks_mark_bank_dead( s->banks, n->idx, idxs, &idxs_cnt );
  INVARIANT( idxs_cnt==expect_cnt, "marking %s dead marked %lu banks, not %lu", LABEL( n ), idxs_cnt, expect_cnt );
  for( ulong i=0UL; i<expect_cnt; i++ ) {
    INVARIANT( idxs[i]==expect[i]->idx, "marking %s dead reported bank %lu, not %s", LABEL( n ), idxs[i], LABEL( expect[i] ) );
  }
  return 1;
}

static int
acquire( scenario_t *     s,
         action_t const * a ) {
  node_t * n = node_find( s, a->label );
  if( !n->live || n->state==FD_BANK_STATE_DEAD || n->state==FD_BANK_STATE_PRUNABLE ) return 0;
  bank_of( s, n )->refcnt++;
  n->refcnt++;
  /* ACQUIRE is not in the paper alphabet: uncounted */
  return 1;
}

static int
release( scenario_t *     s,
         action_t const * a ) {
  node_t * n = node_find( s, a->label );
  if( !n->live || !n->refcnt ) return 0;
  bank_of( s, n )->refcnt--;
  n->refcnt--;
  /* RELEASE is not in the paper alphabet: uncounted */
  return 1;
}

/* Advances the root one child at a time toward n.  fd_banks may refuse
   a step only when the root or a sibling subtree of the next root
   holds references. */

static int
root( scenario_t * s,
      node_t *     n ) {
  if( !n->live || n==s->root || n->state!=FD_BANK_STATE_FROZEN ) return 0;
  int advances = 0;
  while( s->root!=n ) {
    node_t * cand = n;
    while( cand->parent!=s->root ) cand = cand->parent;
    ulong held = s->root->refcnt;
    for( node_t const * c = s->root->child; c; c = c->sibling ) {
      if( c!=cand ) held += subtree_refcnt( c );
    }
    ulong adv = ULONG_MAX;
    int   ok  = fd_banks_advance_root_prepare( s->banks, n->idx, &adv );
    INVARIANT( ok==!held, "advance_root_prepare to %s returned %d with %lu references in the way", LABEL( n ), ok, held );
    if( !ok ) break;
    INVARIANT( adv==cand->idx, "advance_root_prepare to %s picked bank %lu, not %s", LABEL( n ), adv, LABEL( cand ) );
    fd_banks_advance_root( s->banks, adv );

    node_t * old = s->root;
    child_unlink( cand );
    subtree_free( old );
    s->root = cand;
    advances++;
  }
  if( advances ) g_event = EV_ROOT;
  return 1;
}

static int
evict( scenario_t *     s,
       action_t const * a ) {
  node_t * protect = NULL;
  if( a->has_node ) {
    protect = node_find( s, a->label );
    if( !protect->live ) return 0;
  }
  node_t * cand[ BANK_MAX ];
  ulong    cand_cnt = 0UL;
  node_t * pending  = node_of_idx( s, s->banks->prunable_idx );
  if( !pending ) evictable_collect( s, s->root, protect, cand, &cand_cnt );

  ulong idx = fd_banks_get_evictable_bank( s->banks, protect ? bank_of( s, protect ) : NULL );
  if( !cand_cnt ) {
    INVARIANT( idx==ULONG_MAX, "evicted bank %lu with %s", idx, pending ? "a prunable bank pending" : "no evictable leaf" );
    return 1;
  }
  node_t * victim = cand[ s->evict_rr++ % cand_cnt ];
  INVARIANT( idx==victim->idx, "evicted bank %lu, not %s", idx, LABEL( victim ) );
  /* EVICT is not in the paper alphabet: uncounted */
  victim->state = FD_BANK_STATE_PRUNABLE;
  return 1;
}

/* Frees a dead or prunable leaf without references, if fd_banks picks
   one.  A pending prunable bank without references is always picked
   over nothing. */

static int
prune( scenario_t * s ) {
  fd_banks_prune_cancel_info_t cancel[1] = {{ .bank_idx = ULONG_MAX }};
  node_t * pending = node_of_idx( s, s->banks->prunable_idx );
  int ret = fd_banks_prune_one_bank( s->banks, cancel );
  if( !ret ) {
    INVARIANT( !pending || pending->refcnt, "pruned nothing with prunable bank %s unreferenced", LABEL( pending ) );
    return 1;
  }
  node_t * n = node_of_idx( s, cancel->bank_idx );
  INVARIANT( n, "pruned bank %lu, which the model does not hold", cancel->bank_idx );
  INVARIANT( n->state==FD_BANK_STATE_DEAD || n->state==FD_BANK_STATE_PRUNABLE, "pruned bank %s while %s", LABEL( n ), state_name[ n->state ] );
  INVARIANT( !n->child, "pruned bank %s, which has children", LABEL( n ) );
  INVARIANT( ret==1+n->cloned, "pruning %s returned %d", LABEL( n ), ret );
  if( n->cloned ) {
    INVARIANT( cancel->slot==n->label.slot && cancel->bank_seq==n->seq, "pruning %s reported slot %lu seq %lu", LABEL( n ), cancel->slot, cancel->bank_seq );
  }
  g_event = n->state==FD_BANK_STATE_DEAD ? EV_PRUNE_DEAD : -1;
  child_unlink( n );
  node_free( n );
  return 1;
}

static int
action_run( scenario_t *     s,
            action_t const * a ) {
  switch( a->kind ) {
  case NEW_BANK:    return new_bank   ( s, a );
  case BLOCK_START: return block_start( s, a );
  case FINALIZE:    return finalize   ( s, a );
  case DEAD:        return dead       ( s, a );
  case ACQUIRE:     return acquire    ( s, a );
  case RELEASE:     return release    ( s, a );
  case ROOT:        return root       ( s, node_find( s, a->label ) );
  case EVICT:       return evict      ( s, a );
  case PRUNE:       return prune      ( s );
  default:          FD_LOG_CRIT(( "unreachable" ));
  }
}

/* Releases every reference and prunes until fd_banks frees nothing.
   No dead or prunable bank may remain, nor anything in the dead queue.
   Then roots the deepest frozen bank, leftmost on a tie. */

static void
drain( scenario_t * s ) {
  cur_action = s->action_cnt;
  transitions_begin( s );
  for( ulong i=0UL; i<s->slot_cnt*s->width; i++ ) {
    node_t * n = &s->nodes[i];
    if( !n->live ) continue;
    bank_of( s, n )->refcnt -= n->refcnt;
    n->refcnt = 0UL;
  }
  for(;;) {
    ulong used = fd_banks_pool_used( fd_banks_get_bank_pool( s->banks ) );
    prune( s );
    if( fd_banks_pool_used( fd_banks_get_bank_pool( s->banks ) )==used ) break;
  }
  for( ulong i=0UL; i<s->slot_cnt*s->width; i++ ) {
    node_t * n = &s->nodes[i];
    INVARIANT( !n->live || ( n->state!=FD_BANK_STATE_DEAD && n->state!=FD_BANK_STATE_PRUNABLE ),
               "bank %s is still %s with nothing referenced", LABEL( n ), state_name[ n->state ] );
  }
  INVARIANT( fd_banks_dead_empty( fd_banks_get_dead_banks_deque( s->banks ) ), "the dead queue holds %lu entries", fd_banks_dead_cnt( fd_banks_get_dead_banks_deque( s->banks ) ) );

  node_t * tip = NULL;
  for( ulong i=0UL; i<s->slot_cnt*s->width; i++ ) {
    node_t * n = &s->nodes[i];
    if( n->live && n->state==FD_BANK_STATE_FROZEN && n!=s->root && ( !tip || n->label.slot>tip->label.slot ) ) tip = n;
  }
  if( tip ) {
    root( s, tip );
    INVARIANT( s->root==tip, "could not root %s with nothing referenced", LABEL( tip ) );
  }
  transitions_check( s );
  check_structure( s );
}

/* Mapping fresh banks memory for every scenario dominates the run time,
   so a worker reuses one. */

static void * banks_mem;

static void
scenario_run( scenario_t * s ) {
  s->banks = fd_banks_join( fd_banks_new( banks_mem, FD_STAKE_DELEGATIONS_FD, BANK_MAX, FORK_WIDTH, 8UL, 128UL, 8UL, 0, 42UL ) );
  FD_TEST( s->banks );
  fd_bank_t * b = fd_banks_init_bank( s->banks );
  FD_TEST( b );
  b->f.epoch_schedule = (fd_epoch_schedule_t){ .slots_per_epoch = 32UL, .leader_schedule_slot_offset = 32UL };

  s->root        = &s->nodes[0];
  s->root->live  = 1;
  s->root->idx   = b->idx;
  s->root->seq   = b->bank_seq;
  s->root->state = FD_BANK_STATE_FROZEN;
  s->last_seq    = b->bank_seq;
  s->evict_rr    = s->banks->evict_rr_idx;
  cur_action     = ULONG_MAX;
  ev_cnt         = 0UL;
  check_structure( s );

  for( ulong i=0UL; i<s->action_cnt; i++ ) {
    action_t const * a = &s->actions[i];
    cur_action = i;
    transitions_begin( s );
    g_event = -1;
    int ran = action_run( s, a );
    run_cnt[ 2UL*a->kind+(ulong)ran ]++;
    if( g_cov && g_event>=0 && ev_cnt<sizeof(ev_buf) ) ev_buf[ ev_cnt++ ] = (uchar)g_event;
    transitions_check( s );
    check_structure( s );
  }
  if( g_cov ) cov_accumulate();
  drain( s );
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
worker( char ** paths,
        ulong   path_cnt,
        ulong   first,
        ulong   stride,
        ulong * current ) {
  atexit( backtrace_on_exit );
  fd_log_level_logfile_set( 4 );
  fd_log_level_stderr_set ( 4 );

  /* Each worker spills stake delegations to its own file */
  int spill_fd = memfd_create( "bank_scenarios_spill", 0 );
  FD_TEST( spill_fd>=0 );
  FD_TEST( dup2( spill_fd, FD_STAKE_DELEGATIONS_FD )==FD_STAKE_DELEGATIONS_FD );
  FD_TEST( !close( spill_fd ) );
  banks_mem = aligned_alloc( fd_banks_align(), fd_ulong_align_up( fd_banks_footprint( BANK_MAX, FORK_WIDTH, 8UL, 8UL ), fd_banks_align() ) );
  FD_TEST( banks_mem );

  for( ulong i=first; i<path_cnt; i+=stride ) {
    *current = i;
    scenario_t s;
    scenario_load( &s, paths[i] );
    scenario_run( &s );
    scenario_free( &s );
  }
  _exit( 0 );
}

/* Forks --jobs workers over the inputs and prints the first failing
   input, or how many actions of each kind ran and were skipped. */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  ulong jobs = fd_env_strip_cmdline_ulong( &argc, &argv, "--jobs", NULL, (ulong)sysconf( _SC_NPROCESSORS_ONLN ) );

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

  g_cov = !!getenv( "COV" );

  ulong   shared_sz = jobs*sizeof(ulong) + jobs*2UL*ACTION_KIND_CNT*sizeof(ulong);
  ulong * current   = mmap( NULL, shared_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0 );
  pid_t * pids      = malloc( jobs*sizeof(pid_t) );
  FD_TEST( current!=MAP_FAILED && pids );
  ulong * counts = current + jobs;

  ulong cov_off[ COV_MAXT+2 ]; cov_off[1] = 0UL;                 /* byte offset of cov[k] within a worker */
  for( int k=1; k<=COV_MAXT; k++ ) { ulong p=1UL; for( int i=0;i<k;i++) p*=EV_CNT; cov_off[k+1] = cov_off[k] + p; }
  ulong   cov_sz  = cov_off[ COV_MAXT+1 ];                        /* bytes per worker */
  uchar * cov_all = mmap( NULL, jobs*cov_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( cov_all!=MAP_FAILED );

  for( ulong w=0UL; w<jobs; w++ ) {
    pids[w] = fork();
    FD_TEST( pids[w]>=0 );
    if( !pids[w] ) {
      run_cnt = counts + w*2UL*ACTION_KIND_CNT;
      for( int k=1; k<=COV_MAXT; k++ ) cov[k] = cov_all + w*cov_sz + cov_off[k];
      worker( g.gl_pathv, g.gl_pathc, w, jobs, &current[w] );
    }
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

  if( !failed ) {
    FD_LOG_NOTICE(( "pass: %lu scenarios", g.gl_pathc ));
    for( ulong k=0UL; k<ACTION_KIND_CNT; k++ ) {
      ulong run = 0UL, skipped = 0UL;
      for( ulong w=0UL; w<jobs; w++ ) {
        skipped += counts[ w*2UL*ACTION_KIND_CNT + 2UL*k     ];
        run     += counts[ w*2UL*ACTION_KIND_CNT + 2UL*k+1UL ];
      }
      FD_LOG_NOTICE(( "%-11s run %8lu  skipped %8lu", action_kind_name[k], run, skipped ));
    }

    if( g_cov ) {
      /* Aggregate per-worker covered sets and report t=1..COV_MAXT
         coverage against the universe of ordered distinct t-tuples.
         Only distinct tuples are ever set, so a set entry is a covered
         one; iterate each cov[k] and OR across workers. */
      for( int t=1; t<=COV_MAXT; t++ ) {
        ulong lim = 1UL; for( int i=0;i<t;i++) lim *= EV_CNT;
        ulong uni = 1UL; for( int i=0;i<t;i++) uni *= (ulong)( EV_CNT-i ); /* P(EV_CNT,t) */
        ulong covered = 0UL;
        for( ulong i=0UL; i<lim; i++ ) {
          int hit=0; for( ulong w=0UL; w<jobs; w++ ) hit |= cov_all[ w*cov_sz + cov_off[t] + i ];
          covered += !!hit;
        }
        FD_LOG_NOTICE(( "coverage t=%d %lu/%lu (%.2f%%)", t, covered, uni, 100.0*(double)covered/(double)uni ));
      }
    }
  }
  free( pids );
  globfree( &g );
  fd_halt();
  return failed;
}
