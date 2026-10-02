#include "ag_invariant.h"

struct ag_invariant_block {
  ag_block_hash_t hash;
  ag_block_id_t   parent;
};
typedef struct ag_invariant_block ag_invariant_block_t;

/* What one slot recorded.  The replayed and dead counts keep counting
   past AG_INVARIANT_BLOCK_MAX, so a check can tell an unrecorded
   version from one that was never reported. */

struct ag_invariant_slot {
  ulong slot; /* ULONG_MAX if no slot holds the record */

  int             voted_notar;
  int             voted_skip;
  ag_block_hash_t voted_notar_hash;

  int             notarized; /* 0 no notar cert, 1 one for notarized_hash, 2 for several blocks */
  ag_block_hash_t notarized_hash;

  int             finalized;
  ag_block_hash_t finalized_hash;

  ulong                replayed_cnt;
  ag_invariant_block_t replayed[ AG_INVARIANT_BLOCK_MAX ];
  ulong                dead_cnt;
  ag_block_hash_t      dead[ AG_INVARIANT_BLOCK_MAX ];
};
typedef struct ag_invariant_slot ag_invariant_slot_t;

struct __attribute__((aligned(128UL))) ag_invariant {
  ulong                 slot_cnt;     /* power of two */
  ulong                 finalized_hi; /* highest slot finalized directly, ULONG_MAX if none */
  ag_invariant_slot_t * slots;
};

static ulong
slot_cnt( ulong slot_max ) {
  return fd_ulong_pow2_up( 2UL*slot_max );
}

ulong
ag_invariant_align( void ) {
  return alignof(ag_invariant_t);
}

ulong
ag_invariant_footprint( ulong slot_max ) {
  if( FD_UNLIKELY( !slot_max || slot_max>(1UL<<32) ) ) return 0UL;
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(ag_invariant_t),      sizeof(ag_invariant_t)                               ),
      alignof(ag_invariant_slot_t), sizeof(ag_invariant_slot_t)*slot_cnt( slot_max ) ),
    ag_invariant_align() );
}

void *
ag_invariant_new( void * shmem,
                  ulong  slot_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, ag_invariant_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = ag_invariant_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  ulong cnt = slot_cnt( slot_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  ag_invariant_t *      inv   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_invariant_t),      sizeof(ag_invariant_t)          );
  ag_invariant_slot_t * slots = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_invariant_slot_t), sizeof(ag_invariant_slot_t)*cnt );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_invariant_align() )==(ulong)shmem+footprint );

  inv->slot_cnt     = cnt;
  inv->finalized_hi = ULONG_MAX;
  inv->slots        = slots;
  for( ulong i=0UL; i<cnt; i++ ) slots[ i ].slot = ULONG_MAX;

  return shmem;
}

ag_invariant_t *
ag_invariant_join( void * shinv ) {
  ag_invariant_t * inv = (ag_invariant_t *)shinv;

  if( FD_UNLIKELY( !inv ) ) {
    FD_LOG_WARNING(( "NULL invariant" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)inv, ag_invariant_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned invariant" ));
    return NULL;
  }

  return inv;
}

void *
ag_invariant_leave( ag_invariant_t const * inv ) {
  if( FD_UNLIKELY( !inv ) ) {
    FD_LOG_WARNING(( "NULL invariant" ));
    return NULL;
  }

  return (void *)inv;
}

void *
ag_invariant_delete( void * shinv ) {
  if( FD_UNLIKELY( !shinv ) ) {
    FD_LOG_WARNING(( "NULL invariant" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shinv, ag_invariant_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned invariant" ));
    return NULL;
  }

  return shinv;
}

/* slot_query returns slot's record, or NULL if it has none.  *lost is 1
   if a later slot took the record over, so whether slot had one is
   unknown. */

static ag_invariant_slot_t *
slot_query( ag_invariant_t const * inv,
            ulong                  slot,
            int *                  lost ) {
  ag_invariant_slot_t * rec = &inv->slots[ slot & (inv->slot_cnt-1UL) ];
  *lost = rec->slot!=ULONG_MAX && rec->slot>slot;
  return rec->slot==slot ? rec : NULL;
}

/* slot_record returns slot's record, taking it over from an earlier
   slot if needed.  NULL if a later slot already took it over. */

static ag_invariant_slot_t *
slot_record( ag_invariant_t * inv,
             ulong            slot ) {
  ag_invariant_slot_t * rec = &inv->slots[ slot & (inv->slot_cnt-1UL) ];
  if( FD_LIKELY( rec->slot==slot ) ) return rec;
  if( FD_UNLIKELY( rec->slot!=ULONG_MAX && rec->slot>slot ) ) return NULL;
  memset( rec, 0, sizeof(ag_invariant_slot_t) );
  rec->slot = slot;
  return rec;
}

static ag_invariant_block_t const *
replayed_query( ag_invariant_slot_t const * rec,
                uchar const *               hash ) {
  ulong cnt = fd_ulong_min( rec->replayed_cnt, AG_INVARIANT_BLOCK_MAX );
  for( ulong i=0UL; i<cnt; i++ ) {
    if( !memcmp( rec->replayed[ i ].hash, hash, sizeof(ag_block_hash_t) ) ) return &rec->replayed[ i ];
  }
  return NULL;
}

static int
dead_query( ag_invariant_slot_t const * rec,
            uchar const *               hash ) {
  ulong cnt = fd_ulong_min( rec->dead_cnt, AG_INVARIANT_BLOCK_MAX );
  for( ulong i=0UL; i<cnt; i++ ) {
    if( !memcmp( rec->dead[ i ], hash, sizeof(ag_block_hash_t) ) ) return 1;
  }
  return 0;
}

void
ag_invariant_init( ag_invariant_t *      inv,
                   ag_block_id_t const * boot_block ) {
  ag_invariant_slot_t * rec = slot_record( inv, boot_block->slot );
  if( FD_UNLIKELY( !rec ) ) return;
  rec->voted_notar = 1;
  memcpy( rec->voted_notar_hash, boot_block->hash, sizeof(ag_block_hash_t) );
}

void
ag_invariant_replay_completed( ag_invariant_t *      inv,
                               ag_block_id_t const * block,
                               ag_block_id_t const * parent ) {
  ag_invariant_slot_t * rec = slot_record( inv, block->slot );
  if( FD_UNLIKELY( !rec || replayed_query( rec, block->hash ) ) ) return;
  if( FD_LIKELY( rec->replayed_cnt<AG_INVARIANT_BLOCK_MAX ) ) {
    memcpy( rec->replayed[ rec->replayed_cnt ].hash, block->hash, sizeof(ag_block_hash_t) );
    rec->replayed[ rec->replayed_cnt ].parent = *parent;
  }
  rec->replayed_cnt++;
}

void
ag_invariant_replay_dead( ag_invariant_t *      inv,
                          ag_block_id_t const * block ) {
  ag_invariant_slot_t * rec = slot_record( inv, block->slot );
  if( FD_UNLIKELY( !rec || dead_query( rec, block->hash ) ) ) return;
  if( FD_LIKELY( rec->dead_cnt<AG_INVARIANT_BLOCK_MAX ) ) memcpy( rec->dead[ rec->dead_cnt ], block->hash, sizeof(ag_block_hash_t) );
  rec->dead_cnt++;
}

void
ag_invariant_cert_created( ag_invariant_t *  inv,
                           ag_cert_t const * cert ) {
  if( FD_LIKELY( cert->kind!=AG_CERT_KIND_NOTAR ) ) return;
  ag_invariant_slot_t * rec = slot_record( inv, cert->notar.slot );
  if( FD_UNLIKELY( !rec ) ) return;
  if( FD_LIKELY( !rec->notarized ) ) {
    rec->notarized = 1;
    memcpy( rec->notarized_hash, cert->notar.block_hash, sizeof(ag_block_hash_t) );
  } else if( FD_UNLIKELY( memcmp( rec->notarized_hash, cert->notar.block_hash, sizeof(ag_block_hash_t) ) ) ) {
    rec->notarized = 2;
  }
}

void
ag_invariant_vote( ag_invariant_t *  inv,
                   ag_vote_t const * vote ) {
  ulong                 slot = ag_vote_slot( vote );
  ag_invariant_slot_t * rec  = slot_record( inv, slot );
  if( FD_UNLIKELY( !rec ) ) return; /* a later slot took over the record */

  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    uchar const * hash     = vote->notar.block_hash;
    int           replayed = !!replayed_query( rec, hash ) || rec->replayed_cnt>AG_INVARIANT_BLOCK_MAX;
    if( FD_UNLIKELY( rec->voted_skip  ) ) FD_LOG_CRIT(( "INVARIANT: voted notar and skip in slot %lu", slot ));
    if( FD_UNLIKELY( rec->voted_notar ) ) FD_LOG_CRIT(( "INVARIANT: voted notar twice in slot %lu", slot ));
    if( FD_UNLIKELY( !replayed || dead_query( rec, hash ) ) ) FD_LOG_CRIT(( "INVARIANT: voted notar in slot %lu for a block replay did not complete or found dead", slot ));
    rec->voted_notar = 1;
    memcpy( rec->voted_notar_hash, hash, sizeof(ag_block_hash_t) );
    break;
  }
  case AG_VOTE_KIND_SKIP:
    if( FD_UNLIKELY( rec->voted_notar ) ) FD_LOG_CRIT(( "INVARIANT: voted notar and skip in slot %lu", slot ));
    if( FD_UNLIKELY( rec->voted_skip  ) ) FD_LOG_CRIT(( "INVARIANT: voted skip twice in slot %lu", slot ));
    rec->voted_skip = 1;
    break;
  case AG_VOTE_KIND_FINAL: {
    int notar_named = rec->notarized==2 || ( rec->notarized==1 && !memcmp( rec->notarized_hash, rec->voted_notar_hash, sizeof(ag_block_hash_t) ) );
    if( FD_UNLIKELY( !rec->voted_notar || !notar_named ) ) FD_LOG_CRIT(( "INVARIANT: voted final in slot %lu without voting notar for the block a notar cert names", slot ));
    break;
  }
  default:
    break;
  }
}

/* descends returns 1 if replay's parent links lead from top down to
   block, 0 if they lead elsewhere or stop, and -1 if a link is
   unknown. */

static int
descends( ag_invariant_t const * inv,
          ag_block_id_t          top,
          ag_block_id_t const *  block ) {
  while( top.slot>block->slot ) {
    int                         lost;
    ag_invariant_slot_t const * rec = slot_query( inv, top.slot, &lost );
    if( FD_UNLIKELY( !rec ) ) return lost ? -1 : 0;
    ag_invariant_block_t const * replayed = replayed_query( rec, top.hash );
    if( FD_UNLIKELY( !replayed ) ) return rec->replayed_cnt>AG_INVARIANT_BLOCK_MAX ? -1 : 0;
    top = replayed->parent;
  }
  return ag_block_id_eq( &top, block );
}

/* finalized_descendant returns 0 only if no block finalized above
   block descends to it, and none could be unknown. */

static int
finalized_descendant( ag_invariant_t const * inv,
                      ag_block_id_t const *  block ) {
  if( FD_UNLIKELY( inv->finalized_hi==ULONG_MAX || inv->finalized_hi<=block->slot ) ) return 0;
  int   unknown = inv->finalized_hi-block->slot>inv->slot_cnt; /* the ring cannot hold the whole range */
  ulong hi      = fd_ulong_min( inv->finalized_hi, block->slot+inv->slot_cnt );
  for( ulong slot=block->slot+1UL; slot<=hi; slot++ ) {
    int                         lost;
    ag_invariant_slot_t const * rec = slot_query( inv, slot, &lost );
    if( !rec ) { unknown |= lost; continue; }
    if( !rec->finalized ) continue;
    int d = descends( inv, ag_block_id( slot, rec->finalized_hash ), block );
    if( d==1 ) return 1;
    unknown |= d<0;
  }
  return unknown;
}

void
ag_invariant_finalization( ag_invariant_t *                inv,
                           ag_finalization_event_t const * event,
                           ag_slot_certs_t const *         certs ) {
  ag_block_id_t const * finalized = &event->finalized;
  if( finalized->slot!=ULONG_MAX ) {
    int final      = certs && certs->finalize.slot!=ULONG_MAX;
    int notar      = certs && certs->notar.slot!=ULONG_MAX         && !memcmp( certs->notar.block_hash,         finalized->hash, sizeof(ag_block_hash_t) );
    int fast_final = certs && certs->fast_finalize.slot!=ULONG_MAX && !memcmp( certs->fast_finalize.block_hash, finalized->hash, sizeof(ag_block_hash_t) );
    if( FD_UNLIKELY( !( final && notar ) && !fast_final ) ) FD_LOG_CRIT(( "INVARIANT: finalized slot %lu without a final and notar cert or a fast final cert", finalized->slot ));

    /* Raise finalized_hi even when the record is lost, so a search
       that needs it knows it is unknown. */
    inv->finalized_hi = inv->finalized_hi==ULONG_MAX ? finalized->slot : fd_ulong_max( inv->finalized_hi, finalized->slot );
    ag_invariant_slot_t * rec = slot_record( inv, finalized->slot );
    if( FD_LIKELY( rec ) ) {
      rec->finalized = 1;
      memcpy( rec->finalized_hash, finalized->hash, sizeof(ag_block_hash_t) );
    }
  }

  for( ulong i=0UL; i<event->implicitly_finalized_cnt; i++ ) {
    ag_block_id_t const * block = &event->implicitly_finalized[ i ];
    if( FD_UNLIKELY( !finalized_descendant( inv, block ) ) ) FD_LOG_CRIT(( "INVARIANT: implicitly finalized slot %lu without a finalized descendant linked to it", block->slot ));
  }
}
