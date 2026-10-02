#ifndef HEADER_fd_src_choreo_votor_ag_invariant_h
#define HEADER_fd_src_choreo_votor_ag_invariant_h

/* ag_invariant checks votor invariants on behalf of the votor tile and
   aborts with FD_LOG_CRIT on the first violation.  It keeps its own
   record of the blocks replay reported, our votes, the notar certs and
   the finalized blocks, independent of the votor's and pool's state, so
   a bookkeeping bug in either cannot hide a violation.

   On every vote we cast (ag_invariant_vote):

     1. never notar and skip in the same slot
     2. at most one notar per slot
     3. at most one skip per slot
     4. notar only for a block whose replay completed and was not dead
     5. final only after our notar for the block a notar cert names

   On every finalization the pool makes (ag_invariant_finalization):

     6. a finalized block has a final and notar cert, or a fast final
        cert
     7. an implicitly finalized block has a finalized descendant that
        replay's parent links lead down to

   The record is a ring of slots indexed by slot number, covering twice
   the pool's live slots.  A slot whose record a later slot took over is
   unknown, and checks that need it pass rather than fail. */

#include "ag_votor_base.h"
#include "ag_cert.h"
#include "ag_finality_tracker.h"
#include "ag_slot_state.h"
#include "ag_vote.h"

/* AG_INVARIANT_BLOCK_MAX is how many replayed, and how many dead,
   versions of one slot are recorded.  Checks that need a further
   version pass. */

#define AG_INVARIANT_BLOCK_MAX (AG_EQVOC_BLOCK_HASH_MAX+1UL)

typedef struct ag_invariant ag_invariant_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
ag_invariant_align( void );

FD_FN_CONST ulong
ag_invariant_footprint( ulong slot_max );

void *
ag_invariant_new( void * shmem,
                  ulong  slot_max );

ag_invariant_t *
ag_invariant_join( void * shinv );

void *
ag_invariant_leave( ag_invariant_t const * inv );

void *
ag_invariant_delete( void * shinv );

/* ag_invariant_init records boot_block, which ag_votor_init treats as
   already voted notar. */

void
ag_invariant_init( ag_invariant_t *      inv,
                   ag_block_id_t const * boot_block );

/* ag_invariant_replay_completed and ag_invariant_replay_dead record
   what replay reported for a block.  Record a completion before the
   pool or votor sees it: the pool can finalize on it at once. */

void
ag_invariant_replay_completed( ag_invariant_t *      inv,
                               ag_block_id_t const * block,
                               ag_block_id_t const * parent );

void
ag_invariant_replay_dead( ag_invariant_t *      inv,
                          ag_block_id_t const * block );

/* ag_invariant_cert_created records a cert the pool created, before the
   votor sees it.  Only notar certs matter (invariant 5). */

void
ag_invariant_cert_created( ag_invariant_t *  inv,
                           ag_cert_t const * cert );

/* ag_invariant_vote checks invariants 1 to 5 on a vote the votor cast.
   Skip standstill re-broadcasts: they repeat votes already checked. */

void
ag_invariant_vote( ag_invariant_t *  inv,
                   ag_vote_t const * vote );

/* ag_invariant_finalization checks invariants 6 and 7 on a finalization
   event.  certs are the pool's certs for the slot event finalizes
   directly, NULL if it has none. */

void
ag_invariant_finalization( ag_invariant_t *                inv,
                           ag_finalization_event_t const * event,
                           ag_slot_certs_t const *         certs );

FD_PROTOTYPES_END

#endif
