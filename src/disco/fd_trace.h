#ifndef HEADER_fd_src_disco_fd_trace_h
#define HEADER_fd_src_disco_fd_trace_h

/* FD_TRACE logs one consensus event to the log file at INFO level, as

     TRACE <tile> <event> key=value ...

   Tiles trace the decisions that move a slot through Alpenglow: votes
   and certificates sent and received, block versions built, delivered,
   replayed or abandoned, roots, and leader slots.  Every validator in a
   test cluster writes the same format, so contrib/test/
   show_fd_cluster_trace.py can merge one slot's events from all of
   them.  Values never contain spaces.  Block ids are base58, and FEC
   set merkle roots are their first 4 bytes in hex.

   An event is logged once per decision, not per shred or packet.
   Build with EXTRA_CPPFLAGS=-DFD_TRACE_ENABLED=0, in a separate
   BUILDDIR, to compile all events out. */

#include "../util/log/fd_log.h"
#include "../ballet/base58/fd_base58.h"

#ifndef FD_TRACE_ENABLED
#define FD_TRACE_ENABLED 1
#endif

/* FD_TRACE takes a printf format, which starts with "<tile> <event>",
   and at least one argument. */

#define FD_TRACE( fmt, ... ) do {                                         \
    if( FD_TRACE_ENABLED ) FD_LOG_INFO(( "TRACE " fmt, __VA_ARGS__ ));    \
  } while(0)

/* fd_trace_hash writes the base58 form of the 32 bytes at hash to out,
   or "-" if hash is NULL, and returns out.  Usage:

     char b58[ FD_BASE58_ENCODED_32_SZ ];
     FD_TRACE( "votor cert_rx slot=%lu block=%s", slot, fd_trace_hash( b58, hash ) ); */

static inline char *
fd_trace_hash( char         out[ FD_BASE58_ENCODED_32_SZ ],
               void const * hash ) {
  if( FD_UNLIKELY( !hash ) ) { out[ 0 ] = '-'; out[ 1 ] = '\0'; return out; }
  return fd_base58_encode_32( (uchar const *)hash, NULL, out );
}

/* fd_trace_root4 returns the first 4 bytes of a merkle root, to print
   with %08x. */

static inline uint
fd_trace_root4( void const * root ) {
  return fd_uint_bswap( fd_uint_load_4( root ) );
}

#endif /* HEADER_fd_src_disco_fd_trace_h */
