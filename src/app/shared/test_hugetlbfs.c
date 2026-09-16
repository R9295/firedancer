#include "commands/configure/configure.h"
#include "../platform/fd_file_util.h"
#include "../platform/fd_sys_util.h"

#include <errno.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

char const * FD_BINARY_NAME = "test_hugetlbfs";
char const * FD_APP_NAME = "test_hugetlbfs";
action_t * ACTIONS[] = { NULL };
fd_topo_run_tile_t * TILES[] = { NULL };
configure_stage_t * STAGES[] = { NULL };

/* Exercise the real configure init against a simulated four-node kernel.
   In particular, free_hugepages still includes min_size reservations. */
static uint  pool_total[ 4 ][ 2 ];
static uint  pool_free [ 4 ][ 2 ];
static ulong required  [ 4 ][ 2 ];
static ulong reserved  [ 2 ];
static ulong writes;
static ulong mounts;

static ulong test_numa_cnt( void ) { return 4UL; }
static ulong test_huge_cnt( fd_topo_t const * topo, ulong node, int anonymous ) {
  (void)topo; (void)anonymous;
  return required[ node ][ 0 ];
}
static ulong test_gigantic_cnt( fd_topo_t const * topo, ulong node ) {
  (void)topo;
  return required[ node ][ 1 ];
}

static int
test_read_uint( char const * path, uint * value ) {
  ulong node;
  ulong size;
  char field[ 32 ];
  FD_TEST( sscanf( path, "/sys/devices/system/node/node%lu/hugepages/hugepages-%lukB/%31s", &node, &size, field )==3 );
  FD_TEST( node<4UL && (size==2048UL || size==1048576UL) );
  ulong kind = (ulong)(size==1048576UL);
  if( !strcmp( field, "free_hugepages" ) ) *value = pool_free[ node ][ kind ];
  else {
    FD_TEST( !strcmp( field, "nr_hugepages" ) );
    *value = pool_total[ node ][ kind ];
  }
  return 0;
}

static int
test_read_ulong( char const * path, ulong * value ) {
  ulong size;
  char field[ 32 ];
  FD_TEST( sscanf( path, "/sys/kernel/mm/hugepages/hugepages-%lukB/%31s", &size, field )==2 );
  FD_TEST( size==2048UL || size==1048576UL );
  ulong kind = (ulong)(size==1048576UL);
  if( !strcmp( field, "resv_hugepages" ) ) *value = reserved[ kind ];
  else {
    FD_TEST( !strcmp( field, "free_hugepages" ) );
    *value = 0UL;
    for( ulong i=0UL; i<4UL; i++ ) *value += pool_free[ i ][ kind ];
  }
  return 0;
}

static int
test_write_uint( char const * path, uint value ) {
  ulong node;
  ulong size;
  char field[ 32 ];
  FD_TEST( sscanf( path, "/sys/devices/system/node/node%lu/hugepages/hugepages-%lukB/%31s", &node, &size, field )==3 );
  FD_TEST( node<4UL && (size==2048UL || size==1048576UL) && !strcmp( field, "nr_hugepages" ) );
  ulong kind = (ulong)(size==1048576UL);
  FD_TEST( value>=pool_total[ node ][ kind ] );
  pool_free[ node ][ kind ] += value-pool_total[ node ][ kind ];
  pool_total[ node ][ kind ] = value;
  writes++;
  return 0;
}

static int
test_mount( char const * source, char const * target, char const * type, ulong flags, void const * data ) {
  (void)target;
  FD_TEST( !strcmp( source, "none" ) && !strcmp( type, "hugetlbfs" ) && !flags );
  ulong page_size;
  ulong min_size = 0UL;
  FD_TEST( sscanf( data, "pagesize=%lu,min_size=%lu", &page_size, &min_size )>=1 );
  FD_TEST( page_size==2097152UL || page_size==1073741824UL );
  FD_TEST( !(min_size%page_size) );
  ulong kind = (ulong)(page_size==1073741824UL);
  ulong free_pages = 0UL;
  for( ulong i=0UL; i<4UL; i++ ) free_pages += pool_free[ i ][ kind ];
  if( reserved[ kind ]+min_size/page_size>free_pages ) { errno = ENOMEM; return -1; }
  reserved[ kind ] += min_size/page_size;
  mounts++;
  return 0;
}

static int test_mkdir( char const * p, uint u, uint g, int d ) { (void)p; (void)u; (void)g; (void)d; return 0; }
static int test_chown( char const * p, uid_t u, gid_t g ) { (void)p; (void)u; (void)g; return 0; }
static int test_chmod( char const * p, mode_t m ) { (void)p; (void)m; return 0; }

#define fd_shmem_numa_cnt       test_numa_cnt
#define fd_topo_huge_page_cnt   test_huge_cnt
#define fd_topo_gigantic_page_cnt test_gigantic_cnt
#define fd_file_util_read_uint test_read_uint
#define fd_file_util_read_ulong test_read_ulong
#define fd_file_util_write_uint test_write_uint
#define fd_file_util_mkdir_all test_mkdir
#define mount test_mount
#define chown test_chown
#define chmod test_chmod
#include "commands/configure/hugetlbfs.c"

static config_t config;

static void
reset( void ) {
  memset( pool_total, 0, sizeof(pool_total) );
  memset( pool_free,  0, sizeof(pool_free) );
  memset( required,   0, sizeof(required) );
  memset( reserved,   0, sizeof(reserved) );
  writes = mounts = 0UL;
  strcpy( config.hugetlbfs.huge_page_mount_path, "/test/.huge" );
  strcpy( config.hugetlbfs.gigantic_page_mount_path, "/test/.gigantic" );
  config.development.hugetlbfs.min_size = 1;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  /* Three separate mounts on the same NUMA node must have three times
     the capacity, even though none of their pages has been faulted in. */
  reset();
  required[ 1 ][ 0 ] = 100UL;
  required[ 1 ][ 1 ] = 2UL;
  for( ulong i=1UL; i<=3UL; i++ ) {
    init( &config );
    FD_TEST( pool_total[ 1 ][ 0 ]==i*100UL && reserved[ 0 ]==i*100UL );
    FD_TEST( pool_total[ 1 ][ 1 ]==i*2UL   && reserved[ 1 ]==i*2UL );
  }
  FD_TEST( writes==6UL && mounts==6UL );

  /* The observed failure: 11732 free pages, 6221 already reserved.
     The second topology needs 6221, so exactly 710 must be added. */
  reset();
  uint initial[ 4 ] = { 242U, 5667U, 5667U, 156U };
  for( ulong i=0UL; i<4UL; i++ ) pool_total[ i ][ 0 ] = pool_free[ i ][ 0 ] = initial[ i ];
  reserved[ 0 ] = 6221UL;
  required[ 0 ][ 0 ] = 242UL;
  required[ 1 ][ 0 ] = 156UL;
  required[ 2 ][ 0 ] = 5667UL;
  required[ 3 ][ 0 ] = 156UL;
  init( &config );
  FD_TEST( writes==1UL && pool_total[ 2 ][ 0 ]==6377U && reserved[ 0 ]==12442UL );
  FD_TEST( pool_total[ 0 ][ 0 ]==242U && pool_total[ 1 ][ 0 ]==5667U && pool_total[ 3 ][ 0 ]==156U );

  /* Reuse sufficient unreserved capacity, including allocated pages
     in nr_hugepages that are no longer free. */
  reset();
  pool_total[ 0 ][ 0 ] = 400U;
  pool_free [ 0 ][ 0 ] = 200U;
  reserved[ 0 ] = 100UL;
  required[ 0 ][ 0 ] = 100UL;
  init( &config );
  FD_TEST( !writes && reserved[ 0 ]==200UL );

  /* Without min_size, reserve capacity once and do not grow it again
     when configuring another mount before allocating any files. */
  reset();
  config.development.hugetlbfs.min_size = 0;
  required[ 3 ][ 0 ] = 50UL;
  init( &config );
  init( &config );
  FD_TEST( writes==1UL && pool_total[ 3 ][ 0 ]==50U && !reserved[ 0 ] );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
