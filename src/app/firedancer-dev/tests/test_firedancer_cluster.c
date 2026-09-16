#define _GNU_SOURCE
#include "../main.h"

#include "../../firedancer/topology.h"
#include "../../firedancer/config.h"
#include "../../platform/fd_cap_chk.h"
#include "../../platform/fd_file_util.h"
#include "../../platform/fd_sys_util.h"
#include "../../shared/commands/ready.h"
#include "../../shared/fd_bootinfo.h"
#include "../../shared/fd_config.h"
#include "../../shared_dev/commands/dev.h"
#include "../../shared_dev/commands/wksp.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/metrics/generated/fd_metrics_replay.h"
#include "../../../util/shmem/fd_shmem.h"
#include "fd_test_child.h"

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* test_firedancer_cluster runs a multi-validator Alpenglow cluster on
   one host and asserts that every validator roots blocks.

   Each validator is one child process running all of its tiles as
   threads, which is what `--no-clone` gives a single validator.  The
   test supervises them with the pipe handles in fd_test_child.h: a
   validator child never exits on its own, so if one is reported as
   exited the test fails with its status, and only the probe children
   are expected to finish.

   The cluster needs one genesis naming every validator, with a BLS key
   per validator and Alpenglow active at slot 0.  This repository's
   genesis stage only builds a single-validator genesis, so that file
   still comes from `solana-genesis --alpenglow` in an Alpenglow-capable
   Agave checkout.  The node configurations that point at it are host
   specific too: ports, CPU affinities, and identities cannot be
   guessed.  The test therefore reads ready-made configurations from the
   environment, and skips when they are absent, rather than failing on
   hosts that have not been set up for it.

     FD_CLUSTER_CONFIGS   colon-separated node config paths, in order
     FD_CLUSTER_ROOT_SLOT slot every validator must root (default 8)
     FD_CLUSTER_TIMEOUT_S seconds to reach it (default 180)

   The huge page mount, CPU partition, and snapshot directory of every
   node must already be configured, exactly as when running a validator with
   `--no-configure`:

     for cfg in /cluster/node-{0,1,2}.toml; do
       sudo build/firedancer-dev --config "$cfg" --alpenglow \
         configure init hugetlbfs cpuset snapshots
     done

   See the node configuration matrix in README.md. */

#define CLUSTER_MAX (FD_TEST_CHILD_MAX/2UL)

static config_t * cluster_configs[ CLUSTER_MAX ];
static ulong      cluster_root_slot;
static ulong      cluster_timeout_s;

/* Point this process's shared memory domain at the node's huge page
   mount.  Validators in one cluster may each own a mount, and a child
   inherits whichever domain the test booted with, so it must rebind
   before it creates or joins any workspace. */

static void
adopt_shmem_domain( config_t const * config ) {
  char   shmem_path[ PATH_MAX+16UL ];
  char * argv[ 3 ] = { "--shmem-path", shmem_path, NULL };
  char ** pargv = argv;
  int     argc  = 2;

  FD_TEST( fd_cstr_printf_check( shmem_path, sizeof(shmem_path), NULL, "%s", config->hugetlbfs.mount_path ) );
  fd_shmem_private_boot( &argc, &pargv );
}

/* Create the node's workspaces up front, in their own child, rather
   than letting the validator do it on the way up.  A probe attaches to
   a workspace by name, so it would otherwise race the validator that
   creates it. */

static int
cluster_wksp( config_t * config,
              int        pipefd ) {
  (void)pipefd;

  fd_log_thread_set( "wksp" );
  adopt_shmem_domain( config );

  args_t args = {0};
  fd_cap_chk_t * chk = fd_cap_chk_join( fd_cap_chk_new( __builtin_alloca_with_align( fd_cap_chk_footprint(), FD_CAP_CHK_ALIGN ) ) );
  wksp_cmd_perm( &args, chk, config );
  ulong err_cnt = fd_cap_chk_err_cnt( chk );
  if( FD_UNLIKELY( err_cnt ) ) {
    for( ulong i=0UL; i<err_cnt; i++ ) FD_LOG_WARNING(( "%s", fd_cap_chk_err( chk, i ) ));
    FD_LOG_ERR(( "insufficient permissions to create workspaces for `%s`", config->name ));
  }
  wksp_cmd_fn( &args, config );
  return 0;
}

static int
cluster_validator( config_t * config,
                   int        pipefd ) {
  (void)pipefd;

  fd_log_thread_set( "validator" );
  adopt_shmem_domain( config );

  args_t args = {
    .dev.parent_pipefd      = -1,
    .dev.no_configure       = 1,
    .dev.no_init_workspaces = 1,
    .dev.no_agave           = 1,
    .dev.no_watch           = 1,
  };
  fd_cap_chk_t * chk = fd_cap_chk_join( fd_cap_chk_new( __builtin_alloca_with_align( fd_cap_chk_footprint(), FD_CAP_CHK_ALIGN ) ) );
  dev_cmd_perm( &args, chk, config );
  ulong err_cnt = fd_cap_chk_err_cnt( chk );
  if( FD_UNLIKELY( err_cnt ) ) {
    for( ulong i=0UL; i<err_cnt; i++ ) FD_LOG_WARNING(( "%s", fd_cap_chk_err( chk, i ) ));
    FD_LOG_ERR(( "insufficient permissions to run validator `%s`", config->name ));
  }
  dev_cmd_fn( &args, config, NULL );
  return 0;
}

/* wait_for_root reads the validator's replay root slot straight out of
   its metrics workspace.  The root slot only advances on finalization,
   so it is the cluster-wide liveness claim the test is making: it is
   reached only if this validator saw enough of the others to finalize
   that far. */

static void
wait_for_root( config_t * config ) {
  fd_bootinfo_adopt( config );

  ulong wksp_id = fd_topo_find_wksp( &config->topo, "metric_in" );
  FD_TEST( wksp_id!=ULONG_MAX );

  fd_bootinfo_check_layout( config );
  fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ wksp_id ], FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_workspace_fill( &config->topo, &config->topo.workspaces[ wksp_id ] );

  ulong replay_idx = fd_topo_find_tile( &config->topo, "replay", 0UL );
  FD_TEST( replay_idx!=ULONG_MAX );
  fd_topo_tile_t * replay = &config->topo.tiles[ replay_idx ];

  long start = fd_log_wallclock();
  long last  = start;
  for(;;) {
    ulong root_slot = fd_metrics_tile( replay->metrics )[ FD_METRICS_GAUGE_REPLAY_ROOT_SLOT_OFF ];
    if( FD_LIKELY( root_slot>=cluster_root_slot ) ) {
      FD_LOG_NOTICE(( "`%s` rooted slot %lu", config->name, root_slot ));
      break;
    }

    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now-start > (long)cluster_timeout_s*1000000000L ) )
      FD_LOG_ERR(( "`%s` did not root slot %lu within %lu seconds (currently %lu)",
                   config->name, cluster_root_slot, cluster_timeout_s, root_slot ));
    if( FD_UNLIKELY( now-last > 5000000000L ) ) {
      FD_LOG_NOTICE(( "waiting for `%s` to root slot %lu %s(currently %lu)%s",
                      config->name, cluster_root_slot, fd_log_style_dim(), root_slot, fd_log_style_normal() ));
      last = now;
    }
    fd_log_sleep( 100000000L );
  }

  fd_topo_leave_workspaces( &config->topo );
}

static int
cluster_probe( config_t * config,
               int        pipefd ) {
  (void)pipefd;

  fd_log_thread_set( "probe" );
  adopt_shmem_domain( config );

  /* Wait for every tile to come up first, so a validator that never
     boots is reported as a readiness failure rather than as a missing
     root slot much later. */

  args_t args = { .ready.ready_slot = 0UL };
  ready_cmd_fn( &args, config );

  wait_for_root( config );
  return 0;
}

static ulong
parse_configs( char * spec ) {
  ulong cnt = 0UL;
  for( char * path=strtok( spec, ":" ); path; path=strtok( NULL, ":" ) ) {
    if( FD_UNLIKELY( cnt>=CLUSTER_MAX ) ) FD_LOG_ERR(( "too many validators, max %lu", CLUSTER_MAX ));

    ulong  user_config_sz = 0UL;
    char * user_config    = fd_file_util_read_all( path, &user_config_sz );
    if( FD_UNLIKELY( user_config==MAP_FAILED ) )
      FD_LOG_ERR(( "failed to read config `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

    config_t * config = aligned_alloc( alignof(config_t), sizeof(config_t) );
    FD_TEST( config );
    fd_config_load( 1, 1, (char const *)firedancer_default_config, firedancer_default_config_sz,
                    NULL, NULL, 0UL, user_config, user_config_sz, path, config, 1 /* dev */ );
    if( FD_UNLIKELY( -1==munmap( user_config, user_config_sz ) ) )
      FD_LOG_ERR(( "munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    config->has_user_config              = 1;
    config->development.no_clone         = 1;
    config->development.no_agave         = 1;
    config->firedancer.development.alpenglow = 1;
    config->log.log_fd                   = -1;
    fd_topo_initialize( config );

    cluster_configs[ cnt++ ] = config;
  }
  return cnt;
}

/* A workspace file is named "<config name>_<workspace>" inside the
   node's huge page mount, so two validators that agree on both would
   silently share memory and corrupt each other. */

static void
check_distinct( ulong validator_cnt ) {
  for( ulong i=0UL; i<validator_cnt; i++ ) {
    for( ulong j=i+1UL; j<validator_cnt; j++ ) {
      if( FD_UNLIKELY( !strcmp( cluster_configs[ i ]->name, cluster_configs[ j ]->name ) &&
                       !strcmp( cluster_configs[ i ]->hugetlbfs.mount_path, cluster_configs[ j ]->hugetlbfs.mount_path ) ) )
        FD_LOG_ERR(( "validators %lu and %lu share both `name` (%s) and `hugetlbfs.mount_path` (%s); "
                     "give each validator its own name, its own mount, or both",
                     i, j, cluster_configs[ i ]->name, cluster_configs[ i ]->hugetlbfs.mount_path ));
    }
  }
}

static char cluster_child_name[ FD_TEST_CHILD_MAX ][ 96 ];

static int
test_firedancer_cluster( ulong validator_cnt ) {
  struct child_info children    [ FD_TEST_CHILD_MAX ];
  int               is_validator[ FD_TEST_CHILD_MAX ];
  ulong             child_cnt = 0UL;

  for( ulong i=0UL; i<validator_cnt; i++ ) {
    char name[ 96 ];
    FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "wksp %s", cluster_configs[ i ]->name ) );
    struct child_info wksp = fork_child( name, cluster_configs[ i ], cluster_wksp );
    wait_children( &wksp, 1UL, 120UL );
  }

  for( ulong i=0UL; i<validator_cnt; i++ ) {
    char * name = cluster_child_name[ child_cnt ];
    FD_TEST( fd_cstr_printf_check( name, sizeof(cluster_child_name[ 0 ]), NULL, "validator %s", cluster_configs[ i ]->name ) );
    children    [ child_cnt ] = fork_child( name, cluster_configs[ i ], cluster_validator );
    is_validator[ child_cnt ] = 1;
    FD_LOG_NOTICE(( "%s pid %d", name, children[ child_cnt ].pid ));
    child_cnt++;
  }
  for( ulong i=0UL; i<validator_cnt; i++ ) {
    char * name = cluster_child_name[ child_cnt ];
    FD_TEST( fd_cstr_printf_check( name, sizeof(cluster_child_name[ 0 ]), NULL, "probe %s", cluster_configs[ i ]->name ) );
    children    [ child_cnt ] = fork_child( name, cluster_configs[ i ], cluster_probe );
    is_validator[ child_cnt ] = 0;
    child_cnt++;
  }

  /* Every probe must finish and no validator may.  wait_children closes
     the pipe of whichever child it reports, so drop that child from the
     set before waiting again. */

  for( ulong done=0UL; done<validator_cnt; done++ ) {
    ulong exited = wait_children( children, child_cnt, cluster_timeout_s+60UL );
    if( FD_UNLIKELY( is_validator[ exited ] ) )
      FD_LOG_ERR(( "%s exited before the cluster rooted slot %lu", children[ exited ].name, cluster_root_slot ));
    child_cnt--;
    children    [ exited ] = children    [ child_cnt ];
    is_validator[ exited ] = is_validator[ child_cnt ];
  }

  FD_LOG_NOTICE(( "pass" ));
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_log_thread_set( "supervisor" );

  char const * spec = getenv( "FD_CLUSTER_CONFIGS" );
  if( FD_UNLIKELY( !spec || !spec[ 0 ] ) ) {
    FD_LOG_NOTICE(( "skip: set FD_CLUSTER_CONFIGS to a colon-separated list of node configs to run the cluster" ));
    fd_halt();
    return 0;
  }

  cluster_root_slot = fd_env_strip_cmdline_ulong( &argc, &argv, "--root-slot", "FD_CLUSTER_ROOT_SLOT", 8UL   );
  cluster_timeout_s = fd_env_strip_cmdline_ulong( &argc, &argv, "--timeout",   "FD_CLUSTER_TIMEOUT_S", 180UL );

  char spec_buf[ 8192 ];
  FD_TEST( fd_cstr_printf_check( spec_buf, sizeof(spec_buf), NULL, "%s", spec ) );
  ulong validator_cnt = parse_configs( spec_buf );
  FD_TEST( validator_cnt );
  check_distinct( validator_cnt );

  /* A PID namespace makes every validator, and every tile thread they
     spawn, die with the test even if it is killed abruptly. */

  if( FD_UNLIKELY( -1==unshare( CLONE_NEWPID ) ) )
    FD_LOG_ERR(( "unshare(CLONE_NEWPID) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int pid = fork();
  if( FD_UNLIKELY( -1==pid ) ) FD_LOG_ERR(( "fork failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( !pid ) return test_firedancer_cluster( validator_cnt );

  int wstatus;
  for(;;) {
    int exited_pid = waitpid( pid, &wstatus, __WALL );
    if( FD_UNLIKELY( -1==exited_pid && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( -1==exited_pid ) ) FD_LOG_ERR(( "waitpid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    break;
  }

  fd_halt();
  if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) return 128+WTERMSIG( wstatus );
  return WEXITSTATUS( wstatus );
}
