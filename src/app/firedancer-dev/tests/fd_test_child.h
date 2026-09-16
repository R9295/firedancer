#ifndef HEADER_fd_src_app_firedancer_dev_tests_fd_test_child_h
#define HEADER_fd_src_app_firedancer_dev_tests_fd_test_child_h

/* Helpers for tests that run parts of a validator in child processes.

   Each child runs a command against a config and is watched through a
   pipe rather than through SIGCHLD: the write end is only ever closed
   by the child exiting, so the read end polls readable exactly once,
   when that happens.  This lets a test wait on a set of children, some
   of which are expected to exit (a readiness probe) and some of which
   are not (a running validator), and learn which one moved. */

#include "../../shared/fd_config.h"
#include "../../platform/fd_sys_util.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/wait.h>

#define FD_TEST_CHILD_MAX (256UL)

struct child_info {
  char const * name;
  int          pipefd;
  int          pid;
};

typedef struct child_info child_info_t;

/* fork_child runs child( config, pipefd ) in a new process and returns a
   handle to it.  The child's exit status becomes the process exit
   code. */

static inline struct child_info
fork_child( char const * name,
            config_t * config,
            int (* child)( config_t * config, int pipefd ) ) {
  int pipefd[2] = {0};
  if( FD_UNLIKELY( -1==pipe( pipefd ) ) ) FD_LOG_ERR(( "pipe failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  int pid = fork();
  if( FD_UNLIKELY( -1==pid ) ) FD_LOG_ERR(( "fork failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( !pid ) {
    if( FD_UNLIKELY( -1==close( pipefd[ 0 ] ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    int result = child( config, pipefd[ 1 ] );
    fd_sys_util_exit_group( result );
  }
  if( FD_UNLIKELY( -1==close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return (struct child_info){ .name = name, .pipefd = pipefd[ 0 ], .pid = pid };
}

/* wait_children blocks until one of children exits, and returns its
   index.  It fails the test if none exits within timeout_seconds, or if
   the one that exits does so with a signal or a nonzero status.  The
   returned child's pipe is closed, so a caller waiting for more than one
   child must remove it from the array before calling again. */

static inline ulong
wait_children( struct child_info * children,
               ulong               children_cnt,
               ulong               timeout_seconds ) {
  struct pollfd pfd[ FD_TEST_CHILD_MAX ];
  FD_TEST( children_cnt<=FD_TEST_CHILD_MAX );
  for( ulong i=0; i<children_cnt; i++ ) {
    pfd[ i ] = (struct pollfd){
      .fd      = children[ i ].pipefd,
      .events  = 0,
    };
  }

  int exited_child_cnt = poll( pfd, children_cnt, (int)(timeout_seconds*1000UL) );
  if( FD_UNLIKELY( -1==exited_child_cnt ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !exited_child_cnt ) ) FD_LOG_ERR(( "`%s` timed out", children[ 0 ].name ));

  ulong exited_child;
  for( exited_child=0; exited_child<children_cnt; exited_child++ ) {
    if( FD_UNLIKELY( pfd[ exited_child ].revents & POLLHUP ) ) break;
  }
  FD_TEST( exited_child<children_cnt );

  int wstatus;
  int exited_pid = waitpid( children[ exited_child ].pid, &wstatus, __WALL );
  if( FD_UNLIKELY( -1==exited_pid ) ) FD_LOG_ERR(( "waitpid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  else if( FD_UNLIKELY( !exited_pid ) ) FD_LOG_ERR(( "`%s` did not exit", children[ exited_child ].name ));
  else if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) FD_LOG_ERR(( "`%s` failed with signal %d (%s)", children[ exited_child ].name, WTERMSIG( wstatus ), strsignal( WTERMSIG( wstatus ) ) ));
  else if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) FD_LOG_ERR(( "`%s` failed with status %d", children[ exited_child ].name, WEXITSTATUS( wstatus ) ));

  if( FD_UNLIKELY( -1==close( children[ exited_child ].pipefd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return exited_child;
}

#endif /* HEADER_fd_src_app_firedancer_dev_tests_fd_test_child_h */
