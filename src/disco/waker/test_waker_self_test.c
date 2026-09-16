#define _GNU_SOURCE
#include "../../util/fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

/* Exercise the real nested-epoll self-test while varying access to
   procfs.  Only observation is mocked; pipe delivery and epoll are real. */
enum { PROC_NORMAL, PROC_MISSING, PROC_DENIED, PROC_RUNNING };
static int   proc_mode;
static int   proc_fd;
static pid_t parent_pid;
static int   interrupt_wait;

static int
test_open( char const * path, int flags, ... ) {
  /* Opening thread-self in the child would observe the wrong thread. */
  FD_TEST( getpid()==parent_pid );
  FD_TEST( !strcmp( path, "/proc/thread-self/syscall" ) );
  if( proc_mode==PROC_MISSING ) { errno = ENOENT; return -1; }
  proc_fd = open( path, flags );
  FD_TEST( proc_fd>=0 );
  return proc_fd;
}

static long
test_pread( int fd, void * buf, ulong sz, off_t off ) {
  FD_TEST( getpid()!=parent_pid );
  FD_TEST( fd==proc_fd && !off );
  if( proc_mode==PROC_DENIED ) { errno = EACCES; return -1L; }
  if( proc_mode==PROC_RUNNING ) {
    /* A readable procfs that never reports a blocked waiter must not
       keep the child polling until after the parent's epoll timeout. */
    struct timespec delay = { .tv_nsec = 1000000L };
    FD_TEST( !nanosleep( &delay, NULL ) );
    FD_TEST( sz>=8UL );
    memcpy( buf, "running\n", 8UL );
    return 8L;
  }
  return pread( fd, buf, sz, off );
}

static pid_t
test_fork( void ) {
  pid_t pid = fork();
  /* Ensure an accidentally unbounded observer cannot leave the test
     hanging in waitpid (or leave an orphaned polling child). */
  if( !pid ) alarm( 5U );
  return pid;
}

static pid_t
test_waitpid( pid_t pid, int * status, int options ) {
  if( interrupt_wait ) { interrupt_wait = 0; errno = EINTR; return -1; }
  return waitpid( pid, status, options );
}

#define open    test_open
#define pread   test_pread
#define fork    test_fork
#define waitpid test_waitpid
#include "fd_waker.c"
#undef open
#undef pread
#undef fork
#undef waitpid

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  parent_pid = getpid();

  for( proc_mode=PROC_NORMAL; proc_mode<=PROC_RUNNING; proc_mode++ ) {
    FD_LOG_NOTICE(( "procfs observation mode %d", proc_mode ));
    proc_fd = -1;
    interrupt_wait = 1;
    self_test();
    FD_TEST( !interrupt_wait );
    if( proc_fd>=0 ) {
      errno = 0;
      FD_TEST( fcntl( proc_fd, F_GETFD )==-1 && errno==EBADF );
    }
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
