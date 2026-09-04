#define _GNU_SOURCE

#include "../../../util/fd_util_base.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TEST(c) do {                                                           \
    if( FD_UNLIKELY( !(c) ) ) {                                               \
      fprintf( stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #c );        \
      return 1;                                                               \
    }                                                                         \
  } while(0)

static volatile sig_atomic_t fake_stop;

static int
write_file( char const * path,
            char const * text ) {
  int fd = open( path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600 );
  if( fd<0 ) return -1;
  ulong sz = (ulong)strlen( text );
  long written = write( fd, text, sz );
  int err = written==(long)sz ? 0 : -1;
  if( close( fd ) ) err = -1;
  return err;
}

static int
wait_for_path( char const * path,
               ulong        timeout_ms ) {
  for( ulong waited=0UL; waited<timeout_ms; waited+=10UL ) {
    if( !access( path, F_OK ) ) return 0;
    struct timespec delay = { .tv_sec=0, .tv_nsec=10000000L };
    (void)nanosleep( &delay, NULL );
  }
  return -1;
}

static int
wait_for_pid( pid_t pid,
              int * status,
              ulong timeout_ms ) {
  for( ulong waited=0UL; waited<timeout_ms; waited+=10UL ) {
    pid_t result = waitpid( pid, status, WNOHANG );
    if( result==pid ) return 0;
    if( result<0 && errno!=EINTR ) return -1;
    struct timespec delay = { .tv_sec=0, .tv_nsec=10000000L };
    (void)nanosleep( &delay, NULL );
  }
  return -1;
}

static void
fake_signal_handler( int sig ) {
  (void)sig;
  fake_stop = 1;
}

static int
fake_validator( int     argc,
                char ** argv ) {
  char const * testdir = getenv( "FD_CLUSTER_TEST_DIR" );
  char const * config0 = getenv( "FD_CLUSTER_CONFIG0" );
  char const * config1 = getenv( "FD_CLUSTER_CONFIG1" );
  if( !testdir || !config0 || !config1 ) return 90;
  if( argc!=8 )                              return 91;
  if( strcmp( argv[ 1 ], "--config" ) )     return 92;
  if( strcmp( argv[ 3 ], "--alpenglow" ) ) return 93;
  if( strcmp( argv[ 4 ], "--no-clone" ) )  return 94;
  if( strcmp( argv[ 5 ], "dev" ) )          return 95;
  if( strcmp( argv[ 6 ], "--no-watch" ) )  return 96;
  if( strcmp( argv[ 7 ], "--no-configure" ) ) return 97;

  char const * index;
  char const * peer_index;
  if( !strcmp( argv[ 2 ], config0 ) ) {
    index = "0";
    peer_index = "1";
  } else if( !strcmp( argv[ 2 ], config1 ) ) {
    index = "1";
    peer_index = "0";
  } else return 98;

  struct sigaction action;
  memset( &action, 0, sizeof(action) );
  action.sa_handler = fake_signal_handler;
  sigemptyset( &action.sa_mask );
  if( sigaction( SIGINT, &action, NULL ) || sigaction( SIGTERM, &action, NULL ) ||
      sigaction( SIGHUP, &action, NULL ) ) return 99;

  char path[ PATH_MAX ];
  int len = snprintf( path, sizeof(path), "%s/ready-%s", testdir, index );
  if( len<0 || (ulong)len>=sizeof(path) || write_file( path, argv[ 2 ] ) ) return 100;

  char const * fail_config = getenv( "FD_CLUSTER_FAIL_CONFIG" );
  if( fail_config && !strcmp( argv[ 2 ], fail_config ) ) {
    len = snprintf( path, sizeof(path), "%s/ready-%s", testdir, peer_index );
    if( len<0 || (ulong)len>=sizeof(path) || wait_for_path( path, 5000UL ) ) return 101;
    return 42;
  }

  while( !fake_stop ) pause();
  len = snprintf( path, sizeof(path), "%s/stopped-%s", testdir, index );
  if( len<0 || (ulong)len>=sizeof(path) || write_file( path, "stopped\n" ) ) return 102;
  return 0;
}

static pid_t
launch_pattern( char const * cluster,
                char const * self,
                char const * log_dir,
                char const * pattern ) {
  pid_t pid = fork();
  if( pid ) return pid;
  execl( cluster, cluster, "--firedancer", self, "--log-dir", log_dir,
         "--validators", "2", "--config-pattern", pattern, (char *)NULL );
  _exit( 127 );
}

static pid_t
launch_explicit( char const * cluster,
                 char const * self,
                 char const * log_dir,
                 char const * config0,
                 char const * config1 ) {
  pid_t pid = fork();
  if( pid ) return pid;
  execl( cluster, cluster, "--firedancer", self, "--log-dir", log_dir,
         config0, config1, (char *)NULL );
  _exit( 127 );
}

int
main( int     argc,
      char ** argv ) {
  if( getenv( "FD_CLUSTER_FAKE" ) ) return fake_validator( argc, argv );

  char self[ PATH_MAX ];
  ssize_t self_len = readlink( "/proc/self/exe", self, sizeof(self)-1UL );
  TEST( self_len>0 && (ulong)self_len<sizeof(self) );
  self[ self_len ] = '\0';

  char cluster[ PATH_MAX ];
  memcpy( cluster, self, (ulong)self_len+1UL );
  char * slash = strrchr( cluster, '/' );
  TEST( slash );
  *slash = '\0';
  slash = strrchr( cluster, '/' );
  TEST( slash );
  int len = snprintf( slash, (ulong)(cluster+sizeof(cluster)-slash), "/bin/firedancer-cluster" );
  TEST( len>0 && (ulong)len<(ulong)(cluster+sizeof(cluster)-slash) );
  TEST( !access( cluster, X_OK ) );

  char testdir[] = "/tmp/test-firedancer-cluster-XXXXXX";
  TEST( mkdtemp( testdir ) );
  char config0[ PATH_MAX ];
  char config1[ PATH_MAX ];
  char pattern[ PATH_MAX ];
  char log_dir[ PATH_MAX ];
  char ready0[ PATH_MAX ];
  char ready1[ PATH_MAX ];
  char stopped0[ PATH_MAX ];
  char stopped1[ PATH_MAX ];
  char log0[ PATH_MAX ];
  char log1[ PATH_MAX ];
#define PATH_INTO(v, fmt, ...) do {                                            \
    int n = snprintf( (v), sizeof(v), (fmt), __VA_ARGS__ );                   \
    TEST( n>0 && (ulong)n<sizeof(v) );                                        \
  } while(0)
  PATH_INTO( config0,  "%s/node-0.toml", testdir );
  PATH_INTO( config1,  "%s/node-1.toml", testdir );
  PATH_INTO( pattern,  "%s/node-{index}.toml", testdir );
  PATH_INTO( log_dir,  "%s/logs", testdir );
  PATH_INTO( ready0,   "%s/ready-0", testdir );
  PATH_INTO( ready1,   "%s/ready-1", testdir );
  PATH_INTO( stopped0, "%s/stopped-0", testdir );
  PATH_INTO( stopped1, "%s/stopped-1", testdir );
  PATH_INTO( log0,     "%s/validator-0.stderr.log", log_dir );
  PATH_INTO( log1,     "%s/validator-1.stderr.log", log_dir );
#undef PATH_INTO

  TEST( !write_file( config0, "# fake config 0\n" ) );
  TEST( !write_file( config1, "# fake config 1\n" ) );
  TEST( !setenv( "FD_CLUSTER_FAKE", "1", 1 ) );
  TEST( !setenv( "FD_CLUSTER_TEST_DIR", testdir, 1 ) );
  TEST( !setenv( "FD_CLUSTER_CONFIG0", config0, 1 ) );
  TEST( !setenv( "FD_CLUSTER_CONFIG1", config1, 1 ) );
  TEST( !unsetenv( "FD_CLUSTER_FAIL_CONFIG" ) );

  pid_t launcher = launch_pattern( cluster, self, log_dir, pattern );
  TEST( launcher>0 );
  int ready = !wait_for_path( ready0, 5000UL ) && !wait_for_path( ready1, 5000UL );
  if( !ready ) {
    (void)kill( launcher, SIGKILL );
    (void)waitpid( launcher, NULL, 0 );
    TEST( ready );
  }
  TEST( !kill( launcher, SIGTERM ) );
  int status;
  if( wait_for_pid( launcher, &status, 7000UL ) ) {
    (void)kill( launcher, SIGKILL );
    (void)waitpid( launcher, NULL, 0 );
    TEST( 0 );
  }
  TEST( WIFEXITED( status ) && WEXITSTATUS( status )==128+SIGTERM );
  TEST( !wait_for_path( stopped0, 1000UL ) );
  TEST( !wait_for_path( stopped1, 1000UL ) );
  TEST( !access( log0, R_OK ) && !access( log1, R_OK ) );

  TEST( !unlink( ready0 ) && !unlink( ready1 ) );
  TEST( !unlink( stopped0 ) && !unlink( stopped1 ) );
  TEST( !setenv( "FD_CLUSTER_FAIL_CONFIG", config1, 1 ) );

  launcher = launch_explicit( cluster, self, log_dir, config0, config1 );
  TEST( launcher>0 );
  if( wait_for_pid( launcher, &status, 7000UL ) ) {
    (void)kill( launcher, SIGKILL );
    (void)waitpid( launcher, NULL, 0 );
    TEST( 0 );
  }
  TEST( WIFEXITED( status ) && WEXITSTATUS( status )==42 );
  TEST( !wait_for_path( stopped0, 1000UL ) );

  TEST( !unlink( config0 ) && !unlink( config1 ) );
  TEST( !unlink( ready0 ) && !unlink( ready1 ) );
  TEST( !unlink( stopped0 ) );
  TEST( !unlink( log0 ) && !unlink( log1 ) );
  TEST( !rmdir( log_dir ) && !rmdir( testdir ) );
  puts( "pass" );
  return 0;
}
