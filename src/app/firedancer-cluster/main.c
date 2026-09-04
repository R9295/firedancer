#define _GNU_SOURCE

#include "../../util/fd_util_base.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FD_CLUSTER_MAX_VALIDATORS (256UL)
#define FD_CLUSTER_GRACE_MS       (5000L)

typedef struct {
  char const * firedancer;
  char const * config_pattern;
  char const * log_dir;
  char **      configs;
  ulong        validator_cnt;
} fd_cluster_options_t;

static volatile sig_atomic_t fd_cluster_stop_signal;

static void
usage( FILE *      stream,
       char const * prog ) {
  fprintf( stream,
           "Usage:\n"
           "  %s [--firedancer PATH] [--log-dir DIR] CONFIG...\n"
           "  %s [--firedancer PATH] [--log-dir DIR] --validators N\\\n"
           "     --config-pattern PATTERN\n"
           "\n"
           "PATTERN must contain one {index}.  Each child is launched as:\n"
           "  firedancer-dev --config CONFIG --alpenglow --no-clone dev\\\n"
           "    --no-watch --no-configure\n",
           prog, prog );
}

static int
parse_count( char const * text,
             ulong *      count ) {
  if( FD_UNLIKELY( !text || !text[ 0 ] || text[ 0 ]=='-' ) ) return -1;
  errno = 0;
  char * end;
  unsigned long value = strtoul( text, &end, 10 );
  if( FD_UNLIKELY( errno || end[ 0 ] || !value || value>FD_CLUSTER_MAX_VALIDATORS ) ) return -1;
  *count = (ulong)value;
  return 0;
}

static int
render_pattern( char const * pattern,
                ulong        index,
                char *       out,
                ulong        out_sz ) {
  char const token[] = "{index}";
  char const * mark = strstr( pattern, token );
  if( FD_UNLIKELY( !mark || strstr( mark+sizeof(token)-1UL, token ) ) ) return -1;

  ulong prefix_sz = (ulong)(mark-pattern);
  int len = snprintf( out, out_sz, "%.*s%lu%s", (int)prefix_sz, pattern, index,
                      mark+sizeof(token)-1UL );
  return (len<0 || (ulong)len>=out_sz) ? -1 : 0;
}

static int
parse_options( int                    argc,
               char **                argv,
               fd_cluster_options_t * options ) {
  enum { OPT_PATTERN=256, OPT_FIREDANCER, OPT_LOG_DIR };
  static struct option const long_options[] = {
    { "validators",     required_argument, NULL, 'n'            },
    { "config-pattern", required_argument, NULL, OPT_PATTERN    },
    { "firedancer",     required_argument, NULL, OPT_FIREDANCER },
    { "log-dir",        required_argument, NULL, OPT_LOG_DIR    },
    { "help",           no_argument,       NULL, 'h'            },
    { NULL,               0,                 NULL, 0              }
  };

  memset( options, 0, sizeof(*options) );
  int validators_set = 0;
  opterr = 0;

  for(;;) {
    int opt = getopt_long( argc, argv, "+hn:", long_options, NULL );
    if( opt==-1 ) break;
    switch( opt ) {
    case 'h':
      usage( stdout, argv[ 0 ] );
      return 1;
    case 'n':
      if( FD_UNLIKELY( parse_count( optarg, &options->validator_cnt ) ) ) {
        fprintf( stderr, "firedancer-cluster: invalid validator count `%s`\n", optarg );
        return -1;
      }
      validators_set = 1;
      break;
    case OPT_PATTERN:    options->config_pattern = optarg; break;
    case OPT_FIREDANCER: options->firedancer     = optarg; break;
    case OPT_LOG_DIR:    options->log_dir        = optarg; break;
    default:
      fprintf( stderr, "firedancer-cluster: unknown or incomplete option `%s`\n",
               argv[ optind ? optind-1 : 0 ] );
      return -1;
    }
  }

  ulong config_cnt = (ulong)(argc-optind);
  if( options->config_pattern ) {
    if( FD_UNLIKELY( !validators_set || config_cnt ) ) {
      fprintf( stderr, "firedancer-cluster: --config-pattern requires --validators and no CONFIG arguments\n" );
      return -1;
    }
    char path[ PATH_MAX ];
    if( FD_UNLIKELY( render_pattern( options->config_pattern, options->validator_cnt-1UL,
                                     path, sizeof(path) ) ) ) {
      fprintf( stderr, "firedancer-cluster: config pattern must contain one {index} and fit PATH_MAX\n" );
      return -1;
    }
  } else {
    if( FD_UNLIKELY( validators_set || !config_cnt || config_cnt>FD_CLUSTER_MAX_VALIDATORS ) ) {
      fprintf( stderr, "firedancer-cluster: supply 1-%lu CONFIG arguments, or use --validators with --config-pattern\n",
               FD_CLUSTER_MAX_VALIDATORS );
      return -1;
    }
    options->validator_cnt = config_cnt;
    options->configs       = argv+optind;
  }
  return 0;
}

static char const *
default_firedancer_path( char * path,
                         ulong  path_sz ) {
  ssize_t len = readlink( "/proc/self/exe", path, path_sz-1UL );
  if( len>0 && (ulong)len<path_sz ) {
    path[ len ] = '\0';
    char * slash = strrchr( path, '/' );
    if( slash ) {
      char const name[] = "firedancer-dev";
      ulong prefix_sz = (ulong)(slash-path)+1UL;
      if( prefix_sz+sizeof(name)<=path_sz ) {
        memcpy( path+prefix_sz, name, sizeof(name) );
        if( !access( path, X_OK ) ) return path;
      }
    }
  }
  return "firedancer-dev";
}

static void
signal_handler( int sig ) {
  if( !fd_cluster_stop_signal ) fd_cluster_stop_signal = sig;
}

static int
set_signal_handlers( void ) {
  struct sigaction action;
  memset( &action, 0, sizeof(action) );
  action.sa_handler = signal_handler;
  sigemptyset( &action.sa_mask );
  return sigaction( SIGINT,  &action, NULL ) ||
         sigaction( SIGTERM, &action, NULL ) ||
         sigaction( SIGHUP,  &action, NULL );
}

static void
reset_child_signals( void ) {
  struct sigaction action;
  memset( &action, 0, sizeof(action) );
  action.sa_handler = SIG_DFL;
  sigemptyset( &action.sa_mask );
  (void)sigaction( SIGINT,  &action, NULL );
  (void)sigaction( SIGTERM, &action, NULL );
  (void)sigaction( SIGHUP,  &action, NULL );
}

static long
monotonic_millis( void ) {
  struct timespec now;
  (void)clock_gettime( CLOCK_MONOTONIC, &now );
  return now.tv_sec*1000L+now.tv_nsec/1000000L;
}

static void
signal_children( pid_t const * children,
                 ulong         child_cnt,
                 int           sig ) {
  for( ulong i=0UL; i<child_cnt; i++ ) {
    if( children[ i ]<=0 ) continue;
    if( kill( -children[ i ], sig ) && errno==ESRCH ) (void)kill( children[ i ], sig );
  }
}

static int
open_child_log( char const * log_dir,
                ulong        index ) {
  if( !log_dir ) return -1;
  char path[ PATH_MAX ];
  int len = snprintf( path, sizeof(path), "%s/validator-%lu.stderr.log", log_dir, index );
  if( FD_UNLIKELY( len<0 || (ulong)len>=sizeof(path) ) ) {
    errno = ENAMETOOLONG;
    return -2;
  }
  return open( path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600 );
}

static pid_t
spawn_child( char const * firedancer,
             char const * config,
             int          log_fd ) {
  pid_t launcher_pid = getpid();
  pid_t pid = fork();
  if( pid ) {
    if( pid>0 && setpgid( pid, pid ) && errno!=EACCES && errno!=ESRCH )
      fprintf( stderr, "firedancer-cluster: warning: setpgid(%ld) failed (%s)\n",
               (long)pid, strerror( errno ) );
    return pid;
  }

  (void)setpgid( 0, 0 );
  reset_child_signals();
  if( prctl( PR_SET_PDEATHSIG, SIGKILL ) || getppid()!=launcher_pid ) _exit( 127 );
  if( log_fd>=0 ) {
    if( dup2( log_fd, STDOUT_FILENO )<0 || dup2( log_fd, STDERR_FILENO )<0 ||
        fcntl( STDOUT_FILENO, F_SETFD, 0 ) || fcntl( STDERR_FILENO, F_SETFD, 0 ) ) _exit( 127 );
    if( log_fd>STDERR_FILENO ) close( log_fd );
  }

  execlp( firedancer, firedancer, "--config", config, "--alpenglow", "--no-clone",
          "dev", "--no-watch", "--no-configure", (char *)NULL );
  dprintf( STDERR_FILENO, "firedancer-cluster: exec `%s` failed (%s)\n",
           firedancer, strerror( errno ) );
  _exit( 127 );
}

static int
child_exit_code( int status ) {
  if( WIFEXITED( status ) )   return WEXITSTATUS( status );
  if( WIFSIGNALED( status ) ) return 128+WTERMSIG( status );
  return 1;
}

static int
supervise( pid_t * children,
           ulong   child_cnt,
           int     startup_result ) {
  ulong alive = child_cnt;
  int result = startup_result;
  int stopping = !!startup_result;
  int killed = 0;
  long deadline = 0L;

  if( fd_cluster_stop_signal ) {
    result   = 128+(int)fd_cluster_stop_signal;
    stopping = 1;
  }
  if( stopping ) {
    signal_children( children, child_cnt,
                     fd_cluster_stop_signal ? (int)fd_cluster_stop_signal : SIGTERM );
    deadline = monotonic_millis()+FD_CLUSTER_GRACE_MS;
  }

  while( alive ) {
    if( fd_cluster_stop_signal && !stopping ) {
      result   = 128+(int)fd_cluster_stop_signal;
      stopping = 1;
      signal_children( children, child_cnt, (int)fd_cluster_stop_signal );
      deadline = monotonic_millis()+FD_CLUSTER_GRACE_MS;
    }

    int status;
    pid_t pid;
    while( (pid=waitpid( -1, &status, WNOHANG ))>0 ) {
      ulong index;
      for( index=0UL; index<child_cnt && children[ index ]!=pid; index++ ) {}
      if( index==child_cnt ) continue;
      children[ index ] = 0;
      alive--;

      int code = child_exit_code( status );
      fprintf( stderr, "firedancer-cluster: validator %lu (pid %ld) exited with status %d\n",
               index, (long)pid, code );
      if( !stopping ) {
        result   = code ? code : 1;
        stopping = 1;
        signal_children( children, child_cnt, SIGTERM );
        deadline = monotonic_millis()+FD_CLUSTER_GRACE_MS;
      }
    }
    if( pid<0 && errno==ECHILD ) {
      if( alive && !result ) result = 1;
      break;
    }
    if( pid<0 && errno!=EINTR ) {
      fprintf( stderr, "firedancer-cluster: waitpid failed (%s)\n", strerror( errno ) );
      if( !result ) result = 1;
      if( !stopping ) {
        stopping = 1;
        signal_children( children, child_cnt, SIGTERM );
        deadline = monotonic_millis()+FD_CLUSTER_GRACE_MS;
      }
    }
    if( !alive ) break;
    if( stopping && !killed && monotonic_millis()>=deadline ) {
      signal_children( children, child_cnt, SIGKILL );
      killed = 1;
    }
    struct timespec delay = { .tv_sec=0, .tv_nsec=20000000L };
    (void)nanosleep( &delay, NULL );
  }
  return result ? result : 1;
}

int
main( int     argc,
      char ** argv ) {
  fd_cluster_options_t options;
  int parsed = parse_options( argc, argv, &options );
  if( parsed>0 ) return 0;
  if( parsed<0 ) {
    usage( stderr, argv[ 0 ] );
    return 2;
  }

  if( options.log_dir && mkdir( options.log_dir, 0700 ) && errno!=EEXIST ) {
    fprintf( stderr, "firedancer-cluster: cannot create log directory `%s` (%s)\n",
             options.log_dir, strerror( errno ) );
    return 1;
  }
  if( set_signal_handlers() ) {
    fprintf( stderr, "firedancer-cluster: cannot install signal handlers (%s)\n", strerror( errno ) );
    return 1;
  }

  char firedancer_path[ PATH_MAX ];
  char const * firedancer = options.firedancer ? options.firedancer :
                            default_firedancer_path( firedancer_path, sizeof(firedancer_path) );
  pid_t children[ FD_CLUSTER_MAX_VALIDATORS ] = { 0 };
  ulong child_cnt = 0UL;
  int startup_result = 0;

  for( ulong i=0UL; i<options.validator_cnt && !fd_cluster_stop_signal; i++ ) {
    char rendered[ PATH_MAX ];
    char const * config = options.config_pattern ? rendered : options.configs[ i ];
    if( options.config_pattern && render_pattern( options.config_pattern, i, rendered, sizeof(rendered) ) ) {
      startup_result = 1;
      break;
    }

    int log_fd = open_child_log( options.log_dir, i );
    if( log_fd==-2 || (options.log_dir && log_fd<0) ) {
      fprintf( stderr, "firedancer-cluster: cannot open log for validator %lu (%s)\n",
               i, strerror( errno ) );
      startup_result = 1;
      break;
    }
    pid_t pid = spawn_child( firedancer, config, log_fd );
    if( log_fd>=0 ) close( log_fd );
    if( pid<0 ) {
      fprintf( stderr, "firedancer-cluster: cannot launch validator %lu (%s)\n",
               i, strerror( errno ) );
      startup_result = 1;
      break;
    }
    children[ child_cnt++ ] = pid;
    fprintf( stderr, "firedancer-cluster: validator %lu pid %ld config `%s`\n",
             i, (long)pid, config );
  }

  if( !child_cnt ) return fd_cluster_stop_signal ? 128+(int)fd_cluster_stop_signal : 1;
  if( child_cnt<options.validator_cnt && !startup_result && !fd_cluster_stop_signal ) startup_result = 1;
  return supervise( children, child_cnt, startup_result );
}
