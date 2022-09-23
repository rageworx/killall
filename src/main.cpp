#include <unistd.h>
// -- windows related --
#include <windows.h>
#include <process.h>
#include <Tlhelp32.h>
#include <winbase.h>
// ---------------------
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <csignal>
#include <getopt.h>

#define VERSION_S       "0.3"
#define SUPPORTEDSIGS   10

typedef struct _signaltype {
    char sigstr[5];
    int  sigval;
}signaltype;

static struct option long_opts[] = {
    { "exact",          no_argument,        0, 'e' },
    { "ignore-case",    no_argument,        0, 'I' },
    { "preocess-group", required_argument,  0, 'g' },
    { "interactive",    no_argument,        0, 'i' },
    { "list",           no_argument,        0, 'l' },
    { "ns",             required_argument,  0, 'n' },
    { "older-than",     required_argument,  0, 'o' },
    { "quiet",          no_argument,        0, 'q' },
    { "ragexp",         required_argument,  0, 'r' },
    { "signal",         required_argument,  0, 's' },
    { "user",           required_argument,  0, 'u' },
    { "verbose",        no_argument,        0, 'v' },
    { "version",        no_argument,        0, 'V' },
    { "wait",           no_argument,        0, 'w' },
    { "younger-than",   required_argument,  0, 'y' },
    { "context",        required_argument,  0, 'Z' },
    { NULL, 0, 0, 0 }
};

static signaltype supportedsignals[ SUPPORTEDSIGS ] = {
    { "INT",    SIGINT },
    { "QUIT",   3 },    /// MinGW-W64 don't have this.
    { "ILL",    SIGILL },
    { "ABRT",   SIGABRT },
    { "FPE",    SIGFPE },
    { "KILL",   9 },    /// MinGW-W64 don't have this.
    { "SEGV",   SIGSEGV },
    { "PIPE",   13 },   /// MinGW-W64 don't have this.
    { "ALRM",   14 },   /// MinGW-W64 don't have thois.
    { "TERM",   SIGTERM }
};

using namespace std;

// some POSIX arguments may ignored in Windows, as we know.
static int optpar_exact = 0;
static int optpar_prgroup = 0;
static int optpar_interactive = 0;
static int optpar_list = 0;
static int optpar_ns = 0;
static int optpar_olderthan = 0;
static int optpar_quiet = 0;
static int optpar_ragexp = 0;
static int optpar_signal = SIGTERM;
static int optpar_verbose = 0;
static int optpar_wait = 0;
static int optpar_youngerthan = 0;
static int optpar_context = 0;
static int optpar_ignorecase = 0;
static int optpar_killbyPID = 0;
static int opterr_notsupported = 0;
static int opterr_notimplemented = 0;
static string optpar_param_s;
static vector<string> plist;

int convStr2Sig( const char* ss )
{
    int retsig = 0;

    if ( ss != NULL )
    {

        for ( size_t cnt=0; cnt<SUPPORTEDSIGS; cnt++ )
        {
            if ( strncmp( ss, supportedsignals[cnt].sigstr, 4 ) == 0 )
                return supportedsignals[cnt].sigval;
        }

        if ( retsig == 0 )
        {
            // convert to numbers.
            retsig = atoi( ss );
            if ( ( retsig > 0 ) && ( retsig < 200 ) )
                return retsig;
        }
    }

    if ( retsig == 0 )
        retsig = SIGTERM;

    return retsig;
}

// Windows Processing Killing method -
void killProcessByName( const char* filename, bool enm )
{
    HANDLE hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPALL, 0 );
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof (pEntry);
    BOOL hRes = Process32First( hSnapShot, &pEntry );

    while ( hRes )
    {
        bool dorm = false;

        if ( optpar_killbyPID == 0 )
        {
            string curprocname = pEntry.szExeFile;
            string targetname  = filename;

            // let case change if option enabled.
            if ( optpar_ignorecase > 0 )
            {
                transform( curprocname.begin(), curprocname.end(),
                           curprocname.begin(), ::tolower );
                transform( targetname.begin(), targetname.end(),
                           targetname.begin(), ::tolower );
            }

            if ( enm == true )
            {
                if ( curprocname == targetname )
                    dorm = true;
            }
            else
            {
                if ( curprocname.find( targetname ) != string::npos )
                    dorm = true;
            }
        }
        else
        {
            DWORD tgPID = (DWORD)atol( filename );

            if ( tgPID == 0 )
                return;

            if ( tgPID == (DWORD)pEntry.th32ProcessID )
                dorm = true;
        }

        if ( dorm == true )
        {
            HANDLE hProcess = OpenProcess( PROCESS_TERMINATE, 0,
                                           (DWORD)pEntry.th32ProcessID );
            if ( hProcess != NULL )
            {
                bool bskip = false;

                if ( ( optpar_interactive > 0 ) && ( optpar_quiet == 0 ) )
                {
                    // ask to user.
                    fprintf( stdout, 
                             "Process %s (%u) may killed, proceed (Y/n)? ",
                             pEntry.szExeFile,
                             (DWORD)pEntry.th32ProcessID );
                    fflush( stdout );
                    char tmpbuff[2] = {0};
                    while (true)
                    {
                        fgets( tmpbuff, 2, stdin );
                        if ( tmpbuff[0] == 'n' )
                        {
                            bskip = true;
                        }
                        else
                            break;
                    }
                }
                
                if ( bskip == false )
                {
                    TerminateProcess( hProcess, optpar_signal );

                    if ( ( optpar_verbose > 0 ) && ( optpar_quiet == 0 ) )
                    {
                        fprintf( stdout,
                                 "%s (%u) killed.\n",
                                 pEntry.szExeFile,
                                 (DWORD)pEntry.th32ProcessID );
                    }
                }
                else
                if ( optpar_verbose > 0 )
                {
                    if ( optpar_quiet == 0 )
                        fprintf( stdout, 
                                 "%s not killed.\n", 
                                 pEntry.szExeFile );
                }

                CloseHandle( hProcess );
            }
        }

        hRes = Process32Next( hSnapShot, &pEntry );
    }

    CloseHandle(hSnapShot);
}

void showSignalNames()
{
    for( size_t cnt=0; cnt<SUPPORTEDSIGS; cnt++ )
    {
        fprintf( stdout, "%s ", supportedsignals[cnt].sigstr );
    }

    fprintf( stdout, "\n" );
}

void showVersion()
{
    const char aboutIt[] = \
"killall for MSYS2 and MinGW-W64, Version %s\n"
"Copyright (C) 2022 Raphael Kim (rageworx-at-gmail.com)\n"
"\n"
"this killall windows version comes with ABSOLUTELY NO WARRANTY.\n"
"This is free software, and you are welcome to redistribute it under\n"
"the terms of the GNU General Public License.\n"
"For more information about these matters, see the files named COPYING.\n";

    fprintf( stdout, aboutIt, VERSION_S );
}

void showShortHelp()
{
    const char shortusage[] = \
"Usage: killall [-Z CONTEXT] [-u USER] [ -eIgiqrvw ] [ -SIGNAL ] NAME...\n"
"       killall -l, --list\n"
"       killall -V, --version\n"
"\n"
"  -e,--exact          require exact match for very long names\n"
"  -I,--ignore-case    case insensitive process name match\n"
"  -g,--process-group  kill process group instead of process\n"
"  -y,--younger-than   kill processes younger than TIME\n"
"  -o,--older-than     kill processes older than TIME\n"
"  -i,--interactive    ask for confirmation before killing\n"
"  -l,--list           list all known signal names\n"
"  -n,--ns             kill process by PID (WindowsPID).\n"
"  -q,--quiet          don't print complaints\n"
"  -r,--regexp         interpret NAME as an extended regular expression\n"
"  -s,--signal SIGNAL  send this signal instead of SIGTERM\n"
"  -u,--user USER      kill only process(es) running as USER\n"
"  -v,--verbose        report if the signal was successfully sent\n"
"  -V,--version        display version information\n"
"  -w,--wait           wait for processes to die\n"
"  -Z,--context REGEXP kill only process(es) having context\n"
"                      (must precede other arguments)";

    fprintf( stdout, "%s\n", shortusage );
}

void showHelp()
{
    const char mankillall[] = \
"-e, --exact\n"
"      Require an exact match for very long names.  If a command\n"
"      name is longer than 15 characters, the full name may be\n"
"      unavailable (i.e.  it is swapped out).  In this case,\n"
"      killall will kill everything that matches within the first\n"
"      15 characters.  With -e, such entries are skipped.\n"
"      killall prints a message for each skipped entry if -v is\n"
"      specified in addition to -e.\n"
"\n"
"-I, --ignore-case\n"
"      Do case insensitive process name match.\n"
"\n"
"-g, --process-group\n"
"      Kill the process group to which the process belongs.  The\n"
"      kill signal is only sent once per group, even if multiple\n"
"      processes belonging to the same process group were found.\n"
"\n"
"-i, --interactive\n"
"      Interactively ask for confirmation before killing.\n"
"\n"
"-l, --list\n"
"      List all known signal names.\n"
"\n"
"-n, --ns\n"
"      Match against the PID namespace of the given PID. The\n"
"      default is to match against all namespaces.\n"
"      given PID must be Windows PID on Windows.\n"
"\n"
"-o, --older-than\n"
"      Match only processes that are older (started before) the\n"
"      time specified.  The time is specified as a float then a\n"
"      unit.  The units are s,m,h,d,w,M,y for seconds, minutes,\n"
"      hours, days, weeks, months and years respectively.\n"
"\n"
"-q, --quiet\n"
"      Do not complain if no processes were killed.\n"
"\n"
"-r, --regexp\n"
"      * current version not implemented this. *\n"
"      Interpret process name pattern as a POSIX extended regular\n"
"      expression, per regex(3).\n"
"\n"
"-s, --signal, -SIGNAL\n"
"      Send this signal instead of SIGTERM.\n"
"\n"
"-u, --user\n"
"      * it may not availed on Windows. *\n"
"      Kill only processes the specified user owns.  Command\n"
"      names are optional.\n"
"\n"
"-v, --verbose\n"
"      Report if the signal was successfully sent.\n"
"\n"
"-V, --version\n"
"      Display version information.\n"
"\n"
"-w, --wait\n"
"      * it may not availed on Windows. *\n"
"      Wait for all killed processes to die.  killall checks once\n"
"      per second if any of the killed processes still exist and\n"
"      only returns if none are left.  Note that killall may wait\n"
"      forever if the signal was ignored, had no effect, or if\n"
"      the process stays in zombie state.\n"
"\n"
"-y, --younger-than\n"
"      * this version not availed for this option *\n"
"      Match only processes that are younger (started after) the\n"
"      time specified.  The time is specified as a float then a\n"
"      unit.  The units are s,m,h,d,w,M,y for seconds, minutes,\n"
"      hours, days, weeks, Months and years respectively.\n"
"\n"
"-Z, --context\n"
"      * this version not availed for this option *\n"
"      Specify security context: kill only processes having\n"
"      security context that match with given extended regular\n"
"      expression pattern.  Must precede other arguments on the\n"
"      command line.  Command names are optional.";

    fprintf( stdout, "%s\n", mankillall );
}

int main( int argc, char** argv )
{
#if 0
    // get names
    for ( int cnt=1; cnt<argc; cnt++ )
    {
        if ( strlen( argv[cnt] ) > 0 )
        {
            if ( argv[cnt][0] != '-' )
            {
                plist.push_back( argv[cnt] );
            }
        }
    }
#endif

    // getopt
    for(;;)
    {
        int optidx = 0;
        int opt = getopt_long( argc, argv, 
                               " :heIg:iln:o:qr:s:u:vVwy:Z:",
                               long_opts, &optidx );
        if ( opt >= 0 )
        {
            switch( (char)opt )
            {
                default:
                case 'h':
                    showHelp();
                    return 0;

                case 0:
                    printf( "case 0!\n" );
                    fflush( stdout );
                    break;

                case 'l':
                    showSignalNames();
                    return 0;

                case 'V':
                    showVersion();
                    return 0;

                case 'v':
                    optpar_verbose = 1;
                    break;

                case 'q':
                    optpar_quiet = 1;
                    break;

                case 'i':
                    optpar_interactive = 1;
                    break;

                case 'I':
                    optpar_ignorecase = 1;
                    break;

                case 'n':
                    {
                        if ( optpar_killbyPID == 0 )
                            optpar_killbyPID = 1;
                        plist.push_back( optarg );
                    }
                    break;

                case 's':
                    optpar_signal = convStr2Sig( optarg );
                    break;

                case 'g':
                case 'u':
                case 'w':
                    // unsupported on windows.
                    opterr_notsupported = 1;
                    if ( optpar_verbose > 0 )
                    {
                        fprintf( stdout,
                                 "optcion '%c' is not supported.\n",
                                 (char)opt );
                    }
                    break;

                case 'r':
                case 'o':
                case 'y':
                case 'Z':
                    // not implemented options.
                    opterr_notimplemented = 1;
                    if ( optpar_verbose > 0 )
                    {
                        fprintf( stdout,
                                 "option '%c' is not implemented.\n",
                                 (char)opt );
                    }
                    break;
            }
        }
        else
            break;
    } /// of for( == )

    for( ; optind<argc; optind++ )
    {
        const char* pn = argv[optind];
        if ( pn != NULL )
        {
            plist.push_back( pn );
        }
    }

    if ( plist.size() == 0 )
    {
        if ( optpar_quiet == 0 )
        {
            if ( optpar_verbose > 0 )
            {
                fprintf( stdout, "(warning) no process decided.\n" );
            }

            if ( opterr_notsupported > 0 )
            {
                fprintf( stdout, "(warning) %s\n", 
                         "some options are may not supported." );
            }
            else
            if ( opterr_notimplemented > 0 )
            {
                fprintf( stdout, "(warning) %s\n", 
                         "some options are not implemented feature." );
            }
            else
                showShortHelp();

            fflush( stdout );
        }
    }
#ifdef DEBUG    
    else
    {
        for( size_t cnt=0; cnt<plist.size(); cnt++ )
        {
            printf( "kill list [%03zu] %s\n", cnt, plist[cnt].c_str() );
        }
    }
#endif /// of DEBUG

    for( size_t cnt=0; cnt<plist.size(); cnt++ )
    {
        bool parm = false;
        string dstnm = plist[cnt];

        if ( optpar_exact > 0 )
        {
            size_t fpos = dstnm.find_last_of( "." );

            if ( fpos == string::npos )
            {
                // maybe need EXE extention for Windows as default.
                dstnm += ".exe";
            }

            parm = true;
        }

        killProcessByName( dstnm.c_str() , parm );
    }

    return 0;
}
