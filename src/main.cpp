#include <windows.h>
#include <process.h>
#include <Tlhelp32.h>
#include <winbase.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace std;

void killProcessByName( const char *filename )
{
    HANDLE hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPALL, 0 );
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof (pEntry);
    BOOL hRes = Process32First( hSnapShot, &pEntry );

    while (hRes)
    {
        if ( strcmp(pEntry.szExeFile, filename) == 0 )
        {
            HANDLE hProcess = OpenProcess( PROCESS_TERMINATE, 0,
                                           (DWORD)pEntry.th32ProcessID);
            if (hProcess != NULL)
            {
                TerminateProcess(hProcess, 9);
                CloseHandle(hProcess);
            }
        }
        hRes = Process32Next(hSnapShot, &pEntry);
    }

    CloseHandle(hSnapShot);
}

int main( int argc, char** argv )
{
    if ( argc > 1 )
    {
        for( int cnt=1; cnt<argc; cnt++ )
        {
            string dstnm = argv[cnt];

            size_t fpos = dstnm.find_last_of( "." );

            if ( fpos == string::npos )
            {
                dstnm += ".exe";
            }
                              
            killProcessByName( dstnm.c_str() );

        }
    }

    return 0;
}
