#include "Hunt-Sleeping-Beacons.h"

#include "Candidate.h"
#include "Check.h"
#include "EnumTools.h"
#include "StackTools.h"
#include "TokenTools.h"

VOID EnableANSI ( VOID );
BOOL GetCandidates ( std::vector<Process*>&, PConfig );
VOID Help ( VOID );
VOID InitChecks ( std::vector<ThreadChecks::ThreadCheck*>&, PConfig );
VOID Logo ( VOID );
VOID ParseArgs ( int argc, char** argv, PConfig pConfig );

int main ( int argc, char** argv ) {

	BOOL bSuccess = FALSE;
	DWORD tsStart = GetTickCount ( );

	std::vector<ThreadChecks::ThreadCheck*> checks;
	ProcessChecks::EnumerateSuspiciousTimers* enumSuspiciousTimers = NULL;

	std::vector<Process*> processes;

	ThreadDetection* detectionThreadTmp = NULL;
	ProcessDetection* detectionProcessTmp = NULL;

	Config config = { 0 };
	config.dwPid = 0;
	config.stackSpoofing = FALSE;
	config.ignoreDotnet = TRUE;

	ParseArgs ( argc, argv, &config );
	EnableANSI ( );


	bSuccess = TokenTools::IsElevated ( );
	if ( bSuccess == FALSE ) {
		printf ( "- I Need to be elevated\n" );
		goto exit;
	}

	bSuccess = TokenTools::SetDebugPrivilege ( );
	if ( bSuccess == FALSE ) { \
		printf ( "- Failed to enable DebugPrivilege\n" );
		goto exit;
	}

	if ( !config.silent )
		Logo ( );

	printf ( "* Building list of candidate(s)\n" );
	bSuccess = GetCandidates ( processes, &config );
	if ( bSuccess == FALSE )
		goto exit;

	if ( processes.size ( ) == 0 && config.dwPid ) {
		printf ( "- Failed to enumerate threads for pid: %d\n", config.dwPid );
		goto exit;
	}


	printf ( "* Now checking for IOCs, this might take a while ... \n" );

	InitChecks ( checks, &config );
	enumSuspiciousTimers = new ProcessChecks::EnumerateSuspiciousTimers(&config);

	for ( Process* process : processes ) {

		detectionProcessTmp = enumSuspiciousTimers->Go(process);
		if (detectionProcessTmp)
			process->detectionsProcess.push_back(detectionProcessTmp);

		for ( Thread* thread : process->threads ) {

			for ( ThreadChecks::ThreadCheck* check : checks ) {

				detectionThreadTmp = check->Go ( process->hProcess, thread );
				if ( detectionThreadTmp ) 
					process->detectionsThread.push_back ( detectionThreadTmp );

			}

		}

	}

	for ( Process* process : processes ) {

		if ( process->detectionsProcess.size( ) || process->detectionsThread.size ( ) ) {
			printf ( "\033[36m* Detections for: %s ( %Id ) %S\033[0m\n", process->imageName.c_str ( ), ( DWORD64 ) process->pid, ( config.commandline ? process->cmdLine.c_str ( ) : L"" ) );

			for (ProcessDetection* detection : process->detectionsProcess) {
				printf("\t! \033[31m%s\033[0m | ", detection->name.c_str());
				printf("\033[33m%s\033[0m\n", detection->message.c_str());
			}

			for ( ThreadDetection* detection : process->detectionsThread ) {
				printf ( "\t! Thread %Id | \033[31m%s\033[0m | ", ( DWORD64 ) detection->tid, detection->name.c_str ( ) );
				printf ( "\033[33m%s\033[0m\n", detection->message.c_str ( ) );
			}
		}

	}

	bSuccess = TRUE;

	printf ( "* Analysis done in %f seconds \n", ( double ) ( GetTickCount ( ) - tsStart ) / 1000 );

	

exit:

	return bSuccess;

}

BOOL GetCandidates ( std::vector<Process*>& pProcesses, PConfig pConfig) {

	BOOL bSuccess = FALSE;
	SIZE_T dwNumThreads = 0;

	SymSetOptions ( SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS );

	if ( pConfig->dwPid )
		printf ( "\t* Enumerating threads in process %d\n", pConfig->dwPid );
	else if ( pConfig->ignoreDotnet ) {
		printf ( "\t* Enumerating processes and threads ( ignoring Dotnet and 32Bit processes ). This might take a while ... \n" );
	} else {
		printf ( "\t* Enumerating processes and threads ( ignoring 32Bit processes ). This might take a while ... \n" );
	}

	bSuccess = EnumTools::BuildProcessList ( pConfig->dwPid, pProcesses, pConfig->ignoreDotnet );
	if ( bSuccess == FALSE )
		goto Cleanup;


	for ( Process* process : pProcesses ) {
		dwNumThreads += process->threads.size ( );
	}

	printf ( "\t+ Identified a total of %Id processes and %Id threads \n", pProcesses.size (), dwNumThreads );

	bSuccess = TRUE;

Cleanup:

	return bSuccess;

}

VOID InitChecks ( std::vector<ThreadChecks::ThreadCheck*>& checks, PConfig pConfig ) {

	checks.push_back ( new ThreadChecks::CallstackContainsSuspiciousPage ( pConfig ) );
	checks.push_back ( new ThreadChecks::CallstackContainsStompedModules ( pConfig ) );
	checks.push_back ( new ThreadChecks::BlockingTimerCallback ( pConfig ) );
	checks.push_back ( new ThreadChecks::BlockingAPC ( pConfig ) );
	checks.push_back ( new ThreadChecks::AbnormalIntermodularCall ( pConfig ) );

	if ( pConfig->stackSpoofing ) {

		printf ( "\t* Including stackspoofing detections\n" );

		checks.push_back ( new ThreadChecks::ReturnAddressSpoofing ( pConfig ) );
		
	}
}

VOID ParseArgs ( int argc, char** argv, PConfig pConfig ) {

	for ( int i = 1; i < argc; i++ ) {

		if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--pid")) {
			pConfig->dwPid = atoi(argv[i + 1]);
			i++;
		}
		else if (!strcmp(argv[i], "--dotnet"))
			pConfig->ignoreDotnet = FALSE;
		else if (!strcmp(argv[i], "--stackspoofing"))
			pConfig->stackSpoofing = TRUE;
		else if (!strcmp(argv[i], "--commandline"))
			pConfig->commandline = TRUE;
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
			Help();
		else
			Help ( );

	}

}

// Copy paste from https://cboard.cprogramming.com/cplusplus-programming/181215-printing-colored-text-code-blocks-cplusplus.html
VOID EnableANSI ( VOID ) {

	HANDLE h;
	DWORD mode;

	h = GetStdHandle ( STD_OUTPUT_HANDLE );
	GetConsoleMode ( h, &mode );
	SetConsoleMode ( h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING );

}

VOID Help ( VOID ) {

	Logo ( );

	printf ( "-p / --pid {PID}\n" );
	printf ( "\n" );
	printf ( "--dotnet | Set to also include dotnet processes. ( Prone to false positivies )\n" );
	printf ( "--stackspoofing | Enables various checks to detect stackspoofing\n" );
	printf ( "--commandline | Enables output of cmdline for suspicious processes\n" );
	printf ( "-h / --help | Prints this message?\n" );
	printf ( "\n" );
	exit ( 0 );

}

VOID Logo ( VOID ) {

	printf(
		" _   _    _____   ______\r\n"
		"| | | |  /  ___|  | ___ \\\r\n"
		"| |_| |  \\ `--.   | |_/ /\r\n"
		"|  _  |   `--. \\  | ___ \\\r\n"
		"| | | |  /\\__/ /  | |_/ /\r\n"
		"\\_| |_/  \\____/   \\____/\r\n"
		"\r\n"
		"Hunt-Sleeping-Beacons | @thefLinkk\r\n\r\n"
	);

}
