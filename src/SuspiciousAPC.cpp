#include "Check.h"

namespace ThreadChecks {


	VOID BlockingAPC::Describe ( VOID ) {
		printf ( "* Checking for threads waiting due to an APC. This indicates a sleepmask or various callstack spoofing techniques\n" );
	}

	BlockingAPC::BlockingAPC ( PConfig pConfig ) : ThreadCheck ( pConfig ) {

		HMODULE hNtdll = NULL;
		this->pKiUserApcDispatcher = 0;

		hNtdll = GetModuleHandleA ( "ntdll.dll" );
		if ( hNtdll == NULL )
			return;

		this->pKiUserApcDispatcher = ( DWORD64 ) GetProcAddress ( hNtdll, "KiUserApcDispatcher" );
		if ( pKiUserApcDispatcher == 0 )
			return;

	}

	ThreadDetection* BlockingAPC::Go ( HANDLE hProcess, Thread* pCandidate ) {

		BOOL bSuccess = FALSE;
		PVOID readAddr = NULL;
		DWORD64 stackAddr = 0;
		size_t numRead = 0;

		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_ALL;


		bSuccess = GetThreadContext ( pCandidate->hThread, &context );
		if ( bSuccess == FALSE )
			goto Cleanup;

		for (DWORD64 i = context.Rsp ; i <= ( DWORD64 ) pCandidate->stackBase; i += 8) {

			bSuccess = ReadProcessMemory ( hProcess, (LPCVOID)i, &stackAddr, sizeof ( DWORD64 ), &numRead );
			if ( bSuccess == FALSE )
				break;

			if ( stackAddr >= ( DWORD64 ) this->pKiUserApcDispatcher && ( this->pKiUserApcDispatcher + 120 ) > stackAddr ) {

				return new ThreadDetection (
					"Abnormal usage of APC",
					"Thread's blocking state seems to be triggered by ntdll!kiuserapcdispatcher. This indicates usage of multiple sleepmasks",
					 pCandidate->sti.ClientId.UniqueProcess,
					 pCandidate->sti.ClientId.UniqueThread
				);

			}

		}

	Cleanup:

		return NULL;

	}

}