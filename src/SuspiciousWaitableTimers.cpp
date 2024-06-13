#include "Check.h"

namespace ThreadChecks {

	VOID BlockingTimerCallback::Describe ( VOID ) {
		printf ( "* Checking for threads waiting due to a callback of waitable timer. This indicates a sleepmask or various callstack spoofing techniques.\n" );
	}

	ThreadDetection* BlockingTimerCallback::Go ( HANDLE hProcess, Thread* pCandidate ) {

		BOOL bSuccess = FALSE;
		PVOID readAddr = NULL;
		DWORD64 stackAddr = 0;
		size_t numRead = 0;

		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_ALL;

		bSuccess = GetThreadContext ( pCandidate->hThread, &context );
		if ( bSuccess == FALSE )
			goto Cleanup;

		for (DWORD64 i = context.Rsp; i <= (DWORD64)pCandidate->stackBase; i += 8) {

			bSuccess = ReadProcessMemory(hProcess, (LPCVOID)i, &stackAddr, sizeof(DWORD64), &numRead);
			if (bSuccess == FALSE)
				break;

			if ( stackAddr == ( DWORD64 ) this->OffsetDispatcher ) {

				return new ThreadDetection (
					"Abnormal usage of Timers",
					"Thread's blocking state seems to be triggered by ntdll!RtlpTpTimerCallback. This indicates usage of sleepmasks",
					 pCandidate->sti.ClientId.UniqueProcess,
					 pCandidate->sti.ClientId.UniqueThread
				);

			}
			
		}

	Cleanup:

		return NULL;

	}

	BlockingTimerCallback::BlockingTimerCallback ( PConfig pConfig ) : ThreadCheck ( pConfig ) {

		this->GetCbDispatcher ( &this->OffsetDispatcher );

	}

	BOOL BlockingTimerCallback::GetCbDispatcher ( PDWORD64 pdw64OffsetCbDispatcher ) {

		BOOL bSuccess = FALSE;
		PVOID retDispatcher = NULL;

		CBPARAM cbParams = { 0 };
		HANDLE hNewTimer = NULL, hEvent = NULL, hTimerQueue = NULL;
		HMODULE hNtdll = NULL;

		hEvent = CreateEventW ( 0, 0, 0, 0 );
		if ( hEvent == NULL )
			return -1;

		hTimerQueue = CreateTimerQueue ( );
		if ( hTimerQueue == NULL )
			return -1;

		cbParams.hEvent = hEvent;

		CreateTimerQueueTimer ( &hNewTimer, hTimerQueue, ( WAITORTIMERCALLBACK ) ( BlockingTimerCallback::MyCallback ), &cbParams, 0, 0, WT_EXECUTEINTIMERTHREAD );
		WaitForSingleObject ( cbParams.hEvent, INFINITE );

		hNtdll = GetModuleHandleA ( "ntdll.dll" );
		if ( hNtdll == NULL )
			goto exit;

		*pdw64OffsetCbDispatcher = ( DWORD64 ) cbParams.retDispatcher;

		bSuccess = TRUE;

	exit:

		//if ( hNewTimer )
		//	CloseHandle ( hNewTimer );

		if ( hEvent )
			CloseHandle ( hEvent );

		//if ( hTimerQueue )
		//	CloseHandle ( hTimerQueue );

		return bSuccess;

	}


	VOID BlockingTimerCallback::MyCallback ( PCBPARAM cbParams, BOOLEAN TimerOrWaitFired ) {

		CONTEXT context = { 0 };
		STACKFRAME64 stackframe = { 0x00 };

		BOOLEAN bSuccess = FALSE;

		RtlCaptureContext ( &context );

		stackframe.AddrPC.Offset = context.Rip;
		stackframe.AddrPC.Mode = AddrModeFlat;
		stackframe.AddrStack.Offset = context.Rsp;
		stackframe.AddrStack.Mode = AddrModeFlat;
		stackframe.AddrFrame.Offset = context.Rbp;
		stackframe.AddrFrame.Mode = AddrModeFlat;

		SymInitialize ( GetCurrentProcess ( ), NULL, TRUE );

		bSuccess = StackWalk64 ( IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess ( ), GetCurrentThread ( ), &stackframe, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL );
		if ( bSuccess == FALSE )
			return;

		bSuccess = StackWalk64 ( IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess ( ), GetCurrentThread ( ), &stackframe, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL );
		if ( bSuccess == FALSE )
			return;

		SymCleanup ( GetCurrentProcess ( ) );

		cbParams->retDispatcher = ( PVOID ) stackframe.AddrPC.Offset;

		SetEvent ( cbParams->hEvent );

	}

}