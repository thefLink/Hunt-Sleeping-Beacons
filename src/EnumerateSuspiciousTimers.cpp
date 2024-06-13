#include "Check.h"
#include "EnumTools.h"
#include "TPDefs.h"

namespace ProcessChecks {

	SUSPICIOUS_CALLBACK make_callback(std::string name, PVOID addr) {
		SUSPICIOUS_CALLBACK callback;
		callback.name = name;
		callback.addr = addr;
		return callback;
	}

	EnumerateSuspiciousTimers::EnumerateSuspiciousTimers(PConfig pConfig) : ProcessCheck(pConfig) {

		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		HMODULE hKernel32 = GetModuleHandleA ( "kernel32.dll" );

		if (hNtdll && hKernel32) {
			this->SuspiciousCallbacks.push_back ( make_callback ( "ntdll!NtContinue", GetProcAddress(hNtdll, "NtContinue")));
			this->SuspiciousCallbacks.push_back ( make_callback ( "ntdll!RtlCaptureContext", GetProcAddress(hNtdll, "RtlCaptureContext")));
			this->SuspiciousCallbacks.push_back ( make_callback ( "ntdll!RtlCopyMemory", GetProcAddress(hNtdll, "RtlCopyMemory")));
			this->SuspiciousCallbacks.push_back ( make_callback ( "ntdll!RtlMoveMemory", GetProcAddress ( hNtdll, "RtlMoveMemory" ) ) );
			this->SuspiciousCallbacks.push_back ( make_callback ( "ntdll!NtFreeVirtualMemory", GetProcAddress ( hNtdll, "NtFreeVirtualMemory" ) ) );
			this->SuspiciousCallbacks.push_back ( make_callback ( "ntdll!NtAllocateVirtualMemory", GetProcAddress ( hNtdll, "NtAllocateVirtualMemory" ) ) );
			this->SuspiciousCallbacks.push_back ( make_callback ( "ntdll!NtCreateThread", GetProcAddress ( hNtdll, "NtCreateThread" ) ) );
			this->SuspiciousCallbacks.push_back ( make_callback ( "kernel32!ResumeThread", GetProcAddress ( hKernel32, "ResumeThread" ) ) );
		}

	}

	VOID EnumerateSuspiciousTimers::Describe(VOID) {
		printf("* Enumerating suspicious timers\n");
	}

	ProcessDetection* EnumerateSuspiciousTimers::Go( Process* pProcess ) {

		BOOL bSuccess = FALSE;
		std::vector<HANDLE> workerFactories;

		WORKER_FACTORY_BASIC_INFORMATION wfbi = { 0 };
		FULL_TP_POOL full_tp_pool = { 0 };
		PFULL_TP_TIMER p_tp_timer = NULL, p_head = NULL;
		FULL_TP_TIMER tp_timer = { 0 };
		TPP_CLEANUP_GROUP_MEMBER ctx = { 0 };
		SIZE_T len = 0;
		CHAR message[1024] = { 0 };

		bSuccess = EnumTools::GetHandlesOfTypeInProcess( pProcess, L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS, workerFactories );
		if (bSuccess == FALSE)
			goto Cleanup;

		for (HANDLE hWorkerFactory : workerFactories) {

			if (NtQueryInformationWorkerFactory( hWorkerFactory, WorkerFactoryBasicInformation, &wfbi, sizeof(WORKER_FACTORY_BASIC_INFORMATION), NULL) == STATUS_SUCCESS) {

				bSuccess = ReadProcessMemory(pProcess->hProcess, wfbi.StartParameter, &full_tp_pool, sizeof(FULL_TP_POOL), & len);
				if (bSuccess == FALSE)
					continue;

				if ( full_tp_pool.TimerQueue.RelativeQueue.WindowStart.Root )
					p_tp_timer = CONTAINING_RECORD ( full_tp_pool.TimerQueue.RelativeQueue.WindowStart.Root, FULL_TP_TIMER, WindowStartLinks );
				else if ( full_tp_pool.TimerQueue.AbsoluteQueue.WindowStart.Root )
					p_tp_timer = CONTAINING_RECORD ( full_tp_pool.TimerQueue.AbsoluteQueue.WindowStart.Root, FULL_TP_TIMER, WindowStartLinks );
				else 
					continue;


				bSuccess = ReadProcessMemory ( pProcess->hProcess, p_tp_timer, &tp_timer, sizeof ( FULL_TP_TIMER ), &len );
				if ( bSuccess == FALSE )
					continue; 

				PLIST_ENTRY pHead = tp_timer.WindowStartLinks.Children.Flink;
				PLIST_ENTRY pFwd  = tp_timer.WindowStartLinks.Children.Flink;
				LIST_ENTRY entry = { 0 };

				do {

					bSuccess = ReadProcessMemory ( pProcess->hProcess, tp_timer.Work.CleanupGroupMember.Context, &ctx, sizeof ( TPP_CLEANUP_GROUP_MEMBER ), &len );
					if ( bSuccess == FALSE )
						break;

					for ( SUSPICIOUS_CALLBACK suspiciousCallback : this->SuspiciousCallbacks ) {
						if ( suspiciousCallback.addr == ctx.FinalizationCallback ) {

							wsprintfA ( message, "A suspicious timer callback was identified pointing to %s", suspiciousCallback.name.c_str ( ) );
							return new ProcessDetection ( "Suspicious Timer", message, (HANDLE)(DWORD64)pProcess->pid);

						}
					}

					p_tp_timer = CONTAINING_RECORD ( pFwd, FULL_TP_TIMER, WindowStartLinks );
					bSuccess = ReadProcessMemory ( pProcess->hProcess, p_tp_timer, &tp_timer, sizeof ( FULL_TP_TIMER ), &len );
					if ( bSuccess == FALSE )
						break;

					ReadProcessMemory ( pProcess->hProcess, pFwd, &entry, sizeof ( LIST_ENTRY ), &len );
					pFwd = entry.Flink;

				} while ( pHead != pFwd );

			}

		}

	Cleanup:

		return NULL;

	}

}