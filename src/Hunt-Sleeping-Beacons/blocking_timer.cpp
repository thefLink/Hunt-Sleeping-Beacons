#pragma once

#include "phnt.h"
#include "scans.hpp"

namespace hsb::scanning {

	static DWORD64 callback_dispatcher = 0;
	static HANDLE hEvent = NULL;
	static inline std::once_flag dispatcher_resolved;
	static void my_callback(void);
	static bool resolve_callback_dispatcher(void);

	thread_scan thread_scans::blocking_timer = [](process* process,thread* thread) {

		BOOL bSuccess = FALSE;
		PVOID readAddr = NULL;
		DWORD64 stackAddr = 0;
		size_t numRead = 0;

		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_ALL;

		std::call_once(dispatcher_resolved, resolve_callback_dispatcher);
		if (callback_dispatcher == 0) {
			return;
		}

		bSuccess = GetThreadContext(thread->handle, &context);
		if (bSuccess == FALSE)
			goto Cleanup;

		for (DWORD64 i = context.Rsp; i <= (DWORD64)thread->stackbase; i += 8) {

			bSuccess = ReadProcessMemory(process->handle, (LPCVOID)i, &stackAddr, sizeof(DWORD64), &numRead);
			if (bSuccess == FALSE)
				break;

			if (stackAddr == callback_dispatcher) {
			
				thread_detection detection;
				detection.name = L"Blocking Timer detected";
				detection.description = L"Thread's blocking state triggered by ntdll!RtlpTpTimerCallback";
				detection.tid = thread->tid;
				detection.severity = hsb::containers::detections::HIGH;

				process->add_detection(detection);

			}

		}

	Cleanup:

		return;

	};

	static void my_callback(void) {

		CONTEXT context = { 0 };
		STACKFRAME64 stackframe = { 0x00 };

		BOOL bSuccess = FALSE;

		RtlCaptureContext(&context);

		stackframe.AddrPC.Offset = context.Rip;
		stackframe.AddrPC.Mode = AddrModeFlat;
		stackframe.AddrStack.Offset = context.Rsp;
		stackframe.AddrStack.Mode = AddrModeFlat;
		stackframe.AddrFrame.Offset = context.Rbp;
		stackframe.AddrFrame.Mode = AddrModeFlat;

		SymInitialize(GetCurrentProcess(), NULL, TRUE);

		bSuccess = StackWalk64(IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess(), GetCurrentThread(), &stackframe, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);
		if (bSuccess == FALSE)
			return;

		bSuccess = StackWalk64(IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess(), GetCurrentThread(), &stackframe, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);
		if (bSuccess == FALSE)
			return;

		SymCleanup(GetCurrentProcess());

		callback_dispatcher = stackframe.AddrPC.Offset;

		SetEvent(hEvent);


	}

	static bool resolve_callback_dispatcher(void) {

		BOOL bSuccess = FALSE;
		PVOID retDispatcher = NULL;

		HANDLE hNewTimer = NULL, hTimerQueue = NULL;
		HMODULE hNtdll = NULL;

		hEvent = CreateEventW(0, 0, 0, 0);
		if (hEvent == NULL)
			return FALSE;

		hTimerQueue = CreateTimerQueue();
		if (hTimerQueue == NULL)
			return FALSE;

		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)(my_callback), NULL, 0, 0, WT_EXECUTEINTIMERTHREAD);
		WaitForSingleObject(hEvent, INFINITE);

		hNtdll = GetModuleHandleA("ntdll.dll");
		if (hNtdll == NULL)
			goto exit;

		bSuccess = TRUE;

	exit:

		//if ( hNewTimer )
		//	CloseHandle ( hNewTimer );

		if (hEvent)
			CloseHandle(hEvent);

		//if ( hTimerQueue )
		//	CloseHandle ( hTimerQueue );

		return bSuccess;

	}

}