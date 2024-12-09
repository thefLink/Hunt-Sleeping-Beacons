#pragma once

#include "phnt.h"
#include "scans.hpp"

namespace hsb::scanning {

	static inline std::once_flag apc_resolved;

	static DWORD64 pKiUserAPCDispatcher = 0;
	static bool resolve_apc_dispatcher(void);

	thread_scan thread_scans::blocking_apc = [](process* process,thread* thread) {

		BOOL bSuccess = FALSE;
		PVOID readAddr = NULL;
		DWORD64 stackAddr = 0;
		size_t numRead = 0;

		CONTEXT context ={0};
		context.ContextFlags = CONTEXT_ALL;

		std::call_once(apc_resolved, resolve_apc_dispatcher);
		if (pKiUserAPCDispatcher == 0) {
			return;
		}

		bSuccess = GetThreadContext(thread->handle,&context);
		if(bSuccess == FALSE)
			return;

		for(DWORD64 i = context.Rsp ; i <= (DWORD64)thread->stackbase; i += 8) {

			bSuccess = ReadProcessMemory(process->handle,(LPCVOID)i,&stackAddr,sizeof(DWORD64),&numRead);
			if(bSuccess == FALSE)
				break;

			if(stackAddr >= (DWORD64)pKiUserAPCDispatcher && (pKiUserAPCDispatcher + 120) > stackAddr) {

				thread_detection detection;				
				detection.name = L"Blocking APC detected";
				detection.description = L"Thread's state triggered by ntdll!kiuserapcdispatcher";
				detection.tid = thread->tid;
				detection.severity = hsb::containers::detections::HIGH;

				process->add_detection(detection);

			}
		}

	};

	static bool resolve_apc_dispatcher(void) {

		HMODULE hNtdll = NULL;

		hNtdll = GetModuleHandleA("ntdll.dll");
		if (hNtdll == NULL)
			return false;

		pKiUserAPCDispatcher = (DWORD64)GetProcAddress(hNtdll, "KiUserApcDispatcher");
		if (pKiUserAPCDispatcher == 0)
			return false;

		return true;

	}

} 