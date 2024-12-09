#include <string>
#include <iostream>
#include <format>

#include "phnt.h"
#include "shlwapi.h"
#include "psapi.h"
#include "misc.hpp"
#include "scans.hpp"
#include "threadpooling.h"

namespace hsb::scanning {

	typedef struct _SUSPICIOUS_CALLBACK {

		std::wstring name;
		PVOID addr;

	} SUSPICIOUS_CALLBACK, * PSUSPICIOUS_CALLBACK;


	SUSPICIOUS_CALLBACK make_callback(std::wstring name, PVOID addr) {
		SUSPICIOUS_CALLBACK callback;
		callback.name = name;
		callback.addr = addr;
		return callback;
	}

	static std::vector<SUSPICIOUS_CALLBACK> suspicious_callbacks;
	static inline std::once_flag callbacks_resolved;

	static void initialize_suspicious_callbacks(void);
	static BOOL get_workerfactory_handles(process* process, ACCESS_MASK access, std::vector<HANDLE>& pHandleList);
	static std::string addr_to_module(HANDLE, DWORD64);

	process_scan process_scans::suspicious_timer = [](process* process) {

		std::vector<HANDLE> workerFactories;
		WORKER_FACTORY_BASIC_INFORMATION wfbi = { 0 };
		FULL_TP_POOL full_tp_pool = { 0 };
		PFULL_TP_TIMER p_tp_timer = NULL, p_head = NULL;
		FULL_TP_TIMER tp_timer = { 0 };
		TPP_CLEANUP_GROUP_MEMBER ctx = { 0 };
		SIZE_T len = 0;

		BOOL bSuccess = FALSE;

		std::call_once(callbacks_resolved, initialize_suspicious_callbacks);

		bSuccess = get_workerfactory_handles(process, WORKER_FACTORY_ALL_ACCESS, workerFactories);
		if (bSuccess == FALSE)
			return;

		for (HANDLE hWorkerFactory : workerFactories) {

			if (NtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &wfbi, sizeof(WORKER_FACTORY_BASIC_INFORMATION), NULL) == STATUS_SUCCESS) {

				bSuccess = ReadProcessMemory(process->handle, wfbi.StartParameter, &full_tp_pool, sizeof(FULL_TP_POOL), &len);
				if (bSuccess == FALSE)
					continue;

				if (full_tp_pool.TimerQueue.RelativeQueue.WindowStart.Root)
					p_tp_timer = CONTAINING_RECORD(full_tp_pool.TimerQueue.RelativeQueue.WindowStart.Root, FULL_TP_TIMER, WindowStartLinks);
				else if (full_tp_pool.TimerQueue.AbsoluteQueue.WindowStart.Root)
					p_tp_timer = CONTAINING_RECORD(full_tp_pool.TimerQueue.AbsoluteQueue.WindowStart.Root, FULL_TP_TIMER, WindowStartLinks);
				else
					continue;


				bSuccess = ReadProcessMemory(process->handle, p_tp_timer, &tp_timer, sizeof(FULL_TP_TIMER), &len);
				if (bSuccess == FALSE)
					continue;

				PLIST_ENTRY pHead = tp_timer.WindowStartLinks.Children.Flink;
				PLIST_ENTRY pFwd = tp_timer.WindowStartLinks.Children.Flink;
				LIST_ENTRY entry = { 0 };

				do {

					bSuccess = ReadProcessMemory(process->handle, tp_timer.Work.CleanupGroupMember.Context, &ctx, sizeof(TPP_CLEANUP_GROUP_MEMBER), &len);
					if (bSuccess == FALSE)
						break;

					for (SUSPICIOUS_CALLBACK suspiciousCallback : suspicious_callbacks) {
						if (suspiciousCallback.addr == ctx.FinalizationCallback) {

							process_detection p;
							p.name = L"Suspicious Timer";
							p.description = std::format(L"A suspicious timer callback was identified pointing to {}", suspiciousCallback.name);
							p.severity = hsb::containers::detections::CRITICAL;

							process->add_detection(p);

						}
					}

					p_tp_timer = CONTAINING_RECORD(pFwd, FULL_TP_TIMER, WindowStartLinks);
					bSuccess = ReadProcessMemory(process->handle, p_tp_timer, &tp_timer, sizeof(FULL_TP_TIMER), &len);
					if (bSuccess == FALSE)
						break;

					ReadProcessMemory(process->handle, pFwd, &entry, sizeof(LIST_ENTRY), &len);
					pFwd = entry.Flink;

				} while (pHead != pFwd);

			}

			CloseHandle(hWorkerFactory);

		}

	};

	static BOOL get_workerfactory_handles(process* process, ACCESS_MASK access, std::vector<HANDLE>& pHandleList) {

		BOOL bSuccess = FALSE;
		PVOID pBuffer = NULL;
		ULONG uBufferSize = 0;
		NTSTATUS status = 0;
		HANDLE dupHandle = NULL;

		CLIENT_ID clientId = { 0 };

		PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
		PSYSTEM_HANDLE_TABLE_ENTRY_INFO entryInfo = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;

		do {

			status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, pBuffer, uBufferSize, &uBufferSize);
			if (!NT_SUCCESS(status)) {

				if (status == STATUS_INFO_LENGTH_MISMATCH) {
					if (pBuffer != NULL)
						LocalFree(pBuffer);
					pBuffer = LocalAlloc(LMEM_ZEROINIT, uBufferSize);
					if (pBuffer == NULL)
						goto Cleanup;

					continue;
				}
				break;

			}
			else {

				handleInfo = (PSYSTEM_HANDLE_INFORMATION)pBuffer;
				break;

			}

		} while (1);

		if (handleInfo == NULL)
			goto Cleanup;

		objectTypeInfo = (POBJECT_TYPE_INFORMATION)LocalAlloc(LMEM_ZEROINIT, sizeof(OBJECT_TYPE_INFORMATION) * 2);
		if (objectTypeInfo == NULL)
			goto Cleanup;

		for (UINT i = 0; i < handleInfo->NumberOfHandles; i++) {

			entryInfo = &handleInfo->Handles[i];

			if (process->pid != entryInfo->UniqueProcessId)
				continue;

			clientId.UniqueProcess = (HANDLE)entryInfo->UniqueProcessId;
			clientId.UniqueThread = 0;

			if (NtDuplicateObject(process->handle, (HANDLE)(uint64_t)entryInfo->HandleValue, NtCurrentProcess(), &dupHandle, access, 0, 0) == STATUS_SUCCESS) {

				memset(objectTypeInfo, 0, sizeof(OBJECT_TYPE_INFORMATION) * 2);

				if (NtQueryObject(dupHandle, (OBJECT_INFORMATION_CLASS)ObjectTypeInformation, objectTypeInfo, sizeof(OBJECT_TYPE_INFORMATION) * 2, NULL) == STATUS_SUCCESS) {

					if (!lstrcmpW(objectTypeInfo->TypeName.Buffer, L"TpWorkerFactory")) {
						pHandleList.push_back(dupHandle);
					}
					else {
						CloseHandle(dupHandle);
					}

				}

			}

		}

		bSuccess = TRUE;

	Cleanup:

		if (objectTypeInfo)
			LocalFree(objectTypeInfo);

		if (pBuffer)
			LocalFree(pBuffer);

		return bSuccess;

	}

	static std::string addr_to_module(HANDLE hProcess, DWORD64 pAddr) {

		PSTR name = NULL;
		CHAR buffer[MAX_PATH] = { 0 };
		SIZE_T s = 0;
		MEMORY_BASIC_INFORMATION mbe = { 0 };

		s = VirtualQueryEx(hProcess, (PVOID)pAddr, &mbe, sizeof(MEMORY_BASIC_INFORMATION));
		if (s == 0)
			return std::string("");
		
		if (GetMappedFileNameA(hProcess, mbe.AllocationBase, buffer, MAX_PATH) == 0 ) {
			return std::string("");
		}

		name = PathFindFileNameA(buffer);

		return std::string(name);

	}


	static void initialize_suspicious_callbacks(void) {

		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

		if (hNtdll && hKernel32) {
			suspicious_callbacks.push_back(make_callback(L"ntdll!NtContinue", GetProcAddress(hNtdll, "NtContinue")));
			suspicious_callbacks.push_back(make_callback(L"ntdll!RtlCaptureContext", GetProcAddress(hNtdll, "RtlCaptureContext")));
			suspicious_callbacks.push_back(make_callback(L"ntdll!RtlCopyMemory", GetProcAddress(hNtdll, "RtlCopyMemory")));
			suspicious_callbacks.push_back(make_callback(L"ntdll!RtlMoveMemory", GetProcAddress(hNtdll, "RtlMoveMemory")));
			suspicious_callbacks.push_back(make_callback(L"ntdll!NtFreeVirtualMemory", GetProcAddress(hNtdll, "NtFreeVirtualMemory")));
			suspicious_callbacks.push_back(make_callback(L"ntdll!NtAllocateVirtualMemory", GetProcAddress(hNtdll, "NtAllocateVirtualMemory")));
			suspicious_callbacks.push_back(make_callback(L"ntdll!NtCreateThread", GetProcAddress(hNtdll, "NtCreateThread")));
			suspicious_callbacks.push_back(make_callback(L"kernel32!ResumeThread", GetProcAddress(hKernel32, "ResumeThread")));
		}

	}

}