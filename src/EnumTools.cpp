#pragma once
#include "EnumTools.h"
#include "Candidate.h"

namespace EnumTools {

	BOOL BuildProcessList ( DWORD dwPid, std::vector<Process*>& pProcesses, BOOL ignoreDotnet ) {

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PVOID pBuffer = NULL;
		ULONG uBufferSize = 0;
		BOOL bSuccess = FALSE;

		PSYSTEM_PROCESS_INFORMATION pProcessInformation = NULL;
		SYSTEM_THREAD_INFORMATION thread_information = { 0 };

		Process* process = NULL;
		Thread* thread = NULL;

		do {

			status = NtQuerySystemInformation ( ( SYSTEM_INFORMATION_CLASS ) SystemProcessInformation, pBuffer, uBufferSize, &uBufferSize );
			if ( !NT_SUCCESS ( status ) ) {

				if ( status == STATUS_INFO_LENGTH_MISMATCH ) {
					if ( pBuffer != NULL )
						LocalFree ( pBuffer );
					pBuffer = LocalAlloc ( LMEM_ZEROINIT, uBufferSize );
					if ( pBuffer == NULL )
						goto Cleanup;

					continue;
				}
				break;

			}
	else {

	 pProcessInformation = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
	 break;

			}

		} while (1);

		while (pProcessInformation && pProcessInformation->NextEntryOffset) {

			if (dwPid && (DWORD64)pProcessInformation->UniqueProcessId != dwPid)
				goto Next;

			process = Process::make_process(pProcessInformation, ignoreDotnet);
			if (process == NULL)
				goto Next;

			for (ULONG i = 0; i < pProcessInformation->NumberOfThreads; i++) {

				thread_information = pProcessInformation->Threads[i];

				thread = Thread::make_thread(process->hProcess, thread_information);
				if (thread == NULL)
					continue;

				process->threads.push_back(thread);

			}

			pProcesses.push_back(process);
			SymCleanup(process->hProcess);

		Next:
			pProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pProcessInformation + pProcessInformation->NextEntryOffset);

		}

		bSuccess = TRUE;

	Cleanup:

		if (pBuffer)
			LocalFree(pBuffer);

		return bSuccess;

	}

	BOOL GetHandlesOfTypeInProcess(Process* pProcess, PCWSTR typeName, ACCESS_MASK access, std::vector<HANDLE>& pHandleList) {

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

			if (pProcess->pid != entryInfo->UniqueProcessId)
				continue;

			clientId.UniqueProcess = (HANDLE)entryInfo->UniqueProcessId;
			clientId.UniqueThread = 0;

			if ( NtDuplicateObject ( pProcess->hProcess, ( HANDLE ) ( uint64_t ) entryInfo->HandleValue, NtCurrentProcess ( ), &dupHandle, access, 0, 0 ) == STATUS_SUCCESS ) {

				memset(objectTypeInfo, 0, sizeof(OBJECT_TYPE_INFORMATION) * 2);

				if (NtQueryObject(dupHandle, (OBJECT_INFORMATION_CLASS)ObjectTypeInformation, objectTypeInfo, sizeof(OBJECT_TYPE_INFORMATION) * 2, NULL) == STATUS_SUCCESS) {

					if (!lstrcmpW(objectTypeInfo->TypeName.Buffer, typeName)) {
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

		if(objectTypeInfo)
			LocalFree(objectTypeInfo);

		if ( pBuffer )
			LocalFree(pBuffer);

		return bSuccess;

	}

}