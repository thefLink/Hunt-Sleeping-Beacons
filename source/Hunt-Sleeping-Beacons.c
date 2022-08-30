#include "Nt.h"

VOID myCallback(PCBPARAM, BOOLEAN);
BOOL checkCallstack(LPWSTR, DWORD, DWORD);
BOOL checkModuleStomping(HANDLE, DWORD64, SIZE_T, PSTR, PBOOL);
BOOL checkWaitReason(DWORD, DWORD, DWORD64, DWORD64);
BOOL getExportOffset(LPSTR, PDWORD64);
BOOL getOffsetCbDispatcher(PDWORD64);
BOOL getThreadsInState(PTHREAD*, PDWORD, ULONG);
PSTR toLowerA(PSTR str);
PWSTR toLowerW(PWSTR str);
BOOL SetDebugPrivilege();
BOOL IsElevated();

DWORD
main(int argc, char** argv) {

	DWORD dwNumThreadsDelayExecution = 0, dwNumThreadsWaitUserRequest = 0;
	DWORD64 dw64OffsetKiUserApcDispatcher = 0, dw64offsetCbDispatcher = 0;
	PTHREAD threadsDelayExecution[MAX_CANDIDATES] = { 0x00 }, threadsWaitUserRequest[MAX_CANDIDATES] = { 0x00 }, pCandidate = NULL;
	BOOL bSuccess = FALSE;

	printf("* Hunt-Sleeping-Beacons\n");
	printf("* Checking for threads in state wait:DelayExecution\n");
	
	if (!IsElevated()){
                printf("- You need elevated rights to run Hunt Sleeping Beacons\n");
                goto exit;
        }
        SetDebugPrivilege();
	
	bSuccess = getThreadsInState((PTHREAD*)&threadsDelayExecution, &dwNumThreadsDelayExecution, DelayExecution);
	if (bSuccess == FALSE) {
		printf("- Error enumerating threads with state: Wait:DelayExecution\n");
		goto exit;
	}

	printf("* Found %d threads in state DelayExecution, now checking for suspicious callstacks\n", dwNumThreadsDelayExecution);
	for (DWORD dwIdx = 0; dwIdx < dwNumThreadsDelayExecution && threadsDelayExecution[dwIdx] != NULL; dwIdx++) {

		pCandidate = threadsDelayExecution[dwIdx];
		checkCallstack(pCandidate->wProcessName, pCandidate->dwPid, pCandidate->dwTid);

	}

	printf("* Done\n");
	printf("* Now enumerating all thread in state wait:UserRequest\n");
	bSuccess = getThreadsInState((PTHREAD*)&threadsWaitUserRequest, &dwNumThreadsWaitUserRequest, UserRequest);
	if (bSuccess == FALSE) {
		printf("- Error enumerating all delayed threads\n");
		goto exit;
	}
	printf("* Found %d threads, now checking for delays caused by APC or Callbacks of waitable timers\n", dwNumThreadsWaitUserRequest);

	bSuccess = getExportOffset("KiUserApcDispatcher", &dw64OffsetKiUserApcDispatcher);
	if (bSuccess == FALSE) {
		printf("- Failed to find KiUserApcDispatcher\n");
		goto exit;
	}

	bSuccess = getOffsetCbDispatcher(&dw64offsetCbDispatcher);
	if (bSuccess == FALSE) {
		printf("- Failed to find callback dispatcher\n");
		goto exit;
	}

	for (DWORD dwIdx = 0; dwIdx < dwNumThreadsWaitUserRequest && threadsWaitUserRequest[dwIdx] != NULL; dwIdx++) {

		pCandidate = threadsWaitUserRequest[dwIdx];
		checkWaitReason(pCandidate->dwPid, pCandidate->dwTid, dw64OffsetKiUserApcDispatcher, dw64offsetCbDispatcher);

	}

	bSuccess = TRUE;

exit:

	printf("* End\n");

	return bSuccess;

}

//https://github.com/outflanknl/Dumpert/blob/master/Dumpert/Outflank-Dumpert/Dumpert.c Is Elevated() and SetDebugPrivilege was stolen from here :).
BOOL IsElevated() {
        BOOL fRet = FALSE;
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                TOKEN_ELEVATION Elevation = { 0 };
                DWORD cbSize = sizeof(TOKEN_ELEVATION);
                if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
                        fRet = Elevation.TokenIsElevated;
                }
        }
        if (hToken) {
                CloseHandle(hToken);
        }
        return fRet;
}

BOOL SetDebugPrivilege() {
        HANDLE hToken = NULL;
        TOKEN_PRIVILEGES TokenPrivileges = { 0 };

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
                return FALSE;
        }

        TokenPrivileges.PrivilegeCount = 1;
        TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

        LPWSTR lpwPriv = L"SeDebugPrivilege";
        if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
                CloseHandle(hToken);
                return FALSE;
        }

        if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                CloseHandle(hToken);
                return FALSE;
        }

        CloseHandle(hToken);
        return TRUE;
}

BOOL checkWaitReason(DWORD pid, DWORD tid, DWORD64 offsetAPCDispatcher, DWORD64 offsetCbDispatcher) {

	BOOLEAN bSuccess = FALSE;
	DWORD cbNeeded = 0, idx = 0;
	DWORD64 stackAddr = 0;
	SIZE_T numRead = 0;
	HANDLE hProcess = NULL, hThread = NULL;
	PVOID readAddr = NULL, pRemoteApcDispatcher = NULL, pRemoteCbDispatcher = NULL;

	CONTEXT context = { 0 };
	HMODULE modules[128] = { 0 }, hNtdll = NULL;
	CHAR szModName[MAX_PATH];

	context.ContextFlags = CONTEXT_FULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		//printf("- Failed to open process: %d\n", pid);
		goto exit;
	}

	bSuccess = EnumProcessModules(hProcess, (HMODULE*)&modules, sizeof(modules), &cbNeeded);
	if (bSuccess == FALSE) {
		//printf("- Failed to enumerate modules in remote process\n");
		goto exit;
	}

	for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {

		if (GetModuleFileNameExA(hProcess, modules[i], szModName, sizeof(szModName))) {
			if (lstrcmpA("c:\\windows\\system32\\ntdll.dll", toLowerA(szModName)) == 0) {
				hNtdll = modules[i];
				pRemoteApcDispatcher = (PBYTE)((DWORD64)hNtdll + (DWORD64)offsetAPCDispatcher);
				pRemoteCbDispatcher = (PBYTE)((DWORD64)hNtdll + (DWORD64)offsetCbDispatcher);
				break;
			}
		}

	}

	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (hThread == NULL) {
		//printf("- Failed to open thread: %d\n", tid);
		goto exit;
	}

	bSuccess = GetThreadContext(hThread, &context);
	if (bSuccess == FALSE) {
		//printf("- Failed to get thread context: %d\n", tid);
		goto exit;
	}

	/* Attempts to detect Foliage and Ekko/Nighthawk */
	for (int i = 0; i < 8192; i++) {

		readAddr = (PVOID)((DWORD64)context.Rsp + i * 8);

		bSuccess = ReadProcessMemory(hProcess, readAddr, &stackAddr, sizeof(DWORD64), &numRead);
		if (bSuccess == FALSE)
			break;

		if (stackAddr >= (DWORD64)pRemoteApcDispatcher && (DWORD64)((PBYTE)pRemoteApcDispatcher + 120) > stackAddr) {
			printf("! Possible Foliage identified in process: %d\n", pid);
			printf("\t* Thread %d state Wait:UserRequest seems to be triggered by KiUserApcDispatcher\n", tid);
		}


		if(stackAddr == (DWORD64)pRemoteCbDispatcher){
			printf("! Possible Ekko/Nighthawk identified in process: %d\n", pid);
			printf("\t* Thread %d state Wait:UserRequest seems to be triggered by Callback of waitable Timer\n", tid);
		}

	}

	bSuccess = TRUE;

exit:

	if (hProcess)
		CloseHandle(hProcess);

	if (hThread)
		CloseHandle(hThread);

	return bSuccess;


}

BOOL getExportOffset(LPSTR exportName, PDWORD64 pOffset) {

	BOOL bSuccess = FALSE;
	PVOID pKiUserApcDispatcher = NULL;
	HMODULE hNtdll = NULL;

	hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL)
		goto exit;

	pKiUserApcDispatcher = GetProcAddress(hNtdll, exportName);
	if (pKiUserApcDispatcher == NULL)
		goto exit;

	*pOffset = (PBYTE)pKiUserApcDispatcher - (PBYTE)hNtdll;

	bSuccess = TRUE;

exit:
	return bSuccess;


}

BOOL checkCallstack(LPWSTR wProcessName, DWORD dwPid, DWORD dwTid) {

	BOOL bSuccess = FALSE, bModuleFound = FALSE, bAbnormalCalltrace = FALSE, bModuleTampered = FALSE, bModuleStompingDetected = FALSE;
	DWORD64 dw64Displacement = 0x00, dw64Read = 0x00;
	char cSymName[256] = { 0x00 }, cCalltrace[4096] = { 0x00 }, cTmp[256] = { 0x00 }, cStompedModule[MAX_PATH + 1] = { 0x00 };
	HANDLE hProcess = NULL, hThread = NULL;

	LARGE_INTEGER delayInterval = { 0x00 };
	CONTEXT context = { 0x00 };
	STACKFRAME64 stackframe = { 0x00 };
	PIMAGEHLP_SYMBOL64 pSymbol = NULL;
	PIMAGEHLP_MODULE64 pModInfo = NULL;

	context.ContextFlags = CONTEXT_FULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL) {
		printf("- Failed to open process: %S (%d)\n", wProcessName, dwPid);
		return FALSE;
	}

	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwTid);
	if (hThread == NULL) {
		printf("- Failed to open thread: %d\n", dwTid);
		return FALSE;
	}

	bSuccess = GetThreadContext(hThread, &context);
	if (bSuccess == FALSE) {
		printf("- Failed to get thread context for: %d\n", dwTid);
		return FALSE;
	}

	stackframe.AddrPC.Offset = context.Rip;
	stackframe.AddrPC.Mode = AddrModeFlat;
	stackframe.AddrStack.Offset = context.Rsp;
	stackframe.AddrStack.Mode = AddrModeFlat;
	stackframe.AddrFrame.Offset = context.Rbp;
	stackframe.AddrFrame.Mode = AddrModeFlat;

	SymInitialize(hProcess, NULL, TRUE);
	pSymbol = (PIMAGEHLP_SYMBOL64)VirtualAlloc(0, sizeof(IMAGEHLP_SYMBOL64) + 256 * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
	if (pSymbol == NULL)
		return FALSE;

	pModInfo = (PIMAGEHLP_MODULE64)VirtualAlloc(0, sizeof(IMAGEHLP_MODULE64) + 256 * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
	if (pModInfo == NULL)
		return FALSE;

	pSymbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
	pSymbol->MaxNameLength = 255;

	pModInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

	do {

		memset(cTmp, 0, 256);

		bSuccess = StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, &stackframe, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);
		if (bSuccess == FALSE)
			break;

		bModuleFound = SymGetModuleInfo64(hProcess, (ULONG64)stackframe.AddrPC.Offset, pModInfo);
		if (bModuleFound == FALSE) { // This saved instruction pointer cannot be mapped to a file on disk

			wsprintfA(cTmp, "\t\t0x%p -> Unknown module\n", (void*)stackframe.AddrPC.Offset);
			lstrcatA(cCalltrace, cTmp);

			bAbnormalCalltrace = TRUE;

		}
		else { // Has this module been tampered with?

			SymGetSymFromAddr64(hProcess, (ULONG64)stackframe.AddrPC.Offset, &dw64Displacement, pSymbol);
			UnDecorateSymbolName(pSymbol->Name, cSymName, 256, UNDNAME_COMPLETE);
			wsprintfA(cTmp, "\t\t%s -> %s\n", cSymName, pModInfo->ImageName);
			lstrcatA(cCalltrace, cTmp);

			bSuccess = checkModuleStomping(hProcess, pModInfo->BaseOfImage, pModInfo->ImageSize, pModInfo->ImageName, &bModuleTampered);
			if (bSuccess == FALSE)
				printf("- Could not check module: %s for tampering in process: %d\n", pModInfo->ImageName, dwPid);

			if (bModuleTampered) {

				lstrcpyA(cStompedModule, pModInfo->ImageName);
				bModuleStompingDetected = TRUE;

			}

		}



	} while (1);

	if (strstr(cCalltrace, "Microsoft.NET") != NULL) // Cheap way to ignore managed processes :-)
		goto exit;

	if (bAbnormalCalltrace) {

		printf("! Suspicious Process: %S (%d)\n\n", wProcessName, dwPid);
		printf("\t* Thread %d has State: DelayExecution and abnormal calltrace:\n", dwTid);
		printf("\t\t\n%s\n", cCalltrace);

	}
	else if (bModuleStompingDetected) {

		if (strstr(toLowerA(cStompedModule), "ntdll.dll") != NULL || strstr(toLowerA(cStompedModule), "kernelbase.dll") != NULL) // This appears to happen legitimately sometimes  
			goto exit;

		printf("! Suspicious Process: %S (%d)\n\n", wProcessName, dwPid);
		printf("\t* Thread %d has State: DelayExecution and uses potentially stomped module\n", dwTid);
		printf("\t* Potentially stomped module: %s\n", cStompedModule);
		printf("\t\t\n%s\n", cCalltrace);

	}

	if (bModuleStompingDetected || bAbnormalCalltrace) {

		if (strstr(cCalltrace, "Sleep") != NULL) {
			printf("\t* Suspicious Sleep() found\n");
			ReadProcessMemory(hProcess, (LPCVOID)context.Rdx, (LPVOID)&delayInterval.QuadPart, sizeof(LONGLONG), &dw64Read);
			printf("\t* Sleep Time: %llds\n", ((~delayInterval.QuadPart + 1) / 10000) / 1000);
		}

		printf("\n");

	}

	bSuccess = TRUE;

exit:

	if (pSymbol)
		VirtualFree(pSymbol, 0, MEM_RELEASE);

	if (hProcess)
		SymCleanup(hProcess);

	if (hProcess)
		CloseHandle(hProcess);

	return bSuccess;

}

BOOL checkModuleStomping(HANDLE hProc, DWORD64 dw64BaseAddr, SIZE_T sizeImage, PSTR pcModuleName, PBOOL pbModuleTampered) {

	DWORD dwRead = 0;
	SIZE_T nRead = 0;
	BOOL bSuccess = FALSE;
	PVOID pBufModuleTmp = NULL, pBufTextMemory = NULL, pBufTextDisk = NULL;

	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS pNtHdrs = NULL;
	PIMAGE_SECTION_HEADER pSectionHdr = NULL;
	HANDLE hModuleDisk = NULL;

	*pbModuleTampered = FALSE;

	pBufModuleTmp = VirtualAlloc(0, sizeImage, MEM_COMMIT, PAGE_READWRITE);
	if (pBufModuleTmp == NULL)
		goto exit;

	/* Get .text from memory */
	bSuccess = ReadProcessMemory(hProc, (LPCVOID)dw64BaseAddr, pBufModuleTmp, sizeImage, &nRead);
	if (bSuccess == FALSE)
		goto exit;

	pDosHdr = (PIMAGE_DOS_HEADER)pBufModuleTmp;
	pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pBufModuleTmp + pDosHdr->e_lfanew);
	pSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

	for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {

		if (lstrcmpA(pSectionHdr->Name, ".text") == 0) {

			pBufTextMemory = VirtualAlloc(0, pSectionHdr->Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE);
			if (pBufTextMemory == NULL)
				goto exit;

			memcpy(pBufTextMemory, (PBYTE)((PBYTE)pBufModuleTmp + pSectionHdr->VirtualAddress), pSectionHdr->Misc.VirtualSize);

			break;

		}

		pSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pSectionHdr + sizeof(IMAGE_SECTION_HEADER));

	}

	/* Get .text from disk */
	hModuleDisk = CreateFileA(pcModuleName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hModuleDisk == INVALID_HANDLE_VALUE)
		goto exit;

	bSuccess = ReadFile(hModuleDisk, pBufModuleTmp, (DWORD)sizeImage, &dwRead, NULL);
	if (bSuccess == FALSE)
		goto exit;

	pSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));
	for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {

		if (lstrcmpA(pSectionHdr->Name, ".text") == 0) {

			pBufTextDisk = VirtualAlloc(0, pSectionHdr->SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
			if (pBufTextDisk == NULL)
				goto exit;

			memcpy(pBufTextDisk, (PBYTE)((PBYTE)pBufModuleTmp + pSectionHdr->PointerToRawData), pSectionHdr->SizeOfRawData);
			break;

		}

		pSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pSectionHdr + sizeof(IMAGE_SECTION_HEADER));

	}

	if (pBufTextDisk == NULL || pBufTextMemory == NULL)
		goto exit;

	/* Compare the segments */
	int n = memcmp(pBufTextDisk, pBufTextMemory, pSectionHdr->SizeOfRawData);
	if (n != 0)
		*pbModuleTampered = TRUE;

	bSuccess = TRUE;

exit:

	if (pBufModuleTmp)
		VirtualFree(pBufModuleTmp, 0, MEM_RELEASE);

	if (pBufTextMemory)
		VirtualFree(pBufTextMemory, 0, MEM_RELEASE);

	if (pBufTextDisk)
		VirtualFree(pBufTextDisk, 0, MEM_RELEASE);

	if (hModuleDisk)
		CloseHandle(hModuleDisk);

	return bSuccess;

}

BOOL getThreadsInState(PTHREAD* ppThread, PDWORD pdfNumThreads, ULONG waitReason) {

	ULONG uBufferSize = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pBuffer = NULL;
	BOOL bSuccess = FALSE;

	_PSYSTEM_PROCESS_INFORMATION pProcessInformation = NULL;
	_SYSTEM_THREAD_INFORMATION thread_information = { 0x00 };
	PTHREAD pCandidate = NULL;

	do {
		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5, pBuffer, uBufferSize, &uBufferSize);
		if (!NT_SUCCESS(status)) {
			if (status == STATUS_INFO_LENGTH_MISMATCH) {
				if (pBuffer != NULL)
					VirtualFree(pBuffer, 0, MEM_RELEASE);
				pBuffer = VirtualAlloc(NULL, uBufferSize, MEM_COMMIT, PAGE_READWRITE);
				continue;
			}
			break;
		}
		else {
			pProcessInformation = (_PSYSTEM_PROCESS_INFORMATION)pBuffer;
			break;
		}
	} while (1);

	while (pProcessInformation && pProcessInformation->NextEntryOffset) {

		for (ULONG i = 0; i < pProcessInformation->NumberOfThreads; i++) {

			thread_information = pProcessInformation->ThreadInfos[i];

			if (thread_information.WaitReason == Executive)
				continue;

			if ( thread_information.WaitReason == waitReason || waitReason == WAIT_REASON_ALL) {

				pCandidate = (PTHREAD)VirtualAlloc(0, sizeof(THREAD), MEM_COMMIT, PAGE_READWRITE);
				if (pCandidate == NULL)
					goto exit;

				pCandidate->wProcessName = pProcessInformation->ImageName.Buffer;
				pCandidate->dwPid = pProcessInformation->ProcessId;
				pCandidate->dwTid = thread_information.ClientId.UniqueThread;
				pCandidate->ullKernelTime = thread_information.KernelTime.QuadPart;
				pCandidate->ullUserTime = thread_information.UserTime.QuadPart;

				ppThread[*pdfNumThreads] = pCandidate;
				*pdfNumThreads += 1;

			}
		}

		pProcessInformation = (_PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pProcessInformation + pProcessInformation->NextEntryOffset);

	}

	bSuccess = TRUE;

exit:
	return bSuccess;

}

VOID CALLBACK myCallback(PCBPARAM cbParams, BOOLEAN TimerOrWaitFired) {

	CONTEXT context = { 0 };
	STACKFRAME64 stackframe = { 0x00 };

	BOOLEAN bSuccess = FALSE;

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

	cbParams->retDispatcher = (PVOID)stackframe.AddrPC.Offset;
	SetEvent(cbParams->hEvent);

}

BOOL getOffsetCbDispatcher(PDWORD64 pdw64OffsetCbDispatcher) {

	BOOL bSuccess = FALSE;
	PVOID retDispatcher = NULL;

	CBPARAM cbParams = { 0 };
	HANDLE hNewTimer = NULL, hEvent = NULL, hTimerQueue = NULL;
	HMODULE hNtdll = NULL;

	hEvent = CreateEventW(0, 0, 0, 0);
	if (hEvent == NULL)
		return -1;

	hTimerQueue = CreateTimerQueue();
	if (hTimerQueue == NULL)
		return -1;

	cbParams.hEvent = hEvent;

	CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)myCallback, &cbParams, 0, 0, WT_EXECUTEINTIMERTHREAD);
	WaitForSingleObject(cbParams.hEvent, INFINITE);

	hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL)
		goto exit;

	*pdw64OffsetCbDispatcher = (DWORD64)cbParams.retDispatcher - (DWORD64)hNtdll;

	bSuccess = TRUE;

exit:

	if (hNewTimer)
		CloseHandle(hNewTimer);

	if (hEvent)
		CloseHandle(hEvent);

	if (hTimerQueue)
		CloseHandle(hTimerQueue);

	return bSuccess;

}

WCHAR* toLowerW(PWSTR str)
{

	PWSTR start = str;

	while (*str) {

		if (*str <= L'Z' && *str >= 'A') {
			*str += 32;
		}

		str += 1;

	}

	return start;

}

PSTR toLowerA(PSTR str)
{

	PSTR start = str;

	while (*str) {

		if (*str <= L'Z' && *str >= 'A') {
			*str += 32;
		}

		str += 1;

	}

	return start;

}
