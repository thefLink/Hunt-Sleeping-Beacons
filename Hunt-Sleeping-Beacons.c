#include "stdio.h"

#include "windows.h"
#include "dbghelp.h"
#include <winternl.h>
#include <winnt.h>
#include "psapi.h"

#include "Defines.h"

DWORD checkCallstack(LPWSTR, DWORD, DWORD);
DWORD checkHttpCapabilities(DWORD, PBOOL);
DWORD checkInlineHooks(LPWSTR, DWORD);
DWORD checkModuleStomping(HANDLE, DWORD64, SIZE_T, char*, PBOOL);
DWORD checkLandDiff(LPWSTR, DWORD, DWORD, ULONGLONG, ULONGLONG);
DWORD getCandidates(Candidate**, PDWORD);
WCHAR* toLower(WCHAR* str);

DWORD
main(int argc, char** argv) {

	DWORD dwSuccess = FAIL, dwNumCandidates = 0;
	Candidate* candidates[MAX_CANDIDATES] = { 0x00 }, * pCandidate = NULL;;

	printf("[*] Hunt-Sleeping-Beacons\n");
	printf("[*] Checking for processes with loaded wininet/winhttp and threads in state DelayExecution\n");

	dwSuccess = getCandidates(&candidates, &dwNumCandidates);
	if (dwSuccess == FAIL) {
		printf("[-] Error enumerating processes\n");
		goto exit;
	}

	printf("[*] Found %d threads in state DelayExecution, now checking for suspicious artifacts\n", dwNumCandidates);
	printf("[*] Checking for: \n\n\t1. Unknown modules in calltrace to NtDelayExecution\n\t2. Modified modules in calltrace to NtDelayExecution\n\t3. Abnormal difference between time spent in usermode vs kernelmode\n\t4. Abnormal private memory in kernel32 text segment to detect inline hooks of Sleep()\n\n");
	printf("[*] ========================================= \n");

	for (DWORD dwIdx = 0; dwIdx < dwNumCandidates && candidates[dwIdx] != NULL; dwIdx++) {

		pCandidate = candidates[dwIdx];

		checkCallstack(pCandidate->wProcessName, pCandidate->dwPid, pCandidate->dwTid);
		checkLandDiff(pCandidate->wProcessName, pCandidate->dwPid, pCandidate->dwTid, pCandidate->ullUserTime, pCandidate->ullKernelTime);
		checkInlineHooks(pCandidate->wProcessName, pCandidate->dwPid);

	}

	dwSuccess = SUCCESS;

exit:

	printf("[*] End\n");

	return dwSuccess;

}

DWORD checkCallstack(LPWSTR wProcessName, DWORD dwPid, DWORD dwTid) {

	BOOL bSuccess = FALSE, bModuleFound = FALSE, bAbnormalCalltrace = FALSE, bModuleTampered = FALSE, bModuleStompingDetected = FALSE;
	DWORD64 dw64Displacement = 0x00, dw64Read = 0x00;
	DWORD dwSuccess = FAIL;
	char cSymName[256] = { 0x00 }, cCalltrace[4096] = { 0x00 }, cTmp[256] = { 0x00 }, cStompedModule[MAX_PATH + 1] = { 0x00 };
	HANDLE hProcess = NULL, hThread = NULL;

	LARGE_INTEGER delayInterval = { 0x00 };
	CONTEXT context = { 0x00 };
	STACKFRAME64 stackframe = { 0x00 };
	IMAGEHLP_SYMBOL64* pSymbol = NULL;
	IMAGEHLP_MODULE64* pModInfo = NULL;

	context.ContextFlags = CONTEXT_FULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL) {
		printf("[-] Failed to open process: %ws (%d)\n", wProcessName, dwPid);
		return FAIL;
	}

	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwTid);
	if (hThread == NULL) {
		printf("[-] Failed to open thread: %d\n", dwTid);
		return FAIL;
	}

	bSuccess = GetThreadContext(hThread, &context);
	if (bSuccess == FALSE) {
		printf("[-] Failed to get thread context for: %d\n", dwTid);
		return FAIL;
	}

	stackframe.AddrPC.Offset = context.Rip;
	stackframe.AddrPC.Mode = AddrModeFlat;
	stackframe.AddrStack.Offset = context.Rsp;
	stackframe.AddrStack.Mode = AddrModeFlat;
	stackframe.AddrFrame.Offset = context.Rbp;
	stackframe.AddrFrame.Mode = AddrModeFlat;

	SymInitialize(hProcess, NULL, TRUE);
	pSymbol = (IMAGEHLP_SYMBOL64*)VirtualAlloc(0, sizeof(IMAGEHLP_SYMBOL64) + 256 * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
	if (pSymbol == NULL)
		return FAIL;

	pModInfo = (IMAGEHLP_MODULE64*)VirtualAlloc(0, sizeof(IMAGEHLP_MODULE64) + 256 * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
	if (pModInfo == NULL)
		return FAIL;

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

			dwSuccess = checkModuleStomping(hProcess, pModInfo->BaseOfImage, pModInfo->ImageSize, pModInfo->ImageName, &bModuleTampered);
			if (dwSuccess == FAIL)
				printf("[-] Could not check module: %s for tampering in process: %d\n", pModInfo->ImageName, dwPid);

			if (bModuleTampered) {

				lstrcpyA(cStompedModule, pModInfo->ImageName);
				bModuleStompingDetected = TRUE;

			}

		}



	} while (1);

	if (strstr(cCalltrace, "Microsoft.NET") != NULL) // Cheap way to ignore managed processes :-)
		goto exit;

	if (bAbnormalCalltrace) {

		printf("[!] Suspicious Process: %ws (%d)\n\n", wProcessName, dwPid);
		printf("\t[*] Thread (%d) has State: DelayExecution and abnormal calltrace:\n", dwTid);
		printf("\t\t\n%s\n", cCalltrace);

	}
	else if (bModuleStompingDetected) {

		if (strstr(cStompedModule, "ntdll.dll") != NULL || strstr(cStompedModule, "KERNELBASE.dll") != NULL) // This appears to happen legitimately sometimes  
			goto exit;

		printf("[!] Suspicious Process: %ws (%d)\n\n", wProcessName, dwPid);
		printf("\t[*] Thread (%d) has State: DelayExecution and uses potentially stomped module\n", dwTid);
		printf("\t[*] Potentially stomped module: %s\n", cStompedModule);
		printf("\t\t\n%s\n", cCalltrace);

	}

	if (bModuleStompingDetected || bAbnormalCalltrace) {

		if (strstr(cCalltrace, "Sleep") != NULL) {
			printf("\t[*] Suspicious Sleep() found\n");
			ReadProcessMemory(hProcess, (LPCVOID)context.Rdx, (LPVOID)&delayInterval.QuadPart, sizeof(LONGLONG), &dw64Read);
			printf("\t[*] Sleep Time: %llds\n", ((~delayInterval.QuadPart + 1) / 10000) / 1000);
		}

		printf("\n");

	}

	dwSuccess = SUCCESS;

exit:

	if (pSymbol)
		VirtualFree(pSymbol, 0, MEM_RELEASE);

	if (hProcess)
		SymCleanup(hProcess);

	if (hProcess)
		CloseHandle(hProcess);

	return dwSuccess;

}

DWORD checkModuleStomping(HANDLE hProc, DWORD64 dw64BaseAddr, SIZE_T sizeImage, char* pcModuleName, PBOOL pbModuleTampered) {

	DWORD dwSuccess = FAIL, dwRead = 0;
	SIZE_T nRead = 0;
	BOOL bSuccess = FALSE;
	void* pBufModuleTmp = NULL, * pBufTextMemory = NULL, * pBufTextDisk = NULL;

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
	pNtHdrs = (PIMAGE_NT_HEADERS)((uint8_t*)pBufModuleTmp + pDosHdr->e_lfanew);
	pSectionHdr = (PIMAGE_SECTION_HEADER)((uint8_t*)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

	for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {

		if (lstrcmpA(pSectionHdr->Name, ".text") == 0) {

			pBufTextMemory = VirtualAlloc(0, pSectionHdr->Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE);
			if (pBufTextMemory == NULL)
				goto exit;

			memcpy(pBufTextMemory, (uint8_t*)((uint8_t*)pBufModuleTmp + pSectionHdr->VirtualAddress), pSectionHdr->Misc.VirtualSize);

			break;

		}

		pSectionHdr = (PIMAGE_SECTION_HEADER)((uint8_t*)pSectionHdr + sizeof(IMAGE_SECTION_HEADER));

	}

	/* Get .text from disk */
	hModuleDisk = CreateFileA(pcModuleName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hModuleDisk == INVALID_HANDLE_VALUE)
		goto exit;

	bSuccess = ReadFile(hModuleDisk, pBufModuleTmp, (DWORD)sizeImage, &dwRead, NULL);
	if (bSuccess == FALSE)
		goto exit;

	pSectionHdr = (PIMAGE_SECTION_HEADER)((uint8_t*)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));
	for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {

		if (lstrcmpA(pSectionHdr->Name, ".text") == 0) {

			pBufTextDisk = VirtualAlloc(0, pSectionHdr->SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
			if (pBufTextDisk == NULL)
				goto exit;

			memcpy(pBufTextDisk, (uint8_t*)((uint8_t*)pBufModuleTmp + pSectionHdr->PointerToRawData), pSectionHdr->SizeOfRawData);
			break;

		}

		pSectionHdr = (PIMAGE_SECTION_HEADER)((uint8_t*)pSectionHdr + sizeof(IMAGE_SECTION_HEADER));

	}

	if (pBufTextDisk == NULL || pBufTextMemory == NULL)
		goto exit;

	/* Compare the segments */
	int n = memcmp(pBufTextDisk, pBufTextMemory, pSectionHdr->SizeOfRawData);
	if (n != 0)
		*pbModuleTampered = TRUE;

	dwSuccess = SUCCESS;

exit:

	if (pBufModuleTmp)
		VirtualFree(pBufModuleTmp, 0, MEM_RELEASE);

	if (pBufTextMemory)
		VirtualFree(pBufTextMemory, 0, MEM_RELEASE);

	if (pBufTextDisk)
		VirtualFree(pBufTextDisk, 0, MEM_RELEASE);

	if (hModuleDisk)
		CloseHandle(hModuleDisk);

	return dwSuccess;

}

DWORD checkLandDiff(LPWSTR wProcessName, DWORD dwPid, DWORD dwTid, ULONGLONG ullUserTime, ULONGLONG ullKernelTime) {

	DWORD dwSuccess = FAIL, dwPercent = 0, dwOverAll = 0;
	ULONGLONG ullOverAll = 0;

	ullOverAll = (ULONGLONG)(ullUserTime + ullKernelTime);
	if (ullOverAll == 0)
		goto exit;

	dwPercent = (ullUserTime * 100) / ullOverAll;
	if (dwPercent >= 65)
		printf("[!] Suspicious Process: %ws (%d). Thread %d has state DelayExecution and spends ~%d%% of the time in usermode\n",
			wProcessName, dwPid, dwTid, dwPercent);

	dwSuccess = SUCCESS;

exit:

	return dwSuccess;

}

DWORD getCandidates(Candidate** ppCandidate, PDWORD pdwNumCandidates) {

	DWORD dwSuccess = FAIL;
	ULONG uBufferSize = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pBuffer = NULL;
	BOOL bHTTPCapable = FALSE;

	_PSYSTEM_PROCESS_INFORMATION pProcessInformation = NULL;
	_SYSTEM_THREAD_INFORMATION thread_information = { 0x00 };
	Candidate* pCandidate = NULL;

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

			if (thread_information.WaitReason != DelayExecution)
				continue;

			dwSuccess = checkHttpCapabilities((DWORD)pProcessInformation->ProcessId, &bHTTPCapable);
			if (dwSuccess == FALSE || bHTTPCapable == FALSE)
				continue;

			pCandidate = (Candidate*)VirtualAlloc(0, sizeof(Candidate), MEM_COMMIT, PAGE_READWRITE);
			if (pCandidate == NULL)
				goto exit;

			pCandidate->wProcessName = pProcessInformation->ImageName.Buffer;
			pCandidate->dwPid = pProcessInformation->ProcessId;
			pCandidate->dwTid = (DWORD)thread_information.ClientId.UniqueThread;
			pCandidate->ullKernelTime = thread_information.KernelTime.QuadPart;
			pCandidate->ullUserTime = thread_information.UserTime.QuadPart;

			ppCandidate[*pdwNumCandidates] = pCandidate;
			*pdwNumCandidates += 1;

		}

		pProcessInformation = (_PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pProcessInformation + pProcessInformation->NextEntryOffset);

	}

	dwSuccess = SUCCESS;

exit:
	return dwSuccess;

}

/* As documented here https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing */
DWORD checkInlineHooks(LPWSTR wProcessName, DWORD dwPid) { 

	DWORD dwSuccess = FAIL, dwPrivate = 0;
	HANDLE hProcess = NULL, hModuleSnapshot = NULL;
	BOOL bFoundKernel32 = FALSE;

	SYSTEM_INFO si = { 0x00 };
	MEMORY_BASIC_INFORMATION mbi = { 0x00 };
	MODULEENTRY32W mod = { 0x00 };
	PSAPI_WORKING_SET_EX_INFORMATION wsInfo = { 0x00 };

	GetSystemInfo(&si);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL) {
		//printf("[-] Failed to open process: %d\n", dwPid);
		goto exit;
	}

	hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (hModuleSnapshot == INVALID_HANDLE_VALUE) {
		//printf("[-] Failed to snapshot module list for pid: %d\n", dwPid);
		goto exit;
	}

	mod.dwSize = sizeof(MODULEENTRY32W);
	Module32FirstW(hModuleSnapshot, &mod);

	do {

		if (!lstrcmpW(toLower(mod.szModule), L"kernel32.dll"))
			bFoundKernel32 = TRUE;

	} while (bFoundKernel32 == FALSE && Module32NextW(hModuleSnapshot, &mod));

	if (bFoundKernel32 == FALSE) {
		//printf("[-] Failed to identify Kernel32.dll in process: %d\n", dwPid);
		goto exit;
	}

	PVOID pMem = mod.modBaseAddr;
	while (pMem < mod.modBaseAddr + mod.modBaseSize) {

		VirtualQueryEx(hProcess, pMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		pMem = (PVOID)((PBYTE)pMem + 0x1000);

		if (mbi.Type != MEM_IMAGE || mbi.Protect != PAGE_EXECUTE_READ)
			continue;

		wsInfo.VirtualAddress = (PVOID)((PBYTE)mbi.BaseAddress);

		dwSuccess = K32QueryWorkingSetEx(hProcess, &wsInfo, sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
		if (dwSuccess == FAIL) {
			//printf("[-] Failed to Query Working Set\n");
			goto exit;
		}

		if (!wsInfo.VirtualAttributes.Shared)
			dwPrivate += 0x1000;

		if (dwPrivate) {
			printf("[!] Suspicious Process: %ws (%d). Potentially hooked Sleep / Modifies Kernel32.dll\n", wProcessName, dwPid);
			break;
		}

	}

	dwSuccess = SUCCESS;

exit:

	if (hProcess)
		CloseHandle(hProcess);

	return dwSuccess;

}

DWORD checkHttpCapabilities(DWORD dwPid, PBOOL pbHttpCapable) {

	HANDLE hModuleSnapshot = NULL;
	MODULEENTRY32W mod = { 0x00 };

	DWORD dwSuccess = FAIL;

	*pbHttpCapable = FALSE;

	hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (hModuleSnapshot == INVALID_HANDLE_VALUE) {
		//printf("[-] Failed to snapshot module list for pid: %d\n", dwPid);
		goto exit;
	}

	memset(&mod, 0, sizeof(mod));
	mod.dwSize = sizeof(MODULEENTRY32W);
	Module32FirstW(hModuleSnapshot, &mod);

	do {

		if (!lstrcmpW(toLower(mod.szModule), L"wininet.dll") || !lstrcmpW(toLower(mod.szModule), L"winhttp.dll")) {
			*pbHttpCapable = TRUE;
			break;
		}


	} while (Module32NextW(hModuleSnapshot, &mod));

	dwSuccess = SUCCESS;

exit:

	if (hModuleSnapshot)
		CloseHandle(hModuleSnapshot);

	return dwSuccess;

}

WCHAR* toLower(WCHAR* str)
{

	WCHAR* start = str;

	while (*str) {

		if (*str <= L'Z' && *str >= 'A') {
			*str += 32;
		}

		str += 1;

	}

	return start;

}