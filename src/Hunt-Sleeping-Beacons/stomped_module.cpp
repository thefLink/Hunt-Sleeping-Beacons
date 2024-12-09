#include <string>
#include <iostream>
#include <format>

#include "phnt.h"
#include "misc.hpp"
#include "scans.hpp"

namespace hsb::scanning {

	static BOOL ModuleIsSharedOriginal(HANDLE, PVOID);

	thread_scan thread_scans::stomped_module = [](process* process, thread* thread) {

		BOOL bSuspicious = FALSE, bSuccess = FALSE;
		std::wstring message;
		std::string moduleName;

		for (int i = 0; i < thread->calltrace->raw_addresses.size(); i++) {

			DWORD64 savedRet = thread->calltrace->raw_addresses.at(i);
			moduleName = thread->calltrace->modules.at(i);

			if (ModuleIsSharedOriginal(process->handle, (PVOID)savedRet) || moduleName == "unknown")
				continue;

			if (!_strcmpi(moduleName.c_str(), "ntdll") ||
				!_strcmpi(moduleName.c_str(), "kernel32") ||
				!_strcmpi(moduleName.c_str(), "kernelbase") ||
				!_strcmpi(moduleName.c_str(), "user32") ||
				!_strcmpi(moduleName.c_str(), "win32u")
			)
				continue;

			bSuspicious = TRUE;
			break;

		}

		if (bSuspicious) {

			thread_detection detection;
			detection.name = L"Module Stomping";
			detection.description = std::format(L"Callstack contains stomped module: {}", misc::string_to_wstring(moduleName));
			detection.tid = thread->tid;
			detection.severity = hsb::containers::detections::LOW;
			process->add_detection(detection);

		}

	};

	static BOOL ModuleIsSharedOriginal(HANDLE hProcess, PVOID pAddr) {

		BOOL bIsSharedOrig = TRUE;
		SIZE_T s = 0;

		PMEMORY_WORKING_SET_EX_INFORMATION workingSets = { 0 };
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		MEMORY_WORKING_SET_EX_INFORMATION mwsi = { 0 };

		s = VirtualQueryEx(hProcess, (LPCVOID)pAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (s == 0)
			goto Cleanup;

		if (mbi.Type != MEM_IMAGE)
			goto Cleanup;

		mwsi.VirtualAddress = mbi.BaseAddress;
		if (NtQueryVirtualMemory(hProcess, NULL, MemoryWorkingSetExInformation, &mwsi, sizeof(MEMORY_WORKING_SET_EX_INFORMATION), 0) != STATUS_SUCCESS)
			goto Cleanup;

		if (mwsi.u1.VirtualAttributes.SharedOriginal == 0)
			bIsSharedOrig = FALSE;

	Cleanup:

		return bIsSharedOrig;

	}

}