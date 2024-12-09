#pragma once

#include "phnt.h"

#include <memory>
#include <stdint.h>
#include <string>
#include "tlhelp32.h"
#include "shlwapi.h"
#include "strsafe.h"

#include "process.hpp"
#include "thread_builder.hpp"

namespace hsb::containers {
	class process_builder{
	public:
		process_builder(bool ignore_dotnet = true);
		std::unique_ptr<process> build(PSYSTEM_PROCESS_INFORMATION);
	private:
		std::vector<std::unique_ptr<thread>> enumerate_threads(HANDLE, uint32_t, PSYSTEM_THREAD_INFORMATION);
		std::wstring enumerate_commandline(HANDLE);
		bool is_managed_process(DWORD);
		thread_builder thread_builder_;
		bool ignore_dotnet_;

	};

	//implementation
	//================================================================================================

#pragma region constructor and destructor
	process_builder::process_builder(bool ignore_dotnet)
		: ignore_dotnet_(ignore_dotnet)
	{}
#pragma endregion

#pragma region public methods
	std::unique_ptr<process> process_builder::build(PSYSTEM_PROCESS_INFORMATION spi){

		std::unique_ptr<process> p = nullptr;
		HANDLE h_process = nullptr;
		BOOL bIs32Bit = false;

		p = std::make_unique<process>();

#pragma warning(suppress: 4302) // 'type cast' : truncation
#pragma warning(suppress: 4311) // pointer truncation
		p->pid = (DWORD)spi->UniqueProcessId;
		p->handle = OpenProcess(PROCESS_ALL_ACCESS,FALSE,p->pid);
		if(p->handle == nullptr)
			return nullptr;

		IsWow64Process(p->handle, &bIs32Bit);
		if (bIs32Bit) 
			return nullptr;
		
		if (ignore_dotnet_ && is_managed_process(p->pid)) 
			return nullptr;
		
		SymInitialize(p->handle, NULL, TRUE);

		p->imagename = std::wstring(spi->ImageName.Buffer);
		p->cmdline = enumerate_commandline(p->handle);
		p->threads = enumerate_threads(p->handle, spi->NumberOfThreads, spi->Threads);

		SymCleanup(p->handle);

		return p;

	}
#pragma endregion
#pragma region private methods
	std::vector<std::unique_ptr<thread>> process_builder::enumerate_threads(HANDLE h_process, uint32_t n_threads, PSYSTEM_THREAD_INFORMATION sti) {

		std::vector<std::unique_ptr<thread>> threads;

		for(uint32_t i = 0; i < n_threads; i++){

			auto t = thread_builder_.build(h_process, sti);
			if(t == nullptr)
				continue;

			threads.push_back(std::move(t));

			sti = (PSYSTEM_THREAD_INFORMATION)((PBYTE)sti + sizeof(SYSTEM_THREAD_INFORMATION));

		}

		return threads;

	}

	std::wstring process_builder::enumerate_commandline(HANDLE handle) {

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		BOOL bSuccess = FALSE;
		ULONG uLen = 0;
		SIZE_T len = 0;

		PWSTR buf = NULL;
		PEB peb = {0};
		RTL_USER_PROCESS_PARAMETERS parameters = {0};
		PROCESS_BASIC_INFORMATION processInfo = {0};

		std::wstring cmdLine;

		status = NtQueryInformationProcess(handle,(PROCESSINFOCLASS)0,&processInfo,sizeof(PROCESS_BASIC_INFORMATION),&uLen);
		if(status != STATUS_SUCCESS)
			goto Cleanup;

		bSuccess = ReadProcessMemory(handle,processInfo.PebBaseAddress,&peb,sizeof(PEB),&len);
		if(bSuccess == FALSE)
			goto Cleanup;

		bSuccess = ReadProcessMemory(handle,peb.ProcessParameters,&parameters,sizeof(RTL_USER_PROCESS_PARAMETERS),&len);
		if(bSuccess == FALSE)
			goto Cleanup;

		buf = (PWSTR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,parameters.CommandLine.Length * sizeof(WCHAR) + 2);
		if(buf == nullptr)
			goto Cleanup;

		if(parameters.CommandLine.Buffer == nullptr)
			goto Cleanup;

		bSuccess = ReadProcessMemory(handle,parameters.CommandLine.Buffer,buf,parameters.CommandLine.Length,&len);
		if(bSuccess == FALSE)
			goto Cleanup;

		cmdLine = std::wstring(buf);

	Cleanup:
		return cmdLine;

	}

	bool process_builder::is_managed_process(DWORD pid) { // Based on the idea of processhacker: https://processhacker.sourceforge.io/doc/native_8c_source.html#l04766

		std::vector<std::wstring> ManagedDlls ={L"clr.dll",L"mscorwks.dll",L"mscorsvr.dll",L"mscorlib.dll",L"mscorlib.ni.dll",L"coreclr.dll",L"clrjit.dll"};

		PCWSTR fmt_v4 = L"\\BaseNamedObjects\\Cor_Private_IPCBlock_v4_%d";
		PCWSTR fmt_v2 = L"\\BaseNamedObjects\\Cor_Private_IPCBlock_%d";
		WCHAR sectionName[MAX_PATH] ={0};
		UNICODE_STRING UsSectionName ={0};
		OBJECT_ATTRIBUTES objectAttributes ={0};

		BOOL bIsManaged = FALSE;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		HANDLE hSection = NULL;
		
		StringCbPrintfW(sectionName,MAX_PATH,fmt_v4,pid);
		RtlInitUnicodeString(&UsSectionName,sectionName);

		InitializeObjectAttributes(
			&objectAttributes,
			&UsSectionName,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
		);

		status = NtOpenSection(
			&hSection,
			SECTION_QUERY,
			&objectAttributes
		);

		if(NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED) {
			bIsManaged = TRUE;
		}
		else {

			StringCbPrintfW(sectionName,MAX_PATH,fmt_v2,pid);
			RtlInitUnicodeString(&UsSectionName,sectionName);

			InitializeObjectAttributes(
				&objectAttributes,
				&UsSectionName,
				OBJ_CASE_INSENSITIVE,
				NULL,
				NULL
			);

			status = NtOpenSection(
				&hSection,
				SECTION_QUERY,
				&objectAttributes
			);

			if(NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED) {
				bIsManaged = TRUE;
			}
			else {

				MODULEENTRY32 me32;
				auto hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);
				if(hModuleSnap == INVALID_HANDLE_VALUE)
					goto Cleanup;

				me32.dwSize = sizeof(MODULEENTRY32);
				if(!Module32First(hModuleSnap,&me32))
				{
					CloseHandle(hModuleSnap);
					goto Cleanup;
				}

				do {
					if(std::find(ManagedDlls.begin(),ManagedDlls.end(),me32.szModule) != ManagedDlls.end())
					{
						bIsManaged = TRUE;
						break;
					}

				} while(Module32Next(hModuleSnap,&me32));

				CloseHandle(hModuleSnap);

			}

		}

	Cleanup:

		if(hSection)
			CloseHandle(hSection);

		return bIsManaged;
	}

#pragma endregion

}