#pragma once

#include <memory>
#include <vector>

#include "phnt.h"

#include "process.hpp"
#include "process_builder.hpp"

namespace hsb::containers {

	using process = hsb::containers::process;
	using process_builder = hsb::containers::process_builder;

	class process_enumerator{
	public:

		process_enumerator(uint16_t pid_to_scan = 0, bool ignore_dotnet = true);
		~process_enumerator();
		std::vector<std::unique_ptr<process>> enumerate_processes();

	private:
		process_builder process_builder_;
		uint16_t pid_to_scan_;
	};

	//implementation
	//================================================================================================

#pragma region constructor and destructor
	process_enumerator::process_enumerator(uint16_t pid_to_scan, bool ignore_dotnet)
		: pid_to_scan_(pid_to_scan)
		, process_builder_(ignore_dotnet)
	{
		SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
	}

	process_enumerator::~process_enumerator() 
	{}

#pragma endregion

#pragma region public methods

	std::vector<std::unique_ptr<process>> process_enumerator::enumerate_processes(){

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PVOID pBuffer = NULL;
		ULONG uBufferSize = 0;
		BOOL bSuccess = FALSE;

		PSYSTEM_PROCESS_INFORMATION pProcessInformation = NULL;
		SYSTEM_THREAD_INFORMATION thread_information = {0};

		std::vector<std::unique_ptr<process>> processes;
		std::unique_ptr<process> tmp = nullptr;

		do {

			status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation,pBuffer,uBufferSize,&uBufferSize);
			if(!NT_SUCCESS(status)) {

				if(status == STATUS_INFO_LENGTH_MISMATCH) {
					if(pBuffer != NULL)
						LocalFree(pBuffer);
					pBuffer = LocalAlloc(LMEM_ZEROINIT,uBufferSize);
					if(pBuffer == NULL)
						goto Cleanup;

					continue;
				}
				break;

			}
			else {

				pProcessInformation = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
				break;

			}

		} while(1);

		while(pProcessInformation && pProcessInformation->NextEntryOffset) {

#pragma warning(suppress: 4302) // 'type cast' : truncation
#pragma warning(suppress: 4311) // pointer truncation
			if ( pid_to_scan_ && pid_to_scan_ != (uint16_t)pProcessInformation->UniqueProcessId) {
				goto Next;
			}

			tmp = process_builder_.build(pProcessInformation);
			if(tmp)
				processes.push_back(std::move(tmp));

		Next:
			pProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pProcessInformation + pProcessInformation->NextEntryOffset);

		}


	Cleanup:

		return processes;

	}

#pragma endregion


}