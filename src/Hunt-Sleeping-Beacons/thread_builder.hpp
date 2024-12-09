#pragma once

#include <memory>
#include <stdint.h>
#include <string>
#include "phnt.h"

#include "calltrace_builder.hpp"
#include "thread.hpp"

namespace hsb::containers {
	class thread_builder{
	public:
		thread_builder();
		std::unique_ptr<thread> build(HANDLE, PSYSTEM_THREAD_INFORMATION);
	private:
		calltrace_builder calltrace_builder_;
		uint64_t enum_stackbase(HANDLE,HANDLE);
	};

	//implementation
	//================================================================================================

#pragma region constructor and destructor
	thread_builder::thread_builder()
	{}
#pragma endregion

#pragma region public methods
	std::unique_ptr<thread> thread_builder::build(HANDLE h_process, PSYSTEM_THREAD_INFORMATION sti){

		auto t = std::make_unique<thread>();
#pragma warning(suppress: 4302) 
#pragma warning(suppress: 4311) 
		t->tid = (DWORD)sti->ClientId.UniqueThread;
		t->handle = OpenThread(THREAD_ALL_ACCESS,FALSE,t->tid);
		if(t->handle == nullptr)
			return nullptr;

		t->stackbase = enum_stackbase(h_process,t->handle);
		t->calltrace = calltrace_builder_.build(h_process, t->handle);
		if (t->calltrace == nullptr)
			return nullptr;

		return t;

	}

	uint64_t thread_builder::enum_stackbase(HANDLE h_process,HANDLE h_thread) {

		TEB teb ={0};
		PTEB pTeb = NULL;
		THREAD_BASIC_INFORMATION tbi ={0};		
		SIZE_T sRead = 0;

		NTSTATUS status = STATUS_SUCCESS;
		BOOL bSuccess = FALSE;

		status = NtQueryInformationThread(h_thread,(THREADINFOCLASS)ThreadBasicInformation,&tbi,sizeof(THREAD_BASIC_INFORMATION),NULL);
		if(status == STATUS_SUCCESS) {

			bSuccess = ReadProcessMemory(h_process,tbi.TebBaseAddress,&teb,sizeof(TEB),&sRead);
			if(bSuccess == FALSE)
				return 0;

			return (uint64_t)teb.NtTib.StackBase;

		}

		return 0;

	}


#pragma endregion

}