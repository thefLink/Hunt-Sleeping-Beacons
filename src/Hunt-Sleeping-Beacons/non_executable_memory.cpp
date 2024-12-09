#include <string>
#include <iostream>
#include <format>

#include "phnt.h"
#include "scans.hpp"

namespace hsb::scanning {

	thread_scan thread_scans::non_executable_memory = [](process* process,thread* thread) {

		BOOL bSuspicious = FALSE,bSuccess = FALSE;
		SIZE_T s = 0;
		MEMORY_BASIC_INFORMATION mbi ={0};

		for(uint64_t ret : thread->calltrace->raw_addresses) {
				
			s = VirtualQueryEx(process->handle,(LPCVOID)ret,&mbi,sizeof(MEMORY_BASIC_INFORMATION));
			if(s == 0)
				continue;

			if((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0) {
				bSuspicious = TRUE;
				break;
			}

		}

		if(bSuspicious) {

			thread_detection detection;
			detection.name = L"Non-Executable Page in Callstack";
			detection.description = L"Callstack contains memory regions marked as non-executable";
			detection.tid = thread->tid;
			detection.severity = hsb::containers::detections::MID;

			process->add_detection(detection);

		}

	};

}