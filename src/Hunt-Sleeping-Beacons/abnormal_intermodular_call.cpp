#include <string>
#include <iostream>
#include <format>

#include "phnt.h"
#include "misc.hpp"
#include "scans.hpp"

namespace hsb::scanning {


	thread_scan thread_scans::abnormal_intermodular_call = [](process* process, thread* thread) {
		
		BOOL bSuccess = FALSE;

		if (thread->calltrace->raw_addresses.size() <= 2)
			goto Cleanup;

		for (int i = 0; i < thread->calltrace->raw_addresses.size(); i++) {

			std::string module_tmp = thread->calltrace->modules.at(i);

			if (!_stricmp(module_tmp.c_str(), "kernelbase") || !_stricmp(module_tmp.c_str(), "kernel32")) {

				if (i == thread->calltrace->raw_addresses.size() - 2)
					break;

				module_tmp = thread->calltrace->modules.at(i + 1);
				if (!_stricmp(module_tmp.c_str(), "ntdll")) {

					thread_detection detection;
					detection.name = L"Abnormal Intermodular Call";
					detection.description = std::format(L"{} called {}. This indicates module-proxying.", misc::string_to_wstring(thread->calltrace->syms.at(i + 1)), misc::string_to_wstring(thread->calltrace->syms.at(i)));
					detection.tid = thread->tid;
					detection.severity = hsb::containers::detections::CRITICAL;

					process->add_detection(detection);

				}

			}

		}

	Cleanup:

		return;

	};

}