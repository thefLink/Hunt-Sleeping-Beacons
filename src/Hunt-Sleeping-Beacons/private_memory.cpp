#include <string>
#include <iostream>
#include <format>

#include "phnt.h"
#include "scans.hpp"

namespace hsb::scanning {

	thread_scan thread_scans::private_memory = [](process* process, thread* thread) {

		BOOL bSuspicious = FALSE, bSuccess = FALSE;

		for (std::string module : thread->calltrace->modules) {

			if (module == "unknown") {
				bSuspicious = TRUE;
				break;
			}
		}

		if (bSuspicious) {

			thread_detection detection;
			detection.name = L"Abnormal Page in Callstack";
			detection.description = L"Callstack contains private memory regions";
			detection.tid = thread->tid;
			detection.severity = hsb::containers::detections::MID;

			process->add_detection(detection);

		}

	};

}