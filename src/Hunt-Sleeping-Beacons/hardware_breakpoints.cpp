#pragma once

#include "phnt.h"
#include "scans.hpp"

namespace hsb::scanning {

	thread_scan thread_scans::hardware_breakpoints = [](process* process, thread* thread) {

		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_ALL;
        bool bFound = false;


        if (GetThreadContext(thread->handle, &context))
        {
            
            bFound = (context.Dr0 != 0) || (context.Dr1 != 0) || (context.Dr2 != 0) || (context.Dr3 != 0 || (context.Dr7 != 0));
            if (bFound)
            {
                
                thread_detection detection;

                detection.name = L"Identified enabled hardware-breakpoints";
                detection.description = L"Often used as part of patchless-modifications of code";
                detection.tid = thread->tid;
                detection.severity = hsb::containers::detections::CRITICAL;

                process->add_detection(detection);

            }
        }

	};

}