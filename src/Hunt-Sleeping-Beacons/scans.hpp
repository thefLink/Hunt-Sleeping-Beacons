#pragma once 

#include <functional>
#include <memory>

#include "detection.hpp"
#include "process.hpp"

namespace hsb::scanning {

	using process = hsb::containers::process;
	using thread = hsb::containers::thread;
	using thread_detection = hsb::containers::detections::thread_detection;
	using process_detection = hsb::containers::detections::process_detection;

	typedef std::function<void(process*)> process_scan;
	typedef std::function<void(process*, thread*)> thread_scan;

	struct process_scans {

		process_scans() = delete;

		static process_scan suspicious_timer;

	};

	struct thread_scans {

		thread_scans() = delete;

		static thread_scan private_memory;
		static thread_scan stomped_module;
		static thread_scan blocking_apc;
		static thread_scan blocking_timer;
		static thread_scan abnormal_intermodular_call;
		static thread_scan return_address_spoofing;
		static thread_scan hardware_breakpoints;
		static thread_scan non_executable_memory;

	};

}