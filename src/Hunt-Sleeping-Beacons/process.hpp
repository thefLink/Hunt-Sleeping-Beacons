#pragma once

#include "dbghelp.h"
#include <mutex>
#include <string>
#include <vector>

#include "detection.hpp"
#include "thread.hpp"

namespace hsb::containers {

	class process{

	using detection = hsb::containers::detections::detection;

	public:
		inline process();
		inline ~process();
		HANDLE handle;
		DWORD pid;
		std::wstring imagename;
		std::wstring cmdline;
		std::vector<std::unique_ptr<thread>> threads;
		std::vector<std::unique_ptr<detection>> detections;

		template<typename T>
		void add_detection(const T&);

	private:
		std::mutex mutex;
	};

	//implementation
	//================================================================================================

#pragma region constructor and destructor
	process::process() 
		: handle(nullptr)
		, pid(0)
		, imagename(L"")
		, cmdline(L"")
	{ }

	process::~process() {
		CloseHandle(handle);
	}

#pragma endregion

#pragma region private methods
	template<typename T>
	void process::add_detection(const T &d){
		static_assert(std::is_base_of<detection,T>::value,"T must inherit from detection");

		std::lock_guard<std::mutex> lock(mutex);
		detections.push_back(std::make_unique<T>(d));

	}
#pragma endregion


}