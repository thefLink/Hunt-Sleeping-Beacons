#pragma once

#include <stdint.h>
#include <string>

#include "calltrace.hpp"

namespace hsb::containers {
	class thread{
	public:
		inline thread();
		inline ~thread();
		DWORD tid;
		HANDLE handle;
		uint64_t stackbase;
		std::unique_ptr<calltrace> calltrace;
	};

	//implementation
	//================================================================================================

#pragma region constructor and destructor
	thread::thread()
		: tid(0)
		, handle(nullptr)
		, stackbase(0)
	{}

	thread::~thread() {
		CloseHandle(handle);
	}

#pragma endregion

}