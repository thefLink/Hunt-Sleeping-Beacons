#pragma once

#include <string>
#include <vector>

namespace hsb::containers {

	class calltrace{
	public:
		inline calltrace();
		inline ~calltrace();
		std::vector<uint64_t> raw_addresses;
		std::vector<std::string> modules;
		std::vector<std::string> syms;
	};

	//implementation
	//================================================================================================

#pragma region constructor and destructor
	calltrace::calltrace()	{}
	calltrace::~calltrace() {}
#pragma endregion



}