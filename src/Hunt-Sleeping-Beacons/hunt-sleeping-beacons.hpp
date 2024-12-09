#include <vector>

#include "process_enumerator.hpp"
#include "process_scanner.hpp"
#include "misc.hpp"


namespace hsb {

	using process = hsb::containers::process;
	using process_scanner = hsb::scanning::process_scanner;
	using process_enumerator = hsb::containers::process_enumerator;
	using token_helpers = hsb::misc::token_helpers;

	std::vector<std::unique_ptr<process>> hunt(uint16_t pid = 0, bool ignore_dotnet) {

		process_enumerator process_enumerator(pid, ignore_dotnet);
		process_scanner process_scanner;
		std::vector<std::unique_ptr<process>> scanned_processes;

		if (token_helpers::is_elevated() == FALSE)
			return scanned_processes;

		if (token_helpers::set_debug_privilege() == FALSE)
			return scanned_processes;

		scanned_processes = process_enumerator.enumerate_processes();
		return scanned_processes;

	}

}