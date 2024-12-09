#include <chrono>
#include <iostream>

#include "logger.hpp"
#include "process_enumerator.hpp"
#include "process_scanner.hpp"
#include "misc.hpp"

using logger = hsb::logger::logger;
using process = hsb::containers::process;
using process_scanner = hsb::scanning::process_scanner;
using process_enumerator = hsb::containers::process_enumerator;
using token_helpers = hsb::misc::token_helpers;

void parse_args(int argc, char** argv, bool*, bool*, uint16_t*);

int main (int argc,char** argv)
{

	bool print_cmdline = false, ignore_dotnet = true;
	uint16_t scan_pid = 0;
	parse_args(argc, argv, &print_cmdline, &ignore_dotnet, &scan_pid);

	process_enumerator process_enumerator(scan_pid, ignore_dotnet);
	process_scanner process_scanner;
	std::vector<std::unique_ptr<process>> processes;
	std::pair<uint16_t, uint16_t> scan_stats;

	if (token_helpers::is_elevated() == FALSE) {
		std::wcout << L"! Not elevated" << std::endl;
		return 0;
	}

	if (token_helpers::set_debug_privilege() == FALSE) {
		std::wcout << L"! Failed to enable debug privilege" << std::endl;
		return 0;
	}

	logger::init(print_cmdline);
	logger::logo();

	auto t1 = std::chrono::high_resolution_clock::now();

	processes = process_enumerator.enumerate_processes();
	scan_stats = process_scanner.scan_processes(processes);

	for(auto& process : processes){
		if(process->detections.size()){
			logger::print_suspicious_process(process.get());
		}
	}

	auto t2 = std::chrono::high_resolution_clock::now();
	auto ms_int = duration_cast<std::chrono::milliseconds>(t2 - t1);

	logger::print_stats(scan_stats, ms_int.count());

	return 0;

}

void parse_args(int argc, char** argv, bool* print_cmdline, bool* ignore_dotnet, uint16_t* pid) 
{
	for (int i = 1; i < argc; i++) {

		if (!_strcmpi(argv[i], "-p") || !strcmp(argv[i], "--pid")) {
			*pid = atoi(argv[i + 1]);
			i++;
		}
		else if (!_strcmpi(argv[i], "--dotnet"))
			*ignore_dotnet = false;
		else if (!_strcmpi(argv[i], "--commandline"))
			*print_cmdline = true;
		else if (!_strcmpi(argv[i], "-h") || !strcmp(argv[i], "--help"))
			logger::help();
		else
			logger::help();

	}
}