#include "phnt.h"
#include <stdio.h>
#include <iostream>

#include "detection.hpp"
#include "process.hpp"

namespace hsb::logger {

	class logger {

		using detection = hsb::containers::detections::detection;
		using process = hsb::containers::process;

	private:

		logger() = delete;
		static inline bool cmdline_;

	public:

		static void init(bool);
		static void logo(void);
		static void help(void);
		static void print_suspicious_process(process*);
		static void print_stats(std::pair<int, int>, long long);
		
	};

	//implementation
	//================================================================================================

#pragma region public methods

	// Copy paste from https://cboard.cprogramming.com/cplusplus-programming/181215-printing-colored-text-code-blocks-cplusplus.html
	void logger::init(bool cmdline)
	{
		HANDLE h;
		DWORD mode;

		h = GetStdHandle(STD_OUTPUT_HANDLE);
		GetConsoleMode(h, &mode);
		SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

		cmdline_ = cmdline;

	}

	void logger::logo(void)
	{
		std::wcout <<
			L" _   _    _____   ______\r\n"
			L"| | | |  /  ___|  | ___ \\\r\n"
			L"| |_| |  \\ `--.   | |_/ /\r\n"
			L"|  _  |   `--. \\  | ___ \\\r\n"
			L"| | | |  /\\__/ /  | |_/ /\r\n"
			L"\\_| |_/  \\____/   \\____/\r\n"
			L"\r\n"
			L"Hunt-Sleeping-Beacons | @thefLinkk\r\n"
			<< std::endl;
	}

	void logger::help(void)
	{

		std::wcout << std::endl;
		std::wcout << L"-p / --pid {PID}" << std::endl;;
		std::wcout << std::endl;
		std::wcout << L"--dotnet | Set to also include dotnet processes. ( Prone to false positivies )" << std::endl;
		std::wcout << L"--commandline | Enables output of cmdline for suspicious processes" << std::endl;
		std::wcout << L"-h / --help | Prints this message?" << std::endl;
		std::wcout << std::endl;

		exit(0);

	}

	void logger::print_suspicious_process(process* process)
	{

		std::wcout << std::format(L"\033[36m* Detections for: {} ({}) {}\033[0m", process->imagename, process->pid, (cmdline_ ? process->cmdline : L"")) << std::endl;
		for (std::unique_ptr<detection>& detection : process->detections) {
			std::wcout << "\t" << detection->to_string() << std::endl;
		}

	}

	void logger::print_stats(std::pair<int, int> stats, long long time)
	{
		std::wcout << std::endl << std::format(L"* Scanned: {} processes and {} threads in {} seconds", stats.first, stats.second, (double)time / 1000) << std::endl;
	}
#pragma endregion

};