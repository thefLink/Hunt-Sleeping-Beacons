#pragma once

#include <memory>

#include "BS_thread_pool.hpp"

#include "scans.hpp"
#include "process.hpp"

namespace hsb::scanning {

	class process_scanner{
	
		using process_scan = hsb::scanning::process_scan;
		using process = hsb::containers::process;
		using multi_future = BS::multi_future<void>;
		using thread_pool = BS::thread_pool;

	public:

		process_scanner();
		~process_scanner();

		std::pair<uint16_t, uint16_t> scan_processes(std::vector<std::unique_ptr<process>>&);

	private:
		thread_pool thread_pool_;
		multi_future multi_future_;
		std::vector<process_scan> process_scans_;
		std::vector<thread_scan> thread_scans_;
		std::atomic<uint16_t> n_scanned_processes_;
		std::atomic<uint16_t> n_scanned_threads_;
	};

	//implementation
	//================================================================================================

#pragma region constructor and destructor
	process_scanner::process_scanner()	
		: n_scanned_processes_(0)
		, n_scanned_threads_(0)
	{

		process_scans_.push_back(process_scans::suspicious_timer);

		thread_scans_.push_back(thread_scans::blocking_apc);
		thread_scans_.push_back(thread_scans::blocking_timer);
		thread_scans_.push_back(thread_scans::abnormal_intermodular_call);
		thread_scans_.push_back(thread_scans::return_address_spoofing);
		thread_scans_.push_back(thread_scans::private_memory);
		thread_scans_.push_back(thread_scans::stomped_module);
		thread_scans_.push_back(thread_scans::hardware_breakpoints);
		thread_scans_.push_back(thread_scans::non_executable_memory);

	}
	process_scanner::~process_scanner() {}
#pragma endregion

#pragma region public methods

	std::pair<uint16_t, uint16_t> process_scanner::scan_processes(std::vector<std::unique_ptr<process>>& processes)
	{
		
		for(auto& process : processes){

			n_scanned_processes_.fetch_add(1, std::memory_order::relaxed);

			for(auto& process_scan : process_scans_){
				multi_future_.push_back(thread_pool_.submit_task([this, &process_scan, &process]() {
					process_scan(process.get());
				}));
			}

			for(auto& thread : process->threads){
				for(auto& thread_scan : thread_scans_){
					multi_future_.push_back(thread_pool_.submit_task([this, &thread, &thread_scan,&process]() {
						thread_scan(process.get(), thread.get());
					}));
				}

				n_scanned_threads_.fetch_add(1, std::memory_order::relaxed);

			}
		}

		multi_future_.get();

		return std::make_pair(n_scanned_processes_.load(std::memory_order::relaxed), n_scanned_threads_.load(std::memory_order::relaxed));

	}

#pragma endregion

}
