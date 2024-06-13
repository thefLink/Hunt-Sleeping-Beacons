#pragma once
#include "Hunt-Sleeping-Beacons.h"
#include "Detection.h"

#include <memory>
#include <string>

class Thread {

public:

	HANDLE hThread;
	SYSTEM_THREAD_INFORMATION sti;
	Calltrace* calltrace;
	SymCalltrace* symcalltrace;
	ModuleCalltrace* modulecalltrace;
	Rettrace* rettrace;
	BOOL isGuiThread;
	PVOID stackBase;

	static Thread* make_thread ( HANDLE, SYSTEM_THREAD_INFORMATION );

};

class Process {

public:

	std::string imageName;
	std::wstring cmdLine;

	DWORD pid;
	HANDLE hProcess;

	std::vector<ProcessDetection*> detectionsProcess;

	std::vector<Thread*> threads;
	std::vector<ThreadDetection*> detectionsThread;

	static Process* make_process ( PSYSTEM_PROCESS_INFORMATION, BOOL );

};


