#pragma once
#include "Hunt-Sleeping-Beacons.h"
#include "ProcessTools.h"

namespace StackTools {

	BOOL GetCallTraces ( HANDLE, HANDLE, SYSTEM_THREAD_INFORMATION, Calltrace&, SymCalltrace&, ModuleCalltrace&, Rettrace& );
	VOID PrintCallTrace ( HANDLE, HANDLE, Calltrace& );

}