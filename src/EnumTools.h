#pragma once
#include "Hunt-Sleeping-Beacons.h"
#include "Candidate.h"

namespace EnumTools {

	BOOL BuildProcessList ( DWORD, std::vector<Process*>&, BOOL );
	BOOL GetHandlesOfTypeInProcess(Process *, PCWSTR, ACCESS_MASK, std::vector<HANDLE>&);

}