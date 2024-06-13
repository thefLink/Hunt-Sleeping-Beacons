#pragma once
#include "Hunt-Sleeping-Beacons.h"

#include "Candidate.h"

#include "tlhelp32.h"
#include "shlwapi.h"
#include <string>

using namespace std;

namespace ProcessTools {
	
	std::wstring EnumCommandLine ( HANDLE );
	std::string HandleToName ( HANDLE, HMODULE );
	BOOL IsProcessManaged( DWORD );

}