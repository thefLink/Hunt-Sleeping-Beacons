#include "Hunt-Sleeping-Beacons.h"
#include "shlwapi.h"
#include <string>

namespace MemTools {

	BOOL PageIsPrivateExecutable ( HANDLE, PVOID );
	BOOL PageIsExecutable ( HANDLE, PVOID );
	BOOL ModuleIsSharedOriginal ( HANDLE, PVOID );
	std::string AddressToModuleName ( HANDLE, PVOID );
	std::string SymbolNameFromAddress ( HANDLE, PVOID );

}