#include "Check.h"

namespace ThreadChecks {

	CallstackContainsStompedModules::CallstackContainsStompedModules(PConfig pConfig) : ThreadCheck(pConfig) {}

	VOID CallstackContainsStompedModules::Describe ( VOID ) {
		printf ( "* Checking for threads which have stomped modules in their callstack\n" );
	}

	ThreadDetection* CallstackContainsStompedModules::Go ( HANDLE hProcess, Thread* pCandidate ) {

		BOOL bSuspicious = FALSE, bSuccess = FALSE;
		char message [ 512 ] = { 0 };

		for ( int i = 0; i < pCandidate->calltrace->size ( ); i++ ) {

			DWORD64 savedRet = pCandidate->calltrace->at ( i );
			std::string moduleName = pCandidate->modulecalltrace->at ( i );

			if ( MemTools::ModuleIsSharedOriginal ( hProcess, ( PVOID ) savedRet ) )
				continue;
			
			if ( !_strcmpi ( moduleName.c_str ( ), "ntdll" ) ||
				!_strcmpi ( moduleName.c_str ( ), "kernel32" ) ||
				!_strcmpi ( moduleName.c_str ( ), "kernelbase" ) ||
				!_strcmpi ( moduleName.c_str ( ), "user32" ) || 
				!_strcmpi(moduleName.c_str(), "win32u") 
				)
				continue;
			
			wsprintfA ( message, "Callstack to blocking function contains stomped module: %s ( 0x%p )", moduleName.c_str ( ), ( PVOID ) savedRet );
			bSuspicious = TRUE;
			break;

		}
		
		if ( bSuspicious ) {
			
			return new ThreadDetection (
				"Module Stomping",
				message,
				pCandidate->sti.ClientId.UniqueProcess,
				pCandidate->sti.ClientId.UniqueThread
			);

		}

		return NULL;

	}

}