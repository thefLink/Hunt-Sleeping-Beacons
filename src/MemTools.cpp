#include "MemTools.h"

namespace MemTools {

	BOOL PageIsPrivateExecutable ( HANDLE hProcess, PVOID pAddr ) { 

		SIZE_T s = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		BOOL bSuccess = FALSE;

		s = VirtualQueryEx ( hProcess, ( LPCVOID ) pAddr, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
		if ( s == 0 )
			goto Cleanup;

		if ( mbi.Type != MEM_PRIVATE )
			goto Cleanup;

		if ( mbi.Protect != PAGE_EXECUTE && mbi.Protect != PAGE_EXECUTE_READ && mbi.Protect != PAGE_EXECUTE_READWRITE)
			goto Cleanup; 

		bSuccess = TRUE;

	Cleanup:

		return bSuccess;

	}


	BOOL PageIsExecutable ( HANDLE hProcess, PVOID pAddr ) {

		SIZE_T s = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		BOOL bSuccess = FALSE;

		s = VirtualQueryEx ( hProcess, ( LPCVOID ) pAddr, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
		if ( s == 0 )
			goto Cleanup;

		if ( mbi.Protect != PAGE_EXECUTE && mbi.Protect != PAGE_EXECUTE_READ && mbi.Protect != PAGE_EXECUTE_READWRITE )
			goto Cleanup;

		bSuccess = TRUE;

	Cleanup:

		return bSuccess;

	}


	BOOL ModuleIsSharedOriginal ( HANDLE hProcess, PVOID pAddr ) {

		BOOL bIsSharedOrig = TRUE;
		SIZE_T s = 0;

		PSAPI_WORKING_SET_EX_INFORMATION workingSets = { 0 };
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		MEMORY_WORKING_SET_EX_INFORMATION mwsi = { 0 };

		s = VirtualQueryEx ( hProcess, ( LPCVOID ) pAddr, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
		if ( s == 0 )
			goto Cleanup;

		if ( mbi.Type != MEM_IMAGE )
			goto Cleanup;

		mwsi.VirtualAddress = mbi.AllocationBase;
		if ( NtQueryVirtualMemory ( hProcess, NULL, MemoryWorkingSetExInformation, &mwsi, sizeof ( MEMORY_WORKING_SET_EX_INFORMATION ), 0 ) != STATUS_SUCCESS )
			goto Cleanup;

		if ( mwsi.u1.VirtualAttributes.SharedOriginal == 0 ) 
			bIsSharedOrig = FALSE;

	Cleanup:

		return bIsSharedOrig;

	}

	std::string AddressToModuleName ( HANDLE hProcess, PVOID pAddr ) {

		PSTR name = NULL;
		CHAR buffer [ MAX_PATH ] = { 0 };
		SIZE_T s = 0;
		MEMORY_BASIC_INFORMATION mbe = { 0 };

		s = VirtualQueryEx ( hProcess, pAddr, &mbe, sizeof ( MEMORY_BASIC_INFORMATION ) );
		if ( s == 0 )
			return std::string ( "" );

		K32GetModuleFileNameExA ( hProcess, ( HMODULE ) mbe.AllocationBase, buffer, MAX_PATH );

		name = PathFindFileNameA ( buffer );

		if ( !strcmp ( name, "" ) ) { 
			wsprintfA ( buffer, "%p", pAddr );
			return std::string (buffer );
		}

		return std::string ( name );

	}

	std::string SymbolNameFromAddress ( HANDLE hProcess, PVOID pAddr ) {

		BOOL bSuccess = FALSE;
		DWORD64 dw64Displacement = 0;
		CHAR cSymName [ 256 ] = { 0 };
		std::string symbol;

		PIMAGEHLP_SYMBOL64 pSymbol = NULL;

		pSymbol = ( PIMAGEHLP_SYMBOL64 ) HeapAlloc ( GetProcessHeap ( ), HEAP_ZERO_MEMORY, sizeof ( IMAGEHLP_SYMBOL64 ) + 256 * sizeof ( WCHAR ) );
		if ( pSymbol == NULL )
			goto Cleanup;

		pSymbol->SizeOfStruct = sizeof ( IMAGEHLP_SYMBOL64 );
		pSymbol->MaxNameLength = 255;

		bSuccess = SymGetSymFromAddr64 ( hProcess, ( ULONG64 ) pAddr, &dw64Displacement, pSymbol );
		if ( bSuccess == FALSE )
			goto Cleanup;

		UnDecorateSymbolName ( pSymbol->Name, cSymName, 256, UNDNAME_COMPLETE );
		symbol = std::string ( cSymName );

	Cleanup:

		if ( pSymbol )
			HeapFree ( GetProcessHeap ( ), 0, pSymbol );

		return symbol;

	}

}