#include "StackTools.h"
#include "MemTools.h"

namespace StackTools {

	BOOL GetCallTraces ( HANDLE hProcess, HANDLE hThread, SYSTEM_THREAD_INFORMATION sti, Calltrace& pCalltrace, SymCalltrace& pSymCalltrace, ModuleCalltrace& pModuleCalltrace, Rettrace &pRettrace ) {

		BOOL bSuccess = FALSE, bModuleFound = FALSE;
		DWORD64 dw64Displacement = 0x00;
		char cSymName [ 256 ] = { 0x00 }, line [ 512 ] = { 0 };

		CONTEXT context = { 0x00 };
		STACKFRAME64 stackframe = { 0x00 };
		PIMAGEHLP_SYMBOL64 pSymbol = NULL;
		PIMAGEHLP_MODULE64 pModInfo = NULL;
		
		context.ContextFlags = CONTEXT_ALL;
		bSuccess = GetThreadContext ( hThread, &context );
		if ( bSuccess == FALSE )
			goto Cleanup;

		stackframe.AddrPC.Offset = context.Rip;
		stackframe.AddrPC.Mode = AddrModeFlat;
		stackframe.AddrStack.Offset = context.Rsp;
		stackframe.AddrStack.Mode = AddrModeFlat;
		stackframe.AddrFrame.Offset = context.Rbp;
		stackframe.AddrFrame.Mode = AddrModeFlat;

		pSymbol = ( PIMAGEHLP_SYMBOL64 )  LocalAlloc ( LMEM_ZEROINIT, sizeof ( IMAGEHLP_SYMBOL64 ) + 256 * sizeof ( WCHAR ) );
		if ( pSymbol == NULL )
			return FALSE;

		pModInfo = ( PIMAGEHLP_MODULE64 ) LocalAlloc ( LMEM_ZEROINIT, sizeof ( IMAGEHLP_MODULE64 ) + 256 * sizeof ( WCHAR ) );
		if ( pModInfo == NULL )
			return FALSE;

		pSymbol->SizeOfStruct = sizeof ( IMAGEHLP_SYMBOL64 );
		pSymbol->MaxNameLength = 255;
		pModInfo->SizeOfStruct = sizeof ( IMAGEHLP_MODULE64 );

		while ( 1 ) {

			bSuccess = StackWalk64 ( IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, &stackframe, &context, NULL, NULL, NULL, NULL );
			if ( bSuccess == FALSE ) {
				break;
			}

			memset ( line, 0, 512 );
			memset ( cSymName, 0, 256 );

			pCalltrace.push_back ( stackframe.AddrPC.Offset );
			pRettrace.push_back ( stackframe.AddrFrame.Offset );

			bModuleFound = SymGetModuleInfo64 ( hProcess, ( ULONG64 ) stackframe.AddrPC.Offset, pModInfo );
			if ( bModuleFound == FALSE ) {
				pSymCalltrace.push_back ( "unknown" );
				pModuleCalltrace.push_back ( "unknown" );
			} else {
				
				SymGetSymFromAddr64 ( hProcess, ( ULONG64 ) stackframe.AddrPC.Offset, &dw64Displacement, pSymbol );
				UnDecorateSymbolName ( pSymbol->Name, cSymName, 256, UNDNAME_COMPLETE );

				wsprintfA ( line, "%s!%s", pModInfo->ModuleName, cSymName );
				
				pSymCalltrace.push_back ( line );
				pModuleCalltrace.push_back ( pModInfo->ModuleName );

			}
			
		}

		bSuccess = TRUE;

	Cleanup:

		return bSuccess;

	}

}