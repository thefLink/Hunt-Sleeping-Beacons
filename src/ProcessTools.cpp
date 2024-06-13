#include "ProcessTools.h"
#include "MetaHost.h"
#include "strsafe.h"

namespace ProcessTools {

	std::wstring EnumCommandLine ( HANDLE hProcess ) {

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		BOOL bSuccess = FALSE;
		ULONG uLen = 0;
		SIZE_T len = 0;
		
		PWSTR buf = NULL;
		PEB peb = { 0 };
		RTL_USER_PROCESS_PARAMETERS parameters = { 0 };
		PROCESS_BASIC_INFORMATION processInfo = { 0 };

		std::wstring cmdLine;

		status = NtQueryInformationProcess ( hProcess, (PROCESSINFOCLASS) 0, &processInfo, sizeof ( PROCESS_BASIC_INFORMATION ), &uLen );
		if ( status != STATUS_SUCCESS )
			goto Cleanup;

		bSuccess = ReadProcessMemory ( hProcess, processInfo.PebBaseAddress, &peb, sizeof ( PEB ), &len );
		if ( bSuccess == FALSE )
			goto Cleanup;

		bSuccess = ReadProcessMemory ( hProcess, peb.ProcessParameters, &parameters, sizeof ( RTL_USER_PROCESS_PARAMETERS ), &len );
		if ( bSuccess == FALSE )
			goto Cleanup;

		buf = ( PWSTR ) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, parameters.CommandLine.Length * sizeof(WCHAR) + 2);
		if (buf == NULL)
			goto Cleanup;

		bSuccess = ReadProcessMemory ( hProcess, parameters.CommandLine.Buffer, buf, parameters.CommandLine.Length, &len );
		if ( bSuccess == FALSE )
			goto Cleanup;

		cmdLine = wstring ( buf );

	Cleanup:
		return cmdLine;

	}

	std::string HandleToName ( HANDLE hProcess, HMODULE hModule ) {

		PSTR name = NULL;
		CHAR buffer [ MAX_PATH ] = { 0 };
		K32GetModuleFileNameExA ( hProcess, hModule, buffer, MAX_PATH );

		name = PathFindFileNameA ( buffer );

		return string ( name );

	}


	//BOOL IsProcessManaged ( HANDLE hProcess ) {

	//	BOOL bIsDotnet = FALSE;
	//	HRESULT hResult = S_FALSE;
	//	ULONG count = 0;

	//	IEnumUnknown* runtimeEnum = NULL;
	//	ICLRMetaHost* pMetaHost = NULL;
	//	ICLRRuntimeInfo* info = NULL;

	//	hResult = CLRCreateInstance ( CLSID_CLRMetaHost, IID_ICLRMetaHost, ( LPVOID* ) &pMetaHost );
	//	if ( hResult != S_OK )
	//		goto Cleanup;

	//	hResult = pMetaHost->EnumerateLoadedRuntimes ( hProcess, &runtimeEnum );
	//	if ( hResult != S_OK )
	//		goto Cleanup;

	//	runtimeEnum->Next ( 1, ( IUnknown** ) &info, &count );
	//	if ( count )
	//		bIsDotnet = TRUE;

	//Cleanup:

	//	if ( pMetaHost )
	//		pMetaHost->Release ( );

	//	if ( runtimeEnum )
	//		runtimeEnum->Release ( );

	//	return bIsDotnet;

	//}


	std::vector<std::wstring> ManagedDlls = { L"clr.dll", L"mscorwks.dll", L"mscorsvr.dll", L"mscorlib.dll",  L"mscorlib.ni.dll",  L"coreclr.dll",  L"clrjit.dll" };
	BOOL IsProcessManaged(DWORD dwPid) { // Based on the idea of processhacker: https://processhacker.sourceforge.io/doc/native_8c_source.html#l04766

		PCWSTR fmt_v4 = L"\\BaseNamedObjects\\Cor_Private_IPCBlock_v4_%d";
		PCWSTR fmt_v2 = L"\\BaseNamedObjects\\Cor_Private_IPCBlock_%d";
		WCHAR sectionName[MAX_PATH] = { 0 };
		UNICODE_STRING UsSectionName = { 0 };
		OBJECT_ATTRIBUTES objectAttributes = { 0 };

		BOOL bIsManaged = FALSE;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		HANDLE hSection = NULL;

		StringCbPrintfW(sectionName, MAX_PATH, fmt_v4, dwPid);
		RtlInitUnicodeString(&UsSectionName, sectionName);

		InitializeObjectAttributes(
			&objectAttributes,
			&UsSectionName,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
		);

		status = NtOpenSection(
			&hSection,
			SECTION_QUERY,
			&objectAttributes
		);

		if (NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED) {
			bIsManaged = TRUE;
		}
		else {

			StringCbPrintfW(sectionName, MAX_PATH, fmt_v2, dwPid);
			RtlInitUnicodeString(&UsSectionName, sectionName);

			InitializeObjectAttributes(
				&objectAttributes,
				&UsSectionName,
				OBJ_CASE_INSENSITIVE,
				NULL,
				NULL
			);

			status = NtOpenSection(
				&hSection,
				SECTION_QUERY,
				&objectAttributes
			);

			if (NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED) {
				bIsManaged = TRUE;
			}
			else {

				MODULEENTRY32 me32;
				auto hModuleSnap = CreateToolhelp32Snapshot ( TH32CS_SNAPMODULE, dwPid );
				if ( hModuleSnap == INVALID_HANDLE_VALUE )
					goto Cleanup;

				me32.dwSize = sizeof ( MODULEENTRY32 );
				if ( !Module32First ( hModuleSnap, &me32 ) )
				{
					CloseHandle ( hModuleSnap );
					goto Cleanup;
				}

				do {
					if ( std::find ( ManagedDlls.begin ( ), ManagedDlls.end ( ), me32.szModule ) != ManagedDlls.end ( ) )
					{
						bIsManaged = TRUE;
						break;
					}

				}
				while ( Module32Next ( hModuleSnap, &me32 ) );

				CloseHandle ( hModuleSnap );

			}

		}

	Cleanup:

		if (hSection)
			CloseHandle(hSection);

		return bIsManaged;

	}

}