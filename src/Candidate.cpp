#include "Candidate.h"
#include "StackTools.h"
#include "ProcessTools.h"

Process* Process::make_process ( PSYSTEM_PROCESS_INFORMATION spi, BOOL ignoreDotnet ) {
	
	BOOL bIs32Bit = FALSE;

	Process* process = new Process ( );

#pragma warning(suppress: 4302) // 'type cast' : truncation
#pragma warning(suppress: 4311) // pointer truncation
	process->pid = (DWORD) spi->UniqueProcessId;

#pragma warning(suppress: 4311 4302 )
	process->hProcess = OpenProcess ( PROCESS_ALL_ACCESS, FALSE, (DWORD) spi->UniqueProcessId);
	if ( process->hProcess == NULL )
		return NULL;

	IsWow64Process ( process->hProcess, &bIs32Bit ); // Not supported yet :'(
	if ( bIs32Bit )
		return NULL;
	
	if ( ignoreDotnet && ProcessTools::IsProcessManaged ( process->pid ) )
		return NULL;

	SymInitialize ( process->hProcess, NULL, TRUE );

	process->imageName = ProcessTools::HandleToName ( process->hProcess, NULL );
	process->cmdLine = ProcessTools::EnumCommandLine ( process->hProcess );

	return process;

}

Thread* Thread::make_thread ( HANDLE hProcess, SYSTEM_THREAD_INFORMATION  sti ) {

	BOOL bSuccess = FALSE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	HANDLE hThread = NULL;
	Thread* thread = NULL;
	Calltrace* calltrace = NULL;
	SymCalltrace* symCalltrace = NULL;
	ModuleCalltrace* moduleCalltrace = NULL;
	Rettrace* rettrace = NULL;

	PVOID win32Thread = NULL;
	SIZE_T sRead = 0;

	TEB teb = { 0 };
	PTEB pTeb = NULL;
	THREAD_BASIC_INFORMATION tbi = { 0 };

#pragma warning(suppress: 4302) 
#pragma warning(suppress: 4311) 
	hThread = OpenThread ( THREAD_ALL_ACCESS, FALSE, (DWORD) sti.ClientId.UniqueThread );
	if ( hThread == NULL )
		goto Cleanup;

	calltrace = new Calltrace ( );
	if ( calltrace == NULL )
		goto Cleanup;

	symCalltrace = new SymCalltrace ( );
	if ( symCalltrace == NULL )
		goto Cleanup;

	moduleCalltrace = new ModuleCalltrace ( );
	if ( moduleCalltrace == NULL )
		goto Cleanup;
	
	rettrace = new Rettrace ( );
	if ( rettrace == NULL )
		goto Cleanup;

	bSuccess = StackTools::GetCallTraces ( hProcess, hThread, sti, *calltrace, *symCalltrace, *moduleCalltrace, *rettrace );
	if ( bSuccess == FALSE )
		goto Cleanup;

	thread = new Thread ( );
	thread->hThread = hThread;
	thread->sti = sti;
	thread->calltrace = calltrace;
	thread->symcalltrace = symCalltrace;
	thread->modulecalltrace = moduleCalltrace;
	thread->rettrace = rettrace;

	status = NtQueryInformationThread ( hThread, ( THREADINFOCLASS ) ThreadBasicInformation, &tbi, sizeof ( THREAD_BASIC_INFORMATION ), NULL );
	if ( status == STATUS_SUCCESS ) {

		bSuccess = ReadProcessMemory ( hProcess, tbi.TebBaseAddress, &teb, sizeof ( TEB ), &sRead );
		if ( bSuccess == FALSE )
			goto Cleanup;

		if ( !teb.Win32ThreadInfo )
			thread->isGuiThread = TRUE;

		thread->stackBase = teb.NtTib.StackBase;

	}


	bSuccess = TRUE;

Cleanup:

	return bSuccess ? thread : NULL;
}