#include "stdio.h"

#include "windows.h"
#include "dbghelp.h"
#include <TlHelp32.h>
#include <winternl.h>
#include <winnt.h>

#include "Defines.h"

void analyze_processes(wchar_t*, DWORD, DWORD);
DWORD get_delayed_process(struct DelayedProcess**);

DWORD
main(int argc, char** argv) {

	DWORD dw_success = FAIL;
	HANDLE h_threads_snapshot = NULL;

	struct DelayedProcess* delayed_process = NULL;

	dw_success = get_delayed_process(&delayed_process);
	if (dw_success == FAIL) {
		printf("[-] Error enumerating processes\n");
		goto exit;
	}

	while (delayed_process) {

		analyze_processes(delayed_process->w_process_name, delayed_process->pid, delayed_process->tid);
		delayed_process = delayed_process->fDelayedProcess;

	}

exit:
	return dw_success;

}

void analyze_processes(wchar_t* w_process_name, DWORD pid, DWORD tid) {

	BOOL b_success = FALSE, b_has_module_name = FALSE, b_is_supicious = FALSE;
	DWORD64 displacement = 0x00, dw_read = 0x00;
	char sym_name[256] = { 0x00 }, calltrace[4096] = { 0x00 }, tmp[256] = { 0x00 };

	HANDLE h_process = NULL, h_thread = NULL;

	LARGE_INTEGER delayInterval = { 0x00 };
	CONTEXT t_context = { 0x00 };
	STACKFRAME64 stackframe = { 0x00 };
	IMAGEHLP_SYMBOL64* ptr_symbol = NULL;
	IMAGEHLP_MODULE64* ptr_modinfo = NULL;

	t_context.ContextFlags = CONTEXT_FULL;

	h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (h_process == NULL) {
		printf("[-] Failed to open process: %ws (%d)\n", w_process_name, pid);
		return;
	}

	h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (h_thread == NULL) {
		printf("[-] Failed to open thread: %d\n", tid);
		return;
	}

	b_success = GetThreadContext(h_thread, &t_context);
	if (b_success == FALSE) {
		printf("[-] Failed to get thread context for: %d\n", tid);
		return;
	}

	stackframe.AddrPC.Offset = t_context.Rip;
	stackframe.AddrPC.Mode = AddrModeFlat;
	stackframe.AddrStack.Offset = t_context.Rsp;
	stackframe.AddrStack.Mode = AddrModeFlat;
	stackframe.AddrFrame.Offset = t_context.Rbp;
	stackframe.AddrFrame.Mode = AddrModeFlat;

	SymInitialize(h_process, NULL, TRUE);
	ptr_symbol = (IMAGEHLP_SYMBOL64*)VirtualAlloc(0, sizeof(IMAGEHLP_SYMBOL64) + 256 * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
	if (ptr_symbol == NULL)
		return;

	ptr_modinfo = (IMAGEHLP_MODULE64*)VirtualAlloc(0, sizeof(IMAGEHLP_MODULE64) + 256 * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
	if (ptr_modinfo == NULL)
		return;

	ptr_symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
	ptr_symbol->MaxNameLength = 255;

	ptr_modinfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

	do {

		b_success = StackWalk64(IMAGE_FILE_MACHINE_AMD64, h_process, h_thread, &stackframe, &t_context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);
		if (b_success == FALSE)
			break;

		b_has_module_name = SymGetModuleInfo64(h_process, (ULONG64)stackframe.AddrPC.Offset, ptr_modinfo);
		if (b_has_module_name == FALSE) {

			wsprintfA(tmp, "\t\t0x%p -> Unknown or modified module\n", (void*)stackframe.AddrPC.Offset);
			b_is_supicious = TRUE;

		}
		else {

			SymGetSymFromAddr64(h_process, (ULONG64)stackframe.AddrPC.Offset, &displacement, ptr_symbol);
			UnDecorateSymbolName(ptr_symbol->Name, sym_name, 256, UNDNAME_COMPLETE);
			wsprintfA(tmp, "\t\t%s -> %s\n", sym_name, ptr_modinfo->ImageName);

		}

		lstrcatA(calltrace, tmp);
		memset(tmp, 0, 256);

	} while (1);

	if (b_is_supicious) {

		printf("[!] Suspicious Process: %ws\n\n", w_process_name);
		printf("\t[*] Thread (%d) has State: DelayExecution and abnormal calltrace:\n", tid);
		printf("\t\t\n%s\n", calltrace);

		if (strstr(calltrace, "Sleep") != NULL) {
			printf("\t[*] Suspicious Sleep() found\n");
			ReadProcessMemory(h_process, (LPCVOID)t_context.Rdx, (LPVOID)&delayInterval.QuadPart, sizeof(LONGLONG), &dw_read);
			printf("\t[*] Sleep Time: %llds\n", ((~delayInterval.QuadPart + 1) / 10000) / 1000);
		}

		printf("\n");

	}

	SymCleanup(h_process);
	VirtualFree(ptr_symbol, 0, MEM_RELEASE);

}


DWORD get_delayed_process(struct DelayedProcess** pptr_delayed_process) {

	DWORD dw_success = FAIL;
	ULONG buffer_size = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID buffer = NULL;

	_PSYSTEM_PROCESS_INFORMATION process_information = NULL;
	SYSTEM_THREAD_INFORMATION thread_information = { 0x00 };
	struct DelayedProcess* ptr_delayed_process = NULL, * ptr_b_delayed_process = NULL;

	do {
		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5, buffer, buffer_size, &buffer_size);
		if (!NT_SUCCESS(status)) {
			if (status == STATUS_INFO_LENGTH_MISMATCH) {
				if (buffer != NULL)
					VirtualFree(buffer, 0, MEM_RELEASE);
				buffer = VirtualAlloc(NULL, buffer_size, MEM_COMMIT, PAGE_READWRITE);
				continue;
			}
			break;
		}
		else {
			process_information = (_PSYSTEM_PROCESS_INFORMATION)buffer;
			break;
		}
	} while (1);

	while (process_information && process_information->NextEntryOffset) {


		for (ULONG i = 0; i < process_information->NumberOfThreads; i++) {

			thread_information = process_information->ThreadInfos[i];

			if (thread_information.WaitReason == DelayExecution) {

				ptr_delayed_process = (struct DelayedProcess*)VirtualAlloc(0, sizeof(struct DelayedProcess), MEM_COMMIT, PAGE_READWRITE);
				if (ptr_delayed_process == NULL)
					goto exit;

				ptr_delayed_process->w_process_name = process_information->ImageName.Buffer;
				ptr_delayed_process->pid = process_information->ProcessId;
				ptr_delayed_process->tid = (DWORD)thread_information.ClientId.UniqueThread;

				if (ptr_b_delayed_process != NULL) {
					ptr_delayed_process->bDelayedProcess = ptr_b_delayed_process;
					ptr_b_delayed_process->fDelayedProcess = ptr_delayed_process;
				}

				ptr_b_delayed_process = ptr_delayed_process;

			}

		}

		process_information = (_PSYSTEM_PROCESS_INFORMATION)((LPBYTE)process_information + process_information->NextEntryOffset);

	}

	while (ptr_delayed_process && ptr_delayed_process->bDelayedProcess)
		ptr_delayed_process = ptr_delayed_process->bDelayedProcess;

	*pptr_delayed_process = ptr_delayed_process;

	dw_success = SUCCESS;

exit:
	return dw_success;

}
