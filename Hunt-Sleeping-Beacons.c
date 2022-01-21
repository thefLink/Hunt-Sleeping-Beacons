#include "stdio.h"

#include "windows.h"
#include "dbghelp.h"
#include <TlHelp32.h>
#include <winternl.h>
#include <winnt.h>

#include "Defines.h"

void analyze_process(wchar_t*, DWORD, DWORD);
DWORD check_tampering(HANDLE, DWORD64, SIZE_T, char*, PBOOL);
DWORD get_delayed_processes(struct DelayedProcess**);

DWORD
main(int argc, char** argv) {

	DWORD dw_success = FAIL;
	struct DelayedProcess* delayed_process = NULL;

	dw_success = get_delayed_processes(&delayed_process);
	if (dw_success == FAIL) {
		printf("[-] Error enumerating processes\n");
		goto exit;
	}

	while (delayed_process) {

		analyze_process(delayed_process->w_process_name, delayed_process->pid, delayed_process->tid);
		delayed_process = delayed_process->fDelayedProcess;

	}

exit:
	return dw_success;

}

void analyze_process(wchar_t* w_process_name, DWORD pid, DWORD tid) {

	BOOL b_success = FALSE, b_has_module_name = FALSE, b_abnormal_calltrace = FALSE, b_module_is_tampered = FALSE, b_module_stomping_detected = FALSE;
	DWORD64 displacement = 0x00, dw_read = 0x00;
	DWORD dw_success = FAIL;
	char sym_name[256] = { 0x00 }, calltrace[4096] = { 0x00 }, tmp[256] = { 0x00 }, stomped_module_name[MAX_PATH + 1] = { 0x00 };
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

		memset(tmp, 0, 256);

		b_success = StackWalk64(IMAGE_FILE_MACHINE_AMD64, h_process, h_thread, &stackframe, &t_context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);
		if (b_success == FALSE)
			break;

		b_has_module_name = SymGetModuleInfo64(h_process, (ULONG64)stackframe.AddrPC.Offset, ptr_modinfo);
		if (b_has_module_name == FALSE) { // This saved instruction pointer cannot be mapped to a file on disk

			wsprintfA(tmp, "\t\t0x%p -> Unknown module\n", (void*)stackframe.AddrPC.Offset);
			lstrcatA(calltrace, tmp);

			b_abnormal_calltrace = TRUE;

		}
		else { // Has this module been tampered with?

			SymGetSymFromAddr64(h_process, (ULONG64)stackframe.AddrPC.Offset, &displacement, ptr_symbol);
			UnDecorateSymbolName(ptr_symbol->Name, sym_name, 256, UNDNAME_COMPLETE);
			wsprintfA(tmp, "\t\t%s -> %s\n", sym_name, ptr_modinfo->ImageName);
			lstrcatA(calltrace, tmp);

			dw_success = check_tampering(h_process, ptr_modinfo->BaseOfImage, ptr_modinfo->ImageSize, ptr_modinfo->ImageName, &b_module_is_tampered);
			if (dw_success == FAIL)
				printf("[-] Could not check module: %s for tampering in process: %d\n", ptr_modinfo->ImageName, pid);


			if (b_module_is_tampered) {

				lstrcpyA(stomped_module_name, ptr_modinfo->ImageName);
				b_module_stomping_detected = TRUE;

			}

		}



	} while (1);

	if (b_abnormal_calltrace) {

		printf("[!] Suspicious Process: %ws (%d)\n\n", w_process_name, pid);
		printf("\t[*] Thread (%d) has State: DelayExecution and abnormal calltrace:\n", tid);
		printf("\t\t\n%s\n", calltrace);

	}
	else if (b_module_stomping_detected) {

		if (strstr(calltrace, "Microsoft.NET") != NULL) // Cheap way to ignore managed processes :-)
			goto exit;

		printf("[!] Suspicious Process: %ws (%d)\n\n", w_process_name, pid);
		printf("\t[*] Thread (%d) has State: DelayExecution and uses potentially stomped module\n", tid);
		printf("\t[*] Potentially stomped module: %s\n", stomped_module_name);
		printf("\t\t\n%s\n", calltrace);

	

	}

	if (b_module_stomping_detected || b_abnormal_calltrace) {

		if (strstr(calltrace, "Sleep") != NULL) {
			printf("\t[*] Suspicious Sleep() found\n");
			ReadProcessMemory(h_process, (LPCVOID)t_context.Rdx, (LPVOID)&delayInterval.QuadPart, sizeof(LONGLONG), &dw_read);
			printf("\t[*] Sleep Time: %llds\n", ((~delayInterval.QuadPart + 1) / 10000) / 1000);
		}

		printf("\n");

	}

exit:

	if (ptr_symbol)
		VirtualFree(ptr_symbol, 0, MEM_RELEASE);

	if (h_process)
		SymCleanup(h_process);

	if (h_process)
		CloseHandle(h_process);

}

DWORD check_tampering(HANDLE h_proc, DWORD64 base_addr, SIZE_T image_size, char* module_name, PBOOL ptr_bool_tampered) {

	DWORD dw_success = FAIL, dw_read = 0;
	SIZE_T n_read = 0;
	BOOL b_success = FALSE;
	void* buf_module_tmp = NULL, * buf_text_memory = NULL, * buf_text_disk = NULL;

	PIMAGE_DOS_HEADER ptr_dos_hdr = NULL;
	PIMAGE_NT_HEADERS ptr_nt_hdrs = NULL;
	PIMAGE_SECTION_HEADER ptr_section_hdr = NULL;
	HANDLE h_module_disk = NULL;

	*ptr_bool_tampered = FALSE;

	buf_module_tmp = VirtualAlloc(0, image_size, MEM_COMMIT, PAGE_READWRITE);
	if (buf_module_tmp == NULL)
		goto exit;

	/* Get .text from memory */
	b_success = ReadProcessMemory(h_proc, (LPCVOID)base_addr, buf_module_tmp, image_size, &n_read);
	if (b_success == FALSE)
		goto exit;

	ptr_dos_hdr = (PIMAGE_DOS_HEADER)buf_module_tmp;
	ptr_nt_hdrs = (PIMAGE_NT_HEADERS)((uint8_t*)buf_module_tmp + ptr_dos_hdr->e_lfanew);
	ptr_section_hdr = (PIMAGE_SECTION_HEADER)((uint8_t*)&ptr_nt_hdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

	for (int i = 0; i < ptr_nt_hdrs->FileHeader.NumberOfSections; i++) {

		if (lstrcmpA(ptr_section_hdr->Name, ".text") == 0) {

			buf_text_memory = VirtualAlloc(0, ptr_section_hdr->SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
			if (buf_text_memory == NULL)
				goto exit;

			memcpy(buf_text_memory, (uint8_t*)((uint8_t*)buf_module_tmp + ptr_section_hdr->VirtualAddress), ptr_section_hdr->SizeOfRawData);

			break;

		}

		ptr_section_hdr = (PIMAGE_SECTION_HEADER)((uint8_t*)ptr_section_hdr + sizeof(IMAGE_SECTION_HEADER));

	}

	/* Get .text from disk */
	h_module_disk = CreateFileA(module_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_module_disk == INVALID_HANDLE_VALUE)
		goto exit;

	b_success = ReadFile(h_module_disk, buf_module_tmp, (DWORD)image_size, &dw_read, NULL);
	if (b_success == FALSE)
		goto exit;

	ptr_section_hdr = (PIMAGE_SECTION_HEADER)((uint8_t*)&ptr_nt_hdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));
	for (int i = 0; i < ptr_nt_hdrs->FileHeader.NumberOfSections; i++) {

		if (lstrcmpA(ptr_section_hdr->Name, ".text") == 0) {

			buf_text_disk = VirtualAlloc(0, ptr_section_hdr->SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
			if (buf_text_disk == NULL)
				goto exit;

			memcpy(buf_text_disk, (uint8_t*)((uint8_t*)buf_module_tmp + ptr_section_hdr->PointerToRawData), ptr_section_hdr->SizeOfRawData);
			break;

		}

		ptr_section_hdr = (PIMAGE_SECTION_HEADER)((uint8_t*)ptr_section_hdr + sizeof(IMAGE_SECTION_HEADER));

	}

	if (buf_text_disk == NULL || buf_text_memory == NULL)
		goto exit;

	/* Compare the segments */
	int n = memcmp(buf_text_disk, buf_text_memory, ptr_section_hdr->SizeOfRawData);
	if (n != 0)
		*ptr_bool_tampered = TRUE;

	dw_success = SUCCESS;

exit:

	if (buf_module_tmp)
		VirtualFree(buf_module_tmp, 0, MEM_RELEASE);

	if (buf_text_memory)
		VirtualFree(buf_text_memory, 0, MEM_RELEASE);

	if (buf_text_disk)
		VirtualFree(buf_text_disk, 0, MEM_RELEASE);

	if (h_module_disk)
		CloseHandle(h_module_disk);

	return dw_success;

}

DWORD get_delayed_processes(struct DelayedProcess** pptr_delayed_process) {

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