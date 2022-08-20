#include "windows.h"

#include "dbghelp.h"
#include "psapi.h"
#include "stdio.h"
#include <tlhelp32.h>
#include <winternl.h>
#include <winnt.h>

#define MAX_CANDIDATES 8000
#define STATUS_SUCCESS              ((NTSTATUS) 0x00000000)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS) 0x00000001)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)

#define SYSTEMPROCESSINFORMATION 0x05

#define WAIT_REASON_ALL 7331

typedef struct {

    PWSTR wProcessName;

    DWORD dwPid;
    DWORD dwTid;

    ULONGLONG ullUserTime;
    ULONGLONG ullKernelTime;

} THREAD, *PTHREAD;

typedef LONG NTSTATUS;

typedef struct {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} _SYSTEM_THREAD_INFORMATION, * _PSYSTEM_THREAD_INFORMATION;

typedef struct
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    FILETIME CreateTime;
    FILETIME UserTime;
    FILETIME KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
#ifdef _WIN64
    ULONG pad1;
#endif
    ULONG ProcessId;
#ifdef _WIN64
    ULONG pad2;
#endif
    ULONG InheritedFromProcessId;
#ifdef _WIN64
    ULONG pad3;
#endif
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    VM_COUNTERS VirtualMemoryCounters;
    ULONG_PTR PrivatePageCount;
    IO_COUNTERS IoCounters;
    _SYSTEM_THREAD_INFORMATION ThreadInfos[1];
} _SYSTEM_PROCESS_INFORMATION, * _PSYSTEM_PROCESS_INFORMATION;

