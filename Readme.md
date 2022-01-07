# Hunt-Sleeping-Beacons

The idea of this project is to identify beacons which are unpacked at runtime or running in the context of another process (=InMemory malware).
To do so, I make use of the following observations:

1. Malware usually calls Sleep() between callbacks which sets the treadstate to: **DelayExecution**
2. As the malware is injected or unpacked at runtime, the callstack to Sleep() includes addresses which cannot be mapped to a module on disk as it is either not associated with a file on disk or the module has been modified at runtime.

The metric to detect this kind of malware is thus:
1. Enumerate all Threads which state is set to: **DelayExecution**
2. Analyze the callstack of the thread for suspicious memory addresses
3. If a thread is in DelayExecution and one of the return addresses in the callstack cannot be associated with a module on disk its probably a running beacon

```
[-] Failed to open process: System (4)
[-] Failed to open process: System (4)
[-] Failed to open process: MsMpEng.exe (3424)
[!] Suspicious Process: PhantomDllHollower.exe

        [*] Thread (9192) has State: DelayExecution and abnormal calltrace:

                NtDelayExecution -> C:\WINDOWS\SYSTEM32\ntdll.dll
                SleepEx -> C:\WINDOWS\System32\KERNELBASE.dll
                0x00007FF8C13A103F -> Unknown or modified module
                0x000001E3C3F48FD0 -> Unknown or modified module
                0x00007FF700000000 -> Unknown or modified module
                0x00007FF7C00000BB -> Unknown or modified module

        [*] Suspicious Sleep() found
        [*] Sleep Time: 600s
 ``` 
 
To identify the associated module of each saved instruction pointer, I make use of ```SymGetModuleInfo64```. 
This also seems to work fine against file backed memory such as [Phantom Dll Hollowing](https://github.com/forrest-orr/phantom-dll-hollower-poc) or modified text segments.
 
Managed processes calling Sleep() however will always be identified due to Jitted code.
