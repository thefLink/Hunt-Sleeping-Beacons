# Hunt-Sleeping-Beacons

The idea of this project is to identify beacons which are unpacked at runtime or running in the context of another process (=InMemory malware).
To do so, I make use of the following observations:

1. Beacons usually call Sleep() between callbacks which sets the treadstate to: **DelayExecution**
2. If the beacon does not make use of file backed memory, the callstack to NtDelayExecution includes unknown memory regions
3. If the beacon uses module stomping, one of the modules in the callstack to NtDelayExecution is modified

Sample non file backed beacon:
```
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
 
 Sample beacon which uses module stomping:
 ```
[!] Suspicious Process: beacon.exe (5296)

        [*] Thread (2968) has State: DelayExecution and uses potentially stomped module
        [*] Potentially stomped module: C:\Windows\SYSTEM32\xpsservices.dll

                NtDelayExecution -> C:\Windows\SYSTEM32\ntdll.dll
                SleepEx -> C:\Windows\System32\KERNELBASE.dll
                DllGetClassObject -> C:\Windows\SYSTEM32\xpsservices.dll

        [*] Suspicious Sleep() found
        [*] Sleep Time: 5s
```

Comparing the .text segments alone would produce too many false positivies, so another metric had to be applied on top.    

To identify the associated module of each saved instruction pointer, I make use of ```SymGetModuleInfo64```. To identify module stomping I walk the callstack and compare the .text segment of each module in memory with the .text segment on disk.    

Tests were done using [Phantom Dll Hollowing](https://github.com/forrest-orr/phantom-dll-hollower-poc) and Cobalt Strike's module stomping.
 
Managed processes calling Sleep() will always be identified due to Jitted code, so in this POC I ignore them.
There are of course many ways to bypass this project.
