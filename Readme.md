# Hunt-Sleeping-Beacons

The idea of this project is to identify beacons which are unpacked at runtime or running in the context of another process.    

To do so, I make use of the observation that beacons tend to call **Sleep** between their callbacks. A call to sleep sets the state of the thread to **DelayExecution** which is taken as a first indiciator that a thread might be executing a beacon.

After enumerating all threads whose state is **DelayExecution**, multiple metrics are applied to identify potential beacons

## Metrics

1. If the beacon does not make use of file backed memory, the callstack to NtDelayExecution includes memory regions which can not be associated with a file on disk.
2. If the beacon uses module stomping, one of the modules in the callstack to NtDelayExecution is modified

Projects, such as [Threadstackspoofer](https://github.com/mgeeky/ThreadStackSpoofer), hook Sleep to spoof the callstack or to use [another technique to wait between callbacks](https://github.com/waldo-irc/YouMayPasser/blob/master/Lockd/Lockd/Sleep.cpp). Thus, I added two more metrics:

3. Inline Hooks of Sleep can be fingerprinted by enumerating memory areas marked as private (not shared) storing the .text segment of Kernel32. This also applies if the hook is removed temporarily
4. Since a beacon spends more time waiting for commands than actually executing code, it can be fingerprinted by comparing the fields ```KernelTime``` and ```UserTime``` of ```SYSTEM_THREAD_INFORMATION```. Initially I thought that the time sleeping would count as time spent in Kernelmode, but it turned out the other way. I am not sure why :'P Additionally, both fields increase only after the operator executed some commands with the beacon. Also here, I am not sure why :'P

To decrease false positives, I decided to considerate only processes with loaded **wininet.dll** or **winhttp.dll**. Additionally, I had to ignore jitted processes (.NET) and modifications to **ntdll.dll** which also seems to happen legitimately. Metric three and four are still applied though.

## Examples

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
 
 Sample beacon using module stomping:
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
Sample beacon inline hooking sleep
``` 
[!] Suspicious Process: ThreadStackSpoofer.exe (4876). Potentially hooked Sleep / Modifies Kernel32.dll
```
Identification of generic beaconing behaviour by comparing ```KernelTime``` and ```UserTime```:
```
[!] Suspicious Process: ThreadStackSpoofer.exe (4876). Thread 1132 has state DelayExecution and spends 94% of the time in usermode
```

## Misc

There are of course many ways to bypass this project. :-)

## Credits
- [forrestorr](https://twitter.com/_forrestorr) for documenting the detection of modified dlls based on shared/private memory areas [link](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing)
- [waldoirc](https://twitter.com/waldoirc) for general support :-)