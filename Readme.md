# Hunt-Sleeping-Beacons

The idea of this project is to identify beacons which are **unpacked at runtime or running in the context of an other process**.    

All metrics applied are based on the observation that beacons tend to wait between their callbacks and this project aims to identify abnormal behaviour which caused the delay.

## DelayExecution

Most C2 agents tend to call ```Kernel32!Sleep``` which in turn calls ```Ntdll!NtDelayExecution``` to delay the execution of the beacon.
This method sets the state of the thread to ```Wait:DelayExecution``` while it waits.

Beacons using this method can be identified by enumerating all threads in state ```Wait:DelayExecution``` which have an abnormal calltrace to ```Ntdll!NtDelayExecution```:

- Unknown/private committed memory in calltrace
- Stomped Modules in calltrace

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
 
 Sample Beacon using module stomping:
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

## Foliage

[Foliage](https://github.com/SecIdiot/FOLIAGE/) and it's implementations, such as [AceLdr](https://github.com/kyleavery/AceLdr/), avoid the state ```Wait:DelayExecution``` and additionally encrypt themselves while waiting by queueing a series of APCs to ```Ntdll!NtContinue``` one of which triggers the execution of ```Ntdll!WaitForSingleObject``` to delay the execution. 

This effectively sets the state of the thread to ```Wait:UserRequest```. Simply walking the callstack for unknown/tampered memory regions produces to many false positives in this case.    

The observation here is that a call to ```Ntdll!WaitForSingleObject``` initiated by an APC is abnormal and sufficient to build a detection upon. 

[AceLdr](https://github.com/kyleavery/AceLdr/), can thus be identified by enumerating all threads in state ```Wait:UserRequest``` which have a return address to ```Ntdll!KiUserApcDispatcher``` somewhere on the stack. 

AceLdr:  
```
* Now enumerating all thread in state wait:UserRequest
* Found 783 threads, now checking for delays caused by APC
! Possible Foliage identified in process: 16436
        * Thread 15768 state Wait:UserRequest seems to be triggered by KiUserApcDispatcher
* End
```

## Waitable Timers Callbacks

The detection of sleep encryption methods using waitable timers like [Ekko](https://github.com/Cracked5pider/Ekko) is almost the same.
[MSDN](https://docs.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueuetimer) explicitly states that timer callbacks should not be blocking, however the sleep encryption does exactly that. 

In this project, I first locate the dispatcher of callbacks in ntdll.dll by queueing my own timer callback and then use ```RtlCaptureContext``` to be able to walk my own stack. Then, threads in state ```wait:userRequest``` are enumerated and checked for a return address to the dispatcher.

Ekko:
```
! Possible Ekko/Nighthawk identified in process: 3996
        * Thread 14756 state Wait:UserRequest seems to be triggered by Callback of waitable Timer
```

## Usage

Requirements: 

- mingw-w64

```bash
make
```

Executable does not take any parameters 

## Credits
- [Austin Hudson](https://github.com/SecIdiot/) for [Foliage](https://github.com/SecIdiot/FOLIAGE/)
- [Kyleavery](https://github.com/kyleavery) for [AceLdr](https://github.com/kyleavery/AceLdr/)
- [waldoirc](https://twitter.com/waldoirc) for general support :-)
