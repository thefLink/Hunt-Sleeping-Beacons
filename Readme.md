# Hunt-Sleeping-Beacons

This project is ( mostly ) a callstack scanner which tries to identify IOCs indicating an unpacked or injected C2 agent.  

All checks are based on the observation that C2 agents wait between their callbacks causing the beacons thread to idle and this tool aims to analyze what potentially caused the thread to idle.

This includes traditional IOCs, such as unbacked memory or stomped modules, but also attempts to detect multiple implementation of sleepmasks using APCs or Timers. The latter is done by both: analyzing the callstack but also **enumerating timers and their exact callbacks from userland**.

(Almost) none of those IOCs can be considered a 100% true positive, the module stomping detection e.g. is very prone to false positives. Yet, the results might raise suspicion about the behaviour of a process.

DotNet and 32Bit binaries are ignored.

![x](res/1.png?raw=true)

## Checks

### Unbacked Memory 

A private r(w)x page in a callstack might indicate a beacon which was unpacked or injected at runtime. 

### Non-Executable Memory

Multiple Sleepmasks change the page permissions of the beacon's page to non-executable. This leads to a suspicious non-executable page in the callstack. 

### Module Stomping

Often, beacons avoid private memory pages by loading and overwriting a legitimate module from disk.
Thanks to the ``copy on write`` mechanism, manipulated images can be identified by checking the field ``VirtualAttributes.SharedOriginal`` of ``MEMORY_WORKING_SET_EX_INFORMATION``. If any page in the callstack is not private and ``SharedOriginal == 0``, it is considered an IOC.

This is probably the detection the most prone to false positives. :'(

### Suspicious APC

Multiple implementations of sleepmasks queue a series of APCs to ``Ntdll!NtContinue`` one of which triggers the execution of ``Ntdll!WaitForSingleObject``. Thus, if ``Ntdll!KiUserApcDispatcher`` can be found on the callstack to a blocking function, this tool considers it an IOC. 

### Suspicious Timers

Similar to the suspicious usage of APCs, this tool also checks for ``ntdll!RtlpTpTimerCallback`` on the callstack to a blocking function to detect timer-based sleepmasks. 
### Enumerating Timers and Callbacks

To my understanding, Timers are implemented on top of ThreadPools. As [Alon Leviev has demonstrated](https://github.com/SafeBreach-Labs/PoolParty) those can be enumerated using ``NtQueryInformationWorkerFactory`` with ``WorkerFactoryBasicInformation``.    

The ``WORKER_FACTORY_BASIC_INFORMATION`` struct embeds a ``FULL_TP_POOL`` which in turn links to a ``TimerQueue`` double linked list. Traversing that list of ``PFULL_TP_TIMER`` allows accessing each registered callback. If any callback is found pointing to a set of suspicious api calls, such as ``ntdll!ntcontinue``, it can be considered a strong IOC.

![x](res/2.png?raw=true)

### Abnormal Intermodular Calls ( Module Proxying )

Originally module proxying was introduced as a method to [bypass suspicious callstacks](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/).
While the bypass works, it introduces an other strong IOC, as the NTAPI is used to call the WINAPI. This is odd, as WINAPI is an abstraction for NTAPI. Thus, if a callstack is observed in which a sequence of ntdll.dll->kernel32.dll->ntdll.dll is found ending up calling a blocking function it can be considered an IOC.

### Return Address Spoofing

Most Returnaddress spoofing implementations I am aware of make use of a technique in which the called function returns to a ``jmp [Nonvolatile-Register]`` gadget. This project simply iterates every return address in callstacks and searches for patterns indicating the return to a jmp gadget.

![x](res/3.png?raw=true)

# Usage

```
 _   _    _____   ______
| | | |  /  ___|  | ___ \
| |_| |  \ `--.   | |_/ /
|  _  |   `--. \  | ___ \
| | | |  /\__/ /  | |_/ /
\_| |_/  \____/   \____/

Hunt-Sleeping-Beacons | @thefLinkk

-p / --pid {PID}

--dotnet | Set to also include dotnet processes. ( Prone to false positivies )
--commandline | Enables output of cmdline for suspicious processes
-h / --help | Prints this message?
```

# Credits

- https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools/attacking-timer-queues
- https://github.com/mrexodia/phnt-single-header
- https://github.com/SafeBreach-Labs/PoolParty
- https://github.com/bshoshany/thread-pool