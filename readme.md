# Process Injection Technique: PoolParty Attack with Windows API
- This is an implementation of the [PoolParty Attack](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/), the 1st variant using the internals of Windows Thread Pools and some extra Windows APIs.
## Table of Contents
- [How It Works](#How-It-Works)
- [Dependencies](#dependencies)
- [Usage](#usage)
## How It Works
A global overview of the code, for in detail explanation of the code see documentation.md:
1. Run the program process with admin rights.
2. Enable the **"SeDebugPrivilege"** on the current process.
3. Get all the PIDs of a running program.
4. Try to **OpenProcess()** each PID with the flags: **PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION**.
5. Pass the open PIDs to the **hijackProcessHandle()** function, and inside the function:
6. Call **NtQueryInformationProcess** to get the internal **PPROCESS_HANDLE_SNAPSHOT_INFORMATION** that keep the handlers to structures of a process.
7. Try to **DuplicateHandle()** each handler.
8. Call **NtQueryObject** to get the internal **PPUBLIC_OBJECT_TYPE_INFORMATION** that keep the handler's object type name, on a loop until we get the **TpWorkerFactory** structure to inject the malicious function to be executed by the thread pool of that process.
## Dependencies
- C++20
- PHNT Library for some Windows internal structure definitions and function prototypes
- Windows SDK for some headers like: TlHelp32.h and the headers that phnt.h and phnt_windows.h include by themselves *(Windows SDk is installed by default when installing Visual Studio, VS is the easiest way to get a ready-to-use environment)*
## Usage
- Just open the .exe file with admin rights, on errors you should see an output like this with important information:
<img width="563" alt="Capture1" src="https://github.com/user-attachments/assets/56a34afe-c44c-4eb6-8fe8-ac966c80f0fb" />

