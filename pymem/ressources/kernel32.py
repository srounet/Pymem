"""It handles memory management, input/output operations, and interrupts"""
import ctypes

dll = ctypes.WinDLL('kernel32.dll')
#: Opens an existing local process object.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320%28v=vs.85%29.aspx
OpenProcess = dll.OpenProcess
OpenProcess.restype = ctypes.c_ulong

#: Terminates the specified process and all of its threads.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms686714%28v=vs.85%29.aspx
TerminateProcess = dll.TerminateProcess
TerminateProcess.restype = ctypes.c_ulong

#: Closes an open object handle.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211%28v=vs.85%29.aspx
CloseHandle = dll.CloseHandle
CloseHandle.restype = ctypes.c_long

#: Retrieves the calling thread's last-error code value. The last-error code is maintained on a per-thread basis.
#: Multiple threads do not overwrite each other's last-error code.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms679360%28v=vs.85%29.aspx
GetLastError = dll.GetLastError
GetLastError.restype = ctypes.c_ulong

#: Retrieves a pseudo handle for the current process.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms683179%28v=vs.85%29.aspx
GetCurrentProcess = dll.GetCurrentProcess
GetCurrentProcess.restype = ctypes.c_ulong

#: Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx
ReadProcessMemory = dll.ReadProcessMemory
ReadProcessMemory.restype = ctypes.c_long

#: Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320%28v=vs.85%29.aspx
WriteProcessMemory = dll.WriteProcessMemory
WriteProcessMemory.restype = ctypes.c_long

#: Enables a debugger to attach to an active process and debug it.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms679295%28v=vs.85%29.aspx
DebugActiveProcess = dll.DebugActiveProcess
DebugActiveProcess.restype = ctypes.c_long

#: Reserves or commits a region of memory within the virtual address space of a specified process.
#: The function initializes the memory it allocates to zero, unless MEM_RESET is used.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890%28v=vs.85%29.aspx
VirtualAllocEx  = dll.VirtualAllocEx
VirtualAllocEx.restype = ctypes.c_ulong

#: Changes the protection on a region of committed pages in the virtual address space of a specified process.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366899%28v=vs.85%29.aspx
VirtualProtectEx = dll.VirtualProtectEx
VirtualProtectEx.restype = ctypes.c_long

#: Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682489%28v=vs.85%29.aspx
CreateToolhelp32Snapshot = dll.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.restype = ctypes.c_ulong

#: Retrieves information about the first module associated with a process.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684218%28v=vs.85%29.aspx
Module32First = dll.Module32First
Module32First.restype = ctypes.c_long

#: Retrieves information about the next module associated with a process or thread.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684221%28v=vs.85%29.aspx
Module32Next = dll.Module32Next
Module32Next.restype = ctypes.c_long

#: Retrieves information about the first process encountered in a system snapshot.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684834%28v=vs.85%29.aspx
Process32First = dll.Process32First
Process32First.restype = ctypes.c_long

#: Retrieves information about the next process recorded in a system snapshot.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684836%28v=vs.85%29.aspx
Process32Next = dll.Process32Next
Process32Next.restype = ctypes.c_long

#: Retrieves information about the first thread of any process encountered in a system snapshot.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms686728%28v=vs.85%29.aspx
Thread32First = dll.Thread32First
Thread32First.restype = ctypes.c_long

#: Retrieves information about the next thread of any process encountered in the system memory snapshot.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms686731%28v=vs.85%29.aspx
Thread32Next = dll.Thread32Next
Thread32Next.restype = ctypes.c_long

#: Opens an existing thread object.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335%28v=vs.85%29.aspx
OpenThread = dll.OpenThread
OpenThread.restype = ctypes.c_ulong

#: Suspends the specified thread.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms686345%28v=vs.85%29.aspx
SuspendThread = dll.SuspendThread
SuspendThread.restype  = ctypes.c_ulong

#: Decrements a thread's suspend count. When the suspend count is decremented to zero, the execution of the thread is resumed.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms685086%28v=vs.85%29.aspx
ResumeThread = dll.ResumeThread
ResumeThread.restype = ctypes.c_ulong

#: Retrieves the context of the specified thread.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms679362%28v=vs.85%29.aspx
GetThreadContext = dll.GetThreadContext
GetThreadContext.restype = ctypes.c_long

#: Sets the context for the specified thread.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680632%28v=vs.85%29.aspx
SetThreadContext = dll.SetThreadContext
SetThreadContext.restype = ctypes.c_long

#: Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366894%28v=vs.85%29.aspx
VirtualFreeEx = dll.VirtualFreeEx
VirtualFreeEx.restype = ctypes.c_long