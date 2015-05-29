Kernel32
========

.. py:function:: OpenProcess

    Opens an existing local process object.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320%28v=vs.85%29.aspx

    :param dwDesiredAccess: The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the process access rights.
    :param bInheritHandle: If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
    :param dwProcessId: The identifier of the local process to be opened.
    :type dwDesiredAccess: DWORD
    :type bInheritHandle: BOOL
    :type dwProcessId: DWORD
    :rtype: ctypes.c_ulong


.. py:function:: TerminateProcess

    Terminates the specified process and all of its threads.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686714%28v=vs.85%29.aspx

    :param hProcess: A handle to the process to be terminated.
    :param uExitCode: The exit code to be used by the process and threads terminated as a result of this call.
    :type hProcess: HANDLE
    :type uExitCode: UINT
    :rtype: ctypes.c_ulong


.. py:function:: CloseHandle

    Closes an open object handle.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211%28v=vs.85%29.aspx

    :param hObject: A valid handle to an open object.
    :type hObject: HANDLE
    :rtype: ctypes.c_long


.. py:function:: GetLastError

    Retrieves the calling thread's last-error code value. The last-error code is maintained on a per-thread basis.
    Multiple threads do not overwrite each other's last-error code.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms679360%28v=vs.85%29.aspx

    :rtype: ctypes.c_ulong


.. py:function:: GetCurrentProcess

    Retrieves a pseudo handle for the current process.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms683179%28v=vs.85%29.aspx

    :rtype: ctypes.c_ulong


.. py:function:: ReadProcessMemory

    Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param hProcess: A handle to the process with memory that is being read. The handle must have PROCESS_VM_READ access to the process.
    :param lpBaseAddress: A pointer to the base address in the specified process from which to read.
    :param lpBuffer: A pointer to a buffer that receives the contents from the address space of the specified process.
    :param nSize: The number of bytes to be read from the specified process.
    :param lpNumberOfBytesRead: A pointer to a variable that receives the number of bytes transferred into the specified buffer.
    :type hObject: HANDLE
    :type hObject: LPCVOID
    :type hObject: LPVOID
    :type hObject: SIZE_T
    :type hObject: SIZE_T
    :rtype: ctypes.c_long


.. py:function:: WriteProcessMemory

    Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320%28v=vs.85%29.aspx

    :param dwDesiredAccess: A handle to the process with memory that is being read. The handle must have PROCESS_VM_READ access to the process.
    :param bInheritHandle: A pointer to the base address in the specified process from which to read.
    :param dwProcessId: A pointer to a buffer that receives the contents from the address space of the specified process.
    :type dwDesiredAccess: DWORD
    :type bInheritHandle: BOOL
    :type dwProcessId: DWORD
    :rtype: ctypes.c_long


.. py:function:: DebugActiveProcess

    Enables a debugger to attach to an active process and debug it.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms679295%28v=vs.85%29.aspx

    :param dwProcessId: The identifier for the process to be debugged. The debugger is granted debugging access to the process as if it created the process with the DEBUG_ONLY_THIS_PROCESS flag. For more information, see the Remarks section of this topic.
    :type dwProcessId: DWORD
    :rtype: ctypes.c_long


.. py:function:: VirtualAllocEx

    Reserves or commits a region of memory within the virtual address space of a specified process.
    The function initializes the memory it allocates to zero, unless MEM_RESET is used.

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890%28v=vs.85%29.aspx

    :param hProcess: The handle to a process. The function allocates memory within the virtual address space of this process.
    :param lpAddress: The pointer that specifies a desired starting address for the region of pages that you want to allocate.
    :param dwSize: The size of the region of memory to allocate, in bytes.
    :param flAllocationType: The type of memory allocation.
    :param flProtect: The identifier for the process to be debugged. The debugger is granted debugging access to the process as if it created the process with the DEBUG_ONLY_THIS_PROCESS flag.
    :type hProcess: HANDLE
    :type lpAddress: LPVOID
    :type dwSize: SIZE_T
    :type flAllocationType: DWORD
    :type flProtect: DWORD
    :rtype: ctypes.c_ulong


.. py:function:: VirtualProtectEx

    Changes the protection on a region of committed pages in the virtual address space of a specified process.

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366899%28v=vs.85%29.aspx

    :param hProcess: A handle to the process whose memory protection is to be changed. The handle must have the PROCESS_VM_OPERATION access right.
    :param lpAddress: A pointer to the base address of the region of pages whose access protection attributes are to be changed.
    :param dwSize: The size of the region whose access protection attributes are changed, in bytes.
    :param flNewProtect: The memory protection option. This parameter can be one of the memory protection constants.
    :param lpflOldProtect: The handle to a process. The function allocates memory within the virtual address space of this process.
    :type flAllocationType: HANDLE
    :type lpAddress: LPVOID
    :type dwSize: SIZE_T
    :type flNewProtect: DWORD
    :type lpflOldProtect: PDWORD
    :rtype: ctypes.c_long


.. py:function:: CreateToolhelp32Snapshot

    Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms682489%28v=vs.85%29.aspx

    :param dwFlags: The portions of the system to be included in the snapshot.
    :param th32ProcessID: The process identifier of the process to be included in the snapshot. This parameter can be zero to indicate the current process. This parameter is used when the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, or TH32CS_SNAPALL value is specified. Otherwise, it is ignored and all processes are included in the snapshot.
    :type dwFlags: DWORD
    :type th32ProcessID: DWORD
    :rtype: ctypes.c_ulong


.. py:function:: Module32First

    Retrieves information about the first module associated with a process.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684218%28v=vs.85%29.aspx

    :param hSnapshot: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
    :param lpme: A pointer to a MODULEENTRY32 structure.
    :type hSnapshot: HANDLE
    :type lpme: LPMODULEENTRY32
    :rtype: ctypes.c_long


.. py:function:: Module32Next

    Retrieves information about the next module associated with a process or thread.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684221%28v=vs.85%29.aspx

    :param hSnapshot: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
    :param lpme: A pointer to a MODULEENTRY32 structure.
    :type hSnapshot: HANDLE
    :type lpme: LPMODULEENTRY32
    :rtype: ctypes.c_long


.. py:function:: Process32First

    Retrieves information about the first process encountered in a system snapshot.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684834%28v=vs.85%29.aspx

    :param hSnapshot: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
    :param lppe: A pointer to a PROCESSENTRY32 structure. It contains process information such as the name of the executable file, the process identifier, and the process identifier of the parent process.
    :type hSnapshot: HANDLE
    :type lppe: LPPROCESSENTRY32
    :rtype: ctypes.c_long


.. py:function:: Process32Next

    Retrieves information about the next process recorded in a system snapshot.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684836%28v=vs.85%29.aspx

    :param hSnapshot: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
    :param lppe: A pointer to a PROCESSENTRY32 structure.
    :type hSnapshot: HANDLE
    :type lppe: LPPROCESSENTRY32

    :rtype: ctypes.c_long


.. py:function:: Thread32First

    Retrieves information about the first thread of any process encountered in a system snapshot.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686728%28v=vs.85%29.aspx

    :param hSnapshot: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
    :param lpte: A pointer to a THREADENTRY32 structure.
    :type hSnapshot: HANDLE
    :type lpte: LPTHREADENTRY32
    :rtype: ctypes.c_long


.. py:function:: Thread32Next

    Retrieves information about the next thread of any process encountered in the system memory snapshot.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686731%28v=vs.85%29.aspx

    :param hSnapshot: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
    :param lpte: A pointer to a THREADENTRY32 structure.
    :type hSnapshot: HANDLE
    :type lpte: LPTHREADENTRY32
    :rtype: ctypes.c_long


.. py:function:: OpenThread

    Opens an existing thread object.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335%28v=vs.85%29.aspx

    :param dwDesiredAccess: The access to the thread object. This access right is checked against the security descriptor for the thread. This parameter can be one or more of the thread access rights.
    :param bInheritHandle: If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
    :param dwThreadId: The identifier of the thread to be opened.
    :type dwDesiredAccess: DWORD
    :type bInheritHandle: BOOL
    :type dwThreadId: DWORD
    :rtype: ctypes.c_ulong


.. py:function:: SuspendThread

    Suspends the specified thread.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686345%28v=vs.85%29.aspx

    :param hThread: A handle to the thread that is to be suspended.
    :type hThread: HANDLE
    :rtype: ctypes.c_ulong


.. py:function:: ResumeThread

    Decrements a thread's suspend count. When the suspend count is decremented to zero, the execution of the thread is resumed.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms685086%28v=vs.85%29.aspx

    :param hThread: A handle to the thread that is to be suspended.
    :type hThread: HANDLE
    :rtype: ctypes.c_ulong


.. py:function:: GetThreadContext

    Retrieves the context of the specified thread.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms679362%28v=vs.85%29.aspx

    :param hThread: A handle to the thread whose context is to be retrieved. The handle must have THREAD_GET_CONTEXT access to the thread.
    :param lpContext: A pointer to a CONTEXT structure that receives the appropriate context of the specified thread.
    :type hThread: HANDLE
    :type lpContext: LPCONTEXT
    :rtype: ctypes.c_long


.. py:function:: SetThreadContext

    Sets the context for the specified thread.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680632%28v=vs.85%29.aspx

    :param hThread: A handle to the thread whose context is to be set. The handle must have the THREAD_SET_CONTEXT access right to the thread.
    :param lpContext: A pointer to a CONTEXT structure that contains the context to be set in the specified thread.
    :type hThread: HANDLE
    :type lpContext: CONTEXT
    :rtype: ctypes.c_long


.. py:function:: VirtualFreeEx

    Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process.

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366894%28v=vs.85%29.aspx

    :param hProcess: A handle to a process. The function frees memory within the virtual address space of the process.
    :param lpAddress: A pointer to the starting address of the region of memory to be freed.
    :param dwSize: The size of the region of memory to free, in bytes.
    :param dwFreeType: The type of free operation.
    :type hProcess: HANDLE
    :type lpAddress: LPVOID
    :type dwSize: SIZE_T
    :type dwFreeType: DWORD
    :rtype: ctypes.c_long