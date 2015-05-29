Structure
=========

Placeholder for windows structures and constants.

.. py:class:: ModuleEntry32(ctypes.Structure)

    Describes an entry from a list of the modules belonging to the specified process.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684225%28v=vs.85%29.aspx

    .. code-block:: python

        _fields_ = [
            ( 'dwSize' , ctypes.c_ulong ) ,
            ( 'th32ModuleID' , ctypes.c_ulong ),
            ( 'th32ProcessID' , ctypes.c_ulong ),
            ( 'GlblcntUsage' , ctypes.c_ulong ),
            ( 'ProccntUsage' , ctypes.c_ulong ) ,
            ( 'modBaseAddr' , ctypes.POINTER(ctypes.c_byte)),
            ( 'modBaseSize' , ctypes.c_ulong ) ,
            ( 'hModule' , ctypes.c_ulong ) ,
            ( 'szModule' , ctypes.c_char * 256 ),
            ( 'szExePath' , ctypes.c_char * 260 )
        ]

.. py:class:: ProcessEntry32(ctypes.Structure)

    Describes an entry from a list of the processes residing in the system address space when a snapshot was taken.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684839(v=vs.85).aspx

    .. code-block:: python

        _fields_ = [
            ( 'dwSize' , ctypes.c_ulong ) ,
            ( 'cntUsage' , ctypes.c_ulong) ,
            ( 'th32ProcessID' , ctypes.c_ulong) ,
            ( 'th32DefaultHeapID' , ctypes.POINTER(ctypes.c_ulong) ) ,
            ( 'th32ModuleID' , ctypes.c_ulong) ,
            ( 'cntThreads' , ctypes.c_ulong) ,
            ( 'th32ParentProcessID' , ctypes.c_ulong) ,
            ( 'pcPriClassBase' , ctypes.c_long) ,
            ( 'dwFlags' , ctypes.c_ulong) ,
            ( 'szExeFile' , ctypes.c_char * 260 )
        ]

    .. py:attribute:: szExeFile

        :return: The szExeFile as a decoded utf-8 string
        :rtype: string


.. py:class:: ThreadEntry32(ctypes.Structure)

    Describes an entry from a list of the threads executing in the system when a snapshot was taken.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686735(v=vs.85).aspx

    .. code-block:: python

        _fields_ = [
            ('dwSize', ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ThreadID", ctypes.c_ulong),
            ("th32OwnerProcessID", ctypes.c_ulong),
            ("tpBasePri", ctypes.c_ulong),
            ("tpDeltaPri", ctypes.c_ulong),
            ("dwFlags", ctypes.c_ulong)
        ]


.. py:class:: PROCESS(object):

    Process manipulation flags


    .. py:attribute:: PROCESS_CREATE_PROCESS = 0x0080

        Required to create a process.

    .. py:attribute:: PROCESS_CREATE_THREAD = 0x0002

        Required to create a thread.

    .. py:attribute:: PROCESS_DUP_HANDLE = 0x0040

        Required to duplicate a handle using DuplicateHandle.

    .. py:attribute:: PROCESS_QUERY_INFORMATION = 0x0400

        Required to retrieve certain information about a process, such as its token, exit code, and priority class (see OpenProcessToken).

    .. py:attribute:: PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

        Required to retrieve certain information about a process (see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName).

    .. py:attribute:: PROCESS_SET_INFORMATION = 0x0200

        Required to set certain information about a process, such as its priority class (see SetPriorityClass).
    .. py:attribute:: PROCESS_SET_QUOTA = 0x0100

        Required to set memory limits using SetProcessWorkingSetSize.

    .. py:attribute:: PROCESS_SUSPEND_RESUME = 0x0800

        Required to suspend or resume a process.

    .. py:attribute:: PROCESS_TERMINATE = 0x0001

        Required to terminate a process using TerminateProcess.

    .. py:attribute:: PROCESS_VM_OPERATION = 0x0008

        Required to perform an operation on the address space of a process (see VirtualProtectEx and WriteProcessMemory).

    .. py:attribute:: PROCESS_VM_READ = 0x0010

        Required to read memory in a process using ReadProcessMemory.

    .. py:attribute:: PROCESS_VM_WRITE = 0x0020

        Required to write to memory in a process using WriteProcessMemory.

    .. py:attribute:: SYNCHRONIZE = 0x00100000

        Required to wait for the process to terminate using the wait functions.

    .. py:attribute:: PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

        All possible access rights for a process object.

    .. py:attribute:: DELETE = 0x00010000

        Required to delete the object.

    .. py:attribute:: READ_CONTROL = 0x00020000

        Required to read information in the security descriptor for the object, not including the information in the SACL. To read or write the SACL, you must request the ACCESS_SYSTEM_SECURITY access right. For more information, see SACL Access Right.

    .. py:attribute:: WRITE_DAC = 0x00040000

        Required to modify the DACL in the security descriptor for the object.

    .. py:attribute:: WRITE_OWNER = 0x00080000

        Required to change the owner in the security descriptor for the object.


.. py:class:: MemoryAllocation(object)

    The type of memory allocation
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890%28v=vs.85%29.aspx

    .. py:attribute:: MEM_COMMIT = 0x00001000

        Allocates memory charges (from the overall size of memory and the paging files on disk) for the specified reserved memory pages. The function also guarantees that when the caller later initially accesses the memory, the contents will be zero. Actual physical pages are not allocated unless/until the virtual addresses are actually accessed.

    .. py:attribute:: MEM_RESERVE = 0x00002000

        Reserves a range of the process's virtual address space without allocating any actual physical storage in memory or in the paging file on disk.

    .. py:attribute:: MEM_RESET = 0x00080000

        Indicates that data in the memory range specified by lpAddress and dwSize is no longer of interest. The pages should not be read from or written to the paging file. However, the memory block will be used again later, so it should not be decommitted. This value cannot be used with any other value.

    .. py:attribute:: MEM_RESET_UNDO = 0x1000000

        MEM_RESET_UNDO should only be called on an address range to which MEM_RESET was successfully applied earlier. It indicates that the data in the specified memory range specified by lpAddress and dwSize is of interest to the caller and attempts to reverse the effects of MEM_RESET. If the function succeeds, that means all data in the specified address range is intact. If the function fails, at least some of the data in the address range has been replaced with zeroes.

    .. py:attribute:: MEM_LARGE_PAGES = 0x20000000

        Allocates memory using large page support.

    .. py:attribute:: MEM_PHYSICAL = 0x00400000

        Reserves an address range that can be used to map Address Windowing Extensions (AWE) pages.

    .. py:attribute:: MEM_TOP_DOWN = 0x00100000

        Allocates memory at the highest possible address. This can be slower than regular allocations, especially when there are many allocations.

    .. py:attribute:: MEM_DECOMMIT = 0x4000

        Decommits the specified region of committed pages. After the operation, the pages are in the reserved state.

    .. py:attribute:: MEM_RELEASE = 0x8000

        Releases the specified region of pages. After this operation, the pages are in the free state.

.. py:class:: MemoryProtection(object)

    The following are the memory-protection options;
    you must specify one of the following values when allocating or protecting a page in memory

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx

    .. py:attribute:: PAGE_EXECUTE = 0x10

        Enables execute access to the committed region of pages. An attempt to write to the committed region results in an access violation.

    .. py:attribute:: PAGE_EXECUTE_READ = 0x20

        Enables execute or read-only access to the committed region of pages. An attempt to write to the committed region results in an access violation.

    .. py:attribute:: PAGE_EXECUTE_READWRITE = 0x40

        Enables execute, read-only, or read/write access to the committed region of pages.

    .. py:attribute:: PAGE_EXECUTE_WRITECOPY = 0x80

        Enables execute, read-only, or copy-on-write access to a mapped view of a file mapping object. An attempt to write to a committed copy-on-write page results in a private copy of the page being made for the process. The private page is marked as PAGE_EXECUTE_READWRITE, and the change is written to the new page.

    .. py:attribute:: PAGE_NOACCESS = 0x01

        Disables all access to the committed region of pages. An attempt to read from, write to, or execute the committed region results in an access violation.

    .. py:attribute:: PAGE_READONLY = 0x02

        Enables read-only access to the committed region of pages. An attempt to write to the committed region results in an access violation. If Data Execution Prevention is enabled, an attempt to execute code in the committed region results in an access violation.

    .. py:attribute:: PAGE_READWRITE = 0x04

        Enables read-only or read/write access to the committed region of pages. If Data Execution Prevention is enabled, attempting to execute code in the committed region results in an access violation.

    .. py:attribute:: PAGE_WRITECOPY = 0x08

        Enables read-only or copy-on-write access to a mapped view of a file mapping object. An attempt to write to a committed copy-on-write page results in a private copy of the page being made for the process. The private page is marked as PAGE_READWRITE, and the change is written to the new page. If Data Execution Prevention is enabled, attempting to execute code in the committed region results in an access violation.

    .. py:attribute:: PAGE_GUARD = 0x100

        Pages in the region become guard pages. Any attempt to access a guard page causes the system to raise a STATUS_GUARD_PAGE_VIOLATION exception and turn off the guard page status. Guard pages thus act as a one-time access alarm. For more information, see Creating Guard Pages.

    .. py:attribute:: PAGE_NOCACHE = 0x200

        Sets all pages to be non-cachable. Applications should not use this attribute except when explicitly required for a device. Using the interlocked functions with memory that is mapped with SEC_NOCACHE can result in an EXCEPTION_ILLEGAL_INSTRUCTION exception.

    .. py:attribute:: PAGE_WRITECOMBINE = 0x400

        Sets all pages to be write-combined.
        Applications should not use this attribute except when explicitly required for a device. Using the interlocked functions with memory that is mapped as write-combined can result in an EXCEPTION_ILLEGAL_INSTRUCTION exception.


.. py:attribute:: SIZE_OF_80387_REGISTERS = 80
.. py:class:: FLOATING_SAVE_AREA(ctypes.Structure)

    Undocumented ctypes.Structure used for ThreadContext.

    .. code-block:: python

        _fields_ = [
            ('ControlWord', ctypes.c_uint),
            ('StatusWord', ctypes.c_uint),
            ('TagWord', ctypes.c_uint),
            ('ErrorOffset', ctypes.c_uint),
            ('ErrorSelector', ctypes.c_uint),
            ('DataOffset', ctypes.c_uint),
            ('DataSelector', ctypes.c_uint),
            ('RegisterArea', ctypes.c_byte * SIZE_OF_80387_REGISTERS),
            ('Cr0NpxState', ctypes.c_uint)
        ]

.. py:attribute:: MAXIMUM_SUPPORTED_EXTENSION = 512
.. py:class:: ThreadContext(ctypes.Structure)

    Represents a thread context

    .. code-block:: python

        _fields_ = [
            ('ContextFlags', ctypes.c_uint),
            ('Dr0', ctypes.c_uint),
            ('Dr1', ctypes.c_uint),
            ('Dr2', ctypes.c_uint),
            ('Dr3', ctypes.c_uint),
            ('Dr6', ctypes.c_uint),
            ('Dr7', ctypes.c_uint),
            ('FloatSave', FLOATING_SAVE_AREA),
            ('SegGs', ctypes.c_uint),
            ('SegFs', ctypes.c_uint),
            ('SegEs', ctypes.c_uint),
            ('SegDs', ctypes.c_uint),
            ('Edi', ctypes.c_uint),
            ('Esi', ctypes.c_uint),
            ('Ebx', ctypes.c_uint),
            ('Edx', ctypes.c_uint),
            ('Ecx', ctypes.c_uint),
            ('Eax', ctypes.c_uint),
            ('Ebp', ctypes.c_uint),
            ('Eip', ctypes.c_uint),
            ('SegCs', ctypes.c_uint),
            ('EFlags', ctypes.c_uint),
            ('Esp', ctypes.c_uint),
            ('SegSs', ctypes.c_uint),
            ('ExtendedRegisters', ctypes.c_byte * MAXIMUM_SUPPORTED_EXTENSION)
        ]