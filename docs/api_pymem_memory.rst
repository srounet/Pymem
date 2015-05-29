Memory
======


.. function:: allocate_memory(handle, size, allocation_type=None, protection_type=None)

    Reserves or commits a region of memory within the virtual address space of a specified process.
    The function initializes the memory it allocates to zero, unless MEM_RESET is used.

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890%28v=vs.85%29.aspx

    :param handle: The handle to a process. The function allocates memory within the virtual address space of this process.
                   The handle must have the PROCESS_VM_OPERATION access right.
    :param size: The size of the region of memory to allocate, in bytes.
    :param allocation_type: The type of memory allocation.
    :param protection_type: The memory protection for the region of pages to be allocated.
    :type handle: ctypes.wintypes.HANDLE
    :type size: int
    :type allocation_type: pymem.ressources.structure.MemoryAllocation
    :type protection_type: pymem.ressources.structure.MemoryProtection
    :return: return the base address of the allocated region of pages.
    :rtype: ctypes.wintypes.HANDLE


.. function:: free_memory(handle, address, free_type=None)

    Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process.

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366894%28v=vs.85%29.aspx

    :param handle: A handle to a process. The function frees memory within the virtual address space of the process.
                   The handle must have the PROCESS_VM_OPERATION access right.
    :param address: An address of the region of memory to be freed.
    :param free_type: The type of free operation.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type free_type: pymem.ressources.structure.MemoryProtection
    :return: If the function succeeds, the return value is a nonzero value.
    :rtype: ctypes.wintypes.BOOL


.. function:: read_bytes(handle, address, byte)

    Reads data from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :param byte: number of bytes to be read
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type byte: int
    :return: If the function succeeds, returns the raw value read
    :rtype: bytes
    :raise: TypeError if address is not a valid integer


.. function:: read_char(handle, address)

    Reads 1 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<b')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: string of length 1
    :raise: TypeError if address is not a valid integer


.. function:: read_uchar(handle, address)

    Reads 1 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<B')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: int
    :raise: TypeError if address is not a valid integer


.. function:: read_short(handle, address)

    Reads 2 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<h')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: int
    :raise: TypeError if address is not a valid integer


.. function:: read_ushort(handle, address)

    Reads 2 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<H')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: int
    :raise: TypeError if address is not a valid integer


.. function:: read_int(handle, address)

    Reads 4 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<i')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: int
    :raise: TypeError if address is not a valid integer


.. function:: read_uint(handle, address)

    Reads 4 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<I')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: int
    :raise: TypeError if address is not a valid integer


.. function:: read_float(handle, address)

    Reads 4 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<f')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: float
    :raise: TypeError if address is not a valid integer


.. function:: read_long(handle, address)

    Reads 4 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<l')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: int
    :raise: TypeError if address is not a valid integer


.. function:: read_ulong(handle, address)

    Reads 4 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<L')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: int
    :raise: TypeError if address is not a valid integer


.. function:: read_longlong(handle, address)

    Reads 8 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<q')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: int
    :raise: TypeError if address is not a valid integer


.. function:: read_ulonglong(handle, address)

    Reads 8 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<Q')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: int
    :raise: TypeError if address is not a valid integer
    
    bytes = read_bytes(handle, address, struct.calcsize('Q'))
    bytes = struct.unpack('<Q', bytes)[0]
    return bytes


.. function:: read_double(handle, address)

    Reads 8 byte from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    Unpack the value using struct.unpack('<d')

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: float
    :raise: TypeError if address is not a valid integer


.. function:: read_string(handle, address, byte=50)

    Reads n `byte` from an area of memory in a specified process.
    The entire area to be read must be accessible or the operation fails.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx

    :param handle: A handle to the process with memory that is being read.
                   The handle must have PROCESS_VM_READ access to the process.
    :param address: An address of the region of memory to be freed.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :return: If the function succeeds, returns the value read
    :rtype: str
    :raise: TypeError if address is not a valid integer


.. function:: write_bytes(handle, address, src, length)

    Writes data to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Casts address using ctypes.c_char_p.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param src: A buffer that contains data to be written in the address space of the specified process.
    :param length: The number of bytes to be written to the specified process.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type src: int
    :type length: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer

.. function:: write_char(handle, address, value)

    Writes 1 byte to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_char(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_short(handle, address, value)

    Writes 2 bytes to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_short(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_ushort(handle, address, value)

    Writes 2 bytes to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_ushort(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_int(handle, address, value)

    Writes 4 bytes to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_int(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_uint(handle, address, value)

    Writes 4 bytes to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_uint(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_float(handle, address, value)

    Writes 4 bytes to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_float(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: float
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_long(handle, address, value)

    Writes 4 bytes to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_long(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_ulong(handle, address, value)

    Writes 4 bytes to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_ulong(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_longlong(handle, address, value)

    Writes 8 bytes to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_longlong(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_ulonglong(handle, address, value)

    Writes 8 bytes to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_ulonglong(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_double(handle, address, value)

    Writes 8 bytes to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms value using: ctypes.c_double(`value`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param value: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type value: int
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer


.. function:: write_string(handle, address, bytecode)

    Writes n `bytes` of len(`bytecode`) to an area of memory in a specified process.
    The entire area to be written to must be accessible or the operation fails.

    Transforms bytecode using: ctypes.c_char_p(`bytecode`).

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx

    :param handle: A handle to the process memory to be modified.
                   The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
    :param address: An address in the specified process to which data is written.
    :param bytecode: The data to be written.
    :type handle: ctypes.wintypes.HANDLE
    :type address: int
    :type bytecode: str
    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    :raise: TypeError if address is not a valid integer