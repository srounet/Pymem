import ctypes
import struct

import pymem.exception
import pymem.ressources.kernel32
import pymem.ressources.structure


def allocate_memory(handle, size, allocation_type=None, protection_type=None):
    """Reserves or commits a region of memory within the virtual address space of a specified process.
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
    """
    if not allocation_type:
        allocation_type = pymem.ressources.structure.MemoryAllocation.MEM_COMMIT
    if not protection_type:
        protection_type = pymem.ressources.structure.MemoryProtection.PAGE_EXECUTE_READWRITE
    address = pymem.ressources.kernel32.VirtualAllocEx(handle, None, size, allocation_type, protection_type)
    return address


def free_memory(handle, address, free_type=None):
    """Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process.

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
    """
    if not free_type:
        free_type = pymem.ressources.structure.MemoryAllocation.MEM_RELEASE
    ret = pymem.ressources.kernel32.VirtualFreeEx(handle, address, 0, free_type)
    return ret


def read_bytes(handle, address, byte):
    """Reads data from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    if not isinstance(address, int):
        raise TypeError('Address must be int: {}'.format(address))
    buff = ctypes.create_string_buffer(byte)
    bytes_read = ctypes.c_ulong(0)
    pymem.ressources.kernel32.ReadProcessMemory(handle, address, buff, byte, ctypes.byref(bytes_read))
    error_code = ctypes.windll.kernel32.GetLastError()
    if error_code:
        ctypes.windll.kernel32.SetLastError(0)
        raise pymem.exception.WinAPIError(error_code)
    bytes = buff.raw
    return bytes


def read_char(handle, address):
    """Reads 1 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('b'))
    bytes = struct.unpack('<b', bytes)[0]
    return bytes


def read_uchar(handle, address):
    """Reads 1 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('B'))
    bytes = struct.unpack('<B', bytes)[0]
    return bytes


def read_short(handle, address):
    """Reads 2 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('h'))
    bytes = struct.unpack('<h', bytes)[0]
    return bytes


def read_ushort(handle, address):
    """Reads 2 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('H'))
    bytes = struct.unpack('<H', bytes)[0]
    return bytes


def read_int(handle, address):
    """Reads 4 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('i'))
    bytes = struct.unpack('<i', bytes)[0]
    return bytes


def read_uint(handle, address):
    """Reads 4 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('I'))
    bytes = struct.unpack('<I', bytes)[0]
    return bytes


def read_float(handle, address):
    """Reads 4 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('f'))
    bytes = struct.unpack('<f', bytes)[0]
    return bytes


def read_long(handle, address):
    """Reads 4 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('l'))
    bytes = struct.unpack('<l', bytes)[0]
    return bytes


def read_ulong(handle, address):
    """Reads 4 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('L'))
    bytes = struct.unpack('<L', bytes)[0]
    return bytes


def read_longlong(handle, address):
    """Reads 8 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('q'))
    bytes = struct.unpack('<q', bytes)[0]
    return bytes


def read_ulonglong(handle, address):
    """Reads 8 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('Q'))
    bytes = struct.unpack('<Q', bytes)[0]
    return bytes


def read_double(handle, address):
    """Reads 8 byte from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    bytes = read_bytes(handle, address, struct.calcsize('d'))
    bytes = struct.unpack('<d', bytes)[0]
    return bytes


def read_string(handle, address, byte=50):
    """Reads n `byte` from an area of memory in a specified process.
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
    :raise: WinAPIError if ReadProcessMemory failed
    """
    buff = read_bytes(handle, address, byte)
    i = buff.find(b'\x00')
    if i != -1:
        return buff[:i]
    return buff


def write_bytes(handle, address, src, length):
    """Writes data to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    if not isinstance(address, int):
        raise TypeError('Address must be int: {}'.format(address))
    dst = ctypes.cast(address, ctypes.c_char_p)
    ctypes.windll.kernel32.SetLastError(0)
    res = ctypes.windll.kernel32.WriteProcessMemory(handle, dst, src, length, 0x0)
    error_code = ctypes.windll.kernel32.GetLastError()
    if error_code:
        ctypes.windll.kernel32.SetLastError(0)
        raise pymem.exception.WinAPIError(error_code)
    return res

def write_char(handle, address, value):
    """Writes 1 byte to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_char(value)
    length = struct.calcsize('c')
    res = write_bytes(handle, address, src, length)
    return res


def write_short(handle, address, value):
    """Writes 2 bytes to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_short(value)
    length = struct.calcsize('h')
    res = write_bytes(handle, address, ctypes.addressof(src), length)
    return res


def write_ushort(handle, address, value):
    """Writes 2 bytes to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_ushort(value)
    length = struct.calcsize('H')
    res = write_bytes(handle, address, ctypes.addressof(src), length)
    return res


def write_int(handle, address, value):
    """Writes 4 bytes to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_int(value)
    length = struct.calcsize('i')
    res = write_bytes(handle, address, ctypes.addressof(src), length)
    return res


def write_uint(handle, address, value):
    """Writes 4 bytes to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_uint(value)
    length = struct.calcsize('I')
    res = write_bytes(handle, address, ctypes.addressof(src), length)
    return res


def write_float(handle, address, value):
    """Writes 4 bytes to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_float(value)
    length = struct.calcsize('f')
    res = write_bytes(handle, address, ctypes.addressof(src), length)
    return res


def write_long(handle, address, value):
    """Writes 4 bytes to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_long(value)
    length = struct.calcsize('l')
    res = write_bytes(handle, address, ctypes.addressof(src), length)
    return res


def write_ulong(handle, address, value):
    """Writes 4 bytes to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_ulong(value)
    length = struct.calcsize('L')
    res = write_bytes(handle, address, ctypes.addressof(src), length)
    return res


def write_longlong(handle, address, value):
    """Writes 8 bytes to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_longlong(value)
    length = struct.calcsize('q')
    res = write_bytes(handle, address, ctypes.addressof(src), length)
    return res


def write_ulonglong(handle, address, value):
    """Writes 8 bytes to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_ulonglong(value)
    length = struct.calcsize('Q')
    res = write_bytes(handle, address, ctypes.addressof(src), length)
    return res


def write_double(handle, address, value):
    """Writes 8 bytes to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_double(value)
    length = struct.calcsize('d')
    res = write_bytes(handle, address, ctypes.addressof(src), length)
    return res


def write_string(handle, address, bytecode):
    """Writes n `bytes` of len(`bytecode`) to an area of memory in a specified process.
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
    :raise: WinAPIError if WriteProcessMemory failed
    """
    src = ctypes.c_char_p(bytecode)
    length = ctypes.c_int(len(bytecode))
    res = write_bytes(handle, address, src, length)
    return res