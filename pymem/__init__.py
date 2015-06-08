import struct

import pyfasm

import pymem.exception
import pymem.memory
import pymem.process


class Pymem(object):
    """Initialize the Pymem class.
    If process_name is given, will open the process and retrieve a handle over it.

    :param name: The name of the process to be opened
    :type name: str
    """

    def __init__(self, process_name=None):
        self.process_id = None
        self.process_handle = None
        self.main_thread_id = None
        self.thread_handle = None

        if process_name:
            self.open_process_from_name(process_name)

    def open_process_from_name(self, process_name):
        """Open process given it's name and stores the handle into `self.process_handle`.

        :param process_name: The name of the process to be opened
        :type process_name: str
        :raises TypeError: if process_name is not valid
        :raises pymem.exception.ProcessNotFound: if process is not found
        :raises pymem.exception.CouldNotOpenProcess: if process cannot be opened
        """
        if not process_name or not isinstance(process_name, str):
            raise TypeError('Invalid argument: {}'.format(process_name))
        process32 = pymem.process.process_from_name(process_name)
        if not process32:
            raise pymem.exception.ProcessNotFound(process_name)
        self.process_id = process32.th32ProcessID
        self.open_process_from_id(self.process_id)

    def open_process_from_id(self, process_id):
        """Open process given it's name and stores the handle into `self.process_handle`.

        :param process_id: The name of the process to be opened
        :type process_id: int
        :raises TypeError: if process_id is not an integer
        :raises pymem.exception.CouldNotOpenProcess: if process cannot be opened
        """
        if not process_id or not isinstance(process_id, int):
            raise TypeError('Invalid argument: {}'.format(process_id))
        self.process_id = process_id
        self.process_handle = pymem.process.open(self.process_id)
        if not self.process_handle:
            raise pymem.exception.CouldNotOpenProcess(self.process_id)

    @property
    def process_base_address(self):
        """Lookup process base address.

        :return: The base address of the current process.
        :rtype: ctypes.wintypes.HANDLE
        :raises TypeError: if process_id is not an integer
        :raises pymem.exception.ProcessError: if could not find process first module address
        """
        if not self.process_id:
            raise TypeError('You must open a process before calling this property')
        base_address = pymem.process.base_address(self.process_id)
        if not base_address:
            raise pymem.exception.ProcessError("Could not find process first module address")
        base_address = hex(base_address)
        return base_address

    def open_main_thread(self):
        """Open process main thread name and stores the handle into `self.thread_handle`
        the thread_id is also stored into `self.main_thread_id`.

        :raises pymem.exception.ProcessError: if there is no process opened
        :raises pymem.exception.ProcessError: if could not list process thread
        """
        if not self.process_id:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        threads = pymem.process.list_process_thread(self.process_id)
        if not threads:
            raise pymem.exception.ProcessError('Could not list process thread')
        main_thread = threads[0]
        self.main_thread_id = main_thread.th32ThreadID
        self.thread_handle = pymem.process.open_thread(self.main_thread_id)
        if not self.thread_handle:
            raise pymem.exception.ProcessError('Could not open thread: {}'.format(
                self.main_thread_id
            ))

    def close_process(self):
        """Close the current opened process

        :raises pymem.exception.ProcessError: if there is no process opened
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        pymem.process.close_handle(self.process_handle)
        if self.thread_handle:
            pymem.process.close_handle(self.thread_handle)

    def allocate(self, size):
        """Allocate memory into the current opened process.

        :param size: The size of the region of memory to allocate, in bytes.
        :type size: int
        :return: The base address of the current process.
        :rtype: ctypes.wintypes.HANDLE
        :raises pymem.exception.ProcessError: if there is no process opened
        :raises TypeError: if size is not an integer
        """
        if not size or not isinstance(size, int):
            raise TypeError('Invalid argument: {}'.format(size))
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        address = pymem.memory.allocate_memory(self.process_handle, size)
        return address

    def free(self, address):
        """Free memory from the current opened process given an address.

        :param address: An address of the region of memory to be freed.
        :type address: int
        :raises pymem.exception.ProcessError: if there is no process opened
        :raises TypeError: if address is not an integer
        """
        if not address or not isinstance(address, int):
            raise TypeError('Invalid argument: {}'.format(address))
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        pymem.memory.free_memory(self.process_handle, address)

    def assemble(self, address=None, mnemonics=None):
        """Assemble mnemonics to bytes using `pyfasm`.

        If `address` is given then the origin `org` will be set to the address.

        :param address: An address of the region of memory to be freed.
        :param mnemonics: fasm syntax mnemonics
        :type address: int
        :type mnemonics: str
        :return: The assembled mnemonics
        :rtype: bytes
        """
        #XXX :raises:
        if "use32" not in mnemonics:
            mnemonics = "use32\n{}".format(mnemonics)

        if address:
            mnemonics = "org {}\n{}".format(hex(address), mnemonics)

        if type(mnemonics) == str:
            mnemonics = mnemonics.encode('ascii')

        self.mnemonics = mnemonics
        data = pyfasm.assemble(mnemonics)
        return bytes(data)

    def close_main_thread(self):
        """Close the opened main thread

        :raises pymem.exception.ProcessError: if main thread is not opened
        """
        if not self.thread_handle:
            raise pymem.exception.ProcessError('You must open main thread before calling this method')
        pymem.process.close_handle(self.thread_handle)

    def read_bytes(self, address, length):
        """Reads bytes from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :param length: number of bytes to be read
        :type address: int
        :type length: int
        :return: returns the raw value read
        :rtype: bytes
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_bytes(self.process_handle, address, length)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, length, e.error_code)
        return value

    def read_char(self, address):
        """Reads 1 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: string
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_char(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('b'), e.error_code)
        return value

    def read_uchar(self, address):
        """Reads 1 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: string
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise TypeError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_uchar(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('B'), e.error_code)
        return value

    def read_int(self, address):
        """Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_int(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('i'), e.error_code)
        return value

    def read_uint(self, address):
        """Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_uint(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('I'), e.error_code)
        return value

    def read_short(self, address):
        """Reads 2 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_short(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('h'), e.error_code)
        return value

    def read_ushort(self, address):
        """Reads 2 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_ushort(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('H'), e.error_code)
        return value

    def read_float(self, address):
        """Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_float(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('f'), e.error_code)
        return value

    def read_long(self, address):
        """Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_long(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('l'), e.error_code)
        return value

    def read_ulong(self, address):
        """Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_ulong(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('L'), e.error_code)
        return value

    def read_longlong(self, address):
        """Reads 8 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_longlong(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('q'), e.error_code)
        return value

    def read_ulonglong(self, address):
        """Reads 8 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_ulonglong(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('Q'), e.error_code)
        return value

    def read_double(self, address):
        """Reads 8 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_double(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('d'), e.error_code)
        return value

    def read_string(self, address, byte=50):
        """Reads n `byte` from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :param byte: number of bytes to read
        :type address: int
        :type byte: int
        :return: returns the value read
        :rtype: str
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if byte is not a valid integer
        :raise: pymem.exception.MemoryReadError if ReadProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if not byte or not isinstance(byte, int):
            raise TypeError('Invalid argument: {}'.format(byte))
        try:
            value = pymem.memory.read_string(self.process_handle, address, byte)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, byte, e.error_code)
        return value

    def write_int(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid integer
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_int(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_uint(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid integer
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_uint(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_short(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid integer
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_short(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_ushort(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid integer
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_ushort(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_float(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid float
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, float):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_float(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_long(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid int
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, float):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_long(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_ulong(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid int
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, float):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_ulong(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_longlong(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid int
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, float):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_longlong(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_ulonglong(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid int
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, float):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_ulonglong(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_double(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid int
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, float):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_double(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_string(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: bytes
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not bytes
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, bytes):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_string(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_char(self, address, value):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a string
        :raise: pymem.exception.MemoryWriteError if WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, str):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_char(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)