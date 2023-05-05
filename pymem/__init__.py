import ctypes
import ctypes.util
import functools
import logging
import platform
import struct
import sys
import typing

import pymem.exception
import pymem.memory
import pymem.process
import pymem.ressources.kernel32
import pymem.ressources.structure
import pymem.ressources.psapi
import pymem.thread
import pymem.pattern


# Configure pymem's handler to the lowest level possible so everything is cached and could be later displayed
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.NullHandler())


class Pymem(object):
    def __init__(
        self,
        process_name: typing.Union[str, int] = None,
        exact_match: bool = False,
        ignore_case: bool = True,
    ):
        """Initialize the Pymem class.
        If process_name is given, will open the process and retrieve a handle over it.

        :param process_name: The name or process id of the process to be opened
        :param exact_match: Defaults to False, is the full name match or just part of it expected?
        :param ignore_case: Default to True, should ignore process name case?
        """
        self.process_id = None
        self.process_handle = None
        self.thread_handle = None
        self.is_WoW64 = None
        self.py_run_simple_string = None
        self._python_injected = None

        if process_name is not None:
            if isinstance(process_name, str):
                self.open_process_from_name(process_name, exact_match, ignore_case)
            elif isinstance(process_name, int):
                self.open_process_from_id(process_name)
            else:
                raise TypeError(
                    f"process_name must be of type int or string not {type(process_name).__name__}"
                )

        self.check_wow64()

    def check_wow64(self):
        """Check if a process is running under WoW64."""
        self.is_WoW64 = pymem.process.is_64_bit(self.process_handle)

    def list_modules(self) -> typing.Generator['pymem.ressources.structure.MODULEINFO', None, None]:
        """List a process loaded modules.

        :return: List of process loaded modules
        """
        modules = pymem.process.enum_process_module(self.process_handle)
        return modules

    def inject_python_interpreter(self, initsigs: int = 1):
        """Inject python interpreter into target process and call Py_InitializeEx.

        :param initsigs:
        """

        def find_existing_interpreter(_python_version):
            _local_handle = pymem.ressources.kernel32.GetModuleHandleW(_python_version)
            module = pymem.process.module_from_name(self.process_handle, _python_version)

            self.py_run_simple_string = (
                module.lpBaseOfDll + (
                    pymem.ressources.kernel32.GetProcAddress(_local_handle, b'PyRun_SimpleString') - _local_handle
                )
            )
            self._python_injected = True
            pymem.logger.debug('PyRun_SimpleString loc: 0x%08x' % self.py_run_simple_string)
            return module.lpBaseOfDll

        if self._python_injected:
            return

        # find the python library
        python_version = "python{0}{1}.dll".format(sys.version_info.major, sys.version_info.minor)
        python_lib = pymem.process.get_python_dll(python_version)
        if not python_lib:
            raise pymem.exception.PymemError('Could not find python library')

        # Find or inject python module
        python_module = pymem.process.module_from_name(self.process_handle, python_version)
        if python_module:
            python_lib_h = find_existing_interpreter(python_version)
        else:
            python_lib_h = pymem.process.inject_dll(self.process_handle, bytes(python_lib, 'ascii'))
            if not python_lib_h:
                raise pymem.exception.PymemError('Inject dll failed')

        local_handle = pymem.ressources.kernel32.GetModuleHandleW(python_version)
        py_initialize_ex = (
            python_lib_h + (
                pymem.ressources.kernel32.GetProcAddress(local_handle, b'Py_InitializeEx') - local_handle
            )
        )
        self.py_run_simple_string = (
            python_lib_h + (
                pymem.ressources.kernel32.GetProcAddress(local_handle, b'PyRun_SimpleString') - local_handle
            )
        )
        if not py_initialize_ex:
            raise pymem.exception.PymemError('Empty py_initialize_ex')
        if not self.py_run_simple_string:
            raise pymem.exception.PymemError('Empty py_run_simple_string')

        param_addr = self.allocate(4)
        self.write_int(param_addr, initsigs)
        self.start_thread(py_initialize_ex, param_addr)
        self._python_injected = True

        pymem.logger.debug('Py_InitializeEx loc: 0x%08x' % py_initialize_ex)
        pymem.logger.debug('PyRun_SimpleString loc: 0x%08x' % self.py_run_simple_string)

    def inject_python_shellcode(self, shellcode: str):
        """Inject a python shellcode into memory and execute it.

        :param shellcode: A string with python instructions.
        """
        shellcode = shellcode.encode('ascii')
        shellcode_addr = pymem.ressources.kernel32.VirtualAllocEx(
            self.process_handle,
            None,
            len(shellcode),
            pymem.ressources.structure.MEMORY_STATE.MEM_COMMIT.value | pymem.ressources.structure.MEMORY_STATE.MEM_RESERVE.value,
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE.value
        )
        if not shellcode_addr or ctypes.get_last_error():
            raise RuntimeError('Could not allocate memory for shellcode')
        pymem.logger.debug('shellcode_addr loc: 0x%08x' % shellcode_addr)
        written = ctypes.c_ulonglong(0) if '64bit' in platform.architecture() else ctypes.c_ulong(0)
        pymem.ressources.kernel32.WriteProcessMemory(
            self.process_handle,
            shellcode_addr,
            shellcode,
            len(shellcode),
            ctypes.byref(written)
        )
        # check written
        self.start_thread(self.py_run_simple_string, shellcode_addr)

    def start_thread(self, address: int, params: typing.Optional[int] = None) -> int:
        """Create a new thread within the current debugged process.

        :param address: An address from where the thread starts
        :param params: An optional address with thread parameters
        :return: The new thread identifier
        """

        params = params or 0
        NULL_SECURITY_ATTRIBUTES = ctypes.cast(0, pymem.ressources.structure.LPSECURITY_ATTRIBUTES)
        thread_h = pymem.ressources.kernel32.CreateRemoteThread(
            self.process_handle,
            NULL_SECURITY_ATTRIBUTES,
            0,
            address,
            params,
            0,
            ctypes.byref(ctypes.c_ulong(0))
        )
        last_error = ctypes.windll.kernel32.GetLastError()
        if last_error:
            pymem.logger.warning('Got an error in start thread, code: %s' % last_error)
        pymem.ressources.kernel32.WaitForSingleObject(thread_h, -1)
        pymem.logger.debug('New thread_id: 0x%08x' % thread_h)
        return thread_h

    def open_process_from_name(self, process_name: str, exact_match: bool = False, ignore_case: bool = True):
        """Open process given its name and stores the handle into process_handle

        :param process_name: The name of the process to be opened
        :param exact_match: Defaults to False, is the full name match or just part of it expected?
        :param ignore_case: Default to True, should ignore process name case?

        :raises TypeError: If process name is not valid or search parameters are of the wrong type
        :raises ProcessNotFound: If process name is not found
        :raises CouldNotOpenProcess: If process cannot be opened
        """

        if not process_name or not isinstance(process_name, str):
            raise TypeError('Invalid argument: {}'.format(process_name))

        if not isinstance(exact_match, bool):
            raise TypeError('Invalid argument: {}'.format(exact_match))

        if not isinstance(ignore_case, bool):
            raise TypeError('Invalid argument: {}'.format(ignore_case))

        process32 = pymem.process.process_from_name(
            process_name,
            exact_match,
            ignore_case,
        )

        if not process32:
            raise pymem.exception.ProcessNotFound(process_name)
        self.process_id = process32.th32ProcessID
        self.open_process_from_id(self.process_id)

    def open_process_from_id(self, process_id: int):
        """Open process given its name and stores the handle into `self.process_handle`.

        :param process_id: The unique process identifier
        :raises TypeError: If process identifier is not an integer
        :raises CouldNotOpenProcess: If process cannot be opened
        """
        if not process_id or not isinstance(process_id, int):
            raise TypeError('Invalid argument: {}'.format(process_id))
        self.process_id = process_id
        self.process_handle = pymem.process.open(self.process_id)
        if not self.process_handle:
            raise pymem.exception.CouldNotOpenProcess(self.process_id)
        pymem.logger.debug('Process {} is being debugged'.format(
            process_id
        ))

    def close_process(self):
        """Close the current opened process

        :raises ProcessError: If there is no process opened
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        pymem.process.close_handle(self.process_handle)
        self.process_handle = None
        self.process_id = None
        self.is_WoW64 = None
        self.py_run_simple_string = None
        self._python_injected = None
        if self.thread_handle:
            pymem.process.close_handle(self.thread_handle)

    def allocate(self, size: int) -> int:
        """Allocate memory into the current opened process.

        :param size: The size of the region of memory to allocate, in bytes.
        :raises ProcessError: If there is no process opened
        :raises TypeError: If size is not an integer
        :return: The base address of the current process.
        """
        if not size or not isinstance(size, int):
            raise TypeError('Invalid argument: {}'.format(size))
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        address = pymem.memory.allocate_memory(self.process_handle, size)
        return address

    def free(self, address: int) -> bool:
        """Free memory from the current opened process given an address.

        :param address: An address of the region of memory to be freed.
        :raises ProcessError: If there is no process opened
        :raises TypeError: If address is not an integer
        :return: A boolean indicating memory address has been successfully freed
        """
        if not address or not isinstance(address, int):
            raise TypeError('Invalid argument: {}'.format(address))
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        return pymem.memory.free_memory(self.process_handle, address)

    def pattern_scan_all(
            self, pattern: bytes, *, return_multiple: bool = False) -> typing.Optional[typing.Union[int, list]]:
        """Scan the entire address space of this process for a regex pattern

        :param pattern: The regex pattern to search for
        :param return_multiple: If multiple results should be returned
        :return: Memory address of given pattern, or None if one was not found or a list of found addresses
                 if return_multiple is True
        """
        return pymem.pattern.pattern_scan_all(self.process_handle, pattern, return_multiple=return_multiple)

    def pattern_scan_module(
            self, pattern: bytes,
            module: typing.Union[str, pymem.ressources.structure.MODULEINFO],
            *, return_multiple: bool = False) -> typing.Optional[typing.Union[int, list]]:
        """Scan a module for a regex pattern

        :param pattern: The regex pattern to search for
        :param module: Name of the module to search for, or a MODULEINFO object
        :param return_multiple: If multiple results should be returned
        :return: Memory address of given pattern, or None if one was not found or a list of found addresses
                 if return_multiple is True
        """
        if isinstance(module, str):
            module = pymem.process.module_from_name(self.process_handle, module)

        return pymem.pattern.pattern_scan_module(
            self.process_handle,
            module,
            pattern,
            return_multiple=return_multiple
        )

    @property
    def process_base(self) -> pymem.ressources.structure.MODULEINFO:
        """Lookup process base Module.

        :raises TypeError: process_id is not an integer
        :raises ProcessError: Could not find process first module address
        :return: Base module information
        """
        if not self.process_id:
            raise TypeError('You must open a process before calling this property')
        base_module = pymem.process.base_module(self.process_handle)
        if not base_module:
            raise pymem.exception.ProcessError("Could not find process first module")
        return base_module

    @property
    def base_address(self) -> int:
        """Gets the memory address where the main module was loaded (ie address of exe file in memory)

        :raises TypeError: If process_id is not an integer
        :raises ProcessError: Could not find process first module address.
        :return: Address of main module extracted from process base MODULEINFO
        """
        return self.process_base.lpBaseOfDll

    @property
    @functools.lru_cache(maxsize=1)
    def main_thread(self) -> pymem.thread.Thread:
        """Retrieve ThreadEntry32 of main thread given its creation time.

        :raises ProcessError: If there is no process opened or could not list process thread
        :return: Process main thread
        """
        if not self.process_id:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        threads = pymem.process.enum_process_thread(self.process_id)
        threads = sorted(threads, key=lambda k: k.creation_time)

        if not threads:
            raise pymem.exception.ProcessError('Could not list process thread')

        main_thread = threads[0]
        main_thread = pymem.thread.Thread(self.process_handle, main_thread)
        return main_thread

    @property
    @functools.lru_cache(maxsize=1)
    def main_thread_id(self) -> int:
        """Retrieve th32ThreadID from main thread

        :raises ProcessError: If there is no process opened or could not list process thread
        :return: Main thread identifier
        """
        if not self.process_id:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        return self.main_thread.thread_id

    def read_bytes(self, address: int, length: int) -> bytes:
        """Reads bytes from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :param length: Number of bytes to be read
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: If ReadProcessMemory failed
        :return: the raw value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_bytes(self.process_handle, address, length)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, length, e.error_code)
        return value

    def read_ctype(self, address: int, ctype, *, get_py_value: bool = True, raw_bytes: bool = False) -> typing.Any:
        """
        Read a ctype basic type or structure from `address`

        :param address: An address of the region of memory to be read.
        :param ctype: A simple ctypes type or structure
        :param get_py_value: If the corresponding python type should be used instead of returning the ctype.
            This is automatically set to False for ctypes.Structure or ctypes.Array instances
        :param raw_bytes: If we should return the raw ctype bytes
        :raises WinAPIError: If ReadProcessMemory failed
        :return: Will be either the ctype with the read value if get_py_value is false or the corresponding python type
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_ctype(self.process_handle, address, ctype, get_py_value=get_py_value, raw_bytes=raw_bytes)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, ctypes.sizeof(ctype), e.error_code)
        return value

    def read_bool(self, address: int) -> bool:
        """Reads 1 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: the value read as a boolean
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_bool(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('?'), e.error_code)
        return value

    def read_char(self, address: int) -> str:
        """Reads 1 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read as a string
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_char(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('b'), e.error_code)
        return value

    def read_uchar(self, address: int) -> str:
        """Reads 1 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_uchar(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('B'), e.error_code)
        return value

    def read_int(self, address: int) -> int:
        """Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_int(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('i'), e.error_code)
        return value

    def read_uint(self, address: int) -> int:
        """Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_uint(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('I'), e.error_code)
        return value

    def read_short(self, address: int) -> int:
        """Reads 2 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_short(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('h'), e.error_code)
        return value

    def read_ushort(self, address: int) -> int:
        """Reads 2 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_ushort(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('H'), e.error_code)
        return value

    def read_float(self, address: int) -> float:
        """Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_float(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('f'), e.error_code)
        return value

    def read_long(self, address: int) -> int:
        """Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_long(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('l'), e.error_code)
        return value

    def read_ulong(self, address: int) -> int:
        """Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_ulong(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('L'), e.error_code)
        return value

    def read_longlong(self, address: int) -> int:
        """Reads 8 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_longlong(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('q'), e.error_code)
        return value

    def read_ulonglong(self, address: int) -> int:
        """Reads 8 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_ulonglong(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('Q'), e.error_code)
        return value

    def read_double(self, address: int) -> float:
        """Reads 8 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            value = pymem.memory.read_double(self.process_handle, address)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryReadError(address, struct.calcsize('d'), e.error_code)
        return value

    def read_string(self, address: int, byte: int = 50) -> str:
        """Reads n `byte` from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :param byte: Amount of bytes to be read
        :raises ProcessError: If there is no opened process
        :raises MemoryReadError: When ReadProcessMemory failed
        :raises TypeError: When address is not a valid integer
        :return: returns the value read
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

    # TODO: make length optional, remove in 2.0
    def write_bytes(self, address: int, value: bytes, length: int):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :param length: Number of bytes to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid integer
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, bytes):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_bytes(self.process_handle, address, value, length)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_ctype(self, address: int, ctype):
        """Write a ctype basic type or structure to `address`

        :param address: An address of the region of memory to be written.
        :param ctype: A simple ctypes type or structure
        :raises ProcessError: If WriteProcessMemory failed
        :raises MemoryWriteError: When WriteProcessMemory failed
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        try:
            pymem.memory.write_ctype(self.process_handle, address, ctype)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, ctype, e.error_code)

    def write_bool(self, address: int, value: bool):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid boolean
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, bool):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_bool(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_int(self, address: int, value: int):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid integer
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_int(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_uint(self, address: int , value: int):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid integer
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_uint(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_short(self, address: int, value: int):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid integer
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_short(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_ushort(self, address: int, value: int):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid integer
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_ushort(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_float(self, address: int, value: float):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid float
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, float):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_float(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_long(self, address: int, value: int):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid integer
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_long(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_ulong(self, address: int, value: int):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid integer
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_ulong(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_longlong(self, address: int, value: int):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid integer
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_longlong(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_ulonglong(self, address: int, value: int):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid integer
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_ulonglong(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_double(self, address: int, value: float):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid float
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, float):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_double(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_string(self, address: int, value: str):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid string
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, str):
            raise TypeError('Invalid argument: {}'.format(value))
        value = value.encode()
        try:
            pymem.memory.write_string(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_char(self, address: int, value: str):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid string
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, str):
            raise TypeError('Invalid argument: {}'.format(value))
        value = value.encode()
        try:
            pymem.memory.write_char(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)

    def write_uchar(self, address: int, value: str):
        """Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be written.
        :param value: the value to be written
        :raises ProcessError: If there is no opened process
        :raises MemoryWriteError: When WriteProcessMemory failed
        :raises TypeError: When address is not a valid string
        """
        if not self.process_handle:
            raise pymem.exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            pymem.memory.write_uchar(self.process_handle, address, value)
        except pymem.exception.WinAPIError as e:
            raise pymem.exception.MemoryWriteError(address, value, e.error_code)
