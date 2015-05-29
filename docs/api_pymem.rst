Pymem
=====

.. py:class:: Pymem

    .. py:method:: __init__(self, process_name=None)

        Initialize the Pymem class.

        If process_name is given, will open the process and retrieve a handle over it.

        :param name: The name of the process to be opened
        :type name: str


    .. py:method:: open_process_from_name(self, process_name)

        Open process given it's name and stores the handle into `self.process_handle`.

        :param process_name: The name of the process to be opened
        :type process_name: str
        :raises TypeError: if process_name is not valid
        :raises pymem.exception.ProcessNotFound: if process is not found
        :raises pymem.exception.CouldNotOpenProcess: if process cannot be opened
        
        
    .. py:method:: open_process_from_id(self, process_id)

        Open process given it's name and stores the handle into `self.process_handle`.

        :param process_id: The name of the process to be opened
        :type process_id: int
        :raises TypeError: if process_id is not an integer
        :raises pymem.exception.CouldNotOpenProcess: if process cannot be opened



    .. py:attribute:: process_base_address

        Lookup process base address.

        :return: The base address of the current process.
        :rtype: ctypes.wintypes.HANDLE
        :raises TypeError: if process_id is not an integer
        :raises pymem.exception.ProcessError: if could not find process first module address

        
    .. py:method:: open_main_thread(self)

        Open process main thread name and stores the handle into `self.thread_handle`
        the thread_id is also stored into `self.main_thread_id`.

        :raises pymem.exception.ProcessError: if there is no process opened
        :raises pymem.exception.ProcessError: if could not list process thread


    .. py:method:: close_process(self)

        Close the current opened process

        :raises pymem.exception.ProcessError: if there is no process opened


    .. py:method:: allocate(self, size)

        Allocate memory into the current opened process.

        :param size: The size of the region of memory to allocate, in bytes.
        :type size: int
        :return: The base address of the current process.
        :rtype: ctypes.wintypes.HANDLE
        :raises pymem.exception.ProcessError: if there is no process opened
        :raises TypeError: if size is not an integer
        
    .. py:method:: free(self, address)

        Free memory from the current opened process given an address.

        :param address: An address of the region of memory to be freed.
        :type address: int
        :raises pymem.exception.ProcessError: if there is no process opened
        :raises TypeError: if address is not an integer

        
    .. py:method:: assemble(self, address=None, mnemonics=None)

        Assemble mnemonics to bytes using `pyfasm`.

        If `address` is given then the origin `org` will be set to the address.

        :param address: An address of the region of memory to be freed.
        :param mnemonics: fasm syntax mnemonics
        :type address: int
        :type mnemonics: str
        :return: The assembled mnemonics
        :rtype: bytes

        
    .. py:method:: close_main_thread(self)

        Close the opened main thread

        :raises pymem.exception.ProcessError: if main thread is not opened

        
    .. py:method:: read_bytes(self, address, length)

        Reads bytes from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :param length: number of bytes to be read
        :type address: int
        :type length: int
        :return: returns the raw value read
        :rtype: bytes
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_char(self, address)

        Reads 1 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: string
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_uchar(self, address)

        Reads 1 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: string
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_int(self, address)

        Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_uint(self, address)

        Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_short(self, address)

        Reads 2 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_ushort(self, address)

        Reads 2 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_float(self, address)

        Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_long(self, address)

        Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_ulong(self, address)

        Reads 4 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_longlong(self, address)

        Reads 8 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer


    .. py:method:: read_ulonglong(self, address)

        Reads 8 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_double(self, address)

        Reads 8 byte from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :type address: int
        :return: returns the value read
        :rtype: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raise: TypeError if address is not a valid integer

        
    .. py:method:: read_string(self, address, byte=50)

        Reads n `byte` from an area of memory in a specified process.

        :param address: An address of the region of memory to be read.
        :param byte: number of bytes to read
        :type address: int
        :type byte: int
        :return: returns the value read
        :rtype: str
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if byte is not a valid integer
        
    .. py:method:: write_int(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid integer

        
    .. py:method:: write_uint(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid integer

        
    .. py:method:: write_short(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid integer

        
    .. py:method:: write_ushort(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: int
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid integer

        
    .. py:method:: write_float(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid float

        
    .. py:method:: write_long(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid int

        
    .. py:method:: write_ulong(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid int

        
    .. py:method:: write_longlong(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid int

        
    .. py:method:: write_ulonglong(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid int

        
    .. py:method:: write_double(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a valid int

        
    .. py:method:: write_string(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a string

        
    .. py:method:: write_char(self, address, value)

        Write `value` to the given `address` into the current opened process.

        :param address: An address of the region of memory to be read.
        :param value: the value to be written
        :type address: int
        :type value: float
        :raises pymem.exception.ProcessError: if there id no opened process
        :raises: TypeError if value is not a string