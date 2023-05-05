import typing


class WinAPIError(Exception):
    """A generic catchall Exception for Win32 Api errors"""
    def __init__(self, error_code):
        """Initialize a new WinAPIError.

        :param error_code: Generally issued from GetLastError
        """
        self.error_code = error_code
        message = 'Windows api error, error_code: {}'.format(self.error_code)
        super(WinAPIError, self).__init__(message)


class PymemError(Exception):
    """Top level pymem Exception class"""
    def __init__(self, message: str):
        """Initialize a new PymemError.

        :param message: The error message to be displayed
        """
        super(PymemError, self).__init__(message)


class ProcessError(PymemError):
    """Top level pymem process Exception class"""
    def __init__(self, message: str):
        """Initialize a new CouldNotOpenProcess.

        :param message: The error message to be displayed
        """
        super(ProcessError, self).__init__(message)


class ProcessNotFound(ProcessError):
    """Occurs on any process not found error"""
    def __init__(self, process_name: str):
        """Initialize a new CouldNotOpenProcess.

        :param process_name: The process name to be opened
        """
        message = 'Could not find process: {}'.format(process_name)
        super(ProcessNotFound, self).__init__(message)


class CouldNotOpenProcess(ProcessError):
    """Occurs on any open process error"""
    def __init__(self, process_id: int):
        """Initialize a new CouldNotOpenProcess.

        :param process_id: The process id to be opened
        """
        message = 'Could not open process: {}'.format(process_id)
        super(CouldNotOpenProcess, self).__init__(message)


class PymemMemoryError(PymemError):
    """Top level pymem memory Exception class"""
    def __init__(self, message: str):
        """Initialize a new PymemMemoryError.

        :param message: The error message to be displayed
        """
        super(PymemMemoryError, self).__init__(message)


class MemoryReadError(PymemMemoryError):
    """Occurs on any memory read error"""
    def __init__(self, address: int, length: int, error_code: typing.Optional = None):
        """Initialize a new MemoryReadError.

        :param address: The memory address at which the error occurred
        :param length: A value that should have been read
        :error_code: An optional error code to be associated. Generally issued from GetLastError
        """
        message = 'Could not read memory at: {}, length: {}'.format(address, length)
        if error_code:
            message += ' - GetLastError: {}'.format(error_code)
        super(MemoryReadError, self).__init__(message)


class MemoryWriteError(PymemMemoryError):
    """Occurs on any memory write error"""
    def __init__(self, address: int, value: typing.Any, error_code: typing.Optional = None):
        """Initialize a new MemoryWriteError.

        :param address: The memory address at which the error occurred
        :param value: A value that should have been written
        :error_code: An optional error code to be associated. Generally issued from GetLastError
        """
        message = 'Could not write memory at: {}, length: {}'.format(address, value)
        if error_code:
            message += ' - GetLastError: {}'.format(error_code)
        super(MemoryWriteError, self).__init__(message)


class PymemAlignmentError(PymemError):
    """Occurs on any endianess alignment error"""
    def __init__(self, message: str):
        """Initialize a new PymemAlignmentError.

        :param message: The error message to be displayed
        """
        super(PymemAlignmentError, self).__init__(message)


class PymemTypeError(PymemError):
    """Occurs on any type checking error"""
    def __init__(self, message: str):
        """Initialize a new PymemTypeError.

        :param message: The error message to be displayed
        """
        super(PymemTypeError, self).__init__(message)
