Exception's
===========

.. py:exception:: WinAPIError

    Global handler for win32api errors


.. py:exception:: PymemError

    Custom Pymem exception class.

    Except on this class to catch all Pymem specific Exception's


.. py:exception:: ProcessError(PymemError)

    Raised when something required by a process handle went wrong


.. py:exception:: ProcessNotFound(ProcessError)

    Raised when process not found


.. py:exception:: CouldNotOpenProcess(ProcessError)

    Raised when process could not be opened


.. py:exception:: PymemMemoryError(PymemError)

    Raised when a memory error occured


.. py:exception:: MemoryReadError(PymemMemoryError)

    Raised when a memory read error occured


.. py:exception:: MemoryWriteError(PymemMemoryError)

    Raised when a memory write error occured