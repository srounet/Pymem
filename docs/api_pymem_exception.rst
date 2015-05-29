Exception's
===========

.. py:exception:: PymemError

    Custom Pymem exception class.

    Except on this class to catch all Pymem specific Exception's


.. py:exception:: ProcessError(PymemError)

    Raised when something required by a process handle went wrong


.. py:exception:: ProcessNotFound(ProcessError)

    Raised when process not found


.. py:exception:: CouldNotOpenProcess(ProcessError)

    Raised when process could not be opened