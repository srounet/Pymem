Process
=======

.. function:: base_address(process_id)

    Returns process base address, looking at its modules.

    :param process_id: The identifier of the process.
    :type process_id: ctypes.wintypes.HANDLE
    :return: The base address of the current process.
    :rtype: ctypes.wintypes.HANDLE

.. function:: open(process_id, debug=None, process_access=None)

    Open a process given its process_id.
    By default the process is opened with full access and in debug mode.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320%28v=vs.85%29.aspx
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379588%28v=vs.85%29.aspx

    :param process_id: The identifier of the process to be opened
    :param debug: open process in debug mode
    :param process_access: desired access level
    :type process_id: ctypes.wintypes.HANDLE
    :type debug: bool
    :type process_access: pymem.ressources.structure

    :return: A handle of the given process_id
    :rtype: ctypes.wintypes.HANDLE


.. function:: open_main_thread(process_id)

    List given process threads and return a handle to first created one.

    :param process_id: The identifier of the process
    :type process_id: ctypes.wintypes.HANDLE

    :return: A handle to the first thread of the given process_id
    :rtype: ctypes.wintypes.HANDLE


.. function:: open_thread(thread_id, thread_access=None)

    Opens an existing thread object.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335%28v=vs.85%29.aspx

    :param thread_id: The identifier of the thread to be opened.
    :type thread_id: ctypes.wintypes.HANDLE

    :return: A handle to the first thread of the given process_id
    :rtype: ctypes.wintypes.HANDLE


.. function:: close_handle(handle)

    Closes an open object handle.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211%28v=vs.85%29.aspx

    :param handle: A valid handle to an open object.
    :type handle: ctypes.wintypes.HANDLE

    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool


.. function:: list_processes()

    List all processes

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms682489%28v=vs.85%29.aspx
    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684834%28v=vs.85%29.aspx

    :return: a list of process entry 32.
    :rtype: list(pymem.ressources.structure.ProcessEntry32)


.. function:: process_from_name(name)

    Open a process given its name.

    :param name: The name of the process to be opened
    :type name: str

    :return: The ProcessEntry32 structure of the given process.
    :rtype: ctypes.wintypes.HANDLE


.. function:: process_from_id(process_id)

    Open a process given its name.

    :param process_id: The identifier of the process
    :type process_id: ctypes.wintypes.HANDLE

    :return: The ProcessEntry32 structure of the given process.
    :rtype: ctypes.wintypes.HANDLE


.. function:: list_process_thread(process_id)

    List all threads of given processes_id

    :param process_id: The identifier of the process
    :type process_id: ctypes.wintypes.HANDLE

    :return: a list of thread entry 32.
    :rtype: list(pymem.ressources.structure.ThreadEntry32)