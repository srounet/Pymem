import ctypes
import copy

from win32api import GetCurrentProcess
from win32security import GetSecurityInfo
from win32security import SetSecurityInfo
import win32security

import pymem.ressources.kernel32
import pymem.ressources.structure


def base_address(process_id):
    """Returns process base address, looking at its modules.

    :param process_id: The identifier of the process.
    :type process_id: ctypes.wintypes.HANDLE
    :return: The base address of the current process.
    :rtype: ctypes.wintypes.HANDLE
    """
    SNAPMODULE = 0x00000008
    hSnap = pymem.ressources.kernel32.CreateToolhelp32Snapshot(SNAPMODULE, process_id)
    if not hSnap:
        return #xxx
    module_entry = pymem.ressources.structure.ModuleEntry32()
    module_entry.dwSize = ctypes.sizeof(module_entry)
    success = pymem.ressources.kernel32.Module32First(hSnap, ctypes.byref(module_entry))
    pymem.ressources.kernel32.CloseHandle(hSnap)
    if not success:
        return #xxx
    base_address = ctypes.addressof(module_entry.modBaseAddr.contents)
    return base_address


def open(process_id, debug=None, process_access=None):
    """Open a process given its process_id.
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
    """
    if not debug:
        debug = True
    if not process_access:
        process_access = pymem.ressources.structure.PROCESS.PROCESS_ALL_ACCESS
    if debug:
        process_handle = pymem.ressources.kernel32.OpenProcess(
            pymem.ressources.structure.PROCESS.WRITE_DAC,
            0,
            process_id
        )
        info = GetSecurityInfo(GetCurrentProcess(), 6, 0)
        SetSecurityInfo(process_handle, 6,
                    win32security.DACL_SECURITY_INFORMATION |
                    win32security.UNPROTECTED_DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    info.GetSecurityDescriptorDacl(),
                    info.GetSecurityDescriptorGroup())
        pymem.ressources.kernel32.CloseHandle(process_handle)
    process_handle = pymem.ressources.kernel32.OpenProcess(process_access, 0, process_id)
    return process_handle


def open_main_thread(process_id):
    """List given process threads and return a handle to first created one.

    :param process_id: The identifier of the process
    :type process_id: ctypes.wintypes.HANDLE

    :return: A handle to the first thread of the given process_id
    :rtype: ctypes.wintypes.HANDLE
    """
    threads = list_process_thread(process_id)
    if not threads:
        return
    main_thread = threads[0]
    thread_handle = open_thread(main_thread.th32ThreadID)
    return thread_handle


def open_thread(thread_id, thread_access=None):
    """Opens an existing thread object.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335%28v=vs.85%29.aspx

    :param thread_id: The identifier of the thread to be opened.
    :type thread_id: ctypes.wintypes.HANDLE

    :return: A handle to the first thread of the given process_id
    :rtype: ctypes.wintypes.HANDLE
    """
    #XXX
    if not thread_access:
        thread_access = THREAD_ALL = 0x001F03FF
    thread_handle =  pymem.ressources.kernel32.OpenThread(thread_access, 0, thread_id)
    return thread_handle


def close_handle(handle):
    """Closes an open object handle.

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211%28v=vs.85%29.aspx

    :param handle: A valid handle to an open object.
    :type handle: ctypes.wintypes.HANDLE

    :return: If the function succeeds, the return value is nonzero.
    :rtype: bool
    """
    if not handle:
        return
    success = pymem.ressources.kernel32.CloseHandle(handle)
    return success


def list_processes():
    """List all processes

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms682489%28v=vs.85%29.aspx
    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684834%28v=vs.85%29.aspx

    :return: a list of process entry 32.
    :rtype: list(pymem.ressources.structure.ProcessEntry32)
    """
    SNAPPROCESS = 0x00000002
    hSnap = pymem.ressources.kernel32.CreateToolhelp32Snapshot(SNAPPROCESS, 0)
    process_entry = pymem.ressources.structure.ProcessEntry32()
    process_entry.dwSize = ctypes.sizeof(process_entry)
    p32 = pymem.ressources.kernel32.Process32First(hSnap, ctypes.byref(process_entry))
    processes = []
    if p32:
        yield process_entry
    while p32:
        yield process_entry
        p32 = pymem.ressources.kernel32.Process32Next(hSnap, ctypes.byref(process_entry))
    pymem.ressources.kernel32.CloseHandle(hSnap)


def process_from_name(name):
    """Open a process given its name.

    :param name: The name of the process to be opened
    :type name: str

    :return: The ProcessEntry32 structure of the given process.
    :rtype: ctypes.wintypes.HANDLE
    """
    name = name.lower()
    processes = list_processes()
    for process in processes:
        if name in process.szExeFile.decode('utf-8').lower():
            return process


def process_from_id(process_id):
    """Open a process given its name.

    :param process_id: The identifier of the process
    :type process_id: ctypes.wintypes.HANDLE

    :return: The ProcessEntry32 structure of the given process.
    :rtype: ctypes.wintypes.HANDLE
    """
    processes = list_processes()
    for process in processes:
        if process_id ==  process.th32ProcessID:
            return process


def list_process_thread(process_id):
    """List all threads of given processes_id

    :param process_id: The identifier of the process
    :type process_id: ctypes.wintypes.HANDLE

    :return: a list of thread entry 32.
    :rtype: list(pymem.ressources.structure.ThreadEntry32)
    """
    SNAPTHREAD = 0x00000004
    hSnap = pymem.ressources.kernel32.CreateToolhelp32Snapshot(SNAPTHREAD, 0)
    thread_entry = pymem.ressources.structure.ThreadEntry32()
    thread_entry.dwSize = ctypes.sizeof(thread_entry)
    t32 = ctypes.windll.kernel32.Thread32First(hSnap, ctypes.byref(thread_entry))
    threads = []
    if t32 and thread_entry.th32OwnerProcessID == process_id:
        threads.append(copy.copy(thread_entry))
    while t32:
        t32 = pymem.ressources.kernel32.Thread32Next(hSnap, ctypes.byref(thread_entry))
        if t32 and thread_entry.th32OwnerProcessID == process_id:
            threads.append(copy.copy(thread_entry))
    pymem.ressources.kernel32.CloseHandle(hSnap)
    return threads