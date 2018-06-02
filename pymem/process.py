import ctypes
import ctypes.wintypes
import platform
import copy

from win32api import GetCurrentProcess
from win32security import GetSecurityInfo
from win32security import SetSecurityInfo
import win32security
import win32api

import pymem.ressources.kernel32
import pymem.ressources.psapi
import pymem.ressources.structure


def inject_dll(handle, filepath):
    """Inject a dll into opened process.

        Parameters
        ----------
        handle: HANDLE
            Handle to an open object
        filepath: bytes
            Dll to be injected filepath

        Returns
        -------
        DWORD
            The address of injected dll
    """
    filepath_address = pymem.ressources.kernel32.VirtualAllocEx(
        handle,
        0,
        len(filepath),
        pymem.ressources.structure.MEMORY_STATE.MEM_COMMIT.value | pymem.ressources.structure.MEMORY_STATE.MEM_RESERVE.value,
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE.value
    )
    pymem.ressources.kernel32.WriteProcessMemory(handle, filepath_address, filepath, len(filepath), None)
    kernel32_handle = pymem.ressources.kernel32.GetModuleHandleW("kernel32.dll")
    load_library_a_address = pymem.ressources.kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
    thread_h = pymem.ressources.kernel32.CreateRemoteThread(
        handle, None, 0, load_library_a_address, filepath_address, 0, None
    )
    pymem.ressources.kernel32.WaitForSingleObject(thread_h, -1)

    exitcode = ctypes.wintypes.DWORD(0)
    pymem.ressources.kernel32.GetExitCodeThread(thread_h, ctypes.byref(exitcode))
    pymem.ressources.kernel32.VirtualFreeEx(
        handle, filepath_address, len(filepath), pymem.ressources.structure.MEMORY_STATE.MEM_RELEASE.value
    )
    return exitcode.value


def set_debug_privilege(hToken, lpszPrivilege, bEnablePrivilege):
    """Leverage current process privileges.

    :param hToken: Current process handle
    :param lpszPrivilege: privilege name
    :param bEnablePrivilege: Enable privilege
    :type hToken: HANDLE
    :type lpszPrivilege: str
    :type bEnablePrivilege: bool
    :return: True if privileges have been leveraged.
    :rtype: bool
    """
    tp = pymem.ressources.structure.TOKEN_PRIVILEGES()
    luid = pymem.ressources.structure.LUID()

    if not ctypes.windll.advapi32.LookupPrivilegeValueW( None, lpszPrivilege, ctypes.byref(luid)):
        print("LookupPrivilegeValue error: 0x%08x\n" % ctypes.GetLastError())
        return False

    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid

    if bEnablePrivilege:
        tp.Privileges[0].Attributes = pymem.ressources.structure.SE_TOKEN_PRIVILEGE.SE_PRIVILEGE_ENABLED.value
    else:
        tp.Privileges[0].Attributes = pymem.ressources.structure.SE_TOKEN_PRIVILEGE.SE_PRIVILEGE_USED_FOR_ACCESS.value

    if not ctypes.windll.advapi32.AdjustTokenPrivileges( hToken, False, ctypes.byref(tp), ctypes.sizeof(pymem.ressources.structure.TOKEN_PRIVILEGES), None, None):
        print("AdjustTokenPrivileges error: 0x%08x\n", ctypes.GetLastError())
        return False

    if ctypes.GetLastError() == 0x514:
        print("The token does not have the specified privilege. \n")
        return False
    return True


def base_module(handle):
    """Returns process base address, looking at its modules.

    :param handle: A valid handle to an open object.
    :type handle: ctypes.wintypes.HANDLE
    :param process_id: The identifier of the process.
    :type process_id: ctypes.wintypes.HANDLE
    :return: The base address of the current process.
    :rtype: ctypes.wintypes.HANDLE
    """
    hModules  = (ctypes.wintypes.HMODULE * 1024)()
    process_module_success = pymem.ressources.psapi.EnumProcessModulesEx(
        handle,
        ctypes.byref(hModules),
        ctypes.sizeof(hModules),
        ctypes.byref(ctypes.c_ulong()),
        pymem.ressources.structure.EnumProcessModuleEX.LIST_MODULES_ALL
    )
    if not process_module_success:
        return # xxx
    module_info = pymem.ressources.structure.MODULEINFO(handle)
    pymem.ressources.psapi.GetModuleInformation(
        handle,
        ctypes.c_void_p(hModules[0]),
        ctypes.byref(module_info),
        ctypes.sizeof(module_info)
    )
    return module_info


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
        process_access = pymem.ressources.structure.PROCESS.PROCESS_ALL_ACCESS.value
    if debug:
        hToken = ctypes.wintypes.HANDLE()
        hCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess()
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        ctypes.windll.advapi32.OpenProcessToken(hCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken))
        set_debug_privilege(hToken, 'SeDebugPrivilege', True)
    process_handle = pymem.ressources.kernel32.OpenProcess(process_access, 0, process_id)
    return process_handle


def open_main_thread(process_id):
    """List given process threads and return a handle to first created one.

    :param process_id: The identifier of the process
    :type process_id: ctypes.wintypes.HANDLE

    :return: A handle to the first thread of the given process_id
    :rtype: ctypes.wintypes.HANDLE
    """
    threads = enum_process_thread(process_id)
    threads = sorted(threads, key=lambda t32: t32.creation_time)

    if not threads:
        return  # todo: raise exception

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
        if process_id == process.th32ProcessID:
            return process


def module_from_name(process_handle, module_name):
    """Retrieve a module loaded by given process.

    ex:
        d3d9 = module_from_name(process_handle, 'd3d9')

    :param process_handle: A process handle
    :param module_name: The module name
    :type process_handle: ctypes.wintypes.HANDLE
    :type module_name: str
    :return: MODULEINFO
    """
    module_name = module_name.lower()
    modules = enum_process_module(process_handle)
    for module in modules:
        if module.name.lower() == module_name:
            return module


def enum_process_thread(process_id):
    """List all threads of given processes_id

    :param process_id: The identifier of the process
    :type process_id: ctypes.wintypes.HANDLE

    :return: a list of thread entry 32.
    :rtype: list(pymem.ressources.structure.ThreadEntry32)
    """
    TH32CS_SNAPTHREAD = 0x00000004
    hSnap = pymem.ressources.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    thread_entry = pymem.ressources.structure.ThreadEntry32()
    ret = pymem.ressources.kernel32.Thread32First(hSnap, ctypes.byref(thread_entry))

    if not ret:
        raise pymem.exception.PymemError('Could not get Thread32First')

    while ret:
        if thread_entry.th32OwnerProcessID == process_id:
            yield thread_entry
        ret = pymem.ressources.kernel32.Thread32Next(hSnap, ctypes.byref(thread_entry))
    pymem.ressources.kernel32.CloseHandle(hSnap)


def enum_process_module(handle):
    """List and retrieves the base names of the specified loaded module within a process

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms682633(v=vs.85).aspx
    https://msdn.microsoft.com/en-us/library/windows/desktop/ms683196(v=vs.85).aspx

    :param handle: A valid handle to an open object.
    :type handle: ctypes.wintypes.HANDLE

    :return: a list of loaded modules
    :rtype: list(pymem.ressources.structure.MODULEINFO)
    """
    hModules  = (ctypes.wintypes.HMODULE * 1024)()
    process_module_success = pymem.ressources.psapi.EnumProcessModulesEx(
        handle,
        ctypes.byref(hModules),
        ctypes.sizeof(hModules),
        ctypes.byref(ctypes.c_ulong()),
        pymem.ressources.structure.EnumProcessModuleEX.LIST_MODULES_ALL
    )
    if process_module_success:
        hModules = iter(m for m in hModules if m)
        for hModule in hModules:
            module_info = pymem.ressources.structure.MODULEINFO(handle)
            pymem.ressources.psapi.GetModuleInformation(
                handle,
                ctypes.c_void_p(hModule),
                ctypes.byref(module_info),
                ctypes.sizeof(module_info)
            )
            yield module_info


def is_64_bit(handle):
    """Determines whether the specified process is running under WOW64 (emulation).

    :param handle: A valid handle to an open object.
    :type handle: ctypes.wintypes.HANDLE

    :return: True if the 32 bit process is running under WOW64.
    :rtype: bool
    """
    Wow64Process = ctypes.wintypes.BOOL()
    response = pymem.ressources.kernel32.IsWow64Process(handle, ctypes.byref(Wow64Process))
    return Wow64Process