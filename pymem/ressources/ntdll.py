"""It handles memory management, input/output operations, and interrupts"""
import ctypes
import ctypes.wintypes

import pymem.ressources.structure

dll = ctypes.WinDLL('ntdll.dll')

NTSTATUS = ctypes.c_ulong
THREADINFOCLASS = ctypes.wintypes.DWORD

#: Retrieves information about the specified thread.
#:
#: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684283.aspx
NtQueryInformationThread = dll.NtQueryInformationThread
NtQueryInformationThread.restype = NTSTATUS
NtQueryInformationThread.argtypes = [
    ctypes.wintypes.HANDLE,
    THREADINFOCLASS,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.ULONG,
    ctypes.wintypes.PULONG
]
