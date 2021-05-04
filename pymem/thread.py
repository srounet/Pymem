import ctypes

import pymem.memory
import pymem.resources.kernel32
import pymem.resources.ntdll
import pymem.resources.structure


class Thread(object):

    def __init__(self, process_handle, th_entry_32):
        """Provides basic thread informations such as TEB.

            :param process_handle: A handle to an opened process
            :param th_entry_32: A ThreadEntry32 structure
            :type process_handle: ctypes.c_void_p
            :type th_entry_32: pymem.ressources.structure.ThreadEntry32
        """
        self.process_handle = process_handle
        self.thread_id = th_entry_32.th32ThreadID
        self.th_entry_32 = th_entry_32
        self.teb_address = None
        # teb should be tested, not working on x64
        # self.teb = self._query_teb()

    def _query_teb(self):
        """Query current thread informations to extract the TEB structure.

            :return: TEB informations
            :rtype: pymem.ressources.structure.SMALL_TEB
        """
        THREAD_QUERY_INFORMATION = 0x0040

        thread_handle = pymem.resources.kernel32.OpenThread(
            THREAD_QUERY_INFORMATION, False, self.th_entry_32.th32ThreadID
        )
        res = pymem.resources.structure.THREAD_BASIC_INFORMATION()
        ThreadBasicInformation = 0x0

        pymem.resources.ntdll.NtQueryInformationThread(
            thread_handle,
            ThreadBasicInformation,
            ctypes.byref(res),
            ctypes.sizeof(res),
            None
        )
        self.teb_address = res.TebBaseAddress
        bytes = pymem.memory.read_bytes(
            self.process_handle,
            res.TebBaseAddress,
            ctypes.sizeof(pymem.resources.structure.SMALL_TEB)
        )
        teb = pymem.resources.structure.SMALL_TEB.from_buffer_copy(bytes)
        pymem.resources.kernel32.CloseHandle(thread_handle)
        return teb

    def suspend(self):
        THREAD_ALL_ACCESS = (
                pymem.resources.structure.PROCESS.STANDARD_RIGHTS_REQUIRED +
                pymem.resources.structure.PROCESS.SYNCHRONIZE +
                0x3FF
        )
        hThread = self.th_entry_32.th32ThreadID

        thread_handle = pymem.resources.kernel32.OpenThread(THREAD_ALL_ACCESS, 0, hThread)
        pymem.resources.kernel32.SuspendThread(thread_handle)
        pymem.resources.kernel32.CloseHandle(thread_handle)

    def resume(self):
        THREAD_ALL_ACCESS = (
                pymem.resources.structure.PROCESS.STANDARD_RIGHTS_REQUIRED +
                pymem.resources.structure.PROCESS.SYNCHRONIZE +
                0x3FF
        )
        hThread = self.th_entry_32.th32ThreadID

        thread_handle = pymem.resources.kernel32.OpenThread(THREAD_ALL_ACCESS, 0, hThread)
        pymem.resources.kernel32.ResumeThread(thread_handle)
        pymem.resources.kernel32.CloseHandle(thread_handle)

    def terminate(self):
        THREAD_ALL_ACCESS = (
                pymem.resources.structure.PROCESS.STANDARD_RIGHTS_REQUIRED +
                pymem.resources.structure.PROCESS.SYNCHRONIZE +
                0x3FF
        )
        hThread = self.th_entry_32.th32ThreadID
        print(self.th_entry_32)

        thread_handle = pymem.resources.kernel32.OpenThread(THREAD_ALL_ACCESS, 0, hThread)
        res = pymem.resources.kernel32.TerminateThread(thread_handle, 0)
        pymem.resources.kernel32.CloseHandle(thread_handle)
