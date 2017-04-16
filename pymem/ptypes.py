import ctypes
import functools
import struct

import pymem.memory
import pymem.exception


class RemotePointer(object):
    """Pointer capable of reading the value mapped into another process memory.
    """

    ALIGNMENTS = {
        'little-endian': '<',
        'big-endian': '>'
    }

    def __init__(self, handle, v, endianess=None):
        """Initialize a RemotePointer.

            :param handle: A handle to an opened process
            :param v: The address value
            :param endianess: The endianess of the remote process, default to little-endian
            :type handle: ctypes.wintypes.HANDLE
            :type v: [int, RemotePointer, ctypes]
            :type endianess: str
            :raise: PymemAlignmentError if endianess is not correct
            :raise: WinAPIError if ReadProcessMemory failed
        """
        self._set_value(v)

        if not endianess:
            endianess = 'little-endian'
        if not endianess in RemotePointer.ALIGNMENTS:
            raise pymem.exception.PymemAlignmentError(
                "{endianess} is not a valid alignment, it should be one from: {alignments}".format(**{
                    'endianess': endianess,
                    'alignments': ', '.join(RemotePointer.keys())
                })
            )
        self.endianess = endianess

        self.handle = handle
        self._memory_value = None

    def __bool__(self):
        """Overrides boolean operation over the pointer value.

            :return: True if value is > 0
            :rtype: boolean
        """
        return bool(self.value)

    def _set_value(self, v):
        """Given a v value will setup the internal kitchen to map internal v to the correct
        type. self.v has to be a ctype instance.

            :param v: The address value
            :type v: [int, RemotePointer, ctypes]
        """
        if isinstance(v, RemotePointer):
            self.v = v.cvalue
        elif isinstance(v, int) and not hasattr(v, 'value'):
            if v > 2147483647:
                self.v = ctypes.c_ulonglong(v)
            else:
                self.v = ctypes.c_uint(v)
        elif isinstance(v, ctypes._SimpleCData):
            self.v = v
        else:
            raise pymem.exception.PymemTypeError(
                "{type} is not an allowed type, it should be one from: {allowed_types}".format(**{
                    'type': 'None' if not v else str(type(v)),
                    'allowed_types': ', '.join([
                        'RemotePointer', 'ctypes', 'int'
                    ])
                }))

    def __add__(self, a):
        """Add a to the value pointed by the current RemotePointer instance.

            :param a: The value to add
            :type a: integer
            :return: The new ctype value
            :rtype: ctype
        """
        self._memory_value = self.value + a
        return self.cvalue

    @property
    def value(self):
        """Reads targeted process memory and returns the value pointed by the given address.

            :return: The value pointed by the given address.
            :rtype: integer
        """
        if self._memory_value:
            return self._memory_value
        content = pymem.memory.read_bytes(
            self.handle, self.v.value, struct.calcsize(self.v._type_)
        )
        fmt = '{alignment}{type}'.format(**{
            'alignment': RemotePointer.ALIGNMENTS[self.endianess],
            'type': self.v._type_
        })
        content = struct.unpack(fmt, content)
        self._memory_value = content[0]
        return self._memory_value

    @property
    def cvalue(self):
        """Reads targeted process memory and returns the value pointed by the given address.

            :return: The value pointed by the given address as a ctype instance
            :rtype: ctype
        """
        v = self.v.__class__(self.value)
        return v