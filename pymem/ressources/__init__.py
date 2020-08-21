import ctypes

# various Mock that allows the doc to be build on darwin/linux
try:
    import ctypes.wintypes
except ValueError:
    from unittest.mock import Mock

    ctypes.wintypes = Mock()
    ctypes.wintypes.MAX_PATH = 1
    ctypes.WinDLL = Mock()
