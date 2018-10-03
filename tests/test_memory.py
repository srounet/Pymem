import decimal
import logging
import struct

import pymem
import pymem.exception
import pymem.memory

import pytest

logging.getLogger('pymem').setLevel(logging.WARNING)


def test_allocate():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    assert address
    assert pm.free(address)


def test_allocate_bad_type_parameter():
    pm = pymem.Pymem('python.exe')
    with pytest.raises(TypeError):
        pm.allocate("100")


def test_allocate_no_handle():
    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.allocate(100)


def test_free_bad_type_parameter():
    pm = pymem.Pymem('python.exe')
    with pytest.raises(TypeError):
        pm.free("0x111111")


def test_free_no_handle():
    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.free(0x111111)


def test_read_bytes():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    data = struct.pack('c', "s".encode())
    length = struct.calcsize('c')
    pymem.memory.write_bytes(
        pm.process_handle, address, data, length
    )

    assert pm.read_bytes(address, 1) == b's'

    pm.free(address)


def test_read_bytes_bad_parameter():
    pm = pymem.Pymem('python.exe')
    with pytest.raises(TypeError):
        pymem.memory.read_bytes(
            pm.process_handle,
            "0x111111",
            1
        )


def test_read_no_handle():
    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_char(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_uchar(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_int(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_uint(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_short(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_ushort(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_float(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_long(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_ulong(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_longlong(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_ulonglong(0x111111)
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_double(0x111111)


def test_read_string_no_handle():
    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.read_string(0x111111)


def test_read_string_bad_type():
    pm = pymem.Pymem("python.exe")
    with pytest.raises(TypeError):
        pm.read_string(0x111111, "1")


def test_write_bytes_bad_parameter():
    pm = pymem.Pymem('python.exe')

    with pytest.raises(TypeError):
        pymem.memory.write_bytes(
            pm.process_handle,
            "0x111111",
            "0x00",
            1
        )


def test_write_int():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_int(address, 1337)
    assert pm.read_int(address) == 1337
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_int(0x111111, "1337")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_int(0x111111, 1)


def test_write_uint():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_uint(address, 1337)
    assert pm.read_uint(address) == 1337
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_uint(0x111111, "1337")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_uint(0x111111, 1)


def test_write_short():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_short(address, 1)
    assert pm.read_short(address) == 1
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_short(0x111111, "1337")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_short(0x111111, 1)


def test_write_ushort():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_ushort(address, 1)
    assert pm.read_ushort(address) == 1
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_ushort(0x111111, "1337")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_ushort(0x111111, 1)


def test_write_float():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_float(address, 13.3)
    result = decimal.Decimal(
        pm.read_float(address)
    )
    result = decimal.Decimal(
        result.quantize(
            decimal.Decimal('.01'),
            rounding=decimal.ROUND_HALF_UP
        )
    )
    expected = decimal.Decimal('13.30')
    expected = decimal.Decimal(
        expected.quantize(
            decimal.Decimal('.01'),
            rounding=decimal.ROUND_HALF_UP
        )
    )
    assert result == expected
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_float(0x111111, "1337")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_float(0x111111, 13.30)


def test_write_long():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_long(address, 1337)
    assert pm.read_long(address) == 1337
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_long(0x111111, "1337")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_long(0x111111, 1337)


def test_write_ulong():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_ulong(address, 1337)
    assert pm.read_ulong(address) == 1337
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_ulong(0x111111, "1337")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_ulong(0x111111, 1337)


def test_write_longlong():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_longlong(address, 1337)
    assert pm.read_longlong(address) == 1337
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_longlong(0x111111, "1337")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_longlong(0x111111, 1)


def test_write_ulonglong():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_ulonglong(address, 1337)
    assert pm.read_ulonglong(address) == 1337
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_ulonglong(0x111111, "1337")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_ulonglong(0x111111, 1)


def test_write_double():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_double(address, 13.37)
    assert pm.read_double(address) == 13.37
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_double(0x111111, "1337")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_double(0x111111, 13.37)


def test_write_string():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_string(address, "pymem")
    assert pm.read_string(address) == "pymem"
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_string(0x111111, 1)

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_string(0x111111, 1)


def test_write_char():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_char(address, "s")
    assert pm.read_char(address) == "s"
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_char(0x111111, 1)

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_char(0x111111, 1)


def test_write_uchar():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_uchar(address, 114)
    assert pm.read_uchar(address) == 114
    pm.free(address)

    with pytest.raises(TypeError):
        pm.write_uchar(0x111111, "114")

    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        pm.write_uchar(0x111111, 114)

