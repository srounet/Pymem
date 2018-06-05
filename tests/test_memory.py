import decimal
import pymem


def test_allocate():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    assert address
    assert pm.free(address)


def test_write_int():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_int(address, 1337)
    assert pm.read_int(address) == 1337
    pm.free(address)


def test_write_uint():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_uint(address, 1337)
    assert pm.read_uint(address) == 1337
    pm.free(address)


def test_write_short():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_short(address, 1)
    assert pm.read_short(address) == 1
    pm.free(address)


def test_write_ushort():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_ushort(address, 1)
    assert pm.read_ushort(address) == 1
    pm.free(address)


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


def test_write_long():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_long(address, 1337)
    assert pm.read_long(address) == 1337
    pm.free(address)


def test_write_ulong():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_ulong(address, 1337)
    assert pm.read_ulong(address) == 1337
    pm.free(address)


def test_write_longlong():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_longlong(address, 1337)
    assert pm.read_longlong(address) == 1337
    pm.free(address)


def test_write_ulonglong():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_ulonglong(address, 1337)
    assert pm.read_ulonglong(address) == 1337
    pm.free(address)


def test_write_double():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_double(address, 13.37)
    assert pm.read_double(address) == 13.37
    pm.free(address)


def test_write_string():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_string(address, "pymem")
    assert pm.read_string(address) == "pymem"
    pm.free(address)


def test_write_char():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_char(address, "s")
    assert pm.read_char(address) == "s"
    pm.free(address)


def test_write_uchar():
    pm = pymem.Pymem('python.exe')
    address = pm.allocate(10)

    pm.write_uchar(address, 114)
    assert pm.read_uchar(address) == 114
    pm.free(address)

