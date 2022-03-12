import pymem

# TODO: add tests for other two functions


def test_scan_all():
    pm = pymem.Pymem("python.exe")

    address = pm.allocate(5)
    target_bytes = "Hello".encode()

    pm.write_bytes(address, target_bytes, 5)

    found = pymem.pattern.pattern_scan_all(pm.process_handle, target_bytes, return_multiple=True)
    assert address in found
