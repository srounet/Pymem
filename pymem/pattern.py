import re

import pymem.memory
import pymem.ressources.kernel32
import pymem.ressources.structure


def scan_pattern_page(handle, address, pattern):
    """Search a byte pattern given a memory location.
    Will query memory location information and search over until it reaches the
    length of the memory page. If nothing is found the function returns the
    next page location.

    Parameters
    ----------
    handle: HANDLE
        Handle to an open object
    address: int
        An address to search from
    pattern: bytes
        A regex byte pattern to search for

    Returns
    -------
    tuple
        next_region, found address

        found address may be None if one was not found or we didn't have permission to scan
        the region
    """
    mbi = pymem.memory.virtual_query(handle, address)
    next_region = mbi.BaseAddress + mbi.RegionSize
    allowed_protections = [
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READWRITE,
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READONLY,
    ]
    if mbi.state != pymem.ressources.structure.MEMORY_STATE.MEM_COMMIT or mbi.protect not in allowed_protections:
        return next_region, None

    page_bytes = pymem.memory.read_bytes(handle, address, mbi.RegionSize)

    found = None

    match = re.search(pattern, page_bytes)

    if match:
        found = address + match.span()[0]

    return next_region, found


def pattern_scan_module(handle, module, pattern):
    """Given a handle over an opened process and a module will scan memory after
    a byte pattern and return its corresponding memory address.

    Parameters
    ----------
    handle: HANDLE
        Handle to an open object
    module: MODULEINFO
        An instance of a given module
    pattern: bytes
        A regex byte pattern to search for

    Returns
    -------
    Optional[int]
        Memory address of given pattern, or None if one was not found

    Examples
    --------
    >>> pm = pymem.Pymem("Notepad.exe")
    # Here the "." means that the byte can be any byte; a "wildcard"
    # also note that this pattern may be outdated
    >>> character_count_pattern = b".\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    ...                           b"\x00\x00\x00\x00\x00\x00..\x00\x00..\x00\x00\x64\x04"
    >>> module = pymem.process.module_from_name(pm.process_handle, "Notepad.exe")
    >>> character_count_address = pymem.pattern.pattern_scan_module(pm.process_handle, module, character_count_pattern)
    """
    base_address = module.lpBaseOfDll
    max_address = module.lpBaseOfDll + module.SizeOfImage
    page_address = base_address

    found = None
    while page_address < max_address:
        next_page, found = scan_pattern_page(handle, page_address, pattern)
        if found:
            break
        page_address = next_page

    return found
