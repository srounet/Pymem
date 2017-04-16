import ctypes
import struct

import pymem.memory
import pymem.ressources.kernel32


def scan_pattern_page(handle, address, pattern, mask):
    """Search a byte pattern given a memory location.
    Will query memory location informations and search over until it reaches the
    length of the memory page. If nothing is found the function returns the
    next page location.

        :param handle: A valid handle to an open object.
        :param address: An address to search from
        :param pattern: A byte pattern to search for
        :param mask: A mask corresponding to a given pattern of the form: xxx???xxx
        :type handle: ctypes.wintypes.HANDLE
        :type address: Integer
        :type pattern: string
        :type mask: string

        :return: A tuple of next_region, found address
        :rtype: tuple(Integer, Integer)
    """
    mbi = pymem.memory.virtual_query(handle, address)
    next_region = mbi.BaseAddress + mbi.RegionSize
    allowed_protections = [
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READWRITE,
        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READONLY,
    ]
    if (mbi.state != pymem.ressources.structure.MEMORY_STATE.MEM_COMMIT or
        mbi.protect not in allowed_protections
        ):
        return next_region, []
    page_bytes = pymem.memory.read_bytes(handle, address, mbi.RegionSize)

    found = None
    for offset in range(0, (mbi.RegionSize - len(pattern)), 1):
        partial = page_bytes [offset:offset + len(pattern)]
        for x in range(len(pattern)):
            if mask[x] == '?':
                continue
            if mask[x] == 'x' and not partial[x] == pattern[x]:
                break
        else:
            found = address + offset
            del page_bytes
            return None, found
    return next_region, found


def scan_string_page(handle, address, search):
    """Search a string given a memory location.
    Will query memory location informations and search over until it reaches the
    length of the memory page. If nothing is found the function returns the
    next page location.

        :param handle: A valid handle to an open object.
        :param address: An address to search from
        :param search: A string to search for
        :type handle: ctypes.wintypes.HANDLE
        :type address: Integer (32/64)
        :type search: string

        :return: A tuple of next_region, found address
        :rtype: tuple(Integer, Integer)
    """
    mbi = pymem.memory.virtual_query(handle, address)
    next_region = mbi.BaseAddress + mbi.RegionSize
    if (mbi.state != pymem.ressources.structure.MEMORY_STATE.MEM_COMMIT or
        mbi.protect != pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READONLY and
        mbi.type != pymem.ressources.structure.MEMORY_TYPES.MEM_IMAGE
        ):
        return next_region, []
    page_bytes = pymem.memory.read_bytes(handle, address, mbi.RegionSize)

    found = None
    for offset in range(0, (mbi.RegionSize - len(search)), 1):
        partial = page_bytes [offset:offset + len(search)]
        for x in range(len(search)):
            if not partial[x] == search[x]:
                break
        else:
            found = address + offset
            del page_bytes
            return None, found
    return next_region, found


def search_real_address(handle, address, found_address):
    """
    """
    mbi = pymem.memory.virtual_query(handle, address)
    next_region = mbi.BaseAddress + mbi.RegionSize
    # Search within code sections
    if (mbi.protect != pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READ):
        return next_region, None
    page_bytes = pymem.memory.read_bytes(handle, address, mbi.RegionSize)

    found = None
    for i in range(len(page_bytes)):
        try:
            # Search an int32 relative address
            current_bytes = page_bytes[i: i + 4]
            current_bytes = struct.unpack('<I', current_bytes)[0]
        except Exception:
            # In case we reached the page_bytes buffer end
            break
        # compare real address with found_address (follow relative address)
        # 0x7ff66c621000 + index + 0xc83e9b + 4
        if not mbi.BaseAddress + i + current_bytes + 4 == found_address:
            continue
        else:
            # 0x7FF66CD0B856 | 48 8D 0D 9B 3E C8 00     | LEA RCX, QWORD PTR DS:[7FF66D98F6F8]
            # to find the real address we remove the 3 first bytes (0D 8D 48)
            # 0x7ff66c621000 + index - 3
            found = mbi.BaseAddress + i - 3
            del page_bytes
            return None, found
    return next_region, found


def string_scan_module(handle, module, search):
    """Given a handle over an opened process and a module will scan memory after
    a string and return its corresponding address

        :param handle: A valid handle to an open object.
        :param module: An instance of a given module
        :param search: A string to search for
        :type handle: ctypes.wintypes.HANDLE
        :type module: pymem.ressources.structure.MODULEINFO
        :type search: string

        :return: The memory address of given pattern
        :rtype: Integer

        ex:
            p = pymem.Pymem()
            p.open_process_from_name("Gw2-64.exe")
            module = pymem.process.module_from_name(p.process_handle, "Gw2-64.exe")
            GetContext_address = pymem.pattern.pattern_scan_module(
                p.process_handle, module, GetContext_pattern, GetContext_mask
            )
    """
    base_address = module.lpBaseOfDll
    max_address = module.lpBaseOfDll + module.SizeOfImage
    page_address = base_address

    # map search string to a sequence of bytes
    search = bytes(search, 'ascii')
    found = None
    while page_address < max_address:
        next_page, strings_address = scan_string_page(handle, page_address, search)
        if strings_address:
            break
        page_address = next_page

    if not strings_address:
        return

    real_address = None
    page_address = base_address
    while page_address < max_address:
        next_page, real_address = search_real_address(handle, page_address, strings_address)
        if real_address:
            break
        page_address = next_page
    # xxx raise not found
    return real_address
    

def pattern_scan_module(handle, module, pattern, mask):
    """Given a handle over an opened process and a module will scan memory after
    a byte pattern and return its corresponding memory address.

        :param handle: A valid handle to an open object.
        :param module: An instance of a given module
        :param pattern: A byte pattern to search for
        :param mask: A mask corresponding to a given pattern of the form: xxx???xxx
        :type handle: ctypes.wintypes.HANDLE
        :type module: pymem.ressources.structure.MODULEINFO
        :type pattern: string
        :type mask: string

        :return: The memory address of given pattern
        :rtype: Integer

        ex:
            p = pymem.Pymem()
            p.open_process_from_name("Gw2-64.exe")
            GetContext_pattern = b"\x65\x48\x8B\x04\x25\x58\x00\x00\x00\xBA\x08\x00\x00\x00"
            GetContext_mask = "x" * 14
            module = pymem.process.module_from_name(p.process_handle, "Gw2-64.exe")
            GetContext_address = pymem.pattern.pattern_scan_module(
                p.process_handle, module, GetContext_pattern, GetContext_mask
            )
    """
    base_address = module.lpBaseOfDll
    max_address = module.lpBaseOfDll + module.SizeOfImage
    page_address = base_address

    while page_address < max_address:
        next_page, found = scan_pattern_page(handle, page_address, pattern, mask)
        if found:
            break
        page_address = next_page
    # xxx raise not found
    return found