import os

import pytest

import pymem


def test_init_process_by_name():
    process = pymem.Pymem("python.exe")
    assert process.base_address is not None


def test_init_process_by_id():
    process = pymem.Pymem(os.getpid())
    assert process.base_address is not None
    assert process.process_id == os.getpid()


def test_error_init_non_str_int():
    with pytest.raises(TypeError):
        pymem.Pymem(1.0)


def test_init_none():
    process = pymem.Pymem()
    assert process.process_id is None
