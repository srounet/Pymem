import pymem
import pymem.exception
import pymem.process

import pytest


def test_existing_process():
    pm = pymem.Pymem('python.exe')
    assert pm.process_handle


def test_missing_process():
    with pytest.raises(pymem.exception.ProcessNotFound):
        pymem.Pymem('missing.exe')


def test_list_process_modules():
    pm = pymem.Pymem('python.exe')
    modules = pymem.process.enum_process_module(
        pm.process_handle
    )
    modules = list(modules)
    assert len(modules)
    assert 'python3.dll' in [
        m.name for m in modules
    ]


def test_process_base():
    pm = pymem.Pymem('python.exe')
    assert pm.process_base.name == 'python.exe'
