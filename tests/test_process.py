import logging

import pymem
import pymem.exception
import pymem.process

import pytest

logging.getLogger('pymem').setLevel(logging.WARNING)


def test_existing_process():
    pm = pymem.Pymem('python.exe')
    assert pm.process_handle
    assert pm.process_id
    assert pm.process_base
    assert pm.main_thread
    assert pm.main_thread_id


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
    assert 'python.exe' in [
        m.name for m in modules
    ]
