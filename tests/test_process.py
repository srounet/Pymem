import logging
import subprocess

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


def test_process_base():
    pm = pymem.Pymem()

    with pytest.raises(TypeError):
        assert pm.process_base


def test_main_thread_id():
    pm = pymem.Pymem()
    with pytest.raises(pymem.exception.ProcessError):
        assert pm.main_thread_id


def process_from_name_bad_parameter():
    pm = pymem.Pymem()

    with pytest.raises(TypeError):
        pm.open_process_from_name(1253)


def process_from_id_bad_parameter():
    pm = pymem.Pymem()

    with pytest.raises(TypeError):
        pm.open_process_from_name("python.exe")


def test_close_process():
    pm = pymem.Pymem('python.exe')
    pm.close_process()

    assert not pm.process_handle
    assert not pm.process_id
    assert not pm.is_WoW64
    assert not pm.py_run_simple_string
    assert not pm._python_injected

    with pytest.raises(pymem.exception.ProcessError):
        pm.close_process()


def test_missing_process():
    with pytest.raises(pymem.exception.ProcessNotFound):
        pymem.Pymem('missing.exe')


def test_list_process_modules():
    pm = pymem.Pymem('python.exe')
    modules = list(pm.list_modules())
    assert len(modules)
    assert 'python.exe' in [
        m.name for m in modules
    ]
