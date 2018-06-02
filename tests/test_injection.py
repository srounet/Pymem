import pymem


def test_existing_process():
    pm = pymem.Pymem('python.exe')
    pm.inject_python_interpreter()

    assert pm.py_run_simple_string