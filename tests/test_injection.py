import logging
import os
import os.path
import subprocess

import pymem


logging.getLogger('pymem').setLevel(logging.WARNING)


def test_inject_python_interpreter():
    pm = pymem.Pymem('python.exe')
    pm.inject_python_interpreter()

    assert pm.py_run_simple_string


def test_inject_python_shellcode():
    notepad = subprocess.Popen(['notepad.exe'])

    pm = pymem.Pymem('notepad.exe')
    pm.inject_python_interpreter()

    # test already injected
    pm.inject_python_interpreter()

    assert pm.py_run_simple_string

    filepath = os.path.join(os.path.abspath('.'), 'pymem_injection.txt')
    filepath = filepath.replace("\\", "\\\\")

    shellcode = """
f = open("{}", "w+")
f.write("pymem_injection")
f.close()
    """.format(filepath)
    pm.inject_python_shellcode(shellcode)

    assert os.path.exists(filepath)

    os.remove(filepath)
    notepad.kill()


