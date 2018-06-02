import os.path
import pymem


def test_inject_python_interpreter():
    pm = pymem.Pymem('python.exe')
    pm.inject_python_interpreter()

    assert pm.py_run_simple_string


def test_inject_python_shellcode():
    pm = pymem.Pymem('python.exe')
    pm.inject_python_interpreter()

    assert pm.py_run_simple_string
    pm.inject_python_shellcode("""
f = open("C:\\\\pymem_injection.txt", "w+")
f.write("pymem_injection")
f.close()
    """)
    assert os.path.exists("C:\pymem_injection.txt")


