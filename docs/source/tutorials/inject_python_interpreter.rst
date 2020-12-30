Injecting a python interpreter into any process
===============================================

Pymem allow you to inject `python.dll` into a target process and then map `py_run_simple_string`
with a single call to :meth:`~pymem.Pymem.inject_python_interpreter`.

.. code-block:: python

    from pymem import Pymem
    import os
    import subprocess

    notepad = subprocess.Popen(['notepad.exe'])

    pm = Pymem('notepad.exe')
    pm.inject_python_interpreter()
    filepath = os.path.join(os.path.abspath('.'), 'pymem_injection.txt')
    filepath = filepath.replace("\\", "\\\\")
    shellcode = """
    f = open("{}", "w+")
    f.write("pymem_injection")
    f.close()
    """.format(filepath)
    pm.inject_python_shellcode(shellcode)
    notepad.kill()

So what did that code do?

1. we start notepad process and get its handle

2. we hook pymem with notepad process

3. we call :meth:`~pymem.Pymem.inject_python_interpreter` which will:

  * dynamically finds the correct python dll and inject it
  * register **py_run_simple_string**

4. then we inject some python code with :meth:`~pymem.Pymem.inject_python_shellcode` which will:

  - **VirtualAllocEx** some space for the code to be written
  - write the actual payload into allocated space
  - execute **py_run_simple_string** so the python code gets interpreted within the notepad process

5. finally we get rid of notepad process
