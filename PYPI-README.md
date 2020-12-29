[![GitHub license](https://img.shields.io/github/license/srounet/pymem.svg)](https://github.com/srounet/Pymem/)
[![Build status](https://ci.appveyor.com/api/projects/status/sfdvrtuh9qa2f3aa/branch/master?svg=true)](https://ci.appveyor.com/project/srounet/pymem/branch/master)
[![codecov](https://codecov.io/gh/srounet/Pymem/branch/master/graph/badge.svg)](https://codecov.io/gh/srounet/Pymem/branch/master)
[![Discord](https://img.shields.io/discord/342944948770963476.svg)](https://discord.gg/xaWNac8)
[![Documentation Status](https://readthedocs.org/projects/pymem/badge/?version=latest)](https://pymem.readthedocs.io/?badge=latest)

Pymem
=====

A python library to manipulate Windows processes (32 and 64 bits).  
With pymem you can hack into windows process and manipulate memory (read / write).

Documentation
=============
You can find pymem documentation on readthedoc there: http://pymem.readthedocs.io/

Discord Support
=============
For questions and support, join us on discord https://discord.gg/xaWNac8

Examples
========
You can find more examples from the community in the [Examples from the community](https://pymem.readthedocs.io/en/documentation/examples/index.html) of pymem documentation.

Listing process modules
-----------------------

````python
import pymem

pm = pymem.Pymem('python.exe')
modules = list(pm.list_modules())
for module in modules:
    print(module.name)
````

Injecting a python interpreter into any process
-----------------------------------------------

`````python
from pymem import Pymem

notepad = subprocess.Popen(['notepad.exe'])

pm = pymem.Pymem('notepad.exe')
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
`````
