Listing process modules
=======================

Pymem comes with somes process utilities like listing loaded modules.

Here is a snippet that will list loaded process modules


.. code-block:: python

    import pymem

    pm = pymem.Pymem('python.exe')
    modules = list(pm.list_modules())
    for module in modules:
        print(module.name)

So what did that code do?

1. we hook pymem with python.exe process
2. we retrieve the list of loaded modules
3. for every module listed, we display its name

note: every `module` is an instance of :meth:`~pymem.ressources.structure.MODULEINFO`
