Quickstart
==========

Eager to get started? This page gives a good introduction to Pymem.
Follow :doc:`installation` to set up a project and install Pymem first.

A Minimal Application
---------------------

A minimal Pymem application looks something like this:

.. code-block:: python

    from pymem import Pymem

    pm = Pymem('notepad.exe')
    print('Process id: %s' % process_id)
    address = pm.allocate(10)
    print('Allocated address: %s' % address)
    pm.write_int(address, 1337)
    value = pm.read_int(address)
    print('Allocated value: %s' % value)
    pm.free(address)

So what did that code do?

1.  First we imported the :class:`~pymem.Pymem` class. An instance of
    this class will be our win32api wrapper
2.  Next we create an instance of this class. The first argument is the
    name of the windows process we want to hook into.

    Be aware that after creating an instance of Pymem with the process name as
    an argument, the process will be opened with debug mode flags.
3.  We then allocate 10 bytes into given _notepad.exe_ process with :meth:`~pymem.Pymem.allocate`.
4.  For the example we then write an integer with :meth:`~pymem.Pymem.write_int` and read it with :meth:`~pymem.Pymem.read_int`.
5.  We then free memory from the current opened process at the given address with :meth:`~pymem.Pymem.free`.

Save it as :file:`hello.py` or something similar. Make sure to not call
your application :file:`pymem.py` because this would conflict with Pymem
itself.

To run the application, first start `notepad.exe` be sure to have pymem installed within your current
python environment and simply execute your script.

.. code-block:: sh

    $ python hello.py
      Process id: 2345
      Allocated address: 123456789
      Allocated value: 1337

