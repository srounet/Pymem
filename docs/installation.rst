.. _installation:

Installation
============

Pymem depends on some external libraries, like `pyfasm
<http://github.com/srounet/fasm>`_.
Pyfasm is a wrapper around `Flat Assembler <http://flatassembler.net/>`_ and
in its current state only works with x86.

Pyfasm is available on `pypi <https://pypi.python.org/pypi/pyfasm>`_ and
is part of Pymem requirements.txt. The most straightforward method to start
working with Pymem is to use a virtualenv.

You will need Python 3 or newer to get started, so be sure to have an
up-to-date Python 3.x installation.

.. _virtualenv:
Virtualenv
----------

Virtualenv is probably what you want to use during development, and if you have
shell access to your production machines, you'll probably want to use it there,
too.

Virtualenv enables multiple side-by-side installations of Python, one for each
project. It doesn't actually install separate copies of Python, but it does
provide a clever way to keep different project environments isolated.

We will not cover the installation of neither pip or virtualenv here, so
install them first.

Once you have virtualenv installed, just fire up a shell and create
your own environment::

    $ mkdir myproject
    $ cd myproject
    $ virtualenv pymem
    New python executable in pymem/bin/python
    Installing setuptools, pip............done.

Now, whenever you want to work on a project, you only have to activate the
corresponding environment::

    $ pymem\scripts\activate.bat


And if you want to go back to the real world, use the following command::

    $ deactivate

After doing this, the prompt of your shell should be as familiar as before.

Now, let's move on. Enter the following command to get Pymem activated in your
virtualenv::

    $ pip install pymem

A few seconds later and you are good to go.