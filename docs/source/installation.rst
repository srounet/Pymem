Installation
============

Pymem has no dependencies and works on both x86 and x64 architecture.

You will need Python 3 or newer to get started, so be sure to have an up-to-date Python 3.x installation.

If you are familiar with pyenv_, it is highly recommended to sandbox pymem installation within a custom virtualenv.

.. _pyenv: https://github.com/pyenv/pyenv

Path
----

In order to use all pymem fonctionalities you have to first make sure that system python directory is configured within
windows system PATH.

In a PowerShell window type:

.. code-block:: sh

    $env:PATH

This PATH should contain the directory where python is installed system wide or at least have access to pythonXX.dll
If you don't find python in your PATH, then it is recommended to add it.

.. code-block:: sh

    - Open the Start Search, type in "env", and choose "Edit the system environment variables"
    - Click the "Environment Variables..." button
    - Under the "System Variables" section (the lower half), find the row with "Path" in the first column, and click edit.
    - The "Edit environment variable" UI will appear. Here, you can click "New" and type in the new path you want to add.
    - Add your python path and close the windows (something like: C:\Users\xxx\AppData\Local\Programs\Python\Python38)

Virtual environments
--------------------

Use a virtual environment to manage the dependencies for your project, both in
development and in production.

What problem does a virtual environment solve? The more Python projects you
have, the more likely it is that you need to work with different versions of
Python libraries, or even Python itself. Newer versions of libraries for one
project can break compatibility in another project.

Virtual environments are independent groups of Python libraries, one for each
project. Packages installed for one project will not affect other projects or
the operating system's packages.

Python comes bundled with the :mod:`venv` module to create virtual
environments.

.. _install-create-env:

Create an environment
~~~~~~~~~~~~~~~~~~~~~

Create a project folder and a :file:`venv` folder within:

.. code-block:: sh

    $ mkdir myproject
    $ cd myproject
    $ python3 -m venv venv

On Windows:

.. code-block:: bat

    $ py -3 -m venv venv


.. _install-activate-env:

Activate the environment
~~~~~~~~~~~~~~~~~~~~~~~~

Before you work on your project, activate the corresponding environment:

.. code-block:: sh

    $ . venv/bin/activate

On Windows:

.. code-block:: bat

    > venv\Scripts\activate

Your shell prompt will change to show the name of the activated
environment.

Install Pymem
-------------

Within the activated environment, use the following command to install
Pymem:

.. code-block:: sh

    $ pip install pymem

Pymem is now installed. Check out the :doc:`/quickstart` or go to the
:doc:`Documentation Overview </index>`.
