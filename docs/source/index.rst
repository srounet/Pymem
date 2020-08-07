.. rst-class:: hide-header

.. pymem documentation master file, created by
   sphinx-quickstart on Fri May 25 04:41:43 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Pymem's documentation!
=================================

Welcome to Pymem’s documentation.
Get started with :doc:`installation` and then get an overview with the :doc:`quickstart`.
There is also a more detailed :doc:`tutorials/index` section that shows how to write small software with Pymem.
The rest of the docs describe each component of Pymem in detail, with a full reference in the :doc:`api` section.

Except for running tests or buliding the documentation, Pymem does not require any library it only manipulate
ctypes_ and more precisely WinDLL_.

The structure of this documentation is based on Flask_.

.. _WinDLL: https://docs.python.org/3.6/library/ctypes.html?highlight=ctypes%20windll#ctypes.WinDLL
.. _ctypes: https://docs.python.org/3.6/library/ctypes.html
.. _Flask: https://flask.palletsprojects.com/


User's Guide
------------

This part of the documentation, which is mostly prose, begins with some
background information about Pymem, then focuses on step-by-step
instructions for reversing with Pymem.

.. toctree::
   :maxdepth: 1

   foreword
   installation
   quickstart
   tutorials/index

API Reference
-------------

If you are looking for information on a specific function, class or
method, this part of the documentation is for you.

.. toctree::
   :maxdepth: 2

   api

Additional Notes
----------------

Design notes, legal information and changelog are here for the interested.

.. toctree::
   :maxdepth: 2

   license
   contributing
