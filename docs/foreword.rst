Foreword
========

Read this before you get started with Pymem. This hopefully answers some
questions about the purpose and goals of the project, and then why you
should and should not be using it.

Why Pymem ?
-----------

I decided to build pymem after some reading of the wonderfull book `Gray Hat Python <http://www.nostarch.com/ghpython.htm>`_
by Justin Seitz, which I recommend as a first reading before even starting
using Pymem.
The book covers the win32api and important aspects of debuggers.
As I wanted to learn more on debugging, hooking and the windows
API, I figured out that writing a library was the perfect project.


Pymem history
-------------


So back in 2010, with my little knowledge of Python I wrote the first version
of this library (which has been entirely rewritten since). I figured out that
most of the resources you can find covering C, C++, C# of the windows API
works "as it" using python ctypes without any effort, so I decided to wrap
some of them into Pymem.

In 2015, I decided to rebirth the library, and to rewrite it using
python3. The library is a toolbox for process memory manipulations, it
supports memory reads, write and even assembly injection (thanks to `pyfasm <http://github.com/srounet/pyfasm>`_).

Why and when using Pymem
------------------------

Pymem has been built to reverse games such as `Worlf of Warcraft`, so if you plan to write a bot for this kind of game,
you're in the right place. You can also use pymem to do injections, assembly, memory pattern search and a lot more.

You should head over the tutorials and see what Pymem is capable of!



Continue to :ref:`installation` , the :ref:`quickstart` or :ref:`tutorial/index`.