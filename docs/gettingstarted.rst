Getting Started
===============

Supported Platforms
-------------------

LSQUIC compiles and runs on Linux, Windows, FreeBSD, Mac OS, and Android.
It has been tested on i386, x86_64, and ARM (Raspberry Pi and Android).

Dependencies
------------

LSQUIC library uses:

- zlib_;
- BoringSSL_; and
- `ls-hpack`_ (as a Git submodule).
- `ls-qpack`_ (as a Git submodule).

The accompanying demo command-line tools use libevent_.

What's in the box
-----------------

- ``src/liblsquic`` -- the library
- ``bin`` -- demo client and server programs
- ``tests`` -- unit tests

Building
--------

To build the library, follow instructions in the README_ file.

Demo Examples
-------------

Fetch Google home page:

::

    ./http_client -s www.google.com -p / -o version=Q050

Run your own server (it does not touch the filesystem, don't worry):

::

    ./http_server -c www.example.com,fullchain.pem,privkey.pem -s 0.0.0.0:4433

Grab a page from your server:

::

    ./http_client -H www.example.com -s 127.0.0.1:4433 -p /

You can play with various options, of which there are many.  Use
the ``-h`` command-line flag to see them.

More about LSQUIC
-----------------

You may be also interested in this presentation_ about LSQUIC.
Slides are available `here <https://github.com/dtikhonov/talks/tree/master/netdev-0x14>`_.

Next steps
----------

If you want to use LSQUIC in your program, check out the :doc:`tutorial` and
the :doc:`apiref`.

:doc:`internals` covers some library internals.

.. _zlib: https://www.zlib.net/
.. _BoringSSL: https://boringssl.googlesource.com/boringssl/
.. _`ls-hpack`: https://github.com/litespeedtech/ls-hpack
.. _`ls-qpack`: https://github.com/litespeedtech/ls-qpack
.. _libevent: https://libevent.org/
.. _README: https://github.com/litespeedtech/lsquic/blob/master/README.md
.. _presentation: https://www.youtube.com/watch?v=kDwyGNsQXds
