LiteSpeed QUIC (LSQUIC) Client Library - Building for Windows
=============================================================

Description
-----------

This document is intended to supplement the document README.md at the
root of the distribution of the LiteSpeed QUIC (LSQUIC) Client Library
to build the library and programs in a Windows environment.  

The addition of Windows support to the LSQUIC Client was a contribution 
from the user community and this document was based on our experiences
of validating the code.  As for the overall implementation, do not hesitate
to report bugs back to us.  Even better, continue to send us fixes and 
improvements - it makes the code better for everyone.


Preliminaries
-------------
It it recommended that the installer have experience with Windows development,
Visual Studio, and open source projects in Windows.  These instructions assume
a general build, primarily for 64-bit, both of a debug and a release version.

Some open source code required to be installed to build the code include:
   - The [Git version control system executable for Windows](https://git-scm.com/download/win).
   - A version of the Visual Studio development environment for Windows.  
     The Windows SDK and C++ must be installed from it.  The 
     [Visual Studio Community Edition](https://www.visualstudio.com/thank-you-downloading-visual-studio) will be just fine.
   - [cmake for Windows](https://cmake.org/download/).  Download and install the 
     version appropriate for the development/target platform (32 vs 64-bits, 
     etc.).
   - The Windows vcpkg package manager.  It can be cloned from [here](https://github.com/Microsoft/vcpkg).
     Clone it at the same level to be used to clone/develop the lsquic-client.
     The package must be compiled following the instructions on the git 
     repository.  
   - Once the package manager has been built, it must be used to install
     and build some open source projects.  Before doing that, an environment 
     variable must be defined which specifies how the package should be built.
     The easiest way would be to add it into the system environment variables
     in the System applet of the Windows Control Panel.  This example assumes 
     64-bit static libraries will be built, which is what is generally 
     recommended:
        ```
        VCPKG_DEFAULT_TRIPLET=x64-windows-static
        ```
   - From the command line, once the variable above has been defined, install
     both *zlib* and *libevent*.  Note that libevent may also automatically 
     install *openssl*.  If it does not, it may need to be manually specified 
     to properly link the lsquic-client executables.
        ```
        vcpkg install zlib
        vcpkg install libevent
        ```
   - Clone and compile boringssl.  It can be cloned from [here](https://boringssl.googlesource.com/boringssl) 
     and should be cloned at the same level to be used to clone/develop 
     the lsquic-client.  Once cloned, cmake must be run to create the projects 
     (the dot at the end of the line is required):
        ```
        cmake -DCMAKE_GENERATOR_PLATFORM=x64 --config Debug -DBUILD_SHARED_LIBS=OFF -DOPENSSL_NO_ASM=1 .
        ```
   - Visual Studio can be run, and the project opened within the boringssl
     directory.  Set the solution configuration to *Debug* and the solution 
     platform to *64-bit*.  Compile the project.
   - Repeat the cmake and compile steps replacing *Debug* with *Release*.

Make and Compile LSQUIC-Client
------------------------------

The LSQUIC-Client for Windows is currently housed on the master branch.  
To check it out specify (from the directory where the code will be housed):
   ```
   git clone https://github.com/litespeedtech/lsquic-client.git
   cd lsquic-client
   git checkout master
   ```

cmake must be run to prepare to build the software in the top level
cloned directory.  The dot at the end is required.  Begin with the debug
version as it includes all of the programs.
   ```
   cmake -DCMAKE_GENERATOR_PLATFORM=x64 --config Debug -DBUILD_SHARED_LIBS=OFF -DDEVEL_MODE=1 .
   ```

Visual Studio can now be brought up, and there will be projects in the
cloned directory.  The ALL_BUILD project will build the full project.
Make sure the solution configuration is set to *Debug*.  The project may
need to be built twice as the first time some of the compiles will fail
as the lsquic.lib library has not completed building in the first attempt.

Both the debug and optmized versions can co-exist in the same 
environment as they are compiled to different directories.

To build the optimized version, repeat the process above with a slightly
different cmake command:
   ```
   cmake -DCMAKE_GENERATOR_PLATFORM=x64 --config Release -DBUILD_SHARED_LIBS=OFF -DDEVEL_MODE=0 .
   ```

After cmake has finished, you can open the project, set the solution 
configuration to *Release* and build the ALL_BUILD project.  There are 
many fewer programs in the optimized version.

Have fun,

LiteSpeed QUIC Team.

Copyright (c) 2017-2018 LiteSpeed Technologies Inc
