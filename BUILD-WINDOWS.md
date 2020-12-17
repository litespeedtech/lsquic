LiteSpeed QUIC (LSQUIC) Library - Building for Windows
======================================================

Description
-----------

This document is intended to supplement the document README.md at the
root of the distribution of the LiteSpeed QUIC (LSQUIC) Library
to build the library and programs in a Windows environment.  

The addition of Windows support to the LSQUIC was a contribution 
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
     Clone it at the same level to be used to clone/develop the lsquic.
     The package must be compiled following the instructions on the git 
     repository.
   - Perform builds using the _Developer Command Prompt for Visual Studio_ instead
     of the regular `cmd.exe`.
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
     to properly link the lsquic executables.
        ```
        vcpkg install zlib:x64-windows-static
        vcpkg install libevent:x64-windows-static
        vcpkg integrate install
        ```
   - Clone and compile boringssl.  It can be cloned from [here](https://boringssl.googlesource.com/boringssl).
   
        ```
        git clone https://boringssl.googlesource.com/boringssl
        cd boringssl
        cmake -DCMAKE_GENERATOR_PLATFORM=x64 --config Debug -DBUILD_SHARED_LIBS=OFF -DOPENSSL_NO_ASM=1 .
        msbuild ALL_BUILD.vcxproj
        set boringssl=%cd%
        ```
   - Visual Studio can be run, and the project opened within the boringssl
     directory.  Set the solution configuration to *Debug* and the solution 
     platform to *64-bit*.  Compile the project.
   - Repeat the cmake and compile steps replacing *Debug* with *Release*.

Make and Compile LSQUIC
-----------------------


Clone lsquic:

   ```
   git clone https://github.com/litespeedtech/lsquic.git --recurse-submodules
   cd lsquic
   ```

Configure the build using cmake (you can specify `Release` instead of `Debug`
to build an optimized version of the library, but that won't build tests):

   ```
   cmake -DCMAKE_GENERATOR_PLATFORM=x64 -DBUILD_SHARED_LIBS=OFF ^
        -DVCPKG_TARGET_TRIPLET=x64-windows-static -DCMAKE_BUILD_TYPE=Debug ^
        -DCMAKE_TOOLCHAIN_FILE=c:/tools/vcpkg/scripts/buildsystems/vcpkg.cmake ^
        -DBORINGSSL_DIR=%boringssl% .
   ```

Compile everything (add `/m` flag if you have processors to spare):

   ```
   msbuild ALL_BUILD.vcxproj
   ```

`http_client.exe` should be found in the `Debug` (or `Release`) directory.
   
Run tests (assuming `Debug` build):

   ```
   msbuild RUN_TESTS.vcxproj
   ```

Have fun,

LiteSpeed QUIC Team.

Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc
