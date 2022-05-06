# Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE.
- only debug and release are expected in the Cmakelists.txt. If you need a different config, please follow the model in that file to add it.

- vcpkg does not have boringssl, so you'll have to build it yourself. Follow the instructions at the boringssl repository.
  With the caveat that you should do it from a VC command prompt for the correct architecture and make sure to set all 
  the paths for perl,ninja,etc. correctly. Also watch out for C runtime library mismatches with the externals you link.


- zlib and libevent do exist in vcpkg. 

- getopt files are really old and could probably use updating.