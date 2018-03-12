- vcpkg does not have boringssl, so you'll have to build it yourself. Follow the instructions at the boringssl repository.
  With the caveat that you should do it from a VC command prompt for the correct architecture and make sure to set all 
  the paths for perl,ninja,etc. correctly. Also watch out for C runtime library mismatches. The easiest fix for me was to
  change the flags in the CMake cache file.

- zlib and libevent do exist in vcpkg. 

- getopt files are really old and could probably use updating.