
Build lsquic.a
==============
-----------------------------------------------------------------------
1. First replce the CMakeList_iOS.txt to lsquic root path CMakeList,txt
```
cmake -DBORINGSSL_INCLUDE=$BORINGSSL_SOURCE/include -DBORINGSSL_LIB=$HOME/tmp/boringssl-libs -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=arm64 .

cmake -DBORINGSSL_INCLUDE=$BORINGSSL_SOURCE/include -DBORINGSSL_LIB=$HOME/tmp/boringssl-libs -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=armv7s .

cmake -DBORINGSSL_INCLUDE=$BORINGSSL_SOURCE/include -DBORINGSSL_LIB=$HOME/tmp/boringssl-libs -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_OSX_ARCHITECTURES=i386 .

cmake -DBORINGSSL_INCLUDE=$BORINGSSL_SOURCE/include -DBORINGSSL_LIB=$HOME/tmp/boringssl-libs -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_OSX_ARCHITECTURES=x86_64 .
```
then lipo arm64, armv7, armv7s, i386, x86_64 to create one static library.

----------------------------------------------
2. The lsquic.a Depends on BoringSSL and libz.

To run libz.sh to create a libz.a on iOS.

BoringSSL can use BoringSSL pods project

write Podfile blew:
```
platform:ios, "9.0"
target 'QuicClientTest' do
    pod 'BoringSSL', '~> 9.1'
end
```
-------------------------------------------------------------------------
3. Also if you need run the demo project you also need a libevent on iOS.

The libevent build script is libevent.sh. Ofcourse you need do some change.

--------------------------------------------------------------------------------------------
4. lsquic.a libz.a libevent.a is already build in the demo project , You can direct use it .

Have fun.
