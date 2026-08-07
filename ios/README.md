
Build lsquic.a
==============
-----------------------------------------------------------------------

BoringSSL
---------

1.First Clone BoringSSL then Copy CMakeLists.txt libboringssl.sh in ios dir 
to your BORINGSSL_SOURCE dir.

```
git clone https://boringssl.googlesource.com/boringssl
cd boringssl

git checkout chromium-stable

cp ${LSQUIC_SOURCE}/ios/boringssl/CMakeLists.txt ${BORINGSSL_SOURCE}/

cp ${LSQUIC_SOURCE}/ios/boringssl/libboringssl.sh ${BORINGSSL_SOURCE}/

./libboringssl.sh

```
2.Copy the libcrypto.a libssl.a to Your path

```
cd ${LSQUIC_SOURCE}

lipo -info output/lib/libcrypto.a

lipo -info output/lib/libssl.a

cp output/lib/libcrypto.a ${LSQUIC_SOURCE}/ios/QuicClientTest/QuicClientTest/

cp output/lib/libcrypto.a ${LSQUIC_SOURCE}/ios/QuicClientTest/QuicClientTest/

```

libz
----
compile libz

```
cd ${LSQUIC_SOURCE}/ios

./libz.sh

cp ios/prefix/libz_all.a QuicClientTest/QuicClientTest/libz.a

```

libevent
--------
libevent is for the demo run, so we need a libevent run on iOS
compile libevent

```
cd ${LSQUIC_SOURCE}/ios

./libevent.sh

cp dependencies/lib/libevent.a QuicClientTest/QuicClientTest/

```

lsquic.a
--------
complie lsquic.a

```
cd ${LSQUIC_SOURCE}

cp ios/liblsquic.sh .

vi liblsquic.sh //change BORINGSSL_INCLUDE and BORINGSSL_LIB with your path

./liblsquic.sh

cp output/lib/liblsquic.a ios/QuicClientTest/QuicClientTest/

```

Open QuicClientTest workspace with xcode
----------------------------------------
open QuicClientTest.xcworkspace run the demo Click start button.


Have fun.
