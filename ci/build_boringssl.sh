#!/bin/sh
#build last boringssl master (for Travis)

cd ..
git clone --depth 1 https://boringssl.googlesource.com/boringssl
cd boringssl
git checkout chromium-stable
mkdir build
cd build
cmake ..
make -j$(nproc)
BORINGSSL_SOURCE=$PWD
echo $BORINGSSL_SOURCE
mkdir -p $HOME/tmp/boringssl-libs
cd $HOME/tmp/boringssl-libs
ln -s $BORINGSSL_SOURCE/ssl/libssl.a
ln -s $BORINGSSL_SOURCE/crypto/libcrypto.a
