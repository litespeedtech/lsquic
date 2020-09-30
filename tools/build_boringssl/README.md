# Build and install BoringSSL locally

LSQUIC depends on BoringSSL (for now, see [this issue](https://github.com/litespeedtech/lsquic/issues/96#issuecomment-698598577) about OpenSSL), but BoringSSL is not meant as a drop-in replacement at the distro level. This means that BoringSSL must be built locally.

An easy way to do that with CMake is to install BoringSSL locally, and to point `CMAKE_PREFIX_PATH` to this installation (which could contain other dependencies). That's exactly the purpose of this directory. Note that we patch BoringSSL, because it does not have any CMake install target.

First, run the cmake configure command, specifying where BoringSSL should be installed (here we put it in "./install/"):

```sh
cmake -DCMAKE_INSTALL_PREFIX=install -Bbuild -S.
```

Note that with older cmake versions (e.g. on Ubuntu 18.04), `-S.` should actually be `-H.`. It is up to the reader to figure that out.

Once this is done, we can run the cmake build step. It will fetch BoringSSL, patch it, build it and install it:

```sh
cmake --build build
```

If the process succeeds, BoringSSL should be installed in "./install/":

```
% tree install
install
├── include
│   └── openssl
│       ├── aead.h
│       ├── aes.h
│       ├── <many other header files>
└── lib
    ├── libcrypto.a
    ├── libdecrepit.a
    └── libssl.a
```

When building LSQUIC from the root of this repository, we will then tell CMake to go look for BoringSSL in this folder, with something like:

```sh
cmake -DCMAKE_PREFIX_PATH=tools/build_boringssl/install -Bbuild -S.
```
