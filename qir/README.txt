# Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE.
This directory contains files necessary to build Docker container
for use with the QUIC Interop Runner [a].

Build Instructions
------------------

1. Generate source tarball. No longer needed.

The source tarball is what Docker will use to build the image.
To generate the tarball, we use git-archive-all program as
follows:

    sh$ git-archive-all -C $LSQUIC_REPO_PATH --prefix=lsquic lsquic.tar

git-archive-all can be installed via pip
    pip/pip3 install git-archive-all

2. Build the builder image.

This image is based on Ubuntu 20 and in the end will contain
compiled lsquic server and client programs, http_server and
http_client.

The purpose of this Docker image is to be used as the source
for these binaries when building the final image.

    sh$ docker build -f qir/Dockerfile.build -t build-lsquic .

3. Build the final image.

The final image combines the lsquic binaries and run_endpoint.sh
script, which is where the magic (or, to be frank, hairy hackery)
happens to run lsquic server and client based on environment
variables set by the QUIC Interop Runner.

    sh$ docker build -f qir/Dockerfile.final -t try-lsquic .


a. https://github.com/marten-seemann/quic-interop-runner
