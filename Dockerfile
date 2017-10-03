FROM ubuntu:16.04

RUN apt-get update && \
    apt-get install -y build-essential git cmake software-properties-common \
                       zlib1g-dev libevent-dev

RUN add-apt-repository ppa:gophers/archive && \
    apt-get update && \
    apt-get install -y golang-1.9-go && \
    cp /usr/lib/go-1.9/bin/go* /usr/bin/.

RUN mkdir /src
WORKDIR /src

RUN git clone https://boringssl.googlesource.com/boringssl && \
    cd boringssl && \
    git checkout chromium-stable && \
    cmake . && \
    make && \
    BORINGSSL_SOURCE=$PWD && \
    cd /usr/local/lib && \
    cp $BORINGSSL_SOURCE/ssl/libssl.a . && \
    cp $BORINGSSL_SOURCE/crypto/libcrypto.a .

RUN mkdir /src/lsquic-client
COPY ./ /src/lsquic-client/
RUN cd /src/lsquic-client && \
    cmake -DBORINGSSL_INCLUDE=/src/boringssl/include \
          -DBORINGSSL_LIB=/usr/local/lib . && \
    make

RUN cd lsquic-client && make test && cp http_client /usr/bin/
