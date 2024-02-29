FROM ubuntu:20.04 as build-lsquic

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y apt-utils build-essential git cmake software-properties-common \
                       zlib1g-dev libevent-dev

RUN add-apt-repository ppa:longsleep/golang-backports && \
    apt-get update && \
    apt-get install -y golang-1.21-go && \
    cp /usr/lib/go-1.21/bin/go* /usr/bin/.

ENV GOROOT /usr/lib/go-1.21

RUN mkdir /src
WORKDIR /src

RUN mkdir /src/lsquic
COPY ./ /src/lsquic/

RUN git clone https://github.com/google/boringssl.git && \
    cd boringssl && \
    git checkout 9fc1c33e9c21439ce5f87855a6591a9324e569fd && \
    cmake . && \
    make

ENV EXTRA_CFLAGS -DLSQUIC_QIR=1
RUN cd /src/lsquic && \
    cmake -DBORINGSSL_DIR=/src/boringssl . && \
    make

RUN cd lsquic && cp bin/http_client /usr/bin/ && cp bin/http_server /usr/bin

FROM martenseemann/quic-network-simulator-endpoint:latest as lsquic-qir
COPY --from=build-lsquic /usr/bin/http_client /usr/bin/http_server /usr/bin/
COPY qir/run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]
