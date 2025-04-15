#!/bin/bash
set -e

#install env
apt update && apt install -y clang

wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.bz2 && tar -xjf gmp-6.2.1.tar.bz2

PREFIX=/opt/occlum/toolchains/gcc/x86_64-linux-musl
export PATH="/usr/local/occlum/bin:$PATH"

pushd gmp-6.2.1
CC=occlum-gcc CXX=occlum-g++ ./configure --prefix=$PREFIX
make
make install
popd
