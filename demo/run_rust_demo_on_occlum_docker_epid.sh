#!/bin/bash
set -e

# build gmp-musl
#chmod +x ./gmp_musl.sh
#./gmp_musl.sh

# compile rust_app
pushd rust_app
occlum-cargo build
popd

# initialize occlum workspace
rm -rf occlum_instance && mkdir occlum_instance && cd occlum_instance

cp ../occlum_build.mk /opt/occlum/build/bin/occlum_build.mk

occlum init && rm -rf image
cp -r ../rust_app/Occlum.json ../occlum_instance/
cp ../Enclave.xml ../occlum_instance/
cp ../rust_app/sgx_default_qcnl.conf /etc
copy_bom -f ../rust-demo.yaml --root image --include-dir /opt/occlum/etc/template

occlum build