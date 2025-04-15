#!/bin/bash
set -e

# compile rust_app
pushd rust_app
occlum-cargo build
popd

# initialize occlum workspace
rm -rf occlum_instance && mkdir occlum_instance && cd occlum_instance

occlum init && rm -rf image
#cp -r ../rust_app/Occlum.json ../occlum_instance/
new_json="$(jq '.resource_limits.user_space_size = "2000MB" |
                .process.default_mmap_size = "2500MB" |
                .resource_limits.kernel_space_heap_size = "2400MB" |
                .resource_limits.kernel_space_stack_size = "20MB" |
                .process.default_stack_size = "50MB" |
                .process.default_heap_size = "340MB"' Occlum.json)" && \
echo "${new_json}" > Occlum.json

copy_bom -f ../rust-demo.yaml --root image --include-dir /opt/occlum/etc/template

occlum build
occlum run /bin/rust_app