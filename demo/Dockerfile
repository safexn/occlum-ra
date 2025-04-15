FROM occlum/occlum:0.29.1-ubuntu20.04

WORKDIR /RUST

COPY ./occlum-ra ./occlum-ra
COPY ./rust_app ./rust_app
COPY ./gmp_musl.sh ./
COPY ./run_rust_demo_on_occlum_docker.sh ./
COPY ./rust-demo.yaml ./

WORKDIR /RUST

RUN chmod +x ./run_rust_demo_on_occlum_docker.sh
RUN ./run_rust_demo_on_occlum_docker.sh
RUN cd occlum_instance && occlum package --debug
WORKDIR /RUN
RUN cp /RUST/occlum_instance/occlum_instance.tar.gz . &&\
    tar -xvzf occlum_instance.tar.gz
RUN    mkdir -p /var/run/aesmd && \
    echo "LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm nohup /opt/intel/sgx-aesm-service/aesm/aesm_service --no-daemon >/dev/null 2>&1 &" > /root/.bashrc



WORKDIR /RUN