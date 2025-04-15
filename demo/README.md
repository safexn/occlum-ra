# Use Rust with Occlum

This directory contains scripts and source code to demonstrate how to
compile and run Rust programs on Occlum.

# how to start rust-app in Occlum in HW mode

For deployment purpose, `dockerfile.deploy` is provided to build a image with the smallest size for deployment environment.

Size comparison:

dev: 10.2G

deploy: 1500M  

#### use proxy when build
```
docker build --network=host xxxxxxxxx --build-arg http_proxy=http:127.0.0.1:7980 --build-arg https_proxy=http:127.0.0.1:7980
```

## 1. Copy Dockerfile to tkms root directory 
dev:

`cp ./occlum/servers/rust_app/Dockerfile ./`

deploy:

`cp ./occlum/servers/rust_app/Dockerfile.deploy ./`



## 2. build image
dev:

`docker build -f Dockerfile . -t rust-app-dev:latest`

deploy:

`docker build -f Dockerfile.deploy . -t rust-app-deploy:latest`

## 3. start
dev:

`docker run --net=host --env RUST_LOG=debug --name="rust-app-dev" --device /dev/sgx/enclave --device /dev/sgx/provision rust-app-dev:latest`

deploy:

`docker run --net=host --env RUST_LOG=debug --name="rust-dcap" --device /dev/sgx/enclave --device /dev/sgx/provision prz1992/rust-dcap:latest bash -c "source /root/.bashrc; cd /root/occlum_instance; occlum run /bin/rust_app"`

## 4. copy config into container
dev:

```
docker stop rust-app-dev
docker cp ./key_config.toml rust-app-dev:/RUST/occlum/servers/occlum_instance 
docker start rust-app-dev
```

deploy:

```
docker stop rust-app-deploy
docker cp ./key_config.toml rust-app-deploy:/root/occlum_instance
docker start rust-app-deploy
```

## 5 log
`docker logs -f rust-app-deploy`

## 6 Check if it start successfully
`curl -d "aaa" -k http://localhost:port/sign`


## DEV

first pull docker images:
```
docker pull occlum/occlum:0.29.1-ubuntu20.04
```
then start docker:
```
docker run --net=host -it --rm --device /dev/sgx/enclave --device /dev/sgx/provision occlum/occlum:0.29.1-ubuntu20.04
```
or
```
docker run --net=host -it --rm occlum/occlum:0.29.1-ubuntu20.04

```
This directory contains source code of a Rust program with a cpp FFI. The cpp
interface increments the input by one. Rust code calls the function and
displays the result on the terminal.

One can use occlum-cargo in the way cargo is used. In the rust\_app directory,
calling ```occlum-cargo build``` will build the demo and ```occlum-cargo run```
will run the demo on host. To run the demo in occlum, run:
```
run_rust_demo_on_occlum.sh
```

sim mod :
```
SGX_MODE=SIM ./run_rust_demo_on_occlum.sh
```


