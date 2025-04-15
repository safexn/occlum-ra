
mkdir -p /var/run/aesmd && echo '/opt/occlum/start_aesm.sh' >> /root/.bashrc
LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service &

cd occlum_instance
occlum run /bin/rust_app