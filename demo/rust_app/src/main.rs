use occlum_ra;

use occlum_ra::{generate_cert_key, generate_epid, get_fingerprint, get_fingerprint_ex, get_fingerprint_epid, verify_cert};
use std::time::{SystemTime, UNIX_EPOCH};
use occlum_ra::attestation::{AttestationReport, AttestationStyle, IasAttestation};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    env_logger::init();

    // let read_result = std::fs::read_to_string("/host/test.config").unwrap();
    // println!("read_result {:?}",read_result);

    println!("start");
    let cert_der = match generate_cert_key() {
        Err(e) => panic!("error: {:?}", e),
        Ok((a, b)) => b,
    };

    let res = verify_cert(&cert_der);

    println!("verify_cert result {:?}", res);

    let result = IasAttestation::create_report("epid".as_bytes()).unwrap();
    let epid_attestation = AttestationReport{
        style: AttestationStyle::EPID,
        data: result.into_payload()
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let result = IasAttestation::verify(&epid_attestation,now);
    println!("verify epid result {:?}", result);

    let fingerprint = get_fingerprint_epid(2);
    println!("fingerprint {:?}",fingerprint);
    let fingerprint = get_fingerprint(2);
    println!("fingerprint {:?}",fingerprint);
    let key_policy = vec![1u16, 2, 4, 8, 10, 20];
    let key_name = vec![0u16, 1, 2, 3, 4];
    let flag = vec![0u16, 1];
    for name in key_name {
        for policy in key_policy.clone() {
            let fingerprint = get_fingerprint_ex(name, policy, flag);
            if fingerprint != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
                println!("name {} policy {} fingerprint {:?}", name, policy, fingerprint);
            }
        }
    }
}
