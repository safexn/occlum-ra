 // This file is part of BoolNetwork.
 
 // Copyright (C) BoolNetwork (HK) Ltd.
 // SPDX-License-Identifier: Apache-2.0
 
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
 // You may obtain a copy of the License at
 
 // 	http://www.apache.org/licenses/LICENSE-2.0
 
 // Unless required by applicable law or agreed to in writing, software
 // distributed under the License is distributed on an "AS IS" BASIS,
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(dead_code)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::char_lit_as_u8)]
#![allow(unused_imports)]
#![allow(clippy::or_fun_call)]

pub mod attestation;
pub mod dcap;
pub mod epid_occlum;
#[cfg(feature = "std")]
pub mod ias;
#[cfg(feature = "std")]
pub mod occlum_dcap;
#[cfg(feature = "std")]
pub mod tls;
pub mod verify;

use attestation::{DcapAttestation, EnclaveFields};
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};
pub use verify::{verify, verify_only_report};

#[cfg(feature = "std")]
extern crate occlum_dcap as occlum;
#[cfg(feature = "std")]
use occlum::sgx_report_data_t;

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;
#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
extern crate core;

/// return (key_der,cert_der)
#[cfg(feature = "std")]
pub fn generate_cert_key() -> Result<(Vec<u8>, Vec<u8>), String> {
    tls::generate_cert("".to_string())
}

/// verify cert_der
#[cfg(feature = "std")]
pub fn verify_cert(cert: &[u8]) -> Result<EnclaveFields, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    verify(cert, now)
}

/// create dcap report with additional info
#[cfg(feature = "std")]
pub fn create_dcap_report(additional_info: Vec<u8>) -> Result<Vec<u8>, String> {
    let report = match DcapAttestation::create_report(&additional_info) {
        Ok(r) => r,
        Err(_) => return Err("create_report fail".to_string()),
    };
    Ok(report.into_payload())
}

/// verify dcap report with additional info and return (mr_enclave.m,report_data.d)
#[cfg(feature = "std")]
pub fn verify_dcap_report(report: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    verify_only_report(&report, now)
}

#[cfg(feature = "std")]
pub fn get_fingerprint_epid(key_policy: u16) -> Vec<u8> {
    let mut epid = occlum::EpidQuote::new();
    let target_info = epid.get_target_info();
    let report_data = sgx_report_data_t::default();
    let epid_report = epid.get_epid_report(&target_info, &report_data);

    occlum::get_key(&epid_report.body, key_policy).to_vec()
}

#[cfg(feature = "std")]
pub fn get_fingerprint(key_policy: u16) -> Vec<u8> {
    let report_str = "GET KEY";
    let mut dcap_sgx = occlum_dcap::Dcap::new(report_str.as_bytes().to_vec());
    dcap_sgx.dcap_quote_gen().unwrap();
    let report = dcap_sgx.dcap_quote_get_report_body().unwrap();

    occlum::get_key(report, key_policy).to_vec()
}

#[cfg(feature = "std")]
pub fn get_fingerprint_ex(key_name:u16, key_policy: u16) -> Vec<u8> {
    let report_str = "GET KEY";
    let mut dcap_sgx = occlum_dcap::Dcap::new(report_str.as_bytes().to_vec());
    dcap_sgx.dcap_quote_gen().unwrap();
    let report = dcap_sgx.dcap_quote_get_report_body().unwrap();
    if key_name == 0u16 && key_policy == 1u16 {
        unsafe {
            println!("{:?}", (*report).cpu_svn.svn);
            println!("{:?}", (*report).misc_select);
            println!("{:?}", (*report).isv_ext_prod_id);
            println!("{:?}", (*report).attributes.flags);
            println!("{:?}", (*report).attributes.xfrm);
            println!("{:?}", (*report).mr_enclave.m);
            println!("{:?}", (*report).mr_signer.m);
            println!("{:?}", (*report).config_id);
            println!("{:?}", (*report).isv_prod_id);
            println!("{:?}", (*report).isv_svn);
            println!("{:?}", (*report).config_svn);
            println!("{:?}", (*report).isv_family_id);
        }
    }
    occlum::get_key_with_setting(report, key_name, key_policy, 0).to_vec()
}

#[cfg(feature = "std")]
pub fn generate_epid() -> Result<(), String> {
    println!("start epid");
    let mut epid = occlum::EpidQuote::new();
    let group_id = epid.get_group_id();
    let target_info = epid.get_target_info();

    println!(
        "epid group_id{:?} target_info.mr.m{:?}",
        group_id, target_info.mr_enclave.m
    );

    let report_data = sgx_report_data_t::default();
    //report_data.d = [7u8; 64];
    let epid_report = epid.get_epid_report(&target_info, &report_data);
    println!("epid epid_report.cpu.svn{:?}", epid_report.body.cpu_svn.svn);

    Ok(())
}
