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

#[cfg(not(feature = "std"))]
use crate::alloc::string::ToString;
#[cfg(feature = "std")]
use crate::ias::Net;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use occlum::{sgx_quote_nonce_t, sgx_quote_sign_type_t, sgx_report_data_t};
use rand::*;
const SEPARATOR: u8 = 0x7Cu8;

#[derive(Debug)]
pub struct EpidReport {
    pub ra_report: Vec<u8>,
    pub signature: Vec<u8>,
    pub cert_raw: Vec<u8>,
}

impl EpidReport {
    // use for transfer to payload of cert
    pub fn into_payload(self) -> Vec<u8> {
        let separator: &[u8] = &[SEPARATOR];
        let mut payload = Vec::new();
        payload.extend(self.ra_report);
        payload.extend(separator);
        payload.extend(self.signature);
        payload.extend(separator);
        payload.extend(self.cert_raw);
        payload
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, String> {
        let mut iter = payload.split(|x| *x == SEPARATOR);
        let attn_report_raw = iter.next().ok_or("InvalidReportPayload".to_string())?;
        let sig_raw = iter.next().ok_or("InvalidReportPayload".to_string())?;
        let sig_cert_raw = iter.next().ok_or("InvalidReportPayload".to_string())?;
        Ok(Self {
            ra_report: attn_report_raw.to_vec(),
            signature: sig_raw.to_vec(),
            cert_raw: sig_cert_raw.to_vec(),
        })
    }
}

#[cfg(feature = "std")]
pub fn generate_epid_quote(addition: &[u8]) -> Result<EpidReport, String> {
    let spid: String = "B6E792288644E2957A40AF226F5E4DD8".to_string();
    let ias_key: String = "22aa549a2d5e47a2933a753c1cae947c".to_string();
    let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
    let ias_url = "https://api.trustedservices.intel.com".to_string();

    let mut epid = occlum::EpidQuote::new();
    let eg = epid.get_group_id();
    let ti = epid.get_target_info();

    let gid: u32 = u32::from_le_bytes(eg);
    let net = Net::new(spid, ias_key);

    println!(
        "epid group_id{:?} target_info.mr.m{:?}",
        eg, ti.mr_enclave.m
    );

    let sigrl: Vec<u8> = net.get_sigrl(ias_url.clone(), gid)?;

    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    report_data.d[..addition.len()].clone_from_slice(addition);

    let report = epid.get_epid_report(&ti, &report_data);

    println!("report.svn {:?}", report.body.cpu_svn.svn);

    let quote_buff = epid.get_epid_quote(sigrl, net.spid, report_data, sign_type);

    let quote_buff = occlum::EpidQuote::new_buf(&quote_buff).unwrap();
    println!("quote_buff len {:?}", quote_buff.len());
    let report = net.get_report(ias_url, quote_buff)?;
    Ok(report)
}
