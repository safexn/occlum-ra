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

use core::convert::TryFrom;
use occlum_dcap::*;
use std::io::Result;

pub struct Dcap {
    dcap_quote: DcapQuote,
    quote_size: u32,
    quote_buf: Vec<u8>,
    req_data: sgx_report_data_t,
    supplemental_size: u32,
    suppl_buf: Vec<u8>,
}

impl Dcap {
    pub fn new(report_data: Vec<u8>) -> Self {
        let mut dcap = DcapQuote::new();
        let quote_size = dcap.get_quote_size();
        let supplemental_size = dcap.get_supplemental_data_size();
        let quote_buf: Vec<u8> = vec![0; quote_size as usize];
        let suppl_buf: Vec<u8> = vec![0; supplemental_size as usize];
        let mut req_data = sgx_report_data_t::default();

        //fill in the report data array
        for (pos, val) in report_data.iter().enumerate() {
            req_data.d[pos] = *val;
        }

        Self {
            dcap_quote: dcap,
            quote_size,
            quote_buf,
            req_data,
            supplemental_size,
            suppl_buf,
        }
    }

    pub fn dcap_quote_gen(&mut self) -> Result<i32> {
        self.dcap_quote
            .generate_quote(self.quote_buf.as_mut_ptr(), &self.req_data)
            .unwrap();

        println!("DCAP generate quote successfully");

        Ok(0)
    }

    // Quote has type `sgx_quote3_t` and is structured as
    // pub struct sgx_quote3_t {
    //     pub header: sgx_quote_header_t,
    //     pub report_body: sgx_report_body_t,
    //     pub signature_data_len: uint32_t,
    //     pub signature_data: [uint8_t; 0],
    // }

    pub fn dcap_quote_get_report_body(&mut self) -> Result<*const sgx_report_body_t> {
        let report_body_offset = std::mem::size_of::<sgx_quote_header_t>();
        let report_body: *const sgx_report_body_t =
            (self.quote_buf[report_body_offset..]).as_ptr() as _;

        Ok(report_body)
    }

    fn dcap_quote_get_report_data(&mut self) -> Result<*const sgx_report_data_t> {
        let report_body_ptr = self.dcap_quote_get_report_body().unwrap();
        let report_data_ptr = unsafe { &(*report_body_ptr).report_data };

        Ok(report_data_ptr)
    }

    fn dcap_quote_ver(&mut self) -> Result<sgx_ql_qv_result_t> {
        let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
        let mut status = 1;

        let mut verify_arg = IoctlVerDCAPQuoteArg {
            quote_buf: self.quote_buf.as_mut_ptr(),
            quote_size: self.quote_size,
            collateral_expiration_status: &mut status,
            quote_verification_result: &mut quote_verification_result,
            supplemental_data_size: self.supplemental_size,
            supplemental_data: self.suppl_buf.as_mut_ptr(),
        };

        self.dcap_quote.verify_quote(&mut verify_arg).unwrap();
        println!("DCAP verify quote successfully");

        Ok(quote_verification_result)
    }

    fn dcap_dump_quote_info(&mut self) {
        let report_body_ptr = self.dcap_quote_get_report_body().unwrap();

        // Dump ISV FAMILY ID
        let family_id = unsafe { (*report_body_ptr).isv_family_id };
        let (fam_id_l, fam_id_h) = family_id.split_at(8);
        let fam_id_l = <&[u8; 8]>::try_from(fam_id_l).unwrap();
        let fam_id_l = u64::from_le_bytes(*fam_id_l);
        let fam_id_h = <&[u8; 8]>::try_from(fam_id_h).unwrap();
        let fam_id_h = u64::from_le_bytes(*fam_id_h);
        println!("\nSGX ISV Family ID:");
        println!("\t Low 8 bytes: 0x{fam_id_l:016x?}\t");
        println!("\t high 8 bytes: 0x{fam_id_h:016x?}\t");

        // Dump ISV EXT Product ID
        let prod_id = unsafe { (*report_body_ptr).isv_ext_prod_id };
        let (prod_id_l, prod_id_h) = prod_id.split_at(8);
        let prod_id_l = <&[u8; 8]>::try_from(prod_id_l).unwrap();
        let prod_id_l = u64::from_le_bytes(*prod_id_l);
        let prod_id_h = <&[u8; 8]>::try_from(prod_id_h).unwrap();
        let prod_id_h = u64::from_le_bytes(*prod_id_h);
        println!("\nSGX ISV EXT Product ID:");
        println!("\t Low 8 bytes: 0x{prod_id_l:016x?}\t");
        println!("\t high 8 bytes: 0x{prod_id_h:016x?}\t");

        // Dump CONFIG ID
        let conf_id = unsafe { (*report_body_ptr).config_id };
        println!("\nSGX CONFIG ID:");
        println!("\t{:02x?}", &conf_id[..16]);
        println!("\t{:02x?}", &conf_id[16..32]);
        println!("\t{:02x?}", &conf_id[32..48]);
        println!("\t{:02x?}", &conf_id[48..]);

        // Dump CONFIG SVN
        let conf_svn = unsafe { (*report_body_ptr).config_svn };
        println!("\nSGX CONFIG SVN:\t {conf_svn:04x?}");
    }
}

#[cfg(feature = "std")]
impl Drop for Dcap {
    fn drop(&mut self) {
        self.dcap_quote.close();
    }
}

#[cfg(feature = "std")]
pub fn generate_quote(report_str: Vec<u8>) -> Vec<u8> {
    let mut dcap_sgx = Dcap::new(report_str.clone());

    println!("Generate quote with report data : {report_str:?}");
    dcap_sgx.dcap_quote_gen().unwrap();

    // compare the report data in quote buffer
    let report_data_ptr = dcap_sgx.dcap_quote_get_report_data().unwrap();
    let string = unsafe { (*report_data_ptr).d.to_vec() };

    if report_str == string[..report_str.len()] {
        println!("Report data from Quote: '{string:?}' exactly matches.");
    } else {
        println!("Report data from Quote: '{string:?}' doesn't match !!!");
    }

    dcap_sgx.dcap_dump_quote_info();

    let result = dcap_sgx.dcap_quote_ver().unwrap();
    match result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            println!("Succeed to verify the quote!");
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            println!("WARN: App: Verification completed with Non-terminal result: {result:?}");
        }
        _ => println!("Error: App: Verification completed with Terminal result: {result:?}"),
    }

    dcap_sgx.quote_buf.clone()
}
