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
#[cfg(not(feature = "std"))]
use alloc::format;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::mem::size_of;
use core::{fmt, slice};
use itertools::Itertools;
use ring::signature::VerificationAlgorithm;
use sgx_types::*;
use sha2::Digest;
use sha2::Sha256;

pub(crate) fn sha256_combine_slice(pk: &[u8], auth_data: &[u8]) -> [u8; 32] {
    let mut pk_ad = vec![];
    pk_ad.extend_from_slice(pk);
    pk_ad.extend_from_slice(auth_data);
    sha256_slice(&pk_ad)
}

pub(crate) fn sha256_slice(bytes: &[u8]) -> [u8; 32] {
    let mut sha256 = Sha256::new();
    sha256.input(bytes);
    let mut hashed = [0u8; 32];
    let result = &sha256.result()[..];
    hashed.copy_from_slice(result);
    hashed
}
#[derive(Debug, Eq, PartialEq)]
pub enum DCAPError {
    InvalidLength,
    InvalidCertLength,
    InvalidPemCert,
    InvalidCertChain,
    InvalidCACert,
    InvalidPCECert,
    InvalidQuote,
    UnknownPublicKey,
    VerifyFailed,
}

#[derive(Default)]
pub struct Quote {
    pub inner: sgx_quote3_t,
}

impl Quote {
    fn new(inner: sgx_quote3_t) -> Self {
        Self { inner }
    }

    fn header(&self) -> &sgx_quote_header_t {
        &self.inner.header
    }

    fn report_body(&self) -> sgx_report_body_t {
        self.inner.report_body
    }

    fn signature_data_len(&self) -> usize {
        self.inner.signature_data_len as usize
    }
}

impl fmt::Display for Quote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Header: [{}] \n Report Body: [{}]",
            Header::new(self.header()),
            ReportBody::new(self.report_body())
        )
    }
}

pub struct Header<'a> {
    pub inner: &'a sgx_quote_header_t,
}

impl<'a> Header<'a> {
    fn new(inner: &'a sgx_quote_header_t) -> Self {
        Self { inner }
    }
}

impl<'a> fmt::Display for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\t version: {}", { self.inner.version })?;
        write!(f, "\t att_key_type: {}", { self.inner.att_key_type })?;
        write!(f, "\t att_key_data_0: {}", { self.inner.att_key_data_0 })?;
        write!(f, "\t qe_svn: {}", { self.inner.qe_svn })?;
        write!(f, "\t pce_svn: {}", { self.inner.pce_svn })?;
        write!(
            f,
            "\t vendor_id: {:02x}",
            self.inner.vendor_id.iter().format("")
        )?;
        write!(
            f,
            "\t user_data: {:02x}",
            self.inner.user_data.iter().format("")
        )
    }
}

pub struct ReportBody {
    pub inner: sgx_report_body_t,
}

impl ReportBody {
    pub fn new(inner: sgx_report_body_t) -> Self {
        Self { inner }
    }
}

impl fmt::Display for ReportBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\t cpu_svn: {:02x}",
            self.inner.cpu_svn.svn.iter().format("")
        )?;
        write!(f, "\t misc_select: {}", self.inner.misc_select)?;
        write!(
            f,
            "\t mr_enclave: {:02x}",
            self.inner.mr_enclave.m.iter().format("")
        )?;
        write!(
            f,
            "\t mr_signer: {:02x}",
            self.inner.mr_signer.m.iter().format("")
        )?;
        write!(f, "\t isv_prod_id: {}", self.inner.isv_prod_id)?;
        write!(f, "\t isv_svn: {}", self.inner.isv_svn)?;
        write!(
            f,
            "\t report data: {:02x}",
            self.inner.report_data.d.iter().format("")
        )
    }
}

#[derive(Default, Clone)]
pub struct QlEcdsaSig {
    pub inner: sgx_ql_ecdsa_sig_data_t,
}

impl QlEcdsaSig {
    pub fn new(inner: sgx_ql_ecdsa_sig_data_t) -> Self {
        Self { inner }
    }
}

impl fmt::Display for QlEcdsaSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\t sig: {:02x}", self.inner.sig.iter().format(""))?;
        write!(
            f,
            "\t attest_pub_key: {:02x}",
            self.inner.attest_pub_key.iter().format("")
        )?;
        write!(f, "\t qe_report: {}", ReportBody::new(self.inner.qe_report))?;
        write!(
            f,
            "\t qe_report_sig: {:02x}",
            self.inner.qe_report_sig.iter().format("")
        )
    }
}

const INTEL_ROOT_PUB_KEY: &[u8] = &[
    0x04u8, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c,
    0xda, 0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55,
    0x25, 0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2,
    0x6a, 0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae,
    0x73, 0x94,
];

const SGX_QUOTE_LEN: usize = size_of::<sgx_quote3_t>();
const SGX_QUOTE_HEADER_LEN: usize = size_of::<sgx_quote_header_t>();
const SGX_QUOTE_REPORT_BODY_LEN: usize = size_of::<sgx_report_body_t>();
const SGX_QL_ECDSA_SIG_DATA_LEN: usize = size_of::<sgx_ql_ecdsa_sig_data_t>();
const SGX_QL_AUTH_HEADER_LEN: usize = size_of::<sgx_ql_auth_data_t>();
const SGX_QL_CERTIFICATION_HEADER_LEN: usize = size_of::<sgx_ql_certification_data_t>();

#[derive(Default)]
pub struct DcapAttestationReport {
    pub quote: Quote,
    pub ecdsa_sig: QlEcdsaSig,
    pub auth_data: Vec<u8>,
    pub cert_header: sgx_ql_certification_data_t,
    pub cert_data: Vec<u8>,
}

impl DcapAttestationReport {
    ///
    ///  Raw data distribution
    /// | quote3                |
    /// | ql_ecdsa_sig_data_t   |
    /// | ql_auth_data_t        |
    /// | ql_auth_data          |
    /// | ql_cert_data_t        |
    /// | ql_cert_data          |
    ///
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, DCAPError> {
        log::trace!("len: {} , data: {}", data.len(), data.iter().format(""));
        if data.len() < SGX_QUOTE_LEN {
            log::error!(
                "DcapAttestationReport: Invalid quote length, {}",
                data.len()
            );
            return Err(DCAPError::InvalidLength);
        }

        let p_quote3: *const sgx_quote3_t = data.as_ptr() as *const sgx_quote3_t;
        let quote3: sgx_quote3_t = unsafe { *p_quote3 };
        let quote = Quote::new(quote3);

        let quote_signature_data: Vec<u8> = data[size_of::<sgx_quote3_t>()..].into();

        if quote.signature_data_len() != quote_signature_data.len() {
            log::error!("DcapAttestationReport: Invalid quote signature length");
            return Err(DCAPError::InvalidLength);
        }

        let p_sig_data: *const sgx_ql_ecdsa_sig_data_t = quote_signature_data.as_ptr() as _;
        let ecdsa_sig_data: sgx_ql_ecdsa_sig_data_t = unsafe { *p_sig_data };

        let auth_header_offset = SGX_QL_ECDSA_SIG_DATA_LEN;
        let p_auth_data: *const sgx_ql_auth_data_t =
            (quote_signature_data[auth_header_offset..]).as_ptr() as _;
        let auth_data_header: sgx_ql_auth_data_t = unsafe { *p_auth_data };

        let auth_data_offset = auth_header_offset + SGX_QL_AUTH_HEADER_LEN;
        if data.len() < auth_data_offset + auth_data_header.size as usize {
            return Err(DCAPError::InvalidLength);
        }
        let auth_data: Vec<u8> = quote_signature_data
            [auth_data_offset..auth_data_offset + auth_data_header.size as usize]
            .into();

        let cert_header_offset = auth_data_offset + auth_data_header.size as usize;
        let p_cert_header: *const sgx_ql_certification_data_t =
            quote_signature_data[cert_header_offset..].as_ptr() as _;
        let cert_header: sgx_ql_certification_data_t = unsafe { *p_cert_header };

        let cert_info_offset = cert_header_offset + SGX_QL_CERTIFICATION_HEADER_LEN;

        if data.len() != SGX_QUOTE_LEN + cert_info_offset + cert_header.size as usize {
            return Err(DCAPError::InvalidCertLength);
        }
        let cert_data = quote_signature_data[cert_info_offset..].into();

        Ok(Self {
            quote,
            ecdsa_sig: QlEcdsaSig::new(ecdsa_sig_data),
            auth_data,
            cert_header,
            cert_data,
        })
    }

    pub fn ecdsa_sig_data(&self) -> QlEcdsaSig {
        self.ecdsa_sig.clone()
    }

    pub fn auth_data(&self) -> Vec<u8> {
        self.auth_data.clone()
    }

    pub fn cert_key_type(&self) -> u16 {
        self.cert_header.cert_key_type
    }

    // The QE will generate the ECDSA Attestation Key (AK) and include a hash of the AK
    // in the QE.REPORT.ReportData.
    // Sha256(AK + AuthData) = QeReport.ReportData
    pub fn is_valid_attestation_public_key(&self) -> bool {
        let result = sha256_combine_slice(&self.ecdsa_sig.inner.attest_pub_key, &self.auth_data);
        // The first 32 bytes are public keys
        result == self.ecdsa_sig.inner.qe_report.report_data.d[..32]
    }

    pub fn is_valid_quote(&self, pck_pk: [u8; 65]) -> bool {
        // verify quote signature
        let data = unsafe {
            slice::from_raw_parts(
                (&self.quote.inner as *const sgx_quote3_t) as *const u8,
                SGX_QUOTE_HEADER_LEN + SGX_QUOTE_REPORT_BODY_LEN,
            )
        };
        let sig = self.ecdsa_sig.inner.sig;
        let mut ak_pk = [4u8; 65];
        ak_pk[1..].copy_from_slice(&self.ecdsa_sig.inner.attest_pub_key);
        let quote_ret = ring::signature::ECDSA_P256_SHA256_FIXED.verify(
            ak_pk.as_ref().into(),
            data.as_ref().into(),
            sig.as_ref().into(),
        );

        let qe_data = unsafe {
            slice::from_raw_parts(
                core::ptr::addr_of!(self.ecdsa_sig.inner.qe_report) as *const u8, //std::ptr::addr_of!(self.ecdsa_sig.inner.qe3_report)
                SGX_QUOTE_REPORT_BODY_LEN,
            )
        };
        let qe_sig = self.ecdsa_sig.inner.qe_report_sig;
        let qe_ret = ring::signature::ECDSA_P256_SHA256_FIXED.verify(
            pck_pk.as_ref().into(),
            qe_data.as_ref().into(),
            qe_sig.as_ref().into(),
        );

        quote_ret.is_ok() && qe_ret.is_ok()
    }
}

/*
(1) Verify the integrity of thesignature chain from the quote to the Intel-issued PCK certificate.
(2) Verify no keys in the chain have been revoked.
(3) Verify the  quoting  enclave  is  from  a suitable source and up-to-date.
(4) Verify the status of the Intel SGX TCB described in the chain.

Independent of whether EPID or ECDSA attestation is used, the verifier must check if
the  hash  of  the  RA-TLS  certificate’s  public  key  is present in the enclave’s report

MRENCLAVE  and  MRSIGNER  against  the  expected
*/
impl DcapAttestationReport {
    pub fn verify_quote(&self, now: u64) -> Result<(), DCAPError> {
        let certs = DerCertChain::from_bytes(self.cert_data.clone())?;

        let ca_pk = DerCertChain::extract_public_key(&certs.ca_der)?;
        if ca_pk != INTEL_ROOT_PUB_KEY {
            return Err(DCAPError::InvalidCACert);
        }

        certs.verify_cert_chain(now)?;

        let pck_pk = DerCertChain::extract_public_key(&certs.end_der)?;

        if !self.is_valid_quote(pck_pk) {
            return Err(DCAPError::InvalidQuote);
        }
        Ok(())
    }
}

pub type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];
pub static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

#[derive(Debug, Clone)]
pub struct DerCertChain {
    pub end_der: String,
    pub pck_der: String,
    pub ca_der: String,
}

impl DerCertChain {
    const PEM_BEGIN_STRING_X509: &'static str = "-----BEGIN CERTIFICATE-----";
    const PEM_END_STRING_X509: &'static str = "-----END CERTIFICATE-----";

    pub fn from_bytes(data: Vec<u8>) -> Result<Self, DCAPError> {
        let empty = "";
        let full_chain = String::from_utf8(data).map_err(|_| DCAPError::InvalidPemCert)?;
        let certs: Vec<&str> = full_chain
            .split(DerCertChain::PEM_BEGIN_STRING_X509)
            .map(|s| {
                let cert = s.trim_end_matches('\0').trim_end_matches('\n');
                match cert.strip_suffix(DerCertChain::PEM_END_STRING_X509) {
                    Some(c) => c.trim_matches('\n'),
                    None => empty,
                }
            })
            .filter(|s| !s.is_empty())
            .collect();

        if certs.len() != 3 {
            return Err(DCAPError::InvalidCertChain);
        }
        Ok(Self {
            end_der: certs[0].to_string().replace('\n', ""),
            pck_der: certs[1].to_string().replace('\n', ""),
            ca_der: certs[2].to_string().replace('\n', ""),
        })
    }

    pub fn extract_public_key(der: &str) -> Result<[u8; 65], DCAPError> {
        let mut pk = [0u8; 65];
        match base64::decode_config(der, base64::STANDARD) {
            Ok(decoded_der) => {
                let prime256v1_oid = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
                let mut offset = decoded_der
                    .windows(prime256v1_oid.len())
                    .position(|window| window == prime256v1_oid)
                    .ok_or(DCAPError::InvalidPemCert)?;
                offset += 11; // 10 + TAG (0x03)
                              // Obtain Public Key length
                let mut len = decoded_der[offset] as usize;
                if len > 0x80 {
                    len = (decoded_der[offset + 1] as usize) * 0x100
                        + (decoded_der[offset + 2] as usize);
                    offset += 2;
                }
                // Obtain Public Key
                offset += 1;
                if offset + len > decoded_der.len() {
                    return Err(DCAPError::UnknownPublicKey);
                }

                let pub_k = decoded_der[offset + 1..offset + len].to_vec(); // skip "00"
                if pub_k.len() != 65 {
                    return Err(DCAPError::UnknownPublicKey);
                }

                pk.copy_from_slice(&pub_k);
            }
            Err(_e) => return Err(DCAPError::InvalidPemCert),
        }
        Ok(pk)
    }

    pub fn verify_cert_chain(&self, now: u64) -> Result<(), DCAPError> {
        let end_der = base64::decode_config(&self.end_der, base64::STANDARD)
            .map_err(|_| DCAPError::InvalidPemCert)?;
        let pck_der = base64::decode_config(&self.pck_der, base64::STANDARD)
            .map_err(|_| DCAPError::InvalidPemCert)?;
        let ca_der = base64::decode_config(&self.ca_der, base64::STANDARD)
            .map_err(|_| DCAPError::InvalidCACert)?;
        //let ca = webpki::TrustAnchor::try_from_cert_der(&ca_der).map_err(|_| DCAPError::InvalidCACert)?;
        let ca = webpki::trust_anchor_util::cert_der_as_trust_anchor(&ca_der)
            .map_err(|_| DCAPError::InvalidCACert)?;

        let chain: Vec<&[u8]> = vec![&pck_der, &ca_der];
        //let end_cert = webpki::EndEntityCert::try_from(end_der.as_ref()).map_err(|_| DCAPError::InvalidPemCert)?;
        let end_cert =
            webpki::EndEntityCert::from(end_der.as_ref()).map_err(|_| DCAPError::InvalidPemCert)?;

        let trust_anchors: Vec<webpki::TrustAnchor> = vec![ca];
        let time_now = webpki::Time::from_seconds_since_unix_epoch(now);
        end_cert
            .verify_is_valid_tls_server_cert(
                SUPPORTED_SIG_ALGS,
                &webpki::TLSServerTrustAnchors(&trust_anchors),
                &chain,
                time_now,
            )
            .map_err(|_| DCAPError::InvalidPCECert)?;

        Ok(())
    }

    pub fn full_chain_pem(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            DerCertChain::PEM_BEGIN_STRING_X509,
            self.end_der,
            DerCertChain::PEM_END_STRING_X509,
            DerCertChain::PEM_BEGIN_STRING_X509,
            self.pck_der,
            DerCertChain::PEM_END_STRING_X509,
            DerCertChain::PEM_BEGIN_STRING_X509,
            self.ca_der,
            DerCertChain::PEM_END_STRING_X509
        )
    }

    pub fn end_pem(&self) -> String {
        DerCertChain::format_to_pem(&self.end_der)
    }

    pub fn pck_pem(&self) -> String {
        DerCertChain::format_to_pem(&self.pck_der)
    }

    pub fn ca_pem(&self) -> String {
        DerCertChain::format_to_pem(&self.ca_der)
    }

    fn format_to_pem(der: &str) -> String {
        format!(
            "{}\n{}\n{}",
            DerCertChain::PEM_BEGIN_STRING_X509,
            der,
            DerCertChain::PEM_END_STRING_X509
        )
    }
}
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use hex::FromHex;
//     use std::time::{SystemTime, UNIX_EPOCH};
//     use ring::test::from_hex;
//
//     fn now() -> u64 {
//         SystemTime::now()
//             .duration_since(UNIX_EPOCH)
//             .unwrap()
//             .as_secs()
//     }
//
//     // #[test]
//     // fn valid_quote_ok() {
//     //     let quote = include_bytes!("../res/quote.dat");
//     //     let ar = DcapAttestationReport::from_bytes(quote.to_vec()).unwrap();
//     //     let ret = ar.verify_quote(now());
//     //     assert!(ret.is_ok());
//     // }
//     //
//     // #[test]
//     // fn invalid_quote_failed() {
//     //     let quote = include_bytes!("../res/quote.dat");
//     //     let mut invalid_quote: Vec<u8> = vec![];
//     //     invalid_quote.extend_from_slice(quote);
//     //     // hack quote info
//     //     invalid_quote[3] = 8u8;
//     //     let ar = DcapAttestationReport::from_bytes(invalid_quote.clone()).unwrap();
//     //     let ret = ar.verify_quote(now());
//     //     assert!(ret.is_err());
//     //
//     //     // reset quote
//     //     invalid_quote.copy_from_slice(quote);
//     //     let mut ar = DcapAttestationReport::from_bytes(invalid_quote.clone()).unwrap();
//     //     let sig = <Vec<u8>>::from_hex("8a8b81d107001157363ddc3718c6344fc1fcb2f027b278258ec5439878304ebc0cd5a0ab7dbfe7f46ee44d298bc113c12582a8ff1ca3df1ce8b163bd9b2893d1").unwrap();
//     //     // hack qe signature
//     //     ar.ecdsa_sig.inner.sig.copy_from_slice(&sig);
//     //     let ret = ar.verify_quote(now());
//     //     assert!(ret.is_err());
//     // }
//
//     #[test]
//     fn valid_sgx_ecdsa256_verify_ok() {
//         use ::num_bigint::BigUint;
//         // The test data is generated by enclave, The enclave will call 'create_key_pair' and ecdsa_sign_slice
//         let data = [1u8; 77];
//         // use sgx reverse sk and pk.
//         let sk = [
//             200u8, 95, 136, 131, 7, 88, 103, 90, 215, 139, 196, 104, 166, 244, 53, 148, 16, 153,
//             109, 199, 239, 223, 234, 216, 162, 96, 160, 196, 204, 103, 227, 5,
//         ];
//         let pk = [
//             4u8, 99, 93, 202, 90, 191, 174, 147, 21, 184, 78, 69, 172, 172, 61, 142, 230, 105, 170,
//             25, 203, 200, 180, 182, 212, 195, 219, 72, 146, 140, 130, 85, 191, 159, 139, 102, 137,
//             175, 208, 179, 197, 139, 246, 209, 220, 207, 103, 26, 168, 22, 89, 59, 195, 10, 85,
//             176, 115, 105, 227, 99, 208, 22, 95, 165, 252,
//         ];
//         let _pair = ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
//             &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
//             &sk,
//             &pk,
//         )
//             .unwrap();
//         // do'nt reverse the signature.
//         let sig_x = [
//             2245573994, 785864746, 2498530008, 2624339524, 3267948009, 503994198, 3340480099,
//             3696638872,
//         ];
//         let sig_y = [
//             650101574, 1735739819, 2001544028, 4205280702, 2050259917, 1308666114, 4196314819,
//             3321769913,
//         ];
//
//         let b_x = BigUint::from_slice(&sig_x);
//         let b_y = BigUint::from_slice(&sig_y);
//         let mut b_sig = vec![];
//         b_sig.extend_from_slice(&b_x.to_bytes_be());
//         b_sig.extend_from_slice(&b_y.to_bytes_be());
//         let ret = ring::signature::ECDSA_P256_SHA256_FIXED.verify(
//             pk.as_ref().into(),
//             data.as_ref().into(),
//             b_sig.as_slice().into(),
//         );
//         assert!(ret.is_ok());
//         println!("bigend ECDSA_P256_SHA256_FIXED {:?}", ret);
//     }
//
//     // #[test]
//     // fn valid_attestation_public_key_ok() {
//     //     let quote = include_bytes!("../res/quote.dat");
//     //     let ar = DcapAttestationReport::from_bytes(quote.to_vec()).unwrap();
//     //     let ret = ar.is_valid_attestation_public_key();
//     //     assert!(ret);
//     // }
//
//     // #[test]
//     // fn valid_ring_pair_ok() {
//     //     let sk =
//     //         <Vec<u8>>::from_hex("1bad0ec2a1969170e73c919e1bdeb883ce0aa6d27affd8d9a09fe8c6585af45e")
//     //             .unwrap();
//     //     let pk = <Vec<u8>>::from_hex("04cba7767197137f08040530cf79a7aa7085e6dd68c0d04d8a449c5cb40eaced44fbfe8a867b3ee76426e7190b4ccff10985600599764e0157fa8f0d204baf8179").unwrap();
//     //     assert_eq!(sk.len(), 32);
//     //     assert_eq!(pk.len(), 65);
//     //     let pair = ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
//     //         &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
//     //         &sk,
//     //         &pk,
//     //     );
//     //     assert!(pair.is_ok());
//     // }
//
//     #[test]
//     fn valid_p256_data_ok() {
//         // The test data from  https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
//         let pk = <Vec<u8>>::from_hex("04e96568167f3a60040e15f4bfa533a92e8351878f75664655d2d0750a2214f31017b2973c97dbbaff866703abad872bbdac872ad2c41cdeeafc458f9755e8f20e").unwrap();
//         let msg = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
//         let sig = <Vec<u8>>::from_hex("3046022100f9cb9d4a85d978eac0359a1f6da6baec3a95f8389bd0b43f14bb730edb62a194022100da33f741f6863620c1c8d91e62339b37bc26b4712a5ca87bed418ea24bfda026").unwrap();
//
//         let ret = ring::signature::ECDSA_P256_SHA256_ASN1.verify(
//             pk.as_slice().into(),
//             msg.as_ref().into(),
//             sig.as_slice().into(),
//         );
//         println!("bigend ECDSA_P256_SHA256_ASN1 {:?}", ret);
//         assert!(ret.is_ok());
//     }
// }
