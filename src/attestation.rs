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
use crate::dcap::DCAPError;
use crate::dcap::DcapAttestationReport;
use crate::dcap::SUPPORTED_SIG_ALGS;
use crate::epid_occlum::EpidReport;
#[cfg(feature = "std")]
use crate::occlum_dcap::generate_quote;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt;
use itertools::Itertools;
use log::error;
use serde::{self, Deserialize, Serialize};
use sgx_types::sgx_quote_t;
#[derive(Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportData {
    pub id: String,
    pub timestamp: String,
    pub version: u32,
    pub isv_enclave_quote_status: String,
    pub isv_enclave_quote_body: String,
    #[serde(alias = "advisoryURL")]
    pub advisory_url: Option<String>,
    #[serde(alias = "advisoryIDs")]
    pub advisory_ids: Option<Vec<String>>,
    pub nonce: Option<String>,
    pub epid_pseudonym: Option<String>,
    pub revocation_reason: Option<u32>,
    pub pse_manifest_status: Option<String>,
    pub pse_manifest_hash: Option<String>,
    pub platform_info_blob: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationStyle {
    EPID = 1,
    DCAP = 2,
}

#[derive(Clone, Debug)]
pub struct DcapReport {
    pub quote: Vec<u8>,
}

impl DcapReport {
    // use for transfer to payload of cert
    pub fn into_payload(self) -> Vec<u8> {
        self.quote
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DCAPError> {
        // don't use SEPARATOR.
        Ok(Self {
            quote: payload.to_vec(),
        })
    }
}

#[derive(Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveFields {
    pub version: u16,
    pub sign_type: u16,
    pub report_data: Vec<u8>,
    pub mr_enclave: Vec<u8>,
    pub mr_signer: Vec<u8>,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub isv_enclave_quote_status: String,
}

impl fmt::Display for EnclaveFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ version: {}, sign_type: {}, report_data: \"{:02x}\", mr_enclave: \"{:02x}\", mr_signer: \"{:02x}\", isv_prod_id: {}, isv_svn: {}, isv_enclave_quote_status: \"{}\" }}",
               self.version, self.sign_type, self.report_data.iter().format(""),
               self.mr_enclave.iter().format(""), self.mr_signer.iter().format(""),
               self.isv_prod_id, self.isv_svn, self.isv_enclave_quote_status)
    }
}

#[derive(Clone, Debug)]
pub struct AttestationReport {
    pub style: AttestationStyle,
    pub data: Vec<u8>,
}

impl AttestationReport {
    pub fn into_payload(self) -> Vec<u8> {
        let mut ar = self;
        ar.data.insert(0, ar.style as u8);
        ar.data
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DCAPError> {
        let style = match payload[0] {
            1 => AttestationStyle::EPID,
            2 => AttestationStyle::DCAP,
            _ => return Err(DCAPError::VerifyFailed),
        };
        Ok(Self {
            style,
            data: payload[1..].to_vec(),
        })
    }
}

pub const OUTDATED: i64 = 5_184_000; // two month.

// The case that add_pem_file(&mut ca_reader) should use std::io:BufReader which only exist on std.
pub static IAS_SERVER_ROOTS: &[webpki::TrustAnchor] = &[
    /*
     * -----BEGIN CERTIFICATE-----
     * MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
     * BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
     * BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
     * YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
     * MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
     * U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
     * DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
     * CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
     * LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
     * rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
     * L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
     * NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
     * byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
     * afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
     * 6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
     * RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
     * MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
     * L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
     * BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
     * NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
     * hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
     * IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
     * sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
     * zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
     * Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
     * 152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
     * 3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
     * DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
     * DaVzWh5aiEx+idkSGMnX
     * -----END CERTIFICATE-----
     */
    webpki::TrustAnchor {
        subject: b"1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0b0\t\x06\x03U\x04\x08\x0c\x02CA1\x140\x12\x06\x03U\x04\x07\x0c\x0bSanta Clara1\x1a0\x18\x06\x03U\x04\n\x0c\x11Intel Corporation100.\x06\x03U\x04\x03\x0c\'Intel SGX Attestation Report Signing CA",
        spki: b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x8f\x000\x82\x01\x8a\x02\x82\x01\x81\x00\x9f<d~\xb5w<\xbbQ-\'2\xc0\xd7A^\xbbU\xa0\xfa\x9e\xde.d\x91\x99\xe6\x82\x1d\xb9\x10\xd51w7\twFjj^G\x86\xcc\xd2\xdd\xeb\xd4\x14\x9dj/c%R\x9d\xd1\x0c\xc9\x877\xb0w\x9c\x1a\x07\xe2\x9cG\xa1\xae\x00IHGlH\x9fE\xa5\xa1]z\xc8\xec\xc6\xac\xc6E\xad\xb4=\x87g\x9d\xf5\x9c\t;\xc5\xa2\xe9ilTxT\x1b\x97\x9euKW9\x14\xbeU\xd3/\xf4\xc0\x9d\xdf\'!\x994\xcd\x99\x05\'\xb3\xf9.\xd7\x8f\xbf)$j\xbe\xcbq$\x0e\xf3\x9c-q\x07\xb4GTZ\x7f\xfb\x10\xeb\x06\nh\xa9\x85\x80!\x9e6\x91\tRh8\x92\xd6\xa5\xe2\xa8\x08\x03\x19>@u1@N6\xb3\x15b7\x99\xaa\x82Pt@\x97T\xa2\xdf\xe8\xf5\xaf\xd5\xfec\x1e\x1f\xc2\xaf8\x08\x90o(\xa7\x90\xd9\xdd\x9f\xe0`\x93\x9b\x12W\x90\xc5\x80]\x03}\xf5j\x99S\x1b\x96\xdei\xde3\xed\"l\xc1 }\x10B\xb5\xc9\xab\x7f@O\xc7\x11\xc0\xfeGi\xfb\x95x\xb1\xdc\x0e\xc4i\xea\x1a%\xe0\xff\x99\x14\x88n\xf2i\x9b#[\xb4\x84}\xd6\xff@\xb6\x06\xe6\x17\x07\x93\xc2\xfb\x98\xb3\x14X\x7f\x9c\xfd%sb\xdf\xea\xb1\x0b;\xd2\xd9vs\xa1\xa4\xbdD\xc4S\xaa\xf4\x7f\xc1\xf2\xd3\xd0\xf3\x84\xf7J\x06\xf8\x9c\x08\x9f\r\xa6\xcd\xb7\xfc\xee\xe8\xc9\x82\x1a\x8eT\xf2\\\x04\x16\xd1\x8cF\x83\x9a_\x80\x12\xfb\xdd=\xc7M%by\xad\xc2\xc0\xd5Z\xffo\x06\"B]\x1b\x02\x03\x01\x00\x01",
        name_constraints: None
    },
];

pub const IAS_REPORT_CA: &str = "-----BEGIN CERTIFICATE-----
MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
DaVzWh5aiEx+idkSGMnX
-----END CERTIFICATE-----";

pub struct DcapAttestation;

impl DcapAttestation {
    #[cfg(feature = "std")]
    pub fn create_report(addition: &[u8]) -> Result<DcapReport, DCAPError> {
        let quote = generate_quote(addition.to_vec());
        Ok(DcapReport { quote })
    }

    pub fn verify(report: &AttestationReport, now: u64) -> Result<EnclaveFields, DCAPError> {
        assert!(report.style == AttestationStyle::DCAP);

        let report = DcapReport::from_payload(&report.data).map_err(|_| {
            error!("invalid dcap report.");
            DCAPError::VerifyFailed
        })?;
        // Verify attestation report
        let dar: DcapAttestationReport = DcapAttestationReport::from_bytes(report.quote)?;

        dar.verify_quote(now)?;

        let sgx_quote = dar.quote;
        log::trace!("dcap quote: {}", sgx_quote);

        let enclave_field = EnclaveFields {
            version: sgx_quote.inner.header.version,
            sign_type: 1,
            isv_enclave_quote_status: "".to_string(),
            mr_enclave: sgx_quote
                .inner
                .report_body
                .mr_enclave
                .m
                .try_into()
                .map_err(|_| DCAPError::VerifyFailed)?,
            mr_signer: sgx_quote
                .inner
                .report_body
                .mr_signer
                .m
                .try_into()
                .map_err(|_| DCAPError::VerifyFailed)?,
            report_data: sgx_quote
                .inner
                .report_body
                .report_data
                .d
                .try_into()
                .map_err(|_| DCAPError::VerifyFailed)?,
            ..Default::default()
        };

        Ok(enclave_field)
    }
}

#[derive(Default)]
pub struct IasAttestation {}

impl IasAttestation {
    #[cfg(feature = "std")]
    pub fn create_report(addition: &[u8]) -> Result<EpidReport, String> {
        let re = crate::epid_occlum::generate_epid_quote(addition)?;
        Ok(re)
    }

    pub fn verify(report: &AttestationReport, now: u64) -> Result<EnclaveFields, DCAPError> {
        assert!(report.style == AttestationStyle::EPID);

        let report = EpidReport::from_payload(&report.data).map_err(|_| {
            error!("invalid epid report.");
            DCAPError::VerifyFailed
        })?;

        Self::verify_cert(&report, now)?;

        // Verify attestation report
        let report_data: ReportData =
            serde_json::from_slice(&report.ra_report).map_err(|_| DCAPError::VerifyFailed)?;

        log::trace!("attn_report: {:?}", report_data);

        let raw_report_timestamp = report_data.timestamp + "Z";
        let report_timestamp = chrono::DateTime::parse_from_rfc3339(&raw_report_timestamp)
            .or(Err(DCAPError::VerifyFailed))?
            .timestamp();

        if (now as i64 - report_timestamp) >= OUTDATED {
            error!("[EPID VERIFY ERROR]OUTDATED");
            return Err(DCAPError::VerifyFailed);
        }

        let quote = base64::decode(&report_data.isv_enclave_quote_body).map_err(|_| {
            error!("[EPID VERIFY ERROR]OUTDATED");
            DCAPError::VerifyFailed
        })?;
        log::trace!("Quote = {:?}", quote);

        if quote.len() < 432 {
            error!("[EPID VERIFY ERROR]quote.len() < 432");
            return Err(DCAPError::VerifyFailed);
        }

        let sgx_quote: sgx_quote_t = unsafe { core::ptr::read(quote.as_ptr() as *const _) };

        let enclave_field = EnclaveFields {
            version: sgx_quote.version,
            sign_type: sgx_quote.sign_type,
            isv_enclave_quote_status: report_data.isv_enclave_quote_status,
            mr_enclave: sgx_quote
                .report_body
                .mr_enclave
                .m
                .try_into()
                .map_err(|_| DCAPError::VerifyFailed)?,
            mr_signer: sgx_quote
                .report_body
                .mr_signer
                .m
                .try_into()
                .map_err(|_| DCAPError::VerifyFailed)?,
            report_data: sgx_quote
                .report_body
                .report_data
                .d
                .try_into()
                .map_err(|_| DCAPError::VerifyFailed)?,
            ..Default::default()
        };

        Ok(enclave_field)
    }

    fn verify_cert(report: &EpidReport, now: u64) -> Result<(), DCAPError> {
        let sig = base64::decode(&report.signature).map_err(|_| DCAPError::VerifyFailed)?;
        let sig_cert_dec =
            base64::decode_config(&report.cert_raw, base64::STANDARD).map_err(|_| {
                error!("[EPID VERIFY ERROR]sig_cert_dec base64 decode_config");
                DCAPError::VerifyFailed
            })?;
        let sig_cert = webpki::EndEntityCert::from(sig_cert_dec.as_ref()).map_err(|_| {
            error!("[EPID VERIFY ERROR]sig_cert from EndEntityCert ");
            DCAPError::VerifyFailed
        })?;
        log::debug!("sig_cert_dec {:?}", sig_cert_dec);
        let chain: Vec<&[u8]> = vec![];

        // let mut ias_ca_stripped = IAS_REPORT_CA.as_bytes().to_vec();
        // ias_ca_stripped.retain(|&x| x != 0x0d && x != 0x0a);
        // let head_len = "-----BEGIN CERTIFICATE-----".len();
        // let tail_len = "-----END CERTIFICATE-----".len();
        // let full_len = ias_ca_stripped.len();
        // let ias_ca_core : &[u8] = &ias_ca_stripped[head_len..full_len - tail_len];
        // let ias_cert_dec = base64::decode_config(ias_ca_core, base64::MIME).unwrap();
        //
        // let binding = IAS_REPORT_CA;
        // let mut ca_reader = std::io::BufReader::new(&binding.as_bytes()[..]);
        //
        // let mut root_store = rustls::RootCertStore::empty();
        // root_store.add_pem_file(&mut ca_reader).expect("Failed to add CA");
        //
        // let trust_anchors: Vec<webpki::TrustAnchor> = root_store
        //     .roots
        //     .iter()
        //     .map(|cert| cert.to_trust_anchor())
        //     .collect();
        //
        // let mut chain:Vec<&[u8]> = Vec::new();
        // chain.push(&ias_cert_dec);

        let time_now = webpki::Time::from_seconds_since_unix_epoch(now);
        sig_cert
            .verify_is_valid_tls_server_cert(
                SUPPORTED_SIG_ALGS,
                &webpki::TLSServerTrustAnchors(IAS_SERVER_ROOTS),
                &chain,
                time_now,
            )
            .map_err(|e| {
                error!(
                    "[EPID VERIFY ERROR]verify_is_valid_tls_server_cert fail {:?}",
                    e
                );
                DCAPError::VerifyFailed
            })?;

        // Verify the signature against the signing cert
        sig_cert
            .verify_signature(&webpki::RSA_PKCS1_2048_8192_SHA256, &report.ra_report, &sig)
            .map_err(|_| {
                error!("[EPID VERIFY ERROR]verify_signature fail ");
                DCAPError::VerifyFailed
            })?;

        Ok(())
    }
}
