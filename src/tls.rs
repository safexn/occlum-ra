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

#![allow(deprecated)]
use std::time::*;

use bit_vec::BitVec;
use chrono::Duration;
use chrono::TimeZone;
use chrono::Utc as TzUtc;
use num_bigint::BigUint;
use yasna::models::ObjectIdentifier;

use ring;
use ring::{
    rand,
    signature::{self, KeyPair},
};

use crate::attestation::{AttestationReport, AttestationStyle, DcapAttestation};

pub const CERTEXPIRYDAYS: i64 = 90i64;
const ISSUER: &str = "SafeMatrix";
const SUBJECT: &str = "SafeMatrix";

pub fn generate_cert(_payload: String) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (key_pair, key_pair_doc) = ring_key_gen_pcks_8();
    let pub_key = key_pair.public_key().as_ref().to_vec();
    println!("pub_key in this report:{pub_key:?}");

    let report = DcapAttestation::create_report(&pub_key[1..]).unwrap();

    let re = AttestationReport {
        style: AttestationStyle::DCAP,
        data: report.into_payload(),
    };

    println!("DCAP Report{re:?}");

    let cert_der = match gen_ecc_cert(re.into_payload(), key_pair, pub_key) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in gen_ecc_cert: {e:?}");
            return Err("Error in gen_ecc_cert".to_string());
        }
    };

    Ok((key_pair_doc, cert_der))
}

pub fn get_attestation_report(pub_key: Vec<u8>) -> Result<String, String> {
    let (attn_report, sig, cert) = match create_attestation_report(pub_key) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {e:?}");
            return Err("Error in create_attestation_report".to_string());
        }
    };
    let payload = attn_report + "|" + &sig + "|" + &cert;
    Ok(payload)
}

pub fn create_attestation_report(_pub_k: Vec<u8>) -> Result<(String, String, String), String> {
    Ok((
        "attn_report".to_string(),
        "sig".to_string(),
        "cert".to_string(),
    ))
}

pub fn ring_key_gen_pcks_8() -> (signature::EcdsaKeyPair, Vec<u8>) {
    let rng = rand::SystemRandom::new();
    let key_pair =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap();
    let res = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        key_pair.as_ref(),
    )
    .unwrap();

    (res, key_pair.as_ref().to_vec())
}

pub fn gen_ecc_cert(
    payload: Vec<u8>,
    prv_k: signature::EcdsaKeyPair,
    key_pair: Vec<u8>,
) -> Result<Vec<u8>, String> {
    // Generate public key bytes since both DER will use it
    let mut pub_key_bytes: Vec<u8> = Vec::with_capacity(0);
    pub_key_bytes.extend_from_slice(&key_pair);
    // Generate Certificate DER
    let cert_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                // Certificate Version
                writer
                    .next()
                    .write_tagged(yasna::Tag::context(0), |writer| {
                        writer.write_i8(2);
                    });
                // Certificate Serial Number (unused but required)
                writer.next().write_u8(1);
                // Signature Algorithm: ecdsa-with-SHA256
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2]));
                });
                // Issuer: CN=MesaTEE (unused but required)
                writer.next().write_sequence(|writer| {
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer
                                .next()
                                .write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
                            writer.next().write_utf8_string(ISSUER);
                        });
                    });
                });
                // Validity: Issuing/Expiring Time (unused but required)
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let issue_ts = TzUtc.timestamp(now.as_secs() as i64, 0);
                let expire = now + Duration::days(CERTEXPIRYDAYS).to_std().unwrap();
                let expire_ts = TzUtc.timestamp(expire.as_secs() as i64, 0);
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_utctime(&yasna::models::UTCTime::from_datetime(&issue_ts));
                    writer
                        .next()
                        .write_utctime(&yasna::models::UTCTime::from_datetime(&expire_ts));
                });
                // Subject: CN=MesaTEE (unused but required)
                writer.next().write_sequence(|writer| {
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer
                                .next()
                                .write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
                            writer.next().write_utf8_string(SUBJECT);
                        });
                    });
                });
                writer.next().write_sequence(|writer| {
                    // Public Key Algorithm
                    writer.next().write_sequence(|writer| {
                        // id-ecPublicKey
                        writer
                            .next()
                            .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]));
                        // prime256v1
                        writer
                            .next()
                            .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));
                    });
                    // Public Key
                    writer
                        .next()
                        .write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
                });
                // Certificate V3 Extension
                writer
                    .next()
                    .write_tagged(yasna::Tag::context(3), |writer| {
                        writer.write_sequence(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                                    2, 16, 840, 1, 113730, 1, 13,
                                ]));
                                writer.next().write_bytes(&payload);
                            });
                        });
                    });
            });
            // Signature Algorithm: ecdsa-with-SHA256
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2]));
            });
            // Signature
            let sig = {
                let tbs = &writer.buf[4..];
                // ecc_handle.ecdsa_sign_slice(tbs, &prv_k).unwrap()
                let rng = rand::SystemRandom::new();
                prv_k.sign(&rng, tbs).unwrap().as_ref().to_vec()
            };
            let sig_der = yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    //let mut sig_x = sig.x.clone();
                    let mut sig_x = sig[..32].to_vec();
                    sig_x.reverse();
                    //let mut sig_y = sig.y.clone();
                    let mut sig_y = sig[32..].to_vec();
                    sig_y.reverse();
                    writer.next().write_biguint(&BigUint::from_bytes_be(&sig_x));
                    writer.next().write_biguint(&BigUint::from_bytes_be(&sig_y));
                });
            });
            writer.next().write_bitvec(&BitVec::from_bytes(&sig_der));
        });
    });

    Ok(cert_der)
}

pub fn ker_der(prv_k_r: Vec<u8>, pub_key_bytes: Vec<u8>) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u8(0);
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]));
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));
            });
            let inner_key_der = yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    writer.next().write_u8(1);
                    let prv_k_r = prv_k_r.clone();
                    //prv_k_r.reverse();
                    writer.next().write_bytes(&prv_k_r);
                    writer
                        .next()
                        .write_tagged(yasna::Tag::context(1), |writer| {
                            writer.write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
                        });
                });
            });
            writer.next().write_bytes(&inner_key_der);
        });
    })
}
/*
#[cfg(test)]
mod tests {
    use crate::verify::extract_data;
    use super::*;

    pub fn ring_key_gen_pcks_8_pk() -> (signature::EcdsaKeyPair,Vec<u8>,Vec<u8>,Vec<u8>){
        let rng = rand::SystemRandom::new();
        let (key_pair,(prikey,pubkey)) =
            signature::EcdsaKeyPair::generate_pkcs8_with_private_key(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let res = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING,key_pair.as_ref()).unwrap();

        (res,key_pair.as_ref().to_vec(),prikey,pubkey)
    }

    #[test]
    fn test_key_der(){
        let (key_pair, key_pair_doc,prikey,pubkey) = ring_key_gen_pcks_8_pk();
        let pub_key = key_pair.public_key().as_ref().to_vec();
        assert_eq!(pub_key,pubkey);

        let key_der = ker_der(prikey,pubkey);
        assert_eq!(key_der, key_pair_doc);
    }

    #[test]
    fn test_cert_der(){
        let test_payload = "testpayload".to_string();
        let (key_der, cert_der) = generate_cert(test_payload.clone()).unwrap();
        let (payload, pub_k_extract) = extract_data(&cert_der).unwrap();
        assert_eq!(test_payload.as_bytes(), payload);

        println!("pub_k_extract {:?}",pub_k_extract);
    }
}

 */
