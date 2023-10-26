// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use base64ct::{Encoding, Base64UrlUnpadded};
use crypto_bigint::{
    U2048,
    Encoding as OtherEncoding,
    modular::runtime_mod::{
        DynResidue, DynResidueParams
    }
};
use json::parse;
use json_core::Outputs;
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

risc0_zkvm::guest::entry!(main);

fn base64url_to_big_int(x: &str) -> U2048 {
    let mut bytes = [0u8; 256];
    let bytes = Base64UrlUnpadded::decode(x.as_bytes(), &mut bytes).unwrap();
    U2048::from_be_slice(bytes)
}

fn verify_sig(s: &str, pk: &str, hash: &[u8]) {
    let sig = base64url_to_big_int(s);
    println!("sig: {}", sig);
    let modulus = base64url_to_big_int(pk);
    println!("modulus: {}", modulus);

    let params = DynResidueParams::new(&modulus);
    let sig_mod = DynResidue::new(&sig, params);

    // Verify RSA signature
    let e = U2048::from(65537u32);

    let tmp = sig_mod.pow(&e).retrieve();
    // let tmp = sig.modpow(&e, &modulus);

    let bytes = tmp.to_be_bytes();
    // for i in 0..bytes.len() {
    //     println!("{} {}", i, bytes[i]);
    // }

    // Take the last hash.len() bytes 
    let end_bytes = &bytes[bytes.len() - hash.len()..];

    // Compare the hash to the signature
    for i in 0..hash.len() {
        // println!("{} {}", i, hash[i]);
        assert_eq!(end_bytes[i], hash[i]);
    }

    // TODO: Add RSA padding check on rest of bytes
}

pub fn main() {
    let jwt: String = env::read();
    let pk: String = env::read();
    // Split the JWT into its three parts and hash the first two.
    let parts = jwt.split('.').collect::<Vec<&str>>();
    if parts.len() != 3 {
        panic!("Invalid JWT");
    }
    let header: &str = parts[0];
    let data: &str = parts[1];
    // TODO: Verify the signature.
    let signature = parts[2];

    let unsigned_jwt = format!("{}.{}", header, data);
    let sha = *Impl::hash_bytes(&unsigned_jwt.as_bytes());
    verify_sig(signature, &pk, &sha.as_bytes());

    let mut payload_bytes = [0u8; 1024];
    let payload_bytes = Base64UrlUnpadded::decode(data.as_bytes(), &mut payload_bytes).unwrap();
    let payload = String::from_utf8(payload_bytes.to_vec()).unwrap();
    println!("payload: {}", payload);

    // Convert the bytes to a string. This assumes the payload is UTF-8 encoded.
    let data = parse(&payload).unwrap();
    let iss = data["iss"].as_str().unwrap();
    let out = Outputs {
        iss: iss.to_string(),
        hash: sha,
    };
    env::commit(&out);
    env::log("");
}
