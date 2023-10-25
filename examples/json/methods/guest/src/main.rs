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
use json::parse;
use json_core::Outputs;
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let jwt: String = env::read();
    // Split the JWT into its three parts and hash the first two.
    let parts = jwt.split('.').collect::<Vec<&str>>();
    if parts.len() != 3 {
        panic!("Invalid JWT");
    }
    let header: &str = parts[0];
    let data: &str = parts[1];
    // TODO: Verify the signature.
    // let signature = parts[2];

    let unsigned_jwt = format!("{}.{}", header, data);
    let sha = *Impl::hash_bytes(&unsigned_jwt.as_bytes());

    let mut payload_bytes = [0u8; 1024];
    let payload_bytes = Base64UrlUnpadded::decode(data.as_bytes(), &mut payload_bytes).unwrap();
    let payload = String::from_utf8(payload_bytes.to_vec()).unwrap();
    println!("payload: {}", payload);

    // Convert the bytes to a string. This assumes the payload is UTF-8 encoded.
    let data = parse(&payload).unwrap();
    let exp = data["exp"].as_u32().unwrap();
    let out = Outputs {
        data: exp,
        hash: sha,
    };
    env::commit(&out);
    env::log("");
}
