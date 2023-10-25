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

use ::bonsai_sdk::alpha::SessionId;
#[doc = include_str!("../README.md")]
use hello_world_methods::{MULTIPLY_ELF, MULTIPLY_ID};
use risc0_zkvm::{
    default_prover,
    serde::{from_slice, to_vec},
    ExecutorEnv, Receipt,
};

use anyhow::Result;
use bonsai_sdk::alpha as bonsai_sdk;
use risc0_zkvm::{MemoryImage, Program, PAGE_SIZE};
use std::time::Duration;

// This is a Hello World demo for the RISC Zero zkVM.
// By running the demo, Alice can produce a receipt that proves that she knows
// some numbers a and b, such that a*b == 391.
// The factors a and b are kept secret.

// Compute the product a*b inside the zkVM
pub fn local_prove(a: u64, b: u64) -> u64 {
    let env = ExecutorEnv::builder()
        // Send a & b to the guest
        .add_input(&to_vec(&a).unwrap())
        .add_input(&to_vec(&b).unwrap())
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Start a timer
    let start = std::time::Instant::now();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove_elf(env, MULTIPLY_ELF).unwrap();

    let end = std::time::Instant::now();
    let elapsed = end - start;
    println!("Proof generated in {:?}", elapsed);
    process_receipt(receipt)
}

// Note that there are two ways to generate a SNARK proof: 
// 1. Call remote_prove + run_stark2snark
// 2. Call local_prove with the Bonsai API keys set in env vars. Print the session ID by turning on debug logs. Use the sessionID on the Bonsai UI to generate a proof.
pub fn remote_prove(a: u64, b: u64) -> Result<SessionId> {
    let client = bonsai_sdk::Client::from_env()?;

    // create the memoryImg, upload it and return the imageId
    let img_id = {
        let program = Program::load_elf(MULTIPLY_ELF, 1 << 28)?;
        let image = MemoryImage::new(&program, PAGE_SIZE as u32)?;
        let image_id = hex::encode(image.compute_id());
        let image = bincode::serialize(&image).expect("Failed to serialize memory img");
        client.upload_img(&image_id, image)?;
        image_id
    };

    // Prepare input data and upload it.
    let mut input_data: Vec<u8> = vec![];
    input_data.extend_from_slice(bytemuck::cast_slice(&to_vec(&a).unwrap()));
    input_data.extend_from_slice(bytemuck::cast_slice(&to_vec(&b).unwrap()));
    let input_id = client.upload_input(input_data)?;

    // Start a timer
    let start = std::time::Instant::now();

    // Start a session running the prover
    let session = client.create_session(img_id, input_id)?;
    loop {
        let res = session.status(&client)?;
        if res.status == "RUNNING" {
            println!(
                "Current status: {} - state: {} - continue polling...",
                res.status,
                res.state.unwrap_or_default()
            );
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        if res.status == "SUCCEEDED" {
            let end = std::time::Instant::now();
            let elapsed = end - start;
            println!("Proof generated in {:?}", elapsed);

            // Download the receipt, containing the output
            let receipt_url = res
                .receipt_url
                .expect("API error, missing receipt on completed session");

            let receipt_buf = client.download(&receipt_url)?;
            let receipt: Receipt = bincode::deserialize(&receipt_buf)?;
            process_receipt(receipt);
            return Ok(session);
        } else {
            panic!("Workflow exited: {} - | err: {}", res.status, res.error_msg.unwrap_or_default());
        }
    }
}

pub fn process_receipt(receipt: Receipt) -> u64 {
    // Extract journal of receipt (i.e. output c, where c = a * b)
    let c: u64 = from_slice(&receipt.journal).expect(
        "Journal output should deserialize into the same types (& order) that it was written",
    );

    // Report the product
    println!("I know the factors of {}, and I can prove it!", c);    

    // Verify receipt, panic if it's wrong
    receipt.verify(MULTIPLY_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct image ID?",
    );

    c
}

pub fn run_stark2snark(session_id: String) -> Result<()> {
    let client = bonsai_sdk::Client::from_env()?;

    let snark_session = client.create_snark(session_id)?;
    tracing::info!("Created snark session: {}", snark_session.uuid);
    loop {
        let res = snark_session.status(&client)?;
        match res.status.as_str() {
            "RUNNING" => {
                println!("Current status: {} - continue polling...", res.status,);
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
            "SUCCEEDED" => {
                let snark_receipt = res.output;
                println!("Snark proof!: {snark_receipt:?}");
                break;
            }
            _ => {
                panic!("Workflow exited: {} err: {}", res.status, res.error_msg.unwrap_or_default());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world() {
        const TEST_FACTOR_ONE: u64 = 17;
        const TEST_FACTOR_TWO: u64 = 23;
        let result = local_prove(17, 23);
        assert_eq!(
            result,
            TEST_FACTOR_ONE * TEST_FACTOR_TWO,
            "We expect the zkVM output to be the product of the inputs"
        )
    }
}
