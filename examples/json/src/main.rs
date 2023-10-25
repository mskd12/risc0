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

use json_core::Outputs;
use json_methods::SEARCH_JSON_ELF;
use risc0_zkvm::{
    default_prover,
    serde::{from_slice, to_vec},
    ExecutorEnv,
};

fn main() {
    env_logger::init();
    // let data = r#"{"sub":"eeef7e18-0659-42e6-892a-82f0715eec38","aud":"test","nbf":1696016408,"iss":"https://oauth.sui.io","exp":1696102808,"nonce":"hTPpgF7XAKbW37rEUS6pEVZqmoI"}"#;
    let data = "eyJraWQiOiJzdWkta2V5LWlkIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJlZWVmN2UxOC0wNjU5LTQyZTYtODkyYS04MmYwNzE1ZWVjMzgiLCJhdWQiOiJ0ZXN0IiwibmJmIjoxNjk2MDE2NDA4LCJpc3MiOiJodHRwczovL29hdXRoLnN1aS5pbyIsImV4cCI6MTY5NjEwMjgwOCwibm9uY2UiOiJoVFBwZ0Y3WEFLYlczN3JFVVM2cEVWWnFtb0kifQ.sXrG8Deswy-P5D2MX82HqVzkC_fYOAJ1bXLZMzNqV3IQs7bZU-rUQI3ylWreopNHEkg3xWgwt1QHstL9_x5zBH1t3M4p0192WUOA28lh9CehsfWGpCaQrOyW2ntsHVvKDE8ba33qGskuTz1GNRGb9IbWYen4ZavstzgrY0EXsgWBCI8ToI_X5BESugrbNKwdeS9Kc_qKYuJQICPlSZo4SaKjg3qXAndo0d7c7fuI20Am8qQxi08w-dhm0LRrQRmy0wGkTyISSCCbNQ5Tp2n2iteQQvxErv-vpl2Pr5XFkQW3VWc-4zDKojq8x3lZM_oz3HDt4yAGs6IWUc3oRSLd7w";
    let outputs = search_json(data);
    println!();
    println!("  {:?}", outputs.hash);
    println!(
        "provably contains a field 'exp' with value {}",
        outputs.data
    );
}

fn search_json(data: &str) -> Outputs {
    let env = ExecutorEnv::builder()
        .add_input(&to_vec(&data).unwrap())
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    let start = std::time::Instant::now();
    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove_elf(env, SEARCH_JSON_ELF).unwrap();
    println!("Proving took {:?}", start.elapsed());

    from_slice(&receipt.journal).unwrap()
}

#[cfg(test)]
mod tests {
    #[test]
    fn main() {
        let data = include_str!("../res/example.json");
        let outputs = super::search_json(data);
        assert_eq!(
            outputs.data, 47,
            "Did not find the expected value in the critical_data field"
        );
    }
}
