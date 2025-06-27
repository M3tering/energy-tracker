//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use std::{fs::File, io::BufReader};

use alloy_primitives::{B256, U256};
use clap::Parser;
use energy_tracker_lib::{Payload, ProofStruct, PublicValuesStruct};
use energy_tracker_verifier::get_storage_proofs;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

use eyre::{Ok, Result};

// use base64::{Engine as _, alphabet, engine::{self, general_purpose}};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ENERGY_TRACKER_ELF: &[u8] = include_elf!("energy-tracker-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long, default_value = "20")]
    n: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();
    
   // Setup the program.
   let (pk, vk) = client.setup(ENERGY_TRACKER_ELF);

   // Setup the inputs.
   let file = File::open("src/sample.json").unwrap();
   let reader = BufReader::new(file);
   let payload: Payload = serde_json::from_reader(reader).unwrap();

   let slots = payload.mempool.keys()
       .map(|key| {
           let m3ter_id = key.split('&').collect::<Vec<&str>>()[1];
           let slot_key = U256::from(m3ter_id.parse::<u32>().unwrap()).to_be_bytes();
           B256::new(slot_key)
       })
       .collect();

   let (proof_hash, proofs) = get_storage_proofs(slots).await?;

   let previous_nonces = payload.previous_nonces[1..].to_vec();
   let previous_balances = payload.previous_balances[1..].to_vec();

   let payload = Payload {
       mempool: payload.mempool,
       previous_nonces,
       previous_balances,
       proofs: Some(ProofStruct {
           proof_hash, proofs
       })
   };

   let mut stdin = SP1Stdin::new();
   stdin.write(&payload);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(ENERGY_TRACKER_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        // println!("output: {:?}", bincode::deserialize::<PublicValuesStruct>(output.as_slice()).unwrap());

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(ENERGY_TRACKER_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
    Ok(())
}
