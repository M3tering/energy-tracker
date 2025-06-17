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

use base64::Engine;
use clap::Parser;
use energy_tracker_lib::{Payload, PublicValuesStruct};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

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

fn main() {
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
    
    let file = File::open("src/sample.json").unwrap();
    let reader = BufReader::new(file);
    let payload: Payload = serde_json::from_reader(reader).unwrap();
    let previous_nonces = &payload.previous_nonces;
    let previous_balances = &payload.previous_balances;

    let payload = Payload {
        mempool: payload.mempool,
        previous_nonces: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(previous_nonces.as_bytes()),
        previous_balances: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(previous_balances.as_bytes()),
    };

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&payload);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(ENERGY_TRACKER_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        println!("output: {:?}", bincode::deserialize::<PublicValuesStruct>(output.as_slice()).unwrap());

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
}
