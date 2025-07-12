//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```

use std::{fs::File, io::BufReader};
use alloy_primitives::{B256, U256, Bytes};
use clap::{Parser, ValueEnum};
use energy_tracker_lib::{Payload, ProofStruct, PublicValuesStruct, to_keccak_hash};
use energy_tracker_verifier::{get_block_rpl_bytes, get_previous_values, get_storage_proofs};
use eyre::Result;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ENERGY_TRACKER_ELF: &[u8] = include_elf!("energy-tracker-program");

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct EVMArgs {
    #[arg(long, value_enum, default_value = "groth16")]
    system: ProofSystem,
}

/// Enum representing the available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk,
    Groth16,
}
/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofFixture {
    previous_balances: B256,
    previous_nonces: B256,
    new_balances: Bytes,
    new_nonces: Bytes,
    block_hash: B256,
    vkey: String,
    public_values: String,
    proof: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = EVMArgs::parse();

    std::env::set_var("SP1_PROVER", "network");
    std::env::set_var("NETWORK_PRIVATE_KEY", "3b62b0fb8da4fc79eff9236c50527cd8bb9cd7c264f1c838b105d4570aa0491e");

    // Setup the inputs.
    let file = File::open("src/sample.json").unwrap();
    let reader = BufReader::new(file);
    let payload: Payload = serde_json::from_reader(reader).unwrap();

    let previous_nonces = get_previous_values(U256::from(0)).await?;
    let previous_balances = get_previous_values(U256::from(1)).await?;

    let slots = payload
        .mempool
        .keys()
        .map(|key| {
            let base_slot: [u8; 32] = U256::from(0).to_be_bytes();
            let m3ter_id = key.split('&').collect::<Vec<&str>>()[1];
            let key: [u8; 32] = U256::from(m3ter_id.parse::<u32>().unwrap()).to_be_bytes();

            let mut slot_key_raw = vec![];

            slot_key_raw.extend(key);
            slot_key_raw.extend(base_slot);

            to_keccak_hash(slot_key_raw)
        })
        .collect();

    let (account_proof, encoded_account, storage_hash, proofs, anchor_block) =
        get_storage_proofs(slots).await?;
    let block_bytes = get_block_rpl_bytes(anchor_block).await?;

    println!("Anchor Block: {}", anchor_block);
    let payload = Payload {
        mempool: payload.mempool,
        previous_nonces: previous_nonces.to_vec(),
        previous_balances: previous_balances.to_vec(),
        proofs: Some(ProofStruct {
            account_proof,
            encoded_account,
            storage_hash,
            proofs,
        }),
        block_bytes: Some(block_bytes),
    };

    let mut stdin = SP1Stdin::new();
    stdin.write(&payload);

    // Setup the prover client.
    let client = ProverClient::from_env();

    // let (_, _report) = client.execute(ENERGY_TRACKER_ELF, &stdin).run().expect("failed to execute program");

    // Setup the program.
    let (pk, vk) = client.setup(ENERGY_TRACKER_ELF);

    println!("Proof System: {:?}", args.system);
    let proof = match args.system {
        ProofSystem::Plonk => client.prove(&pk, &stdin).plonk().run(),
        ProofSystem::Groth16 => client.prove(&pk, &stdin).groth16().run(),
    }
    .expect("failed to generate proof");

    create_proof_fixture(&proof, &vk, args.system);
    Ok(())
}

// Create a fixture for the given proof.
fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    system: ProofSystem,
) {
    let bytes = proof.public_values.as_slice();
    let output = PublicValuesStruct::from_bytes(bytes);
    let PublicValuesStruct {
        previous_balances,
        previous_nonces,
        new_balances,
        new_nonces,
        block_hash,
    } = output;

    // Create the testing fixture so we can test things end-to-end.
    let fixture = ProofFixture {
        previous_balances,
        previous_nonces,
        new_balances,
        new_nonces,
        block_hash,
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join(format!("{:?}-fixture.json", system).to_lowercase()),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
