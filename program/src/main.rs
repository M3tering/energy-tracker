#![no_main]
sp1_zkvm::entrypoint!(main);

use energy_tracker_lib::{
    get_state_root, to_keccak_hash, track_energy, verify_account_proof, M3ter, Payload,
    PublicValuesStruct,
};
use std::ops::Mul;

pub fn main() {
    let payload = sp1_zkvm::io::read::<Payload>();
    let address = "40a36C0eF29A49D1B1c1fA45fab63762f8FC423F";

    let mempool = &payload.mempool;
    let previous_nonces = payload.previous_nonces;
    let previous_balances = payload.previous_balances;

    let (account_proof, encoded_account, storage_hash, proofs) = match payload.proofs {
        Some(value) => (
            value.account_proof,
            value.encoded_account,
            value.storage_hash,
            value.proofs,
        ),
        None => panic!("storage proofs missing"),
    };

    let (state_root, block_bytes) = match payload.block_bytes {
        Some(value) => (get_state_root(&value), value),
        None => panic!("block bytes missing"),
    };

    if !verify_account_proof(
        state_root,
        hex::decode(address).unwrap(),
        encoded_account,
        account_proof,
    ) {
        panic!("Account proof verification failed");
    };

    let mut new_nonces = previous_nonces.clone();
    let mut new_balances = previous_balances.clone();

    let m3ter_position = |m3ter_id: usize| (m3ter_id * 6, m3ter_id * 6 + 6);
    let decode_slice = |data: &[u8; 6]| -> u64 {
        // Convert 6 bytes to i64 (big-endian, pad with zeros)
        let mut buf = [0u8; 8];
        buf[2..].copy_from_slice(data); // pad the first 2 bytes with zeros
        u64::from_be_bytes(buf)
    };

    let encode_slice = |value: u64| -> [u8; 6] {
        let bytes: [u8; 8] = value.to_be_bytes(); // [u8; 8]
        if bytes[..2][0] + bytes[..2][1] > 0 {
            return [0; 6];
        }

        let six_bytes = &bytes[2..8]; // Take the last 6 bytes (big-endian)
        six_bytes.try_into().unwrap()
    };

    if previous_nonces.len() != previous_balances.len() {
        panic!(
            "total nonces {} does not equal total balances {}",
            previous_nonces.len(),
            previous_balances.len()
        )
    }
    for (m3ter_key, m3ter_payloads) in mempool {
        let m3ter = m3ter_key.split('&').collect::<Vec<&str>>();
        let m3ter_id = m3ter[1].parse::<usize>().unwrap();
        let m3ter = M3ter::new(m3ter[1], m3ter[0]);

        let (start, end) = m3ter_position(m3ter_id);
        if start >= previous_nonces.len() || previous_nonces.len() < 6 {
            let padding_len = end - previous_nonces.len();
            let padding = vec![0u8; padding_len];
            new_nonces.extend(&padding);
            new_balances.extend(padding);
        }

        println!(
            "Decoding previous values for M3ter ID: {}, nonce {}, balance {}",
            m3ter_id,
            hex::encode(&new_nonces[start..end]),
            hex::encode(&new_balances[start..end])
        );
        let current_nonce = decode_slice(&new_nonces[start..end].try_into().unwrap());
        let current_balance = decode_slice(&new_balances[start..end].try_into().unwrap());
        println!(
            "Decoded values = Current Nonce: {}, Current Balance: {}",
            current_nonce, current_balance
        );
        let (energy_sum, latest_nonce) = track_energy(
            m3ter,
            m3ter_payloads,
            current_nonce,
            (&storage_hash, &proofs[m3ter_id]),
        );
        let energy_sum = (energy_sum.mul(10_f64.powi(7))) as u64 + current_balance;
        println!(
            "Values after tracking = Energy Sum: {}, Latest Nonce: {}",
            energy_sum, latest_nonce
        );
        let nonce_encoded = encode_slice(latest_nonce);
        let balance_encoded = encode_slice(energy_sum);
        if nonce_encoded == [0u8; 6] || balance_encoded == [0u8; 6] {
            println!(
                "Nonce or balance exceeds the 6-byte limit for m3ter ID: {}",
                m3ter_id
            );
            continue;
        }
        println!(
            "Encoded values = Nonce: {}, Balance: {}",
            &hex::encode(nonce_encoded),
            &hex::encode(balance_encoded)
        );

        new_nonces[start..end].copy_from_slice(&nonce_encoded);
        new_balances[start..end].copy_from_slice(&balance_encoded);

        println!(
            "M3ter ID: {}, Energy Sum: {}, Latest Nonce: {}",
            m3ter_id, energy_sum, latest_nonce
        );
    }

    if new_balances == previous_balances {
        panic!("New balances matches previous balances")
    }

    let block_hash = to_keccak_hash(block_bytes);
    let previous_balances = to_keccak_hash(previous_balances);
    let previous_nonces = to_keccak_hash(previous_nonces);
    let new_balances = new_balances.into();
    let new_nonces = new_nonces.into();

    let public_values = PublicValuesStruct {
        block_hash,
        previous_balances,
        previous_nonces,
        new_balances,
        new_nonces,
    };
    sp1_zkvm::io::commit_slice(&public_values.concat_bytes());
}
