#![no_main]
sp1_zkvm::entrypoint!(main);

use std::ops::Mul;
use energy_tracker_lib::{track_energy, to_keccak_hash, M3ter, Payload, PublicValuesStruct};

pub fn main() {
    let payload = sp1_zkvm::io::read::<Payload>();

    let mempool = &payload.mempool;
    let previous_nonces = payload.previous_nonces;
    let previous_balances = payload.previous_balances;

    

    let (storage_hash, proofs) = match payload.proofs {
        Some(value) => (value.proof_hash, value.proofs),
        None => panic!("storage proofs missing")
    };

    let mut new_nonces = previous_nonces.clone();
    let mut new_balances = previous_balances.clone();
    
    let m3ter_position = |m3ter_id: usize| (m3ter_id * 6, m3ter_id * 6 + 6);
    let decode_slice = |data: &[u8; 6]| -> i64 {
        // Convert 6 bytes to i64 (big-endian, pad with zeros)
        let mut buf = [0u8; 8];
        buf[2..].copy_from_slice(data); // pad the first 2 bytes with zeros
        i64::from_be_bytes(buf)
    };

    let encode_slice = |value: i64| -> [u8; 6] {
        let bytes: [u8; 8] = value.to_be_bytes(); // [u8; 8]
        if bytes[..2][0] + bytes[..2][1] > 0 {
            return [0; 6];
        }

        let six_bytes = &bytes[2..8]; // Take the last 6 bytes (big-endian)
        six_bytes.try_into().unwrap()
    };
    let mut index = 0;
    for (m3ter_key, m3ter_payloads) in mempool {
        let m3ter = m3ter_key.split('&').collect::<Vec<&str>>();
        let m3ter_id = m3ter[1].parse::<usize>().unwrap();
        let m3ter = M3ter::new(m3ter[1], m3ter[0]);

        let (start, end) = m3ter_position(m3ter_id);
        println!(
            "Decoding previous values for M3ter ID: {}, nonce {}, balance {}",
            m3ter_id,
            hex::encode(&previous_nonces[start..end]),
            hex::encode(&previous_balances[start..end])
        );
        let current_nonce = decode_slice(&previous_nonces[start..end].try_into().unwrap());
        let current_balance = decode_slice(&previous_balances[start..end].try_into().unwrap());
        println!(
            "Decoded values = Current Nonce: {}, Current Balance: {}",
            current_nonce, current_balance
        );
        let (energy_sum, latest_nonce) = track_energy(m3ter, m3ter_payloads, current_nonce, (&storage_hash, &proofs[index]));
        let energy_sum = (energy_sum.mul(10_f64.powi(7))) as i64 + current_balance;
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
            index += 1_usize;
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
        
        index += 1_usize;
    }

    if new_balances == previous_balances {
        panic!("New balances matches previous balances")
    }

    let previous_balances =  format!("0x{}", hex::encode(to_keccak_hash(previous_balances)));
    let previous_nonces =  format!("0x{}", hex::encode(to_keccak_hash(previous_nonces)));
    let new_balances =  format!("0x{}", hex::encode(to_keccak_hash(new_balances)));
    let new_nonces = format!("0x{}", hex::encode(to_keccak_hash(new_nonces)));

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit(&PublicValuesStruct {
        previous_balances,
        previous_nonces,
        new_balances,
        new_nonces,
    });
}
