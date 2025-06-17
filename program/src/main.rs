#![no_main]
sp1_zkvm::entrypoint!(main);

use std::ops::Mul;

use base64::{engine::general_purpose, Engine as _};
use energy_tracker_lib::{track_energy, M3ter, Payload, PublicValuesStruct};

pub fn main() {
    let payload = sp1_zkvm::io::read::<Payload>();

    let mempool = &payload.mempool;
    let previous_nonces = payload.previous_nonces;
    let previous_balances = payload.previous_balances;

    let mut new_nonces = previous_nonces.clone();
    let mut new_balances = previous_balances.clone();
    let m3ter_position = |m3ter_id: usize| (m3ter_id * 8, m3ter_id * 8 + 8);
    let decode_slice = |data: &str| -> i64 {
        let decoded = general_purpose::URL_SAFE_NO_PAD
            .decode(data)
            .expect("Failed to decode data");
        let bytes: [u8; 6] = decoded[..6].try_into().expect("Not enough bytes");
        // Convert 6 bytes to i64 (big-endian, pad with zeros)
        let mut buf = [0u8; 8];
        buf[2..].copy_from_slice(&bytes); // pad the first 2 bytes with zeros

        i64::from_be_bytes(buf)
    };
    let encode_slice = |value: i64| -> String {
        // Check if n fits in 6 bytes (48 bits signed)
        // Range: -2^47 to 2^47-1
        if !(-(1 << 47)..=(1 << 47) - 1).contains(&value) {
            return "too large".into();
        }

        let bytes = value.to_be_bytes(); // [u8; 8]
        let six_bytes = &bytes[2..8]; // Take the last 6 bytes (big-endian)

        general_purpose::URL_SAFE_NO_PAD.encode(six_bytes)
    };

    for (m3ter_key, m3ter_payloads) in mempool {
        let m3ter = m3ter_key.split('&').collect::<Vec<&str>>();
        let m3ter_id = m3ter[1].parse::<usize>().unwrap();
        let m3ter = M3ter::new(m3ter[1], m3ter[0]);

        let (start, end) = m3ter_position(m3ter_id);
        println!(
            "Decoding previous values for M3ter ID: {}, nonce {}, balance {}", 
            m3ter_id, &previous_nonces[start..end], &previous_balances[start..end]
        );
        let current_nonce = decode_slice(&previous_nonces[start..end]);
        let current_balance = decode_slice(&previous_balances[start..end]);
        println!(
            "Decoded values = Current Nonce: {}, Current Balance: {}",
            current_nonce, current_balance
        );
        let (energy_sum, latest_nonce) = track_energy(m3ter, m3ter_payloads, current_nonce);
        let energy_sum = (energy_sum.mul(10_f64.powi(7))) as i64 + current_balance;
        println!(
            "Values after tracking = Energy Sum: {}, Latest Nonce: {}",
            energy_sum, latest_nonce
        );
        let nonce_encoded = encode_slice(latest_nonce);
        let balance_encoded = encode_slice(energy_sum);
        if nonce_encoded == "too large" || balance_encoded == "too large" {
            println!("Nonce or balance exceeds the 6-byte limit for m3ter ID: {}", m3ter_id);
            continue;
        }
        println!(
            "Encoded values = Nonce: {}, Balance: {}",
            nonce_encoded, balance_encoded
        );
        new_nonces.replace_range(start..end, &nonce_encoded);
        new_balances.replace_range(start..end, &balance_encoded);

        println!(
            "M3ter ID: {}, Energy Sum: {}, Latest Nonce: {}",
            m3ter_id, energy_sum, latest_nonce
        );
    }

    assert_ne!(new_balances, previous_balances, "New balances matches previous balances");
    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit(&PublicValuesStruct {
        previous_balances,
        previous_nonces,
        new_balances,
        new_nonces,
    });
}
