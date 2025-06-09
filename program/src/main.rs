
#![no_main]
sp1_zkvm::entrypoint!(main);

use energy_tracker_lib::{track_energy, M3ter, Payload, PublicValuesStruct};


pub fn main() {
    let payload = sp1_zkvm::io::read::<Payload>();

    let mempool = &payload.mempool; 
    let previous_nonces = payload.previous_nonces;
    let previous_balances = payload.previous_balances;

    let mut new_nonces = previous_nonces.clone();
    let mut new_balances = previous_balances.clone();

    for (m3ter_key, m3ter_payloads) in mempool {
        let m3ter = m3ter_key.split('&').collect::<Vec<&str>>();
        let m3ter_id = m3ter[1].parse::<usize>().unwrap();
        let m3ter = M3ter::new(m3ter[1], m3ter[0]);
        let current_nonce = previous_nonces[m3ter_id];
        let current_balance = previous_balances[m3ter_id];
        let (energy_sum, latest_nonce) = track_energy(m3ter, m3ter_payloads, current_nonce);

        if energy_sum == 0.0 && latest_nonce == current_nonce {
            continue; // No energy consumed, skip this m3ter
        }
        new_nonces[m3ter_id] = latest_nonce;
        new_balances[m3ter_id] = current_balance + energy_sum as f32;
        println!("M3ter ID: {}, Energy Sum: {}, Latest Nonce: {}", m3ter_id, energy_sum, latest_nonce);
    }
    // Encode the public values of the program.
    // let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { n, a, b });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit(&PublicValuesStruct{
        previous_balances, previous_nonces, new_balances, new_nonces
    });
}
