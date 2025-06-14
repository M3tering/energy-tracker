use std::{collections::HashMap, fmt::Debug};

use serde::{Deserialize, Serialize};

mod util;
use util::{validate_signature};

// use alloy_sol_types::sol;

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicValuesStruct {
    pub previous_balances: String,
    pub previous_nonces: String,
    pub new_balances: String,
    pub new_nonces: String
}


#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Payload {
    pub mempool: HashMap<String, Vec<M3terPayload>>,
    pub previous_nonces: String,
    pub previous_balances: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct M3terPayload {
    pub signature: String,
    pub nonce: i64,
    pub energy: f64,
}

impl M3terPayload {
    pub fn new(
        signature: &str,
        nonce: i64,
        energy: f64,
    ) -> Self {
        M3terPayload {
            signature: String::from(signature),
            nonce,
            energy,
        }
    }

    fn msg_to_vec(&self) -> Vec<u8> {
        let message = format!("{}-{}", self.energy, self.nonce);
        message.as_bytes().to_vec()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct M3ter {
    pub m3ter_id: String,
    pub public_key: String,
}

impl M3ter {
    pub fn new(m3ter_id: &str, public_key: &str) -> Self {
        M3ter {
            m3ter_id: String::from(m3ter_id),
            public_key: String::from(public_key),
        }
    }

    fn validate_payload(&self, payload: &M3terPayload) -> bool {
        match validate_signature(payload.msg_to_vec(), &self.public_key, &payload.signature)  {
            Some(is_valid) => is_valid,
            None => {
                println!("Invalid signature for payload: {:?}", payload);
                false
            }
        }
    }
}

pub fn track_energy(m3ter: M3ter, m3ter_payloads: &[M3terPayload], start_nonce: i64) -> (f64, i64) {
    let mut energy_sum = 0.0;
    let mut latest_nonce = start_nonce;
    for payload in m3ter_payloads.iter() {
        if latest_nonce + 1 != payload.nonce {
            println!("Invalid nonce: {} < {} for m3ter_id {}", &payload.nonce, &latest_nonce, &m3ter.m3ter_id);
            break; // Nonce is not sequential or is less than the latest nonce
        }
        if !m3ter.validate_payload(payload) {
            println!("Invalid payload: {:?}", payload);
            break
        }
        energy_sum += payload.energy;
        latest_nonce = payload.nonce;
    }

    (energy_sum, latest_nonce)
}
