use std::{collections::HashMap, fmt::Debug};

use alloy_sol_types::sol;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::Nibbles;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod util;
use util::validate_signature;

pub use util::{to_keccak_hash, verify_account_proof, get_state_root};

sol! {
    #[derive(Serialize, Deserialize, Debug)]
    struct PublicValuesStruct {
        bytes32 block_hash;
        bytes32 previous_balances;
        bytes32 previous_nonces;
        bytes new_balances;
        bytes new_nonces;
    }
}

fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = if s.starts_with("0x") {
        s.strip_prefix("0x").unwrap()
    } else {
        s.as_str()
    };
    hex::decode(s).map_err(serde::de::Error::custom)
}

pub fn serialize_hex<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_str = hex::encode(bytes);
    serializer.serialize_str(&hex_str)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProofStruct {
    pub storage_hash: B256,
    pub proofs: Vec<Vec<Bytes>>,
    pub encoded_account: Vec<u8>,
    pub account_proof: Vec<Bytes>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Payload {
    pub mempool: HashMap<String, Vec<M3terPayload>>,
    #[serde(deserialize_with = "deserialize_hex", serialize_with = "serialize_hex")]
    pub previous_nonces: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex", serialize_with = "serialize_hex")]
    pub previous_balances: Vec<u8>,
    pub proofs: Option<ProofStruct>,
    pub block_bytes: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct M3terPayload {
    pub signature: String,
    pub nonce: i64,
    pub energy: f64,
}

impl M3terPayload {
    pub fn new(signature: &str, nonce: i64, energy: f64) -> Self {
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

    fn  validate_payload(&self, payload: &M3terPayload) -> bool {
        match validate_signature(payload.msg_to_vec(), &self.public_key, &payload.signature) {
            Some(is_valid) => is_valid,
            None => {
                println!("Invalid signature for payload: {:?}", payload);
                false
            }
        }
    }

    fn verify_public_key(&self, storage_hash: &B256, proof: &Vec<Bytes>) -> bool {
        println!("storage hash = {:?}\nproof = {:?}", storage_hash, proof);
        let (m3ter_id, public_key) = (&self.m3ter_id, &self.public_key);
        let slot_key: [u8; 32] = U256::from(m3ter_id.parse::<u32>().unwrap()).to_be_bytes();
        let slot_key = Nibbles::unpack(keccak256(slot_key));
        let public_key = if public_key.starts_with("0x") {
            public_key.strip_prefix("0x").unwrap()
        } else {
            public_key.as_str()
        };

        let expected_value = U256::from_be_slice(&hex::decode(public_key).unwrap());
        println!("expected_value = {:?}", expected_value);
        let expected_value = alloy_rlp::encode(expected_value);
        let result = alloy_trie::proof::verify_proof(
            *storage_hash,
            slot_key,
            Some(expected_value),
            proof,
        );
        match result {
            Ok(()) => true,
            Err(_err) => false,
        }
    }
}

pub fn track_energy(
    m3ter: M3ter,
    m3ter_payloads: &[M3terPayload],
    start_nonce: i64,
    (storage_hash, proof): (&B256, &Vec<Bytes>),
) -> (f64, i64) {
    if !m3ter.verify_public_key(storage_hash, proof) {
        println!(
            "encountered invalid public_key for m3ter {}",
            m3ter.m3ter_id
        );
        return (0.0, start_nonce);
    }

    let mut energy_sum = 0.0;
    let mut latest_nonce = start_nonce;
    for payload in m3ter_payloads.iter() {
        // if latest_nonce + 1 != payload.nonce {
        //     println!("Invalid nonce: {} < {} for m3ter_id {}", &payload.nonce, &latest_nonce, &m3ter.m3ter_id);
        //     break; // Nonce is not sequential or is less than the latest nonce
        // }
        // if !m3ter.validate_payload(payload) {
        //     println!("Invalid payload: {:?}", payload);
        //     break
        // }
        energy_sum += payload.energy;
        latest_nonce = payload.nonce;
        println!("State: energy {:?}, nonce {:?}", energy_sum, latest_nonce);
    }

    (energy_sum, latest_nonce)
}
