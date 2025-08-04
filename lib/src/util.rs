use alloy_consensus::Header;
use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_trie::Nibbles;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub fn validate_signature(
    message_hash: Vec<u8>,
    public_key: &str,
    signature_str: &str,
) -> Option<bool> {
    // Decode the signature and public key using ed25519-dalek
    let signature = build_signature(signature_str)?;
    let verify_key = build_verifying_key(public_key)?;

    // Verify the signature using ed25519-dalek
    if verify_key.verify(&message_hash, &signature).is_ok() {
        Some(true)
    } else {
        None
    }
}

fn build_signature(raw_signature: &str) -> Option<Signature> {
    let signature = Signature::from_slice(&decode_hex(raw_signature));
    match signature {
        Ok(sign) => Some(sign),
        Err(err) => {
            print!("failed to build from slice with err {:?}", err);
            None
        }
    }
}

fn build_verifying_key(raw_public_key: &str) -> Option<VerifyingKey> {
    let mut raw_hex = [0u8; 32];
    let _ = hex::decode_to_slice(raw_public_key, &mut raw_hex as &mut [u8]);
    let verifying_key = VerifyingKey::from_bytes(&raw_hex);
    match verifying_key {
        Ok(verifier) => Some(verifier),
        Err(err) => {
            print!("failed to build from slice with err {:?}", err);
            None
        }
    }
}

fn decode_hex(data: &str) -> Vec<u8> {
    match hex::decode(data) {
        Ok(data) => data,
        Err(error) => panic!("failed with error {}", error),
    }
}

pub fn get_state_root(block_bytes: &Vec<u8>) -> B256 {
    let block_header =
        alloy_rlp::decode_exact::<Header>(block_bytes).expect("Failed to decode block header");

    block_header.state_root
}

pub fn verify_account_proof(
    state_root: B256,
    address: Vec<u8>,
    expected_value: Vec<u8>,
    proof: Vec<Bytes>,
) -> bool {
    let address = Nibbles::unpack(to_keccak_hash(address));
    alloy_trie::proof::verify_proof(state_root, address, Some(expected_value), &proof).is_ok()
}

pub fn destructure_payload(payload: &str) -> (&str, &str, u64, u64) {
    let payload_bytes = hex::decode(payload).expect("Failed to decode hex payload");
    let (message, signature) = payload.split_at(16);
    let nonce_bytes: [u8; 4] = payload_bytes[0..4].try_into().expect("Failed to get nonce bytes");
    let energy_bytes: [u8; 4] = payload_bytes[4..8].try_into().expect("Failed to get energy bytes");
    let nonce = u32::from_be_bytes(nonce_bytes) as u64;
    let energy = u32::from_be_bytes(energy_bytes) as u64; 
    (message, signature, nonce, energy)
}

pub fn to_b256(value: U256) -> B256 {
    B256::from_slice(&value.to_be_bytes_vec())
}

pub fn to_keccak_hash(input: Vec<u8>) -> B256 {
    keccak256(input)
}

pub fn calc_slot_key(key: U256) -> Option<U256> {
    let slot_literal: U256 =
        "97075990194835763561528983445257952440596761921281503889599705229225710478219"
            .parse()
            .expect("invalid slot literal");
    
    key.checked_add(slot_literal)
}
