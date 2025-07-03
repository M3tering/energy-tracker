
use alloy_consensus::Header;
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_trie::Nibbles;
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};

pub fn validate_signature(message_hash: Vec<u8>, public_key: &str, signature_str: &str) -> Option<bool> {
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

// pub fn _validate_unique_nonce(nonce: u128) -> bool {
//     // Check if the nonce is unique (greater than 0)
//     nonce > 0
// }

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
    match general_purpose::STANDARD.decode(data) {
        Ok(data) => data,
        Err(error) =>  panic!("failed with error {}", error)
    }
}

pub fn get_state_root(block_bytes: &Vec<u8>) -> B256 {
    let block_header = alloy_rlp::decode_exact::<Header>(block_bytes)
        .expect("Failed to decode block header");

    block_header.state_root
}

pub fn verify_account_proof(state_root: B256, address: Vec<u8>, expected_value: Vec<u8>, proof: Vec<Bytes>) -> bool {
    let address = Nibbles::unpack(to_keccak_hash(address));
    alloy_trie::proof::verify_proof(state_root, address, Some(expected_value), &proof).is_ok()
}

pub fn to_keccak_hash(input: Vec<u8>) -> [u8; 32] {
    *keccak256(input)
}
