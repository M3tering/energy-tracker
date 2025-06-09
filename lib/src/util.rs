
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

pub fn _validate_unique_nonce(nonce: u128) -> bool {
    // Check if the nonce is unique (greater than 0)
    nonce > 0
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
    match general_purpose::STANDARD.decode(data) {
        Ok(data) => data,
        Err(error) =>  panic!("failed with error {}", error)
    }
}

