
use alloy::{
    primitives::{Address, Bytes, B256},
    providers::{Provider, ProviderBuilder},
};
use eyre::Result;

pub async fn get_storage_proofs(slots: Vec<B256>) -> Result<(B256, Vec<Vec<Bytes>>)> {
    
    let rpc_url = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY".to_string());
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);

    // Address to verify
    let address: Address = "0x5b0204b10262c7364b31e229253795167bf92b8a".parse()?;
    let proof = provider.get_proof(address, slots).await?;

    let storage_proofs = proof
        .storage_proof
        .iter()
        .map(|value| value.proof.clone())
        .collect();

    // let slot_key = Nibbles::unpack(keccak256(slot_key));
    // let value = Input {
    //     key: U256::from_be_slice(
    //         &hex::decode("5e42d8bb9567663151f49e56c996a558ac8516abc8ef65d783ea2e8d0af68a54")
    //             .unwrap(),
    //     ),
    // };
    // let out = rlp::encode(value.key);
    // let result = alloy_trie::proof::verify_proof(
    //     proof.storage_hash,
    //     slot_key,
    //     Some(out),
    //     &proof.storage_proof[0].proof,
    // );
    // assert!(result.is_ok());

    Ok((proof.storage_hash, storage_proofs))
}
