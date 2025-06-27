
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

    println!("storage_proofs = {:?}", proof.storage_proof);

    let storage_proofs = proof
        .storage_proof
        .iter()
        .map(|value| value.proof.clone())
        .collect();

    Ok((proof.storage_hash, storage_proofs))
}
