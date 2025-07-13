use alloy::{
    eips::BlockNumberOrTag,
    json_abi::JsonAbi,
    primitives::{Address, Bytes, B256, U256},
    providers::{Provider, ProviderBuilder},
};
use alloy_contract::Interface;
use alloy_rlp::{encode, RlpEncodable};
use eyre::{Ok, Result};

#[derive(Debug, RlpEncodable)]
pub struct Account {
    nonce: u64,
    balance: U256,
    storage_hash: B256,
    code_hash: B256,
}

// sol! {
//     #[sol(rpc)]
//     contract RollUp {
//         function latestStateAddress(uint io) public returns (address);
//     }
// }

pub fn get_address() -> Address {
    "0x302087A3FaEc7Ff7B18B6A618BBC75dD91D3bee8"
        .parse()
        .expect("Invalid address")
}

async fn get_provider() -> Result<impl Provider> {
    let rpc_url = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY".to_string());
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);
    Ok(Box::new(provider))
}

pub async fn get_storage_proofs(
    slots: Vec<B256>,
) -> Result<(Vec<Bytes>, Vec<u8>, B256, Vec<Vec<Bytes>>, u64)> {
    let provider = get_provider().await?;

    println!("{:?}", &slots[0]);

    let value_at_storage = 
        provider.get_storage_at(get_address(), U256::from_be_slice(slots[0].as_slice())).await?;

    println!("value_at_storage = {:?}", B256::from_slice(&value_at_storage.to_be_bytes_vec()));

    let anchor_block = provider.get_block_number().await?;

    println!("Anchor Block: {:?}", anchor_block);
    // Address to verify
    let proof = provider.get_proof(get_address(), slots);

    let proof_at_block = proof
        .number(anchor_block)
        .await
        .map_err(|e| eyre::eyre!("Failed to get proof: {}", e))?;

    println!("storage_proofs = {:?}", proof_at_block.storage_proof);

    let account = Account {
        nonce: proof_at_block.nonce,
        balance: proof_at_block.balance,
        code_hash: proof_at_block.code_hash,
        storage_hash: proof_at_block.storage_hash,
    };

    let encoded_account = encode(account);

    let storage_proofs = proof_at_block
        .storage_proof
        .iter()
        .map(|value| value.proof.clone())
        .collect();

    Ok((
        proof_at_block.account_proof,
        encoded_account,
        proof_at_block.storage_hash,
        storage_proofs,
        anchor_block,
    ))
}

pub async fn get_block_rpl_bytes(block_number: u64) -> Result<Vec<u8>> {
    let provider = get_provider().await?;
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_number))
        .await
        .map_err(|e| eyre::eyre!("Failed to get block: {}", e))?;

    if let Some(block) = block {
        let block_header = block.header;
        let block_bytes = encode(block_header.into_consensus());
        Ok(block_bytes)
    } else {
        Err(eyre::eyre!("Block not found"))
    }
}

pub async fn get_previous_values(selector: U256) -> Result<Bytes> {
    let call_abi = r#"[
        {
            "name": "latestStateAddress",
            "type": "function",
            "inputs": [
                {
                    "name": "io",
                    "type": "uint256"
                }
            ],
            "outputs": [
                {
                    "type": "address"
                }
            ],
            "stateMutability": "view"
        }
    ]"#;

    let provider = get_provider().await?;
    let rollup_address = "0xe7f4b0a3c9Bbf1af1456266e16412585eA6d172B"
        .parse()
        .expect("invalid address");

    let abi: JsonAbi = serde_json::from_str(call_abi)?;
    let interface = Interface::new(abi);

    let contract = interface.connect(rollup_address, &provider);
    let call_builder = contract.function("latestStateAddress", &[selector.into()])?;
    println!("getting state address");
    let state_address = call_builder.call().await?;

    println!("state address {:?}", state_address);
    let code = provider.get_code_at(state_address[0].as_address().unwrap()).await?;
    println!("code length: {}", code.len());
    Ok(code)
}
