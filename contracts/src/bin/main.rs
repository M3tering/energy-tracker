use alloy::{
   // contract::,
   hex,
   // node_bindings::Anvil,
   primitives::{Address, Bytes, FixedBytes},
   providers::{ProviderBuilder},
   sol,
};
use eyre::Result;

// Define the SP1 Verifier interface using sol! macro
sol! {
   #[sol(rpc)]
   interface ISP1Verifier {
       /// @notice Verifies a proof with given public values and vkey.
       /// @param programVKey The verification key for the RISC-V program.
       /// @param publicValues The public values encoded as bytes.
       /// @param proofBytes The proof of the program execution the SP1 zkVM encoded as bytes.
       function verifyProof(
           bytes32 programVKey,
           bytes calldata publicValues,
           bytes calldata proofBytes
       ) external view;
   }
}

#[tokio::main]
async fn main() -> Result<()> {
   // Contract address
   let contract_address: Address = "0x397A5f7f3dBd538f23DE225B51f532c34448dA9B".parse()?;
   
   // Verification parameters
   let program_vkey: FixedBytes<32> = hex!("000abd9266caaa1025d27da6a98b16c1333de91e5b39f4d15c78e1fa6a164b54").into();
   
   let public_values = Bytes::from(hex!("0x21a64fea3bffd659d523c1b85ac28f75030f5503570ee7c1e1df942cce9d144054a8c0ab653c15bfb48b47fd011ba2b9617af01cb45cab344acd57c924d5679854a8c0ab653c15bfb48b47fd011ba2b9617af01cb45cab344acd57c924d56798000000f0eb89000000cadda0000000000002000000000002"));
   
   let proof_bytes = Bytes::from(hex!("a4594c59190e557e0dd8ce1d0a9f4070407680e8dbb0ecee314e222eb1a53f1d92cf9d30170de137c2f93da050f3317232cd760071921f0d0f57c8a3b15806121b9bb899035c969d578a8eb240238592eba419b74ca239b5835c55e78960d101c94b2ac806381a8a8b1d45c6f7fd7e393b916bd5a4b1ad0faea2c28257a8dd93c27affbc047c0db8896d877c6ab00ba746aa63fab3b76a674ba6e85011a7c1862922d3781a402f08e5988eb220bbf9ca98704d8c8049b31643a2114750c15bccbd8541a9196ad7612f2b296b8de16670f952e89dab95affdbb9de767f97d4ac54a6f0ff326217073fba7e0b8c1d062dabc11a78feb5ccdc1a342cadb9ac3732cd1e83805"));

   // Set up the HTTP provider
   // Replace with your actual RPC URL
   let rpc_url = std::env::var("RPC_URL")
       .unwrap_or_else(|_| "https://eth-sepolia.g.alchemy.com/v2/URjQnzNCUHumxPFL8VDoFBmpX4uqL6X8".to_string());

   println!("Using RPC URL: {}", rpc_url);
   
   let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);

   println!("🚀 Starting SP1 Verifier call...");
   println!("📍 Contract address: {}", contract_address);
   println!("🔑 Program VKey: 0x{}", hex::encode(program_vkey));
   println!("📊 Public values length: {} bytes", public_values.len());
   println!("🔍 Proof length: {} bytes", proof_bytes.len());


   // Create the contract instance
   let contract = ISP1Verifier::new(contract_address, &provider);

   // Call the verifyProof function
   match contract.verifyProof(program_vkey, public_values, proof_bytes).call().await {
       Ok(_res) => {
           println!("✅ Proof verification successful!");
       }
       Err(e) => {
           println!("❌ Proof verification failed: {}", e);
           
           // Try to get more detailed error information
         //   if let Some(revert_reason) = e.as_revert() {
         //       println!("🔍 Revert reason: {}", revert_reason);
         //   }
       }
   }

   Ok(())
}