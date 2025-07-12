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
   let program_vkey: FixedBytes<32> = hex!("00e64d74c60f66f2479dbf6cd8fe39a09ed90737a533660b2710bba732d85906").into();
   
   let public_values = Bytes::from(hex!("0600000000000000c3f5a83f712c2e42d9ddb2426abc01421f851b405839743f06000000000000004401000017110000e510000082090000de020000e00b00000600000000000000c3f5a83f712c2e42d9ddb2426abc01421f851b40c05d883f06000000000000004401000017110000e510000082090000de020000ea0b0000"));
   
   let proof_bytes = Bytes::from(hex!("a4594c5910f0e82df1b833f70771d3c51860d9852578a551e91e2315960d71d49ac67e7c286e35d480b3abcc9cbdccbce4b420a854d1e3255bda58ddc447dc461492a77f0577a2acf6814b1bd3fba4eeac9ed9fb95b0cac97520fa4d8ee9176cddce980500199294f534132eef1f3e9ad395ddcaf1a6526f8fcfd50503cddfccd7ac764306477288f4c3d4fe92862a6fd0485578dfc6c1f8d1d7a9d08e3f05732fc8147e223e25b5ec49905e8088d22718b4b5c72410d757558e0dad0b4c96bd47d77e6724fc81e0d6cc33ffd8b39ce9d9d1bd3bc099dd7f7923766a67563b19afdf4ae014ad57e9f4b88c8cf5d09a3d3eb71aaadcd342579fd8e8d3b199cc8bed3406d0"));

   // Set up the HTTP provider
   // Replace with your actual RPC URL
   let rpc_url = std::env::var("RPC_URL")
       .unwrap_or_else(|_| "https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY".to_string());

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