use std::{collections::HashMap, env, sync::Arc};

use alloy_primitives::{B256, Bytes, U256, hex};
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use diesel::{
    PgConnection, RunQueryDsl,
    prelude::{Insertable, Queryable, QueryableByName},
    r2d2::{self, ConnectionManager, PooledConnection},
    sql_query, table,
};

use energy_tracker_lib::{
    Payload, ProofStruct, PublicValuesStruct, calc_slot_key, destructure_payload, extract_nonce,
};
use energy_tracker_verifier::{
    commit_state, get_block_rpl_bytes, get_previous_values, get_provider, get_storage_proofs,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp1_sdk::{
    HashableKey, Prover, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
    include_elf,
};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ENERGY_TRACKER_ELF: &[u8] = include_elf!("energy-tracker-program");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofFixture {
    previous_balances: B256,
    previous_nonces: B256,
    new_balances: Bytes,
    new_nonces: Bytes,
    block_hash: B256,
    vkey: String,
    public_values: String,
    proof: Bytes,
}

#[derive(Serialize, Deserialize, Debug)]
struct M3terPayloadInbound {
    m3ter_id: i64,
    message: String,
}

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[derive(Queryable, QueryableByName, Insertable, Serialize, Debug)]
struct M3terPayload {
    id: i32,
    m3ter_id: i64,
    message: String,
    signature: String,
    nonce: i64,
    energy: i64,
    is_verified: bool,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = m3ter_payloads)]
struct NewM3terPayload {
    m3ter_id: i64,
    message: String,
    signature: String,
    nonce: i64,
    energy: i64,
    is_verified: bool,
}

table! {
    m3ter_payloads (id) {
        id -> Int4,
        m3ter_id -> Int8,
        message -> VarChar,
        signature -> VarChar,
        nonce -> Int8,
        energy -> Int8,
        is_verified -> Bool,
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    sp1_sdk::utils::setup_logger();
    // Define a simple route
    println!("connecting to database...");
    let db_pool = establish_db_connection();
    let db_state = Arc::new(db_pool);
    println!("connected to database");

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/payload", post(payload_handler))
        .route("/batch-payloads", post(batch_payload_handler))
        .route("/run_prover", get(run_prover_handler))
        .route("/vkey", get(get_prover_vkey))
        .with_state(db_state);

    println!("Starting server on http://localhost:8080");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    axum::serve::serve(listener, app).await.unwrap();
}

fn establish_db_connection() -> DbPool {
    let manager = ConnectionManager::<PgConnection>::new(
        "postgres://aquinas:aquinas@localhost:5432/m3tering-db",
    );
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}

// Handler function
async fn root() -> Json<serde_json::Value> {
    Json(json!({ "message": "Hello, world!" }))
}

async fn health(State(db_state): State<Arc<DbPool>>) -> Json<serde_json::Value> {
    let connection = db_state.get().is_ok();
    let code = if connection { 200 } else { 500 };
    Json(json!({ "code": code, "success": code == 200 }))
}

async fn payload_handler(
    State(db_state): State<Arc<DbPool>>,
    Json(payload): Json<M3terPayloadInbound>,
) -> (StatusCode, Json<serde_json::Value>) {
    println!("Received payload: {:?}", payload);

    let mut connection = db_state.get().unwrap();

    let m3ter_id = payload.m3ter_id;
    let (message, signature, nonce, energy) = destructure_payload(&payload.message);

    if !is_unique_nonce(&mut connection, m3ter_id, nonce as i64) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Nonce already exists" })),
        );
    }

    let new_payload = NewM3terPayload {
        m3ter_id,
        message: message.to_string(),
        signature: signature.to_string(),
        nonce: nonce as i64,
        energy: energy as i64,
        is_verified: false
    };
    println!("Inserting payload");
    let inserted: M3terPayload = diesel::insert_into(m3ter_payloads::table)
        .values(&new_payload)
        .get_result(&mut connection)
        .expect("Failed to insert payload");

    println!("Inserted payload: {:?}", inserted);
    (StatusCode::OK, Json(json!({ "received": inserted })))
}

async fn batch_payload_handler(
    State(db_state): State<Arc<DbPool>>,
    Json(payloads): Json<Vec<M3terPayloadInbound>>,
) -> Json<serde_json::Value> {
    let mut connection = db_state.get().unwrap();
    let received_count = payloads.len();

    let new_payloads = payloads
        .into_iter()
        .filter(|item| {
            is_unique_nonce(&mut connection, item.m3ter_id, extract_nonce(&item.message))
        })
        .map(|payload| {
            let m3ter_id = payload.m3ter_id;
            let (message, signature, nonce, energy) = destructure_payload(&payload.message);
            NewM3terPayload {
                m3ter_id,
                message: message.to_string(),
                signature: signature.to_string(),
                nonce: nonce as i64,
                energy: energy as i64,
                is_verified: false
            }
        })
        .collect::<Vec<NewM3terPayload>>();

    println!("Inserting payload");
    let inserted: Vec<M3terPayload> = diesel::insert_into(m3ter_payloads::table)
        .values(&new_payloads)
        .get_results(&mut connection)
        .expect("Failed to insert payload");

    println!("Inserted payload: {:?}", inserted);
    Json(
        json!({ "inserted": inserted, "nonces_inserted": inserted.len(), "nonces_repeated": received_count - inserted.len() }),
    )
}

async fn run_prover_handler(
    State(db_state): State<Arc<DbPool>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let proof_type = params
        .get("proof_type")
        .map(|s| {
            if s != "plonk" && s != "groth16" {
                "groth16"
            } else {
                s
            }
        })
        .unwrap_or("groth16");

    let mut connection = db_state.get().unwrap();
    let provider = get_provider().await.expect("Failed to get provider");
    let proving_payload = sql_query(
        "SELECT *
        FROM m3ter_payloads
        WHERE is_verified = FALSE 
        ORDER BY m3ter_id, nonce ASC",
    )
    .load::<M3terPayload>(&mut connection)
    .expect("Failed to load payloads");

    let mut grouped: HashMap<String, Vec<energy_tracker_lib::M3terPayload>> = HashMap::new();
    for payload in &proving_payload {
        grouped
            .entry(payload.m3ter_id.to_string())
            .or_default()
            .push(energy_tracker_lib::M3terPayload::new(
                payload.message.clone(),
                payload.signature.clone(),
                payload.nonce as u64,
                payload.energy as u64,
            ));
    }

    let previous_nonces = get_previous_values(&provider, U256::from(1)).await.unwrap();
    let previous_balances = get_previous_values(&provider, U256::from(0)).await.unwrap();

    let slot_keys = grouped
        .keys()
        .map(|key| {
            let m3ter_id: u64 = key.parse().expect("meter id not valid");
            m3ter_id
        })
        .map(|m3ter_id| calc_slot_key(U256::from(m3ter_id)).unwrap())
        .map(|slot_key| B256::from_slice(&slot_key.to_be_bytes_vec()))
        .collect();

    let (account_proof, encoded_account, storage_hash, proofs, anchor_block) =
        get_storage_proofs(&provider, slot_keys).await.unwrap();

        println!("{:?}", proofs);

    let block_bytes = get_block_rpl_bytes(&provider, anchor_block).await.unwrap();

    println!("Loaded payloads: {:?}", grouped);
    println!("Anchor Block: {}", anchor_block);
    let payload = Payload {
        mempool: grouped,
        previous_nonces: previous_nonces.into(),
        previous_balances: previous_balances.into(),
        proofs: Some(ProofStruct {
            account_proof,
            encoded_account,
            storage_hash,
            proofs,
        }),
        block_bytes: Some(block_bytes),
    };

    let mut stdin = SP1Stdin::new();
    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set in .env");
    let rpc_url = env::var("NETWORK_RPC_URL").expect("RPC_URL not set in .env");
    stdin.write(&payload);
    let prover_client = ProverClient::builder()
        // .network()
        // .private_key(&private_key)
        // .rpc_url(&rpc_url)
        .cpu()
        .build();

    let (pk, vk) = prover_client.setup(ENERGY_TRACKER_ELF);

    let proof = match proof_type {
        "plonk" => prover_client.prove(&pk, &stdin).plonk().run(),
        "groth16" => prover_client.prove(&pk, &stdin).groth16().run(),
        _ => panic!("Unsupported proof type: {}", proof_type),
    }
    .expect("proof supposed to be generated");

    let proof_fixture = create_proof_fixture(&proof, &vk);
    println!("Proof generated successfully proof = {:?}", &proof_fixture);

    println!("Committing state ...");
    let hash = commit_state(
        &provider,
        anchor_block,
        &proof_fixture.new_balances,
        &proof_fixture.new_nonces,
        &proof_fixture.proof,
    )
    .await
    .expect("msg: Failed to commit state");

    update_payload(&mut connection, proving_payload).await;
    Json(json!({
        "code": 200,
        "success": true,
        "proof": proof_fixture,
        "tx_hash": hash,
    }))
}

async fn get_prover_vkey() -> Json<serde_json::Value> {
    let prover = ProverClient::builder().cpu().build();
    let (_, vk) = prover.setup(ENERGY_TRACKER_ELF);
    Json(json!({
        "vkey": vk.bytes32()
    }))
}

async fn update_payload(
    connection: &mut PooledConnection<ConnectionManager<PgConnection>>,
    payloads: Vec<M3terPayload>
) {
    use diesel::prelude::*;
    use self::m3ter_payloads::dsl::*;

    diesel::update(m3ter_payloads.filter(id.eq_any(payloads.iter().map(|p| p.id))))
        .set(is_verified.eq(true))
        .execute(connection)
        .expect("Failed to update payloads");
    println!("Updated {} payloads to verified", payloads.len());
}

fn is_unique_nonce(
    connection: &mut PooledConnection<ConnectionManager<PgConnection>>,
    i_m3ter_id: i64,
    i_nonce: i64,
) -> bool {
    use self::m3ter_payloads::dsl::*;
    use diesel::prelude::*;

    match m3ter_payloads
        .filter(m3ter_id.eq(i_m3ter_id).and(nonce.eq(i_nonce)))
        .first::<M3terPayload>(connection)
    {
        Ok(_) => {
            println!(
                "Nonce {} for m3ter {} already exists in the database",
                i_nonce, i_m3ter_id
            );
            false
        }
        Err(_) => {
            println!("Nonce {} for m3ter {} is unique", i_nonce, i_m3ter_id);
            true
        }
    }
}

fn create_proof_fixture(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey) -> ProofFixture {
    let bytes = proof.public_values.as_slice();
    let output = PublicValuesStruct::from_bytes(bytes);
    let PublicValuesStruct {
        previous_balances,
        previous_nonces,
        new_balances,
        new_nonces,
        block_hash,
    } = output;

    // Create the testing fixture so we can test things end-to-end.
    ProofFixture {
        previous_balances,
        previous_nonces,
        new_balances,
        new_nonces,
        block_hash,
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: proof.bytes().into(),
    }
}
