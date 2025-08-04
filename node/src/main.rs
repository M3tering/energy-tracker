use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    response::Json,
    routing::{get, post},
};
use diesel::{
    prelude::{Insertable, Queryable}, r2d2::{self, ConnectionManager}, table, PgConnection, RunQueryDsl
};
use energy_tracker_lib::{destructure_payload};
use serde::{Deserialize, Serialize};
use serde_json::json;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[derive(Queryable, Serialize, Debug)]
struct M3terPayload {
    id: i32,
    m3ter_id: i64,
    message: String,
    signature: String,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = m3ter_payloads)]
struct NewM3terPayload {
    m3ter_id: i64,
    message: String,
    signature: String,
}

table! {
    m3ter_payloads (id) {
        id -> Int4,
        m3ter_id -> Int8,
        message -> VarChar,
        signature -> VarChar,
    }
}

#[tokio::main]
async fn main() {
    // Define a simple route
    println!("connecting to database...");
    let db_pool = establish_db_connection();
    let db_state = Arc::new(db_pool);
    println!("connected to database");

    let app = Router::new()
        .route("/", get(root))
        .route("/payload", post(payload_handler))
        .with_state(db_state);

    // Run the server on localhost:3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve::serve(listener, app).await.unwrap();
    println!("Server running on http://localhost:3000");
}

fn establish_db_connection() -> DbPool {
    let manager =
        ConnectionManager::<PgConnection>::new("postgres://aquinas:aquinas@localhost:5432/m3tering-db");
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}

// Handler function
async fn root() -> Json<serde_json::Value> {
    Json(json!({ "message": "Hello, world!" }))
}

async fn payload_handler(
    State(db_state): State<Arc<DbPool>>,
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    println!("Received payload: {:?}", payload);
    let mut connection = db_state.get().unwrap();

    let m3ter_id = payload.get("m3ter_id")
        .and_then(|v| v.as_str())
        .expect("Missing m3ter_id")
        .parse::<i64>()
        .expect("Invalid m3ter_id");
    let (message, signature, _, _) = payload.get("payload")
        .and_then(|v| v.as_str())
        .map(destructure_payload)
        .expect("Missing payload");
    
    let new_payload = NewM3terPayload {
        m3ter_id,
        message: message.to_string(),
        signature: signature.to_string(),
    };
    println!("Inserting payload");
    let inserted: M3terPayload = diesel::insert_into(m3ter_payloads::table)
        .values(&new_payload)
        .get_result(&mut connection)
        .expect("Failed to insert payload");

    println!("Inserted payload: {:?}", inserted);
    Json(json!({ "received": inserted }))
}
