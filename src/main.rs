mod models;
use models::user::{User, LoginRequest, RegisterRequest};
use serde_json::json;
use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use jsonwebtoken::{encode, Header, EncodingKey};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use tokio_postgres::{NoTls, Client, Error};
use std::env;
use dotenvy::dotenv;
use std::sync::Arc;
use tokio::sync::Mutex;
use chrono::Utc;

/// JWT claims for authentication
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

/// DB Client
struct AppState {
    db_client: Client,
}

/// Connection to PSQL DB
async fn connect_db() -> Result<Client, Error> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Database connection error: {}", e);
        }
    });

    Ok(client)
}

/// User credentials in DB
async fn register_user(
    db: web::Data<Arc<Mutex<AppState>>>,
    req: web::Json<RegisterRequest>
) -> impl Responder {
    let db = db.lock().await;
    let client = &db.db_client;

    // Check if username already exists
    let rows = client.query("SELECT id FROM users WHERE username = $1", &[&req.username]).await;
    if let Ok(rows) = rows {
        if !rows.is_empty() {
            return HttpResponse::BadRequest().body("Username already taken");
        }
    }

    // Hash password
    let hashed_password = match hash(&req.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().body("Error hashing password"),
    };

    // Convert UUID to a string before inserting
    let id = Uuid::new_v4().to_string();

    let result = client
        .execute(
            "INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)",
            &[&id.to_string(), &req.username, &hashed_password],
        )
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("User registered successfully"),
        Err(_) => HttpResponse::InternalServerError().body("Error registering user"),
    }
}

/// User Authentication and generates JWT for valid user
async fn login(
    db: web::Data<Arc<Mutex<AppState>>>,
    req: web::Json<LoginRequest>
) -> impl Responder {
    let db = db.lock().await;
    let client = &db.db_client;

    // Find user
    let row = client
        .query_opt("SELECT password_hash FROM users WHERE username = $1", &[&req.username])
        .await
        .ok()
        .flatten();

    let user_password_hash = match row {
        Some(row) => row.get::<_, String>(0),
        None => return HttpResponse::Unauthorized().body("Invalid username or password"),
    };

    // Verify password
    if verify(&req.password, &user_password_hash).unwrap_or(false) {
        let expiration = Utc::now()
            .checked_add_signed(chrono::Duration::hours(24))
            .expect("valid timestamp")
            .timestamp() as usize;

        let claims = Claims {
            sub: req.username.clone(),
            exp: expiration,
        };

        let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "super_secret_key".to_string());
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref())
        )
            .unwrap();

        return HttpResponse::Ok().json(serde_json::json!({ "token": token }));
    }

    HttpResponse::Unauthorized().body("Invalid username or password")
}

async fn protected_route() -> impl Responder {
    HttpResponse::Ok().body("You have accessed a protected route!")
}

/// Main fxn for Actix web server
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let db_client = connect_db().await.expect("Failed to connect to DB");
    let app_state = Arc::new(Mutex::new(AppState { db_client }));

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .route("/register", web::post().to(register_user))
            .route("/login", web::post().to(login))
            .route("/protected", web::get().to(protected_route))
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
