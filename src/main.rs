use actix_web::{web, App, HttpResponse, HttpServer, Result};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
};
use spl_token::instruction as spl_instruction;
use spl_associated_token_account::get_associated_token_address;
use std::str::FromStr;
use base64::Engine;

// Error response structure
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// Keypair endpoint
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    let response = KeypairResponse {
        pubkey: keypair.pubkey().to_string(),
        secret: bs58::encode(keypair.to_bytes()).into_string(),
    };
    Ok(HttpResponse::Ok().json(response))
}

// Token create endpoint
#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct MintTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid mint authority".to_string() })),
    };
    
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid mint address".to_string() })),
    };

    let instruction = spl_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ).unwrap();

    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response = CreateTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(response))
}

// Token mint endpoint
#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid mint address".to_string() })),
    };
    
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid destination address".to_string() })),
    };
    
    let authority = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid authority address".to_string() })),
    };

    let instruction = spl_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ).unwrap();

    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response = MintTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(response))
}

// Message signing endpoint
#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    if req.message.is_empty() || req.secret.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Missing required fields".to_string() }));
    }

    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid secret key format".to_string() })),
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid secret key".to_string() })),
    };

    let message_bytes = req.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response = SignMessageResponse {
        signature: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: req.message.clone(),
    };

    Ok(HttpResponse::Ok().json(response))
}

// Message verification endpoint
#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid public key".to_string() })),
    };

    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid signature format".to_string() })),
    };

    let signature = match solana_sdk::signature::Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid signature".to_string() })),
    };

    let message_bytes = req.message.as_bytes();
    let valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    let response = VerifyMessageResponse {
        valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    };

    Ok(HttpResponse::Ok().json(response))
}

// Send SOL endpoint
#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    let from_pubkey = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid from address".to_string() })),
    };
    
    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid to address".to_string() })),
    };

    if req.lamports == 0 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Amount must be greater than 0".to_string() }));
    }

    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);

    let response = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect(),
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(response))
}

// Send Token endpoint
#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct TokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<TokenAccountInfo>,
    instruction_data: String,
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid destination address".to_string() })),
    };
    
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid mint address".to_string() })),
    };
    
    let owner = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid owner address".to_string() })),
    };

    if req.amount == 0 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: "Amount must be greater than 0".to_string() }));
    }

    // Get associated token accounts
    let source_ata = get_associated_token_address(&owner, &mint);
    let destination_ata = get_associated_token_address(&destination, &mint);

    let instruction = spl_instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &destination_ata,
        &owner,
        &[],
        req.amount,
    ).unwrap();

    let accounts: Vec<TokenAccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| TokenAccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    let response = SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting Solana HTTP server on port 8080...");

    HttpServer::new(|| {
        App::new()
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
