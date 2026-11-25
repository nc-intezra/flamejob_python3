//! Interop fixture generator.
//!
//! Replicates, byte-for-byte, the crypto/auth primitives the flamejob Rust
//! server uses (crypto.rs `Cipher` + `key_from_config`, auth.rs `issue_token`
//! / `hash_password` / `api_key_hash`), using the SAME crate versions. It
//! emits a JSON blob of real Rust-produced artifacts that the Python port's
//! pytest suite then verifies/decrypts — the Phase-0 format-interop proof that
//! underwrites the strangler migration.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng as RandOsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use uuid::Uuid;

// Mirror of flamejob-core model.rs Role (serde rename_all = "lowercase").
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    Superadmin,
    Admin,
    Operator,
    Viewer,
}

// Mirror of flamejob-server auth.rs Claims.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: Uuid,
    username: String,
    roles: Vec<Role>,
    exp: i64,
    iat: i64,
}

// crypto.rs: nonce(12) || ciphertext(+16 tag).
fn aes_encrypt(key_bytes: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
    let mut out = nonce.to_vec();
    let ct = cipher.encrypt(&nonce, plaintext).expect("encrypt");
    out.extend(ct);
    out
}

// crypto.rs key_from_config dev path: SHA-256(jwt_secret).
fn key_from_secret(secret: &str) -> [u8; 32] {
    let digest = Sha256::digest(secret.as_bytes());
    let mut k = [0u8; 32];
    k.copy_from_slice(&digest);
    k
}

// auth.rs issue_token: HS256 over Claims.
fn issue_token(secret: &str, claims: &Claims) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("encode jwt")
}

// auth.rs hash_password: Argon2::default() (Argon2id, v19, default params).
fn hash_password(pw: &str) -> String {
    let salt = SaltString::generate(&mut RandOsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .expect("hash")
        .to_string()
}

// auth.rs api_key_hash: hex(SHA-256(key)).
fn api_key_hash(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Serialize)]
struct Fixtures {
    note: String,
    jwt_secret: String,
    user_id: Uuid,
    username: String,
    roles: Vec<Role>,
    jwt: String,
    jwt_exp: i64,
    jwt_iat: i64,
    // AES record whose key is SHA-256(jwt_secret) (the dev-derivation path).
    aes_key_from_secret_hex: String,
    aes_plaintext: String,
    aes_record_hex: String,
    // AES record under an explicit random 32-byte key (the key-file path).
    aes_explicit_key_hex: String,
    aes_explicit_plaintext: String,
    aes_explicit_record_hex: String,
    // Argon2id PHC string for the given password.
    password: String,
    argon2_hash: String,
    // API-key fingerprint.
    api_key: String,
    api_key_hash: String,
}

/// Request the Python side writes to this binary's stdin in `verify` mode:
/// Python-produced artifacts that the real Rust crates must accept.
#[derive(Deserialize)]
struct VerifyReq {
    jwt: String,
    jwt_secret: String,
    argon2_hash: String,
    password: String,
    aes_key_hex: String,
    aes_record_hex: String,
    aes_expect_plaintext: String,
}

/// `verify` mode: read a VerifyReq JSON on stdin, prove each Python-produced
/// artifact verifies/decrypts under the real Rust crates. Exit 0 on full
/// success; print the first failure and exit 1. This is the Python->Rust
/// direction of the interop proof.
fn run_verify() -> i32 {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        eprintln!("verify: failed to read stdin");
        return 1;
    }
    let req: VerifyReq = match serde_json::from_str(&buf) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("verify: bad request json: {e}");
            return 1;
        }
    };

    // 1) JWT minted by Python verifies under Rust jsonwebtoken (HS256).
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    match decode::<Claims>(
        &req.jwt,
        &DecodingKey::from_secret(req.jwt_secret.as_bytes()),
        &validation,
    ) {
        Ok(data) => {
            eprintln!("verify: jwt OK (sub={}, roles={:?})", data.claims.sub, data.claims.roles);
        }
        Err(e) => {
            eprintln!("verify: jwt FAILED: {e}");
            return 1;
        }
    }

    // 2) Argon2 PHC string produced by Python verifies under Rust argon2.
    match PasswordHash::new(&req.argon2_hash)
        .and_then(|p| Argon2::default().verify_password(req.password.as_bytes(), &p))
    {
        Ok(()) => eprintln!("verify: argon2 OK"),
        Err(e) => {
            eprintln!("verify: argon2 FAILED: {e}");
            return 1;
        }
    }

    // 3) AES-GCM record written by Python decrypts under Rust aes-gcm.
    let key_bytes = match hex::decode(&req.aes_key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            eprintln!("verify: aes key bad");
            return 1;
        }
    };
    let record = match hex::decode(&req.aes_record_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("verify: aes record hex bad: {e}");
            return 1;
        }
    };
    if record.len() < 12 {
        eprintln!("verify: aes record too short");
        return 1;
    }
    let (nonce, ct) = record.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    match cipher.decrypt(Nonce::from_slice(nonce), ct) {
        Ok(pt) if pt == req.aes_expect_plaintext.as_bytes() => eprintln!("verify: aes OK"),
        Ok(_) => {
            eprintln!("verify: aes plaintext mismatch");
            return 1;
        }
        Err(e) => {
            eprintln!("verify: aes FAILED: {e}");
            return 1;
        }
    }

    eprintln!("verify: ALL OK");
    0
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("verify") {
        std::process::exit(run_verify());
    }
    let jwt_secret = "interop-proof-secret-0123456789abcdef";
    let user_id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
    let username = "interop.user";
    let roles = vec![Role::Operator, Role::Admin];

    let now = Utc::now();
    let exp = (now + Duration::hours(1)).timestamp();
    let iat = now.timestamp();
    let claims = Claims {
        sub: user_id,
        username: username.to_string(),
        roles: roles.clone(),
        exp,
        iat,
    };
    let jwt = issue_token(jwt_secret, &claims);

    let key = key_from_secret(jwt_secret);
    let aes_plaintext = "hunter2 :: cracked plaintext ✓";
    let record = aes_encrypt(&key, aes_plaintext.as_bytes());

    let mut explicit_key = [0u8; 32];
    use rand::RngCore;
    RandOsRng.fill_bytes(&mut explicit_key);
    let aes_explicit_plaintext = "second-record under an explicit key-file key";
    let explicit_record = aes_encrypt(&explicit_key, aes_explicit_plaintext.as_bytes());

    let password = "correct horse battery staple";
    let argon2_hash = hash_password(password);

    let api_key = "fj_0123456789abcdef0123456789abcdef";

    let fixtures = Fixtures {
        note: "Real Rust-produced crypto/auth artifacts (pinned crate versions). \
               Consumed by the Python port's interop pytest."
            .to_string(),
        jwt_secret: jwt_secret.to_string(),
        user_id,
        username: username.to_string(),
        roles,
        jwt,
        jwt_exp: exp,
        jwt_iat: iat,
        aes_key_from_secret_hex: hex::encode(key),
        aes_plaintext: aes_plaintext.to_string(),
        aes_record_hex: hex::encode(record),
        aes_explicit_key_hex: hex::encode(explicit_key),
        aes_explicit_plaintext: aes_explicit_plaintext.to_string(),
        aes_explicit_record_hex: hex::encode(explicit_record),
        password: password.to_string(),
        argon2_hash,
        api_key: api_key.to_string(),
        api_key_hash: api_key_hash(api_key),
    };

    println!("{}", serde_json::to_string_pretty(&fixtures).unwrap());
}
