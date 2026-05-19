use std::fs;
use std::path::PathBuf;

use chrono::Utc;
use clap::{Parser, Subcommand};
use ope_crypto::{encode, mock_keypair_from_seed, DEV_VECTOR_001_SEED};
use ope_envelope::{sign_envelope, verify_envelope, Envelope, VerifyOptions};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Parser)]
#[command(name = "ope", about = "Open Privacy Envelope tooling")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify an envelope from a vector JSON file
    Verify {
        #[arg(long)]
        vector: PathBuf,
    },
    /// Sign and refresh a vector JSON file (dev mock keys)
    Sign {
        #[arg(long)]
        vector: PathBuf,
    },
    /// Print dev mock public key (hex) for vector 001
    Keygen,
    /// Run X25519MLKEM768 hybrid KEX self-test
    TransportTest,
}

#[derive(Serialize, Deserialize)]
struct VectorFile {
    vector_id: String,
    description: String,
    dev_only: bool,
    signing_key_seed_hex: String,
    verifying_key_hex: String,
    envelope: Envelope,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify { vector } => cmd_verify(&vector)?,
        Commands::Sign { vector } => cmd_sign(&vector)?,
        Commands::Keygen => cmd_keygen()?,
        Commands::TransportTest => cmd_transport_test()?,
    }
    Ok(())
}

fn cmd_verify(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let vector = load_vector(path)?;
    let seed = hex::decode(vector.signing_key_seed_hex.trim())?;
    if seed.len() != 32 {
        return Err("signing_key_seed_hex must be 32 bytes".into());
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let kp = mock_keypair_from_seed(&seed_arr);

    verify_envelope(
        &vector.envelope,
        &kp.public,
        &VerifyOptions::with_defaults(),
    )?;
    println!("OK: {}", vector.vector_id);
    Ok(())
}

fn cmd_sign(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut vector = if path.exists() {
        load_vector(path)?
    } else {
        default_vector_001()?
    };

    let seed = hex::decode(vector.signing_key_seed_hex.trim())?;
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let kp = mock_keypair_from_seed(&seed_arr);

    let mut env = sample_envelope();
    sign_envelope(&mut env, &kp.secret)?;
    vector.envelope = env;
    vector.verifying_key_hex = hex::encode(kp.public_key_bytes());

    let out = serde_json::to_string_pretty(&vector)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, out)?;
    println!("Wrote signed vector to {}", path.display());
    Ok(())
}

fn cmd_keygen() -> Result<(), Box<dyn std::error::Error>> {
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    println!("seed_hex: {}", hex::encode(DEV_VECTOR_001_SEED));
    println!("verify_key_hex: {}", hex::encode(kp.public_key_bytes()));
    Ok(())
}

fn cmd_transport_test() -> Result<(), Box<dyn std::error::Error>> {
    use ope_transport::{client_shared_secret, ClientKeyExchange, ServerKeyExchange};

    let client = ClientKeyExchange::generate()?;
    let (server, server_ss) = ServerKeyExchange::respond_to(&client)?;
    let client_ss = client_shared_secret(&client, &server)?;
    assert_eq!(client_ss, server_ss);
    println!(
        "OK: X25519MLKEM768 shared secret {} bytes",
        client_ss.len()
    );
    Ok(())
}

fn load_vector(path: &PathBuf) -> Result<VectorFile, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn default_vector_001() -> Result<VectorFile, Box<dyn std::error::Error>> {
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    Ok(VectorFile {
        vector_id: "001-valid-plaintext".into(),
        description: "Valid signed plaintext envelope (enc=none), mock dev keys".into(),
        dev_only: true,
        signing_key_seed_hex: hex::encode(DEV_VECTOR_001_SEED),
        verifying_key_hex: hex::encode(kp.public_key_bytes()),
        envelope: sample_envelope(),
    })
}

fn sample_envelope() -> Envelope {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);

    Envelope {
        ope_version: Envelope::VERSION.into(),
        alg: Envelope::ALG_EDDSA.into(),
        enc: Envelope::ENC_NONE.into(),
        kid: "mock-sender-001".into(),
        recipient: "gateway-dev".into(),
        ts: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        nonce: encode(&nonce),
        payload_hash: String::new(),
        payload: Some(json!({
            "model": "gpt-4.1@openai",
            "messages": [{"role": "user", "content": "hello"}]
        })),
        ciphertext: None,
        iv: None,
        aad: None,
        meta: None,
        sig: None,
    }
}
