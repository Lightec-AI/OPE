mod vectors;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};
use ope_envelope::{verify_envelope, VerifyOptions};
use vectors::VectorFile;

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
    /// Sign and refresh vector 001 (legacy)
    Sign {
        #[arg(long)]
        vector: PathBuf,
    },
    /// Regenerate all spec vectors 001–008
    GenVectors {
        #[arg(long, default_value = "spec/vectors")]
        dir: PathBuf,
    },
    /// Print dev mock public key (hex) for vector 001
    Keygen,
    /// Run X25519MLKEM768 hybrid KEX self-test
    TransportTest,
    /// HKDF record-key derivation self-test
    HkdfTest,
    /// Start mock attestation + verification HTTP server (§14)
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify { vector } => cmd_verify(&vector)?,
        Commands::Sign { vector } => {
            vectors::write_all_vectors(
                vector
                    .parent()
                    .unwrap_or(std::path::Path::new("spec/vectors")),
            )?;
            println!("Regenerated vectors in {}", vector.parent().unwrap().display());
        }
        Commands::GenVectors { dir } => {
            vectors::write_all_vectors(&dir)?;
            println!("Wrote vectors 001–008 to {}", dir.display());
        }
        Commands::Keygen => cmd_keygen()?,
        Commands::TransportTest => cmd_transport_test()?,
        Commands::HkdfTest => cmd_hkdf_test()?,
        Commands::Serve { addr } => cmd_serve(&addr)?,
    }
    Ok(())
}

fn cmd_verify(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let vector: VectorFile = serde_json::from_str(&text)?;
    let seed = hex::decode(vector.signing_key_seed_hex.trim())?;
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let kp = mock_keypair_from_seed(&seed_arr);

    let content_key = if vector.envelope.enc != "none" {
        Some(ope_crypto::DEV_CONTENT_KEY)
    } else {
        None
    };

    verify_envelope(
        &vector.envelope,
        &kp.public,
        &VerifyOptions {
            content_key,
            ..VerifyOptions::with_defaults()
        },
    )?;

    if vector.expect_verify == "fail" {
        return Err("vector marked expect_verify=fail but verification succeeded".into());
    }
    println!("OK: {}", vector.vector_id);
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

fn cmd_hkdf_test() -> Result<(), Box<dyn std::error::Error>> {
    use ope_transport::{client_shared_secret, derive_record_keys, ClientKeyExchange, ServerKeyExchange};

    let client = ClientKeyExchange::generate()?;
    let (server, _) = ServerKeyExchange::respond_to(&client)?;
    let secret = client_shared_secret(&client, &server)?;
    let keys = derive_record_keys(&secret, &[1u8; 32], &[2u8; 32])?;
    println!(
        "OK: HKDF record keys client={}… server={}…",
        hex::encode(&keys.client_write_key[..4]),
        hex::encode(&keys.server_write_key[..4]),
    );
    Ok(())
}

fn cmd_serve(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let socket: SocketAddr = addr.parse()?;
    println!("OPE mock server listening on http://{socket}");
    println!("  POST /v1/ope/attestations");
    println!("  POST /v1/ope/verifications:verifyEnvelope");
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(ope_server::serve(socket))?;
    Ok(())
}
