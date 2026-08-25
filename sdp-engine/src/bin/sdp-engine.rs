//! Thin CLI wrapper. All real logic lives in `sdp_engine::api` and is shared verbatim
//! with the FFI boundary (`sdp_engine::ffi`) used by the Java host — this binary exists
//! for local testing, scripting, and the standalone demo commands, not as a second
//! implementation of the algorithm.

use clap::{Parser, Subcommand};
use std::fs;
use std::process::exit;

use sdp_engine::api::{api_commit, api_generate_keypair, api_verify};

#[derive(Parser)]
#[command(name = "sdp-engine", about = "SDP-1 Semantic Delta Proof deterministic core")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 keypair. Prints "<privkey_hex> <pubkey_hex>" to stdout.
    GenerateKeypair,
    /// Commit a document: extract claims, canonicalize, build Merkle tree, sign root.
    Commit {
        #[arg(long)]
        doc: String,
        #[arg(long)]
        schema: String,
        #[arg(long)]
        privkey: String,
        #[arg(long, default_value = "1.0")]
        schema_version: String,
    },
    /// Verify a current document representation against a signed original commitment.
    Verify {
        #[arg(long)]
        doc: String,
        #[arg(long)]
        schema: String,
        #[arg(long)]
        commitment: String,
    },
}

fn read_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("cannot read {}: {}", path, e)))
}

fn fail(msg: &str) -> ! {
    println!("{}", serde_json::json!({ "error": msg }));
    exit(1);
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::GenerateKeypair => {
            println!("{}", api_generate_keypair());
        }

        Command::Commit { doc, schema, privkey, schema_version } => {
            let doc_json = read_file(&doc);
            let schema_json = read_file(&schema);
            match api_commit(&doc_json, &schema_json, &privkey, &schema_version) {
                Ok(out) => println!("{}", out),
                Err(e) => fail(&e),
            }
        }

        Command::Verify { doc, schema, commitment } => {
            let doc_json = read_file(&doc);
            let schema_json = read_file(&schema);
            let commitment_json = read_file(&commitment);
            match api_verify(&doc_json, &schema_json, &commitment_json) {
                Ok(out) => println!("{}", out),
                Err(e) => fail(&e),
            }
        }
    }
}
