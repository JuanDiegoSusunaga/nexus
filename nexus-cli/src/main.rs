//! NEXUS CLI - Command Line Interface
//!
//! Main entry point for the NEXUS blockchain node.

use clap::{Parser, Subcommand};
use nexus_core::SignatureScheme;
use nexus_crypto::DilithiumKeypair;
use nexus_node::{NexusNode, NodeRole};
mod testnet;

#[derive(Parser)]
#[command(name = "nexus")]
#[command(author = "Juan Diego Susunaga Velasquez")]
#[command(version = "0.1.0")]
#[command(about = "NEXUS Dual-Chain Post-Quantum Blockchain", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize, run or query the experimental TCP testnet
    Testnet {
        #[command(subcommand)]
        command: testnet::Command,
    },
    /// Start a node
    Node {
        /// Node role (validator, sequencer, full, light)
        #[arg(short, long, default_value = "full")]
        role: String,

        /// Data directory
        #[arg(short, long, default_value = "./data")]
        data_dir: String,
    },

    /// Generate a new keypair
    Keygen {
        /// Security level (2, 3, or 5)
        #[arg(short, long, default_value = "3")]
        level: u8,

        /// Output file
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Show node info
    Info,

    /// Run benchmarks
    Bench {
        /// Benchmark type (crypto, consensus, all)
        #[arg(short, long, default_value = "all")]
        bench_type: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ML-DSA and the debug async state machines exceed the default Windows
    // main-thread stack. A Rust thread creates no additional console window.
    std::thread::Builder::new().name("nexus-main".into()).stack_size(8 * 1024 * 1024)
        .spawn(|| run_main().map_err(|error| error.to_string()))?
        .join().map_err(|_| "NEXUS runtime thread failed")?
        .map_err(Into::into)
}

#[tokio::main(worker_threads = 4)]
async fn run_main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("nexus=info".parse()?)
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Testnet { command } => testnet::execute(command).await?,
        Commands::Node { role, data_dir } => {
            run_node(&role, &data_dir).await?;
        }
        Commands::Keygen { level, output } => {
            generate_keypair(level, output)?;
        }
        Commands::Info => {
            show_info();
        }
        Commands::Bench { bench_type } => {
            run_benchmarks(&bench_type)?;
        }
    }

    Ok(())
}

async fn run_node(role: &str, _data_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let node_role = match role {
        "validator" => NodeRole::Validator,
        "sequencer" => NodeRole::Sequencer,
        "light" => NodeRole::LightClient,
        _ => NodeRole::FullNode,
    };

    println!("NEXUS Dual-Chain Blockchain");
    println!("===========================");
    println!("Starting {} node...", role);

    // Generate temporary keypair (in production, load from file)
    let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3)?;
    println!("Node address: {}", keypair.address());

    let node = NexusNode::new(node_role, keypair);
    node.start().await?;

    let info = node.info();
    println!("L1 Height: {:?}", info.l1_height);
    println!("L2 Height: {:?}", info.l2_height);

    // Keep running
    println!("\nLocal reference initialized. Use 'nexus testnet run' for TCP networking. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;

    node.stop().await?;
    println!("Node stopped.");

    Ok(())
}

fn generate_keypair(level: u8, output: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let scheme = match level {
        2 => SignatureScheme::Dilithium2,
        3 => SignatureScheme::Dilithium3,
        5 => SignatureScheme::Dilithium5,
        _ => {
            println!("Invalid level. Using Dilithium3.");
            SignatureScheme::Dilithium3
        }
    };

    println!("Generating {:?} keypair...", scheme);
    let keypair = DilithiumKeypair::generate(scheme)?;

    println!("Address: {}", keypair.address());
    println!("Public key size: {} bytes", keypair.public_key().as_bytes().len());

    if let Some(path) = output {
        let bytes = keypair.to_bytes();
        std::fs::write(&path, &bytes)?;
        println!("Keypair saved to: {}", path);
    } else {
        println!("Public key (hex): {}", hex::encode(keypair.public_key().as_bytes()));
    }

    Ok(())
}

fn show_info() {
    println!("NEXUS Dual-Chain Blockchain");
    println!("===========================");
    println!("Version: 0.1.0");
    println!();
    println!("Architecture:");
    println!("  - Anchor Layer (L1): Consensus, Data Availability");
    println!("  - Active Layer (L2): Execution, Sequencing");
    println!();
    println!("Cryptography:");
    println!("  - Signatures: CRYSTALS-Dilithium (PQC)");
    println!("  - Hashing: SHA3-256, BLAKE3");
    println!("  - Validity experiment: scalar AIR/FRI, finite classical ROM analysis");
    println!("  - General transaction execution proofs and full PQ composition remain pending");
    println!();
    println!("Security Features:");
    println!("  - ML-DSA signatures; full-system quantum resilience requires further validation");
    println!("  - Entropy monitoring (Sentinel-Seed)");
    println!("  - Local key rotation and independent emergency freeze authority");
    println!("  - NIST SP 800-90B health tests (RCT/APT)");
}

fn run_benchmarks(bench_type: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running {} benchmarks...\n", bench_type);

    if bench_type == "crypto" || bench_type == "all" {
        crypto_benchmarks()?;
    }

    Ok(())
}

fn crypto_benchmarks() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    println!("Cryptographic Benchmarks");
    println!("------------------------");

    // Key generation
    let start = Instant::now();
    let iterations = 10;
    for _ in 0..iterations {
        let _ = DilithiumKeypair::generate(SignatureScheme::Dilithium3)?;
    }
    let elapsed = start.elapsed();
    println!("Key Generation (Dilithium3): {:.2}ms avg", elapsed.as_millis() as f64 / iterations as f64);

    // Signing
    let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3)?;
    let message = b"NEXUS Post-Quantum Blockchain Benchmark Message";

    let start = Instant::now();
    let iterations = 100;
    for _ in 0..iterations {
        let _ = keypair.sign(message)?;
    }
    let elapsed = start.elapsed();
    println!("Signing (Dilithium3): {:.2}ms avg", elapsed.as_millis() as f64 / iterations as f64);

    // Verification
    let signature = keypair.sign(message)?;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = keypair.verify(message, &signature)?;
    }
    let elapsed = start.elapsed();
    println!("Verification (Dilithium3): {:.2}ms avg", elapsed.as_millis() as f64 / iterations as f64);

    // Entropy calculation
    use nexus_crypto::EntropyMonitor;
    let data: Vec<u8> = (0..1024).map(|_| rand::random()).collect();

    let start = Instant::now();
    let iterations = 1000;
    for _ in 0..iterations {
        let _ = EntropyMonitor::shannon_entropy(&data);
    }
    let elapsed = start.elapsed();
    println!("Entropy (1KB): {:.3}ms avg", elapsed.as_micros() as f64 / iterations as f64 / 1000.0);

    Ok(())
}
