//! Basic example: Monitor all HCI packets
//!
//! Run with: sudo setcap 'cap_net_raw+ep' target/debug/examples/basic && cargo run --example basic
//! Or: sudo cargo run --example basic

use mini_btmon_rs::{HciPacket, Monitor};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Starting HCI Monitor...");
    println!("Press Ctrl+C to stop\n");

    // Create monitor
    let mut monitor = match Monitor::new().await {
        Ok(m) => m,
        Err(e) if e.is_permission_denied() => {
            eprintln!("Error: {}", e);
            eprintln!("\nTo fix this, run one of the following:");
            eprintln!("  1. sudo setcap 'cap_net_raw+ep' target/debug/examples/basic");
            eprintln!("  2. sudo cargo run --example basic");
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    };

    // Monitor packets
    let mut count = 0;
    while let Some(packet) = monitor.next_packet().await? {
        count += 1;

        match packet {
            HciPacket::Command { opcode, params } => {
                println!(
                    "[{}] Command: OGF={:#x} OCF={:#x} len={}",
                    count,
                    opcode.ogf(),
                    opcode.ocf(),
                    params.len()
                );
            }
            HciPacket::Event { event_code, params } => {
                println!("[{}] Event: {:?} len={}", count, event_code, params.len());
            }
            HciPacket::AclData { handle, data, .. } => {
                println!(
                    "[{}] ACL Data: handle={:#x} len={}",
                    count,
                    handle,
                    data.len()
                );
            }
            HciPacket::ScoData { handle, data } => {
                println!(
                    "[{}] SCO Data: handle={:#x} len={}",
                    count,
                    handle,
                    data.len()
                );
            }
            _ => {
                println!("[{}] Other packet", count);
            }
        }
    }

    Ok(())
}
