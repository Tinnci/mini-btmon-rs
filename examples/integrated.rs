//! Example: Using mini-btmon in your application
//!
//! This demonstrates how to integrate HCI monitoring into your Bluetooth application
//! for debugging purposes without affecting the main application logic.

use mini_btmon_rs::{HciPacket, Monitor};
use tokio::time::{Duration, sleep};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Application with HCI monitoring\n");

    // Spawn monitoring task in background
    let monitor_handle = tokio::spawn(async {
        if let Ok(mut monitor) = Monitor::new().await {
            println!("[Monitor] Started successfully\n");

            let mut events = 0;
            let mut commands = 0;

            while let Ok(Some(packet)) = monitor.next_packet().await {
                match packet {
                    HciPacket::Event { .. } => events += 1,
                    HciPacket::Command { .. } => commands += 1,
                    _ => {}
                }

                // Print stats every 100 packets
                if (events + commands) % 100 == 0 {
                    println!("[Monitor] Stats: {} events, {} commands", events, commands);
                }
            }
        } else {
            eprintln!("[Monitor] Failed to start (insufficient permissions)");
            eprintln!("[Monitor] App will continue without HCI monitoring");
        }
    });

    // Main application logic
    println!("[App] Running main application logic...");
    for i in 0..10 {
        println!("[App] Tick {}", i);
        sleep(Duration::from_secs(1)).await;
    }

    println!("\n[App] Shutting down...");
    monitor_handle.abort();

    Ok(())
}
