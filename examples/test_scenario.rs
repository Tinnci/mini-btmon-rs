//! Example: Automated testing with mini-btmon
//!
//! This demonstrates how mini-btmon-rs enables automated Bluetooth testing
//! by providing structured, synchronous access to HCI packets.
//!
//! Run with: sudo setcap 'cap_net_raw+ep' target/debug/examples/test_scenario && cargo run --example test_scenario

use mini_btmon_rs::{HciEvent, HciOpcode, HciPacket, Monitor};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bluetooth Testing Scenario Example ===\n");

    let mut monitor = Monitor::new().await.map_err(|e| {
        if e.is_permission_denied() {
            eprintln!("{}", e);
            std::process::exit(1);
        }
        e
    })?;

    // Scenario 1: Wait for any HCI Reset command
    println!("Test 1: Waiting for HCI Reset command (opcode 0x0c03)...");
    println!("  (Trigger this by running: sudo hciconfig hci0 reset)\n");

    match monitor
        .expect_command(HciOpcode(0x0c03), Duration::from_secs(30))
        .await
    {
        Ok(packet) => {
            println!("  ✅ HCI Reset command detected!");
            if let HciPacket::Command { opcode, params } = packet {
                println!(
                    "     Opcode: OGF={:#x} OCF={:#x}",
                    opcode.ogf(),
                    opcode.ocf()
                );
                println!("     Params: {} bytes", params.len());
            }
        }
        Err(e) => {
            println!("  ⏱️  Timeout (no reset detected): {}", e);
        }
    }
    println!();

    // Scenario 2: Collect packets for analysis
    println!("Test 2: Collecting all packets for 3 seconds...");
    let packets = monitor.collect_for(Duration::from_secs(3)).await?;

    let mut cmd_count = 0;
    let mut evt_count = 0;
    let mut acl_count = 0;

    for packet in &packets {
        match packet {
            HciPacket::Command { .. } => cmd_count += 1,
            HciPacket::Event { .. } => evt_count += 1,
            HciPacket::AclData { .. } => acl_count += 1,
            _ => {}
        }
    }

    println!("  📊 Statistics:");
    println!("     Total packets: {}", packets.len());
    println!("     Commands: {}", cmd_count);
    println!("     Events: {}", evt_count);
    println!("     ACL Data: {}", acl_count);
    println!();

    // Scenario 3: Verify connection sequence
    println!("Test 3: Monitoring for connection events...");
    println!("  (Connect a BLE device to trigger this)\n");

    // Wait for connection complete or timeout
    match monitor
        .expect_event(HciEvent::ConnectionComplete, Duration::from_secs(15))
        .await
    {
        Ok(packet) => {
            println!("  ✅ Connection Complete event received!");
            if let HciPacket::Event { event_code, params } = packet {
                println!("     Event: {:?}", event_code);
                println!("     Params: {:02x?}", &params[..params.len().min(8)]);
            }
        }
        Err(_) => {
            println!("  ⏱️  No connection events detected (timeout)");
        }
    }
    println!();

    // Scenario 4: Negative test - ensure no disconnects
    println!("Test 4: Ensuring no disconnect events for 2 seconds...");
    match monitor
        .assert_no_match(
            |p| {
                matches!(p, HciPacket::Event { event_code, .. }
                if *event_code == HciEvent::DisconnectionComplete)
            },
            Duration::from_secs(2),
        )
        .await
    {
        Ok(()) => println!("  ✅ No unexpected disconnects detected"),
        Err(e) => println!("  ❌ Unexpected disconnect: {}", e),
    }
    println!();

    println!("=== Testing scenario complete ===");
    Ok(())
}
