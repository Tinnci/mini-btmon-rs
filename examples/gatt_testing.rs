//! Example: BLE GATT testing workflow
//!
//! This demonstrates a real-world testing scenario: verifying that a BLE
//! GATT operation produces the correct HCI packet sequence.
//!
//! This is the "Holy Grail" for BLE testing - being able to assert on the
//! actual protocol layer while testing high-level APIs.

use mini_btmon_rs::{HciPacket, Monitor};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== BLE GATT Testing Workflow ===\n");

    let mut monitor = Monitor::new().await.map_err(|e| {
        if e.is_permission_denied() {
            eprintln!("{}", e);
            std::process::exit(1);
        }
        e
    })?;

    println!("Monitoring BLE GATT operations...");
    println!("Connect to a BLE device and perform GATT reads/writes\n");

    let mut gatt_operations = 0;
    let start_time = std::time::Instant::now();

    // Monitor for 30 seconds or until 10 GATT operations
    while gatt_operations < 10 && start_time.elapsed() < Duration::from_secs(30) {
        match monitor.next_filtered(|p| p.is_att()).await {
            Ok(Some(packet)) => {
                gatt_operations += 1;

                if let HciPacket::AclData { handle, data, .. } = packet {
                    // Parse ATT opcode
                    if data.len() > 4 {
                        let att_opcode = data[4];
                        let operation = match att_opcode {
                            0x02 => "MTU Exchange Request",
                            0x03 => "MTU Exchange Response",
                            0x08 => "Read By Type Request",
                            0x09 => "Read By Type Response",
                            0x0a => "Read Request",
                            0x0b => "Read Response",
                            0x12 => "Write Request",
                            0x13 => "Write Response",
                            0x1b => "Notification",
                            0x1d => "Indication",
                            0x52 => "Write Command",
                            _ => "Unknown",
                        };

                        println!(
                            "[{}] GATT Operation: {} (opcode={:#x}) on handle {:#x}",
                            gatt_operations, operation, att_opcode, handle
                        );

                        // For write operations, show the data
                        if (att_opcode == 0x12 || att_opcode == 0x52) && data.len() > 7 {
                            let att_handle = u16::from_le_bytes([data[5], data[6]]);
                            let value = &data[7..];
                            println!(
                                "      → Handle: {:#x}, Value: {:02x?}",
                                att_handle,
                                &value[..value.len().min(16)]
                            );
                        }

                        // For notifications, show the data
                        if att_opcode == 0x1b && data.len() > 6 {
                            let att_handle = u16::from_le_bytes([data[5], data[6]]);
                            let value = &data[7..];
                            println!(
                                "      ← Handle: {:#x}, Value: {:02x?}",
                                att_handle,
                                &value[..value.len().min(16)]
                            );
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Total GATT operations captured: {}", gatt_operations);
    println!("\nThis demonstrates how mini-btmon-rs enables you to:");
    println!("  ✅ Verify exact protocol behavior during testing");
    println!("  ✅ Debug GATT interactions in real-time");
    println!("  ✅ Assert on low-level details from high-level tests");

    Ok(())
}
