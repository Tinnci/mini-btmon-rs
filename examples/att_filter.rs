//! Example: Filter only ATT/GATT packets (BLE debugging)
//!
//! This example demonstrates how to filter for specific packet types,
//! particularly useful when debugging BLE GATT interactions.
//!
//! Run with: sudo setcap 'cap_net_raw+ep' target/debug/examples/att_filter && cargo run --example att_filter

use mini_btmon_rs::{HciPacket, Monitor};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Monitoring ATT/GATT packets only...\n");

    let mut monitor = Monitor::new().await.map_err(|e| {
        if e.is_permission_denied() {
            eprintln!("{}", e);
            std::process::exit(1);
        }
        e
    })?;

    let mut count = 0;
    while let Some(packet) = monitor.next_filtered(|p| p.is_att()).await? {
        count += 1;

        if let HciPacket::AclData { handle, data, .. } = packet {
            // Parse L2CAP header
            if data.len() >= 4 {
                let l2cap_len = u16::from_le_bytes([data[0], data[1]]);
                let l2cap_cid = u16::from_le_bytes([data[2], data[3]]);

                println!("[{}] ATT Packet on handle {:#x}:", count, handle);
                println!("  L2CAP: len={} cid={:#x}", l2cap_len, l2cap_cid);

                // ATT opcode is the first byte after L2CAP header
                if data.len() > 4 {
                    let att_opcode = data[4];
                    let att_name = match att_opcode {
                        0x01 => "Error Response",
                        0x02 => "Exchange MTU Request",
                        0x03 => "Exchange MTU Response",
                        0x08 => "Read By Type Request",
                        0x09 => "Read By Type Response",
                        0x0a => "Read Request",
                        0x0b => "Read Response",
                        0x12 => "Write Request",
                        0x13 => "Write Response",
                        0x1b => "Handle Value Notification",
                        0x1d => "Handle Value Indication",
                        0x52 => "Write Command",
                        _ => "Unknown",
                    };
                    println!("  ATT: opcode={:#x} ({})", att_opcode, att_name);

                    // Show payload hex dump (first 32 bytes)
                    if data.len() > 5 {
                        let payload = &data[5..];
                        let display_len = payload.len().min(32);
                        print!("  Data: ");
                        for b in &payload[..display_len] {
                            print!("{:02x} ", b);
                        }
                        if payload.len() > display_len {
                            print!("... ({} more bytes)", payload.len() - display_len);
                        }
                        println!();
                    }
                }
                println!();
            }
        }
    }

    Ok(())
}
