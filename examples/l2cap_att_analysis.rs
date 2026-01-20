//! L2CAP/ATT Protocol Analysis Example
//!
//! This example demonstrates the new L2CAP and ATT protocol parsing capabilities.
//! It captures BLE packets and displays detailed protocol information.
//!
//! # Permission Requirements
//!
//! This program requires CAP_NET_RAW capability:
//! ```bash
//! cargo build --example l2cap_att_analysis
//! sudo setcap 'cap_net_raw+ep' target/debug/examples/l2cap_att_analysis
//! ./target/debug/examples/l2cap_att_analysis
//! ```

use mini_btmon_rs::{AttPdu, HciPacket, L2capCid, Monitor};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           L2CAP/ATT Protocol Analyzer                        ║");
    println!("║                  mini-btmon-rs                               ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Monitoring Bluetooth HCI traffic...");
    println!("Waiting for BLE activity (ATT/GATT operations)...");
    println!();

    let mut monitor = Monitor::new().await?;
    let mut packet_count = 0u64;
    let mut att_count = 0u64;
    let mut l2cap_count = 0u64;

    loop {
        // Use timeout to periodically show stats
        match tokio::time::timeout(Duration::from_secs(10), monitor.next_packet()).await {
            Ok(Ok(Some(packet))) => {
                packet_count += 1;
                process_packet(&packet, &mut l2cap_count, &mut att_count);
            }
            Ok(Ok(None)) => {
                println!("[INFO] Monitor stream ended");
                break;
            }
            Ok(Err(e)) => {
                eprintln!("[ERROR] {}", e);
                break;
            }
            Err(_) => {
                // Timeout - show stats
                println!(
                    "[STATS] Total: {} packets | L2CAP: {} | ATT: {}",
                    packet_count, l2cap_count, att_count
                );
            }
        }
    }

    Ok(())
}

fn process_packet(packet: &HciPacket, l2cap_count: &mut u64, att_count: &mut u64) {
    // Check if this is an ACL data packet
    if let HciPacket::AclData {
        handle,
        pb_flag,
        bc_flag,
        ..
    } = packet
    {
        // Try to parse as L2CAP
        if let Some(l2cap) = packet.as_l2cap() {
            *l2cap_count += 1;

            print!(
                "[L2CAP] Handle=0x{:04x} PB={} BC={} CID={} Len={}",
                handle, pb_flag, bc_flag, l2cap.cid, l2cap.length
            );

            // Detailed analysis based on CID
            match l2cap.cid {
                L2capCid::Att => {
                    *att_count += 1;
                    if let Some(att) = packet.as_att() {
                        println!();
                        print_att_pdu(&att);
                    } else {
                        println!(" (ATT parse failed)");
                    }
                }
                L2capCid::Smp | L2capCid::SmpBrEdr => {
                    println!(" [SMP]");
                    print_hex_dump(&l2cap.payload, 16);
                }
                L2capCid::SignalingLe | L2capCid::SignalingBrEdr => {
                    println!(" [Signaling]");
                    if let Some(sig) = mini_btmon_rs::L2capSignaling::parse(l2cap.payload.clone()) {
                        println!("    Code: {:?} ID: {}", sig.code, sig.identifier);
                    }
                }
                L2capCid::Dynamic(cid) => {
                    println!(" [Dynamic CID 0x{:04x}]", cid);
                }
                _ => {
                    println!();
                }
            }
        }
    }
}

fn print_att_pdu(att: &AttPdu) {
    let direction = if att.opcode().is_request() || att.opcode().is_command() {
        "→" // Request/Command (client to server)
    } else if att.opcode().is_response() {
        "←" // Response (server to client)
    } else if att.opcode().is_notification_or_indication() {
        "⇐" // Notification/Indication (server to client, unsolicited)
    } else {
        "·"
    };

    println!("    {} ATT: {}", direction, att);

    // Additional details for specific PDU types
    match att {
        AttPdu::ErrorResponse {
            request_opcode,
            handle,
            error,
        } => {
            println!(
                "       ⚠ Error for {} at handle 0x{:04x}: {}",
                request_opcode, handle, error
            );
        }
        AttPdu::ExchangeMtuRequest { client_mtu } => {
            println!("       MTU requested by client: {} bytes", client_mtu);
        }
        AttPdu::ExchangeMtuResponse { server_mtu } => {
            println!("       MTU offered by server: {} bytes", server_mtu);
        }
        AttPdu::ReadByTypeRequest {
            start_handle,
            end_handle,
            uuid,
        } => {
            println!(
                "       Range: 0x{:04x} - 0x{:04x}",
                start_handle, end_handle
            );
            print!("       UUID: ");
            print_uuid(uuid);
        }
        AttPdu::ReadByGroupTypeRequest {
            start_handle,
            end_handle,
            uuid,
        } => {
            println!(
                "       Range: 0x{:04x} - 0x{:04x}",
                start_handle, end_handle
            );
            print!("       UUID: ");
            print_uuid(uuid);
        }
        AttPdu::WriteRequest { handle, value }
        | AttPdu::WriteCommand { handle, value }
        | AttPdu::HandleValueNotification { handle, value }
        | AttPdu::HandleValueIndication { handle, value } => {
            println!("       Handle: 0x{:04x}", handle);
            print!("       Data: ");
            print_hex_dump(value, 16);
        }
        AttPdu::ReadResponse { value } => {
            print!("       Value: ");
            print_hex_dump(value, 16);
        }
        _ => {}
    }
}

fn print_uuid(uuid: &bytes::Bytes) {
    match uuid.len() {
        2 => {
            let short_uuid = u16::from_le_bytes([uuid[0], uuid[1]]);
            println!("0x{:04x} ({})", short_uuid, uuid_name(short_uuid));
        }
        4 => {
            let uuid32 = u32::from_le_bytes([uuid[0], uuid[1], uuid[2], uuid[3]]);
            println!("0x{:08x}", uuid32);
        }
        16 => {
            // Full 128-bit UUID (little-endian in ATT)
            print!("{{ ");
            for (i, byte) in uuid.iter().rev().enumerate() {
                print!("{:02x}", byte);
                if i == 3 || i == 5 || i == 7 || i == 9 {
                    print!("-");
                }
            }
            println!(" }}");
        }
        _ => {
            println!("{:02x?}", uuid);
        }
    }
}

fn uuid_name(uuid16: u16) -> &'static str {
    match uuid16 {
        // GATT Declarations
        0x2800 => "Primary Service",
        0x2801 => "Secondary Service",
        0x2802 => "Include",
        0x2803 => "Characteristic",
        // GATT Descriptors
        0x2900 => "Characteristic Extended Properties",
        0x2901 => "Characteristic User Description",
        0x2902 => "Client Characteristic Configuration",
        0x2903 => "Server Characteristic Configuration",
        0x2904 => "Characteristic Presentation Format",
        0x2905 => "Characteristic Aggregate Format",
        // Common Characteristics
        0x2a00 => "Device Name",
        0x2a01 => "Appearance",
        0x2a02 => "Peripheral Privacy Flag",
        0x2a03 => "Reconnection Address",
        0x2a04 => "Peripheral Preferred Connection Parameters",
        0x2a05 => "Service Changed",
        0x2a19 => "Battery Level",
        0x2a29 => "Manufacturer Name",
        0x2a24 => "Model Number",
        0x2a25 => "Serial Number",
        0x2a26 => "Firmware Revision",
        0x2a27 => "Hardware Revision",
        0x2a28 => "Software Revision",
        0x2a23 => "System ID",
        // Common Services
        0x1800 => "Generic Access",
        0x1801 => "Generic Attribute",
        0x180a => "Device Information",
        0x180f => "Battery Service",
        0x1812 => "HID Service",
        _ => "Unknown",
    }
}

fn print_hex_dump(data: &bytes::Bytes, max_bytes: usize) {
    let display_len = data.len().min(max_bytes);
    for byte in data.iter().take(display_len) {
        print!("{:02x} ", byte);
    }
    if data.len() > max_bytes {
        print!("... ({} more bytes)", data.len() - max_bytes);
    }
    println!();
}
