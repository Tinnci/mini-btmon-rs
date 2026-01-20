//! SMP (Security Manager Protocol) Analysis Example
//!
//! This example demonstrates the SMP protocol parsing capabilities.
//! It captures BLE packets and displays detailed pairing and key exchange information.
//!
//! # Permission Requirements
//!
//! This program requires CAP_NET_RAW capability:
//! ```bash
//! cargo build --example smp_analysis
//! sudo setcap 'cap_net_raw+ep' target/debug/examples/smp_analysis
//! ./target/debug/examples/smp_analysis
//! ```

use mini_btmon_rs::{HciPacket, L2capCid, Monitor, SmpPdu};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           SMP (Security Manager Protocol) Analyzer           ║");
    println!("║                      mini-btmon-rs                           ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Monitoring Bluetooth HCI traffic for SMP pairing operations...");
    println!("Initiate a BLE pairing to see the security handshake.");
    println!();

    let mut monitor = Monitor::new().await?;
    let mut packet_count = 0u64;
    let mut smp_count = 0u64;

    loop {
        match tokio::time::timeout(Duration::from_secs(30), monitor.next_packet()).await {
            Ok(Ok(Some(packet))) => {
                packet_count += 1;
                if process_smp_packet(&packet, &mut smp_count) {
                    // Continue
                }
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
                    "\n[STATS] Total: {} packets | SMP: {}",
                    packet_count, smp_count
                );
                if smp_count == 0 {
                    println!("Tip: Initiate a BLE pairing to capture SMP traffic.");
                }
            }
        }
    }

    Ok(())
}

fn process_smp_packet(packet: &HciPacket, smp_count: &mut u64) -> bool {
    // Only process ACL data packets
    if let HciPacket::AclData { handle, .. } = packet
        && let Some(l2cap) = packet.as_l2cap()
    {
        // Only process SMP channel
        if l2cap.cid != L2capCid::Smp && l2cap.cid != L2capCid::SmpBrEdr {
            return false;
        }

        if let Some(smp) = packet.as_smp() {
            *smp_count += 1;
            let channel = if l2cap.cid == L2capCid::Smp {
                "LE"
            } else {
                "BR/EDR"
            };

            print!("[SMP-{}] Handle=0x{:04x} ", channel, handle);

            match &smp {
                SmpPdu::PairingRequest {
                    io_capability,
                    oob_data_flag,
                    auth_req,
                    max_key_size,
                    initiator_key_dist,
                    responder_key_dist,
                } => {
                    println!("→ PAIRING REQUEST");
                    println!("    IO Capability: {}", format_io_capability(io_capability));
                    println!("    OOB Data: {}", oob_data_flag);
                    println!("    Auth Requirements: {}", auth_req);
                    println!("    Max Encryption Key Size: {} bytes", max_key_size);
                    println!("    Initiator Key Distribution: {}", initiator_key_dist);
                    println!("    Responder Key Distribution: {}", responder_key_dist);
                    print_security_level(auth_req);
                }
                SmpPdu::PairingResponse {
                    io_capability,
                    oob_data_flag,
                    auth_req,
                    max_key_size,
                    initiator_key_dist,
                    responder_key_dist,
                } => {
                    println!("← PAIRING RESPONSE");
                    println!("    IO Capability: {}", format_io_capability(io_capability));
                    println!("    OOB Data: {}", oob_data_flag);
                    println!("    Auth Requirements: {}", auth_req);
                    println!("    Max Encryption Key Size: {} bytes", max_key_size);
                    println!("    Initiator Key Distribution: {}", initiator_key_dist);
                    println!("    Responder Key Distribution: {}", responder_key_dist);
                    print_security_level(auth_req);
                    predict_pairing_method(io_capability, oob_data_flag);
                }
                SmpPdu::PairingConfirm { confirm_value } => {
                    println!("◆ PAIRING CONFIRM");
                    print!("    Confirm Value: ");
                    for b in confirm_value {
                        print!("{:02x}", b);
                    }
                    println!();
                }
                SmpPdu::PairingRandom { random_value } => {
                    println!("◆ PAIRING RANDOM");
                    print!("    Random Value: ");
                    for b in random_value {
                        print!("{:02x}", b);
                    }
                    println!();
                }
                SmpPdu::PairingFailed { reason } => {
                    println!("✗ PAIRING FAILED");
                    println!("    Reason: {}", reason);
                }
                SmpPdu::EncryptionInfo { ltk } => {
                    println!("🔑 ENCRYPTION INFO (LTK)");
                    print!("    Long Term Key: ");
                    for b in ltk {
                        print!("{:02x}", b);
                    }
                    println!();
                    println!("    ⚠️ WARNING: LTK captured! Connection can be decrypted.");
                }
                SmpPdu::CentralIdent { ediv, rand } => {
                    println!("🔑 CENTRAL IDENTIFICATION");
                    println!("    EDIV: 0x{:04x}", ediv);
                    print!("    Rand: ");
                    for b in rand {
                        print!("{:02x}", b);
                    }
                    println!();
                }
                SmpPdu::IdentityInfo { irk } => {
                    println!("🔑 IDENTITY INFO (IRK)");
                    print!("    Identity Resolving Key: ");
                    for b in irk {
                        print!("{:02x}", b);
                    }
                    println!();
                    println!("    Used to resolve resolvable private addresses.");
                }
                SmpPdu::IdentityAddrInfo { addr_type, address } => {
                    println!("📍 IDENTITY ADDRESS INFO");
                    println!(
                        "    Address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} ({})",
                        address[5],
                        address[4],
                        address[3],
                        address[2],
                        address[1],
                        address[0],
                        addr_type
                    );
                }
                SmpPdu::SigningInfo { csrk } => {
                    println!("🔑 SIGNING INFO (CSRK)");
                    print!("    Connection Signature Resolving Key: ");
                    for b in csrk {
                        print!("{:02x}", b);
                    }
                    println!();
                }
                SmpPdu::SecurityRequest { auth_req } => {
                    println!("⚡ SECURITY REQUEST");
                    println!("    Auth Requirements: {}", auth_req);
                    print_security_level(auth_req);
                }
                SmpPdu::PairingPublicKey { .. } => {
                    println!("🔐 PAIRING PUBLIC KEY (LE Secure Connections)");
                    println!("    Using ECDH P-256 key exchange");
                }
                SmpPdu::PairingDhKeyCheck { .. } => {
                    println!("✓ PAIRING DHKEY CHECK (LE Secure Connections)");
                }
                SmpPdu::KeypressNotification { notification_type } => {
                    println!("⌨️ KEYPRESS NOTIFICATION: {}", notification_type);
                }
                SmpPdu::Raw { code, data } => {
                    println!("{}: {} bytes", code, data.len());
                }
            }

            println!();
            return true;
        }
    }
    false
}

fn format_io_capability(cap: &mini_btmon_rs::IoCapability) -> String {
    use mini_btmon_rs::IoCapability;
    match cap {
        IoCapability::DisplayOnly => "Display Only (can show 6-digit code)".to_string(),
        IoCapability::DisplayYesNo => "Display Yes/No (can show code and confirm)".to_string(),
        IoCapability::KeyboardOnly => "Keyboard Only (can enter 6-digit code)".to_string(),
        IoCapability::NoInputNoOutput => "No Input/No Output (Just Works)".to_string(),
        IoCapability::KeyboardDisplay => "Keyboard + Display (full capability)".to_string(),
        IoCapability::Unknown(v) => format!("Unknown(0x{:02x})", v),
    }
}

fn print_security_level(auth: &mini_btmon_rs::AuthReq) {
    println!("    Security Profile:");
    if auth.secure_connections() {
        println!("      ✓ LE Secure Connections (ECDH P-256)");
    } else {
        println!("      ⚠ Legacy Pairing (vulnerable to MITM attacks)");
    }

    if auth.mitm() {
        println!("      ✓ MITM Protection Required");
    } else {
        println!("      ⚠ No MITM Protection");
    }

    if auth.bonding() {
        println!("      ✓ Bonding (keys will be stored)");
    } else {
        println!("      ○ No Bonding (temporary connection)");
    }
}

fn predict_pairing_method(io_cap: &mini_btmon_rs::IoCapability, oob: &mini_btmon_rs::OobDataFlag) {
    use mini_btmon_rs::{IoCapability, OobDataFlag};

    let method = if matches!(oob, OobDataFlag::Present) {
        "Out-of-Band (OOB) authentication"
    } else {
        match io_cap {
            IoCapability::DisplayOnly => "Passkey Entry (display on this device)",
            IoCapability::DisplayYesNo => "Numeric Comparison",
            IoCapability::KeyboardOnly => "Passkey Entry (input on this device)",
            IoCapability::NoInputNoOutput => "Just Works (NO AUTHENTICATION!)",
            IoCapability::KeyboardDisplay => "Numeric Comparison or Passkey",
            IoCapability::Unknown(_) => "Unknown method",
        }
    };

    println!();
    println!("    Predicted Pairing Method: {}", method);
}
