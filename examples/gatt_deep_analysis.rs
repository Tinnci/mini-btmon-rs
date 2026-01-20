//! GATT Protocol Deep Analysis Example
//!
//! This example demonstrates the new GATT protocol parsing capabilities.
//! It captures BLE packets and displays detailed GATT service discovery
//! information, building a local GATT database as services are discovered.
//!
//! # Permission Requirements
//!
//! This program requires CAP_NET_RAW capability:
//! ```bash
//! cargo build --example gatt_deep_analysis
//! sudo setcap 'cap_net_raw+ep' target/debug/examples/gatt_deep_analysis
//! ./target/debug/examples/gatt_deep_analysis
//! ```

use bytes::Bytes;
use mini_btmon_rs::{
    AttPdu, CharacteristicProperties, GattCharacteristic, GattDatabase, GattDescriptor,
    GattService, HciPacket, L2capCid, Monitor, Uuid, parse_characteristic_declaration,
    parse_find_info_response, parse_read_by_group_type_response, parse_read_by_type_response,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           GATT Deep Protocol Analyzer                        ║");
    println!("║                  mini-btmon-rs                               ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Monitoring Bluetooth HCI traffic for GATT operations...");
    println!("This analyzer will build a GATT database as services are discovered.");
    println!();

    let mut monitor = Monitor::new().await?;
    let mut gatt_db = GattDatabase::new();
    let mut packet_count = 0u64;
    let mut gatt_count = 0u64;

    loop {
        match tokio::time::timeout(Duration::from_secs(15), monitor.next_packet()).await {
            Ok(Ok(Some(packet))) => {
                packet_count += 1;
                if process_gatt_packet(&packet, &mut gatt_db, &mut gatt_count) {
                    // Print updated database summary periodically
                    if gatt_count.is_multiple_of(5) {
                        print_database_summary(&gatt_db);
                    }
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
                    "\n[STATS] Total: {} packets | GATT: {} | Services: {} | Characteristics: {}",
                    packet_count,
                    gatt_count,
                    gatt_db.service_count(),
                    gatt_db.characteristic_count()
                );
                print_database_summary(&gatt_db);
            }
        }
    }

    // Final summary
    println!("\n════════════════════════════════════════════════════════════════");
    println!("Final GATT Database:");
    println!("{}", gatt_db);

    Ok(())
}

fn process_gatt_packet(
    packet: &HciPacket,
    gatt_db: &mut GattDatabase,
    gatt_count: &mut u64,
) -> bool {
    // Only process ACL data packets
    if let HciPacket::AclData { handle, .. } = packet
        && let Some(l2cap) = packet.as_l2cap()
    {
        // Only process ATT channel
        if l2cap.cid != L2capCid::Att {
            return false;
        }

        if let Some(att) = packet.as_att() {
            *gatt_count += 1;
            print!("[GATT] Handle=0x{:04x} ", handle);

            match &att {
                AttPdu::ReadByGroupTypeResponse { length, data } => {
                    println!("◆ Read By Group Type Response (Services)");
                    process_services_response(*length, data.clone(), gatt_db);
                    return true;
                }
                AttPdu::ReadByTypeResponse { length, data } => {
                    println!("◆ Read By Type Response (Characteristics)");
                    process_characteristics_response(*length, data.clone(), gatt_db);
                    return true;
                }
                AttPdu::FindInformationResponse { format, data } => {
                    println!(
                        "◆ Find Information Response (Descriptors, {})",
                        if *format == 0x01 { "16-bit" } else { "128-bit" }
                    );
                    process_descriptors_response(*format, data.clone(), gatt_db);
                    return true;
                }
                AttPdu::ReadByGroupTypeRequest {
                    start_handle,
                    end_handle,
                    uuid,
                } => {
                    println!(
                        "→ Discover Services: 0x{:04x}-0x{:04x} {}",
                        start_handle,
                        end_handle,
                        format_uuid(uuid)
                    );
                }
                AttPdu::ReadByTypeRequest {
                    start_handle,
                    end_handle,
                    uuid,
                } => {
                    println!(
                        "→ Discover Characteristics: 0x{:04x}-0x{:04x} {}",
                        start_handle,
                        end_handle,
                        format_uuid(uuid)
                    );
                }
                AttPdu::FindInformationRequest {
                    start_handle,
                    end_handle,
                } => {
                    println!(
                        "→ Discover Descriptors: 0x{:04x}-0x{:04x}",
                        start_handle, end_handle
                    );
                }
                AttPdu::ReadRequest { handle } => {
                    if let Some((svc, chrc)) = gatt_db.characteristic_by_handle(*handle) {
                        println!(
                            "→ Read Characteristic: {} → {}",
                            svc.uuid.name(),
                            chrc.uuid.name()
                        );
                    } else {
                        println!("→ Read: handle=0x{:04x}", handle);
                    }
                }
                AttPdu::ReadResponse { value } => {
                    println!("← Read Response: {} bytes", value.len());
                    print_value_preview(value);
                }
                AttPdu::WriteRequest { handle, value } => {
                    if let Some((svc, chrc)) = gatt_db.characteristic_by_handle(*handle) {
                        println!(
                            "→ Write Characteristic: {} → {} ({} bytes)",
                            svc.uuid.name(),
                            chrc.uuid.name(),
                            value.len()
                        );
                    } else {
                        println!("→ Write: handle=0x{:04x} {} bytes", handle, value.len());
                    }
                    print_value_preview(value);
                }
                AttPdu::WriteCommand { handle, value } => {
                    if let Some((svc, chrc)) = gatt_db.characteristic_by_handle(*handle) {
                        println!(
                            "→ Write Command: {} → {} ({} bytes)",
                            svc.uuid.name(),
                            chrc.uuid.name(),
                            value.len()
                        );
                    } else {
                        println!(
                            "→ Write Command: handle=0x{:04x} {} bytes",
                            handle,
                            value.len()
                        );
                    }
                }
                AttPdu::HandleValueNotification { handle, value } => {
                    if let Some((svc, chrc)) = gatt_db.characteristic_by_handle(*handle) {
                        println!(
                            "⇐ Notification: {} → {} ({} bytes)",
                            svc.uuid.name(),
                            chrc.uuid.name(),
                            value.len()
                        );
                    } else {
                        println!(
                            "⇐ Notification: handle=0x{:04x} {} bytes",
                            handle,
                            value.len()
                        );
                    }
                    print_value_preview(value);
                }
                AttPdu::HandleValueIndication { handle, value } => {
                    if let Some((svc, chrc)) = gatt_db.characteristic_by_handle(*handle) {
                        println!(
                            "⇐ Indication: {} → {} ({} bytes)",
                            svc.uuid.name(),
                            chrc.uuid.name(),
                            value.len()
                        );
                    } else {
                        println!(
                            "⇐ Indication: handle=0x{:04x} {} bytes",
                            handle,
                            value.len()
                        );
                    }
                    print_value_preview(value);
                }
                AttPdu::ErrorResponse {
                    request_opcode,
                    handle,
                    error,
                } => {
                    println!(
                        "✗ Error: {} for {} at 0x{:04x}",
                        error, request_opcode, handle
                    );
                }
                _ => {
                    println!("{}", att);
                }
            }
        }
    }
    false
}

fn process_services_response(length: u8, data: Bytes, gatt_db: &mut GattDatabase) {
    let entries = parse_read_by_group_type_response([&[length][..], &data[..]].concat().into());

    for entry in entries {
        if let Some(uuid) = Uuid::parse(entry.value) {
            let service = GattService {
                start_handle: entry.handle,
                end_handle: entry.end_group_handle,
                uuid: uuid.clone(),
                is_primary: true,
                includes: vec![],
                characteristics: vec![],
            };

            println!(
                "    ✓ Service: 0x{:04x}-0x{:04x} {}",
                service.start_handle, service.end_handle, uuid
            );

            gatt_db.add_service(service);
        }
    }
}

fn process_characteristics_response(length: u8, data: Bytes, gatt_db: &mut GattDatabase) {
    let entries = parse_read_by_type_response([&[length][..], &data[..]].concat().into());

    for entry in entries {
        if let Some((props, value_handle, uuid)) = parse_characteristic_declaration(&entry.value) {
            // Find the service that contains this characteristic
            if let Some(service) = gatt_db
                .services
                .values_mut()
                .find(|s| entry.handle >= s.start_handle && entry.handle <= s.end_handle)
            {
                // Determine end handle (next chrc declaration - 1 or service end)
                let end_handle = service.end_handle;

                let chrc = GattCharacteristic {
                    declaration_handle: entry.handle,
                    value_handle,
                    end_handle,
                    properties: props,
                    uuid: uuid.clone(),
                    descriptors: vec![],
                    value: None,
                };

                println!(
                    "    ✓ Characteristic: 0x{:04x} {} [{}]",
                    value_handle, uuid, props
                );

                service.characteristics.push(chrc);
            }
        }
    }
}

fn process_descriptors_response(format: u8, data: Bytes, gatt_db: &mut GattDatabase) {
    let entries = parse_find_info_response([&[format][..], &data[..]].concat().into());

    for entry in entries {
        println!("    ✓ Descriptor: 0x{:04x} {}", entry.handle, entry.uuid);

        // Find the characteristic that contains this descriptor
        for service in gatt_db.services.values_mut() {
            for chrc in &mut service.characteristics {
                if entry.handle > chrc.value_handle && entry.handle <= chrc.end_handle {
                    let desc = GattDescriptor {
                        handle: entry.handle,
                        uuid: entry.uuid.clone(),
                        value: None,
                    };
                    chrc.descriptors.push(desc);
                    break;
                }
            }
        }
    }
}

fn format_uuid(data: &Bytes) -> String {
    match Uuid::parse(data.clone()) {
        Some(uuid) => format!("{}", uuid),
        None => format!("{:02x?}", data),
    }
}

fn print_value_preview(value: &Bytes) {
    if value.is_empty() {
        return;
    }

    let display_len = value.len().min(16);
    print!("       Data: ");
    for byte in value.iter().take(display_len) {
        print!("{:02x} ", byte);
    }
    if value.len() > 16 {
        print!("... (+{} bytes)", value.len() - 16);
    }
    println!();

    // Try to interpret as ASCII string
    if value
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        && let Ok(s) = std::str::from_utf8(value)
    {
        println!("       Text: \"{}\"", s);
    }
}

fn print_database_summary(gatt_db: &GattDatabase) {
    if gatt_db.service_count() == 0 {
        return;
    }

    println!("\n┌─────────────────────────────────────────────────────────────┐");
    println!("│ GATT Database Summary                                       │");
    println!("├─────────────────────────────────────────────────────────────┤");

    for service in gatt_db.iter_services() {
        println!(
            "│ ▸ {} [0x{:04x}-0x{:04x}]",
            service.uuid, service.start_handle, service.end_handle
        );

        for chrc in &service.characteristics {
            let props = format_props(&chrc.properties);
            println!(
                "│   ├─ {} @0x{:04x} {}",
                chrc.uuid, chrc.value_handle, props
            );

            for desc in &chrc.descriptors {
                println!("│   │  └─ {} @0x{:04x}", desc.uuid, desc.handle);
            }
        }
    }

    println!("└─────────────────────────────────────────────────────────────┘");
}

fn format_props(props: &CharacteristicProperties) -> String {
    let mut flags = Vec::new();
    if props.can_read() {
        flags.push("R");
    }
    if props.can_write() {
        flags.push("W");
    }
    if props.can_write_without_response() {
        flags.push("WnR");
    }
    if props.can_notify() {
        flags.push("N");
    }
    if props.can_indicate() {
        flags.push("I");
    }
    if flags.is_empty() {
        String::from("[-]")
    } else {
        format!("[{}]", flags.join(","))
    }
}
