//! mini-btmon-rs: Rust library for Bluetooth HCI monitoring
//!
//! This library provides programmatic access to Bluetooth HCI monitor data,
//! similar to the `btmon` tool from BlueZ, but with a Rust-native async API.
//!
//! ## Permission Requirements
//!
//! This library requires `CAP_NET_RAW` capability to open the HCI monitor socket.
//!
//! ### Option 1: Using setcap (Recommended for development)
//! ```bash
//! sudo setcap 'cap_net_raw+ep' target/debug/your-binary
//! ```
//!
//! ### Option 2: Running with sudo
//! ```bash
//! sudo ./your-binary
//! ```
//!
//! ## Quick Start
//!
//! ```no_run
//! use mini_btmon_rs::Monitor;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut monitor = Monitor::new().await?;
//!     
//!     while let Some(packet) = monitor.next_packet().await? {
//!         println!("{:?}", packet);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Testing Integration
//!
//! The library is designed for automated testing scenarios:
//!
//! ```no_run
//! use mini_btmon_rs::{Monitor, HciEvent};
//! use std::time::Duration;
//!
//! #[tokio::test]
//! async fn test_connection_flow() {
//!     let mut monitor = Monitor::new().await.unwrap();
//!     
//!     // Trigger connection in your app...
//!     
//!     // Assert that connection complete event arrives
//!     let packet = monitor.expect_event(
//!         HciEvent::ConnectionComplete,
//!         Duration::from_secs(5)
//!     ).await.unwrap();
//! }
//! ```

pub mod att;
pub mod btsnoop;
mod error;
pub mod gatt;
pub mod l2cap;
mod monitor;
mod packet;
mod socket;
pub mod testing;

pub use att::{AttError, AttOpcode, AttPdu};
pub use btsnoop::{
    BtsnoopReader, BtsnoopRecord, BtsnoopWriter, PacketFlags, create_btsnoop, open_btsnoop,
};
pub use error::{Error, Result};
pub use gatt::{
    CccdValue, CharacteristicProperties, GattCharacteristic, GattDatabase, GattDescriptor,
    GattService, GroupTypeEntry, HandleUuidEntry, IncludedService, TypeValueEntry, Uuid,
    parse_characteristic_declaration, parse_find_info_response, parse_read_by_group_type_response,
    parse_read_by_type_response, uuid16_name,
};
pub use l2cap::{L2capCid, L2capPacket, L2capSignaling, L2capSignalingCode};
pub use monitor::Monitor;
pub use packet::{HciEvent, HciOpcode, HciPacket, HciPacketType};
