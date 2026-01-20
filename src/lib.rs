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

mod error;
mod monitor;
mod packet;
mod socket;
pub mod testing;

pub use error::{Error, Result};
pub use monitor::Monitor;
pub use packet::{HciEvent, HciOpcode, HciPacket, HciPacketType};
