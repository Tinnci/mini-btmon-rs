//! Packet source abstraction for mocking and testing
//!
//! This module provides a `PacketSource` trait that abstracts over different
//! sources of HCI packets, enabling testing without real Bluetooth hardware.
//!
//! ## Usage in Tests
//!
//! ```no_run
//! use mini_btmon_rs::{PacketSource, BtsnoopSource, HciPacket};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load packets from a btsnoop file
//! let mut source = BtsnoopSource::open("capture.btsnoop")?;
//!
//! while let Some(packet) = source.next_packet().await? {
//!     println!("{:?}", packet);
//! }
//! # Ok(())
//! # }
//! ```

use crate::btsnoop::{BtsnoopReader, BtsnoopRecord};
use crate::error::{Error, Result};
use crate::packet::HciPacket;
use std::collections::VecDeque;
use std::io::Read;
use std::path::Path;

/// A source of HCI packets
///
/// This trait abstracts over different packet sources, allowing the same
/// code to work with both live monitoring and recorded data.
pub trait PacketSource {
    /// Read the next HCI packet
    ///
    /// Returns `Ok(Some(packet))` if a packet is available,
    /// `Ok(None)` if the source is exhausted, or `Err` on error.
    fn next_packet(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<HciPacket>>> + Send;

    /// Read the next packet matching a predicate
    fn next_filtered<F>(
        &mut self,
        predicate: F,
    ) -> impl std::future::Future<Output = Result<Option<HciPacket>>> + Send
    where
        F: FnMut(&HciPacket) -> bool + Send,
        Self: Send,
    {
        async move {
            let mut pred = predicate;
            loop {
                match self.next_packet().await? {
                    Some(packet) if pred(&packet) => return Ok(Some(packet)),
                    Some(_) => continue,
                    None => return Ok(None),
                }
            }
        }
    }
}

/// A packet source that reads from a btsnoop file
///
/// This is useful for testing and offline analysis. The source reads
/// packets sequentially from a btsnoop capture file.
pub struct BtsnoopSource<R: Read> {
    reader: BtsnoopReader<R>,
    /// Optional delay simulation (in microseconds between packets)
    simulate_delay: bool,
    /// Last packet timestamp for delay simulation
    last_timestamp: Option<i64>,
}

impl<R: Read> BtsnoopSource<R> {
    /// Create a new btsnoop source from a reader
    pub fn new(reader: R) -> Result<Self> {
        Ok(Self {
            reader: BtsnoopReader::new(reader)?,
            simulate_delay: false,
            last_timestamp: None,
        })
    }

    /// Enable delay simulation based on packet timestamps
    ///
    /// When enabled, the source will sleep between packets based on the
    /// time difference in the original capture. This is useful for
    /// realistic replay scenarios.
    pub fn with_simulated_delay(mut self) -> Self {
        self.simulate_delay = true;
        self
    }

    /// Get the number of records read
    pub fn records_read(&self) -> u64 {
        self.reader.records_read()
    }

    /// Read the next raw btsnoop record
    pub fn next_record(&mut self) -> Result<Option<BtsnoopRecord>> {
        self.reader.next_record()
    }
}

impl BtsnoopSource<std::fs::File> {
    /// Open a btsnoop file
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| Error::InvalidPacket(format!("Failed to open file: {}", e)))?;
        Self::new(file)
    }
}

impl<R: Read + Send> PacketSource for BtsnoopSource<R> {
    async fn next_packet(&mut self) -> Result<Option<HciPacket>> {
        match self.reader.next_record()? {
            Some(record) => {
                // Simulate delay if enabled
                if self.simulate_delay {
                    if let Some(last_ts) = self.last_timestamp {
                        let delay_us = record.timestamp_us.saturating_sub(last_ts);
                        if delay_us > 0 && delay_us < 10_000_000 {
                            // Max 10 seconds
                            tokio::time::sleep(std::time::Duration::from_micros(delay_us as u64))
                                .await;
                        }
                    }
                    self.last_timestamp = Some(record.timestamp_us);
                }

                Ok(Some(record.parse_packet()?))
            }
            None => Ok(None),
        }
    }
}

/// A mock packet source for testing
///
/// Allows injecting pre-defined packets for unit testing.
pub struct MockSource {
    packets: VecDeque<HciPacket>,
}

impl MockSource {
    /// Create a new empty mock source
    pub fn new() -> Self {
        Self {
            packets: VecDeque::new(),
        }
    }

    /// Create a mock source from a vector of packets
    pub fn from_packets(packets: Vec<HciPacket>) -> Self {
        Self {
            packets: packets.into(),
        }
    }

    /// Add a packet to the queue
    pub fn push(&mut self, packet: HciPacket) {
        self.packets.push_back(packet);
    }

    /// Add multiple packets to the queue
    pub fn extend(&mut self, packets: impl IntoIterator<Item = HciPacket>) {
        self.packets.extend(packets);
    }

    /// Get the number of remaining packets
    pub fn remaining(&self) -> usize {
        self.packets.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

impl Default for MockSource {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketSource for MockSource {
    async fn next_packet(&mut self) -> Result<Option<HciPacket>> {
        Ok(self.packets.pop_front())
    }
}

/// Extension trait for convenient packet iteration
pub trait PacketSourceExt: PacketSource {
    /// Collect up to `count` packets
    fn collect_packets(
        &mut self,
        count: usize,
    ) -> impl std::future::Future<Output = Result<Vec<HciPacket>>> + Send
    where
        Self: Send,
    {
        async move {
            let mut packets = Vec::with_capacity(count);
            for _ in 0..count {
                match self.next_packet().await? {
                    Some(p) => packets.push(p),
                    None => break,
                }
            }
            Ok(packets)
        }
    }

    /// Collect all remaining packets
    fn collect_all(&mut self) -> impl std::future::Future<Output = Result<Vec<HciPacket>>> + Send
    where
        Self: Send,
    {
        async move {
            let mut packets = Vec::new();
            while let Some(p) = self.next_packet().await? {
                packets.push(p);
            }
            Ok(packets)
        }
    }

    /// Skip packets until predicate matches
    fn skip_until<F>(
        &mut self,
        mut predicate: F,
    ) -> impl std::future::Future<Output = Result<Option<HciPacket>>> + Send
    where
        F: FnMut(&HciPacket) -> bool + Send,
        Self: Send,
    {
        async move {
            loop {
                match self.next_packet().await? {
                    Some(packet) if predicate(&packet) => return Ok(Some(packet)),
                    Some(_) => continue,
                    None => return Ok(None),
                }
            }
        }
    }
}

// Implement PacketSourceExt for all PacketSource implementors
impl<T: PacketSource> PacketSourceExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::io::Cursor;

    fn create_test_btsnoop() -> Vec<u8> {
        let mut data = Vec::new();

        // Header
        data.extend_from_slice(b"btsnoop\x00");
        data.extend_from_slice(&1u32.to_be_bytes()); // Version
        data.extend_from_slice(&1002u32.to_be_bytes()); // HCI UART

        // Record 1: HCI Command (Reset)
        let packet1 = [0x01u8, 0x03, 0x0c, 0x00];
        data.extend_from_slice(&(packet1.len() as u32).to_be_bytes());
        data.extend_from_slice(&(packet1.len() as u32).to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes()); // Flags (sent, cmd)
        data.extend_from_slice(&0u32.to_be_bytes()); // Drops
        data.extend_from_slice(&1000000i64.to_be_bytes()); // Timestamp
        data.extend_from_slice(&packet1);

        // Record 2: HCI Event (Command Complete)
        let packet2 = [0x04u8, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00];
        data.extend_from_slice(&(packet2.len() as u32).to_be_bytes());
        data.extend_from_slice(&(packet2.len() as u32).to_be_bytes());
        data.extend_from_slice(&3u32.to_be_bytes()); // Flags (recv, event)
        data.extend_from_slice(&0u32.to_be_bytes()); // Drops
        data.extend_from_slice(&2000000i64.to_be_bytes()); // Timestamp
        data.extend_from_slice(&packet2);

        data
    }

    #[tokio::test]
    async fn test_btsnoop_source() {
        let data = create_test_btsnoop();
        let mut source = BtsnoopSource::new(Cursor::new(data)).unwrap();

        let packet1 = source.next_packet().await.unwrap().unwrap();
        assert!(matches!(packet1, HciPacket::Command { .. }));

        let packet2 = source.next_packet().await.unwrap().unwrap();
        assert!(matches!(packet2, HciPacket::Event { .. }));

        assert!(source.next_packet().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_mock_source() {
        let packets = vec![
            HciPacket::Command {
                opcode: crate::packet::HciOpcode(0x0c03),
                params: Bytes::new(),
            },
            HciPacket::Event {
                event_code: crate::packet::HciEvent::CommandComplete,
                params: Bytes::from_static(&[0x01, 0x03, 0x0c, 0x00]),
            },
        ];

        let mut source = MockSource::from_packets(packets);
        assert_eq!(source.remaining(), 2);

        let p1 = source.next_packet().await.unwrap().unwrap();
        assert!(matches!(p1, HciPacket::Command { .. }));

        let p2 = source.next_packet().await.unwrap().unwrap();
        assert!(matches!(p2, HciPacket::Event { .. }));

        assert!(source.next_packet().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_collect_packets() {
        let packets = vec![
            HciPacket::Command {
                opcode: crate::packet::HciOpcode(0x0c03),
                params: Bytes::new(),
            },
            HciPacket::Command {
                opcode: crate::packet::HciOpcode(0x0c05),
                params: Bytes::new(),
            },
            HciPacket::Command {
                opcode: crate::packet::HciOpcode(0x0c13),
                params: Bytes::new(),
            },
        ];

        let mut source = MockSource::from_packets(packets);
        let collected = source.collect_packets(2).await.unwrap();
        assert_eq!(collected.len(), 2);
        assert_eq!(source.remaining(), 1);
    }

    #[tokio::test]
    async fn test_next_filtered() {
        let packets = vec![
            HciPacket::Command {
                opcode: crate::packet::HciOpcode(0x0c03),
                params: Bytes::new(),
            },
            HciPacket::Event {
                event_code: crate::packet::HciEvent::CommandComplete,
                params: Bytes::new(),
            },
            HciPacket::Command {
                opcode: crate::packet::HciOpcode(0x0c05),
                params: Bytes::new(),
            },
        ];

        let mut source = MockSource::from_packets(packets);

        // Filter for events only
        let event = source
            .next_filtered(|p| matches!(p, HciPacket::Event { .. }))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(event, HciPacket::Event { .. }));

        // One command remains
        assert_eq!(source.remaining(), 1);
    }
}
