//! Testing utilities and assertion helpers
//!
//! This module provides test-friendly APIs for automated Bluetooth testing scenarios.

use crate::Monitor;
use crate::error::{Error, Result};
use crate::packet::{HciEvent, HciOpcode, HciPacket};
use std::time::Duration;

/// Packet matcher for test expectations
pub trait PacketMatcher: Send {
    fn matches(&self, packet: &HciPacket) -> bool;
    fn description(&self) -> String;
}

/// Match command packets by opcode
pub struct CommandMatcher {
    pub opcode: HciOpcode,
}

impl PacketMatcher for CommandMatcher {
    fn matches(&self, packet: &HciPacket) -> bool {
        matches!(packet, HciPacket::Command { opcode, .. } if *opcode == self.opcode)
    }

    fn description(&self) -> String {
        format!(
            "Command(OGF={:#x}, OCF={:#x})",
            self.opcode.ogf(),
            self.opcode.ocf()
        )
    }
}

/// Match event packets by event code
pub struct EventMatcher {
    pub event_code: HciEvent,
}

impl PacketMatcher for EventMatcher {
    fn matches(&self, packet: &HciPacket) -> bool {
        matches!(packet, HciPacket::Event { event_code, .. } if *event_code == self.event_code)
    }

    fn description(&self) -> String {
        format!("Event({:?})", self.event_code)
    }
}

/// Match any command complete event
pub struct CommandCompleteAnyMatcher;

impl PacketMatcher for CommandCompleteAnyMatcher {
    fn matches(&self, packet: &HciPacket) -> bool {
        packet.is_command_complete()
    }

    fn description(&self) -> String {
        "CommandComplete(any)".to_string()
    }
}

/// Match ACL data by handle
pub struct AclDataMatcher {
    pub handle: Option<u16>,
}

impl PacketMatcher for AclDataMatcher {
    fn matches(&self, packet: &HciPacket) -> bool {
        match packet {
            HciPacket::AclData { handle, .. } => self.handle.is_none_or(|h| *handle == h),
            _ => false,
        }
    }

    fn description(&self) -> String {
        match self.handle {
            Some(h) => format!("AclData(handle={:#x})", h),
            None => "AclData(any)".to_string(),
        }
    }
}

/// Testing extensions for Monitor
impl Monitor {
    /// Wait for a packet matching a predicate with timeout
    ///
    /// This is the core API for test assertions. It will wait up to `timeout_duration`
    /// for a packet that matches the given predicate.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mini_btmon_rs::{Monitor, HciPacket};
    /// use std::time::Duration;
    ///
    /// #[tokio::test]
    /// async fn test_connection_complete() {
    ///     let mut monitor = Monitor::new().await.unwrap();
    ///     
    ///     // Trigger connection...
    ///     
    ///     // Wait for connection complete event
    ///     let packet = monitor.expect(
    ///         |p| p.is_command_complete(),
    ///         Duration::from_secs(5)
    ///     ).await.unwrap();
    /// }
    /// ```
    pub async fn expect<F>(&mut self, predicate: F, timeout_duration: Duration) -> Result<HciPacket>
    where
        F: Fn(&HciPacket) -> bool,
    {
        tokio::time::timeout(timeout_duration, async {
            loop {
                match self.next_packet().await? {
                    Some(packet) if predicate(&packet) => return Ok(packet),
                    Some(_) => continue,
                    None => return Err(Error::SocketClosed),
                }
            }
        })
        .await
        .map_err(|_| Error::Other("Timeout waiting for expected packet".into()))?
    }

    /// Expect a packet matching the given matcher
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mini_btmon_rs::{Monitor, testing::EventMatcher, HciEvent};
    /// use std::time::Duration;
    ///
    /// #[tokio::test]
    /// async fn test_inquiry_complete() {
    ///     let mut monitor = Monitor::new().await.unwrap();
    ///     
    ///     let matcher = EventMatcher {
    ///         event_code: HciEvent::InquiryComplete
    ///     };
    ///     
    ///     let packet = monitor.expect_match(
    ///         &matcher,
    ///         Duration::from_secs(30)
    ///     ).await.unwrap();
    /// }
    /// ```
    pub async fn expect_match<M: PacketMatcher>(
        &mut self,
        matcher: &M,
        timeout_duration: Duration,
    ) -> Result<HciPacket> {
        let description = matcher.description();
        self.expect(|p| matcher.matches(p), timeout_duration)
            .await
            .map_err(|e| match e {
                Error::Other(msg) if msg.contains("Timeout") => {
                    Error::Other(format!("Timeout waiting for {}", description))
                }
                e => e,
            })
    }

    /// Expect a command packet with specific opcode
    pub async fn expect_command(
        &mut self,
        opcode: HciOpcode,
        timeout_duration: Duration,
    ) -> Result<HciPacket> {
        self.expect_match(&CommandMatcher { opcode }, timeout_duration)
            .await
    }

    /// Expect an event packet with specific event code
    pub async fn expect_event(
        &mut self,
        event_code: HciEvent,
        timeout_duration: Duration,
    ) -> Result<HciPacket> {
        self.expect_match(&EventMatcher { event_code }, timeout_duration)
            .await
    }

    /// Expect any command complete event
    pub async fn expect_command_complete(
        &mut self,
        timeout_duration: Duration,
    ) -> Result<HciPacket> {
        self.expect_match(&CommandCompleteAnyMatcher, timeout_duration)
            .await
    }

    /// Expect ACL data on specific handle
    pub async fn expect_acl_data(
        &mut self,
        handle: Option<u16>,
        timeout_duration: Duration,
    ) -> Result<HciPacket> {
        self.expect_match(&AclDataMatcher { handle }, timeout_duration)
            .await
    }

    /// Collect all packets within a time window
    ///
    /// Useful for batch verification in tests. Returns all packets received
    /// within the specified duration.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mini_btmon_rs::Monitor;
    /// use std::time::Duration;
    ///
    /// #[tokio::test]
    /// async fn test_advertising_burst() {
    ///     let mut monitor = Monitor::new().await.unwrap();
    ///     
    ///     // Trigger advertising...
    ///     
    ///     // Collect all packets in the next 2 seconds
    ///     let packets = monitor.collect_for(Duration::from_secs(2)).await.unwrap();
    ///     
    ///     // Verify we got the expected sequence
    ///     assert!(packets.len() >= 3, "Expected at least 3 packets");
    /// }
    /// ```
    pub async fn collect_for(&mut self, duration: Duration) -> Result<Vec<HciPacket>> {
        let collect_future = async {
            let mut packets = Vec::new();
            while let Some(packet) = self.next_packet().await? {
                packets.push(packet);
            }
            Ok::<_, Error>(packets)
        };

        match tokio::time::timeout(duration, collect_future).await {
            Ok(result) => result,
            Err(_) => Ok(Vec::new()), // Timeout is expected, return empty vec
        }
    }

    /// Assert that no packets matching a predicate arrive within timeout
    ///
    /// This is useful for negative testing - ensuring certain events DON'T happen.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mini_btmon_rs::{Monitor, HciPacket};
    /// use std::time::Duration;
    ///
    /// #[tokio::test]
    /// async fn test_no_spurious_disconnects() {
    ///     let mut monitor = Monitor::new().await.unwrap();
    ///     
    ///     // Ensure no disconnect events for 5 seconds
    ///     monitor.assert_no_match(
    ///         |p| matches!(p, HciPacket::Event { event_code, .. }
    ///             if *event_code == mini_btmon_rs::HciEvent::DisconnectionComplete),
    ///         Duration::from_secs(5)
    ///     ).await.unwrap();
    /// }
    /// ```
    pub async fn assert_no_match<F>(
        &mut self,
        predicate: F,
        timeout_duration: Duration,
    ) -> Result<()>
    where
        F: Fn(&HciPacket) -> bool,
    {
        let check_future = async {
            loop {
                match self.next_packet().await? {
                    Some(packet) if predicate(&packet) => {
                        return Err(Error::Other(
                            "Unexpected packet matched during assert_no_match".into(),
                        ));
                    }
                    Some(_) => continue,
                    None => return Err(Error::SocketClosed),
                }
            }
        };

        match tokio::time::timeout(timeout_duration, check_future).await {
            Ok(result) => result,
            Err(_) => Ok(()), // Timeout is expected and means success
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_matcher() {
        let matcher = CommandMatcher {
            opcode: HciOpcode(0x0c03),
        };

        let cmd = HciPacket::Command {
            opcode: HciOpcode(0x0c03),
            params: bytes::Bytes::new(),
        };

        assert!(matcher.matches(&cmd));
        assert_eq!(matcher.description(), "Command(OGF=0x3, OCF=0x3)");
    }

    #[test]
    fn test_event_matcher() {
        let matcher = EventMatcher {
            event_code: HciEvent::CommandComplete,
        };

        let evt = HciPacket::Event {
            event_code: HciEvent::CommandComplete,
            params: bytes::Bytes::new(),
        };

        assert!(matcher.matches(&evt));
    }
}
