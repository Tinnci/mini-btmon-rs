use crate::error::{Error, Result};
use crate::packet::{HciPacket, MonitorHeader, MonitorOpcode};
use crate::socket;
use bytes::{Buf, BytesMut};
use std::os::unix::io::AsRawFd;
use tokio::io::unix::AsyncFd;

/// Bluetooth HCI Monitor
///
/// Provides async access to HCI packets from the kernel's Bluetooth monitor interface.
pub struct Monitor {
    async_fd: AsyncFd<socket2::Socket>,
    buffer: BytesMut,
    filter_index: Option<u16>,
}

impl Monitor {
    /// Create a new HCI monitor
    ///
    /// # Errors
    ///
    /// Returns `Error::PermissionDenied` if the process doesn't have CAP_NET_RAW capability.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mini_btmon_rs::Monitor;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let monitor = Monitor::new().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new() -> Result<Self> {
        let socket = socket::open_monitor_socket()?;
        let async_fd = AsyncFd::new(socket)?;

        Ok(Self {
            async_fd,
            buffer: BytesMut::with_capacity(4096),
            filter_index: None,
        })
    }

    /// Create a new HCI monitor filtered for a specific controller index
    pub async fn new_with_index(index: u16) -> Result<Self> {
        let mut monitor = Self::new().await?;
        monitor.filter_index = Some(index);
        Ok(monitor)
    }

    /// Set a filter for a specific controller index
    pub fn set_filter_index(&mut self, index: Option<u16>) {
        self.filter_index = index;
    }

    /// Read the next HCI packet
    ///
    /// This is a blocking async call that waits for the next packet from the kernel.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mini_btmon_rs::Monitor;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut monitor = Monitor::new().await?;
    ///     
    ///     while let Some(packet) = monitor.next_packet().await? {
    ///         println!("Received: {:?}", packet);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn next_packet(&mut self) -> Result<Option<HciPacket>> {
        loop {
            // Try to parse existing buffer first
            if let Some(packet) = self.try_parse_packet()? {
                return Ok(Some(packet));
            }

            // Need more data - wait for socket to be readable
            let mut guard = self.async_fd.readable().await?;

            // Try to read from socket
            match guard.try_io(|inner| {
                // Read directly from socket into buffer
                let socket_fd = inner.get_ref().as_raw_fd();
                let buf = self.buffer.spare_capacity_mut();

                unsafe {
                    let result = libc::recv(
                        socket_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    );

                    if result < 0 {
                        Err(std::io::Error::last_os_error())
                    } else if result == 0 {
                        // Socket closed
                        Ok(0)
                    } else {
                        Ok(result as usize)
                    }
                }
            }) {
                Ok(Ok(0)) => {
                    // Socket closed
                    return Ok(None);
                }
                Ok(Ok(n)) => {
                    unsafe {
                        self.buffer.set_len(self.buffer.len() + n);
                    }
                    // Continue to try parsing
                }
                Ok(Err(e)) => {
                    return Err(Error::Io(e));
                }
                Err(_would_block) => {
                    // Spurious wakeup, try again
                    continue;
                }
            }
        }
    }

    /// Try to parse a complete packet from the buffer
    fn try_parse_packet(&mut self) -> Result<Option<HciPacket>> {
        while self.buffer.len() >= 6 {
            let header = match MonitorHeader::parse(&self.buffer[0..6]) {
                Some(h) => h,
                None => return Ok(None),
            };

            let packet_len = header.len as usize;

            // Check if we have the complete packet (header + payload)
            if self.buffer.len() < 6 + packet_len {
                return Ok(None);
            }

            // Apply controller index filter if set
            if let Some(target_index) = self.filter_index {
                // index 0xFFFF is typically used for system-wide monitor events
                if header.index != target_index && header.index != 0xFFFF {
                    self.buffer.advance(6 + packet_len);
                    continue;
                }
            }

            if let Some(packet_type) = header.opcode.to_packet_type() {
                // Extract header and payload
                let _header_data = self.buffer.split_to(6);
                let payload_data = self.buffer.split_to(packet_len).freeze();

                // Parse the HCI packet (the payload doesn't have an H4 indicator)
                match HciPacket::parse_no_indicator(packet_type, payload_data) {
                    Ok(packet) => return Ok(Some(packet)),
                    Err(e) => {
                        tracing::error!("Failed to parse HCI packet from monitor data: {}", e);
                        return Err(e);
                    }
                }
            } else {
                // This is a system/vendor diagnostic message, not a standard HCI packet
                match header.opcode {
                    MonitorOpcode::VendorDiag
                    | MonitorOpcode::SystemNote
                    | MonitorOpcode::UserLogging => {
                        let _header_data = self.buffer.split_to(6);
                        let payload_data = self.buffer.split_to(packet_len).freeze();
                        return Ok(Some(HciPacket::Raw {
                            packet_type: crate::packet::HciPacketType::Diag,
                            data: payload_data,
                        }));
                    }
                    _ => {
                        // Ignore other index/control/logging events for now and continue searching buffer
                        self.buffer.advance(6 + packet_len);
                        continue;
                    }
                }
            }
        }
        Ok(None)
    }

    /// Create a filtered stream that only yields packets matching a predicate
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mini_btmon_rs::{Monitor, HciPacket};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut monitor = Monitor::new().await?;
    ///     
    ///     // Only show ATT packets (BLE GATT)
    ///     while let Some(packet) = monitor.next_packet().await? {
    ///         if packet.is_att() {
    ///             println!("ATT: {:?}", packet);
    ///         }
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn next_filtered<F>(&mut self, mut predicate: F) -> Result<Option<HciPacket>>
    where
        F: FnMut(&HciPacket) -> bool,
    {
        loop {
            match self.next_packet().await? {
                Some(packet) if predicate(&packet) => return Ok(Some(packet)),
                Some(_) => continue,
                None => return Ok(None),
            }
        }
    }
}

// Implement PacketSource for Monitor
impl crate::source::PacketSource for Monitor {
    async fn next_packet(&mut self) -> Result<Option<HciPacket>> {
        Monitor::next_packet(self).await
    }
}
