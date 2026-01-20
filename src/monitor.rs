use crate::error::{Error, Result};
use crate::packet::HciPacket;
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
        })
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
        if self.buffer.is_empty() {
            return Ok(None);
        }

        // HCI monitor packets have this structure:
        // [packet_type: 1 byte][packet_data: variable]
        //
        // We need to peek ahead to determine packet length
        let packet_type = self.buffer[0];

        let packet_len = match packet_type {
            0x01 => {
                // Command
                if self.buffer.len() < 4 {
                    return Ok(None); // Need more data
                }
                let param_len = self.buffer[3] as usize;
                4 + param_len
            }
            0x04 => {
                // Event
                if self.buffer.len() < 3 {
                    return Ok(None);
                }
                let param_len = self.buffer[2] as usize;
                3 + param_len
            }
            0x02 => {
                // ACL Data
                if self.buffer.len() < 5 {
                    return Ok(None);
                }
                let data_len = u16::from_le_bytes([self.buffer[3], self.buffer[4]]) as usize;
                5 + data_len
            }
            0x03 => {
                // SCO Data
                if self.buffer.len() < 4 {
                    return Ok(None);
                }
                let data_len = self.buffer[3] as usize;
                4 + data_len
            }
            _ => {
                // Unknown packet type - skip this byte
                tracing::warn!("Unknown packet type: 0x{:02x}", packet_type);
                self.buffer.advance(1);
                return Ok(None);
            }
        };

        // Check if we have the complete packet
        if self.buffer.len() < packet_len {
            return Ok(None);
        }

        // Extract packet data
        let packet_data = self.buffer.split_to(packet_len).freeze();

        // Parse the packet
        match HciPacket::parse(packet_data) {
            Ok(packet) => Ok(Some(packet)),
            Err(e) => {
                tracing::error!("Failed to parse packet: {}", e);
                Err(e)
            }
        }
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
