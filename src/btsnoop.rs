//! btsnoop file format support
//!
//! btsnoop is a standard file format for storing Bluetooth packet traces.
//! It's used by tools like BlueZ's `btmon` and Wireshark.
//!
//! ## File Format
//!
//! The file consists of:
//! - 16-byte file header
//! - Multiple packet records, each with a 24-byte header followed by packet data
//!
//! ## References
//! - [btsnoop format](https://www.fte.com/webhelp/bpa600/Content/Technical_Information/BT_Snoop_File_Format.htm)

use crate::error::{Error, Result};
use crate::packet::{HciPacket, HciPacketType};
use bytes::{BufMut, Bytes, BytesMut};
use std::io::{Read, Write};
use std::path::Path;

/// btsnoop file magic bytes: "btsnoop\0"
const BTSNOOP_MAGIC: [u8; 8] = *b"btsnoop\x00";

/// btsnoop format version
const BTSNOOP_VERSION: u32 = 1;

/// Datalink type for HCI UART (H4)
const DATALINK_HCI_UART: u32 = 1002;

/// btsnoop packet flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlags(u32);

impl PacketFlags {
    /// Direction: Host to Controller
    pub const DIRECTION_SENT: u32 = 0;
    /// Direction: Controller to Host
    pub const DIRECTION_RECV: u32 = 1;
    /// Packet type: Command/Event
    pub const TYPE_CMD_EVENT: u32 = 2;

    /// Create new packet flags
    pub fn new(sent: bool, is_command_or_event: bool) -> Self {
        let mut flags = 0u32;
        if !sent {
            flags |= Self::DIRECTION_RECV;
        }
        if is_command_or_event {
            flags |= Self::TYPE_CMD_EVENT;
        }
        Self(flags)
    }

    /// Create flags from raw value
    pub fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Check if packet was sent (Host to Controller)
    pub fn is_sent(&self) -> bool {
        (self.0 & Self::DIRECTION_RECV) == 0
    }

    /// Check if packet was received (Controller to Host)
    pub fn is_received(&self) -> bool {
        (self.0 & Self::DIRECTION_RECV) != 0
    }

    /// Check if this is a command or event packet
    pub fn is_command_or_event(&self) -> bool {
        (self.0 & Self::TYPE_CMD_EVENT) != 0
    }

    /// Get raw value
    pub fn raw(&self) -> u32 {
        self.0
    }
}

/// A single btsnoop packet record
#[derive(Debug, Clone)]
pub struct BtsnoopRecord {
    /// Original packet length
    pub original_length: u32,
    /// Included packet length
    pub included_length: u32,
    /// Packet flags
    pub flags: PacketFlags,
    /// Cumulative drops
    pub cumulative_drops: u32,
    /// Timestamp in microseconds since Unix epoch
    pub timestamp_us: i64,
    /// Packet data (including HCI packet type byte)
    pub data: Bytes,
}

impl BtsnoopRecord {
    /// Parse HCI packet from record data
    pub fn parse_packet(&self) -> Result<HciPacket> {
        HciPacket::parse(self.data.clone())
    }

    /// Get packet direction as string
    pub fn direction_str(&self) -> &'static str {
        if self.flags.is_sent() { ">>>" } else { "<<<" }
    }

    /// Get timestamp in seconds (floating point)
    pub fn timestamp_secs(&self) -> f64 {
        self.timestamp_us as f64 / 1_000_000.0
    }
}

/// btsnoop file reader
pub struct BtsnoopReader<R: Read> {
    reader: R,
    datalink_type: u32,
    records_read: u64,
}

impl<R: Read> BtsnoopReader<R> {
    /// Create a new btsnoop reader
    pub fn new(mut reader: R) -> Result<Self> {
        // Read file header (16 bytes)
        let mut header = [0u8; 16];
        reader
            .read_exact(&mut header)
            .map_err(|e| Error::InvalidPacket(format!("Failed to read btsnoop header: {}", e)))?;

        // Verify magic
        if header[0..8] != BTSNOOP_MAGIC {
            return Err(Error::InvalidPacket("Invalid btsnoop magic".into()));
        }

        // Read version (big-endian)
        let version = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        if version != BTSNOOP_VERSION {
            return Err(Error::InvalidPacket(format!(
                "Unsupported btsnoop version: {}",
                version
            )));
        }

        // Read datalink type (big-endian)
        let datalink_type = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);

        Ok(Self {
            reader,
            datalink_type,
            records_read: 0,
        })
    }

    /// Get the datalink type
    pub fn datalink_type(&self) -> u32 {
        self.datalink_type
    }

    /// Get number of records read
    pub fn records_read(&self) -> u64 {
        self.records_read
    }

    /// Read the next record
    pub fn next_record(&mut self) -> Result<Option<BtsnoopRecord>> {
        // Read record header (24 bytes)
        let mut header = [0u8; 24];
        match self.reader.read_exact(&mut header) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => {
                return Err(Error::InvalidPacket(format!(
                    "Failed to read record header: {}",
                    e
                )));
            }
        }

        // Parse header fields (all big-endian)
        let original_length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let included_length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let flags = PacketFlags::from_raw(u32::from_be_bytes([
            header[8], header[9], header[10], header[11],
        ]));
        let cumulative_drops = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);
        let timestamp_us = i64::from_be_bytes([
            header[16], header[17], header[18], header[19], header[20], header[21], header[22],
            header[23],
        ]);

        // Read packet data
        let mut data = vec![0u8; included_length as usize];
        self.reader
            .read_exact(&mut data)
            .map_err(|e| Error::InvalidPacket(format!("Failed to read packet data: {}", e)))?;

        self.records_read += 1;

        Ok(Some(BtsnoopRecord {
            original_length,
            included_length,
            flags,
            cumulative_drops,
            timestamp_us,
            data: Bytes::from(data),
        }))
    }
}

impl<R: Read> IntoIterator for BtsnoopReader<R> {
    type Item = Result<BtsnoopRecord>;
    type IntoIter = BtsnoopIterator<R>;

    fn into_iter(self) -> Self::IntoIter {
        BtsnoopIterator { reader: self }
    }
}

/// Iterator over btsnoop records
pub struct BtsnoopIterator<R: Read> {
    reader: BtsnoopReader<R>,
}

impl<R: Read> Iterator for BtsnoopIterator<R> {
    type Item = Result<BtsnoopRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// btsnoop file writer
pub struct BtsnoopWriter<W: Write> {
    writer: W,
    records_written: u64,
    start_time_us: i64,
}

impl<W: Write> BtsnoopWriter<W> {
    /// Create a new btsnoop writer
    pub fn new(mut writer: W) -> Result<Self> {
        // Write file header
        let mut header = [0u8; 16];
        header[0..8].copy_from_slice(&BTSNOOP_MAGIC);
        header[8..12].copy_from_slice(&BTSNOOP_VERSION.to_be_bytes());
        header[12..16].copy_from_slice(&DATALINK_HCI_UART.to_be_bytes());

        writer
            .write_all(&header)
            .map_err(|e| Error::InvalidPacket(format!("Failed to write btsnoop header: {}", e)))?;

        // Start time for relative timestamps
        let start_time_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);

        Ok(Self {
            writer,
            records_written: 0,
            start_time_us,
        })
    }

    /// Write a packet record
    pub fn write_packet(
        &mut self,
        packet: &HciPacket,
        sent: bool,
        timestamp_us: Option<i64>,
    ) -> Result<()> {
        // Serialize packet
        let data = serialize_packet(packet);
        let length = data.len() as u32;

        // Determine packet flags
        let is_cmd_or_event = matches!(packet, HciPacket::Command { .. } | HciPacket::Event { .. });
        let flags = PacketFlags::new(sent, is_cmd_or_event);

        // Use provided timestamp or current time
        let timestamp = timestamp_us.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_micros() as i64)
                .unwrap_or(self.start_time_us)
        });

        // Write record header (24 bytes, all big-endian)
        let mut header = BytesMut::with_capacity(24);
        header.put_u32(length); // Original length
        header.put_u32(length); // Included length
        header.put_u32(flags.raw()); // Flags
        header.put_u32(0); // Cumulative drops
        header.put_i64(timestamp); // Timestamp

        self.writer
            .write_all(&header)
            .map_err(|e| Error::InvalidPacket(format!("Failed to write record header: {}", e)))?;

        // Write packet data
        self.writer
            .write_all(&data)
            .map_err(|e| Error::InvalidPacket(format!("Failed to write packet data: {}", e)))?;

        self.records_written += 1;
        Ok(())
    }

    /// Write a raw btsnoop record
    pub fn write_record(&mut self, record: &BtsnoopRecord) -> Result<()> {
        // Write record header (24 bytes, all big-endian)
        let mut header = BytesMut::with_capacity(24);
        header.put_u32(record.original_length);
        header.put_u32(record.included_length);
        header.put_u32(record.flags.raw());
        header.put_u32(record.cumulative_drops);
        header.put_i64(record.timestamp_us);

        self.writer
            .write_all(&header)
            .map_err(|e| Error::InvalidPacket(format!("Failed to write record header: {}", e)))?;

        self.writer
            .write_all(&record.data)
            .map_err(|e| Error::InvalidPacket(format!("Failed to write packet data: {}", e)))?;

        self.records_written += 1;
        Ok(())
    }

    /// Get number of records written
    pub fn records_written(&self) -> u64 {
        self.records_written
    }

    /// Flush the writer
    pub fn flush(&mut self) -> Result<()> {
        self.writer
            .flush()
            .map_err(|e| Error::InvalidPacket(format!("Failed to flush: {}", e)))
    }
}

/// Serialize an HCI packet to bytes (including packet type byte)
fn serialize_packet(packet: &HciPacket) -> Bytes {
    let mut buf = BytesMut::new();

    match packet {
        HciPacket::Command { opcode, params } => {
            buf.put_u8(HciPacketType::Command as u8);
            buf.put_u16_le(opcode.0);
            buf.put_u8(params.len() as u8);
            buf.put_slice(params);
        }
        HciPacket::Event { event_code, params } => {
            buf.put_u8(HciPacketType::Event as u8);
            buf.put_u8(event_code.code());
            buf.put_u8(params.len() as u8);
            buf.put_slice(params);
        }
        HciPacket::AclData {
            handle,
            pb_flag,
            bc_flag,
            data,
        } => {
            buf.put_u8(HciPacketType::AclData as u8);
            let handle_flags =
                (*handle & 0x0fff) | ((*pb_flag as u16) << 12) | ((*bc_flag as u16) << 14);
            buf.put_u16_le(handle_flags);
            buf.put_u16_le(data.len() as u16);
            buf.put_slice(data);
        }
        HciPacket::ScoData { handle, data } => {
            buf.put_u8(HciPacketType::ScoData as u8);
            buf.put_u16_le(*handle & 0x0fff);
            buf.put_u8(data.len() as u8);
            buf.put_slice(data);
        }
        HciPacket::IsoData { data } => {
            buf.put_u8(HciPacketType::IsoData as u8);
            buf.put_slice(data);
        }
        HciPacket::Raw { packet_type, data } => {
            buf.put_u8(*packet_type as u8);
            buf.put_slice(data);
        }
    }

    buf.freeze()
}

/// Open a btsnoop file for reading
pub fn open_btsnoop<P: AsRef<Path>>(path: P) -> Result<BtsnoopReader<std::fs::File>> {
    let file = std::fs::File::open(path)
        .map_err(|e| Error::InvalidPacket(format!("Failed to open file: {}", e)))?;
    BtsnoopReader::new(file)
}

/// Create a new btsnoop file for writing
pub fn create_btsnoop<P: AsRef<Path>>(path: P) -> Result<BtsnoopWriter<std::fs::File>> {
    let file = std::fs::File::create(path)
        .map_err(|e| Error::InvalidPacket(format!("Failed to create file: {}", e)))?;
    BtsnoopWriter::new(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn create_test_file() -> Vec<u8> {
        let mut data = Vec::new();

        // Header
        data.extend_from_slice(&BTSNOOP_MAGIC);
        data.extend_from_slice(&BTSNOOP_VERSION.to_be_bytes());
        data.extend_from_slice(&DATALINK_HCI_UART.to_be_bytes());

        // One record: HCI Command (Reset)
        let packet_data = [0x01u8, 0x03, 0x0c, 0x00]; // Type=Command, Opcode=0x0c03, Len=0
        let original_length = packet_data.len() as u32;
        let flags = PacketFlags::new(true, true);
        let timestamp: i64 = 1_704_067_200_000_000; // 2024-01-01 00:00:00 UTC

        data.extend_from_slice(&original_length.to_be_bytes());
        data.extend_from_slice(&original_length.to_be_bytes());
        data.extend_from_slice(&flags.raw().to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes()); // drops
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(&packet_data);

        data
    }

    #[test]
    fn test_read_btsnoop() {
        let data = create_test_file();
        let cursor = Cursor::new(data);

        let mut reader = BtsnoopReader::new(cursor).unwrap();
        assert_eq!(reader.datalink_type(), DATALINK_HCI_UART);

        let record = reader.next_record().unwrap().unwrap();
        assert!(record.flags.is_sent());
        assert!(record.flags.is_command_or_event());

        let packet = record.parse_packet().unwrap();
        if let HciPacket::Command { opcode, .. } = packet {
            assert_eq!(opcode.0, 0x0c03); // HCI Reset
        } else {
            panic!("Expected Command packet");
        }

        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn test_write_btsnoop() {
        let mut buf = Vec::new();
        {
            let mut writer = BtsnoopWriter::new(&mut buf).unwrap();

            let packet = HciPacket::Command {
                opcode: crate::packet::HciOpcode(0x0c03),
                params: Bytes::new(),
            };
            writer
                .write_packet(&packet, true, Some(1_704_067_200_000_000))
                .unwrap();
            writer.flush().unwrap();
        }

        // Read it back
        let cursor = Cursor::new(buf);
        let mut reader = BtsnoopReader::new(cursor).unwrap();

        let record = reader.next_record().unwrap().unwrap();
        assert!(record.flags.is_sent());

        let packet = record.parse_packet().unwrap();
        if let HciPacket::Command { opcode, params } = packet {
            assert_eq!(opcode.0, 0x0c03);
            assert!(params.is_empty());
        } else {
            panic!("Expected Command packet");
        }
    }

    #[test]
    fn test_packet_flags() {
        let flags = PacketFlags::new(true, true);
        assert!(flags.is_sent());
        assert!(flags.is_command_or_event());

        let flags = PacketFlags::new(false, false);
        assert!(flags.is_received());
        assert!(!flags.is_command_or_event());
    }
}
