use crate::error::{Error, Result};
use bytes::{Buf, Bytes};

/// HCI packet types from the Bluetooth specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HciPacketType {
    /// HCI Command packet
    Command = 0x01,
    /// HCI ACL Data packet
    AclData = 0x02,
    /// HCI SCO Data packet
    ScoData = 0x03,
    /// HCI Event packet
    Event = 0x04,
    /// ISO Data packet
    IsoData = 0x05,
    /// Vendor diagnostic packet
    Diag = 0xf0,
    /// Unknown packet type
    Unknown = 0xff,
}

impl From<u8> for HciPacketType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => HciPacketType::Command,
            0x02 => HciPacketType::AclData,
            0x03 => HciPacketType::ScoData,
            0x04 => HciPacketType::Event,
            0x05 => HciPacketType::IsoData,
            0xf0 => HciPacketType::Diag,
            _ => HciPacketType::Unknown,
        }
    }
}

/// Linux HCI Monitor Opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MonitorOpcode {
    NewIndex = 0,
    DelIndex = 1,
    CommandPkt = 2,
    EventPkt = 3,
    AclTxPkt = 4,
    AclRxPkt = 5,
    ScoTxPkt = 6,
    ScoRxPkt = 7,
    OpenIndex = 8,
    CloseIndex = 9,
    IndexInfo = 10,
    VendorDiag = 11,
    SystemNote = 12,
    UserLogging = 13,
    CtrlOpen = 14,
    CtrlClose = 15,
    CtrlCommand = 16,
    CtrlEvent = 17,
    IsoTxPkt = 18,
    IsoRxPkt = 19,
    Unknown = 0xffff,
}

impl From<u16> for MonitorOpcode {
    fn from(value: u16) -> Self {
        match value {
            0 => MonitorOpcode::NewIndex,
            1 => MonitorOpcode::DelIndex,
            2 => MonitorOpcode::CommandPkt,
            3 => MonitorOpcode::EventPkt,
            4 => MonitorOpcode::AclTxPkt,
            5 => MonitorOpcode::AclRxPkt,
            6 => MonitorOpcode::ScoTxPkt,
            7 => MonitorOpcode::ScoRxPkt,
            8 => MonitorOpcode::OpenIndex,
            9 => MonitorOpcode::CloseIndex,
            10 => MonitorOpcode::IndexInfo,
            11 => MonitorOpcode::VendorDiag,
            12 => MonitorOpcode::SystemNote,
            13 => MonitorOpcode::UserLogging,
            14 => MonitorOpcode::CtrlOpen,
            15 => MonitorOpcode::CtrlClose,
            16 => MonitorOpcode::CtrlCommand,
            17 => MonitorOpcode::CtrlEvent,
            18 => MonitorOpcode::IsoTxPkt,
            19 => MonitorOpcode::IsoRxPkt,
            _ => MonitorOpcode::Unknown,
        }
    }
}

impl MonitorOpcode {
    /// Convert monitor opcode to HciPacketType if applicable
    pub fn to_packet_type(self) -> Option<HciPacketType> {
        match self {
            MonitorOpcode::CommandPkt => Some(HciPacketType::Command),
            MonitorOpcode::EventPkt => Some(HciPacketType::Event),
            MonitorOpcode::AclTxPkt | MonitorOpcode::AclRxPkt => Some(HciPacketType::AclData),
            MonitorOpcode::ScoTxPkt | MonitorOpcode::ScoRxPkt => Some(HciPacketType::ScoData),
            MonitorOpcode::IsoTxPkt | MonitorOpcode::IsoRxPkt => Some(HciPacketType::IsoData),
            _ => None,
        }
    }
}

/// Linux HCI Monitor Header (6 bytes)
#[derive(Debug, Clone, Copy)]
pub struct MonitorHeader {
    pub opcode: MonitorOpcode,
    pub index: u16,
    pub len: u16,
}

impl MonitorHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let opcode = MonitorOpcode::from(u16::from_le_bytes([data[0], data[1]]));
        let index = u16::from_le_bytes([data[2], data[3]]);
        let len = u16::from_le_bytes([data[4], data[5]]);
        Some(Self { opcode, index, len })
    }
}

/// HCI Command Opcode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HciOpcode(pub u16);

impl HciOpcode {
    pub fn ogf(&self) -> u16 {
        self.0 >> 10
    }

    pub fn ocf(&self) -> u16 {
        self.0 & 0x3ff
    }
}

/// HCI Event codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HciEvent {
    InquiryComplete = 0x01,
    InquiryResult = 0x02,
    ConnectionComplete = 0x03,
    ConnectionRequest = 0x04,
    DisconnectionComplete = 0x05,
    CommandComplete = 0x0e,
    CommandStatus = 0x0f,
    LeMetaEvent = 0x3e,
    Unknown = 0xff,
}

impl From<u8> for HciEvent {
    fn from(value: u8) -> Self {
        match value {
            0x01 => HciEvent::InquiryComplete,
            0x02 => HciEvent::InquiryResult,
            0x03 => HciEvent::ConnectionComplete,
            0x04 => HciEvent::ConnectionRequest,
            0x05 => HciEvent::DisconnectionComplete,
            0x0e => HciEvent::CommandComplete,
            0x0f => HciEvent::CommandStatus,
            0x3e => HciEvent::LeMetaEvent,
            _ => HciEvent::Unknown,
        }
    }
}

/// Parsed HCI packet
#[derive(Debug, Clone)]
pub enum HciPacket {
    /// HCI Command
    Command { opcode: HciOpcode, params: Bytes },
    /// HCI Event
    Event { event_code: HciEvent, params: Bytes },
    /// ACL Data
    AclData {
        handle: u16,
        pb_flag: u8,
        bc_flag: u8,
        data: Bytes,
    },
    /// SCO Data
    ScoData { handle: u16, data: Bytes },
    /// ISO Data
    IsoData { data: Bytes },
    /// Raw packet (unparsed)
    Raw {
        packet_type: HciPacketType,
        data: Bytes,
    },
}

impl HciPacket {
    /// Parse a raw HCI packet from bytes (with H4 packet type indicator)
    pub fn parse(mut data: Bytes) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidPacket("Empty packet".into()));
        }

        let packet_type = HciPacketType::from(data.get_u8());
        Self::parse_no_indicator(packet_type, data)
    }

    /// Parse a raw HCI packet without the H4 indicator byte
    pub fn parse_no_indicator(packet_type: HciPacketType, mut data: Bytes) -> Result<Self> {
        match packet_type {
            HciPacketType::Command => {
                if data.remaining() < 3 {
                    return Ok(HciPacket::Raw { packet_type, data });
                }
                let opcode = HciOpcode(data.get_u16_le());
                let param_len = data.get_u8() as usize;

                if data.remaining() < param_len {
                    return Err(Error::InvalidPacket(format!(
                        "Command packet too short: expected {} bytes, got {}",
                        param_len,
                        data.remaining()
                    )));
                }

                let params = data.split_to(param_len);
                Ok(HciPacket::Command { opcode, params })
            }

            HciPacketType::Event => {
                if data.remaining() < 2 {
                    return Ok(HciPacket::Raw { packet_type, data });
                }
                let event_code = HciEvent::from(data.get_u8());
                let param_len = data.get_u8() as usize;

                if data.remaining() < param_len {
                    return Err(Error::InvalidPacket(format!(
                        "Event packet too short: expected {} bytes, got {}",
                        param_len,
                        data.remaining()
                    )));
                }

                let params = data.split_to(param_len);
                Ok(HciPacket::Event { event_code, params })
            }

            HciPacketType::AclData => {
                if data.remaining() < 4 {
                    return Ok(HciPacket::Raw { packet_type, data });
                }
                let handle_flags = data.get_u16_le();
                let handle = handle_flags & 0x0fff;
                let pb_flag = ((handle_flags >> 12) & 0x3) as u8;
                let bc_flag = ((handle_flags >> 14) & 0x3) as u8;
                let data_len = data.get_u16_le() as usize;

                if data.remaining() < data_len {
                    return Err(Error::InvalidPacket(format!(
                        "ACL packet too short: expected {} bytes, got {}",
                        data_len,
                        data.remaining()
                    )));
                }

                let acl_data = data.split_to(data_len);
                Ok(HciPacket::AclData {
                    handle,
                    pb_flag,
                    bc_flag,
                    data: acl_data,
                })
            }

            HciPacketType::ScoData => {
                if data.remaining() < 3 {
                    return Ok(HciPacket::Raw { packet_type, data });
                }
                let handle = data.get_u16_le() & 0x0fff;
                let data_len = data.get_u8() as usize;

                if data.remaining() < data_len {
                    return Err(Error::InvalidPacket(format!(
                        "SCO packet too short: expected {} bytes, got {}",
                        data_len,
                        data.remaining()
                    )));
                }

                let sco_data = data.split_to(data_len);
                Ok(HciPacket::ScoData {
                    handle,
                    data: sco_data,
                })
            }

            HciPacketType::IsoData => Ok(HciPacket::IsoData { data }),

            _ => Ok(HciPacket::Raw { packet_type, data }),
        }
    }

    /// Check if this is an ATT packet (for BLE GATT debugging)
    pub fn is_att(&self) -> bool {
        if let HciPacket::AclData { data, .. } = self {
            // L2CAP header: 2 bytes length + 2 bytes CID
            if data.len() >= 4 {
                let cid = u16::from_le_bytes([data[2], data[3]]);
                return cid == 0x0004; // ATT_CID
            }
        }
        false
    }

    /// Check if this is a command complete event
    pub fn is_command_complete(&self) -> bool {
        matches!(
            self,
            HciPacket::Event {
                event_code: HciEvent::CommandComplete,
                ..
            }
        )
    }

    /// Parse L2CAP packet from ACL data
    /// Returns None if this is not an ACL packet or L2CAP parsing fails
    pub fn as_l2cap(&self) -> Option<crate::l2cap::L2capPacket> {
        if let HciPacket::AclData { data, .. } = self {
            crate::l2cap::L2capPacket::parse(data.clone())
        } else {
            None
        }
    }

    /// Parse ATT PDU from ACL data
    /// Returns None if this is not an ATT packet or parsing fails
    pub fn as_att(&self) -> Option<crate::att::AttPdu> {
        self.as_l2cap().and_then(|l2cap| {
            if l2cap.is_att() {
                crate::att::AttPdu::parse(l2cap.payload)
            } else {
                None
            }
        })
    }

    /// Check if this is an SMP (Security Manager Protocol) packet
    pub fn is_smp(&self) -> bool {
        self.as_l2cap().map(|l| l.is_smp()).unwrap_or(false)
    }

    /// Get the L2CAP CID if this is an ACL packet
    pub fn l2cap_cid(&self) -> Option<crate::l2cap::L2capCid> {
        self.as_l2cap().map(|l| l.cid)
    }
}
