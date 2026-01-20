//! L2CAP (Logical Link Control and Adaptation Protocol) parsing
//!
//! L2CAP provides connection-oriented and connectionless data services
//! to upper layer protocols with protocol multiplexing capability,
//! segmentation and reassembly operation, and group abstractions.

use bytes::{Buf, Bytes};
use std::fmt;

/// L2CAP Channel Identifiers (CIDs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum L2capCid {
    /// Null identifier
    Null = 0x0000,
    /// L2CAP Signaling channel (BR/EDR)
    SignalingBrEdr = 0x0001,
    /// Connectionless channel
    Connectionless = 0x0002,
    /// AMP Manager Protocol
    AmpManager = 0x0003,
    /// Attribute Protocol (ATT)
    Att = 0x0004,
    /// LE L2CAP Signaling channel
    SignalingLe = 0x0005,
    /// Security Manager Protocol
    Smp = 0x0006,
    /// BR/EDR Security Manager
    SmpBrEdr = 0x0007,
    /// Dynamic channel (range 0x0040-0xFFFF)
    Dynamic(u16),
    /// Unknown CID
    Unknown(u16),
}

impl From<u16> for L2capCid {
    fn from(value: u16) -> Self {
        match value {
            0x0000 => L2capCid::Null,
            0x0001 => L2capCid::SignalingBrEdr,
            0x0002 => L2capCid::Connectionless,
            0x0003 => L2capCid::AmpManager,
            0x0004 => L2capCid::Att,
            0x0005 => L2capCid::SignalingLe,
            0x0006 => L2capCid::Smp,
            0x0007 => L2capCid::SmpBrEdr,
            0x0040..=0xFFFF => L2capCid::Dynamic(value),
            _ => L2capCid::Unknown(value),
        }
    }
}

impl L2capCid {
    /// Get the raw CID value
    pub fn value(&self) -> u16 {
        match self {
            L2capCid::Null => 0x0000,
            L2capCid::SignalingBrEdr => 0x0001,
            L2capCid::Connectionless => 0x0002,
            L2capCid::AmpManager => 0x0003,
            L2capCid::Att => 0x0004,
            L2capCid::SignalingLe => 0x0005,
            L2capCid::Smp => 0x0006,
            L2capCid::SmpBrEdr => 0x0007,
            L2capCid::Dynamic(v) | L2capCid::Unknown(v) => *v,
        }
    }
}

impl fmt::Display for L2capCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            L2capCid::Null => write!(f, "Null"),
            L2capCid::SignalingBrEdr => write!(f, "L2CAP Signaling (BR/EDR)"),
            L2capCid::Connectionless => write!(f, "Connectionless"),
            L2capCid::AmpManager => write!(f, "AMP Manager"),
            L2capCid::Att => write!(f, "ATT"),
            L2capCid::SignalingLe => write!(f, "L2CAP Signaling (LE)"),
            L2capCid::Smp => write!(f, "SMP"),
            L2capCid::SmpBrEdr => write!(f, "SMP (BR/EDR)"),
            L2capCid::Dynamic(v) => write!(f, "Dynamic(0x{:04x})", v),
            L2capCid::Unknown(v) => write!(f, "Unknown(0x{:04x})", v),
        }
    }
}

/// L2CAP Signaling Command codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L2capSignalingCode {
    CommandReject = 0x01,
    ConnectionRequest = 0x02,
    ConnectionResponse = 0x03,
    ConfigureRequest = 0x04,
    ConfigureResponse = 0x05,
    DisconnectionRequest = 0x06,
    DisconnectionResponse = 0x07,
    EchoRequest = 0x08,
    EchoResponse = 0x09,
    InformationRequest = 0x0a,
    InformationResponse = 0x0b,
    CreateChannelRequest = 0x0c,
    CreateChannelResponse = 0x0d,
    MoveChannelRequest = 0x0e,
    MoveChannelResponse = 0x0f,
    MoveChannelConfirm = 0x10,
    MoveChannelConfirmResponse = 0x11,
    ConnectionParameterUpdateRequest = 0x12,
    ConnectionParameterUpdateResponse = 0x13,
    LeCreditBasedConnectionRequest = 0x14,
    LeCreditBasedConnectionResponse = 0x15,
    FlowControlCreditInd = 0x16,
    CreditBasedConnectionRequest = 0x17,
    CreditBasedConnectionResponse = 0x18,
    CreditBasedReconfigureRequest = 0x19,
    CreditBasedReconfigureResponse = 0x1a,
    Unknown(u8),
}

impl From<u8> for L2capSignalingCode {
    fn from(value: u8) -> Self {
        match value {
            0x01 => L2capSignalingCode::CommandReject,
            0x02 => L2capSignalingCode::ConnectionRequest,
            0x03 => L2capSignalingCode::ConnectionResponse,
            0x04 => L2capSignalingCode::ConfigureRequest,
            0x05 => L2capSignalingCode::ConfigureResponse,
            0x06 => L2capSignalingCode::DisconnectionRequest,
            0x07 => L2capSignalingCode::DisconnectionResponse,
            0x08 => L2capSignalingCode::EchoRequest,
            0x09 => L2capSignalingCode::EchoResponse,
            0x0a => L2capSignalingCode::InformationRequest,
            0x0b => L2capSignalingCode::InformationResponse,
            0x0c => L2capSignalingCode::CreateChannelRequest,
            0x0d => L2capSignalingCode::CreateChannelResponse,
            0x0e => L2capSignalingCode::MoveChannelRequest,
            0x0f => L2capSignalingCode::MoveChannelResponse,
            0x10 => L2capSignalingCode::MoveChannelConfirm,
            0x11 => L2capSignalingCode::MoveChannelConfirmResponse,
            0x12 => L2capSignalingCode::ConnectionParameterUpdateRequest,
            0x13 => L2capSignalingCode::ConnectionParameterUpdateResponse,
            0x14 => L2capSignalingCode::LeCreditBasedConnectionRequest,
            0x15 => L2capSignalingCode::LeCreditBasedConnectionResponse,
            0x16 => L2capSignalingCode::FlowControlCreditInd,
            0x17 => L2capSignalingCode::CreditBasedConnectionRequest,
            0x18 => L2capSignalingCode::CreditBasedConnectionResponse,
            0x19 => L2capSignalingCode::CreditBasedReconfigureRequest,
            0x1a => L2capSignalingCode::CreditBasedReconfigureResponse,
            v => L2capSignalingCode::Unknown(v),
        }
    }
}

/// Parsed L2CAP packet
#[derive(Debug, Clone)]
pub struct L2capPacket {
    /// L2CAP payload length
    pub length: u16,
    /// Channel Identifier
    pub cid: L2capCid,
    /// Payload data
    pub payload: Bytes,
}

impl L2capPacket {
    /// Parse L2CAP packet from ACL data
    pub fn parse(mut data: Bytes) -> Option<Self> {
        if data.remaining() < 4 {
            return None;
        }

        let length = data.get_u16_le();
        let cid = L2capCid::from(data.get_u16_le());
        let payload = data;

        Some(L2capPacket {
            length,
            cid,
            payload,
        })
    }

    /// Check if this is an ATT packet
    pub fn is_att(&self) -> bool {
        self.cid == L2capCid::Att
    }

    /// Check if this is an SMP packet
    pub fn is_smp(&self) -> bool {
        self.cid == L2capCid::Smp || self.cid == L2capCid::SmpBrEdr
    }

    /// Check if this is a signaling packet
    pub fn is_signaling(&self) -> bool {
        self.cid == L2capCid::SignalingBrEdr || self.cid == L2capCid::SignalingLe
    }
}

/// L2CAP Signaling packet
#[derive(Debug, Clone)]
pub struct L2capSignaling {
    /// Command code
    pub code: L2capSignalingCode,
    /// Identifier
    pub identifier: u8,
    /// Command data length
    pub length: u16,
    /// Command data
    pub data: Bytes,
}

impl L2capSignaling {
    /// Parse L2CAP signaling command from payload
    pub fn parse(mut data: Bytes) -> Option<Self> {
        if data.remaining() < 4 {
            return None;
        }

        let code = L2capSignalingCode::from(data.get_u8());
        let identifier = data.get_u8();
        let length = data.get_u16_le();

        Some(L2capSignaling {
            code,
            identifier,
            length,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cid_parsing() {
        assert_eq!(L2capCid::from(0x0004), L2capCid::Att);
        assert_eq!(L2capCid::from(0x0006), L2capCid::Smp);
        assert!(matches!(L2capCid::from(0x0040), L2capCid::Dynamic(0x0040)));
    }

    #[test]
    fn test_l2cap_packet_parse() {
        // Length=5, CID=0x0004 (ATT), payload=0x01,0x02,0x03,0x04,0x05
        let data = Bytes::from_static(&[0x05, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let packet = L2capPacket::parse(data).unwrap();

        assert_eq!(packet.length, 5);
        assert_eq!(packet.cid, L2capCid::Att);
        assert!(packet.is_att());
        assert_eq!(packet.payload.len(), 5);
    }
}
