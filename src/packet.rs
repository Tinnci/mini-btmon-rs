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

/// HCI Event codes from Bluetooth Core Specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HciEvent {
    /// Inquiry Complete Event
    InquiryComplete,
    /// Inquiry Result Event
    InquiryResult,
    /// Connection Complete Event
    ConnectionComplete,
    /// Connection Request Event
    ConnectionRequest,
    /// Disconnection Complete Event
    DisconnectionComplete,
    /// Authentication Complete Event
    AuthenticationComplete,
    /// Remote Name Request Complete Event
    RemoteNameRequestComplete,
    /// Encryption Change Event
    EncryptionChange,
    /// Change Connection Link Key Complete Event
    ChangeConnectionLinkKeyComplete,
    /// Read Remote Supported Features Complete Event
    ReadRemoteSupportedFeaturesComplete,
    /// Read Remote Version Information Complete Event
    ReadRemoteVersionInformationComplete,
    /// QoS Setup Complete Event
    QosSetupComplete,
    /// Command Complete Event
    CommandComplete,
    /// Command Status Event
    CommandStatus,
    /// Hardware Error Event
    HardwareError,
    /// Flush Occurred Event
    FlushOccurred,
    /// Role Change Event
    RoleChange,
    /// Number Of Completed Packets Event
    NumberOfCompletedPackets,
    /// Mode Change Event
    ModeChange,
    /// Return Link Keys Event
    ReturnLinkKeys,
    /// PIN Code Request Event
    PinCodeRequest,
    /// Link Key Request Event
    LinkKeyRequest,
    /// Link Key Notification Event
    LinkKeyNotification,
    /// Data Buffer Overflow Event
    DataBufferOverflow,
    /// Max Slots Change Event
    MaxSlotsChange,
    /// Read Clock Offset Complete Event
    ReadClockOffsetComplete,
    /// Connection Packet Type Changed Event
    ConnectionPacketTypeChanged,
    /// QoS Violation Event
    QosViolation,
    /// Page Scan Repetition Mode Change Event
    PageScanRepetitionModeChange,
    /// Inquiry Result with RSSI Event
    InquiryResultWithRssi,
    /// Read Remote Extended Features Complete Event
    ReadRemoteExtendedFeaturesComplete,
    /// Synchronous Connection Complete Event
    SynchronousConnectionComplete,
    /// Synchronous Connection Changed Event
    SynchronousConnectionChanged,
    /// Extended Inquiry Result Event
    ExtendedInquiryResult,
    /// Encryption Key Refresh Complete Event
    EncryptionKeyRefreshComplete,
    /// IO Capability Request Event
    IoCapabilityRequest,
    /// IO Capability Response Event
    IoCapabilityResponse,
    /// User Confirmation Request Event
    UserConfirmationRequest,
    /// User Passkey Request Event
    UserPasskeyRequest,
    /// Simple Pairing Complete Event
    SimplePairingComplete,
    /// Link Supervision Timeout Changed Event
    LinkSupervisionTimeoutChanged,
    /// Enhanced Flush Complete Event
    EnhancedFlushComplete,
    /// User Passkey Notification Event
    UserPasskeyNotification,
    /// LE Meta Event
    LeMetaEvent,
    /// Authenticated Payload Timeout Expired Event
    AuthenticatedPayloadTimeoutExpired,
    /// Vendor Specific Event
    VendorSpecific,
    /// Unknown Event
    Unknown(u8),
}

impl HciEvent {
    /// Get the raw event code
    pub fn code(&self) -> u8 {
        match self {
            HciEvent::InquiryComplete => 0x01,
            HciEvent::InquiryResult => 0x02,
            HciEvent::ConnectionComplete => 0x03,
            HciEvent::ConnectionRequest => 0x04,
            HciEvent::DisconnectionComplete => 0x05,
            HciEvent::AuthenticationComplete => 0x06,
            HciEvent::RemoteNameRequestComplete => 0x07,
            HciEvent::EncryptionChange => 0x08,
            HciEvent::ChangeConnectionLinkKeyComplete => 0x09,
            HciEvent::ReadRemoteSupportedFeaturesComplete => 0x0b,
            HciEvent::ReadRemoteVersionInformationComplete => 0x0c,
            HciEvent::QosSetupComplete => 0x0d,
            HciEvent::CommandComplete => 0x0e,
            HciEvent::CommandStatus => 0x0f,
            HciEvent::HardwareError => 0x10,
            HciEvent::FlushOccurred => 0x11,
            HciEvent::RoleChange => 0x12,
            HciEvent::NumberOfCompletedPackets => 0x13,
            HciEvent::ModeChange => 0x14,
            HciEvent::ReturnLinkKeys => 0x15,
            HciEvent::PinCodeRequest => 0x16,
            HciEvent::LinkKeyRequest => 0x17,
            HciEvent::LinkKeyNotification => 0x18,
            HciEvent::DataBufferOverflow => 0x1a,
            HciEvent::MaxSlotsChange => 0x1b,
            HciEvent::ReadClockOffsetComplete => 0x1c,
            HciEvent::ConnectionPacketTypeChanged => 0x1d,
            HciEvent::QosViolation => 0x1e,
            HciEvent::PageScanRepetitionModeChange => 0x20,
            HciEvent::InquiryResultWithRssi => 0x22,
            HciEvent::ReadRemoteExtendedFeaturesComplete => 0x23,
            HciEvent::SynchronousConnectionComplete => 0x2c,
            HciEvent::SynchronousConnectionChanged => 0x2d,
            HciEvent::ExtendedInquiryResult => 0x2f,
            HciEvent::EncryptionKeyRefreshComplete => 0x30,
            HciEvent::IoCapabilityRequest => 0x31,
            HciEvent::IoCapabilityResponse => 0x32,
            HciEvent::UserConfirmationRequest => 0x33,
            HciEvent::UserPasskeyRequest => 0x34,
            HciEvent::SimplePairingComplete => 0x36,
            HciEvent::LinkSupervisionTimeoutChanged => 0x38,
            HciEvent::EnhancedFlushComplete => 0x39,
            HciEvent::UserPasskeyNotification => 0x3b,
            HciEvent::LeMetaEvent => 0x3e,
            HciEvent::AuthenticatedPayloadTimeoutExpired => 0x57,
            HciEvent::VendorSpecific => 0xff,
            HciEvent::Unknown(v) => *v,
        }
    }

    /// Get the event name as a string
    pub fn name(&self) -> &'static str {
        match self {
            HciEvent::InquiryComplete => "Inquiry Complete",
            HciEvent::InquiryResult => "Inquiry Result",
            HciEvent::ConnectionComplete => "Connection Complete",
            HciEvent::ConnectionRequest => "Connection Request",
            HciEvent::DisconnectionComplete => "Disconnection Complete",
            HciEvent::AuthenticationComplete => "Authentication Complete",
            HciEvent::RemoteNameRequestComplete => "Remote Name Request Complete",
            HciEvent::EncryptionChange => "Encryption Change",
            HciEvent::ChangeConnectionLinkKeyComplete => "Change Connection Link Key Complete",
            HciEvent::ReadRemoteSupportedFeaturesComplete => {
                "Read Remote Supported Features Complete"
            }
            HciEvent::ReadRemoteVersionInformationComplete => {
                "Read Remote Version Information Complete"
            }
            HciEvent::QosSetupComplete => "QoS Setup Complete",
            HciEvent::CommandComplete => "Command Complete",
            HciEvent::CommandStatus => "Command Status",
            HciEvent::HardwareError => "Hardware Error",
            HciEvent::FlushOccurred => "Flush Occurred",
            HciEvent::RoleChange => "Role Change",
            HciEvent::NumberOfCompletedPackets => "Number Of Completed Packets",
            HciEvent::ModeChange => "Mode Change",
            HciEvent::ReturnLinkKeys => "Return Link Keys",
            HciEvent::PinCodeRequest => "PIN Code Request",
            HciEvent::LinkKeyRequest => "Link Key Request",
            HciEvent::LinkKeyNotification => "Link Key Notification",
            HciEvent::DataBufferOverflow => "Data Buffer Overflow",
            HciEvent::MaxSlotsChange => "Max Slots Change",
            HciEvent::ReadClockOffsetComplete => "Read Clock Offset Complete",
            HciEvent::ConnectionPacketTypeChanged => "Connection Packet Type Changed",
            HciEvent::QosViolation => "QoS Violation",
            HciEvent::PageScanRepetitionModeChange => "Page Scan Repetition Mode Change",
            HciEvent::InquiryResultWithRssi => "Inquiry Result with RSSI",
            HciEvent::ReadRemoteExtendedFeaturesComplete => {
                "Read Remote Extended Features Complete"
            }
            HciEvent::SynchronousConnectionComplete => "Synchronous Connection Complete",
            HciEvent::SynchronousConnectionChanged => "Synchronous Connection Changed",
            HciEvent::ExtendedInquiryResult => "Extended Inquiry Result",
            HciEvent::EncryptionKeyRefreshComplete => "Encryption Key Refresh Complete",
            HciEvent::IoCapabilityRequest => "IO Capability Request",
            HciEvent::IoCapabilityResponse => "IO Capability Response",
            HciEvent::UserConfirmationRequest => "User Confirmation Request",
            HciEvent::UserPasskeyRequest => "User Passkey Request",
            HciEvent::SimplePairingComplete => "Simple Pairing Complete",
            HciEvent::LinkSupervisionTimeoutChanged => "Link Supervision Timeout Changed",
            HciEvent::EnhancedFlushComplete => "Enhanced Flush Complete",
            HciEvent::UserPasskeyNotification => "User Passkey Notification",
            HciEvent::LeMetaEvent => "LE Meta Event",
            HciEvent::AuthenticatedPayloadTimeoutExpired => "Authenticated Payload Timeout Expired",
            HciEvent::VendorSpecific => "Vendor Specific",
            HciEvent::Unknown(_) => "Unknown",
        }
    }
}

impl From<u8> for HciEvent {
    fn from(value: u8) -> Self {
        match value {
            0x01 => HciEvent::InquiryComplete,
            0x02 => HciEvent::InquiryResult,
            0x03 => HciEvent::ConnectionComplete,
            0x04 => HciEvent::ConnectionRequest,
            0x05 => HciEvent::DisconnectionComplete,
            0x06 => HciEvent::AuthenticationComplete,
            0x07 => HciEvent::RemoteNameRequestComplete,
            0x08 => HciEvent::EncryptionChange,
            0x09 => HciEvent::ChangeConnectionLinkKeyComplete,
            0x0b => HciEvent::ReadRemoteSupportedFeaturesComplete,
            0x0c => HciEvent::ReadRemoteVersionInformationComplete,
            0x0d => HciEvent::QosSetupComplete,
            0x0e => HciEvent::CommandComplete,
            0x0f => HciEvent::CommandStatus,
            0x10 => HciEvent::HardwareError,
            0x11 => HciEvent::FlushOccurred,
            0x12 => HciEvent::RoleChange,
            0x13 => HciEvent::NumberOfCompletedPackets,
            0x14 => HciEvent::ModeChange,
            0x15 => HciEvent::ReturnLinkKeys,
            0x16 => HciEvent::PinCodeRequest,
            0x17 => HciEvent::LinkKeyRequest,
            0x18 => HciEvent::LinkKeyNotification,
            0x1a => HciEvent::DataBufferOverflow,
            0x1b => HciEvent::MaxSlotsChange,
            0x1c => HciEvent::ReadClockOffsetComplete,
            0x1d => HciEvent::ConnectionPacketTypeChanged,
            0x1e => HciEvent::QosViolation,
            0x20 => HciEvent::PageScanRepetitionModeChange,
            0x22 => HciEvent::InquiryResultWithRssi,
            0x23 => HciEvent::ReadRemoteExtendedFeaturesComplete,
            0x2c => HciEvent::SynchronousConnectionComplete,
            0x2d => HciEvent::SynchronousConnectionChanged,
            0x2f => HciEvent::ExtendedInquiryResult,
            0x30 => HciEvent::EncryptionKeyRefreshComplete,
            0x31 => HciEvent::IoCapabilityRequest,
            0x32 => HciEvent::IoCapabilityResponse,
            0x33 => HciEvent::UserConfirmationRequest,
            0x34 => HciEvent::UserPasskeyRequest,
            0x36 => HciEvent::SimplePairingComplete,
            0x38 => HciEvent::LinkSupervisionTimeoutChanged,
            0x39 => HciEvent::EnhancedFlushComplete,
            0x3b => HciEvent::UserPasskeyNotification,
            0x3e => HciEvent::LeMetaEvent,
            0x57 => HciEvent::AuthenticatedPayloadTimeoutExpired,
            0xff => HciEvent::VendorSpecific,
            v => HciEvent::Unknown(v),
        }
    }
}

impl std::fmt::Display for HciEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (0x{:02x})", self.name(), self.code())
    }
}

/// LE Meta Event Subevent codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeMetaSubevent {
    /// LE Connection Complete Event
    ConnectionComplete,
    /// LE Advertising Report Event
    AdvertisingReport,
    /// LE Connection Update Complete Event
    ConnectionUpdateComplete,
    /// LE Read Remote Features Complete Event
    ReadRemoteFeaturesComplete,
    /// LE Long Term Key Request Event
    LongTermKeyRequest,
    /// LE Remote Connection Parameter Request Event
    RemoteConnectionParameterRequest,
    /// LE Data Length Change Event
    DataLengthChange,
    /// LE Read Local P-256 Public Key Complete Event
    ReadLocalP256PublicKeyComplete,
    /// LE Generate DHKey Complete Event
    GenerateDhKeyComplete,
    /// LE Enhanced Connection Complete Event
    EnhancedConnectionComplete,
    /// LE Directed Advertising Report Event
    DirectedAdvertisingReport,
    /// LE PHY Update Complete Event
    PhyUpdateComplete,
    /// LE Extended Advertising Report Event
    ExtendedAdvertisingReport,
    /// LE Periodic Advertising Sync Established Event
    PeriodicAdvertisingSyncEstablished,
    /// LE Periodic Advertising Report Event
    PeriodicAdvertisingReport,
    /// LE Periodic Advertising Sync Lost Event
    PeriodicAdvertisingSyncLost,
    /// LE Scan Timeout Event
    ScanTimeout,
    /// LE Advertising Set Terminated Event
    AdvertisingSetTerminated,
    /// LE Scan Request Received Event
    ScanRequestReceived,
    /// LE Channel Selection Algorithm Event
    ChannelSelectionAlgorithm,
    /// LE CIS Established Event
    CisEstablished,
    /// LE CIS Request Event
    CisRequest,
    /// LE Create BIG Complete Event
    CreateBigComplete,
    /// LE Terminate BIG Complete Event
    TerminateBigComplete,
    /// LE BIG Sync Established Event
    BigSyncEstablished,
    /// LE BIG Sync Lost Event
    BigSyncLost,
    /// Unknown subevent
    Unknown(u8),
}

impl LeMetaSubevent {
    /// Get the raw subevent code
    pub fn code(&self) -> u8 {
        match self {
            LeMetaSubevent::ConnectionComplete => 0x01,
            LeMetaSubevent::AdvertisingReport => 0x02,
            LeMetaSubevent::ConnectionUpdateComplete => 0x03,
            LeMetaSubevent::ReadRemoteFeaturesComplete => 0x04,
            LeMetaSubevent::LongTermKeyRequest => 0x05,
            LeMetaSubevent::RemoteConnectionParameterRequest => 0x06,
            LeMetaSubevent::DataLengthChange => 0x07,
            LeMetaSubevent::ReadLocalP256PublicKeyComplete => 0x08,
            LeMetaSubevent::GenerateDhKeyComplete => 0x09,
            LeMetaSubevent::EnhancedConnectionComplete => 0x0a,
            LeMetaSubevent::DirectedAdvertisingReport => 0x0b,
            LeMetaSubevent::PhyUpdateComplete => 0x0c,
            LeMetaSubevent::ExtendedAdvertisingReport => 0x0d,
            LeMetaSubevent::PeriodicAdvertisingSyncEstablished => 0x0e,
            LeMetaSubevent::PeriodicAdvertisingReport => 0x0f,
            LeMetaSubevent::PeriodicAdvertisingSyncLost => 0x10,
            LeMetaSubevent::ScanTimeout => 0x11,
            LeMetaSubevent::AdvertisingSetTerminated => 0x12,
            LeMetaSubevent::ScanRequestReceived => 0x13,
            LeMetaSubevent::ChannelSelectionAlgorithm => 0x14,
            LeMetaSubevent::CisEstablished => 0x19,
            LeMetaSubevent::CisRequest => 0x1a,
            LeMetaSubevent::CreateBigComplete => 0x1b,
            LeMetaSubevent::TerminateBigComplete => 0x1c,
            LeMetaSubevent::BigSyncEstablished => 0x1d,
            LeMetaSubevent::BigSyncLost => 0x1e,
            LeMetaSubevent::Unknown(v) => *v,
        }
    }

    /// Get the subevent name as a string
    pub fn name(&self) -> &'static str {
        match self {
            LeMetaSubevent::ConnectionComplete => "LE Connection Complete",
            LeMetaSubevent::AdvertisingReport => "LE Advertising Report",
            LeMetaSubevent::ConnectionUpdateComplete => "LE Connection Update Complete",
            LeMetaSubevent::ReadRemoteFeaturesComplete => "LE Read Remote Features Complete",
            LeMetaSubevent::LongTermKeyRequest => "LE Long Term Key Request",
            LeMetaSubevent::RemoteConnectionParameterRequest => {
                "LE Remote Connection Parameter Request"
            }
            LeMetaSubevent::DataLengthChange => "LE Data Length Change",
            LeMetaSubevent::ReadLocalP256PublicKeyComplete => {
                "LE Read Local P-256 Public Key Complete"
            }
            LeMetaSubevent::GenerateDhKeyComplete => "LE Generate DHKey Complete",
            LeMetaSubevent::EnhancedConnectionComplete => "LE Enhanced Connection Complete",
            LeMetaSubevent::DirectedAdvertisingReport => "LE Directed Advertising Report",
            LeMetaSubevent::PhyUpdateComplete => "LE PHY Update Complete",
            LeMetaSubevent::ExtendedAdvertisingReport => "LE Extended Advertising Report",
            LeMetaSubevent::PeriodicAdvertisingSyncEstablished => {
                "LE Periodic Advertising Sync Established"
            }
            LeMetaSubevent::PeriodicAdvertisingReport => "LE Periodic Advertising Report",
            LeMetaSubevent::PeriodicAdvertisingSyncLost => "LE Periodic Advertising Sync Lost",
            LeMetaSubevent::ScanTimeout => "LE Scan Timeout",
            LeMetaSubevent::AdvertisingSetTerminated => "LE Advertising Set Terminated",
            LeMetaSubevent::ScanRequestReceived => "LE Scan Request Received",
            LeMetaSubevent::ChannelSelectionAlgorithm => "LE Channel Selection Algorithm",
            LeMetaSubevent::CisEstablished => "LE CIS Established",
            LeMetaSubevent::CisRequest => "LE CIS Request",
            LeMetaSubevent::CreateBigComplete => "LE Create BIG Complete",
            LeMetaSubevent::TerminateBigComplete => "LE Terminate BIG Complete",
            LeMetaSubevent::BigSyncEstablished => "LE BIG Sync Established",
            LeMetaSubevent::BigSyncLost => "LE BIG Sync Lost",
            LeMetaSubevent::Unknown(_) => "Unknown",
        }
    }
}

impl From<u8> for LeMetaSubevent {
    fn from(value: u8) -> Self {
        match value {
            0x01 => LeMetaSubevent::ConnectionComplete,
            0x02 => LeMetaSubevent::AdvertisingReport,
            0x03 => LeMetaSubevent::ConnectionUpdateComplete,
            0x04 => LeMetaSubevent::ReadRemoteFeaturesComplete,
            0x05 => LeMetaSubevent::LongTermKeyRequest,
            0x06 => LeMetaSubevent::RemoteConnectionParameterRequest,
            0x07 => LeMetaSubevent::DataLengthChange,
            0x08 => LeMetaSubevent::ReadLocalP256PublicKeyComplete,
            0x09 => LeMetaSubevent::GenerateDhKeyComplete,
            0x0a => LeMetaSubevent::EnhancedConnectionComplete,
            0x0b => LeMetaSubevent::DirectedAdvertisingReport,
            0x0c => LeMetaSubevent::PhyUpdateComplete,
            0x0d => LeMetaSubevent::ExtendedAdvertisingReport,
            0x0e => LeMetaSubevent::PeriodicAdvertisingSyncEstablished,
            0x0f => LeMetaSubevent::PeriodicAdvertisingReport,
            0x10 => LeMetaSubevent::PeriodicAdvertisingSyncLost,
            0x11 => LeMetaSubevent::ScanTimeout,
            0x12 => LeMetaSubevent::AdvertisingSetTerminated,
            0x13 => LeMetaSubevent::ScanRequestReceived,
            0x14 => LeMetaSubevent::ChannelSelectionAlgorithm,
            0x19 => LeMetaSubevent::CisEstablished,
            0x1a => LeMetaSubevent::CisRequest,
            0x1b => LeMetaSubevent::CreateBigComplete,
            0x1c => LeMetaSubevent::TerminateBigComplete,
            0x1d => LeMetaSubevent::BigSyncEstablished,
            0x1e => LeMetaSubevent::BigSyncLost,
            v => LeMetaSubevent::Unknown(v),
        }
    }
}

impl std::fmt::Display for LeMetaSubevent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (0x{:02x})", self.name(), self.code())
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

// ============================================================================
// Builder methods for HciPacket
// ============================================================================

impl HciPacket {
    /// Create an HCI Command packet
    ///
    /// # Example
    /// ```
    /// use mini_btmon_rs::HciPacket;
    ///
    /// // HCI Reset command (OGF=0x03, OCF=0x003)
    /// let reset = HciPacket::command(0x0c03, &[]);
    /// ```
    pub fn command(opcode: u16, params: &[u8]) -> Self {
        HciPacket::Command {
            opcode: HciOpcode(opcode),
            params: Bytes::copy_from_slice(params),
        }
    }

    /// Create an HCI Command packet from OGF and OCF
    ///
    /// # Example
    /// ```
    /// use mini_btmon_rs::HciPacket;
    ///
    /// // HCI Reset command (OGF=0x03, OCF=0x003)
    /// let reset = HciPacket::command_ogf_ocf(0x03, 0x003, &[]);
    /// ```
    pub fn command_ogf_ocf(ogf: u8, ocf: u16, params: &[u8]) -> Self {
        let opcode = ((ogf as u16) << 10) | (ocf & 0x3ff);
        Self::command(opcode, params)
    }

    /// Create an HCI Event packet
    ///
    /// # Example
    /// ```
    /// use mini_btmon_rs::{HciPacket, HciEvent};
    ///
    /// let event = HciPacket::event(HciEvent::CommandComplete, &[0x01, 0x03, 0x0c, 0x00]);
    /// ```
    pub fn event(event_code: HciEvent, params: &[u8]) -> Self {
        HciPacket::Event {
            event_code,
            params: Bytes::copy_from_slice(params),
        }
    }

    /// Create an ACL Data packet
    ///
    /// # Example
    /// ```
    /// use mini_btmon_rs::HciPacket;
    ///
    /// let acl = HciPacket::acl_data(0x0040, 0x02, 0x00, &[0x05, 0x00, 0x04, 0x00]);
    /// ```
    pub fn acl_data(handle: u16, pb_flag: u8, bc_flag: u8, data: &[u8]) -> Self {
        HciPacket::AclData {
            handle,
            pb_flag,
            bc_flag,
            data: Bytes::copy_from_slice(data),
        }
    }

    /// Create an ACL Data packet with first fragment (PB=0x02, BC=0x00)
    pub fn acl_first_fragment(handle: u16, data: &[u8]) -> Self {
        Self::acl_data(handle, 0x02, 0x00, data)
    }

    /// Create an ACL Data packet with continuation fragment (PB=0x01, BC=0x00)
    pub fn acl_continuation(handle: u16, data: &[u8]) -> Self {
        Self::acl_data(handle, 0x01, 0x00, data)
    }
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

    /// Parse SMP PDU from ACL data
    /// Returns None if this is not an SMP packet or parsing fails
    pub fn as_smp(&self) -> Option<crate::smp::SmpPdu> {
        self.as_l2cap().and_then(|l2cap| {
            if l2cap.is_smp() {
                crate::smp::SmpPdu::parse(l2cap.payload)
            } else {
                None
            }
        })
    }

    /// Get the L2CAP CID if this is an ACL packet
    pub fn l2cap_cid(&self) -> Option<crate::l2cap::L2capCid> {
        self.as_l2cap().map(|l| l.cid)
    }

    /// Check if this is an LE Meta Event
    pub fn is_le_meta_event(&self) -> bool {
        matches!(
            self,
            HciPacket::Event {
                event_code: HciEvent::LeMetaEvent,
                ..
            }
        )
    }

    /// Parse LE Meta Subevent from an LE Meta Event
    ///
    /// Returns the subevent code and remaining parameters if this is an LE Meta Event.
    /// The first byte of an LE Meta Event's parameters is the subevent code.
    ///
    /// # Example
    /// ```
    /// use mini_btmon_rs::{HciPacket, HciEvent, LeMetaSubevent};
    ///
    /// // LE Connection Complete subevent (0x01) with some dummy params
    /// let event = HciPacket::event(HciEvent::LeMetaEvent, &[0x01, 0x00, 0x40, 0x00]);
    /// let (subevent, params) = event.as_le_meta_subevent().unwrap();
    /// assert_eq!(subevent, LeMetaSubevent::ConnectionComplete);
    /// assert_eq!(params, &[0x00, 0x40, 0x00]);
    /// ```
    pub fn as_le_meta_subevent(&self) -> Option<(LeMetaSubevent, &[u8])> {
        if let HciPacket::Event {
            event_code: HciEvent::LeMetaEvent,
            params,
        } = self
            && !params.is_empty()
        {
            let subevent_code = params[0];
            let subevent = LeMetaSubevent::from(subevent_code);
            return Some((subevent, &params[1..]));
        }
        None
    }
}
