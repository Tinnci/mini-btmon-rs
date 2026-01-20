//! SMP (Security Manager Protocol) parsing
//!
//! SMP is used to support pairing and key distribution between
//! Bluetooth Low Energy devices.

use bytes::{Buf, Bytes};
use std::fmt;

/// SMP Command Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SmpCode {
    /// Pairing Request
    PairingRequest = 0x01,
    /// Pairing Response
    PairingResponse = 0x02,
    /// Pairing Confirm
    PairingConfirm = 0x03,
    /// Pairing Random
    PairingRandom = 0x04,
    /// Pairing Failed
    PairingFailed = 0x05,
    /// Encryption Information
    EncryptionInfo = 0x06,
    /// Central Identification (formerly Master Identification)
    CentralIdent = 0x07,
    /// Identity Information
    IdentityInfo = 0x08,
    /// Identity Address Information
    IdentityAddrInfo = 0x09,
    /// Signing Information
    SigningInfo = 0x0a,
    /// Security Request
    SecurityRequest = 0x0b,
    /// Pairing Public Key (LE Secure Connections)
    PairingPublicKey = 0x0c,
    /// Pairing DHKey Check (LE Secure Connections)
    PairingDhKeyCheck = 0x0d,
    /// Keypress Notification
    KeypressNotification = 0x0e,
    /// Unknown command
    Unknown(u8),
}

impl From<u8> for SmpCode {
    fn from(value: u8) -> Self {
        match value {
            0x01 => SmpCode::PairingRequest,
            0x02 => SmpCode::PairingResponse,
            0x03 => SmpCode::PairingConfirm,
            0x04 => SmpCode::PairingRandom,
            0x05 => SmpCode::PairingFailed,
            0x06 => SmpCode::EncryptionInfo,
            0x07 => SmpCode::CentralIdent,
            0x08 => SmpCode::IdentityInfo,
            0x09 => SmpCode::IdentityAddrInfo,
            0x0a => SmpCode::SigningInfo,
            0x0b => SmpCode::SecurityRequest,
            0x0c => SmpCode::PairingPublicKey,
            0x0d => SmpCode::PairingDhKeyCheck,
            0x0e => SmpCode::KeypressNotification,
            v => SmpCode::Unknown(v),
        }
    }
}

impl fmt::Display for SmpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmpCode::PairingRequest => write!(f, "Pairing Request"),
            SmpCode::PairingResponse => write!(f, "Pairing Response"),
            SmpCode::PairingConfirm => write!(f, "Pairing Confirm"),
            SmpCode::PairingRandom => write!(f, "Pairing Random"),
            SmpCode::PairingFailed => write!(f, "Pairing Failed"),
            SmpCode::EncryptionInfo => write!(f, "Encryption Information"),
            SmpCode::CentralIdent => write!(f, "Central Identification"),
            SmpCode::IdentityInfo => write!(f, "Identity Information"),
            SmpCode::IdentityAddrInfo => write!(f, "Identity Address Information"),
            SmpCode::SigningInfo => write!(f, "Signing Information"),
            SmpCode::SecurityRequest => write!(f, "Security Request"),
            SmpCode::PairingPublicKey => write!(f, "Pairing Public Key"),
            SmpCode::PairingDhKeyCheck => write!(f, "Pairing DHKey Check"),
            SmpCode::KeypressNotification => write!(f, "Keypress Notification"),
            SmpCode::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
        }
    }
}

/// SMP IO Capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoCapability {
    /// Display Only
    DisplayOnly = 0x00,
    /// Display Yes/No
    DisplayYesNo = 0x01,
    /// Keyboard Only
    KeyboardOnly = 0x02,
    /// No Input No Output
    NoInputNoOutput = 0x03,
    /// Keyboard Display
    KeyboardDisplay = 0x04,
    /// Reserved/Unknown
    Unknown(u8),
}

impl From<u8> for IoCapability {
    fn from(value: u8) -> Self {
        match value {
            0x00 => IoCapability::DisplayOnly,
            0x01 => IoCapability::DisplayYesNo,
            0x02 => IoCapability::KeyboardOnly,
            0x03 => IoCapability::NoInputNoOutput,
            0x04 => IoCapability::KeyboardDisplay,
            v => IoCapability::Unknown(v),
        }
    }
}

impl fmt::Display for IoCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoCapability::DisplayOnly => write!(f, "DisplayOnly"),
            IoCapability::DisplayYesNo => write!(f, "DisplayYesNo"),
            IoCapability::KeyboardOnly => write!(f, "KeyboardOnly"),
            IoCapability::NoInputNoOutput => write!(f, "NoInputNoOutput"),
            IoCapability::KeyboardDisplay => write!(f, "KeyboardDisplay"),
            IoCapability::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
        }
    }
}

/// SMP OOB Data Flag
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OobDataFlag {
    /// OOB Authentication data not present
    NotPresent = 0x00,
    /// OOB Authentication data from remote device present
    Present = 0x01,
    /// Unknown
    Unknown(u8),
}

impl From<u8> for OobDataFlag {
    fn from(value: u8) -> Self {
        match value {
            0x00 => OobDataFlag::NotPresent,
            0x01 => OobDataFlag::Present,
            v => OobDataFlag::Unknown(v),
        }
    }
}

impl fmt::Display for OobDataFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OobDataFlag::NotPresent => write!(f, "Not Present"),
            OobDataFlag::Present => write!(f, "Present"),
            OobDataFlag::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
        }
    }
}

/// SMP Authentication Requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthReq(pub u8);

impl AuthReq {
    /// No bonding
    pub const BONDING_NONE: u8 = 0x00;
    /// Bonding
    pub const BONDING: u8 = 0x01;
    /// MITM protection required
    pub const MITM: u8 = 0x04;
    /// Secure Connections
    pub const SC: u8 = 0x08;
    /// Keypress notifications
    pub const KEYPRESS: u8 = 0x10;
    /// CT2 (Cross-Transport Key Derivation)
    pub const CT2: u8 = 0x20;

    /// Check if bonding is requested
    pub fn bonding(&self) -> bool {
        (self.0 & 0x03) == Self::BONDING
    }

    /// Check if MITM protection is requested
    pub fn mitm(&self) -> bool {
        self.0 & Self::MITM != 0
    }

    /// Check if Secure Connections is requested
    pub fn secure_connections(&self) -> bool {
        self.0 & Self::SC != 0
    }

    /// Check if keypress notifications are requested
    pub fn keypress(&self) -> bool {
        self.0 & Self::KEYPRESS != 0
    }

    /// Check if CT2 is requested
    pub fn ct2(&self) -> bool {
        self.0 & Self::CT2 != 0
    }
}

impl fmt::Display for AuthReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();

        if self.bonding() {
            flags.push("Bonding");
        }
        if self.mitm() {
            flags.push("MITM");
        }
        if self.secure_connections() {
            flags.push("SC");
        }
        if self.keypress() {
            flags.push("Keypress");
        }
        if self.ct2() {
            flags.push("CT2");
        }

        if flags.is_empty() {
            write!(f, "None")
        } else {
            write!(f, "{}", flags.join("|"))
        }
    }
}

/// SMP Key Distribution flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyDist(pub u8);

impl KeyDist {
    /// Distribute LTK using Encrypt Info
    pub const ENC_KEY: u8 = 0x01;
    /// Distribute IRK using Identity Info
    pub const ID_KEY: u8 = 0x02;
    /// Distribute CSRK using Signing Info
    pub const SIGN: u8 = 0x04;
    /// Derive Link Key from LTK
    pub const LINK_KEY: u8 = 0x08;

    /// Check if encryption key distribution is requested
    pub fn enc_key(&self) -> bool {
        self.0 & Self::ENC_KEY != 0
    }

    /// Check if identity key distribution is requested
    pub fn id_key(&self) -> bool {
        self.0 & Self::ID_KEY != 0
    }

    /// Check if signing key distribution is requested
    pub fn sign(&self) -> bool {
        self.0 & Self::SIGN != 0
    }

    /// Check if link key derivation is requested
    pub fn link_key(&self) -> bool {
        self.0 & Self::LINK_KEY != 0
    }
}

impl fmt::Display for KeyDist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();

        if self.enc_key() {
            flags.push("LTK");
        }
        if self.id_key() {
            flags.push("IRK");
        }
        if self.sign() {
            flags.push("CSRK");
        }
        if self.link_key() {
            flags.push("LinkKey");
        }

        if flags.is_empty() {
            write!(f, "None")
        } else {
            write!(f, "{}", flags.join("|"))
        }
    }
}

/// SMP Pairing Failed Reason
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PairingFailedReason {
    /// Passkey entry failed
    PasskeyEntryFailed = 0x01,
    /// OOB not available
    OobNotAvailable = 0x02,
    /// Authentication requirements not met
    AuthRequirements = 0x03,
    /// Confirm value failed
    ConfirmFailed = 0x04,
    /// Pairing not supported
    PairingNotSupported = 0x05,
    /// Encryption key size too short
    EncryptionKeySize = 0x06,
    /// Command not supported
    CommandNotSupported = 0x07,
    /// Unspecified reason
    UnspecifiedReason = 0x08,
    /// Repeated attempts
    RepeatedAttempts = 0x09,
    /// Invalid parameters
    InvalidParameters = 0x0a,
    /// DHKey check failed
    DhKeyCheckFailed = 0x0b,
    /// Numeric comparison failed
    NumericComparisonFailed = 0x0c,
    /// BR/EDR pairing in progress
    BrEdrPairingInProgress = 0x0d,
    /// Cross-transport key derivation not allowed
    CrossTransportNotAllowed = 0x0e,
    /// Key rejected
    KeyRejected = 0x0f,
    /// Unknown reason
    Unknown(u8),
}

impl From<u8> for PairingFailedReason {
    fn from(value: u8) -> Self {
        match value {
            0x01 => PairingFailedReason::PasskeyEntryFailed,
            0x02 => PairingFailedReason::OobNotAvailable,
            0x03 => PairingFailedReason::AuthRequirements,
            0x04 => PairingFailedReason::ConfirmFailed,
            0x05 => PairingFailedReason::PairingNotSupported,
            0x06 => PairingFailedReason::EncryptionKeySize,
            0x07 => PairingFailedReason::CommandNotSupported,
            0x08 => PairingFailedReason::UnspecifiedReason,
            0x09 => PairingFailedReason::RepeatedAttempts,
            0x0a => PairingFailedReason::InvalidParameters,
            0x0b => PairingFailedReason::DhKeyCheckFailed,
            0x0c => PairingFailedReason::NumericComparisonFailed,
            0x0d => PairingFailedReason::BrEdrPairingInProgress,
            0x0e => PairingFailedReason::CrossTransportNotAllowed,
            0x0f => PairingFailedReason::KeyRejected,
            v => PairingFailedReason::Unknown(v),
        }
    }
}

impl fmt::Display for PairingFailedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PairingFailedReason::PasskeyEntryFailed => write!(f, "Passkey Entry Failed"),
            PairingFailedReason::OobNotAvailable => write!(f, "OOB Not Available"),
            PairingFailedReason::AuthRequirements => write!(f, "Authentication Requirements"),
            PairingFailedReason::ConfirmFailed => write!(f, "Confirm Value Failed"),
            PairingFailedReason::PairingNotSupported => write!(f, "Pairing Not Supported"),
            PairingFailedReason::EncryptionKeySize => write!(f, "Encryption Key Size"),
            PairingFailedReason::CommandNotSupported => write!(f, "Command Not Supported"),
            PairingFailedReason::UnspecifiedReason => write!(f, "Unspecified Reason"),
            PairingFailedReason::RepeatedAttempts => write!(f, "Repeated Attempts"),
            PairingFailedReason::InvalidParameters => write!(f, "Invalid Parameters"),
            PairingFailedReason::DhKeyCheckFailed => write!(f, "DHKey Check Failed"),
            PairingFailedReason::NumericComparisonFailed => write!(f, "Numeric Comparison Failed"),
            PairingFailedReason::BrEdrPairingInProgress => write!(f, "BR/EDR Pairing In Progress"),
            PairingFailedReason::CrossTransportNotAllowed => {
                write!(f, "Cross-Transport Not Allowed")
            }
            PairingFailedReason::KeyRejected => write!(f, "Key Rejected"),
            PairingFailedReason::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
        }
    }
}

/// Address Type for Identity Address Info
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    /// Public Device Address
    Public = 0x00,
    /// Random Device Address
    Random = 0x01,
    /// Unknown
    Unknown(u8),
}

impl From<u8> for AddressType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => AddressType::Public,
            0x01 => AddressType::Random,
            v => AddressType::Unknown(v),
        }
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressType::Public => write!(f, "Public"),
            AddressType::Random => write!(f, "Random"),
            AddressType::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
        }
    }
}

/// Keypress Notification Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeypressType {
    /// Passkey entry started
    EntryStarted = 0x00,
    /// Passkey digit entered
    DigitEntered = 0x01,
    /// Passkey digit erased
    DigitErased = 0x02,
    /// Passkey cleared
    Cleared = 0x03,
    /// Passkey entry completed
    EntryCompleted = 0x04,
    /// Unknown
    Unknown(u8),
}

impl From<u8> for KeypressType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => KeypressType::EntryStarted,
            0x01 => KeypressType::DigitEntered,
            0x02 => KeypressType::DigitErased,
            0x03 => KeypressType::Cleared,
            0x04 => KeypressType::EntryCompleted,
            v => KeypressType::Unknown(v),
        }
    }
}

impl fmt::Display for KeypressType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeypressType::EntryStarted => write!(f, "Entry Started"),
            KeypressType::DigitEntered => write!(f, "Digit Entered"),
            KeypressType::DigitErased => write!(f, "Digit Erased"),
            KeypressType::Cleared => write!(f, "Cleared"),
            KeypressType::EntryCompleted => write!(f, "Entry Completed"),
            KeypressType::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
        }
    }
}

/// Parsed SMP PDU
#[derive(Debug, Clone)]
pub enum SmpPdu {
    /// Pairing Request
    PairingRequest {
        io_capability: IoCapability,
        oob_data_flag: OobDataFlag,
        auth_req: AuthReq,
        max_key_size: u8,
        initiator_key_dist: KeyDist,
        responder_key_dist: KeyDist,
    },
    /// Pairing Response
    PairingResponse {
        io_capability: IoCapability,
        oob_data_flag: OobDataFlag,
        auth_req: AuthReq,
        max_key_size: u8,
        initiator_key_dist: KeyDist,
        responder_key_dist: KeyDist,
    },
    /// Pairing Confirm (128-bit confirm value)
    PairingConfirm { confirm_value: [u8; 16] },
    /// Pairing Random (128-bit random value)
    PairingRandom { random_value: [u8; 16] },
    /// Pairing Failed
    PairingFailed { reason: PairingFailedReason },
    /// Encryption Information (LTK)
    EncryptionInfo { ltk: [u8; 16] },
    /// Central Identification (EDIV + Rand)
    CentralIdent { ediv: u16, rand: [u8; 8] },
    /// Identity Information (IRK)
    IdentityInfo { irk: [u8; 16] },
    /// Identity Address Information
    IdentityAddrInfo {
        addr_type: AddressType,
        address: [u8; 6],
    },
    /// Signing Information (CSRK)
    SigningInfo { csrk: [u8; 16] },
    /// Security Request
    SecurityRequest { auth_req: AuthReq },
    /// Pairing Public Key (LE Secure Connections)
    PairingPublicKey { x: [u8; 32], y: [u8; 32] },
    /// Pairing DHKey Check
    PairingDhKeyCheck { check: [u8; 16] },
    /// Keypress Notification
    KeypressNotification { notification_type: KeypressType },
    /// Raw/unparsed PDU
    Raw { code: SmpCode, data: Bytes },
}

impl SmpPdu {
    /// Parse SMP PDU from L2CAP payload
    pub fn parse(mut data: Bytes) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let code = SmpCode::from(data.get_u8());

        match code {
            SmpCode::PairingRequest | SmpCode::PairingResponse => {
                if data.remaining() < 6 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let io_capability = IoCapability::from(data.get_u8());
                let oob_data_flag = OobDataFlag::from(data.get_u8());
                let auth_req = AuthReq(data.get_u8());
                let max_key_size = data.get_u8();
                let initiator_key_dist = KeyDist(data.get_u8());
                let responder_key_dist = KeyDist(data.get_u8());

                if code == SmpCode::PairingRequest {
                    Some(SmpPdu::PairingRequest {
                        io_capability,
                        oob_data_flag,
                        auth_req,
                        max_key_size,
                        initiator_key_dist,
                        responder_key_dist,
                    })
                } else {
                    Some(SmpPdu::PairingResponse {
                        io_capability,
                        oob_data_flag,
                        auth_req,
                        max_key_size,
                        initiator_key_dist,
                        responder_key_dist,
                    })
                }
            }
            SmpCode::PairingConfirm => {
                if data.remaining() < 16 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let mut confirm_value = [0u8; 16];
                data.copy_to_slice(&mut confirm_value);
                Some(SmpPdu::PairingConfirm { confirm_value })
            }
            SmpCode::PairingRandom => {
                if data.remaining() < 16 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let mut random_value = [0u8; 16];
                data.copy_to_slice(&mut random_value);
                Some(SmpPdu::PairingRandom { random_value })
            }
            SmpCode::PairingFailed => {
                if data.remaining() < 1 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let reason = PairingFailedReason::from(data.get_u8());
                Some(SmpPdu::PairingFailed { reason })
            }
            SmpCode::EncryptionInfo => {
                if data.remaining() < 16 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let mut ltk = [0u8; 16];
                data.copy_to_slice(&mut ltk);
                Some(SmpPdu::EncryptionInfo { ltk })
            }
            SmpCode::CentralIdent => {
                if data.remaining() < 10 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let ediv = data.get_u16_le();
                let mut rand = [0u8; 8];
                data.copy_to_slice(&mut rand);
                Some(SmpPdu::CentralIdent { ediv, rand })
            }
            SmpCode::IdentityInfo => {
                if data.remaining() < 16 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let mut irk = [0u8; 16];
                data.copy_to_slice(&mut irk);
                Some(SmpPdu::IdentityInfo { irk })
            }
            SmpCode::IdentityAddrInfo => {
                if data.remaining() < 7 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let addr_type = AddressType::from(data.get_u8());
                let mut address = [0u8; 6];
                data.copy_to_slice(&mut address);
                Some(SmpPdu::IdentityAddrInfo { addr_type, address })
            }
            SmpCode::SigningInfo => {
                if data.remaining() < 16 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let mut csrk = [0u8; 16];
                data.copy_to_slice(&mut csrk);
                Some(SmpPdu::SigningInfo { csrk })
            }
            SmpCode::SecurityRequest => {
                if data.remaining() < 1 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let auth_req = AuthReq(data.get_u8());
                Some(SmpPdu::SecurityRequest { auth_req })
            }
            SmpCode::PairingPublicKey => {
                if data.remaining() < 64 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let mut x = [0u8; 32];
                let mut y = [0u8; 32];
                data.copy_to_slice(&mut x);
                data.copy_to_slice(&mut y);
                Some(SmpPdu::PairingPublicKey { x, y })
            }
            SmpCode::PairingDhKeyCheck => {
                if data.remaining() < 16 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let mut check = [0u8; 16];
                data.copy_to_slice(&mut check);
                Some(SmpPdu::PairingDhKeyCheck { check })
            }
            SmpCode::KeypressNotification => {
                if data.remaining() < 1 {
                    return Some(SmpPdu::Raw { code, data });
                }
                let notification_type = KeypressType::from(data.get_u8());
                Some(SmpPdu::KeypressNotification { notification_type })
            }
            _ => Some(SmpPdu::Raw { code, data }),
        }
    }

    /// Get the SMP command code
    pub fn code(&self) -> SmpCode {
        match self {
            SmpPdu::PairingRequest { .. } => SmpCode::PairingRequest,
            SmpPdu::PairingResponse { .. } => SmpCode::PairingResponse,
            SmpPdu::PairingConfirm { .. } => SmpCode::PairingConfirm,
            SmpPdu::PairingRandom { .. } => SmpCode::PairingRandom,
            SmpPdu::PairingFailed { .. } => SmpCode::PairingFailed,
            SmpPdu::EncryptionInfo { .. } => SmpCode::EncryptionInfo,
            SmpPdu::CentralIdent { .. } => SmpCode::CentralIdent,
            SmpPdu::IdentityInfo { .. } => SmpCode::IdentityInfo,
            SmpPdu::IdentityAddrInfo { .. } => SmpCode::IdentityAddrInfo,
            SmpPdu::SigningInfo { .. } => SmpCode::SigningInfo,
            SmpPdu::SecurityRequest { .. } => SmpCode::SecurityRequest,
            SmpPdu::PairingPublicKey { .. } => SmpCode::PairingPublicKey,
            SmpPdu::PairingDhKeyCheck { .. } => SmpCode::PairingDhKeyCheck,
            SmpPdu::KeypressNotification { .. } => SmpCode::KeypressNotification,
            SmpPdu::Raw { code, .. } => *code,
        }
    }
}

impl fmt::Display for SmpPdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmpPdu::PairingRequest {
                io_capability,
                oob_data_flag,
                auth_req,
                max_key_size,
                initiator_key_dist,
                responder_key_dist,
            }
            | SmpPdu::PairingResponse {
                io_capability,
                oob_data_flag,
                auth_req,
                max_key_size,
                initiator_key_dist,
                responder_key_dist,
            } => {
                let name = if matches!(self, SmpPdu::PairingRequest { .. }) {
                    "Pairing Request"
                } else {
                    "Pairing Response"
                };
                write!(
                    f,
                    "{}: IO={}, OOB={}, Auth=[{}], MaxKey={}, Init=[{}], Resp=[{}]",
                    name,
                    io_capability,
                    oob_data_flag,
                    auth_req,
                    max_key_size,
                    initiator_key_dist,
                    responder_key_dist
                )
            }
            SmpPdu::PairingConfirm { confirm_value } => {
                write!(f, "Pairing Confirm: ")?;
                for b in confirm_value {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            SmpPdu::PairingRandom { random_value } => {
                write!(f, "Pairing Random: ")?;
                for b in random_value {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            SmpPdu::PairingFailed { reason } => {
                write!(f, "Pairing Failed: {}", reason)
            }
            SmpPdu::EncryptionInfo { ltk } => {
                write!(f, "Encryption Info (LTK): ")?;
                for b in ltk {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            SmpPdu::CentralIdent { ediv, rand } => {
                write!(f, "Central Ident: EDIV=0x{:04x}, Rand=", ediv)?;
                for b in rand {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            SmpPdu::IdentityInfo { irk } => {
                write!(f, "Identity Info (IRK): ")?;
                for b in irk {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            SmpPdu::IdentityAddrInfo { addr_type, address } => {
                write!(
                    f,
                    "Identity Address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ({})",
                    address[5],
                    address[4],
                    address[3],
                    address[2],
                    address[1],
                    address[0],
                    addr_type
                )
            }
            SmpPdu::SigningInfo { csrk } => {
                write!(f, "Signing Info (CSRK): ")?;
                for b in csrk {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            SmpPdu::SecurityRequest { auth_req } => {
                write!(f, "Security Request: Auth=[{}]", auth_req)
            }
            SmpPdu::PairingPublicKey { .. } => {
                write!(f, "Pairing Public Key (64 bytes)")
            }
            SmpPdu::PairingDhKeyCheck { .. } => {
                write!(f, "Pairing DHKey Check (16 bytes)")
            }
            SmpPdu::KeypressNotification { notification_type } => {
                write!(f, "Keypress Notification: {}", notification_type)
            }
            SmpPdu::Raw { code, data } => {
                write!(f, "{}: {} bytes", code, data.len())
            }
        }
    }
}

/// Format a Bluetooth address from bytes
pub fn format_bd_addr(addr: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smp_code_parsing() {
        assert_eq!(SmpCode::from(0x01), SmpCode::PairingRequest);
        assert_eq!(SmpCode::from(0x05), SmpCode::PairingFailed);
        assert!(matches!(SmpCode::from(0xff), SmpCode::Unknown(0xff)));
    }

    #[test]
    fn test_auth_req() {
        let auth = AuthReq(0x0d); // Bonding | MITM | SC
        assert!(auth.bonding());
        assert!(auth.mitm());
        assert!(auth.secure_connections());
        assert!(!auth.keypress());
    }

    #[test]
    fn test_key_dist() {
        let dist = KeyDist(0x03); // LTK | IRK
        assert!(dist.enc_key());
        assert!(dist.id_key());
        assert!(!dist.sign());
    }

    #[test]
    fn test_pairing_request_parse() {
        // Code=0x01, IO=0x03 (NoInputNoOutput), OOB=0x00, Auth=0x01 (Bonding),
        // MaxKey=16, InitDist=0x01, RespDist=0x01
        let data = Bytes::from_static(&[0x01, 0x03, 0x00, 0x01, 0x10, 0x01, 0x01]);
        let pdu = SmpPdu::parse(data).unwrap();

        if let SmpPdu::PairingRequest {
            io_capability,
            oob_data_flag,
            auth_req,
            max_key_size,
            ..
        } = pdu
        {
            assert_eq!(io_capability, IoCapability::NoInputNoOutput);
            assert_eq!(oob_data_flag, OobDataFlag::NotPresent);
            assert!(auth_req.bonding());
            assert_eq!(max_key_size, 16);
        } else {
            panic!("Expected PairingRequest");
        }
    }

    #[test]
    fn test_pairing_failed_parse() {
        // Code=0x05, Reason=0x04 (Confirm Failed)
        let data = Bytes::from_static(&[0x05, 0x04]);
        let pdu = SmpPdu::parse(data).unwrap();

        if let SmpPdu::PairingFailed { reason } = pdu {
            assert_eq!(reason, PairingFailedReason::ConfirmFailed);
        } else {
            panic!("Expected PairingFailed");
        }
    }
}
