//! ATT (Attribute Protocol) parsing
//!
//! ATT defines the protocol for accessing data contained in an Attribute Server.
//! This is the foundation for GATT (Generic Attribute Profile) which defines
//! how attribute data is grouped into services and characteristics.

use bytes::{Buf, Bytes};
use std::fmt;

/// ATT Opcode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttOpcode {
    // Requests
    ErrorResponse = 0x01,
    ExchangeMtuRequest = 0x02,
    ExchangeMtuResponse = 0x03,
    FindInformationRequest = 0x04,
    FindInformationResponse = 0x05,
    FindByTypeValueRequest = 0x06,
    FindByTypeValueResponse = 0x07,
    ReadByTypeRequest = 0x08,
    ReadByTypeResponse = 0x09,
    ReadRequest = 0x0a,
    ReadResponse = 0x0b,
    ReadBlobRequest = 0x0c,
    ReadBlobResponse = 0x0d,
    ReadMultipleRequest = 0x0e,
    ReadMultipleResponse = 0x0f,
    ReadByGroupTypeRequest = 0x10,
    ReadByGroupTypeResponse = 0x11,
    WriteRequest = 0x12,
    WriteResponse = 0x13,
    WriteCommand = 0x52,
    PrepareWriteRequest = 0x16,
    PrepareWriteResponse = 0x17,
    ExecuteWriteRequest = 0x18,
    ExecuteWriteResponse = 0x19,
    ReadMultipleVariableRequest = 0x20,
    ReadMultipleVariableResponse = 0x21,
    MultipleHandleValueNotification = 0x23,
    HandleValueNotification = 0x1b,
    HandleValueIndication = 0x1d,
    HandleValueConfirmation = 0x1e,
    SignedWriteCommand = 0xd2,
    Unknown(u8),
}

impl From<u8> for AttOpcode {
    fn from(value: u8) -> Self {
        match value {
            0x01 => AttOpcode::ErrorResponse,
            0x02 => AttOpcode::ExchangeMtuRequest,
            0x03 => AttOpcode::ExchangeMtuResponse,
            0x04 => AttOpcode::FindInformationRequest,
            0x05 => AttOpcode::FindInformationResponse,
            0x06 => AttOpcode::FindByTypeValueRequest,
            0x07 => AttOpcode::FindByTypeValueResponse,
            0x08 => AttOpcode::ReadByTypeRequest,
            0x09 => AttOpcode::ReadByTypeResponse,
            0x0a => AttOpcode::ReadRequest,
            0x0b => AttOpcode::ReadResponse,
            0x0c => AttOpcode::ReadBlobRequest,
            0x0d => AttOpcode::ReadBlobResponse,
            0x0e => AttOpcode::ReadMultipleRequest,
            0x0f => AttOpcode::ReadMultipleResponse,
            0x10 => AttOpcode::ReadByGroupTypeRequest,
            0x11 => AttOpcode::ReadByGroupTypeResponse,
            0x12 => AttOpcode::WriteRequest,
            0x13 => AttOpcode::WriteResponse,
            0x52 => AttOpcode::WriteCommand,
            0x16 => AttOpcode::PrepareWriteRequest,
            0x17 => AttOpcode::PrepareWriteResponse,
            0x18 => AttOpcode::ExecuteWriteRequest,
            0x19 => AttOpcode::ExecuteWriteResponse,
            0x20 => AttOpcode::ReadMultipleVariableRequest,
            0x21 => AttOpcode::ReadMultipleVariableResponse,
            0x23 => AttOpcode::MultipleHandleValueNotification,
            0x1b => AttOpcode::HandleValueNotification,
            0x1d => AttOpcode::HandleValueIndication,
            0x1e => AttOpcode::HandleValueConfirmation,
            0xd2 => AttOpcode::SignedWriteCommand,
            v => AttOpcode::Unknown(v),
        }
    }
}

impl AttOpcode {
    /// Check if this is a request opcode
    pub fn is_request(&self) -> bool {
        matches!(
            self,
            AttOpcode::ExchangeMtuRequest
                | AttOpcode::FindInformationRequest
                | AttOpcode::FindByTypeValueRequest
                | AttOpcode::ReadByTypeRequest
                | AttOpcode::ReadRequest
                | AttOpcode::ReadBlobRequest
                | AttOpcode::ReadMultipleRequest
                | AttOpcode::ReadByGroupTypeRequest
                | AttOpcode::WriteRequest
                | AttOpcode::PrepareWriteRequest
                | AttOpcode::ExecuteWriteRequest
                | AttOpcode::ReadMultipleVariableRequest
        )
    }

    /// Check if this is a response opcode
    pub fn is_response(&self) -> bool {
        matches!(
            self,
            AttOpcode::ErrorResponse
                | AttOpcode::ExchangeMtuResponse
                | AttOpcode::FindInformationResponse
                | AttOpcode::FindByTypeValueResponse
                | AttOpcode::ReadByTypeResponse
                | AttOpcode::ReadResponse
                | AttOpcode::ReadBlobResponse
                | AttOpcode::ReadMultipleResponse
                | AttOpcode::ReadByGroupTypeResponse
                | AttOpcode::WriteResponse
                | AttOpcode::PrepareWriteResponse
                | AttOpcode::ExecuteWriteResponse
                | AttOpcode::ReadMultipleVariableResponse
        )
    }

    /// Check if this is a command opcode (no response expected)
    pub fn is_command(&self) -> bool {
        matches!(
            self,
            AttOpcode::WriteCommand | AttOpcode::SignedWriteCommand
        )
    }

    /// Check if this is a notification or indication
    pub fn is_notification_or_indication(&self) -> bool {
        matches!(
            self,
            AttOpcode::HandleValueNotification
                | AttOpcode::HandleValueIndication
                | AttOpcode::MultipleHandleValueNotification
        )
    }
}

impl fmt::Display for AttOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttOpcode::ErrorResponse => write!(f, "Error Response"),
            AttOpcode::ExchangeMtuRequest => write!(f, "Exchange MTU Request"),
            AttOpcode::ExchangeMtuResponse => write!(f, "Exchange MTU Response"),
            AttOpcode::FindInformationRequest => write!(f, "Find Information Request"),
            AttOpcode::FindInformationResponse => write!(f, "Find Information Response"),
            AttOpcode::FindByTypeValueRequest => write!(f, "Find By Type Value Request"),
            AttOpcode::FindByTypeValueResponse => write!(f, "Find By Type Value Response"),
            AttOpcode::ReadByTypeRequest => write!(f, "Read By Type Request"),
            AttOpcode::ReadByTypeResponse => write!(f, "Read By Type Response"),
            AttOpcode::ReadRequest => write!(f, "Read Request"),
            AttOpcode::ReadResponse => write!(f, "Read Response"),
            AttOpcode::ReadBlobRequest => write!(f, "Read Blob Request"),
            AttOpcode::ReadBlobResponse => write!(f, "Read Blob Response"),
            AttOpcode::ReadMultipleRequest => write!(f, "Read Multiple Request"),
            AttOpcode::ReadMultipleResponse => write!(f, "Read Multiple Response"),
            AttOpcode::ReadByGroupTypeRequest => write!(f, "Read By Group Type Request"),
            AttOpcode::ReadByGroupTypeResponse => write!(f, "Read By Group Type Response"),
            AttOpcode::WriteRequest => write!(f, "Write Request"),
            AttOpcode::WriteResponse => write!(f, "Write Response"),
            AttOpcode::WriteCommand => write!(f, "Write Command"),
            AttOpcode::PrepareWriteRequest => write!(f, "Prepare Write Request"),
            AttOpcode::PrepareWriteResponse => write!(f, "Prepare Write Response"),
            AttOpcode::ExecuteWriteRequest => write!(f, "Execute Write Request"),
            AttOpcode::ExecuteWriteResponse => write!(f, "Execute Write Response"),
            AttOpcode::ReadMultipleVariableRequest => write!(f, "Read Multiple Variable Request"),
            AttOpcode::ReadMultipleVariableResponse => write!(f, "Read Multiple Variable Response"),
            AttOpcode::MultipleHandleValueNotification => {
                write!(f, "Multiple Handle Value Notification")
            }
            AttOpcode::HandleValueNotification => write!(f, "Handle Value Notification"),
            AttOpcode::HandleValueIndication => write!(f, "Handle Value Indication"),
            AttOpcode::HandleValueConfirmation => write!(f, "Handle Value Confirmation"),
            AttOpcode::SignedWriteCommand => write!(f, "Signed Write Command"),
            AttOpcode::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
        }
    }
}

/// ATT Error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttError {
    InvalidHandle = 0x01,
    ReadNotPermitted = 0x02,
    WriteNotPermitted = 0x03,
    InvalidPdu = 0x04,
    InsufficientAuthentication = 0x05,
    RequestNotSupported = 0x06,
    InvalidOffset = 0x07,
    InsufficientAuthorization = 0x08,
    PrepareQueueFull = 0x09,
    AttributeNotFound = 0x0a,
    AttributeNotLong = 0x0b,
    InsufficientEncryptionKeySize = 0x0c,
    InvalidAttributeValueLength = 0x0d,
    UnlikelyError = 0x0e,
    InsufficientEncryption = 0x0f,
    UnsupportedGroupType = 0x10,
    InsufficientResources = 0x11,
    Unknown(u8),
}

impl From<u8> for AttError {
    fn from(value: u8) -> Self {
        match value {
            0x01 => AttError::InvalidHandle,
            0x02 => AttError::ReadNotPermitted,
            0x03 => AttError::WriteNotPermitted,
            0x04 => AttError::InvalidPdu,
            0x05 => AttError::InsufficientAuthentication,
            0x06 => AttError::RequestNotSupported,
            0x07 => AttError::InvalidOffset,
            0x08 => AttError::InsufficientAuthorization,
            0x09 => AttError::PrepareQueueFull,
            0x0a => AttError::AttributeNotFound,
            0x0b => AttError::AttributeNotLong,
            0x0c => AttError::InsufficientEncryptionKeySize,
            0x0d => AttError::InvalidAttributeValueLength,
            0x0e => AttError::UnlikelyError,
            0x0f => AttError::InsufficientEncryption,
            0x10 => AttError::UnsupportedGroupType,
            0x11 => AttError::InsufficientResources,
            v => AttError::Unknown(v),
        }
    }
}

impl fmt::Display for AttError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttError::InvalidHandle => write!(f, "Invalid Handle"),
            AttError::ReadNotPermitted => write!(f, "Read Not Permitted"),
            AttError::WriteNotPermitted => write!(f, "Write Not Permitted"),
            AttError::InvalidPdu => write!(f, "Invalid PDU"),
            AttError::InsufficientAuthentication => write!(f, "Insufficient Authentication"),
            AttError::RequestNotSupported => write!(f, "Request Not Supported"),
            AttError::InvalidOffset => write!(f, "Invalid Offset"),
            AttError::InsufficientAuthorization => write!(f, "Insufficient Authorization"),
            AttError::PrepareQueueFull => write!(f, "Prepare Queue Full"),
            AttError::AttributeNotFound => write!(f, "Attribute Not Found"),
            AttError::AttributeNotLong => write!(f, "Attribute Not Long"),
            AttError::InsufficientEncryptionKeySize => {
                write!(f, "Insufficient Encryption Key Size")
            }
            AttError::InvalidAttributeValueLength => write!(f, "Invalid Attribute Value Length"),
            AttError::UnlikelyError => write!(f, "Unlikely Error"),
            AttError::InsufficientEncryption => write!(f, "Insufficient Encryption"),
            AttError::UnsupportedGroupType => write!(f, "Unsupported Group Type"),
            AttError::InsufficientResources => write!(f, "Insufficient Resources"),
            AttError::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
        }
    }
}

/// Parsed ATT PDU
#[derive(Debug, Clone)]
pub enum AttPdu {
    /// Error Response
    ErrorResponse {
        request_opcode: AttOpcode,
        handle: u16,
        error: AttError,
    },
    /// Exchange MTU Request
    ExchangeMtuRequest { client_mtu: u16 },
    /// Exchange MTU Response
    ExchangeMtuResponse { server_mtu: u16 },
    /// Find Information Request
    FindInformationRequest { start_handle: u16, end_handle: u16 },
    /// Read By Type Request
    ReadByTypeRequest {
        start_handle: u16,
        end_handle: u16,
        uuid: Bytes,
    },
    /// Read Request
    ReadRequest { handle: u16 },
    /// Read Response
    ReadResponse { value: Bytes },
    /// Read Blob Request
    ReadBlobRequest { handle: u16, offset: u16 },
    /// Read By Group Type Request
    ReadByGroupTypeRequest {
        start_handle: u16,
        end_handle: u16,
        uuid: Bytes,
    },
    /// Write Request
    WriteRequest { handle: u16, value: Bytes },
    /// Write Response
    WriteResponse,
    /// Write Command (no response)
    WriteCommand { handle: u16, value: Bytes },
    /// Handle Value Notification
    HandleValueNotification { handle: u16, value: Bytes },
    /// Handle Value Indication
    HandleValueIndication { handle: u16, value: Bytes },
    /// Handle Value Confirmation
    HandleValueConfirmation,
    /// Raw/unparsed PDU
    Raw { opcode: AttOpcode, data: Bytes },
}

impl AttPdu {
    /// Parse ATT PDU from L2CAP payload
    pub fn parse(mut data: Bytes) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let opcode = AttOpcode::from(data.get_u8());

        match opcode {
            AttOpcode::ErrorResponse => {
                if data.remaining() < 4 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let request_opcode = AttOpcode::from(data.get_u8());
                let handle = data.get_u16_le();
                let error = AttError::from(data.get_u8());
                Some(AttPdu::ErrorResponse {
                    request_opcode,
                    handle,
                    error,
                })
            }
            AttOpcode::ExchangeMtuRequest => {
                if data.remaining() < 2 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let client_mtu = data.get_u16_le();
                Some(AttPdu::ExchangeMtuRequest { client_mtu })
            }
            AttOpcode::ExchangeMtuResponse => {
                if data.remaining() < 2 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let server_mtu = data.get_u16_le();
                Some(AttPdu::ExchangeMtuResponse { server_mtu })
            }
            AttOpcode::FindInformationRequest => {
                if data.remaining() < 4 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let start_handle = data.get_u16_le();
                let end_handle = data.get_u16_le();
                Some(AttPdu::FindInformationRequest {
                    start_handle,
                    end_handle,
                })
            }
            AttOpcode::ReadByTypeRequest => {
                if data.remaining() < 4 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let start_handle = data.get_u16_le();
                let end_handle = data.get_u16_le();
                let uuid = data;
                Some(AttPdu::ReadByTypeRequest {
                    start_handle,
                    end_handle,
                    uuid,
                })
            }
            AttOpcode::ReadRequest => {
                if data.remaining() < 2 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let handle = data.get_u16_le();
                Some(AttPdu::ReadRequest { handle })
            }
            AttOpcode::ReadResponse => Some(AttPdu::ReadResponse { value: data }),
            AttOpcode::ReadBlobRequest => {
                if data.remaining() < 4 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let handle = data.get_u16_le();
                let offset = data.get_u16_le();
                Some(AttPdu::ReadBlobRequest { handle, offset })
            }
            AttOpcode::ReadByGroupTypeRequest => {
                if data.remaining() < 4 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let start_handle = data.get_u16_le();
                let end_handle = data.get_u16_le();
                let uuid = data;
                Some(AttPdu::ReadByGroupTypeRequest {
                    start_handle,
                    end_handle,
                    uuid,
                })
            }
            AttOpcode::WriteRequest => {
                if data.remaining() < 2 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let handle = data.get_u16_le();
                let value = data;
                Some(AttPdu::WriteRequest { handle, value })
            }
            AttOpcode::WriteResponse => Some(AttPdu::WriteResponse),
            AttOpcode::WriteCommand => {
                if data.remaining() < 2 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let handle = data.get_u16_le();
                let value = data;
                Some(AttPdu::WriteCommand { handle, value })
            }
            AttOpcode::HandleValueNotification => {
                if data.remaining() < 2 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let handle = data.get_u16_le();
                let value = data;
                Some(AttPdu::HandleValueNotification { handle, value })
            }
            AttOpcode::HandleValueIndication => {
                if data.remaining() < 2 {
                    return Some(AttPdu::Raw { opcode, data });
                }
                let handle = data.get_u16_le();
                let value = data;
                Some(AttPdu::HandleValueIndication { handle, value })
            }
            AttOpcode::HandleValueConfirmation => Some(AttPdu::HandleValueConfirmation),
            _ => Some(AttPdu::Raw { opcode, data }),
        }
    }

    /// Get the opcode of this PDU
    pub fn opcode(&self) -> AttOpcode {
        match self {
            AttPdu::ErrorResponse { .. } => AttOpcode::ErrorResponse,
            AttPdu::ExchangeMtuRequest { .. } => AttOpcode::ExchangeMtuRequest,
            AttPdu::ExchangeMtuResponse { .. } => AttOpcode::ExchangeMtuResponse,
            AttPdu::FindInformationRequest { .. } => AttOpcode::FindInformationRequest,
            AttPdu::ReadByTypeRequest { .. } => AttOpcode::ReadByTypeRequest,
            AttPdu::ReadRequest { .. } => AttOpcode::ReadRequest,
            AttPdu::ReadResponse { .. } => AttOpcode::ReadResponse,
            AttPdu::ReadBlobRequest { .. } => AttOpcode::ReadBlobRequest,
            AttPdu::ReadByGroupTypeRequest { .. } => AttOpcode::ReadByGroupTypeRequest,
            AttPdu::WriteRequest { .. } => AttOpcode::WriteRequest,
            AttPdu::WriteResponse => AttOpcode::WriteResponse,
            AttPdu::WriteCommand { .. } => AttOpcode::WriteCommand,
            AttPdu::HandleValueNotification { .. } => AttOpcode::HandleValueNotification,
            AttPdu::HandleValueIndication { .. } => AttOpcode::HandleValueIndication,
            AttPdu::HandleValueConfirmation => AttOpcode::HandleValueConfirmation,
            AttPdu::Raw { opcode, .. } => *opcode,
        }
    }
}

impl fmt::Display for AttPdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttPdu::ErrorResponse {
                request_opcode,
                handle,
                error,
            } => {
                write!(
                    f,
                    "Error Response: {} for {} at handle 0x{:04x}",
                    error, request_opcode, handle
                )
            }
            AttPdu::ExchangeMtuRequest { client_mtu } => {
                write!(f, "Exchange MTU Request: client_mtu={}", client_mtu)
            }
            AttPdu::ExchangeMtuResponse { server_mtu } => {
                write!(f, "Exchange MTU Response: server_mtu={}", server_mtu)
            }
            AttPdu::FindInformationRequest {
                start_handle,
                end_handle,
            } => {
                write!(
                    f,
                    "Find Information Request: 0x{:04x}-0x{:04x}",
                    start_handle, end_handle
                )
            }
            AttPdu::ReadByTypeRequest {
                start_handle,
                end_handle,
                uuid,
            } => {
                write!(
                    f,
                    "Read By Type Request: 0x{:04x}-0x{:04x} uuid={:02x?}",
                    start_handle, end_handle, uuid
                )
            }
            AttPdu::ReadRequest { handle } => {
                write!(f, "Read Request: handle=0x{:04x}", handle)
            }
            AttPdu::ReadResponse { value } => {
                write!(f, "Read Response: {} bytes", value.len())
            }
            AttPdu::ReadBlobRequest { handle, offset } => {
                write!(
                    f,
                    "Read Blob Request: handle=0x{:04x} offset={}",
                    handle, offset
                )
            }
            AttPdu::ReadByGroupTypeRequest {
                start_handle,
                end_handle,
                uuid,
            } => {
                write!(
                    f,
                    "Read By Group Type Request: 0x{:04x}-0x{:04x} uuid={:02x?}",
                    start_handle, end_handle, uuid
                )
            }
            AttPdu::WriteRequest { handle, value } => {
                write!(
                    f,
                    "Write Request: handle=0x{:04x} {} bytes",
                    handle,
                    value.len()
                )
            }
            AttPdu::WriteResponse => write!(f, "Write Response"),
            AttPdu::WriteCommand { handle, value } => {
                write!(
                    f,
                    "Write Command: handle=0x{:04x} {} bytes",
                    handle,
                    value.len()
                )
            }
            AttPdu::HandleValueNotification { handle, value } => {
                write!(
                    f,
                    "Handle Value Notification: handle=0x{:04x} {} bytes",
                    handle,
                    value.len()
                )
            }
            AttPdu::HandleValueIndication { handle, value } => {
                write!(
                    f,
                    "Handle Value Indication: handle=0x{:04x} {} bytes",
                    handle,
                    value.len()
                )
            }
            AttPdu::HandleValueConfirmation => write!(f, "Handle Value Confirmation"),
            AttPdu::Raw { opcode, data } => {
                write!(f, "{}: {} bytes", opcode, data.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_parsing() {
        assert_eq!(AttOpcode::from(0x02), AttOpcode::ExchangeMtuRequest);
        assert_eq!(AttOpcode::from(0x12), AttOpcode::WriteRequest);
        assert!(AttOpcode::ExchangeMtuRequest.is_request());
        assert!(!AttOpcode::ExchangeMtuRequest.is_response());
    }

    #[test]
    fn test_mtu_request_parse() {
        // Opcode=0x02, MTU=517 (0x0205)
        let data = Bytes::from_static(&[0x02, 0x05, 0x02]);
        let pdu = AttPdu::parse(data).unwrap();

        if let AttPdu::ExchangeMtuRequest { client_mtu } = pdu {
            assert_eq!(client_mtu, 517);
        } else {
            panic!("Expected ExchangeMtuRequest");
        }
    }

    #[test]
    fn test_write_request_parse() {
        // Opcode=0x12, Handle=0x000f, Value=0x01,0x00
        let data = Bytes::from_static(&[0x12, 0x0f, 0x00, 0x01, 0x00]);
        let pdu = AttPdu::parse(data).unwrap();

        if let AttPdu::WriteRequest { handle, value } = pdu {
            assert_eq!(handle, 0x000f);
            assert_eq!(value.as_ref(), &[0x01, 0x00]);
        } else {
            panic!("Expected WriteRequest");
        }
    }

    #[test]
    fn test_error_response_parse() {
        // Opcode=0x01, RequestOpcode=0x0a (Read), Handle=0x0010, Error=0x0a (Attribute Not Found)
        let data = Bytes::from_static(&[0x01, 0x0a, 0x10, 0x00, 0x0a]);
        let pdu = AttPdu::parse(data).unwrap();

        if let AttPdu::ErrorResponse {
            request_opcode,
            handle,
            error,
        } = pdu
        {
            assert_eq!(request_opcode, AttOpcode::ReadRequest);
            assert_eq!(handle, 0x0010);
            assert_eq!(error, AttError::AttributeNotFound);
        } else {
            panic!("Expected ErrorResponse");
        }
    }
}
