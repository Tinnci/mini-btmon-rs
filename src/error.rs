use std::io;
use thiserror::Error;

/// Result type for mini-btmon operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when using mini-btmon
#[derive(Debug, Error)]
pub enum Error {
    /// IO error occurred
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Insufficient permissions to open HCI monitor socket
    #[error(
        "Permission denied: CAP_NET_RAW capability required. Try: sudo setcap 'cap_net_raw+ep' /path/to/binary"
    )]
    PermissionDenied,

    /// Invalid packet format
    #[error("Invalid packet format: {0}")]
    InvalidPacket(String),

    /// Monitor socket closed
    #[error("Monitor socket closed")]
    SocketClosed,

    /// Other error
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Check if this error is due to insufficient permissions
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Error::PermissionDenied)
    }
}
