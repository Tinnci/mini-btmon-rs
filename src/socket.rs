use crate::error::{Error, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::mem;
use std::os::unix::io::AsRawFd;

// Bluetooth socket constants (from linux/bluetooth.h)
const AF_BLUETOOTH: i32 = 31;
const BTPROTO_HCI: i32 = 1;

// HCI socket options (from linux/hci.h)
const HCI_CHANNEL_MONITOR: u16 = 2;
const HCI_DEV_NONE: u16 = 0xffff;

/// Socket address structure for HCI
#[repr(C)]
struct SockAddrHci {
    sa_family: u16,
    hci_dev: u16,
    hci_channel: u16,
}

/// Opens a Bluetooth HCI monitor socket
///
/// This requires CAP_NET_RAW capability. The socket will receive all HCI packets
/// from all Bluetooth controllers on the system.
pub fn open_monitor_socket() -> Result<Socket> {
    // Create RAW Bluetooth socket
    let socket = Socket::new(
        Domain::from(AF_BLUETOOTH),
        Type::from(libc::SOCK_RAW),
        Some(Protocol::from(BTPROTO_HCI)),
    )
    .map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            Error::PermissionDenied
        } else {
            Error::Io(e)
        }
    })?;

    // Construct bind address for monitor channel
    let addr = SockAddrHci {
        sa_family: AF_BLUETOOTH as u16,
        hci_dev: HCI_DEV_NONE,
        hci_channel: HCI_CHANNEL_MONITOR,
    };

    // Bind socket to monitor channel
    unsafe {
        let addr_ptr = &addr as *const _ as *const libc::sockaddr;
        let addr_len = mem::size_of::<SockAddrHci>() as libc::socklen_t;

        let ret = libc::bind(socket.as_raw_fd(), addr_ptr, addr_len);
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return if err.kind() == std::io::ErrorKind::PermissionDenied {
                Err(Error::PermissionDenied)
            } else {
                Err(Error::Io(err))
            };
        }
    }

    // Set non-blocking mode
    socket.set_nonblocking(true)?;

    Ok(socket)
}
