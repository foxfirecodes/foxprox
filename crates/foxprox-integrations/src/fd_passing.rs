use std::io;
use std::mem::{align_of, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

#[derive(Debug)]
pub enum FdPassingError {
    Send(io::Error),
    Receive(io::Error),
    MissingFd,
    WrongControlLength,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: libc::pid_t,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

#[derive(Debug)]
pub enum PeerCredentialError {
    Query(io::Error),
    UnexpectedUid {
        expected: libc::uid_t,
        actual: libc::uid_t,
    },
}

impl PartialEq for PeerCredentialError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Query(_), Self::Query(_)) => true,
            (
                Self::UnexpectedUid {
                    expected: expected_left,
                    actual: actual_left,
                },
                Self::UnexpectedUid {
                    expected: expected_right,
                    actual: actual_right,
                },
            ) => expected_left == expected_right && actual_left == actual_right,
            _ => false,
        }
    }
}

impl Eq for PeerCredentialError {}

impl PartialEq for FdPassingError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Send(_), Self::Send(_))
                | (Self::Receive(_), Self::Receive(_))
                | (Self::MissingFd, Self::MissingFd)
                | (Self::WrongControlLength, Self::WrongControlLength)
        )
    }
}

impl Eq for FdPassingError {}

pub fn peer_credentials(socket: &UnixStream) -> Result<PeerCredentials, PeerCredentialError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` and `len` point to valid writable storage for
    // SO_PEERCRED, and `socket` is an open Unix domain socket.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(PeerCredentialError::Query(io::Error::last_os_error()));
    }
    if len != size_of::<libc::ucred>() as libc::socklen_t {
        return Err(PeerCredentialError::Query(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SO_PEERCRED length",
        )));
    }
    Ok(PeerCredentials {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

pub fn validate_peer_uid(
    socket: &UnixStream,
    expected_uid: libc::uid_t,
) -> Result<PeerCredentials, PeerCredentialError> {
    let credentials = peer_credentials(socket)?;
    if credentials.uid == expected_uid {
        Ok(credentials)
    } else {
        Err(PeerCredentialError::UnexpectedUid {
            expected: expected_uid,
            actual: credentials.uid,
        })
    }
}

pub fn send_fd(socket: &UnixStream, fd: RawFd) -> Result<(), FdPassingError> {
    let byte = [0_u8; 1];
    let iov = libc::iovec {
        iov_base: byte.as_ptr().cast_mut().cast(),
        iov_len: byte.len(),
    };
    let mut control = vec![0_u8; cmsg_space(size_of::<RawFd>())];
    // SAFETY: `control` is sized with CMSG_SPACE for one RawFd, and cmsghdr
    // fields are initialized before sendmsg reads them.
    unsafe {
        let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = cmsg_len(size_of::<RawFd>());
        let data = cmsg_data(header).cast::<RawFd>();
        *data = fd;
    }
    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: (&iov as *const libc::iovec).cast_mut(),
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: control.len(),
        msg_flags: 0,
    };
    // SAFETY: `msg` references valid iovec/control buffers for this call and
    // `socket` is an open Unix domain socket.
    let rc = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, 0) };
    if rc < 0 {
        Err(FdPassingError::Send(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

pub fn receive_fd(socket: &UnixStream) -> Result<OwnedFd, FdPassingError> {
    let mut byte = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut control = vec![0_u8; cmsg_space(2 * size_of::<RawFd>())];
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: (&mut iov as *mut libc::iovec).cast(),
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: control.len(),
        msg_flags: 0,
    };

    // SAFETY: `msg` references valid mutable iovec/control buffers and `socket`
    // is an open Unix domain socket. recvmsg initializes the buffers on return.
    let rc = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    if rc < 0 {
        return Err(FdPassingError::Receive(io::Error::last_os_error()));
    }
    if msg.msg_controllen < cmsg_len(size_of::<RawFd>()) {
        return Err(FdPassingError::MissingFd);
    }

    // SAFETY: recvmsg reported enough control bytes for one cmsghdr. We validate
    // level/type/length before reading the RawFd payload.
    unsafe {
        let header = msg.msg_control.cast::<libc::cmsghdr>();
        if (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS {
            return Err(FdPassingError::MissingFd);
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            close_control_fds(header);
            return Err(FdPassingError::WrongControlLength);
        }
        if (*header).cmsg_len != cmsg_len(size_of::<RawFd>()) {
            close_control_fds(header);
            return Err(FdPassingError::WrongControlLength);
        }
        let fd = *cmsg_data(header).cast::<RawFd>();
        if fd < 0 {
            return Err(FdPassingError::MissingFd);
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

fn cmsg_align(len: usize) -> usize {
    (len + align_of::<libc::cmsghdr>() - 1) & !(align_of::<libc::cmsghdr>() - 1)
}

fn cmsg_space(len: usize) -> usize {
    cmsg_align(size_of::<libc::cmsghdr>()) + cmsg_align(len)
}

fn cmsg_len(len: usize) -> usize {
    cmsg_align(size_of::<libc::cmsghdr>()) + len
}

unsafe fn close_control_fds(header: *mut libc::cmsghdr) {
    let payload_len = (*header).cmsg_len.saturating_sub(cmsg_len(0));
    let fd_count = payload_len / size_of::<RawFd>();
    let data = cmsg_data(header).cast::<RawFd>();
    for index in 0..fd_count {
        let fd = *data.add(index);
        if fd >= 0 {
            let _ = libc::close(fd);
        }
    }
}

unsafe fn cmsg_data(header: *mut libc::cmsghdr) -> *mut u8 {
    // SAFETY: caller ensures `header` points to a valid cmsghdr in a buffer at
    // least CMSG_LEN(payload) bytes long. Data starts after aligned cmsghdr.
    unsafe {
        header
            .cast::<u8>()
            .add(cmsg_align(size_of::<libc::cmsghdr>()))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::mem::size_of;
    use std::os::fd::AsRawFd;

    use super::*;

    #[test]
    fn sends_exactly_one_fd_over_unix_socket() {
        let (left, right) = UnixStream::pair().unwrap();
        let (pipe_read, pipe_write) = UnixStream::pair().unwrap();

        send_fd(&left, pipe_write.as_raw_fd()).unwrap();
        drop(pipe_write);
        let received = receive_fd(&right).unwrap();

        let mut received_file = std::fs::File::from(received);
        let mut writer = pipe_read.try_clone().unwrap();
        writer.write_all(b"fd-ok").unwrap();
        let mut buffer = [0_u8; 5];
        received_file.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"fd-ok");
    }

    #[test]
    fn receiving_without_fd_fails_closed() {
        let (mut left, right) = UnixStream::pair().unwrap();
        left.write_all(b"x").unwrap();

        assert!(matches!(receive_fd(&right), Err(FdPassingError::MissingFd)));
    }

    #[test]
    fn receiving_multiple_fds_fails_closed() {
        let (left, right) = UnixStream::pair().unwrap();
        let (fd_a, fd_b) = UnixStream::pair().unwrap();
        send_two_fds(&left, fd_a.as_raw_fd(), fd_b.as_raw_fd()).unwrap();

        assert_eq!(
            receive_fd(&right).unwrap_err(),
            FdPassingError::WrongControlLength
        );
    }

    #[test]
    fn peer_credentials_validate_expected_uid() {
        let (left, _) = UnixStream::pair().unwrap();
        // SAFETY: geteuid has no preconditions and does not mutate Rust-owned memory.
        let uid = unsafe { libc::geteuid() };

        let credentials = validate_peer_uid(&left, uid).unwrap();
        assert_eq!(credentials.uid, uid);
        assert!(credentials.pid > 0);
    }

    #[test]
    fn peer_credentials_reject_unexpected_uid() {
        let (left, _) = UnixStream::pair().unwrap();
        // SAFETY: geteuid has no preconditions and does not mutate Rust-owned memory.
        let uid = unsafe { libc::geteuid() };
        let unexpected = if uid == libc::uid_t::MAX {
            uid - 1
        } else {
            uid + 1
        };

        assert_eq!(
            validate_peer_uid(&left, unexpected).unwrap_err(),
            PeerCredentialError::UnexpectedUid {
                expected: unexpected,
                actual: uid,
            }
        );
    }

    fn send_two_fds(socket: &UnixStream, fd_a: RawFd, fd_b: RawFd) -> io::Result<()> {
        let byte = [0_u8; 1];
        let iov = libc::iovec {
            iov_base: byte.as_ptr().cast_mut().cast(),
            iov_len: byte.len(),
        };
        let mut control = vec![0_u8; cmsg_space(2 * size_of::<RawFd>())];
        // SAFETY: `control` is sized for two RawFd payloads and all cmsghdr
        // fields are initialized before sendmsg reads the control message.
        unsafe {
            let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = cmsg_len(2 * size_of::<RawFd>());
            let data = cmsg_data(header).cast::<RawFd>();
            *data = fd_a;
            *data.add(1) = fd_b;
        }
        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: (&iov as *const libc::iovec).cast_mut(),
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr().cast(),
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        // SAFETY: `msg` points at valid iovec/control buffers for this call.
        let rc = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, 0) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
