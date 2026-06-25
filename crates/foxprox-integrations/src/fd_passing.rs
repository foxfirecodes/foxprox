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
    let mut control = vec![0_u8; cmsg_space(size_of::<RawFd>())];
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
        if (*header).cmsg_len != cmsg_len(size_of::<RawFd>()) {
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
}
