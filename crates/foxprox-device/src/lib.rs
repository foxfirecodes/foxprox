//! Linux fd/device helpers for foxprox harnesses and future broker device integration.

#[cfg(unix)]
pub mod fd {
    use std::io;
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::raw::{c_int, c_void};
    use std::os::unix::net::UnixStream;

    const SOL_SOCKET: c_int = 1;
    const SCM_RIGHTS: c_int = 1;
    const F_GETFD: c_int = 1;
    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0x800;

    #[repr(C)]
    struct Iovec {
        iov_base: *mut c_void,
        iov_len: usize,
    }

    #[repr(C)]
    struct Msghdr {
        msg_name: *mut c_void,
        msg_namelen: u32,
        msg_iov: *mut Iovec,
        msg_iovlen: usize,
        msg_control: *mut c_void,
        msg_controllen: usize,
        msg_flags: c_int,
    }

    #[repr(C)]
    struct Cmsghdr {
        cmsg_len: usize,
        cmsg_level: c_int,
        cmsg_type: c_int,
    }

    extern "C" {
        fn recvmsg(fd: c_int, msg: *mut Msghdr, flags: c_int) -> isize;
        fn sendmsg(fd: c_int, msg: *const Msghdr, flags: c_int) -> isize;
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
        fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
        fn close(fd: c_int) -> c_int;
    }

    pub fn recv_fd(socket_fd: RawFd) -> Result<RawFd, String> {
        let mut byte = [0_u8];
        let mut iov = Iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };
        let mut control = vec![0_u8; cmsg_space(size_of::<RawFd>())];
        let mut msg = Msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr().cast(),
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        let received = unsafe { recvmsg(socket_fd, &mut msg, 0) };
        if received < 0 {
            return Err(format!(
                "failed to receive fd over handoff socket: {}",
                io::Error::last_os_error()
            ));
        }
        if received == 0 {
            return Err("handoff socket closed without fd".to_string());
        }
        let header = control.as_ptr().cast::<Cmsghdr>();
        let valid_header = unsafe {
            (*header).cmsg_len >= cmsg_len(size_of::<RawFd>())
                && (*header).cmsg_level == SOL_SOCKET
                && (*header).cmsg_type == SCM_RIGHTS
        };
        if !valid_header {
            return Err("handoff message did not contain SCM_RIGHTS fd".to_string());
        }
        let data = unsafe {
            control
                .as_ptr()
                .add(cmsg_align(size_of::<Cmsghdr>()))
                .cast::<RawFd>()
        };
        Ok(unsafe { *data })
    }

    pub fn send_fd_to_unix_socket(socket_path: &str, fd_to_send: RawFd) -> Result<(), String> {
        let stream = UnixStream::connect(socket_path)
            .map_err(|err| format!("failed to connect fd handoff socket {socket_path}: {err}"))?;
        let socket_fd = stream.as_raw_fd();
        let mut byte = [b'T'];
        let mut iov = Iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };
        let mut control = vec![0_u8; cmsg_space(size_of::<RawFd>())];
        let header = control.as_mut_ptr().cast::<Cmsghdr>();
        unsafe {
            (*header).cmsg_len = cmsg_len(size_of::<RawFd>());
            (*header).cmsg_level = SOL_SOCKET;
            (*header).cmsg_type = SCM_RIGHTS;
            let data = control
                .as_mut_ptr()
                .add(cmsg_align(size_of::<Cmsghdr>()))
                .cast::<RawFd>();
            *data = fd_to_send;
        }
        let msg = Msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr().cast(),
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        let sent = unsafe { sendmsg(socket_fd, &msg, 0) };
        if sent == 1 {
            Ok(())
        } else if sent < 0 {
            Err(format!(
                "failed to send fd over handoff socket: {}",
                io::Error::last_os_error()
            ))
        } else {
            Err(format!("short fd handoff send: {sent}"))
        }
    }

    pub fn fd_is_valid(fd: RawFd) -> bool {
        unsafe { fcntl(fd, F_GETFD) >= 0 }
    }

    pub fn set_nonblocking(fd: RawFd) -> Result<(), String> {
        let flags = unsafe { fcntl(fd, F_GETFL) };
        if flags < 0 {
            return Err(format!(
                "failed to read fd flags: {}",
                io::Error::last_os_error()
            ));
        }
        let rc = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!(
                "failed to set fd nonblocking: {}",
                io::Error::last_os_error()
            ))
        }
    }

    pub fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        let rc = unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if rc >= 0 {
            Ok(rc as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<(), String> {
        while !buf.is_empty() {
            let rc = unsafe { write(fd, buf.as_ptr().cast(), buf.len()) };
            if rc > 0 {
                buf = &buf[rc as usize..];
            } else if rc == 0 {
                return Err("short write to fd".to_string());
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("failed to write fd: {err}"));
            }
        }
        Ok(())
    }

    pub fn close_fd(fd: RawFd) {
        unsafe {
            close(fd);
        }
    }

    fn cmsg_align(len: usize) -> usize {
        let align = size_of::<usize>();
        (len + align - 1) & !(align - 1)
    }

    fn cmsg_len(payload_len: usize) -> usize {
        cmsg_align(size_of::<Cmsghdr>()) + payload_len
    }

    fn cmsg_space(payload_len: usize) -> usize {
        cmsg_align(size_of::<Cmsghdr>()) + cmsg_align(payload_len)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cmsg_space_includes_aligned_header_and_payload() {
            assert!(cmsg_space(size_of::<RawFd>()) >= cmsg_len(size_of::<RawFd>()));
            assert_eq!(cmsg_align(size_of::<Cmsghdr>()) % size_of::<usize>(), 0);
        }

        #[test]
        fn invalid_fd_is_not_valid() {
            assert!(!fd_is_valid(-1));
        }
    }
}

#[cfg(unix)]
pub mod caps {
    use std::io;
    use std::os::raw::c_int;

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const CAP_NET_ADMIN: usize = 12;

    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    extern "C" {
        fn capget(header: *mut CapUserHeader, data: *mut CapUserData) -> c_int;
        fn capset(header: *mut CapUserHeader, data: *const CapUserData) -> c_int;
    }

    pub fn drop_net_admin_capability() -> Result<(), String> {
        let mut header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        let rc = unsafe { capget(&mut header, data.as_mut_ptr()) };
        if rc != 0 {
            return Err(format!(
                "capget before target exec failed: {}",
                io::Error::last_os_error()
            ));
        }
        let word = CAP_NET_ADMIN / 32;
        let bit = 1_u32 << (CAP_NET_ADMIN % 32);
        data[word].effective &= !bit;
        data[word].permitted &= !bit;
        data[word].inheritable &= !bit;
        let rc = unsafe { capset(&mut header, data.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!(
                "capset dropping CAP_NET_ADMIN before target exec failed: {}",
                io::Error::last_os_error()
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn net_admin_capability_bit_is_in_first_word() {
            assert_eq!(CAP_NET_ADMIN / 32, 0);
            assert_eq!(1_u32 << (CAP_NET_ADMIN % 32), 0x1000);
        }
    }
}
