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

    #[derive(Debug)]
    pub struct DeviceFd {
        fd: RawFd,
    }

    pub trait PacketDevice {
        fn set_nonblocking(&self) -> Result<(), String>;
        fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize>;
        fn write_packet(&self, packet: &[u8]) -> Result<(), String>;
    }

    impl DeviceFd {
        pub fn new(fd: RawFd) -> Result<Self, String> {
            if fd_is_valid(fd) {
                Ok(Self { fd })
            } else {
                Err(format!("invalid device fd: {fd}"))
            }
        }

        pub fn raw_fd(&self) -> RawFd {
            self.fd
        }

        pub fn is_valid(&self) -> bool {
            fd_is_valid(self.fd)
        }

        pub fn set_nonblocking(&self) -> Result<(), String> {
            set_nonblocking(self.fd)
        }

        pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
            read_fd(self.fd, buf)
        }

        pub fn write_packet(&self, packet: &[u8]) -> Result<(), String> {
            write_all_fd(self.fd, packet)
        }

        pub fn close(self) {
            drop(self);
        }
    }

    impl PacketDevice for DeviceFd {
        fn set_nonblocking(&self) -> Result<(), String> {
            DeviceFd::set_nonblocking(self)
        }

        fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
            DeviceFd::read_packet(self, buf)
        }

        fn write_packet(&self, packet: &[u8]) -> Result<(), String> {
            DeviceFd::write_packet(self, packet)
        }
    }

    impl Drop for DeviceFd {
        fn drop(&mut self) {
            if self.fd >= 0 {
                close_fd(self.fd);
                self.fd = -1;
            }
        }
    }

    pub fn recv_device_fd(socket_fd: RawFd) -> Result<DeviceFd, String> {
        recv_fd(socket_fd).and_then(DeviceFd::new)
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

        #[test]
        fn device_fd_rejects_invalid_raw_fd() {
            assert!(DeviceFd::new(-1).is_err());
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

#[cfg(unix)]
pub mod linux_tun {
    use std::net::IpAddr;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TunConfig {
        pub tun_name: String,
        pub sandbox_ip: IpAddr,
        pub prefix_len: u8,
        pub mtu: u16,
        pub install_default_route: bool,
    }

    #[derive(Debug)]
    pub struct ConfiguredTun {
        raw_fd: i32,
    }

    impl ConfiguredTun {
        pub fn raw_fd(&self) -> i32 {
            self.raw_fd
        }
    }

    impl Drop for ConfiguredTun {
        fn drop(&mut self) {
            close_fd(self.raw_fd);
        }
    }

    use std::fs::OpenOptions;
    use std::io;
    use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
    use std::os::raw::{c_char, c_int, c_short, c_ulong, c_void};

    const IFNAMSIZ: usize = 16;
    const AF_INET: c_int = 2;
    const SOCK_DGRAM: c_int = 2;

    const IFF_TUN: c_short = 0x0001;
    const IFF_NO_PI: c_short = 0x1000;
    const IFF_UP: c_short = 0x0001;
    const IFF_RUNNING: c_short = 0x0040;

    const TUNSETIFF: c_ulong = 0x4004_54ca;
    const SIOCGIFFLAGS: c_ulong = 0x8913;
    const SIOCSIFFLAGS: c_ulong = 0x8914;
    const SIOCSIFADDR: c_ulong = 0x8916;
    const SIOCSIFNETMASK: c_ulong = 0x891c;
    const SIOCSIFMTU: c_ulong = 0x8922;
    const SIOCADDRT: c_ulong = 0x890b;

    const RTF_UP: u16 = 0x0001;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockAddr {
        sa_family: u16,
        sa_data: [u8; 14],
    }

    #[repr(C)]
    union IfReqData {
        addr: SockAddr,
        flags: c_short,
        mtu: c_int,
    }

    #[repr(C)]
    struct IfReq {
        name: [c_char; IFNAMSIZ],
        data: IfReqData,
    }

    #[repr(C)]
    struct RtEntry {
        rt_pad1: c_ulong,
        rt_dst: SockAddr,
        rt_gateway: SockAddr,
        rt_genmask: SockAddr,
        rt_flags: u16,
        rt_pad2: c_short,
        rt_pad3: c_ulong,
        rt_pad4: *mut c_void,
        rt_metric: c_short,
        rt_dev: *mut c_char,
        rt_mtu: c_ulong,
        rt_window: c_ulong,
        rt_irtt: u16,
    }

    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    }

    pub fn configure_tun(config: &TunConfig) -> Result<ConfiguredTun, String> {
        let tun_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|err| format!("failed to open /dev/net/tun: {err}"))?;
        let tun_fd = tun_file.as_raw_fd();
        create_tun(tun_fd, &config.tun_name)?;
        let ctl_fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        if ctl_fd < 0 {
            return Err(format!(
                "failed to open AF_INET control socket: {}",
                io::Error::last_os_error()
            ));
        }
        let control = FdGuard(ctl_fd);
        set_addr(control.0, &config.tun_name, config.sandbox_ip)?;
        set_netmask(control.0, &config.tun_name, config.prefix_len)?;
        set_mtu(control.0, &config.tun_name, config.mtu)?;
        set_up(control.0, &config.tun_name)?;
        if config.install_default_route {
            add_default_route(control.0, &config.tun_name)?;
        }
        Ok(ConfiguredTun {
            raw_fd: tun_file.into_raw_fd(),
        })
    }

    pub fn close_fd(fd: RawFd) {
        crate::fd::close_fd(fd);
    }

    struct FdGuard(RawFd);

    impl Drop for FdGuard {
        fn drop(&mut self) {
            close_fd(self.0);
        }
    }

    fn create_tun(fd: RawFd, name: &str) -> Result<(), String> {
        let mut ifr = ifreq_flags(name, IFF_TUN | IFF_NO_PI)?;
        ioctl_check(fd, TUNSETIFF, &mut ifr, "TUNSETIFF")
    }

    fn set_addr(fd: RawFd, name: &str, ip: IpAddr) -> Result<(), String> {
        let mut ifr = ifreq_addr(name, ip)?;
        ioctl_check(fd, SIOCSIFADDR, &mut ifr, "SIOCSIFADDR")
    }

    fn set_netmask(fd: RawFd, name: &str, prefix_len: u8) -> Result<(), String> {
        if prefix_len > 32 {
            return Err(
                "only IPv4 prefix lengths up to /32 are supported for alpha TUN setup".to_string(),
            );
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX.checked_shl((32 - prefix_len) as u32).unwrap_or(0)
        };
        let mut ifr = ifreq_addr(name, IpAddr::from(mask.to_be_bytes()))?;
        ioctl_check(fd, SIOCSIFNETMASK, &mut ifr, "SIOCSIFNETMASK")
    }

    fn set_mtu(fd: RawFd, name: &str, mtu: u16) -> Result<(), String> {
        let mut ifr = ifreq_mtu(name, i32::from(mtu))?;
        ioctl_check(fd, SIOCSIFMTU, &mut ifr, "SIOCSIFMTU")
    }

    fn set_up(fd: RawFd, name: &str) -> Result<(), String> {
        let mut ifr = ifreq_flags(name, 0)?;
        ioctl_check(fd, SIOCGIFFLAGS, &mut ifr, "SIOCGIFFLAGS")?;
        let current = unsafe { ifr.data.flags };
        ifr.data.flags = current | IFF_UP | IFF_RUNNING;
        ioctl_check(fd, SIOCSIFFLAGS, &mut ifr, "SIOCSIFFLAGS")
    }

    fn add_default_route(fd: RawFd, name: &str) -> Result<(), String> {
        let mut name = interface_name(name)?;
        let mut route = RtEntry {
            rt_pad1: 0,
            rt_dst: sockaddr_v4([0, 0, 0, 0]),
            rt_gateway: sockaddr_v4([0, 0, 0, 0]),
            rt_genmask: sockaddr_v4([0, 0, 0, 0]),
            rt_flags: RTF_UP,
            rt_pad2: 0,
            rt_pad3: 0,
            rt_pad4: std::ptr::null_mut(),
            rt_metric: 0,
            rt_dev: name.as_mut_ptr(),
            rt_mtu: 0,
            rt_window: 0,
            rt_irtt: 0,
        };
        let rc = unsafe { ioctl(fd, SIOCADDRT, &mut route) };
        if rc == 0 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(17) {
                Ok(())
            } else {
                Err(format!("SIOCADDRT default dev route failed: {err}"))
            }
        }
    }

    fn ioctl_check(
        fd: RawFd,
        request: c_ulong,
        ifr: &mut IfReq,
        label: &str,
    ) -> Result<(), String> {
        let rc = unsafe { ioctl(fd, request, ifr) };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!("{label} failed: {}", io::Error::last_os_error()))
        }
    }

    fn ifreq_flags(name: &str, flags: c_short) -> Result<IfReq, String> {
        let mut ifr = ifreq_empty(name)?;
        ifr.data.flags = flags;
        Ok(ifr)
    }

    fn ifreq_addr(name: &str, ip: IpAddr) -> Result<IfReq, String> {
        let mut ifr = ifreq_empty(name)?;
        let IpAddr::V4(ip) = ip else {
            return Err("alpha TUN setup currently supports IPv4 addresses only".to_string());
        };
        ifr.data.addr = sockaddr_v4(ip.octets());
        Ok(ifr)
    }

    fn ifreq_mtu(name: &str, mtu: c_int) -> Result<IfReq, String> {
        let mut ifr = ifreq_empty(name)?;
        ifr.data.mtu = mtu;
        Ok(ifr)
    }

    fn ifreq_empty(name: &str) -> Result<IfReq, String> {
        Ok(IfReq {
            name: interface_name(name)?,
            data: IfReqData { flags: 0 },
        })
    }

    fn interface_name(name: &str) -> Result<[c_char; IFNAMSIZ], String> {
        let bytes = name.as_bytes();
        if bytes.is_empty() {
            return Err("TUN interface name must not be empty".to_string());
        }
        if bytes.len() >= IFNAMSIZ {
            return Err(format!("TUN interface name '{name}' is too long"));
        }
        let mut out = [0 as c_char; IFNAMSIZ];
        for (idx, byte) in bytes.iter().enumerate() {
            out[idx] = *byte as c_char;
        }
        Ok(out)
    }

    fn sockaddr_v4(octets: [u8; 4]) -> SockAddr {
        let mut sa_data = [0_u8; 14];
        sa_data[2..6].copy_from_slice(&octets);
        SockAddr {
            sa_family: AF_INET as u16,
            sa_data,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_overlong_interface_names() {
            assert!(interface_name("123456789012345").is_ok());
            assert!(interface_name("1234567890123456").is_err());
        }

        #[test]
        fn sockaddr_v4_places_ipv4_octets_after_port() {
            let addr = sockaddr_v4([10, 0, 2, 2]);
            assert_eq!(addr.sa_family, AF_INET as u16);
            assert_eq!(&addr.sa_data[2..6], &[10, 0, 2, 2]);
        }
    }
}

#[cfg(not(unix))]
pub mod linux_tun {
    use std::net::IpAddr;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TunConfig {
        pub tun_name: String,
        pub sandbox_ip: IpAddr,
        pub prefix_len: u8,
        pub mtu: u16,
        pub install_default_route: bool,
    }

    #[derive(Debug)]
    pub struct ConfiguredTun;

    impl ConfiguredTun {
        pub fn raw_fd(&self) -> i32 {
            -1
        }
    }

    pub fn configure_tun(_config: &TunConfig) -> Result<ConfiguredTun, String> {
        Err("direct TUN configuration is only supported on Unix/Linux".to_string())
    }
}
