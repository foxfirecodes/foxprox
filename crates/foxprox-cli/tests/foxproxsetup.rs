use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::Duration;

use foxprox_integrations::receive_fd;

#[test]
#[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
fn foxproxsetup_creates_tun_sends_fd_and_execs_target() {
    let (broker, helper) = UnixStream::pair().unwrap();
    clear_cloexec(helper.as_raw_fd());

    let output_path =
        std::env::temp_dir().join(format!("foxproxsetup-target-{}", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_foxproxsetup"))
        .args([
            "--control-fd",
            &helper.as_raw_fd().to_string(),
            "--tun-name",
            "fp0",
            "--address",
            "10.0.0.1/24",
            "--route",
            "0.0.0.0/0",
            "--mtu",
            "1300",
            "--",
            "sh",
            "-c",
            &format!(
                "ip link show fp0 >/dev/null && echo target-ran > {}",
                output_path.display()
            ),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        std::fs::read_to_string(&output_path).unwrap().trim(),
        "target-ran"
    );
    let _ = std::fs::remove_file(&output_path);

    let received = receive_fd(&broker).unwrap();
    set_nonblocking(received.as_raw_fd());
    let mut file = std::fs::File::from(received);
    let mut packet = [0_u8; 2048];
    let mut ping = Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.0.0.2"])
        .spawn()
        .unwrap();
    let mut observed = false;
    for _ in 0..20 {
        match file.read(&mut packet) {
            Ok(n) if n > 0 => {
                observed = true;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            other => panic!("unexpected tun fd read result: {other:?}"),
        }
    }
    let _ = ping.wait();
    assert!(
        observed,
        "received fd should remain a live TUN fd after helper exits"
    );
}

fn clear_cloexec(fd: i32) {
    // SAFETY: fcntl only reads/modifies flags for the inherited Unix socket fd.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        assert!(flags >= 0);
        assert_eq!(libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC), 0);
    }
}

fn set_nonblocking(fd: i32) {
    // SAFETY: fcntl only reads/modifies flags for the received TUN fd.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
    }
}
