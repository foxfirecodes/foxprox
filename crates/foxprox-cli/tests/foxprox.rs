use std::io::{Read as _, Write as _};
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::process::Command;

use foxprox_core::{build_dns_address_response, parse_dns_query, DnsQueryType};

#[test]
#[ignore = "requires bwrap with user/network namespace and /dev/net/tun access"]
fn foxprox_launches_bwrap_and_bridges_allowed_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let host_addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 1024];
        let n = stream.read(&mut buffer).unwrap();
        assert!(String::from_utf8_lossy(&buffer[..n]).contains("GET /"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\nalpha-ok")
            .unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_foxprox"))
        .args([
            "--setup-helper",
            env!("CARGO_BIN_EXE_foxproxsetup"),
            "--tcp-map",
            &format!("10.0.0.2:8080={host_addr}"),
            "--max-runtime-ms",
            "5000",
            "--",
            "sh",
            "-c",
            "curl --max-time 3 -s http://10.0.0.2:8080/",
        ])
        .output()
        .unwrap();
    server.join().unwrap();

    assert!(
        output.status.success(),
        "foxprox failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alpha-ok"), "stdout was {stdout}");
    assert!(
        stdout.contains("\"kind\":\"tcp_connect\""),
        "stdout was {stdout}"
    );
    assert!(
        stdout.contains("\"decision\":\"allow\""),
        "stdout was {stdout}"
    );
}

#[test]
#[ignore = "requires bwrap with user/network namespace and /dev/net/tun access"]
fn foxprox_launches_bwrap_and_default_denies_dns() {
    let output = Command::new(env!("CARGO_BIN_EXE_foxprox"))
        .args([
            "--setup-helper",
            env!("CARGO_BIN_EXE_foxproxsetup"),
            "--max-runtime-ms",
            "5000",
            "--",
            "python3",
            "-c",
            "import socket; socket.gethostbyname('blocked.example')",
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "blocked DNS unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"kind\":\"dns_query\""),
        "stdout was {stdout}"
    );
    assert!(
        stdout.contains("\"decision\":\"deny\""),
        "stdout was {stdout}"
    );
    assert!(
        stdout.contains("\"reason\":\"default_deny\""),
        "stdout was {stdout}"
    );
}

#[test]
#[ignore = "requires bwrap with user/network namespace and /dev/net/tun access"]
fn foxprox_launches_bwrap_and_forwards_allowed_dns() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut buffer = [0_u8; 512];
        let (n, peer) = upstream.recv_from(&mut buffer).unwrap();
        let query = parse_dns_query(&buffer[..n], 512).unwrap();
        let addresses = match query.query_type {
            DnsQueryType::A => vec!["198.51.100.77".parse::<IpAddr>().unwrap()],
            DnsQueryType::Aaaa => vec!["2001:db8::77".parse::<IpAddr>().unwrap()],
            _ => Vec::new(),
        };
        let response = build_dns_address_response(&query, addresses, 30, 512, 4).unwrap();
        upstream.send_to(&response, peer).unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_foxprox"))
        .args([
            "--setup-helper",
            env!("CARGO_BIN_EXE_foxproxsetup"),
            "--allow-domain",
            "allowed.example:53",
            "--dns-upstream",
            &upstream_addr.to_string(),
            "--max-runtime-ms",
            "5000",
            "--",
            "python3",
            "-c",
            "import socket; print(socket.gethostbyname('allowed.example'))",
        ])
        .output()
        .unwrap();
    server.join().unwrap();

    assert!(
        output.status.success(),
        "foxprox DNS failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("198.51.100.77"), "stdout was {stdout}");
    assert!(
        stdout.contains("\"kind\":\"dns_query\""),
        "stdout was {stdout}"
    );
    assert!(
        stdout.contains("\"kind\":\"dns_response\""),
        "stdout was {stdout}"
    );
    assert!(
        stdout.contains("\"decision\":\"allow\""),
        "stdout was {stdout}"
    );
}
