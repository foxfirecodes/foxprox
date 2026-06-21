use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::attribution::{HostAttribution, Hostname};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5Greeting {
    pub selected_method: Socks5AuthMethod,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Socks5AuthMethod {
    NoAuthentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5ConnectMetadata {
    pub destination: Socks5Destination,
    pub port: u16,
    pub attribution: HostAttribution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Socks5Destination {
    Hostname(Hostname),
    Ip(IpAddr),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Socks5ParseError {
    MessageTooLarge,
    Incomplete,
    InvalidVersion,
    UnsupportedAuthMethod,
    UnsupportedCommand,
    InvalidReservedByte,
    UnsupportedAddressType,
    InvalidDomainLength,
    InvalidHost,
    InvalidPort,
    TrailingBytes,
}

pub fn parse_socks5_greeting(
    bytes: &[u8],
    max_message_bytes: usize,
) -> Result<Socks5Greeting, Socks5ParseError> {
    if bytes.len() > max_message_bytes {
        return Err(Socks5ParseError::MessageTooLarge);
    }
    if bytes.len() < 2 {
        return Err(Socks5ParseError::Incomplete);
    }
    if bytes[0] != 0x05 {
        return Err(Socks5ParseError::InvalidVersion);
    }

    let method_count = usize::from(bytes[1]);
    let expected_len = 2 + method_count;
    if bytes.len() < expected_len {
        return Err(Socks5ParseError::Incomplete);
    }
    if bytes.len() != expected_len {
        return Err(Socks5ParseError::TrailingBytes);
    }
    if method_count == 0 || !bytes[2..].contains(&0x00) {
        return Err(Socks5ParseError::UnsupportedAuthMethod);
    }

    Ok(Socks5Greeting {
        selected_method: Socks5AuthMethod::NoAuthentication,
    })
}

pub fn parse_socks5_connect_request(
    bytes: &[u8],
    max_message_bytes: usize,
) -> Result<Socks5ConnectMetadata, Socks5ParseError> {
    if bytes.len() > max_message_bytes {
        return Err(Socks5ParseError::MessageTooLarge);
    }
    if bytes.len() < 4 {
        return Err(Socks5ParseError::Incomplete);
    }
    if bytes[0] != 0x05 {
        return Err(Socks5ParseError::InvalidVersion);
    }
    if bytes[1] != 0x01 {
        return Err(Socks5ParseError::UnsupportedCommand);
    }
    if bytes[2] != 0x00 {
        return Err(Socks5ParseError::InvalidReservedByte);
    }

    let (destination, port_offset) = match bytes[3] {
        0x01 => parse_ipv4_destination(bytes)?,
        0x03 => parse_domain_destination(bytes)?,
        0x04 => parse_ipv6_destination(bytes)?,
        _ => return Err(Socks5ParseError::UnsupportedAddressType),
    };

    let port_end = port_offset + 2;
    if bytes.len() < port_end {
        return Err(Socks5ParseError::Incomplete);
    }
    if bytes.len() != port_end {
        return Err(Socks5ParseError::TrailingBytes);
    }

    let port = u16::from_be_bytes([bytes[port_offset], bytes[port_offset + 1]]);
    if port == 0 {
        return Err(Socks5ParseError::InvalidPort);
    }

    let attribution = match &destination {
        Socks5Destination::Hostname(hostname) => HostAttribution::explicit_proxy(hostname.clone()),
        Socks5Destination::Ip(_) => HostAttribution::ip_only(),
    };

    Ok(Socks5ConnectMetadata {
        destination,
        port,
        attribution,
    })
}

fn parse_ipv4_destination(bytes: &[u8]) -> Result<(Socks5Destination, usize), Socks5ParseError> {
    if bytes.len() < 8 {
        return Err(Socks5ParseError::Incomplete);
    }
    let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    Ok((Socks5Destination::Ip(IpAddr::V4(ip)), 8))
}

fn parse_ipv6_destination(bytes: &[u8]) -> Result<(Socks5Destination, usize), Socks5ParseError> {
    if bytes.len() < 20 {
        return Err(Socks5ParseError::Incomplete);
    }
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&bytes[4..20]);
    Ok((
        Socks5Destination::Ip(IpAddr::V6(Ipv6Addr::from(octets))),
        20,
    ))
}

fn parse_domain_destination(bytes: &[u8]) -> Result<(Socks5Destination, usize), Socks5ParseError> {
    if bytes.len() < 5 {
        return Err(Socks5ParseError::Incomplete);
    }
    let domain_len = usize::from(bytes[4]);
    if domain_len == 0 {
        return Err(Socks5ParseError::InvalidDomainLength);
    }
    let domain_start = 5;
    let domain_end = domain_start + domain_len;
    if bytes.len() < domain_end {
        return Err(Socks5ParseError::Incomplete);
    }
    let domain = std::str::from_utf8(&bytes[domain_start..domain_end])
        .map_err(|_| Socks5ParseError::InvalidHost)?;
    if !domain.is_ascii() {
        return Err(Socks5ParseError::InvalidHost);
    }
    let hostname = Hostname::parse(domain).map_err(|_| Socks5ParseError::InvalidHost)?;
    Ok((Socks5Destination::Hostname(hostname), domain_end))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::types::{HostnameConfidence, HostnameSource};

    use super::*;

    #[test]
    fn selects_no_auth_method_from_valid_greeting() {
        let parsed = parse_socks5_greeting(&[0x05, 0x02, 0x02, 0x00], 16).unwrap();
        assert_eq!(parsed.selected_method, Socks5AuthMethod::NoAuthentication);
    }

    #[test]
    fn rejects_greeting_without_supported_auth_or_with_malformed_lengths() {
        assert_eq!(
            parse_socks5_greeting(&[0x04, 0x01, 0x00], 16),
            Err(Socks5ParseError::InvalidVersion)
        );
        assert_eq!(
            parse_socks5_greeting(&[0x05, 0x01, 0x02], 16),
            Err(Socks5ParseError::UnsupportedAuthMethod)
        );
        assert_eq!(
            parse_socks5_greeting(&[0x05, 0x02, 0x00], 16),
            Err(Socks5ParseError::Incomplete)
        );
        assert_eq!(
            parse_socks5_greeting(&[0x05, 0x01, 0x00, 0x01], 16),
            Err(Socks5ParseError::TrailingBytes)
        );
        assert_eq!(
            parse_socks5_greeting(&[0x05, 0x01, 0x00], 2),
            Err(Socks5ParseError::MessageTooLarge)
        );
    }

    #[test]
    fn parses_domain_connect_with_explicit_proxy_attribution() {
        let parsed = parse_socks5_connect_request(
            &[
                0x05, 0x01, 0x00, 0x03, 11, b'E', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'C',
                b'O', b'M', 0x01, 0xbb,
            ],
            64,
        )
        .unwrap();

        let Socks5Destination::Hostname(hostname) = parsed.destination else {
            panic!("expected hostname destination");
        };
        assert_eq!(hostname.as_str(), "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.attribution.source, HostnameSource::ExplicitProxy);
        assert_eq!(parsed.attribution.confidence, HostnameConfidence::High);
    }

    #[test]
    fn parses_ip_connect_without_domain_attribution() {
        let parsed =
            parse_socks5_connect_request(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90], 64)
                .unwrap();
        assert_eq!(
            parsed.destination,
            Socks5Destination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.attribution.source, HostnameSource::IpOnly);
        assert_eq!(parsed.attribution.confidence, HostnameConfidence::Low);

        let parsed = parse_socks5_connect_request(
            &[
                0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0x00, 0x50,
            ],
            64,
        )
        .unwrap();
        assert_eq!(
            parsed.destination,
            Socks5Destination::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,)))
        );
        assert_eq!(parsed.port, 80);
    }

    #[test]
    fn rejects_unsupported_socks_commands_and_address_types() {
        assert_eq!(
            parse_socks5_connect_request(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 53], 64),
            Err(Socks5ParseError::UnsupportedCommand)
        );
        assert_eq!(
            parse_socks5_connect_request(&[0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0, 80], 64),
            Err(Socks5ParseError::InvalidReservedByte)
        );
        assert_eq!(
            parse_socks5_connect_request(&[0x05, 0x01, 0x00, 0x05, 127, 0, 0, 1, 0, 80], 64),
            Err(Socks5ParseError::UnsupportedAddressType)
        );
    }

    #[test]
    fn rejects_malformed_domain_or_port_and_bounded_messages() {
        assert_eq!(
            parse_socks5_connect_request(&[0x05, 0x01, 0x00, 0x03, 0, 0, 80], 64),
            Err(Socks5ParseError::InvalidDomainLength)
        );
        assert_eq!(
            parse_socks5_connect_request(&[0x05, 0x01, 0x00, 0x03, 3, b'b', b'a'], 64),
            Err(Socks5ParseError::Incomplete)
        );
        assert_eq!(
            parse_socks5_connect_request(
                &[
                    0x05, 0x01, 0x00, 0x03, 8, b'b', b'a', b'd', b'_', b'h', b'o', b's', b't', 0,
                    80
                ],
                64,
            ),
            Err(Socks5ParseError::InvalidHost)
        );
        assert_eq!(
            parse_socks5_connect_request(
                &[
                    0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
                    b'c', b'o', b'm', 0, 0
                ],
                64,
            ),
            Err(Socks5ParseError::InvalidPort)
        );
        assert_eq!(
            parse_socks5_connect_request(
                &[
                    0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
                    b'c', b'o', b'm', 0, 80, 0
                ],
                64,
            ),
            Err(Socks5ParseError::TrailingBytes)
        );
        assert_eq!(
            parse_socks5_connect_request(
                &[
                    0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
                    b'c', b'o', b'm', 0, 80
                ],
                8,
            ),
            Err(Socks5ParseError::MessageTooLarge)
        );
    }
}
