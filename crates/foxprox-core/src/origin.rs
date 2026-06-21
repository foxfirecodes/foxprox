use crate::types::{Hostname, Origin, Scheme};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginError {
    Empty,
    MissingHost,
    MissingPort,
    InvalidPort,
    UnsupportedScheme,
    InvalidHostname,
}

pub fn parse_connect_target(input: &str) -> Result<Origin, OriginError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(OriginError::Empty);
    }
    let (host, port) = split_host_port(input, Some(443))?;
    Ok(Origin {
        scheme: Scheme::Https,
        host,
        port,
    })
}

pub fn parse_http_origin(input: &str) -> Result<Origin, OriginError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(OriginError::Empty);
    }
    let (scheme, remainder, default_port) = if let Some(rest) = input.strip_prefix("http://") {
        (Scheme::Http, rest, 80)
    } else if let Some(rest) = input.strip_prefix("https://") {
        (Scheme::Https, rest, 443)
    } else {
        return Err(OriginError::UnsupportedScheme);
    };
    let authority = remainder.split('/').next().unwrap_or(remainder);
    let (host, port) = split_host_port(authority, Some(default_port))?;
    Ok(Origin { scheme, host, port })
}

pub(crate) fn split_host_port(
    authority: &str,
    default_port: Option<u16>,
) -> Result<(Hostname, u16), OriginError> {
    if authority.is_empty() {
        return Err(OriginError::MissingHost);
    }
    if authority.starts_with('[') {
        // IPv6 literals are intentionally not accepted as hostnames in domain
        // policy paths. IP literals should use IP/CIDR rules instead.
        return Err(OriginError::InvalidHostname);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            let port = port.parse::<u16>().map_err(|_| OriginError::InvalidPort)?;
            (host, port)
        }
        Some((_, "")) => return Err(OriginError::MissingPort),
        _ => (authority, default_port.ok_or(OriginError::MissingPort)?),
    };
    let host = Hostname::normalize(host).map_err(|_| OriginError::InvalidHostname)?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_target_defaulting_to_https_port() {
        let origin = parse_connect_target("Example.COM").unwrap();
        assert_eq!(origin.scheme, Scheme::Https);
        assert_eq!(origin.host.as_str(), "example.com");
        assert_eq!(origin.port, 443);
    }

    #[test]
    fn parses_absolute_http_origin() {
        let origin = parse_http_origin("http://Example.com:8080/path?q=1").unwrap();
        assert_eq!(origin.scheme, Scheme::Http);
        assert_eq!(origin.host.as_str(), "example.com");
        assert_eq!(origin.port, 8080);
    }
}
