use crate::attribution::{HostAttribution, Hostname, HostnameError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequestMetadata {
    pub method: String,
    pub host: Hostname,
    pub port: u16,
    pub path_query: String,
    pub attribution: HostAttribution,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HttpParseError {
    HeaderTooLarge,
    IncompleteHeaders,
    NonAscii,
    MalformedRequestLine,
    UnsupportedHttpVersion,
    InvalidMethod,
    MissingHost,
    DuplicateHost,
    HostMismatch,
    InvalidHost,
    InvalidPort,
    InvalidTarget,
}

pub fn parse_http_request_head(
    bytes: &[u8],
    max_header_bytes: usize,
) -> Result<HttpRequestMetadata, HttpParseError> {
    let scan_len = bytes.len().min(max_header_bytes);
    let Some(head_end) = find_header_end(&bytes[..scan_len]) else {
        if bytes.len() >= max_header_bytes {
            return Err(HttpParseError::HeaderTooLarge);
        }
        return Err(HttpParseError::IncompleteHeaders);
    };

    let head = std::str::from_utf8(&bytes[..head_end]).map_err(|_| HttpParseError::NonAscii)?;
    if !head.is_ascii() {
        return Err(HttpParseError::NonAscii);
    }

    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(HttpParseError::MalformedRequestLine)?;
    let (method, target, version) = parse_request_line(request_line)?;
    validate_method(method)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(HttpParseError::UnsupportedHttpVersion);
    }

    let mut host_header = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpParseError::MalformedRequestLine);
        };
        if name.eq_ignore_ascii_case("host") {
            if host_header.is_some() {
                return Err(HttpParseError::DuplicateHost);
            }
            host_header = Some(value.trim());
        }
    }

    let target_parts = parse_target(target)?;
    let host_parts = host_header
        .map(parse_host_port)
        .transpose()?
        .or_else(|| target_parts.host.clone())
        .ok_or(HttpParseError::MissingHost)?;

    if let Some(target_host) = &target_parts.host {
        if target_host != &host_parts {
            return Err(HttpParseError::HostMismatch);
        }
    }

    Ok(HttpRequestMetadata {
        method: method.to_owned(),
        host: host_parts.host.clone(),
        port: host_parts.port.unwrap_or(80),
        path_query: target_parts.path_query,
        attribution: HostAttribution::plaintext_http(host_parts.host),
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 2)
}

fn parse_request_line(line: &str) -> Result<(&str, &str, &str), HttpParseError> {
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(HttpParseError::MalformedRequestLine)?;
    let target = parts.next().ok_or(HttpParseError::MalformedRequestLine)?;
    let version = parts.next().ok_or(HttpParseError::MalformedRequestLine)?;
    if parts.next().is_some() || method.is_empty() || target.is_empty() || version.is_empty() {
        return Err(HttpParseError::MalformedRequestLine);
    }
    Ok((method, target, version))
}

fn validate_method(method: &str) -> Result<(), HttpParseError> {
    if method
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
    {
        Ok(())
    } else {
        Err(HttpParseError::InvalidMethod)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TargetParts {
    host: Option<HostPort>,
    path_query: String,
}

fn parse_target(target: &str) -> Result<TargetParts, HttpParseError> {
    if let Some(rest) = target.strip_prefix("http://") {
        let (authority, path_query) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(HttpParseError::InvalidTarget);
        }
        return Ok(TargetParts {
            host: Some(parse_host_port(authority)?),
            path_query: validate_path(path_query)?.to_owned(),
        });
    }

    Ok(TargetParts {
        host: None,
        path_query: validate_path(target)?.to_owned(),
    })
}

fn validate_path(path_query: &str) -> Result<&str, HttpParseError> {
    if path_query.starts_with('/') && !path_query.bytes().any(|byte| byte.is_ascii_control()) {
        Ok(path_query)
    } else {
        Err(HttpParseError::InvalidTarget)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostPort {
    host: Hostname,
    port: Option<u16>,
}

fn parse_host_port(value: &str) -> Result<HostPort, HttpParseError> {
    if value.is_empty() || value.starts_with('[') {
        return Err(HttpParseError::InvalidHost);
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port_text))
            if !port_text.is_empty() && port_text.bytes().all(|b| b.is_ascii_digit()) =>
        {
            let port = port_text.parse().map_err(|_| HttpParseError::InvalidPort)?;
            if port == 0 {
                return Err(HttpParseError::InvalidPort);
            }
            (host, Some(port))
        }
        Some(_) if value.matches(':').count() == 1 => return Err(HttpParseError::InvalidPort),
        _ => (value, None),
    };

    let host = Hostname::parse(host).map_err(map_hostname_error)?;
    Ok(HostPort { host, port })
}

fn map_hostname_error(_error: HostnameError) -> HttpParseError {
    HttpParseError::InvalidHost
}

#[cfg(test)]
mod tests {
    use crate::types::{HostnameConfidence, HostnameSource};

    use super::*;

    #[test]
    fn parses_origin_form_with_normalized_host_attribution() {
        let parsed = parse_http_request_head(
            b"GET /path?q=1 HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: test\r\n\r\nbody",
            1024,
        )
        .unwrap();

        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.host.as_str(), "example.com");
        assert_eq!(parsed.port, 80);
        assert_eq!(parsed.path_query, "/path?q=1");
        assert_eq!(parsed.attribution.source, HostnameSource::PlaintextHttpHost);
        assert_eq!(parsed.attribution.confidence, HostnameConfidence::High);
    }

    #[test]
    fn parses_explicit_port_and_absolute_form() {
        let parsed = parse_http_request_head(
            b"POST http://api.example.com:8080/v1 HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n",
            1024,
        )
        .unwrap();

        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.host.as_str(), "api.example.com");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.path_query, "/v1");
    }

    #[test]
    fn rejects_missing_duplicate_or_conflicting_host() {
        assert_eq!(
            parse_http_request_head(b"GET / HTTP/1.1\r\n\r\n", 1024),
            Err(HttpParseError::MissingHost)
        );
        assert_eq!(
            parse_http_request_head(
                b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: a.example\r\n\r\n",
                1024,
            ),
            Err(HttpParseError::DuplicateHost)
        );
        assert_eq!(
            parse_http_request_head(
                b"GET http://a.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n",
                1024,
            ),
            Err(HttpParseError::HostMismatch)
        );
    }

    #[test]
    fn rejects_malformed_request_lines_and_invalid_versions() {
        assert_eq!(
            parse_http_request_head(b"get / HTTP/1.1\r\nHost: example.com\r\n\r\n", 1024),
            Err(HttpParseError::InvalidMethod)
        );
        assert_eq!(
            parse_http_request_head(b"GET / HTTP/2\r\nHost: example.com\r\n\r\n", 1024),
            Err(HttpParseError::UnsupportedHttpVersion)
        );
        assert_eq!(
            parse_http_request_head(b"GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n", 1024),
            Err(HttpParseError::MalformedRequestLine)
        );
    }

    #[test]
    fn rejects_invalid_hosts_ports_and_targets() {
        assert_eq!(
            parse_http_request_head(b"GET / HTTP/1.1\r\nHost: bad_host.example\r\n\r\n", 1024),
            Err(HttpParseError::InvalidHost)
        );
        assert_eq!(
            parse_http_request_head(b"GET / HTTP/1.1\r\nHost: example.com:0\r\n\r\n", 1024),
            Err(HttpParseError::InvalidPort)
        );
        assert_eq!(
            parse_http_request_head(b"GET * HTTP/1.1\r\nHost: example.com\r\n\r\n", 1024),
            Err(HttpParseError::InvalidTarget)
        );
    }

    #[test]
    fn enforces_header_scan_limit_and_complete_headers() {
        assert_eq!(
            parse_http_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\n", 1024),
            Err(HttpParseError::IncompleteHeaders)
        );
        assert_eq!(
            parse_http_request_head(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Long: 1234567890\r\n\r\n",
                32,
            ),
            Err(HttpParseError::HeaderTooLarge)
        );
    }
}
