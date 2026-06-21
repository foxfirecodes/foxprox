use crate::types::normalize_hostname;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryMetadata {
    pub transaction_id: u16,
    pub hostname: String,
    pub query_type: DnsQueryType,
    pub query_class: u16,
    pub question_end: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsQueryType {
    A,
    Aaaa,
    Https,
    Svcb,
    Other(u16),
}

impl DnsQueryType {
    pub fn from_code(code: u16) -> Self {
        match code {
            1 => Self::A,
            28 => Self::Aaaa,
            65 => Self::Https,
            64 => Self::Svcb,
            other => Self::Other(other),
        }
    }

    pub fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Https => 65,
            Self::Svcb => 64,
            Self::Other(code) => code,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsParseError {
    ShortHeader,
    NotQuery,
    UnsupportedQuestionCount(u16),
    NameCompressionInQuestion,
    LabelTooLong,
    TruncatedQuestion,
    MissingQuestionType,
}

pub fn parse_dns_query(packet: &[u8]) -> Result<DnsQueryMetadata, DnsParseError> {
    if packet.len() < 12 {
        return Err(DnsParseError::ShortHeader);
    }
    let transaction_id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 != 0 {
        return Err(DnsParseError::NotQuery);
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount != 1 {
        return Err(DnsParseError::UnsupportedQuestionCount(qdcount));
    }

    let mut cursor = 12usize;
    let mut labels = Vec::new();
    loop {
        let Some(&len) = packet.get(cursor) else {
            return Err(DnsParseError::TruncatedQuestion);
        };
        cursor += 1;
        if len == 0 {
            break;
        }
        if len & 0b1100_0000 != 0 {
            return Err(DnsParseError::NameCompressionInQuestion);
        }
        if len > 63 {
            return Err(DnsParseError::LabelTooLong);
        }
        let len = len as usize;
        if packet.len().saturating_sub(cursor) < len {
            return Err(DnsParseError::TruncatedQuestion);
        }
        let label = std::str::from_utf8(&packet[cursor..cursor + len])
            .map_err(|_| DnsParseError::TruncatedQuestion)?;
        labels.push(label.to_string());
        cursor += len;
    }
    if packet.len().saturating_sub(cursor) < 4 {
        return Err(DnsParseError::MissingQuestionType);
    }
    let qtype = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
    let qclass = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
    cursor += 4;

    Ok(DnsQueryMetadata {
        transaction_id,
        hostname: normalize_hostname(&labels.join(".")),
        query_type: DnsQueryType::from_code(qtype),
        query_class: qclass,
        question_end: cursor,
    })
}

pub fn build_refused_response(query: &[u8]) -> Result<Vec<u8>, DnsParseError> {
    let metadata = parse_dns_query(query)?;
    let mut response = query[..metadata.question_end].to_vec();
    // QR=1, opcode copied as query (bits 14..11), AA=0, TC=0, RD copied, RA=0, RCODE=5/refused.
    response[2] = (query[2] & 0x78) | 0x80 | (query[2] & 0x01);
    response[3] = 0x05;
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses_dns_query_with_structured_qtype() {
        let query = dns_query(0x1234, "Example.COM", 1);
        let metadata = parse_dns_query(&query).unwrap();
        assert_eq!(metadata.transaction_id, 0x1234);
        assert_eq!(metadata.hostname, "example.com");
        assert_eq!(metadata.query_type, DnsQueryType::A);
        assert_eq!(metadata.query_class, 1);
        assert_eq!(metadata.question_end, query.len());
    }

    #[test]
    fn malformed_dns_query_is_rejected() {
        assert_eq!(parse_dns_query(&[0; 11]), Err(DnsParseError::ShortHeader));
        let mut compressed = dns_query(1, "example.com", 28);
        compressed[12] = 0xc0;
        assert_eq!(
            parse_dns_query(&compressed),
            Err(DnsParseError::NameCompressionInQuestion)
        );
    }

    #[test]
    fn refused_response_preserves_question_and_sets_rcode() {
        let query = dns_query(0xbeef, "blocked.example", 65);
        let response = build_refused_response(&query).unwrap();
        assert_eq!(&response[0..2], &[0xbe, 0xef]);
        assert_eq!(response[2] & 0x80, 0x80);
        assert_eq!(response[3] & 0x0f, 5);
        assert_eq!(&response[4..6], &[0, 1]);
        assert_eq!(&response[6..12], &[0, 0, 0, 0, 0, 0]);
        assert_eq!(&response[12..], &query[12..]);
    }

    fn dns_query(transaction_id: u16, hostname: &str, query_type: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&transaction_id.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired query
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        for label in hostname.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&query_type.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }
}
