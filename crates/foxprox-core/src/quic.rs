#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QuicHeaderForm {
    Long,
    Short,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QuicLongPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicPacketMetadata {
    pub header_form: QuicHeaderForm,
    pub long_packet_type: Option<QuicLongPacketType>,
    pub version: Option<u32>,
    pub version_supported: bool,
    pub destination_connection_id_len: Option<u8>,
    pub source_connection_id_len: Option<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QuicParseError {
    PacketTooLarge,
    Empty,
    MissingFixedBit,
    TruncatedLongHeader,
    InvalidConnectionIdLength,
}

pub fn parse_quic_candidate(
    bytes: &[u8],
    max_packet_bytes: usize,
) -> Result<QuicPacketMetadata, QuicParseError> {
    if bytes.len() > max_packet_bytes {
        return Err(QuicParseError::PacketTooLarge);
    }
    let first = *bytes.first().ok_or(QuicParseError::Empty)?;
    if first & 0x40 == 0 {
        return Err(QuicParseError::MissingFixedBit);
    }

    if first & 0x80 == 0 {
        return Ok(QuicPacketMetadata {
            header_form: QuicHeaderForm::Short,
            long_packet_type: None,
            version: None,
            version_supported: false,
            destination_connection_id_len: None,
            source_connection_id_len: None,
        });
    }

    if bytes.len() < 7 {
        return Err(QuicParseError::TruncatedLongHeader);
    }

    let packet_type = match (first & 0x30) >> 4 {
        0 => QuicLongPacketType::Initial,
        1 => QuicLongPacketType::ZeroRtt,
        2 => QuicLongPacketType::Handshake,
        _ => QuicLongPacketType::Retry,
    };
    let version = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    let dcid_len = bytes[5];
    if dcid_len > 20 {
        return Err(QuicParseError::InvalidConnectionIdLength);
    }
    let scid_len_offset = 6 + usize::from(dcid_len);
    let scid_len = *bytes
        .get(scid_len_offset)
        .ok_or(QuicParseError::TruncatedLongHeader)?;
    if scid_len > 20 {
        return Err(QuicParseError::InvalidConnectionIdLength);
    }
    let header_end = scid_len_offset + 1 + usize::from(scid_len);
    if bytes.len() < header_end {
        return Err(QuicParseError::TruncatedLongHeader);
    }

    Ok(QuicPacketMetadata {
        header_form: QuicHeaderForm::Long,
        long_packet_type: Some(packet_type),
        version: Some(version),
        version_supported: version == 1,
        destination_connection_id_len: Some(dcid_len),
        source_connection_id_len: Some(scid_len),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_long_header_initial_metadata() {
        let packet = [
            0xc3, // long header, fixed bit, Initial, packet number bits
            0x00, 0x00, 0x00, 0x01, // QUIC v1
            0x08, // dcid len
            1, 2, 3, 4, 5, 6, 7, 8,    // dcid
            0x04, // scid len
            9, 10, 11, 12,   // scid
            0x00, // token length varint begins after parsed metadata
        ];

        let parsed = parse_quic_candidate(&packet, 1200).unwrap();
        assert_eq!(parsed.header_form, QuicHeaderForm::Long);
        assert_eq!(parsed.long_packet_type, Some(QuicLongPacketType::Initial));
        assert_eq!(parsed.version, Some(1));
        assert!(parsed.version_supported);
        assert_eq!(parsed.destination_connection_id_len, Some(8));
        assert_eq!(parsed.source_connection_id_len, Some(4));
    }

    #[test]
    fn parses_short_header_candidate_without_claiming_hostname_or_version() {
        let parsed = parse_quic_candidate(&[0x43, 0xaa, 0xbb, 0xcc], 1200).unwrap();
        assert_eq!(parsed.header_form, QuicHeaderForm::Short);
        assert_eq!(parsed.long_packet_type, None);
        assert_eq!(parsed.version, None);
        assert!(!parsed.version_supported);
        assert_eq!(parsed.destination_connection_id_len, None);
    }

    #[test]
    fn represents_unknown_long_header_version_explicitly() {
        let packet = [
            0xd0, // 0-RTT
            0xff, 0x00, 0x00, 0x1d, // unsupported draft/version
            0x00, // empty dcid
            0x00, // empty scid
        ];
        let parsed = parse_quic_candidate(&packet, 1200).unwrap();
        assert_eq!(parsed.long_packet_type, Some(QuicLongPacketType::ZeroRtt));
        assert_eq!(parsed.version, Some(0xff00001d));
        assert!(!parsed.version_supported);
    }

    #[test]
    fn rejects_missing_fixed_bit_empty_and_oversized_packets() {
        assert_eq!(parse_quic_candidate(&[], 1200), Err(QuicParseError::Empty));
        assert_eq!(
            parse_quic_candidate(&[0x80, 0, 0, 0, 1, 0, 0], 1200),
            Err(QuicParseError::MissingFixedBit)
        );
        assert_eq!(
            parse_quic_candidate(&[0x40; 8], 4),
            Err(QuicParseError::PacketTooLarge)
        );
    }

    #[test]
    fn rejects_truncated_or_invalid_connection_id_lengths() {
        assert_eq!(
            parse_quic_candidate(&[0xc0, 0, 0, 0, 1, 8, 1], 1200),
            Err(QuicParseError::TruncatedLongHeader)
        );
        assert_eq!(
            parse_quic_candidate(&[0xc0, 0, 0, 0, 1, 21, 0, 0], 1200),
            Err(QuicParseError::InvalidConnectionIdLength)
        );

        let mut packet = vec![0xc0, 0, 0, 0, 1, 0, 21];
        packet.extend([0; 21]);
        assert_eq!(
            parse_quic_candidate(&packet, 1200),
            Err(QuicParseError::InvalidConnectionIdLength)
        );
    }
}
