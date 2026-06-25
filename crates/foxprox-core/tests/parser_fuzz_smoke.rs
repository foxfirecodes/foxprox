use foxprox_core::{
    parse_dns_address_response, parse_dns_query, parse_http_request_head, parse_https_connect_head,
    parse_ip_packet, parse_quic_candidate, parse_socks5_connect_request, parse_socks5_greeting,
    parse_tls_client_hello,
};

#[test]
fn arbitrary_bytes_do_not_panic_packet_or_protocol_parsers() {
    let mut rng = Lcg::new(0xfeed_f00d_dead_beef);
    for len in 0..512_usize {
        let bytes = rng.bytes(len);
        let _ = parse_ip_packet(&bytes);
        let _ = parse_dns_query(&bytes, 512);
        let _ = parse_dns_address_response(&bytes, 512, 16);
        let _ = parse_http_request_head(&bytes, 1024);
        let _ = parse_https_connect_head(&bytes, 1024);
        let _ = parse_tls_client_hello(&bytes, 2048);
        let _ = parse_quic_candidate(&bytes, 2048);
        let _ = parse_socks5_greeting(&bytes, 512);
        let _ = parse_socks5_connect_request(&bytes, 512);
    }
}

#[test]
fn oversized_parser_inputs_fail_closed_without_large_allocations() {
    let bytes = vec![0xff; 4096];
    assert!(parse_dns_query(&bytes, 512).is_err());
    assert!(parse_dns_address_response(&bytes, 512, 16).is_err());
    assert!(parse_http_request_head(&bytes, 1024).is_err());
    assert!(parse_https_connect_head(&bytes, 1024).is_err());
    assert!(parse_tls_client_hello(&bytes, 1024).is_err());
    assert!(parse_quic_candidate(&bytes, 1024).is_err());
    assert!(parse_socks5_greeting(&bytes, 512).is_err());
    assert!(parse_socks5_connect_request(&bytes, 512).is_err());
}

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u8 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        (self.0 >> 32) as u8
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next()).collect()
    }
}
