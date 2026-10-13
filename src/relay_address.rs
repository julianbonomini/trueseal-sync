//! The Relay Address (ADR-0028): the single string that names a Relay —
//! `trueseal://<relay public key hex>@host[:receivePort][?push=pushPort]`.
//!
//! The key comes first because it is what authenticates the Relay. The
//! ports default to 7700 (receive) and 7701 (push). A port is never
//! dropped silently: a port present in the string is always honoured, and
//! a missing port always resolves to its default.

use crate::keys::NoisePublicKey;

/// Default port of the Relay's Receive Session listener (Noise XX).
pub const DEFAULT_RECEIVE_PORT: u16 = 7700;
/// Default port of the Relay's Push Session listener (Noise NK).
pub const DEFAULT_PUSH_PORT: u16 = 7701;

const SCHEME: &str = "trueseal://";

/// A parsed Relay Address (ADR-0028's typed form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAddress {
    /// Relay hostname or IP, e.g. `"relay.example.com"` or `"[::1]"`.
    pub host: String,
    /// The Relay's 32-byte X25519 public key — what authenticates it.
    pub public_key: NoisePublicKey,
    /// Receive Session port (defaults to 7700).
    pub receive_port: u16,
    /// Push Session port (defaults to 7701).
    pub push_port: u16,
}

/// A malformed Relay Address string. Carries a human-readable reason; the
/// FFI maps it to the typed `invalidRelayAddress` error (ADR-0028).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid relay address: {0}")]
pub struct RelayAddressError(pub String);

impl RelayAddress {
    /// Parse `trueseal://<relay public key hex>@host[:receivePort][?push=pushPort]`.
    ///
    /// Strict by design — this string authenticates the Relay, so anything
    /// unexpected (unknown query parameters, a second `@`, an unbracketed
    /// IPv6 host) is an error rather than a guess.
    pub fn parse(input: &str) -> Result<Self, RelayAddressError> {
        let err = |msg: &str| RelayAddressError(msg.to_string());

        let rest = input
            .strip_prefix(SCHEME)
            .ok_or_else(|| err("missing `trueseal://` scheme"))?;

        // The key is 64 hex chars and contains no '@', so the first '@'
        // separates key from authority. A second '@' inside the authority
        // is rejected below via the port/host parsing.
        let (key_hex, authority) = rest
            .split_once('@')
            .ok_or_else(|| err("missing `@` between the relay public key and the host"))?;

        let public_key = parse_key_hex(key_hex)?;

        let (host_port, query) = match authority.split_once('?') {
            Some((hp, q)) => (hp, Some(q)),
            None => (authority, None),
        };

        let (host, receive_port) = parse_host_port(host_port)?;

        let mut push_port = DEFAULT_PUSH_PORT;
        if let Some(q) = query {
            let value = q
                .strip_prefix("push=")
                .ok_or_else(|| err("only the `push=` query parameter is supported"))?;
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(err("`push` port must be a number"));
            }
            push_port = value
                .parse::<u16>()
                .map_err(|_| err("`push` port out of range (0-65535)"))?;
        }

        Ok(Self {
            host,
            public_key,
            receive_port,
            push_port,
        })
    }

    /// `host:receivePort` — the Receive Session dial address.
    pub fn receive_addr(&self) -> String {
        format!("{}:{}", self.host, self.receive_port)
    }

    /// `host:pushPort` — the Push Session dial address.
    pub fn push_addr(&self) -> String {
        format!("{}:{}", self.host, self.push_port)
    }

    /// The canonical string form. Round-trips through [`Self::parse`].
    pub fn to_canonical_string(&self) -> String {
        let key_hex: String = self
            .public_key
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut s = format!("{SCHEME}{key_hex}@{}", self.host);
        if self.receive_port != DEFAULT_RECEIVE_PORT {
            s.push_str(&format!(":{}", self.receive_port));
        }
        if self.push_port != DEFAULT_PUSH_PORT {
            s.push_str(&format!("?push={}", self.push_port));
        }
        s
    }
}

/// Parse exactly 64 hex characters into the relay's 32-byte public key.
fn parse_key_hex(hex: &str) -> Result<NoisePublicKey, RelayAddressError> {
    let err = || {
        RelayAddressError(
            "relay public key must be 64 hex characters (32 bytes)".to_string(),
        )
    };
    if hex.len() != 64 {
        return Err(err());
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0]).ok_or_else(err)?;
        let lo = hex_val(chunk[1]).ok_or_else(err)?;
        bytes[i] = (hi << 4) | lo;
    }
    Ok(NoisePublicKey(bytes))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse `host[:port]`, with `[v6addr][:port]` support. A second colon in an
/// unbracketed host means a bare IPv6 address, which is ambiguous with the
/// port separator — require brackets.
fn parse_host_port(s: &str) -> Result<(String, u16), RelayAddressError> {
    let err = |msg: &str| RelayAddressError(msg.to_string());
    if s.is_empty() {
        return Err(err("missing host"));
    }
    if let Some(after_bracket) = s.strip_prefix('[') {
        let (v6, rest) = after_bracket
            .split_once(']')
            .ok_or_else(|| err("unterminated `[` in IPv6 host"))?;
        if v6.is_empty() {
            return Err(err("empty IPv6 host"));
        }
        let host = format!("[{v6}]");
        match rest.strip_prefix(':') {
            Some(port) if !port.is_empty() => Ok((host, parse_port(port)?)),
            None if rest.is_empty() => Ok((host, DEFAULT_RECEIVE_PORT)),
            _ => Err(err("unexpected characters after `]`")),
        }
    } else {
        match s.matches(':').count() {
            0 => Ok((s.to_string(), DEFAULT_RECEIVE_PORT)),
            1 => {
                let (host, port) = s.split_once(':').expect("exactly one colon");
                if host.is_empty() {
                    return Err(err("missing host"));
                }
                Ok((host.to_string(), parse_port(port)?))
            }
            _ => Err(err(
                "an IPv6 host must be bracketed: `[2001:db8::1][:port]`",
            )),
        }
    }
}

fn parse_port(s: &str) -> Result<u16, RelayAddressError> {
    let err = |msg: &str| RelayAddressError(msg.to_string());
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err("port must be a number"));
    }
    s.parse::<u16>()
        .map_err(|_| err("port out of range (0-65535)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn key_bytes() -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, pair) in KEY.as_bytes().chunks_exact(2).enumerate() {
            b[i] = (hex_val(pair[0]).unwrap() << 4) | hex_val(pair[1]).unwrap();
        }
        b
    }

    #[test]
    fn parses_key_and_host_with_default_ports() {
        let a = RelayAddress::parse(&format!("trueseal://{KEY}@relay.example.com")).unwrap();
        assert_eq!(a.host, "relay.example.com");
        assert_eq!(a.public_key.0, key_bytes());
        assert_eq!(a.receive_port, 7700);
        assert_eq!(a.push_port, 7701);
        assert_eq!(a.receive_addr(), "relay.example.com:7700");
        assert_eq!(a.push_addr(), "relay.example.com:7701");
    }

    #[test]
    fn explicit_ports_are_never_dropped() {
        let a = RelayAddress::parse(&format!("trueseal://{KEY}@10.0.0.2:8800?push=8801")).unwrap();
        assert_eq!(a.receive_port, 8800);
        assert_eq!(a.push_port, 8801);
        assert_eq!(a.receive_addr(), "10.0.0.2:8800");
        assert_eq!(a.push_addr(), "10.0.0.2:8801");
    }

    #[test]
    fn only_push_query_overrides_push_port() {
        let a = RelayAddress::parse(&format!("trueseal://{KEY}@host?push=9999")).unwrap();
        assert_eq!(a.receive_port, 7700);
        assert_eq!(a.push_port, 9999);
    }

    #[test]
    fn bracketed_ipv6_with_and_without_port() {
        let a = RelayAddress::parse(&format!("trueseal://{KEY}@[2001:db8::1]")).unwrap();
        assert_eq!(a.host, "[2001:db8::1]");
        assert_eq!(a.receive_port, 7700);
        let a = RelayAddress::parse(&format!("trueseal://{KEY}@[2001:db8::1]:1234")).unwrap();
        assert_eq!(a.receive_port, 1234);
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = KEY.to_uppercase();
        let a = RelayAddress::parse(&format!("trueseal://{upper}@host")).unwrap();
        assert_eq!(a.public_key.0, key_bytes());
    }

    #[test]
    fn canonical_string_round_trips() {
        for input in [
            format!("trueseal://{KEY}@relay.example.com"),
            format!("trueseal://{KEY}@relay.example.com:8800"),
            format!("trueseal://{KEY}@relay.example.com?push=8801"),
            format!("trueseal://{KEY}@relay.example.com:8800?push=8801"),
        ] {
            let parsed = RelayAddress::parse(&input).unwrap();
            let again = RelayAddress::parse(&parsed.to_canonical_string()).unwrap();
            assert_eq!(parsed, again, "round trip of {input}");
        }
    }

    #[test]
    fn malformed_addresses_are_rejected() {
        let cases = [
            format!("http://{KEY}@host"),            // wrong scheme
            format!("trueseal://{KEY}"),             // missing @host
            format!("trueseal://{KEY}@"),            // empty host
            format!("trueseal://{KEY}:host"),        // missing @
            "trueseal://zz@host".to_string(),        // bad hex
            format!("trueseal://{}@host", &KEY[..62]), // short key
            format!("trueseal://{KEY}@host:abc"),    // non-numeric port
            format!("trueseal://{KEY}@host:99999"),  // port overflow
            format!("trueseal://{KEY}@host:7700x"),  // trailing junk
            format!("trueseal://{KEY}@host?foo=1"),  // unknown query param
            format!("trueseal://{KEY}@host?push="),  // empty push port
            format!("trueseal://{KEY}@2001:db8::1"), // unbracketed IPv6
            format!("trueseal://{KEY}@[::1"),        // unterminated bracket
            format!("trueseal://{KEY}@:7700"),       // empty host with port
        ];
        for c in &cases {
            assert!(
                RelayAddress::parse(c).is_err(),
                "should reject: {c}"
            );
        }
    }
}
