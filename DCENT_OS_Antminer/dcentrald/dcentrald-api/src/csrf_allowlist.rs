//! First-boot CSRF host allowlist.
//!
//! `Origin == Host` is necessary but not sufficient: after DNS rebinding the
//! browser sends `Origin: http://evil.example` with `Host: evil.example`, so
//! the strings match while the request is still cross-site from the miner's
//! point of view.
//!
//! Admitted Host values (port stripped):
//! - loopback (`localhost`, `127.0.0.1`, `::1`)
//! - IPv4 / IPv6 literals (LAN dashboard by address)
//! - mDNS `*.local`
//! - extras from `DCENT_CSRF_ALLOWED_HOSTS` (comma-separated)
//!
//! Call site (auth.rs): `is_allowed_dashboard_origin` →
//! [`origin_matches_allowed_host`]. Coordinator: one-line wire; do not edit
//! `is_pre_setup_safe`.

use std::net::IpAddr;

/// Environment variable listing extra admitted Host values (comma-separated).
pub const CSRF_ALLOWED_HOSTS_ENV: &str = "DCENT_CSRF_ALLOWED_HOSTS";

/// Strip an optional port from a Host / origin-host value.
///
/// `host:port` → `host`; `[v6]:port` → `v6`. A trailing DNS dot is dropped.
pub fn strip_host_port(host: &str) -> &str {
    let host = host.trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    if let Some((name, port)) = host.rsplit_once(':') {
        if !name.is_empty()
            && !name.contains(':')
            && !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
        {
            return name;
        }
    }
    host
}

fn is_loopback_or_literal_ip(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok()
}

fn is_mdns_local(host: &str) -> bool {
    host.rsplit('.')
        .next()
        .map(|label| label.eq_ignore_ascii_case("local"))
        .unwrap_or(false)
}

/// Extra admitted hosts from `DCENT_CSRF_ALLOWED_HOSTS`.
pub fn extra_allowed_hosts_from(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Process env extras. Empty when the variable is unset.
pub fn extra_allowed_hosts() -> Vec<String> {
    match std::env::var(CSRF_ALLOWED_HOSTS_ENV) {
        Ok(raw) => extra_allowed_hosts_from(&raw),
        Err(_) => Vec::new(),
    }
}

/// True when `host` (Host header, optional port) is an admitted dashboard host.
pub fn host_header_is_allowed_with_extras(host: &str, extras: &[String]) -> bool {
    let host = strip_host_port(host);
    if host.is_empty() {
        return false;
    }
    if is_loopback_or_literal_ip(host) || is_mdns_local(host) {
        return true;
    }
    extras
        .iter()
        .any(|extra| strip_host_port(extra).eq_ignore_ascii_case(host))
}

/// Production check: literals / `.local` / `DCENT_CSRF_ALLOWED_HOSTS`.
pub fn host_header_is_allowed(host: &str) -> bool {
    host_header_is_allowed_with_extras(host, &extra_allowed_hosts())
}

/// Same-origin setup CSRF: Origin/Referer host equals Host **and** Host is
/// on the allowlist (closes DNS-rebinding `Origin == Host`).
pub fn origin_matches_allowed_host(origin_host: &str, host: &str) -> bool {
    let origin_host = strip_host_port(origin_host);
    let host_bare = strip_host_port(host);
    !origin_host.is_empty()
        && origin_host.eq_ignore_ascii_case(host_bare)
        && host_header_is_allowed(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_host_port_handles_v4_v6_and_names() {
        assert_eq!(strip_host_port("203.0.113.50:8080"), "203.0.113.50");
        assert_eq!(strip_host_port("[::1]:8080"), "::1");
        assert_eq!(strip_host_port("dcentos.local:80"), "dcentos.local");
        assert_eq!(strip_host_port("localhost"), "localhost");
        assert_eq!(strip_host_port("evil.example."), "evil.example");
    }

    #[test]
    fn lan_ip_and_mdns_and_loopback_are_admitted() {
        let none: [String; 0] = [];
        assert!(host_header_is_allowed_with_extras("203.0.113.25:8080", &none));
        assert!(host_header_is_allowed_with_extras("dcentos.local", &none));
        assert!(host_header_is_allowed_with_extras("localhost:8080", &none));
        assert!(host_header_is_allowed_with_extras("[::1]:8080", &none));
        assert!(host_header_is_allowed_with_extras("127.0.0.1", &none));
    }

    #[test]
    fn dns_rebind_hostname_is_rejected_even_when_origin_equals_host() {
        let none: [String; 0] = [];
        assert!(!host_header_is_allowed_with_extras("evil.example", &none));
        assert!(!origin_matches_allowed_host("evil.example", "evil.example"));
        // Origin == Host used to pass; allowlist now fails closed.
        assert!(!origin_matches_allowed_host(
            "evil.example:8080",
            "evil.example:8080"
        ));
    }

    #[test]
    fn substring_local_is_not_a_tld() {
        let none: [String; 0] = [];
        assert!(!host_header_is_allowed_with_extras(
            "evil.local.attacker.example",
            &none
        ));
        assert!(!host_header_is_allowed_with_extras("local.example", &none));
    }

    #[test]
    fn extras_admit_operator_hostname() {
        let extras = extra_allowed_hosts_from("miner.lan, bench.home");
        assert!(host_header_is_allowed_with_extras(
            "miner.lan:8080",
            &extras
        ));
        assert!(host_header_is_allowed_with_extras("bench.home", &extras));
        assert!(!host_header_is_allowed_with_extras("other.lan", &extras));
    }

    #[test]
    fn same_origin_ip_dashboard_is_admitted() {
        assert!(origin_matches_allowed_host(
            "203.0.113.25:8080",
            "203.0.113.25:8080"
        ));
        assert!(origin_matches_allowed_host("dcent.local", "dcent.local:80"));
    }
}
