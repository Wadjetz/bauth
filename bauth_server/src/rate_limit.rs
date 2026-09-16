//! In-memory rate limits for endpoints that burn CPU (argon2) or send emails.
//! Budgets live in this process: with several instances, each enforces its own.

use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use governor::DefaultKeyedRateLimiter;
use governor::Quota;
use governor::clock::Clock;
use governor::clock::DefaultClock;

use crate::AppState;
use crate::errors::ApiError;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub struct Limiter {
    limiter: DefaultKeyedRateLimiter<String>,
    clock: DefaultClock,
}

impl Limiter {
    /// Allows `burst` requests at once, then one more every `replenish_one_every`.
    fn new(burst: u32, replenish_one_every: Duration) -> Self {
        let quota = Quota::with_period(replenish_one_every)
            .expect("period is not zero")
            .allow_burst(NonZeroU32::new(burst).expect("burst is not zero"));
        Self {
            limiter: DefaultKeyedRateLimiter::keyed(quota),
            clock: DefaultClock::default(),
        }
    }

    pub fn check(&self, key: &str) -> Result<(), ApiError> {
        self.limiter
            .check_key(&key.to_owned())
            .map_err(|not_until| ApiError::RateLimited {
                retry_after: not_until.wait_time_from(self.clock.now()),
            })
    }
}

pub struct RateLimits {
    trusted_proxies: Vec<IpAddr>,
    /// Password attempts per account: slows down guessing without locking the owner out.
    pub login_per_email: Limiter,
    /// Password attempts per client IP, across accounts (credential stuffing).
    pub login_per_ip: Limiter,
    /// Emails per recipient (verification, reset, magic link), against inbox flooding.
    pub email_per_address: Limiter,
    /// Requests that send an email, per client IP.
    pub email_per_ip: Limiter,
    /// Token confirmations (email links, password reset), per client IP.
    pub token_per_ip: Limiter,
}

impl RateLimits {
    pub fn new(trusted_proxies: Vec<IpAddr>) -> Self {
        Self {
            trusted_proxies,
            login_per_email: Limiter::new(10, Duration::from_secs(30)),
            login_per_ip: Limiter::new(30, Duration::from_secs(2)),
            email_per_address: Limiter::new(5, Duration::from_secs(3 * 60)),
            email_per_ip: Limiter::new(20, Duration::from_secs(30)),
            token_per_ip: Limiter::new(30, Duration::from_secs(2)),
        }
    }

    /// Forgets keys whose budget is full again, so memory doesn't grow with every IP seen.
    pub fn spawn_cleanup(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                for limiter in [
                    &self.login_per_email,
                    &self.login_per_ip,
                    &self.email_per_address,
                    &self.email_per_ip,
                    &self.token_per_ip,
                ] {
                    limiter.limiter.retain_recent();
                    limiter.limiter.shrink_to_fit();
                }
            }
        });
    }
}

/// `BAUTH_TRUSTED_PROXIES`: comma-separated IPs allowed to set `X-Forwarded-For`.
pub fn parse_trusted_proxies(value: &str) -> Result<Vec<IpAddr>, String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .map(|ip| {
            ip.parse()
                .map_err(|_| format!("BAUTH_TRUSTED_PROXIES: `{ip}` is not an IP address"))
        })
        .collect()
}

/// Rate limit key for an email, normalized like the database does.
pub fn email_key(email: &str) -> String {
    email.trim_matches(' ').to_lowercase()
}

/// The end user's address. Behind a trusted proxy (reverse proxy, app server) it comes from
/// `X-Forwarded-For` (the RFC 7239 `Forwarded` header is not read); otherwise from the TCP peer,
/// since anyone can forge that header.
pub struct ClientIp(pub IpAddr);

impl ClientIp {
    pub fn key(&self) -> String {
        match self.0 {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(ip) => ip.to_string(),
                // One IPv6 user usually owns a whole /64: limit the prefix, not each address.
                None => {
                    let s = ip.segments();
                    format!("{}/64", Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
                }
            },
        }
    }
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let ConnectInfo(peer) = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .copied()
            .ok_or_else(|| {
                ApiError::Internal("server must be started with ConnectInfo<SocketAddr>".into())
            })?;
        let forwarded_for = parts
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(",");
        Ok(Self(resolve(
            peer.ip(),
            &forwarded_for,
            &state.rate_limits.trusted_proxies,
        )))
    }
}

/// Walks `X-Forwarded-For` from the closest hop and stops at the first address not trusted.
fn resolve(peer: IpAddr, forwarded_for: &str, trusted: &[IpAddr]) -> IpAddr {
    let mut client = peer;
    if !trusted.contains(&client) {
        return client;
    }
    for hop in forwarded_for.split(',').map(str::trim).rev() {
        let Ok(ip) = hop.parse::<IpAddr>() else {
            break;
        };
        client = ip;
        if !trusted.contains(&ip) {
            break;
        }
    }
    client
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn limiter_allows_burst_then_asks_to_wait() {
        let limiter = Limiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(limiter.check("a").is_ok());
        }
        let Err(ApiError::RateLimited { retry_after }) = limiter.check("a") else {
            panic!("4th request should be limited");
        };
        assert!(retry_after > Duration::from_secs(50));
        assert!(limiter.check("b").is_ok(), "keys have separate budgets");
    }

    #[test]
    fn keys_normalize_emails_and_ipv6_prefixes() {
        assert_eq!(email_key(" Alice@Example.COM "), "alice@example.com");
        assert_eq!(ClientIp(ip("203.0.113.7")).key(), "203.0.113.7");
        assert_eq!(ClientIp(ip("::ffff:203.0.113.7")).key(), "203.0.113.7");
        assert_eq!(
            ClientIp(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")).key(),
            ClientIp(ip("2001:db8:1:2::1")).key()
        );
    }

    #[test]
    fn forwarded_for_is_only_trusted_from_trusted_proxies() {
        let proxy = ip("10.0.0.2");
        let trusted = [proxy, ip("10.0.0.3")];
        // Direct client: the header is ignored, it could be forged.
        assert_eq!(
            resolve(ip("198.51.100.1"), "1.2.3.4", &trusted),
            ip("198.51.100.1")
        );
        // Through a trusted proxy: the last hop it saw.
        assert_eq!(
            resolve(proxy, "1.2.3.4, 198.51.100.1", &trusted),
            ip("198.51.100.1")
        );
        // Through two trusted proxies.
        assert_eq!(
            resolve(proxy, "198.51.100.1, 10.0.0.3", &trusted),
            ip("198.51.100.1")
        );
        // Trusted proxy without header, or with garbage.
        assert_eq!(resolve(proxy, "", &trusted), proxy);
        assert_eq!(resolve(proxy, "nope", &trusted), proxy);
    }

    #[test]
    fn parses_trusted_proxies() {
        assert_eq!(parse_trusted_proxies("").unwrap(), Vec::<IpAddr>::new());
        assert_eq!(
            parse_trusted_proxies("127.0.0.1, ::1").unwrap(),
            vec![ip("127.0.0.1"), ip("::1")]
        );
        assert!(parse_trusted_proxies("10.0.0.0/8").is_err());
    }
}
