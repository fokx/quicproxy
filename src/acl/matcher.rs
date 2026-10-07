use anyhow::{bail, Context, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::geo::{DomainType, GeoIp, GeoLoader, GeoSite};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostInfo {
    pub name: String,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl HostInfo {
    pub fn cache_string(&self) -> String {
        format!(
            "{}|{}|{}",
            self.name,
            self.ipv4
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            self.ipv6
                .map(|ip| ip.to_string())
                .unwrap_or_default()
        )
    }
}

pub trait HostMatcher: Send + Sync {
    fn matches(&self, host: &HostInfo) -> bool;
}

pub struct AllMatcher;

impl HostMatcher for AllMatcher {
    fn matches(&self, _host: &HostInfo) -> bool {
        true
    }
}

pub struct IpMatcher {
    pub ip: IpAddr,
}

impl HostMatcher for IpMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        match self.ip {
            IpAddr::V4(v4) => host.ipv4 == Some(v4),
            IpAddr::V6(v6) => host.ipv6 == Some(v6),
        }
    }
}

pub struct CidrMatcher {
    pub net: IpNet,
}

impl HostMatcher for CidrMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        match self.net {
            IpNet::V4(v4_net) => {
                if let Some(host_v4) = host.ipv4 {
                    v4_net.contains(&host_v4)
                } else {
                    false
                }
            }
            IpNet::V6(v6_net) => {
                if let Some(host_v6) = host.ipv6 {
                    v6_net.contains(&host_v6)
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainMatchMode {
    Exact,
    Wildcard,
    Suffix,
}

pub struct DomainMatcher {
    pub pattern: String,
    pub mode: DomainMatchMode,
    pattern_chars: Vec<char>,
}

impl DomainMatcher {
    pub fn new(pattern: String, mode: DomainMatchMode) -> Self {
        let pattern_chars = pattern.chars().collect();
        Self {
            pattern,
            mode,
            pattern_chars,
        }
    }
}

impl HostMatcher for DomainMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        if host.name.is_empty() {
            return false;
        }

        let unicode_name = match idna::domain_to_unicode(&host.name) {
            (name, Ok(())) => name,
            _ => host.name.clone(),
        };

        match self.mode {
            DomainMatchMode::Exact => unicode_name == self.pattern,
            DomainMatchMode::Suffix => {
                unicode_name == self.pattern
                    || unicode_name.ends_with(&format!(".{}", self.pattern))
            }
            DomainMatchMode::Wildcard => {
                let name_chars: Vec<char> = unicode_name.chars().collect();
                deep_match_chars(&name_chars, &self.pattern_chars)
            }
        }
    }
}

fn deep_match_chars(s: &[char], p: &[char]) -> bool {
    let mut s = s;
    let mut p = p;
    while !p.is_empty() {
        match p[0] {
            '*' => {
                return deep_match_chars(s, &p[1..])
                    || (!s.is_empty() && deep_match_chars(&s[1..], p));
            }
            c => {
                if s.is_empty() || s[0] != c {
                    return false;
                }
            }
        }
        s = &s[1..];
        p = &p[1..];
    }
    s.is_empty() && p.is_empty()
}

pub struct GeoIpMatcher {
    n4: Vec<Ipv4Net>,
    n6: Vec<Ipv6Net>,
    inverse: bool,
}

impl GeoIpMatcher {
    pub fn from_geoip(geoip: &GeoIp) -> Result<Self> {
        let mut n4 = Vec::new();
        let mut n6 = Vec::new();

        for cidr in &geoip.cidr {
            if cidr.ip.len() == 4 {
                let bytes: [u8; 4] = cidr
                    .ip
                    .as_slice()
                    .try_into()
                    .context("Invalid IPv4 bytes length")?;
                let ip = Ipv4Addr::from(bytes);
                let net = Ipv4Net::new(ip, cidr.prefix as u8)
                    .map_err(|e| anyhow::anyhow!("Invalid IPv4 CIDR prefix: {}", e))?;
                n4.push(net);
            } else if cidr.ip.len() == 16 {
                let bytes: [u8; 16] = cidr
                    .ip
                    .as_slice()
                    .try_into()
                    .context("Invalid IPv6 bytes length")?;
                let ip = Ipv6Addr::from(bytes);
                let net = Ipv6Net::new(ip, cidr.prefix as u8)
                    .map_err(|e| anyhow::anyhow!("Invalid IPv6 CIDR prefix: {}", e))?;
                n6.push(net);
            } else {
                bail!("Invalid IP length {} in GeoIP entry", cidr.ip.len());
            }
        }

        // Sort by network address for binary search matching Hysteria
        n4.sort_by(|a, b| a.network().octets().cmp(&b.network().octets()));
        n6.sort_by(|a, b| a.network().octets().cmp(&b.network().octets()));

        Ok(Self {
            n4,
            n6,
            inverse: geoip.inverse_match,
        })
    }

    fn match_ipv4(&self, ip: Ipv4Addr) -> bool {
        let mut left = 0;
        let mut right = self.n4.len().saturating_sub(1);
        while left <= right && right < self.n4.len() {
            let mid = (left + right) / 2;
            let net = &self.n4[mid];
            if net.contains(&ip) {
                return true;
            } else if net.network().octets() < ip.octets() {
                left = mid + 1;
            } else {
                if mid == 0 {
                    break;
                }
                right = mid - 1;
            }
        }
        false
    }

    fn match_ipv6(&self, ip: Ipv6Addr) -> bool {
        let mut left = 0;
        let mut right = self.n6.len().saturating_sub(1);
        while left <= right && right < self.n6.len() {
            let mid = (left + right) / 2;
            let net = &self.n6[mid];
            if net.contains(&ip) {
                return true;
            } else if net.network().octets() < ip.octets() {
                left = mid + 1;
            } else {
                if mid == 0 {
                    break;
                }
                right = mid - 1;
            }
        }
        false
    }
}

impl HostMatcher for GeoIpMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        if let Some(v4) = host.ipv4 {
            if self.match_ipv4(v4) {
                return !self.inverse;
            }
        }
        if let Some(v6) = host.ipv6 {
            if self.match_ipv6(v6) {
                return !self.inverse;
            }
        }
        self.inverse
    }
}

struct ParsedGeoSiteDomain {
    domain_type: DomainType,
    value: String,
    regex: Option<Regex>,
    attrs: HashMap<String, bool>,
}

pub struct GeoSiteMatcher {
    domains: Vec<ParsedGeoSiteDomain>,
    attrs: Vec<String>,
}

impl GeoSiteMatcher {
    pub fn from_geosite(site: &GeoSite, attrs: Vec<String>) -> Result<Self> {
        let mut domains = Vec::with_capacity(site.domain.len());
        for d in &site.domain {
            let domain_type = match DomainType::try_from(d.r#type) {
                Ok(t) => t,
                Err(_) => bail!("Unsupported GeoSite domain type {}", d.r#type),
            };

            let regex = if domain_type == DomainType::Regex {
                Some(
                    Regex::new(&d.value)
                        .with_context(|| format!("Invalid regex in geosite domain: {}", d.value))?,
                )
            } else {
                None
            };

            let mut domain_attrs = HashMap::new();
            for attr in &d.attribute {
                domain_attrs.insert(attr.key.clone(), true);
            }

            domains.push(ParsedGeoSiteDomain {
                domain_type,
                value: d.value.clone(),
                regex,
                attrs: domain_attrs,
            });
        }

        Ok(Self { domains, attrs })
    }

    fn match_domain(&self, d: &ParsedGeoSiteDomain, host_name: &str) -> bool {
        // Attribute matching (AND logic)
        if !self.attrs.is_empty() {
            if d.attrs.is_empty() {
                return false;
            }
            for attr in &self.attrs {
                if !d.attrs.get(attr).copied().unwrap_or(false) {
                    return false;
                }
            }
        }

        match d.domain_type {
            DomainType::Plain => host_name.contains(&d.value),
            DomainType::Regex => {
                if let Some(re) = &d.regex {
                    re.is_match(host_name)
                } else {
                    false
                }
            }
            DomainType::Full => host_name == d.value,
            DomainType::RootDomain => {
                host_name == d.value || host_name.ends_with(&format!(".{}", d.value))
            }
        }
    }
}

impl HostMatcher for GeoSiteMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        for d in &self.domains {
            if self.match_domain(d, &host.name) {
                return true;
            }
        }
        false
    }
}

pub fn parse_geosite_name(s: &str) -> (String, Vec<String>) {
    let parts: Vec<&str> = s.split('@').collect();
    let name = parts[0].trim().to_string();
    let attrs: Vec<String> = parts[1..]
        .iter()
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect();
    (name, attrs)
}

pub async fn compile_host_matcher(
    addr: &str,
    geo_loader: &dyn GeoLoader,
) -> Result<Box<dyn HostMatcher>> {
    let addr = addr.trim_end_matches('.').to_ascii_lowercase();
    if addr == "*" || addr == "all" {
        return Ok(Box::new(AllMatcher));
    }

    if let Some(country) = addr.strip_prefix("geoip:") {
        let country = country.trim();
        if country.is_empty() {
            bail!("empty GeoIP country code");
        }
        let geoip_map = geo_loader.load_geoip().await?;
        let entry = geoip_map
            .get(country)
            .with_context(|| format!("GeoIP country code {} not found", country))?;
        return Ok(Box::new(GeoIpMatcher::from_geoip(entry)?));
    }

    if let Some(site_spec) = addr.strip_prefix("geosite:") {
        let (name, attrs) = parse_geosite_name(site_spec);
        if name.is_empty() {
            bail!("empty GeoSite name");
        }
        let geosite_map = geo_loader.load_geosite().await?;
        let entry = geosite_map
            .get(&name)
            .with_context(|| format!("GeoSite name {} not found", name))?;
        return Ok(Box::new(GeoSiteMatcher::from_geosite(entry, attrs)?));
    }

    if let Some(suffix) = addr.strip_prefix("suffix:") {
        let suffix = suffix.trim();
        if suffix.is_empty() {
            bail!("empty domain suffix");
        }
        return Ok(Box::new(DomainMatcher::new(
            suffix.to_string(),
            DomainMatchMode::Suffix,
        )));
    }

    if addr.contains('/') {
        let net = addr
            .parse::<IpNet>()
            .map_err(|_| anyhow::anyhow!("invalid CIDR address: {}", addr))?;
        return Ok(Box::new(CidrMatcher { net }));
    }

    if let Ok(ip) = addr.parse::<IpAddr>() {
        return Ok(Box::new(IpMatcher { ip }));
    }

    if addr.contains('*') {
        return Ok(Box::new(DomainMatcher::new(
            addr,
            DomainMatchMode::Wildcard,
        )));
    }

    Ok(Box::new(DomainMatcher::new(addr, DomainMatchMode::Exact)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_matcher() {
        let m = IpMatcher {
            ip: "127.0.0.1".parse().unwrap(),
        };
        assert!(m.matches(&HostInfo {
            ipv4: Some("127.0.0.1".parse().unwrap()),
            ..Default::default()
        }));
        assert!(!m.matches(&HostInfo {
            ipv4: Some("127.0.0.2".parse().unwrap()),
            ..Default::default()
        }));
    }

    #[test]
    fn test_cidr_matcher() {
        let m = CidrMatcher {
            net: "192.168.1.0/24".parse().unwrap(),
        };
        assert!(m.matches(&HostInfo {
            ipv4: Some("192.168.1.50".parse().unwrap()),
            ..Default::default()
        }));
        assert!(!m.matches(&HostInfo {
            ipv4: Some("192.168.2.50".parse().unwrap()),
            ..Default::default()
        }));
    }

    #[test]
    fn test_domain_matcher_exact() {
        let m = DomainMatcher::new("example.com".to_string(), DomainMatchMode::Exact);
        assert!(m.matches(&HostInfo {
            name: "example.com".to_string(),
            ..Default::default()
        }));
        assert!(!m.matches(&HostInfo {
            name: "sub.example.com".to_string(),
            ..Default::default()
        }));
    }

    #[test]
    fn test_domain_matcher_suffix() {
        let m = DomainMatcher::new("example.com".to_string(), DomainMatchMode::Suffix);
        assert!(m.matches(&HostInfo {
            name: "example.com".to_string(),
            ..Default::default()
        }));
        assert!(m.matches(&HostInfo {
            name: "sub.example.com".to_string(),
            ..Default::default()
        }));
        assert!(m.matches(&HostInfo {
            name: "a.b.example.com".to_string(),
            ..Default::default()
        }));
        assert!(!m.matches(&HostInfo {
            name: "notexample.com".to_string(),
            ..Default::default()
        }));
    }

    #[test]
    fn test_domain_matcher_wildcard() {
        let m = DomainMatcher::new("*.example.com".to_string(), DomainMatchMode::Wildcard);
        assert!(m.matches(&HostInfo {
            name: "foo.example.com".to_string(),
            ..Default::default()
        }));
        assert!(!m.matches(&HostInfo {
            name: "example.com".to_string(),
            ..Default::default()
        }));

        let m2 = DomainMatcher::new("example*.com".to_string(), DomainMatchMode::Wildcard);
        assert!(m2.matches(&HostInfo {
            name: "example2.com".to_string(),
            ..Default::default()
        }));

        // IDN test
        let m_idn = DomainMatcher::new("战狼*.com".to_string(), DomainMatchMode::Wildcard);
        assert!(m_idn.matches(&HostInfo {
            name: "xn--2-x14by21c.com".to_string(), // 战狼2.com in punycode
            ..Default::default()
        }));
    }
}
