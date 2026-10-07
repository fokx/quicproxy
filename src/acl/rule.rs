use anyhow::{Result, bail};
use regex::Regex;
use std::fmt;
use std::sync::LazyLock;

static LINE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^([\w\-]+)\s*\(([^,]+)(?:,([^,]+))?(?:,([^,]+))?\)$"#).unwrap());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Protocol {
    #[default]
    Both,
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Both => write!(f, "tcp+udp"),
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextRule {
    pub outbound: String,
    pub address: String,
    pub proto_port: String,
    pub hijack_address: String,
    pub line_num: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSyntaxError {
    pub line: String,
    pub line_num: usize,
}

impl fmt::Display for InvalidSyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid syntax at line {}: {}", self.line_num, self.line)
    }
}

impl std::error::Error for InvalidSyntaxError {}

fn parse_line(line: &str, num: usize) -> Option<TextRule> {
    let caps = LINE_REGEX.captures(line)?;
    let outbound = caps.get(1)?.as_str().to_string();
    let address = caps.get(2)?.as_str().trim().to_string();
    let proto_port = caps
        .get(3)
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();
    let hijack_address = caps
        .get(4)
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();

    Some(TextRule {
        outbound,
        address,
        proto_port,
        hijack_address,
        line_num: num,
    })
}

pub fn parse_text_rules(text: &str) -> Result<Vec<TextRule>> {
    let mut rules = Vec::new();
    for (idx, mut line) in text.lines().enumerate() {
        let line_num = idx + 1;
        // Strip comment
        if let Some(pos) = line.find('#') {
            line = &line[..pos];
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match parse_line(line, line_num) {
            Some(rule) => rules.push(rule),
            None => bail!(InvalidSyntaxError {
                line: line.to_string(),
                line_num,
            }),
        }
    }
    Ok(rules)
}

pub fn parse_proto_port(proto_port: &str) -> Result<(Protocol, u16, u16)> {
    let s = proto_port.trim().to_ascii_lowercase();
    if s.is_empty() || s == "*" || s == "*/*" {
        return Ok((Protocol::Both, 0, 0));
    }

    if let Some((proto_str, port_str)) = s.split_once('/') {
        let proto = match proto_str {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "*" => Protocol::Both,
            other => bail!("invalid protocol '{}', expected tcp, udp, or *", other),
        };

        if port_str == "*" {
            return Ok((proto, 0, 0));
        }

        let (start_port, end_port) = if let Some((start_s, end_s)) = port_str.split_once('-') {
            let start = start_s
                .trim()
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("invalid start port: {}", start_s))?;
            let end = end_s
                .trim()
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("invalid end port: {}", end_s))?;
            if start > end {
                bail!("start port {} is greater than end port {}", start, end);
            }
            (start, end)
        } else {
            let p = port_str
                .trim()
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("invalid port: {}", port_str))?;
            (p, p)
        };

        Ok((proto, start_port, end_port))
    } else {
        // No slash, only protocol
        match s.as_str() {
            "tcp" => Ok((Protocol::Tcp, 0, 0)),
            "udp" => Ok((Protocol::Udp, 0, 0)),
            other => bail!("invalid protocol '{}', expected tcp or udp", other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_text_rules() {
        let text = r#"
# Comment line
direct(1.2.3.4)
reject(10.0.0.0/8, tcp/80)
default(8.8.8.8, udp/53, 1.1.1.1)
  # Another comment
outbound-name ( example.com , */443 , 1.2.3.4 ) # trailing comment
"#;
        let rules = parse_text_rules(text).unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(
            rules[0],
            TextRule {
                outbound: "direct".to_string(),
                address: "1.2.3.4".to_string(),
                proto_port: "".to_string(),
                hijack_address: "".to_string(),
                line_num: 3,
            }
        );
        assert_eq!(
            rules[1],
            TextRule {
                outbound: "reject".to_string(),
                address: "10.0.0.0/8".to_string(),
                proto_port: "tcp/80".to_string(),
                hijack_address: "".to_string(),
                line_num: 4,
            }
        );
        assert_eq!(
            rules[2],
            TextRule {
                outbound: "default".to_string(),
                address: "8.8.8.8".to_string(),
                proto_port: "udp/53".to_string(),
                hijack_address: "1.1.1.1".to_string(),
                line_num: 5,
            }
        );
        assert_eq!(
            rules[3],
            TextRule {
                outbound: "outbound-name".to_string(),
                address: "example.com".to_string(),
                proto_port: "*/443".to_string(),
                hijack_address: "1.2.3.4".to_string(),
                line_num: 7,
            }
        );
    }

    #[test]
    fn test_parse_syntax_error() {
        let err = parse_text_rules("invalid line").unwrap_err();
        assert!(err.to_string().contains("invalid syntax at line 1"));

        let err2 = parse_text_rules("outbound(1, 2, 3, 4)").unwrap_err();
        assert!(err2.to_string().contains("invalid syntax at line 1"));
    }

    #[test]
    fn test_parse_proto_port() {
        assert_eq!(parse_proto_port("").unwrap(), (Protocol::Both, 0, 0));
        assert_eq!(parse_proto_port("*").unwrap(), (Protocol::Both, 0, 0));
        assert_eq!(parse_proto_port("*/*").unwrap(), (Protocol::Both, 0, 0));
        assert_eq!(parse_proto_port("tcp").unwrap(), (Protocol::Tcp, 0, 0));
        assert_eq!(parse_proto_port("udp").unwrap(), (Protocol::Udp, 0, 0));
        assert_eq!(parse_proto_port("tcp/*").unwrap(), (Protocol::Tcp, 0, 0));
        assert_eq!(parse_proto_port("udp/*").unwrap(), (Protocol::Udp, 0, 0));
        assert_eq!(parse_proto_port("tcp/80").unwrap(), (Protocol::Tcp, 80, 80));
        assert_eq!(parse_proto_port("udp/53").unwrap(), (Protocol::Udp, 53, 53));
        assert_eq!(
            parse_proto_port("*/443").unwrap(),
            (Protocol::Both, 443, 443)
        );
        assert_eq!(
            parse_proto_port("udp/20000-30000").unwrap(),
            (Protocol::Udp, 20000, 30000)
        );
        assert_eq!(
            parse_proto_port("*/1000-2000").unwrap(),
            (Protocol::Both, 1000, 2000)
        );

        assert!(parse_proto_port("http").is_err());
        assert!(parse_proto_port("tcp/70000").is_err());
        assert!(parse_proto_port("tcp/2000-1000").is_err());
    }
}
