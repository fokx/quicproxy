use anyhow::Result;
use quicproxy::acl::geo::{DefaultGeoLoader, GeoLoader};
use quicproxy::acl::matcher::HostInfo;
use quicproxy::acl::rule::{Protocol, parse_text_rules};
use quicproxy::acl::{ACLEngine, DEFAULT_ACL_CACHE_SIZE, compile};
use quicproxy::outbound::Outbound;
use quicproxy::outbound::direct::{DirectMode, DirectOutbound};
use quicproxy::outbound::reject::RejectOutbound;
use quicproxy::protocol::TargetAddr;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct TestGeoLoader {
    geoip_path: PathBuf,
    geosite_path: PathBuf,
}

impl TestGeoLoader {
    fn new() -> Self {
        Self {
            geoip_path: PathBuf::from("/f/hysteria/extras/outbounds/acl/v2geo/geoip.dat"),
            geosite_path: PathBuf::from("/f/hysteria/extras/outbounds/acl/v2geo/geosite.dat"),
        }
    }

    fn is_available(&self) -> bool {
        self.geoip_path.exists() && self.geosite_path.exists()
    }
}

impl GeoLoader for TestGeoLoader {
    fn load_geoip<'a>(
        &'a self,
    ) -> quicproxy::outbound::BoxFuture<'a, Result<Arc<HashMap<String, quicproxy::acl::geo::GeoIp>>>>
    {
        Box::pin(async move {
            let map = quicproxy::acl::geo::load_geoip_file(&self.geoip_path)?;
            Ok(Arc::new(map))
        })
    }

    fn load_geosite<'a>(
        &'a self,
    ) -> quicproxy::outbound::BoxFuture<
        'a,
        Result<Arc<HashMap<String, quicproxy::acl::geo::GeoSite>>>,
    > {
        Box::pin(async move {
            let map = quicproxy::acl::geo::load_geosite_file(&self.geosite_path)?;
            Ok(Arc::new(map))
        })
    }
}

#[tokio::test]
async fn test_compile_and_match_comprehensive() -> Result<()> {
    let geo_loader = TestGeoLoader::new();
    if !geo_loader.is_available() {
        eprintln!("Skipping geo test: database files not found");
        return Ok(());
    }

    let rules_text = r#"
# Test ACL Rules
ob1(1.2.3.4)
ob2(8.8.8.0/24, *, 1.1.1.1)
ob3(all, udp/443)
ob1(2606:4700::6810:85e5, tcp, 2606:4700::6810:85e6)
ob2(2606:4700::/44, */8888)
ob3(*.v2ex.com, udp)
ob1(crap.v2ex.com, tcp/80, 2.2.2.2)
ob2(geoip:JP, */*)
ob4(geosite:4chan, */*)
ob4(geosite:google @cn, */*)
ob5(suffix:microsoft.com, */*)
ob6(all, tcp/6881-6889)
ob1(dotpattern.test., tcp/443)
"#;

    let text_rules = parse_text_rules(rules_text)?;
    assert_eq!(text_rules.len(), 13);

    let mut ob_map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
    let ob1 = Arc::new(DirectOutbound::new("ob1", DirectMode::Auto, None, None));
    let ob2 = Arc::new(DirectOutbound::new("ob2", DirectMode::Auto, None, None));
    let ob3 = Arc::new(DirectOutbound::new("ob3", DirectMode::Auto, None, None));
    let ob4 = Arc::new(DirectOutbound::new("ob4", DirectMode::Auto, None, None));
    let ob5 = Arc::new(DirectOutbound::new("ob5", DirectMode::Auto, None, None));
    let ob6 = Arc::new(DirectOutbound::new("ob6", DirectMode::Auto, None, None));

    ob_map.insert("ob1".to_string(), ob1);
    ob_map.insert("ob2".to_string(), ob2);
    ob_map.insert("ob3".to_string(), ob3);
    ob_map.insert("ob4".to_string(), ob4);
    ob_map.insert("ob5".to_string(), ob5);
    ob_map.insert("ob6".to_string(), ob6);

    let rule_set = compile(&text_rules, &ob_map, DEFAULT_ACL_CACHE_SIZE, &geo_loader).await?;

    struct TestCase {
        host: HostInfo,
        proto: Protocol,
        port: u16,
        want_ob: Option<&'static str>,
        want_ip: Option<IpAddr>,
    }

    let test_cases = vec![
        TestCase {
            host: HostInfo {
                name: "1.2.3.4".to_string(),
                ipv4: Some("1.2.3.4".parse()?),
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 1234,
            want_ob: Some("ob1"),
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "8.8.8.4".to_string(),
                ipv4: Some("8.8.8.4".parse()?),
                ipv6: None,
            },
            proto: Protocol::Udp,
            port: 5353,
            want_ob: Some("ob2"),
            want_ip: Some("1.1.1.1".parse()?),
        },
        TestCase {
            host: HostInfo {
                name: "lean.delicious.com".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Udp,
            port: 443,
            want_ob: Some("ob3"),
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "2606:4700::6810:85e5".to_string(),
                ipv4: None,
                ipv6: Some("2606:4700::6810:85e5".parse()?),
            },
            proto: Protocol::Tcp,
            port: 80,
            want_ob: Some("ob1"),
            want_ip: Some("2606:4700::6810:85e6".parse()?),
        },
        TestCase {
            host: HostInfo {
                name: "2606:4700::1".to_string(),
                ipv4: None,
                ipv6: Some("2606:4700::1".parse()?),
            },
            proto: Protocol::Udp,
            port: 8888,
            want_ob: Some("ob2"),
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "www.v2ex.com".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Udp,
            port: 1234,
            want_ob: Some("ob3"),
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "crap.v2ex.com".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 80,
            want_ob: Some("ob1"),
            want_ip: Some("2.2.2.2".parse()?),
        },
        TestCase {
            host: HostInfo {
                name: "crap.v2ex.com".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 81,
            want_ob: None, // no match
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "crap.v2ex.com".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Udp,
            port: 80,
            want_ob: Some("ob3"),
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "210.140.92.187".to_string(),
                ipv4: Some("210.140.92.187".parse()?),
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 25,
            want_ob: Some("ob2"), // geoip:JP
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "175.45.176.73".to_string(),
                ipv4: Some("175.45.176.73".parse()?),
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 80,
            want_ob: None, // not JP
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "boards.4channel.org".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 443,
            want_ob: Some("ob4"), // geosite:4chan
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "gstatic-cn.com".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Udp,
            port: 9999,
            want_ob: Some("ob4"), // geosite:google @cn
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "hoho.waymo.com".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Udp,
            port: 9999,
            want_ob: None, // google but not @cn
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "microsoft.com".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 6000,
            want_ob: Some("ob5"), // suffix:microsoft.com
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "real.microsoft.com".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Udp,
            port: 5353,
            want_ob: Some("ob5"),
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "fakemicrosoft.com".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 5000,
            want_ob: None,
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "223.1.1.1".to_string(),
                ipv4: Some("223.1.1.1".parse()?),
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 6883,
            want_ob: Some("ob6"), // port range 6881-6889
            want_ip: None,
        },
        TestCase {
            host: HostInfo {
                name: "crap.v2ex.com.".to_string(), // trailing dot
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 80,
            want_ob: Some("ob1"),
            want_ip: Some("2.2.2.2".parse()?),
        },
        TestCase {
            host: HostInfo {
                name: "dotpattern.test".to_string(),
                ipv4: None,
                ipv6: None,
            },
            proto: Protocol::Tcp,
            port: 443,
            want_ob: Some("ob1"),
            want_ip: None,
        },
    ];

    for tc in test_cases {
        let (matched_ob, matched_ip) = rule_set.match_target(tc.host.clone(), tc.proto, tc.port);
        match tc.want_ob {
            Some(expected_name) => {
                assert!(
                    matched_ob.is_some(),
                    "Expected match for host {}, but got none",
                    tc.host.name
                );
                assert_eq!(
                    matched_ob.unwrap().name(),
                    expected_name,
                    "Host {} matched wrong outbound",
                    tc.host.name
                );
            }
            None => {
                assert!(
                    matched_ob.is_none(),
                    "Expected no match for host {}, but got {:?}",
                    tc.host.name,
                    matched_ob.map(|o| o.name().to_string())
                );
            }
        }
        assert_eq!(
            matched_ip, tc.want_ip,
            "Host {} matched wrong hijack IP",
            tc.host.name
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_acl_cache_behavior() -> Result<()> {
    let dummy_loader = DefaultGeoLoader::new(None, None, None);
    let rules_text = "direct(127.0.0.1, tcp/80)\nreject(all)";
    let text_rules = parse_text_rules(rules_text)?;
    let mut ob_map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
    ob_map.insert(
        "direct".to_string(),
        Arc::new(DirectOutbound::new("direct", DirectMode::Auto, None, None)),
    );
    ob_map.insert(
        "reject".to_string(),
        Arc::new(RejectOutbound::new("reject")),
    );

    let rule_set = compile(&text_rules, &ob_map, 2, &dummy_loader).await?;

    let host1 = HostInfo {
        name: "127.0.0.1".to_string(),
        ipv4: Some("127.0.0.1".parse()?),
        ipv6: None,
    };
    let host2 = HostInfo {
        name: "example.com".to_string(),
        ipv4: None,
        ipv6: None,
    };

    // First lookup: misses cache, evaluates rules
    let (ob, _) = rule_set.match_target(host1.clone(), Protocol::Tcp, 80);
    assert_eq!(ob.unwrap().name(), "direct");

    // Second lookup: hits cache
    let (ob, _) = rule_set.match_target(host1.clone(), Protocol::Tcp, 80);
    assert_eq!(ob.unwrap().name(), "direct");

    // Lookup host2
    let (ob, _) = rule_set.match_target(host2.clone(), Protocol::Tcp, 80);
    assert_eq!(ob.unwrap().name(), "reject");

    Ok(())
}

#[tokio::test]
async fn test_acl_engine_handle_and_hijack() -> Result<()> {
    let dummy_loader = DefaultGeoLoader::new(None, None, None);
    let rules_text = "direct(1.2.3.4, tcp/80, 127.0.0.1)";
    let engine = ACLEngine::new_from_string(rules_text, &[], &dummy_loader).await?;

    let target = TargetAddr::Ip("1.2.3.4:80".parse().unwrap());
    let (ob, final_target) = engine.handle(&target, Protocol::Tcp).await;

    assert_eq!(ob.name(), "direct");
    assert_eq!(
        final_target,
        TargetAddr::Ip("127.0.0.1:80".parse().unwrap())
    );

    Ok(())
}

#[tokio::test]
async fn test_client_socks5_with_acl_rules() -> Result<()> {
    // 1. Start a local TCP echo server
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 2. Start SOCKS5 listener with ACL rules:
    //    - reject(127.0.0.99, *) -> reject
    //    - direct(127.0.0.1, *)  -> direct
    //    - direct(10.0.0.1, *, 127.0.0.1) -> hijack to 127.0.0.1!
    let socks5_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let socks5_addr = socks5_listener.local_addr()?;
    drop(socks5_listener);

    let acl_rules =
        format!("reject(127.0.0.99)\ndirect(10.0.0.1, *, 127.0.0.1)\ndirect(127.0.0.1)\n");

    let client_config = quicproxy::config::ClientConfig {
        socks5_listen: socks5_addr,
        servers: vec![quicproxy::config::ServerNodeConfig {
            name: "test-node".to_string(),
            server_addr: "127.0.0.1".to_string(),
            server_port: 14433,
            auth_key: "test-key".to_string(),
            ..Default::default()
        }],
        acl: Some(quicproxy::config::AclConfig {
            inline: Some(quicproxy::config::InlineRules(
                acl_rules.lines().map(|s| s.to_string()).collect(),
            )),
            ..Default::default()
        }),
        ..Default::default()
    };

    tokio::spawn(async move {
        if let Err(e) = quicproxy::client::run_client(client_config).await {
            eprintln!("run_client error: {:#}", e);
        }
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // 3. Test 1: SOCKS5 CONNECT to 127.0.0.99:9999 -> must be rejected with REP = 0x02
    {
        let mut client = tokio::net::TcpStream::connect(socks5_addr).await?;
        // SOCKS5 auth negotiation: NO_AUTH
        client.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await?;
        assert_eq!(resp, [0x05, 0x00]);

        // SOCKS5 CONNECT to 127.0.0.99:9999
        let req = [
            0x05,
            0x01,
            0x00,
            0x01,
            127,
            0,
            0,
            99,
            (9999u16 >> 8) as u8,
            (9999u16 & 0xff) as u8,
        ];
        client.write_all(&req).await?;
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await?;
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x02); // REP_CONNECTION_NOT_ALLOWED_BY_RULESET
    }

    // 4. Test 2: SOCKS5 CONNECT to 127.0.0.1:echo_port -> matches direct -> connects & echoes!
    {
        let mut client = tokio::net::TcpStream::connect(socks5_addr).await?;
        client.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await?;
        assert_eq!(resp, [0x05, 0x00]);

        let port = echo_addr.port();
        let req = [
            0x05,
            0x01,
            0x00,
            0x01,
            127,
            0,
            0,
            1,
            (port >> 8) as u8,
            (port & 0xff) as u8,
        ];
        client.write_all(&req).await?;
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await?;
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00); // REP_SUCCESS

        client.write_all(b"hello direct acl").await?;
        let mut echo_buf = [0u8; 16];
        client.read_exact(&mut echo_buf).await?;
        assert_eq!(&echo_buf, b"hello direct acl");
    }

    // 5. Test 3: SOCKS5 CONNECT to 10.0.0.1:echo_port -> hijacked to 127.0.0.1:echo_port -> succeeds!
    {
        let mut client = tokio::net::TcpStream::connect(socks5_addr).await?;
        client.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await?;
        assert_eq!(resp, [0x05, 0x00]);

        let port = echo_addr.port();
        let req = [
            0x05,
            0x01,
            0x00,
            0x01,
            10,
            0,
            0,
            1,
            (port >> 8) as u8,
            (port & 0xff) as u8,
        ];
        client.write_all(&req).await?;
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await?;
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00); // REP_SUCCESS

        client.write_all(b"hello hijack acl").await?;
        let mut echo_buf = [0u8; 16];
        client.read_exact(&mut echo_buf).await?;
        assert_eq!(&echo_buf, b"hello hijack acl");
    }

    Ok(())
}
