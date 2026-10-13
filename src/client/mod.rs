pub mod router;
pub mod socks5;
pub mod udp;

use anyhow::Result;
use std::sync::Arc;

use self::router::MultiServerRouter;
use crate::config::ClientConfig;
use crate::transport::ActiveTransport;

pub async fn run_client(mut config: ClientConfig) -> Result<()> {
    config.validate_and_normalize()?;

    let datagram_router = Arc::new(crate::client::udp::DatagramRouter::new());
    let router = MultiServerRouter::new(&config, Arc::clone(&datagram_router));

    // Start background connection managers for each configured server
    router.start_connection_managers(&config.servers);

    let metrics = Arc::new(crate::metrics::Metrics::new());
    if config.enable_metrics {
        Arc::clone(&metrics).start_periodic_logging();
    }

    println!("================================================================================");
    println!("  QuicProxy Multi-Server Client is starting...");
    println!("  SOCKS5 proxy endpoint: {}", config.socks5_listen);
    println!(
        "  Traffic Mode: {} (Strategy: {})",
        config.routing.mode, config.routing.strategy
    );
    if let Some(ref anchor) = config.routing.relay_to_server {
        println!(
            "  Outbound IP Anchor: Relaying all egress traffic via [{}]",
            anchor
        );
    } else {
        println!("  Outbound IP Anchor: None (Direct exit from each server)");
    }
    println!("  Upstream Servers ({} total):", config.servers.len());
    for s in &config.servers {
        if s.is_realm() {
            println!(
                "    - [{}] {} (realm P2P, weight: {}, priority: {})",
                s.name, s.server_addr, s.weight, s.priority
            );
        } else {
            println!(
                "    - [{}] {}:{} (transport: {}, weight: {}, priority: {})",
                s.name, s.server_addr, s.server_port, s.transport, s.weight, s.priority
            );
        }
    }
    println!("================================================================================");

    let router_for_socks = Arc::clone(&router);
    let conn_provider: Arc<dyn Fn() -> Option<Arc<ActiveTransport>> + Send + Sync> =
        Arc::new(move || router_for_socks.try_select_transport());

    let acl_engine = if let Some(ref acl_cfg) = config.acl {
        let rules_str = acl_cfg.load_rules_string()?;
        if rules_str.trim().is_empty() {
            Arc::new(crate::acl::ACLEngine::new_client_default())
        } else {
            let geo_loader = crate::acl::geo::DefaultGeoLoader::new(
                acl_cfg.geoip.clone(),
                acl_cfg.geosite.clone(),
                acl_cfg.parse_geo_update_interval(),
            );
            Arc::new(
                crate::acl::ACLEngine::new_client_from_string(
                    &rules_str,
                    &config.outbounds,
                    &geo_loader,
                )
                .await?,
            )
        }
    } else {
        Arc::new(crate::acl::ACLEngine::new_client_default())
    };

    let config_arc = Arc::new(config);
    socks5::run_socks5_listener(config_arc, conn_provider, datagram_router, acl_engine).await
}
